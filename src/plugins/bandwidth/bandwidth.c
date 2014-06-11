/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <endian.h>
#include <inttypes.h>

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"

#define WINDOW_GROUPS_CNT 3
#define DEFAULT_WINDOWS_CNT 20

//Settings for communication protocol
#define PROTO_ITEMS_PER_WINDOW 3

struct frame {
	uint64_t in_sum;
	uint64_t out_sum;
};

struct window {
	uint64_t len; //length of window in us
	size_t cnt;
	size_t current_frame;
	uint64_t timestamp;
	uint64_t in_max;
	uint64_t out_max;
	struct frame *frames;
};

struct user_data {
	struct window windows[WINDOW_GROUPS_CNT];
	uint64_t timestamp;
};

static float get_speed(uint64_t bytes_in_window, uint64_t window_size) {
	uint64_t windows_in_second = 1000000/window_size;

	return (bytes_in_window*windows_in_second/(float)(1024*1024));
}

static uint64_t current_timestamp(void) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (1000000*tv.tv_sec) + (tv.tv_usec);
}

static uint64_t delayed_timestamp(uint64_t timestamp, uint64_t window_len, size_t windows_cnt) {
	return (timestamp - window_len*windows_cnt);
}

static struct window init_window(struct mem_pool *pool, uint64_t length, size_t count, uint64_t current_time) {
	size_t mem_size = count * sizeof(struct frame);
	struct frame *frames = mem_pool_alloc(pool, mem_size);
	memset(frames, 0, mem_size);

	return (struct window) {
		.len = length,
		.cnt = count,
		.timestamp = delayed_timestamp(current_time, length, count),
		.frames = frames
	};
}

void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *d = context->user_data;
	struct window *cwindow;

	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		//Make variables shorter
		cwindow = &(d->windows[window]);

		//Check that the clock did not change
		if (info->timestamp < cwindow->timestamp) {
			//The only reasonable reaction is replace position of window and drop numbers of "broken window"
			cwindow->timestamp = delayed_timestamp(current_timestamp(), cwindow->len, cwindow->cnt);
			memset(cwindow->frames, 0, cwindow->cnt);
			cwindow->current_frame = 0;
			ulog(LLOG_DEBUG_VERBOSE, "Dropping window - time changed?\n");
		}

		while (info->timestamp > cwindow->timestamp + cwindow->len) {
			//Erase dropped frame

			if (cwindow->frames[cwindow->current_frame].in_sum > cwindow->in_max) {
				cwindow->in_max = cwindow->frames[cwindow->current_frame].in_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WINDOW %" PRIu64 " us: New download maximum achieved: %" PRIu64 " (%f MB/s)\n", cwindow->len, cwindow->in_max, get_speed(cwindow->in_max, cwindow->len));
			}
			if (cwindow->frames[cwindow->current_frame].out_sum > cwindow->out_max) {
				cwindow->out_max = cwindow->frames[cwindow->current_frame].out_sum;
				ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: WINDOW %" PRIu64 " us: New upload maximum achieved: %" PRIu64 " (%f MB/s)\n", cwindow->len, cwindow->out_max, get_speed(cwindow->out_max, cwindow->len));
			}

			//Move current frame pointer and update timestamp!!
			cwindow->frames[cwindow->current_frame] = (struct frame) { .in_sum = 0 };
			cwindow->timestamp += cwindow->len;
			cwindow->current_frame = (cwindow->current_frame + 1) % cwindow->cnt;
		}

		if (info->direction == DIR_IN) {
			cwindow->frames[cwindow->current_frame].in_sum += info->length;
		} else {
			cwindow->frames[cwindow->current_frame].out_sum += info->length;
		}
	}
}
static void communicate(struct context *context, const uint8_t *data, size_t length) {
	struct user_data *d = context->user_data;
	struct window *cwindow;

	// Check validity of request
	if (length != sizeof(uint64_t))
		die("Invalid request from upstream to plugin bandwidth, size %zu\n", length);

	//Get maximum also from buffered history
	uint64_t frame_in_sum = 0, frame_out_sum = 0;
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		cwindow = &(d->windows[window]);

		for (size_t frame = 0; frame < cwindow->cnt; frame++) {
			frame_in_sum = cwindow->frames[(cwindow->current_frame + frame) % cwindow->cnt].in_sum;
			frame_out_sum = cwindow->frames[(cwindow->current_frame + frame) % cwindow->cnt].out_sum;

			if (frame_in_sum > cwindow->in_max) {
				cwindow->in_max = frame_in_sum;
			}

			if (frame_out_sum > cwindow->out_max) {
				cwindow->out_max = frame_out_sum;
			}

		}
	}

	/*
		Prepare message.
		Message format is:
		 - timestamp
		 - for every window:
			- window length
			- in_max
			- out_max
	*/
	uint64_t *msg;
	size_t msg_size = (PROTO_ITEMS_PER_WINDOW * WINDOW_GROUPS_CNT + 1) * sizeof *msg;
	msg = mem_pool_alloc(context->temp_pool, msg_size);

	size_t fill = 0;
	msg[fill++] = htobe64(d->timestamp);
	ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: Sending timestamp %" PRIu64 "\n", d->timestamp);
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		msg[fill++] = htobe64(d->windows[window].len);
		msg[fill++] = htobe64(d->windows[window].in_max);
		msg[fill++] = htobe64(d->windows[window].out_max);
	}

	// Send message. Don't check return code. Server ignores old data anyway.
	uplink_plugin_send_message(context, msg, msg_size);

	// Extract timestamp for the next interval
	uint64_t timestamp;
	memcpy(&timestamp, data, length);
	d->timestamp = be64toh(timestamp);
	ulog(LLOG_DEBUG_VERBOSE, "BANDWIDTH: Receiving timestamp %" PRIu64 "\n", d->timestamp);

	// Reset counters
	for (size_t window = 0; window < WINDOW_GROUPS_CNT; window++) {
		cwindow = &(d->windows[window]);
		cwindow->in_max = 0;
		cwindow->out_max = 0;
	}

}

void init(struct context *context) {
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);

	//Configuration of windows and static initialization
	size_t i = 0;
	uint64_t common_start_timestamp = current_timestamp();
	context->user_data->timestamp = 0;
	context->user_data->windows[i++] = init_window(context->permanent_pool, 5000, DEFAULT_WINDOWS_CNT, common_start_timestamp);
	context->user_data->windows[i++] = init_window(context->permanent_pool, 100000, DEFAULT_WINDOWS_CNT, common_start_timestamp);
	context->user_data->windows[i++] = init_window(context->permanent_pool, 1000000, DEFAULT_WINDOWS_CNT, common_start_timestamp);

	//Dynamic initialization

}

#ifdef STATIC
struct plugin *plugin_info_bandwidth(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Bandwidth",
		.packet_callback = packet_handle,
		.init_callback = init,
		.uplink_data_callback = communicate
	};
	return &plugin;
}
