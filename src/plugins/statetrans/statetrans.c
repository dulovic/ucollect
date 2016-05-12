/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2016 Tomas Morvay

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

/*
 * test e.g.:
 *	learning:
 *	       for i in `seq 1 30`; do curl google.com; sleep 0.2; done 
 *	detection
 *	       sudo nmap -PN -sS -p 1000-1005 1.1.1.1
 * 
 * build with -DSTATETRANS_DEBUG to enable debugging outputs 
 */


#include "engine.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/trie.h"
#include "../../core/packet.h"
#include "packet_buffer.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

// printf formatter for uint64_t
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

struct user_data {
	struct engine *engine;
	struct packet_buffer *packet_buf;
};

static void timeout(struct context *context, void *data __attribute__((unused)), size_t id __attribute__((unused))) {
	ulog(LLOG_DEBUG, "Statetrans: changing mode to DETECTION ============================================\n");
	struct user_data *u = context->user_data;
	
	engine_change_mode(u->engine, context, DETECTION);
	ulog(LLOG_DEBUG, "Statetrans: mode change finished\n");
}

static void init(struct context *context) {
	ulog(LLOG_DEBUG, "Statetrans: Init\n");
#ifdef STATETRANS_DEBUG
	ulog(LLOG_DEBUG, "Statetrans: STATETRANS_DEBUG defined\n");
#endif	
	
	context->user_data = mem_pool_alloc(context->permanent_pool, sizeof(struct user_data));
	struct user_data *u = context->user_data;
	
	timeslot_interval_t timeslots[] = {1, 10, 100, 1000, 10000, 100000, 1000000};
	size_t timeslot_cnt = sizeof(timeslots) / sizeof(timeslot_interval_t);
	
	double threshold = 0.95;
	char *logfile = "statetrans.log";
	size_t pkt_buf_size = 20;
	
	u->packet_buf = packet_buffer_create(context->permanent_pool, pkt_buf_size);
	u->engine = engine_create(context, timeslots, timeslot_cnt, threshold, logfile);
			
	// Switch to detection after given time
	// TODO: more advanced mode change condition can be given by server
	
	
	uint32_t learning_length = 90000;
	loop_timeout_add(context->loop, learning_length, context, NULL, timeout);
}

static void packet_handle(struct context *context, const struct packet_info *info) {
	struct user_data *u = context->user_data;
	
	// Debug log
	char *fourtuple = packet_format_4tuple(context->temp_pool, info, " ==> ");
	char *layers = packet_format_layer_info(context->temp_pool, info, " -> ");
	ulog(LLOG_DEBUG, "Statetrans: Packet[%s] %s\n", layers, fourtuple);
	
	// Buffer packets & get the oldest one after the buffer is filled
	const struct packet_info *buffered_pkt = packet_buffer_add(u->packet_buf, info);
	if(!buffered_pkt) {
#ifdef STATETRANS_DEBUG
		ulog(LLOG_DEBUG, "Statetrans: Not enough packets in packet buffer, delaying processing\n");
#endif
		return;
	}
	
	// Debug log
	fourtuple = packet_format_4tuple(context->temp_pool, buffered_pkt, " ==> ");
	//layers = packet_format_layer_info(context->temp_pool, buffered_pkt, " -> ");
	ulog(LLOG_DEBUG, "Statetrans: Processing buffered packet [%s] ts=%"PRIu64"\n", fourtuple, buffered_pkt->timestamp);
	
	engine_handle_packet(u->engine, context, buffered_pkt);
}

void destroy(struct context *context) {
	struct user_data *u = context->user_data;
	
	engine_destroy(u->engine, context);
}

#ifndef STATIC
unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}

#endif
#ifdef STATIC
struct plugin *plugin_info_statetrans(void) {
#else
struct plugin *plugin_info(void) {
#endif
	static struct plugin plugin = {
		.name = "Statetrans",
		.version = 1,
		.init_callback = init,
		.finish_callback = destroy, 
		.packet_callback = packet_handle
	};
	return &plugin;
}
