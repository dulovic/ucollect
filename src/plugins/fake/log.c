/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2014-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "log.h"

#include "../../core/mem_pool.h"
#include "../../core/trie.h"
#include "../../core/context.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"
#include "../../core/util.h"

#include <string.h>
#include <arpa/inet.h>
#include <inttypes.h>

/*
 * Single event in the log.
 */
struct log_event {
	struct log_event *next;		// For linked list managment
	char code;			// The server name/code that generated the event
	const uint8_t *rem_addr;	// Which address was the remote
	const uint8_t *loc_addr;	// Which one was the local
	uint16_t rem_port;		// Which was the remote port
	uint64_t timestamp;		// When it happened
	uint8_t addr_len;
	enum event_type type;
	uint8_t info_count;		// Some extra info about the event
	struct event_info extra_info[];
};

/*
 * The log consists of two main items.
 * • Sequential log of the events, in a linked list. This is eventually dumped to
 *   the server.
 * • A trie with login IDs (server name+remote IP address), each holding number of
 *   login attempts on that ID. This is to check if anythig exceeds the limit.
 *
 * Then there's some metadata.
 */
struct log {
	struct mem_pool *pool;
	struct log_event *head, *tail;
	struct trie *limit_trie;
	size_t expected_serialized_size; // How large the result will be when we dump it.
	uint32_t ip_limit, size_limit;   // Limits on when to send.
	uint32_t throttle_holdback;	 // How long to wait until sending logs because of some IP address again
	bool log_credentials;		 // Should we send the login name and password?
	bool attempts_reached;		 // When we reached the maximum number of attempts
};

struct trie_data {
	unsigned attempt_count;
	uint64_t holdback_until;
};

#define LIST_NODE struct log_event
#define LIST_BASE struct log
#define LIST_NAME(X) log_##X
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

struct holdback_item {
	struct holdback_item *next;
	uint64_t holdback_until;
	size_t key_size;
	uint8_t key[];
};

struct holdback_tmp {
	struct holdback_item *head, *tail;
	struct mem_pool *tmp_pool;
	uint64_t now;
};

#define LIST_NODE struct holdback_item
#define LIST_BASE struct holdback_tmp
#define LIST_NAME(X) holdback_##X
#define LIST_WANT_INSERT_AFTER
#define LIST_WANT_LFOR
#include "../../core/link_list.h"

static void holdback_store(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	struct holdback_tmp *tmp = userdata;
	if (data && data->holdback_until > tmp->now) {
		struct holdback_item *item = mem_pool_alloc(tmp->tmp_pool, sizeof *item + key_size);
		*item = (struct holdback_item) {
			.holdback_until = data->holdback_until,
			.key_size = key_size
		};
		memcpy(item->key, key, key_size);
		holdback_insert_after(tmp, item, tmp->tail);
	}
}

static void log_clean_internal(struct log *log, struct mem_pool *tmp_pool, uint64_t now) {
	struct holdback_tmp tmp = {
		.tmp_pool = tmp_pool,
		.now = now
	};
	if (log->limit_trie) {
		sanity(tmp_pool, "Missing temporary pool\n");
		trie_walk(log->limit_trie, holdback_store, &tmp, tmp_pool);
	}
	mem_pool_reset(log->pool);
	log->head = log->tail = NULL;
	log->expected_serialized_size = 0;
	log->limit_trie = trie_alloc(log->pool);
	log->attempts_reached = false;
	if (tmp.head) {
		ulog(LLOG_DEBUG_VERBOSE, "Copying holdback times, now %llu\n", (long long unsigned)now);
		LFOR(holdback, item, &tmp) {
			ulog(LLOG_DEBUG_VERBOSE, "Copy holdback time %llu for %s\n", (long long unsigned)item->holdback_until, mem_pool_hex(tmp_pool, item->key, item->key_size));
			struct trie_data **data = trie_index(log->limit_trie, item->key, item->key_size);
			*data = mem_pool_alloc(log->pool, sizeof **data);
			**data = (struct trie_data) {
				.holdback_until = item->holdback_until
			};
		}
	}
}

struct log *log_alloc(struct mem_pool *permanent_pool, struct mem_pool *log_pool) {
	struct log *result = mem_pool_alloc(permanent_pool, sizeof *result);
	*result = (struct log) {
		.pool = log_pool,
		// Some arbitrary defaults, it should be overwritten by server config
		.ip_limit = 5,
		.size_limit = 4096 * 1024,
		.throttle_holdback = 120000, // Two minutes
	};
	log_clean_internal(result, NULL, 0);
	return result;
}

enum addr_type {
	AT_IPv4,
	AT_IPv6
};

struct event_header {
	uint32_t timestamp;		// How many milliseconds ago it happened. uint32_t is enough, as it is more than 49 days.
	enum event_type type:8;
	enum addr_type addr:8;
	uint8_t info_count;
	char code;
	uint16_t remote_port;
} __attribute__((packed));

// The IPv6 mapped IPv4 addresses are ::FFFF:<IP>.
static const uint8_t mapped_prefix[] = { [10] = 0xFF, [11] = 0xFF };

enum log_send_status log_event(struct context *context, struct log *log, char server_code, const uint8_t *rem_address, const uint8_t *loc_address, size_t addr_len, uint16_t rem_port, enum event_type type, struct event_info *info) {
	// If it's IPv6 mapped IPv4, store it as IPv4 only
	if (memcmp(rem_address, mapped_prefix, sizeof mapped_prefix) == 0) {
		addr_len -= sizeof mapped_prefix;
		rem_address += sizeof mapped_prefix;
		loc_address += sizeof mapped_prefix;
	}
	size_t info_count = 0;
	size_t expected_size = sizeof(struct event_header);
	expected_size += 2 * addr_len;
	if (info)
		for (struct event_info *i = info; i->type != EI_LAST; i ++)
			if (log->log_credentials || (i->type != EI_NAME && i->type != EI_PASSWORD))
					info_count ++;
	struct log_event *event = mem_pool_alloc(log->pool, sizeof *event + info_count * sizeof event->extra_info[0]);
	uint8_t *addr_cp = mem_pool_alloc(log->pool, 2 * addr_len);
	memcpy(addr_cp, rem_address, addr_len);
	memcpy(addr_cp + addr_len, loc_address, addr_len);
	uint64_t now = loop_now(context->loop);
	*event = (struct log_event) {
		.code = server_code,
		.rem_addr = addr_cp,
		.loc_addr = addr_cp + addr_len,
		.rem_port = rem_port,
		.addr_len = addr_len,
		.timestamp = now,
		.type = type,
		.info_count = info_count
	};
	for (size_t i = 0; i < info_count; i ++) {
		if (!log->log_credentials && (info[i].type == EI_NAME || info[i].type == EI_PASSWORD))
			// Skip the login credentials if we shouldn't log them
			continue;
		event->extra_info[i] = (struct event_info) {
			.type = info[i].type,
			.content = mem_pool_strdup(log->pool, info[i].content)
		};
		expected_size += 5 + strlen(info[i].content); // +4 for length, +1 for the info flags/type.
	}
	log_insert_after(log, event, log->tail);
	log->expected_serialized_size += expected_size;
	bool attempts_reached = false;
	if (type == EVENT_LOGIN) {
		size_t id_len = 1 + addr_len;
		uint8_t login_id[id_len];
		*login_id = server_code;
		memcpy(login_id + 1, rem_address, addr_len);
		struct trie_data **data = trie_index(log->limit_trie, login_id, id_len);
		if (!*data) {
			*data = mem_pool_alloc(log->pool, sizeof **data);
			(*data)->attempt_count = 1;
			(*data)->holdback_until = 0;
		} else {
			(*data)->attempt_count ++;
		}
		if ((*data)->attempt_count >= log->ip_limit && (*data)->holdback_until <= now) {
			(*data)->holdback_until = now + log->throttle_holdback;
			attempts_reached = true;
		}
	}
	log->attempts_reached = log->attempts_reached || attempts_reached;
	return log_status(log);
}

enum log_send_status log_status(struct log *log) {
	if (log->expected_serialized_size >= 2 * log->size_limit)
		return LS_FORCE_SEND; // We really need to send now
	if (log->attempts_reached || log->expected_serialized_size >= log->size_limit)
		return LS_SEND; // If we reached attempts (even several times), it is not a reason to drop the log if it can't be sent. But attempt to send it, please.
	return LS_NONE;
}

uint8_t *log_dump(struct context *context, struct log *log, size_t *size) {
	if (!log->expected_serialized_size) {
		*size = 0;
		return NULL;
	}
	uint64_t now = loop_now(context->loop);
	uint64_t limit = 0x100000000;
	*size = log->expected_serialized_size + 1;
	uint8_t *result = mem_pool_alloc(context->temp_pool, log->expected_serialized_size + 1), *pos = result + 1;
	size_t rest = *size - 1;
	*result = 'L';
	LFOR(log, event, log) {
		sanity(event->timestamp + limit > now, "Timestamp %" PRIu64 " is too old for current time %" PRIu64 "\n", event->timestamp, now);
		sanity(event->addr_len == 4 || event->addr_len == 16, "Wrong event address length %hhu\n", event->addr_len);
		sanity(event->info_count < 16, "Too many additional info records: %hhu\n", event->info_count);
		struct event_header header = {
			.timestamp = htonl(now - event->timestamp),
			.type = event->type,
			.addr = event->addr_len == 4 ? AT_IPv4 : AT_IPv6,
			.info_count = event->info_count,
			.code = event->code,
			.remote_port = htons(event->rem_port)
		};
		sanity(rest >= 2 * event->addr_len + sizeof header, "Not enough buffer space, %zu available, %zu needed\n", rest, 2 * event->addr_len + sizeof header);
		memcpy(pos, &header, sizeof header);
		pos += sizeof header;
		memcpy(pos, event->rem_addr, event->addr_len);
		memcpy(pos + event->addr_len, event->loc_addr, event->addr_len);
		pos += 2 * event->addr_len;
		rest -= 2 * event->addr_len + sizeof header;
		for (size_t i = 0; i < event->info_count; i ++) {
			sanity(rest > 0, "No buffer space available for additional info\n");
			sanity(event->extra_info[i].type != EI_LAST, "Last additional info in the middle of array\n");
			*pos ++ = event->extra_info[i].type;
			rest --;
			uplink_render_string(event->extra_info[i].content, strlen(event->extra_info[i].content), &pos, &rest);
		}
	}
	sanity(pos == result + *size, "Length and pointer mismatch at log dump\n");
	sanity(rest == 0, "Log dump buffer leftover of %zu bytes\n", rest);
	return result;
}

void log_clean(struct context *context, struct log *log) {
	log_clean_internal(log, context->temp_pool, loop_now(context->loop));
}

void log_set_send_credentials(struct log *log, bool send) {
	ulog(LLOG_INFO, "Sending login credentials %s\n", send ? "enabled" : "disabled");
	log->log_credentials = send;
}

void log_set_limits(struct log *log, uint32_t max_size, uint32_t max_attempts, uint32_t throttle_holdback) {
	log->size_limit = max_size;
	log->ip_limit = max_attempts;
	log->throttle_holdback = throttle_holdback;
}
