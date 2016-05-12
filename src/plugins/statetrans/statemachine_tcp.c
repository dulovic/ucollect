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

#include "statemachine_tcp.h"
#include "conversation.h"

#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/trie.h"
#include "../../core/util.h"


#include <stdbool.h>
#include <string.h>
#include <inttypes.h>

////////////////////////////////////////////////////////////////////////////////

static void tcp_init(struct statemachine_context *ctx);
static void tcp_destroy(struct statemachine_context *ctx);
static void tcp_packet(struct statemachine_context *ctx, const struct packet_info *pkt);
static struct statemachine_conversation *tcp_get_next_finished_conv(struct statemachine_context *ctx, uint64_t now);
static void tcp_clean_timedout(struct statemachine_context *ctx, uint64_t now);

struct statemachine *statemachine_info_tcp(void) {
	static struct statemachine statemachine = {
		.name = "TCP",
		.transition_count = TCP_STATE_COUNT,

		.init_callback = tcp_init,
		.finish_callback = tcp_destroy,
		.packet_callback = tcp_packet,
		.get_next_finished_conv_callback = tcp_get_next_finished_conv,
		.clean_timedout_convs_callback = tcp_clean_timedout
	};

	return &statemachine;
}

////////////////////////////////////////////////////////////////////////////////

// Conversation - trie conversations, linked list of timedout convs
struct trie_data {
	struct trie_data *next, *prev; // Link list sorted by last access time
	struct statemachine_conversation c; // Follow state only for local endpoint of the connection
	bool deleted;
};

struct tcp_conv_list {
	struct trie_data *head, *tail;
	size_t count;
};

#define LIST_NODE struct trie_data
#define LIST_BASE struct tcp_conv_list
#define LIST_PREV prev
#define LIST_NAME(X) tcp_conv_list_##X
#define LIST_COUNT count
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_REMOVE
#define LIST_WANT_LFOR
#define LIST_INSERT_AFTER
#include "../../core/link_list.h"

struct statemachine_data {
	struct mem_pool *active_pool;
	struct trie *conv_trie; // Trie of conversations for fast lookup
	struct tcp_conv_list conv_list; // Link list sorted by the last packet ts
	size_t delayed_deleted_count;

	size_t consolidate_lower_treshold; // Minimal # of items to be deleted on consolidation
	double consolidate_treshold_portion;

	// How often should be tree of active conversations checked for the timed out ones (in us)
	uint64_t timeout_check_interval;
	// Timestamp of last timeout check in us
	uint64_t last_timedout_check_ts;

	// Connection timouts (in ms)
	uint32_t syn_timeout;
	uint32_t estab_timeout;
	uint32_t rst_timeout;
	uint32_t fin_timeout;
	uint32_t last_ack_timeout;
	
	// Pointer to keep remember next conv. from linked list that should be checked by get_next_finished_conv()
	struct trie_data *next_finished_conv;
};

struct tcp_conv_key {
	uint8_t size;
	uint16_t src_port, dst_port;
	uint8_t addresses[];
};

// Prototypes
static struct tcp_conv_key *tcp_get_key(const struct packet_info *pkt, struct mem_pool *pool, bool reversed);
static struct tcp_conv_key *tcp_get_key_from_conv_id(struct conversation_id *conv_id, struct mem_pool *pool);
static bool tcp_is_timedout(struct statemachine_data *d, struct trie_data *conv, uint64_t now);
static struct trie_data *tcp_lookup_conv(struct statemachine_context *ctx, const struct packet_info *pkt_tcp, const struct packet_info *pkt_outer);
static void tcp_init_conv(struct statemachine_context *ctx, struct trie_data *conv, struct mem_pool *pool, const struct packet_info *pkt_tcp, const struct packet_info *pkt_outer);
static void tcp_add_pkt_to_conv(struct statemachine_context *ctx, struct trie_data *conv, const struct packet_info *pkt);
static enum statemachine_tcp_transition tcp_track_state(struct trie_data *conv, const struct packet_info *pkt);
static bool tcp_is_in_timeslot(uint64_t timeslot_start, timeslot_interval_t interval, uint64_t now);
static void tcp_mark_conv_as_deleted(struct statemachine_data *d, struct trie_data *conv);
static bool tcp_should_consolidate_convs(struct statemachine_context *ctx);
static void tcp_consolidate_convs(struct statemachine_context *ctx);
static struct trie_data *tcp_duplicate_conv(struct statemachine_context *ctx, struct trie_data *conv, struct mem_pool *pool);
static void tcp_sumup_finished_conv(struct statemachine_context *ctx, struct trie_data *conv);
char *tpc_state2str(enum statemachine_tcp_state state);
char *tpc_transition2str(enum statemachine_tcp_transition transition);

// DEBUG
void TCP_DBG_PRINT_CONV_LIST(struct statemachine_context *ctx);

////////////////////////////////////////////////////////////////////////////////

static void tcp_init(struct statemachine_context *ctx) {
	ulog(LLOG_DEBUG, "Statetrans TCP: init \n");
	// Alloc statemachine data
	ctx->data = mem_pool_alloc(ctx->plugin_ctx->permanent_pool, sizeof (struct statemachine_data));
	struct statemachine_data *d = ctx->data;

	// Connection pool and combined trie linked list of conversations
	d->active_pool = mem_pool_create("Statetrans TCP connections");
	d->conv_trie = trie_alloc(d->active_pool);
	d->conv_list.count = 0;
	d->conv_list.head = d->conv_list.tail = NULL;
	d->delayed_deleted_count = 0;

	// Config
	d->consolidate_lower_treshold = 200;
	d->consolidate_treshold_portion = 0.2;
	d->last_timedout_check_ts = 0;
	d->timeout_check_interval = 2 * 1000 * 1000; // 2s
	
	// DEBUG
	d->consolidate_lower_treshold = 10000;
	d->consolidate_treshold_portion = 0.1;

	// Connection timeouts in secs
	// TODO: move to config
	d->syn_timeout = 120 ;
	d->estab_timeout = 5 * 24 * 3600 ; // 5 days
	d->rst_timeout = 10 ;
	d->fin_timeout = 120;
	d->last_ack_timeout = 30;
	
	// Overwrite for demostration purpose
	d->syn_timeout = 12;
	d->estab_timeout = 30;
	d->fin_timeout = 15;
	d->last_ack_timeout = 10;
	
	d->next_finished_conv = NULL;
}

static void tcp_destroy(struct statemachine_context *ctx) {
	ulog(LLOG_DEBUG, "Statetrans TCP: destroy\n");
	struct statemachine_data *d = ctx->data;
	mem_pool_destroy(d->active_pool); 
}

static void tcp_packet(struct statemachine_context *ctx, const struct packet_info *pkt) {

	// Process only TCP packets inside ethernet
	const struct packet_info *pkt_tcp = NULL;
	const struct packet_info *pkt_outer = pkt;
	while (pkt) {
		if (pkt->app_protocol == 'T') {
			pkt_tcp = pkt;
			break;
		}
		
		pkt = pkt->next;
	}
	if(!pkt_tcp || !pkt_outer) {
		ulog(LLOG_DEBUG, "Statetrans TCP: IGNORING packet - not  a TCP packet\n");
		return;
	}
	//ulog(LLOG_DEBUG, "Statetrans TCP: got TCP packet\n");

	//struct statemachine_data *d = ctx->data;
	//uint64_t now = pkt->timestamp;

	// Lookup conversation 
	struct trie_data *conv = tcp_lookup_conv(ctx, pkt_tcp, pkt_outer);
	
	char *pkt_str = packet_format_4tuple(ctx->plugin_ctx->temp_pool, pkt, " ==> ");
	char *conv_str = conversation_id_format_4tuple(ctx->plugin_ctx->temp_pool, &conv->c.id, " ==> ");
	ulog(LLOG_DEBUG, "Statetrans TCP: packet[%s, flags=%hhx] assigned to conv [%s]\n", pkt_str, pkt_tcp->tcp_flags, conv_str);

	// Track conversation state & count transitions
	tcp_add_pkt_to_conv(ctx, conv, pkt_tcp);
}

static struct statemachine_conversation *tcp_get_next_finished_conv(struct statemachine_context *ctx, uint64_t now) {
#ifdef STATETRANS_DEBUG
	ulog(LLOG_DEBUG, "Statetrans TCP: Next finished conversation requested\n");
#endif
	
	struct statemachine_data *d = ctx->data;
	
	// Check last accessed conversation
	struct trie_data *conv = d->conv_list.tail;
	if (conv && (!conv->deleted) && conv->c.terminated) {
		tcp_mark_conv_as_deleted(d, conv); // Mark to be deleted at next consolidation
		tcp_sumup_finished_conv(ctx, conv);
		
#ifdef STATETRANS_DEBUG
		ulog(LLOG_DEBUG, "Statetrans TCP:   Last packet finished its conversation\n");
#endif
		return &conv->c;
	}
	
	// Check linked list of connections
	if (!d->next_finished_conv) {		
		
#ifdef STATETRANS_DEBUG
		TCP_DBG_PRINT_CONV_LIST(ctx);
#endif

		d->next_finished_conv = d->conv_list.head;
		
		
		// Check timedout only once per interval
		bool should_check_timedout = (now > d->last_timedout_check_ts + d->timeout_check_interval);
		if (!should_check_timedout) {
#ifdef STATETRANS_DEBUG
			ulog(LLOG_DEBUG, "Statetrans TCP:   No finished conversation (timeout check interval not reached) \n");
#endif
			return NULL;
		}
	}
	d->last_timedout_check_ts = now;
	
	conv = d->next_finished_conv;
	
	// Skip deleted not terminated and not timedout
	// TODO: the freshest conversations (in the tail of linked list) may be skipped
	while (conv && (conv->deleted || (!conv->c.terminated && !tcp_is_timedout(d, conv, now))) ) {
		// Debug
//		char *conv_str = conversation_id_format_4tuple(ctx->plugin_ctx->temp_pool, &conv->c.id, " ==> ");
//		ulog(LLOG_DEBUG, "Statetrans TCP: NEXT CONV skipping [%s] state=%s term=%d del=%d last_ts=%"PRIu64"s\n",
//			conv_str, 
//			tpc_state2str((enum statemachine_tcp_state) conv->c.state),
//			(int)conv->deleted,
//			(int)conv->c.terminated,
//			conv->c.last_pkt_ts / 1000000
//		);
		
		conv = conv->next;
	}
	
	if (conv) {
#ifdef STATETRANS_DEBUG
		ulog(LLOG_DEBUG, "Statetrans TCP:   Found next finished conversation (timedout) \n");
#endif
		tcp_sumup_finished_conv(ctx, conv);
		tcp_mark_conv_as_deleted(d, conv); // Mark to be deleted at next consolidation
		d->next_finished_conv = conv->next; // On next call of this function continue here
		return &conv->c;
	} 
	
	// No more packets to check
#ifdef STATETRANS_DEBUG
	ulog(LLOG_DEBUG, "Statetrans TCP:   No finished conversation left (timeouts checked) \n");
#endif
	d->next_finished_conv = NULL;
	return NULL;
}

static void tcp_clean_timedout(struct statemachine_context *ctx, uint64_t now __attribute__((unused))) {
	if (tcp_should_consolidate_convs(ctx)) {
		struct statemachine_data *d = ctx->data;
		ulog(LLOG_DEBUG, "Statetrans TCP: Starting conversation DB consolidation (%zu of %zu marked to be deleted)\n",
			d->delayed_deleted_count,
			d->conv_list.count
		);
		
		tcp_consolidate_convs(ctx);
		ulog(LLOG_DEBUG, "Statetrans TCP: Conversation DB consolidation finished\n");
	}
}
////////////////////////////////////////////////////////////////////////////////

static struct tcp_conv_key *tcp_get_key(const struct packet_info *pkt, struct mem_pool *pool, bool reversed) {
	size_t size = sizeof (struct tcp_conv_key) + 2 * pkt->addr_len;
	struct tcp_conv_key *key = mem_pool_alloc(pool, size);
	key->size = size;

	enum endpoint src_ep = reversed ? END_DST : END_SRC;
	enum endpoint dst_ep = reversed ? END_SRC : END_DST;

	key->src_port = pkt->ports[src_ep];
	key->dst_port = pkt->ports[dst_ep];

	// Src & dst address
	memcpy(key->addresses, pkt->addresses[src_ep], pkt->addr_len);
	uint8_t *dst_ip_ptr = key->addresses + pkt->addr_len;
	memcpy(dst_ip_ptr, pkt->addresses[dst_ep], pkt->addr_len);

	return key;
}

static struct tcp_conv_key *tcp_get_key_from_conv_id(struct conversation_id *conv_id, struct mem_pool *pool) {
	size_t addr_len = conversation_id_addr_len(conv_id);
	size_t size = sizeof (struct tcp_conv_key) + 2 * addr_len;
	
	struct tcp_conv_key *key = mem_pool_alloc(pool, size);
	key->size = size;
	
	key->src_port = conv_id->src_port;
	key->dst_port = conv_id->dst_port;

	// Src & dst address
	memcpy(key->addresses, conv_id->src_ip, addr_len);
	uint8_t *dst_ip_ptr = key->addresses + addr_len;
	memcpy(dst_ip_ptr, conv_id->dst_ip, addr_len);

	return key;
}

static bool tcp_is_timedout(struct statemachine_data *d, struct trie_data *conv, uint64_t now) {
	uint32_t timeout_sec;

	switch (conv->c.state) {
		case TCP_ST_SYN_RECD:
		case TCP_ST_ACK_WAIT:
		case TCP_ST_SYN_SENT:
			timeout_sec = d->syn_timeout;
			break;

		case TCP_ST_ESTABLISHED:
			timeout_sec = d->estab_timeout;
			break;

		case TCP_ST_FIN_WAIT_1:
		case TCP_ST_FIN_WAIT_2:
		case TCP_ST_CLOSING_1:
		case TCP_ST_CLOSING_2:
		case TCP_ST_CLOSING:
			timeout_sec = d->fin_timeout;
			break;

		case TCP_ST_CLOSE_WAIT:
		case TCP_ST_CLOSE_WAIT_1:
		case TCP_ST_LAST_ACK_1:
		case TCP_ST_LAST_ACK:
		case TCP_ST_LAST_ACK_2:
			timeout_sec = d->last_ack_timeout;
			break;

		default:
			timeout_sec = d->syn_timeout;
			break;
	}

	uint64_t max_allowed_us = conv->c.last_pkt_ts + 1000000 * (uint64_t) timeout_sec;
	bool is_timedout = (now > max_allowed_us);
	if (is_timedout) {
		conv->c.state = TCP_ST_TIMEDOUT;
		conv->c.terminated = true;
	}
	
	
#ifdef STATETRANS_DEBUG
	char *conv_str = conversation_id_format_4tuple(d->active_pool, &conv->c.id, " ==> ");
	ulog(LLOG_DEBUG, "Statetrans TCP: timeout_check [%s] last_ts_s=%"PRIu64" now_s=%"PRIu64" diff_s=%"PRIu64" timeout_s=%"PRIu32" timedout=%d\n", 
		conv_str,
		conv->c.last_pkt_ts / 1000000,
		now / 1000000,
		(now - conv->c.last_pkt_ts) ,
		timeout_sec,
		(int) is_timedout
	);
#endif
	
	return is_timedout;
}

// Find/create conversation & keep the last accessed conv. in the tail of linked list
static struct trie_data *tcp_lookup_conv(struct statemachine_context *ctx, const struct packet_info *pkt_tcp, const struct packet_info *pkt_outer) {
	struct statemachine_data *d = ctx->data;
	uint64_t now = pkt_tcp->timestamp;
	char *msg = "Using conversation";

	// Lookup conversation 
	const struct tcp_conv_key *key = tcp_get_key(pkt_tcp, ctx->plugin_ctx->temp_pool, false);
	struct trie_data *conv = trie_lookup(d->conv_trie, (const uint8_t *) key, key->size);
	// Found 
	if (conv) {
		// Found but timed out
		if (tcp_is_timedout(d, conv, now)) {
			/* Found but timed out ..How to solve this?:
			 * 1. Mark old connection as timedout
			 * 2. Leave conv untouched in linked list (will be detected on next timeout check).
			 * 3. Add new_conv to linked list
			 * 4. Reuse trie item pointer to point to new_conv.
			 */
			conv->c.terminated = true;
			conv->c.state = TCP_ST_TIMEDOUT;
			
			conv = *trie_index(d->conv_trie, (const uint8_t *) key, key->size) = tcp_conv_list_append_pool(&d->conv_list, d->active_pool);
			tcp_init_conv(ctx, conv, d->active_pool, pkt_tcp, pkt_outer);
		
			msg = "Timedout conversation, creating new";
		}
		// Found & not timed out
		else {
			// Move conv to the end of linked list (last accessed): remove, append to tail
			tcp_conv_list_remove(&d->conv_list, conv);
			tcp_conv_list_insert_after(&d->conv_list, conv, d->conv_list.tail);		
		}
	}
	// Not found in original direction, try reversed
	if (!conv) {
		// Try to search for conversation in reversed direction
		struct tcp_conv_key *r_key = tcp_get_key(pkt_tcp, ctx->plugin_ctx->temp_pool, true);
		conv = trie_lookup(d->conv_trie,  (const uint8_t *) r_key, r_key->size);

		// Found reverse but timed out
		if (conv && tcp_is_timedout(d, conv, now)) {
			// Leave found conv. to be timeout detected and create new conv. in original direction
			conv->c.terminated = true;
			conv->c.state = TCP_ST_TIMEDOUT;
			conv = NULL;
		}

		// If conv found, move to the end of linked list (last accessed): remove, append to tail
		if (conv) {
			tcp_conv_list_remove(&d->conv_list, conv);
			tcp_conv_list_insert_after(&d->conv_list, conv, d->conv_list.tail);
		}
	}

	// No coresponding active conversation found, create new - append to list & insert to tree
	if (!conv) {
		conv = *trie_index(d->conv_trie, (const uint8_t *) key, key->size) = tcp_conv_list_append_pool(&d->conv_list, d->active_pool);
		tcp_init_conv(ctx, conv, d->active_pool, pkt_tcp, pkt_outer);
		
		msg = "New conversation";
	}

	
#ifdef STATETRANS_DEBUG
	char *conv_str = conversation_id_format_4tuple(ctx->plugin_ctx->temp_pool, &conv->c.id, " ==> ");
	ulog(LLOG_DEBUG, "Statetrans TCP: conv lookup: %s: [%s]\n", msg, conv_str);
#endif
	
	return conv;
}

static void tcp_init_conv(struct statemachine_context *ctx, struct trie_data *conv, struct mem_pool *pool, const struct packet_info *pkt_tcp, const struct packet_info *pkt_outer) {
	struct statemachine_data *d = ctx->data;
	
	conv->deleted = false;
	conversation_id_from_packet(&conv->c.id, d->active_pool, pkt_outer);
	conv->c.state = TCP_ST_NO_STATE;
	conv->c.first_pkt_ts = pkt_tcp->timestamp;
	conv->c.last_pkt_ts = pkt_tcp->timestamp;
	conv->c.terminated = false;

	// Alloc timeslots & set to zero
	conv->c.timeslots = mem_pool_alloc(pool, ctx->timeslot_cnt * sizeof (struct statemachine_timeslot *));
	size_t i;
	size_t size = TCP_TRANS_COUNT * sizeof (struct statemachine_timeslot);
	for (i = 0; i < ctx-> timeslot_cnt; i++) {
		conv->c.timeslots[i] = mem_pool_alloc(pool, size);
		memset(conv->c.timeslots[i], 0, size);
	}
	
	// Timeslot start timestamps
	size = ctx->timeslot_cnt * sizeof (uint64_t);
	conv->c.timeslot_starts = mem_pool_alloc(pool, size);
	memset(conv->c.timeslot_starts, 0, size);
}

// TODO: implement loop transitions (#ifdef STATETRANS_TCP_LOOP_TRANSITIONS)
// TODO: consider transition matrix[old_state][new_state]
static enum statemachine_tcp_transition tcp_track_state(struct trie_data *conv, const struct packet_info *pkt) {
	enum statemachine_tcp_transition transition = TCP_TRANS_NO_TRANS;
	enum statemachine_tcp_state new_state = conv->c.state;

	enum statemachine_tcp_state old_state = conv->c.state;
	enum tcp_flags flags = pkt->tcp_flags;
	enum direction dir = pkt->direction;

	if ((flags & TCP_RESET) && (old_state != TCP_ST_ESTABLISHED)) {
		new_state = TCP_ST_RST_SEEN;
		transition = TCP_TRANS_T8;
	} else {
		switch (old_state) {
			case TCP_ST_NO_STATE:
				// First packet seen should be from client to server
				if (dir == DIR_IN) {
					// Local side is the server 
					if (flags & TCP_SYN) {
						new_state = TCP_ST_SYN_RECD;
						transition = TCP_TRANS_T1;
					}
				} else { // DIR_OUT
					// Local site will be the client
					if (flags & TCP_SYN) {
						new_state = TCP_ST_SYN_SENT;
						transition = TCP_TRANS_T2;
					}
				}
				break;

			case TCP_ST_SYN_RECD:
				if (dir == DIR_OUT) {
					if ((flags & TCP_ACK) && (flags & TCP_SYN)) {
						new_state = TCP_ST_ACK_WAIT;
						transition = TCP_TRANS_T3;
					} else if (flags & TCP_FIN) {
						new_state = TCP_ST_FIN_WAIT_1;
						transition = TCP_TRANS_T29;
					}
				}
				break;

			case TCP_ST_ACK_WAIT:
				if (dir == DIR_IN) {
					if ((flags & TCP_ACK) && (flags & TCP_FIN)) {
						new_state = TCP_ST_CLOSE_WAIT_1;
						transition = TCP_TRANS_T7;
					} else if (flags & TCP_ACK) {
						new_state = TCP_ST_ESTABLISHED;
						transition = TCP_TRANS_T6;
					}
				} else { // DIR_OUT
					if (flags & TCP_FIN) {
						new_state = TCP_ST_FIN_WAIT_1;
						transition = TCP_TRANS_T30;
					}
				}
				break;
				
			case TCP_ST_SYN_SENT:
				if (dir == DIR_IN) {
					if ((flags & TCP_ACK) && (flags & TCP_SYN)) {
						if (flags & TCP_FIN) {
							new_state = TCP_ST_CLOSE_WAIT_1;
							transition = TCP_TRANS_T31;
						} else {
							new_state = TCP_ST_ESTABLISHED;
							transition = TCP_TRANS_T5;
						}
					} else if (flags & TCP_SYN) {
						new_state = TCP_ST_SYN_RECD;
						transition = TCP_TRANS_T4;
					}
				}
				// ...
				break;
				
			case TCP_ST_ESTABLISHED:
				// SYN can be retransmitted
				if ((flags & TCP_RESET) /*|| (flags & TCP_SYN)*/) {
					new_state = TCP_ST_CLOSED;
					transition = TCP_TRANS_T20;
				} else if (dir == DIR_IN) { 
					if (flags & TCP_FIN) {
						new_state = TCP_ST_CLOSE_WAIT_1;
						transition = TCP_TRANS_T10;
					}
				} else { // DIR_OUT
					if (flags & TCP_FIN) {
						new_state = TCP_ST_FIN_WAIT_1;
						transition = TCP_TRANS_T11;
					}
				}
				break;
				
			// Active close states
				
			case TCP_ST_FIN_WAIT_1:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						if (flags & TCP_FIN) {
							new_state = TCP_ST_CLOSING_2;
							transition = TCP_TRANS_T16;
						} else {
							new_state = TCP_ST_FIN_WAIT_2;
							transition = TCP_TRANS_T13;
						}
					} else if (flags & TCP_FIN) {
						new_state = TCP_ST_CLOSING_1;
						transition = TCP_TRANS_T12;
					} 
				}
				break;
				
			case TCP_ST_FIN_WAIT_2:
				if (dir == DIR_IN) {
					if (flags & TCP_FIN) {
						new_state = TCP_ST_CLOSING_2;
						transition = TCP_TRANS_T14;
					} 
				}
				break;
				
			case TCP_ST_CLOSING_1:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						new_state = TCP_ST_CLOSING_2;
						transition = TCP_TRANS_T15;
					} 
				} else { // DIR_OUT
					if (flags & TCP_ACK) {
						new_state = TCP_ST_CLOSING;
						transition = TCP_TRANS_T17;
					}
				}
				break;
				
			case TCP_ST_CLOSING_2:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						new_state = TCP_ST_CLOSED;
						transition = TCP_TRANS_T19;
					} 
				}
				break;
				
			case TCP_ST_CLOSING:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						new_state = TCP_ST_CLOSED;
						transition = TCP_TRANS_T18;
					} 
				}
				break;
				
			// Passive close states
				
			case TCP_ST_CLOSE_WAIT_1:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						if (flags & TCP_FIN) {
							new_state = TCP_ST_LAST_ACK;
							transition = TCP_TRANS_T25;
						} else {
							new_state = TCP_ST_CLOSE_WAIT;
							transition = TCP_TRANS_T22;
						}
					} else if (flags & TCP_FIN) {
						new_state = TCP_ST_LAST_ACK_1;
						transition = TCP_TRANS_T21;
					} 
				}
				break;
				
			case TCP_ST_CLOSE_WAIT:
				if (dir == DIR_OUT) {
					if (flags & TCP_FIN) {
						new_state = TCP_ST_LAST_ACK;
						transition = TCP_TRANS_T23;
					} 
				}
				break;
				
			case TCP_ST_LAST_ACK_1:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						new_state = TCP_ST_LAST_ACK;
						transition = TCP_TRANS_T24;
					} 
				} else { // DIR_IN
					if (flags & TCP_ACK) {
						new_state = TCP_ST_LAST_ACK_2;
						transition = TCP_TRANS_T26;
					}
				}
				break;
				
			case TCP_ST_LAST_ACK:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						new_state = TCP_ST_CLOSED;
						transition = TCP_TRANS_T28;
					} 
				}
				break;
				
			case TCP_ST_LAST_ACK_2:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						new_state = TCP_ST_CLOSED;
						transition = TCP_TRANS_T27;
					} 
				}
				break;
				
			default:
				break;
		}
	}

	if (new_state == TCP_ST_RST_SEEN || new_state == TCP_ST_CLOSED) {
		conv->c.terminated = true;
	}
	
	ulog(LLOG_DEBUG, "Statetrans TCP: state tracker: %s --> %s [transition %s] %s\n", 
		tpc_state2str(old_state), 
		tpc_state2str(new_state), 
		tpc_transition2str(transition), 
		(conv->c.terminated ? "terminated" : "active")
	);
	
	conv->c.state = new_state;
	return transition;
}

// Adds packet to conversation - udate state and count transitions in all timeslots
static void tcp_add_pkt_to_conv(struct statemachine_context *ctx, struct trie_data *conv, const struct packet_info *pkt) {
	conv->c.last_pkt_ts = pkt->timestamp;
	
#ifdef STATETRANS_DEBUG
	// Process only first fragments in IP datagrams (ignore 3bits for flags))
	if (pkt->frag_off & 0x1FFF) {
		ulog(LLOG_DEBUG, "Statetrans TCP:   Not first IP fragment, ignoring packet\n");
		return;
	}
	ulog(LLOG_INFO, "Statetrans TCP:   Adding packet to conversation\n");
#endif
	
	// Track the state (get transition)
	enum statemachine_tcp_transition transition;
	transition = tcp_track_state(conv, pkt);
	
	if (transition == TCP_TRANS_NO_TRANS)
		return;	// No transition occured - nothing to do
	
	uint64_t now = pkt->timestamp;
	
	size_t i_ts;
	for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
		uint64_t timeslot_start = conv->c.timeslot_starts[i_ts];
		timeslot_interval_t interval = ctx->timeslots[i_ts];
		
		// Check if the packet belongs to opened interval, if not sum up the old interval & switch to new
		if (!tcp_is_in_timeslot(timeslot_start, interval, now)) {
			size_t i_trans;
			for (i_trans = 0; i_trans < TCP_TRANS_COUNT; i_trans++) {
				// Add to sumup
				conv->c.timeslots[i_ts][i_trans].aggr_value += conv->c.timeslots[i_ts][i_trans].value;
				conv->c.timeslots[i_ts][i_trans].aggr_cnt++;

				// Reset values for new slot
				conv->c.timeslots[i_ts][i_trans].value = 0;
				conv->c.timeslot_starts[i_ts] = now;
			}
		}
		
		// Count the transition occured
		conv->c.timeslots[i_ts][transition].value++;	
	}
}

static bool tcp_is_in_timeslot(uint64_t timeslot_start, timeslot_interval_t interval, uint64_t now) {
	return (now < timeslot_start + interval);
}

static void tcp_mark_conv_as_deleted(struct statemachine_data *d, struct trie_data *conv) {
	conv->deleted = true; // Mark as finished
	d->delayed_deleted_count++;
}


static bool tcp_should_consolidate_convs(struct statemachine_context *ctx) {
	struct statemachine_data *d = ctx->data;
	
	// Minimal number of deleted items
	if (d->delayed_deleted_count < d->consolidate_lower_treshold) 
		return false;
	
	// Minimal portion of all conversations to be deleted

	if (d->delayed_deleted_count < d->consolidate_treshold_portion * d->conv_list.count) 
		return false;
	
	// Ok, perform consolidation
	return true;
}

static void tcp_consolidate_convs(struct statemachine_context *ctx) {
	struct statemachine_data *d = ctx->data;
	
	
	struct mem_pool *new_pool = mem_pool_create("Statetrans TCP connections NEW");
	struct trie *new_trie = trie_alloc(new_pool);
	struct tcp_conv_list new_list;
	new_list.count = 0;
	new_list.head = new_list.tail = NULL;
	
	// new pool - new list & trie
	
	//struct trie_data *conv; //tmp
	
	// Copy only not deleted items
	LFOR(tcp_conv_list, conv, &d->conv_list) {
		if (!conv->deleted) {
			
			struct trie_data *new_conv = tcp_duplicate_conv(ctx, conv, new_pool);
			
			// Append to new list
			tcp_conv_list_insert_after(&new_list, new_conv, new_list.tail);
			
			// Insert to new trie
			struct tcp_conv_key *key = tcp_get_key_from_conv_id(&conv->c.id, ctx->plugin_ctx->temp_pool);
			*trie_index(d->conv_trie, (const uint8_t *) key, key->size) = new_conv;
		}
	}
	
	// Update active list & trie in statemachine
	d->conv_list = new_list;
	d->conv_trie = new_trie;
	d->delayed_deleted_count = 0;
	
	// Switch to new active mem_pool
	mem_pool_destroy(d->active_pool);
	d->active_pool = new_pool;
}

static struct trie_data *tcp_duplicate_conv(struct statemachine_context *ctx, struct trie_data *conv, struct mem_pool *pool) {
	struct trie_data *new_conv = mem_pool_alloc(pool, sizeof(struct trie_data));
	new_conv->deleted = conv->deleted;
	new_conv->next = new_conv->prev = NULL;	// Just to be sure
	
	// Copy whole statemachine_conversation, pointers will be changed
	new_conv->c = conv->c;
	
	// Alloc timeslots & copy
	new_conv->c.timeslots = mem_pool_alloc(pool, ctx->timeslot_cnt * sizeof (struct statemachine_timeslot *));
	size_t i_ts;
	size_t size = TCP_TRANS_COUNT * sizeof (struct statemachine_timeslot);
	for (i_ts = 0; i_ts < ctx-> timeslot_cnt; i_ts++) {
		new_conv->c.timeslots[i_ts] = mem_pool_alloc(pool, size);
		memcpy(new_conv->c.timeslots[i_ts], conv->c.timeslots[i_ts], size);
	}
	
	// Timeslot start timestamps
	size = ctx->timeslot_cnt * sizeof (uint64_t);
	new_conv->c.timeslot_starts = mem_pool_alloc(pool, size);
	memcpy(new_conv->c.timeslot_starts, conv->c.timeslot_starts, size);
	
	return new_conv;
}

static void tcp_sumup_finished_conv(struct statemachine_context *ctx, struct trie_data *conv) {
	size_t i_ts, trans;
	for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
		for (trans = 0; trans < TCP_TRANS_COUNT; trans++) {
			// Ignore zeros
			if (!conv->c.timeslots[i_ts][trans].value)
				continue;

			// Add to sumup
			conv->c.timeslots[i_ts][trans].aggr_value += conv->c.timeslots[i_ts][trans].value;
			conv->c.timeslots[i_ts][trans].aggr_cnt++;
		}
	}
}

// String for states & transitions
static char *statemachine_tcp_state_strs[] = {
	"TCP_NO_STAT",
	"TCP_RST_SEEN",
	"TCP_SYN_SENT",
	"TCP_SYN_RECD",
	"TCP_ACK_WAIT",
	"TCP_ESTABLISHED",

	"TCP_FIN_WAIT_1",
	"TCP_FIN_WAIT_2",
	"TCP_CLOSING_1",
	"TCP_CLOSING_2",
	"TCP_CLOSING",

	"TCP_CLOSE_WAIT_1",
	"TCP_CLOSE_WAIT",
	"TCP_LAST_ACK_1",
	"TCP_LAST_ACK",
	"TCP_LAST_ACK_2",

	"TCP_CLOSED",

	"TCP_TIMEDOUT",
	"TCP_RST",

	"TCP_STATE_COUNT" // Must be the last one
};

static char *statemachine_tcp_transition_strs[] ={
	"TCP_TRANS_NO_TRANS",

	"TCP_TRANS_T1",
	"TCP_TRANS_T2",
	"TCP_TRANS_T3",
	"TCP_TRANS_T4",
	"TCP_TRANS_T5",
	"TCP_TRANS_T6",
	"TCP_TRANS_T7",
	"TCP_TRANS_T8",
	"TCP_TRANS_T9",
	"TCP_TRANS_T10",
	"TCP_TRANS_T11",
	"TCP_TRANS_T12",
	"TCP_TRANS_T13",
	"TCP_TRANS_T14",
	"TCP_TRANS_T15",
	"TCP_TRANS_T16",
	"TCP_TRANS_T17",
	"TCP_TRANS_T18",
	"TCP_TRANS_T19",
	"TCP_TRANS_T20",
	"TCP_TRANS_T21",
	"TCP_TRANS_T22",
	"TCP_TRANS_T23",
	"TCP_TRANS_T24",
	"TCP_TRANS_T25",
	"TCP_TRANS_T26",
	"TCP_TRANS_T27",
	"TCP_TRANS_T28",
	"TCP_TRANS_T29",
	"TCP_TRANS_T30",
	"TCP_TRANS_T31",

#ifdef STATETRANS_TCP_LOOP_TRANSITIONS
	"TCP_TRANS_T32",
	"TCP_TRANS_T33",
	"TCP_TRANS_T34",
	"TCP_TRANS_T35",
	"TCP_TRANS_T36",
	"TCP_TRANS_T37",
	"TCP_TRANS_T38",
	"TCP_TRANS_T39",
	"TCP_TRANS_T40",
	"TCP_TRANS_T41",
	"TCP_TRANS_T42",
#endif // STATETRANS_TCP_LOOP_TRANSITIONS

	"TCP_TRANS_COUNT"	// Must be the last one
};

char *tpc_state2str(enum statemachine_tcp_state state) {
	return statemachine_tcp_state_strs[state];
}

char *tpc_transition2str(enum statemachine_tcp_transition transition) {
	return statemachine_tcp_transition_strs[transition];
}

void TCP_DBG_PRINT_CONV_LIST(struct statemachine_context *ctx) {
	struct statemachine_data *d = ctx->data;
	
	ulog(LLOG_DEBUG, "Statetrans TCP: ----- DUMPING CONV LINKED LIST (TCP) -----\n");
	ulog(LLOG_DEBUG, "Statetrans TCP:  count=%zu\n",  d->conv_list.count);
	size_t i_conv = 0;
	LFOR(tcp_conv_list, conv, &d->conv_list) {
		char *conv_str = conversation_id_format_4tuple(ctx->plugin_ctx->temp_pool, &conv->c.id, " ==> ");
		ulog(LLOG_DEBUG, "Statetrans TCP: | %3zu [%s] state=%s term=%d del=%d last_ts=%"PRIu64"s\n", 
			i_conv++,
			conv_str, 
			tpc_state2str((enum statemachine_tcp_state) conv->c.state),
			(int)conv->c.terminated,
			(int)conv->deleted,
			conv->c.last_pkt_ts / 1000000
		);
	}
	ulog(LLOG_DEBUG, "Statetrans TCP: \\_______________\n");
}