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

#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/trie.h"

#include <stdbool.h>

//#include "statemachine_tcp_conv_list.h"



// Conversation - trie conversations, linked list of timedout convs

struct trie_data {
	struct trie_data *next, *prev; // Link list sorted by last access time
	struct statemachine_conversation c; // Follow state only for local endpoint of the connection
};

struct tcp_conv_list {
	struct trie_data *head, *tail;
	size_t count;
};

#define LIST_NODE struct tcp_conv_list
#define LIST_BASE struct user_data
#define LIST_PREV prev
#define LIST_NAME(X) conv_list_##X
#define LIST_COUNT count
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_REMOVE
#define LIST_WANT_LFOR
#define LIST_INSERT_AFTER
#include "../../core/link_list.h"
#include "conversation.h"

struct statemachine_data {
	struct mem_pool *active_pool;
	struct trie *conv_tree; // Trie of conversations for fast lookup
	struct tcp_conv_list conv_list; // Link list sorted by the last packet ts
	size_t delayed_deleted_count;

	size_t consolidate_lower_treshold;
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
};

struct tcp_conv_key {
	uint8_t size;
	uint16_t src_port, dst_port;
	uint8_t addresses[];
};

// Prototypes
struct tcp_conv_key *tcp_get_key(struct packet_info *pkt, struct mem_pool *pool, bool reversed);
bool tcp_is_timedout(struct statemachine_data *d, struct trie_data *conv, uint64_t now);
struct trie_data *tcp_lookup_conv(struct statemachine_context *ctx, const struct packet_info *pkt);
void tcp_init_conv(struct statemachine_context *ctx, struct trie_data *conv, struct mem_pool *pool);
enum statemachine_tcp_transition tcp_track_state(struct trie_data *conv, const struct packet_info *pkt);
void tcp_add_pkt_to_conv(struct trie_data *conv, const struct packet_info *pkt);
void tcp_lookup_timedout_convs(struct statemachine_context *ctx, uint64_t now);
void tcp_lookup_timedout_callback(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata);

static void tcp_init(struct statemachine_context *ctx) {
	// Alloc statemachine data
	ctx->data = mem_pool_alloc(ctx->plugin_ctx->permanent_pool, sizeof (struct statemachine_data));
	struct statemachine_data *d = ctx->data;

	// Connection pool and combined trie linked list of conversations
	d->active_pool = mem_pool_create("Statetrans TCP connections pool");
	d->conv_tree = trie_alloc(d->active_pool);
	d->conv_list.count = 0;
	d->conv_list.head = d->conv_list.tail = NULL;


	// Hardcoded
	d->consolidate_lower_treshold = 200;
	d->consolidate_treshold_portion = 0.2;
	d->last_timedout_check_ts = 0;
	d->timeout_check_interval = 5 * 1000 * 1000; // 5s

	// Connection timeouts in secs
	d->syn_timeout = 120 * 1000;
	d->estab_timeout = 5 * 24 * 3600 * 1000;
	d->rst_timeout = 10 * 1000;
	d->fin_timeout = 120 * 1000;
	d->last_ack_timeout = 30 * 1000;
}

static void tcp_destroy(struct statemachine_context *ctx) {
	struct statemachine_data *d = ctx->data;

	mem_pool_destroy(d->active_pool);
}

static void tcp_packet(struct statemachine_context *ctx, const struct packet_info *pkt) {

	// Filter
	while (pkt && pkt->app_protocol != 'T') {
		pkt = pkt->next;
	}
	if (pkt->app_protocol != 'T')
		return;

	struct statemachine_data *d = ctx->data;
	uint64_t now = info->timestamp;

	// Lookup conversation 
	struct trie_data *conv = tcp_lookup_conv(ctx, pkt);

	tcp_add_pkt_to_conv(conv, pkt);
	// New conversation




	// lookup conv or 

	// check timedtou

	// add pkt to sm conv





	// filter tcp





	/*
	// Look for TCP timeouts if interval passed since last check
	if (d->last_timedout_check_ts + d->timeout_check_interval >= now) {
		tcp_lookup_timedout_convs(ctx, now);
	} 
	 */

}

struct statemachine_conversation *tcp_get_next_finished_conv(struct statemachine_context *ctx) {

}

static struct tcp_conv_key *tcp_get_key(struct packet_info *pkt, struct mem_pool *pool, bool reversed) {
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

	memcpy(dst_ip_ptr, pkt->addresses[src_ep], pkt->addr_len);

	return key;
};

static bool tcp_is_timedout(struct statemachine_data *d, struct trie_data *conv, uint64_t now) {
	uint32_t timeout_sec;

	switch (conv->c.state) {
		case TCP_SYN_RECD:
		case TCP_ACK_WAIT:
		case TCP_SYN_SENT:
			timeout_sec = d->estab_timeout;
			break;

		case TCP_ESTABLISHED:
			timeout_sec = d->estab_timeout;
			break;

		case TCP_FIN_WAIT_1:
		case TCP_FIN_WAIT_2:
		case TCP_CLOSING_1:
		case TCP_CLOSING_2:
		case TCP_CLOSING:
			timeout_sec = d->fin_timeout;
			break;

		case TCP_CLOSE_WAIT:
		case TCP_CLOSE_WAIT_1:
		case TCP_LAST_ACK_1:
		case TCP_LAST_ACK:
		case TCP_LAST_ACK_2:
			timeout_sec = d->last_ack_timeout;
			break;

		default:
			return false;
	}

	uint64_t max_allowd_us = conv->c.last_pkt_ts + 1000000 * (uint64_t) timeout_sec;
	return (now > max_allowd_us);
}

static struct trie_data *tcp_lookup_conv(struct statemachine_context *ctx, const struct packet_info *pkt) {
	struct statemachine_data *d = ctx->data;
	uint64_t now = info->timestamp;

	// Lookup conversation 
	struct tcp_conv_key *key = tcp_get_key(pkt, ctx->plugin_ctx->temp_pool, false);
	struct trie_data *conv = trie_lookup(d->conv_tree, key, key->size);
	// Found in
	if (conv) {
		// Found but timed out
		if (tcp_is_timedout(d, conv, now)) {
			/* Found but timed out ..How to solve this?:
			 * 1. Leave conv untouched in linked list (will be detected on next timeout check).
			 * 2. Add new_conv to linked list
			 * 3. Reuse trie item pointer to point to new_conv.
			 */
			conv = *trie_index(d->conv_tree, key, key->size) = conv_list_append_pool(d->conv_list, d->active_pool);
			tcp_init_conv(ctx, conv, d->active_pool, now);
		}
			// Found & not timed out
		else {
			// Move conv to the end of linked list (last accessed): remove, append to tail
			conv_list_remove(&d->conv_list, conv);
			conv_list_insert_after(&d->conv_list, conv, d->conv_list.tail);
		}
	}
		// Not found in original direction, try reversed
	else if (!conv) {
		// Try to search for conversation in reversed direction
		struct tcp_conv_key *r_key = tcp_get_key(pkt, ctx->plugin_ctx->temp_pool, true);
		conv = trie_lookup(d->conv_tree, r_key, r_key->size);

		// Found reverse but timed out
		if (conv && tcp_is_timedout(d, conv, now)) {
			// Leave found conv. to be timeout detected and create new conv. in original direction
			conv = NULL
		}

		// If conv found, move to the end of linked list (last accessed): remove, append to tail
		if (conv) {
			conv_list_remove(&d->conv_list, conv);
			conv_list_insert_after(&d->conv_list, conv, d->conv_list.tail);
		}
	}

	// No coresponding active conversation found, create new - append to list & insert to tree
	if (!conv) {
		conv = *trie_index(d->conv_tree, key, key->size) = conv_list_append_pool(d->conv_list, d->active_pool);
		tcp_init_conv(ctx, conv, d->active_pool, now);
	}

	return conv;
}

static void tcp_init_conv(struct statemachine_context *ctx, struct trie_data *conv, struct mem_pool *pool, uint64_t now) {
	//conv[key].timeslots[ts][trans_cnt]

	conv->c.state = TCP_NO_STATE;
	conv->c.first_pkt_ts = now;
	conv->c.last_pkt_ts = now;

	// Alloc timeslots & set to zero
	conv->c.timeslots = mem_pool_alloc(mem_pool, ctx->timeslot_cnt * sizeof (struct statemachine_timeslot *));
	int i;
	for (i = 0; i < ctx-> timeslot_cnt; i++) {
		size_t size = TCP_TRANS_COUNT * sizeof (struct statemachine_timeslot);
		conv->c.timeslots[i] = mem_pool_alloc(mem_pool, size);
		memset(conv->c.timeslots[i], 0, size);
	}
}

// TODO: implement loop transitions (#ifdef STATETRANS_TCP_LOOP_TRANSITIONS)
// TODO: consider transition matrix[old_state][new_state]
static enum statemachine_tcp_transition tcp_track_state(struct trie_data *conv, const struct packet_info *pkt) {
	// Get direction info
	bool is_src_client = (memcmp(conv->c.id.src_ip, pkt->addresses) == 0);
	enum statemachine_tcp_transition transition = TCP_NO_TRANS;
	enum statemachine_tcp_state new_state = conv->c.state;

	enum statemachine_tcp_state old_state = conv->c.state;
	enum tcp_flags flags = pkt->tcp_flags;
	enum direction dir = pkt->direction;

	if ((flags & TCP_RESET) && (old_state != TCP_ESTABLISHED)) {
		new_state = TCP_RST_SEEN;
		transition = T8;
	} else {
		switch (old_state) {
			case TCP_NO_TRANS:
				// First packet seen should be from client to server
				if (dir == DIR_IN) {
					// Local side is the server 
					if (flags & TCP_SYN) {
						new_state = TCP_SYN_RECD;
						transition = T1;
					}
				} else {
					// Local site will be the client
					if (flags & TCP_SYN) {
						new_state = TCP_SYN_SENT;
						transition = T2;
					}
				}
				break;

			case TCP_SYN_RECD:
				if (dir == DIR_OUT) {
					if ((flags & TCP_ACK) && (flags & TCP_SYN)) {
						new_state = TCP_ACK_WAIT;
						transition = T3;
					} else if (flags & TCP_FIN) {
						new_state = TCP_FIN_WAIT_1;
						transition = T29;
					}
				}
				break;

			case TCP_ACK_WAIT:
				if (dir == DIR_IN) {
					if ((flags & TCP_ACK) && (flags & TCP_FIN)) {
						new_state = TCP_CLOSE_WAIT_1;
						transition = T7;
					} else if (flags & TCP_ACK) {
						new_state = TCP_ESTABLISHED;
						transition = T6;
					}
				} else { // DIR_OUT
					if (flags & TCP_FIN) {
						new_state = TCP_FIN_WAIT_1;
						transition = T30;
					}
				}
				break;
				
			case TCP_SYN_SENT:
				if (dir == DIR_IN) {
					if ((flags & TCP_ACK) && (flags & TCP_SYN)) {
						if (flags & TCP_FIN) {
							new_state = TCP_CLOSE_WAIT_1;
							transition = T31;
						} else {
							new_state = TCP_ESTABLISHED;
							transition = T5;
						}
					} else if (flags & TCP_SYN) {
						new_state = TCP_SYN_RECD;
						transition = T4;
					}
				}
				// ...
				break;
				
			case TCP_ESTABLISHED:
				if (dir == DIR_IN) {
					if ((flags & TCP_RESET) || (flags & TCP_SYN)) {
						new_state = TCP_CLOSED;
						transition = T20;
					} else if (flags & TCP_FIN) {
						new_state = TCP_CLOSE_WAIT_1;
						transition = T10;
					}
				} else { // DIR_OUT
					if (flags & TCP_FIN) {
						new_state = TCP_FIN_WAIT_1;
						transition = T11;
					}
				}
				break;
				
			// Active close states
				
			case TCP_FIN_WAIT_1:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						if (flags & TCP_FIN) {
							new_state = TCP_CLOSING_2;
							transition = T16;
						} else {
							new_state = TCP_FIN_WAIT_2;
							transition = T13;
						}
					} else if (flags & TCP_FIN) {
						new_state = TCP_CLOSING_1;
						transition = T12;
					} 
				}
				break;
				
			case TCP_FIN_WAIT_2:
				if (dir == DIR_IN) {
					if (flags & TCP_FIN) {
						new_state = TCP_CLOSING_2;
						transition = T14;
					} 
				}
				break;
				
			case TCP_CLOSING_1:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						new_state = TCP_CLOSING_2;
						transition = T15;
					} 
				} else { // DIR_OUT
					if (flags & TCP_ACK) {
						new_state = TCP_CLOSING;
						transition = T17;
					}
				}
				break;
				
			case TCP_FIN_WAIT_2:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						new_state = TCP_CLOSED;
						transition = T19;
					} 
				}
				break;
				
			case TCP_CLOSING:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						new_state = TCP_CLOSED;
						transition = T18;
					} 
				}
				break;
				
			// Passive close states
				
			case TCP_CLOSE_WAIT_1:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						if (flags & TCP_FIN) {
							new_state = TCP_LAST_ACK;
							transition = T25;
						} else {
							new_state = TCP_CLOSE_WAIT;
							transition = T22;
						}
					} else if (flags & TCP_FIN) {
						new_state = TCP_LAST_ACK_1;
						transition = T21;
					} 
				}
				break;
				
			case TCP_CLOSE_WAIT:
				if (dir == DIR_OUT) {
					if (flags & TCP_FIN) {
						new_state = TCP_LAST_ACK;
						transition = T23;
					} 
				}
				break;
				
			case TCP_LAST_ACK_1:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						new_state = TCP_LAST_ACK;
						transition = T24;
					} 
				} else { // DIR_IN
					if (flags & TCP_ACK) {
						new_state = TCP_LAST_ACK_2;
						transition = T26;
					}
				}
				break;
				
			case TCP_LAST_ACK:
				if (dir == DIR_IN) {
					if (flags & TCP_ACK) {
						new_state = TCP_CLOSED;
						transition = T19;
					} 
				}
				break;
				
			case TCP_LAST_ACK_2:
				if (dir == DIR_OUT) {
					if (flags & TCP_ACK) {
						new_state = TCP_CLOSED;
						transition = T27;
					} 
				}
				break;
		}
	}





	conv.c->state = new_state;
	return transition;

}

/*
 | SM.add_pkt_to_conv(conv, pkt) //return 1 if finished
|	-> internal(return)
|		| conv.last_ts = pkt.ts
|		| if pkt.ip.fragment_offset != 0	// Process only first fragment of datagram (assume header fits, check min. size!!)
|		|	return
|		|
|		| transition = track_state(pkt)		// state machine conditions implementation
|		| for each timeslot_value ts do
|		|	if !is_in_slot(conv.timeslots[ts], ts, pkt.ts) 
|		|		for each trans in statemachine.transitions
|		|			conv.timeslots[ts].aggr_val[trans] += conv.timeslots[ts].value[trans]
|		|			conv.timeslots[ts].aggr_cnt[trans]++
|		|			conv.timeslots[ts].value[trans] = 0
|		|		
|		|	if transition = NO_TRANSITION_OCCURED		// e.g. value -1
|		|		conv.timeslots[ts].value[transition]++;
 
 */
static void tcp_add_pkt_to_conv(struct trie_data *conv, const struct packet_info *pkt) {





	//transition = track_state(conv, pkt);
}

static void tcp_clean_timedout(struct statemachine_context *ctx) {

}


///

struct tcp_lookup_timedout_data {
	struct statemachine_context *ctx;
	uint64_t now;
};

static void tcp_lookup_timedout_convs(struct statemachine_context *ctx, uint64_t now) {
	struct statemachine_data *d = ctx->data;

	// Reset list of finished conversations and its mem pool
	d->finished_convs.count = 0;
	d->finished_convs.head = NULL;
	mem_pool_reset(d->finished_convs_pool);

	struct tcp_lookup_timedout_data userdata = {
		.ctx = ctx,
		.now = now
	};
	// Mark
	trie_walk(d->active_convs, tcp_lookup_timedout_callback, &userdata, ctx->plugin_ctx->temp_pool);

}

static void tcp_lookup_timedout_callback(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	struct statemachine_context *ctx;


}

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