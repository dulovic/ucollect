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

#include "statemachine_tcp_conv_list.h"

/*
STATEMACHINE
	initializator:
	 - statemachine_info_[statemachine_name]() 

	consts:
	- transitions[]
	- transition_cnt
	- consolidate_lower_tresh = 200
	- consolidate_treshold_portion = 0.2
	
	internal data:
	//TODO: use one mem pool & copy in evaluator
	- conv_active_mempool		- to store data for active conv. for this SM  
	- conv_trie_active_mempool	- to store trie "overhead" structs
	- active_conversations = trie()				// permanent pool, changed when consolidating
	- timedout_conversations = linked_list()	// in tmp_pool
	- last_timedout_check_ts = 0
	- delayed_deleted_count = 0
	
	functions:
	- add_pkt_to_conv(conv, pkt)
	- detect_timedout_convs(now)
	
	callback functions:
	- init()
	- finish()
	- handle_packet(learning_profiles[host][SM], pk)
	- get_next_finished_conv()
	- cleanup_timedout_convs()
*/

////

struct statemachine_data {
    struct mem_pool *active_convs_pool;
    struct trie *active_convs;
    size_t delayed_deleted_count;
    
    struct mem_pool *finished_convs_pool;
    struct tcp_conv_list finished_convs;
    
    // How often should be tree of active conversations checked for the timed out ones
    uint64_t timeout_check_interval; 
    // Timestamp of last n microseconds
    uint64_t last_timedout_check_ts; 
    
    size_t consolidate_lower_treshold;
    double consolidate_treshold_portion;
};

// Trie data for active conversations
struct trie_data {
    struct statemachine_conversation *conv;
};


static void tcp_lookup_timedout_convs(struct statemachine_context *ctx, uint64_t now);
static void tcp_lookup_timedout_callback(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata);

static void tcp_init(struct statemachine_context *ctx) {
    ctx->data = mem_pool_alloc(ctx->plugin_ctx->permanent_pool, sizeof(struct statemachine_data));
    struct statemachine_data *d = ctx->data;
    
    d->active_convs_pool = mem_pool_create("Statetrans TCP active conversations");
    d->active_convs = trie_alloc(d->active_convs_pool);
    
    d->finished_convs_pool = mem_pool_create("Statetrans TCP finished conversations");
    
    d->last_timedout_check_ts = 0;
    d->timeout_check_interval = 
    
    // Hardcoded
    d->consolidate_lower_treshold = 200;
    d->consolidate_treshold_portion = 0.2;
    
}

static void tcp_destroy(struct statemachine_context *ctx) {
    struct statemachine_data *d = ctx->data;
    
    mem_pool_destroy(d->active_convs_pool);
    mem_pool_destroy(d->finished_convs_pool);
}

static void tcp_packet(struct statemachine_context *ctx, const struct packet_info *info) {
    struct statemachine_data *d = ctx->data;
    
    uint64_t now = info->timestamp;
    d->finished_convs = trie_alloc(d->finished_convs_pool);
    
    // Look for TCP timeouts if interval passed since last check
    if (d->last_timedout_check_ts + d->timeout_check_interval >= now) {
        tcp_lookup_timedout_convs(ctx, now);
    }
    
}

struct statemachine_conversation *tcp_get_next_finished_conv(struct statemachine_context *ctx) {

}

static void tcp_clean_timedout(struct statemachine_context *ctx) {
    
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