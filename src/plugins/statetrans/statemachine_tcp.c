/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2015 Tomas Morvay

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

#include "statemachine.h"

#include "../../core/context.h"

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

static void tcp_init(struct statemachine_context *ctx) {

}

static void tcp_destroy(struct statemachine_context *ctx) {

}

static void tcp_packet(struct statemachine_context *ctx, const struct packet_info *info); {

}

struct conversation *tcp_get_next_finished_conv(struct statemachine_context *ctx) {

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

static 