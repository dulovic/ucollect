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

#ifndef UCOLLECT_STATETRANS_STATEMACHINE_H
#define UCOLLECT_STATETRANS_STATEMACHINE_H

#include "../../core/context.h"

#include "conversation.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint16_t statemachine_state_t;
typedef uint16_t statemachine_transition_t;

typedef uint32_t timeslot_interval_t;
typedef uint32_t timeslot_value_t;
typedef double timeslot_aggr_value_t;
typedef uint32_t timeslot_aggr_cnt_t;

struct statemachine_data;

struct statemachine_context {
	struct context *plugin_ctx; // Plugin context
	timeslot_interval_t *timeslots;
	size_t timeslot_cnt;
        struct statemachine_data *data; // Can be changed by statemachine
};

struct statemachine_timeslot {
	timeslot_value_t value;
	timeslot_aggr_value_t aggr_value;
	timeslot_aggr_cnt_t aggr_cnt;
};

// Generalized conversation - each statemachine can have different nu
struct statemachine_conversation {
    struct conversation_id id;
    statemachine_state_t state;
    uint64_t first_pkt_ts;
    uint64_t last_pkt_ts;
    bool terminated;    // Finished correctly or timed out
    
    // Number of elements is equal to number of timeslots
    //  usage: timeslots[ts][statemachine.trans_cnt]
    struct statemachine_timeslot **timeslots; 
    // timeslot_starts[ts]
    uint64_t *timeslot_starts;
};

// Statemachine specific
struct learn_profile;
struct detect_profile;

struct statemachine {
	const char *name;
	size_t transition_count; // Number of states used by statemachine
	
	void(*init_callback) (struct statemachine_context *ctx);
	void(*finish_callback) (struct statemachine_context *ctx);
	void(*packet_callback) (struct statemachine_context *ctx, const struct packet_info *pkt);	
	struct statemachine_conversation *(*get_next_finished_conv_callback) (struct statemachine_context *ctx, uint64_t now);
	void(*clean_timedout_convs_callback) (struct statemachine_context *ctx, uint64_t now);
	
	// TODO: transition & state to string convertors
};

#endif
