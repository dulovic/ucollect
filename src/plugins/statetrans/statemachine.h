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

#ifndef UCOLLECT_STATETRANS_STATEMACHINE_H
#define UCOLLECT_STATETRANS_STATEMACHINE_H

#include "../../core/context.h"

typedef uint16_t statemachine_state_t;
typedef uint16_t statemachine_transition_t;

typedef uint32_t timeslot_interval_t;
typedef uint32_t timeslot_value_t;
typedef double timeslot_aggr_value_t;
typedef uint32_t timeslot_aggr_cnt_t;


struct statemachine_context {
	struct context *plugin_ctx; // Plugin context

	timeslot_interval_t *timeslots;
	size_t timeslot_cnt;
};

struct statemachine_conversation {
        //TODO: add fivetuple
    
	statemachine_state_t state;
	uint64_t timestamp;
	statemachine_timeslot timeslots[]; // Flexible array member, number of elements should be equal to statemachine.transition_count
};



// learning_profiles[host_key][evaluator][convers_index].timeslots[ts] 
//      host_key - tree key
//      evaluator - array index
//      convers_index - index in linked list
//      ts - timeslot index


////////////////

// Statemachine specific
struct learn_profile;
struct detect_profile;



struct statemachine {
	const char *name;
	size_t transition_count; // Number of states used by statemachine
	
	void(*init_callback) (struct statemachine_context *ctx);
	void(*finish_callback) (struct statemachine_context *ctx);
	void(*packet_callback) (struct statemachine_context *ctx, const struct packet_info *info);	
	struct statemachine_conversation *(*get_next_finished_conv_callback) (struct statemachine_context *ctx);
	void(*clean_timedout_convs_callback) (struct statemachine_context *ctx);
};


struct statemachine_timeslot {
	timeslot_value_t value;
	timeslot_aggr_value_t aggr_value;
	timeslot_aggr_cnt_t aggr_cnt;
};

/*
	conversations[key<five_touple>]  // four_touple is enough
						.state
						.last_packet_ts
						.timeslots[ts]
							.values[statemachine.state_cnt] 			// Define type for count
							.aggr_values[statemachine.state_cnt]
							.aggr_value_cnt[statemachine.state_cnt]
							.last_ts
		
*/

#endif
