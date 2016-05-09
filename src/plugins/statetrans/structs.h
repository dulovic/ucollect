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

#ifndef UCOLLECT_STATETRANS_STRUCTS_H
#define UCOLLECT_STATETRANS_STRUCTS_H

#include "../../core/context.h"

struct statemachine_context {
	struct context *plugin_ctx; // Plugin context

	size_t timeslot_cnt;
	uint32_t *timeslots;

	mem_pool *permanent_pool; // ?
	// timeslot intervals
	// timeslot cnt
	
	
	
};



// learning_profiles[host_key][evaluator][convers_index].timeslots[ts]  
//      host_key - tree key
//      evaluator - array index
//      convers_index - index in linked list
//      ts - timeslot index
struct learning_profile {
    
};


struct detection_profile {

};

////////////////
struct statemachine_context;
struct learning_profile;
struct detection_profile;

struct statemachine {
	const char *name;
	size_t state_count; // Number of states used by statemachine
	
	void(*init_callback) (struct statemachine_context *ctx);
	void(*finish_callback) (struct statemachine_context *ctx);
	void(*packet_callback) (struct statemachine_context *ctx, const struct packet_info *info);	
	struct conversation *(*get_next_finished_conv_callback) (struct statemachine_context *ctx);
	void(*clean_timedout_convs_callback) (struct statemachine_context *ctx);
};

#endif
