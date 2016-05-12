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

#ifndef UCOLLECT_STATETRANS_EVALUATOR_H
#define UCOLLECT_STATETRANS_EVALUATOR_H

#include "statemachine.h"
//#include "../../core/context.h"

#include <stddef.h>
#include <stdint.h>

struct context;
struct statemachine_conversation;
struct evaluator_data;

struct evaluator_context {
	struct context *plugin_ctx; // Plugin context

	size_t timeslot_cnt;
	timeslot_interval_t *timeslots;
        
        // Set when meaning full, should be 0 otherwise (init etc..)
	size_t transition_cnt;	
        size_t statemachine_index;
        
        struct evaluator_data *data;
};

struct learn_profile;
struct detect_profile;

struct anomaly_location {
    size_t timeslot;
    size_t transition;
};

struct evaluator {
    const char *name;
    size_t learn_profile_size;
    size_t detect_profile_size;

    
    //TODO: update param list
    void (*init_callback) (struct evaluator_context *ctx);
    void (*finish_callback) (struct evaluator_context *ctx);
    void (*learn_callback) (struct evaluator_context *ctx, struct learn_profile *learning, const struct statemachine_conversation *conv);
    double (*detect_callback) (struct evaluator_context *ctx, struct detect_profile *detection, const struct statemachine_conversation *conv, struct anomaly_location *anom_loc);
    void (*create_profile) (struct evaluator_context *ctx, struct learn_profile *learning, struct detect_profile *detection);
};

#endif
