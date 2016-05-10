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

#include "engine.h"

#include "../../core/mem_pool.h"
#include "../../core/context.h"
#include "../../core/trie.h"
#include "../../core/packet.h"

#include <assert.h>

struct engine {
    enum detection_mode mode;

    timeslot_interval_t *timeslots;
    size_t timeslot_cnt;

    size_t statemachine_cnt;
    struct statemachine **statemachines;
    struct statemachine_data **statemachines_data;

    size_t evaluator_cnt;
    struct evaluator **evaluators;
    struct evaluators_data **evaluators_data;

    struct mem_pool *learn_profiles_pool;
    struct trie *learn_profiles;
    size_t learn_host_profile_size;      // Size for one host 
    size_t *learn_eval_profile_offsets;  // For each host large block of data is allocated. Evaluator specific data begins at given offset for each evaluator

    struct mem_pool *detect_profiles_pool;
    struct trie *detect_profiles;
    size_t detect_host_profile_size;     // Size for one host 
    size_t *detect_eval_profile_offsets; // For each host large block of data is allocated. Evaluator specific data begins at given offset for each evaluator

    struct context *plugin_ctx;     // For internal purposes, should not be changed outside engine
};

struct trie_data {
    int dummy; // Just to prevent warning about empty struct
};

// Prototypes
void engine_alloc_profiles(struct engine *engine);
void engine_alloc_profiles(struct engine *en);
void engine_init_statemachines(struct engine *e);
void engine_init_evaluators(struct engine *e);
uint8_t *engine_lookup_get_host_key(const struct packet_info *packet, size_t *key_size);
uint8_t *engine_get_host_profile(struct engine *en, enum  uint8_t *host_key, size_t host_key_size, enum detection_mode mode);
double engine_process_finished_conv(struct engine *en, struct evaluator_context ev_ctx, const uint8_t *host_profile, const struct statemachine_conversation *conv);
void engine_change_mode(struct engine *en, struct context *ctx, enum detection_mode mode);
void engined_change_mode_walk_trie_cb(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata);


struct engine *engine_create(struct context *ctx, timeslot_interval_t *timeslots, size_t timeslot_cnt) {
    struct engine *en;
    en = mem_pool_alloc(ctx->permanent_pool, sizeof (struct engine*));
    en->mode = LEARNING;
    en->plugin_ctx = ctx;   // This will be updated on each call

    // Copy timeslot intervals
    en->timeslot_cnt = timeslot_cnt;
    size_t timeslots_size = timeslot_cnt * sizeof (timeslot_interval_t);
    en->timeslots = mem_pool_alloc(ctx->permanent_pool, timeslots_size);
    memcpy(en->timeslots, timeslots, timeslots_size);

    // Get info about statemachines
    en->statemachine_cnt = 1;
    en->statemachines = mem_pool_alloc(ctx->permanent_pool, en->statemachine_cnt * sizeof (struct statemachine*));
    en->statemachines[0] = statemachine_info_tcp();`

    // Get info about evaluators
    en->evaluator_cnt = 1;
    en->evaluators = mem_pool_alloc(ctx->permanent_pool, en->evaluator_cnt * sizeof (struct evaluator*));
    en->evaluators[0] = evaluator_info_chebyshev();

    // Create tres for learning & detection profiles per host
    engine_alloc_profiles(en);

    engine_init_statemachines(en);
    engine_init_evaluators(en);

    return en;
}

void engine_handle_packet(struct engine *en, struct context *ctx, const struct packet_info *packet) {
    assert(en->mode == LEARNING || en->mode == DETECTION);
    en->plugin_ctx = ctx;   // This will be updated on each call
    
    // Prepare statemachine context
    struct statemachine_context sm_ctx = {
        .plugin_ctx = ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt
    };

    // Prepare evaluator context
    struct evaluator_context ev_ctx = {
        .plugin_ctx = ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt,
        //.transition_count = 0		// Will be set per statemachine
        //.statmachine_index = 0        // Per statemachin
    };

    //Get host key
    size_t host_key_size;
    uint8_t *host_key;
    
    host_key = engine_lookup_get_host_key(packet, &host_key_size);

    // Load (learning or detection) host profile 
    uint8_t *host_profile = engine_get_host_profile(en, host_key, host_key_size, en->mode);
    

    // Pass packet to each statemachine & process new finished conversations reported by statemachine
    size_t i_sm; // Statemachine index
    for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm++) {
        struct statemachine *sm = en->statemachines[i_sm];
        
        sm_ctx.data = en->statemachines_data[i_sm]; // Restore pointer to statemachine data
        sm->packet_callback(&sm_ctx, packet);

        // Modify evaluator context according to current statemachine
        ev_ctx.statmachine_index = i_sm;
        ev_ctx.transition_count = sm->transition_count;

        // Process finished (closed, timedout, ..) conversations from statemachine
        struct statemachine_conversation *conv;
        while (conv = sm->get_next_finished_conv_callback(&sm_ctx)) {
            engine_process_finished_conv(en, ev_ctx, host_profile, conv);
        }
        en->statemachines_data[i_sm] = sm_ctx.data; // Save pointer to statemachine data
    }

}

void engine_change_mode(struct engine *en, struct context *ctx, enum detection_mode mode) {
    char *old_s = (en->mode == LEARNING) ? "LEARNING" : "DETECTION";
    char *new_s = (mode == LEARNING) ? "LEARNING" : "DETECTION";

    ulog(LLOG_WARN, "Statetrans engine: Changing mode (%s -> %s)", old_s, new_s);
    
    if (en->mode != LEARNING || mode != DETECTION) {
        ulog(LLOG_WARN, "Statetrans engine: Unsupported mode change (%d -> %d)", en->mode, mode);
        return;
    }

    // Clear detection profiles trie
    mem_pool_reset(en->detect_profiles_pool);
    en->detect_profiles = trie_alloc(en->detect_profiles_pool);

    trie_walk(en->learn_profiles, engined_change_mode_walk_trie_cb, en, ctx->temp_pool);
    en->mode = mode;
}

void engine_destroy(struct engine *en, struct context *ctx) {


}


static void engine_alloc_profiles(struct engine *en) {
    en->learn_profiles_pool = mem_pool_create("Statetrans learning profiles");
    en->learn_profiles = trie_alloc(en->learn_profiles_pool);

    en->detect_profiles_pool = mem_pool_create("Statetrans detection profiles");
    en->detect_profiles = trie_alloc(en->detect_profiles_pool);
}

static void engine_init_statemachines(struct engine *en) {
    // Alloc storage for pointers to statemachine data
    en->statemachines_data = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->statemachine_cnt * sizeof(struct statemachine_data *));
    
    struct statemachine_context sm_ctx = {
        .plugin_ctx = en->plugin_ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt
    };

    size_t i_sm;
    for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm++) {
        ulog(LLOG_DEBUG, "Statetrans engine: Initializing statemachine '%s'\n", en->statemachines[i_sm]->name);
        
        // Initialize statemachine data
        en->statemachines_data[i_sm] = NULL;
        sm_ctx.data = en->statemachines_data[i_sm];
        
        // Initialize statemachine
        en->statemachines[i_sm]->init_callback(sm_ctx);
        
        // Save statemachine data
        en->statemachines_data[i_sm] = sm_ctx.data;
        
    }
}

static void engine_init_evaluators(struct engine *en) {
    // Alloc storage for pointers to statemachine data
    en->evaluators_data = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->evaluator_cnt * sizeof(struct evaluators_data *));
    
    struct evaluator_context ev_ctx = {
        .plugin_ctx = en->plugin_ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt,
        .transition_count = 0,
        .statmachine_index = en->statemachine_cnt // Pass total number of statemachines
    };

    // Offsets for each evaluator within host profile
    en->learn_eval_profile_offsets = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->evaluator_cnt * sizeof (size_t));
    en->detect_eval_profile_offsets = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->evaluator_cnt * sizeof (size_t));

    // Profile size per host
    en->learn_host_profile_size = 0;
    en->detect_host_profile_size = 0;

    size_t i_ev;
    for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
        ulog(LLOG_DEBUG, "Statetrans engine: Initializing evaluator '%s'\n", en->evaluators[i_ev]->name);
        
        // Initialize evaluator data pointe & call evaluator initializer
        en->evaluators_data[i_ev] = NULL;
        ev_ctx.data = en->evaluators_data[i_ev];
        en->evaluators[i_ev]->init_callback(ev_ctx);
        en->evaluators_data[i_ev] = ev_ctx.data;

        // Remember evaluator offset in common profile data block for one host
        en->learn_eval_profile_offsets[i_ev] = en->learn_host_profile_size;
        en->detect_eval_profile_offsets[i_ev] = en->detect_host_profile_size;

        // Memory occupied by one host from viewpoint of engine
        en->learn_host_profile_size += en->evaluators[i_ev]->learn_profile_size;
        en->detect_host_profile_size += en->evaluators[i_ev]->detect_profile_size;
    }
    ulog(LLOG_DEBUG, "Statetrans engine: Learning profile size per host '%d'\n", en->learn_host_profile_size);
    ulog(LLOG_DEBUG, "Statetrans engine: Detection profile size per host '%d'\n", en->detect_host_profile_size);
}

static uint8_t *engine_lookup_get_host_key(const struct packet_info *packet, size_t *key_size) {

    // Host key = local MAC address
    if (packet->layer != 'E')
        return; // Can't obtain host key
    enum endpoint local_ep = local_endpoint(packet->direction);
    *key = packet->addresses[local_ep];
    *key_size = packet->addr_len;
}

static uint8_t *engine_get_host_profile(struct engine *en, enum  uint8_t *host_key, size_t host_key_size, enum detection_mode mode) {
    struct trie *profiles_trie;
    struct trie_data **data;
    
    // Find or add to correct trie according to mode
    profiles_trie = (mode == LEARNING) ? en->learn_profiles : en->detect_profiles;
    data = trie_index(profiles_trie, host_key, host_key_size);
        
    // Host seen first time - alloc profile & initialize to zeros
    if (*data == NULL) {
        if (mode == LEARNING) {
            *data = mem_pool_alloc(en->learn_profiles_pool, en->);
            memset(*data, 0, en->learn_host_profile_size);
        } else { // DETECTION
            *data = mem_pool_alloc(en->detect_profiles_pool, en->);
            memset(*data, 0, en->detect_host_profile_size);
        }
    }
    
    return (uint8_t *)*data;
}

// Pass conversation to all evaluators and return max anomaly score (in learning mode always 0.0)
static double engine_process_finished_conv(struct engine *en, struct evaluator_context ev_ctx, const uint8_t *host_profile, const struct statemachine_conversation *conv) {
    int i_ev;
    double max_score = 0.0L;

    // Choose evaluator callback according to mode
    if (en->mode == LEARNING) {
        // Pass next finished conversation to all evaluators
        for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
            struct evaluator *ev = en->evaluators[i_ev];
            
            // Evaluator-specific data in learning profile
            struct learn_profile *learning;
            learning = (struct learn_profile *) (host_profile + en->learn_eval_profile_offsets[i_ev]);

            // Restore evaluator data pointer, do the learning and save the pointer
            ev_ctx.data = en->evaluators_data[i_ev]; 
            ev->learn_callback(ev_ctx, learning, conv);
            en->evaluators_data[i_ev] = ev_ctx.data;
        }
        // max_score unchanged - not detecting
        
    } else { // if (en->mode == DETECTION) 
        
        // Pass next finished conversation to all evaluators
        for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
            struct evaluator *ev = en->evaluators[i_ev];
            
            // Evaluator-specific data in detection profile
            struct detect_profile *detection;
            detection = (struct detect_profile *) (host_profile + en->detect_eval_profile_offsets[i_ev]);

            
            // Restore evaluator data pointer, do the detection and save the pointer
            ev_ctx.data = en->evaluators_data[i_ev]; 
            double score = ev->detect_callback(ev_ctx, detection, conv);
            en->evaluators_data[i_ev] = ev_ctx.data;
            
            if (score > max_score)
                max_score = score;  // TODO: remember evaluator index?
        }
        ulog(LLOG_INFO, "Statetrans engine: Anomaly score = %.2lf", max_score);
    }

    return max_score;
}

static void engined_change_mode_walk_trie_cb(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
    struct engine *en = (struct engine*) userdata;
    
    // Prepare evaluator context
    struct evaluator_context ev_ctx = {
        .plugin_ctx = en->plugin_ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt,
        //.transition_count = 0		// Will be set per statemachine
        //.statmachine_index = 0        // Per statemachine
    };
    
    uint8_t *host_learning = engine_get_host_profile(en, key, key_size, LEARNING);
    uint8_t *host_detection = engine_get_host_profile(en, key, key_size, DETECTION);
    
    // Call detection profile creation for each evaluator
    size_t i_sm;
    for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm++) {
        struct statemachine *sm = en->statemachines[i_sm];
        
        // Modify evaluator context according to current statemachine
        ev_ctx.statmachine_index = i_sm;
        ev_ctx.transition_count = sm->transition_count;
        
        size_t i_ev;
        for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
            struct evaluator *ev = en->evaluators[i_ev];

            // Evaluator-specific data for learning profile
            struct learn_profile *learning;
            learning = (struct learn_profile *) (host_learning + en->learn_eval_profile_offsets[i_ev]);

            // Evaluator-specific data for detection profile
            struct detect_profile *detection;
            detection = (struct detect_profile *) (host_detection + en->learn_eval_profile_offsets[i_ev]);

            
            // Restore evaluator data pointer, do the profile creation and save the pointer
            ev_ctx.data = en->evaluators_data[i_ev]; 
            ev->create_profile(ev_ctx, learning, detection);
            en->evaluators_data[i_ev] = ev_ctx.data;
        }
    }
}


