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

struct engine {
    enum detection_mode mode;

    timeslot_interval_t *timeslots;
    size_t timeslot_cnt;

    struct statemachine **statemachines;
    size_t statemachine_cnt;

    struct evaluator **evaluators;
    size_t evaluator_cnt;

    struct mem_pool *learn_profiles_pool;
    struct trie *learn_profiles;
    size_t learn_profile_size;      // Size for one host 
    size_t *learn_profile_offsets;  // For each host large block of data is allocated. Evaluator specific data begins at given offset for each evaluator

    struct mem_pool *detect_profiles_pool;
    struct trie *detect_profiles;
    size_t detect_profile_size;     // Size for one host 
    size_t *detect_profile_offsets; // For each host large block of data is allocated. Evaluator specific data begins at given offset for each evaluator

    /*

    learning_prof_offsets
    detection_prof_offsets

    learn_profiles[host_id][statemachine]
    detect_profiles[host_id][statemachine]


    - learn_profiles= trie()
    - detect_profiles = trie()
    - learn_profile_size
    - detect_profile_size
     */
};

struct trie_data {
    int dummy; // Just to prevent warning about empty struct
};

void engine_alloc_profiles(struct engine *engine);
void engine_init_statemachines(struct engine *e);
void engine_init_evaluators(struct engine *e);

struct engine *engine_create(struct context *ctx, timeslot_interval_t *timeslots, size_t timeslot_cnt) {
    struct engine *en;
    en = mem_pool_alloc(ctx->permanent_pool, sizeof (struct engine*));
    en->mode = LEARNING;

    // Copy timeslot intervals
    en->timeslot_cnt = timeslot_cnt;
    size_t timeslots_size = timeslot_cnt * sizeof (timeslot_interval_t);
    en->timeslots = mem_pool_alloc(ctx->permanent_pool, timeslots_size);
    memcpy(en->timeslots, timeslots, timeslots_size);


    // Get info about statemachines
    en->statemachine_cnt = 1;
    en->statemachines = mem_pool_alloc(ctx->permanent_pool, en->statemachine_cnt * sizeof (struct statemachine*));
    en->statemachines[0] = statemachine_info_tcp();

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

static void engine_alloc_profiles(struct context *ctx, struct engine *en) {
    en->learn_profiles_pool = mem_pool_create("Statetrans learning profiles");
    en->learn_profiles = trie_alloc(en->learn_profiles_pool);

    en->detect_profiles_pool = mem_pool_create("Statetrans detection profiles");
    en->detect_profiles = trie_alloc(en->detect_profiles_pool);
}

static void engine_init_statemachines(struct context *ctx, struct engine *en) {
    int i;
    struct statemachine_context sm_ctx = {
        .plugin_ctx = ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt
    };

    for (i = 0; i < en->statemachine_cnt; i++) {
        ulog(LLOG_DEBUG, "Statetrans engine: Initializing statemachine '%s'\n", en->statemachines[i]->name);
        en->statemachines[i]->init_callback(sm_ctx);
    }
}

static void engine_init_evaluators(struct context *ctx, struct engine *en) {
    int i;
    struct evaluator_context ev_ctx = {
        .plugin_ctx = ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt,
        .transition_count = 0
    };

    en->learn_profile_offsets = mem_pool_alloc(ctx->permanent_pool, en->timeslot_cnt * sizeof (size_t));
    en->detect_profile_offsets = mem_pool_alloc(ctx->permanent_pool, en->timeslot_cnt * sizeof (size_t));

    en->learn_profile_size = 0;
    en->detect_profile_size = 0;

    for (i = 0; i < en->evaluator_cnt; i++) {
        ulog(LLOG_DEBUG, "Statetrans engine: Initializing evaluator '%s'\n", en->evaluators[i]->name);
        en->evaluators[i]->init_callback(ev_ctx);

        // Remember evaluator offset in common profile data block for one host
        en->learn_profile_offsets[i] = en->learn_profile_size;
        en->detect_profile_offsets[i] = en->detect_profile_size;

        // Memory occupied by one host from viewpoint of engine
        en->learn_profile_size += en->evaluators[i]->learn_profile_size;
        en->detect_profile_size += en->evaluators[i]->detect_profile_size;
    }
    ulog(LLOG_DEBUG, "Statetrans engine: Learning profile size per host '%d'\n", en->learn_profile_size);
    ulog(LLOG_DEBUG, "Statetrans engine: Detection profile size per host '%d'\n", en->detect_profile_size);
}

///////////////////


// Gets host get (local MAC) and sets the key_size output parameter

static uint8_t *engine_lookup_get_host_key(const struct packet_info *packet, size_t *key_size) {

    // Host key = local MAC address
    if (packet->layer != 'E')
        return; // Can't obtain host key
    enum endpoint local_ep = local_endpoint(packet->direction);
    *key = packet->addresses[local_ep];
    *key_size = packet->addr_len;
}

void asdf(struct engine *asdf) {

}

//void engine_lookup_host_learn_profiles(struct engine *en, struct context *ctx, const struct packet_info *packet) {

static uint8_t *engine_lookup_host_learn_profiles(struct engine *en, const uint8_t *key, size_t key_size) {

    struct trie_data **data = trie_index(en->learn_profiles, key, key_size);

    // New host - alloc & initialize to zeros
    if (*data == NULL) {
        *data = mem_pool_alloc(en->learn_profiles_pool, en->);
        memset(*data, 0, en->learn_profile_size);
    }

    return (uint8_t *)*data;
}

static uint8_t *engine_lookup_host_detect_profiles(struct engine *en, uint8_t *key, size_t key_size) {

    struct trie_data **data = trie_index(en->detect_profiles, key, key_size);

    // New host - alloc & initialize to zeros
    if (*data == NULL) {
        *data = mem_pool_alloc(en->detect_profiles_pool, en->detect_profile_size);
        memset(*data, 0, en->detect_profile_size);
    }

    return (uint8_t *)*data;
}
static uint8_t *engine_get_host_profile(struct engine *en, uint8_t *host_key, size_t host_key_size) {
    struct trie *profiles_trie;
    struct trie_data **data;
    
    // Find or add to correct trie according to mode
    profiles_trie = (en->mode == LEARNING) ? en->learn_profiles : en->detect_profiles;
    data = trie_index(profiles_trie, host_key, host_key_size);
        
    // Host seen first time - alloc profile & initialize to zeros
    if (*data == NULL) {
        if (en->mode == LEARNING) {
            *data = mem_pool_alloc(en->learn_profiles_pool, en->);
            memset(*data, 0, en->learn_profile_size);
        } else { // DETECTION
            *data = mem_pool_alloc(en->detect_profiles_pool, en->);
            memset(*data, 0, en->detect_profile_size);
        }
    }
    
    return (uint8_t *)*data;
}

static void engine_process_finished_conv(struct engine *en, const struct conversation *conv, const uint8_t *host_profile) {
    
}

void engine_handle_packet(struct engine *en, struct context *ctx, const struct packet_info *packet) {
    // Prepare evaluator context
    struct evaluator_context ev_ctx = {
        .plugin_ctx = ctx,
        .timeslots = en->timeslots,
        .timeslot_cnt = en->timeslot_cnt,
        //.transition_count = 0		// Will be set per statemachine
    };

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
    };

    //Get host key
    size_t host_key_size;
    uint8_t *host_key;
    
    host_key = engine_lookup_get_host_key(packet, &host_key_size);

    // Load host profile 
    
    uint8_t *host_profile = NULL;
    

    // Pass packet to each statemachine & process new finished conversations reported by statemachine
    int i_sm; // Statemachine index
    for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm++) {
        struct statemachine *sm = en->statemachines[i_sm];
        sm->packet_callback(&sm_ctx, packet);

        // Modify evaluator context according to current statemachine
        ev_ctx.transition_count = sm->transition_count;

        // Process finished (closed, timedout, ..) conversations from statemachine
        struct conversation *conv;
        while (conv = sm->get_next_finished_conv_callback(&sm_ctx)) {
            
            // Pass next finished conversation to all evaluators
            int i_ev;
            for (i_ev = 0; i_ev < en->statemachine_cnt; i_ev++) {
                struct evaluator *ev = en->evaluators[i_ev];
                
                // Choose evalutor callback according to mode
                if (en->mode == LEARNING) {
                    // Evaluator-specific data in learning profile
                    struct learn_profile *learning; 
                    learning = (struct learn_profile *) (host_profile + en->learn_profile_offsets[i_ev]);
                    
                    ev->learn_callback(ev_ctx, learning, conv);
                    
                } else if (en->mode == DETECTION) {
                    // Evaluator-specific data in detection profile
                    struct detect_profile *detection; 
                    detection = (struct detect_profile *) (host_profile + en->detect_profile_offsets[i_ev]);
                
                    ev->detect_callback(ev_ctx, detection, conv);
                } else {
                    ulog(LLOG_ERROR, "Statetrans engine: Invalid mode(%d)\n", en->mode)
                }
                
            }
        }
    }

}



void engine_change_mode(struct engine *en, struct context *ctx, detection_mode mode) {
    if (en->mode != LEARNING || mode != DETECTION) {
        ulog(LLOG_WARN, "Statetrans engine: Unsupported mode change (%d -> %d)", en->mode, mode);
        return;
    }

    en->mode = mode;

    // TODO: create detection_profiles:
    /*
            free old profiles mem_pool
            create new profiles mem_pool
            for each learning_profile
                    host = learning_profile.host
                    for each evaluator
                            detection_profiles[host][evaluator] = evaluator.create_profile(learning_profile.conv_list)

     */
}

void engine_destroy(struct engine *en, struct context *ctx) {


}