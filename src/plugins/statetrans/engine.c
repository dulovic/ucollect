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
	size_t timeslot_cnt

	struct statemachine **statemachines;
	size_t statemachine_cnt;

	struct evaluator **evaluators;
	size_t evaluator_cnt;

	struct mem_pool *learning_profiles_pool;
	struct trie *learning_profiles;
	sizet_t learning_profile_size_per_host;

	struct mem_pool *detection_profiles_pool;
	struct trie *detection_profiles;
	size_t detection_profile_size_per_host;

	/*

	learning_prof_offsets
	detection_prof_offsets

	learning_profiles[host_id][statemachine]
	detection_profiles[host_id][statemachine]


	- learning_profiles= trie()
	- detection_profiles = trie()
	- learning_profile_size_per_host
	- detection_profile_size_per_host
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
	en = mem_pool_alloc(ctx->permanent_pool, sizeof(struct engine*));
	en->mode = LEARNING;

	// Copy timeslot intervals
	en->timeslot_cnt = timeslot_cnt;
	size_t timeslots_size = timeslot_cnt * sizeof(timeslot_interval_t);
	en->timeslots = mem_pool_alloc(ctx->permanent_pool, timeslots_size);
	memcpy(en->timeslots, timeslots, timeslots_size);


	// Get info about statemachines
	en->statemachine_cnt = 1;
	en->statemachines = mem_pool_alloc(ctx->permanent_pool, en->statemachine_cnt * sizeof(struct statemachine*));
	en->statemachines[0] = statemachine_info_tcp();

	// Get info about evaluators
	en->evaluator_cnt = 1;
	en->evaluators = mem_pool_alloc(ctx->permanent_pool, en->evaluator_cnt * sizeof(struct evaluator*));
	en->evaluators[0] = evaluator_info_chebyshev();

	// Create tres for learning & detection profiles per host
	engine_alloc_profiles(en);

	engine_init_statemachines(en);
	engine_init_evaluators(en);

	return en;
}

static void engine_alloc_profiles(struct context *ctx, struct engine *en) {
	en->learning_profiles_pool = mem_pool_create("Statetrans learning profiles");
	en->learning_profiles = trie_alloc(en->learning_profiles_pool);

	en->detection_profiles_pool = mem_pool_create("Statetrans detection profiles");
	en->detection_profiles = trie_alloc(en->detection_profiles_pool);
}

static void engine_init_statemachines(struct context *ctx, struct engine *en) {
	int i;
	struct statemachine_context sm_ctx = {
		.plugin_ctx = ctx,
		.timeslots = en->timeslots,
		.timeslot_cnt = en->timeslot_cnt
	};

	for (i = 0; i < en->statemachine_cnt, i++) {
		ulog(LLOG, "Statetrans engine: Initializing statemachine '%s'\n", en->statemachines[i]->name);
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

	en->learning_profile_size_per_host = 0;
	en->detection_profile_size_per_host = 0;

	for (i = 0; i < en->evaluator_cnt, i++) {
		ulog(LLOG, "Statetrans engine: Initializing evaluator '%s'\n", en->evaluators[i]->name);
		en->evaluators[i]->init_callback(ev_ctx);

		// Memory occupied by one host from viewpoint of engine
		en->learning_profile_size_per_host += en->evaluators[i]->learning_profile_size;
		en->detection_profile_size_per_host += en->evaluators[i]->detection_profile_size;
	}
	ulog(LLOG, "Statetrans engine: Learning profile size per host '%d'\n", en->learning_profile_size_per_host);
	ulog(LLOG, "Statetrans engine: Detection profile size per host '%d'\n", en->detection_profile_size_per_host);
}

///////////////////


// Gets host get (local MAC) and sets the key_size ouptut parameter
static uint8_t *engine_lookup_get_host_key(const struct packet_info *packet, size_t *key_size) {

	// Host key = local MAC address
	if (packet->layer != 'E')
		return;	// Can't obtain host key
	enum endpoint local_ep = local_endpoint(packet->direction);
	*key = packet->addresses[local_ep];
	*key_size = packet->addr_len;
}

static uint8_t *engine_lookup_host_learning_profiles(struct engine *en, struct *tconst uint8_t *key, size_t key_size){

	struct trie_data **data = trie_index(em->learning_profiles, key, key_size);

	// New host - alloc & initialize to zeros
	if (*data == NULL) {
		*data = mem_pool_alloc(em->learning_profiles_pool, em->learning_profile_size_per_host);
		memset(*data, 0, em->learning_profile_size_per_host);
	}

	return (uint8_t *)*data;
}


void engine_handle_packet(struct engine *en, struct context *ctx, const struct packet_info *packet) {
	

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

	uint8_t *learning_profiles = engine_lookup_host_learning_profiles(en, key, key_size);

	uint8_t *detection_profiles = NULL;
	if (en->mode == DETECTION) {

	}





	// Pass packet to each statemachine & process new finished conversations reported by statemachine
	int i_sm;	// Statemachine index
	for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm) {
		statemachine *sm = en->statemachines[i_sm];
		sm->packet_callback(&sm_ctx, packet);

		// Modify evaluator context according to current statemachine
		ev_ctx.transition_count = sm->transition_count;
		
		// Process finished (closed, timedout, ..) conversations from statemachine
		struct conversation *conv;
		while (conv = sm->get_next_finished_conv_callback(&sm_ctx)) {
			struct learning_profile = trie
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