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

#include "engine.h"
#include "logger.h"

#include "../../core/mem_pool.h"
#include "../../core/context.h"
#include "../../core/trie.h"
#include "../../core/packet.h"
#include "../../core/util.h"
#include "../../core/loop.h"

#include "conversation.h"
#include "statemachine_tcp.h"
#include "evaluator_chebyshev.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <endian.h>
#include <arpa/inet.h>

struct engine {
	enum detection_mode mode;

	timeslot_interval_t *timeslots;
	size_t timeslot_cnt;

	size_t statemachine_cnt;
	struct statemachine **statemachines;
	struct statemachine_data **statemachines_data;

	size_t evaluator_cnt;
	struct evaluator **evaluators;
	struct evaluator_data **evaluators_data;

	struct mem_pool *learn_profiles_pool;
	struct trie *learn_profiles;
	size_t learn_host_profile_size; // Size for one host 
	size_t *learn_eval_profile_offsets; // For each host large block of data is allocated. Evaluator specific data begins at given offset for each evaluator

	struct mem_pool *detect_profiles_pool;
	struct trie *detect_profiles;
	size_t detect_host_profile_size; // Size for one host 
	size_t *detect_eval_profile_offsets; // For each host large block of data is allocated. Evaluator specific data begins at given offset for each evaluator

	struct context *plugin_ctx; // For internal purposes, should not be changed outside engine
	
	double threshold;
	
	FILE *logfile;
};

struct trie_data {
	int dummy; // Just to prevent warning about empty struct
};

////////////////////////////////////////////////////////////////////////////////

// Prototypes
static void engine_print_init_info(struct context *ctx, timeslot_interval_t *timeslots, size_t timeslot_cnt, double threshold, const char *logfile);
static void engine_alloc_profiles(struct engine *en);
static void engine_init_statemachines(struct engine *e);
static void engine_init_evaluators(struct engine *e);
static uint8_t *engine_get_host_profile(struct engine *en, const uint8_t *host_key, size_t host_key_size, enum detection_mode mode);
static double engine_process_finished_conv(struct engine *en, struct evaluator_context *ev_ctx, const uint8_t *host_profile, const struct statemachine_conversation *conv, struct anomaly_location *anom_loc);
static void engined_change_mode_walk_trie_cb(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata);
static void engine_log(struct engine *en, const char *level, const char *msg);

////////////////////////////////////////////////////////////////////////////////

void update_treshold(struct engine *en, double threshold, struct logger *log) {
  
  char msg[64];
  snprintf(msg, sizeof msg, "ENGINE Update - Changing Threshold form %.2f to %.2f", en->threshold, threshold);
  write_t(log, "INFO", msg);
  
  en-> threshold = threshold;
}

struct engine *engine_create(struct context *ctx, timeslot_interval_t *timeslots, size_t timeslot_cnt, double threshold, const char *logfile, struct logger *log) {
  
	write_t(log, "INFO", "ENGINE - creating engine (start)");
	
	engine_print_init_info(ctx, timeslots, timeslot_cnt, threshold, logfile);
	
	struct engine *en;
	en = mem_pool_alloc(ctx->permanent_pool, sizeof (struct engine));
	en->mode = LEARNING;
	en->plugin_ctx = ctx; // This will be updated on each call
	
	en->threshold = threshold;
	
	char msgg[64];
	snprintf(msgg, sizeof msgg, "ENGINE - Treshold: %.2lf", en->threshold);
	write_t(log, "INFO", msgg);

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

	// Create tries for learning & detection profiles per host
	engine_alloc_profiles(en);

	engine_init_statemachines(en);
	engine_init_evaluators(en);
	
	en->logfile = fopen(logfile, "w");

	ulog(LLOG_DEBUG, "Statetrans engine: init done\n");
	write_t(log, "INFO", "ENGINE - creating engine (done)");
	
	return en;
}

struct ss {
  uint16_t score;
  //uint16_t src_port;
} __attribute__((packed));

void engine_handle_packet(struct engine *en, struct context *ctx, const struct packet_info *pkt, struct logger *log) {
	assert(en->mode == LEARNING || en->mode == DETECTION);

	char *fourtuple = packet_format_4tuple(ctx->temp_pool, pkt, " ==> ");
	char *layers = packet_format_layer_info(ctx->temp_pool, pkt, " -> ");
	ulog(LLOG_DEBUG, "Statetrans engine: got packet[%s] %s\n", layers, fourtuple);
	
	uint16_t dp = dst_port(pkt);
	uint16_t sp = src_port(pkt);
	
	if(dp == 5679 || sp == 5679) {
	  //write_t(log, "WARN", "client-server communication - ignore");
	  return;
	}

	//write_t(log, "WARN", "ENGINE - packet handle");

	en->plugin_ctx = ctx; // Updated on each call
	uint64_t now = pkt->timestamp;
	
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
		//.statemachine_index = 0	// Per statemachine
	};

	// Pass packet to each statemachine & process new finished conversations reported by statemachine
	size_t i_sm; // Statemachine index
	for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm++) {
		struct statemachine *sm = en->statemachines[i_sm];
		
		ulog(LLOG_DEBUG, "Statetrans engine: passing packet to statemachine '%s'\n", sm->name);

		sm_ctx.data = en->statemachines_data[i_sm]; // Restore pointer to statemachine data
		if (sm->packet_callback)
			sm->packet_callback(&sm_ctx, pkt);

		// Modify evaluator context according to current statemachine
		ev_ctx.statemachine_index = i_sm;
		ev_ctx.transition_cnt = sm->transition_count;

		//write_t(log, "WARN", "ENGINE - FOR");
		
		// Process finished (closed, timedout, ..) conversations from statemachine
		struct statemachine_conversation *conv;
		while ((conv = sm->get_next_finished_conv_callback(&sm_ctx, now))) {
			char *fourtuple = conversation_id_format_4tuple(ctx->temp_pool, &conv->id, " -> ");
			ulog(LLOG_DEBUG, "Statetrans engine: got finished conversation %s\n", fourtuple);
			
			//write_t(log, "WARN", "ENGINE - WHILE");
			
			//Get host key (local MAC address)
			uint8_t *host_key = conv->id.profile_key;
			size_t host_key_size = conv->id.profile_key_len;

			// Get (learning or detection) host profile 
			uint8_t *host_profile = engine_get_host_profile(en, host_key, host_key_size, en->mode);
			
			char *mac_str = format_mac(ctx->temp_pool,host_key);
			ulog(LLOG_DEBUG, "Statetrans engine: using host_profile[%s] = %p\n", mac_str, host_profile);

			struct anomaly_location anom_loc;
			double score = engine_process_finished_conv(en, &ev_ctx, host_profile, conv, &anom_loc);

			ulog(LLOG_INFO, "Statetrans engine: Anomaly score = %.2lf for conv [%s]\n", score, fourtuple);
			
			if (score >= en->threshold) {
				char *msg = mem_pool_printf(ctx->temp_pool, "score(%.2lf) [%s] timeslot=%zums transition=%zu", 
					score, 
					fourtuple, 
					(size_t) en->timeslots[anom_loc.timeslot], 
					anom_loc.transition	// TODO: print str
				);
				ulog(LLOG_WARN, "Statetrans engine: [ANOMALY] %s\n", msg);
				
				// Log to file
				engine_log(en, "ANOMALY", msg);

				write_t(log, "WARN", msg);
				
				
				// Threshold to BYTE-ORDER
				int thr = (int)(en->threshold * 100);
				thr = htons(thr);
				
				// Score to BYTE-ORDER
				int scr = (int)(score * 100);
				scr = htons(scr);
				
				uint8_t *d_ip = dst_ip_conv(ctx->temp_pool, &conv->id);
				uint8_t *s_ip = src_ip_conv(ctx->temp_pool, &conv->id);
				
				size_t ip_len = conversation_id_addr_len(&conv->id);
				uint8_t family;
				if (ip_len == 4)
				  family = 4;
				else
				  family = 6;
				
				if ((s_ip[0] == 192 && s_ip[1] == 168) || (s_ip[0] == 10) || (s_ip[0] == 172) ) {
				  write_t(log, "ERROR", "SRC IP - PRIVATE IP !");
				}

				// DST port to BYTE-ORDER
				uint16_t d_port = dst_port_conv(ctx->temp_pool, &conv->id);
				d_port = htons(d_port);
				
				// SRC port to BYTE-ORDER
				uint16_t s_port = src_port_conv(ctx->temp_pool, &conv->id);
				s_port = htons(s_port);
				
				// Actual UNIX time to BYTE-ORDER
				uint64_t now = htobe64((unsigned long)time(NULL));
				
				size_t message_size = 1 + 8 + 2 + 1 + 2 + 2 + ip_len + ip_len;
				uint8_t *message;
				*message = (uint8_t)'A';			// 1 Byte - OP code
				memcpy(message + 1,  &now, 8); 			// 8 Byte - Unix time
				memcpy(message + 9,  &scr, 2);			// 2 Byte - Score
				memcpy(message + 11, &family, 1);		// 1 Byte - Family
				memcpy(message + 12, &s_port, 2);		// 2 Byte - SRC port
				memcpy(message + 14, &d_port, 2);		// 2 Byte - DST port
				memcpy(message + 16, s_ip, ip_len);		// 4/16 Byte - SRC IP
				memcpy(message + 16 + ip_len, d_ip, ip_len);	// 4/16 Byte - DST IP	

				send_to_server(ctx, log, message, message_size);
			} 
			else {
				char *msg = mem_pool_printf(ctx->temp_pool, "score(%.2lf) [%s]", score, fourtuple);
				engine_log(en, "INFO", msg);
				
				//write_t(log, "INFO", "ENGINE - NOT ANOMALY (info)");
			}


		}

		// Perform statemachine-level cleanup
		sm->clean_timedout_convs_callback(&sm_ctx, pkt->timestamp);

		// Save pointer to statemachine data
		en->statemachines_data[i_sm] = sm_ctx.data;
	}
	ulog(LLOG_DEBUG, "Statetrans engine: packet processing finished\n");
}

void engine_change_mode(struct engine *en, struct context *ctx, enum detection_mode mode, struct logger *log) {
  
	en->plugin_ctx = ctx;

	char *old_s = (en->mode == LEARNING) ? "LEARNING" : "DETECTION";
	char *new_s = (mode == LEARNING) ? "LEARNING" : "DETECTION";

	ulog(LLOG_DEBUG, "Statetrans engine: Changing mode (%s -> %s)\n", old_s, new_s);

	if (en->mode != LEARNING || mode != DETECTION) {
		ulog(LLOG_INFO, "Statetrans engine: Unsupported mode change (%d -> %d)\n", en->mode, mode);
		return;
	}
	
	char *msg = mem_pool_printf(en->plugin_ctx->temp_pool, "Switching mode (%s -> %s)\n", old_s, new_s);
	engine_log(en, "INFO", msg);

	// Clear detection profiles trie
	mem_pool_reset(en->detect_profiles_pool);
	en->detect_profiles = trie_alloc(en->detect_profiles_pool);

	trie_walk(en->learn_profiles, engined_change_mode_walk_trie_cb, en, ctx->temp_pool);
	en->mode = mode;
	
	ulog(LLOG_INFO, "Statetrans engine: Mode change finished (%s -> %s)\n", old_s, new_s);
	
	char msgg[64];
	snprintf(msgg, sizeof msgg, "ENGINE - Changing mode (%s -> %s)", old_s, new_s);
	write_t(log, "INFO", msgg);
}

void engine_destroy(struct engine *en __attribute__((unused)), struct context *ctx __attribute__((unused))) {
	ulog(LLOG_INFO, "Statetrans engine: Destroy called\n");
	fclose(en->logfile);
	
	// TODO:
	// Here we should call destroy for all statemachines & evaluators
	// For now we assume that the whole plugin/ucollect is going to be destroyed
}

////////////////////////////////////////////////////////////////////////////////

static void engine_alloc_profiles(struct engine *en) {
	ulog(LLOG_INFO, "Statetrans engine: allocating memory for host profiles\n");
	
	en->learn_profiles_pool = mem_pool_create("Statetrans learning profiles");
	en->learn_profiles = trie_alloc(en->learn_profiles_pool);

	en->detect_profiles_pool = mem_pool_create("Statetrans detection profiles");
	en->detect_profiles = trie_alloc(en->detect_profiles_pool);
}

static void engine_init_statemachines(struct engine *en) {
	// Alloc storage for pointers to statemachine data
	en->statemachines_data = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->statemachine_cnt * sizeof (struct statemachine_data *));

	struct statemachine_context sm_ctx = {
		.plugin_ctx = en->plugin_ctx,
		.timeslots = en->timeslots,
		.timeslot_cnt = en->timeslot_cnt
	};

	size_t i_sm;
	for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm++) {
		ulog(LLOG_INFO, "Statetrans engine: Initializing statemachine '%s'\n", en->statemachines[i_sm]->name);
		if (!en->statemachines[i_sm]->init_callback)
			continue;

		// Initialize statemachine data
		en->statemachines_data[i_sm] = NULL;
		sm_ctx.data = en->statemachines_data[i_sm];

		// Initialize statemachine
		en->statemachines[i_sm]->init_callback(&sm_ctx);

		// Save statemachine data
		en->statemachines_data[i_sm] = sm_ctx.data;

	}
}

static void engine_init_evaluators(struct engine *en) {
	// Alloc storage for pointers to statemachine data
	en->evaluators_data = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->evaluator_cnt * sizeof (struct evaluator_data *));

	struct evaluator_context ev_ctx = {
		.plugin_ctx = en->plugin_ctx,
		.timeslots = en->timeslots,
		.timeslot_cnt = en->timeslot_cnt,
		.transition_cnt = 0,
		.statemachine_index = en->statemachine_cnt // Pass total number of statemachines
	};

	// Offsets for each evaluator within host profile
	en->learn_eval_profile_offsets = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->evaluator_cnt * sizeof (size_t));
	en->detect_eval_profile_offsets = mem_pool_alloc(en->plugin_ctx->permanent_pool, en->evaluator_cnt * sizeof (size_t));

	// Profile size per host
	en->learn_host_profile_size = 0;
	en->detect_host_profile_size = 0;

	size_t i_ev;
	for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
		ulog(LLOG_INFO, "Statetrans engine: Initializing evaluator '%s'\n", en->evaluators[i_ev]->name);

		if (!en->evaluators[i_ev]->init_callback)\
		continue;

		// Initialize evaluator data pointe & call evaluator initializer
		en->evaluators_data[i_ev] = NULL;
		ev_ctx.data = en->evaluators_data[i_ev];
		en->evaluators[i_ev]->init_callback(&ev_ctx);
		en->evaluators_data[i_ev] = ev_ctx.data;

		// Remember evaluator offset in common profile data block for one host
		en->learn_eval_profile_offsets[i_ev] = en->learn_host_profile_size;
		en->detect_eval_profile_offsets[i_ev] = en->detect_host_profile_size;

		// Memory occupied by one host from viewpoint of engine
		en->learn_host_profile_size += en->evaluators[i_ev]->learn_profile_size;
		en->detect_host_profile_size += en->evaluators[i_ev]->detect_profile_size;
	}
	ulog(LLOG_INFO, "Statetrans engine: Learning profile size per host '%zd'\n", en->learn_host_profile_size);
	ulog(LLOG_INFO, "Statetrans engine: Detection profile size per host '%zd'\n", en->detect_host_profile_size);
}

static uint8_t *engine_get_host_profile(struct engine *en, const uint8_t *host_key, size_t host_key_size, enum detection_mode mode) {
	struct trie *profiles_trie;
	struct trie_data **data;

	// Find or add to correct trie according to mode
	profiles_trie = (mode == LEARNING) ? en->learn_profiles : en->detect_profiles;
	data = trie_index(profiles_trie, host_key, host_key_size);

	// Host seen first time - alloc profile & initialize to zeros
	if (*data == NULL) {
		if (mode == LEARNING) {
			*data = mem_pool_alloc(en->learn_profiles_pool, en->learn_host_profile_size);
			memset(*data, 0, en->learn_host_profile_size);
		} else { // DETECTION
			*data = mem_pool_alloc(en->detect_profiles_pool, en->detect_host_profile_size);
			memset(*data, 0, en->detect_host_profile_size);
		}
	}

	return (uint8_t *)*data;
}

// Pass conversation to all evaluators and return max anomaly score (in learning mode always 0.0)
static double engine_process_finished_conv(struct engine *en, struct evaluator_context *ev_ctx, const uint8_t *host_profile, const struct statemachine_conversation *conv, struct anomaly_location *anom_loc) {
	size_t i_ev;
	double max_score = 0.0L;

	// Choose evaluator callback according to mode
	if (en->mode == LEARNING) {
		// Pass next finished conversation to all evaluators
		for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
			struct evaluator *ev = en->evaluators[i_ev];

			ulog(LLOG_DEBUG, "Statetrans engine: Running LEARNING for evaluator '%s'\n", ev->name);
			
			// Evaluator-specific data in learning profile
			struct learn_profile *learning;
			learning = (struct learn_profile *) (host_profile + en->learn_eval_profile_offsets[i_ev]);

			// Restore evaluator data pointer, do the learning and save the pointer
			ev_ctx->data = en->evaluators_data[i_ev];
			ev->learn_callback(ev_ctx, learning, conv);
			en->evaluators_data[i_ev] = ev_ctx->data;
		}

		// max_score 0.0 - not detecting
		max_score = 0.0L;
		anom_loc->timeslot = 0;
		anom_loc->transition = 0;

	} else { // if (en->mode == DETECTION) 
		// Default values
		anom_loc->timeslot = 0;
		anom_loc->transition = 0;

		// Pass next finished conversation to all evaluators
		for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
			struct evaluator *ev = en->evaluators[i_ev];

			ulog(LLOG_DEBUG, "Statetrans engine: Running DETECTION for evaluator '%s'\n", ev->name);
			
			// Evaluator-specific data in detection profile
			struct detect_profile *detection;
			detection = (struct detect_profile *) (host_profile + en->detect_eval_profile_offsets[i_ev]);

			struct anomaly_location cur_anom_loc;

			// Restore evaluator data pointer, do the detection and save the pointer
			ev_ctx->data = en->evaluators_data[i_ev];
			double score = ev->detect_callback(ev_ctx, detection, conv, &cur_anom_loc);
			en->evaluators_data[i_ev] = ev_ctx->data;

			if (score > max_score) {
				max_score = score; // TODO: remember evaluator index?
				*anom_loc = cur_anom_loc;
			}
		}
		//ulog(LLOG_INFO, "Statetrans engine: Anomaly score = %.2lf\n", max_score);
	}

	return max_score;
}

static void engined_change_mode_walk_trie_cb(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	struct engine *en = (struct engine*) userdata;
	
	char *mac_str = format_mac(en->plugin_ctx->temp_pool, key);
	ulog(LLOG_DEBUG, "Statetrans engine: Creating detection profile for host [%s]\n", mac_str);
	
	// Prepare evaluator context
	struct evaluator_context ev_ctx = {
		.plugin_ctx = en->plugin_ctx,
		.timeslots = en->timeslots,
		.timeslot_cnt = en->timeslot_cnt,
		//.transition_count = 0		// Will be set per statemachine
		//.statmachine_index = 0        // Per statemachine
	};

	uint8_t *host_learning = (uint8_t *) data;
	uint8_t *host_detection = engine_get_host_profile(en, key, key_size, DETECTION);

	// Call detection profile creation for each evaluator
	size_t i_sm;
	for (i_sm = 0; i_sm < en->statemachine_cnt; i_sm++) {
		struct statemachine *sm = en->statemachines[i_sm];

		// Modify evaluator context according to current statemachine
		ev_ctx.statemachine_index = i_sm;
		ev_ctx.transition_cnt = sm->transition_count;

		size_t i_ev;
		for (i_ev = 0; i_ev < en->evaluator_cnt; i_ev++) {
			struct evaluator *ev = en->evaluators[i_ev];

			ulog(LLOG_INFO, "Statetrans engine:    statemachine '%s' and evaluator '%s'\n", sm->name,  ev->name);
		
			// Evaluator-specific data for learning profile
			struct learn_profile *learning;
			learning = (struct learn_profile *) (host_learning + en->learn_eval_profile_offsets[i_ev]);

			// Evaluator-specific data for detection profile
			struct detect_profile *detection;
			detection = (struct detect_profile *) (host_detection + en->detect_eval_profile_offsets[i_ev]);


			// Restore evaluator data pointer, do the profile creation and save the pointer
			ev_ctx.data = en->evaluators_data[i_ev];
			ev->create_profile(&ev_ctx, learning, detection);
			en->evaluators_data[i_ev] = ev_ctx.data;
		}
	}
	ulog(LLOG_DEBUG, "Statetrans engine: Detection profile for host [%s] finished\n", mac_str);
}

static void engine_print_init_info(struct context *ctx, timeslot_interval_t *timeslots, size_t timeslot_cnt, double threshold, const char *logfile) {
	char *buf;
	if (timeslot_cnt)
		buf = mem_pool_printf(ctx->temp_pool, "%zu", (size_t) timeslots[0]);
	else 
		buf = NULL;
	
	size_t i_ts;
	for (i_ts = 1; i_ts < timeslot_cnt; i_ts++) {
		buf = mem_pool_printf(ctx->temp_pool, "%s,%zu", buf, (size_t) timeslots[i_ts]);
	}

	ulog(LLOG_DEBUG, "Statetrans engine: init: threshold=%.2lf timesslots[%zu]={%s} logfile='%s'\n", threshold, timeslot_cnt, buf, logfile);
}

static void engine_log(struct engine *en, const char *level, const char *msg) {
	time_t t;
	struct tm tm;
	
	t = time(NULL);
	localtime_r(&t, &tm);
	fprintf(en->logfile, "%02d-%02d-%02d %2d:%02d:%02d [%s]: %s\n",
		tm.tm_year + 1900,
		tm.tm_mon + 1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec,
		level,
		msg
	);
	fflush(en->logfile);
	
}