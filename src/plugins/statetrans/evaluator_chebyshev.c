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

#include "evaluator_chebyshev.h"
#include "../../core/mem_pool.h"
#include "../../core/util.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

// Debug
#include "conversation.h"
#include "stdio.h"

////////////////////////////////////////////////////////////////////////////////

// learning_profiles[host_id][statemachine][convers_index].timeslots[ts][statemachine.trans_cnt]
// host_id managed by engine

struct cheb_conv_list_node {
	struct cheb_conv_list_node *next, *prev;
	double **values;	// value for each transition & each timeslot
};

struct cheb_conv_list {
	struct cheb_conv_list_node *head, *tail;
	size_t count;
};

#define LIST_NODE struct cheb_conv_list_node
#define LIST_BASE struct cheb_conv_list
#define LIST_PREV prev
#define LIST_NAME(X) cheb_conv_list_##X
#define LIST_COUNT count
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#define LIST_INSERT_AFTER
#include "../../core/link_list.h"

struct learn_profile {
	struct cheb_conv_list* lists;
};

struct cheb_detect_value {
	double mean, variance;
};

// detection_profiles[host_id][statemachine].timeslots[ts][statemachine.trans_cnt]
// host_id managed by engine
struct detect_profile {
	// [statemachine][ts][statemachine.trans_cnt]
	struct cheb_detect_value ***values_per_statemachine;
};

struct evaluator_data {
	struct mem_pool *learn_pool, *detect_pool;
	size_t statemachine_cnt;
	//double variance_coef;
};

// Callback prototypes
static void chebyshev_init(struct evaluator_context *ctx);
static void chebyshev_destroy(struct evaluator_context *ctx);
static void chebyshev_learn(struct evaluator_context *ctx, struct learn_profile *learning, const struct statemachine_conversation *conv);
static double chebyshev_detect(struct evaluator_context *ctx, struct detect_profile *detection, const struct statemachine_conversation *conv, struct anomaly_location *anom_loc);
static void chebyshev_create_profile(struct evaluator_context *ctx, struct learn_profile *learning, struct detect_profile *detection);

struct evaluator *evaluator_info_chebyshev(void) {
	static struct evaluator evaluator = {
		.name = "Chebyshev mean-variance",
		.learn_profile_size = sizeof(struct learn_profile),
		.detect_profile_size = sizeof(struct detect_profile),

		.init_callback = chebyshev_init,
		.finish_callback = chebyshev_destroy,
		.learn_callback = chebyshev_learn,
		.detect_callback = chebyshev_detect,
		.create_profile = chebyshev_create_profile
	};

	return &evaluator;
}

////////////////////////////////////////////////////////////////////////////////

// Prototypes
static void cheb_init_learn_profile(struct evaluator_context *ctx,struct learn_profile *learning);
static void cheb_init_detect_profile(struct evaluator_context *ctx,struct detect_profile *detection);
static double **cheb_alloc_learn_values(struct evaluator_context *ctx, struct mem_pool * pool);
static struct cheb_detect_value **cheb_alloc_detect_values(struct evaluator_context *ctx, struct mem_pool * pool);
static double chebyshev_probability(double val, double mean, double variance);





////////////////////////////////////////////////////////////////////////////////
//				DEBUG RROTOTYPE
////////////////////////////////////////////////////////////////////////////////
static void CH_DBG_LEARNING_PROFILES(struct evaluator_context *ctx, struct learn_profile *learning) ;
static void CH_DBG_DETECTION_PROFILES(struct evaluator_context *ctx, struct detect_profile *detection);




////////////////////////////////////////////////////////////////////////////////

static void chebyshev_init(struct evaluator_context *ctx) {
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: init \n");
	ctx->data = mem_pool_alloc(ctx->plugin_ctx->permanent_pool, sizeof (struct evaluator_data));
	struct evaluator_data *d = ctx->data;
	
	d->learn_pool = mem_pool_create("Statetrans Chebyshev evaluator learning");
	d->detect_pool = mem_pool_create("Statetrans Chebyshev evaluator detection");;
	d->statemachine_cnt = ctx->statemachine_index;
	//d->variance_coef = 0.5;
}

static void chebyshev_destroy(struct evaluator_context *ctx) {
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: destroy \n");
	struct evaluator_data *d = ctx->data;
	mem_pool_destroy(d->learn_pool); 
	mem_pool_destroy(d->detect_pool); 
	
}

static void chebyshev_learn(struct evaluator_context *ctx, struct learn_profile *learning, const struct statemachine_conversation *conv) {
	char *fourtuple = conversation_id_format_4tuple(ctx->plugin_ctx->temp_pool, &conv->id, " -> ");
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: Learning called for conversation [%s] using learn_profile=%p\n\n", 
		fourtuple,
		(void *) learning
	);
	
	struct evaluator_data *d = ctx->data;
		
	// New unseen profile
	if (!learning->lists) {
		ulog(LLOG_DEBUG, "Statetrans Chebyshev: unseen learning profile, initializing\n");
		cheb_init_learn_profile(ctx, learning);
	}
	
	// Get conversation list for given statemachine
	struct cheb_conv_list *conv_list = &learning->lists[ctx->statemachine_index];
	
	// Allocate memory aggregated conv data in learning profile
	double **values = cheb_alloc_learn_values(ctx, d->learn_pool);
	
	// Distr transitions per timeslot 
	size_t i_ts;
	for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
		// Sum of avg aggregated for timeslot & transition
		double sum = 0.0L;
		size_t trans;
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			values[i_ts][trans] += conv->timeslots[i_ts][trans].aggr_value / conv->timeslots[i_ts][trans].aggr_cnt;
			sum += values[i_ts][trans];
		}

		// Transform to distribution (proportional value for each transition count)
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			if (sum != 0.0L)
				values[i_ts][trans] /= sum;
			else 
				values[i_ts][trans] = 0.0L;
		}
	}
	
	// Append to list
	struct cheb_conv_list_node *node = cheb_conv_list_append_pool(conv_list, d->learn_pool);
	node->values = values;
	
#ifdef STATETRANS_DEBUG
	// DEBUG
	//ulog(LLOG_DEBUG, "Statetrans Chebyshev: Learning - added conversation [%s]\n", fourtuple);
	//CH_DBG_LEARNING_PROFILES(ctx, learning);
#endif
}

static double chebyshev_detect(struct evaluator_context *ctx, struct detect_profile *detection, const struct statemachine_conversation *conv, struct anomaly_location *anom_loc) {
	
#ifdef STATETRANS_DEBUG
	char *fourtuple = conversation_id_format_4tuple(ctx->plugin_ctx->temp_pool, &conv->id, " -> ");
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: Detection called for conversation [%s] using detection_profile=%p\n", 
		fourtuple,
		(void *) detection
	);
#endif
	
	// Remember the highest probability of anomaly 
	double max_score = 0.0L;
	size_t ts_max = 0;
	size_t trans_max = 0;
	
	size_t i_ts, trans;
	
	//double *values = mem_pool_alloc(ctx->plugin_ctx->temp_pool, ctx->transition_cnt * sizeof(double));
	
	for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
	
		// Copy conversation values & calc. sum
		double sum = 0.0L;
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			if (conv->timeslots[i_ts][trans].aggr_cnt != 0.0L)
				conv->timeslots[i_ts][trans].aggr_value /= conv->timeslots[i_ts][trans].aggr_cnt;
			else
				conv->timeslots[i_ts][trans].aggr_value = 0.0L;
				
			sum += conv->timeslots[i_ts][trans].aggr_value;
		}
		
		// Transform to distribution (proportional value for each transition count)
		// Then calculate the score
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			// Transform to distribution (proportional value for each transition count)
			double value = conv->timeslots[i_ts][trans].aggr_value / sum;
			
			// Get mean & variance from detection profile
			double mean = detection->values_per_statemachine[ctx->statemachine_index][i_ts][trans].mean;			
			double variance = detection->values_per_statemachine[ctx->statemachine_index][i_ts][trans].variance;
			
			// Calculate score using Chebyshev's inequality
			double score = chebyshev_probability(value, mean, variance);
			
			// Save the highest score
			if (ts_max == 0 || score > max_score) {
				max_score = score;
				ts_max = i_ts;
				trans_max = trans;
			}
		} 
	}
	
	// Output parameter for anomaly location
	if (anom_loc) {
		anom_loc->timeslot = ts_max;
		anom_loc->transition = trans_max;
	}
	
#ifdef STATETRANS_DEBUG
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: Detection score for [%s] is %.lf, location=(timestamp=%zu, transition=%zu)\n", 
		fourtuple,
		max_score,
		ts_max,
		trans_max
	);
#endif
	return max_score;
}

static void chebyshev_create_profile(struct evaluator_context *ctx, struct learn_profile *learning, struct detect_profile *detection) {
	
#ifdef STATETRANS_DEBUG
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: Create profile using learning_profile=%p and detection_profile=%p\n", 
		(void *) learning,
		(void *) detection
	);
#endif
	
	struct evaluator_data *d = ctx->data;
	if (!learning->lists) {
		return; // Nothing to do
	}	

	// New unseen detection profile - initialize
	if (!detection->values_per_statemachine) {
		cheb_init_detect_profile(ctx, detection);
	}
	
	// Initialize for current statemachine - allocate matrix
	struct cheb_detect_value **values = cheb_alloc_detect_values(ctx, d->detect_pool);
	
	// Get conversation list for given statemachine
	struct cheb_conv_list *learn_conv_list = &learning->lists[ctx->statemachine_index];
	
	// Calculate mean from all conversations (sum / count)
	size_t i_ts, trans;
	LFOR(cheb_conv_list, learn_conv, learn_conv_list) {
		for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
			for (trans = 0; trans < ctx->transition_cnt; trans++) {
				// Sum
				values[i_ts][trans].mean += learn_conv->values[i_ts][trans];
			}
		}
	}
	for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			// Mean = sum / count
			if (learn_conv_list->count)
				values[i_ts][trans].mean /= learn_conv_list->count;
			else
				values[i_ts][trans].mean = 0.0L;
		}
	}
	
	// Calculate variance from all conversations (sum of squared deviations from mean / count)
	LFOR(cheb_conv_list, learn_conv, learn_conv_list) {
		for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
			for (trans = 0; trans < ctx->transition_cnt; trans++) {
				double mean= values[i_ts][trans].mean;
				double val = learn_conv->values[i_ts][trans];
				double dev = val - mean; // deviation
				
				// Sum of squared deviations from mean
				values[i_ts][trans].variance += dev * dev;
			}
		}
	}
	
	for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			// Variance = sum of squared deviations from mean / count
			if (learn_conv_list->count)
				values[i_ts][trans].variance /= learn_conv_list->count;
			else
				values[i_ts][trans].variance = 0.0L;
		}
	}
	
	// Now we have the matrix of transition distribution for each timeslot
	
	// Save detection profile for current statemachine 
	detection->values_per_statemachine[ctx->statemachine_index]  = values;
	
#ifdef STATETRANS_DEBUG
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: Profile creation finished\n");
	
	// DEBUG
	CH_DBG_LEARNING_PROFILES(ctx, learning);
	CH_DBG_DETECTION_PROFILES(ctx, detection);
#endif
}

////////////////////////////////////////////////////////////////////////////////

static void cheb_init_learn_profile(struct evaluator_context *ctx, struct learn_profile *learning) {
	struct evaluator_data *d = ctx->data;
	
	size_t size = d->statemachine_cnt * sizeof(struct cheb_conv_list);
	learning->lists = mem_pool_alloc(d->learn_pool, size);
	memset(learning->lists, 0, size);	
}

// Allocate matrix of doubles of size [timeslot_cnt x transition_cnt]
static double **cheb_alloc_learn_values(struct evaluator_context *ctx, struct mem_pool * pool) {
	//struct evaluator_data *d = ctx->data;
	
	double **values = mem_pool_alloc(pool, ctx->timeslot_cnt * sizeof(double *));
	size_t trans;
	for (trans = 0; trans < ctx->timeslot_cnt; trans++) {
		size_t size = ctx->transition_cnt * sizeof(double);
		values[trans] = mem_pool_alloc(pool, size);
		memset(values[trans], 0, size);
	}
	
	return values;
}

// Allocate matrix of doubles of size [timeslot_cnt x transition_cnt]
static struct cheb_detect_value **cheb_alloc_detect_values(struct evaluator_context *ctx, struct mem_pool * pool) {
	//struct evaluator_data *d = ctx->data;
	
	struct cheb_detect_value **values = mem_pool_alloc(pool, ctx->timeslot_cnt * sizeof(struct cheb_detect_value *));
	size_t trans;
	for (trans = 0; trans < ctx->timeslot_cnt; trans++) {
		size_t size = ctx->transition_cnt * sizeof(struct cheb_detect_value);
		values[trans] = mem_pool_alloc(pool, size);
		memset(values[trans], 0, size);
	}
	
	return values;
}

static void cheb_init_detect_profile(struct evaluator_context *ctx, struct detect_profile *detection) {
	struct evaluator_data *d = ctx->data;
	
	size_t size = d->statemachine_cnt * sizeof(struct cheb_detect_value **);
	
	detection->values_per_statemachine = mem_pool_alloc(d->detect_pool, size);
	memset(detection->values_per_statemachine, 0, size);	
}

// This is the place where Chebyshev's magic happens
static double chebyshev_probability(double val, double mean, double variance) {
	double dev, p;

	/* Deviation of observed length from mean */
	dev = val - mean;

	/* Probability that observed length is regular (i.e. non-anomalous) */
	//if (dev != 0)
	if (fabs(dev) > 0.01L)
		p = variance / (dev * dev);
	else
		p = 1.0L;
	
	if (p > 1.0L) {
#ifdef STATETRANS_DEBUG
		ulog(LLOG_DEBUG, "Statetrans Chebyshev: inequality fixing too big value %.2lf to 1.0\n", p);
#endif
		p = 1.0L;
	}

	
#ifdef STATETRANS_DEBUG
	ulog(LLOG_DEBUG, "Statetrans Chebyshev: inequality val=%.2lf mean=%.2lf dev=%.2lf var=%.2lf ret=%.2lf\n", val, mean, dev, variance, 1-p);
#endif
	/* 
	  The probability is substracted form 1 because probability close to
	  zero indicates anomalous event 
	 */
	return 1 - p;
}

////////////////////////////////////////////////////////////////////////////////
//				DEBUG
////////////////////////////////////////////////////////////////////////////////
static void CH_DBG_LEARNING_PROFILES(struct evaluator_context *ctx, struct learn_profile *learning) {
	
	struct cheb_conv_list *learn_conv_list = &learning->lists[ctx->statemachine_index];

	
	ulog(LLOG_DEBUG, "----- DUMPING LEARNING PROFILE CONVERSATIONS (chebyshev) -----\n");
	ulog(LLOG_DEBUG, " conversations=%zu, timestamps=%zu, transitions=%zu\n", learn_conv_list->count, ctx->timeslot_cnt, ctx->transition_cnt);
	
	size_t i_ts, trans, i_conv = 0;
	LFOR(cheb_conv_list, learn_conv, learn_conv_list) {
		
		ulog(LLOG_DEBUG, "  / COVN %zu -------------\n", i_conv++);
				
		char buf[2000];
		char *cursor = buf;
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			cursor += sprintf(cursor, " %4zu", trans);
		}
		ulog(LLOG_DEBUG, "  |        %s\n", buf);
			
		for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
			cursor = buf;
			
			cursor += sprintf(cursor, " ts %zu> ", i_ts);
			
			for (trans = 0; trans < ctx->transition_cnt; trans++) {
				cursor += sprintf(cursor, " %4.2lf", learn_conv->values[i_ts][trans]);
			}
			ulog(LLOG_DEBUG, "  | %s\n", buf);
		}
		ulog(LLOG_DEBUG, "  \\____________\n\n");
	}
	
	ulog(LLOG_DEBUG, "----- DUMPING FINISHED (chebyshev) -----\n\n");
}

static void CH_DBG_DETECTION_PROFILES(struct evaluator_context *ctx, struct detect_profile *detection) {
	
	struct cheb_detect_value **values = detection->values_per_statemachine[ctx->statemachine_index];

	
	ulog(LLOG_DEBUG, "----- DUMPING DETECTION PROFILE (chebyshev) -----\n");
	ulog(LLOG_DEBUG, " timestamps=%zu, transitions=%zu\n",  ctx->timeslot_cnt, ctx->transition_cnt);
	
	size_t i_ts, trans;
				
	char buf[2000];
	char *cursor = buf;
	for (trans = 0; trans < ctx->transition_cnt; trans++) {
		cursor += sprintf(cursor, " %4zu", trans);
	}
	ulog(LLOG_DEBUG, "  |             %s\n", buf);

	for (i_ts = 0; i_ts < ctx->timeslot_cnt; i_ts++) {
		// Mean
		cursor = buf;
		cursor += sprintf(cursor, " ts %zu mean> ", i_ts);
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			cursor += sprintf(cursor, " %4.2lf", values[i_ts][trans].mean);
		}
		ulog(LLOG_DEBUG, "  | %s\n", buf);
		
		
		// Variance
		cursor = buf;
		cursor += sprintf(cursor, " ts %zu var > ", i_ts);
		for (trans = 0; trans < ctx->transition_cnt; trans++) {
			cursor += sprintf(cursor, " %4.2lf", values[i_ts][trans].variance);
		}
		ulog(LLOG_DEBUG, "  | %s\n", buf);
		ulog(LLOG_DEBUG, "  |------\n");
	}
	ulog(LLOG_DEBUG, "  \\____________\n\n");

	ulog(LLOG_DEBUG, "----- DUMPING DETECTION FINISHED (chebyshev) -----\n\n");
	
}