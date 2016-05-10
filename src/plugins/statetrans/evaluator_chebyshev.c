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

struct learn_profile {

};


struct detect_profile {

};

static void chebyshev_init(struct evaluator_context *ctx) {

}

static void chebyshev_destroy(struct evaluator_context *ctx) {

}

static void chebyshev_learn(struct evaluator_context *ctx, struct learn_profile *learning, size_t transition_count, const struct statemachine_conversation *conv) {

}

static double chebyshev_detect(struct evaluator_context *ctx, struct detect_profile *detection, size_t transition_count, const struct statemachine_conversation *conv) {

}

static void chebyshev_create_profile(struct evaluator_context *ctx, struct learn_profile *learning, struct detect_profile *detection) {

}


////
struct evaluator *evaluator_info_chebyshev(void) {
	static struct evaluator evaluator = {
		.name = "Chebyshev mean-distance",
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
///
