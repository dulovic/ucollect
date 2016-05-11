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

#ifndef UCOLLECT_STATETRANS_ENGINE_H
#define UCOLLECT_STATETRANS_ENGINE_H

#include "statemachine.h"
#include "evaluator.h"

enum detection_mode {
    LEARNING,
    DETECTION
};

struct engine *engine_create(struct context *ctx, timeslot_interval_t *timeslots, size_t timeslot_cnt);

void engine_handle_packet(struct engine *en, struct context *ctx, const struct packet_info *info);

void engine_change_mode(struct engine *en, struct context *ctx, detection_mode mode);

void engine_destroy(struct engine *en, struct context *ctx);

#endif
