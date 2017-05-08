/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2017 Martin Dulovic

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

#include "conversation.h"
#include "engine.h"

struct logger;

struct logger *logger_create(struct context *ctx, const char *logfile);

void file_close(struct logger *log);

void write_log(struct logger *log, const char *msg);

void write_t(struct logger *log, const char *level, const char *msg);

void send_anomaly(struct context *context, double score, double threshold, const struct conversation_id *conv, struct logger *log);

void send_to_server(struct context *context, struct logger *log, uint8_t *msg, size_t msg_size);