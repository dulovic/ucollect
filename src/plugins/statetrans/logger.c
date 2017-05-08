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

#include "logger.h"
#include "conversation.h"
#include "engine.h"

#include "../../core/mem_pool.h"
#include "../../core/context.h"
#include "../../core/trie.h"
#include "../../core/packet.h"
#include "../../core/util.h"

#include "../../core/packet.h"
#include "../../core/uplink.h"

#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <endian.h>

struct logger {
  FILE *logfile;

  struct context *plugin_ctx;
};

void write_log(struct logger *log, const char *msg);
void write_t(struct logger *log, const char *level, const char *msg);


struct logger *logger_create(struct context *ctx, const char *logfile) {
  struct logger *log;
  log = mem_pool_alloc(ctx->permanent_pool, sizeof (struct logger));
  log->plugin_ctx = ctx;
  
  log->logfile = fopen(logfile, "w");
  
  write_t(log, "INFO", "Logging started !");
  
  return log;
}

void file_close(struct logger *log) {
  fclose(log->logfile);
}

void write_t(struct logger *log, const char *level, const char *msg) {
  time_t result;
  result = time(NULL);
  
  struct tm tm;
  localtime_r(&result, &tm);
  
  char *time = asctime(localtime(&result));
  time[strlen(time) - 1] = 0;
  
  //fprintf(log->logfile, "%s - %s\n", time, msg);
  
  fprintf(log->logfile, "%02d-%02d-%02d %2d:%02d:%02d  [%s]\t%s\n",
    tm.tm_year + 1900,
    tm.tm_mon + 1,
    tm.tm_mday,
    tm.tm_hour,
    tm.tm_min,
    tm.tm_sec,
    level,
    msg
  );

  fflush(log->logfile);
}

void send_to_server(struct context *context, struct logger *log, uint8_t *msg, size_t msg_size) {
  write_t(log, "INFO", "uplink - Sending DATA to server");
  
  if(!uplink_plugin_send_message(context, msg, msg_size)) {
    write_t(log, "ERROR", "uplink - data NOT send !");
  }
  else {
    write_t(log, "INFO", "uplink - data SEND successfully");
  }
} 

void send_anomaly(struct context *context, double score, double threshold, const struct conversation_id *conv, struct logger *log) {
  // Threshold to BYTE-ORDER
  int thr = (int)(threshold * 100);
  thr = htons(thr);

  // Score to BYTE-ORDER
  int scr = (int)(score * 100);
  scr = htons(scr);

  uint8_t *d_ip = dst_ip_conv(context->temp_pool, &conv);
  uint8_t *s_ip = src_ip_conv(context->temp_pool, &conv);

  // DST port to BYTE-ORDER
  uint16_t d_port = dst_port_conv(context->temp_pool, &conv);
  d_port = htons(d_port);

  // SRC port to BYTE-ORDER
  uint16_t s_port = src_port_conv(context->temp_pool, &conv);
  s_port = htons(s_port);

  // Actual UNIX time to BYTE-ORDER
  uint64_t now = htobe64((unsigned long)time(NULL));

  size_t message_size = 1 + 8 + 2 + 4 + 2 ;
  uint8_t *message;
  *message = (uint8_t)'D';		// 1 Byte - OP code
  memcpy(message + 1,  &now, 2); 	// 8 Byte - Unix time
  memcpy(message + 9,  &scr, 2);	// 2 Byte - Score
  memcpy(message + 11, d_ip, 4);	// 4 Byte - DST IP
  memcpy(message + 15, &d_port, 2);	// 2 Byte - DST port

  send_to_server(context, log, message, message_size);
}