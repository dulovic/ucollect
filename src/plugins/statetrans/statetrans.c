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

/*
 * test e.g.:
 *	learning:
 *	       for i in `seq 1 30`; do curl google.com; sleep 0.2; done 
 *	detection
 *	       sudo nmap -PN -sS -p 1000-1005 1.1.1.1
 * 
 * build with -DSTATETRANS_DEBUG to enable debugging outputs 
 */

// ali - logger.h

#include "logger.h"

#include "engine.h"
#include "packet_buffer.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/trie.h"
#include "../../core/packet.h"
#include "../../core/uplink.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <endian.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <inttypes.h>


// printf formatter for uint64_t
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

typedef unsigned __int128 uint128_t;

struct user_data {
  struct engine *engine;
  struct packet_buffer *packet_buf;
  
  // ali - logger
  struct logger *log;
  
  struct loop *lop;
  
  double   threshold;
  uint64_t learn;
  
  // ali - data from server
  float    s_treshold_f;
  uint32_t s_treshold;
  uint64_t s_learn;
};

struct block_packet_v4 {
  uint32_t ip_block_v4;
} __attribute__((packed));

struct block_packet_v6 {
  uint128_t ip_block_v6;
} __attribute__((packed));

struct config_packet {
  uint32_t p_treshold;
  uint32_t p_learn;
} __attribute__((packed));

char* IPAddressToString(int ip) {
  char result[16];

  sprintf(result, "%d.%d.%d.%d",
    (ip >> 24) & 0xFF,
    (ip >> 16) & 0xFF,
    (ip >>  8) & 0xFF,
    (ip      ) & 0xFF);

  return result;
}  

static void timeout(struct context *context, void *data __attribute__((unused)), size_t id __attribute__((unused))) {
  ulog(LLOG_DEBUG, "Statetrans: changing mode to DETECTION ============================================\n");
  struct user_data *u = context->user_data;
  
  write_t(u->log, "INFO", "Learning loop finished");
  
  //connected(context);
  
  engine_change_mode(u->engine, context, DETECTION, u->log);
  ulog(LLOG_DEBUG, "Statetrans: mode change finished\n");
}

static void start(struct context *context) {
  struct user_data *u = context->user_data;
  
  write_t(u->log, "INFO", "START function - (start)");

  timeslot_interval_t timeslots[] = {1, 10, 100, 1000, 10000, 100000, 1000000};
  size_t timeslot_cnt = sizeof(timeslots) / sizeof(timeslot_interval_t);
  
  size_t pkt_buf_size = 20;
  u->packet_buf = packet_buffer_create(context->permanent_pool, pkt_buf_size);
    
  char *logfile = "statetrans.log";
  
  u->engine = engine_create(context, timeslots, timeslot_cnt, u->threshold, logfile, u->log);
  loop_timeout_add(context->loop, u->learn, context, NULL, timeout);
  
  char msg[64];
  snprintf(msg, sizeof msg, "START function - Engine set to Learning mode for %u seconds!", (unsigned)((u->learn)/1000));
  write_t(u->log, "INFO", msg);

  write_t(u->log, "INFO", "START function - (end)");
  
}

static void packet_handle(struct context *context, const struct packet_info *info) {
  struct user_data *u = context->user_data;
    
  /*
  if(info->ip_protocol == 6) {
    write_t(u->log, "WARN", "Throwing away IPv6 packet");
    return;
  }*/
 
  // Debug log
  char *fourtuple = packet_format_4tuple(context->temp_pool, info, " ==> ");
  char *layers = packet_format_layer_info(context->temp_pool, info, " -> ");
  ulog(LLOG_DEBUG, "Statetrans: Packet[%s] %s\n", layers, fourtuple);
  
  // Buffer packets & get the oldest one after the buffer is filled
  const struct packet_info *buffered_pkt = packet_buffer_add(u->packet_buf, info);
  if(!buffered_pkt) {
#ifdef STATETRANS_DEBUG
    ulog(LLOG_DEBUG, "Statetrans: Not enough packets in packet buffer, delaying processing\n");
#endif
  return;
  }
  
  // Debug log
  fourtuple = packet_format_4tuple(context->temp_pool, buffered_pkt, " ==> ");
  layers = packet_format_layer_info(context->temp_pool, buffered_pkt, " -> ");
  ulog(LLOG_DEBUG, "Statetrans: Processing buffered packet [%s] ts=%"PRIu64"\n", fourtuple, buffered_pkt->timestamp);

  engine_handle_packet(u->engine, context, buffered_pkt, u->log);
}

static void connected(struct context *context) {
  struct user_data *u = context->user_data;
  
  ulog(LLOG_DEBUG, "Statetrans: Connected\n");
  write_t(u->log, "INFO", "uplink_connected_callback - (start)");

  // ask server for config
  write_t(u->log, "INFO", "uplink_connected_callback - Sending C message");
  if(!uplink_plugin_send_message(context, "C", 1)) {
      write_t(u->log, "ERROR", "uplink_connected_callback - C message NOT send!");
  }
  else {
      write_t(u->log, "INFO", "uplink_connected_callback - C message send");
  }
  
  write_t(u->log, "INFO", "uplink_connected_callback - (done)");
}

static void communicate(struct context *context, const uint8_t *data, size_t lenght) {
  struct user_data *u = context->user_data;
  ulog(LLOG_DEBUG, "Statetrans: Communicate\n");
  write_t(u->log, "INFO", "uplink_data_callback - (start)");

  if (!lenght) {
    ulog(LLOG_ERROR, "Statetrans: Empty message from server\n");
    write_t(u->log, "ERROR", "uplink_data_callback - Statetrans: Empty message from server !");
    abort();
  }
  switch (*data) {
    case 'C' :{
      ulog(LLOG_DEBUG, "Statetrans: C (config) message from server\n");
      write_t(u->log, "INFO", "uplink_data_callback - Recieved C message from server");
      
      const struct config_packet *packet = (const struct config_packet *)(data +1);
      
      u->s_treshold = ntohl(packet->p_treshold);
      u->s_learn = ntohl(packet->p_learn);
      
      u->s_treshold_f = (float)((int)u->s_treshold/100.0f);
      
      ulog(LLOG_DEBUG, "Statetrans: Config from server -> Treshold: %f\n", (float)u->s_treshold_f);
      ulog(LLOG_DEBUG, "Statetrans: Config from server -> Learn lenght: %u\n", (unsigned)u->s_learn);
      
      char msg[64];
      snprintf(msg, sizeof msg, "uplink_data_callback - Config from server: Treshold: %.2f, Learn lenght: %u", (float)u->s_treshold_f, (unsigned)u->s_learn);
      write_t(u->log, "INFO", msg);
      
      //update_treshold(u->engine, u->s_treshold_f, u->log);
      
      //start(context);
      
      break;
    }
    case 'B' : {
      write_t(u->log, "INFO", "uplink_data_callback - Recieved B message from server");
      
      if ((sizeof (data-1)) != 17) {
	const struct block_packet_v4 *packet = (const struct block_packet_v4 *)(data +1);
	uint32_t blockip = ntohl(packet->ip_block_v4);

	char msg[128];
	snprintf(msg, sizeof msg, "uplink_data_callback - IP to BLOCK from server: IP: %s", IPAddressToString((int)blockip));
	write_t(u->log, "WARN", msg);
	
	// first we try to delete rule (avoid adding duplicate rules)
	char delete[256];
	snprintf(delete, sizeof delete, "iptables -D INPUT -s %s -j DROP", IPAddressToString((int)blockip));
	int delete_cmd = system(delete);
	
	// then we add FW rule
	char add[256];
	snprintf(add, sizeof add, "sudo iptables -A INPUT -s %s -j DROP", IPAddressToString((int)blockip));
	
	int status = system(add);
	
	char iptables[256];
	if (status == 0) {
	  snprintf(iptables, sizeof iptables, "Created FW rule >> iptables -A INPUT -s %s -j DROP", IPAddressToString((int)blockip));
	  write_t(u->log, "WARN", iptables);
	}
	else {
	  snprintf(iptables, sizeof iptables, "Couldn't crate FW rule >> iptables -A INPUT -s %s -j DROP", IPAddressToString((int)blockip));
	  write_t(u->log, "ERROR", iptables);
	}
	break;
      }
      else {
	const struct block_packet_v6 *packet = (const struct block_packet_v6 *)(data +1);
	uint128_t unblockip = ntohl(packet->ip_block_v6);
	
	char msg[256];
	snprintf(msg, sizeof msg, "uplink_data_callback - MSG size = %u, struct size = %u.....MSG = ,%u,", (sizeof (data-1)), (sizeof (struct block_packet_v4)), data);
	write_t(u->log, "WARN", msg);
		
	break;
      }
    }
    case 'U' : {
      write_t(u->log, "INFO", "uplink_data_callback - Recieved U message from server");
      
      if ((sizeof (data-1)) == (sizeof (struct block_packet_v4))) {
	const struct block_packet_v4 *packet = (const struct block_packet_v4 *)(data +1);
	uint32_t unblockip = ntohl(packet->ip_block_v4);

	char msg[128];
	snprintf(msg, sizeof msg, "uplink_data_callback - UnBlock from server: IP: %s", IPAddressToString((int)unblockip));
	write_t(u->log, "WARN", msg);
	
	char iptables[256];
	snprintf(iptables, sizeof iptables, "iptables -D INPUT -s %s -j DROP", IPAddressToString((int)unblockip));
	
	int status = system(iptables);
        
	snprintf(iptables, sizeof iptables, "Creating FW rule >> iptables -D INPUT -s %s -j DROP", IPAddressToString((int)unblockip));
	write_t(u->log, "WARN", msg);
	
	break;
      }
      else {
	const struct block_packet_v6 *packet = (const struct block_packet_v6 *)(data +1);
	uint128_t unblockip = ntohl(packet->ip_block_v6);
	
	break;
      }
    }
      
    default :
      ulog(LLOG_ERROR, "Statetrans: Invalid opcode from server: %c!\n", (char)*data);
      write_t(u->log, "ERROR", "uplink_data_callback - Recieved Invalid opcode from server !");
      return;
  }
  write_t(u->log, "INFO", "uplink_data_callback - (done)");
}

static void init(struct context *context) {
  ulog(LLOG_DEBUG, "Statetrans: Init\n");
  
#ifdef STATETRANS_DEBUG
  ulog(LLOG_DEBUG, "Statetrans: STATETRANS_DEBUG defined");
#endif	

  context->user_data = mem_pool_alloc(context->permanent_pool, sizeof(struct user_data));
  struct user_data *u = context->user_data;
  
  // logger
  char *tmp = "debug.log";
  u->log = logger_create(context, tmp);
  
  write_t(u->log, "INFO", "init_callback - (start)");

  // We ask server for config on startup
  connected(context);
  
  write_t(u->log, "INFO", "init_callback - Waiting for Config from server");
  
  /*
  char *logfile = "statetrans.log";
  
  u->org_learn     = 60000; // in miliseconds
  u->org_threshold = 0.90;
  
  timeslot_interval_t timeslots[] = {1, 10, 100, 1000, 10000, 100000, 1000000};
  size_t timeslot_cnt = sizeof(timeslots) / sizeof(timeslot_interval_t);
  
  size_t pkt_buf_size = 20;
  u->packet_buf = packet_buffer_create(context->permanent_pool, pkt_buf_size);
  u->engine = engine_create(context, timeslots, timeslot_cnt, u->org_threshold,  logfile, u->log);
  
  loop_timeout_add(context->loop, u->org_learn, context, NULL, timeout);
  */ 
  write_t(u->log, "INFO", "init_callback - (done)");
}

static bool config_check(struct context *context) {
  // return false to fail with "no configuration available" message
    
  struct user_data *u = context->user_data;
  write_t(u->log, "INFO", "config_check_callback (start)");

  const struct config_node *conf = loop_plugin_option_get(context, "threshold");
  if (conf) {
    write_t(u->log, "INFO", "config_check_callback - threshold in config");
  }
  
  conf = loop_plugin_option_get(context, "learn_length");
  if (conf) {
    write_t(u->log, "INFO", "config_check_callback - learn_length in config");
    
    return true;
  }

  write_t(u->log, "ERROR", "config_check_callback - No valid config !");
  write_t(u->log, "INFO", "config_check_callback (done)");
  return false;
}

void finish_config(struct context *context, bool commit) {
  struct user_data *u = context->user_data;

  double threshold;
  int learn_len;
  
  write_t(u->log, "INFO", "config_finish_callback (start)");
  
  // Do nothing on revert
  if (!commit)
    return;

  const struct config_node *conf = loop_plugin_option_get(context, "threshold");
  if (!conf)
    return;
  else {
      for (size_t i = 0; i < 1; i++) {      
      char msg[64];
      snprintf(msg, sizeof msg, "config_check_callback - Threshold loaded: %s", conf->values[i]);
      write_t(u->log, "INFO", msg);
      
      sscanf(conf->values[i], "%lf", &threshold);
      
      u->threshold = threshold;
    }
  }
  
  conf = loop_plugin_option_get(context, "learn_length");
  if (!conf)
    return;
  else {
      for (size_t i = 0; i < 1; i++) {
      char msg[128];
      snprintf(msg, sizeof msg, "config_check_callback - Learning length loaded: %s", conf->values[i]);
      write_t(u->log, "INFO", msg);
      
      sscanf(conf->values[i], "%d", &learn_len);
      // transform seconds into miliseconds
      u->learn = learn_len*1000;
      
      write_t(u->log, "INFO", "config_finish_callback (done)");
      
      // start Engine  
      start(context);
    }
  }
  
  write_t(u->log, "INFO", "config_check_callback (start)");
}

void destroy(struct context *context) {
  struct user_data *u = context->user_data;
  write_t(u->log, "INFO", "finish_callback (start)");
  
  engine_destroy(u->engine, context);
  write_t(u->log, "WARN", "finish_callback (done)");
}

#ifndef STATIC
unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}

#endif
#ifdef STATIC
struct plugin *plugin_info_statetrans(void) {
#else
struct plugin *plugin_info(void) {
#endif
  static struct plugin plugin = {
    .name = "Statetrans",
    .version = 2,
    .init_callback = init,
    .finish_callback = destroy,
    .packet_callback = packet_handle,
    .uplink_data_callback = communicate,
    .uplink_connected_callback = connected,
    .config_check_callback = config_check,
    .config_finish_callback = finish_config
  };
  return &plugin;
}
