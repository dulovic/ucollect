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

#include "conversation.h"

#include "../../core/util.h"

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

size_t conversation_id_addr_len(struct conversation_id *conv) {
	if (!conv)
		return 0;
	
	return (conv->v6) ? 16 : 4;
}

// Create conversation identifier from packet info
void conversation_id_from_packet(struct conversation_id *conv, struct mem_pool *pool, const struct packet_info *pkt) {
	const struct packet_info *p;
	bool found;
	
	// Find Ethernet layer & extract local MAC as key
	found = false;
	for (p = pkt; p != NULL; p = p->next) {

		if (p->layer == 'E') { // Found Ethernet layer
			enum endpoint local_ep = local_endpoint(p->direction);
			conv->profile_key_len = (uint8_t) p->addr_len;
			conv->profile_key = mem_pool_alloc(pool, conv->profile_key_len);
			memcpy(conv->profile_key, p->addresses[local_ep], conv->profile_key_len);
			
			found = true;
			break;
		}
	}
	if (!found) {
		conv->profile_key = NULL;
		conv->profile_key_len = 0;
	}
	
	// Find IP layer with TCP & extract info
	found = false;
	for (p = pkt; p != NULL; p = p->next) {
		if (p->app_protocol == 'T') {
			// IP version (to get addr_len)
			conv->v6 = (p->ip_protocol == 6);

			// IP addresses
			if (p->ip_protocol) {
				conv->src_ip = mem_pool_alloc(pool, p->addr_len);
				memcpy((void *) conv->src_ip, p->addresses[END_SRC], p->addr_len);
				conv->dst_ip = mem_pool_alloc(pool, p->addr_len);
				memcpy((void *) conv->dst_ip, p->addresses[END_DST], p->addr_len);
			} else {
				conv->src_ip = NULL;
				conv->dst_ip = NULL;
			}

			// Ports
			conv->src_port = p->ports[END_SRC];
			conv->dst_port = p->ports[END_DST];

			// App ('T' - TCP, 'U' - UDP, 'I' - ICMP) - removed
			//conv->app_protocol = pkt->app_protocol;
			
			found = true;
			break;
		}
	}
	if (!found) {
		conv->v6 = false;
		conv->src_ip = NULL;
		conv->dst_ip = NULL;
		conv->src_port = 0;
		conv->dst_port = 0;
		//conv->app_protocol = '?'; // removed
	}
}

char *format_ip4(struct mem_pool *pool, const uint8_t *ip) {
	if (!ip)
		return "[null]";
	
	return mem_pool_printf(pool, "%hhu.%hhu.%hhu.%hhu", ip[0], ip[1], ip[2], ip[3]);
}

char *format_ip6(struct mem_pool *pool,const uint8_t *ip) {
	if (!ip)
		return "[null]";
	
	char *buf = mem_pool_alloc(pool, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, ip, buf, INET6_ADDRSTRLEN);
	
	return buf;
}

char *format_ip(struct mem_pool *pool,const uint8_t *ip, bool ip4) {
	if (ip4)
		return format_ip4(pool, ip);
	
	return format_ip6(pool, ip);
}

char *format_mac(struct mem_pool *pool,const uint8_t *mac) {
	return mem_pool_printf(pool, "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

char *format_4tuple(struct mem_pool *pool,const uint8_t *ip1, uint16_t port1, const uint8_t *ip2, uint16_t port2, bool ipv4, const char *arrow) {
	char *buf;
	buf = mem_pool_printf(pool, "%s:%hu%s%s:%hu",
		format_ip(pool, ip1, ipv4),
		port1,
		arrow,
		format_ip(pool, ip2, ipv4),
		port2
	);
	
	return buf;	
}

char *conversation_id_format_4tuple(struct mem_pool *pool, const struct conversation_id *conv, const char *arrow) {
	char *buf;
	buf = format_4tuple(pool,
		conv->src_ip,
		conv->src_port,
		conv->dst_ip,
		conv->dst_port,
		! conv->v6,
		arrow
	);
	
	return buf;
}

char *packet_format_4tuple(struct mem_pool *pool, const struct packet_info *pkt, const char *arrow) {
	char *buf;
	
	while (pkt && !pkt->ip_protocol)
		pkt = pkt->next;
	
	if (!pkt || !pkt->ip_protocol)
	{
		buf  = mem_pool_printf(pool, "[NOT IP]");
	} else {
		buf = format_4tuple(pool,
			pkt->addresses[END_SRC],
			pkt->ports[END_SRC],
			pkt->addresses[END_DST],
			pkt->ports[END_DST],
			(pkt->addr_len == 4),
			arrow
		);
	}
	
	return buf;
}

char *packet_format_layer_info(struct mem_pool *pool, const struct packet_info *pkt, const char *arrow) {
	char *buf = NULL;
	while (pkt) {
		if (buf)
			buf = mem_pool_printf(pool, "%s%s(%c,%c)", buf, arrow, pkt->layer, pkt->app_protocol);
		else
			buf = mem_pool_printf(pool, "(%c,%c)", pkt->layer, pkt->app_protocol);
		
		pkt = pkt->next;
	}

	return buf;
}

// Martin

uint16_t dst_port(const struct packet_info *pkt) {
  uint16_t d_p;
  
  while (pkt && !pkt->ip_protocol)
    pkt = pkt->next;
  
  if (!pkt || !pkt->ip_protocol) {
    //|TODO
  }
  else {
     d_p = pkt->ports[END_DST];
  }
  return d_p;
}

uint16_t src_port(const struct packet_info *pkt) {
  uint16_t d_p;
  
  while (pkt && !pkt->ip_protocol)
    pkt = pkt->next;
  
  if (!pkt || !pkt->ip_protocol) {
    //|TODO
  }
  else {
     d_p = pkt->ports[END_SRC];
  }
  return d_p;
}

char pkt_direction(const struct packet_info *pkt) {
  switch (pkt->direction) {
    case DIR_IN:
      return 'I';
      break;	    
    case DIR_OUT:
      return 'O';
      break;
  
    default:
      return 'U';
  }
}

uint8_t *dst_ip_conv(struct mem_pool *pool, const struct conversation_id *conv) {
  return conv->dst_ip;
}

uint8_t *src_ip_conv(struct mem_pool *pool, const struct conversation_id *conv) {
  return conv->src_ip;
}

uint16_t dst_port_conv(struct mem_pool *pool, const struct conversation_id *conv) {
  return conv->dst_port;
}

uint16_t src_port_conv(struct mem_pool *pool, const struct conversation_id *conv) {
  return conv->src_port;
}