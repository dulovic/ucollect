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

#ifndef UCOLLECT_STATETRANS_CONVERSATION_H
#define UCOLLECT_STATETRANS_CONVERSATION_H

#include "../../core/packet.h"
#include "../../core/mem_pool.h"

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct profile_key;

// Identifier made up from field in struct packet (core/packet.h)
struct conversation_id {
    // If v6 == true addr_len is 16, else 4
    bool v6;
    
    const void *src_ip;
    const void *dst_ip;
    
    uint16_t src_port;
    uint16_t dst_port;
    
    uint8_t *profile_key;
    uint8_t profile_key_len;
    
    // ('T' - TCP, 'U' - UDP, 'I' - ICMP) - removed
    //char app_protocol;  
};

size_t conversation_id_addr_len(struct conversation_id *conv);
void conversation_id_from_packet(struct conversation_id *conv, struct mem_pool *pool, const struct packet_info *pkt);
char *conversation_id_format_4tuple(struct mem_pool *pool, const struct conversation_id *conv, const char *arrow);


char *format_ip4(struct mem_pool *pool, const uint8_t *ip);
char *format_ip6(struct mem_pool *pool,const uint8_t *ip);
char *format_ip(struct mem_pool *pool,const uint8_t *ip, bool ip4);
char *format_mac(struct mem_pool *pool,const uint8_t *mac);
char *format_4tuple(struct mem_pool *pool,const uint8_t *ip1, uint16_t port1, const uint8_t *ip2, uint16_t port2, bool ipv4, const char *arrow);
char *packet_format_4tuple(struct mem_pool *pool, const struct packet_info *pkt, const char *arrow);
char *packet_format_layer_info(struct mem_pool *pool, const struct packet_info *pkt, const char *arrow);

#endif
