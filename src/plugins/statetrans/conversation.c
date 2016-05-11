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

#include "conversation.h"

size_t conversation_addr_len(struct conversation_id *conv) {
    switch(conv->ip_protocol) {
        case 4:
            return 4;
            break;
            
        case 6:
            return 16;
            break;
    }
    return 0; // Not IP or invalid value
}

// Create conversation identifier from packet info
void conversation_extract_identifier(struct conversation_id *identif, struct mem_pool *pool, const struct packet_info *pkt) {
    identif->ip_protocol = pkt->ip_protocol;
    
    identif->src_ip = mem_pool_alloc(pool, pkt->addr_len);
    memcpy(identif->src_ip, pkt->addresses[END_SRC]);
    identif->dst_ip = mem_pool_alloc(pool, pkt->addr_len);
    memcpy(identif->dst_ip, pkt->addresses[END_DST]);
        
    identif->src_port = pkt->ports[END_SRC];
    identif->dst_port = pkt->ports[END_DST];
    
    identif->app_protocol = pkt->app_protocol;
}

