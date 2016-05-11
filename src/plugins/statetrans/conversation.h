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

/*
init(sm_list, evaluator_list)

// use loader.h pluglib_load() - returns struct returned by pluglib_info() in lib
load_plugin()
	load_statemachine()
	load_evaluator()

handle_packet()
*/



// Identifier made up from field in struct packet (core/packet.h)
struct conversation_id {
    // If ip_protocol == 4 addr_len is 4, if ip_protocol == 6 addr_len = 16
    unsigned char ip_protocol;
    
    const void *src_ip;
    const void *dst_ip;
    
    uint16_t src_port;
    uint16_t dst_port;
    
    // 'T' - TCP, 'U' - UDP, 'I' - ICMP
    char app_protocol;  
};

size_t conversation_addr_len(struct conversation_id *conv);
void conversation_extract_identifier(const packet_info *pkt);


#endif
