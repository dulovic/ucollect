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


#ifndef UCOLLECT_STATETRANS_PACKET_BUFFER_H
#define UCOLLECT_STATETRANS_PACKET_BUFFER_H

#include "../../core/mem_pool.h"
#include "../../core/packet.h"

/*
	Used to buffer deep copies of last packets to eliminate problem with
	order of packet caused by asynchronous pcap id two directions.
 */


struct packet_buffer;

struct packet_buffer *packet_buffer_create(struct mem_pool *pool, size_t size);

// Adds pkt to buffer (deep copy is created) and returns the oldes pkt only if the buffer is full
struct packet_info *packet_buffer_add(struct packet_buffer *pb, const struct packet_info *pkt);


#endif /* UCOLLECT_STATETRANS_PACKET_BUFFER_H */

