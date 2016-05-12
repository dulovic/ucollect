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

#include "packet_buffer.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define MAX_ADDR_LEN 16


// Struct to keep packet_info (2 nested layers) 
struct packet_buffer_node {
	uint64_t ts;
	bool used;
	
	// Packets
	struct packet_info p_inner, p_outer;
	
	//Addresses
	uint8_t a_outer1[MAX_ADDR_LEN];
	uint8_t a_outer2[MAX_ADDR_LEN];
	uint8_t a_innter1[MAX_ADDR_LEN];
	uint8_t a_innter2[MAX_ADDR_LEN];
};


struct packet_buffer {
	// Size of buffer
	size_t size;
	// Number of ocupied entries
	size_t pkt_count;
	
	// Arrray of node kept
	struct packet_buffer_node *nodes;
};

// Prototypes
static void packet_buffer_create_item(struct packet_buffer_node *n, const struct packet_info *pkt);
static void packet_buffer_copy_pkt(struct packet_info *dest_pkt, uint8_t *a1, uint8_t *a2, const struct packet_info *pkt);
static size_t packet_buffer_get_oldes_index(struct packet_buffer *pb);

struct packet_buffer *packet_buffer_create(struct mem_pool *pool, size_t size) {
	struct packet_buffer *pb = mem_pool_alloc(pool, sizeof(struct packet_buffer));
	pb->size = size;
	pb->pkt_count = 0;
	
	pb->nodes = mem_pool_alloc(pool, size * sizeof(struct packet_buffer_node));
	size_t i;
	for (i = 0; i < size; i++) {
		pb->nodes[i].used = false;
	}
	
	return pb;
}

struct packet_info *packet_buffer_add(struct packet_buffer *pb, const struct packet_info *pkt) {
	// Find unused item (one must be unused)
	size_t i = 0;
	while (pb->nodes[i].used) {
		i++;
		assert(i < pb->size);
	}
	
	// Copy values
	packet_buffer_create_item(&pb->nodes[i], pkt);
	pb->nodes[i].used = true;
	pb->pkt_count++;
	
	// If full return the oldest pkt & mark as unused
	if (pb->pkt_count >= pb->size) {
		size_t i_oldest = packet_buffer_get_oldes_index(pb);
		
		pb->nodes[i_oldest].used = false; // "free"
		pb->pkt_count--;
		
		return &pb->nodes[i_oldest].p_outer;
	}
	
	
	// Not full yet
	return NULL;
}

// Create deep copy
static void packet_buffer_create_item(struct packet_buffer_node *n, const struct packet_info *pkt) {
	// Copy outer pkt
	packet_buffer_copy_pkt(&n->p_outer, n->a_outer1, n->a_outer2, pkt);
	
	
	// Copy inner pkt
	if (pkt->next) {
		packet_buffer_copy_pkt(&n->p_inner, n->a_innter1, n->a_innter2, pkt->next);
		n->p_outer.next = &n->p_inner;
	}
	n->used = true;
	n->ts = pkt->timestamp;	
}

static void packet_buffer_copy_pkt(struct packet_info *dest_pkt, uint8_t *a1, uint8_t *a2, const struct packet_info *pkt) {
	memcpy(dest_pkt, pkt, sizeof(struct packet_info));
	dest_pkt->data = NULL;
	dest_pkt->next = NULL;
	
	// Addresses
	assert(MAX_ADDR_LEN >= pkt->addr_len);
	memcpy(a1, pkt->addresses[END_SRC], pkt->addr_len);
	dest_pkt->addresses[END_SRC] = a1;
	memcpy(a2, pkt->addresses[END_DST], pkt->addr_len);
	dest_pkt->addresses[END_DST] = a2;
}


// Look for the oldes pkt in full buffer
static size_t packet_buffer_get_oldes_index(struct packet_buffer *pb) {
	size_t i, i_oldest = 0;
	for (i = 1; i < pb->size; i++) {
		if (pb->nodes[i].ts < pb->nodes[i_oldest].ts)
			i_oldest = i;
	}
	
	return i_oldest;
}