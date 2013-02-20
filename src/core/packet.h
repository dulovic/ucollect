#ifndef UCOLLECT_PACKET_H
#define UCOLLECT_PACKET_H

#include <stddef.h>
#include <stdint.h>

// Some forward declarations
struct mem_pool;
struct address_list;

// One endpoint of communication.
enum endpoint {
	END_SRC,  // The source endpoint
	END_DST,  // The destination endpoint
	END_COUNT // Not a real endpoint, but a stop-mark to know the count.
};

// Direction of the packet
enum direction {
	DIR_IN,		// The packet goes in
	DIR_OUT,        // The packet goes out
	DIR_UNKNOWN,    // Can't guess the direction (it might be a packet in internal network)
	DIR_COUNT       // Not a real direction, a stop-mark.
};

struct packet_info {
	// The parsed embedded packet, in case of app_protocol == '4' || '6'
	const struct packet_info *next;
	// Length and raw data of the packet (starts with IP header or similar on the same level)
	size_t length;
	const void *data;
	// Textual name of the interface it was captured on
	const char *interface;
	/*
	 * Length of headers (IP+TCP (or equivalent) together).
	 * Can be used to find application data.
	 *
	 * This is 0 in case ip_protocol != 4 && 6 or app_protocol != 'T' && 'U'.
	 */
	size_t hdr_length;
	/*
	 * Source and destination address. Raw data (addr_len bytes each).
	 * Is set only with ip_protocol == 4 || 6, otherwise it is NULL.
	 */
	const void *addresses[END_COUNT];
	/*
	 * Source and destination ports. Converted to the host byte order.
	 * Filled in only in case the app_protocol is T or U. Otherwise, it is 0.
	 */
	uint16_t ports[END_COUNT];
	// As in iphdr, 6 for IPv6, 4 for IPv4. Others may be present.
	unsigned char ip_protocol;
	/*
	 * The application-facing protocol. Currently, these are recognized:
	 * - 'T': TCP
	 * - 'U': UDP
	 * - 'i': ICMP
	 * - 'I': ICMPv6
	 * - '4': Encapsulated IPv4 packet
	 * - '6': Encapsulated IPv6 packet
	 * - '?': Other, not recognized protocol.
	 *
	 * This is set only with ip_protocol == 4 || 6, otherwise it is
	 * zero.
	 *
	 * Beware that we may add more known protocols in future.
	 */
	char app_protocol;
	/*
	 * The raw byte specifying what protocol is used below IP. The app_proto
	 * is more friendly.
	 *
	 * In case the ip_protocol is not 4 nor 6, it 255 (which is "Reserved").
	 */
	uint8_t app_protocol_raw;
	// Length of one address field. 0 in case ip_protocol != 4 && 6
	unsigned char addr_len;
	// Direction of the packet.
	enum direction direction;
};

/*
 * Parse the stuff in the passed packet. It expects length and data are already
 * set, it fills the addresses, protocols, etc. The local_addresses are used to
 * guess the direction of the packet.
 */
void parse_packet(struct packet_info *packet, const struct address_list *local_addresses, struct mem_pool *pool) __attribute__((nonnull));

/*
 * Which endpoint is the remote one for the given direction?
 *
 * This returns END_COUNT in case the direction is not DIR_IN or DIR_OUT.
 */
static inline enum endpoint remote_endpoint(enum direction direction) {
	switch (direction) {
		case DIR_IN:
			return END_SRC;
		case DIR_OUT:
			return END_DST;
		default:
			return END_COUNT;
	}
}

#endif