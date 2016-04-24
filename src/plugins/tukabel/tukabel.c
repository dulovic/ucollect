/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/packet.h"

//#define PLUGLIB_DO_IMPORT PLUGLIB_LOCAL
//#include "../../core/pluglib.h"
//#include "../../core/pluglib_macros.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

// printf formatter for uint64_t
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

static void timeout(struct context *context, void *data __attribute__((unused)), size_t id __attribute__((unused))) {
	ulog(LLOG_WARN, "TUKABEL timeout\n");
	loop_timeout_add(context->loop, 1000, context, NULL, timeout);
}

static void init(struct context *context) {
	ulog(LLOG_WARN, "TUKABEL init\n");
	//timeout(context, NULL, 0);
}

#ifndef STATIC
unsigned api_version() {
	ulog(LLOG_WARN, "TUKABEL api_version\n");
	return UCOLLECT_PLUGIN_API_VERSION;
}
#endif

static void packet_handle(struct context *context, const struct packet_info *info) {
	ulog(LLOG_WARN, "TUKABEL packet_handle ------\n");
	char *buf = mem_pool_alloc(context->temp_pool, 2000);

	// ---- GENERAL PACKET INFO ----
	sprintf(buf, "Packet(");
	
	// Textual name of the interface it was captured on
	sprintf(buf, "%s int:%s", buf, info->interface);

	/* Length and raw data of the packet (starts with IP header or similar on the same level)
	 *
	 * Length of headers (IP+TCP (or equivalent) together).
	 * Can be used to find application data.
	 *
	 * This is 0 in case ip_protocol != 4 && 6 or app_protocol != 'T' && 'U'.
	 */
	sprintf(buf, "%s len=%zu hdr_len=%zu", buf, info->length, info->hdr_length);

	// Direction of the packet.
	char * dir = NULL;
	switch (info->direction) {
		case DIR_IN:
			dir = "in";
			break;
		case DIR_OUT:
			dir = "out";
			break;
		default:
			dir = "unknown";
			break;
	}
	sprintf(buf, "%s, dir=%s", buf, dir);
	
	// Packet timestamp in microseconds since epoch
	struct timeval tv = {
		.tv_sec = (time_t) info->timestamp / 1000000,
		.tv_usec = (suseconds_t) info->timestamp % 1000000,
	};	
	struct tm * tm = localtime(&tv.tv_sec);
	char tbuf[20];
	strftime(tbuf, sizeof(tbuf), "%F %T", tm);
	sprintf(buf, "%s\n  ts=%s.%lu (%" PRIu64 ")", buf, tbuf, tv.tv_usec, info->timestamp);
	sprintf(buf, "%s\n", buf);

	// ---- L2 - L4 info ----

	const struct packet_info *pi = info;
	while (pi) {
		/*
		 * The layer of the packet:
		 * - 'E': Ethernet.
		 * - 'I': IP layer.
		 * - 'S': Linux SLL.
		 * - '?': Some other layer (unknown).
		 */	
		sprintf(buf, "%s  layer=%c(raw=%#x)", buf, pi->layer, pi->layer_raw);
		sprintf(buf, "%s vlan=%hu", buf, (int)pi->vlan_tag); 
		sprintf(buf, "%s ipver=%hhu", buf, pi->ip_protocol); // 4 for IPv4, 6 for IPv6
		sprintf(buf, "%s\n   ", buf);

		// Addresses
		char ip6str[INET6_ADDRSTRLEN];
		if (pi->addr_len) {
			switch(pi->layer) {
			case 'E':
				sprintf(buf, "%s eth.src=%s", buf, ether_ntoa((struct ether_addr*)pi->addresses[END_SRC]));
				sprintf(buf, "%s eth.dst=%s", buf, ether_ntoa((struct ether_addr*)pi->addresses[END_DST]));
				break;

			case 'I':
				switch(pi->ip_protocol) {
				case 4:
					sprintf(buf, "%s ipv4.src=%s", buf, inet_ntoa(*(struct in_addr*)pi->addresses[END_SRC]));
					sprintf(buf, "%s ipv4.dst=%s", buf, inet_ntoa(*(struct in_addr*)pi->addresses[END_DST]));
					break;
			
				case 6:
					inet_ntop(AF_INET6, pi->addresses[END_SRC], ip6str, INET6_ADDRSTRLEN);
					sprintf(buf, "%s ipv6.src=%s", buf, ip6str);
					inet_ntop(AF_INET6, pi->addresses[END_DST], ip6str, INET6_ADDRSTRLEN);
					sprintf(buf, "%s ipv6.dst=%s", buf, ip6str);
					break;

				default:
					sprintf(buf, "%s addr_len=%hhu", buf, pi->addr_len);
					break;
				}	
				break;

			default:
				sprintf(buf, "%s addr_len=%hhu(a=%c)", buf, pi->addr_len, pi->app_protocol);
				break;
			}
		}
		
		// TCP/UDP Ports
		if (pi->app_protocol == 'T' || pi->app_protocol == 'U') {
			sprintf(buf, "%s sport=%hu, dport=%hu)", buf,
				pi->ports[END_SRC],
				pi->ports[END_DST]
			);
		}
		if (pi->app_protocol == 'T') {
			sprintf(buf, "%s tcp.flags=%#hhx", buf, pi->tcp_flags);
		}

		/*
		 * The application-facing protocol. Currently, these are recognized for IP layer:
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
		 * These are on the ethernet and SLL layer:
		 * - 'I': An IP packet is below.
		 * - 'A': ARP.
		 * - 'R': Reverse ARP.
		 * - 'W': Wake On Lan
		 * - 'X': IPX
		 * - 'E': EAP
		 * - 'P': PPPoE
		 * - '?': Unrecognized
		 * Beware that we may add more known protocols in future.
		 */
		if (pi->ip_protocol == 4 || pi->ip_protocol == 6) {
			sprintf(buf, "%s app=%c(raw=%hhu)", buf, pi->app_protocol, pi->app_protocol_raw);
		}
		if (pi->layer == 'E' || pi->layer == 'S') {
			sprintf(buf, "%s app=%c(raw=%hhu)", buf, pi->app_protocol, pi->app_protocol_raw);
		}
		sprintf(buf, "%s\n", buf);
		
		pi = pi->next;
	}
	ulog(LLOG_WARN, " # %s\n", buf);

	//ulog(LLOG_WARN, "nasrac nevyrucil som sebe\n");
	return;

}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	ulog(LLOG_WARN, "TUKABEL communicate\n");
}

static bool config_check(struct context *context) {	
	// return false to fail with "no configuration available" message

	const struct config_node *conf = loop_plugin_option_get(context, "test");
	ulog(LLOG_WARN, "TUKABEL: There are %zu options\n", conf ? conf->value_count : 0);
	if (conf) {
		for (size_t i = 0; i < conf->value_count; i++)
			ulog(LLOG_WARN, "  Val: %s\n", conf->values[i]);
	}
	conf = loop_plugin_option_get(context, "Test3");
	if (conf) {
		ulog(LLOG_ERROR, "Test3 is available\n");
		return true;
	}
	ulog(LLOG_ERROR, "<--------------------->\n");
	return true;
}

static void config_finish(struct context *context, bool activate) {
	(void)context;
	ulog(LLOG_WARN, "TUKABEL finish, activate: %d\n", (int)activate);
}

void destroy(struct context *context) {
	ulog(LLOG_WARN, "TUKABEL destroy\n");
	// from Majordomo
	//dump(context);
}

#ifdef STATIC
struct plugin *plugin_info_tukabel(void) {
#else
struct plugin *plugin_info(void) {
#endif
	ulog(LLOG_WARN, "TUKABEL plugin_info\n");
	//static struct pluglib_import *imports[] = {
	//	&hello_world_import,
	//	NULL
	//};
	static struct plugin plugin = {
		.name = "TUKABEL, nasrac abo dajaky ZLOBR",
		.version = 1,
		//.imports = imports,
		.init_callback = init,
		.finish_callback = destroy, 
		.packet_callback = packet_handle,
		.uplink_data_callback = communicate,
		.config_check_callback = config_check,
		.config_finish_callback = config_finish
	};
	return &plugin;
}
