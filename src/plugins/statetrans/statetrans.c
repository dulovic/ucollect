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

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/util.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/trie.h"
#include "../../core/packet.h"

#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>

// printf formatter for uint64_t
#define __STDC_FORMAT_MACROS
#include <inttypes.h>

struct user_data {
	bool active;
	struct mem_pool *active_pool, *standby_pool; // One pool to allocate the trie from, another to be able to copy some data to when cleaning the first one
	
};

static void timeout(struct context *context, void *data __attribute__((unused)), size_t id __attribute__((unused))) {
	ulog(LLOG_WARN, "TUKABEL timeout\n");
	loop_timeout_add(context->loop, 1000, context, NULL, timeout);
}

static void init(struct context *context) {
	//timeout(context, NULL, 0);
}


static void packet_handle(struct context *context, const struct packet_info *info) {
	ulog(LLOG_WARN, "TUKABEL packet_handle ------\n");
	char *buf = mem_pool_alloc(context->temp_pool, 2000);
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
	return true;
}

static void config_finish(struct context *context, bool activate) {
	(void)context;
	ulog(LLOG_WARN, "TUKABEL finish, activate: %d\n", (int)activate);
}

void destroy(struct context *context) {
	ulog(LLOG_WARN, "TUKABEL destroy\n");
}

#ifndef STATIC
unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}

#endif
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
		.name = "Statetrans",
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
