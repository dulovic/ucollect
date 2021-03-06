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

#include "type.h"
#include "queue.h"

#define PLUGLIB_DO_IMPORT PLUGLIB_LOCAL
#include "../../libs/diffstore/diff_store.h"

#include "../../core/plugin.h"
#include "../../core/context.h"
#include "../../core/mem_pool.h"
#include "../../core/loop.h"
#include "../../core/uplink.h"
#include "../../core/util.h"
#include "../../core/trie.h"

#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>

enum set_state {
	SS_VALID,	// The set is valid and up to date, or a diff update would be enough. Propagate changes to the kernel.
	SS_PENDING,	// The set needs data from server, the local storage is empty. Not sending this to the kernel.
	SS_DEAD,	// Set previously available, but is no longer present in the config. It shall be deleted soon from the kernel.
	SS_DEAD_PENDING,// Like dead, but it was pending before.
	SS_COPIED,	// The set is copied into a newer storage. This one can be dropped, but leave it intact in kernel.
	SS_NEWBORN	// Set that was just received from config and needs to be created in the kernel.
};

struct set {
	const char *name;
	// When we replace the content, we do so in a temporary set we'll switch afterwards. This is the temporary name.
	const char *tmp_name;
	enum set_state state;
	const struct set_type *type;
	size_t max_size, hash_size;
	struct diff_addr_store *store;
	struct context *context; // Filled in before each call on a function manipulating the set. It is needed inside the hooks.
};

struct user_data {
	struct mem_pool *conf_pool, *standby_pool;
	struct queue *queue;
	bool configured;
	uint32_t config_version; // Stored in network byte order. We compare only for equality.
	size_t set_count;
	struct set *sets;
	// Cache of the query to the kernel what sets exist.
	const char **existing_sets;
	size_t existing_set_count;
};

// Check if a set exists in kernel. The query to kernel is cached.
static bool set_exists(struct context *context, const char *name) {
	struct user_data *u = context->user_data;
	if (!u->existing_sets) {
		ulog(LLOG_DEBUG, "Asking kernel for a list of IPsets\n");
		int pipes[2];
		sanity(pipe(pipes) == 0, "Couldn't create ipset pipe: %s\n", strerror(errno));
		/*
		 * Register just to make sure it isn't leaked if we crash here.
		 * It will get unregistered before it causes any callbacks.
		 */
		loop_plugin_register_fd(context, pipes[0], NULL);
		pid_t pid = loop_fork(context->loop);
		if (pid == 0) {
			// We are the child here. Screw the pipe to our stdout and exec.
			sanity(dup2(pipes[1], 1) != -1, "Failed to dup the ipset pipe: %s\n", strerror(errno));
			sanity(close(pipes[1]) != -1, "Failed to close the ipset child write end: %s\n", strerror(errno));
			sanity(execl("/usr/sbin/ipset", "ipset", "-n", "list", (char *)NULL) != -1, "Exec to ipset -n list failed: %s\n", strerror(errno));
		}
		sanity(close(pipes[1]) != -1, "Failed to close the ipset write pipe end: %s\n", strerror(errno));
		sanity(pid != -1, "Failed to fork ipset -n list: %s\n", strerror(errno));
		// Read the output, into a double-growing buffer
		size_t block = 1000, pos = 0;
		char *output = NULL;
		bool eof = false;
		while (!eof) {
			char *new = mem_pool_alloc(context->temp_pool, block);
			block *= 2;
			memcpy(new, output, pos);
			output = new;
			ssize_t res = read(pipes[0], output + pos, block - pos - 1);
			sanity(res != -1, "Failed to read output of ipset -n list: %s\n", strerror(errno));
			if (res == 0) {
				eof = true;
			} else {
				pos += res;
			}
			sanity(pos < block, "Confused sizes, %zu bytes in buffer of %zu bytes\n", pos, block);
		}
		output[pos] = '\0';
		loop_plugin_unregister_fd(context, pipes[0]);
		sanity(close(pipes[0]) != -1, "Failed to close the ipset read pipe end: %s\n", strerror(errno));
		// Wait for the termination of the child process
		int status;
		pid_t terminated = waitpid(pid, &status, 0);
		sanity(pid == terminated, "Wrong PID returned/error? %d/%s\n", (int)terminated, strerror(errno));
		sanity(WIFEXITED(status) && WEXITSTATUS(status) == 0, "The ipset -n list died: %d\n", status);
		// Split the output to lines
		// Count the number of lines first
		size_t count = 1;
		for (size_t i = 0; i < pos; i ++)
			if (output[i] == '\n')
				count ++;
		const char **positions = mem_pool_alloc(context->temp_pool, count);
		size_t lcount = 0;
		positions[lcount ++] = output;
		for (size_t i = 0; i < pos; i ++)
			if (output[i] == '\n') {
				output[i] = '\0';
				positions[lcount ++] = &output[i + 1];
			}
		sanity(lcount == count, "Mismatch of newline count, %zu vs %zu\n", lcount, count);
		u->existing_sets = positions;
		u->existing_set_count = count;
	}
	for (size_t i = 0; i < u->existing_set_count; i ++)
		if (strcmp(name, u->existing_sets[i]) == 0)
			return true;
	return false;
}

static void set_create(struct context *context, struct set *set) {
	/*
	 * Don't try to create the set if it pre-exists.
	 * It may be the correct type but wrong size,
	 * which is OK (we'll swap it), but it would produce error here.
	 */
	if (!set_exists(context, set->name))
		enqueue(context, context->user_data->queue, mem_pool_printf(context->temp_pool, "create %s %s family %s hashsize %zu maxelem %zu\n", set->name, set->type->desc, set->type->family, set->hash_size, set->max_size));
}

static void connected(struct context *context) {
	// Just ask for config
	uplink_plugin_send_message(context, "C", 1);
}

struct config {
	uint32_t version;
	uint32_t set_count;
} __attribute__((packed));

static void addr_cmd(struct diff_addr_store *store, const char *cmd, const uint8_t *addr, size_t length) {
	struct set *set = store->userdata;
	char *composed = mem_pool_printf(set->context->temp_pool, "%s %s %s\n", cmd, set->tmp_name ? set->tmp_name : set->name, set->type->addr2str(addr, length, set->context->temp_pool));
	// If we have the port, we need to push both tcp and udp. The XXX is a mark.
	char *proto = strstr(composed, "XXX");
	if (proto) {
		memcpy(proto, "tcp", 3);
		enqueue(set->context, set->context->user_data->queue, composed);
		memcpy(proto, "udp", 3);
		enqueue(set->context, set->context->user_data->queue, composed);
	} else {
		enqueue(set->context, set->context->user_data->queue, composed);
	}
}

static void add_item(struct diff_addr_store *store, const uint8_t *addr, size_t length) {
	addr_cmd(store, "add", addr, length);
}

static void remove_item(struct diff_addr_store *store, const uint8_t *addr, size_t length) {
	addr_cmd(store, "del", addr, length);
}

static void replace_start(struct diff_addr_store *store) {
	// In the replace start hook, we prepare a temporary set. All the data are going to be filled into the temporary set and then we switch the sets.
	struct set *set = store->userdata;
	sanity(!set->tmp_name, "Replace already started\n");
	struct mem_pool *tmp_pool = set->context->temp_pool;
	// It is OK to allocate the data from the temporary memory pool. It's lifetime is at least the length of call to the plugin communication callback, and the whole set replacement happens there.
	set->tmp_name = mem_pool_printf(tmp_pool, "%s-rep", set->name);
	// Make sure the real set exists ‒ we may have missed it in case of broken queue
	set_create(set->context, set);
	// Delete any previous instance if it is left there, to prevent problems with creating.
	if (set_exists(set->context, set->tmp_name))
		enqueue(set->context, set->context->user_data->queue, mem_pool_printf(tmp_pool, "destroy %s\n", set->tmp_name));
	enqueue(set->context, set->context->user_data->queue, mem_pool_printf(tmp_pool, "create %s %s family %s hashsize %zu maxelem %zu\n", set->tmp_name, set->type->desc, set->type->family, set->hash_size, set->max_size));
}

static void replace_end(struct diff_addr_store *store) {
	struct set *set = store->userdata;
	sanity(set->tmp_name, "Replace started already\n");
	struct mem_pool *tmp_pool = set->context->temp_pool;
	struct queue *queue = set->context->user_data->queue;
	// Swap the sets and drop the temporary one
	enqueue(set->context, queue, mem_pool_printf(tmp_pool, "swap %s %s\n", set->name, set->tmp_name));
	enqueue(set->context, queue, mem_pool_printf(tmp_pool, "destroy %s\n", set->tmp_name));
	set->tmp_name = NULL;
}

static void store_set_hooks(struct set *set) {
	set->store->add_hook = add_item;
	set->store->remove_hook = remove_item;
	set->store->replace_start_hook = replace_start;
	set->store->replace_end_hook = replace_end;
	set->store->userdata = set;
}

static bool set_parse(struct mem_pool *pool, struct set *target, const uint8_t **data, size_t *length) {
	char *name;
	uint8_t t;
	uint32_t max_size;
	uint32_t hash_size;
	uplink_parse(data, length, "scuu",
			&name, NULL, pool, "set name in FWUp config",
			&t, "set type in FWUp config",
			&max_size, "max size of set in FWUp config",
			&hash_size, "hash size of set in FWUp config");
	const struct set_type *type = &set_types[t];
	if (!type->desc) {
		ulog(LLOG_WARN, "Set %s of unknown type '%c' (%hhu), ignoring\n", name, t, t);
		return false;
	}
	*target = (struct set) {
		.name = name,
		.type = type,
		.state = SS_NEWBORN,
		.max_size = max_size,
		.hash_size = hash_size,
		.store = diff_addr_store_init(pool, name)
	};
	store_set_hooks(target);
	return true;
}

static void version_ask(struct context *context, const char *setname) {
	size_t len;
	const uint8_t *message = uplink_render_alloc(&len, 0, context->temp_pool, "cs", 'A' /* 'A'sk for a version */, setname, strlen(setname));
	// Ignore success result ‒ if it fails, it's because we aren't connected. We shall ask again once we connect.
	uplink_plugin_send_message(context, message, len);
}

static void set_reload(struct context *context, struct set *set);

static void config_parse(struct context *context, const uint8_t *data, size_t length) {
	struct config c;
	sanity(length >= sizeof c, "Not enough FWUp data for config, got %zu, needed %zu\n", length, sizeof c);
	memcpy(&c, data, sizeof c); // Need to copy it out, because of alignment
	struct user_data *u = context->user_data;
	if (u->config_version == c.version) {
		ulog(LLOG_DEBUG, "FWUp config up to date\n");
		for (size_t i = 0; i < u->set_count; i ++)
			version_ask(context, u->sets[i].name);
		return;
	}
	// Some preparations
	data += sizeof c;
	length -= sizeof c;
	// OK. We're loading the new config. First, parse which sets we have.
	size_t count = ntohl(c.set_count);
	ulog(LLOG_INFO, "FWUp config %u with %zu sets\n", (unsigned)ntohl(c.version), count);
	size_t target_count = count;
	struct mem_pool *pool = u->standby_pool;
	struct set *sets = mem_pool_alloc(pool, count * sizeof *sets);
	size_t pos = 0;
	for (size_t i = 0; i < count; i ++)
		if (set_parse(pool, &sets[pos], &data, &length))
			pos ++;
		else
			target_count --; // The set is strange, skip it.
	if (length)
		ulog(LLOG_WARN, "Extra data after set list (%zu)\n", length);
	// Go through the old sets and mark them as dead (so they could be resurected in the new ones)
	for (size_t i = 0; i < u->set_count; i ++)
		switch (u->sets[i].state) {
			case SS_VALID:
				u->sets[i].state = SS_DEAD;
				break;
			case SS_PENDING:
				u->sets[i].state = SS_DEAD_PENDING;
				break;
			default:
				insane("Unsupported set state %u on old set %s\n", (unsigned)u->sets[i].state, u->sets[i].name);// It's not supposed to have other states now.
		}
	// Go through the new ones and look for corresponding sets in the old config
	for (size_t i = 0; i < target_count; i ++) {
		for (size_t j = 0; j < u->set_count; j ++)
			if (strcmp(sets[i].name, u->sets[j].name) == 0 && sets[i].type == u->sets[j].type) {
				ulog(LLOG_DEBUG, "Copying previous set %s\n", u->sets[j].name);
				switch (u->sets[j].state) {
					case SS_DEAD:
						ulog(LLOG_DEBUG, "Copying content\n");
						diff_addr_store_cp(sets[i].store, u->sets[j].store, context->temp_pool);
						sets[i].state = SS_VALID; // We got the data, it is valid now
						u->sets[j].state = SS_COPIED;
						if (sets[i].hash_size != u->sets[j].hash_size || sets[i].max_size != u->sets[j].max_size) {
							ulog(LLOG_DEBUG, "Changing set size by reloading in kernel\n");
							/*
							 * It is the same set with the same content,
							 * but the sizes changed. Therefore, we need
							 * to reload the set in kernel. Swapping sets
							 * of different sizes seems to work.
							 */
							set_reload(context, &sets[i]);
						}
						break;
					case SS_DEAD_PENDING:
						// No valid data inside. So nothing to copy, really.
						sets[i].state = SS_PENDING; // It is ready in kernel
						u->sets[j].state = SS_COPIED;
						break;
					default:
						insane("Invalid set state when copying: %s %hhu\n", u->sets[j].name, (uint8_t)u->sets[j].state); // Invalid states now
						break;
				}
			}
	}
	for (size_t i = 0; i < u->set_count; i ++) {
		switch (u->sets[i].state) {
			case SS_DEAD:
			case SS_DEAD_PENDING:
				enqueue(context, u->queue, mem_pool_printf(context->temp_pool, "destroy %s\n", u->sets[i].name));
				break;
			case SS_COPIED:
				// OK, nothing to do here
				break;
			default:
				insane("Invalid set state when destroying: %s %hhu\n", u->sets[i].name, (uint8_t)u->sets[i].state); // Invalid states now
				break;
		}
	}
	for (size_t i = 0; i < target_count; i ++) {
		switch (sets[i].state) {
			case SS_NEWBORN:
				set_create(context, &sets[i]);
				sets[i].state = SS_PENDING;
				// Fall through to SS_PENDING, as we want to ask for the version too
			case SS_PENDING:
			case SS_VALID:
				// Validate the data is up to date even with the new config (we may have been disconnected for a while)
				version_ask(context, sets[i].name);
				break;
			default:
				insane("Invalid set state when creating: %s %hhu\n", sets[i].name, (uint8_t)sets[i].state); // Invalid states now
				break;
		}
	}
	// Drop the old config and replace by the new one
	mem_pool_reset(u->conf_pool);
	u->standby_pool = u->conf_pool;
	u->conf_pool = pool;
	u->config_version = c.version;
	u->set_count = target_count;
	u->sets = sets;
	u->configured = true;
}

// Check the version corresponds to the one we are configured for.
static bool config_version_check(struct user_data *u, const uint8_t **data, size_t *length, const char *operation) {
	uint32_t config_version;
	sanity(*length >= sizeof config_version, "Not enough data to hold config version for %s, only %zu bytes\n", operation, *length);
	memcpy(&config_version, *data, sizeof config_version);
	if (u->config_version != config_version) {
		ulog(LLOG_WARN, "Wrong target config version on %s (%u vs %u)\n", operation, (unsigned)ntohl(u->config_version), (unsigned)ntohl(config_version));
		return false;
	}
	*length -= sizeof config_version;
	*data += sizeof config_version;
	return true;
}

static struct set *set_find(struct user_data *u, const char *name) {
	for (size_t i = 0; i < u->set_count; i ++)
		if (strcmp(name, u->sets[i].name) == 0)
			return &u->sets[i];
	return NULL;
}

static void handle_action(struct context *context, const char *name, enum diff_store_action action, uint32_t epoch, uint32_t old_version, uint32_t new_version) {
	struct user_data *u = context->user_data;
	switch (action) {
		case DIFF_STORE_UNKNOWN:
			break;
		case DIFF_STORE_NO_ACTION:
			set_find(u, name)->state = SS_VALID;
			break;
		case DIFF_STORE_CONFIG_RELOAD: {
			// A reload is requested. Copy all the sets into new memory pool, but with dropping dead elements.
			struct mem_pool *pool = u->standby_pool;
			size_t sets_size = u->set_count * sizeof *u->sets;
			struct set *new = mem_pool_alloc(pool, sets_size);
			memcpy(new, u->sets, sets_size);
			for (size_t i = 0; i < u->set_count; i ++) {
				new[i].name = mem_pool_strdup(pool, new[i].name);
				sanity(!new[i].tmp_name, "Request to reconfigure during update of %s\n", new[i].name);
				new[i].store = diff_addr_store_init(pool, new[i].name);
				store_set_hooks(&new[i]);
				diff_addr_store_cp(new[i].store, u->sets[i].store, context->temp_pool);
			}
			// Update data in the user data
			u->standby_pool = u->conf_pool;
			u->conf_pool = pool;
			u->sets = new;
			// Try it once more, if it wants data from the server
			struct set *set = set_find(u, name);
			action = diff_addr_store_action(set->store, epoch, new_version, &old_version);
			sanity(action != DIFF_STORE_CONFIG_RELOAD, "Double reload requested on set %s\n", name);
			handle_action(context, name, action, epoch, old_version, new_version);
			break;
		}
		case DIFF_STORE_INCREMENTAL:
		case DIFF_STORE_FULL: {
			bool full = (action == DIFF_STORE_FULL);
			set_find(u, name)->state = full ? SS_PENDING : SS_VALID;
			size_t len = 1 /* 'U' */ + 1 /* full? */ + sizeof(uint32_t) + strlen(name) + (2 + !full) * sizeof(uint32_t);
			uint8_t *message = mem_pool_alloc(context->temp_pool, len);
			uint8_t *pos = message;
			size_t rest = len;
			uplink_render(&pos, &rest, "cbsu", 'U', full, name, strlen(name), epoch);
			if (!full)
				uplink_render_uint32(old_version, &pos, &rest);
			uplink_render_uint32(new_version, &pos, &rest);
			sanity(!rest, "Leftover of %zu bytes after rendering request for update on %s\n", rest, name);
			uplink_plugin_send_message(context, message, len);
			break;
		}
	}
}

static void version_received(struct context *context, const uint8_t *data, size_t length) {
	ulog(LLOG_DEBUG, "Parsing IPSet version offer\n");
	struct user_data *u = context->user_data;
	if (!config_version_check(u, &data, &length, "version update"))
		return;
	char *name;
	uint32_t epoch, version;
	uplink_parse(&data, &length, "suu",
			&name, NULL, context->temp_pool, "version IPSet name",
			&epoch, "version epoch",
			&version, "version");
	if (length)
		ulog(LLOG_WARN, "Extra %zu bytes after version for IPSet %s, ignoring for compatibility reasons\n", length, name);
	struct set *set = set_find(u, name);
	if (!set) {
		ulog(LLOG_ERROR, "Update for unknown set %s received\n", name);
		return;
	}
	set->context = context;
	ulog(LLOG_DEBUG, "Received IPset version update for %s: %u %u\n", name, epoch, version);
	uint32_t orig_version;
	enum diff_store_action action = diff_addr_store_action(set->store, epoch, version, &orig_version);
	handle_action(context, name, action, epoch, orig_version, version);
	set->context = NULL;
}

static void diff_received(struct context *context, const uint8_t *data, size_t length) {
	ulog(LLOG_DEBUG, "Parsing IPSet diff update\n");
	struct user_data *u = context->user_data;
	if (!config_version_check(u, &data, &length, "diff update"))
		return;
	char *name;
	bool full;
	uint32_t epoch, from = 0, to;
	uplink_parse(&data, &length, "sbu",
			&name, NULL, context->temp_pool, "diff IPset",
			&full, "diff fullness flag",
			&epoch, "diff epoch");
	if (!full)
		from = uplink_parse_uint32(&data, &length);
	to = uplink_parse_uint32(&data, &length);
	struct set *set = set_find(u, name);
	if (!set) {
		ulog(LLOG_ERROR, "Diff for unknown set %s received\n", name);
		return;
	}
	set->context = context;
	uint32_t orig_version;
	ulog(LLOG_INFO, "Updating ipset %s from version %u to version %u (epoch %u)\n", name, (unsigned)from, (unsigned)to, (unsigned)epoch);
	enum diff_store_action action = diff_addr_store_apply(context->temp_pool, set->store, full, epoch, from, to, data, length, &orig_version);
	switch (action) {
		case DIFF_STORE_INCREMENTAL:
		case DIFF_STORE_FULL:
			ulog(LLOG_WARN, "IPSet %s out of sync, dropping diff\n", name);
			break;
		default:;
	}
	handle_action(context, name, action, epoch, orig_version, to);
	set->context = NULL;
}

static void replace_add(const uint8_t *key, size_t key_size, struct trie_data *data, void *userdata) {
	struct diff_addr_store *store = userdata;
	if (data) // Skip over the entries that are not there
		add_item(store, key, key_size);
}

static void set_reload(struct context *context, struct set *set) {
	set->context = context;
	// Reuse the hooks to replace the content of the set and to add items there.
	replace_start(set->store);
	trie_walk(set->store->trie, replace_add, set->store, context->temp_pool);
	replace_end(set->store);
	set->context = NULL;
}

static void sets_reload(struct context *context) {
	ulog(LLOG_INFO, "Reloading all IPsets\n");
	struct user_data *u = context->user_data;
	for (size_t i = 0; i < u->set_count; i ++) {
		struct set *s = &u->sets[i];
		set_reload(context, s);
	}
}

static void communicate(struct context *context, const uint8_t *data, size_t length) {
	// Reset the cache, it might be outdated and in invalid memory
	context->user_data->existing_sets = NULL;
	sanity(length, "A zero-length message delivered to the FWUp plugin\n");
	switch (*data) {
		case 'C':
			config_parse(context, data + 1, length - 1);
			break;
		case 'V': // Information about version of a set
			version_received(context, data + 1, length - 1);
			break;
		case 'D': // A difference update to a set
			diff_received(context, data + 1, length - 1);
			break;
		case 'R': // Reload the data in kernel
			sets_reload(context);
			break;
		default:
			ulog(LLOG_WARN, "Unknown message opcode on FWUp: '%c' (%hhu), ignoring\n", *data, *data);
			break;
	}
}

static void child_died(struct context *context, int state, pid_t pid) {
	sanity(context->user_data->queue, "Missing the ipset queue\n");
	queue_child_died(context, state, pid, context->user_data->queue);
}

static void initialize(struct context *context) {
	struct user_data *u = context->user_data = mem_pool_alloc(context->permanent_pool, sizeof *context->user_data);
	*u = (struct user_data) {
		.conf_pool = loop_pool_create(context->loop, context, "FWUp set pool 1"),
		.standby_pool = loop_pool_create(context->loop, context, "FWUp set pool 2"),
		.queue = queue_alloc(context, sets_reload)
	};
	// Ask for config, if already connected (unlikely, but then, the message will get blackholed).
	connected(context);
}

#ifdef STATIC
#error "FWUp is not ready for static linkage. Nobody needed it."
#else
struct plugin *plugin_info(void) {
	static struct pluglib_import *imports[] = {
		&diff_addr_store_init_import,
		&diff_addr_store_cp_import,
		&diff_addr_store_apply_import,
		&diff_addr_store_action_import,
		NULL
	};
	static struct plugin plugin = {
		.name = "Fwup",
		.version = 1,
		.init_callback = initialize,
		.uplink_data_callback = communicate,
		.uplink_connected_callback = connected,
		.fd_callback = queue_fd_data,
		.child_died_callback = child_died,
		.imports = imports
	};
	return &plugin;
}

unsigned api_version() {
	return UCOLLECT_PLUGIN_API_VERSION;
}
#endif
