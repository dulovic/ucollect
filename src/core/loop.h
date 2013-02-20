#ifndef UCOLLECT_LOOP_H
#define UCOLLECT_LOOP_H

#include <stdbool.h>

struct loop;
struct plugin;

struct loop *loop_create() __attribute__((malloc));
void loop_run(struct loop *loop) __attribute__((nonnull));
void loop_break(struct loop *loop) __attribute__((nonnull));
void loop_destroy(struct loop *loop) __attribute__((nonnull));

bool loop_add_pcap(struct loop *loop, const char *interface) __attribute__((nonnull));
// Add a local address for the last added pcap interface. Can be net address (eg. 192.168.0.0/16).
bool loop_pcap_add_address(struct loop *loop, const char *address) __attribute__((nonnull));
void loop_add_plugin(struct loop *loop, struct plugin *plugin) __attribute__((nonnull));

#endif