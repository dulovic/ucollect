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

#ifndef STATEMACHINE_TCP_CONV_LINK_LIST_H
#define STATEMACHINE_TCP_CONV_LINK_LIST_H

struct statemachine_conversation;

struct tcp_conv_list_node {
    struct tcp_conv_list_node *next;
    struct statemachine_conversation *conv;
};

struct tcp_conv_list {
    struct tcp_conv_list_node *head, *tail;
    size_t count;
};

#define LIST_NAME(X) tcp_conv_list_##X
#define LIST_NODE struct tcp_conv_list_node
#define LIST_BASE struct tcp_conv_list
#define LIST_COUNT
#define LIST_WANT_APPEND_POOL
#define LIST_WANT_LFOR
#include "../../core/link_list.h"



#endif /* STATEMACHINE_TCP_CONV_LINK_LIST_H */

