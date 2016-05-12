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

#ifndef UCOLLECT_STATETRANS_STATEMACHINE_TCP_H
#define UCOLLECT_STATETRANS_STATEMACHINE_TCP_H

#include "statemachine.h"

enum statemachine_tcp_state /*: statemachine_state_t */ {
    TCP_ST_NO_STATE = 0,
    TCP_ST_RST_SEEN,
    TCP_ST_SYN_SENT,
    TCP_ST_SYN_RECD,
    TCP_ST_ACK_WAIT,
    TCP_ST_ESTABLISHED,

    TCP_ST_FIN_WAIT_1,
    TCP_ST_FIN_WAIT_2,
    TCP_ST_CLOSING_1,
    TCP_ST_CLOSING_2,
    TCP_ST_CLOSING,

    TCP_ST_CLOSE_WAIT_1,
    TCP_ST_CLOSE_WAIT,
    TCP_ST_LAST_ACK_1,
    TCP_ST_LAST_ACK,
    TCP_ST_LAST_ACK_2,

    TCP_ST_CLOSED,

    TCP_ST_TIMEDOUT,
    TCP_ST_RST,

    TCP_STATE_COUNT // Must be the last one
};

enum statemachine_tcp_transition /* : statemachine_transition_t */ {
	TCP_TRANS_NO_TRANS = 0,
	
	TCP_TRANS_T1,
	TCP_TRANS_T2,
	TCP_TRANS_T3,
	TCP_TRANS_T4,
	TCP_TRANS_T5,
	TCP_TRANS_T6,
	TCP_TRANS_T7,
	TCP_TRANS_T8,
	TCP_TRANS_T9,
	TCP_TRANS_T10,
	TCP_TRANS_T11,
	TCP_TRANS_T12,
	TCP_TRANS_T13,
	TCP_TRANS_T14,
	TCP_TRANS_T15,
	TCP_TRANS_T16,
	TCP_TRANS_T17,
	TCP_TRANS_T18,
	TCP_TRANS_T19,
	TCP_TRANS_T20,
	TCP_TRANS_T21,
	TCP_TRANS_T22,
	TCP_TRANS_T23,
	TCP_TRANS_T24,
	TCP_TRANS_T25,
	TCP_TRANS_T26,
	TCP_TRANS_T27,
	TCP_TRANS_T28,
	TCP_TRANS_T29,
	TCP_TRANS_T30,
	TCP_TRANS_T31,

#ifdef STATETRANS_TCP_LOOP_TRANSITIONS
	TCP_TRANS_T32,
	TCP_TRANS_T33,
	TCP_TRANS_T34,
	TCP_TRANS_T35,
	TCP_TRANS_T36,
	TCP_TRANS_T37,
	TCP_TRANS_T38,
	TCP_TRANS_T39,
	TCP_TRANS_T40,
	TCP_TRANS_T41,
	TCP_TRANS_T42,
#endif // STATETRANS_TCP_LOOP_TRANSITIONS

	TCP_TRANS_COUNT	// Must be the last one
};

struct statemachine_tcp_conversation {
	enum statemachine_tcp_state state;
	uint64_t timestamp;
	struct statemachine_timeslot timeslots[TCP_TRANS_COUNT];
};

struct statemachine *statemachine_info_tcp(void);

#endif