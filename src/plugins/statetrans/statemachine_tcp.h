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

#ifndef UCOLLECT_STATETRANS_STATEMACHINE_TCP_H
#define UCOLLECT_STATETRANS_STATEMACHINE_TCP_H

#include "statemachine.h"

enum statemachine_tcp_state : statemachine_state_t {
	TCP_NO_STATE,
	TCP_SYN_SENT,
	TCP_SYN_RECD,
	TCP_ACK_WAIT,
	TCP_ESTABLISHED,

	TCP_FIN_WAIT_1,
	TCP_FIN_WAIT_2,
	TCP_CLOSING_1,
	TCP_CLOSING_2,
	TCP_CLOSING,

	TCP_CLOSE_WAIT,
	TCP_CLOSE_WAIT_1,
	TCP_LAST_ACK_1,
	TCP_LAST_ACK,
	TCP_LAST_ACK_2,

	TCP_CLOSED,

	// timedout?
	// rst ?

	TCP_STATE_COUNT	// Must be the last one
};

enum statemachine_tcp_transition : statemachine_transition_t {
	TCP_NO_TRANS,
	
	T1,
	T2,
	T3,
	T4,
	T5,
	T6,
	T7,
	T8,
	T9,
	T10,
	T11,
	T12,
	T13,
	T14,
	T15,
	T16,
	T17,
	T18,
	T19,
	T20,
	T21,
	T22,
	T23,
	T24,
	T25,
	T26,
	T27,
	T28,
	T29,
	T30,
	T31,

#ifdef STATETRANS_TCP_LOOP_TRANSITIONS
	T32,
	T33,
	T34,
	T35,
	T36,
	T37,
	T38,
	T39,
	T40,
	T41,
	T42,
#endif

	TCP_TRANS_COUNT	// Must be the last one
}

struct statemachine_tcp_conversation {
	statemachine_tcp_state_t state;
	uint64_t timestamp;
	statemachine_timeslot timeslots[TCP_STATE_COUNTS];
};


struct statemachine *statemachine_info_tcp(void);


#endif