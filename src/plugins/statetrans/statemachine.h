/*
    Ucollect - small utility for real-time analysis of network data
    Tomas Morvay 

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

#ifndef UCOLLECT_STATEMACHINE_H
#define UCOLLECT_STATEMACHINE_H

#include "../../core/context.h"

struct statemachine_context {
	struct context *pctx; // Plugin context
	
	// timeslot intervals
	// timeslot cnt
	
	
	
};

struct statemachine_

struct statemachine {
	const char *name;
	size_t state_count; // Number of states used by statemachine
	void (*init_callback) (struct statemachine_context *context);
	void (*packet_callback)(struct statemachine_context *context, const struct packet_info *info);
	void (*change_mode_callback) (mode);
	
		
};

#endif
