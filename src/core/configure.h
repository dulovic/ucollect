/*
    Ucollect - small utility for real-time analysis of network data
    Copyright (C) 2013-2015 CZ.NIC, z.s.p.o. (http://www.nic.cz/)

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

#ifndef UCOLLECT_CONFIGURE_H
#define UCOLLECT_CONFIGURE_H

#include <stdbool.h>

struct loop;

/*
 * Set the configuration directory. Not copied, should be preserved for the
 * whole lifetime of the program.
 */
void config_set_dir(const char *dir) __attribute__((nonnull));
void config_set_package(const char *package_name) __attribute__((nonnull));
const char *config_get_package();
void config_allow_null_uplink(void);
bool load_config(struct loop *loop) __attribute__((nonnull));

#endif
