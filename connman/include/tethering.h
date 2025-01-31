/*
 *
 *  Connection Manager
 *
 *  Copyright (C) 2007-2013  Intel Corporation. All rights reserved.
 *  Copyright (C) 2018 GlobalLogic. All rights reserved.
 *  Copyright (C) 2025 Jolla Mobile Ltd
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#ifndef __CONNMAN_TETHERING_H
#define __CONNMAN_TETHERING_H

#include <connman/service.h>

#ifdef __cplusplus
extern "C" {
#endif

void connman_tethering_client_register(const char *addr,
						enum connman_service_type type,
						uint8_t version);
void connman_tethering_client_unregister(const char *addr);
GList *connman_tethering_get_clients(void);

#ifdef __cplusplus
}
#endif

#endif /* __CONNMAN_TETHERING_H */
