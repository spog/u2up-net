/*
 * The u2up-netsim CLI server functions
 *
 * This file is part of the "u2up-net" software project.
 *
 *  Copyright (C) 2020 Samo Pogacnik <samo_pogacnik@t-2.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
*/

#ifndef U2UP_NET_FILE_netsim_clisrv_h
#define U2UP_NET_FILE_netsim_clisrv_h

#ifdef U2UP_NET_FILE_netsim_clisrv_c
/* PRIVATE usage of the PUBLIC part. */
#	undef EXTERN
#	define EXTERN
#else
/* PUBLIC usage of the PUBLIC part. */
#	undef EXTERN
#	define EXTERN extern
#endif

#define U2UP_NET_TRUE (0 == 0)
#define U2UP_NET_FALSE (0 != 0)

#define CLISRV_SOCK_PATH "/tmp/u2up-netsim-cli"
#define LISTEN_BACKLOG 50
#define CLISRV_MAX_CMDSZ 512
#define CLISRV_MAX_MSGSZ 1024

static inline char * clisrv_strncat(char *dst, const char *src, int dstsz)
{
	int room = dstsz - strlen(dst) - 1;
	if (room > 0)
		return strncat(dst, src, room);
	return dst;
}

EXTERN int simulation_clisrv_init(evmStruct *evm);

#endif /*U2UP_NET_FILE_netsim_clisrv_h*/
