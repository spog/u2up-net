/*
 * The u2up-net-sim network simulation program
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

#ifndef U2UP_NET_FILE_u2up_net_sim_h
#define U2UP_NET_FILE_u2up_net_sim_h

#ifdef U2UP_NET_FILE_u2up_net_sim_c
/* PRIVATE usage of the PUBLIC part. */
#	undef EXTERN
#	define EXTERN
#else
/* PUBLIC usage of the PUBLIC part. */
#	undef EXTERN
#	define EXTERN extern
#endif

#define MAX_BUFF_SIZE 1024

typedef struct u2up_node_addr_list u2upNetAddrListStruct;
struct u2up_node_addr_list {
	uint32_t addr;
	u2upNetAddrListStruct *next;
}; /*u2upNetAddrListStruct*/

typedef struct u2up_net_addr u2upNetAddrStruct;
struct u2up_net_addr {
	uint32_t addr;
	unsigned int nodeId;
	u2upNetAddrStruct *next;
	u2upNetAddrStruct *prev;
}; /*u2upNetAddrStruct*/

typedef struct u2up_net_addr_ring {
	pthread_mutex_t amtx;
	u2upNetAddrStruct *first;
} u2upNetAddrRingStruct;

typedef struct u2up_net_node {
	unsigned int nodeId;
	u2upNetAddrStruct *nodeAddr;
	evmConsumerStruct *consumer;
} u2upNetNodeStruct;

#endif /*U2UP_NET_FILE_u2up_net_sim_h*/
