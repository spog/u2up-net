/*
 * The u2up-net common functions
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

#ifndef U2UP_NET_FILE_u2up_net_common_h
#define U2UP_NET_FILE_u2up_net_common_h

#ifdef U2UP_NET_FILE_u2up_net_common_c
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

//EXTERN int32_t calcDistance(uint32_t from_addr, uint32_t to_addr);
EXTERN uint32_t calcUDistance(uint32_t from_addr, uint32_t to_addr);

EXTERN u2upNodeRingContactStruct * newU2upNodeContact(unsigned int id, uint32_t addr);
EXTERN u2upNodeOwnCtactStruct * newU2upNodeOwnContact(u2upNetNodeStruct *node, unsigned int id, uint32_t addr);
EXTERN u2upNodeOwnCtactStruct * insertNodeOwnContact(u2upNetNodeStruct *node, unsigned int id, uint32_t addr);
EXTERN u2upNodeRingContactStruct * insertNodeContact(u2upNodeOwnCtactStruct *ownCtact, unsigned int id, uint32_t addr);
EXTERN u2upNodeRingContactStruct * deleteNodeContact(u2upNetNodeStruct *node, uint32_t addr);
EXTERN u2upNodeRingContactStruct * deleteNodeMyself(u2upNetNodeStruct *node, uint32_t addr);
EXTERN u2upNodeRingContactStruct * getRandomRemoteContact(u2upNodeOwnCtactStruct *ownCtact);
EXTERN u2upNodeRingContactStruct * findNearNextContact(u2upNetNodeStruct *node, uint32_t addr);
EXTERN u2upNodeRingContactStruct * findNearPrevContact(u2upNetNodeStruct *node, uint32_t addr);
EXTERN u2upNodeRingContactStruct * insertNearAddrContact(u2upNodeOwnCtactStruct *ownCtact, unsigned int id, uint32_t addr);
EXTERN int getNumAllCtacts(u2upNetNodeStruct *node);

EXTERN u2upNetRingAddrStruct * newU2upNetAddr(uint32_t addr);
EXTERN u2upNetRingAddrStruct * insertNewNetAddr(u2upNetRingHeadStruct *ring, uint32_t addr);

#endif /*U2UP_NET_FILE_u2up_net_common_h*/
