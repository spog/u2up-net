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

#ifndef U2UP_NET_FILE_u2up_net_common_c
#define U2UP_NET_FILE_u2up_net_common_c
#else
#error Preprocesor macro U2UP_NET_FILE_u2up_net_common_c conflict!
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include <evm/libevm.h>
#include "u2up-netsim.h"
#include "u2up-net-common.h"

#if 0
int32_t calcDistance(uint32_t from_addr, uint32_t to_addr)
{
	return ((int32_t)to_addr - (int32_t)from_addr);
}
#endif

uint32_t calcUDistance(uint32_t from_addr, uint32_t to_addr)
{
	return (uint32_t)((int32_t)to_addr - (int32_t)from_addr);
}

u2upNodeRingContactStruct * newU2upNodeContact(unsigned int id, uint32_t addr)
{
	u2upNodeRingContactStruct *new = (u2upNodeRingContactStruct *)calloc(1, sizeof(u2upNodeRingContactStruct));
	if (new == NULL)
		abort();

	new->id = id;
	new->addr = addr;
	new->own = 0;

	return new;
}

u2upNodeOwnCtactStruct * newU2upNodeOwnContact(u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
	u2upNodeOwnCtactStruct *new = (u2upNodeOwnCtactStruct *)calloc(1, sizeof(u2upNodeOwnCtactStruct));
	if (new == NULL)
		abort();

	new->next = NULL;
	if ((new->myself = newU2upNodeContact(id, addr)) == NULL) {
		free(new);
		new = NULL;
	}	
	new->numCtacts = 0; /*number of per-own-address maintained remote contacts*/
	new->ownNode = node; /*link to our own node structure*/
	new->myself->own = 1; /*indicates that this contact represents our own node*/
	new->sentMsgs = 0;
	new->recvdMsgs = 0;

	return new;
}

u2upNodeOwnCtactStruct * insertNodeOwnContact(u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeOwnCtactStruct *own_last = NULL;
	u2upNodeRingContactStruct *new = NULL;
	u2upNodeRingContactStruct *tmpNext = NULL;
	u2upNodeRingContactStruct *tmpPrev = NULL;
	uint32_t uDist2myself, uDist2next, uDist2prev;
	int not_done = U2UP_NET_TRUE;

	if (node == NULL)
		abort();

	pthread_mutex_lock(&node->amtx);

	own = node->ctacts;
	if (own == NULL) { /*no own addresses yet*/
		if ((own = newU2upNodeOwnContact(node, id, addr)) == NULL)
			abort();
		node->ctacts = own;
		node->numOwns++;
		new = own->myself;
		new->next = new;
		new->prev = new;
	} else {
		/*Check own IDs and change them, if required*/
		do {
			if (own->myself->id != id)
				own->myself->id = id;
			own = own->next;
		} while (own != NULL);
		own = node->ctacts;
		do {
			if (addr == own->myself->addr) { /*found existing own address - return that contact*/
				pthread_mutex_unlock(&node->amtx);
				return own;
			}
			own_last = own;
			own = own->next;
		} while (own != NULL);
		tmpNext = node->ctacts->myself->next;
		uDist2myself = calcUDistance(node->ctacts->myself->addr, addr);
		do {
			if (tmpNext->addr == addr) { /*NOT own contact address existing (if happens -> REPLACE IT)*/
				if ((own = newU2upNodeOwnContact(node, id, addr)) == NULL)
					abort();
				own_last->next = own;
				new = own->myself;
				node->numOwns++;
				new->prev = tmpNext->prev;
				new->next = tmpNext->next;
				tmpNext->prev->next = new;
				tmpNext->next->prev = new;
				free(tmpNext);
				break;
			}
			if (tmpPrev->addr == addr) { /*NOT own contact address existing (if happens -> REPLACE IT)*/
				if ((own = newU2upNodeOwnContact(node, id, addr)) == NULL)
					abort();
				own_last->next = own;
				new = own->myself;
				node->numOwns++;
				new->prev = tmpPrev->prev;
				new->next = tmpPrev->next;
				tmpPrev->prev->next = new;
				tmpPrev->next->prev = new;
				free(tmpPrev);
				break;
			}
			uDist2next = calcUDistance(node->ctacts->myself->addr, tmpNext->addr);
			uDist2prev = calcUDistance(node->ctacts->myself->addr, tmpPrev->addr);
			if ((tmpNext->next->addr != addr) && ((tmpNext == tmpNext->next) || (uDist2next > uDist2myself))) { /*insertion point found*/
				if ((own = newU2upNodeOwnContact(node, id, addr)) == NULL)
					abort();
				own_last->next = own;
				new = own->myself;
				node->numOwns++;
				new->next = tmpNext;
				new->prev = tmpNext->prev;
				tmpNext->prev->next = new;
				tmpNext->prev = new;
				break;
			}
			if ((tmpPrev->prev->addr != addr) && ((tmpPrev == tmpPrev->prev) || (uDist2prev < uDist2myself))) { /*insertion point found*/
				if ((own = newU2upNodeOwnContact(node, id, addr)) == NULL)
					abort();
				own_last->next = own;
				new = own->myself;
				node->numOwns++;
				new->next = tmpPrev;
				new->prev = tmpPrev->prev;
				tmpPrev->prev->next = new;
				tmpPrev->prev = new;
				break;
			}
			if (uDist2next >= uDist2prev)
				not_done = U2UP_NET_FALSE;
			tmpNext = tmpNext->next;
			tmpPrev = tmpNext->prev;
		} while (not_done);
	}

	pthread_mutex_unlock(&node->amtx);
	return own;
}

static u2upNodeRingContactStruct * _deleteNextContact(u2upNodeOwnCtactStruct *ownCtact, u2upNodeRingContactStruct *ctact)
{
	u2upNodeRingContactStruct *tmp = NULL;

	if ((ownCtact == NULL) || (ctact == NULL))
		return NULL;

	tmp = ctact;
	do {
		/*Skip own contacts*/
		if (tmp->own != 1)
			break;
		tmp = tmp->next;
	} while (tmp != ctact);
	if ((tmp != tmp->prev) && (tmp != tmp->next) && (tmp->own != 1)) {
		tmp->prev->next = tmp->next;
		tmp->next->prev = tmp->prev;
		free(tmp);
		ownCtact->numCtacts--;
		return tmp;
	}
	return NULL;
}

static u2upNodeRingContactStruct * _deletePrevContact(u2upNodeOwnCtactStruct *ownCtact, u2upNodeRingContactStruct *ctact)
{
	u2upNodeRingContactStruct *tmp = NULL;

	if ((ownCtact == NULL) || (ctact == NULL))
		return NULL;

	tmp = ctact;
	do {
		/*Skip own contacts*/
		if (tmp->own != 1)
			break;
		tmp = tmp->prev;
	} while (tmp != ctact);
	if ((tmp != tmp->prev) && (tmp != tmp->next) && (tmp->own != 1)) {
		tmp->prev->next = tmp->next;
		tmp->next->prev = tmp->prev;
		free(tmp);
		ownCtact->numCtacts--;
		return tmp;
	}
	return NULL;
}

u2upNodeRingContactStruct * insertNodeContact(u2upNodeOwnCtactStruct *ownCtact, unsigned int id, uint32_t addr)
{
	uint32_t uDist2myself, uDist2next, uDist2prev;
	u2upNetNodeStruct *node = NULL;
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeRingContactStruct *tmpNext = NULL;
	u2upNodeRingContactStruct *tmpPrev = NULL;
	u2upNodeRingContactStruct *new = NULL;
	int not_done = U2UP_NET_TRUE;

	if (ownCtact == NULL)
		return NULL;

	if ((node = ownCtact->ownNode) == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	if (ownCtact->numCtacts >= node->maxCtacts) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*Check own addresses first - DO NOT CHANGE THEM HERE!*/
	own = node->ctacts;
	do {
		if (addr == own->myself->addr) { /*found existing own address - FAIL: return NULL*/
			pthread_mutex_unlock(&node->amtx);
			return NULL;
		}
		own = own->next;
	} while (own != NULL);

	/*Should NEVER come down here, if "addr" is one of our own!*/
	tmpNext = ownCtact->myself->next;
	tmpPrev = ownCtact->myself->prev;
	uDist2myself = calcUDistance(ownCtact->myself->addr, addr);
	do {
		if (tmpNext->addr == addr) { /*already inserted*/
			if (tmpNext->id != id) /*set new ID, if required*/
				tmpNext->id = id;
			new = tmpNext;
			break;
		}
		if (tmpPrev->addr == addr) { /*already inserted*/
			if (tmpPrev->id != id) /*set new ID, if required*/
				tmpPrev->id = id;
			new = tmpPrev;
			break;
		}
		uDist2next = calcUDistance(ownCtact->myself->addr, tmpNext->addr);
		uDist2prev = calcUDistance(ownCtact->myself->addr, tmpPrev->addr);
		if ((tmpNext->next->addr != addr) && ((tmpNext == tmpNext->next) || (uDist2next > uDist2myself))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->next = tmpNext;
			new->prev = tmpNext->prev;
			tmpNext->prev->next = new;
			tmpNext->prev = new;
			ownCtact->numCtacts++;
			break;
		}
		if ((tmpPrev->prev->addr != addr) && ((tmpPrev == tmpPrev->prev) || (uDist2prev < uDist2myself))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->next = tmpPrev;
			new->prev = tmpPrev->prev;
			tmpPrev->prev->next = new;
			tmpPrev->prev = new;
			ownCtact->numCtacts++;
			break;
		}
		if (uDist2next >= uDist2prev)
			not_done = U2UP_NET_FALSE;
		tmpNext = tmpNext->next;
		tmpPrev = tmpPrev->prev;
	} while (not_done);

	pthread_mutex_unlock(&node->amtx);
	return new;
}

static u2upNodeRingContactStruct * _deleteNodeContact(u2upNetNodeStruct *node, uint32_t addr)
{
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeRingContactStruct *tmp = NULL;

	if ((node == NULL) || (node->ctacts == NULL) || (node->ctacts->myself == NULL))
		return NULL;

	own = node->ctacts;
	if (own == NULL) /*no own addresses yet -> nothing to delete*/
		return NULL;

	do {
		if (addr == own->myself->addr) /*found existing own address - DO NOT REMOVE HERE!*/
			return NULL;
		own = own->next;
	} while (own != NULL);

	tmp = node->ctacts->myself;
	do {
		if (tmp->addr == addr) { /*address found -> DELETE -> return tmp*/
			tmp->prev->next = tmp->next;
			tmp->next->prev = tmp->prev;
			free(tmp);
			return tmp;
		}
		tmp = tmp->next;
	} while (tmp != node->ctacts->myself);

	return NULL;
}

u2upNodeRingContactStruct * deleteNodeContact(u2upNetNodeStruct *node, uint32_t addr)
{
	u2upNodeRingContactStruct *tmp = NULL;

	if (node == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	tmp = _deleteNodeContact(node, addr);

	pthread_mutex_unlock(&node->amtx);
	return tmp;
}

u2upNodeRingContactStruct * deleteNodeMyself(u2upNetNodeStruct *node, uint32_t addr)
{
	u2upNodeOwnCtactStruct *own = NULL;
#if 0 /*spog - TODO*/
	u2upNodeOwnCtactStruct *own_prev = NULL;
	u2upNodeRingContactStruct *tmp = NULL;
#endif

	if (node == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	own = node->ctacts;
	if (own == NULL) { /*no own addresses yet -> nothing to delete*/
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

#if 0 /*spog - TODO*/
	do {
		if (addr == own->myself->addr) { /*found existing own address - REMOVE HERE!*/
			tmp = own->myself;
			if (own_prev == NULL)
				node->ctacts = own->next;
			else
				own_prev = own->next;
			free(own);
			pthread_mutex_unlock(&node->amtx);
			return NULL;
		}
		own_prev = own;
		own = own->next;
	} while (own != NULL);
#endif

	pthread_mutex_unlock(&node->amtx);
	return NULL;
}

static int _getNumAllCtacts(u2upNetNodeStruct *node)
{
	int all = 0;
	u2upNodeOwnCtactStruct *own = NULL;

	if (node == NULL)
		return 0;

	own = node->ctacts;
	while (own != NULL) {
		all += own->numCtacts;
		own = own->next;
	}
	all += node->numOwns;

	return all;
}

int getNumAllCtacts(u2upNetNodeStruct *node)
{
	int all = 0;

	if (node == NULL)
		return 0;

	pthread_mutex_lock(&node->amtx);
	all = _getNumAllCtacts(node);
	pthread_mutex_unlock(&node->amtx);

	return all;
}

/*
 * Function: getRandomRemoteContact()
 * Description:
 * - In provided node's contacts ring a random remote contact.
 * Returns:
 * - Contact pointer on a random remote contact.
 * - NULL, if no contacts available.
 */
u2upNodeRingContactStruct * getRandomRemoteContact(u2upNodeOwnCtactStruct *ownCtact)
{
	u2upNetNodeStruct *node = NULL;
	u2upNodeRingContactStruct *tmp = NULL;
	unsigned int rand_count, numAllCtacts = 0;

	if (ownCtact == NULL)
		return NULL;

	if ((node = ownCtact->ownNode) == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	if ((numAllCtacts = _getNumAllCtacts(node)) == 0) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	rand_count = rand() % numAllCtacts;

	/*Find first remote ctact after rand_count*/
	tmp = node->ctacts->myself;
	while (rand_count > 0) {
		tmp = tmp->next;
		rand_count--;
		if (tmp == node->ctacts->myself)
			break;
	}

	if (tmp->own != 0) {
		while (tmp != node->ctacts->myself) {
			/*Brak on remote contacts*/
			if (tmp->own == 0)
				break;
			tmp = tmp->next;
		}
		if (tmp->own != 0)
			tmp = NULL;
	}

	pthread_mutex_unlock(&node->amtx);
	return tmp;
}

/*
 * Function: findNearNextContact()
 * Description:
 * - In provided node's contacts ring find a contact nearest to
 *   the supplied address.
 * Returns:
 * - Contact pointer on the NEXT side nearest to the supplied address excluding
 *   a contact with this same address.
 * - NULL, if nothing nearer or we are asking ourself.
 */
u2upNodeRingContactStruct * findNearNextContact(u2upNetNodeStruct *node, uint32_t addr)
{
	uint32_t nearest_dist = 0, tmp_dist = 0;
	u2upNodeRingContactStruct *tmp = NULL;
	u2upNodeRingContactStruct *myself = NULL;
	u2upNodeRingContactStruct *nearest_ctact = NULL;

	if (node == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*Find closest next of all our contact addresses*/
	myself = node->ctacts->myself;
	nearest_dist = calcUDistance(addr, myself->addr);
	nearest_ctact = myself;
	tmp = myself->next;
	do {
		tmp_dist = calcUDistance(addr, tmp->addr);
		if (tmp_dist < nearest_dist) {
			nearest_dist = tmp_dist;
			nearest_ctact = tmp;
		}
		tmp = tmp->next;
	} while (tmp != myself); 

	pthread_mutex_unlock(&node->amtx);
	return nearest_ctact;
}

/*
 * Function: findNearPrevContact()
 * Description:
 * - In provided node's contacts ring find a contact nearest to
 *   the supplied address.
 * Returns:
 * - Contact pointer on the PREV side nearest to the supplied address excluding
 *   a contact with this same address.
 * - NULL, if nothing nearer or we are asking ourself.
 */
u2upNodeRingContactStruct * findNearPrevContact(u2upNetNodeStruct *node, uint32_t addr)
{
//	int32_t own_dist = 0, tmp_dist = 0;
	uint32_t nearest_dist = 0, tmp_dist = 0;
	u2upNodeRingContactStruct *tmp = NULL;
	u2upNodeRingContactStruct *myself = NULL;
	u2upNodeRingContactStruct *nearest_ctact = NULL;

	if (node == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*Find closest prev of all our contact addresses*/
	myself = node->ctacts->myself;
	nearest_dist = calcUDistance(addr, myself->addr);
	nearest_ctact = myself;
	tmp = myself->prev;
	do {
		tmp_dist = calcUDistance(addr, tmp->addr);
		if (tmp_dist > nearest_dist) {
			nearest_dist = tmp_dist;
			nearest_ctact = tmp;
		}
		tmp = tmp->prev;
	} while (tmp != myself); 

	pthread_mutex_unlock(&node->amtx);
	return nearest_ctact;
}

u2upNodeRingContactStruct * insertNearAddrContact(u2upNodeOwnCtactStruct *ownCtact, unsigned int id, uint32_t addr)
{
	uint32_t uDist2myself, uDist2next, uDist2prev;
	u2upNetNodeStruct *node = NULL;
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeRingContactStruct *tmpNext = NULL;
	u2upNodeRingContactStruct *tmpPrev = NULL;
	u2upNodeRingContactStruct *new = NULL;
	int not_done = U2UP_NET_TRUE;

	if (ownCtact == NULL)
		return NULL;

	if ((node = ownCtact->ownNode) == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*Check own addresses first - DO NOT CHANGE THEM HERE!*/
	own = node->ctacts;
	do {
		if (addr == own->myself->addr) { /*found existing own address - FAIL: return NULL*/
			pthread_mutex_unlock(&node->amtx);
			return NULL;
		}
		own = own->next;
	} while (own != NULL);

	/*Should NEVER come down here, if "addr" is one of our own!*/
	tmpNext = ownCtact->myself->next;
	tmpPrev = ownCtact->myself->prev;
	uDist2myself = calcUDistance(ownCtact->myself->addr, addr);
	do {
		if (tmpNext->addr == addr) { /*already inserted*/
			if (tmpNext->id != id) /*set new ID, if required*/
				tmpNext->id = id;
			new = tmpNext;
			break;
		}
		if (tmpPrev->addr == addr) { /*already inserted*/
			if (tmpPrev->id != id) /*set new ID, if required*/
				tmpPrev->id = id;
			new = tmpPrev;
			break;
		}
		uDist2next = calcUDistance(ownCtact->myself->addr, tmpNext->addr);
		uDist2prev = calcUDistance(ownCtact->myself->addr, tmpPrev->addr);
		if ((tmpNext->next->addr != addr) && ((tmpNext == tmpNext->next) || (uDist2next > uDist2myself))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->next = tmpNext;
			new->prev = tmpNext->prev;
			tmpNext->prev->next = new;
			tmpNext->prev = new;
			ownCtact->numCtacts++;
			if (ownCtact->numCtacts > node->maxCtacts)
				_deleteNextContact(ownCtact, new->next);
			break;
		}
		if ((tmpPrev->prev->addr != addr) && ((tmpPrev == tmpPrev->prev) || (uDist2prev < uDist2myself))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->prev = tmpPrev;
			new->next = tmpPrev->next;
			tmpPrev->next->prev = new;
			tmpPrev->next = new;
			ownCtact->numCtacts++;
			if (ownCtact->numCtacts > node->maxCtacts)
				_deletePrevContact(ownCtact, new->prev);
			break;
		}
		if (uDist2next >= uDist2prev)
			not_done = U2UP_NET_FALSE;
		tmpNext = tmpNext->next;
		tmpPrev = tmpPrev->prev;
	} while (not_done);

	pthread_mutex_unlock(&node->amtx);
	return new;
}

u2upNetRingAddrStruct * newU2upNetAddr(uint32_t addr)
{
	u2upNetRingAddrStruct *new = (u2upNetRingAddrStruct *)calloc(1, sizeof(u2upNetRingAddrStruct));

	if (new == NULL)
		abort();

	new->addr = addr;

	return new;
}

u2upNetRingAddrStruct * insertNewNetAddr(u2upNetRingHeadStruct *ring, uint32_t addr)
{
	u2upNetRingAddrStruct *tmp = NULL;
	u2upNetRingAddrStruct *new = NULL;

	if (ring == NULL)
		abort();

	pthread_mutex_lock(&ring->amtx);

	if (ring->first == NULL) {
		new = newU2upNetAddr(addr);
		new->next = new;
		new->prev = new;
		ring->first = new;
	} else {
		tmp = ring->first;
		do {
			if (tmp->addr == addr) {
				pthread_mutex_unlock(&ring->amtx);
				return NULL;
			}
			if (tmp->addr > addr) {
				new = newU2upNetAddr(addr);
				new->next = tmp;
				new->prev = tmp->prev;
				tmp->prev->next = new;
				tmp->prev = new;
				/*TODO - maybe ->prev is closer*/
				if (addr < ring->first->addr)
					ring->first = new;
				pthread_mutex_unlock(&ring->amtx);
				return new;
			}
			tmp = tmp->next;
		} while (tmp != ring->first);

		new = newU2upNetAddr(addr);
		new->next = tmp;
		new->prev = tmp->prev;
		tmp->prev->next = new;
		tmp->prev = new;
		/*TODO - maybe ->prev is closer*/
		if (addr < ring->first->addr)
			ring->first = new;
	}

	pthread_mutex_unlock(&ring->amtx);
	return new;
}

