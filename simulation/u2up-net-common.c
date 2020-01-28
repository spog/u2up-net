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
#include "u2up-net-sim.h"
#include "u2up-net-common.h"

int32_t calcDistance(uint32_t from_addr, uint32_t to_addr)
{
	return ((int32_t)to_addr - (int32_t)from_addr);
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

u2upNodeOwnCtactStruct * newU2upNodeOwnContact(unsigned int id, uint32_t addr)
{
	u2upNodeOwnCtactStruct *new = (u2upNodeOwnCtactStruct *)calloc(1, sizeof(u2upNodeOwnCtactStruct));
	if (new == NULL)
		abort();

	new->next = NULL;
	if ((new->myself = newU2upNodeContact(id, addr)) == NULL) {
		free(new);
		new = NULL;
	}	
	new->myself->own = 1;

	return new;
}

u2upNodeRingContactStruct * insertNodeMyself(u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeOwnCtactStruct *own_last = NULL;
	u2upNodeRingContactStruct *tmp = NULL;
	u2upNodeRingContactStruct *new = NULL;

	if (node == NULL)
		abort();

	pthread_mutex_lock(&node->amtx);

	own = node->ctacts;
	if (own == NULL) { /*no own addresses yet*/
		if ((own = newU2upNodeOwnContact(id, addr)) == NULL)
			abort();
		node->ctacts = own;
		new = own->myself;
		new->next = new;
		new->prev = new;
	} else {
		do {
			if (addr == own->myself->addr) { /*found existing own address - return that contact*/
				pthread_mutex_unlock(&node->amtx);
				return own->myself;
			}
			own_last = own;
			own = own->next;
		} while (own != NULL);
		if ((own = newU2upNodeOwnContact(id, addr)) == NULL)
			abort();
		own_last->next = own;
		new = own->myself;
		tmp = node->ctacts->myself;
		do {
			if (tmp->addr == addr) { /*NOT own contact address existing (if happens -> REPLACE IT)*/
				new->prev = tmp->prev;
				new->next = tmp->next;
				tmp->prev->next = new;
				tmp->next->prev = new;
				free(tmp);
				break;
			}
			if (tmp->addr > addr) { /*insertion point found*/
				new->next = tmp;
				new->prev = tmp->prev;
				tmp->prev->next = new;
				tmp->prev = new;
				break;
			}
			tmp = tmp->next;
		} while (tmp != node->ctacts->myself);
	}

	pthread_mutex_unlock(&node->amtx);
	return new;
}

static u2upNodeRingContactStruct * _deleteNextContact(u2upNetNodeStruct *node, u2upNodeRingContactStruct *ctact)
{
	u2upNodeRingContactStruct *tmp = NULL;

	if ((node == NULL) || (ctact == NULL))
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
		node->numCtacts--;
		return tmp;
	}
	return NULL;
}

static u2upNodeRingContactStruct * _deletePrevContact(u2upNetNodeStruct *node, u2upNodeRingContactStruct *ctact)
{
	u2upNodeRingContactStruct *tmp = NULL;

	if ((node == NULL) || (ctact == NULL))
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
		node->numCtacts--;
		return tmp;
	}
	return NULL;
}

u2upNodeRingContactStruct * insertNodeContact(u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
	int32_t dist2myself, dist2next, dist2prev;
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeRingContactStruct *tmpNext = NULL;
	u2upNodeRingContactStruct *tmpPrev = NULL;
	u2upNodeRingContactStruct *new = NULL;

	if (node == NULL)
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
	tmpNext = node->ctacts->myself->next;
	tmpPrev = node->ctacts->myself->prev;
	dist2myself = calcDistance(node->ctacts->myself->addr, addr);
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
		dist2next = calcDistance(node->ctacts->myself->addr, tmpNext->addr);
		dist2prev = calcDistance(node->ctacts->myself->addr, tmpNext->addr);
		if ((tmpNext->next->addr != addr) && ((tmpNext == tmpNext->next) || (abs(dist2next) > abs(dist2myself)))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->next = tmpNext;
			new->prev = tmpNext->prev;
			tmpNext->prev->next = new;
			tmpNext->prev = new;
			node->numCtacts++;
			if (node->numCtacts > node->maxCtacts)
				_deleteNextContact(node, new->next);
			break;
		}
		if ((tmpPrev->prev->addr != addr) && ((tmpPrev == tmpPrev->prev) || (abs(dist2prev) > abs(dist2myself)))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->next = tmpPrev;
			new->prev = tmpPrev->prev;
			tmpPrev->prev->next = new;
			tmpPrev->prev = new;
			node->numCtacts++;
			if (node->numCtacts > node->maxCtacts)
				_deletePrevContact(node, new->prev);
			break;
		}
		tmpNext = tmpNext->next;
		tmpPrev = tmpNext->prev;
	} while ((tmpNext != node->ctacts->myself) || (tmpPrev != node->ctacts->myself));

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
	int32_t own_dist = 0, tmp_dist = 0;
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeOwnCtactStruct *nearest_own = NULL;
	u2upNodeRingContactStruct *tmp_contact = NULL;

	if (node == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*First find closest of our own addresses*/
	own = node->ctacts;
	nearest_own = own;
	own_dist = calcDistance(own->myself->addr, addr);
	own = own->next;
	while (own != NULL) {
		tmp_dist = calcDistance(own->myself->addr, addr);
		if (tmp_dist == 0) {
			own_dist = tmp_dist;
			nearest_own = own;
			break;
		} else {
			if (abs(tmp_dist) < abs(own_dist)) {
				own_dist = tmp_dist;
				nearest_own = own;
			}
		}
		own = own->next;
	};

	if (own_dist == 0) {
		/* we are looking for closest to one of our own addresses - return nothing */
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*Find closest contact around our own closest address*/
	tmp_contact = nearest_own->myself;
	do {
		if (own_dist < 0) { /* addr is closer to us on the prev side of the contacts ring */
			tmp_contact = tmp_contact->prev;
			break;
		} else { /* addr is closer to us on the next side of the contacts ring */
			tmp_contact = tmp_contact->next;
		}
		tmp_dist = calcDistance(tmp_contact->addr, addr);
		/* Bumped into a contact with the "search" address! - Break, to use the one before */
		if (tmp_dist == 0)
			break;
	} while ((abs(tmp_dist) < abs(own_dist)) && (tmp_contact != nearest_own->myself));

	if (own_dist > 0)
		tmp_contact = tmp_contact->prev;

	pthread_mutex_unlock(&node->amtx);
	return tmp_contact;
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
	int32_t own_dist = 0, tmp_dist = 0;
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeOwnCtactStruct *nearest_own = NULL;
	u2upNodeRingContactStruct *tmp_contact = NULL;

	if (node == NULL)
		return NULL;

	pthread_mutex_lock(&node->amtx);

	if ((node->ctacts == NULL) || (node->ctacts->myself == NULL)) {
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*First find closest of our own addresses*/
	own = node->ctacts;
	nearest_own = own;
	own_dist = calcDistance(own->myself->addr, addr);
	own = own->next;
	while (own != NULL) {
		tmp_dist = calcDistance(own->myself->addr, addr);
		if (tmp_dist == 0) {
			own_dist = tmp_dist;
			nearest_own = own;
			break;
		} else {
			if (abs(tmp_dist) < abs(own_dist)) {
				own_dist = tmp_dist;
				nearest_own = own;
			}
		}
		own = own->next;
	};

	if (own_dist == 0) {
		/* we are looking for closest to one of our own addresses - return nothing */
		pthread_mutex_unlock(&node->amtx);
		return NULL;
	}

	/*Find closest contact around our own closest address*/
	tmp_contact = nearest_own->myself;
	do {
		if (own_dist < 0) { /* addr is closer to us on the prev side of the contacts ring */
			tmp_contact = tmp_contact->prev;
		} else { /* addr is closer to us on the next side of the contacts ring */
			tmp_contact = tmp_contact->next;
			break;
		}
		tmp_dist = calcDistance(tmp_contact->addr, addr);
		/* Bumped into a contact with the "search" address! - Break, to use the one before */
		if (tmp_dist == 0)
			break;
	} while ((abs(tmp_dist) < abs(own_dist)) && (tmp_contact != nearest_own->myself));

	if (own_dist < 0)
		tmp_contact = tmp_contact->next;

	pthread_mutex_unlock(&node->amtx);
	return tmp_contact;
}

u2upNodeRingContactStruct * insertNearAddrContact(u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
	int32_t dist2myself, dist2next, dist2prev;
	u2upNodeOwnCtactStruct *own = NULL;
	u2upNodeRingContactStruct *tmpNext = NULL;
	u2upNodeRingContactStruct *tmpPrev = NULL;
	u2upNodeRingContactStruct *new = NULL;

	if (node == NULL)
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
	tmpNext = node->ctacts->myself->next;
	tmpPrev = node->ctacts->myself->prev;
	dist2myself = calcDistance(node->ctacts->myself->addr, addr);
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
		dist2next = calcDistance(node->ctacts->myself->addr, tmpNext->addr);
		dist2prev = calcDistance(node->ctacts->myself->addr, tmpPrev->addr);
		if ((tmpNext->next->addr != addr) && ((tmpNext == tmpNext->next) || (abs(dist2next) > abs(dist2myself)))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->next = tmpNext;
			new->prev = tmpNext->prev;
			tmpNext->prev->next = new;
			tmpNext->prev = new;
			node->numCtacts++;
			if (node->numCtacts > node->maxCtacts)
				_deleteNextContact(node, new->next);
			break;
		}
		if ((tmpPrev->prev->addr != addr) && ((tmpPrev == tmpPrev->prev) || (abs(dist2prev) > abs(dist2myself)))) { /*insertion point found*/
			if ((new = newU2upNodeContact(id, addr)) == NULL)
				abort();
			new->prev = tmpPrev;
			new->next = tmpPrev->next;
			tmpPrev->next->prev = new;
			tmpPrev->next = new;
			node->numCtacts++;
			if (node->numCtacts > node->maxCtacts)
				_deletePrevContact(node, new->prev);
			break;
		}
		tmpNext = tmpNext->next;
		tmpPrev = tmpNext->prev;
	} while (calcDistance(tmpPrev->addr, tmpNext->addr) > 0);

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

