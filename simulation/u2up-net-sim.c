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

/*
 * This network simulation program tries to achieve several tasks:
 * 1. "Randomly" generate network nodes.
 * 2. Generate network node contacts (acquaintances) according to specific
 *    rules.
 * 3. Periodically generate snapshot of the current network state
 *    (network nodes and their contacts).
*/

#ifndef U2UP_NET_FILE_u2up_net_sim_c
#define U2UP_NET_FILE_u2up_net_sim_c
#else
#error Preprocesor macro U2UP_NET_FILE_u2up_net_sim_c conflict!
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <signal.h>
#include <pthread.h>
#include <time.h>

#include <evm/libevm.h>
#include "u2up-net-sim.h"
#include "u2up-net-common.h"

#include <userlog/log_module.h>
EVMLOG_MODULE_INIT(U2UP_SIM, 2);

enum evm_consumer_ids {
	EVM_CONSUMER_AUTH = 0,
	EVM_CONSUMER_PROTOCOL
};

enum evm_msgtype_ids {
	EV_TYPE_UNKNOWN_MSG = 0,
	EV_TYPE_PROTOCOL_MSG
};

enum evm_msg_ids {
	EV_ID_PROTOCOL_MSG_INIT = 0,
	EV_ID_PROTOCOL_MSG_NEAR_REQ,
	EV_ID_PROTOCOL_MSG_NEAR_REPL
};

enum evm_tmr_ids {
	TMR_ID_AUTH_BATCH = 0,
	TMR_ID_NEAR_REQ,
	EV_ID_HELLO_TMR_QUIT
};

static evmTimerStruct * auth_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr);

static int evProtocolInitMsg(evmConsumerStruct *consumer, evmMessageStruct *msg);
#if 0
static int evHelloTmrIdle(evmConsumerStruct *consumer, evmTimerStruct *tmr);
static int evHelloTmrQuit(evmConsumerStruct *consumer, evmTimerStruct *tmr);
#endif

static pthread_mutex_t simulation_global_mutex;
static int simulation_evm_init(void);
static int simulation_authority_run(void);
unsigned int batch_nodes = 1;
unsigned int max_nodes = 10;
static char *default_outfile = "./u2up-net-ring";
static char *outfile = NULL;
static struct tm start;

/*
 * The EVM part.
 */

/*
 * General EVM structure - Provided by evm_init():
 */
static evmStruct *evm;
static evmConsumerStruct *auth_consumer;
static evmConsumerStruct *protocol_consumer;
static u2upNetNodeStruct *nodes;
static u2upNetRingHeadStruct net_addr_ring;
static int next_node = 0;

static evmMsgtypeStruct *msgtype_ptr;
static evmMsgidStruct *msgid_init_ptr;
static evmMsgidStruct *msgid_near_req_ptr;
static evmMsgidStruct *msgid_near_repl_ptr;
#if 0
/* HELLO messages */
static char *hello_str = "HELLO";
static char msg_buff[MAX_BUFF_SIZE];
static struct iovec *iov_buff = NULL;
evmMessageStruct *helloMsg;

/* HELLO timers */
#endif
/* Timers */
static evmTmridStruct *tmridNearReq;
static evmTimerStruct *tmrAuthBatch;
//orig:static evmTimerStruct *tmrNearReq = NULL;
//orig:static evmTimerStruct *helloQuitTmr;

static evmTimerStruct * auth_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr)
{
	evm_log_info("(entry) tmr=%p, sec=%ld, nsec=%ld, ctx_ptr=%p\n", tmr, tv_sec, tv_nsec, ctx_ptr);
	evm_timer_stop(tmr);
	return evm_timer_start(auth_consumer, tmrid_ptr, tv_sec, tv_nsec, ctx_ptr);
}

static evmTimerStruct * protocol_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr)
{
	evm_log_info("(entry) tmr=%p, sec=%ld, nsec=%ld, ctx_ptr=%p\n", tmr, tv_sec, tv_nsec, ctx_ptr);
//orig:	evm_timer_stop(tmr);
	return evm_timer_start(protocol_consumer, tmrid_ptr, tv_sec, tv_nsec, ctx_ptr);
}

/* Send PROTOCOL messages */
static int send_protocol_msg(evmConsumerStruct *consumer, evmMsgidStruct *msgid_ptr, u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
	evmMessageStruct *msg;
	u2upNodeRingContactStruct *contact = NULL;
	evm_log_info("(entry) consumer=%p, msgid_ptr=%p, node=%p, addr=%u\n", consumer, msgid_ptr, node, addr);

	if ((consumer == NULL) || (msgid_ptr == NULL) || (node == NULL))
		return -1;

	if ((msg = evm_message_new(msgtype_ptr, msgid_ptr, sizeof(u2upNodeRingContactStruct))) == NULL) {
		evm_log_error("evm_message_new() failed!\n");
		return -1;
	}

	if ((contact = (u2upNodeRingContactStruct *)evm_message_data_get(msg)) == NULL) {
		evm_log_error("evm_message_data_get() failed!\n");
		return -1;
	}

	/* Set contact into the message. */
	contact->id = id;
	contact->addr = addr;
	/* Set destination node as context. */
	evm_message_ctx_set(msg, (void *)node);
	/* Send protocom message with contact to another node. */
	evm_message_pass(consumer, msg);

	return 0;
}

static int send_protocol_init_msg(evmConsumerStruct *consumer, u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
#if 0 /*spog - orig*/
	evmMessageStruct *msg;
	u2upNodeRingContactStruct *contact = NULL;
#endif
	evm_log_info("(entry) consumer=%p, node=%p, addr=%u\n", consumer, node, addr);

	if ((consumer == NULL) || (node == NULL))
		return -1;

#if 0 /*spog - orig*/
	if ((msg = evm_message_new(msgtype_ptr, msgid_init_ptr, sizeof(u2upNodeRingContactStruct))) == NULL) {
		evm_log_error("evm_message_new() failed!\n");
		return -1;
	}

	if ((contact = (u2upNodeRingContactStruct *)evm_message_data_get(msg)) == NULL) {
		evm_log_error("evm_message_data_get() failed!\n");
		return -1;
	}
	/*set random contact into the message*/
	contact->id = id;
	contact->addr = addr;

	evm_message_ctx_set(msg, (void *)node);
	/* Send Initial random contact to the node. */
	evm_message_pass(consumer, msg);
#else
	if (send_protocol_msg(consumer, msgid_init_ptr, node, id, addr) != 0)
		return -1;
#endif

	return 0;
}

static int send_protocol_near_req_msg(evmConsumerStruct *consumer, u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
#if 0 /*spog - orig*/
	evmMessageStruct *msg;
	u2upNodeRingContactStruct *contact = NULL;
#endif
	evm_log_info("(entry) consumer=%p, node=%p, addr=%u\n", consumer, node, addr);

	if ((consumer == NULL) || (node == NULL))
		return -1;

#if 0 /*spog - orig*/
	if ((msg = evm_message_new(msgtype_ptr, msgid_near_req_ptr, sizeof(u2upNodeRingContactStruct))) == NULL) {
		evm_log_error("evm_message_new() failed!\n");
		return -1;
	}

	if ((contact = (u2upNodeRingContactStruct *)evm_message_data_get(req_msg)) == NULL) {
		evm_log_error("evm_message_data_get() failed!\n");
		return -1;
	}
	/*set own node contact into the message*/
	contact->id = id;
	contact->addr = addr;

	evm_message_ctx_set(msg, (void *)node);
	/* Send near_req message to the contact node. */
	evm_message_pass(consumer, msg);
#else
	if (send_protocol_msg(consumer, msgid_near_req_ptr, node, id, addr) != 0)
		return -1;
#endif

	return 0;
}

static int send_protocol_near_repl_msg(evmConsumerStruct *consumer, u2upNetNodeStruct *node, unsigned int id, uint32_t addr)
{
	evm_log_info("(entry) consumer=%p, node=%p, addr=%u\n", consumer, node, addr);

	if ((consumer == NULL) || (node == NULL))
		return -1;

	if (send_protocol_msg(consumer, msgid_near_repl_ptr, node, id, addr) != 0)
		return -1;

	return 0;
}

/* PROTOCOL event handlers */
static int evProtocolInitMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNetNodeStruct *node, *req_node;
	u2upNodeRingContactStruct *contact = NULL;
	evm_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((node = evm_message_ctx_get(msg)) == NULL)
		return -1;

	if ((contact = (u2upNodeRingContactStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	evm_log_info("(node id: %u) INIT msg received: contact: %u@%.8u\n", node->ctacts->myself->id, contact->id, contact->addr);

	if (insertNodeContact(node, contact->id, contact->addr) == NULL)
		return -1;

#if 1 /*spog - orig*/
	/*set protocol timeout to find nearest nodes*/
	node->tmrNearReq = protocol_start_timer(node->tmrNearReq, 3, 0, (void *)node, tmridNearReq);
#endif

	req_node = &nodes[contact->id];
	if (send_protocol_near_req_msg(consumer, req_node, node->ctacts->myself->id, node->ctacts->myself->addr) != 0)
		return -1;

	return 0;
}

static int handleTmrNearReq(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	u2upNetNodeStruct *node, *req_node;
	u2upNodeRingContactStruct *tmp = NULL;
	evm_log_info("(cb entry) tmr=%p\n", tmr);

	if ((node = evm_timer_ctx_get(tmr)) == NULL)
		return -1;

	evm_log_info("(node id: %u) NEAR REQUEST started:\n", node->ctacts->myself->id);

	tmp = node->ctacts->myself->next;
	do {
		if (tmp->own != 1) {
			req_node = &nodes[tmp->id];
			if (send_protocol_near_req_msg(consumer, req_node, node->ctacts->myself->id, node->ctacts->myself->addr) != 0)
				return -1;
			evm_log_info("(node id: %u) NEAR REQUEST sent to: %u@%.8u\n", node->ctacts->myself->id, req_node->ctacts->myself->id, req_node->ctacts->myself->addr);
		}
		tmp = tmp->next;
	} while (tmp != node->ctacts->myself);

	/*set protocol timeout to find nearest nodes*/
	node->tmrNearReq = protocol_start_timer(node->tmrNearReq, 1, 0, (void *)node, tmridNearReq);

	return 0;
}

static int evProtocolNearReqMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNetNodeStruct *node, *repl_node;
	u2upNodeRingContactStruct *contact = NULL;
	u2upNodeRingContactStruct *near_contact = NULL;
	evm_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((node = evm_message_ctx_get(msg)) == NULL)
		return -1;

	if ((contact = (u2upNodeRingContactStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	evm_log_info("(node id: %u) NEAR REQUEST msg received: contact: %u@%.8u\n", node->ctacts->myself->id, contact->id, contact->addr);

	if (insertNearAddrContact(node, contact->id, contact->addr) == NULL)
		return -1;

	repl_node = &nodes[contact->id];
	if ((near_contact = findNearNextContact(node, contact->addr)) == NULL)
		return -1;
	if (send_protocol_near_repl_msg(consumer, repl_node, near_contact->id, near_contact->addr) != 0)
		return -1;

	if ((near_contact = findNearPrevContact(node, contact->addr)) == NULL)
		return -1;
	if (send_protocol_near_repl_msg(consumer, repl_node, near_contact->id, near_contact->addr) != 0)
		return -1;

	return 0;
}

static int evProtocolNearReplMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNetNodeStruct *node;
	u2upNodeRingContactStruct *contact = NULL;
	evm_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((node = evm_message_ctx_get(msg)) == NULL)
		return -1;

	if ((contact = (u2upNodeRingContactStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	evm_log_info("(node id: %u) NEAR REPLY msg received: contact: %u@%.8u\n", node->ctacts->myself->id, contact->id, contact->addr);

	if (insertNearAddrContact(node, contact->id, contact->addr) == NULL)
		return -1;

	return 0;
}

static u2upNetRingAddrStruct * generateNewNetAddr(u2upNetRingHeadStruct *ring)
{
	int max_retry = 10;
	uint32_t addr = (uint32_t)rand();
	u2upNetRingAddrStruct *tmp = NULL;

	if (ring == NULL)
		abort();

	while ((max_retry > 0) && ((tmp = insertNewNetAddr(ring, addr)) == NULL)) {
		addr = (uint32_t)rand();
		max_retry--;
	}
	if (max_retry <= 0)
		abort();

	return tmp;
}

static unsigned int secs = 0;
int dump_u2up_net_ring(u2upNetRingHeadStruct *ring)
{
	u2upNetRingAddrStruct *ring_addr = NULL;
	u2upNodeRingContactStruct *ctact = NULL;
	char *pathname;
	FILE *file;

	if (ring == NULL)
		abort();

	asprintf(&pathname, "%s_%.8u.gv", outfile, secs);
	evm_log_notice("(Write file: %s)\n", pathname);
	if ((file = fopen(pathname, "w")) != NULL) {
		fprintf(file, "/* circo -Tsvg %s -o %s.svg -Nshape=box */\n", pathname, pathname);
		fprintf(file, "digraph \"u2upNet\" {\n");
		pthread_mutex_lock(&ring->amtx);

		/* Draw initial ring of addressed nodes */
		ring_addr = ring->first;
		if (ring_addr != NULL) {
			do {
				fprintf(file, "\"%.8x\" [label=\"%.8x\\n(%u)\"];\n", ring_addr->addr, ring_addr->addr, ring_addr->node->ctacts->myself->id);
				fprintf(file, "\"%.8x\" -> \"%.8x\" [color=black,arrowsize=0,style=dotted];\n", ring_addr->addr, ring_addr->next->addr);
				fprintf(file, "\"%.8x\" -> \"%.8x\" [color=black,arrowsize=0,style=dotted];\n", ring_addr->addr, ring_addr->prev->addr);
				ring_addr = ring_addr->next;
			} while (ring_addr != ring->first);
		}

		/* Draw all node contacts */
		ring_addr = ring->first;
		if (ring_addr != NULL) {
			do {
				ctact = ring_addr->node->ctacts->myself;
				if (ctact != NULL) {
					do {
						fprintf(file, "\"%.8x\" -> \"%.8x\" [color=black,arrowsize=0.7];\n", ring_addr->addr, ctact->addr);
						ctact = ctact->next;
					} while (ctact != ring_addr->node->ctacts->myself);
				}
				ring_addr = ring_addr->next;
			} while (ring_addr != ring->first);
		}

		pthread_mutex_unlock(&ring->amtx);
		fprintf(file, "}\n");
		fflush(file);
	}
	free(pathname);
	return 0;
}

static int handleTmrAuthBatch(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	int i;
	unsigned int rand_id;
	evmTmridStruct *tmrid_ptr;
	evm_log_info("(cb entry) tmr=%p\n", tmr);

	secs++;
	if (pthread_mutex_trylock(&simulation_global_mutex) == EBUSY) {
		evm_log_info("SIGUSR1 RECEIVED!\n");
		dump_u2up_net_ring(&net_addr_ring);
	}
	pthread_mutex_unlock(&simulation_global_mutex);

	evm_log_debug("AUTH_BATCH timer expired!\n");
	if (next_node < max_nodes) {
		evm_log_notice("(%d nodes)\n", next_node);
		for (i = 0; i < batch_nodes; i++) {
			if (next_node < max_nodes) {
				nodes[next_node].ringAddr = generateNewNetAddr(&net_addr_ring);
				nodes[next_node].maxCtacts = 7;
				nodes[next_node].numCtacts = 0;
				if (insertNodeMyself(&nodes[next_node], next_node, nodes[next_node].ringAddr->addr) == NULL)
					abort();
				pthread_mutex_init(&nodes[next_node].amtx, NULL);
				pthread_mutex_unlock(&nodes[next_node].amtx);
				nodes[next_node].consumer = protocol_consumer;
				nodes[next_node].tmrNearReq = NULL;
				nodes[next_node].ringAddr->node = &nodes[next_node];
				if (next_node > 0) {
					rand_id = rand() % next_node;
					send_protocol_init_msg(protocol_consumer, &nodes[next_node], nodes[rand_id].ctacts->myself->id, nodes[rand_id].ctacts->myself->addr);
				}
				next_node++;
			} else {
				evm_log_notice("(all %d nodes created)\n", next_node);
				break;
			}
		}
	}

	if ((tmrid_ptr = evm_tmrid_get(evm, TMR_ID_AUTH_BATCH)) == NULL)
		abort();
	tmrAuthBatch = auth_start_timer(tmrAuthBatch, 1, 0, NULL, tmrid_ptr);
	evm_log_debug("AUTH_BATCH timer set: 1 s\n");

	return 0;
}

#if 0
static int evHelloTmrQuit(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	evm_log_info("(cb entry) tmr=%p\n", tmr);

	evm_log_notice("QUIT timer expired (%d messages sent)!\n", count);

	exit(EXIT_SUCCESS);
}
#endif

/* EVM initialization */
static int simulation_evm_init(void)
{
	int rv = 0;

	evm_log_info("(entry)\n");

	/* Initialize event machine... */
	if ((evm = evm_init()) != NULL) {
#if 0
		if ((rv == 0) && ((consumer = evm_consumer_add(evm, EVM_CONSUMER_ID_0)) == NULL)) {
			evm_log_error("evm_consumer_add() failed!\n");
			rv = -1;
		}
#endif
		if ((rv == 0) && ((auth_consumer = evm_consumer_add(evm, EVM_CONSUMER_AUTH)) == NULL)) {
			evm_log_error("evm_consumer_add(EVM_CONSUMER_AUTH) failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((protocol_consumer = evm_consumer_add(evm, EVM_CONSUMER_PROTOCOL)) == NULL)) {
			evm_log_error("evm_consumer_add(EVM_CONSUMER_PROTOCOL) failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgtype_ptr = evm_msgtype_add(evm, EV_TYPE_PROTOCOL_MSG)) == NULL)) {
			evm_log_error("evm_msgtype_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_init_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_INIT)) == NULL)) {
			evm_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_init_ptr, evProtocolInitMsg) < 0)) {
			evm_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_near_req_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_NEAR_REQ)) == NULL)) {
			evm_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_near_req_ptr, evProtocolNearReqMsg) < 0)) {
			evm_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_near_repl_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_NEAR_REPL)) == NULL)) {
			evm_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_near_repl_ptr, evProtocolNearReplMsg) < 0)) {
			evm_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
	} else {
		evm_log_error("evm_init() failed!\n");
		rv = -1;
	}

	return rv;
}

/* Protocol processing thread */
static void * simulation_protocol_run(void *arg)
{
	evmConsumerStruct *consumer;

	evm_log_info("(entry)\n");

	if (arg == NULL)
		return NULL;

	consumer = (evmConsumerStruct *)arg;

	/* Prepare NEAR_REQ timer */
	if ((tmridNearReq = evm_tmrid_add(evm, TMR_ID_NEAR_REQ)) == NULL) {
		evm_log_error("evm_tmrid_add() failed!\n");
		abort();
	}
	if (evm_tmrid_cb_handle_set(tmridNearReq, handleTmrNearReq) < 0) {
		evm_log_error("evm_tmrid_cb_handle_set() failed!\n");
		abort();
	}
	/*
	 * Aditional thread EVM processing (event loop)
	 */
	evm_run(consumer);
	return NULL;
}

/* Main authority processing thread */
static int simulation_authority_run(void)
{
	int rv = 0;
	pthread_attr_t attr;
	pthread_t protocol_thread;
	evmTmridStruct *tmrid_ptr;
	evm_log_info("(entry)\n");

	/* Create additional protocol thread */
	if ((rv = pthread_attr_init(&attr)) != 0)
		evm_log_return_system_err("pthread_attr_init()\n");

	if ((rv = pthread_create(&protocol_thread, &attr, simulation_protocol_run, (void *)protocol_consumer)) != 0)
		evm_log_return_system_err("pthread_create()\n");
	evm_log_debug("pthread_create() rv=%d\n", rv);

	/* Prepare AUTH_BATCH periodic timer */
	if ((tmrid_ptr = evm_tmrid_add(evm, TMR_ID_AUTH_BATCH)) == NULL) {
		evm_log_error("evm_tmrid_add() failed!\n");
		abort();
	}
	if (evm_tmrid_cb_handle_set(tmrid_ptr, handleTmrAuthBatch) < 0) {
		evm_log_error("evm_tmrid_cb_handle_set() failed!\n");
		abort();
	}
	tmrAuthBatch = auth_start_timer(NULL, 1, 0, NULL, tmrid_ptr);
	evm_log_notice("AUTH_BATCH timer set: 1 s\n");

#if 0
	/* Set initial QUIT timer */
	if ((tmrid_ptr = evm_tmrid_add(evm, EV_ID_HELLO_TMR_QUIT)) == NULL)
		return -1;
	if (evm_tmrid_cb_handle_set(tmrid_ptr, evHelloTmrQuit) < 0)
		return -1;
	helloQuitTmr = start_timer(NULL, 60, 0, NULL, tmrid_ptr);
	evm_log_notice("QUIT timer set: 60 s\n");
#endif

	/*
	 * Main EVM processing (event loop)
	 */
#if 1 /*orig*/
	return evm_run(auth_consumer);
#else
	while (1) {
		evm_run_async(consumer);
		evm_log_notice("Returned from evm_run_async()\n");
/**/		sleep(15);
		evm_log_notice("Returned from sleep()\n");
/**/		sleep(2);
	}
	return 1;
#endif
}

static void simulation_sighandler(int signum, siginfo_t *siginfo, void *context)
{
	pthread_mutex_lock(&simulation_global_mutex);
}

static int simulation_sighandler_install(int signum)
{
	struct sigaction act;

	memset (&act, '\0', sizeof(act));
	/* Use the sa_sigaction field because the handle has two additional parameters */
	act.sa_sigaction = &simulation_sighandler;
	/* The SA_SIGINFO flag tells sigaction() to use the sa_sigaction field, not sa_handler. */
	act.sa_flags = SA_SIGINFO;

	if (sigaction(signum, &act, NULL) < 0)
		evm_log_return_system_err("sigaction() for signum %d\n", signum);

	return 0;
}

/*
 * The MAIN part.
 */
unsigned int log_mask;
unsigned int evmlog_normal = 1;
unsigned int evmlog_verbose = 0;
unsigned int evmlog_trace = 0;
unsigned int evmlog_debug = 0;
unsigned int evmlog_use_syslog = 0;
unsigned int evmlog_add_header = 1;

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options]\n", argv[0]);
	printf("options:\n");
	printf("\t-q, --quiet              Disable all output.\n");
	printf("\t-v, --verbose            Enable verbose output.\n");
	printf("\t-b, --batch-nodes        Number of nodes to be created in a batch (default=%u).\n", batch_nodes);
	printf("\t-m, --max-nodes          Maximum number of all nodes to be created (default=%u).\n", max_nodes);
	printf("\t-o, --outfile            Output [path/]filename prefix (default=%s).\n", default_outfile);
#if (EVMLOG_MODULE_TRACE != 0)
	printf("\t-t, --trace              Enable trace output.\n");
#endif
#if (EVMLOG_MODULE_DEBUG != 0)
	printf("\t-g, --debug              Enable debug output.\n");
#endif
	printf("\t-s, --syslog             Enable syslog output (instead of stdout, stderr).\n");
	printf("\t-n, --no-header          No EVMLOG header added to every evm_log_... output.\n");
	printf("\t-h, --help               Displays this text.\n");
}

static int usage_check(int argc, char *argv[])
{
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"quiet", 0, 0, 'q'},
			{"verbose", 0, 0, 'v'},
			{"batch-nodes", 1, 0, 'b'},
			{"max-nodes", 1, 0, 'm'},
			{"outfile", 1, 0, 'o'},
#if (EVMLOG_MODULE_TRACE != 0)
			{"trace", 0, 0, 't'},
#endif
#if (EVMLOG_MODULE_DEBUG != 0)
			{"debug", 0, 0, 'g'},
#endif
			{"no-header", 0, 0, 'n'},
			{"syslog", 0, 0, 's'},
			{"help", 0, 0, 'h'},
			{0, 0, 0, 0}
		};

#if (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qvb:m:o:tgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE == 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qvb:m:o:gnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG == 0)
		c = getopt_long(argc, argv, "qvb:m:o:tnsh", long_options, &option_index);
#else
		c = getopt_long(argc, argv, "qvb:m:o:nsh", long_options, &option_index);
#endif
		if (c == -1)
			break;

		switch (c) {
		case 'q':
			evmlog_normal = 0;
			break;

		case 'v':
			evmlog_verbose = 1;
			break;

		case 'b':
			printf("batch-nodes: optarg=%s\n", optarg);
			batch_nodes = atoi(optarg);
			break;

		case 'm':
			printf("max-nodes: optarg=%s\n", optarg);
			max_nodes = atoi(optarg);
			break;

		case 'o':
			printf("outfile: optarg=%s\n", optarg);
			asprintf(&outfile, "%s_%.4d-%.2d-%.2d-%.2d%.2d", optarg, start.tm_year + 1900, start.tm_mon + 1, start.tm_mday, start.tm_hour, start.tm_min);
			break;

#if (EVMLOG_MODULE_TRACE != 0)
		case 't':
			evmlog_trace = 1;
			break;
#endif

#if (EVMLOG_MODULE_DEBUG != 0)
		case 'g':
			evmlog_debug = 1;
			break;
#endif

		case 'n':
			evmlog_add_header = 0;
			break;

		case 's':
			evmlog_use_syslog = 1;
			break;

		case 'h':
			usage_help(argv);
			exit(EXIT_SUCCESS);

		case '?':
			exit(EXIT_FAILURE);
			break;

		default:
			printf("?? getopt returned character code 0%o ??\n", c);
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		printf("non-option ARGV-elements: ");
		while (optind < argc)
			printf("%s ", argv[optind++]);
		printf("\n");
		exit(EXIT_FAILURE);
	}

	if (outfile == NULL)
		asprintf(&outfile, "%s_%.4d-%.2d-%.2d-%.2d%.2d", default_outfile, start.tm_year + 1900, start.tm_mon + 1, start.tm_mday, start.tm_hour, start.tm_min);

#if 1 /*samo - test:*/
	printf("batch_nodes = %u\n", batch_nodes);
	printf("max_nodes = %u\n", max_nodes);
	printf("outfile = %s\n", outfile);
	printf("distance from 0xffffffff to 0x0 = %d\n", calcDistance((uint32_t)0xffffffff, (uint32_t)0x0));
	printf("distance from 0x1 to 0xffffffff = %d\n", calcDistance((uint32_t)0x1, (uint32_t)0xffffffff));
	printf("distance from 0x7fffffff to 0x0 = %d\n", calcDistance((uint32_t)0x7fffffff, (uint32_t)0x0));
	printf("distance from 0x1 to 0x7fffffff = %d\n", calcDistance((uint32_t)0x1, (uint32_t)0x7fffffff));
	printf("distance from 0x80000000 to 0x0 = %d\n", calcDistance((uint32_t)0x80000000, (uint32_t)0x0));
	printf("distance from 0x80000001 to 0x0 = %d\n", calcDistance((uint32_t)0x80000001, (uint32_t)0x0));
	printf("distance from 0x1 to 0x80000000 = %d\n", calcDistance((uint32_t)0x1, (uint32_t)0x80000000));
	printf("distance from 0x1 to 0x80000001 = %d\n", calcDistance((uint32_t)0x1, (uint32_t)0x80000001));
	printf("distance from 0x1 to 0x80000002 = %d\n", calcDistance((uint32_t)0x1, (uint32_t)0x80000002));
	printf("distance from 0x7ffffffd to 0x80000003 = %d\n", calcDistance((uint32_t)0x7ffffffd, (uint32_t)0x80000003));
	printf("distance from 0x7ffffffe to 0x80000003 = %d\n", calcDistance((uint32_t)0x7ffffffe, (uint32_t)0x80000003));
	printf("distance from 0x7fffffff to 0x80000003 = %d\n", calcDistance((uint32_t)0x7fffffff, (uint32_t)0x80000003));
	printf("distance from 0x80000000 to 0x80000003 = %d\n", calcDistance((uint32_t)0x80000000, (uint32_t)0x80000003));
	printf("distance from 0x80000001 to 0x80000003 = %d\n", calcDistance((uint32_t)0x80000001, (uint32_t)0x80000003));
	printf("distance from 0x80000002 to 0x80000003 = %d\n", calcDistance((uint32_t)0x80000002, (uint32_t)0x80000003));
	printf("distance from 0x80000003 to 0x80000003 = %d\n", calcDistance((uint32_t)0x80000003, (uint32_t)0x80000003));
	printf("distance = %d\n", calcDistance((uint32_t)6, (uint32_t)6));
#endif
	return 0;
}

int main(int argc, char *argv[])
{
	time_t loctime;

	time(&loctime);
	localtime_r(&loctime, &start);

	usage_check(argc, argv);

	log_mask = LOG_MASK(LOG_EMERG) | LOG_MASK(LOG_ALERT) | LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR);

	/* Setup LOG_MASK according to startup arguments! */
	if (evmlog_normal) {
		log_mask |= LOG_MASK(LOG_WARNING);
		log_mask |= LOG_MASK(LOG_NOTICE);
	}
	if ((evmlog_verbose) || (evmlog_trace))
		log_mask |= LOG_MASK(LOG_INFO);
	if (evmlog_debug)
		log_mask |= LOG_MASK(LOG_DEBUG);

	setlogmask(log_mask);

	/* Prepare nodes table */
	if ((nodes = (u2upNetNodeStruct *)calloc(max_nodes, sizeof(u2upNetNodeStruct))) == NULL)
		abort();

	/* Initialize net_addr_ring structure */
	net_addr_ring.first = NULL;
	pthread_mutex_init(&net_addr_ring.amtx, NULL);
	pthread_mutex_unlock(&net_addr_ring.amtx);

	pthread_mutex_init(&simulation_global_mutex, NULL);
	pthread_mutex_unlock(&simulation_global_mutex);

	if (simulation_sighandler_install(SIGUSR1) != 0)
		exit(EXIT_FAILURE);

	srand(time(NULL));   /*to be called only once*/
	if (simulation_evm_init() < 0)
		exit(EXIT_FAILURE);

	if (simulation_authority_run() < 0)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}


