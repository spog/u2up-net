/*
 * The u2up-netsim network simulation program
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

#ifndef U2UP_NET_FILE_u2up_netsim_c
#define U2UP_NET_FILE_u2up_netsim_c
#else
#error Preprocesor macro U2UP_NET_FILE_u2up_netsim_c conflict!
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
#include "u2up-netsim.h"
#include "netsim-common.h"
#include "netsim-clisrv.h"

#define U2UP_LOG_NAME U2NETSIM
#include <u2up-log/u2up-log.h>
/* Declare all other used "u2up-log" modules: */
U2UP_LOG_DECLARE(EVM_CORE);
U2UP_LOG_DECLARE(EVM_MSGS);
U2UP_LOG_DECLARE(EVM_TMRS);
U2UP_LOG_DECLARE(U2NETCLI);
U2UP_LOG_DECLARE(U2CLISRV);

unsigned int log_mask;

unsigned int auto_dump = 0;
unsigned int batch_nodes = 1;
unsigned int max_nodes = 10;
static char *default_outfile = "./dump-net-ring";
static char *outfile = NULL;
static char *start_time = NULL;
static struct tm start;

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options]\n", argv[0]);
	printf("options:\n");
	printf("\t-a, --auto-dump          Automatically dump u2up network ring on node changes.\n");
	printf("\t-b, --batch-nodes NUM    Number of nodes to be created in a batch (default=%u).\n", batch_nodes);
	printf("\t-m, --max-nodes NUM      Maximum number of all nodes to be created (default=%u).\n", max_nodes);
	printf("\t-o, --outfile PREFIX     Output [path/]filename prefix (default=%s).\n", default_outfile);
	printf("\t-q, --log-quiet          Disable all output.\n");
	printf("\t-v, --log-verbose        Enable verbose output.\n");
#if (U2UP_LOG_MODULE_TRACE != 0)
	printf("\t-t, --log-trace          Enable trace output.\n");
#endif
#if (U2UP_LOG_MODULE_DEBUG != 0)
	printf("\t-g, --log-debug          Enable debug output.\n");
#endif
	printf("\t-s, --log-syslog         Enable syslog output (instead of stdout, stderr).\n");
	printf("\t-n, --log-no-header      No U2UP_LOG header added to every u2up_log_... output.\n");
	printf("\t-f, --log-filter NAME    Disable outout from U2UP_LOG module NAME prefix.\n");
	printf("\t-h, --help               Displays this text.\n");
}

static int usage_check(int argc, char *argv[])
{
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"auto-dump", 0, 0, 'a'},
			{"batch-nodes", 1, 0, 'b'},
			{"max-nodes", 1, 0, 'm'},
			{"outfile", 1, 0, 'o'},
			{"log-quiet", 0, 0, 'q'},
			{"log-verbose", 0, 0, 'v'},
#if (U2UP_LOG_MODULE_TRACE != 0)
			{"log-trace", 0, 0, 't'},
#endif
#if (U2UP_LOG_MODULE_DEBUG != 0)
			{"log-debug", 0, 0, 'g'},
#endif
			{"log-syslog", 0, 0, 's'},
			{"log-no-header", 0, 0, 'n'},
			{"log-filter", 1, 0, 'f'},
			{"help", 0, 0, 'h'},
			{0, 0, 0, 0}
		};

#if (U2UP_LOG_MODULE_TRACE != 0) && (U2UP_LOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "ab:m:o:qvtgsnf:h", long_options, &option_index);
#elif (U2UP_LOG_MODULE_TRACE == 0) && (U2UP_LOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "ab:m:o:qvgsnf:h", long_options, &option_index);
#elif (U2UP_LOG_MODULE_TRACE != 0) && (U2UP_LOG_MODULE_DEBUG == 0)
		c = getopt_long(argc, argv, "ab:m:o:qvtsnf:h", long_options, &option_index);
#else
		c = getopt_long(argc, argv, "ab:m:o:qvsnf:h", long_options, &option_index);
#endif
		if (c == -1)
			break;

		switch (c) {
		case 'a':
			auto_dump = 1;
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

		case 'q':
			U2UP_LOG_SET_QUIET(1);
			U2UP_LOG_SET_QUIET2(EVM_CORE, 1);
			U2UP_LOG_SET_QUIET2(EVM_MSGS, 1);
			U2UP_LOG_SET_QUIET2(EVM_TMRS, 1);
			U2UP_LOG_SET_QUIET2(U2NETCLI, 1);
			U2UP_LOG_SET_QUIET2(U2CLISRV, 1);
			break;

		case 'v':
			U2UP_LOG_SET_VERBOSE(1);
			U2UP_LOG_SET_VERBOSE2(EVM_CORE, 1);
			U2UP_LOG_SET_VERBOSE2(EVM_MSGS, 1);
			U2UP_LOG_SET_VERBOSE2(EVM_TMRS, 1);
			U2UP_LOG_SET_VERBOSE2(U2NETCLI, 1);
			U2UP_LOG_SET_VERBOSE2(U2CLISRV, 1);
			break;

#if (U2UP_LOG_MODULE_TRACE != 0)
		case 't':
			U2UP_LOG_SET_TRACE(1);
			U2UP_LOG_SET_TRACE2(EVM_CORE, 1);
			U2UP_LOG_SET_TRACE2(EVM_MSGS, 1);
			U2UP_LOG_SET_TRACE2(EVM_TMRS, 1);
			U2UP_LOG_SET_TRACE2(U2NETCLI, 1);
			U2UP_LOG_SET_TRACE2(U2CLISRV, 1);
			break;
#endif

#if (U2UP_LOG_MODULE_DEBUG != 0)
		case 'g':
			U2UP_LOG_SET_DEBUG(1);
			U2UP_LOG_SET_DEBUG2(EVM_CORE, 1);
			U2UP_LOG_SET_DEBUG2(EVM_MSGS, 1);
			U2UP_LOG_SET_DEBUG2(EVM_TMRS, 1);
			U2UP_LOG_SET_DEBUG2(U2NETCLI, 1);
			U2UP_LOG_SET_DEBUG2(U2CLISRV, 1);
			break;
#endif

		case 's':
			U2UP_LOG_SET_SYSLOG(1);
			U2UP_LOG_SET_SYSLOG2(EVM_CORE, 1);
			U2UP_LOG_SET_SYSLOG2(EVM_MSGS, 1);
			U2UP_LOG_SET_SYSLOG2(EVM_TMRS, 1);
			U2UP_LOG_SET_SYSLOG2(U2NETCLI, 1);
			U2UP_LOG_SET_SYSLOG2(U2CLISRV, 1);
			break;

		case 'n':
			U2UP_LOG_SET_HEADER(0);
			U2UP_LOG_SET_HEADER2(EVM_CORE, 0);
			U2UP_LOG_SET_HEADER2(EVM_MSGS, 0);
			U2UP_LOG_SET_HEADER2(EVM_TMRS, 0);
			U2UP_LOG_SET_HEADER2(U2NETCLI, 0);
			U2UP_LOG_SET_HEADER2(U2CLISRV, 0);
			break;

		case 'f': {
				size_t optlen = strlen(optarg);
				printf("no-module: optlen=%zd, optarg=%s\n", optlen, optarg);
				if (strlen(U2UP_LOG_GET_NAME()) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME(), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET(1);
					}
				if (strlen(U2UP_LOG_GET_NAME2(EVM_CORE)) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME2(EVM_CORE), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET2(EVM_CORE, 1);
					}
				if (strlen(U2UP_LOG_GET_NAME2(EVM_MSGS)) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME2(EVM_MSGS), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET2(EVM_MSGS, 1);
					}
				if (strlen(U2UP_LOG_GET_NAME2(EVM_TMRS)) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME2(EVM_TMRS), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET2(EVM_TMRS, 1);
					}
				if (strlen(U2UP_LOG_GET_NAME2(U2NETCLI)) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME2(U2NETCLI), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET2(U2NETCLI, 1);
					}
				if (strlen(U2UP_LOG_GET_NAME2(U2CLISRV)) >= optlen)
					if (strncmp(U2UP_LOG_GET_NAME2(U2CLISRV), optarg, optlen) == 0) {
						U2UP_LOG_SET_QUIET2(U2CLISRV, 1);
					}
			}
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
		asprintf(&outfile, "%s", default_outfile);
	if (start_time == NULL)
		asprintf(&start_time, "%.4d-%.2d-%.2d-%.2d%.2d", start.tm_year + 1900, start.tm_mon + 1, start.tm_mday, start.tm_hour, start.tm_min);

	printf("batch_nodes = %u\n", batch_nodes);
	printf("max_nodes = %u\n", max_nodes);
	printf("outfile = %s\n", outfile);
	printf("start_time = %s\n", start_time);
	return 0;
}

enum evm_msg_ids {
	EV_ID_PROTOCOL_MSG_INIT = 0,
	EV_ID_PROTOCOL_MSG_RANDOM_REQ,
	EV_ID_PROTOCOL_MSG_RANDOM_REPL,
	EV_ID_PROTOCOL_MSG_NEAR_REQ,
	EV_ID_PROTOCOL_MSG_NEAR_REPL
};

static evmTimerStruct * auth_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr);

static int evProtocolInitMsg(evmConsumerStruct *consumer, evmMessageStruct *msg);

static pthread_mutex_t simulation_global_mutex;
static int simulation_evm_init(void);
static int simulation_authority_run(void);

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
static evmMsgidStruct *msgid_random_req_ptr;
static evmMsgidStruct *msgid_random_repl_ptr;
static evmMsgidStruct *msgid_near_req_ptr;
static evmMsgidStruct *msgid_near_repl_ptr;

static u2upNodeOwnCtactStruct * getOwnCtact(unsigned int id, uint32_t addr)
{
	u2upNetNodeStruct *node = &nodes[id];
	u2upNodeOwnCtactStruct *ownCtact;

	if (node == NULL)
		return NULL;

	ownCtact = node->ctacts;
	while (ownCtact != NULL) {
		if (ownCtact->myself != NULL)
			if (ownCtact->myself->addr == addr)
				break;
		ownCtact = ownCtact->next;
	}

	return ownCtact;
}

/* Timers */
static evmTmridStruct *tmridProtoRun;
static evmTmridStruct *tmridWaitRepl;
static evmTimerStruct *tmrAuthBatch;

static evmTimerStruct * auth_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr)
{
	u2up_log_info("(entry) tmr=%p, sec=%ld, nsec=%ld, ctx_ptr=%p\n", tmr, tv_sec, tv_nsec, ctx_ptr);

	if (evm_timer_stop(tmr) == 0)
		evm_timer_delete(tmr);

	return evm_timer_start(auth_consumer, tmrid_ptr, tv_sec, tv_nsec, ctx_ptr);
}

static evmTimerStruct * startTmrProtoRun(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr)
{
	u2up_log_info("(entry) tmr=%p, sec=%ld, nsec=%ld, ctx_ptr=%p\n", tmr, tv_sec, tv_nsec, ctx_ptr);

	if (evm_timer_stop(tmr) == 0)
		evm_timer_delete(tmr);

	return evm_timer_start(protocol_consumer, tmrid_ptr, tv_sec, tv_nsec, ctx_ptr);
}

/* Send PROTOCOL messages */
static int send_protocol_msg(evmConsumerStruct *consumer, evmMsgidStruct *msgid_ptr, u2upNodeOwnCtactStruct *destCtact, unsigned int id, uint32_t addr, void *ref)
{
	evmMessageStruct *msg;
	u2upProtocolMsgDataStruct *data = NULL;
	u2up_log_info("(entry) consumer=%p, msgid_ptr=%p, destCtact=%p, from=%u@%.8x\n", consumer, msgid_ptr, destCtact, id, addr);

	if ((consumer == NULL) || (msgid_ptr == NULL) || (destCtact == NULL))
		return -1;

	if ((msg = evm_message_new(msgtype_ptr, msgid_ptr, sizeof(u2upProtocolMsgDataStruct))) == NULL) {
		u2up_log_error("evm_message_new() failed!\n");
		return -1;
	}

	if ((data = (u2upProtocolMsgDataStruct *)evm_message_data_get(msg)) == NULL) {
		u2up_log_error("evm_message_data_get() failed!\n");
		return -1;
	}

	/* Set data into the message (data to be used at destination). */
	data->id = id; /* contact info */
	data->addr = addr; /* contact info */
	data->ref = ref; /* link to reply timeout */
	/* Set destination node as context. */
	evm_message_ctx_set(msg, (void *)destCtact);
	/* Send protocom message with contact info to another node. */
	evm_message_pass(consumer, msg);

	return 0;
}

static int send_protocol_init_msg(evmConsumerStruct *consumer, u2upNodeOwnCtactStruct *destCtact, unsigned int id, uint32_t addr)
{
	u2up_log_info("(entry) consumer=%p, destCtact=%p, from=%u@%.8x\n", consumer, destCtact, id, addr);

	if ((consumer == NULL) || (destCtact == NULL))
		return -1;

	if (send_protocol_msg(consumer, msgid_init_ptr, destCtact, id, addr, NULL) != 0)
		return -1;

	return 0;
}

static int send_protocol_random_req_msg(evmConsumerStruct *consumer, u2upNodeOwnCtactStruct *destCtact, unsigned int id, uint32_t addr)
{
	evmTimerStruct *tmr;
	u2upProtocolTmrCtxStruct *tmrCtx;
	u2up_log_info("(entry) consumer=%p, destCtact=%p, from=%u@%.8x\n", consumer, destCtact, id, addr);

	if ((consumer == NULL) || (destCtact == NULL))
		return -1;

	if ((tmrCtx = (u2upProtocolTmrCtxStruct *)calloc(1, sizeof(u2upProtocolTmrCtxStruct))) == NULL)
		abort();
	tmrCtx->src_id = id;
	tmrCtx->src_addr = addr;
	tmrCtx->dst_id = destCtact->myself->id;
	tmrCtx->dst_addr = destCtact->myself->addr;

	tmr = evm_timer_start(protocol_consumer, tmridWaitRepl, /*tv_sec*/ 5, /*tv_nsec*/ 0, (void *)tmrCtx);

	if (send_protocol_msg(consumer, msgid_random_req_ptr, destCtact, id, addr, (void *)tmr) != 0)
		return -1;
	u2up_log_info("(node: %u@%.8x with tmr=%p) RANDOM REQUEST sent to: %u@%.8x\n",
			id, addr, tmr, destCtact->myself->id, destCtact->myself->addr);

	return 0;
}

static int send_protocol_random_repl_msg(evmConsumerStruct *consumer, u2upNodeOwnCtactStruct *destCtact, unsigned int id, uint32_t addr, void *ref)
{
	u2up_log_info("(entry) consumer=%p, destCtact=%p, from=%u@%.8x, ref=%p\n", consumer, destCtact, id, addr, ref);

	if ((consumer == NULL) || (destCtact == NULL))
		return -1;

	if (send_protocol_msg(consumer, msgid_random_repl_ptr, destCtact, id, addr, ref) != 0)
		return -1;
	u2up_log_info("(contact: %u@%.8x with ref=%p) RANDOM REPLY sent to: %u@%.8x\n",
			id, addr, ref, destCtact->myself->id, destCtact->myself->addr);

	return 0;
}

static int send_protocol_near_req_msg(evmConsumerStruct *consumer, u2upNodeOwnCtactStruct *destCtact, unsigned int id, uint32_t addr)
{
	evmTimerStruct *tmr;
	u2upProtocolTmrCtxStruct *tmrCtx;
	u2up_log_info("(entry) consumer=%p, destCtact=%p, from=%u@%.8x\n", consumer, destCtact, id, addr);

	if ((consumer == NULL) || (destCtact == NULL))
		return -1;

	if ((tmrCtx = (u2upProtocolTmrCtxStruct *)calloc(1, sizeof(u2upProtocolTmrCtxStruct))) == NULL)
		abort();
	tmrCtx->src_id = id;
	tmrCtx->src_addr = addr;
	tmrCtx->dst_id = destCtact->myself->id;
	tmrCtx->dst_addr = destCtact->myself->addr;

	tmr = evm_timer_start(protocol_consumer, tmridWaitRepl, /*tv_sec*/ 5, /*tv_nsec*/ 0, (void *)tmrCtx);

	if (send_protocol_msg(consumer, msgid_near_req_ptr, destCtact, id, addr, (void *)tmr) != 0)
		return -1;
	u2up_log_info("(node: %u@%.8x with tmr=%p) NEAR REQUEST sent to: %u@%.8x\n",
			id, addr, tmr, destCtact->myself->id, destCtact->myself->addr);

	return 0;
}

static int send_protocol_near_repl_msg(evmConsumerStruct *consumer, u2upNodeOwnCtactStruct *destCtact, unsigned int id, uint32_t addr, void *ref)
{
	u2up_log_info("(entry) consumer=%p, destCtact=%p, from=%u@%.8x, ref=%p\n", consumer, destCtact, id, addr, ref);

	if ((consumer == NULL) || (destCtact == NULL))
		return -1;

	if (send_protocol_msg(consumer, msgid_near_repl_ptr, destCtact, id, addr, ref) != 0)
		return -1;
	u2up_log_info("(contact: %u@%.8x with ref=%p) NEAR REPLY sent to: %u@%.8x\n",
			id, addr, ref, destCtact->myself->id, destCtact->myself->addr);

	return 0;
}

/* PROTOCOL event handlers */
static int evProtocolInitMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNodeOwnCtactStruct *ownCtact;
	u2upNodeOwnCtactStruct *destCtact;
	u2upNodeRingContactStruct *contact = NULL;
	u2up_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((ownCtact = (u2upNodeOwnCtactStruct *)evm_message_ctx_get(msg)) == NULL)
		return -1;

	if ((contact = (u2upNodeRingContactStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	u2up_log_info("(node: %u@%.8x) INIT msg received: contact: %u@%.8x\n", ownCtact->myself->id, ownCtact->myself->addr, contact->id, contact->addr);

	insertNodeContact(ownCtact, contact->id, contact->addr);

	if ((destCtact = getOwnCtact(contact->id, contact->addr)) == NULL)
		return -1;

	if (send_protocol_random_req_msg(consumer, destCtact, ownCtact->myself->id, ownCtact->myself->addr) != 0)
		return -1;
	ownCtact->sentMsgs++;

	return 0;
}

static int handleTmrProtoRun(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	u2upNetNodeStruct *node, *dest_node;
	u2upNodeOwnCtactStruct *ownCtact;
	u2upNodeRingContactStruct *tmp = NULL;
	u2up_log_info("(cb entry) tmr=%p\n", tmr);

	if ((ownCtact = (u2upNodeOwnCtactStruct *)evm_timer_ctx_get(tmr)) == NULL)
		return -1;

	if ((node = ownCtact->ownNode) == NULL)
		return -1;

#if 1
	/*set protocol timeout to find nearest nodes*/
	ownCtact->tmrProtoRun = startTmrProtoRun(ownCtact->tmrProtoRun, 1, 0, (void *)ownCtact, tmridProtoRun);
#endif

	if (node->active != U2UP_NET_TRUE) {
		u2up_log_info("(node: %u@%.8x disabled) PROTO RUN ignored\n", ownCtact->myself->id, ownCtact->myself->addr);
		return -1;
	}

	u2up_log_info("(node: %u@%.8x) PROTO RUN started\n", ownCtact->myself->id, ownCtact->myself->addr);

#if 0
	/*set protocol timeout to find nearest nodes*/
	ownCtact->tmrProtoRun = startTmrProtoRun(ownCtact->tmrProtoRun, 1, 0, (void *)ownCtact, tmridProtoRun);
#endif

	pthread_mutex_lock(&node->amtx);
	tmp = node->ctacts->myself->next;
	/* got through all remote contacts of the node */
	do {
		/* skip own addresses */
		if (tmp->own != 1) {
			dest_node = &nodes[tmp->id];
			/* Until maxCtacts reached search for "random" contacts, afterwards optimize for "nearest" contacts! */
			if (ownCtact->numCtacts < node->maxCtacts) {
				send_protocol_random_req_msg(consumer, dest_node->ctacts, node->ctacts->myself->id, node->ctacts->myself->addr);
				ownCtact->sentMsgs++;
			} else {
				send_protocol_near_req_msg(consumer, dest_node->ctacts, node->ctacts->myself->id, node->ctacts->myself->addr);
				ownCtact->sentMsgs++;
			}
		}
		tmp = tmp->next;
	} while (tmp != node->ctacts->myself);
	pthread_mutex_unlock(&node->amtx);

	return 0;
}

static int handleTmrWaitRepl(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	u2upProtocolTmrCtxStruct *tmrCtx;
	u2upNodeOwnCtactStruct *ownCtact;
	u2up_log_info("(cb entry) tmr=%p\n", tmr);

	if ((tmrCtx = (u2upProtocolTmrCtxStruct *)evm_timer_ctx_get(tmr)) == NULL)
		return -1;

	u2up_log_info(
		"(node: %u@%.8x, tmr=%p) WAIT REPLY expired (expected from: %u@%.8x)\n",
		tmrCtx->src_id, tmrCtx->src_addr, tmr, tmrCtx->dst_id, tmrCtx->dst_addr
	);

	if ((ownCtact = getOwnCtact(tmrCtx->src_id, tmrCtx->src_addr)) == NULL)
		return -1;

	retireNodeContactByAddr(ownCtact->ownNode, tmrCtx->dst_addr);

	return 0;
}

static int evProtocolRandomReqMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNetNodeStruct *node;
	u2upNodeOwnCtactStruct *ownCtact;
	u2upNodeOwnCtactStruct *destCtact;
	u2upProtocolMsgDataStruct *data = NULL;
	u2upNodeRingContactStruct *random_contact = NULL;
	u2up_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((ownCtact = (u2upNodeOwnCtactStruct *)evm_message_ctx_get(msg)) == NULL)
		return -1;
	ownCtact->recvdMsgs++;

	if ((node = ownCtact->ownNode) == NULL)
		return -1;

	if (node->active != U2UP_NET_TRUE) {
		u2up_log_info("(node: %u@%.8x disabled) RANDOM REQUEST msg ignored\n", ownCtact->myself->id, ownCtact->myself->addr);
		return -1;
	}

	if ((data = (u2upProtocolMsgDataStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	u2up_log_info(
		"(node: %u@%.8x) RANDOM REQUEST msg received (from: %u@%.8x with ref=%p)\n",
		ownCtact->myself->id, ownCtact->myself->addr, data->id, data->addr, data->ref
	);

	insertNodeContact(ownCtact, data->id, data->addr);

	if ((destCtact = getOwnCtact(data->id, data->addr)) == NULL)
		return -1;

	if ((random_contact = getRandomRemoteContact(ownCtact)) != NULL) {
		send_protocol_random_repl_msg(consumer, destCtact, random_contact->id, random_contact->addr, data->ref);
		ownCtact->sentMsgs++;
	} else {
		send_protocol_random_repl_msg(consumer, destCtact, ownCtact->myself->id, ownCtact->myself->addr, data->ref);
		ownCtact->sentMsgs++;
	}

	return 0;
}

static int evProtocolRandomReplMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNodeOwnCtactStruct *ownCtact;
	u2upProtocolMsgDataStruct *data = NULL;
	u2up_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((ownCtact = (u2upNodeOwnCtactStruct *)evm_message_ctx_get(msg)) == NULL)
		return -1;
	ownCtact->recvdMsgs++;

	if ((data = (u2upProtocolMsgDataStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	u2up_log_info(
		"(node: %u@%.8x) RANDOM REPLY msg received: (contact: %u@%.8x, ref=%p)\n",
		ownCtact->myself->id, ownCtact->myself->addr, data->id, data->addr, data->ref
	);

	if (evm_timer_stop((evmTimerStruct *)data->ref) == 0)
		evm_timer_delete((evmTimerStruct *)data->ref);

	insertNodeContact(ownCtact, data->id, data->addr);

	return 0;
}

static int evProtocolNearReqMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNetNodeStruct *node;
	u2upNodeOwnCtactStruct *ownCtact;
	u2upNodeOwnCtactStruct *destCtact;
	u2upProtocolMsgDataStruct *data = NULL;
	u2upNodeRingContactStruct *near_contact = NULL;
	u2up_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((ownCtact = (u2upNodeOwnCtactStruct *)evm_message_ctx_get(msg)) == NULL)
		return -1;
	ownCtact->recvdMsgs++;

	if ((node = ownCtact->ownNode) == NULL)
		return -1;

	if (node->active != U2UP_NET_TRUE) {
		u2up_log_info("(node: %u@%.8x disabled) NEAR REQUEST msg ignored\n", ownCtact->myself->id, ownCtact->myself->addr);
		return -1;
	}

	if ((data = (u2upProtocolMsgDataStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	u2up_log_info(
		"(node: %u@%.8x) NEAR REQUEST msg received (from: %u@%.8x with ref=%p)\n",
		ownCtact->myself->id, ownCtact->myself->addr, data->id, data->addr, data->ref
	);

	insertNearAddrContact(ownCtact, data->id, data->addr);

	if ((destCtact = getOwnCtact(data->id, data->addr)) == NULL)
		return -1;

	if ((near_contact = findNearNextContact(node, data->addr)) != NULL) {
		send_protocol_near_repl_msg(consumer, destCtact, near_contact->id, near_contact->addr, data->ref);
		ownCtact->sentMsgs++;
	} else {
		send_protocol_near_repl_msg(consumer, destCtact, ownCtact->myself->id, ownCtact->myself->addr, data->ref);
		ownCtact->sentMsgs++;
	}

	return 0;
}

static int evProtocolNearReplMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2upNodeOwnCtactStruct *ownCtact;
	u2upProtocolMsgDataStruct *data = NULL;
	u2up_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	if ((ownCtact = (u2upNodeOwnCtactStruct *)evm_message_ctx_get(msg)) == NULL)
		return -1;
	ownCtact->recvdMsgs++;

	if ((data = (u2upProtocolMsgDataStruct *)evm_message_data_get(msg)) == NULL)
		return -1;

	u2up_log_info(
		"(node: %u@%.8x) NEAR REPLY msg received: (contact: %u@%.8x, ref=%p)\n",
		ownCtact->myself->id, ownCtact->myself->addr, data->id, data->addr, data->ref
	);

	if (evm_timer_stop((evmTimerStruct *)data->ref) == 0)
		evm_timer_delete((evmTimerStruct *)data->ref);

	insertNearAddrContact(ownCtact, data->id, data->addr);

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

int set_dump_filename_prefix(char *prefix)
{
	if (outfile != NULL)
		free(outfile);

	asprintf(&outfile, "%s", prefix);

	return 0;
}

static unsigned int secs = 0;
int dump_u2up_net_ring(u2upNetRingHeadStruct *ring, char *buff, int size)
{
	u2upNetRingAddrStruct *ring_addr = NULL;
	u2upNodeRingContactStruct *ctact = NULL;
	char *pathname;
	FILE *file;

	if (ring == NULL)
		abort();

	asprintf(&pathname, "%s_%s_%.8u.gv", outfile, start_time, secs);
	u2up_log_notice("(Write file: %s)\n", pathname);
	if (buff != NULL) {
		snprintf(buff, size, "Dump u2upNet to: '%s'", pathname);
	}
	if ((file = fopen(pathname, "w")) != NULL) {
		fprintf(file, "/* circo -Tsvg %s -o %s.svg -Nshape=box */\n", pathname, pathname);
		fprintf(file, "digraph \"u2upNet\" {\n");
		pthread_mutex_lock(&ring->amtx);

		/* Draw initial ring of addressed nodes */
		ring_addr = ring->first;
		if (ring_addr != NULL) {
			do {
				fprintf(file, "\"%.8x\" [label=\"%.8x\\n(%u: %u)\"];\n", ring_addr->addr, ring_addr->addr, ring_addr->ownCtact->myself->id, ring_addr->ownCtact->numCtacts);
				fprintf(file, "\"%.8x\" -> \"%.8x\" [color=black,arrowsize=0,style=dotted];\n", ring_addr->addr, ring_addr->next->addr);
				ring_addr = ring_addr->next;
			} while (ring_addr != ring->first);
		}

		/* Draw all node contacts */
		ring_addr = ring->first;
		if (ring_addr != NULL) {
			do {
				pthread_mutex_lock(&ring_addr->ownCtact->ownNode->amtx);
				ctact = ring_addr->ownCtact->myself;
				if (ctact != NULL) {
					do {
						if (ctact->own != 1)
							fprintf(file, "\"%.8x\" -> \"%.8x\" [color=black,arrowsize=0.7];\n", ring_addr->addr, ctact->addr);
						ctact = ctact->next;
					} while (ctact != ring_addr->ownCtact->myself);
				}
				pthread_mutex_unlock(&ring_addr->ownCtact->ownNode->amtx);
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

int u2up_dump_u2up_net_ring(char *buff, int size)
{
	pthread_mutex_lock(&simulation_global_mutex);
	dump_u2up_net_ring(&net_addr_ring, buff, size);
	pthread_mutex_unlock(&simulation_global_mutex);
	return 0;
}

int disableNodeById(unsigned int id)
{
	u2upNodeRingContactStruct *tmp = NULL;

	pthread_mutex_lock(&simulation_global_mutex);
	if (id >= max_nodes) {
		pthread_mutex_unlock(&simulation_global_mutex);
		return -1;
	}

	pthread_mutex_lock(&nodes[id].amtx);
	nodes[id].active = U2UP_NET_FALSE;
	tmp = nodes[id].ctacts->myself->next;
	/* Retire all remote contacts of the node */
	do {
		/* skip own addresses */
		if (tmp->own != 1) {
			tmp = _retireNodeContact(&nodes[id], tmp);
		} else
			tmp = tmp->next;
	} while (tmp != nodes[id].ctacts->myself);
	pthread_mutex_unlock(&nodes[id].amtx);

	pthread_mutex_unlock(&simulation_global_mutex);
	return 0;
}

int enableNodeById(unsigned int id)
{
	u2upNodeRingContactStruct *tmp = NULL;

	pthread_mutex_lock(&simulation_global_mutex);
	if (id >= max_nodes) {
		pthread_mutex_unlock(&simulation_global_mutex);
		return -1;
	}

	pthread_mutex_lock(&nodes[id].amtx);
	tmp = nodes[id].retired_yng;
	/* Reload all retired remote contacts of the node */
	while (tmp->next != NULL) {
		_insertNodeContact(nodes[id].ctacts, tmp->id, tmp->addr);
		tmp = tmp->next;
	}
	nodes[id].active = U2UP_NET_TRUE;
	pthread_mutex_unlock(&nodes[id].amtx);

	pthread_mutex_unlock(&simulation_global_mutex);
	return 0;
}

int enableAllNodes(void)
{
	int i, rv;

	for (i = 0; i < max_nodes; i++) {
		if (nodes[i].active == U2UP_NET_FALSE) {
			if ((rv = enableNodeById(i)) != 0)
				return rv;
		}
	}
	return 0;
}

int getNodeFirstAddrById(unsigned int id, uint32_t *addr)
{
	u2upNodeOwnCtactStruct *own = NULL;

	if (addr == NULL)
		return -1;

	pthread_mutex_lock(&simulation_global_mutex);
	if (id < max_nodes) {
		if (
			((own = nodes[id].ctacts) != NULL) &&
			(own->myself != NULL)
		   ) {
			*addr = own->myself->addr;
			pthread_mutex_unlock(&simulation_global_mutex);
			return 0;
		}
	}
	pthread_mutex_unlock(&simulation_global_mutex);
	return -1;
}

int getNodeIdByAddr(uint32_t addr, unsigned int *id)
{
	u2upNodeOwnCtactStruct *own = NULL;
	int i;

	if (id == NULL)
		return -1;

	pthread_mutex_lock(&simulation_global_mutex);
	for (i = 0; i < max_nodes; i++) {
		/*Check all our own addresses*/
		if ((own = nodes[i].ctacts) == NULL)
			break;
		do {
			if (addr == own->myself->addr) { /*found existing own address*/
				pthread_mutex_unlock(&simulation_global_mutex);
				*id = i;
				return 0;
			}
			own = own->next;
		} while (own != NULL);
	}
	pthread_mutex_unlock(&simulation_global_mutex);
	return -1;
}

static int handleTmrAuthBatch(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	int i;
	unsigned int rand_id;
	evmTmridStruct *tmrid_ptr;
	u2upNetRingAddrStruct *ringAddr;
	u2upNodeOwnCtactStruct *ownCtact;
	u2up_log_info("(cb entry) tmr=%p\n", tmr);

	secs++;
	if (pthread_mutex_trylock(&simulation_global_mutex) == EBUSY) {
		u2up_log_info("SIGUSR1 RECEIVED!\n");
		dump_u2up_net_ring(&net_addr_ring, NULL, 0);
	}
	pthread_mutex_unlock(&simulation_global_mutex);

	u2up_log_debug("AUTH_BATCH timer expired!\n");
	if (next_node < max_nodes) {
		u2up_log_notice("(%d nodes)\n", next_node);
		for (i = 0; i < batch_nodes; i++) {
			if (next_node < max_nodes) {
				ringAddr = generateNewNetAddr(&net_addr_ring);
				nodes[next_node].active = U2UP_NET_TRUE;
				nodes[next_node].maxCtacts = 5;
				nodes[next_node].numOwns = 0;
				nodes[next_node].maxRetired = 4;
				nodes[next_node].numRetired = 0;
				nodes[next_node].retired_old = NULL;
				nodes[next_node].retired_yng = NULL;
				nodes[next_node].consumer = protocol_consumer;
				pthread_mutex_init(&nodes[next_node].amtx, NULL);
				pthread_mutex_unlock(&nodes[next_node].amtx);
				if ((ownCtact = insertNodeOwnContact(&nodes[next_node], next_node, ringAddr->addr)) == NULL)
					abort();
				pthread_mutex_lock(&nodes[next_node].amtx);
				ownCtact->ringAddr = ringAddr;
				ownCtact->ringAddr->ownCtact = ownCtact;
				if (next_node > 0) {
					rand_id = rand() % next_node;
					send_protocol_init_msg(protocol_consumer, ownCtact, nodes[rand_id].ctacts->myself->id, nodes[rand_id].ctacts->myself->addr);
				}
				/*set protocol timeout to find nearest nodes*/
				ownCtact->tmrProtoRun = startTmrProtoRun(ownCtact->tmrProtoRun, 3, 0, (void *)ownCtact, tmridProtoRun);
				pthread_mutex_unlock(&nodes[next_node].amtx);
				next_node++;
			} else {
				break;
			}
		}
		if (next_node >= max_nodes) {
			u2up_log_notice("(all %d nodes created)\n", next_node);
#if 0 /*spog - test stop of the auth thread*/
			while (1)
				sleep(1000);
#endif
		}
		if (auto_dump == 1)
			kill(0, SIGUSR1);
	}

	if ((tmrid_ptr = evm_tmrid_get(evm, TMR_ID_AUTH_BATCH)) == NULL)
		abort();
	tmrAuthBatch = auth_start_timer(tmrAuthBatch, 1, 0, NULL, tmrid_ptr);
	u2up_log_debug("AUTH_BATCH timer set: 1 s\n");

	return 0;
}

/* EVM initialization */
static int simulation_evm_init(void)
{
	int rv = 0;

	u2up_log_info("(entry)\n");

	/* Initialize event machine... */
	if ((evm = evm_init()) != NULL) {
		if ((rv == 0) && ((auth_consumer = evm_consumer_add(evm, EVM_CONSUMER_AUTH)) == NULL)) {
			u2up_log_error("evm_consumer_add(EVM_CONSUMER_AUTH) failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((protocol_consumer = evm_consumer_add(evm, EVM_CONSUMER_PROTOCOL)) == NULL)) {
			u2up_log_error("evm_consumer_add(EVM_CONSUMER_PROTOCOL) failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgtype_ptr = evm_msgtype_add(evm, EV_TYPE_PROTOCOL_MSG)) == NULL)) {
			u2up_log_error("evm_msgtype_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_init_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_INIT)) == NULL)) {
			u2up_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_init_ptr, evProtocolInitMsg) < 0)) {
			u2up_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_random_req_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_RANDOM_REQ)) == NULL)) {
			u2up_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_random_req_ptr, evProtocolRandomReqMsg) < 0)) {
			u2up_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_random_repl_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_RANDOM_REPL)) == NULL)) {
			u2up_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_random_repl_ptr, evProtocolRandomReplMsg) < 0)) {
			u2up_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_near_req_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_NEAR_REQ)) == NULL)) {
			u2up_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_near_req_ptr, evProtocolNearReqMsg) < 0)) {
			u2up_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_near_repl_ptr = evm_msgid_add(msgtype_ptr, EV_ID_PROTOCOL_MSG_NEAR_REPL)) == NULL)) {
			u2up_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_near_repl_ptr, evProtocolNearReplMsg) < 0)) {
			u2up_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
	} else {
		u2up_log_error("evm_init() failed!\n");
		rv = -1;
	}

	return rv;
}

/* Protocol processing thread */
static void * simulation_protocol_run(void *arg)
{
	evmConsumerStruct *consumer;

	u2up_log_info("(entry)\n");

	if (arg == NULL)
		return NULL;

	consumer = (evmConsumerStruct *)arg;

	/* Prepare PROTO_RUN timer */
	if ((tmridProtoRun = evm_tmrid_add(evm, TMR_ID_PROTO_RUN)) == NULL) {
		u2up_log_error("evm_tmrid_add() failed!\n");
		abort();
	}
	if (evm_tmrid_cb_handle_set(tmridProtoRun, handleTmrProtoRun) < 0) {
		u2up_log_error("evm_tmrid_cb_handle_set() failed!\n");
		abort();
	}

	/* Prepare WAIT_REPLY timer */
	if ((tmridWaitRepl = evm_tmrid_add(evm, TMR_ID_WAIT_REPL)) == NULL) {
		u2up_log_error("evm_tmrid_add() failed!\n");
		abort();
	}
	if (evm_tmrid_cb_handle_set(tmridWaitRepl, handleTmrWaitRepl) < 0) {
		u2up_log_error("evm_tmrid_cb_handle_set() failed!\n");
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
	u2up_log_info("(entry)\n");

	/* Create additional protocol thread */
	if ((rv = pthread_attr_init(&attr)) != 0)
		u2up_log_return_system_err("pthread_attr_init()\n");

	if ((rv = pthread_create(&protocol_thread, &attr, simulation_protocol_run, (void *)protocol_consumer)) != 0)
		u2up_log_return_system_err("pthread_create()\n");
	u2up_log_debug("pthread_create() rv=%d\n", rv);

	/* Prepare AUTH_BATCH periodic timer */
	if ((tmrid_ptr = evm_tmrid_add(evm, TMR_ID_AUTH_BATCH)) == NULL) {
		u2up_log_error("evm_tmrid_add() failed!\n");
		abort();
	}
	if (evm_tmrid_cb_handle_set(tmrid_ptr, handleTmrAuthBatch) < 0) {
		u2up_log_error("evm_tmrid_cb_handle_set() failed!\n");
		abort();
	}
	tmrAuthBatch = auth_start_timer(NULL, 1, 0, NULL, tmrid_ptr);
	u2up_log_notice("AUTH_BATCH timer set: 1 s\n");

	/* Initialize CLI server */
	if (simulation_clisrv_init(evm) < 0) {
		u2up_log_error("simulation_clisrv_init() failed!\n");
		abort();
	}

	/*
	 * Main EVM processing (event loop)
	 */
	return evm_run(auth_consumer);
}

static void simulation_sighandler(int signum, siginfo_t *siginfo, void *context)
{
	pthread_mutex_trylock(&simulation_global_mutex);
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
		u2up_log_return_system_err("sigaction() for signum %d\n", signum);

	return 0;
}

/*
 * The MAIN part.
 */
int main(int argc, char *argv[])
{
	time_t loctime;

	time(&loctime);
	localtime_r(&loctime, &start);

	usage_check(argc, argv);

	log_mask = LOG_MASK(LOG_EMERG) | LOG_MASK(LOG_ALERT) | LOG_MASK(LOG_CRIT) | LOG_MASK(LOG_ERR);

	/* Setup LOG_MASK according to startup arguments! */
	if (U2UP_LOG_GET_NORMAL()) {
		log_mask |= LOG_MASK(LOG_WARNING);
		log_mask |= LOG_MASK(LOG_NOTICE);
	}
	if ((U2UP_LOG_GET_VERBOSE()) || (U2UP_LOG_GET_TRACE()))
		log_mask |= LOG_MASK(LOG_INFO);
	if (U2UP_LOG_GET_DEBUG())
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


