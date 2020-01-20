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

#include <evm/libevm.h>
#include "u2up-net-sim.h"

#include <userlog/log_module.h>
EVMLOG_MODULE_INIT(U2UP_SIM, 2);

enum evm_consumer_ids {
	EVM_CONSUMER_ID_0 = 0
};

enum evm_msgtype_ids {
	EV_TYPE_UNKNOWN_MSG = 0,
	EV_TYPE_HELLO_MSG
};

enum evm_msg_ids {
	EV_ID_HELLO_MSG_HELLO = 0
};

enum evm_tmr_ids {
	TMR_ID_AUTH_BATCH = 0,
	EV_ID_HELLO_TMR_QUIT
};

static evmTimerStruct * hello_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr);

#if 0
static int evHelloMsg(evmConsumerStruct *consumer, evmMessageStruct *msg);
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

/*
 * The EVM part.
 */

/*
 * General EVM structure - Provided by evm_init():
 */
static evmStruct *evm;
static evmConsumerStruct *auth_consumer;
static u2upNetNodeStruct *nodes;
static u2upNetAddrRingStruct addr_ring;
static int next_node = 0;

#if 0
/* HELLO messages */
static char *hello_str = "HELLO";
static char msg_buff[MAX_BUFF_SIZE];
static struct iovec *iov_buff = NULL;
evmMessageStruct *helloMsg;

/* HELLO timers */
#endif
/* Timers */
static evmTimerStruct *tmrAuthBatch;
//orig:static evmTimerStruct *helloQuitTmr;

static evmTimerStruct * hello_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr)
{
	evm_log_info("(entry) tmr=%p, sec=%ld, nsec=%ld, ctx_ptr=%p\n", tmr, tv_sec, tv_nsec, ctx_ptr);
	evm_timer_stop(tmr);
	return evm_timer_start(auth_consumer, tmrid_ptr, tv_sec, tv_nsec, ctx_ptr);
}

#if 0
/* HELLO event handlers */
static int evHelloMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	evmTmridStruct *tmrid_ptr;
	struct iovec *iov_buff = NULL;
	evm_log_info("(cb entry) msg_ptr=%p\n", msg);

	if (msg == NULL)
		return -1;

	if ((iov_buff = (struct iovec *)evm_message_data_get(msg)) == NULL)
		return -1;
	evm_log_notice("HELLO msg received: \"%s\"\n", (char *)iov_buff->iov_base);

	return 0;
}
#endif

static u2upNetAddrStruct * newU2upNetAddr(uint32_t addr)
{
	u2upNetAddrStruct *new = (u2upNetAddrStruct *)calloc(1, sizeof(u2upNetAddrStruct));

	if (new == NULL)
		abort();

	new->addr = addr;

	return new;
}

static u2upNetAddrStruct * insertNewNetAddr(u2upNetAddrRingStruct *ring, uint32_t addr)
{
	u2upNetAddrStruct *tmp = NULL;
	u2upNetAddrStruct *new = NULL;

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
		while (tmp->next != ring->first) {
			if (tmp->addr == addr) {
				pthread_mutex_unlock(&ring->amtx);
				return new;
			}
			if (tmp->next->addr > addr) {
				new = newU2upNetAddr(addr);
				new->next = tmp->next;
				new->prev = tmp;
				tmp->next->prev = new;
				tmp->next = new;
				if (addr < ring->first->addr)
					ring->first = new;
				pthread_mutex_unlock(&ring->amtx);
				return new;
			}
			tmp = tmp->next;
		}
		if (tmp->addr == addr) {
			pthread_mutex_unlock(&ring->amtx);
			return new;
		}
		new = newU2upNetAddr(addr);
		new->next = tmp->next;
		new->prev = tmp;
		tmp->next->prev = new;
		tmp->next = new;
		if (addr < ring->first->addr)
			ring->first = new;
	}

	pthread_mutex_unlock(&ring->amtx);
	return new;
}

static u2upNetAddrStruct * generateNewNetAddr(u2upNetAddrRingStruct *ring)
{
	int max_retry = 10;
	uint32_t addr = (uint32_t)rand();
	u2upNetAddrStruct *tmp = NULL;

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
int dump_u2up_net_ring(u2upNetAddrRingStruct *ring)
{
	evm_log_notice("Dump U2UP net ring to %s_%.8u.gv\n", outfile, secs);
	return 0;
}

static int handleTmrAuthBatch(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	int i;
	evmTmridStruct *tmrid_ptr;
	evm_log_info("(cb entry) tmr=%p\n", tmr);

	secs++;
	if (pthread_mutex_trylock(&simulation_global_mutex) == EBUSY) {
		evm_log_notice("SIGUSR1 RECEIVED!\n");
		dump_u2up_net_ring(&addr_ring);
	}
	pthread_mutex_unlock(&simulation_global_mutex);

	evm_log_debug("AUTH_BATCH timer expired!\n");
	if (next_node < max_nodes) {
		for (i = 0; i < batch_nodes; i++) {
			if (next_node < max_nodes) {
				nodes[next_node].nodeAddr = generateNewNetAddr(&addr_ring);
				nodes[next_node].nodeId = next_node;
				if ((nodes[next_node].consumer = evm_consumer_add(evm, next_node)) == NULL) {
					evm_log_error("evm_consumer_add() failed!\n");
					abort();
				}
				nodes[next_node].nodeAddr->node = &nodes[next_node];
				next_node++;
			} else {
				break;
			}
		}
	}

	if ((tmrid_ptr = evm_tmrid_get(evm, TMR_ID_AUTH_BATCH)) == NULL)
		abort();
	tmrAuthBatch = hello_start_timer(tmrAuthBatch, 1, 0, NULL, tmrid_ptr);
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
	evmMsgtypeStruct *msgtype_ptr;
	evmMsgidStruct *msgid_ptr;

	evm_log_info("(entry)\n");

	/* Initialize event machine... */
	if ((evm = evm_init()) != NULL) {
#if 0
		if ((rv == 0) && ((consumer = evm_consumer_add(evm, EVM_CONSUMER_ID_0)) == NULL)) {
			evm_log_error("evm_consumer_add() failed!\n");
			rv = -1;
		}
#endif
		if ((rv == 0) && ((msgtype_ptr = evm_msgtype_add(evm, EV_TYPE_HELLO_MSG)) == NULL)) {
			evm_log_error("evm_msgtype_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_ptr = evm_msgid_add(msgtype_ptr, EV_ID_HELLO_MSG_HELLO)) == NULL)) {
			evm_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
#if 0
		if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_ptr, evHelloMsg) < 0)) {
			evm_log_error("evm_msgid_cb_handle() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((helloMsg = evm_message_new(msgtype_ptr, msgid_ptr, sizeof(struct iovec))) == NULL)) {
			evm_log_error("evm_message_new() failed!\n");
			rv = -1;
		}
		if (rv == 0) {
			evm_message_persistent_set(helloMsg);
			if ((iov_buff = (struct iovec *)evm_message_data_get(helloMsg)) == NULL)
				rv = -1;
			else
				iov_buff->iov_base = msg_buff;
		}
#endif
	} else {
		evm_log_error("evm_init() failed!\n");
		rv = -1;
	}

	return rv;
}

/* Main core processing (event loop) */
static int simulation_authority_run(void)
{
	evmTmridStruct *tmrid_ptr;

	if ((auth_consumer = evm_consumer_add(evm, max_nodes)) == NULL) {
		evm_log_error("evm_consumer_add() failed!\n");
		abort();
	}
	/* Set initial IDLE timer */
	if ((tmrid_ptr = evm_tmrid_add(evm, TMR_ID_AUTH_BATCH)) == NULL) {
		evm_log_error("evm_tmrid_add() failed!\n");
		abort();
	}
	if (evm_tmrid_cb_handle_set(tmrid_ptr, handleTmrAuthBatch) < 0) {
		evm_log_error("evm_tmrid_cb_handle_set() failed!\n");
		abort();
	}
	tmrAuthBatch = hello_start_timer(NULL, 1, 0, NULL, tmrid_ptr);
	evm_log_notice("AUTH_BATCH timer set: 0 s\n");

#if 0
	/* Set initial QUIT timer */
	if ((tmrid_ptr = evm_tmrid_add(evm, EV_ID_HELLO_TMR_QUIT)) == NULL)
		return -1;
	if (evm_tmrid_cb_handle_set(tmrid_ptr, evHelloTmrQuit) < 0)
		return -1;
	helloQuitTmr = hello_start_timer(NULL, 60, 0, NULL, tmrid_ptr);
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
	printf("\t-o, --outfile           Output filename prefix (default=%s).\n", default_outfile);
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
			asprintf(&outfile, "%s", optarg);
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
		outfile = default_outfile;

#if 1 /*samo - test:*/
	printf("batch_nodes = %u\n", batch_nodes);
	printf("max_nodes = %u\n", max_nodes);
	printf("outfile = %s\n", outfile);
#endif
	return 0;
}

int main(int argc, char *argv[])
{
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

	/* Initialize addr_ring structure */
	addr_ring.first = NULL;
	pthread_mutex_init(&addr_ring.amtx, NULL);
	pthread_mutex_unlock(&addr_ring.amtx);

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


