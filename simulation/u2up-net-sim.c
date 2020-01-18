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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#include <evm/libevm.h>
#include "u2up-net-sim.h"

#include <userlog/log_module.h>
EVMLOG_MODULE_INIT(DEMO1EVM, 2);

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
	EV_ID_HELLO_TMR_IDLE = 0,
	EV_ID_HELLO_TMR_QUIT
};

static evmTimerStruct * hello_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr);

static int evHelloMsg(evmConsumerStruct *consumer, evmMessageStruct *msg);
static int evHelloTmrIdle(evmConsumerStruct *consumer, evmTimerStruct *tmr);
static int evHelloTmrQuit(evmConsumerStruct *consumer, evmTimerStruct *tmr);

static int hello_evm_init(void);
static int hello_evm_run(void);

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
unsigned int demo_liveloop = 0;

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options]\n", argv[0]);
	printf("options:\n");
	printf("\t-q, --quiet              Disable all output.\n");
	printf("\t-v, --verbose            Enable verbose output.\n");
	printf("\t-l, --liveloop           Enable liveloop measurement mode.\n");
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
			{"liveloop", 0, 0, 'l'},
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
		c = getopt_long(argc, argv, "qvltgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE == 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "qvlgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG == 0)
		c = getopt_long(argc, argv, "qvltnsh", long_options, &option_index);
#else
		c = getopt_long(argc, argv, "qvlnsh", long_options, &option_index);
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

		case 'l':
			demo_liveloop = 1;
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

	if (hello_evm_init() < 0)
		exit(EXIT_FAILURE);

	if (hello_evm_run() < 0)
		exit(EXIT_FAILURE);

	exit(EXIT_SUCCESS);
}

/*
 * The EVM part.
 */

/*
 * General EVM structure - Provided by evm_init():
 */
static evmStruct *evm;
static evmConsumerStruct *consumer;

/* HELLO messages */
static char *hello_str = "HELLO";
static char msg_buff[MAX_BUFF_SIZE];
static struct iovec *iov_buff = NULL;
evmMessageStruct *helloMsg;

/* HELLO timers */
static evmTimerStruct *helloIdleTmr;
static evmTimerStruct *helloQuitTmr;

static evmTimerStruct * hello_start_timer(evmTimerStruct *tmr, time_t tv_sec, long tv_nsec, void *ctx_ptr, evmTmridStruct *tmrid_ptr)
{
	evm_log_info("(entry) tmr=%p, sec=%ld, nsec=%ld, ctx_ptr=%p\n", tmr, tv_sec, tv_nsec, ctx_ptr);
	evm_timer_stop(tmr);
	return evm_timer_start(consumer, tmrid_ptr, tv_sec, tv_nsec, ctx_ptr);
}

static unsigned int count;

/* HELLO event handlers */
static int evHelloMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	evmTmridStruct *tmrid_ptr;
	struct iovec *iov_buff = NULL;
	evm_log_info("(cb entry) msg_ptr=%p\n", msg);

	if (msg == NULL)
		return -1;

	if (demo_liveloop == 0) {
		if ((iov_buff = (struct iovec *)evm_message_data_get(msg)) == NULL)
			return -1;
		evm_log_notice("HELLO msg received: \"%s\"\n", (char *)iov_buff->iov_base);

		if ((tmrid_ptr = evm_tmrid_get(evm, EV_ID_HELLO_TMR_IDLE)) == NULL)
			return -1;
		helloIdleTmr = hello_start_timer(helloIdleTmr, 10, 0, NULL, tmrid_ptr);
		evm_log_notice("IDLE timer set: 10 s\n");
	} else {
		count++;
		/* liveloop - 100 %CPU usage */
		evm_message_pass(consumer, msg);
	}

	return 0;
}

static int evHelloTmrIdle(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	int rv = 0;
	evm_log_info("(cb entry) tmr=%p\n", tmr);

	evm_log_notice("IDLE timer expired!\n");

	count++;
	sprintf((char *)iov_buff->iov_base, "%s: %u", hello_str, count);
	evm_message_pass(consumer, helloMsg);
	evm_log_notice("HELLO msg sent: \"%s\"\n", (char *)iov_buff->iov_base);

	return rv;
}

static int evHelloTmrQuit(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	evm_log_info("(cb entry) tmr=%p\n", tmr);

	evm_log_notice("QUIT timer expired (%d messages sent)!\n", count);

	exit(EXIT_SUCCESS);
}

/* EVM initialization */
static int hello_evm_init(void)
{
	int rv = 0;
	evmMsgtypeStruct *msgtype_ptr;
	evmMsgidStruct *msgid_ptr;

	evm_log_info("(entry)\n");

	/* Initialize event machine... */
	if ((evm = evm_init()) != NULL) {
		if ((rv == 0) && ((consumer = evm_consumer_add(evm, EVM_CONSUMER_ID_0)) == NULL)) {
			evm_log_error("evm_consumer_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgtype_ptr = evm_msgtype_add(evm, EV_TYPE_HELLO_MSG)) == NULL)) {
			evm_log_error("evm_msgtype_add() failed!\n");
			rv = -1;
		}
		if ((rv == 0) && ((msgid_ptr = evm_msgid_add(msgtype_ptr, EV_ID_HELLO_MSG_HELLO)) == NULL)) {
			evm_log_error("evm_msgid_add() failed!\n");
			rv = -1;
		}
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
	} else {
		evm_log_error("evm_init() failed!\n");
		rv = -1;
	}

	return rv;
}

/* Main core processing (event loop) */
static int hello_evm_run(void)
{
	evmTmridStruct *tmrid_ptr;

	/* Set initial IDLE timer */
	if ((tmrid_ptr = evm_tmrid_add(evm, EV_ID_HELLO_TMR_IDLE)) == NULL)
		return -1;
	if (evm_tmrid_cb_handle_set(tmrid_ptr, evHelloTmrIdle) < 0)
		return -1;
	helloIdleTmr = hello_start_timer(NULL, 0, 0, NULL, tmrid_ptr);
	evm_log_notice("IDLE timer set: 0 s\n");

	/* Set initial QUIT timer */
	if ((tmrid_ptr = evm_tmrid_add(evm, EV_ID_HELLO_TMR_QUIT)) == NULL)
		return -1;
	if (evm_tmrid_cb_handle_set(tmrid_ptr, evHelloTmrQuit) < 0)
		return -1;
	helloQuitTmr = hello_start_timer(NULL, 60, 0, NULL, tmrid_ptr);
	evm_log_notice("QUIT timer set: 60 s\n");

	/*
	 * Main EVM processing (event loop)
	 */
#if 1 /*orig*/
	return evm_run(consumer);
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

