/*
 * The u2up-netsim-cli network simulation CLI program
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
 * This CLI program connects to network simulation simulation process.
*/

#ifndef U2UP_NET_FILE_u2up_netsim_cli_c
#define U2UP_NET_FILE_u2up_netsim_cli_c
#else
#error Preprocesor macro U2UP_NET_FILE_u2up_netsim_cli_c conflict!
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <evm/libevm.h>
#include "netsim-clisrv.h"
#include "u2up-netsim-cli.h"

#include <userlog/log_module.h>
EVMLOG_MODULE_INIT(U2UP_CLI, 2);

unsigned int log_mask;
unsigned int evmlog_normal = 1;
unsigned int evmlog_verbose = 0;
unsigned int evmlog_trace = 0;
unsigned int evmlog_debug = 0;
unsigned int evmlog_use_syslog = 0;
unsigned int evmlog_add_header = 1;

static unsigned int option_cmd = 0;

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options]\n", argv[0]);
	printf("options:\n");
	printf("\t-c, --cmd                Execute command and exit.");
	printf("\t-q, --quiet              Disable all output.\n");
	printf("\t-v, --verbose            Enable verbose output.\n");
#if (EVMLOG_MODULE_TRACE != 0)
	printf("\t-t, --trace              Enable trace output.\n");
#endif
#if (EVMLOG_MODULE_DEBUG != 0)
	printf("\t-g, --debug              Enable debug output.\n");
#endif
	printf("\t-s, --syslog             Redirect EVMLOG output to syslog (instead of stdout, stderr).\n");
	printf("\t-n, --no-header          No EVMLOG header added to every evm_log_... output.\n");
	printf("\t-h, --help               Displays this text.\n");
}

static int usage_check(int argc, char *argv[])
{
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"cmd", 0, 0, 'c'},
			{"quiet", 0, 0, 'q'},
			{"verbose", 0, 0, 'v'},
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
		c = getopt_long(argc, argv, "cqvtgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE == 0) && (EVMLOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "cqvgnsh", long_options, &option_index);
#elif (EVMLOG_MODULE_TRACE != 0) && (EVMLOG_MODULE_DEBUG == 0)
		c = getopt_long(argc, argv, "cqvtnsh", long_options, &option_index);
#else
		c = getopt_long(argc, argv, "cqvnsh", long_options, &option_index);
#endif
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			option_cmd = 1;
			break;

		case 'q':
			evmlog_normal = 0;
			break;

		case 'v':
			evmlog_verbose = 1;
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

int clisrvSocket_init(const char *path)
{
	int rv = 0;
	int conn_sd;
	struct stat st;
	struct sockaddr_un addr;
	evm_log_info("(entry) path: %s\n", path);

	if (path == NULL)
		evm_log_return_err("socket path not provided (NULL)!\n");

	if (*path == '\0')
		evm_log_return_err("socket name is empty string!\n");

	/* Initialize FD passing socket address... */
	if ((rv = stat(path, &st)) == 0) {
		/* Fle exists - check if socket */
		if ((st.st_mode & S_IFMT) != S_IFSOCK) {
			/* Not a socket, so do not unlink */
			evm_log_return_err("The path already exists and is not a socket.\n");
		}
	} else {
		if (errno != ENOENT) {
			evm_log_return_err("stat() - Error on the socket path");
		}
	}

	/* Create a socket */
	if ((conn_sd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		evm_log_return_system_err("socket()\n");

	/* Initialize socket address structure and connect. */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if ((rv = connect(conn_sd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))) == -1)
		evm_log_return_system_err("connect() - conn_d=%d\n", conn_sd);

	evm_log_debug("Client socket connected (connect FD: %d).\n", conn_sd);

	return conn_sd;
}

/*
 * The MAIN part.
 */
int main(int argc, char *argv[])
{
	int rv = 0;
	int sockfd;
	char snd_buf[CLISRV_MAX_MSGSZ];
	char rcv_buf[CLISRV_MAX_MSGSZ];
	usage_check(argc, argv);

	/* Initialize CLI server listen socket */
	if ((rv == 0) && ((sockfd = clisrvSocket_init(CLISRV_SOCK_PATH)) < 0)) {
		evm_log_error("clisrvSocket_init() failed!\n");
		rv = -1;
	}
	while (U2UP_NET_TRUE) {
		printf("netsim-cli> ");
		/* Enter one line message string to be sent */
		fgets(snd_buf, CLISRV_MAX_MSGSZ, stdin);

		/* Send data over the connection socket (including terminating null byte) */
		rv = send(sockfd, snd_buf, strlen(snd_buf) + 1, 0);
		if (rv != strlen(snd_buf) + 1) {
			evm_log_system_error("send()\n");
			close(sockfd);
			break;
		}
		evm_log_debug("%d bytes sent\n", rv);

		/* Receive data from the connection socket (including terminating null byte) */
		rv = recv(sockfd, rcv_buf, sizeof(rcv_buf), 0);
		if (rv != strlen(snd_buf) + 1) {
			evm_log_system_error("recv()\n");
			close(sockfd);
			break;
		}
		evm_log_debug("%d bytes received\n", rv);
//not needed:	rcv_buf[rv] = '\0';
		printf("%s", rcv_buf);
	}

	/* Close the connection socket */
	close(sockfd);

	if (rv == 0) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}
