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

#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <u2up-cli/u2up-clicli.h>

#define U2UP_LOG_NAME U2NETCLI
#include <u2up-log/u2up-log.h>
U2UP_LOG_DECLARE(U2CLICLI);

#include "u2up-netsim-cli.h"

static unsigned int option_cmd = 0;

static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options]\n", argv[0]);
	printf("options:\n");
	printf("\t-c, --cmd          Execute command and exit.\n");
	printf("\t-q, --quiet        Disable all output.\n");
	printf("\t-v, --verbose      Enable verbose output.\n");
#if (U2UP_LOG_MODULE_TRACE != 0)
	printf("\t-t, --trace        Enable trace output.\n");
#endif
#if (U2UP_LOG_MODULE_DEBUG != 0)
	printf("\t-g, --debug        Enable debug output.\n");
#endif
	printf("\t-s, --syslog       Redirect U2UP_LOG output to syslog (instead of stdout, stderr).\n");
	printf("\t-n, --no-header    No U2UP_LOG header added to every u2up_log_... output.\n");
	printf("\t-h, --help         Displays this text.\n");
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
#if (U2UP_LOG_MODULE_TRACE != 0)
			{"trace", 0, 0, 't'},
#endif
#if (U2UP_LOG_MODULE_DEBUG != 0)
			{"debug", 0, 0, 'g'},
#endif
			{"no-header", 0, 0, 'n'},
			{"syslog", 0, 0, 's'},
			{"help", 0, 0, 'h'},
			{0, 0, 0, 0}
		};

#if (U2UP_LOG_MODULE_TRACE != 0) && (U2UP_LOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "cqvtgnsh", long_options, &option_index);
#elif (U2UP_LOG_MODULE_TRACE == 0) && (U2UP_LOG_MODULE_DEBUG != 0)
		c = getopt_long(argc, argv, "cqvgnsh", long_options, &option_index);
#elif (U2UP_LOG_MODULE_TRACE != 0) && (U2UP_LOG_MODULE_DEBUG == 0)
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
			U2UP_LOG_SET_NORMAL(0);
			U2UP_LOG_SET_NORMAL2(U2CLICLI, 0);
			break;

		case 'v':
			U2UP_LOG_SET_VERBOSE(1);
			U2UP_LOG_SET_VERBOSE2(U2CLICLI, 1);
			break;

#if (U2UP_LOG_MODULE_TRACE != 0)
		case 't':
			U2UP_LOG_SET_TRACE(1);
			U2UP_LOG_SET_TRACE2(U2CLICLI, 1);
			break;
#endif

#if (U2UP_LOG_MODULE_DEBUG != 0)
		case 'g':
			U2UP_LOG_SET_DEBUG(1);
			U2UP_LOG_SET_DEBUG2(U2CLICLI, 1);
			break;
#endif

		case 'n':
			U2UP_LOG_SET_HEADER(0);
			U2UP_LOG_SET_HEADER2(U2CLICLI, 0);
			break;

		case 's':
			U2UP_LOG_SET_SYSLOG(1);
			U2UP_LOG_SET_SYSLOG2(U2CLICLI, 1);
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
	u2up_log_info("(entry) path: %s\n", path);

	if (path == NULL)
		u2up_log_return_err("socket path not provided (NULL)!\n");

	if (*path == '\0')
		u2up_log_return_err("socket name is empty string!\n");

	/* Initialize FD passing socket address... */
	if ((rv = stat(path, &st)) == 0) {
		/* Fle exists - check if socket */
		if ((st.st_mode & S_IFMT) != S_IFSOCK) {
			/* Not a socket, so do not unlink */
			u2up_log_return_err("The path already exists and is not a socket.\n");
		}
	} else {
		if (errno != ENOENT) {
			u2up_log_return_err("stat() - Error on the socket path");
		}
	}

	/* Create a socket */
	if ((conn_sd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
		u2up_log_return_system_err("socket()\n");

	/* Initialize socket address structure and connect. */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if ((rv = connect(conn_sd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))) == -1)
		u2up_log_return_system_err("connect() - conn_d=%d\n", conn_sd);

	u2up_log_debug("Client socket connected (connect FD: %d).\n", conn_sd);

	return conn_sd;
}

static int socketSendReceive(int sock, char *snd_str, char *rcv_buf, size_t rcv_buf_size)
{
	int rv = 0;
	u2up_log_info("(entry) sock=%d\n", sock);

	/* Send cmd-data string over the connection socket (including terminating null byte) */
	rv = send(sock, snd_str, strlen(snd_str) + 1, 0);
	if (rv != strlen(snd_str) + 1) {
		u2up_log_system_error("send()\n");
		close(sock);
		return -1;
	}
	u2up_log_debug("%d bytes sent\n", rv);

	/* Receive data from the connection socket (including terminating null byte) */
	rv = recv(sock, rcv_buf, rcv_buf_size, 0);
	if (rv <= 0) {
		u2up_log_system_error("recv()\n");
		close(sock);
		return -1;
	}
	u2up_log_debug("%d bytes received\n", rv);

	return 0;
}

/*
 * The MAIN part.
 */
int main(int argc, char *argv[])
{
	int sockfd;
	
	usage_check(argc, argv);

	/* Initialize CLI server listen socket */
	if ((sockfd = clisrvSocket_init(CLISRV_SOCK_PATH)) < 0) {
		u2up_log_error("clisrvSocket_init() failed!\n");
		exit(EXIT_FAILURE);
	}

	/* Initialize History-log file (and trim to the last 100 lines) */
	if (initCmdLineLog(".u2up_clisrv_cmdlog", 100) < 0) {
		u2up_log_error("initCmdLineLog()\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	/* Process CLI commands */
	if (processCliCmds("netsim-cli> ", sockfd, socketSendReceive) < 0) {
		u2up_log_error("processCliCmds()\n");
		close(sockfd);
		exit(EXIT_FAILURE);
	}

	close(sockfd);
	exit(EXIT_SUCCESS);
}

