/*
 * The u2up-netsim CLI server functions
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

#ifndef U2UP_NET_FILE_netsim_clisrv_c
#define U2UP_NET_FILE_netsim_clisrv_c
#else
#error Preprocesor macro U2UP_NET_FILE_netsim_clisrv_c conflict!
#endif

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

#include <evm/libevm.h>
#include "u2up-netsim.h"
#include "netsim-common.h"
#include "netsim-clisrv.h"

#include <userlog/log_module.h>
EVMLOG_MODULE_INIT(CLISRV, 2);

enum evm_msg_ids {
	MSG_ID_CLISRV_INIT = 0,
	MSG_ID_CLISRV_COMMAND,
	MSG_ID_CLISRV_REPLY
};

static evmConsumerStruct *clisrv_consumer;
static evmMsgtypeStruct *msgtype_ptr;
static evmMsgidStruct *msgid_init_ptr;
static evmTmridStruct *tmridClisrvCmdTout;

static int clisrv_lsd;
static struct pollfd *clisrvFds;
static int clisrvNfds = 1;
static struct timespec timeOut = {
	.tv_sec = 10,
	.tv_nsec = 0
};
static sigset_t clisrv_sigmask;

static int evClisrvInitMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	evm_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	return 0;
}

static int handleTmrClisrvCmdTout(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	evm_log_info("(cb entry) tmr=%p\n", tmr);

	return 0;
}

/* CLI socket server thread */
void * clisrv_ppoll_loop(void *arg)
{
	int rv = 0, i, j, len;
	int new_sd;
	int currentNfds;
	int end_server = U2UP_NET_FALSE;
	int close_conn = U2UP_NET_FALSE;
	int squeeze_array = U2UP_NET_FALSE;
	struct pollfd *newClisrvFds;
	char buffer[CLISRV_MAX_MSGSZ];
	evm_log_info("(entry)\n");

	/* Loop waiting for incoming connects or incoming data */
	do {
		if ((rv = ppoll(clisrvFds, clisrvNfds, &timeOut, &clisrv_sigmask)) < 0) {
			evm_log_system_error("ppoll()\n");
			break;
		}

		/* Check if time out expired. */
		if (rv == 0) {
			evm_log_debug("ppoll() rv=%d\n", rv);
			continue;
		}

		/* Determine readable descriptors */
		currentNfds = clisrvNfds;
		for (i = 0; i < currentNfds; i++) {
			/* Check flaged descriptors */
			if (clisrvFds[i].revents == 0)
				continue;

			/* Handle unexpected (non-POLLIN) events as fatal error */
			if (clisrvFds[i].revents != POLLIN) {
				evm_log_error("ppoll() - Unexpected event! revents = %d\n", clisrvFds[i].revents);
				end_server = U2UP_NET_TRUE;
				break;
			}

			/* Handle listening socket */
			if (clisrvFds[i].fd == clisrv_lsd) {
				evm_log_debug("Listening socket is readable\n");

				/* Accept all connection queued up listening */
				do {
					/* EWOULDBLOCK indicates there is nothing to accept left */
					/* (all other errors are treated as fatal) */
					if ((new_sd = accept(clisrv_lsd, NULL, NULL)) < 0) {
						if (errno != EWOULDBLOCK) {
							evm_log_system_error("accept()\n");
							end_server = U2UP_NET_TRUE;
						}
						break;
					}

					/* New incoming connection - extend the pollfd structure */
					evm_log_debug("New incoming connection - %d\n", new_sd);
					if ((newClisrvFds = (struct pollfd *)reallocarray(clisrvFds, clisrvNfds + 1, sizeof(struct pollfd))) == NULL) {
						evm_log_system_error("realocarray()\n");
						end_server = U2UP_NET_TRUE;
						break;
					}
					clisrvFds = newClisrvFds;
					clisrvFds[clisrvNfds].fd = new_sd;
					clisrvFds[clisrvNfds].events = POLLIN;
					clisrvNfds++;
				} while (new_sd != -1);
			}

			/* Not the listening socket - an existing connection must be readable */
			else {
				evm_log_debug("Descriptor %d is readable\n", clisrvFds[i].fd);
				close_conn = U2UP_NET_FALSE;

				/* Receive all incoming data on this socket */
				do {
					/* EWOULDBLOCK indicates there is nothing left to receive */
					/* (all other errors close the connection) */
					if ((rv = recv(clisrvFds[i].fd, buffer, sizeof(buffer), 0)) < 0) {
						if (errno != EWOULDBLOCK) {
							evm_log_system_error("recv()\n");
							close_conn = U2UP_NET_TRUE;
						}
						break;
					}

					/* Has the connection been closed by the client? */
					if (rv == 0) {
						evm_log_debug("Connection closed\n");
						close_conn = U2UP_NET_TRUE;
						break;
					}

					/* Data was received */
					len = rv;
					evm_log_debug("  %d bytes received\n", len);

					/* Echo the data back to the client */
					if ((rv = send(clisrvFds[i].fd, buffer, len, 0)) < 0) {
						evm_log_system_error("send()\n");
						close_conn = U2UP_NET_TRUE;
						break;
					}

				} while(U2UP_NET_TRUE);

				/* Clean up closed connection (flagged*) */
				if (close_conn) {
					close(clisrvFds[i].fd);
					clisrvFds[i].fd = -1;
					squeeze_array = U2UP_NET_TRUE;
				}

			}  /* End of existing connection being readable */
		} /* End of loop through pollable descriptors */

		/* Squeeze pollfds array, if connections closed */
		if (squeeze_array) {
			squeeze_array = U2UP_NET_FALSE;
			for (i = 0; i < clisrvNfds; i++) {
				if (clisrvFds[i].fd == -1) {
					for(j = i; j < clisrvNfds; j++) {
						clisrvFds[j].fd = clisrvFds[j + 1].fd;
						/* not really needed - always POLLIN */
						clisrvFds[j].events = clisrvFds[j + 1].events;
					}
					i--;
					clisrvNfds--;
				}
			}
		}

	} while (end_server == U2UP_NET_FALSE); /* End of serving running. */

	/* Clean up all open sockets */
	for (i = 0; i < clisrvNfds; i++) {
		if(clisrvFds[i].fd >= 0)
			close(clisrvFds[i].fd);
	}

	return NULL;
}

int clisrvSocket_init(const char *path)
{
	int rv = 0, on = 1;
	int listen_sd, flags;
	struct stat st;
	struct sockaddr_un addr;
	pthread_attr_t attr;
	pthread_t ppoll_thread;

	if (path == NULL)
		evm_log_return_err("socket path not provided (NULL)!\n");

	if (*path == '\0')
		evm_log_return_err("socket name is empty string!\n");

	/* Initialize FD passing socket address... */
	if ((rv = stat(path, &st)) == 0) {
		/* Fle exists - check if socket */
		if ((st.st_mode & S_IFMT) == S_IFSOCK) {
			rv = unlink(path);
			if (rv != 0) {
				evm_log_return_err("Error unlinking the socket node");
			}
		} else {
			/* Not a socket, so do not unlink */
			evm_log_return_err("The path already exists and is not a socket.\n");
		}
	} else {
		if (errno != ENOENT) {
			evm_log_return_err("stat() - Error on the socket path");
		}
	}

	/* Create a socket */
	listen_sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_sd == -1)
		evm_log_return_err("socket()\n");

	/* Make socket reusable */
	rv = setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
	if (rv < 0)
		evm_log_return_err("setsockopt()\n");

	/* Set socket nonblocking (and all its successors) */
	if ((flags = fcntl(listen_sd, F_GETFL, 0)) < 0)
		evm_log_return_err("fcntl()\n");

	if ((rv = fcntl(listen_sd, F_SETFL, flags | O_NONBLOCK)) < 0)
		evm_log_return_err("fcntl()\n");

	/* Ready to bind a Unix socket. */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if ((rv = bind(listen_sd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))) == -1)
		evm_log_return_err("bind() sockfd=%d\n", listen_sd);

	if ((rv = listen(listen_sd, LISTEN_BACKLOG)) == -1)
		evm_log_return_err("listen() sockfd=%d\n", listen_sd);

	evm_log_debug("CLI server listening socket ready (bind FD: %d).\n", listen_sd);

	/* Initialize the pollfd structure */
	if ((clisrvFds = (struct pollfd *)calloc(clisrvNfds, sizeof(struct pollfd))) == NULL) {
		evm_log_system_error("calloc() - struct pollfd\n");
		return -1;
	}

	/* Set up the initial listening socket */
	clisrvFds[0].fd = listen_sd;
	clisrvFds[0].events = POLLIN;

	/* Prepare module-local empty signal mask, used in ppoll() to allow catching all signals there! */
        sigemptyset(&clisrv_sigmask);

	/* Start the polling thread */
	if ((rv = pthread_attr_init(&attr)) != 0)
		evm_log_return_system_err("pthread_attr_init()\n");

	if ((rv = pthread_create(&ppoll_thread, &attr, clisrv_ppoll_loop, NULL)) != 0)
		evm_log_return_system_err("pthread_create()\n");
	evm_log_debug("pthread_create() rv=%d\n", rv);

	return listen_sd;
}

/* CLI server initialization */
int simulation_clisrv_init(evmStruct *evm)
{
	int rv = 0;

	evm_log_info("(entry)\n");

	if (evm == NULL)
		return -1;

	if ((rv == 0) && ((clisrv_consumer = evm_consumer_add(evm, EVM_CONSUMER_CLISRV)) == NULL)) {
		evm_log_error("evm_consumer_add(EVM_CONSUMER_CLISRV) failed!\n");
		rv = -1;
	}
	if ((rv == 0) && ((msgtype_ptr = evm_msgtype_add(evm, EV_TYPE_CLISRV_MSG)) == NULL)) {
		evm_log_error("evm_msgtype_add() failed!\n");
		rv = -1;
	}
	if ((rv == 0) && ((msgid_init_ptr = evm_msgid_add(msgtype_ptr, MSG_ID_CLISRV_INIT)) == NULL)) {
		evm_log_error("evm_msgid_add() failed!\n");
		rv = -1;
	}
	if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_init_ptr, evClisrvInitMsg) < 0)) {
		evm_log_error("evm_msgid_cb_handle() failed!\n");
		rv = -1;
	}
	/* Prepare CLISRV_CMDTOUT timer */
	if ((rv == 0) && ((tmridClisrvCmdTout = evm_tmrid_add(evm, TMR_ID_CLISRV_CMDTOUT)) == NULL)) {
		evm_log_error("evm_tmrid_add() failed!\n");
		rv = -1;
	}
	if ((rv == 0) && (evm_tmrid_cb_handle_set(tmridClisrvCmdTout, handleTmrClisrvCmdTout) < 0)) {
		evm_log_error("evm_tmrid_cb_handle_set() failed!\n");
		rv = -1;
	}
	/* Initialize CLI server listen socket */
	if ((rv == 0) && ((clisrv_lsd = clisrvSocket_init(CLISRV_SOCK_PATH)) < 0)) {
		evm_log_error("clisrvSocket_init() failed!\n");
		rv = -1;
	}

	return rv;
}
