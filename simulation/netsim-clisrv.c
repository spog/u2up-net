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

#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>

#include <u2up-cli/u2up-clisrv.h>

#include <evm/libevm.h>
#include "u2up-netsim.h"
#include "netsim-common.h"
#include "netsim-clisrv.h"

#define U2UP_LOG_NAME U2NETCLI
#include <u2up-log/u2up-log.h>

enum evm_msg_ids {
	MSG_ID_CLISRV_INIT = 0,
	MSG_ID_CLISRV_COMMAND,
	MSG_ID_CLISRV_REPLY
};

static evmConsumerStruct *clisrv_consumer;
static evmMsgtypeStruct *msgtype_ptr;
static evmMsgidStruct *msgid_init_ptr;
static evmTmridStruct *tmridClisrvCmdTout;

static struct clisrv_conn *clisrvConns;

static int clisrv_lsd;
static struct pollfd *clisrvFds;
static int clisrvNfds = 1;
static struct timespec timeOut = {
	.tv_sec = 10,
	.tv_nsec = 0
};
static sigset_t clisrv_sigmask;

static char *clisrv_cmds[] = {
	"help",
	"dump [prefix=%s]",
	"log list {modules}",
	"log set {module=%s} {quiet|verbose|trace|debug|syslog|header}",
	"log reset {module=%s} {quiet|verbose|trace|debug|syslog|header}",
	"node enable {all | addr=%8x | id=%u}",
	"node disable {addr=%8x | id=%u}",
	"quit",
	NULL
};

static int help_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int dump_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int log_list_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int log_set_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int log_reset_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int node_enable_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int node_disable_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int quit_handle(clisrv_token_struct *curr_tokens, char *buff, int size);

static int (*cmd_handle[])(clisrv_token_struct *curr_tokens, char *buff, int size) = {
	help_handle,
	dump_handle,
	log_list_handle,
	log_set_handle,
	log_reset_handle,
	node_enable_handle,
	node_disable_handle,
	quit_handle,
};

static int help_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	printf("help command handle called!'\n");
	clisrv_strncat(buff, "\nPress TAB-TAB to display all available commands.\n", size);
	clisrv_strncat(buff, "Use TAB for auto-complete.\n", size);
	clisrv_strncat(buff, "Use TAB-TAB for auto-suggest.\n", size);
	clisrv_strncat(buff, "Use UP and DOWN keys to walk the commands history.\n", size);
	return 0;
}

static int dump_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *prefix_token;

	if ((prefix_token = getCurrentToken(curr_tokens, "prefix")) != NULL) {
		if ((prefix_token->eqval != NULL) && (strlen(prefix_token->eqval) > 0)) {
			set_dump_filename_prefix(prefix_token->eqval);
		}
	}

	printf("dump command handle called!'\n");

	u2up_dump_u2up_net_ring(buff, size);
	freePcmdCurrentTokens(&curr_tokens);

	return 0;
}

static int log_list_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *modules_token;

	if ((modules_token = getCurrentToken(curr_tokens, "modules")) != NULL) {
		printf("log list handle called (modules)!'\n");
		clisrv_strncat(buff, "Log modules:\n ", size);
		u2up_log_list_modules(buff, size);
	} else
		printf("log list handle called (missing parameter)!'\n");

	return 0;
}

static int log_set_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *module_token;
	clisrv_token_struct *quiet_token;
	clisrv_token_struct *verbose_token;
	clisrv_token_struct *trace_token;
	clisrv_token_struct *debug_token;
	clisrv_token_struct *syslog_token;
	clisrv_token_struct *header_token;

	if ((module_token = getCurrentToken(curr_tokens, "module")) != NULL) {
		if ((module_token->eqval != NULL) && (strlen(module_token->eqval) > 0)) {
			printf("log set handle called (module=%s)!'\n", module_token->eqval);
		}
	}

	if ((quiet_token = getCurrentToken(curr_tokens, "quiet")) != NULL) {
		printf("log set handle called (quiet)!'\n");
		return u2up_log_set(module_token->eqval, "quiet");
	} else
	if ((verbose_token = getCurrentToken(curr_tokens, "verbose")) != NULL) {
		printf("log set handle called (verbose)!'\n");
		return u2up_log_set(module_token->eqval, "verbose");
	} else
	if ((trace_token = getCurrentToken(curr_tokens, "trace")) != NULL) {
		printf("log set handle called (trace)!'\n");
		return u2up_log_set(module_token->eqval, "trace");
	} else
	if ((debug_token = getCurrentToken(curr_tokens, "debug")) != NULL) {
		printf("log set handle called (debug)!'\n");
		return u2up_log_set(module_token->eqval, "debug");
	} else
	if ((syslog_token = getCurrentToken(curr_tokens, "syslog")) != NULL) {
		printf("log set handle called (syslog)!'\n");
		return u2up_log_set(module_token->eqval, "syslog");
	} else
	if ((header_token = getCurrentToken(curr_tokens, "header")) != NULL) {
		printf("log set handle called (header)!'\n");
		return u2up_log_set(module_token->eqval, "header");
	} else
		printf("log set handle called (missing parameter)!'\n");

	return 0;
}

static int log_reset_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *module_token;
	clisrv_token_struct *quiet_token;
	clisrv_token_struct *verbose_token;
	clisrv_token_struct *trace_token;
	clisrv_token_struct *debug_token;
	clisrv_token_struct *syslog_token;
	clisrv_token_struct *header_token;

	if ((module_token = getCurrentToken(curr_tokens, "module")) != NULL) {
		if ((module_token->eqval != NULL) && (strlen(module_token->eqval) > 0)) {
			printf("log reset handle called (module=%s)!'\n", module_token->eqval);
		}
	}

	if ((quiet_token = getCurrentToken(curr_tokens, "quiet")) != NULL) {
		printf("log reset handle called (quiet)!'\n");
		return u2up_log_reset(module_token->eqval, "quiet");
	} else
	if ((verbose_token = getCurrentToken(curr_tokens, "verbose")) != NULL) {
		printf("log reset handle called (verbose)!'\n");
		return u2up_log_reset(module_token->eqval, "verbose");
	} else
	if ((trace_token = getCurrentToken(curr_tokens, "trace")) != NULL) {
		printf("log reset handle called (trace)!'\n");
		return u2up_log_reset(module_token->eqval, "trace");
	} else
	if ((debug_token = getCurrentToken(curr_tokens, "debug")) != NULL) {
		printf("log reset handle called (debug)!'\n");
		return u2up_log_reset(module_token->eqval, "debug");
	} else
	if ((syslog_token = getCurrentToken(curr_tokens, "syslog")) != NULL) {
		printf("log reset handle called (syslog)!'\n");
		return u2up_log_reset(module_token->eqval, "syslog");
	} else
	if ((header_token = getCurrentToken(curr_tokens, "header")) != NULL) {
		printf("log reset handle called (header)!'\n");
		return u2up_log_reset(module_token->eqval, "header");
	} else
		printf("log reset handle called (missing parameter)!'\n");
	return 0;
}

static int node_disable_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *addr_token;
	clisrv_token_struct *id_token;
	uint32_t addr;
	unsigned int id;

	if ((addr_token = getCurrentToken(curr_tokens, "addr")) != NULL) {
		if ((addr_token->eqval != NULL) && (strlen(addr_token->eqval) > 0)) {
			sscanf(addr_token->eqval, addr_token->eqspec, &addr);
		}
		printf("node disable command handle called (addr=%8x)!'\n", addr);
		if (getNodeIdByAddr(addr, &id) != 0) {
			clisrv_strncat(buff, "error: node id by addr not found!", size);
			return 0;
		}
	} else
	if ((id_token = getCurrentToken(curr_tokens, "id")) != NULL) {
		if ((id_token->eqval != NULL) && (strlen(id_token->eqval) > 0)) {
			sscanf(id_token->eqval, id_token->eqspec, &id);
		}
		printf("node disable command handle called (id=%u)!'\n", id);
		if (getNodeFirstAddrById(id, &addr) != 0) {
			clisrv_strncat(buff, "error: node addr by id not found!", size);
			return 0;
		}
	}
	printf("node disable command handle called (addr=%8x, id=%u)!'\n", addr, id);

	if (disableNodeById(id) != 0)
		snprintf(buff, size, "error: failed to disable node id=%u (addr=%.8x)!", id, addr);
	else
		snprintf(buff, size, "disabled node id=%u (addr=%.8x)", id, addr);

	return 0;
}

static int node_enable_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *all_token;
	clisrv_token_struct *addr_token;
	clisrv_token_struct *id_token;
	uint32_t addr;
	unsigned int id;

	if ((all_token = getCurrentToken(curr_tokens, "all")) != NULL) {
		printf("node enable command handle called (all)!'\n");
		if (enableAllNodes() != 0)
			snprintf(buff, size, "error: failed to enable all nodes!");
		else
			snprintf(buff, size, "enabled all nodes");
		return 0;
	} else
	if ((addr_token = getCurrentToken(curr_tokens, "addr")) != NULL) {
		if ((addr_token->eqval != NULL) && (strlen(addr_token->eqval) > 0)) {
			sscanf(addr_token->eqval, addr_token->eqspec, &addr);
		}
		printf("node enable command handle called (addr=%8x)!'\n", addr);
		if (getNodeIdByAddr(addr, &id) != 0) {
			clisrv_strncat(buff, "error: node id by addr not found!", size);
			return 0;
		}
	} else
	if ((id_token = getCurrentToken(curr_tokens, "id")) != NULL) {
		if ((id_token->eqval != NULL) && (strlen(id_token->eqval) > 0)) {
			sscanf(id_token->eqval, id_token->eqspec, &id);
		}
		printf("node enable command handle called (id=%u)!'\n", id);
		if (getNodeFirstAddrById(id, &addr) != 0) {
			clisrv_strncat(buff, "error: node addr by id not found!", size);
			return 0;
		}
	}
	printf("node enable command handle called (addr=%8x, id=%u)!'\n", addr, id);

	if (enableNodeById(id) != 0)
		snprintf(buff, size, "error: failed to enable node id=%u (addr=%.8x)!", id, addr);
	else
		snprintf(buff, size, "enabled node id=%u (addr=%.8x)", id, addr);

	return 0;
}

static int quit_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	printf("quit command handle called!'\n");
	return 127;
}

static int evClisrvInitMsg(evmConsumerStruct *consumer, evmMessageStruct *msg)
{
	u2up_log_info("(cb entry) msg=%p\n", msg);

	if ((consumer == NULL) || (msg == NULL))
		return -1;

	return 0;
}

static int handleTmrClisrvCmdTout(evmConsumerStruct *consumer, evmTimerStruct *tmr)
{
	u2up_log_info("(cb entry) tmr=%p\n", tmr);

	return 0;
}

/* CLI socket server thread */
void * clisrv_ppoll_loop(void *arg)
{
	int rv = 0, i, j, len;
	int new_sd;
	int currentNfds;
	int end_server = U2UP_CLI_FALSE;
	int close_conn = U2UP_CLI_FALSE;
	int squeeze_array = U2UP_CLI_FALSE;
	struct pollfd *newClisrvFds;
	struct clisrv_conn *newClisrvConns;
	clisrv_pconn_struct *pconn;
	char buffer[CLISRV_MAX_CMDSZ];
	u2up_log_info("(entry)\n");

	/* Loop waiting for incoming connects or incoming data */
	do {
		if ((rv = ppoll(clisrvFds, clisrvNfds, &timeOut, &clisrv_sigmask)) < 0) {
			u2up_log_system_error("ppoll()\n");
			break;
		}

		/* Check if time out expired. */
		if (rv == 0) {
			u2up_log_debug("ppoll() rv=%d\n", rv);
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
				u2up_log_error("ppoll() - Unexpected event! revents = %d\n", clisrvFds[i].revents);
				end_server = U2UP_CLI_TRUE;
				break;
			}

			/* Handle listening socket */
			if (clisrvFds[i].fd == clisrv_lsd) {
				u2up_log_debug("Listening socket is readable\n");

				/* Accept all connection queued up listening */
				do {
					/* EWOULDBLOCK indicates there is nothing to accept left */
					/* (all other errors are treated as fatal) */
					if ((new_sd = accept(clisrv_lsd, NULL, NULL)) < 0) {
						if (errno != EWOULDBLOCK) {
							u2up_log_system_error("accept()\n");
							end_server = U2UP_CLI_TRUE;
						}
						break;
					}

					/* New incoming connection - extend the pollfd structure */
					u2up_log_debug("New incoming connection - %d\n", new_sd);
#if 0 /*orig*/
					if ((newClisrvFds = (struct pollfd *)reallocarray(clisrvFds, clisrvNfds + 1, sizeof(struct pollfd))) == NULL) {
#else
					if ((newClisrvFds = (struct pollfd *)clisrv_realloc(clisrvFds, clisrvNfds + 1, sizeof(struct pollfd))) == NULL) {
#endif
						u2up_log_system_error("realocarray() - clisrvFds\n");
						end_server = U2UP_CLI_TRUE;
						break;
					}
					clisrvFds = newClisrvFds;
					clisrvFds[clisrvNfds].fd = new_sd;
					clisrvFds[clisrvNfds].events = POLLIN;
#if 0 /*orig*/
					if ((newClisrvConns = (struct clisrv_conn *)reallocarray(clisrvConns, clisrvNfds + 1, sizeof(struct clisrv_conn))) == NULL) {
#else
					if ((newClisrvConns = (struct clisrv_conn *)clisrv_realloc(clisrvConns, clisrvNfds + 1, sizeof(struct clisrv_conn))) == NULL) {
#endif
						u2up_log_system_error("realocarray() - clisrvConns\n");
						end_server = U2UP_CLI_TRUE;
						break;
					}
					clisrvConns = newClisrvConns;
					if ((pconn = (clisrv_pconn_struct *)calloc(1, sizeof(clisrv_pconn_struct))) == NULL) {
						u2up_log_system_error("calloc() - pconn\n");
						end_server = U2UP_CLI_TRUE;
						break;
					}
					clisrvConns[clisrvNfds].pconn = pconn;
					clisrvConns[clisrvNfds].pconn->rcv = NULL;
					clisrvConns[clisrvNfds].pconn->rcvlen = 0;
					clisrvConns[clisrvNfds].pconn->tokens = NULL;
					clisrvConns[clisrvNfds].pconn->nr_tokens = 0;
					clisrvConns[clisrvNfds].pconn->snd = NULL;
					clisrvConns[clisrvNfds].pconn->sndsz = 0;
					clisrvNfds++;
				} while (new_sd != -1);
			}

			/* Not the listening socket - an existing connection must be readable */
			else {
				u2up_log_debug("Descriptor %d is readable\n", clisrvFds[i].fd);
				close_conn = U2UP_CLI_FALSE;

				/* Receive all incoming data on this socket */
				do {
					/* EWOULDBLOCK indicates there is nothing left to receive */
					/* (all other errors close the connection) */
					if ((rv = recv(clisrvFds[i].fd, buffer, sizeof(buffer), 0)) < 0) {
						if (errno != EWOULDBLOCK) {
							u2up_log_system_error("recv()\n");
							close_conn = U2UP_CLI_TRUE;
						}
						break;
					}

					/* Has the connection been closed by the client? */
					if (rv == 0) {
						u2up_log_debug("Connection closed\n");
						close_conn = U2UP_CLI_TRUE;
						break;
					}

					/* Data was received (including terminating null byte, if all data received) */
					len = rv;
					u2up_log_debug("  %d bytes received\n", len);
					printf("received data(strlen=%ld): '%s'\n", strlen(buffer), buffer);

					/* Parse received data */
					if ((rv = parseReceivedData(clisrvConns[i].pconn, buffer, len)) < 0) {
						u2up_log_error("parseReceivedData()\n");
						close_conn = U2UP_CLI_TRUE;
						break;
					}

					/* Send response data (including terminating null byte) back to the client */
					if ((rv = send(clisrvFds[i].fd, clisrvConns[i].pconn->snd, clisrvConns[i].pconn->sndsz, 0)) < 0) {
						u2up_log_system_error("send()\n");
						close_conn = U2UP_CLI_TRUE;
						break;
					}

				} while (U2UP_CLI_TRUE);

				/* Clean up closed connection (flagged*) */
				if (close_conn) {
					close(clisrvFds[i].fd);
					clisrvFds[i].fd = -1;
					squeeze_array = U2UP_CLI_TRUE;
				}

			}  /* End of existing connection being readable */
		} /* End of loop through pollable descriptors */

		/* Squeeze pollfds array, if connections closed */
		if (squeeze_array) {
			squeeze_array = U2UP_CLI_FALSE;
			for (i = 0; i < clisrvNfds; i++) {
				if (clisrvFds[i].fd == -1) {
					for(j = i; j < clisrvNfds; j++) {
						clisrvFds[j].fd = clisrvFds[j + 1].fd;
						/* not really needed - always POLLIN */
						clisrvFds[j].events = clisrvFds[j + 1].events;
//Not good point to free - let's leave it now:	free(clisrvConns[j].pconn);
						clisrvConns[j].pconn = clisrvConns[j + 1].pconn;
					}
					i--;
					clisrvNfds--;
				}
			}
		}

	} while (end_server == U2UP_CLI_FALSE); /* End of serving running. */

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
		u2up_log_return_err("socket path not provided (NULL)!\n");

	if (*path == '\0')
		u2up_log_return_err("socket name is empty string!\n");

	/* Initialize FD passing socket address... */
	if ((rv = stat(path, &st)) == 0) {
		/* Fle exists - check if socket */
		if ((st.st_mode & S_IFMT) == S_IFSOCK) {
			rv = unlink(path);
			if (rv != 0) {
				u2up_log_return_err("Error unlinking the socket node");
			}
		} else {
			/* Not a socket, so do not unlink */
			u2up_log_return_err("The path already exists and is not a socket.\n");
		}
	} else {
		if (errno != ENOENT) {
			u2up_log_return_err("stat() - Error on the socket path");
		}
	}

	/* Create a socket */
	listen_sd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_sd == -1)
		u2up_log_return_err("socket()\n");

	/* Make socket reusable */
	rv = setsockopt(listen_sd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
	if (rv < 0)
		u2up_log_return_err("setsockopt()\n");

	/* Set socket nonblocking (and all its successors) */
	if ((flags = fcntl(listen_sd, F_GETFL, 0)) < 0)
		u2up_log_return_err("fcntl()\n");

	if ((rv = fcntl(listen_sd, F_SETFL, flags | O_NONBLOCK)) < 0)
		u2up_log_return_err("fcntl()\n");

	/* Ready to bind a Unix socket. */
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, path);

	if ((rv = bind(listen_sd, (struct sockaddr *)&addr, sizeof(struct sockaddr_un))) == -1)
		u2up_log_return_err("bind() sockfd=%d\n", listen_sd);

	if ((rv = listen(listen_sd, LISTEN_BACKLOG)) == -1)
		u2up_log_return_err("listen() sockfd=%d\n", listen_sd);

	u2up_log_debug("CLI server listening socket ready (bind FD: %d).\n", listen_sd);

	/* Initialize the pollfd structure */
	if ((clisrvFds = (struct pollfd *)calloc(1, sizeof(struct pollfd))) == NULL) {
		u2up_log_system_error("calloc() - struct pollfd\n");
		return -1;
	}

	/* Set up the initial listening socket */
	clisrvFds[0].fd = listen_sd;
	clisrvFds[0].events = POLLIN;

	/* Initialize the clisrv_conn structure */
	if ((clisrvConns = (struct clisrv_conn *)calloc(1, sizeof(struct clisrv_conn))) == NULL) {
		u2up_log_system_error("calloc() - struct clisrv_conn\n");
		return -1;
	}

	/* Set NULL for the listening socket - it does not represent a connection */
	clisrvConns[0].pconn = NULL;

	/* Prepare module-local empty signal mask, used in ppoll() to allow catching all signals there! */
        sigemptyset(&clisrv_sigmask);

	/* Start the polling thread */
	if ((rv = pthread_attr_init(&attr)) != 0)
		u2up_log_return_system_err("pthread_attr_init()\n");

	if ((rv = pthread_create(&ppoll_thread, &attr, clisrv_ppoll_loop, NULL)) != 0)
		u2up_log_return_system_err("pthread_create()\n");
	u2up_log_debug("pthread_create() rv=%d\n", rv);

	return listen_sd;
}

/* CLI server initialization */
int simulation_clisrv_init(evmStruct *evm)
{
	int rv = 0;

	u2up_log_info("(entry)\n");

	if (evm == NULL)
		return -1;

#if 1
	if ((rv == 0) && ((clisrv_pcmds = tokenizeCliCmds(clisrv_cmds)) == NULL)) {
		u2up_log_error("tokenizeCliCmds() failed!\n");
		rv = -1;
	}
#endif
	if ((rv == 0) && ((clisrv_consumer = evm_consumer_add(evm, EVM_CONSUMER_CLISRV)) == NULL)) {
		u2up_log_error("evm_consumer_add(EVM_CONSUMER_CLISRV) failed!\n");
		rv = -1;
	}
	if ((rv == 0) && ((msgtype_ptr = evm_msgtype_add(evm, EV_TYPE_CLISRV_MSG)) == NULL)) {
		u2up_log_error("evm_msgtype_add() failed!\n");
		rv = -1;
	}
	if ((rv == 0) && ((msgid_init_ptr = evm_msgid_add(msgtype_ptr, MSG_ID_CLISRV_INIT)) == NULL)) {
		u2up_log_error("evm_msgid_add() failed!\n");
		rv = -1;
	}
	if ((rv == 0) && (evm_msgid_cb_handle_set(msgid_init_ptr, evClisrvInitMsg) < 0)) {
		u2up_log_error("evm_msgid_cb_handle() failed!\n");
		rv = -1;
	}
	/* Prepare CLISRV_CMDTOUT timer */
	if ((rv == 0) && ((tmridClisrvCmdTout = evm_tmrid_add(evm, TMR_ID_CLISRV_CMDTOUT)) == NULL)) {
		u2up_log_error("evm_tmrid_add() failed!\n");
		rv = -1;
	}
	if ((rv == 0) && (evm_tmrid_cb_handle_set(tmridClisrvCmdTout, handleTmrClisrvCmdTout) < 0)) {
		u2up_log_error("evm_tmrid_cb_handle_set() failed!\n");
		rv = -1;
	}
	/* Initialize CLI server listen socket */
	if ((rv == 0) && ((clisrv_lsd = clisrvSocket_init(CLISRV_SOCK_PATH)) < 0)) {
		u2up_log_error("clisrvSocket_init() failed!\n");
		rv = -1;
	}

	return rv;
}
