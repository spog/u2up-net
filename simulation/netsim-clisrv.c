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

typedef struct clisrv_pconn {
	int fd;
	char *msg;
	int msgsz; /*without termination null character*/
	char *tokens;
	int nr_tokens;
} clisrv_pconn_struct;

struct clisrv_conn {
	clisrv_pconn_struct * pconn;
};

static evmConsumerStruct *clisrv_consumer;
static evmMsgtypeStruct *msgtype_ptr;
static evmMsgidStruct *msgid_init_ptr;
static evmTmridStruct *tmridClisrvCmdTout;

static int clisrv_lsd;
static struct pollfd *clisrvFds;
static struct clisrv_conn *clisrvConns;
static int clisrvNfds = 1;
static struct timespec timeOut = {
	.tv_sec = 10,
	.tv_nsec = 0
};
static sigset_t clisrv_sigmask;

enum clisrv_auto_cmdline {
	CLISRV_AUTO_COMPLETE = 0,
	CLISRV_AUTO_SUGGEST
};

enum clisrv_cmd_types {
	CLISRV_CMD = 0,
	CLISRV_ARG,
	CLISRV_VAL,
	CLISRV_EQUALS,
	CLISRV_SQUARE_L,
	CLISRV_SQUARE_R,
	CLISRV_CURLY_L,
	CLISRV_CURLY_R,
	CLISRV_VERTBAR
};

typedef struct clisrv_token clisrv_token_struct;
struct clisrv_token {
	clisrv_token_struct *base;
	clisrv_token_struct *next;
	int type; /*(command, argument, value, CTRL)*/
	int cub;
	int sqb;
	char *strval;
};

typedef struct clisrv_cmd clisrv_cmd_struct;
struct clisrv_cmd {
	clisrv_cmd_struct *next;
	char *cmd;
	int cmdsz;
	clisrv_token_struct *tokens;
	int nr_tokens;
	int (*cmd_handle)(clisrv_pconn_struct *pconn_cmd);
};

typedef struct clisrv_cmds {
	clisrv_cmd_struct *first;
	char **clicmds;
	int nr_cmds;
} clisrv_cmds_struct;

static clisrv_cmds_struct *clisrv_pcmds;
static char *clisrv_cmds[] = {
	"help",
	"dump",
	"disable addr",
	"enable {all | addr=%.8x | id=%u}",
	NULL
};

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

static char * squeezeStrIfBegin(char *str, char c)
{
	int squeeze;
	char *begin = str;
	char *tmp;
	
	if (str == NULL)
		return NULL;

	do {
		squeeze = 0;
		if (*begin == c)
			squeeze = 1;

		if (squeeze != 0) {
			tmp = begin;
			while (*tmp != '\0') {
				*tmp = *(tmp + 1);
				tmp++;
			}
		}
	} while (squeeze != 0);

	return begin;
}

static char * squeezeStrIfNext(char *str, char c)
{
	int squeeze;
	char *next = str + 1;
	char *tmp;
	
	if (str == NULL)
		return NULL;

	do {
		squeeze = 0;
		if (*next == c)
			squeeze = 1;

		if (squeeze != 0) {
			tmp = next;
			while (*tmp != '\0') {
				*tmp = *(tmp + 1);
				tmp++;
			}
		}
	} while (squeeze != 0);

	return next;
}

static clisrv_token_struct * tokenizeCmdStr(clisrv_cmd_struct *clicmd)
{
	int rv = 0, i = 0;
	char *tmp;
	int cub, sqb;
	int token_on;
	clisrv_token_struct *new;
	clisrv_token_struct *base = NULL;
	clisrv_token_struct *current;
	clisrv_token_struct *curr_base;
	evm_log_info("(entry)\n");

	if (clicmd == NULL) {
		evm_log_error("Invalid argument clicmd=%p\n", clicmd);
		return NULL;
	}

	evm_log_debug("tokenizeCmdStr clicmd->cmd: %s\n", clicmd->cmd);

	tmp = clicmd->cmd;
	sqb = 0;
	cub = 0;
	token_on = U2UP_NET_FALSE;
	while (*tmp != '\0') {
		evm_log_debug("tokenizeCmdStr tmp: %s\n", tmp);
		if (*tmp == '{') {
			cub++;
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: left curly bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_CURLY_L;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->sqb = current->sqb;
			new->cub = cub;

			current = new;
		}
		if (*tmp == '}') {
			cub--;
			if (cub < 0) {
				evm_log_error("Syntax error - curly brackets: more rights then lefts\n");
				abort();
			}
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: right curly bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_CURLY_R;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->sqb = current->sqb;
			new->cub = cub;
			curr_base = current->base;
			while (curr_base->type != CLISRV_CURLY_L) {
				curr_base = curr_base->base;
				if (curr_base == base)
					break;
			}
			if (curr_base->type != CLISRV_CURLY_L) {
				evm_log_error("Syntax error - curly brackets: left not found\n");
				abort();
			}
			new->base = curr_base;
			if (new->cub != (new->base->cub - 1)) {
				evm_log_error("Syntax error - curly brackets: left not matched\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '[') {
			sqb++;
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: left square bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_SQUARE_L;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->cub = current->cub;
			new->sqb = sqb;

			current = new;
		}
		if (*tmp == ']') {
			sqb--;
			if (sqb < 0) {
				evm_log_error("Syntax error - square brackets: more rights then lefts\n");
				abort();
			}
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: right square bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_SQUARE_R;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->cub = current->cub;
			new->sqb = sqb;
			curr_base = current->base;
			while (curr_base->type != CLISRV_SQUARE_L) {
				curr_base = curr_base->base;
				if (curr_base == base)
					break;
			}
			if (curr_base->type != CLISRV_SQUARE_L) {
				evm_log_error("Syntax error - square brackets: left not found\n");
				abort();
			}
			new->base = curr_base;
			if (new->sqb != (new->base->sqb - 1)) {
				evm_log_error("Syntax error - square brackets: left not matched\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '|') {
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: vertbar\n");
				abort();
			}
			current->next = new;
			new->type = CLISRV_VERTBAR;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->cub = current->cub;
			new->sqb = current->sqb;
			curr_base = current;
			do {
				curr_base = curr_base->base;
				if (curr_base == base)
					break;
			} while (
				(curr_base->type == CLISRV_VERTBAR) ||
				(curr_base->type == CLISRV_ARG)
			);
			new->base = curr_base;
			if (
				(curr_base->type == CLISRV_VERTBAR) ||
				(curr_base->type == CLISRV_ARG)
			) {
				evm_log_error("Syntax error - verbar\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '=') {
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: equals\n");
				abort();
			}
			current->next = new;
			new->type = CLISRV_EQUALS;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->cub = current->cub;
			new->sqb = current->sqb;
			new->base = current;
			if (new->base->type != CLISRV_ARG) {
				evm_log_error("Syntax error - equals\n");
				abort();
			}

			current = new;
		}
		switch (*tmp) {
		case ' ':
		case '{':
		case '}':
		case '[':
		case ']':
		case '|':
		case '=':
			token_on = U2UP_NET_FALSE;
			squeezeStrIfNext(tmp, ' ');
			*tmp = '\0';
			break;
		default:
			if (token_on == U2UP_NET_FALSE) {
				token_on = U2UP_NET_TRUE;
				if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
					evm_log_system_error("calloc() - clisrv_token_struct: strval\n");
					abort();
				}
				if (base == NULL) {
					base = new;
					new->base = new;
					new->type = CLISRV_CMD;
					evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
				} else {
					current->next = new;
					new->base = current;
					if (new->base->type != CLISRV_EQUALS) {
						new->type = CLISRV_ARG;
						evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
					} else {
						new->type = CLISRV_VAL;
						evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
					}
				}
				new->strval = tmp;
				evm_log_debug("tokenizeCmdStr new->strval: %s\n", new->strval);

				current = new;
			}
		}
		tmp++;
	}

	return base;
}

static clisrv_cmd_struct * tokenizeCliCmd(char *clicmd)
{
	int rv = 0, i = 0;
	clisrv_cmd_struct *tmp;
	evm_log_info("(entry) clicmd=%p\n", clicmd);

	if (clicmd == NULL) {
		evm_log_error("Invalid argument clicmd=%p\n", clicmd);
		return NULL;
	}

	printf("tokenize cmd: %s\n", clicmd);
	if ((tmp = (clisrv_cmd_struct *)calloc(1, sizeof(clisrv_cmd_struct))) == NULL) {
		evm_log_system_error("calloc() - clisrv_cmd_struct\n");
		return NULL;
	}
	tmp->cmdsz = strlen(clicmd);
	if ((tmp->cmd = (char *)calloc(tmp->cmdsz, sizeof(char))) == NULL) {
		evm_log_system_error("calloc() - cmd string\n");
		return NULL;
	}
	memcpy(tmp->cmd, clicmd, tmp->cmdsz + 1);
	if ((tmp->tokens = tokenizeCmdStr(tmp)) == NULL) {
		abort();
	}

#if 1 /*test init result*/
	{
		clisrv_token_struct *token = tmp->tokens;
		printf("cmd tokens: ");
		while (token != NULL) {
			if (
				(token->type == CLISRV_CMD) ||
				(token->type == CLISRV_ARG) ||
				(token->type == CLISRV_VAL)
			   ) {
				printf("%s ", token->strval);
			}
			token = token->next;
		}
		printf("\n");
	}
#endif

	return tmp;
}

static clisrv_cmds_struct * tokenizeCliCmds(char *clicmds[])
{
	int rv = 0, i = 0;
	clisrv_cmd_struct **tmp;
	clisrv_cmds_struct *pcmds;
	evm_log_info("(entry) clicmds=%p\n", clicmds);

	if (clicmds == NULL) {
		evm_log_error("Invalid argument clicmds=%p\n", clicmds);
		return NULL;
	}

	if ((pcmds = (clisrv_cmds_struct *)calloc(1, sizeof(clisrv_cmds_struct))) == NULL) {
		evm_log_system_error("calloc() - clisrv_cmds_struct\n");
		return NULL;
	}

	pcmds->clicmds = clicmds;
	while (clicmds[i] != NULL) {
		evm_log_debug("cmd[%d]: %s\n", i, clicmds[i]);
		if (pcmds->first == NULL)
			tmp = &pcmds->first;
		if ((*tmp = tokenizeCliCmd(clicmds[i])) == NULL) {
			abort();
		}
		tmp = &(*tmp)->next;
		i++;
	}
	pcmds->nr_cmds = i;
#if 1
	printf("nr_cmds=%d\n", pcmds->nr_cmds);
	tmp = &pcmds->first;
	i = 0;
	while ((*tmp) != NULL) {
		printf("cmd[%d]\n", i);
		tmp = &(*tmp)->next;
		i++;
	}
#endif

	return pcmds;
}

static int tokenizeCmdLine(clisrv_pconn_struct *pconn)
{
	int rv = 0;
	char *tmp;
	evm_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}
#if 1
	if ((tmp = (char *)reallocarray(pconn->tokens, (pconn->msgsz + 1), sizeof(char))) == NULL) {
		evm_log_return_system_err("realocarray() - tokens\n");
	}
#else
	free(pconn->tokens);
	pconn->tokens = NULL;
	if ((tmp = (char *)calloc((pconn->msgsz + 1), sizeof(char))) == NULL) {
		evm_log_return_system_err("calloc() - tokens\n");
	}
#endif
	memcpy(tmp, pconn->msg, pconn->msgsz + 1);
	pconn->tokens = tmp;
	pconn->nr_tokens = 0;
	while (*tmp != '\0') {
		switch (*tmp) {
		case ' ':
		case ',':
		case ';':
		case '\t':
		case '\n':
		case '\r':
			if (tmp == pconn->tokens) {
				squeezeStrIfBegin(tmp, *tmp);
			} else {
				int squeeze;
				char *next = tmp + 1;
				do {
					squeeze = U2UP_NET_FALSE;
					switch (*next) {
					case ' ':
					case ',':
					case ';':
					case '\t':
						squeeze = U2UP_NET_TRUE;
					}
					if (squeeze == U2UP_NET_TRUE) {
						char *next_tmp = next;
						while (*next_tmp != '\0') {
							*next_tmp = *(next_tmp + 1);
							next_tmp++;
						}
					}
				} while (squeeze == U2UP_NET_TRUE);
				*tmp = '\0';
				if ((tmp > pconn->tokens) && (*(tmp - 1) != '\0')) 
					pconn->nr_tokens++;
			}
		}
		tmp++;
	}
	return 0;
}

static int setCliCmdResponseByTokens(clisrv_cmds_struct *pcmds, clisrv_pconn_struct *pconn, char *buff, int size, int mode)
{
	int i;
	int cmd_found = 0;
	int cmd_part_found = 0;
	char *token;
	char *strval;
	clisrv_cmd_struct *pcmd;
	evm_log_info("(entry)\n");

	if (pcmds == NULL) {
		evm_log_error("Invalid argument pcmds=%p\n", pcmds);
		return -1;
	}

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	token = pconn->tokens;
	pcmd = pcmds->first;
	for (i = 0; i < pcmds->nr_cmds; i++) {
		strval = pcmd->tokens->strval;
		printf("%s\n", strval);
		printf("Comparing: mode=%d, strval=%s, token=%s\n", mode, strval, token);
		if (strlen(strval) >= strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				printf("partially compared: strval=%s, token=%s\n", strval, token);
				cmd_part_found++;
				printf("buff-1: '%s'\n", buff);
#if 0
				strncat (buff, pconn->msg, size);
				printf("buff-2: '%s'\n", buff);
				if (buff[strlen(buff) - 1] == '\t')
					buff[strlen(buff) - 1] = '\0';
				printf("buff-3: '%s'\n", buff);
#endif
				if (mode == CLISRV_AUTO_SUGGEST) {
					strncat(buff, "\n", size);
					strncat(buff, pconn->msg, size);
				}

				strncat (buff, &strval[strlen(token)], size);
				printf("buff-4: '%s'\n", buff);
				strncat (buff, " ", size);
				printf("buff-5: '%s'\n", buff);
#if 0
				if (strlen(strval) == strlen(token)) {
					printf("fully compared: strval=%s, token=%s\n", strval, token);
					cmd_found++;
					strncat (buff, " ", size);
					break;
				}
				if (mode == CLISRV_AUTO_SUGGEST)
					strncat (buff, "\n", size);
#endif
			}
		}
		pcmd = pcmd->next;
	}
	if (cmd_found != 0) {
		for (i = 0; i < pconn->nr_tokens; i++) {
			printf("%s\n", token);

			token += (strlen(token) + 1);
		}
	}

	return cmd_part_found;
}

static int autoCmdLine(clisrv_pconn_struct *pconn, int mode)
{
	int rv = 0, i;
	char *token;
	char buff[1024] = "";
	evm_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (mode == CLISRV_AUTO_SUGGEST)
		strncat (buff, "<pre>", 1024);

	if ((rv = setCliCmdResponseByTokens(clisrv_pcmds, pconn, buff, 1024, mode)) < 0) {
		evm_log_error("setCliCmdResponseByToken() failed\n");
		return -1;
	}

	switch (mode) {
	case CLISRV_AUTO_COMPLETE:
		if (rv == 1) {
			printf("Auto-Complete-send(len=%ld):'%s'\n", strlen(buff), buff);
			if ((rv = send(pconn->fd, buff, (strlen(buff) + 1), 0)) < 0) {
				evm_log_system_error("send()\n");
			}
		} else {
			/* If AUTO-COMPLETE returns more matches, send back only '\t'! */
			printf("Auto-Complete(pconn->msgsz=%d):'%s'\n", pconn->msgsz, pconn->msg);
			printf("Auto-Complete-send(len=1):'\t'\n");
			if ((rv = send(pconn->fd, "\t", 2, 0)) < 0) {
				evm_log_system_error("send()\n");
			}
		}
		break;
	case CLISRV_AUTO_SUGGEST:
		{
			strncat (buff, "</pre>", 1024);
			strncat (buff, pconn->msg, 1024);
			printf("Auto-Suggest(len=%ld, pconn->msgsz=%d):'%s'\n", strlen(buff), pconn->msgsz, buff);
			/* Echo the data back to the client */
			if ((rv = send(pconn->fd, buff, (strlen(buff) + 1), 0)) < 0) {
				evm_log_system_error("send()\n");
			}
		}
		break;
	}
	return 0;
}

static int execCmdLine(clisrv_pconn_struct *pconn)
{
	int rv = 0, i;
	char *token;
	char buff[1024] = "";
	evm_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

#if 0
	token = pconn->tokens;
	for (i = 0; i < pconn->nr_tokens; i++) {

	}
#endif

	strncat (buff, "<pre>", 1024);
	strncat (buff, pconn->msg, 1024);
	strncat (buff, "</pre>", 1024);
	printf("sending msg: '%s'\n", buff);
	/* Echo the data back to the client */
	if ((rv = send(pconn->fd, buff, (strlen(buff) + 1), 0)) < 0) {
		evm_log_system_error("send()\n");
	}
	return 0;
}

static int parseCmdLine(clisrv_pconn_struct *pconn)
{
	int rv = 0;
	evm_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	tokenizeCmdLine(pconn);
#if 1
	printf("pconn->tokens=%s, pconn->nr_tokens=%d\n", pconn->tokens, pconn->nr_tokens);
	{
		char *token = pconn->tokens;
		while (rv < pconn->nr_tokens) {
			printf("%s\n", token);
			token += (strlen(token) + 1);
			rv++;
		}
	}
	rv = 0;
#endif

	printf("pconn->msgsz=%d'\n", pconn->msgsz);
	printf("pconn->msg='%s'\n", pconn->msg);
	if (pconn->msgsz > 0) {
#if 0
		if (
			(pconn->msg[pconn->msgsz - 1] == '\t') &&
			(pconn->msg[pconn->msgsz - 2] == '\t') 
		) {
			/* Auto-suggest the cmdline */
			if ((rv = autoCmdLine(pconn, CLISRV_AUTO_SUGGEST)) < 0) {
				evm_log_error("Failed to auto-suggest cmdline!\n");
			}
			return rv;
		}
#endif

		if (pconn->msg[pconn->msgsz - 1] == '\t') {
			if (pconn->msgsz > 1) {
				if (pconn->msg[pconn->msgsz - 2] == '\t') {
					pconn->msg[pconn->msgsz - 2] = '\0';
					pconn->msgsz -= 2;
					/* Auto-suggest the cmdline */
					if ((rv = autoCmdLine(pconn, CLISRV_AUTO_SUGGEST)) < 0) {
						evm_log_error("Failed to auto-suggest cmdline!\n");
					}
					return rv;
				}
			}
			/* Auto-complete the cmdline */
			if ((rv = autoCmdLine(pconn, CLISRV_AUTO_COMPLETE)) < 0) {
				evm_log_error("Failed to auto-complete cmdline!\n");
			}
			return rv;
		}

		if (pconn->msg[pconn->msgsz - 1] == '\n') {
#if 0
			/* Echo the data back to the client */
			if ((rv = send(pconn->fd, pconn->msg, (pconn->msgsz + 1), 0)) < 0) {
				evm_log_system_error("send()\n");
			}
#else
#if 1
//			if (pconn->msg[strlen(pconn->msg) - 1] == '\n') {
//				pconn->msg[strlen(pconn->msg) - 1] = '\0';
			pconn->msg[pconn->msgsz - 1] = '\0';
			pconn->msgsz--;
//			}
#endif
			/* Execute the cmdline */
			if ((rv = execCmdLine(pconn)) < 0) {
				evm_log_error("Failed to execute the cmdline!\n");
			}
#if 0 /*maybe not necessary*/
			/* Clear current message - pconn->tokens get reallocated -> no need to free */
			pconn->msg[0] = '\0';
			pconn->msgsz = 0;
#endif
#endif
			return rv;
		} else {
			/*message incomplete*/
			rv = 0;
		}
	} else {
		/*message empty*/
		rv = 0;
	}

	return rv;
}

static int parseReceivedData(clisrv_pconn_struct *pconn, char *buff, int len)
{
	char *tmp;
	evm_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (buff == NULL) {
		evm_log_error("Invalid argument buff=%p\n", buff);
		return -1;
	}

	if (len != (strlen(buff) + 1)) {
		evm_log_error("Invalid argument len=%d (does not match string size)\n", len);
		return -1;
	}

#if 0
#if 1
//	printf("pconn->msg=%p, pconn->msgsz=%d, len=%d\n", pconn->msg, pconn->msgsz, len);
	if ((tmp = (char *)reallocarray(pconn->msg, pconn->msgsz + len, sizeof(char))) == NULL) {
		evm_log_system_error("realocarray() - msg\n");
	}
#else
	printf("pconn->msg=%p, pconn->msgsz=%d, len=%d\n", pconn->msg, pconn->msgsz, len);
	if ((tmp = (char *)calloc((pconn->msgsz + len), sizeof(char))) == NULL) {
		evm_log_return_system_err("realocarray() - msg\n");
	}
	if (pconn->msg != NULL) {
		memcpy(tmp, pconn->msg, pconn->msgsz + 1);
		free(pconn->msg);
	}
#endif
	pconn->msg = tmp;
	tmp += pconn->msgsz;
	memcpy(tmp, buff, len);
	pconn->msgsz += (len - 1);
#else
	if ((tmp = (char *)reallocarray(pconn->msg, len, sizeof(char))) == NULL) {
		evm_log_system_error("realocarray() - msg\n");
		abort();
	}
	pconn->msg = tmp;
	memcpy(tmp, buff, len);
	pconn->msgsz = len - 1;
#if 0
	if (pconn->msg[strlen(pconn->msg) - 1] == '\n') {
		pconn->msg[strlen(pconn->msg) - 1] = '\0';
		if (pconn->msgsz > 0)
			pconn->msgsz--;
	}
#endif
#endif

	return parseCmdLine(pconn);
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
	struct clisrv_conn *newClisrvConns;
	clisrv_pconn_struct *pconn;
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
						evm_log_system_error("realocarray() - clisrvFds\n");
						end_server = U2UP_NET_TRUE;
						break;
					}
					clisrvFds = newClisrvFds;
					clisrvFds[clisrvNfds].fd = new_sd;
					clisrvFds[clisrvNfds].events = POLLIN;
					if ((newClisrvConns = (struct clisrv_conn *)reallocarray(clisrvConns, clisrvNfds + 1, sizeof(struct clisrv_conn))) == NULL) {
						evm_log_system_error("realocarray() - clisrvConns\n");
						end_server = U2UP_NET_TRUE;
						break;
					}
					clisrvConns = newClisrvConns;
					if ((pconn = (clisrv_pconn_struct *)calloc(1, sizeof(clisrv_pconn_struct))) == NULL) {
						evm_log_system_error("calloc() - pconn\n");
						end_server = U2UP_NET_TRUE;
						break;
					}
					clisrvConns[clisrvNfds].pconn = pconn;
					clisrvConns[clisrvNfds].pconn->fd = new_sd;
					clisrvConns[clisrvNfds].pconn->msg = NULL;
					clisrvConns[clisrvNfds].pconn->msgsz = 0;
					clisrvConns[clisrvNfds].pconn->tokens = NULL;
					clisrvConns[clisrvNfds].pconn->nr_tokens = 0;
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
					printf("received msg(len=%ld): '%s'\n", strlen(buffer), buffer);

/*TODO - Parse the received data, take action an reply! */
#if 0 /*orig*/
					/* Echo the data back to the client */
					if ((rv = send(clisrvFds[i].fd, buffer, len, 0)) < 0) {
						evm_log_system_error("send()\n");
						close_conn = U2UP_NET_TRUE;
						break;
					}
#else
					/* Parse received data */
					if ((rv = parseReceivedData(clisrvConns[i].pconn, buffer, len)) < 0) {
						evm_log_error("parseReceivedData()\n");
						close_conn = U2UP_NET_TRUE;
						break;
					}
#endif

				} while(U2UP_NET_TRUE);

				/* Clean up closed connection (flagged*) */
				if (close_conn) {
					close(clisrvFds[i].fd);
					clisrvFds[i].fd = -1;
					clisrvConns[i].pconn->fd = -1;
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
//Not good point to free - let's leave it now:	free(clisrvConns[j].pconn);
						clisrvConns[j].pconn = clisrvConns[j + 1].pconn;
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
	if ((clisrvFds = (struct pollfd *)calloc(1, sizeof(struct pollfd))) == NULL) {
		evm_log_system_error("calloc() - struct pollfd\n");
		return -1;
	}

	/* Set up the initial listening socket */
	clisrvFds[0].fd = listen_sd;
	clisrvFds[0].events = POLLIN;

	/* Initialize the clisrv_conn structure */
	if ((clisrvConns = (struct clisrv_conn *)calloc(1, sizeof(struct clisrv_conn))) == NULL) {
		evm_log_system_error("calloc() - struct clisrv_conn\n");
		return -1;
	}

	/* Set NULL for the listening socket - it does not represent a connection */
	clisrvConns[0].pconn = NULL;

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

#if 1
	if ((rv == 0) && ((clisrv_pcmds = tokenizeCliCmds(clisrv_cmds)) == NULL)) {
		evm_log_error("tokenizeCliCmds() failed!\n");
		rv = -1;
	}
#endif
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
