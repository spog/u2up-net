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
	int level;
	int mand;
	int opti;
	int altr;
	char *strval;
	char *eqspec;
	char eqval[100];
};

typedef struct clisrv_cmd clisrv_cmd_struct;
struct clisrv_cmd {
	clisrv_cmd_struct *next;
	char *cmd;
	int cmdsz;
	clisrv_token_struct *tokens;
	int nr_tokens;
	int (*cmd_handle)(clisrv_token_struct *curr_tokens, char *buff, int size);
};

typedef struct clisrv_cmds {
	clisrv_cmd_struct *first;
	char **clicmds;
	int nr_cmds;
} clisrv_cmds_struct;

static clisrv_cmds_struct *clisrv_pcmds;
static char *clisrv_cmds[] = {
	"help",
	"dump [prefix=%s]",
	"disable {addr=%8x | id=%u}",
	"enable {all | addr=%8x | id=%u}",
	"quit",
#if 0 /*test*/
	"test1 {a|b c|d}",
	"test2 {a} {b} {c}",
	"test3 {a=%d | b|c}|{d | e}",
#endif
	NULL
};

static int help_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int dump_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int disable_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int enable_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int quit_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
#if 1 /*test*/
static int test1_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int test2_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
static int test3_handle(clisrv_token_struct *curr_tokens, char *buff, int size);
#endif

static int (*cmd_handle[])(clisrv_token_struct *curr_tokens, char *buff, int size) = {
	help_handle,
	dump_handle,
	disable_handle,
	enable_handle,
	quit_handle,
#if 0 /*test*/
	test1_handle,
	test2_handle,
	test3_handle,
#endif
};

static int pconnCmdRemoveToken(clisrv_pconn_struct *pconn, char *token)
{
	char *next_token;
	int i, remain;

	if (pconn == NULL)
		return -1;

	if (token == NULL)
		return -1;

	if (pconn->nr_tokens <= 0)
		return -1;

	if ((token < pconn->tokens) || ((token - pconn->tokens) > (pconn->msgsz + 1)))
		return -1;

	next_token = token + (strlen(token) + 1);
	remain = pconn->tokens + pconn->msgsz + 1 - next_token;

#if 1
	printf("1 - pconn->nr_tokens=%d: ", pconn->nr_tokens);
	{
		int rv = 0;
		char *cmd_token = pconn->tokens;
		while (rv < pconn->nr_tokens) {
			printf("'%s' ", cmd_token);
			cmd_token += (strlen(cmd_token) + 1);
			rv++;
		}
		printf("\n");
	}
#endif
	for (i = 0; i < remain; i++) {
		token[i] = next_token[i];
	}
	pconn->nr_tokens--;
#if 1
	printf("2 - pconn->nr_tokens=%d: ", pconn->nr_tokens);
	{
		int rv = 0;
		char *cmd_token = pconn->tokens;
		while (rv < pconn->nr_tokens) {
			printf("'%s' ", cmd_token);
			cmd_token += (strlen(cmd_token) + 1);
			rv++;
		}
		printf("\n");
	}
#endif

	return 0;
}

void freePcmdCurrentTokens(clisrv_token_struct **curr_tokens)
{
	printf("freePcmdCurrentTokens: entry\n");
	/* Recursive freing */
	if (curr_tokens != NULL) {
		if (*curr_tokens != NULL) {
			while ((*curr_tokens)->next != NULL) {
				freePcmdCurrentTokens(&((*curr_tokens)->next));
				(*curr_tokens)->next = NULL;
			}
			free(*curr_tokens);
			*curr_tokens = NULL;
		}
	}
}

static clisrv_token_struct * clisrvCheckAndSetCommand(clisrv_token_struct *pcmd_token, clisrv_pconn_struct *pconn)
{
	clisrv_token_struct *new;

	if (pcmd_token == NULL)
		return NULL;

	if (pconn == NULL)
		return NULL;

	if (pconn->nr_tokens == 0)
		return NULL;

	if (strcmp(pcmd_token->strval, pconn->tokens) != 0)
		return NULL;

	if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
		evm_log_system_error("calloc() - clisrv_token_struct: command\n");
		abort();
	}

	new->type = CLISRV_CMD;
	new->strval = pcmd_token->strval;
	pconnCmdRemoveToken(pconn, pconn->tokens);

	return new;
}

static clisrv_token_struct * clisrvCheckAndSetArgument(clisrv_token_struct *pcmd_token, clisrv_pconn_struct *pconn, clisrv_token_struct *curr_tokens)
{
	clisrv_token_struct *last;
	char *token, *eq;
	int i;

	if (pcmd_token == NULL)
		return NULL;

	if (curr_tokens == NULL)
		return NULL;

	if (pconn == NULL)
		return NULL;

#if 0
	if (pcmd_token->opti <= pcmd_token->mand)
		if (pconn->nr_tokens == 0)
			return NULL;
#endif
#if 0
	printf("(pcmd_token=%p) '%s'\n", pcmd_token, pcmd_token->strval);
	printf(" level=%d\n", pcmd_token->level);
	printf(" mand=%d\n", pcmd_token->mand);
	printf(" opti=%d\n", pcmd_token->opti);
	printf(" altr=%d\n", pcmd_token->altr);
	printf("\n");
#endif

	last = curr_tokens;
	while (last->next != NULL) {
		last = last->next;
	}

#if 0
	printf("(last=%p) '%s'\n", last, last->strval);
	printf(" level=%d\n", last->level);
	printf(" mand=%d\n", last->mand);
	printf(" opti=%d\n", last->opti);
	printf(" altr=%d\n", last->altr);
	printf("\n");
#endif
#if 1
	if (pconn->nr_tokens == 0) {
		if ((pcmd_token->opti <= pcmd_token->mand) && (pcmd_token->altr == 0)) {
//	if ((last->opti <= last->mand) && (last->altr == 0)) {
//		if (pconn->nr_tokens == 0) {
			/*ERROR: mandatory command arguments required, but no more pconn tokens provided */
			printf("mandatory command arguments required, but no more pconn tokens provided\n");
			evm_log_debug("mandatory command arguments required, but no more pconn tokens provided\n");
			return NULL;
		}
	}
#endif

	i = pconn->nr_tokens;
	token = pconn->tokens;
	while (i > 0) {
		if (strncmp(token, pcmd_token->strval, strlen(pcmd_token->strval)) == 0) {

			if ((last->next = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: argument\n");
				abort();
			}

			last->next->type = CLISRV_ARG;
			last->next->strval = pcmd_token->strval;
			last->next->level = pcmd_token->level;
			last->next->mand = pcmd_token->mand;
			last->next->opti = pcmd_token->opti;
			last->next->altr = pcmd_token->altr;
			if ((last->next->altr != 0) && (last->next->altr == last->altr)) {
				/*ERROR: more than one alternative arguments provided*/
				evm_log_debug("more than one alternative arguments provided\n");
				freePcmdCurrentTokens(&curr_tokens);
				return NULL;
			}
			if ((eq = strchr(token, '=')) != NULL) {
				/*argument with value provided*/
				if ((pcmd_token->next != NULL) && (pcmd_token->next->type == CLISRV_EQUALS)) {
					if ((pcmd_token->next->next != NULL) && (pcmd_token->next->next->type == CLISRV_VAL)) {
						last->next->altr = pcmd_token->next->next->altr;
						last->next->eqspec = pcmd_token->next->next->strval;
						eq++;
						if (strlen(eq) < 100) {
							strncpy(last->next->eqval, eq, 100);
						} else {
							/*ERROR: value string too long*/
							evm_log_debug("argument value string too long\n");
							freePcmdCurrentTokens(&curr_tokens);
							return NULL;
						}
					} else {
						/*ERROR: value required, but value specification missing*/
						evm_log_debug("argument value required, but value specification missing\n");
						freePcmdCurrentTokens(&curr_tokens);
						return NULL;
					}
				} else {
					/*ERROR: value not required, but provided*/
					evm_log_debug("argument value provided, but none required\n");
					freePcmdCurrentTokens(&curr_tokens);
					return NULL;
				}
			} else {
				/*argument without provided value*/
				if ((pcmd_token->next != NULL) && (pcmd_token->next->type == CLISRV_EQUALS)) {
					/*ERROR: value required, but none provided*/
					evm_log_debug("argument value required, but none provided\n");
					freePcmdCurrentTokens(&curr_tokens);
					return NULL;
				}
				last->next->eqval[0] = '\0';
			}
			pconnCmdRemoveToken(pconn, token);
			break;
		}
		i--;
		token += (strlen(token) + 1);
	}

	return curr_tokens;
}

clisrv_token_struct * checkSyntaxAndSetValues(clisrv_cmd_struct *this, clisrv_pconn_struct *pconn)
{
	clisrv_token_struct *pcmd_token;
	clisrv_token_struct *curr_tokens;

	if (this == NULL)
		return NULL;

	if (pconn == NULL)
		return NULL;

	/* Analyse command token */
	pcmd_token = this->tokens;
	if (pcmd_token->type != CLISRV_CMD) {
		return NULL;
	}
	if ((curr_tokens = clisrvCheckAndSetCommand(pcmd_token, pconn)) == NULL) {
		return NULL;
	}

	/* Analyse command argument tokens: walk through command specification! */
	while (U2UP_NET_TRUE) {
		pcmd_token = pcmd_token->next;
		if (pcmd_token == NULL) {
			/* We got through command template! */
			if (pconn->nr_tokens != 0) {
				/* pconn tokens remaining: unknown cmd arguments */
				freePcmdCurrentTokens(&curr_tokens);
				return NULL;
			}
			return curr_tokens;
		}

		/* Error check - just in case */
		if (pcmd_token->type == CLISRV_CMD) {
			evm_log_error("CLISRV_CMD should not be detected here!\n");
			freePcmdCurrentTokens(&curr_tokens);
			return NULL;
		}
		/* Skip! */
		if (pcmd_token->type != CLISRV_ARG) {
			continue;
		}

#if 0
		/* mandatory command arguments required, but no more pconn tokens provided */
		if (pcmd_token->opti <= pcmd_token->mand) {
			if (pconn->nr_tokens == 0) {
				/* no more pconn tokens: missing cmd arguments */
				freePcmdCurrentTokens(&curr_tokens);
				return NULL;
			}
		}
#endif
		/* Still not through command template! */
		if (pcmd_token->type != CLISRV_ARG) {
			evm_log_error("Only CLISRV_ARG should be detected here (type=%d)!\n", pcmd_token->type);
			freePcmdCurrentTokens(&curr_tokens);
			return NULL;
		}

		if ((curr_tokens = clisrvCheckAndSetArgument(pcmd_token, pconn, curr_tokens)) == NULL) {
			return NULL;
		}
	}

	return curr_tokens;
}

static clisrv_token_struct * getCurrentToken(clisrv_token_struct *curr_tokens, char *strval)
{
	clisrv_token_struct *curr_token;

	if (curr_tokens == NULL)
		return NULL;

	if (strval == NULL)
		return NULL;

	if (strlen(strval) == 0)
		return NULL;

	curr_token = curr_tokens;
	while (curr_token != NULL) {
		if ((curr_token->strval != NULL) && (strlen(curr_token->strval) > 0)) {
			if (strcmp(curr_token->strval, strval) == 0) {
				break;
			}
		}
		curr_token = curr_token->next;
	}

	return curr_token;
}

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

static int disable_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *addr_token;
	clisrv_token_struct *id_token;
	uint32_t addr;
	unsigned int id;

	if ((addr_token = getCurrentToken(curr_tokens, "addr")) != NULL) {
		if ((addr_token->eqval != NULL) && (strlen(addr_token->eqval) > 0)) {
			sscanf(addr_token->eqval, addr_token->eqspec, &addr);
		}
		printf("disable command handle called (addr=%8x)!'\n", addr);
		if (getNodeIdByAddr(addr, &id) != 0) {
			clisrv_strncat(buff, "error: node id by addr not found!", size);
			return 0;
		}
	} else
	if ((id_token = getCurrentToken(curr_tokens, "id")) != NULL) {
		if ((id_token->eqval != NULL) && (strlen(id_token->eqval) > 0)) {
			sscanf(id_token->eqval, id_token->eqspec, &id);
		}
		printf("disable command handle called (id=%u)!'\n", id);
		if (getNodeFirstAddrById(id, &addr) != 0) {
			clisrv_strncat(buff, "error: node addr by id not found!", size);
			return 0;
		}
	}
	printf("disable command handle called (addr=%8x, id=%u)!'\n", addr, id);

	if (disableNodeById(id) != 0)
		snprintf(buff, size, "error: failed to disable node id=%u (addr=%.8x)!", id, addr);
	else
		snprintf(buff, size, "disabled node id=%u (addr=%.8x)", id, addr);

	return 0;
}

static int enable_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	clisrv_token_struct *all_token;
	clisrv_token_struct *addr_token;
	clisrv_token_struct *id_token;
	uint32_t addr;
	unsigned int id;

	if ((all_token = getCurrentToken(curr_tokens, "all")) != NULL) {
		printf("enable command handle called (all)!'\n");
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
		printf("enable command handle called (addr=%8x)!'\n", addr);
		if (getNodeIdByAddr(addr, &id) != 0) {
			clisrv_strncat(buff, "error: node id by addr not found!", size);
			return 0;
		}
	} else
	if ((id_token = getCurrentToken(curr_tokens, "id")) != NULL) {
		if ((id_token->eqval != NULL) && (strlen(id_token->eqval) > 0)) {
			sscanf(id_token->eqval, id_token->eqspec, &id);
		}
		printf("enable command handle called (id=%u)!'\n", id);
		if (getNodeFirstAddrById(id, &addr) != 0) {
			clisrv_strncat(buff, "error: node addr by id not found!", size);
			return 0;
		}
	}
	printf("enable command handle called (addr=%8x, id=%u)!'\n", addr, id);

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

#if 1 /*test*/
static int test1_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	printf("test1 command handle called!'\n");
	return 0;
}

static int test2_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	printf("test2 command handle called!'\n");
	return 0;
}

static int test3_handle(clisrv_token_struct *curr_tokens, char *buff, int size)
{
	printf("test3 command handle called!'\n");
	return 0;
}
#endif

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
	char *tmp;
	int level = 0;
	int mand = 0;
	int opti = 0;
	int altr = 0;
	int altr_last = 0;
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
	token_on = U2UP_NET_FALSE;
	while (*tmp != '\0') {
		evm_log_debug("tokenizeCmdStr tmp: %s\n", tmp);
		if (*tmp == '{') {
			level++;
			mand = level;
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: left curly bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_CURLY_L;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;

			current = new;
		}
		if (*tmp == '}') {
			level--;
			mand = level;
			if (altr > 0)
				altr_last = altr;
			altr = 0;
			if (level < 0) {
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
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
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
			if (new->level != (new->base->level - 1)) {
				evm_log_error("Syntax error - curly brackets: left not matched\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '[') {
			level++;
			opti = level;
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: left square bracket\n");
				abort();
			}
			current->next = new;
			new->base = current;
			new->type = CLISRV_SQUARE_L;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;

			current = new;
		}
		if (*tmp == ']') {
			level--;
			opti = level;
			if (altr > 0)
				altr_last = altr;
			altr = 0;
			if (level < 0) {
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
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
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
			if (new->level != (new->base->level - 1)) {
				evm_log_error("Syntax error - square brackets: left not matched\n");
				abort();
			}

			current = new;
		}
		if (*tmp == '|') {
			if (altr == 0) {
				altr = altr_last + 1;
			}
			if ((new = (clisrv_token_struct *)calloc(1, sizeof(clisrv_token_struct))) == NULL) {
				evm_log_system_error("calloc() - clisrv_token_struct: vertbar\n");
				abort();
			}
			current->next = new;
			current->altr = altr;
			new->type = CLISRV_VERTBAR;
			evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
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
			new->level = level;
			new->mand = mand;
			new->opti = opti;
			new->altr = altr;
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
						if (new->base->type != CLISRV_VERTBAR) {
							if (altr > 0)
								altr_last = altr;
							altr = 0;
						}
					} else {
						new->type = CLISRV_VAL;
						evm_log_debug("tokenizeCmdStr new->type: %d\n", new->type);
					}
				}
				new->level = level;
				new->mand = mand;
				new->opti = opti;
				new->altr = altr;
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
	clisrv_cmd_struct *tmp;
	evm_log_info("(entry) clicmd=%p\n", clicmd);

	if (clicmd == NULL) {
		evm_log_error("Invalid argument clicmd=%p\n", clicmd);
		return NULL;
	}

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
		printf("pcmd tokens:\n");
		while (token != NULL) {
#if 0
			if (
				(token->type == CLISRV_CMD) ||
				(token->type == CLISRV_ARG) ||
				(token->type == CLISRV_VAL)
			   ) {
				printf("%s ", token->strval);
			}
#else
			printf("tokenize cmd: %s\n", clicmd);
			switch (token->type) {
			case CLISRV_CMD:
				printf("COMMAND:\n");
				break;
			case CLISRV_ARG:
				printf("ARGUMENT NAME:\n");
				break;
			case CLISRV_VAL:
				printf("ARGUMENT VALUE:\n");
				break;
			case CLISRV_EQUALS:
				printf("EQUALS:\n");
				break;
			case CLISRV_SQUARE_L:
				printf("OPTIONALY BEGIN:\n");
				break;
			case CLISRV_SQUARE_R:
				printf("OPTIONALY END:\n");
				break;
			case CLISRV_CURLY_L:
				printf("MANDATORY BEGIN:\n");
				break;
			case CLISRV_CURLY_R:
				printf("MANDATORY END:\n");
				break;
			case CLISRV_VERTBAR:
				printf("VERTBAR:\n");
				break;
			}
			printf("(%p) '%s'\n", token, token->strval);
			printf(" base=%p\n", token->base);
			printf(" next=%p\n", token->next);
			printf(" level=%d\n", token->level);
			printf(" mand=%d\n", token->mand);
			printf(" opti=%d\n", token->opti);
			printf(" altr=%d\n", token->altr);
			printf("\n");
#endif
			token = token->next;
		}
		printf("\n");
	}
#endif

	return tmp;
}

static clisrv_cmds_struct * tokenizeCliCmds(char *clicmds[])
{
	int i = 0;
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
		(*tmp)->cmd_handle = cmd_handle[i];
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
#if 0
		printf("tmp='%s'\n", tmp);
#endif
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
#if 0
				printf("tmp:'%s'\n", tmp);
#endif
				if (*(tmp + 1) == '=') {
					*tmp = '=';
					squeezeStrIfNext(tmp, *(tmp + 1));
					switch (*(tmp + 1)) {
					case ' ':
					case '\t':
						squeezeStrIfNext(tmp, *(tmp + 1));
					}
				} else if (*(tmp - 1) == '=') {
					switch (*tmp) {
					case ' ':
					case '\t':
						squeezeStrIfNext((tmp - 1), *tmp);
					}
				} else {
					*tmp = '\0';
					if ((tmp > pconn->tokens) && (*(tmp - 1) != '\0'))
						pconn->nr_tokens++;
				}
			}
		}
		tmp++;
	}
	return 0;
}

static int setCliCmdAutoSuggestByToken(clisrv_token_struct *pcmd_tokens, clisrv_pconn_struct *pconn, char *token, char *buff, int size)
{
	int braces = 0;
	int opt_part_found = 0;
	char *strval;
	clisrv_token_struct *pcmd_token;
	evm_log_info("(entry)\n");

	if (pcmd_tokens == NULL) {
		evm_log_error("Invalid argument pcmd_tokens=%p\n", pcmd_tokens);
		return -1;
	}

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (token == NULL) {
		evm_log_error("Invalid argument token=%p\n", token);
		return -1;
	}

	printf("TEST: setCliCmdAutoSuggestByToken()\n");
	pcmd_token = pcmd_tokens->next;
	while (pcmd_token != NULL) {
		if (
			(pcmd_token->type != CLISRV_CMD) &&
			(pcmd_token->type != CLISRV_ARG)
		   ) {
			pcmd_token = pcmd_token->next;
			continue;
		}
		strval = pcmd_token->strval;
		printf("AutoSuggest - strval: '%s'\n", strval);
		printf("AutoSuggest - Comparing-opts: strval=%s, token=%s\n", strval, token);
		/* Force multi-match, if token empty! */
		if (strlen(token) == 0)
			opt_part_found++;
		if (strlen(strval) >= strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				printf("AutoSuggest - opts - partially compared: strval=%s, token=%s\n", strval, token);
				opt_part_found++;
				printf("AutoSuggest - opts - buff-1: '%s'\n", buff);
#if 0
				if (strlen(strval) == strlen(token)) {
					opt_found = 1;
				}
#endif
			}
		}
		pcmd_token = pcmd_token->next;
	}

	if (opt_part_found > 0) {
		pcmd_token = pcmd_tokens->next;
		braces = 0;
		while (pcmd_token != NULL) {
			if (
				(pcmd_token->type != CLISRV_CMD) &&
				(pcmd_token->type != CLISRV_ARG)
			   ) {
				pcmd_token = pcmd_token->next;
				continue;
			}
			strval = pcmd_token->strval;
			printf("AutoSuggest - strval: '%s'\n", strval);
			if (braces == 0)
				clisrv_strncat(buff, "\n", size);
			printf("AutoSuggest - buff-2: '%s'\n", buff);
			if (
				(pcmd_token->base->type != CLISRV_CMD) &&
				(pcmd_token->base->type != CLISRV_ARG)
			) {
				switch (pcmd_token->base->type) {
				case CLISRV_SQUARE_L:
				case CLISRV_CURLY_L:
					braces++;
					pcmd_token = pcmd_token->base;
					break;
				default:
					pcmd_token = pcmd_token->next;
				};
				while ((braces > 0) && (pcmd_token != NULL)) {
					if (
						(pcmd_token->type != CLISRV_CMD) &&
						(pcmd_token->type != CLISRV_ARG) &&
						(pcmd_token->type != CLISRV_VAL)
					) {
						switch (pcmd_token->type) {
						case CLISRV_SQUARE_L:
							braces++;
//							clisrv_strncat(buff, "[", size);
							if ((strlen(buff) > 0) && (buff[strlen(buff) - 1] != '\n'))
								clisrv_strncat(buff, " [", size);
							else
								clisrv_strncat(buff, "[", size);
							break;
						case CLISRV_SQUARE_R:
							braces--;
							clisrv_strncat(buff, "]", size);
							break;
						case CLISRV_CURLY_L:
							braces++;
							printf("AutoSuggest - curly brace left: strlen(buff)=%ld, buff='%s'\n", strlen(buff), buff);
							if ((strlen(buff) > 0) && (buff[strlen(buff) - 1] != '\n'))
								clisrv_strncat(buff, " {", size);
							else
								clisrv_strncat(buff, "{", size);
							break;
						case CLISRV_CURLY_R:
							braces--;
							clisrv_strncat(buff, "}", size);
							break;
						case CLISRV_EQUALS:
							clisrv_strncat(buff, "=", size);
							break;
						case CLISRV_VERTBAR:
							clisrv_strncat(buff, " | ", size);
							break;
						};
					} else
						clisrv_strncat(buff, pcmd_token->strval, size);

					pcmd_token = pcmd_token->next;
				}
				continue;
			} else {
				clisrv_strncat(buff, strval, size);
				if (pcmd_token->next != NULL)
					if (pcmd_token->next->type == CLISRV_EQUALS)
						if (pcmd_token->next->next != NULL) {
							clisrv_strncat(buff, "=", size);
							clisrv_strncat(buff, pcmd_token->next->next->strval, size);
						}
			}

			printf("AutoSuggest - opts - buff-4: '%s'\n", buff);
			if (buff[strlen(buff) - 1] != '=')
				clisrv_strncat(buff, " ", size);
			printf("AutoSuggest - opts - buff-5: '%s'\n", buff);
			pcmd_token = pcmd_token->next;
		}
	}

	return opt_part_found;
}

static int setCliCmdAutoCompleteByToken(clisrv_token_struct *pcmd_tokens, clisrv_pconn_struct *pconn, char *token, char *buff, int size)
{
	int opt_found = 0;
	int opt_part_found = 0;
	char *strval;
	clisrv_token_struct *pcmd_token;
	evm_log_info("(entry)\n");

	if (pcmd_tokens == NULL) {
		evm_log_error("Invalid argument pcmd_tokens=%p\n", pcmd_tokens);
		return -1;
	}

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (token == NULL) {
		evm_log_error("Invalid argument token=%p\n", token);
		return -1;
	}

	printf("TEST: setCliCmdAutoCompleteByToken()\n");
	pcmd_token = pcmd_tokens->next;
	while (pcmd_token != NULL) {
		if (
			(pcmd_token->type != CLISRV_CMD) &&
			(pcmd_token->type != CLISRV_ARG)
		   ) {
			pcmd_token = pcmd_token->next;
			continue;
		}
		strval = pcmd_token->strval;
		printf("%s\n", strval);
		printf("AutoComplete - Comparing-opts: strval=%s, token=%s\n", strval, token);
		/* Force multi-match, if token empty! */
		if (strlen(token) == 0)
			opt_part_found++;
		if (strlen(strval) >= strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				printf("AutoComplete - opts - partially compared: strval=%s, token=%s\n", strval, token);
				opt_part_found++;
				printf("AutoComplete - opts - buff-1: '%s'\n", buff);

				if (strlen(strval) == strlen(token)) {
					opt_found = 1;
				}

				if (opt_part_found == 1) {
					clisrv_strncat(buff, &strval[strlen(token)], size);
					if (pcmd_token->next->type == CLISRV_EQUALS)
						clisrv_strncat(buff, "=", size);
					if (opt_found == 1)
						break;
				} else {
					int j = 0;
					do {
						if (buff[j] != strval[strlen(token) + j]) {
							buff[j] = '\0';
							break;
						}
						j++;
					} while (j < strlen(buff));
				}
			}
		}
		pcmd_token = pcmd_token->next;
	}

	return opt_part_found;
}

static int setCliCmdsResponseByTokens(clisrv_cmds_struct *pcmds, clisrv_pconn_struct *pconn, char *buff, int size, int mode)
{
	int i;
	int opt_part_found = 0;
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
		printf("Comparing-cmds: mode=%d, strval=%s, token=%s\n", mode, strval, token);
		if (strlen(strval) >= strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				printf("cmds - partially compared: strval=%s, token=%s\n", strval, token);
				cmd_part_found++;
				printf("cmds - buff-1: '%s'\n", buff);

				if (strlen(strval) == strlen(token)) {
					printf("buff-2: '%s'\n", buff);
					cmd_found = 1;
					break;
				}

				if (mode == CLISRV_AUTO_COMPLETE) {
					if (cmd_part_found == 1)
						clisrv_strncat(buff, &strval[strlen(token)], size);
					else {
						int j = 0;
						do {
							if (buff[j] != strval[strlen(token) + j]) {
								buff[j] = '\0';
								break;
							}
							j++;
						} while (j < strlen(buff));
					}
				}
				if (mode == CLISRV_AUTO_SUGGEST) {
					clisrv_strncat(buff, "\n", size);
					clisrv_strncat(buff, strval, size);

					printf("cmds - buff-4: '%s'\n", buff);
					clisrv_strncat(buff, " ", size);
					printf("cmds - buff-5: '%s'\n", buff);
				}
			}
		}
		pcmd = pcmd->next;
	}
	if (cmd_found != 0) {
		printf("fully compared: strval=%s, token(nr_tokens=%d)=%s\n", strval, pconn->nr_tokens, token);
		if (pconn->nr_tokens > 0) {
			i = 1;
			token += (strlen(token) + 1);
			while (i < pconn->nr_tokens) {
				if (mode == CLISRV_AUTO_COMPLETE) {
					opt_part_found = setCliCmdAutoCompleteByToken(pcmd->tokens, pconn, token, buff, size);
					printf("2 - opt_part_found=%d\n", opt_part_found);
					if (strncmp(strval, token, size) == 0)
						break;
				}
				i++;
				if (i >= pconn->nr_tokens)
					break;
				token += (strlen(token) + 1);
			}
			if (mode == CLISRV_AUTO_SUGGEST) {
				opt_part_found = setCliCmdAutoSuggestByToken(pcmd->tokens, pconn, token, buff, size);
				printf("3 - opt_part_found=%d\n", opt_part_found);
			}
		}
	}

	/* Adding additional space to auto-complete, if needed! */
	if (mode == CLISRV_AUTO_COMPLETE) {
		printf("checkend - pconn->msg(sz=%ld): '%c' cmd_found=%d, cmd_part_found=%d, opt_part_found=%d\n",
				strlen(pconn->msg), pconn->msg[strlen(pconn->msg) - 2], cmd_found, cmd_part_found, opt_part_found);
		printf("checkend - buff(len=%ld): '%c'\n", strlen(buff), buff[strlen(buff) - 1]);
		if (
			((cmd_part_found == 1) || (opt_part_found == 1)) &&
			(pconn->msg[strlen(pconn->msg) - 2] != ' ') &&
			(pconn->msg[strlen(pconn->msg) - 2] != '=') &&
			(strlen(buff) > 0) &&
			(buff[strlen(buff) - 1] != '=')
		) {
			printf("adding space 1\n");
			clisrv_strncat(buff, " ", size);
		} else if (
			((cmd_part_found == 1) && (opt_part_found == 1)) &&
			(pconn->msg[strlen(pconn->msg) - 2] != ' ') &&
			(pconn->msg[strlen(pconn->msg) - 2] != '=') &&
			(strlen(buff) == 0)
		) {
			printf("adding space 2\n");
			clisrv_strncat(buff, " ", size);
		} else if (
			((cmd_part_found == 1) && (opt_part_found == 0)) &&
			(pconn->msg[strlen(pconn->msg) - 2] != ' ') &&
			(pconn->nr_tokens == 1)
		) {
			printf("adding space 3\n");
			clisrv_strncat(buff, " ", size);
		}
	}

	cmd_part_found = opt_part_found;

	return cmd_part_found;
}

static int autoCmdLine(clisrv_pconn_struct *pconn, int mode)
{
	int rv = 0;
	char buff[CLISRV_MAX_MSGSZ] = "";
	evm_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (mode == CLISRV_AUTO_SUGGEST)
		clisrv_strncat(buff, "<pre>", CLISRV_MAX_MSGSZ);

	if ((rv = setCliCmdsResponseByTokens(clisrv_pcmds, pconn, buff, CLISRV_MAX_MSGSZ, mode)) < 0) {
		evm_log_error("setCliCmdResponseByTokens() failed\n");
		return -1;
	}

	switch (mode) {
	case CLISRV_AUTO_COMPLETE:
		printf("Auto-Complete(buff_len=%ld):'%s'\n", strlen(buff), buff);
		printf("Auto-Complete(pconn->msgsz=%d):'%s'\n", pconn->msgsz, pconn->msg);
		clisrv_strncat(buff, "\t", CLISRV_MAX_MSGSZ);
		printf("Auto-Complete-send(len=1):'%s'\n", buff);
		if ((rv = send(pconn->fd, buff, (strlen(buff) + 1), 0)) < 0) {
			evm_log_system_error("send()\n");
		}
		break;
	case CLISRV_AUTO_SUGGEST:
		{
			clisrv_strncat(buff, "</pre>", CLISRV_MAX_MSGSZ);
			clisrv_strncat(buff, pconn->msg, CLISRV_MAX_MSGSZ);
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

static int execCliCmdsTokens(clisrv_cmds_struct *pcmds, clisrv_pconn_struct *pconn, char *buff, int size)
{
	int i;
	int cmd_found = 0;
	char *token;
	char *strval;
	clisrv_cmd_struct *pcmd;
	clisrv_token_struct *curr_tokens;
	evm_log_info("(entry)\n");

	if (pcmds == NULL) {
		evm_log_error("Invalid argument pcmds=%p\n", pcmds);
		return -1;
	}

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if (pconn->nr_tokens == 0) {
		evm_log_debug("Empty command\n");
		return 0;
	}

	token = pconn->tokens;
	pcmd = pcmds->first;
	/* First check command */
	for (i = 0; i < pcmds->nr_cmds; i++) {
		strval = pcmd->tokens->strval;
		printf("%s\n", strval);
		printf("Comparing-cmds: strval='%s', token='%s'\n", strval, token);
		if (strlen(strval) == strlen(token)) {
			if (strncmp(strval, token, strlen(token)) == 0) {
				printf("command found: cmd='%s'\n", token);
				cmd_found = 1;
				break;
			}
		}
		pcmd = pcmd->next;
	}
	if (cmd_found == 0) {
		return -2;
	}

	if ((curr_tokens = checkSyntaxAndSetValues(pcmd, pconn)) == NULL) {
		if (pconn->nr_tokens == 0)
			clisrv_strncat(buff, "Missing command arguments!\n", CLISRV_MAX_MSGSZ);
		else
			clisrv_strncat(buff, "Unknown command arguments!\n", CLISRV_MAX_MSGSZ);
		return -3;
	}

	return pcmd->cmd_handle(curr_tokens, buff, size);
}

static int execCmdLine(clisrv_pconn_struct *pconn)
{
	int rv = 0;
	int close_conn = 0;
	char buff[CLISRV_MAX_MSGSZ] = "";
	char response[CLISRV_MAX_MSGSZ] = "";
	evm_log_info("(entry) pconn=%p\n", pconn);

	if (pconn == NULL) {
		evm_log_error("Invalid argument pconn=%p\n", pconn);
		return -1;
	}

	if ((rv = execCliCmdsTokens(clisrv_pcmds, pconn, buff, CLISRV_MAX_MSGSZ)) < 0) {
		evm_log_error("execCliCmdsTokens() failed (rv=%d)\n", rv);
		switch (rv) {
		case (-1):
			clisrv_strncat(buff, "error: invalid execution call (check code)", CLISRV_MAX_MSGSZ);
			break;
		case (-2):
			clisrv_strncat(buff, "error: unknown command", CLISRV_MAX_MSGSZ);
			break;
		case (-3):
			clisrv_strncat(buff, "error: invalid command syntax", CLISRV_MAX_MSGSZ);
			break;
		}
	} else {
		switch (rv) {
		case (127):
			clisrv_strncat(buff, "Bye...", CLISRV_MAX_MSGSZ);
			close_conn = 1;
			break;
		}
	}

	clisrv_strncat(response, "<pre>", CLISRV_MAX_MSGSZ);
	clisrv_strncat(response, buff, CLISRV_MAX_MSGSZ);
	clisrv_strncat(response, "</pre>", CLISRV_MAX_MSGSZ);
	if (close_conn != 0) {
		clisrv_strncat(response, "<quit>", CLISRV_MAX_MSGSZ);
	}
	printf("sending msg: '%s'\n", response);
	/* Echo the data back to the client */
	if ((rv = send(pconn->fd, response, (strlen(response) + 1), 0)) < 0) {
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
			pconn->msg[pconn->msgsz - 1] = '\0';
			pconn->msgsz--;
			/* Execute the cmdline */
			if ((rv = execCmdLine(pconn)) < 0) {
				evm_log_error("Failed to execute the cmdline!\n");
			}
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

	if ((tmp = (char *)reallocarray(pconn->msg, len, sizeof(char))) == NULL) {
		evm_log_system_error("realocarray() - msg\n");
		abort();
	}
	pconn->msg = tmp;
	memcpy(tmp, buff, len);
	pconn->msgsz = len - 1;

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
	char buffer[CLISRV_MAX_CMDSZ];
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
