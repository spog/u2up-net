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

#include <ctype.h>
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

#include <unistd.h>
#include <termios.h>

typedef struct netsim_cli_log netsimCliLogStruct;
typedef struct netsim_cli_log_entry netsimCliLogEntryStruct;

struct netsim_cli_log {
	FILE *file;
	int num_file_entries;
	netsimCliLogEntryStruct *first;
	netsimCliLogEntryStruct *last;
}; /*netsimCliLogStruct*/

struct netsim_cli_log_entry {
	netsimCliLogEntryStruct *prev;
	netsimCliLogEntryStruct *next;
	char *entry;
}; /*netsimCliLogEntryStruct*/

static netsimCliLogStruct netsimCliLog;
static char incomplete_line[CLISRV_MAX_CMDSZ];

#define CLISRV_BUFFSZ 512

static int initCmdLineLog(char *fileName, netsimCliLogStruct *log, int logTrimLines)
{
	static char buff[CLISRV_BUFFSZ];
	static char line[CLISRV_MAX_CMDSZ];
	netsimCliLogEntryStruct **tmp, *prev;
	char *token, *nl;
	int tokensz, consumed;
	size_t n;

	if (fileName == NULL) {
		evm_log_error("History log filename not specified!\n");
		return -1;
	}

	if (log == NULL) {
		evm_log_error("History log structure pointer not specified!\n");
		return -1;
	}

	log->num_file_entries = 0;
	log->file = fopen(fileName, "a+");
	if (log->file == NULL) {
		evm_log_system_error("fopen()\n");
		return -1;
	}

	tmp = &(log->first);
	if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
		evm_log_system_error("calloc() - Log entry struct\n");
		abort();
	}
	(*tmp)->prev = *tmp;
	(*tmp)->entry = NULL;
	line[0] = '\0';
	prev = *tmp;
	tmp = &((*tmp)->next);
	while (U2UP_NET_TRUE) {
		n = fread(buff, 1, (CLISRV_BUFFSZ - 1), log->file);
		buff[n] = '\0';
		consumed = 0;
		evm_log_debug("n=%d, consumed=%d, buff='%s'\n", n, consumed, buff);
		if (n > 0) {
			token = buff;
			nl = strchr(token, '\n');
			while (nl != NULL) {
				*nl = '\0';
				tokensz = strlen(token) + 1;
				clisrv_strncat(line, token, CLISRV_MAX_CMDSZ);
				evm_log_debug("tokensz=%d, token='%s' line='%s'\n", tokensz, token, line);
				if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
					evm_log_system_error("calloc() - Log entry struct\n");
					abort();
				}
				(*tmp)->prev = prev;
				if (((*tmp)->entry = (char *)calloc((strlen(line) + 1), sizeof(char))) == NULL) {
					evm_log_system_error("calloc() - Log entry line\n");
					abort();
				}
				strncpy((*tmp)->entry, line, (strlen(line) + 1));
				evm_log_debug("(*tmp)->entry='%s'\n", (*tmp)->entry);
				line[0] = '\0';
				prev = *tmp;
				tmp = &((*tmp)->next);
				consumed += tokensz;
				token = &buff[consumed];
				log->num_file_entries++;
				evm_log_debug("num_file_entries=%d, nl=%p, consumed=%d, token='%s'\n", log->num_file_entries, nl, consumed, token);
				nl = strchr(token, '\n');
			}
			if (nl == NULL) {
				clisrv_strncat(line, &buff[consumed], CLISRV_MAX_CMDSZ);
				evm_log_debug("nl=%p, consumed=%d, line='%s'\n", nl, consumed, line);
				buff[0] = '\0';
			}
		}
		if (n < (CLISRV_BUFFSZ - 1))
			break;
	}
	if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
		evm_log_system_error("calloc() - Log entry struct\n");
		abort();
	}
	(*tmp)->prev = prev;
	(*tmp)->next = *tmp;
	(*tmp)->entry = NULL;
	log->last = *tmp;

	if ((logTrimLines != 0) && (log->num_file_entries > logTrimLines)) {
		int i;
		netsimCliLogEntryStruct *next;

		for (i = 0; i < (log->num_file_entries - logTrimLines); i++) {
			next = log->first->next->next;
			free(log->first->next->entry);
			free(log->first->next);
			log->first->next = next;
			next->prev = log->first;
		}
		evm_log_debug("Removing first %d entries (num_file_entries=%d)\n", (log->num_file_entries - logTrimLines), logTrimLines);
		log->num_file_entries = logTrimLines;
		fclose(log->file);
		log->file = fopen(fileName, "w");
		if (log->file == NULL) {
			evm_log_system_error("fopen()\n");
			return -1;
		}
		next = log->first->next;
		while (next != next->next) {
			int len = strlen(next->entry);

			n = 0;
			while ((n += fwrite(&(next->entry[n]), sizeof(char), (len - n), log->file)) < len);
			fwrite("\n", sizeof(char), 1, log->file);
			next = next->next;
		}
		fflush(log->file);
		fclose(log->file);
		log->file = fopen(fileName, "a+");
		if (log->file == NULL) {
			evm_log_system_error("fopen()\n");
			return -1;
		}
	}

	return 0;
}

static int saveCmdLineLog(char *cmdline, netsimCliLogStruct *log)
{
	netsimCliLogEntryStruct **tmp, *prev;
	size_t n = 0;
	int cmdlen;
	int tslen;
	char *prevEntry;
	char tsStr[200];
	time_t t;
	struct tm *ptm;

	if (log == NULL)
		abort();

	if (log->file == NULL)
		abort();

	if (cmdline == NULL)
		abort();

	if (cmdline[0] == '\n')
		return 0;

	if ((cmdlen = strlen(cmdline) - 1) <= 0)
		return 0;

	evm_log_debug("cmdlen=%d\n", cmdlen);
	prev = log->last->prev;
	if (prev->entry != NULL) {
		if ((prevEntry = strstr(prev->entry, "> ")) != NULL)
			prevEntry += 2;
		else
			prevEntry = prev->entry;
		evm_log_debug("prevLen=%d, prevEntry=%s\n", strlen(prevEntry), prevEntry);
		if ((strlen(cmdline) == (strlen(prevEntry) + 1)) && (strncmp(cmdline, prevEntry, cmdlen) == 0))
			return 0;
	}

	/* Prepare time-stamp string */
	t = time(NULL);
	ptm = localtime(&t);
	if (ptm == NULL) {
		evm_log_system_error("localtime() - Log entry new time-stamp\n");
		abort();
	}
	if (strftime(tsStr, sizeof(tsStr), "<%a, %d %b %Y %T> ", ptm) == 0) {
		evm_log_error("strftime() returned 0\n");
		abort();
	}
	tslen = strlen(tsStr);
	evm_log_debug("tslen=%d\n", tslen);

	tmp = &(prev->next);
	if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
		evm_log_system_error("calloc() - Log entry struct\n");
		abort();
	}
	(*tmp)->prev = prev;
	(*tmp)->next = log->last;
	log->last->prev = *tmp;
	if (((*tmp)->entry = (char *)calloc((tslen + cmdlen + 1), sizeof(char))) == NULL) {
		evm_log_system_error("calloc() - Log entry new time-stamp and cmdline\n");
		abort();
	}
	strncpy((*tmp)->entry, tsStr, tslen);
	strncat((*tmp)->entry, cmdline, cmdlen);

	while ((n += fwrite(&((*tmp)->entry[n]), sizeof(char), (tslen + cmdlen - n), log->file)) < (tslen + cmdlen));
	fwrite("\n", sizeof(char), 1, log->file);
	fflush(log->file);

	return 0;
}

static char getchr()
{
	char buf = 0;
	struct termios old = {0};

	if (tcgetattr(0, &old) < 0)
		evm_log_return_system_err("tcsetattr()\n");
	old.c_lflag &= ~ICANON;
	old.c_lflag &= ~ECHO;
	old.c_cc[VMIN] = 1;
	old.c_cc[VTIME] = 0;
	if (tcsetattr(0, TCSANOW, &old) < 0)
		evm_log_return_system_err("tcsetattr() ICANON\n");
	if (read(0, &buf, 1) < 0)
		evm_log_return_system_err("read()\n");
	old.c_lflag |= ICANON;
	old.c_lflag |= ECHO;
	if (tcsetattr(0, TCSADRAIN, &old) < 0)
		evm_log_return_system_err("tcsetattr() ~ICANON\n");
	return buf;
}

#define REMOVE_FROM_LINE(buf, idx, cnt) { \
	idx -= cnt; \
	buf[idx] = '\0'; \
}

/*
 * !!!IMPORTANT!!!
 * Evaluate functions do nothing, if indexed char equals '\0'!
 */
static int evaluate4char_sequence(char *const line, int i, char *const rline, int *const rip)
{
	int j;
	evm_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 2) {
		evm_log_debug("Called with wrong index (i=%d)\n", i);
		return i;
	}

	/* Check if 4-char ESC sequence */
	if (
		(line[i - 3] == 27 /*ESC*/) &&
		(line[i - 2] == 91 /*'['*/) &&
		(line[i - 1] == 51 /*'3'*/)
	) {
		if (line[i] == 126 /*'~'*/) {
			/* evaluate 'DEL' key */
			evm_log_debug("Key DEL pressed\n");
			REMOVE_FROM_LINE(line, i, 3);
			if (rline[*rip] != '\0') {
				(*rip)++;
				printf("%s", &rline[*rip]);
				printf(" \b");
				for (j = 0; j < strlen(&rline[*rip]); j++)
					printf("\b");
				fflush(stdout);
			}
		} else {
			evm_log_debug("Unknown 4-char ESC sequence received!\n");
			REMOVE_FROM_LINE(line, i, 3);
		}
	}
	return i;
}

static netsimCliLogEntryStruct *cliLogEntryCurrent = NULL;

static int evaluate3char_sequence(char *const line, int i, char *const rline, int *const rip)
{
	char *cmdEntry;
	evm_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 2) {
		evm_log_debug("Called with wrong index (i=%d)\n", i);
		return i;
	}

	/* Check if 3-char ESC sequence */
	if ((line[i - 2] == 27 /*ESC*/) && (line[i - 1] == 91 /*'['*/)) {
		/* evaluate 'arrow keys' */
		if (line[i] == 65 /*'A'*/) {
			evm_log_debug("Key UP pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			line[i] = '\0';
			if (cliLogEntryCurrent == NULL) {
				cliLogEntryCurrent = netsimCliLog.last;
				evm_log_debug("Initialized cliLogEntryCurrent to last (dummy)!'\n");
			}
			if (cliLogEntryCurrent != cliLogEntryCurrent->prev) {
				if (i > 0) {
					clisrv_strncat(line, &rline[*rip], CLISRV_MAX_CMDSZ);
					evm_log_debug("old-line='%s'\n", line);
					printf("%s", &rline[*rip]);
					fflush(stdout);
					*rip = CLISRV_MAX_CMDSZ - 1;
					i = strlen(line);
				}
				if (cliLogEntryCurrent == netsimCliLog.last) {
					incomplete_line[0] = '\0';
					clisrv_strncat(incomplete_line, line, CLISRV_MAX_CMDSZ);
				}
				cliLogEntryCurrent = cliLogEntryCurrent->prev;
				if (cliLogEntryCurrent != cliLogEntryCurrent->prev) {
					while (i > 0) {
						printf("\b \b");
						i--;
					}
					line[0] = '\0';
					if ((cmdEntry = strstr(cliLogEntryCurrent->entry, "> ")) != NULL)
						cmdEntry += 2;
					else
						cmdEntry = cliLogEntryCurrent->entry;
					clisrv_strncat(line, cmdEntry, CLISRV_MAX_CMDSZ);
					evm_log_debug("new-line='%s'\n", line);
					i = strlen(line);
					line[i] = '\0';
					printf("%s", line);
					fflush(stdout);
				}
			}
		} else
		if (line[i] == 66 /*'B'*/) {
			evm_log_debug("Key DOWN pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			line[i] = '\0';
			if (cliLogEntryCurrent == NULL) {
				cliLogEntryCurrent = netsimCliLog.last;
				evm_log_debug("Initialized cliLogEntryCurrent to last (dummy)!'\n");
			}
			if (cliLogEntryCurrent == cliLogEntryCurrent->prev)
				cliLogEntryCurrent = cliLogEntryCurrent->next;
			if (cliLogEntryCurrent != cliLogEntryCurrent->next) {
				if (i > 0) {
					clisrv_strncat(line, &rline[*rip], CLISRV_MAX_CMDSZ);
					evm_log_debug("old-line='%s'\n", line);
					printf("%s", &rline[*rip]);
					fflush(stdout);
					*rip = CLISRV_MAX_CMDSZ - 1;
					i = strlen(line);
				}
				cliLogEntryCurrent = cliLogEntryCurrent->next;
				if (cliLogEntryCurrent != cliLogEntryCurrent->next) {
					while (i > 0) {
						printf("\b \b");
						i--;
					}
					line[0] = '\0';
					if ((cmdEntry = strstr(cliLogEntryCurrent->entry, "> ")) != NULL)
						cmdEntry += 2;
					else
						cmdEntry = cliLogEntryCurrent->entry;
					clisrv_strncat(line, cmdEntry, CLISRV_MAX_CMDSZ);
					evm_log_debug("new-line='%s'\n", line);
					i = strlen(line);
					line[i] = '\0';
					printf("%s", line);
					fflush(stdout);
				} else {
					while (i > 0) {
						printf("\b \b");
						i--;
					}
					line[0] = '\0';
					clisrv_strncat(line, incomplete_line, CLISRV_MAX_CMDSZ);
					incomplete_line[0] = '\0';
					i = strlen(line)/* - 1*/;
					line[i] = '\0';
					printf("%s", line);
					fflush(stdout);
				}
			}
		} else
		if (line[i] == 67 /*'C'*/) {
			evm_log_debug("Key RIGHT pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			if ((i < (CLISRV_MAX_CMDSZ - 1)) && (rline[*rip] != '\0')) {
				line[i] = rline[*rip];
				printf("%c", line[i]);
				fflush(stdout);
				i++;
				(*rip)++;
				line[i] = '\0';
			}
		} else
		if (line[i] == 68 /*'D'*/) {
			evm_log_debug("Key LEFT pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			if ((i > 0) && (*rip > 0)) {
				i--;
				(*rip)--;
				rline[*rip] = line[i];
				line[i] = '\0';
				printf("\b");
				fflush(stdout);
			}
		} else
		if (line[i] == 70 /*End*/) {
			evm_log_debug("Key END pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			while ((i < (CLISRV_MAX_CMDSZ - 1)) && (rline[*rip] != '\0')) {
				line[i] = rline[*rip];
				printf("%c", line[i]);
				fflush(stdout);
				i++;
				(*rip)++;
				line[i] = '\0';
			}
		} else
		if (line[i] == 72 /*Home*/) {
			evm_log_debug("Key HOME pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			while ((i > 0) && (*rip > 0)) {
				i--;
				(*rip)--;
				rline[*rip] = line[i];
				line[i] = '\0';
				printf("\b");
				fflush(stdout);
			}
		} else
		if (line[i] == 51 /*'3'*/) {
			evm_log_debug("Potential 4-char ESC sequence\n");
			i++;
		} else {
			evm_log_debug("Unknown 3 chars ESC sequence received!\n");
			REMOVE_FROM_LINE(line, i, 2);
		}
	}
	return i;
}

static int evaluate2char_sequence(char *const line, int i, char *const rline, int *const rip)
{
	evm_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 1) {
		evm_log_debug("Called with wrong index (i=%d)\n", i);
		return i;
	}

#if 0
	if ((i >= 2) && (line[i - 2] == 27 /*ESC*/)) {
		evm_log_debug("Potentially 4-char ESC sequence\n");
		i++;
		return i;
	}

	if ((i >= 1) && (line[i - 1] == 27 /*ESC*/)) {
		evm_log_debug("Potentially 3-char ESC sequence\n");
		i++;
		return i;
	}
#endif

	/* Check if 2-char ESC sequence */
	if (line[i - 1] == 27 /*ESC*/) {
		if (line[i] == 91 /*'['*/) {
			evm_log_debug("Proper ESC sequence start detected: 'ESC-['\n");
			i++;
		} else {
			/* evaluate '2-char' sequence */
			evm_log_debug("Unexpected 2-char sequence: 'ESC'-%d\n", line[i]);
			REMOVE_FROM_LINE(line, i, 1);
		}
	}
	return i;
}

static int evaluate1char_sequence(char *const line, int i, char *const rline, int *const rip)
{
	int j;
//	netsimCliLogEntryStruct *lastcmd;
	evm_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 0) {
		evm_log_debug("Error - abort: Called with negative line position index (i=%d)\n", i);
		return i;
	}

	if (line[i] != '\t') {
		/* Extra TAB-[TAB] handling */
		if ((i > 0) && (line[i - 1] == '\t')) {
			line[i - 1] = line[i];
			line[i] = '\0';
			i--;
			evm_log_debug("Removed previous TAB input (i=%d)\n", i);
		}
	}

	if (line[i - 0] == 27 /*ESC*/) {
		/* Extra ESC-... handling */
		evm_log_debug("Potential ESC sequence start\n");
		i++;
		return i;
	}

	if (isprint(line[i])) {
		/* Printable single character input */
		evm_log_debug("Printable character input\n");
		evm_log_debug("Key '%c' pressed\n", line[i]);
		printf("%c%s", line[i], &rline[*rip]);
		for (j = 0; j < strlen(&rline[*rip]); j++)
			printf("\b");
		fflush(stdout);
		i++;
	} else {
		/* Non-printable single character input */
		evm_log_debug("Non-printable character input\n");
		if (line[i] == '\t') {
			evm_log_debug("Key TAB pressed\n");
			i++;
		} else
		if (line[i] == 127) {
			evm_log_debug("Key BACKSPACE pressed\n");
			line[i] = '\0';
			if (i > 0) {
				i--;
				line[i] = '\0';
				printf("\b \b");
				printf("%s", &rline[*rip]);
				printf(" \b");
				for (j = 0; j < strlen(&rline[*rip]); j++)
					printf("\b");
				fflush(stdout);
			}
		} else
		if (line[i] == '\n') {
			evm_log_debug("Key ENTER pressed (i=%d, *rip=%d)\n", i, *rip);
			line[i] = '\0';
			clisrv_strncat(line, &rline[*rip], CLISRV_MAX_CMDSZ);
			*rip = CLISRV_MAX_CMDSZ - 1;
			i = strlen(line);
			if (i < (CLISRV_MAX_CMDSZ - 1)) {
				line[i] = '\n';
				i++;
				line[i] = '\0';
			} else {
				line[i - 1] = '\n';
			}
			printf("\n");
			fflush(stdout);
			if (saveCmdLineLog(line, &netsimCliLog) == 0) {
				evm_log_debug("Successfully saved new cmdline!\n");
			}
			cliLogEntryCurrent = netsimCliLog.last;
		} else {
			evm_log_debug("Unexpected Key (%d) pressed\n", line[i]);
		}
	}

	return i;
}

static int getherCmdLine(char * const cmdline, int size)
{
	static char rline[CLISRV_MAX_CMDSZ];
	static int ri = CLISRV_MAX_CMDSZ - 1;
	int i, j;
	char *line;

	if (cmdline == NULL)
		return -1;

	i = strlen(cmdline);
	line = cmdline;

	rline[CLISRV_MAX_CMDSZ - 1] = '\0';

	printf("%s", &rline[ri]);
	printf(" \b");
	for (j = 0; j < strlen(&rline[ri]); j++)
		printf("\b");
	fflush(stdout);

	do {
		line[i] = getchr();
		evm_log_debug("line[%d]=%d\n", i, line[i]);
		if ((i + 1)  < size)
			line[i + 1] = '\0';
		else {
			evm_log_debug("Error - abort: Line too long (i=%d)\n", i);
			abort();
		}

		/*
		 * Evaluate input sequences and chars
		 */
		/* Start with longest ESC sequences (4-chars) */
		if (i >= 3) {
			evm_log_debug("(i >= 3) i=%d, ri=%d\n", i, ri);
			i = evaluate4char_sequence(line, i, rline, &ri);
			if (i >= 1) {
				i = evaluate3char_sequence(line, i, rline, &ri);
				if (i >= 0) {
					i = evaluate2char_sequence(line, i, rline, &ri);
					if (i >= 0) {
						i = evaluate1char_sequence(line, i, rline, &ri);
					}
				}
			}
		} else
		if (i >= 2) {
			evm_log_debug("(i >= 2) i=%d, ri=%d\n", i, ri);
			i = evaluate3char_sequence(line, i, rline, &ri);
			if (i >= 1) {
				i = evaluate2char_sequence(line, i, rline, &ri);
				if (i >= 0) {
					i = evaluate1char_sequence(line, i, rline, &ri);
				}
			}
		} else
		if (i >= 1) {
			evm_log_debug("(i >= 1) i=%d, ri=%d\n", i, ri);
			i = evaluate2char_sequence(line, i, rline, &ri);
			if (i >= 0) {
				i = evaluate1char_sequence(line, i, rline, &ri);
			}
		} else
		if (i >= 0) {
			evm_log_debug("(i >= 0) i=%d, ri=%d\n", i, ri);
			i = evaluate1char_sequence(line, i, rline, &ri);
		} else {
			evm_log_debug("Error - abort: negative line position index i=%d\n", i);
			abort();
		}

		if ((line[i - 1] == '\t') || (line[i - 1] == '\n'))
			break;

	} while (i < size);

	return 0;
}

/*
 * The MAIN part.
 */
int main(int argc, char *argv[])
{
	int rv = 0;
	int sockfd;
	char snd_buf[CLISRV_MAX_CMDSZ] = "";
	char rcv_buf[CLISRV_MAX_MSGSZ] = "";
	char *pre_begin, *pre_end, *remain_str;
	
	usage_check(argc, argv);

	/* Initialize CLI server listen socket */
	if ((rv == 0) && ((sockfd = clisrvSocket_init(CLISRV_SOCK_PATH)) < 0)) {
		evm_log_error("clisrvSocket_init() failed!\n");
		exit(EXIT_FAILURE);
	}

	/* Initialize History-log file (and trim to the last 100 lines)*/
	if (initCmdLineLog(".u2up_clisrv_cmdlog", &netsimCliLog, 100) < 0) {
		evm_log_error("initCmdLineLog()\n");
		exit(EXIT_FAILURE);
	}

	printf("netsim-cli> ");
	fflush(stdout);
	while (U2UP_NET_TRUE) {
#if 0 /*orig*/
		/* Enter one line message string to be sent */
		fgets(snd_buf, CLISRV_MAX_CMDSZ, stdin);
#else
		/* Gether-together a cmd-line */
		if (getherCmdLine(snd_buf, CLISRV_MAX_CMDSZ) < 0) {
			evm_log_error("getherCmdLine()\n");
			close(sockfd);
			break;
		}
#endif

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
		if (rv <= 0) {
			evm_log_system_error("recv()\n");
			close(sockfd);
			break;
		}
		evm_log_debug("%d bytes received\n", rv);
//not needed:	rcv_buf[rv] = '\0';

		/* Process received data */
		pre_begin = NULL;
		pre_end = NULL;
		remain_str = rcv_buf;
		if (strlen(rcv_buf) >= (strlen("<pre>") + strlen("</pre>"))) {
			if (strncmp(rcv_buf, "<pre>", strlen("<pre>")) == 0) {
				pre_begin = (rcv_buf + 5);
				if ((pre_end = strstr(rcv_buf, "</pre>")) != NULL) {
					remain_str = pre_end + 6;
					*pre_end = '\0';
				}
			}
		}

		/* Clear all potential TABS at the end of the sending buffer */
		while ((strlen(snd_buf) > 0) && (snd_buf[strlen(snd_buf) - 1] == '\t'))
			snd_buf[strlen(snd_buf) - 1] = '\0';

		if ((pre_begin != NULL) && (pre_end != NULL)) {
			snd_buf[0] = '\0';
			printf("%s", pre_begin);
//			printf("%ld", strlen(pre_begin));
			/* Add additional newline, if preformated response not empty */
			if (strlen(pre_begin) > 0) {
				printf("\n");
			} else {
				if (strlen(remain_str) > 0)
					printf("\n");
			}
		}
		if (strlen(remain_str) >= strlen("<quit>")) {
			if (strstr(remain_str, "<quit>") != NULL) {
				evm_log_debug("quit command confirmation received - exit!\n");
				break;
			}
		}
		clisrv_strncat(snd_buf, remain_str, CLISRV_MAX_CMDSZ);

		if (strlen(remain_str) > 0) {
			if (remain_str[strlen(remain_str) - 1] == '\t') {
				remain_str[strlen(remain_str) - 1] = '\0';
			}
		}
		if ((pre_begin == NULL) && (pre_end == NULL)) {
			printf("%s", remain_str);
		} else {
			printf("netsim-cli> %s", remain_str);
		}
		fflush(stdout);
	}

	/* Close the connection socket */
	close(sockfd);

	if (rv == 0) {
		exit(EXIT_SUCCESS);
	} else {
		exit(EXIT_FAILURE);
	}
}

