/*
 * The u2up-clicli Command Line Interface module (client side)
 *
 * This file is part of the "u2up-cli" software project.
 *
 *  Copyright (C) 2020 Samo Pogacnik <samo_pogacnik@t-2.net>
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
*/

#ifndef U2UP_CLI_FILE_u2up_clicli_h
#define U2UP_CLI_FILE_u2up_clicli_h

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>

#include <u2up-cli/u2up-cli.h>

#define U2UP_LOG_NAME U2CLICLI
#include <u2up-log/u2up-log.h>

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
#define CLISRV_TSF "%a, %d %b %Y %T"
#define CLISRV_LTSM "["
#define CLISRV_RTSM "] "

static int initCmdLineLog(char *fileName, int logTrimLines)
{
	static char buff[CLISRV_BUFFSZ];
	static char line[CLISRV_MAX_CMDSZ];
	static netsimCliLogStruct *log = &netsimCliLog;
	netsimCliLogEntryStruct **tmp, *prev;
	char *token, *nl;
	int tokensz, consumed;
	size_t n;

	if (fileName == NULL) {
		u2up_log_error("History log filename not specified!\n");
		return -1;
	}

	if (log == NULL) {
		u2up_log_error("History log structure pointer not specified!\n");
		return -1;
	}

	log->num_file_entries = 0;
	log->file = fopen(fileName, "a+");
	if (log->file == NULL) {
		u2up_log_system_error("fopen()\n");
		return -1;
	}

	tmp = &(log->first);
	if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
		u2up_log_system_error("calloc() - Log entry struct\n");
		abort();
	}
	(*tmp)->prev = *tmp;
	(*tmp)->entry = NULL;
	line[0] = '\0';
	prev = *tmp;
	tmp = &((*tmp)->next);
	while (U2UP_CLI_TRUE) {
		n = fread(buff, 1, (CLISRV_BUFFSZ - 1), log->file);
		buff[n] = '\0';
		consumed = 0;
		u2up_log_debug("n=%zu, consumed=%d, buff='%s'\n", n, consumed, buff);
		if (n > 0) {
			token = buff;
			nl = strchr(token, '\n');
			while (nl != NULL) {
				*nl = '\0';
				tokensz = strlen(token) + 1;
				clisrv_strncat(line, token, CLISRV_MAX_CMDSZ);
				u2up_log_debug("tokensz=%d, token='%s' line='%s'\n", tokensz, token, line);
				if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
					u2up_log_system_error("calloc() - Log entry struct\n");
					abort();
				}
				(*tmp)->prev = prev;
				if (((*tmp)->entry = (char *)calloc((strlen(line) + 1), sizeof(char))) == NULL) {
					u2up_log_system_error("calloc() - Log entry line\n");
					abort();
				}
				strncpy((*tmp)->entry, line, (strlen(line) + 1));
				u2up_log_debug("(*tmp)->entry='%s'\n", (*tmp)->entry);
				line[0] = '\0';
				prev = *tmp;
				tmp = &((*tmp)->next);
				consumed += tokensz;
				token = &buff[consumed];
				log->num_file_entries++;
				u2up_log_debug("num_file_entries=%d, nl=%p, consumed=%d, token='%s'\n", log->num_file_entries, nl, consumed, token);
				nl = strchr(token, '\n');
			}
			if (nl == NULL) {
				clisrv_strncat(line, &buff[consumed], CLISRV_MAX_CMDSZ);
				u2up_log_debug("nl=%p, consumed=%d, line='%s'\n", nl, consumed, line);
				buff[0] = '\0';
			}
		}
		if (n < (CLISRV_BUFFSZ - 1))
			break;
	}
	if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
		u2up_log_system_error("calloc() - Log entry struct\n");
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
		u2up_log_debug("Removing first %d entries (num_file_entries=%d)\n", (log->num_file_entries - logTrimLines), logTrimLines);
		log->num_file_entries = logTrimLines;
		fclose(log->file);
		log->file = fopen(fileName, "w");
		if (log->file == NULL) {
			u2up_log_system_error("fopen()\n");
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
			u2up_log_system_error("fopen()\n");
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

	u2up_log_debug("cmdlen=%d\n", cmdlen);
	prev = log->last->prev;
	if (prev->entry != NULL) {
		if ((prevEntry = strstr(prev->entry, CLISRV_RTSM)) != NULL)
			prevEntry += 2;
		else
			prevEntry = prev->entry;
		u2up_log_debug("prevLen=%zu, prevEntry=%s\n", strlen(prevEntry), prevEntry);
		if ((strlen(cmdline) == (strlen(prevEntry) + 1)) && (strncmp(cmdline, prevEntry, cmdlen) == 0))
			return 0;
	}

	/* Prepare time-stamp string */
	t = time(NULL);
	ptm = localtime(&t);
	if (ptm == NULL) {
		u2up_log_system_error("localtime() - Log entry new time-stamp\n");
		abort();
	}
	if (strftime(tsStr, sizeof(tsStr), CLISRV_LTSM CLISRV_TSF CLISRV_RTSM, ptm) == 0) {
		u2up_log_error("strftime() returned 0\n");
		abort();
	}
	tslen = strlen(tsStr);
	u2up_log_debug("tslen=%d\n", tslen);

	tmp = &(prev->next);
	if ((*tmp = (netsimCliLogEntryStruct *)calloc(1, sizeof(netsimCliLogEntryStruct))) == NULL) {
		u2up_log_system_error("calloc() - Log entry struct\n");
		abort();
	}
	(*tmp)->prev = prev;
	(*tmp)->next = log->last;
	log->last->prev = *tmp;
	if (((*tmp)->entry = (char *)calloc((tslen + cmdlen + 1), sizeof(char))) == NULL) {
		u2up_log_system_error("calloc() - Log entry new time-stamp and cmdline\n");
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
		u2up_log_return_system_err("tcsetattr()\n");
	old.c_lflag &= ~ICANON;
	old.c_lflag &= ~ECHO;
	old.c_cc[VMIN] = 1;
	old.c_cc[VTIME] = 0;
	if (tcsetattr(0, TCSANOW, &old) < 0)
		u2up_log_return_system_err("tcsetattr() ICANON\n");
	if (read(0, &buf, 1) < 0)
		u2up_log_return_system_err("read()\n");
	old.c_lflag |= ICANON;
	old.c_lflag |= ECHO;
	if (tcsetattr(0, TCSADRAIN, &old) < 0)
		u2up_log_return_system_err("tcsetattr() ~ICANON\n");
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
	u2up_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 2) {
		u2up_log_debug("Called with wrong index (i=%d)\n", i);
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
			u2up_log_debug("Key DEL pressed\n");
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
			u2up_log_debug("Unknown 4-char ESC sequence received!\n");
			REMOVE_FROM_LINE(line, i, 3);
		}
	}
	return i;
}

static netsimCliLogEntryStruct *cliLogEntryCurrent = NULL;

static int evaluate3char_sequence(char *const line, int i, char *const rline, int *const rip)
{
	char *cmdEntry;
	u2up_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 2) {
		u2up_log_debug("Called with wrong index (i=%d)\n", i);
		return i;
	}

	/* Check if 3-char ESC sequence */
	if ((line[i - 2] == 27 /*ESC*/) && (line[i - 1] == 91 /*'['*/)) {
		/* evaluate 'arrow keys' */
		if (line[i] == 65 /*'A'*/) {
			u2up_log_debug("Key UP pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			line[i] = '\0';
			if (cliLogEntryCurrent == NULL) {
				cliLogEntryCurrent = netsimCliLog.last;
				u2up_log_debug("Initialized cliLogEntryCurrent to last (dummy)!'\n");
			}
			if (cliLogEntryCurrent != cliLogEntryCurrent->prev) {
				if (i > 0) {
					clisrv_strncat(line, &rline[*rip], CLISRV_MAX_CMDSZ);
					u2up_log_debug("old-line='%s'\n", line);
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
					if ((cmdEntry = strstr(cliLogEntryCurrent->entry, CLISRV_RTSM)) != NULL)
						cmdEntry += 2;
					else
						cmdEntry = cliLogEntryCurrent->entry;
					clisrv_strncat(line, cmdEntry, CLISRV_MAX_CMDSZ);
					u2up_log_debug("new-line='%s'\n", line);
					i = strlen(line);
					line[i] = '\0';
					printf("%s", line);
					fflush(stdout);
				}
			}
		} else
		if (line[i] == 66 /*'B'*/) {
			u2up_log_debug("Key DOWN pressed\n");
			REMOVE_FROM_LINE(line, i, 2);
			line[i] = '\0';
			if (cliLogEntryCurrent == NULL) {
				cliLogEntryCurrent = netsimCliLog.last;
				u2up_log_debug("Initialized cliLogEntryCurrent to last (dummy)!'\n");
			}
			if (cliLogEntryCurrent == cliLogEntryCurrent->prev)
				cliLogEntryCurrent = cliLogEntryCurrent->next;
			if (cliLogEntryCurrent != cliLogEntryCurrent->next) {
				if (i > 0) {
					clisrv_strncat(line, &rline[*rip], CLISRV_MAX_CMDSZ);
					u2up_log_debug("old-line='%s'\n", line);
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
					if ((cmdEntry = strstr(cliLogEntryCurrent->entry, CLISRV_RTSM)) != NULL)
						cmdEntry += 2;
					else
						cmdEntry = cliLogEntryCurrent->entry;
					clisrv_strncat(line, cmdEntry, CLISRV_MAX_CMDSZ);
					u2up_log_debug("new-line='%s'\n", line);
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
			u2up_log_debug("Key RIGHT pressed\n");
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
			u2up_log_debug("Key LEFT pressed\n");
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
			u2up_log_debug("Key END pressed\n");
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
			u2up_log_debug("Key HOME pressed\n");
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
			u2up_log_debug("Potential 4-char ESC sequence\n");
			i++;
		} else {
			u2up_log_debug("Unknown 3 chars ESC sequence received!\n");
			REMOVE_FROM_LINE(line, i, 2);
		}
	}
	return i;
}

static int evaluate2char_sequence(char *const line, int i, char *const rline, int *const rip)
{
	u2up_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 1) {
		u2up_log_debug("Called with wrong index (i=%d)\n", i);
		return i;
	}

#if 0
	if ((i >= 2) && (line[i - 2] == 27 /*ESC*/)) {
		u2up_log_debug("Potentially 4-char ESC sequence\n");
		i++;
		return i;
	}

	if ((i >= 1) && (line[i - 1] == 27 /*ESC*/)) {
		u2up_log_debug("Potentially 3-char ESC sequence\n");
		i++;
		return i;
	}
#endif

	/* Check if 2-char ESC sequence */
	if (line[i - 1] == 27 /*ESC*/) {
		if (line[i] == 91 /*'['*/) {
			u2up_log_debug("Proper ESC sequence start detected: 'ESC-['\n");
			i++;
		} else {
			/* evaluate '2-char' sequence */
			u2up_log_debug("Unexpected 2-char sequence: 'ESC'-%d\n", line[i]);
			REMOVE_FROM_LINE(line, i, 1);
		}
	}
	return i;
}

static int evaluate1char_sequence(char *const line, int i, char *const rline, int *const rip)
{
	int j;
	u2up_log_info("(entry) i=%d\n", i);

	if (line[i] == '\0')
		return i;

	if (i < 0) {
		u2up_log_debug("Error - abort: Called with negative line position index (i=%d)\n", i);
		return i;
	}

	if (line[i] != '\t') {
		/* Extra TAB-[TAB] handling */
		if ((i > 0) && (line[i - 1] == '\t')) {
			line[i - 1] = line[i];
			line[i] = '\0';
			i--;
			u2up_log_debug("Removed previous TAB input (i=%d)\n", i);
		}
	}

	if (line[i - 0] == 27 /*ESC*/) {
		/* Extra ESC-... handling */
		u2up_log_debug("Potential ESC sequence start\n");
		i++;
		return i;
	}

	if (isprint(line[i])) {
		/* Printable single character input */
		u2up_log_debug("Printable character input\n");
		u2up_log_debug("Key '%c' pressed\n", line[i]);
		printf("%c%s", line[i], &rline[*rip]);
		for (j = 0; j < strlen(&rline[*rip]); j++)
			printf("\b");
		fflush(stdout);
		i++;
	} else {
		/* Non-printable single character input */
		u2up_log_debug("Non-printable character input\n");
		if (line[i] == '\t') {
			u2up_log_debug("Key TAB pressed\n");
			i++;
		} else
		if ((line[i] == 8) || (line[i] == 127)) {
			u2up_log_debug("Key BACKSPACE pressed\n");
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
			u2up_log_debug("Key ENTER pressed (i=%d, *rip=%d)\n", i, *rip);
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
				u2up_log_debug("Successfully saved new cmdline!\n");
			}
			cliLogEntryCurrent = netsimCliLog.last;
		} else {
			u2up_log_debug("Unexpected Key (%d) pressed\n", line[i]);
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
		u2up_log_debug("line[%d]=%d\n", i, line[i]);
		if ((i + 1)  < size)
			line[i + 1] = '\0';
		else {
			u2up_log_debug("Error - abort: Line too long (i=%d)\n", i);
			abort();
		}

		/*
		 * Evaluate input sequences and chars
		 */
		/* Start with longest ESC sequences (4-chars) */
		if (i >= 3) {
			u2up_log_debug("(i >= 3) i=%d, ri=%d\n", i, ri);
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
			u2up_log_debug("(i >= 2) i=%d, ri=%d\n", i, ri);
			i = evaluate3char_sequence(line, i, rline, &ri);
			if (i >= 1) {
				i = evaluate2char_sequence(line, i, rline, &ri);
				if (i >= 0) {
					i = evaluate1char_sequence(line, i, rline, &ri);
				}
			}
		} else
		if (i >= 1) {
			u2up_log_debug("(i >= 1) i=%d, ri=%d\n", i, ri);
			i = evaluate2char_sequence(line, i, rline, &ri);
			if (i >= 0) {
				i = evaluate1char_sequence(line, i, rline, &ri);
			}
		} else
		if (i >= 0) {
			u2up_log_debug("(i >= 0) i=%d, ri=%d\n", i, ri);
			i = evaluate1char_sequence(line, i, rline, &ri);
		} else {
			u2up_log_debug("Error - abort: negative line position index i=%d\n", i);
			abort();
		}

		if ((line[i - 1] == '\t') || (line[i - 1] == '\n'))
			break;

	} while (i < size);

	return 0;
}

int processCliCmds(char *cli_prompt, int sockfd, int (*cmd_send_receive)(int sock, char *snd_str, char *rcv_buf, size_t rcv_buf_size))
{
	char snd_buf[CLISRV_MAX_CMDSZ] = "";
	char rcv_buf[CLISRV_MAX_MSGSZ] = "";
	char *pre_begin, *pre_end, *remain_str;
	u2up_log_info("(entry) sockfd=%d\n", sockfd);

	printf("%s", cli_prompt);
	fflush(stdout);
	while (U2UP_CLI_TRUE) {
		/* Gether-together a cmd-line */
		if (getherCmdLine(snd_buf, CLISRV_MAX_CMDSZ) < 0) {
			u2up_log_error("getherCmdLine()\n");
			return -1;
		}

		/* Call the socket Send-Receive callback! */
		if (cmd_send_receive(sockfd, snd_buf, rcv_buf, sizeof(rcv_buf)) < 0) {
			u2up_log_error("cmd_send_receive()\n");
			return -1;
		}

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
				u2up_log_debug("quit command confirmation received - exit!\n");
				fflush(stdout);
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
			printf("%s%s", cli_prompt, remain_str);
		}
		fflush(stdout);
	}

	return 0;
}

#undef U2UP_LOG_NAME
#endif /*U2UP_CLI_FILE_u2up_clicli_h*/

