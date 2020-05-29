/*
 * The u2up-cli Command Line Interface module (common)
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

#ifndef U2UP_CLI_FILE_u2up_cli_h
#define U2UP_CLI_FILE_u2up_cli_h

#define U2UP_CLI_TRUE (0 == 0)
#define U2UP_CLI_FALSE (0 != 0)

#define CLISRV_SOCK_PATH "/tmp/u2up-netsim-cli"
#define LISTEN_BACKLOG 50
#define CLISRV_MAX_CMDSZ 512
#define CLISRV_MAX_MSGSZ 1024

static inline char * clisrv_strncat(char *dst, const char *src, int dstsz)
{
	int room = dstsz - strlen(dst) - 1;
	if (room > 0)
		return strncat(dst, src, room);
	return dst;
}

static inline void * clisrv_realloc(void *ptr, size_t nmemb, size_t size)
{
	size_t tmp = nmemb * size;

	if ((nmemb > 0) && ((tmp / nmemb) != size)) {
		/* multiplication overflow: return NULL! */
		return NULL;
	}

	return realloc(ptr, tmp);
}

#endif /*U2UP_CLI_FILE_u2up_cli_h*/
