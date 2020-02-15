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

#include "u2up-netsim-cli.h"

/*
 * The MAIN part.
 */
static void usage_help(char *argv[])
{
	printf("Usage:\n");
	printf("\t%s [options]\n", argv[0]);
	printf("options:\n");
	printf("\t-h, --help               Displays this text.\n");
}

static int usage_check(int argc, char *argv[])
{
	int c;

	while (1) {
		int option_index = 0;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{0, 0, 0, 0}
		};

		c = getopt_long(argc, argv, "h", long_options, &option_index);
		if (c == -1)
			break;

		switch (c) {
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

	exit(EXIT_SUCCESS);
}

