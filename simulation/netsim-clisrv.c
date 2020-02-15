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

#include <evm/libevm.h>
#include "u2up-netsim.h"
#include "netsim-common.h"
#include "netsim-clisrv.h"


