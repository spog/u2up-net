/*
 * The u2up-log Logging support module
 *
 * This file is part of the "u2up-log" software project.
 *
 *  Copyright 2019 Samo Pogacnik <samo_pogacnik@t-2.net>
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

/*
 * This "u2up-log" module provides various output definitions
 * in a single header file.
 */

#ifndef U2UP_LOG_FILE_PRE_u2up_log_h
#define U2UP_LOG_FILE_PRE_u2up_log_h

#include <errno.h>
#include <stdio.h>
#include <syslog.h>
#include <unistd.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>

typedef struct u2up_log {
	int quiet;
	int normal;
	int verbose;
	int trace;
	int debug;
	int header;
	int syslog;
	char *name;
} u2up_log_struct;

#define _MKU2UPSTR(name) #name
#define MKU2UPSTR(name) _MKU2UPSTR(name)

#define _MKU2UPLOG_VAR_STRUCT(name) u2upLogVarStruct_##name
#define MKU2UPLOG_VAR_STRUCT(name) _MKU2UPLOG_VAR_STRUCT(name)

#define _MKU2UPLOG_VAR_STRING(name) u2upLogVarString_##name
#define MKU2UPLOG_VAR_STRING(name) _MKU2UPLOG_VAR_STRING(name)

#define _MKU2UPLOG_SET_QUIET(name) u2upLogSetQuiet_##name
#define MKU2UPLOG_SET_QUIET(name) _MKU2UPLOG_SET_QUIET(name)
#define _MKU2UPLOG_GET_QUIET(name) u2upLogGetQuiet_##name
#define MKU2UPLOG_GET_QUIET(name) _MKU2UPLOG_GET_QUIET(name)

#define _MKU2UPLOG_SET_NORMAL(name) u2upLogSetNormal_##name
#define MKU2UPLOG_SET_NORMAL(name) _MKU2UPLOG_SET_NORMAL(name)
#define _MKU2UPLOG_GET_NORMAL(name) u2upLogGetNormal_##name
#define MKU2UPLOG_GET_NORMAL(name) _MKU2UPLOG_GET_NORMAL(name)

#define _MKU2UPLOG_SET_VERBOSE(name) u2upLogSetVerbose_##name
#define MKU2UPLOG_SET_VERBOSE(name) _MKU2UPLOG_SET_VERBOSE(name)
#define _MKU2UPLOG_GET_VERBOSE(name) u2upLogGetVerbose_##name
#define MKU2UPLOG_GET_VERBOSE(name) _MKU2UPLOG_GET_VERBOSE(name)

#define _MKU2UPLOG_SET_TRACE(name) u2upLogSetTrace_##name
#define MKU2UPLOG_SET_TRACE(name) _MKU2UPLOG_SET_TRACE(name)
#define _MKU2UPLOG_GET_TRACE(name) u2upLogGetTrace_##name
#define MKU2UPLOG_GET_TRACE(name) _MKU2UPLOG_GET_TRACE(name)

#define _MKU2UPLOG_SET_DEBUG(name) u2upLogSetDebug_##name
#define MKU2UPLOG_SET_DEBUG(name) _MKU2UPLOG_SET_DEBUG(name)
#define _MKU2UPLOG_GET_DEBUG(name) u2upLogGetDebug_##name
#define MKU2UPLOG_GET_DEBUG(name) _MKU2UPLOG_GET_DEBUG(name)

#define _MKU2UPLOG_SET_HEADER(name) u2upLogSetHeader_##name
#define MKU2UPLOG_SET_HEADER(name) _MKU2UPLOG_SET_HEADER(name)
#define _MKU2UPLOG_GET_HEADER(name) u2upLogGetHeader_##name
#define MKU2UPLOG_GET_HEADER(name) _MKU2UPLOG_GET_HEADER(name)

#define _MKU2UPLOG_SET_SYSLOG(name) u2upLogSetSyslog_##name
#define MKU2UPLOG_SET_SYSLOG(name) _MKU2UPLOG_SET_SYSLOG(name)
#define _MKU2UPLOG_GET_SYSLOG(name) u2upLogGetSyslog_##name
#define MKU2UPLOG_GET_SYSLOG(name) _MKU2UPLOG_GET_SYSLOG(name)

#define _MKU2UPLOG_GET_NAME(name) u2upLogGetName_##name
#define MKU2UPLOG_GET_NAME(name) _MKU2UPLOG_GET_NAME(name)

#endif /*U2UP_LOG_FILE_PRE_u2up_log_h*/

static char MKU2UPLOG_VAR_STRING(U2UP_LOG_NAME)[] = MKU2UPSTR(U2UP_LOG_NAME);

static u2up_log_struct MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME) = {
	.quiet = 0,
	.normal = 1,
	.verbose = 0,
	.trace = 0,
	.debug = 0,
	.header = 1,
	.syslog = 0,
	.name = MKU2UPLOG_VAR_STRING(U2UP_LOG_NAME)
};

void MKU2UPLOG_SET_QUIET(U2UP_LOG_NAME)(int val) {
	MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).quiet = val;
}
void MKU2UPLOG_SET_NORMAL(U2UP_LOG_NAME)(int val) {
	MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal = val;
}
void MKU2UPLOG_SET_VERBOSE(U2UP_LOG_NAME)(int val) {
	MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose = val;
}
void MKU2UPLOG_SET_TRACE(U2UP_LOG_NAME)(int val) {
	MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace = val;
}
void MKU2UPLOG_SET_DEBUG(U2UP_LOG_NAME)(int val) {
	MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug = val;
}
void MKU2UPLOG_SET_HEADER(U2UP_LOG_NAME)(int val) {
	MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header = val;
}
void MKU2UPLOG_SET_SYSLOG(U2UP_LOG_NAME)(int val) {
	MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog = val;
}

int MKU2UPLOG_GET_QUIET(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).quiet;
}
int MKU2UPLOG_GET_NORMAL(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal;
}
int MKU2UPLOG_GET_VERBOSE(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose;
}
int MKU2UPLOG_GET_TRACE(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace;
}
int MKU2UPLOG_GET_DEBUG(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug;
}
int MKU2UPLOG_GET_HEADER(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header;
}
int MKU2UPLOG_GET_SYSLOG(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog;
}
char * MKU2UPLOG_GET_NAME(U2UP_LOG_NAME)(void) {
	return MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).name;
}

#ifndef U2UP_LOG_FILE_POST_u2up_log_h
#define U2UP_LOG_FILE_POST_u2up_log_h

#define U2UP_LOG_DECLARE(modName) \
extern void MKU2UPLOG_SET_QUIET(modName)(int val); \
extern void MKU2UPLOG_SET_NORMAL(modName)(int val); \
extern void MKU2UPLOG_SET_VERBOSE(modName)(int val); \
extern void MKU2UPLOG_SET_TRACE(modName)(int val); \
extern void MKU2UPLOG_SET_DEBUG(modName)(int val); \
extern void MKU2UPLOG_SET_HEADER(modName)(int val); \
extern void MKU2UPLOG_SET_SYSLOG(modName)(int val); \
extern int MKU2UPLOG_GET_QUIET(modName)(void); \
extern int MKU2UPLOG_GET_NORMAL(modName)(void); \
extern int MKU2UPLOG_GET_VERBOSE(modName)(void); \
extern int MKU2UPLOG_GET_TRACE(modName)(void); \
extern int MKU2UPLOG_GET_DEBUG(modName)(void); \
extern int MKU2UPLOG_GET_HEADER(modName)(void); \
extern int MKU2UPLOG_GET_SYSLOG(modName)(void); \
extern char * MKU2UPLOG_GET_NAME(modName)(void)

#define U2UP_LOG_SET_QUIET(val) MKU2UPLOG_SET_QUIET(U2UP_LOG_NAME)(val)
#define U2UP_LOG_SET_QUIET2(name, val) MKU2UPLOG_SET_QUIET(name)(val)
#define U2UP_LOG_GET_QUIET() MKU2UPLOG_GET_QUIET(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_QUIET2(name) MKU2UPLOG_GET_QUIET(name)()

#define U2UP_LOG_SET_NORMAL(val) MKU2UPLOG_SET_NORMAL(U2UP_LOG_NAME)(val)
#define U2UP_LOG_SET_NORMAL2(name, val) MKU2UPLOG_SET_NORMAL(name)(val)
#define U2UP_LOG_GET_NORMAL() MKU2UPLOG_GET_NORMAL(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_NORMAL2(name) MKU2UPLOG_GET_NORMAL(name)()

#define U2UP_LOG_SET_VERBOSE(val) MKU2UPLOG_SET_VERBOSE(U2UP_LOG_NAME)(val)
#define U2UP_LOG_SET_VERBOSE2(name, val) MKU2UPLOG_SET_VERBOSE(name)(val)
#define U2UP_LOG_GET_VERBOSE() MKU2UPLOG_GET_VERBOSE(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_VERBOSE2(name) MKU2UPLOG_GET_VERBOSE(name)()

#define U2UP_LOG_SET_TRACE(val) MKU2UPLOG_SET_TRACE(U2UP_LOG_NAME)(val)
#define U2UP_LOG_SET_TRACE2(name, val) MKU2UPLOG_SET_TRACE(name)(val)
#define U2UP_LOG_GET_TRACE() MKU2UPLOG_GET_TRACE(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_TRACE2(name) MKU2UPLOG_GET_TRACE(name)()

#define U2UP_LOG_SET_DEBUG(val) MKU2UPLOG_SET_DEBUG(U2UP_LOG_NAME)(val)
#define U2UP_LOG_SET_DEBUG2(name, val) MKU2UPLOG_SET_DEBUG(name)(val)
#define U2UP_LOG_GET_DEBUG() MKU2UPLOG_GET_DEBUG(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_DEBUG2(name) MKU2UPLOG_GET_DEBUG(name)()

#define U2UP_LOG_SET_HEADER(val) MKU2UPLOG_SET_HEADER(U2UP_LOG_NAME)(val)
#define U2UP_LOG_SET_HEADER2(name, val) MKU2UPLOG_SET_HEADER(name)(val)
#define U2UP_LOG_GET_HEADER() MKU2UPLOG_GET_HEADER(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_HEADER2(name) MKU2UPLOG_GET_HEADER(name)()

#define U2UP_LOG_SET_SYSLOG(val) MKU2UPLOG_SET_SYSLOG(U2UP_LOG_NAME)(val)
#define U2UP_LOG_SET_SYSLOG2(name, val) MKU2UPLOG_SET_SYSLOG(name)(val)
#define U2UP_LOG_GET_SYSLOG() MKU2UPLOG_GET_SYSLOG(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_SYSLOG2(name) MKU2UPLOG_GET_SYSLOG(name)()

#define U2UP_LOG_GET_NAME() MKU2UPLOG_GET_NAME(U2UP_LOG_NAME)()
#define U2UP_LOG_GET_NAME2(name) MKU2UPLOG_GET_NAME(name)()

#define U2UP_LOG_5DIGIT_SECS(timespec_x) (timespec_x.tv_sec % 100000)
#define U2UP_LOG_6DIGIT_USECS(timespec_x) (timespec_x.tv_nsec / 1000)

#define U2UP_LOG_WITH_HEADER_DEBUG_FORMAT "[%05ld.%06ld|%d|%s] %s:%d %s(): "
#define U2UP_LOG_WITH_HEADER_DEBUG_ARGS U2UP_LOG_5DIGIT_SECS(ts), U2UP_LOG_6DIGIT_USECS(ts), (int)syscall(SYS_gettid), MKU2UPSTR(U2UP_LOG_NAME), __FILE__, __LINE__, __FUNCTION__
#define U2UP_LOG_WITH_HEADER_TRACE_FORMAT "[%05ld.%06ld|%d|%s] %s(): "
#define U2UP_LOG_WITH_HEADER_TRACE_ARGS U2UP_LOG_5DIGIT_SECS(ts), U2UP_LOG_6DIGIT_USECS(ts), (int)syscall(SYS_gettid), MKU2UPSTR(U2UP_LOG_NAME), __FUNCTION__
#define U2UP_LOG_WITH_HEADER_NORMAL_FORMAT "[%05ld.%06ld|%d|%s] "
#define U2UP_LOG_WITH_HEADER_NORMAL_ARGS U2UP_LOG_5DIGIT_SECS(ts), U2UP_LOG_6DIGIT_USECS(ts), (int)syscall(SYS_gettid), MKU2UPSTR(U2UP_LOG_NAME)

#define U2UP_LOG_NO_HEADER_DEBUG_FORMAT "%s:%d %s(): "
#define U2UP_LOG_NO_HEADER_DEBUG_ARGS __FILE__, __LINE__, __FUNCTION__
#define U2UP_LOG_NO_HEADER_TRACE_FORMAT "%s(): "
#define U2UP_LOG_NO_HEADER_TRACE_ARGS __FUNCTION__
#define U2UP_LOG_NO_HEADER_NORMAL_FORMAT "%s"
#define U2UP_LOG_NO_HEADER_NORMAL_ARGS ""

#define u2up_log_warning(format, args...) \
if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).quiet == 0) {\
	if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_WARNING, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_WARNING, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				syslog(LOG_WARNING, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_WARNING, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_WARNING, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				syslog(LOG_WARNING, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_notice(format, args...) \
if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).quiet == 0) {\
	if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_NOTICE, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_NOTICE, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				syslog(LOG_NOTICE, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_NOTICE, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_NOTICE, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				syslog(LOG_NOTICE, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).normal || MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_info(format, args...) \
if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).quiet == 0) {\
	if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_INFO, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_INFO, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				syslog(LOG_INFO, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_INFO, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_INFO, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				syslog(LOG_INFO, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stdout);\
			} else if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).verbose) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_debug(format, args...) \
if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).quiet == 0) {\
	if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_DEBUG, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	} else {\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_DEBUG, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stdout, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stdout);\
			}\
		}\
	}\
}

#define u2up_log_system_error(format, args...) {\
	char buf[1024];\
	strerror_r(errno, buf, 1024);\
	if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, buf, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, buf, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, buf, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, buf, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, buf, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, buf, ##args);\
				fflush(stderr);\
			}\
		}\
	} else {\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, buf, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_TRACE_ARGS, buf, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, buf, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_DEBUG_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, buf, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_TRACE_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_TRACE_ARGS, buf, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_NORMAL_FORMAT "%s >> " format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, buf, ##args);\
				fflush(stderr);\
			}\
		}\
	}\
}

#define u2up_log_error(format, args...) {\
	if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).header) {\
		struct timespec ts;\
		clock_gettime(CLOCK_MONOTONIC, &ts);\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_DEBUG_FORMAT format, U2UP_LOG_WITH_HEADER_DEBUG_ARGS, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_TRACE_FORMAT format, U2UP_LOG_WITH_HEADER_TRACE_ARGS, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_WITH_HEADER_NORMAL_FORMAT format, U2UP_LOG_WITH_HEADER_NORMAL_ARGS, ##args);\
				fflush(stderr);\
			}\
		}\
	} else {\
		if (MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).syslog) {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
			} else {\
				syslog(LOG_ERR, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
			}\
		} else {\
			if (U2UP_LOG_MODULE_DEBUG && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).debug) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_DEBUG_FORMAT format, U2UP_LOG_NO_HEADER_DEBUG_ARGS, ##args);\
				fflush(stderr);\
			} else if (U2UP_LOG_MODULE_TRACE && MKU2UPLOG_VAR_STRUCT(U2UP_LOG_NAME).trace) {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_TRACE_FORMAT format, U2UP_LOG_NO_HEADER_TRACE_ARGS, ##args);\
				fflush(stderr);\
			} else {\
				fprintf(stderr, U2UP_LOG_NO_HEADER_NORMAL_FORMAT format, U2UP_LOG_NO_HEADER_NORMAL_ARGS, ##args);\
				fflush(stderr);\
			}\
		}\
	}\
}

#define u2up_log_return_system_err(msg, args...) {\
	int errsv = errno;\
	u2up_log_system_error(msg, ##args);\
	return -errsv;\
}

#define u2up_log_return_err(msg, args...) {\
	int errsv = errno;\
	u2up_log_error(msg, ##args);\
	return -errsv;\
}

#endif /*U2UP_LOG_FILE_POST_u2up_log_h*/

