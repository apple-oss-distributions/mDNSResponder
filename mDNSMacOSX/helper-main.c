/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

    Change History (most recent first):

$Log: helper-main.c,v $
Revision 1.15  2008/03/13 20:55:16  mcguire
<rdar://problem/5769316> fix deprecated warnings/errors
Additional cleanup: use a conditional macro instead of lots of #if

Revision 1.14  2008/03/12 23:02:59  mcguire
<rdar://problem/5769316> fix deprecated warnings/errors

Revision 1.13  2007/09/21 16:13:14  cheshire
Additional Tiger compatibility fix: After bootstrap_check_in, we need to give
ourselves a Mach "send" right to the port, otherwise our ten-second idle timeout
mechanism is not able to send the "mDNSIdleExit" message to itself

Revision 1.12  2007/09/20 22:26:20  cheshire
Add necessary bootstrap_check_in() in Tiger compatibility code (not used on Leopard)

Revision 1.11  2007/09/18 19:09:02  cheshire
<rdar://problem/5489549> mDNSResponderHelper (and other binaries) missing SCCS version strings

Revision 1.10  2007/09/09 02:21:17  mcguire
<rdar://problem/5469345> Leopard Server9A547(Insatll):mDNSResponderHelper crashing

Revision 1.9  2007/09/07 22:44:03  mcguire
<rdar://problem/5448420> Move CFUserNotification code to mDNSResponderHelper

Revision 1.8  2007/09/07 22:24:36  vazquez
<rdar://problem/5466301> Need to stop spewing mDNSResponderHelper logs

Revision 1.7  2007/08/31 18:09:32  cheshire
<rdar://problem/5434050> Restore ability to run mDNSResponder on Tiger

Revision 1.6  2007/08/31 17:45:13  cheshire
Allow maxidle time of zero, meaning "run indefinitely"

Revision 1.5  2007/08/31 00:09:54  cheshire
Deleted extraneous whitespace (shortened code from 260 lines to 160)

Revision 1.4  2007/08/28 00:33:04  jgraessley
<rdar://problem/5423932> Selective compilation options

Revision 1.3  2007/08/23 23:21:24  cheshire
Tiger compatibility: Use old bootstrap_register() instead of Leopard-only bootstrap_register2()

Revision 1.2  2007/08/23 21:36:17  cheshire
Made code layout style consistent with existing project style; added $Log header

Revision 1.1  2007/08/08 22:34:58  mcguire
<rdar://problem/5197869> Security: Run mDNSResponder as user id mdnsresponder instead of root
 */

#define _FORTIFY_SOURCE 2
#include <CoreFoundation/CoreFoundation.h>
#include <sys/cdefs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <mach/mach_error.h>
#include <servers/bootstrap.h>
#include <asl.h>
#include <launch.h>
#include <pwd.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <Security/Security.h>
#include "helper.h"
#include "helper-server.h"
#include "helpermsg.h"
#include "helpermsgServer.h"

#if TARGET_OS_EMBEDDED
#include <bootstrap_priv.h>
#define NO_SECURITYFRAMEWORK 1

#define bootstrap_register(A,B,C) bootstrap_register2((A),(B),(C),0)
#endif

#ifndef LAUNCH_JOBKEY_MACHSERVICES
#define LAUNCH_JOBKEY_MACHSERVICES "MachServices"
#define LAUNCH_DATA_MACHPORT 10
#define launch_data_get_machport launch_data_get_fd
#endif

union max_msg_size
	{
	union __RequestUnion__proxy_helper_subsystem req;
	union __ReplyUnion__proxy_helper_subsystem rep;
	};

static const mach_msg_size_t MAX_MSG_SIZE = sizeof(union max_msg_size) + MAX_TRAILER_SIZE;
static aslclient logclient = NULL;
static int opt_debug;
static pthread_t idletimer_thread;

unsigned long maxidle = 10;
unsigned long actualidle = 3600;

CFRunLoopRef gRunLoop = NULL;
CFRunLoopTimerRef gTimer = NULL;

static void helplogv(int level, const char *fmt, va_list ap)
	{
	if (NULL == logclient) { vfprintf(stderr, fmt, ap); fflush(stderr); }
	else asl_vlog(logclient, NULL, level, fmt, ap);
	}

void helplog(int level, const char *fmt, ...)
	{
	va_list ap;
	va_start(ap, fmt);
	helplogv(level, fmt, ap);
	va_end(ap);
	}

static void initialize_logging(void)
	{
	logclient = asl_open(NULL, kmDNSHelperServiceName, (opt_debug ? ASL_OPT_STDERR : 0));
	if (NULL == logclient) { fprintf(stderr, "Could not initialize ASL logging.\n"); fflush(stderr); return; }
	if (opt_debug) asl_set_filter(logclient, ASL_FILTER_MASK_UPTO(ASL_LEVEL_DEBUG));
	}

static void initialize_id(void)
	{
	static char login[] = "_mdnsresponder";
	struct passwd *pwd = getpwnam(login);

	if (!pwd) { helplog(ASL_LEVEL_ERR, "Could not find account name `%s'.  I will only help root.", login); return; }
	mDNSResponderUID = pwd->pw_uid;
	mDNSResponderGID = pwd->pw_gid;
	}

static void diediedie(CFRunLoopTimerRef timer, void *context)
	{
	debug("entry");
	assert(gTimer == timer);
	if (maxidle)
	  (void)proxy_mDNSIdleExit((mach_port_t)context);
	}

void pause_idle_timer(void)
	{
	debug("entry");
	assert(gTimer);
	assert(gRunLoop);
	CFRunLoopRemoveTimer(gRunLoop, gTimer, kCFRunLoopDefaultMode);
	}

void unpause_idle_timer(void)
	{
	debug("entry");
	assert(gRunLoop);
	assert(gTimer);
	CFRunLoopAddTimer(gRunLoop, gTimer, kCFRunLoopDefaultMode);
	}

void update_idle_timer(void)
	{
	debug("entry");
	assert(gTimer);
	CFRunLoopTimerSetNextFireDate(gTimer, CFAbsoluteTimeGetCurrent() + actualidle);
	}

static void *idletimer(void *context)
	{
	debug("entry context=%p", context);
	gRunLoop = CFRunLoopGetCurrent();
	
	unpause_idle_timer();

	for (;;)
		{
		debug("Running CFRunLoop");
		CFRunLoopRun();
		sleep(1);
		}

	return NULL;
	}

static void initialize_timer(mach_port_t port)
	{
	CFRunLoopTimerContext cxt = {0, (void *)port, NULL, NULL, NULL};
	gTimer = CFRunLoopTimerCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + actualidle, actualidle, 0, 0, diediedie, &cxt);
	int err = 0;

	debug("entry port=%p", port);
	if (0 != (err = pthread_create(&idletimer_thread, NULL, idletimer, (void *)port)))
		helplog(ASL_LEVEL_ERR, "Could not start idletimer thread: %s", strerror(err));
	}

static mach_port_t checkin(char *service_name)
	{
	kern_return_t kr = KERN_SUCCESS;
	mach_port_t port = MACH_PORT_NULL;
	launch_data_t msg = NULL, reply = NULL, datum = NULL;

	if (NULL == (msg = launch_data_new_string(LAUNCH_KEY_CHECKIN)))
		{ helplog(ASL_LEVEL_ERR, "Could not create checkin message for launchd."); goto fin; }
	if (NULL == (reply = launch_msg(msg)))
		{ helplog(ASL_LEVEL_ERR, "Could not message launchd."); goto fin; }
	if (LAUNCH_DATA_ERRNO == launch_data_get_type(reply))
		{
		if (launch_data_get_errno(reply) == EACCES) { launch_data_free(msg); launch_data_free(reply); return(MACH_PORT_NULL); }
		helplog(ASL_LEVEL_ERR, "Launchd checkin failed: %s.", strerror(launch_data_get_errno(reply))); goto fin;
		}
	if (NULL == (datum = launch_data_dict_lookup(reply, LAUNCH_JOBKEY_MACHSERVICES)) || LAUNCH_DATA_DICTIONARY != launch_data_get_type(datum))
		{ helplog(ASL_LEVEL_ERR, "Launchd reply does not contain %s dictionary.", LAUNCH_JOBKEY_MACHSERVICES); goto fin; }
	if (NULL == (datum = launch_data_dict_lookup(datum, service_name)) || LAUNCH_DATA_MACHPORT != launch_data_get_type(datum))
		{ helplog(ASL_LEVEL_ERR, "Launchd reply does not contain %s Mach port.", service_name); goto fin; }
	if (MACH_PORT_NULL == (port = launch_data_get_machport(datum)))
		{ helplog(ASL_LEVEL_ERR, "Launchd gave me a null Mach port."); goto fin; }
	if (KERN_SUCCESS != (kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND)))
		{ helplog(ASL_LEVEL_ERR, "mach_port_insert_right: %s", mach_error_string(kr)); goto fin; }

fin:
	if (NULL != msg)   launch_data_free(msg);
	if (NULL != reply) launch_data_free(reply);
	if (MACH_PORT_NULL == port) exit(EXIT_FAILURE);
	return port;
	}

static mach_port_t register_service(const char *service_name)
	{
	mach_port_t port = MACH_PORT_NULL;
	kern_return_t kr;

	if (KERN_SUCCESS == (kr = bootstrap_check_in(bootstrap_port, (char *)service_name, &port)))
		{
		if (KERN_SUCCESS != (kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND)))
			helplog(ASL_LEVEL_ERR, "mach_port_insert_right: %s", mach_error_string(kr));
		else
			return port;
		}
	if (KERN_SUCCESS != (kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port)))
		{ helplog(ASL_LEVEL_ERR, "mach_port_allocate: %s", mach_error_string(kr)); goto error; }
	if (KERN_SUCCESS != (kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND)))
		{ helplog(ASL_LEVEL_ERR, "mach_port_insert_right: %s", mach_error_string(kr)); goto error; }

	// XXX bootstrap_register does not modify its second argument, but the prototype does not include const.
	if (KERN_SUCCESS != (kr = bootstrap_register(bootstrap_port, (char *)service_name, port)))
		{ helplog(ASL_LEVEL_ERR, "bootstrap_register failed: %s", mach_error_string(kr)); goto error; }

	return port;
error:
	if (MACH_PORT_NULL != port) mach_port_deallocate(mach_task_self(), port);
	return MACH_PORT_NULL;
	}

int main(int ac, char *av[])
	{
	char *p = NULL;
	kern_return_t kr = KERN_FAILURE;
	mach_port_t port = MACH_PORT_NULL;
	long n;
	int ch;

	while ((ch = getopt(ac, av, "dt:")) != -1)
		switch (ch)
		{
		case 'd': opt_debug = 1; break;
		case 't':
			n = strtol(optarg, &p, 0);
			if ('\0' == optarg[0] || '\0' != *p || n > LONG_MAX || n < 0)
				{ fprintf(stderr, "Invalid idle timeout: %s\n", optarg); exit(EXIT_FAILURE); }
			maxidle = n;
			break;
		case '?':
		default:
			fprintf(stderr, "Usage: mDNSResponderHelper [-d] [-t maxidle]\n");
			exit(EXIT_FAILURE);
		}
	ac -= optind;
	av += optind;

	initialize_logging();
	helplog(ASL_LEVEL_INFO, "Starting");
	initialize_id();

#ifndef NO_SECURITYFRAMEWORK
	// We should normally be running as a system daemon.  However, that might not be the case in some scenarios (e.g. debugging).
	// Explicitly ensure that our Keychain operations utilize the system domain.
	SecKeychainSetPreferenceDomain(kSecPreferencesDomainSystem);
#endif
	port = checkin(kmDNSHelperServiceName);
	if (!port)
		{
		helplog(ASL_LEVEL_ERR, "Launchd provided no launchdata; will open Mach port explicitly");
		port = register_service(kmDNSHelperServiceName);
		}

	if (maxidle) actualidle = maxidle;
	initialize_timer(port);

	kr = mach_msg_server(helper_server, MAX_MSG_SIZE, port,
		MACH_RCV_TRAILER_ELEMENTS(MACH_RCV_TRAILER_AUDIT) | MACH_RCV_TRAILER_TYPE(MACH_MSG_TRAILER_FORMAT_0));
	if (KERN_SUCCESS != kr)
		{ helplog(ASL_LEVEL_ERR, "mach_msg_server: %s\n", mach_error_string(kr)); exit(EXIT_FAILURE); }
	exit(EXIT_SUCCESS);
	}

// Note: The C preprocessor stringify operator ('#') makes a string from its argument, without macro expansion
// e.g. If "version" is #define'd to be "4", then STRINGIFY_AWE(version) will return the string "version", not "4"
// To expand "version" to its value before making the string, use STRINGIFY(version) instead
#define STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s) #s
#define STRINGIFY(s) STRINGIFY_ARGUMENT_WITHOUT_EXPANSION(s)

// For convenience when using the "strings" command, this is the last thing in the file
// The "@(#) " pattern is a special prefix the "what" command looks for
const char VersionString_SCCS[] = "@(#) mDNSResponderHelper " STRINGIFY(mDNSResponderVersion) " (" __DATE__ " " __TIME__ ")";

// If the process crashes, then this string will be magically included in the automatically-generated crash log
const char *__crashreporter_info__ = VersionString_SCCS + 5;
asm(".desc ___crashreporter_info__, 0x10");
