/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@

    Change History (most recent first):

$Log: ExampleClientApp.c,v $
Revision 1.12  2004/11/30 22:37:00  cheshire
Update copyright dates and add "Mode: C; tab-width: 4" headers

Revision 1.11  2004/09/17 01:08:53  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.10  2004/09/16 01:58:22  cheshire
Fix compiler warnings

Revision 1.9  2003/08/12 19:56:26  cheshire
Update to APSL 2.0

Revision 1.8  2003/07/02 21:19:58  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.7  2003/06/18 05:48:41  cheshire
Fix warnings

Revision 1.6  2003/03/31 22:44:36  cheshire
Add log header

 */

#include <stdio.h>			// For printf()
#include <stdlib.h>			// For exit() etc.
#include <string.h>			// For strlen() etc.
#include <unistd.h>			// For select()
#include <errno.h>			// For errno, EINTR
#include <arpa/inet.h>		// For inet_addr()
#include <netinet/in.h>		// For INADDR_NONE
#include <netdb.h>			// For gethostbyname()
#include <signal.h>			// For SIGINT, etc.

#include "mDNSEmbeddedAPI.h"  // Defines the interface to the client layer above
#include "mDNSPosix.h"      // Defines the specific types needed to run mDNS on this platform

//*******************************************************************************************
// Main

static volatile mDNSBool StopNow;

mDNSlocal void HandleSIG(int signal)
	{
	(void)signal;	// Unused
	debugf("%s","");
	debugf("HandleSIG");
	StopNow = mDNStrue;
	}

mDNSexport void ExampleClientEventLoop(mDNS *const m)
	{
	signal(SIGINT, HandleSIG);	// SIGINT is what you get for a Ctrl-C
	signal(SIGTERM, HandleSIG);

	while (!StopNow)
		{
		int nfds = 0;
		fd_set readfds;
		struct timeval timeout;
		int result;
		
		// 1. Set up the fd_set as usual here.
		// This example client has no file descriptors of its own,
		// but a real application would call FD_SET to add them to the set here
		FD_ZERO(&readfds);
		
		// 2. Set up the timeout.
		// This example client has no other work it needs to be doing,
		// so we set an effectively infinite timeout
		timeout.tv_sec = 0x3FFFFFFF;
		timeout.tv_usec = 0;
		
		// 3. Give the mDNSPosix layer a chance to add its information to the fd_set and timeout
		mDNSPosixGetFDSet(m, &nfds, &readfds, &timeout);
		
		// 4. Call select as normal
		verbosedebugf("select(%d, %d.%06d)", nfds, timeout.tv_sec, timeout.tv_usec);
		result = select(nfds, &readfds, NULL, NULL, &timeout);
		
		if (result < 0)
			{
			verbosedebugf("select() returned %d errno %d", result, errno);
			if (errno != EINTR) StopNow = mDNStrue;
			}
		else
			{
			// 5. Call mDNSPosixProcessFDSet to let the mDNSPosix layer do its work
			mDNSPosixProcessFDSet(m, &readfds);
			
			// 6. This example client has no other work it needs to be doing,
			// but a real client would do its work here
			// ... (do work) ...
			}
		}

	debugf("Exiting");
	}
