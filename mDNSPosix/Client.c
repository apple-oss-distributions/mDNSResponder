/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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

$Log: Client.c,v $
Revision 1.11  2003/11/17 20:14:32  cheshire
Typo: Wrote "domC" where it should have said "domainC"

Revision 1.10  2003/11/14 21:27:09  cheshire
<rdar://problem/3484766>: Security: Crashing bug in mDNSResponder
Fix code that should use buffer size MAX_ESCAPED_DOMAIN_NAME (1005) instead of 256-byte buffers.

Revision 1.9  2003/08/14 02:19:55  cheshire
<rdar://problem/3375491> Split generic ResourceRecord type into two separate types: AuthRecord and CacheRecord

Revision 1.8  2003/08/12 19:56:26  cheshire
Update to APSL 2.0

Revision 1.7  2003/07/02 21:19:58  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.6  2003/06/18 05:48:41  cheshire
Fix warnings

Revision 1.5  2003/05/06 00:00:50  cheshire
<rdar://problem/3248914> Rationalize naming of domainname manipulation functions

Revision 1.4  2002/12/23 22:13:31  jgraessl

Reviewed by: Stuart Cheshire
Initial IPv6 support for mDNSResponder.

Revision 1.3  2002/09/21 20:44:53  zarzycki
Added APSL info

Revision 1.2  2002/09/19 04:20:44  cheshire
Remove high-ascii characters that confuse some systems

Revision 1.1  2002/09/17 06:24:35  cheshire
First checkin

*/

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "mDNSClientAPI.h"// Defines the interface to the mDNS core code
#include "mDNSPosix.h"    // Defines the specific types needed to run mDNS on this platform
#include "ExampleClientApp.h"

// Globals
static mDNS mDNSStorage;       // mDNS core uses this to store its globals
static mDNS_PlatformSupport PlatformStorage;  // Stores this platform's globals
#define RR_CACHE_SIZE 500
static CacheRecord gRRCache[RR_CACHE_SIZE];

static const char *gProgramName = "mDNSResponderPosix";

static void BrowseCallback(mDNS *const m, DNSQuestion *question, const ResourceRecord *const answer, mDNSBool AddRecord)
    // A callback from the core mDNS code that indicates that we've received a 
    // response to our query.  Note that this code runs on the main thread 
    // (in fact, there is only one thread!), so we can safely printf the results.
{
    domainlabel name;
    domainname  type;
    domainname  domain;
	char nameC  [MAX_DOMAIN_LABEL+1];			// Unescaped name: up to 63 bytes plus C-string terminating NULL.
	char typeC  [MAX_ESCAPED_DOMAIN_NAME];
	char domainC[MAX_ESCAPED_DOMAIN_NAME];
    const char *state;

	(void)m;		// Unused
	(void)question;	// Unused

    assert(answer->rrtype == kDNSType_PTR);

    DeconstructServiceName(&answer->rdata->u.name, &name, &type, &domain);

    ConvertDomainLabelToCString_unescaped(&name, nameC);
    ConvertDomainNameToCString(&type, typeC);
    ConvertDomainNameToCString(&domain, domainC);

    // If the TTL has hit 0, the service is no longer available.
    if (!AddRecord) {
        state = "Lost ";
    } else {
        state = "Found";
    }
    fprintf(stderr, "*** %s name = '%s', type = '%s', domain = '%s'\n", state, nameC, typeC, domainC);
}

static mDNSBool CheckThatServiceTypeIsUsable(const char *serviceType, mDNSBool printExplanation)
    // Checks that serviceType is a reasonable service type 
    // label and, if it isn't and printExplanation is true, prints 
    // an explanation of why not.
{
    mDNSBool result;
    
    result = mDNStrue;
    if (result && strlen(serviceType) > 63) {
        if (printExplanation) {
            fprintf(stderr, 
                    "%s: Service type specified by -t is too long (must be 63 characters or less)\n", 
                    gProgramName);
        }
        result = mDNSfalse;
    }
    if (result && serviceType[0] == 0) {
        if (printExplanation) {
            fprintf(stderr, 
                    "%s: Service type specified by -t can't be empty\n", 
                    gProgramName);
        }
        result = mDNSfalse;
    }
    return result;
}

static const char kDefaultServiceType[] = "_afpovertcp._tcp.";

static void PrintUsage()
{
    fprintf(stderr, 
            "Usage: %s [-v level] [-t type]\n", 
            gProgramName);
    fprintf(stderr, "          -v verbose mode, level is a number from 0 to 2\n");
    fprintf(stderr, "             0 = no debugging info (default)\n");
    fprintf(stderr, "             1 = standard debugging info\n");
    fprintf(stderr, "             2 = intense debugging info\n");
    fprintf(stderr, "          -t uses 'type' as the service type (default is '%s')\n", kDefaultServiceType);
}

static const char *gServiceType      = kDefaultServiceType;

static void ParseArguments(int argc, char **argv)
    // Parses our command line arguments into the global variables 
    // listed above.
{
    int ch;
    
    // Set gProgramName to the last path component of argv[0]
    
    gProgramName = strrchr(argv[0], '/');
    if (gProgramName == NULL) {
        gProgramName = argv[0];
    } else {
        gProgramName += 1;
    }
    
    // Parse command line options using getopt.
    
    do {
        ch = getopt(argc, argv, "v:t:");
        if (ch != -1) {
            switch (ch) {
                case 'v':
                    gMDNSPlatformPosixVerboseLevel = atoi(optarg);
                    if (gMDNSPlatformPosixVerboseLevel < 0 || gMDNSPlatformPosixVerboseLevel > 2) {
                        fprintf(stderr, 
                                "%s: Verbose mode must be in the range 0..2\n", 
                                gProgramName);
                        exit(1);
                    }
                    break;
                case 't':
                    gServiceType = optarg;
                    if ( ! CheckThatServiceTypeIsUsable(gServiceType, mDNStrue) ) {
                        exit(1);
                    }
                    break;
                case '?':
                default:
                    PrintUsage();
                    exit(1);
                    break;
            }
        }
    } while (ch != -1);

    // Check for any left over command line arguments.
    
    if (optind != argc) {
        fprintf(stderr, "%s: Unexpected argument '%s'\n", gProgramName, argv[optind]);
        exit(1);
    }
}

int main(int argc, char **argv)
    // The program's main entry point.  The program does a trivial 
    // mDNS query, looking for all AFP servers in the local domain.
{
    int     result;
    mStatus     status;
    DNSQuestion question;
    domainname  type;
    domainname  domain;

    // Parse our command line arguments.  This won't come back if there's an error.
    ParseArguments(argc, argv);

    // Initialise the mDNS core.
	status = mDNS_Init(&mDNSStorage, &PlatformStorage,
    	gRRCache, RR_CACHE_SIZE,
    	mDNS_Init_DontAdvertiseLocalAddresses,
    	mDNS_Init_NoInitCallback, mDNS_Init_NoInitCallbackContext);
    if (status == mStatus_NoError) {
    
        // Construct and start the query.
        
        MakeDomainNameFromDNSNameString(&type, gServiceType);
        MakeDomainNameFromDNSNameString(&domain, "local.");

        status = mDNS_StartBrowse(&mDNSStorage, &question, &type, &domain, mDNSInterface_Any, BrowseCallback, NULL);
    
        // Run the platform main event loop until the user types ^C. 
        // The BrowseCallback routine is responsible for printing 
        // any results that we find.
        
        if (status == mStatus_NoError) {
            fprintf(stderr, "Hit ^C when you're bored waiting for responses.\n");
        	ExampleClientEventLoop(&mDNSStorage);
            mDNS_StopQuery(&mDNSStorage, &question);
			mDNS_Close(&mDNSStorage);
        }
    }
    
    if (status == mStatus_NoError) {
        result = 0;
    } else {
        result = 2;
    }
    if ( (result != 0) || (gMDNSPlatformPosixVerboseLevel > 0) ) {
        fprintf(stderr, "%s: Finished with status %ld, result %d\n", gProgramName, status, result);
    }

    return 0;
}
