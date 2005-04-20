/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

$Log: PlatformCommon.c,v $
Revision 1.5  2005/02/01 19:33:30  ksekar
<rdar://problem/3985239> Keychain format too restrictive

Revision 1.4  2005/01/19 19:19:21  ksekar
<rdar://problem/3960191> Need a way to turn off domain discovery

Revision 1.3  2004/12/13 17:46:52  cheshire
Use sizeof(buf) instead of fixed constant 1024

Revision 1.2  2004/12/01 03:30:29  cheshire
<rdar://problem/3889346> Add Unicast DNS support to mDNSPosix

Revision 1.1  2004/12/01 01:51:35  cheshire
Move ReadDDNSSettingsFromConfFile() from mDNSMacOSX.c to PlatformCommon.c

 */

#include <stdio.h>				// Needed for fopen() etc.
#include <unistd.h>				// Needed for close()
#include <string.h>				// Needed for strlen() etc.
#include <sys/errno.h>			// Needed for errno etc.
#include <sys/socket.h>			// Needed for socket() etc.
#include <netinet/in.h>			// Needed for sockaddr_in

#include "mDNSEmbeddedAPI.h"	// Defines the interface provided to the client layer above
#include "PlatformCommon.h"

#ifdef NOT_HAVE_SOCKLEN_T
    typedef unsigned int socklen_t;
#endif

// Bind a UDP socket to a global destination to find the default route's interface address
mDNSexport void FindDefaultRouteIP(mDNSAddr *a)
	{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	int sock = socket(AF_INET,SOCK_DGRAM,0);
	a->type = mDNSAddrType_None;
	if (sock == -1) return;
	addr.sin_family = AF_INET;
	addr.sin_port = 1;	// Not important, any port and public address will do
	addr.sin_addr.s_addr = 0x11111111;
	if ((connect(sock,(const struct sockaddr*)&addr,sizeof(addr))) == -1) { close(sock); return; }
	if ((getsockname(sock,(struct sockaddr*)&addr, &len)) == -1) { close(sock); return; }
	close(sock);
	a->type = mDNSAddrType_IPv4;
	a->ip.v4.NotAnInteger = addr.sin_addr.s_addr;
	}

// dst must be at least MAX_ESCAPED_DOMAIN_NAME bytes, and option must be less than 32 bytes in length
mDNSlocal mDNSBool GetConfigOption(char *dst, const char *option, FILE *f)
	{
	char buf[32+1+MAX_ESCAPED_DOMAIN_NAME];	// Option name, one space, option value
	unsigned int len = strlen(option);
	if (len + 1 + MAX_ESCAPED_DOMAIN_NAME > sizeof(buf)-1) { LogMsg("GetConfigOption: option %s too long", option); return mDNSfalse; }
	fseek(f, 0, SEEK_SET);  // set position to beginning of stream
	while (fgets(buf, sizeof(buf), f))		// Read at most sizeof(buf)-1 bytes from file, and append '\0' C-string terminator
		{
		if (!strncmp(buf, option, len))
			{
			strncpy(dst, buf + len + 1, MAX_ESCAPED_DOMAIN_NAME-1);
			if (dst[MAX_ESCAPED_DOMAIN_NAME-1]) dst[MAX_ESCAPED_DOMAIN_NAME-1] = '\0';
			len = strlen(dst);
			if (len && dst[len-1] == '\n') dst[len-1] = '\0';  // chop newline
			return mDNStrue;
			}
		}
	debugf("Option %s not set", option);
	return mDNSfalse;
	}

mDNSexport void ReadDDNSSettingsFromConfFile(mDNS *const m, const char *const filename, domainname *const hostname, domainname *const domain, mDNSBool *DomainDiscoveryDisabled)
	{
	char buf   [MAX_ESCAPED_DOMAIN_NAME];
	char secret[MAX_ESCAPED_DOMAIN_NAME] = "";
	mStatus err;
	FILE *f = fopen(filename, "r");

    if (hostname)                 hostname->c[0] = 0;
    if (domain)                   domain->c[0] = 0;
	if (DomainDiscoveryDisabled) *DomainDiscoveryDisabled = mDNSfalse;

	if (f)
		{
		if (DomainDiscoveryDisabled && GetConfigOption(buf, "DomainDiscoveryDisabled", f) && !strcasecmp(buf, "true")) *DomainDiscoveryDisabled = mDNStrue;
		if (hostname && GetConfigOption(buf, "hostname", f) && !MakeDomainNameFromDNSNameString(hostname, buf)) goto badf;
		if (domain && GetConfigOption(buf, "zone", f) && !MakeDomainNameFromDNSNameString(domain, buf)) goto badf;
		GetConfigOption(secret, "secret-64", f);  // failure means no authentication	   		
		fclose(f);
		f = NULL;
		}
	else
		{
		if (errno != ENOENT) LogMsg("ERROR: Config file exists, but cannot be opened.");
		return;
		}

	if (domain && domain->c[0] && secret[0])
		{
		// for now we assume keyname = service reg domain and we use same key for service and hostname registration
		err = mDNS_SetSecretForZone(m, domain, domain, secret);
		if (err) LogMsg("ERROR: mDNS_SetSecretForZone returned %d for domain %##s", err, domain->c);
		}

	return;

	badf:
	LogMsg("ERROR: malformatted config file");
	if (f) fclose(f);	
	}
