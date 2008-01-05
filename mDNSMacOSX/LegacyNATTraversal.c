/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

$Log: LegacyNATTraversal.c,v $
Revision 1.45  2007/12/06 00:22:27  mcguire
<rdar://problem/5604567> BTMM: Doesn't work with Linksys WAG300N 1.01.06 (sending from 1026/udp)

Revision 1.44  2007/11/02 20:45:40  cheshire
Don't log "connection failed" in customer builds

Revision 1.43  2007/10/18 20:09:47  cheshire
<rdar://problem/5545930> BTMM: Back to My Mac not working with D-Link DGL-4100 NAT gateway

Revision 1.42  2007/10/16 17:37:18  cheshire
<rdar://problem/3557903> Performance: Core code will not work on platforms with small stacks
Cut SendSOAPMsgControlAction stack from 2144 to 96 bytes

Revision 1.41  2007/10/15 23:02:00  cheshire
Off-by-one error: Incorrect trailing zero byte on the end of the SSDP Discovery message

Revision 1.40  2007/09/20 21:41:49  cheshire
<rdar://problem/5495568> Legacy NAT Traversal - unmap request failed with error -65549

Revision 1.39  2007/09/20 20:41:40  cheshire
Reordered functions in file, in preparation for following fix

Revision 1.38  2007/09/18 21:42:30  cheshire
To reduce programming mistakes, renamed ExtPort to RequestedPort

Revision 1.37  2007/09/14 21:26:09  cheshire
<rdar://problem/5482627> BTMM: Need to manually avoid port conflicts when using UPnP gateways

Revision 1.36  2007/09/14 01:15:50  cheshire
Minor fixes for problems discovered in pre-submission testing

Revision 1.35  2007/09/13 00:16:42  cheshire
<rdar://problem/5468706> Miscellaneous NAT Traversal improvements

Revision 1.34  2007/09/12 23:03:08  cheshire
<rdar://problem/5476978> DNSServiceNATPortMappingCreate callback not giving correct interface index

Revision 1.33  2007/09/12 19:22:20  cheshire
Variable renaming in preparation for upcoming fixes e.g. priv/pub renamed to intport/extport
Made NAT Traversal packet handlers take typed data instead of anonymous "mDNSu8 *" byte pointers

Revision 1.32  2007/09/11 19:19:16  cheshire
Correct capitalization of "uPNP" to "UPnP"

Revision 1.31  2007/09/10 22:14:16  cheshire
When constructing fake NATAddrReply or NATPortMapReply packet, need to calculate
plausible upseconds value or core logic will think NAT engine has been rebooted

Revision 1.30  2007/09/05 20:46:17  cheshire
Tidied up alignment of code layout

Revision 1.29  2007/08/03 20:18:01  vazquez
<rdar://problem/5382177> LegacyNATTraversal: reading out of bounds can lead to DoS

Revision 1.28  2007/07/31 02:28:36  vazquez
<rdar://problem/3734269> NAT-PMP: Detect public IP address changes and base station reboot

Revision 1.27  2007/07/30 23:17:03  vazquez
Since lease times are meaningless in UPnP, return NATMAP_DEFAULT_LEASE in UPnP port mapping reply

Revision 1.26  2007/07/27 22:50:08  vazquez
Allocate memory for UPnP request and reply buffers instead of using arrays

Revision 1.25  2007/07/27 20:33:44  vazquez
Make sure we clean up previous port mapping requests before starting an unmap

Revision 1.24  2007/07/27 00:57:48  vazquez
If a tcp connection is already established for doing a port mapping, don't start it again

Revision 1.23  2007/07/26 21:19:26  vazquez
Retry port mapping with incremented port number (up to max) in order to handle
port mapping conflicts on UPnP gateways

Revision 1.22  2007/07/25 21:41:00  vazquez
Make sure we clean up opened sockets when there are network transitions and when changing
port mappings

Revision 1.21  2007/07/25 03:05:03  vazquez
Fixes for:
<rdar://problem/5338913> LegacyNATTraversal: UPnP heap overflow
<rdar://problem/5338933> LegacyNATTraversal: UPnP stack buffer overflow
and a myriad of other security problems

Revision 1.20  2007/07/16 20:15:10  vazquez
<rdar://problem/3867231> LegacyNATTraversal: Need complete rewrite

Revision 1.19  2007/06/21 16:37:43  jgraessley
Bug #: 5280520
Reviewed by: Stuart Cheshire
Additional changes to get this compiling on the embedded platform.

Revision 1.18  2007/05/09 01:43:32  cheshire
<rdar://problem/5187028> Change sprintf and strcpy to their safer snprintf and strlcpy equivalents

Revision 1.17  2007/02/27 02:48:25  cheshire
Parameter to LNT_GetPublicIP function is IPv4 address, not anonymous "mDNSOpaque32" object

Revision 1.16  2006/08/14 23:24:39  cheshire
Re-licensed mDNSResponder daemon source code under Apache License, Version 2.0

Revision 1.15  2006/07/05 23:30:57  cheshire
Rename LegacyNATInit() -> LNT_Init()

Revision 1.14  2005/12/08 03:00:33  cheshire
<rdar://problem/4349971> Byte order bugs in Legacy NAT traversal code

Revision 1.13  2005/09/07 18:23:05  ksekar
<rdar://problem/4151514> Off-by-one overflow in LegacyNATTraversal

Revision 1.12  2005/07/22 21:36:16  ksekar
Fix GCC 4.0/Intel compiler warnings

Revision 1.11  2004/12/03 03:34:20  ksekar
<rdar://problem/3882674> LegacyNATTraversal.c leaks threads

Revision 1.10  2004/12/01 02:43:49  cheshire
Update copyright message

Revision 1.9  2004/10/27 02:25:05  cheshire
<rdar://problem/3816029> Random memory smashing bug

Revision 1.8  2004/10/27 02:17:21  cheshire
Turn off "safe_close: ERROR" error messages -- there are too many of them

Revision 1.7  2004/10/26 21:15:40  cheshire
<rdar://problem/3854314> Legacy NAT traversal code closes file descriptor 0
Additional fixes: Code should set fds to -1 after closing sockets.

Revision 1.6  2004/10/26 20:59:20  cheshire
<rdar://problem/3854314> Legacy NAT traversal code closes file descriptor 0

Revision 1.5  2004/10/26 01:01:35  cheshire
Use "#if 0" instead of commenting out code

Revision 1.4  2004/10/10 06:51:36  cheshire
Declared some strings "const" as appropriate

Revision 1.3  2004/09/21 23:40:12  ksekar
<rdar://problem/3810349> mDNSResponder to return errors on NAT traversal failure

Revision 1.2  2004/09/17 01:08:52  cheshire
Renamed mDNSClientAPI.h to mDNSEmbeddedAPI.h
  The name "mDNSClientAPI.h" is misleading to new developers looking at this code. The interfaces
  declared in that file are ONLY appropriate to single-address-space embedded applications.
  For clients on general-purpose computers, the interfaces defined in dns_sd.h should be used.

Revision 1.1  2004/08/18 17:35:41  ksekar
<rdar://problem/3651443>: Feature #9586: Need support for Legacy NAT gateways
*/

#ifdef _LEGACY_NAT_TRAVERSAL_

#include "stdlib.h"			// For strtol()
#include "string.h"			// For strlcpy(), For strncpy(), strncasecmp()
#include <arpa/inet.h>		// For inet_pton()

#include "mDNSEmbeddedAPI.h"
#include "uDNS.h"			// For natTraversalHandleAddressReply() etc.

// used to format SOAP port mapping arguments
typedef struct Property_struct
	{
	char *name;
	char *type;
	char *value;
	} Property;

// All of the text parsing in this file is intentionally transparent so that we know exactly
// what's being done to the text, with an eye towards preventing security problems.

// This is an evolving list of useful acronyms to know. Please add to it at will.
// ST      Service Type
// NT      Notification Type
// USN     Unique Service Name
// UDN     Unique Device Name
// UUID    Universally Unique Identifier
// URN/urn Universal Resource Name

// Forward declaration because of circular reference:
// SendPortMapRequest -> SendSOAPMsgControlAction -> MakeTCPConnection -> tcpConnectionCallback -> handleLNTPortMappingResponse
// In the event of a port conflict, handleLNTPortMappingResponse then increments tcpInfo->retries and calls back to SendPortMapRequest to try again
mDNSlocal mStatus SendPortMapRequest(mDNS *m, NATTraversalInfo *n);

#define RequestedPortNum(n) (mDNSVal16(mDNSIPPortIsZero((n)->RequestedPort) ? (n)->IntPort : (n)->RequestedPort) + (n)->tcpInfo.retries)

// This function parses the xml body of the device description response from the router. Basically, we look to make sure this is a response
// referencing a service we care about (WANIPConnection), look for the "controlURL" header immediately following, and copy the addressing and URL info we need
mDNSlocal void handleLNTDeviceDescriptionResponse(tcpLNTInfo *tcpInfo)
	{
	mDNS    *m   = tcpInfo->m;
	char    *ptr = (char *)tcpInfo->Reply;
	char    *end = (char *)tcpInfo->Reply + tcpInfo->nread;

	// find the service we care about
	while (ptr && ptr != end)
		{
		if (*ptr == 'W' && (strncasecmp(ptr, "WANIPConnection:1", 17) == 0)) break;	// find the first 'W'; is this WANIPConnection? if not, keep looking
		ptr++;
		}
	if (ptr == mDNSNULL || ptr == end) { LogOperation("handleLNTDeviceDescriptionResponse: didn't find WANIPConnection:1 string"); return; }

	// find "controlURL", starting from where we left off
	while (ptr && ptr != end)
		{
		if (*ptr == 'c' && (strncasecmp(ptr, "controlURL", 10) == 0)) break;			// find the first 'c'; is this controlURL? if not, keep looking
		ptr++;
		}
	if (ptr == mDNSNULL || ptr == end) { LogOperation("handleLNTDeviceDescriptionResponse: didn't find controlURL string"); return; }
	ptr += 11;							// skip over "controlURL>"
	if (ptr >= end) { LogOperation("handleLNTDeviceDescriptionResponse: past end of buffer and no body!"); return; } // check ptr again in case we skipped over the end of the buffer

	// is there an address string "http://"? starting from where we left off
	if (strncasecmp(ptr, "http://", 7) == 0)
		{
		int  i;
		char *addrPtr = mDNSNULL;
		
		ptr += 7;						//skip over "http://"
		if (ptr >= end) { LogOperation("handleLNTDeviceDescriptionResponse: past end of buffer and no URL!"); return; }
		addrPtr = ptr;
		for (i = 0; addrPtr && addrPtr != end; i++, addrPtr++) if (*addrPtr == '/') break; // first find the beginning of the URL and count the chars
		if (addrPtr == mDNSNULL || addrPtr == end) { LogOperation("handleLNTDeviceDescriptionResponse: didn't find SOAP address string"); return; }

		// allocate the buffer (len i+1 so we have space to terminate the string)
		if (m->UPnPSOAPAddressString != mDNSNULL)  mDNSPlatformMemFree(m->UPnPSOAPAddressString);
		if ((m->UPnPSOAPAddressString = (mDNSu8 *) mDNSPlatformMemAllocate(i+1)) == mDNSNULL) { LogMsg("can't allocate SOAP address string"); return; }
		
		strncpy((char *)m->UPnPSOAPAddressString, ptr, i);				// copy the address string
		m->UPnPSOAPAddressString[i] = '\0';								// terminate the string
		}
	
	if (m->UPnPSOAPAddressString == mDNSNULL) m->UPnPSOAPAddressString = m->UPnPRouterAddressString; // just copy the pointer, don't allocate more memory
	LogOperation("handleLNTDeviceDescriptionResponse: SOAP address string [%s]", m->UPnPSOAPAddressString);

	// find port and router URL, starting after the "http://" if it was there
	while (ptr && ptr != end)
		{
		if (*ptr == ':')										// found the port number
			{
			int port;
			ptr++;										// skip over ':'
			if (ptr == end) { LogOperation("handleLNTDeviceDescriptionResponse: reached end of buffer and no address!"); return; }
			port = (int)strtol(ptr, (char **)mDNSNULL, 10);				// get the port
			m->UPnPSOAPPort = mDNSOpaque16fromIntVal(port);		// store it properly converted
			}
		else if (*ptr == '/')									// found SOAP URL
			{
			int j;
			char *urlPtr = mDNSNULL;
			if (mDNSIPPortIsZero(m->UPnPSOAPPort)) m->UPnPSOAPPort = m->UPnPRouterPort;	// fill in default port if we didn't find one before

			urlPtr = ptr;
			for (j = 0; urlPtr && urlPtr != end; j++, urlPtr++) if (*urlPtr == '<') break;	// first find the next '<' and count the chars
			if (urlPtr == mDNSNULL || urlPtr == end) { LogOperation("handleLNTDeviceDescriptionResponse: didn't find SOAP URL string"); return; }

			// allocate the buffer (len j+2 because we're copying from the first '/' and so we have space to terminate the string)
			if (m->UPnPSOAPURL != mDNSNULL) mDNSPlatformMemFree(m->UPnPSOAPURL);
			if ((m->UPnPSOAPURL = (mDNSu8 *)mDNSPlatformMemAllocate(j+1)) == mDNSNULL) { LogMsg("can't mDNSPlatformMemAllocate SOAP URL"); return; }
			
			// now copy
			strncpy((char *)m->UPnPSOAPURL, ptr, j);			// this URL looks something like "/uuid:0013-108c-4b3f0000f3dc"
			m->UPnPSOAPURL[j] = '\0';					// terminate the string
			break;									// we've got everything we need, so get out here
			}
		ptr++;	// continue
		}

	// if we get to the end and haven't found the URL fill in the defaults
	if (m->UPnPSOAPURL == mDNSNULL)
		{
		m->UPnPSOAPURL  = m->UPnPRouterURL;				// just copy the pointer, don't allocate more memory
		m->UPnPSOAPPort = m->UPnPRouterPort;
		}
	
	LogOperation("handleLNTDeviceDescriptionResponse: SOAP URL [%s] port %d", m->UPnPSOAPURL, mDNSVal16(m->UPnPSOAPPort));
	}

mDNSlocal void handleLNTGetExternalAddressResponse(tcpLNTInfo *tcpInfo)
	{
	mDNS       *m = tcpInfo->m;
	mDNSu16     err = NATErr_None;
	mDNSv4Addr  ExtAddr;
	char       *ptr = (char *)tcpInfo->Reply;
	char       *end = (char *)tcpInfo->Reply + tcpInfo->nread;
	char       *addrend;
	static char tagname[20] = "NewExternalIPAddress";		// Array NOT including a terminating nul

//	LogOperation("handleLNTGetExternalAddressResponse: %s", ptr);

	while (ptr < end && strncasecmp(ptr, tagname, sizeof(tagname))) ptr++;
	ptr += sizeof(tagname);						// Skip over "NewExternalIPAddress"
	while (ptr < end && *ptr != '>') ptr++;
	ptr += 1;									// Skip over ">"
	// Find the end of the address and terminate the string so inet_pton() can convert it
	addrend = ptr;
	while (addrend < end && (mdnsIsDigit(*addrend) || *addrend == '.')) addrend++;
	if (addrend >= end) return;
	*addrend = 0;

	if (inet_pton(AF_INET, ptr, &ExtAddr) <= 0)
		{ LogMsg("handleLNTGetExternalAddressResponse: Router returned bad address %s", ptr); err = NATErr_NetFail; }
	if (!err) LogOperation("handleLNTGetExternalAddressResponse: External IP address is %.4a", &ExtAddr);

	natTraversalHandleAddressReply(m, err, ExtAddr);
	}

mDNSlocal void handleLNTPortMappingResponse(tcpLNTInfo *tcpInfo)
	{
	mDNS             *m       = tcpInfo->m;
	mDNSIPPort        extport = zeroIPPort;
	char             *ptr     = (char *)tcpInfo->Reply;
	char             *end     = (char *)tcpInfo->Reply + tcpInfo->nread;
	NATTraversalInfo *natInfo;

	for (natInfo = m->NATTraversals; natInfo; natInfo=natInfo->next) { if (natInfo == tcpInfo->parentNATInfo) break; }

	if (!natInfo) { LogOperation("handleLNTPortMappingResponse: can't find matching tcpInfo in NATTraversals!"); return; }

	// start from the beginning of the HTTP header; find "200 OK" status message; if the first characters after the
	// space are not "200" then this is an error message or invalid in some other way
	// if the error is "500" this is an internal server error
	while (ptr && ptr != end)
		{
		if (*ptr == ' ')
			{
			ptr++;
			if (ptr == end) { LogOperation("handleLNTPortMappingResponse: past end of buffer!"); return; }
			if      (strncasecmp(ptr, "200", 3) == 0) break;
			else if (strncasecmp(ptr, "500", 3) == 0)
				{
				// now check to see if this was a port mapping conflict
				while (ptr && ptr != end)
					{
					if ((*ptr == 'c' || *ptr == 'C') && strncasecmp(ptr, "Conflict", 8) == 0)
						{
						if (tcpInfo->retries < 100)
							{ tcpInfo->retries++; SendPortMapRequest(tcpInfo->m, natInfo); }
						else
							{
							LogMsg("handleLNTPortMappingResponse too many conflict retries %d %d", mDNSVal16(natInfo->IntPort), mDNSVal16(natInfo->RequestedPort));
							natTraversalHandlePortMapReply(m, natInfo, m->UPnPInterfaceID, NATErr_Refused, zeroIPPort, 0);
							}
						return;
						}
					ptr++;
					}
				break;	// out of HTTP status search
				}
			}
		ptr++;
		}
	if (ptr == mDNSNULL || ptr == end) return;
	
	LogOperation("handleLNTPortMappingResponse: got a valid response, sending reply to natTraversalHandlePortMapReply(internal %d external %d retries %d)",
		mDNSVal16(natInfo->IntPort), RequestedPortNum(natInfo), tcpInfo->retries);

	// Make sure to compute extport *before* we zero tcpInfo->retries
	extport = mDNSOpaque16fromIntVal(RequestedPortNum(natInfo));
	tcpInfo->retries = 0;
	natTraversalHandlePortMapReply(m, natInfo, m->UPnPInterfaceID, mStatus_NoError, extport, NATMAP_DEFAULT_LEASE);
	}

mDNSlocal void DisposeInfoFromUnmapList(mDNS *m, tcpLNTInfo *tcpInfo)
	{
	tcpLNTInfo **ptr = &m->tcpInfoUnmapList;
	while (*ptr && *ptr != tcpInfo) ptr = &(*ptr)->next;
	if (*ptr) { *ptr = (*ptr)->next; mDNSPlatformMemFree(tcpInfo); }	// If we found it, cut it from our list and free the memory
	}

mDNSlocal void tcpConnectionCallback(TCPSocket *sock, void *context, mDNSBool ConnectionEstablished, mStatus err)
	{
	mStatus     status  = mStatus_NoError;
	tcpLNTInfo *tcpInfo = (tcpLNTInfo *)context;
	mDNSBool    closed  = mDNSfalse;
	long        n       = 0;
	long        nsent   = 0;

	if (tcpInfo == mDNSNULL) { LogOperation("tcpConnectionCallback: no tcpInfo context"); status = mStatus_Invalid; goto exit; }

	// The handlers below expect to be called with the lock held
	mDNS_Lock(tcpInfo->m);
	
	if (err) { LogOperation("tcpConnectionCallback: received error"); goto exit; }

	if (ConnectionEstablished)		// connection is established - send the message
		{
		LogOperation("tcpConnectionCallback: connection established, sending message");
		nsent = mDNSPlatformWriteTCP(sock, (char *)tcpInfo->Request, tcpInfo->requestLen);
		if (nsent != (long)tcpInfo->requestLen) { LogMsg("tcpConnectionCallback: error writing"); status = mStatus_UnknownErr; goto exit; }
		}
	else
		{
		n = mDNSPlatformReadTCP(sock, (char *)tcpInfo->Reply + tcpInfo->nread, tcpInfo->replyLen - tcpInfo->nread, &closed);
		LogOperation("tcpConnectionCallback: mDNSPlatformReadTCP read %d bytes", n);

		if      (n < 0)  { LogOperation("tcpConnectionCallback - read returned %d", n);                           status = mStatus_ConnFailed; goto exit; }
		else if (closed) { LogOperation("tcpConnectionCallback: socket closed by remote end %d", tcpInfo->nread); status = mStatus_ConnFailed; goto exit; }

		tcpInfo->nread += n;
		LogOperation("tcpConnectionCallback tcpInfo->nread %d", tcpInfo->nread);
		if (tcpInfo->nread > LNT_MAXBUFSIZE)
			{
			LogOperation("result truncated...");
			tcpInfo->nread = LNT_MAXBUFSIZE;
			}

		switch (tcpInfo->op)
			{
			case LNTDiscoveryOp:     handleLNTDeviceDescriptionResponse (tcpInfo); break;
			case LNTExternalAddrOp:  handleLNTGetExternalAddressResponse(tcpInfo); break;
			case LNTPortMapOp:       handleLNTPortMappingResponse       (tcpInfo); break;
			case LNTPortMapDeleteOp: status = mStatus_ConfigChanged;               break;
			default: LogMsg("tcpConnectionCallback: bad tcp operation! %d", tcpInfo->op); status = mStatus_Invalid; break;
			}
		}
exit:
	if (err || status)
		{
		mDNSPlatformTCPCloseConnection(tcpInfo->sock);
		tcpInfo->sock = mDNSNULL;
		if (tcpInfo->Request) { mDNSPlatformMemFree(tcpInfo->Request); tcpInfo->Request = mDNSNULL; }
		if (tcpInfo->Reply  ) { mDNSPlatformMemFree(tcpInfo->Reply);   tcpInfo->Reply   = mDNSNULL; }
		}

	if (tcpInfo) mDNS_Unlock(tcpInfo->m);

	if (status == mStatus_ConfigChanged) DisposeInfoFromUnmapList(tcpInfo->m, tcpInfo);
	}

mDNSlocal mStatus MakeTCPConnection(mDNS *const m, tcpLNTInfo *info, const mDNSAddr *const Addr, const mDNSIPPort Port, LNTOp_t op)
	{
	mStatus err = mStatus_NoError;
	mDNSIPPort srcport = zeroIPPort;

	if (mDNSIPv4AddressIsZero(Addr->ip.v4) || mDNSIPPortIsZero(Port))
	    { LogMsg("LNT MakeTCPConnection: bad address/port %#a:%d", Addr, mDNSVal16(Port)); return(mStatus_Invalid); }
	info->m         = m;
	info->Address   = *Addr;
	info->Port      = Port;
	info->op        = op;
	info->nread     = 0;
	info->replyLen  = LNT_MAXBUFSIZE;
	if      (info->Reply != mDNSNULL)  mDNSPlatformMemZero(info->Reply, LNT_MAXBUFSIZE);   // reuse previously allocated buffer
	else if ((info->Reply = (mDNSs8 *) mDNSPlatformMemAllocate(LNT_MAXBUFSIZE)) == mDNSNULL) { LogOperation("can't allocate reply buffer"); return (mStatus_NoMemoryErr); }

	if (info->sock) { LogOperation("MakeTCPConnection: closing previous open connection"); mDNSPlatformTCPCloseConnection(info->sock); info->sock = mDNSNULL; }
	info->sock = mDNSPlatformTCPSocket(m, kTCPSocketFlags_Zero, &srcport);
	if (!info->sock) { LogMsg("LNT MakeTCPConnection: unable to create TCP socket"); mDNSPlatformMemFree(info->Reply); info->Reply = mDNSNULL; return(mStatus_NoMemoryErr); }
	LogOperation("MakeTCPConnection: connecting to %#a:%d", &info->Address, mDNSVal16(info->Port));
	err = mDNSPlatformTCPConnect(info->sock, Addr, Port, 0, tcpConnectionCallback, info);

	if      (err == mStatus_ConnPending) err = mStatus_NoError;
	else if (err == mStatus_ConnEstablished)
		{
		mDNS_DropLockBeforeCallback();
		tcpConnectionCallback(info->sock, info, mDNStrue, mStatus_NoError);
		mDNS_ReclaimLockAfterCallback();
		err = mStatus_NoError;
		}
	else
		{
		// Don't need to log this in customer builds -- it happens quite often during sleep, wake, configuration changes, etc.
		LogOperation("LNT MakeTCPConnection: connection failed");
		mDNSPlatformTCPCloseConnection(info->sock);	// Dispose the socket we created with mDNSPlatformTCPSocket() above
		info->sock = mDNSNULL;
		mDNSPlatformMemFree(info->Reply);
		info->Reply = mDNSNULL;
		}
	return(err);
	}

mDNSlocal unsigned int AddSOAPArguments(char *buf, unsigned int maxlen, int numArgs, Property *a)
	{
	static const char f1[] = "<%s>%s</%s>";
	static const char f2[] = "<%s xmlns:dt=\"urn:schemas-microsoft-com:datatypes\" dt:dt=\"%s\">%s</%s>";
	int i, len = 0;
	*buf = 0;
	for (i = 0; i < numArgs; i++)
		{
		if (a[i].type) len += mDNS_snprintf(buf + len, maxlen - len, f2, a[i].name, a[i].type, a[i].value, a[i].name);
		else           len += mDNS_snprintf(buf + len, maxlen - len, f1, a[i].name,            a[i].value, a[i].name);
		}
	return(len);
	}

mDNSlocal mStatus SendSOAPMsgControlAction(mDNS *m, tcpLNTInfo *info, char *Action, int numArgs, Property *Arguments, LNTOp_t op)
	{
	// SOAP message header format -
	//  - control URL
	//  - action (string)
	//  - router's host/port ("host:port")
	//  - content-length
	static const char header[] =
		"POST %s HTTP/1.1\r\n"
		"Content-Type: text/xml; charset=\"utf-8\"\r\n"
		"SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#%s\"\r\n"
		"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; Windows 9x)\r\n"
		"Host: %s\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n"
		"Pragma: no-cache\r\n"
		"\r\n"
		"%s\r\n";

	static const char body1[] =
		"<?xml version=\"1.0\"?>\r\n"
		"<SOAP-ENV:Envelope"
		" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\""
		" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">"
		"<SOAP-ENV:Body>"
		"<m:%s xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">";

	static const char body2[] =
		"</m:%s>"
		"</SOAP-ENV:Body>"
		"</SOAP-ENV:Envelope>\r\n";

	mStatus err;
	char   *body = (char *)&m->omsg;			// Typically requires 1110-1122 bytes; m->omsg is 8952 bytes, which is plenty
	int     bodyLen;

	if (m->UPnPSOAPURL == mDNSNULL || m->UPnPSOAPAddressString == mDNSNULL)	// if no SOAP URL or address exists get out here
		{ LogOperation("SendSOAPMsgControlAction: no SOAP URL or address string"); return mStatus_Invalid; }

	// Create body
	bodyLen  = mDNS_snprintf   (body,           sizeof(m->omsg),           body1,   Action);
	bodyLen += AddSOAPArguments(body + bodyLen, sizeof(m->omsg) - bodyLen, numArgs, Arguments);
	bodyLen += mDNS_snprintf   (body + bodyLen, sizeof(m->omsg) - bodyLen, body2,   Action);

	// Create info->Request; the header needs to contain the bodyLen in the "Content-Length" field
	if (!info->Request) info->Request = mDNSPlatformMemAllocate(LNT_MAXBUFSIZE);
	if (!info->Request) { LogMsg("SendSOAPMsgControlAction: Can't allocate info->Request"); return mStatus_NoMemoryErr; }
	info->requestLen = mDNS_snprintf((char *)info->Request, LNT_MAXBUFSIZE, header, m->UPnPSOAPURL, Action, m->UPnPSOAPAddressString, bodyLen, body);

	err = MakeTCPConnection(m, info, &m->Router, m->UPnPSOAPPort, op);
	if (err) { mDNSPlatformMemFree(info->Request); info->Request = mDNSNULL; }
	return err;
	}

// Build port mapping request with new port (up to max) and send it
mDNSlocal mStatus SendPortMapRequest(mDNS *m, NATTraversalInfo *n)
	{
	char              externalPort[6];
	char              internalPort[6];
	char              localIPAddrString[30];
	char              publicPortString[40];
	Property          propArgs[8];
	mDNSu16           ReqPortNum = RequestedPortNum(n);
	NATTraversalInfo *n2 = m->NATTraversals;

	// Scan our m->NATTraversals list to make sure the external port we're requesting is locally unique.
	// UPnP gateways will report conflicts if different devices request the same external port, but if two
	// clients on the same device request the same external port the second one just stomps over the first.
	// One way this can happen is like this:
	// 1. Client A binds local port 80
	// 2. Client A requests external port 80 -> internal port 80
	// 3. UPnP NAT gateway refuses external port 80 (some other client already has it)
	// 4. Client A tries again, and successfully gets external port 80 -> internal port 81
	// 5. Client B on same machine tries to bind local port 80, and fails
	// 6. Client B tries again, and successfully binds local port 81
	// 7. Client B now requests external port 81 -> internal port 81
	// 8. UPnP NAT gateway allows this, stomping over Client A's existing mapping

	while (n2)
		{
		if (n2 == n || RequestedPortNum(n2) != ReqPortNum) n2=n2->next;
		else
			{
			if (n->tcpInfo.retries < 100)
				{
				n->tcpInfo.retries++;
				ReqPortNum = RequestedPortNum(n);	// Pick a new port number
				n2 = m->NATTraversals;				// And re-scan the list looking for conflicts
				}
			else
				{
				natTraversalHandlePortMapReply(m, n, m->UPnPInterfaceID, NATErr_Refused, zeroIPPort, 0);
				return mStatus_NoError;
				}
			}
		}

	// create strings to use in the message
	mDNS_snprintf(externalPort,      sizeof(externalPort),      "%u",   ReqPortNum);
	mDNS_snprintf(internalPort,      sizeof(internalPort),      "%u",   mDNSVal16(n->IntPort));
	mDNS_snprintf(publicPortString,  sizeof(publicPortString),  "iC%u", ReqPortNum);
	mDNS_snprintf(localIPAddrString, sizeof(localIPAddrString), "%u.%u.%u.%u",
	    m->AdvertisedV4.ip.v4.b[0], m->AdvertisedV4.ip.v4.b[1], m->AdvertisedV4.ip.v4.b[2], m->AdvertisedV4.ip.v4.b[3]);

	// build the message
	mDNSPlatformMemZero(propArgs, sizeof(propArgs));
	propArgs[0].name  = "NewRemoteHost";
	propArgs[0].type  = "string";
	propArgs[0].value = "";
	propArgs[1].name  = "NewExternalPort";
	propArgs[1].type  = "ui2";
	propArgs[1].value = externalPort;
	propArgs[2].name  = "NewProtocol";
	propArgs[2].type  = "string";
	propArgs[2].value = (n->Protocol == NATOp_MapUDP) ? "UDP" : "TCP";
	propArgs[3].name  = "NewInternalPort";
	propArgs[3].type  = "ui2";
	propArgs[3].value = internalPort;
	propArgs[4].name  = "NewInternalClient";
	propArgs[4].type  = "string";
	propArgs[4].value = localIPAddrString;
	propArgs[5].name  = "NewEnabled";
	propArgs[5].type  = "boolean";
	propArgs[5].value = "1";
	propArgs[6].name  = "NewPortMappingDescription";
	propArgs[6].type  = "string";
	propArgs[6].value = publicPortString;
	propArgs[7].name  = "NewLeaseDuration";
	propArgs[7].type  = "ui4";
	propArgs[7].value = "0";

	LogOperation("SendPortMapRequest: internal %u external %u", mDNSVal16(n->IntPort), ReqPortNum);
	return SendSOAPMsgControlAction(m, &n->tcpInfo, "AddPortMapping", 8, propArgs, LNTPortMapOp);
	}

mDNSexport mStatus LNT_MapPort(mDNS *m, NATTraversalInfo *n)
	{
	LogOperation("LNT_MapPort");
	if (n->tcpInfo.sock) return(mStatus_NoError);	// If we already have a connection up don't make another request for the same thing
	n->tcpInfo.parentNATInfo = n;
	n->tcpInfo.retries       = 0;
	return SendPortMapRequest(m, n);
	}

mDNSexport mStatus LNT_UnmapPort(mDNS *m, NATTraversalInfo *n)
	{
	char        externalPort[10];
	Property    propArgs[3];
	tcpLNTInfo  *info;
	tcpLNTInfo  **infoPtr = &m->tcpInfoUnmapList;
	mStatus     err;

	// If no NAT gateway to talk to, no need to do all this work for nothing
	if (!m->UPnPSOAPURL || !m->UPnPSOAPAddressString) return mStatus_NoError;

	mDNS_snprintf(externalPort, sizeof(externalPort), "%u", mDNSVal16(mDNSIPPortIsZero(n->RequestedPort) ? n->IntPort : n->RequestedPort));

	mDNSPlatformMemZero(propArgs, sizeof(propArgs));
	propArgs[0].name  = "NewRemoteHost";
	propArgs[0].type  = "string";
	propArgs[0].value = "";
	propArgs[1].name  = "NewExternalPort";
	propArgs[1].type  = "ui2";
	propArgs[1].value = externalPort;
	propArgs[2].name  = "NewProtocol";
	propArgs[2].type  = "string";
	propArgs[2].value = (n->Protocol == NATOp_MapUDP) ? "UDP" : "TCP";

	n->tcpInfo.parentNATInfo = n;

	// clean up previous port mapping requests and allocations
	if (n->tcpInfo.sock) LogOperation("LNT_UnmapPort: closing previous open connection");
	if (n->tcpInfo.sock   ) { mDNSPlatformTCPCloseConnection(n->tcpInfo.sock); n->tcpInfo.sock    = mDNSNULL; }
	if (n->tcpInfo.Request) { mDNSPlatformMemFree(n->tcpInfo.Request);         n->tcpInfo.Request = mDNSNULL; }
	if (n->tcpInfo.Reply  ) { mDNSPlatformMemFree(n->tcpInfo.Reply);           n->tcpInfo.Reply   = mDNSNULL; }
	
	// make a copy of the tcpInfo that we can clean up later (the one passed in will be destroyed by the client as soon as this returns)
	if ((info = mDNSPlatformMemAllocate(sizeof(tcpLNTInfo))) == mDNSNULL)
		{ LogOperation("LNT_UnmapPort: can't allocate tcpInfo"); return(mStatus_NoMemoryErr); }
	*info = n->tcpInfo;
	
	while (*infoPtr) infoPtr = &(*infoPtr)->next;	// find the end of the list
	*infoPtr = info;    // append

	err = SendSOAPMsgControlAction(m, info, "DeletePortMapping", 3, propArgs, LNTPortMapDeleteOp);
	if (err) DisposeInfoFromUnmapList(m, info);
	return err;
	}

mDNSexport mStatus LNT_GetExternalAddress(mDNS *m)
	{
	return SendSOAPMsgControlAction(m, &m->tcpAddrInfo, "GetExternalIPAddress", 0, mDNSNULL, LNTExternalAddrOp);
	}

mDNSlocal mStatus GetDeviceDescription(mDNS *m, tcpLNTInfo *info)
	{
	// Device description format -
	//  - device description URL
	//  - host/port
	static const char szSSDPMsgDescribeDeviceFMT[] =
		"GET %s HTTP/1.1\r\n"
		"Accept: text/xml, application/xml\r\n"
		"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; Windows NT/5.1)\r\n"
		"Host: %s\r\n"
		"Connection: close\r\n"
		"\r\n";

	if (m->UPnPRouterURL == mDNSNULL || m->UPnPRouterAddressString == mDNSNULL)     { LogOperation("GetDeviceDescription: no router URL or address string!"); return (mStatus_Invalid); }

	// build message
	if      (info->Request != mDNSNULL)  mDNSPlatformMemZero(info->Request, LNT_MAXBUFSIZE); // reuse previously allocated buffer
	else if ((info->Request = (mDNSs8 *) mDNSPlatformMemAllocate(LNT_MAXBUFSIZE)) == mDNSNULL) { LogOperation("can't allocate send buffer for discovery"); return (mStatus_NoMemoryErr); }
	info->requestLen = mDNS_snprintf((char *)info->Request, LNT_MAXBUFSIZE, szSSDPMsgDescribeDeviceFMT, m->UPnPRouterURL, m->UPnPRouterAddressString);
	LogOperation("Describe Device: [%s]", info->Request);
	return MakeTCPConnection(m, info, &m->Router, m->UPnPRouterPort, LNTDiscoveryOp);
	}

// This function parses the response to our SSDP discovery message. Basically, we look to make sure this is a response
// referencing a service we care about (WANIPConnection), then look for the "Location:" header and copy the addressing and
// URL info we need.
mDNSexport void LNT_ConfigureRouterInfo(mDNS *m, const mDNSInterfaceID InterfaceID, mDNSu8 *data, mDNSu16 len)
	{
	char *ptr = (char *)data;
	char *end = (char *)data + len;

	// The formatting of the HTTP header is not always the same when it comes to the placement of
	// the service and location strings, so we just look for each of them from the beginning for every response
	
	// figure out if this is a message from a service we care about
	while (ptr && ptr != end)
		{
		if (*ptr == 'W' && (strncasecmp(ptr, "WANIPConnection:1", 17) == 0)) break;	// find the first 'W'; is this WANIPConnection? if not, keep looking
		ptr++;
		}
	if (ptr == mDNSNULL || ptr == end) return;	// not a message we care about

	// find "Location:", starting from the beginning
	ptr = (char *)data;
	while (ptr && ptr != end)
		{
		if (*ptr == 'L' && (strncasecmp(ptr, "Location", 8) == 0)) break;			// find the first 'L'; is this Location? if not, keep looking
		ptr++;
		}
	if (ptr == mDNSNULL || ptr == end) return;	// not a message we care about
	
	// find "http://", starting from where we left off
	while (ptr && ptr != end)
		{
		if (*ptr == 'h' && (strncasecmp(ptr, "http://", 7) == 0))					// find the first 'h'; is this a URL? if not, keep looking
			{
			int i;
			char *addrPtr = mDNSNULL;
			
			ptr += 7;							//skip over "http://"
			if (ptr >= end) { LogOperation("LNT_ConfigureRouterInfo: past end of buffer and no URL!"); return; }
			addrPtr = ptr;
			for (i = 0; addrPtr && addrPtr != end; i++, addrPtr++) if (*addrPtr == '/') break;	// first find the beginning of the URL and count the chars
			if (addrPtr == mDNSNULL || addrPtr == end) return; // not a valid message
	
			// allocate the buffer (len i+1 so we have space to terminate the string)
			if (m->UPnPRouterAddressString != mDNSNULL)  mDNSPlatformMemFree(m->UPnPRouterAddressString);
			if ((m->UPnPRouterAddressString = (mDNSu8 *) mDNSPlatformMemAllocate(i+1)) == mDNSNULL) { LogMsg("can't mDNSPlatformMemAllocate router address string"); return; }
			
			strncpy((char *)m->UPnPRouterAddressString, ptr, i);	// copy the address string
			m->UPnPRouterAddressString[i] = '\0';					// terminate the string
			LogOperation("LNT_ConfigureRouterInfo: router address string [%s]", m->UPnPRouterAddressString);
			break;
			}
		ptr++;	// continue
		}

	// find port and router URL, starting after the "http://" if it was there
	while (ptr && ptr != end)
		{
		if (*ptr == ':')										// found the port number
			{
			int port;
			ptr++;										// skip over ':'
			if (ptr == end) { LogOperation("LNT_ConfigureRouterInfo: reached end of buffer and no address!"); return; }
			port = (int)strtol(ptr, (char **)mDNSNULL, 10);			// get the port
			m->UPnPRouterPort = mDNSOpaque16fromIntVal(port);	// store it properly converted
			}
		else if (*ptr == '/')									// found router URL
			{
			int j;
			char *urlPtr;
			m->UPnPInterfaceID = InterfaceID;
			if (mDNSIPPortIsZero(m->UPnPRouterPort)) m->UPnPRouterPort = mDNSOpaque16fromIntVal(80);		// fill in default port if we didn't find one before
			
			urlPtr = ptr;
			for (j = 0; urlPtr && urlPtr != end; j++, urlPtr++) if (*urlPtr == '\r') break;	// first find the end of the line and count the chars
			if (urlPtr == mDNSNULL || urlPtr == end) return; // not a valid message
			
			// allocate the buffer (len j+1 so we have space to terminate the string)
			if (m->UPnPRouterURL != mDNSNULL) mDNSPlatformMemFree(m->UPnPRouterURL);
			if ((m->UPnPRouterURL = (mDNSu8 *) mDNSPlatformMemAllocate(j+1)) == mDNSNULL) { LogMsg("can't allocate router URL"); return; }
			
			// now copy everything to the end of the line
			strncpy((char *)m->UPnPRouterURL, ptr, j);			// this URL looks something like "/dyndev/uuid:0013-108c-4b3f0000f3dc"
			m->UPnPRouterURL[j] = '\0';					// terminate the string
			break;									// we've got everything we need, so get out here
			}
		ptr++;	// continue
		}

	if (ptr == mDNSNULL || ptr == end) return;	// not a valid message
	LogOperation("Router port %d, URL set to [%s]...", mDNSVal16(m->UPnPRouterPort), m->UPnPRouterURL);
	
	// Don't need the SSDP socket anymore
	if (m->SSDPSocket) { LogOperation("LNT_ConfigureRouterInfo destroying SSDPSocket %p", &m->SSDPSocket); mDNSPlatformUDPClose(m->SSDPSocket); m->SSDPSocket = mDNSNULL; }

	// now send message to get the device description
	GetDeviceDescription(m, &m->tcpDeviceInfo);
	}

mDNSexport void LNT_SendDiscoveryMsg(mDNS *m)
	{
	static const mDNSu8 msg[] =
		"M-SEARCH * HTTP/1.1\r\n"
		"Host:239.255.255.250:1900\r\n"
		"ST:urn:schemas-upnp-org:service:WANIPConnection:1\r\n"
		"Man:\"ssdp:discover\"\r\n"
		"MX:3\r\n\r\n";

	LogOperation("LNT_SendDiscoveryMsg Router %.4a Current External Address %.4a", &m->Router.ip.v4, &m->ExternalAddress);

	if (!mDNSIPv4AddressIsZero(m->Router.ip.v4) && mDNSIPv4AddressIsZero(m->ExternalAddress))
		{
		if (!m->SSDPSocket) { m->SSDPSocket = mDNSPlatformUDPSocket(m, zeroIPPort); LogOperation("LNT_SendDiscoveryMsg created SSDPSocket %p", &m->SSDPSocket); }
		mDNSPlatformSendUDP(m, msg, msg + sizeof(msg) - 1, 0, &m->Router, SSDPPort);
		}
	}

#endif /* _LEGACY_NAT_TRAVERSAL_ */
