/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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

$Log: mDNSMacOS9.c,v $
Revision 1.19  2003/08/18 23:09:20  cheshire
<rdar://problem/3382647> mDNSResponder divide by zero in mDNSPlatformTimeNow()

Revision 1.18  2003/08/12 19:56:24  cheshire
Update to APSL 2.0

 */

#include <LowMem.h>						// For LMGetCurApName()
#include <TextUtils.h>					// For smSystemScript
#include <UnicodeConverter.h>			// For ConvertFromPStringToUnicode()

#include <stdio.h>
#include <stdarg.h>						// For va_list support

#include "mDNSClientAPI.h"				// Defines the interface provided to the client layer above
#include "mDNSPlatformFunctions.h"		// Defines the interface to the supporting layer below

#include "mDNSMacOS9.h"					// Defines the specific types needed to run mDNS on this platform

// ***************************************************************************
// Constants

static const TSetBooleanOption kReusePortOption =
	{ sizeof(TSetBooleanOption),      INET_IP, IP_REUSEPORT,      0, true };

// IP_RCVDSTADDR gives error #-3151 (kOTBadOptionErr)
static const TSetBooleanOption kRcvDestAddrOption =
	{ sizeof(TSetBooleanOption),      INET_IP, IP_REUSEPORT,     0, true };

static const TIPAddMulticastOption kAddLinkMulticastOption  =
	{ sizeof(TIPAddMulticastOption), INET_IP, IP_ADD_MEMBERSHIP, 0, { 224,  0,  0,251 }, { 0,0,0,0 } };

static const TIPAddMulticastOption kAddAdminMulticastOption =
	{ sizeof(TIPAddMulticastOption), INET_IP, IP_ADD_MEMBERSHIP, 0, { 239,255,255,251 }, { 0,0,0,0 } };

// Bind endpoint to port number. Don't specify any specific IP address --
// we want to receive unicasts on all interfaces, as well as multicasts.
typedef struct { OTAddressType fAddressType; mDNSIPPort fPort; mDNSv4Addr fHost; UInt8 fUnused[8]; } mDNSInetAddress;
//static const mDNSInetAddress mDNSPortInetAddress = { AF_INET, { 0,0 }, { 0,0,0,0 } };	// For testing legacy client support
#define MulticastDNSPortAsNumber 5353
static const mDNSInetAddress mDNSPortInetAddress = { AF_INET, { MulticastDNSPortAsNumber >> 8, MulticastDNSPortAsNumber & 0xFF }, { 0,0,0,0 } };
static const TBind mDNSbindReq = { sizeof(mDNSPortInetAddress), sizeof(mDNSPortInetAddress), (UInt8*)&mDNSPortInetAddress, 0 };

static const TNetbuf zeroTNetbuf = { 0 };

// ***************************************************************************
// Functions

#if MDNS_DEBUGMSGS
mDNSexport void debugf_(const char *format, ...)
	{
	unsigned char buffer[256];
    va_list ptr;
	va_start(ptr,format);
	buffer[0] = (unsigned char)mDNS_vsnprintf((char*)buffer+1, 255, format, ptr);
	va_end(ptr);
#if __ONLYSYSTEMTASK__
	buffer[1+buffer[0]] = 0;
	fprintf(stderr, "%s\n", buffer+1);
	fflush(stderr);
#else
	DebugStr(buffer);
#endif
	}
#endif

mDNSexport void LogMsg(const char *format, ...)
	{
	unsigned char buffer[256];
    va_list ptr;
	va_start(ptr,format);
	buffer[0] = (unsigned char)mDNS_vsnprintf((char*)buffer+1, 255, format, ptr);
	va_end(ptr);
#if __ONLYSYSTEMTASK__
	buffer[1+buffer[0]] = 0;
	fprintf(stderr, "%s\n", buffer+1);
	fflush(stderr);
#else
	DebugStr(buffer);
#endif
	}

mDNSexport mStatus mDNSPlatformSendUDP(const mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end,
	mDNSInterfaceID InterfaceID, mDNSIPPort srcPort, const mDNSAddr *dst, mDNSIPPort dstPort)
	{
	// Note: If we did multi-homing, we'd have to use the InterfaceID parameter to specify from which interface to send this response
	#pragma unused(InterfaceID, srcPort)

	InetAddress InetDest;
	TUnitData senddata;
	
	InetDest.fAddressType = AF_INET;
	InetDest.fPort        = dstPort.NotAnInteger;
	InetDest.fHost        = dst->ip.v4.NotAnInteger;

	senddata.addr .maxlen = sizeof(InetDest);
	senddata.addr .len    = sizeof(InetDest);
	senddata.addr .buf    = (UInt8*)&InetDest;
	senddata.opt          = zeroTNetbuf;
	senddata.udata.maxlen = (UInt32)((UInt8*)end - (UInt8*)msg);
	senddata.udata.len    = (UInt32)((UInt8*)end - (UInt8*)msg);
	senddata.udata.buf    = (UInt8*)msg;
	
	return(OTSndUData(m->p->ep, &senddata));
	}

mDNSlocal OSStatus readpacket(mDNS *m)
	{
	mDNSAddr senderaddr, destaddr;
	mDNSInterfaceID interface;
	mDNSIPPort senderport;
	InetAddress sender;
	char options[512];
	DNSMessage packet;
	TUnitData recvdata;
	OTFlags flags = 0;
	OSStatus err;
	
	recvdata.addr .maxlen = sizeof(sender);
	recvdata.addr .len    = 0;
	recvdata.addr .buf    = (UInt8*)&sender;
	recvdata.opt  .maxlen = sizeof(options);
	recvdata.opt  .len    = 0;
	recvdata.opt  .buf    = (UInt8*)&options;
	recvdata.udata.maxlen = sizeof(packet);
	recvdata.udata.len    = 0;
	recvdata.udata.buf    = (UInt8*)&packet;
	
	err = OTRcvUData(m->p->ep, &recvdata, &flags);
	if (err && err != kOTNoDataErr) debugf("OTRcvUData error %d", err);
	
	if (err) return(err);

	senderaddr.type = mDNSAddrType_IPv4;
	senderaddr.ip.v4.NotAnInteger = sender.fHost;
	senderport.NotAnInteger = sender.fPort;
	destaddr.type = mDNSAddrType_IPv4;
	destaddr.ip.v4  = AllDNSLinkGroup;		// For now, until I work out how to get the dest address, assume it was sent to AllDNSLinkGroup
	interface = m->HostInterfaces->InterfaceID;
	
	if (recvdata.opt.len) debugf("readpacket: got some option data at %X, len %d", options, recvdata.opt.len);

	if      (flags & T_MORE)                                debugf("ERROR: OTRcvUData() buffer too small (T_MORE set)");
	else if (recvdata.addr.len < sizeof(InetAddress))       debugf("ERROR: recvdata.addr.len (%d) too short", recvdata.addr.len);
	else if (recvdata.udata.len < sizeof(DNSMessageHeader)) debugf("ERROR: recvdata.udata.len (%d) too short", recvdata.udata.len);
	else mDNSCoreReceive(m, &packet, recvdata.udata.buf + recvdata.udata.len, &senderaddr, senderport, &destaddr, MulticastDNSPort, interface, 255);
	
	return(err);
	}


mDNSlocal void mDNSOptionManagement(mDNS *const m)
	{
	OSStatus err;

	// Make sure the length in the TNetbuf agrees with the length in the TOptionHeader
	m->p->optReq.opt.len = m->p->optBlock.h.len;
	err = OTOptionManagement(m->p->ep, &m->p->optReq, NULL);
	if (err) debugf("OTOptionManagement failed %d", err);
	}

mDNSlocal void mDNSinitComplete(mDNS *const m, mStatus result)
	{
	m->mDNSPlatformStatus = result;
	mDNSCoreInitComplete(m, mStatus_NoError);
	}

mDNSlocal pascal void mDNSNotifier(void *contextPtr, OTEventCode code, OTResult result, void *cookie)
	{
	mDNS *const m = (mDNS *const)contextPtr;
	if (!m) debugf("mDNSNotifier FATAL ERROR! No context");
	switch (code)
		{
		case T_OPENCOMPLETE:
			{
			OSStatus err;
			InetInterfaceInfo interfaceinfo;
			if (result) { debugf("T_OPENCOMPLETE failed %d", result); mDNSinitComplete(m, result); return; }
			//debugf("T_OPENCOMPLETE");
			m->p->ep = (EndpointRef)cookie;
			//debugf("OTInetGetInterfaceInfo");
			// (In future may want to loop over all interfaces instead of just using kDefaultInetInterface)
			err = OTInetGetInterfaceInfo(&interfaceinfo, kDefaultInetInterface);
			if (err) { debugf("OTInetGetInterfaceInfo failed %d", err); mDNSinitComplete(m, err); return; }

			// Make our basic standard host resource records (address, PTR, etc.)
			m->p->interface.ip.type               = mDNSAddrType_IPv4;
			m->p->interface.ip.ip.v4.NotAnInteger = interfaceinfo.fAddress;
			m->p->interface.Advertise             = m->AdvertiseLocalAddresses;
			m->p->interface.InterfaceID           = (mDNSInterfaceID)&m->p->interface;
			mDNS_RegisterInterface(m, &m->p->interface);
			}
			
		case T_OPTMGMTCOMPLETE:
			if (result) { debugf("T_OPTMGMTCOMPLETE failed %d", result); mDNSinitComplete(m, result); return; }
			//debugf("T_OPTMGMTCOMPLETE");
			switch (++m->p->mOTstate)
				{
				case mOT_ReusePort:		m->p->optBlock.b = kReusePortOption;         mDNSOptionManagement(m); break;
				case mOT_RcvDestAddr:	m->p->optBlock.b = kRcvDestAddrOption;       mDNSOptionManagement(m); break;
				case mOT_LLScope:		m->p->optBlock.m = kAddLinkMulticastOption;  mDNSOptionManagement(m); break;
				case mOT_AdminScope:	m->p->optBlock.m = kAddAdminMulticastOption; mDNSOptionManagement(m); break;
				case mOT_Bind:			OTBind(m->p->ep, (TBind*)&mDNSbindReq, NULL); break;
				}
			break;

		case T_BINDCOMPLETE:
			if (result) { debugf("T_BINDCOMPLETE failed %d", result); return; }
			if (m->p->mOTstate != mOT_Bind) { debugf("T_BINDCOMPLETE in wrong mDNS state %d", m->p->mOTstate); return; }
			m->p->mOTstate++;
			//debugf("T_BINDCOMPLETE");
			mDNSinitComplete(m, mStatus_NoError);
			break;

		case T_DATA:
			//debugf("T_DATA");
			while (readpacket(m) == kOTNoError) continue;	// Read packets until we run out
			break;

		case kOTProviderWillClose:
		case kOTProviderIsClosed:		// Machine is going to sleep, shutting down, or reconfiguring IP
			if (m->p->ep) { OTCloseProvider(m->p->ep); m->p->ep = NULL; }
			break;						// Do we need to do anything?

		default: debugf("mDNSNotifier: Unexpected OTEventCode %X", code);
			break;
		}
	}

#if __ONLYSYSTEMTASK__

static Boolean     ONLYSYSTEMTASKevent;
static void       *ONLYSYSTEMTASKcontextPtr;
static OTEventCode ONLYSYSTEMTASKcode;
static OTResult    ONLYSYSTEMTASKresult;
static void       *ONLYSYSTEMTASKcookie;

mDNSlocal pascal void CallmDNSNotifier(void *contextPtr, OTEventCode code, OTResult result, void *cookie)
	{
	ONLYSYSTEMTASKcontextPtr = contextPtr;
	ONLYSYSTEMTASKcode       = code;
	ONLYSYSTEMTASKresult     = result;
	ONLYSYSTEMTASKcookie     = cookie;
	}

#else

mDNSlocal pascal void CallmDNSNotifier(void *contextPtr, OTEventCode code, OTResult result, void *cookie)
	{
	mDNS *const m = (mDNS *const)contextPtr;
	if (!m) debugf("mDNSNotifier FATAL ERROR! No context");
	
	// Increment m->p->nesting to indicate to mDNSPlatformLock that there's no need
	// to call OTEnterNotifier() (because we're already in OTNotifier context)
	if (m->p->nesting) DebugStr("\pCallmDNSNotifier ERROR! OTEnterNotifier is supposed to suppress notifier callbacks");
	m->p->nesting++;
	mDNSNotifier(contextPtr, code, result, cookie);
	m->p->nesting--;
	ScheduleNextTimerCallback(m);
	}

#endif

mDNSlocal OSStatus mDNSOpenEndpoint(const mDNS *const m)
	{
	OSStatus err;
	TEndpointInfo endpointinfo;
	// m->optReq is pre-set to point to the shared m->optBlock
	// m->optBlock is filled in by each OTOptionManagement call
	m->p->optReq.opt.maxlen = sizeof(m->p->optBlock);
	m->p->optReq.opt.len    = sizeof(m->p->optBlock);
	m->p->optReq.opt.buf    = (UInt8*)&m->p->optBlock;
	m->p->optReq.flags      = T_NEGOTIATE;

	// Open an endpoint and start answering queries
	//printf("Opening endpoint now...\n");
	m->p->ep = NULL;
	m->p->mOTstate = mOT_Start;
//	err = OTAsyncOpenEndpoint(OTCreateConfiguration("udp(RxICMP=1)"), 0, &endpointinfo, CallmDNSNotifier, (void*)m); // works
//	err = OTAsyncOpenEndpoint(OTCreateConfiguration("udp(RxICMP)"), 0, &endpointinfo, CallmDNSNotifier, (void*)m); // -3151 bad option
//	err = OTAsyncOpenEndpoint(OTCreateConfiguration("udp,ip(RxICMP=1)"), 0, &endpointinfo, CallmDNSNotifier, (void*)m); // -3151
//	err = OTAsyncOpenEndpoint(OTCreateConfiguration("udp,ip"), 0, &endpointinfo, CallmDNSNotifier, (void*)m); // works
//	err = OTAsyncOpenEndpoint(OTCreateConfiguration("udp,rawip"), 0, &endpointinfo, CallmDNSNotifier, (void*)m); // -3221 invalid arg
	err = OTAsyncOpenEndpoint(OTCreateConfiguration(kUDPName), 0, &endpointinfo, NewOTNotifyUPP(CallmDNSNotifier), (void*)m);
	if (err) { debugf("ERROR: OTAsyncOpenEndpoint(UDP) failed with error <%d>", err); return(err); }
	
	return(kOTNoError);
	}

// Define these here because they're not in older versions of OpenTransport.h
enum
	{
	xOTStackIsLoading   = 0x27000001,	/* Sent before Open Transport attempts to load the TCP/IP protocol stack.*/
	xOTStackWasLoaded   = 0x27000002,	/* Sent after the TCP/IP stack has been successfully loaded.*/
	xOTStackIsUnloading = 0x27000003	/* Sent before Open Transport unloads the TCP/IP stack.*/
	};

static mDNS *ClientNotifierContext;

mDNSlocal pascal void ClientNotifier(void *contextPtr, OTEventCode code, OTResult result, void *cookie)
	{
	mDNS *const m = ClientNotifierContext;

	#pragma unused(contextPtr)		// Usually zero (except one in the 'xOTStackIsLoading' case)
	#pragma unused(cookie)			// Usually 'ipv4' (except for kOTPortNetworkChange)
	#pragma unused(result)			// Usually zero

	switch (code)
		{
		case xOTStackIsLoading:   break;
		case xOTStackWasLoaded:   m->mDNSPlatformStatus = mStatus_Waiting; m->p->mOTstate = mOT_Reset; break;
		case xOTStackIsUnloading: break;
		case kOTPortNetworkChange: break;
		default: debugf("ClientNotifier unknown code %X, %X, %d", contextPtr, code, result); break;
		}
	}

#if TARGET_API_MAC_CARBON

mDNSlocal void GetUserSpecifiedComputerName(domainlabel *const namelabel)
	{
	CFStringRef cfs = CSCopyMachineName();
	CFStringGetPascalString(cfs, namelabel->c, sizeof(*namelabel), kCFStringEncodingUTF8);
	CFRelease(cfs);
	}

#else

mDNSlocal OSStatus ConvertStringHandleToUTF8(const StringHandle machineName, UInt8 *const utf8, ByteCount maxlen)
	{
	OSStatus status;
	TextEncoding utf8TextEncoding, SystemTextEncoding;
	UnicodeMapping theMapping;
	TextToUnicodeInfo textToUnicodeInfo;		
	ByteCount unicodelen = 0;
	
	if (maxlen > 255) maxlen = 255;	// Can't put more than 255 in a Pascal String

	utf8TextEncoding = CreateTextEncoding(kTextEncodingUnicodeDefault, kTextEncodingDefaultVariant, kUnicodeUTF8Format);
	UpgradeScriptInfoToTextEncoding(smSystemScript, kTextLanguageDontCare, kTextRegionDontCare, NULL, &SystemTextEncoding);
	theMapping.unicodeEncoding = utf8TextEncoding;
	theMapping.otherEncoding   = SystemTextEncoding;
	theMapping.mappingVersion  = kUnicodeUseLatestMapping;
	status = CreateTextToUnicodeInfo(&theMapping, &textToUnicodeInfo);
	if (status == noErr)
		{
		status = ConvertFromPStringToUnicode(textToUnicodeInfo, *machineName, maxlen, &unicodelen, (UniCharArrayPtr)&(utf8[1]));
		DisposeTextToUnicodeInfo(&textToUnicodeInfo);
		}
	utf8[0] = (UInt8)unicodelen;
	return(status);
	}

mDNSlocal void GetUserSpecifiedComputerName(domainlabel *const namelabel)
	{
	StringHandle machineName = GetString(-16413);	// Get machine name set in file sharing
	if (machineName)
		{
		char machineNameState = HGetState((Handle)machineName);
		HLock((Handle)machineName);
		ConvertStringHandleToUTF8(machineName, namelabel->c, MAX_DOMAIN_LABEL);
		HSetState((Handle)machineName, machineNameState);
		}
	}

#endif

static pascal void mDNSTimerTask(void *arg)
	{
#if __ONLYSYSTEMTASK__
#pragma unused(arg)
	ONLYSYSTEMTASKevent = true;
#else
	mDNS *const m = (mDNS *const)arg;
	// Increment m->p->nesting to indicate to mDNSPlatformLock that there's no need
	// to call OTEnterNotifier() (because we're already in OTNotifier context)
	if (m->p->nesting) DebugStr("\pmDNSTimerTask ERROR! OTEnterNotifier is supposed to suppress timer callbacks too");
	m->p->nesting++;
	mDNS_Execute(m);
	m->p->nesting--;
	ScheduleNextTimerCallback(m);
#endif
	}

#if TEST_SLEEP
long sleep, wake, mode;
#endif

mDNSexport mStatus mDNSPlatformInit(mDNS *const m)
	{
	OSStatus err;
	
	// Set up the nice label
	m->nicelabel.c[0] = 0;
	GetUserSpecifiedComputerName(&m->nicelabel);
//	m->nicelabel = *(domainlabel*)"\pStu";	// For conflict testing
	if (m->nicelabel.c[0] == 0) MakeDomainLabelFromLiteralString(&m->nicelabel, "Macintosh");

	// Set up the RFC 1034-compliant label
	m->hostlabel.c[0] = 0;
	ConvertUTF8PstringToRFC1034HostLabel(m->nicelabel.c, &m->hostlabel);
	if (m->hostlabel.c[0] == 0) MakeDomainLabelFromLiteralString(&m->hostlabel, "Macintosh");

	mDNS_GenerateFQDN(m);

	ClientNotifierContext = m;

#if !TARGET_API_MAC_CARBON
	err = OTRegisterAsClient(LMGetCurApName(), NewOTNotifyUPP(ClientNotifier));
	if (err) debugf("OTRegisterAsClient failed %d", err);
#endif
	
	err = mDNSOpenEndpoint(m);
	if (err) { debugf("mDNSOpenEndpoint failed %d", err); return(err); }

	m->p->OTTimerTask = OTCreateTimerTask(NewOTProcessUPP(mDNSTimerTask), m);
	m->p->nesting     = 0;

#if TEST_SLEEP
	sleep = TickCount() + 600;
	wake = TickCount() + 1200;
	mode = 0;
#endif

	return(err);
	}

extern void mDNSPlatformClose (mDNS *const m)
	{
	if (m->p->OTTimerTask) { OTDestroyTimerTask(m->p->OTTimerTask); m->p->OTTimerTask = 0;    }
	if (m->p->ep)          { OTCloseProvider   (m->p->ep);          m->p->ep          = NULL; }
	CloseOpenTransport();
	}

extern void mDNSPlatformIdle(mDNS *const m);
mDNSexport void mDNSPlatformIdle(mDNS *const m)
	{
#if __ONLYSYSTEMTASK__
	while (ONLYSYSTEMTASKcontextPtr)
		{
		void *contextPtr = ONLYSYSTEMTASKcontextPtr;
		ONLYSYSTEMTASKcontextPtr = NULL;
		mDNSNotifier(contextPtr, ONLYSYSTEMTASKcode, ONLYSYSTEMTASKresult, ONLYSYSTEMTASKcookie);
		}
	if (ONLYSYSTEMTASKevent)
		{
		ONLYSYSTEMTASKevent = false;
		mDNS_Execute(m);
		}
#endif

	if (m->p->mOTstate == mOT_Reset)
		{
		printf("\n");
		printf("******************************************************************************\n");
		printf("\n");
		printf("Reopening endpoint\n");
		mDNSOpenEndpoint(m);
		m->ResourceRecords = NULL;
		}

#if TEST_SLEEP
	switch (mode)
		{
		case 0: if ((long)TickCount() - sleep >= 0) { mDNSCoreMachineSleep(m, 1); mode++; }
				break;
		case 1: if ((long)TickCount() - wake >= 0) { mDNSCoreMachineSleep(m, 0); mode++; }
				break;
		}
#endif

	}

mDNSexport void    mDNSPlatformLock(const mDNS *const m)
	{
	if (!m) { DebugStr("\pmDNSPlatformLock m NULL!"); return; }
	if (!m->p) { DebugStr("\pmDNSPlatformLock m->p NULL!"); return; }
	if (!m->p->ep) { DebugStr("\pmDNSPlatformLock m->p->ep NULL!"); return; }

	// If we try to call OTEnterNotifier and fail because we're already running at
	// Notifier context, then make sure we don't do the matching OTLeaveNotifier() on exit.
	if (m->p->nesting || OTEnterNotifier(m->p->ep) == false) m->p->nesting++;
	}

mDNSlocal void ScheduleNextTimerCallback(const mDNS *const m)
	{
	SInt32 interval;
	interval = m->NextScheduledEvent - mDNSPlatformTimeNow();
	if      (interval < 0)                 interval = 0;
	else if (interval > 0x7FFFFFFF / 1000) interval = 0x7FFFFFFF / mDNSPlatformOneSecond;
	else                                   interval = interval * 1000 / mDNSPlatformOneSecond;
	//debugf("mDNSPlatformScheduleTask Interval %d", interval);
	OTScheduleTimerTask(m->p->OTTimerTask, (OTTimeout)interval);
	}

mDNSexport void    mDNSPlatformUnlock(const mDNS *const m)
	{
	if (!m) { DebugStr("\pmDNSPlatformUnlock m NULL!"); return; }
	if (!m->p) { DebugStr("\pmDNSPlatformUnlock m->p NULL!"); return; }
	if (!m->p->ep) { DebugStr("\pmDNSPlatformUnlock m->p->ep NULL!"); return; }
	if (m->p->nesting) m->p->nesting--;
	else
		{
		ScheduleNextTimerCallback(m);
		OTLeaveNotifier(m->p->ep);
		}
	}

mDNSexport void     mDNSPlatformStrCopy(const void *src,       void *dst)             { OTStrCopy((char*)dst, (char*)src); }
mDNSexport UInt32   mDNSPlatformStrLen (const void *src)                              { return(OTStrLength((char*)src)); }
mDNSexport void     mDNSPlatformMemCopy(const void *src,       void *dst, UInt32 len) { OTMemcpy(dst, src, len); }
mDNSexport mDNSBool mDNSPlatformMemSame(const void *src, const void *dst, UInt32 len) { return(OTMemcmp(dst, src, len)); }
mDNSexport void     mDNSPlatformMemZero(                       void *dst, UInt32 len) { OTMemzero(dst, len); }
mDNSexport void *   mDNSPlatformMemAllocate(mDNSu32 len)                              { return(OTAllocMem(len)); }
mDNSexport void     mDNSPlatformMemFree    (void *mem)                                { OTFreeMem(mem); }
mDNSexport mStatus  mDNSPlatformTimeInit(mDNSs32 *timenow) { *timenow = mDNSPlatformTimeNow(); return(mStatus_NoError); }
mDNSexport SInt32   mDNSPlatformTimeNow()                                             { return((SInt32)TickCount()); }
mDNSexport SInt32   mDNSPlatformOneSecond = 60;
