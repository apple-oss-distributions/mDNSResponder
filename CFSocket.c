/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * The contents of this file constitute Original Code as defined in
 * and are subject to the Apple Public Source License Version 1.1
 * (the "License").  You may not use this file except in compliance
 * with the License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 *
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

// ***************************************************************************
// mDNS-CFSocket.c:
// Supporting routines to run mDNS on a CFRunLoop platform
// ***************************************************************************

// Open Transport 2.7.x on Mac OS 9 used to send Multicast DNS queries to UDP port 53,
// before the Multicast DNS port was changed to 5353. For this reason, the mDNSResponder
// in earlier versions of Mac OS X 10.2 Jaguar used to set mDNS_AllowPort53 to 1 to allow
// it to also listen and answer queries on UDP port 53. Now that Transport 2.8 (included in
// the Classic subsystem of Mac OS X 10.2 Jaguar) has been corrected to issue Multicast DNS
// queries on UDP port 5353, this backwards-compatibility legacy support is no longer needed.
#define mDNS_AllowPort53 1

// Normally mDNSResponder is advertising local services on all active interfaces.
// However, should you wish to build a query-only mDNS client, setting mDNS_AdvertiseLocalAddresses
// to zero will cause CFSocket.c to not set the Advertise flag in its mDNS_RegisterInterface calls.
int mDNS_AdvertiseLocalAddresses = 1;

void (*NotifyClientNetworkChanged)(void);

#include "mDNSClientAPI.h"           // Defines the interface provided to the client layer above
#include "mDNSPlatformFunctions.h"   // Defines the interface to the supporting layer below
#include "mDNSPlatformEnvironment.h" // Defines the specific types needed to run mDNS on this platform
#include "mDNSvsprintf.h"            // Used to implement debugf_();

#include <stdio.h>
#include <stdarg.h>                  // For va_list support
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/socket.h>

// Code contributed by Dave Heller:
// Define RUN_ON_PUMA_WITHOUT_IFADDRS to compile code that will
// work on Mac OS X 10.1, which does not have the getifaddrs call.
#define RUN_ON_PUMA_WITHOUT_IFADDRS 0

#if RUN_ON_PUMA_WITHOUT_IFADDRS

#include <sys/ioctl.h>
#include <sys/sockio.h>
#define ifaddrs ifa_info
#ifndef	ifa_broadaddr
#define	ifa_broadaddr	ifa_dstaddr	/* broadcast address interface */
#endif
#include <sys/cdefs.h>

#else

#include <ifaddrs.h>

#endif

#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>

// ***************************************************************************
// Structures

typedef struct NetworkInterfaceInfo2_struct NetworkInterfaceInfo2;
struct NetworkInterfaceInfo2_struct
	{
	NetworkInterfaceInfo ifinfo;
	mDNS *m;
	char *ifa_name;
	NetworkInterfaceInfo2 *alias;
	int socket;
	CFSocketRef cfsocket;
#if mDNS_AllowPort53
	int socket53;
	CFSocketRef cfsocket53;
#endif
	};

// ***************************************************************************
// Functions

mDNSexport void debugf_(const char *format, ...)
	{
	unsigned char buffer[512];
	va_list ptr;
	va_start(ptr,format);
	buffer[mDNS_vsprintf((char *)buffer, format, ptr)] = 0;
	va_end(ptr);
	fprintf(stderr, "%s\n", buffer);
	fflush(stderr);
	}

mDNSexport mStatus mDNSPlatformSendUDP(const mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end,
	mDNSIPAddr src, mDNSIPPort srcport, mDNSIPAddr dst, mDNSIPPort dstport)
	{
	NetworkInterfaceInfo2 *info = (NetworkInterfaceInfo2 *)(m->HostInterfaces);
	struct sockaddr_in to;
	to.sin_family      = AF_INET;
	to.sin_port        = dstport.NotAnInteger;
	to.sin_addr.s_addr = dst.    NotAnInteger;

	if (src.NotAnInteger == 0) debugf("mDNSPlatformSendUDP ERROR! Cannot send from zero source address");

	while (info)
		{
		if (info->ifinfo.ip.NotAnInteger == src.NotAnInteger)
			{
			int s, err;
			if      (srcport.NotAnInteger == MulticastDNSPort.NotAnInteger) s = info->socket;
#if mDNS_AllowPort53
			else if (srcport.NotAnInteger == UnicastDNSPort.NotAnInteger  ) s = info->socket53;
#endif
			else { debugf("Source port %d not allowed", (mDNSu16)srcport.b[0]<<8 | srcport.b[1]); return(-1); }
			err = sendto(s, msg, (UInt8*)end - (UInt8*)msg, 0, (struct sockaddr *)&to, sizeof(to));
			if (err < 0) { perror("mDNSPlatformSendUDP sendto"); return(err); }
			}
		info = (NetworkInterfaceInfo2 *)(info->ifinfo.next);
		}

	return(mStatus_NoError);
	}

static ssize_t myrecvfrom(const int s, void *const buffer, const size_t max,
	struct sockaddr *const from, size_t *const fromlen, struct in_addr *dstaddr, char ifname[128])
	{
	struct iovec databuffers = { (char *)buffer, max };
	struct msghdr   msg;
	ssize_t         n;
	struct cmsghdr *cmPtr;
	char            ancillary[1024];

	// Set up the message
	msg.msg_name       = (caddr_t)from;
	msg.msg_namelen    = *fromlen;
	msg.msg_iov        = &databuffers;
	msg.msg_iovlen     = 1;
	msg.msg_control    = (caddr_t)&ancillary;
	msg.msg_controllen = sizeof(ancillary);
	msg.msg_flags      = 0;
	
	// Receive the data
	n = recvmsg(s, &msg, 0);
	if (n<0 || msg.msg_controllen < sizeof(struct cmsghdr) || (msg.msg_flags & MSG_CTRUNC))
		{ perror("recvmsg"); return(n); }
	
	*fromlen = msg.msg_namelen;
	
	// Parse each option out of the ancillary data.
	for (cmPtr = CMSG_FIRSTHDR(&msg); cmPtr; cmPtr = CMSG_NXTHDR(&msg, cmPtr))
		{
		// debugf("myrecvfrom cmsg_level %d cmsg_type %d", cmPtr->cmsg_level, cmPtr->cmsg_type);
		if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVDSTADDR)
			*dstaddr = *(struct in_addr *)CMSG_DATA(cmPtr);
		if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVIF)
			{
			struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmPtr);
			if (sdl->sdl_nlen < sizeof(ifname))
				{
				mDNSPlatformMemCopy(sdl->sdl_data, ifname, sdl->sdl_nlen);
				ifname[sdl->sdl_nlen] = 0;
				// debugf("IP_RECVIF sdl_index %d, sdl_data %s len %d", sdl->sdl_index, ifname, sdl->sdl_nlen);
				}
			}
		}

	return(n);
	}

mDNSlocal void myCFSocketCallBack(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *context)
	{
	mDNSIPAddr senderaddr, destaddr;
	mDNSIPPort senderport;
	NetworkInterfaceInfo2 *info = (NetworkInterfaceInfo2 *)context;
	mDNS *const m = info->m;
	DNSMessage packet;
	struct in_addr to;
	struct sockaddr_in from;
	size_t fromlen = sizeof(from);
	char packetifname[128] = "";
	int err;
	
	(void)address;	// Parameter not used
	(void)data;		// Parameter not used
	
	if (type != kCFSocketReadCallBack) debugf("myCFSocketCallBack: Why is type not kCFSocketReadCallBack?");
#if mDNS_AllowPort53
	if (s == info->cfsocket53)
		err = myrecvfrom(info->socket53, &packet, sizeof(packet), (struct sockaddr *)&from, &fromlen, &to, packetifname);
	else
#endif
	err = myrecvfrom(info->socket, &packet, sizeof(packet), (struct sockaddr *)&from, &fromlen, &to, packetifname);

	if (err < 0) { debugf("myCFSocketCallBack recvfrom error %d", err); return; }

	senderaddr.NotAnInteger = from.sin_addr.s_addr;
	senderport.NotAnInteger = from.sin_port;
	destaddr.NotAnInteger   = to.s_addr;

	// Even though we indicated a specific interface in the IP_ADD_MEMBERSHIP call, a weirdness of the
	// sockets API means that even though this socket has only officially joined the multicast group
	// on one specific interface, the kernel will still deliver multicast packets to it no matter which
	// interface they arrive on. According to the official Unix Powers That Be, this is Not A Bug.
	// To work around this weirdness, we use the IP_RECVIF option to find the name of the interface
	// on which the packet arrived, and ignore the packet if it really arrived on some other interface.
	if (strcmp(info->ifa_name, packetifname))
		{
		verbosedebugf("myCFSocketCallBack got a packet from %.4a to %.4a on interface %.4a/%s (Ignored -- really arrived on interface %s)",
			&senderaddr, &destaddr, &info->ifinfo.ip, info->ifa_name, packetifname);
		return;
		}
	else
		verbosedebugf("myCFSocketCallBack got a packet from %.4a to %.4a on interface %.4a/%s",
			&senderaddr, &destaddr, &info->ifinfo.ip, info->ifa_name);

	if (err < sizeof(DNSMessageHeader)) { debugf("myCFSocketCallBack packet length (%d) too short", err); return; }
	
#if mDNS_AllowPort53
	if (s == info->cfsocket53)
		mDNSCoreReceive(m, &packet, (unsigned char*)&packet + err, senderaddr, senderport, destaddr, UnicastDNSPort, info->ifinfo.ip);
	else
#endif
	mDNSCoreReceive(m, &packet, (unsigned char*)&packet + err, senderaddr, senderport, destaddr, MulticastDNSPort, info->ifinfo.ip);
	}

mDNSlocal void myCFRunLoopTimerCallBack(CFRunLoopTimerRef timer, void *info)
	{
	(void)timer;	// Parameter not used
	mDNSCoreTask((mDNS *const)info);
	}

// This gets the text of the field currently labelled "Computer Name" in the Sharing Prefs Control Panel
mDNSlocal void GetUserSpecifiedFriendlyComputerName(domainlabel *const namelabel)
	{
	CFStringEncoding encoding = kCFStringEncodingUTF8;
	CFStringRef cfs = SCDynamicStoreCopyComputerName(NULL, &encoding);
	if (cfs)
		{
		CFStringGetPascalString(cfs, namelabel->c, sizeof(*namelabel), kCFStringEncodingUTF8);
		CFRelease(cfs);
		}
	}

// This gets the text of the field currently labelled "Rendezvous Name" in the Sharing Prefs Control Panel
mDNSlocal void GetUserSpecifiedRFC1034ComputerName(domainlabel *const namelabel)
	{
	CFStringRef cfs = SCDynamicStoreCopyLocalHostName(NULL);
	if (cfs)
		{
		CFStringGetPascalString(cfs, namelabel->c, sizeof(*namelabel), kCFStringEncodingUTF8);
		CFRelease(cfs);
		}
	}

mDNSlocal mStatus SetupSocket(struct sockaddr_in *ifa_addr, mDNSIPPort port, int *s, CFSocketRef *c, CFSocketContext *context)
	{
	mStatus err;
	const int on = 1;
	const int twofivefive = 255;
	struct ip_mreq imr;
	struct sockaddr_in listening_sockaddr;
	CFRunLoopSourceRef rls;
	
	// Open the socket...
	*s = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	*c = NULL;
	if (*s < 0) { perror("socket"); return(*s); }
	
	// ... with a shared UDP port
	err = setsockopt(*s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
	if (err < 0) { perror("setsockopt - SO_REUSEPORT"); return(err); }

	// We want to receive destination addresses
	err = setsockopt(*s, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on));
	if (err < 0) { perror("setsockopt - IP_RECVDSTADDR"); return(err); }
	
	// We want to receive interface identifiers
	err = setsockopt(*s, IPPROTO_IP, IP_RECVIF, &on, sizeof(on));
	if (err < 0) { perror("setsockopt - IP_RECVIF"); return(err); }
	
	// Add multicast group membership on this interface
	imr.imr_multiaddr.s_addr = AllDNSLinkGroup.NotAnInteger;
	imr.imr_interface        = ifa_addr->sin_addr;
	err = setsockopt(*s, IPPROTO_IP, IP_ADD_MEMBERSHIP, &imr, sizeof(struct ip_mreq));	
	if (err < 0) { perror("setsockopt - IP_ADD_MEMBERSHIP"); return(err); }

	// Specify outgoing interface too
	err = setsockopt(*s, IPPROTO_IP, IP_MULTICAST_IF, &ifa_addr->sin_addr, sizeof(ifa_addr->sin_addr));
	if (err < 0) { perror("setsockopt - IP_MULTICAST_IF"); return(err); }

	// Send unicast packets with TTL 255
	err = setsockopt(*s, IPPROTO_IP, IP_TTL, &twofivefive, sizeof(twofivefive));
	if (err < 0) { perror("setsockopt - IP_TTL"); return(err); }

	// And multicast packets with TTL 255 too
	err = setsockopt(*s, IPPROTO_IP, IP_MULTICAST_TTL, &twofivefive, sizeof(twofivefive));
	if (err < 0) { perror("setsockopt - IP_MULTICAST_TTL"); return(err); }

	// And start listening for packets
	listening_sockaddr.sin_family      = AF_INET;
	listening_sockaddr.sin_port        = port.NotAnInteger;
	listening_sockaddr.sin_addr.s_addr = 0; // Want to receive multicasts AND unicasts on this socket
	err = bind(*s, (struct sockaddr *) &listening_sockaddr, sizeof(listening_sockaddr));
	if (err)
		{
		if (port.NotAnInteger == UnicastDNSPort.NotAnInteger) err = 0;
		else perror("bind");
		return(err);
		}

	*c = CFSocketCreateWithNative(kCFAllocatorDefault, *s, kCFSocketReadCallBack, myCFSocketCallBack, context);
	rls = CFSocketCreateRunLoopSource(kCFAllocatorDefault, *c, 0);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
	CFRelease(rls);
	
	return(err);
	}

#if 0
mDNSlocal NetworkInterfaceInfo2 *SearchForInterfaceByAddr(mDNS *const m, mDNSIPAddr ip)
	{
	NetworkInterfaceInfo2 *info = (NetworkInterfaceInfo2*)(m->HostInterfaces);
	while (info)
		{
		if (info->ifinfo.ip.NotAnInteger == ip.NotAnInteger) return(info);
		info = (NetworkInterfaceInfo2 *)(info->ifinfo.next);
		}
	return(NULL);
	}
#endif

mDNSlocal NetworkInterfaceInfo2 *SearchForInterfaceByName(mDNS *const m, char *ifname)
	{
	NetworkInterfaceInfo2 *info = (NetworkInterfaceInfo2*)(m->HostInterfaces);
	while (info)
		{
		if (!strcmp(info->ifa_name, ifname)) return(info);
		info = (NetworkInterfaceInfo2 *)(info->ifinfo.next);
		}
	return(NULL);
	}

#if RUN_ON_PUMA_WITHOUT_IFADDRS

/* Our own header for the programs that need interface configuration info.
   Include this file, instead of "unp.h". */

#define	IFA_NAME	16			/* same as IFNAMSIZ in <net/if.h> */
#define	IFA_HADDR	 8			/* allow for 64-bit EUI-64 in future */

struct ifa_info {
  char    ifa_name[IFA_NAME];	/* interface name, null terminated */
  u_char  ifa_haddr[IFA_HADDR];	/* hardware address */
  u_short ifa_hlen;				/* #bytes in hardware address: 0, 6, 8 */
  short   ifa_flags;			/* IFF_xxx constants from <net/if.h> */
  short   ifa_myflags;			/* our own IFI_xxx flags */
  struct sockaddr  *ifa_addr;	/* primary address */
  struct sockaddr  *ifa_brdaddr;/* broadcast address */
  struct sockaddr  *ifa_dstaddr;/* destination address */
  struct ifa_info  *ifa_next;	/* next of these structures */
};

#define	IFI_ALIAS	1			/* ifa_addr is an alias */

					/* function prototypes */
struct ifa_info	*get_ifa_info(int, int);
struct ifa_info	*Get_ifa_info(int, int);
void			 free_ifa_info(struct ifa_info *);

#define HAVE_SOCKADDR_SA_LEN	1

struct ifa_info *
get_ifa_info(int family, int doaliases)
{
	struct ifa_info		*ifi, *ifihead, **ifipnext;
	int					sockfd, len, lastlen, flags, myflags;
	char				*ptr, *buf, lastname[IFNAMSIZ], *cptr;
	struct ifconf		ifc;
	struct ifreq		*ifr, ifrcopy;
	struct sockaddr_in	*sinptr;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	lastlen = 0;
	len = 100 * sizeof(struct ifreq);	/* initial buffer size guess */
	for ( ; ; ) {
		buf = (char *) malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = buf;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0)
				debugf("ioctl error");
		} else {
			if (ifc.ifc_len == lastlen)
				break;		/* success, len has not changed */
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof(struct ifreq);	/* increment */
		free(buf);
	}
	ifihead = NULL;
	ifipnext = &ifihead;
	lastname[0] = 0;
/* end get_ifa_info1 */

/* include get_ifa_info2 */
	for (ptr = buf; ptr < buf + ifc.ifc_len; ) {
		ifr = (struct ifreq *) ptr;

#ifdef	HAVE_SOCKADDR_SA_LEN
		len = MAX(sizeof(struct sockaddr), ifr->ifr_addr.sa_len);
#else
		switch (ifr->ifr_addr.sa_family) {
#ifdef	IPV6
		case AF_INET6:	
			len = sizeof(struct sockaddr_in6);
			break;
#endif
		case AF_INET:	
		default:	
			len = sizeof(struct sockaddr);
			break;
		}
#endif	/* HAVE_SOCKADDR_SA_LEN */
		ptr += sizeof(ifr->ifr_name) + len;	/* for next one in buffer */

		if (ifr->ifr_addr.sa_family != family)
			continue;	/* ignore if not desired address family */

		myflags = 0;
		if ( (cptr = strchr(ifr->ifr_name, ':')) != NULL)
			*cptr = 0;		/* replace colon will null */
		if (strncmp(lastname, ifr->ifr_name, IFNAMSIZ) == 0) {
			if (doaliases == 0)
				continue;	/* already processed this interface */
			myflags = IFI_ALIAS;
		}
		memcpy(lastname, ifr->ifr_name, IFNAMSIZ);

		ifrcopy = *ifr;
		ioctl(sockfd, SIOCGIFFLAGS, &ifrcopy);
		flags = ifrcopy.ifr_flags;
		if ((flags & IFF_UP) == 0)
			continue;	/* ignore if interface not up */

		ifi = (struct ifa_info *) calloc(1, sizeof(struct ifa_info));
		*ifipnext = ifi;			/* prev points to this new one */
		ifipnext = &ifi->ifa_next;	/* pointer to next one goes here */

		ifi->ifa_flags = flags;		/* IFF_xxx values */
		ifi->ifa_myflags = myflags;	/* IFI_xxx values */
		memcpy(ifi->ifa_name, ifr->ifr_name, IFA_NAME);
		ifi->ifa_name[IFA_NAME-1] = '\0';
/* end get_ifa_info2 */
/* include get_ifa_info3 */
		switch (ifr->ifr_addr.sa_family) {
		case AF_INET:
			sinptr = (struct sockaddr_in *) &ifr->ifr_addr;
			if (ifi->ifa_addr == NULL) {
				ifi->ifa_addr = (struct sockaddr *) calloc(1, sizeof(struct sockaddr_in));
				memcpy(ifi->ifa_addr, sinptr, sizeof(struct sockaddr_in));

#ifdef	SIOCGIFBRDADDR
				if (flags & IFF_BROADCAST) {
					ioctl(sockfd, SIOCGIFBRDADDR, &ifrcopy);
					sinptr = (struct sockaddr_in *) &ifrcopy.ifr_broadaddr;
					ifi->ifa_brdaddr = (struct sockaddr *) calloc(1, sizeof(struct sockaddr_in));
					memcpy(ifi->ifa_brdaddr, sinptr, sizeof(struct sockaddr_in));
				}
#endif

#ifdef	SIOCGIFDSTADDR
				if (flags & IFF_POINTOPOINT) {
					ioctl(sockfd, SIOCGIFDSTADDR, &ifrcopy);
					sinptr = (struct sockaddr_in *) &ifrcopy.ifr_dstaddr;
					ifi->ifa_dstaddr = (struct sockaddr *) calloc(1, sizeof(struct sockaddr_in));
					memcpy(ifi->ifa_dstaddr, sinptr, sizeof(struct sockaddr_in));
				}
#endif
			}
			break;

		default:
			break;
		}
	}
	free(buf);
	return(ifihead);	/* pointer to first structure in linked list */
}
/* end get_ifa_info3 */

/* include free_ifa_info */
mDNSlocal void freeifaddrs(struct ifa_info *ifihead)
{
	struct ifa_info	*ifi, *ifinext;

	for (ifi = ifihead; ifi != NULL; ifi = ifinext) {
		if (ifi->ifa_addr != NULL)
			free(ifi->ifa_addr);
		if (ifi->ifa_brdaddr != NULL)
			free(ifi->ifa_brdaddr);
		if (ifi->ifa_dstaddr != NULL)
			free(ifi->ifa_dstaddr);
		ifinext = ifi->ifa_next;	/* can't fetch ifa_next after free() */
		free(ifi);					/* the ifa_info{} itself */
	}
}
/* end free_ifa_info */

struct ifa_info *
Get_ifa_info(int family, int doaliases)
{
	struct ifa_info	*ifi;

	if ( (ifi = get_ifa_info(family, doaliases)) == NULL)
		debugf("get_ifa_info error");
	return(ifi);
}

mDNSlocal int getifaddrs(struct ifa_info **ifalist)
	{
	*ifalist = get_ifa_info(PF_INET, false);
	if( ifalist == nil )
		return -1;
	else
		return(0);
	}

#endif

mDNSlocal mStatus SetupInterface(mDNS *const m, NetworkInterfaceInfo2 *info, struct ifaddrs *ifa)
	{
	mStatus err = 0;
	struct sockaddr_in *ifa_addr = (struct sockaddr_in *)ifa->ifa_addr;
	CFSocketContext myCFSocketContext = { 0, info, NULL, NULL, NULL };

	info->ifinfo.ip.NotAnInteger = ifa_addr->sin_addr.s_addr;
	info->ifinfo.Advertise       = mDNS_AdvertiseLocalAddresses;
	info->m         = m;
	info->ifa_name  = (char *)mallocL("NetworkInterfaceInfo2 name", strlen(ifa->ifa_name) + 1);
	if (!info->ifa_name) return(-1);
	strcpy(info->ifa_name, ifa->ifa_name);
	info->alias     = SearchForInterfaceByName(m, ifa->ifa_name);
	info->socket    = 0;
	info->cfsocket  = 0;
#if mDNS_AllowPort53
	info->socket53   = 0;
	info->cfsocket53 = 0;
#endif

	mDNS_RegisterInterface(m, &info->ifinfo);

	if (info->alias)
		debugf("SetupInterface: %s Flags %04X %.4a is an alias of %.4a",
			ifa->ifa_name, ifa->ifa_flags, &info->ifinfo.ip, &info->alias->ifinfo.ip);

#if mDNS_AllowPort53
	err = SetupSocket(ifa_addr, UnicastDNSPort,   &info->socket53, &info->cfsocket53, &myCFSocketContext);
#endif
	if (!err)
		err = SetupSocket(ifa_addr, MulticastDNSPort, &info->socket, &info->cfsocket, &myCFSocketContext);

	debugf("SetupInterface: %s Flags %04X %.4a Registered",
		ifa->ifa_name, ifa->ifa_flags, &info->ifinfo.ip);

	return(err);
	}

mDNSlocal void ClearInterfaceList(mDNS *const m)
	{
	while (m->HostInterfaces)
		{
		NetworkInterfaceInfo2 *info = (NetworkInterfaceInfo2*)(m->HostInterfaces);
		mDNS_DeregisterInterface(m, &info->ifinfo);
		if (info->ifa_name  ) freeL("NetworkInterfaceInfo2 name", info->ifa_name);
		if (info->socket > 0) shutdown(info->socket, 2);
		if (info->cfsocket) { CFSocketInvalidate(info->cfsocket); CFRelease(info->cfsocket); }
#if mDNS_AllowPort53
		if (info->socket53 > 0) shutdown(info->socket53, 2);
		if (info->cfsocket53) { CFSocketInvalidate(info->cfsocket53); CFRelease(info->cfsocket53); }
#endif
		freeL("NetworkInterfaceInfo2", info);
		}
	}

mDNSlocal mStatus SetupInterfaceList(mDNS *const m)
	{
	struct ifaddrs *ifalist;
	int err = getifaddrs(&ifalist);
	struct ifaddrs *ifa = ifalist;
	struct ifaddrs *theLoopback = NULL;
	if (err) return(err);

	// Set up the nice label
	m->nicelabel.c[0] = 0;
	GetUserSpecifiedFriendlyComputerName(&m->nicelabel);
	if (m->nicelabel.c[0] == 0) ConvertCStringToDomainLabel("Macintosh", &m->nicelabel);

	// Set up the RFC 1034-compliant label
	m->hostlabel.c[0] = 0;
	GetUserSpecifiedRFC1034ComputerName(&m->hostlabel);
	if (m->hostlabel.c[0] == 0) ConvertCStringToDomainLabel("Macintosh", &m->hostlabel);

	mDNS_GenerateFQDN(m);

	while (ifa)
		{
#if 0
		if (ifa->ifa_addr->sa_family != AF_INET)
			debugf("SetupInterface: %s Flags %04X Family %d not AF_INET",
				ifa->ifa_name, ifa->ifa_flags, ifa->ifa_addr->sa_family);
		if (!(ifa->ifa_flags & IFF_UP))
			debugf("SetupInterface: %s Flags %04X Interface not IFF_UP", ifa->ifa_name, ifa->ifa_flags);
		if (ifa->ifa_flags & IFF_LOOPBACK)
			debugf("SetupInterface: %s Flags %04X Interface IFF_LOOPBACK", ifa->ifa_name, ifa->ifa_flags);
		if (ifa->ifa_flags & IFF_POINTOPOINT)
			debugf("SetupInterface: %s Flags %04X Interface IFF_POINTOPOINT", ifa->ifa_name, ifa->ifa_flags);
#endif
		if (ifa->ifa_addr->sa_family == AF_INET && (ifa->ifa_flags & IFF_UP) &&
			!(ifa->ifa_flags & IFF_POINTOPOINT))
			{
			if (ifa->ifa_flags & IFF_LOOPBACK)
				theLoopback = ifa;
			else
				{
				NetworkInterfaceInfo2 *info = (NetworkInterfaceInfo2 *)mallocL("NetworkInterfaceInfo2", sizeof(*info));
				if (!info) debugf("SetupInterfaceList: Out of Memory!");
				else SetupInterface(m, info, ifa);
				}
			}
		ifa = ifa->ifa_next;
		}

	if (!m->HostInterfaces && theLoopback)
		{
		NetworkInterfaceInfo2 *info = (NetworkInterfaceInfo2 *)mallocL("NetworkInterfaceInfo2", sizeof(*info));
		if (!info) debugf("SetupInterfaceList: (theLoopback) Out of Memory!");
		else SetupInterface(m, info, theLoopback);
		}

	freeifaddrs(ifalist);
	return(err);
	}

mDNSlocal void NetworkChanged(SCDynamicStoreRef store, CFArrayRef changedKeys, void *context)
	{
	mDNS *const m = (mDNS *const)context;
	debugf("***   Network Configuration Change   ***");
	(void)store;		// Parameter not used
	(void)changedKeys;	// Parameter not used
	
	ClearInterfaceList(m);
	SetupInterfaceList(m);
	if (NotifyClientNetworkChanged) NotifyClientNetworkChanged();
	mDNSCoreSleep(m, false);
	}

mDNSlocal mStatus WatchForNetworkChanges(mDNS *const m)
	{
	mStatus err = -1;
	SCDynamicStoreContext context = { 0, m, NULL, NULL, NULL };
	SCDynamicStoreRef     store    = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder"), NetworkChanged, &context);
	CFStringRef           key1     = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv4);
	CFStringRef           key2     = SCDynamicStoreKeyCreateComputerName(NULL);
	CFStringRef           key3     = SCDynamicStoreKeyCreateHostNames(NULL);
	CFStringRef           pattern  = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
	CFMutableArrayRef     keys     = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
	CFMutableArrayRef     patterns = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

	if (!store) { fprintf(stderr, "SCDynamicStoreCreate failed: %s\n", SCErrorString(SCError())); goto error; }
	if (!key1 || !key2 || !key3 || !keys || !pattern || !patterns) goto error;

	CFArrayAppendValue(keys, key1);
	CFArrayAppendValue(keys, key2);
	CFArrayAppendValue(keys, key3);
	CFArrayAppendValue(patterns, pattern);
	if (!SCDynamicStoreSetNotificationKeys(store, keys, patterns))
		{ fprintf(stderr, "SCDynamicStoreSetNotificationKeys failed: %s\n", SCErrorString(SCError())); goto error; }

	m->p->StoreRLS = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
	if (!m->p->StoreRLS) { fprintf(stderr, "SCDynamicStoreCreateRunLoopSource failed: %s\n", SCErrorString(SCError())); goto error; }

	CFRunLoopAddSource(CFRunLoopGetCurrent(), m->p->StoreRLS, kCFRunLoopDefaultMode);
	m->p->Store = store;
	err = 0;
	goto exit;

error:
	if (store)    CFRelease(store);

exit:
	if (key1)     CFRelease(key1);
	if (key2)     CFRelease(key2);
	if (key3)     CFRelease(key3);
	if (pattern)  CFRelease(pattern);
	if (keys)     CFRelease(keys);
	if (patterns) CFRelease(patterns);
	
	return(err);
	}

mDNSlocal void PowerChanged(void *refcon, io_service_t service, natural_t messageType, void *messageArgument)
	{
	mDNS *const m = (mDNS *const)refcon;
	(void)service;		// Parameter not used
	switch(messageType)
		{
		case kIOMessageCanSystemPowerOff:     debugf("PowerChanged kIOMessageCanSystemPowerOff (no action)");               break; // E0000240
		case kIOMessageSystemWillPowerOff:    debugf("PowerChanged kIOMessageSystemWillPowerOff"); mDNSCoreSleep(m, true);  break; // E0000250
		case kIOMessageSystemWillNotPowerOff: debugf("PowerChanged kIOMessageSystemWillNotPowerOff (no action)");           break; // E0000260
		case kIOMessageCanSystemSleep:        debugf("PowerChanged kIOMessageCanSystemSleep (no action)");                  break; // E0000270
		case kIOMessageSystemWillSleep:       debugf("PowerChanged kIOMessageSystemWillSleep");    mDNSCoreSleep(m, true);  break; // E0000280
		case kIOMessageSystemWillNotSleep:    debugf("PowerChanged kIOMessageSystemWillNotSleep (no action)");              break; // E0000290
		case kIOMessageSystemHasPoweredOn:    debugf("PowerChanged kIOMessageSystemHasPoweredOn"); mDNSCoreSleep(m, false); break; // E0000300
		default:                              debugf("PowerChanged unknown message %X", messageType);                       break;
		}
	IOAllowPowerChange(m->p->PowerConnection, (long)messageArgument);
	}

mDNSlocal mStatus WatchForPowerChanges(mDNS *const m)
	{
	IONotificationPortRef thePortRef;
	m->p->PowerConnection = IORegisterForSystemPower(m, &thePortRef, PowerChanged, &m->p->PowerNotifier);
	if (m->p->PowerConnection)
		{
		m->p->PowerRLS = IONotificationPortGetRunLoopSource(thePortRef);
		CFRunLoopAddSource(CFRunLoopGetCurrent(), m->p->PowerRLS, kCFRunLoopDefaultMode);
		return(mStatus_NoError);
		}
	return(-1);
	}

mDNSlocal mStatus mDNSPlatformInit_setup(mDNS *const m)
	{
	mStatus err;

	CFRunLoopTimerContext myCFRunLoopTimerContext = { 0, m, NULL, NULL, NULL };
	
	// Note: Every CFRunLoopTimer has to be created with an initial fire time, and a repeat interval, or it becomes
	// a one-shot timer and you can't use CFRunLoopTimerSetNextFireDate(timer, when) to schedule subsequent firings.
	// Here we create it with an initial fire time ten seconds from now, and a repeat interval of ten seconds,
	// knowing that we'll reschedule it using CFRunLoopTimerSetNextFireDate(timer, when) long before that happens.
	m->p->CFTimer = CFRunLoopTimerCreate(kCFAllocatorDefault, CFAbsoluteTimeGetCurrent() + 10.0, 10.0, 0, 1,
											myCFRunLoopTimerCallBack, &myCFRunLoopTimerContext);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), m->p->CFTimer, kCFRunLoopDefaultMode);

	SetupInterfaceList(m);

	err = WatchForNetworkChanges(m);
	if (err) return(err);
	
	err = WatchForPowerChanges(m);
	return(err);
	}

mDNSexport mStatus mDNSPlatformInit(mDNS *const m)
	{
	mStatus result = mDNSPlatformInit_setup(m);
	// We don't do asynchronous initialization on OS X, so by the time we get here the setup will already
	// have succeeded or failed -- so if it succeeded, we should just call mDNSCoreInitComplete() immediately
	if (result == mStatus_NoError) mDNSCoreInitComplete(m, mStatus_NoError);
	return(result);
	}

mDNSexport void mDNSPlatformClose(mDNS *const m)
	{
	if (m->p->PowerConnection)
		{
		CFRunLoopRemoveSource(CFRunLoopGetCurrent(), m->p->PowerRLS, kCFRunLoopDefaultMode);
		CFRunLoopSourceInvalidate(m->p->PowerRLS);
		CFRelease(m->p->PowerRLS);
		IODeregisterForSystemPower(&m->p->PowerNotifier);
		m->p->PowerConnection = NULL;
		m->p->PowerNotifier   = NULL;
		m->p->PowerRLS        = NULL;
		}
	
	if (m->p->Store)
		{
		CFRunLoopRemoveSource(CFRunLoopGetCurrent(), m->p->StoreRLS, kCFRunLoopDefaultMode);
		CFRunLoopSourceInvalidate(m->p->StoreRLS);
		CFRelease(m->p->StoreRLS);
		CFRelease(m->p->Store);
		m->p->Store    = NULL;
		m->p->StoreRLS = NULL;
		}
	
	ClearInterfaceList(m);
	
	if (m->p->CFTimer)
		{
		CFRunLoopTimerInvalidate(m->p->CFTimer);
		CFRelease(m->p->CFTimer);
		m->p->CFTimer = NULL;
		}
	}

mDNSexport void mDNSPlatformScheduleTask(const mDNS *const m, SInt32 NextTaskTime)
	{
	if (m->p->CFTimer)
		{
		CFAbsoluteTime ticks    = (CFAbsoluteTime)(NextTaskTime - mDNSPlatformTimeNow());
		CFAbsoluteTime interval = ticks / (CFAbsoluteTime)mDNSPlatformOneSecond;
		CFRunLoopTimerSetNextFireDate(m->p->CFTimer, CFAbsoluteTimeGetCurrent() + interval);
		}
	}

// Locking is a no-op here, because we're CFRunLoop-based, so we can never interrupt ourselves
mDNSexport void    mDNSPlatformLock   (const mDNS *const m) { (void)m; }
mDNSexport void    mDNSPlatformUnlock (const mDNS *const m) { (void)m; }
mDNSexport void    mDNSPlatformStrCopy(const void *src,       void *dst)             { strcpy((char *)dst, (char *)src); }
mDNSexport UInt32  mDNSPlatformStrLen (const void *src)                              { return(strlen((char*)src)); }
mDNSexport void    mDNSPlatformMemCopy(const void *src,       void *dst, UInt32 len) { memcpy(dst, src, len); }
mDNSexport Boolean mDNSPlatformMemSame(const void *src, const void *dst, UInt32 len) { return(memcmp(dst, src, len) == 0); }
mDNSexport void    mDNSPlatformMemZero(                       void *dst, UInt32 len) { bzero(dst, len); }

mDNSexport SInt32  mDNSPlatformTimeNow()
	{
	struct timeval tp;
	gettimeofday(&tp, NULL);
	// tp.tv_sec is seconds since 1st January 1970 (GMT, with no adjustment for daylight savings time)
	// tp.tv_usec is microseconds since the start of this second (i.e. values 0 to 999999)
	// We use the lower 22 bits of tp.tv_sec for the top 22 bits of our result
	// and we multiply tp.tv_usec by 16 / 15625 to get a value in the range 0-1023 to go in the bottom 10 bits.
	// This gives us a proper modular (cyclic) counter that has a resolution of roughly 1ms (actually 1/1024 second)
	// and correctly cycles every 2^22 seconds (4194304 seconds = approx 48 days).
	return( (tp.tv_sec << 10) | (tp.tv_usec * 16 / 15625) );
	}

mDNSexport SInt32  mDNSPlatformOneSecond = 1024;
