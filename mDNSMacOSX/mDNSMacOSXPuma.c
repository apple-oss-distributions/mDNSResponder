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
 *
 * This file is not normally used.
 * It can be conditionally compiled in by defining RUN_ON_PUMA_WITHOUT_IFADDRS
 * in CFSocket.c. It is included mainly as sample code for people building
 * for other platforms that (like Puma) lack the getifaddrs() call.
 * NOTE: YOU CANNOT use this code to build an mDNSResponder daemon for Puma
 * that works just like the Jaguar one, because Puma lacks other necessary
 * functionality (like the LibInfo support to receive MIG messages from clients).

    Change History (most recent first):

$Log: mDNSMacOSXPuma.c,v $
Revision 1.4  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

Revision 1.3  2003/07/02 21:19:51  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.2  2002/09/21 20:44:51  zarzycki
Added APSL info

Revision 1.1  2002/09/17 01:36:23  cheshire
Move Puma support to CFSocketPuma.c

 */

#include <sys/ioctl.h>
#include <sys/sockio.h>
#define ifaddrs ifa_info
#ifndef	ifa_broadaddr
#define	ifa_broadaddr	ifa_dstaddr	/* broadcast address interface */
#endif
#include <sys/cdefs.h>

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
