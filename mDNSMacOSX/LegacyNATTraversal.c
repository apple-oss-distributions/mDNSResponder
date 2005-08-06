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

$Log: LegacyNATTraversal.c,v $
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

#include "mDNSEmbeddedAPI.h"
#include "mDNSMacOSX.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/sysctl.h>
#include <net/route.h>
#include "memory.h"
#include <ctype.h>
#include <arpa/inet.h>

//#include "IPAddr.h"
//#include "upnp.h"
//#include "debug.h"

// use error codes
//#include "netaddr.h"

// TODO: remove later and do variable length
#define MAX_SOAPMSGSIZE		65536

static int safe_close(int fd)
	{
	if (fd < 3) { /* LogMsg("safe_close: ERROR sd %d < 3", fd); */ return(-1); }
	return(close(fd));
	}

#define close safe_close

////////////////////////////////////////////////////////////////////////
// NetAddr Functions
////////////////////////////////////////////////////////////////////////

// Return codes
#define NA_E_SUCCESS				(0)
#define NA_E_INTERNAL_ERROR			(-1)	/* somewhere something wrong */
#define NA_E_INVALID_PARAMETER		(-2)	/* bad params */
#define NA_E_OPERATION_FAILED		(-3)	/* can't fulfill request */
#define NA_E_TIMEOUT				(-4)	/* operation timed out */
#define NA_E_THREAD_ERROR			(-5)	/* some error related to threads */
#define NA_E_PARSE_ERROR			(-6)	/* a parsing error occured */
#define NA_E_NOT_READY				(-7)	/* this op can't proceed yet */
#define NA_E_NOT_FOUND				(-8)	/* resource/prereq not found */
#define NA_E_NOT_AVAILABLE			(-9)	/* service not available */
#define NA_E_EXISTS					(-10)	/* can't modify existing item */
#define NA_E_AGAIN					(-11)	/* something wrong - try again */
#define NA_E_NOT_SUPPORTED			(-12)	/* wait until next version */
#define NA_E_ABORT					(-14)	/* operation aborted */
#define NA_E_NET					(-15)	/* network layer problem */

// Logging flags - log types (increasing degree of detail)
#define NALOG_ERROR					(1UL)		/* error messages */
#define NALOG_ALERT					(2UL)		/* useful warning/alerts */
#define NALOG_INFO0					(4UL)		/* info - potential problem */
#define NALOG_INFO1					(8UL)		/* extra info */
#define NALOG_DUMP					(16UL)		/* data dumps */

#define NALOG_RSRV1					(32UL)		/* reserved */
#define NALOG_RSRV2					(64UL)		/* reserved */
#define NALOG_RSRV3					(128UL)		/* reserved */

// Logging flags - component (not used for now)
#define NALOG_UPNP					(256)		/* UPnP */

// Default Logging levels
#define NALOG_LEVEL0				(0)
#define NALOG_LEVEL1				(NALOG_UPNP | NALOG_ERROR)
#define NALOG_LEVEL2				(NALOG_LEVEL1 | NALOG_ALERT)
#define NALOG_LEVEL3				(NALOG_LEVEL2 | NALOG_INFO0)
#define NALOG_LEVEL4				(NALOG_LEVEL3 | NALOG_INFO1)
#define NALOG_LEVEL5				(NALOG_LEVEL4 | NALOG_DUMP)
#define NALOG_DEFAULT_LEVEL			(NALOG_LEVEL2)

// Default timeout values (in m-seconds (milli))
// 50 milliseconds for function timeout
#define NA_DEFAULT_FUNCTION_TIMEOUT	(50)

////////////////////////////////////////////////////////////////////////
// GLOBAL Defines
////////////////////////////////////////////////////////////////////////
#define SSDP_IP "239.255.255.250"
#define SSDP_PORT 1900
#define SSDP_TTL 4

#define CRLF "\r\n"
#define H_CRLF "\r\n"
// SOAP message's CRLF:
//#define S_CRLF "\r\n"
#define S_CRLF

// standard 200 ok msg
#define HTTP200OK		"HTTP/1.1 200 OK\r\n\r\n"
#define HTTP200OKLEN	(sizeof(HTTP200OK) - 1)

// maximum time to wait for an event (in microseconds)
#define MAX_EXPECTEVENTTIME		(10000)

////////////////////////////////////////////////////////////////////////
// GLOBAL Data Types
////////////////////////////////////////////////////////////////////////
typedef struct tagProperty {
	char		*pszName;
	char		*pszValue;
	char		*pszType;
} Property, *PProperty;

typedef struct tagHTTPResponse {
	char		*pszStatus;
	char		*pszReason;
	int			iNumHeaders;
	Property	aHeaders[30];  // assume at most this many headers
	char		*pszBody;

	// for admin use
	int			fFree;
	char		*buf;
} HTTPResponse, *PHTTPResponse, **PPHTTPResponse;

////////////////////////////////////////////////////////////////////////
// GLOBAL Constants
////////////////////////////////////////////////////////////////////////
static const char szSSDPMsgDiscoverRoot[] =
	"M-SEARCH * HTTP/1.1\r\n"
	"Host:239.255.255.250:1900\r\n"
	"ST:upnp:rootdevice\r\n"
	"Man:\"ssdp:discover\"\r\n"
	"MX:3\r\n"
	"\r\n";

static const char szSSDPMsgDiscoverIGD[] =
	"M-SEARCH * HTTP/1.1\r\n"
	"Host:239.255.255.250:1900\r\n"
	"ST:urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
	"Man:\"ssdp:discover\"\r\n"
	"MX:3\r\n"
	"\r\n";

static const char szSSDPMsgDiscoverNAT[] =
	"M-SEARCH * HTTP/1.1\r\n"
	"Host:239.255.255.250:1900\r\n"
	"ST:urn:schemas-upnp-org:service:WANIPConnection:1\r\n"
	"Man:\"ssdp:discover\"\r\n"
	"MX:3\r\n"
	"\r\n";

//// Subscribe message
// 1$s: control URL
// 2$s: local's host/port ("host:port")
// 3$s: router's host/port ("host:port")
// 4$d: subscription timeout in seconds
static const char szEventMsgSubscribeFMT[] =
	"SUBSCRIBE %1$s HTTP/1.1\r\n"
	"NT: upnp:event\r\n"
	"Callback: <http://%2$s/notify>\r\n"
	"Timeout: Second-%4$d\r\n"
	"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; Windows NT/5.1)\r\n"
	"Host: %3$s\r\n"
	"Content-Length: 0\r\n"
	"Pragma: no-cache\r\n"
	"\r\n";

//// Unsubscribe message
// 1$s: control URL
// 2$s: SID (some uuid passed back during subscribe)
// 3$s: router's host ("host")
#if 0
static const char szEventMsgUnsubscribeFMT[] =
	"UNSUBSCRIBE %1$s HTTP/1.1\r\n"
	"SID: %2$s\r\n"
	"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; Windows NT/5.1)\r\n"
	"Host: %3$s\r\n"
	"Content-Length: 0\r\n"
	"Pragma: no-cache\r\n"
	"\r\n";
#endif

//// Generic SOAP Control:Action request messages
// 1$s: control URL
// 2$s: router's host/port ("host:port")
// 3$s: action (string)
// 4$d: content-length
static const char szSOAPMsgControlAHeaderFMT[] =
	//"M-POST %1$s HTTP/1.1\r\n"
	"POST %1$s HTTP/1.1\r\n"
	"Content-Type: text/xml; charset=\"utf-8\"\r\n"
	//"TEST: \"http://schemas.xmlsoap.org/soap/envelope/\"; ns=01\r\n"
	//"Man: \"http://schemas.xmlsoap.org/soap/envelope/\"; ns=01\r\n"
	//"01-SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#%3$s\"\r\n"
	"SOAPAction: \"urn:schemas-upnp-org:service:WANIPConnection:1#%3$s\"\r\n"
	"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; Windows 9x)\r\n"
	"Host: %2$s\r\n"
	"Content-Length: %4$d\r\n"
	"Connection: close\r\n"
//	"Connection: Keep-Alive\r\n"
	"Pragma: no-cache\r\n"
	"\r\n";

// 1$: action (string)
// 2$: argument list
static const char szSOAPMsgControlABodyFMT[] =
	"<?xml version=\"1.0\"?>" CRLF
	"<SOAP-ENV:Envelope" S_CRLF
	" xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\"" S_CRLF
	" SOAP-ENV:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" S_CRLF
	"<SOAP-ENV:Body>" S_CRLF
	"<m:%1$s" S_CRLF
	" xmlns:m=\"urn:schemas-upnp-org:service:WANIPConnection:1\">" S_CRLF
	"%2$s" 
	"</m:%1$s>" S_CRLF
	"</SOAP-ENV:Body>" S_CRLF
	"</SOAP-ENV:Envelope>" S_CRLF
//	CRLF
//	"0"
//	CRLF
	CRLF;

// 1$: argument name
// 2$: argument value
static const char szSOAPMsgControlAArgumentFMT[] =
	"<%1$s>%2$s</%1$s>" S_CRLF;

// 1$: argument name
// 2$: argument value
// 3$: argument type
static const char szSOAPMsgControlAArgumentFMT_t[] =
	"<%1$s"
	" xmlns:dt=\"urn:schemas-microsoft-com:datatypes\""
	" dt:dt=\"%3$s\">%2$s</%1$s>" S_CRLF;

#if 0
//// Generic SOAP Control:Query request messages
// 1$s: control URL
// 2$s: router's host/port ("host:port")
// 3$d: content-length
static const char szSOAPMsgControlQHeaderFMT[] =
	"M-POST %1$s HTTP/1.1\r\n"
	//"POST %1$s HTTP/1.1\r\n"
	"Host: %2$s\r\n"
	"Content-Length: %3$d\r\n"
	"Content-Type: text/xml; charset-\"utf-8\"\r\n"
	//"Man: \"http://schemas.xmlsoap.org/soap/envelope/\"; ns=01\r\n"
	//"SOAPAction: \"urn:schemas-upnp-org:control-1-0#QueryStateVariable\"\r\n"
	"01-SOAPAction: \"urn:schemas-upnp-org:control-1-0#QueryStateVariable\"\r\n"
	"\r\n";

// 1$: variable name
static const char szSOAPMsgControlQBodyFMT[] =
	"<s:Envelope" S_CRLF
	" xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"" S_CRLF
	" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" S_CRLF
	"<s:Body>" S_CRLF
	"<u:QueryStateVariable xmlns:u=\"urn:schemas-upnp-org:control-1-0\"" S_CRLF
	"<u:varName>%s</u:varName>" S_CRLF
	"</u:QueryStateVariable>" S_CRLF
	"</s:Body>" S_CRLF
	"</s:Envelope>" S_CRLF
	"" S_CRLF;
#endif
// 1$: device description URL
// 2$: host/port
static const char szSSDPMsgDescribeDeviceFMT[] =
	"GET %s HTTP/1.1\r\n"
	"Accept: text/xml, application/xml\r\n"
	"User-Agent: Mozilla/4.0 (compatible; UPnP/1.0; Windows NT/5.1)\r\n"
	"Host: %s\r\n"
	"Connection: close\r\n"
//	"Connection: Keep-Alive\r\n"
	"\r\n";

////////////////////////////////////////////////////////////////////////
// GLOBAL Variables
////////////////////////////////////////////////////////////////////////

static int					g_fFirstInit = TRUE;
static int					g_fQuit = FALSE;
static FILE					*g_log;
static int					g_fLogging;

// Globally-accessible UDP socket
static int					g_sUDP       = -1;
static int					g_sUDPCancel = -1;

// Globally-accessible TCP socket
static int					g_sTCP       = -1;
static int					g_sTCPCancel = -1;

// Event Vars
static int					g_fEventEnabled = FALSE;
static unsigned short		g_wEventPort;
static struct sockaddr_in	g_saddrRouterEvent;
static char 				g_szRouterHostPortEvent[1024];
static char 				g_szEventURL[1024];

// UPnP Router info
static char 				g_szFriendlyName[1024];
static char 				g_szManufacturer[1024];
static char 				g_szModelName[1024];
static char 				g_szModelDescription[1024];

// URL base
static struct sockaddr_in	g_saddrRouterBase;
static char 				g_szRouterHostPortBase[1024];

// the threads
static pthread_t			g_UDPthread = NULL;
static pthread_t			g_TCPthread = NULL;

// Local IP
static unsigned long		g_dwLocalIP = 0;

// Globally accessible info about the router/UPnP
static int					g_fUPnPEnabled = FALSE;
static char 				g_szUSN[1024];

static struct sockaddr_in	g_saddrRouterDesc;
static char 				g_szRouterHostPortDesc[1024];
static char 				g_szNATDevDescURL[1024];

static struct sockaddr_in	g_saddrRouterSOAP;
static char 				g_szRouterHostPortSOAP[1024];
static char 				g_szControlURL[1024];
static int					g_fControlURLSet = FALSE;

// Lock/condvar for synchronous upnp calls
static pthread_mutex_t				g_xUPnP;
static pthread_mutex_t				g_xUPnPMsg;
static pthread_cond_t				g_condUPnP;
static pthread_cond_t				g_condUPnPControlURL;
static struct timeval				g_tvUPnPInitTime;
static struct timeval				g_tvLastUpdateTime;

// timeout values in seconds
static int      					g_iFunctionTimeout = NA_DEFAULT_FUNCTION_TIMEOUT;

static void GetDeviceDescription(void);
static void SetLocalIP(void);

////////////////////////////////////////////////////////////////////////
// IPAddr Functions
////////////////////////////////////////////////////////////////////////


#define ISIPV6          0x01
#define ISPPP           0x02
#define IFNAMELEN       16      /* Interface Name Length                */
#define IPLEN           16      /* 16 bytes(128 bits) for IPv6  */

typedef struct tagIPINFO
{
        int                             iFlags;
        char                    szIfName[IFNAMELEN];    /* Interface name                       */
        unsigned char   abIP[IPLEN];                    /* IP in host byte order        */
        unsigned short  wPort;
} IPINFO, *PIPINFO, **PPIPINFO;

typedef struct hostent	HOSTENT, *PHOSTENT;

static unsigned long GetNATIPNetmask(unsigned long dwIP)
{
	if ((dwIP & 0xFF000000) == 0x0A000000)  return 0xFF000000;
	if ((dwIP & 0xFFF00000) == 0xAC100000)  return 0xFFF00000;
	if ((dwIP & 0xFFFF0000) == 0xC0a80000)  return 0xFFFF0000;

	return 0;	/* No NAT IP */
}

static int GetIPInfo(PPIPINFO ppIPInfo)
{
	int				fd;
	int				iLastLen, iLen, iNum = 0, iMax = 0;
	unsigned long	dwIP;
	char			*pcBuf, *pcTemp;
	PIPINFO			pIPInfo = NULL;
	struct ifconf	ifc;
	struct ifreq	*ifr, ifrcopy;

	if (ppIPInfo == NULL) return 0;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

	iLastLen = -1;
	iLen = 100 * sizeof(struct ifreq);

	for (;;)
	{
		pcBuf = (char *)malloc(iLen);
		ifc.ifc_len = iLen;
		ifc.ifc_buf = pcBuf;

		if (ioctl(fd, SIOCGIFCONF, &ifc) < 0)
		{
			if (errno != EINVAL || iLastLen != -1)
			{
//				DbgPrint(ELL_ERROR, "ioctl failed(%d)\n", errno);
				free(pcBuf);
				close(fd);
				return 0;
			}
		}
		else
		{
			if (ifc.ifc_len == iLastLen) break;
			iLastLen = ifc.ifc_len;
		}

		iLen += 10 * sizeof(struct ifreq);
		free(pcBuf);
	}

	for (pcTemp = pcBuf; pcTemp < pcBuf + ifc.ifc_len; )
	{
		if (iNum >= iMax)
		{
			PIPINFO	pIPInfoNew;

			iMax += 10;
			pIPInfoNew = (PIPINFO)realloc(pIPInfo, sizeof(IPINFO) * iMax);
			if (pIPInfoNew == NULL)
			{
				free(pIPInfo);
				free(pcBuf);
				close(fd);
				return 0;
			}
			else pIPInfo = pIPInfoNew;

			memset(pIPInfo + (iMax - 10), 0, sizeof(IPINFO) * 10);
		}

		ifr = (struct ifreq *)pcTemp;

		pcTemp += sizeof(ifr->ifr_name) + ifr->ifr_addr.sa_len;

		/* discard invalid address families & loopback */
		if ((ifr->ifr_addr.sa_family != AF_INET &&
			ifr->ifr_addr.sa_family != AF_INET6) ||
			strncmp(ifr->ifr_name, "lo", 2) == 0) continue;

		ifrcopy = *ifr;
		ioctl(fd, SIOCGIFFLAGS, &ifrcopy);
		if ((ifrcopy.ifr_flags & IFF_UP) == 0) continue;

		switch (ifr->ifr_addr.sa_family)
		{
		case AF_INET:
			memcpy(pIPInfo[iNum].szIfName, ifr->ifr_name, IFNAMELEN);
			dwIP =
				ntohl(((struct sockaddr_in *)&ifr->ifr_addr)->sin_addr.s_addr);
			memcpy(pIPInfo[iNum].abIP, &dwIP, sizeof(unsigned long));
			if (ifrcopy.ifr_flags & IFF_POINTOPOINT)
				pIPInfo[iNum].iFlags |= ISPPP;
			iNum++;
			break;

		case AF_INET6:
			memcpy(pIPInfo[iNum].szIfName, ifr->ifr_name, IFNAMELEN);
			memcpy(pIPInfo[iNum].abIP,
				((struct sockaddr_in6 *)&(ifr->ifr_addr))-> sin6_addr.s6_addr,
				16);
			pIPInfo[iNum].iFlags |= ISIPV6;
			if (ifrcopy.ifr_flags & IFF_POINTOPOINT)
				pIPInfo[iNum].iFlags |= ISPPP;
			iNum++;
			break;

		default:
			break;
		}
	}

	free(pcBuf);
	close(fd);

	*ppIPInfo = pIPInfo;

	return iNum;
}

static void FreeIPInfo(PIPINFO pIPInfo)
{
	if (pIPInfo != NULL) free(pIPInfo);
}


////////////////////////////////////////////////////////////////////////
// Function Definitions
////////////////////////////////////////////////////////////////////////

static void SendDiscoveryMsg();

// SSDPListen
//   Creates a UDP multicast socket and listens to the SSDP IP/PORT
// Returns
//   -1 on error, or the socket descriptor if success
static int SSDPListen()
{
	char				fLoop;
	int					iTTL;
	struct ip_mreq		mreq;
	struct sockaddr_in	saddr;
	int					sd;

    // IPPROTO_IP == 0; IPPROTO_TCP == 6; IPPROTO_UDP == 17; etc.
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd == -1) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "Can't create socket! SSDPListen exiting\n");
		return NA_E_NET;
	}

	// sock options values
	fLoop = 0; // false - don't send copy to self
	iTTL = SSDP_TTL;

	// bind to listen to ssdp multicast address
	bzero(&saddr, sizeof(saddr));
	saddr.sin_len = sizeof(saddr);
	saddr.sin_family = AF_INET;
	//saddr.sin_addr.s_addr = inet_addr(SSDP_IP);
	//saddr.sin_port = htons(SSDP_PORT);
	saddr.sin_addr.s_addr = htonl(g_dwLocalIP);
	saddr.sin_port = 0;

	// and set the multicast add_member structure
	// (TODO: need to find interfaces later - ioctl, with:
	//  SIOCFIFCONF to find if's, SIOCGIFADDR to get addr, and SIOCFIFFLAGS
	//  to check for IFF_MULTICAST flag for multicast support on an if)
	bzero(&mreq, sizeof(mreq));
	mreq.imr_interface.s_addr = g_dwLocalIP;
	mreq.imr_multiaddr.s_addr = inet_addr(SSDP_IP);

	if (
		bind(sd, (struct sockaddr *)&saddr, sizeof(saddr)) //||
		//setsockopt(sd, IPPROTO_IP, IP_MULTICAST_LOOP, &fLoop, sizeof(fLoop)) ||
		//setsockopt(sd, IPPROTO_IP, IP_MULTICAST_TTL, &iTTL, sizeof(iTTL)) ||
		//setsockopt(sd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))
		) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log,
				"bind/setsockopt for multicast failed... errno = %d\n", errno);
		close(sd);
		return NA_E_NET;
	}

	return sd;
}

static int EventListen()
{
	struct sockaddr_in	saddr;
	int					sd;

	// try 5 ports before failing completely
	for (g_wEventPort = 5000; g_wEventPort < 5005; g_wEventPort++)
	{
		sd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sd == -1) {
			if (g_fLogging & NALOG_ERROR)
				fprintf(g_log, "Can't create socket! EventListen exiting\n");
			return NA_E_NET;
		}

		bzero(&saddr, sizeof(saddr));
		saddr.sin_len = sizeof(saddr);
		saddr.sin_family = AF_INET;
		saddr.sin_addr.s_addr = htonl(g_dwLocalIP);
		saddr.sin_port = htons(g_wEventPort);

		// return if okay
		if (bind(sd, (struct sockaddr *)&saddr, sizeof(saddr)) == 0)
		{
			listen(sd, 128);
			////TracePrint(ELL_TRACE, "UPnP: EventListen @%u\n", g_wEventPort);
			return sd;
		}

		// unsuccessful - close sd and try again
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log,
				"bind TCP port %u failed: errno = %d\n", g_wEventPort, errno);
		close(sd);
	}

	return NA_E_NET;
}

static void *TCPProc(void *in);

static int EventInit()
{
	int				iRet;
	pthread_attr_t	attr;

	if (g_fEventEnabled == FALSE)
	{
		// initialize TCP socket for Eventing
		g_sTCP = EventListen();
		if (g_sTCP < 0) {
			if (g_fLogging & NALOG_ERROR)
				fprintf(g_log, "EventInit - Failed to init tcp socket.\n");
			return NA_E_INTERNAL_ERROR;
		}

		// make TCP thread
		pthread_attr_init(&attr);
		iRet = pthread_create(&g_TCPthread, &attr, TCPProc, 0);
		if (iRet != 0) {
			close(g_sTCP);
			g_sTCP = -1;
			if (g_fLogging & NALOG_ERROR)
				fprintf(g_log, "EventInit: TCPProc create failed(%d)\n", iRet);
			return NA_E_THREAD_ERROR;
		}
	}

	g_fEventEnabled = TRUE;

	return NA_E_SUCCESS;
}

static void DumpHex(char *buf, int len)
{
	int		i;
	int		nexti;
	int		j;
	int		endj;

	if (g_fLogging & NALOG_DUMP) {
		if (buf == NULL) return;
		if (len <= 0) return;

		for (i = 0; i < len; i = nexti) {
			fprintf(g_log, "%04x:  ", i);
			nexti = i + 16;
			endj = (nexti > len) ? len : nexti;
			for (j = i; j < endj; j++)
				fprintf(g_log, "%02x ", buf[j] & 0xff);
			if (j == len) {
				if ((j % 16) != 0) {
					char pad[3 * 16 + 1];  // don't need the last 3 bytes anyway
					j = (16 - (j % 16)) * 3;
					memset(pad, ' ', j);
					pad[j] = '\0';
					fputs(pad, g_log);
				}
			}
			for (j = i; j < endj; j++)
				isprint(buf[j]) ? fputc(buf[j], g_log) : fputc('.', g_log);
			fputc('\n', g_log);
		}

	}
}

// FindHTTPHeaderNewLine
//   Returns a pointer to the beginning of a CRLF, that is not a
//   part of LWS.  (LWS is CRLF followed by a space or tab, and in
//   HTTP, considered as equivalent to a single space) (LWS stands
//   for "linear white space")
// Returns a pointer the beginning of CRLF, and sets the EOH flag to
//   whether this is the last header in the HTTP header section.
//   Also, if pbuf is NULL, or if there isn't any CRLF found in the
//   string, or if the HTTP syntax is wrong, NULL is returned, and
//   the EOH flag is not touched.
static char *FindHTTPHeaderNewLine(char *pbuf, int iBufSize, int *pfEOH)
{
	char *result;
	int i = 0;

	if (pbuf == NULL) return NULL;

	for (;;) {
		result = memchr(pbuf, '\r', iBufSize);
		if (result == NULL) {
			if (g_fLogging & NALOG_INFO0) {
				fprintf(g_log, "FindHTTPHeaderNewLine: er @(%d)\n", i);
				fflush(g_log);
			}
			return NULL;
		}
		i++; // count chars

		// decrement iBufSize, and move pbuf forward
		iBufSize -= (result - pbuf);
		pbuf = result;

		++pbuf;  // now pointing right after "\r"
		--iBufSize;
		if (*pbuf == '\0') break;
		if (*pbuf != '\n') continue;

		++pbuf;  // now pointing after "\r\n"
		--iBufSize;
		if (*pbuf == '\0') break;
		if ((*pbuf == ' ') || (*pbuf == '\t')) continue;

		// at this point we know we're at the end of a header field,
		// and there's more stuff coming...

		// just need to check if this is the last header
		if ((pbuf[0] == '\r') && (pbuf[1] == '\n'))
			*pfEOH = TRUE;
		else
			*pfEOH = FALSE;

		return result;
	}

	return NULL;
}

// NewHTTPResponse_sz
//   Creates an HTTPResponse structure from a string (sz).  Set
//   fDestroyOriginal to TRUE if the buffer passed in can be overwritten.
//   Otherwise, NewHTTPResponse_sz will duplicate the buffer.
// Returns the created HTTPResponse structure if successful, or if an
//   error occured (out of memory, or bad http syntax), returns NULL.
// NOTE: ALWAYS call DeleteHTTPResponse after using the HTTPResponse structure.
// NOTE: The input is assumed to be correct.  If there're HTTP syntax errors,
//   and the pszHTTPResponse is not null-terminated, result may be undefined.
//   (to be fixed next version)
static PHTTPResponse NewHTTPResponse_sz(
	char *pszHTTPResponse,
	int iBufferSize,
	int fDestroyOriginal)
{
	PHTTPResponse	pResponse;
	int				fEOH;
	char			*pszEOL;
	int				iNumHeaders;
	char			*pBuf;

	if ((pResponse = (PHTTPResponse)malloc(sizeof(HTTPResponse))) == NULL) {
		if (g_fLogging & NALOG_INFO0) {
			fprintf(g_log, "NewHTTPResponse_sz: er 1\n");
			fflush(g_log);
		}
		return NULL;
	}

	// make copy of buffer now
	if (fDestroyOriginal) {
		pResponse->buf = NULL;
		pBuf = pszHTTPResponse;
	}
	else {
		int len = strlen(pszHTTPResponse);
		if ((len+1) > iBufferSize) {
			if (g_fLogging & NALOG_INFO0)
				fprintf(g_log, "Length: %d > %d\n", len+1, iBufferSize);
			iBufferSize = len+1;
		}
		if ((pResponse->buf = (char *)malloc(iBufferSize)) == NULL) {
			free(pResponse);
			if (g_fLogging & NALOG_INFO0) {
				fprintf(g_log, "NewHTTPResponse_sz: er 2\n");
				fflush(g_log);
			}
			return NULL;
		}
		memcpy(pResponse->buf, pszHTTPResponse, iBufferSize);
		pBuf = pResponse->buf;
	}

	// get the first line
	pszEOL = FindHTTPHeaderNewLine(pBuf, iBufferSize, &fEOH);
	if (pszEOL == NULL) {
		if (g_fLogging & NALOG_INFO0) {
			fprintf(g_log, "NewHTTPResponse_sz: er 3\n");
			fflush(g_log);
		}
		goto cleanup;
	}

	*pszEOL = '\0';    // terminate the status line
	pszEOL += 2;       // point to the rest of the buffer

	// set the status string first
	pResponse->pszStatus = strchr(pBuf, ' ');
	if (pResponse->pszStatus == NULL) {
		if (g_fLogging & NALOG_INFO0) {
			fprintf(g_log, "NewHTTPResponse_sz: er 4\n");
			fflush(g_log);
		}
		goto cleanup;  // syntax error
	}

	pResponse->pszStatus++;  // point to the actual status

	pResponse->pszReason = strchr(pResponse->pszStatus, ' ');
	if (pResponse->pszReason == NULL) {
		if (g_fLogging & NALOG_INFO0) {
			fprintf(g_log, "NewHTTPResponse_sz: er 5\n");
			fflush(g_log);
		}
		goto cleanup;  // syntax error
	}

	pResponse->pszReason[0] = '\0';  // terminate status string
	pResponse->pszReason++;          // point to the reason string

	iNumHeaders = 0;  // initialize to 0 headers

	// parse header fields line by line (while not end of headers)
	while (!fEOH) {
		PProperty	pHeader = &(pResponse->aHeaders[iNumHeaders]);
		// point header field name to the first char of the line
		pHeader->pszName = pszEOL;

		// search for the end of line
		pszEOL = FindHTTPHeaderNewLine(pszEOL,
			iBufferSize - (pszEOL - pBuf),  // remainder size
			&fEOH);
		if (pszEOL == NULL) goto cleanup;  // syntax error

		*pszEOL = '\0';  // terminate this string
		pszEOL += 2;  // point to beginning of next line

		pHeader->pszValue = strchr(pHeader->pszName, ':');
		if (pHeader->pszValue == NULL) {
			if (g_fLogging & NALOG_INFO0) {
				fprintf(g_log, "NewHTTPResponse_sz: er 6\n");
				fflush(g_log);
			}
			goto cleanup;  // syntax error (header field has no ":")
		}

		pHeader->pszValue[0] = '\0';  // terminate the header name string
		pHeader->pszValue++;  // point after the ":"
		// get rid of leading spaces for the value part
		while (
			(pHeader->pszValue[0] == ' ') ||
			(pHeader->pszValue[0] == '\t') ||
			(pHeader->pszValue[0] == '\r') ||
			(pHeader->pszValue[0] == '\n')
			) {
			pHeader->pszValue++;  // skip the space
		}

		iNumHeaders++;  // added one more header
		pHeader++;      // point to the next header in pResponse->aHeaders
	}

	pResponse->iNumHeaders = iNumHeaders;  // remember to set it in pResponse

	pResponse->pszBody = pszEOL + 2;  // point after the empty line

	return pResponse;

cleanup:
	if (pResponse->buf != NULL) free(pResponse->buf);
	free(pResponse);
	return NULL;
}

// DeleteHTTPResponse
//   Deallocates stuff in the HTTPResponse structure, effectively returning
//   memory to the system and destroying the structure.
// NOTE: The pointer pResponse WILL BE FREED, and will be unusable after
//   the call to DeleteHTTPResponse.
static void DeleteHTTPResponse(PHTTPResponse pResponse)
{
//	int i;

	if (pResponse == NULL) return;

	// Current impl is just simple array - no need to free()
	//for (i = 0; i < pResponse->iNumHeaders; i++) {
	//	free(pResponse->aHeaders[i]);
	//}

	if (pResponse->buf != NULL)
		free(pResponse->buf);
	free(pResponse);
}

//typedef struct tagHTTPResponse {
//	char		*pszStatus;
//	char		*pszReason;
//	int			iNumHeaders;
//	Property	aHeaders[30];  // assume at most this many headers
//	char		*pszBody;
//
//	// for admin use
//	int			fFree;
//	char		*buf;
//} HTTPResponse, *PHTTPResponse, **PPHTTPResponse;

static void PrintHTTPResponse(PHTTPResponse pResponse)
{
	int		i;

	if (g_fLogging & (NALOG_INFO1)) {
		if (pResponse == NULL) return;
		fprintf(g_log, " *** HTTP response begin *** \n");
		fprintf(g_log, " * status = [%s], reason = [%s] *\n",
			pResponse->pszStatus, pResponse->pszReason);
		for (i = 0; i < pResponse->iNumHeaders; i++) {
			fprintf(g_log, " * Header \"%s\" = [%s]\n",
				pResponse->aHeaders[i].pszName,
				pResponse->aHeaders[i].pszValue);
		}
		if (g_fLogging & NALOG_DUMP)
			fprintf(g_log, " * body = [%s] *\n", pResponse->pszBody);
		fprintf(g_log, " *** HTTP response end *** \n");
	}
}

static int DiscoverRouter(PHTTPResponse pResponse)
{
	int			i;
	int			fLocation = FALSE;
	int			fUSN = FALSE;
	int			fIsNATDevice = FALSE;

#if 0
	if (strcmp(pResponse->pszStatus, "200") != 0)
		return -1;
#endif

	if (pResponse == NULL) {
		if (g_fLogging & NALOG_INFO0)
			fprintf(g_log, "DiscoverRouter: pResponse == NULL\n");
		return -1;
	}

	// check to see if this is a relevant packet
	for (i = 0; i < pResponse->iNumHeaders; i++) {
		PProperty pHeader = &(pResponse->aHeaders[i]);

		if ((strcasecmp(pHeader->pszName, "ST") == 0) ||
			(strcasecmp(pHeader->pszName, "NT") == 0)) {
			if ((strcmp(pHeader->pszValue,
				"urn:schemas-upnp-org:service:WANIPConnection:1") == 0) ||
				(strcmp(pHeader->pszValue,
				"urn:schemas-upnp-org:device:InternetGatewayDevice:1") == 0)) {
				fIsNATDevice = TRUE;
			}
		}
	}

	// leave the message alone if we don't need it
	if (!fIsNATDevice)
		return -1;

	// Now that we know we're looking at the message about the NAT device:
	pthread_mutex_lock(&g_xUPnP);

	// set upnp to be unconfigured for now
	g_fUPnPEnabled = FALSE;

	// loop through the headers
	for (i = 0; i < pResponse->iNumHeaders; i++) {
		PProperty pHeader = &(pResponse->aHeaders[i]);

		if (strcasecmp(pHeader->pszName, "Location") == 0) {
			char *p;
			char *q;

			if (g_fLogging & NALOG_INFO1)
				fprintf(g_log, "Checking Location...\n");
			p = pHeader->pszValue;
			if (strncmp(p, "http://", 7) != 0)
				continue;  // hope for another Location header to correct it
			p += 7;  // skip over "http://"
			q = strchr(p, '/');

			// set the control URL first
			if (q == NULL) {
				g_szNATDevDescURL[0] = '/';
				g_szNATDevDescURL[1] = '\0';
			}
			else {
				strncpy(g_szNATDevDescURL, q, sizeof(g_szNATDevDescURL) - 1);
				g_szNATDevDescURL[sizeof(g_szNATDevDescURL) - 1] = '\0';
				// terminate the host/port string
				*q = '\0';
			}

			if (g_fLogging & NALOG_INFO1)
				fprintf(g_log, "  Device Description URL set to[%s]...\n",
					g_szNATDevDescURL);

			// see if port is specified
			q = strchr(p, ':');
			if (q == NULL) {
				sprintf(g_szRouterHostPortDesc, "%s", p);

				g_saddrRouterDesc.sin_addr.s_addr = inet_addr(p);
				g_saddrRouterDesc.sin_port = htons(80);
			}
			else {
				// don't include the ":80" - HTTP is by default port 80
				if (atoi(q+1) == 80) *q = '\0';

				strcpy(g_szRouterHostPortDesc, p);

				// terminate the host part and point to it
				*q = '\0';
				q++;

				g_saddrRouterDesc.sin_addr.s_addr = inet_addr(p);
				g_saddrRouterDesc.sin_port = htons(atoi(q));
			}

			g_saddrRouterDesc.sin_family = AF_INET;

			if (g_fLogging & NALOG_INFO1)
				fprintf(g_log, "  Router Address set to[%s]...\n",
					g_szRouterHostPortDesc);
			fLocation = TRUE;
		}
		else if (strcasecmp(pHeader->pszName, "USN") == 0) {
			if (g_fLogging & NALOG_INFO1)
				fprintf(g_log, "Checking USN...\n");
			strncpy(g_szUSN, pHeader->pszValue, sizeof(g_szUSN) - 1);
			g_szUSN[sizeof(g_szUSN) - 1] = '\0';
			fUSN = TRUE;
		}
		else {
			;  // do nothing for other headers for now
		}
	}

	// now check flags and set enabled if all set
	if (fLocation && fUSN) {
		if (g_fLogging & NALOG_INFO1) {
			fprintf(g_log,
				"Description Host/port string: [%s]\n"
				"NATDevDescURL: [%s], USN: [%s]\n",
				g_szRouterHostPortDesc,
				g_szNATDevDescURL, g_szUSN);
			if (g_fLogging & NALOG_INFO1)
				fprintf(g_log, "Got router information\n");
		}

		g_fUPnPEnabled = TRUE;
		pthread_cond_broadcast(&g_condUPnP);
	}

	// remember to unlock before return
	pthread_mutex_unlock(&g_xUPnP);

	return 0;
}

// granularity is specified as: granularity = 1/nth seconds
#define UPNP_TIMEOUT_GRANULARITY	(1000)
#define U_TOGRAN					UPNP_TIMEOUT_GRANULARITY

// result = a - b
static void TimevalSubtract(
	struct timeval *result,
	const struct timeval *a,
	const struct timeval *b)
{
	result->tv_sec = a->tv_sec - b->tv_sec;

	if (b->tv_usec > a->tv_usec) {
		result->tv_sec--;
		result->tv_usec = 1000000 + a->tv_usec - b->tv_usec;
	}
	else
		result->tv_usec = a->tv_usec - b->tv_usec;
}

// elapsed = end - start
static void GetTimeElapsed(
	const struct timeval *tv_start,
	const struct timeval *tv_end,
	struct timeval *tv_elapsed)
{
	TimevalSubtract(tv_elapsed, tv_end, tv_start);
#if 0
	tv_elapsed->tv_sec = tv_end->tv_sec - tv_start->tv_sec;

	if (tv_start->tv_usec > tv_end->tv_usec) {
		tv_elapsed->tv_sec--;
		tv_elapsed->tv_usec = 1000000 + tv_end->tv_usec - tv_start->tv_usec;
	}
	else
		tv_elapsed->tv_usec = tv_end->tv_usec - tv_start->tv_usec;
#endif
}

// returns +1, 0, or -1, if a>b, a==b, a<b, respectively
static int CompareTime(
	const struct timeval *a,
	const struct timeval *b
	)
{
	if ((a->tv_sec == b->tv_sec) &&
		(a->tv_usec == b->tv_usec)) return 0;

	if (a->tv_sec > b->tv_sec) return 1;
	else if (a->tv_sec < b->tv_sec) return -1;

	// if seconds are equal...
	if (a->tv_usec > b->tv_usec) return 1;
	else return -1;
}

static int WaitControlURLSet(double timeout)
{
	struct timespec		ts;
	struct timeval		tv;
	struct timeval		tv_start;
	int					iRet;
	long				to_sec = (int) (timeout / U_TOGRAN);
	long				to_usec =
		(int) (((timeout / U_TOGRAN) - to_sec) * 1000000.0);
	//long				to_sec = (int) timeout;
	//long				to_usec = (int) ((timeout - to_sec) * 1000000.0);
	struct timeval		elapsed;

	// get function start time
	gettimeofday(&tv_start, NULL);

	pthread_mutex_lock(&g_xUPnP);

#if 0
	// if last update is too long ago then wait for it
	GetTimeElapsed(&g_tvLastUpdateTime, &tv_start, &elapsed);
	if ((elapsed.tv_sec + (elapsed.tv_usec / 1000000.0)) >
		(((double) g_iUPnPTimeout) / U_TOGRAN))
		g_fControlURLSet = 0;
#endif

	while (!g_fControlURLSet) {
		// get current time
		gettimeofday(&tv, NULL);

#if 0
for now ignore device timeout
		// see if we've past the device's timeout first
		GetTimeElapsed(&g_tvUPnPInitTime, &tv, &elapsed);
		if ((elapsed.tv_sec > g_timeout_sec) ||
			(	(elapsed.tv_sec == g_timeout_sec) &&
				(elapsed.tv_usec > g_timeout_usec)
			))
		{
			pthread_mutex_unlock(&g_xUPnP);
			return FALSE;
		}
#endif

		// calculate ts to sleep till
		ts.tv_sec = tv.tv_sec + to_sec;
		ts.tv_nsec = (tv.tv_usec + to_usec) * 1000;
		if (ts.tv_nsec > 1000000000) {
			ts.tv_nsec -= 1000000000;
			ts.tv_sec += 1;
		}

		// now get how long we've been in this function already and deduct
		GetTimeElapsed(&tv_start, &tv, &elapsed);
		ts.tv_sec -= elapsed.tv_sec;
		if (ts.tv_nsec < (elapsed.tv_usec * 1000)) {
			ts.tv_sec--;
			ts.tv_nsec = 1000000000 + ts.tv_nsec - (elapsed.tv_usec * 1000);
		}
		else {
			ts.tv_nsec -= (elapsed.tv_usec * 1000);
		}

		iRet = pthread_cond_timedwait(&g_condUPnPControlURL, &g_xUPnP, &ts);

		// if timeout then return false
		if (iRet != 0)
		{
			pthread_mutex_unlock(&g_xUPnP);
			return FALSE;
		}
	}
	pthread_mutex_unlock(&g_xUPnP);

	return TRUE;
}

static int WaitUPnPFunction()
{
	struct timeval	start;
//	struct timeval	end;
	double			wait2;
//	struct timeval	elapsed;

	gettimeofday(&start, NULL);

	wait2 = (double)g_iFunctionTimeout;

	WaitControlURLSet(wait2);

//gettimeofday(&end, NULL);
//GetTimeElapsed(&start, &end, &elapsed);
//fprintf(stderr, "== wait2: (%f) %d.%06d\n",
//	wait2/U_TOGRAN, elapsed.tv_sec, elapsed.tv_usec);

	return g_fControlURLSet;
}

static void SetLocalIP();

static int SendTCPMsg_saddr_parse(
	char *msg, int iLen,
	char *result, int resultSize,
	struct sockaddr_in *saHost);

static void *TCPProc(void *in)
{
	int				iRet;
	unsigned char	buf[MAX_SOAPMSGSIZE];
	int				iBufLen;
	
	(void)in; // unused
	WaitUPnPFunction();
	//TracePrint(ELL_TRACE, "UPnP: Begin TCPProc\n");
	
	// do the subscription
	{
		char callback[100];
		char response[2000];
		PHTTPResponse resp;
		int n;
		sprintf(callback, "%lu.%lu.%lu.%lu:%u", 
			(g_dwLocalIP >> 24) & 0xFF,
			(g_dwLocalIP >> 16) & 0xFF,
			(g_dwLocalIP >> 8) & 0xFF,
			(g_dwLocalIP >> 0) & 0xFF,
			g_wEventPort);

		n = sprintf((char *)buf,
			szEventMsgSubscribeFMT,
			g_szEventURL,
			callback, g_szRouterHostPortEvent, 1800);

		memset(response, 0, 2000);
		n = SendTCPMsg_saddr_parse(
			(char *)buf, n,
			response, 2000,
			&g_saddrRouterEvent);
		if (n > 0)
		{
			response[n] = '\0';
			resp = NewHTTPResponse_sz((char *)buf, n, TRUE);
			if (NULL != resp)
			{
////TracePrint(ELL_TRACE, "UPnP Subscribe returns %s/%d\n", resp->pszStatus, n);
			}
			else
			{
////TracePrint(ELL_TRACE, "UPnP Subscribe not enough response (%d) \n[%s]\n",
//	n, response);
			}
			DeleteHTTPResponse(resp);
		}
		else
		{
////TracePrint(ELL_TRACE, "UPnP Subscribe failed (%d)\n", n);
			return NULL;
		}
	}

	//TracePrint(ELL_TRACE, "UPnP: TCPProc begin loop\n");

	g_sTCPCancel = -1;

	for (;;)
	{
//		ssize_t				n;
		struct sockaddr_in	recvaddr;
		socklen_t		    recvaddrlen;
		fd_set				readfds;
		struct timeval		timeout;
		int					sEvent;
		int					fFirstRecv;
		int					sMax;

		// for after responding to long(?) TCP event
		if (g_fQuit)
			goto cleanup;

		if (g_sTCPCancel != -1) close(g_sTCPCancel);
		sMax = g_sTCPCancel = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sMax < g_sTCP) sMax = g_sTCP;

		FD_ZERO(&readfds);
		FD_SET(g_sTCP, &readfds);
		FD_SET(g_sTCPCancel, &readfds);
		iRet = select(sMax+1, &readfds, NULL, NULL, NULL);
		if (iRet <= 0) {
			if (EBADF == errno)
				continue;
			//TracePrint(ELL_TRACE, "UPnP Event select failed (%d)\n", errno);
			continue;
		}

		recvaddrlen = sizeof(recvaddr);
		sEvent = accept(g_sTCP, (struct sockaddr *)&recvaddr, &recvaddrlen);
		// not likely - (system's descriptor/file table full)
		if (sEvent <= 0) continue;

		////TracePrint(ELL_TRACE, "UPnP receiving event..\n");

		// read all we could from this event
		fFirstRecv = 1;
		iBufLen = 0;
		for (;;)
		{
			FD_ZERO(&readfds);
			FD_SET(sEvent, &readfds);
			timeout.tv_sec = 0;
			timeout.tv_usec = 400000;	// long cause we're dealing with input
			iRet = select(sEvent+1, &readfds, NULL, NULL, &timeout);
			if (iRet <= 0) {
				if (g_fQuit)
				{
					close(sEvent);
					goto cleanup;
				}
				break;
			}

			// recv
			iRet = recv(sEvent, buf + iBufLen, MAX_SOAPMSGSIZE - iBufLen, 0);
			if (iRet < 0)
			{
				// something is wrong
				break;
			}
			else if (iRet == 0)
			{
				break;
			}

			iBufLen += iRet;

			if (fFirstRecv)
			{
				int iTemp;
				iTemp = send(sEvent, HTTP200OK, HTTP200OKLEN, 0);
				shutdown(sEvent, 1);
				fFirstRecv = 0;
			}
		}

		// now send 200 OK and be done
		close(sEvent);

		////TracePrint(ELL_TRACE, "UPnP event (%d) received (%d)\n", g_fExpectEvent, iBufLen);

		// and parse the XML here.
		if (iBufLen < MAX_SOAPMSGSIZE)
		{
			buf[iBufLen] = '\0';
			// for now do nothing
		}
		else
		{
			buf[MAX_SOAPMSGSIZE - 1] = '\0';
		}
	}

cleanup:
	//TracePrint(ELL_TRACE, "UPnP: TCPProc end\n");
	close(g_sTCP);
	g_sTCP = -1;
	g_fEventEnabled = FALSE;
	if (g_sTCPCancel != -1) close(g_sTCPCancel);
	g_sTCPCancel = -1;
	return NULL;
}

static void *UDPProc(void *in)
{
//	char			fLoop = 0; // false - don't send copy to self
//	int				iTTL = SSDP_TTL;
	int				iRet;
//	struct ip_mreq	mreq;
//	struct sockaddr_in	saddr;
	unsigned char	buf[65536];
//	FILE			*log = g_log;
	static time_t	last_getdevicedesc_t = 0;
	
	(void)in;  // unused
	pthread_mutex_lock(&g_xUPnP);
	gettimeofday(&g_tvUPnPInitTime, NULL);
	pthread_mutex_unlock(&g_xUPnP);

	for (;;) {
		ssize_t				n;
		struct sockaddr_in	recvaddr;
		socklen_t					recvaddrlen;
		fd_set				readfds;
		//struct timeval		timeout;
		//int					i;
		int					sMax;

		if (g_sUDPCancel < g_sUDP) sMax = g_sUDP;
		else                       sMax = g_sUDPCancel;

		FD_ZERO(&readfds);
		FD_SET(g_sUDP, &readfds);
		FD_SET(g_sUDPCancel, &readfds);
		iRet = select(sMax+1, &readfds, NULL, NULL, NULL);

		if (iRet <= 0) {
			if (g_fQuit)
			{
				close(g_sUDP);
				close(g_sUDPCancel);
				g_sUDP = -1;
				g_sUDPCancel = -1;
				return NULL;
			}
			continue;
		}

		if (!FD_ISSET(g_sUDP, &readfds)) continue;
		recvaddrlen = sizeof(recvaddr);
		n = recvfrom(g_sUDP, buf, sizeof(buf), 0,
			(struct sockaddr *)&recvaddr, &recvaddrlen);
		if (n < 0) {
			if (g_fLogging & NALOG_ERROR)
				fprintf(g_log, "recv failed (%d)\n", errno);
			close(g_sUDP);
			close(g_sUDPCancel);
			g_sUDP = -1;
			g_sUDPCancel = -1;
			return NULL;
		}
		buf[n] = '\0';
		if (strncmp((char *)buf, "HTTP/1.1", 8) == 0) {
			PHTTPResponse pResponse = NewHTTPResponse_sz((char *)buf, n, TRUE);
			PrintHTTPResponse(pResponse);
			if (DiscoverRouter(pResponse) == 0)
			{
				time_t	now = time(NULL);
				if (!g_fControlURLSet ||
					((now - last_getdevicedesc_t) > 5))
				{
					GetDeviceDescription();
					SetLocalIP();
					last_getdevicedesc_t = now;
				}
			}
			DeleteHTTPResponse(pResponse);
		}
		else if (strncmp((char *)buf, "NOTIFY * HTTP/1.1", 7) == 0) {
			// temporarily use this to fudge - will have the exact same
			// parsing, only status/reason set to "*" and "HTTP/1.1".
			// TODO: add support for HTTP requests
			PHTTPResponse pResponse = NewHTTPResponse_sz((char *)buf, n, TRUE);
			if (DiscoverRouter(pResponse) == 0)
			{
				time_t	now = time(NULL);
				if (!g_fControlURLSet ||
					((now - last_getdevicedesc_t) > 5))
				{
					GetDeviceDescription();
					SetLocalIP();
					last_getdevicedesc_t = now;
				}
			}
			DeleteHTTPResponse(pResponse);
		}
		else {
			if (g_fLogging & NALOG_DUMP)
				fprintf(g_log, "(%ld) Buffer: \n[%s]\n", time(NULL), buf);
			fflush(g_log);
		}
	}

	close(g_sUDP);
	g_sUDP = -1;
}

static void SendUDPMsg(const char *msg) {
	struct sockaddr_in	saSendTo;
	int					iRet;
	int					iLen;

	bzero(&saSendTo, sizeof(saSendTo));
	saSendTo.sin_family = AF_INET;
	saSendTo.sin_addr.s_addr = inet_addr(SSDP_IP);
	saSendTo.sin_port = htons(SSDP_PORT);

	iLen = strlen(msg);

	if (g_fLogging & NALOG_DUMP)
		fprintf(g_log, "SendUDP: [%s]\n", msg);

	iRet = sendto(g_sUDP, msg, iLen, 0,
		(struct sockaddr *)&saSendTo, sizeof(saSendTo));

	// sanity check
	if (iRet != iLen)
		if (g_fLogging & NALOG_ALERT)
			fprintf(g_log,
				"SendUDPMsg: iRet(%d) != strlen(msg)(%d)! (errno %d)\n",
				iRet, iLen, errno);
}

// strstr, case insensitive, and is limited by len
static char *strcasestr_n(const char *big, const char *little, int len)
{
	int bigLen;
	int littleLen;
	int i;
	int end;

	if (little == NULL) return (char *)big;
	if (big == NULL) return NULL;

	//bigLen = strlen(big);
	bigLen = len;
	littleLen = strlen(little);

	if (bigLen < littleLen) return NULL;

	end = bigLen - littleLen;
	for (i = 0; i <= end; (i++), (big++)) {
		if (strncasecmp(big, little, littleLen) == 0)
			return (char *)big;
	}

	return NULL;
}

// this is strnstr, only portable
static char *strstr_n(const char *big, const char *little, int len)
{
	int		iBigLen;
	int		iLittleLen;

	(void)len;  // unused

	if ((big == NULL) || (little == NULL)) return NULL;

	iBigLen = strlen(big);
	iLittleLen = strlen(little);

	// this part is basically strnstr, except this is portable
	for (;;) {
		if (iBigLen < iLittleLen)
			return NULL;
		if (strncmp(big, little, iLittleLen) == 0)
			return (char *)big;
		++big;
		--iBigLen;
	}
}

// returns -1 for "not found"
static int FindContentLength(char *pbuf, int iLen)
{
	// non reusable HTTP header parsing code:
	// ----------------------------------------------
	char			*p;
	int				iResult;

	// find content length header
	p = strcasestr_n(pbuf, "\r\nContent-Length:", iLen);
	if (p == NULL) return -1;

	p += sizeof("\r\nContent-Length:") - 1;	// minus '\0'

	iResult = atoi(p);

	return iResult;
	// ----------------------------------------------
}

// returns -1 for "not found"
static int FindBody(char *pbuf, int iLen)
{
	// non reusable HTTP header parsing code:
	// ----------------------------------------------
	char			*p;
//	int				iResult;

	// find the empty line
	p = strstr_n(pbuf, "\r\n\r\n", iLen);
	if (p == NULL) return -1;

	p += sizeof("\r\n\r\n") - 1;	// minus '\0'

	return (p - pbuf);
	// ----------------------------------------------
}

static int SendTCPMsg_saddr_2part(
	char *msg, int iLen,
	char *msg2, int iLen2,
	char *result, int resultSize,
	struct sockaddr_in *saHost)
{
	int					s;
	struct sockaddr_in	saSendTo;
	int					iRet;
	int					iBufLen;
	int					fND;
	int					fcntl_flags;
	int					iRetcode;
	struct timeval		tv;
	fd_set				writefds;

	struct timeval		tv_start;
	struct timeval		tv_end;
	struct timeval		tv_elapsed;

	int					iContentLength = -1;
	int					iBodyOffset = -1;

	gettimeofday(&tv_start, NULL);

	if (g_fUPnPEnabled != TRUE) {
//TracePrint(ELL_TRACE, "UPnP not enabled\n");
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "UPnP not enabled (no UPnP device found yet)\n");
		return NA_E_NOT_AVAILABLE;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "Can't get TCP socket (%d)\n", errno);
		return NA_E_NET;
	}

	fND = 1;
	if (setsockopt(s, IPPROTO_IP, TCP_NODELAY, &fND, sizeof(fND)) != 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/2part: Can't set TCP_NODELAY option!\n");
		iRetcode = NA_E_NET;
		goto cleanup;
	}

	fcntl_flags = 0;
	fcntl_flags = fcntl(s, F_GETFL, 0);
	fcntl_flags |= O_NONBLOCK;
	if (fcntl(s, F_SETFL, fcntl_flags) != 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/2part: Can't set O_NONBLOCK option!\n");
		iRetcode = NA_E_NET;
		goto cleanup;
	}

	if (saHost == NULL)
		memcpy(&saSendTo, &g_saddrRouterDesc, sizeof(saSendTo));
	else
		memcpy(&saSendTo, saHost, sizeof(saSendTo));

	iRet = connect(s, (struct sockaddr *) &saSendTo, sizeof(saSendTo));
	if ((iRet < 0) && (errno != EINPROGRESS)) {
//TracePrint(ELL_TRACE, "UPnP connect failed\n");
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/2part: connect failed (%d)\n", errno);
		iRetcode = NA_E_NET;
		goto cleanup;
	}

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log,
			"- Before Sending TCP Msg1: %d == %lu?\n", iLen, strlen(msg));
	if (g_fLogging & NALOG_DUMP)
		fprintf(g_log, "Sending TCP msg part 1:\n[%s]\n", msg);

	tv.tv_sec = g_iFunctionTimeout / UPNP_TIMEOUT_GRANULARITY;
	tv.tv_usec = (g_iFunctionTimeout % U_TOGRAN) * 1000000 / U_TOGRAN;
	FD_ZERO(&writefds);
	FD_SET(s, &writefds);
	iRet = select(s+1, 0, &writefds, 0, &tv);
	if (iRet < 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/2part: select failed (%d)\n", errno);
		iRetcode = NA_E_NET;
		goto cleanup;
	}
	if (iRet == 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/2part: select timed out\n");
		iRetcode = NA_E_TIMEOUT;
gettimeofday(&tv_end, NULL);
GetTimeElapsed(&tv_start, &tv_end, &tv_elapsed);
//TracePrint(ELL_TRACE, "UPnP 2part: timeout @1st after %lu.%06lu secs\n",
//	tv_elapsed.tv_sec, tv_elapsed.tv_usec);
		goto cleanup;
	}

	iRet = send(s, msg, iLen, 0);
	// sanity check
	if (iRet != iLen)
		if (g_fLogging & NALOG_ALERT)
			fprintf(g_log, "SendTCPMsg/2part: iRet(%d) != strlen(msg)(%d)!\n",
				iRet, iLen);

//TracePrint(ELL_TRACE, "UPnP 2part: 1st %d == %d (%d) (%d)?\n", iRet, iLen, strlen(msg), errno);

	tv.tv_sec = g_iFunctionTimeout / UPNP_TIMEOUT_GRANULARITY;
	tv.tv_usec = (g_iFunctionTimeout % U_TOGRAN) * 1000000 / U_TOGRAN;
	FD_ZERO(&writefds);
	FD_SET(s, &writefds);
	// calculate how much time elapsed
	gettimeofday(&tv_end, NULL);
	GetTimeElapsed(&tv_start, &tv_end, &tv_elapsed);
	if (CompareTime(&tv_elapsed, &tv) > 0) {
		close(s);
		return NA_E_TIMEOUT;
		//tv.tv_sec = 0;
		//tv.tv_usec = 0;
	}
	else {
		// subtract that from timeout accordingly
		tv.tv_sec -= tv_elapsed.tv_sec;
		if (tv.tv_usec < tv_elapsed.tv_usec) {
			tv.tv_sec--;
			tv.tv_usec = 1000000 + tv.tv_usec - tv_elapsed.tv_usec;
		}
		else
			tv.tv_usec = tv.tv_usec - tv_elapsed.tv_usec;
	}
	iRet = select(s+1, 0, &writefds, 0, &tv);
	if (iRet < 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/2part: select2 failed (%d)\n", errno);
		iRetcode = NA_E_NET;
		goto cleanup;
	}
	if (iRet == 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/2part: select2 timed out\n");
		iRetcode = NA_E_TIMEOUT;
gettimeofday(&tv_end, NULL);
GetTimeElapsed(&tv_start, &tv_end, &tv_elapsed);
//TracePrint(ELL_TRACE, "UPnP 2part: timeout @2nd after %lu.%06lu secs\n",
//	tv_elapsed.tv_sec, tv_elapsed.tv_usec);
		goto cleanup;
	}

	iRet = send(s, msg2, iLen2, 0);
	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log,
			"SendTCPMsg/parse: Before Sending TCP Msg2: %d == %lu?\n",
			iLen2, strlen(msg2));
	if (g_fLogging & NALOG_DUMP)
		fprintf(g_log, "Sending TCP msg part 2:\n[%s]\n", msg2);

//TracePrint(ELL_TRACE, "UPnP 2part: 2nd %d == %d (%d) (%d)?\n", iRet, iLen2, strlen(msg2), errno);

	// sanity check
	if (iRet != iLen2)
		if (g_fLogging & NALOG_ALERT)
			fprintf(g_log, "SendTCPMsg/2part: iRet(%d) != strlen(msg2)(%d)!\n",
				iRet, iLen2);

	if (result == NULL) {    // if caller just want to send/display msgs
		if (g_fLogging & NALOG_DUMP)
			fprintf(g_log, "TCP Buffer: [");
	}

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log, "start recv @%lu\n", time(NULL));

	iBufLen = 0;
	iContentLength = -1;
	iBodyOffset = -1;
	for (;;) {
		fd_set			readfds;
		struct timeval	timeout;
		int				i;

		FD_ZERO(&readfds);
		FD_SET(s, &readfds);
		//timeout.tv_sec = g_iFunctionTimeout / U_TOGRAN;
		//timeout.tv_usec = (g_iFunctionTimeout % U_TOGRAN) * 1000000 / U_TOGRAN;
		// just do flat 2 sec now, since connection already established
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;


		iRet = select(s+1, &readfds, NULL, NULL, &timeout);
		if (iRet <= 0)
		{
//TracePrint(ELL_TRACE, "UPnP 2part: select timeout? (%d, %d)\n",
//	iRet, errno);
			break;
		}

//gettimeofday(&tv_end, NULL);
//GetTimeElapsed(&tv_start, &tv_end, &tv_elapsed);
//fprintf(stderr, "2 == loop: %d.%06d\n", tv_elapsed.tv_sec, tv_elapsed.tv_usec);

		// if only sending messages
		if (result == NULL) {
			char	t[1000];
			i = recv(s, t, 1000-1, 0);	// leave room for '\0' for dump
			if (i== 0) break;
			if (g_fLogging & NALOG_DUMP) {
				t[i] = '\0';
				fprintf(g_log, "%s", t);
			}
			continue;
		}

		// EO result buf: discard extra bytes
		if (resultSize <= iBufLen) {
			char	t[1000];
			i = recv(s, &t, 1000, 0);
			if (i== 0) break;
			// Note that there's no dump here - prevents DoS attack from
			// flooding the logs/diskspace
			continue;
		}

		i = recv(s, result + iBufLen, resultSize - iBufLen, 0);
		if (i <= 0) {
//TracePrint(ELL_TRACE, "UPnP 2part: recv done %d (%d, %d)\n",
//	iBufLen, i, errno);
			break;
		}

		iBufLen += i;

		// parse and see if we can find content-length to quit early
		iContentLength = FindContentLength(result, iBufLen);

		// now if we're still in header, see if we can find body
		iBodyOffset = FindBody(result, iBufLen);

		// now check if we can leave early.  conditions are:
		// past headers, and we've already recv'ed content-length of body
		if ((iBodyOffset >= 0) &&
			(iContentLength >= 0) &&
			((iBufLen - iBodyOffset) >= iContentLength))
		{
//TracePrint(ELL_TRACE, "UPnP 2part: read all specified %d (%d, %d) (%d, %d)\n",
//	iBufLen, i, errno, iBodyOffset, iContentLength);
			break;
		}
	}

//fprintf(stderr, "2 -- \n");

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log, "done recv @%lu\n", time(NULL));

	if (result == NULL) {    // if caller just want to send/display msgs
		if (g_fLogging & NALOG_DUMP)
			fprintf(g_log, "]\n");
	}

	close(s);
	return iBufLen;

cleanup:
	close(s);
	return iRetcode;
}

static int SendTCPMsg_saddr_parse(
	char *msg, int iLen,
	char *result, int resultSize,
	struct sockaddr_in *saHost)
{
	int					s;
	struct sockaddr_in	saSendTo;
	int					iRet;
	int					iBufLen;
	int					fcntl_flags;
	fd_set				writefds;
	struct timeval		tv;

	struct timeval		tv_start;
//	struct timeval		tv_end;
//	struct timeval		tv_elapsed;

	// HTTP parsing vars
	char				*pszCurHdr;
	int					iContentLength;
	int					iBodyOffset;
//	char				prevChar;

	tv.tv_sec = 0;
	tv.tv_usec = 25000;
	select(0, NULL, NULL, NULL, &tv);

	pthread_mutex_lock(&g_xUPnPMsg);

	gettimeofday(&tv_start, NULL);

	if (g_fUPnPEnabled != TRUE) {
//TracePrint(ELL_TRACE, "UPnP not enabled\n");
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "UPnP not enabled (no UPnP device found yet)\n");
		pthread_mutex_unlock(&g_xUPnPMsg);
		return NA_E_NOT_AVAILABLE;
	}

	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == -1) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "Can't get TCP socket (%d)\n", errno);
		pthread_mutex_unlock(&g_xUPnPMsg);
		return NA_E_NET;
	}

	fcntl_flags = 0;
	fcntl_flags = fcntl(s, F_GETFL, 0);
	fcntl_flags |= O_NONBLOCK;
	if (fcntl(s, F_SETFL, fcntl_flags) != 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/parse: Can't set O_NONBLOCK option!\n");
		close(s);
		pthread_mutex_unlock(&g_xUPnPMsg);
		return NA_E_NET;
	}

	if (saHost == NULL)
		memcpy(&saSendTo, &g_saddrRouterDesc, sizeof(saSendTo));
	else
		memcpy(&saSendTo, saHost, sizeof(saSendTo));

	iRet = connect(s, (struct sockaddr *) &saSendTo, sizeof(saSendTo));
	if ((iRet < 0) && (errno != EINPROGRESS)) {
//TracePrint(ELL_TRACE, "UPnP connect failed\n");
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/parse: connect failed (%d)\n", errno);
		close(s);
		pthread_mutex_unlock(&g_xUPnPMsg);
		return NA_E_NET;
	}

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log, "SendTCPMsg/parse: Before Sending TCP Msg: %d == %lu?\n",
			iLen, strlen(msg));
	if (g_fLogging & NALOG_DUMP)
		fprintf(g_log,"Sending TCP msg:\n[%s]\n", msg);

	tv.tv_sec = g_iFunctionTimeout / UPNP_TIMEOUT_GRANULARITY;
	tv.tv_usec = (g_iFunctionTimeout % U_TOGRAN) * 1000000 / U_TOGRAN;
	FD_ZERO(&writefds);
	FD_SET(s, &writefds);
	iRet = select(s+1, 0, &writefds, 0, &tv);
	if (iRet < 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/parse: select failed (%d)\n", errno);
		close(s);
		pthread_mutex_unlock(&g_xUPnPMsg);
		return NA_E_NET;
	}
	if (iRet == 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "SendTCPMsg/parse: select timed out\n");
		close(s);
		pthread_mutex_unlock(&g_xUPnPMsg);
		return NA_E_TIMEOUT;
	}

	iRet = send(s, msg, iLen, 0);

	// sanity check
	if (iRet != iLen)
		if (g_fLogging & NALOG_ALERT)
			fprintf(g_log, "SendTCPMsg: iRet (%d) != strlen(msg) (%d)!\n",
				iRet, iLen);

	if (result == NULL) {    // if caller just want to send/display msgs
		if (g_fLogging & NALOG_DUMP)
			fprintf(g_log, "TCP Buffer: [");
	}

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log, "start recv @%lu\n", time(NULL));

	iBufLen = 0;
	pszCurHdr = result;
	iContentLength = -1;
	iBodyOffset = -1;
	for (;;) {
		fd_set			readfds;
		struct timeval	timeout;
		int				i;

		FD_ZERO(&readfds);
		FD_SET(s, &readfds);
		//timeout.tv_sec = g_iFunctionTimeout / U_TOGRAN;
		//timeout.tv_usec = (g_iFunctionTimeout % U_TOGRAN) * 1000000 / U_TOGRAN;
		// just do flat 2 sec now, since connection already established
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;

		iRet = select(s+1, &readfds, NULL, NULL, &timeout);
		if (iRet <= 0) {
//fprintf(stderr, "**********: select failed (%d/%d)\n", iRet, errno);
			break;
		}

//gettimeofday(&tv_end, NULL);
//GetTimeElapsed(&tv_start, &tv_end, &tv_elapsed);
//fprintf(stderr, "p == loop: %d.%06d\n", tv_elapsed.tv_sec, tv_elapsed.tv_usec);

		// if only sending messages
		if (result == NULL) {
			char	t[1000];
			i = recv(s, t, 1000-1, 0);	// leave room for '\0' for dump
			if (i== 0) break;
			if (g_fLogging & NALOG_DUMP) {
				t[i] = '\0';
				fprintf(g_log, "%s", t);
			}
			continue;
		}

		// EO result buf: discard extra bytes
		if (resultSize <= iBufLen) {
			char	t[1000];
			i = recv(s, &t, 1000, 0);
			if (i== 0) break;
			// Note that there's no dump here - prevents DoS attack from
			// flooding the logs/diskspace
			continue;
		}

		i = recv(s, result + iBufLen, resultSize - iBufLen, 0);
		if (0 == i) {

			break;
		}
		else if (i < 0) {
			if (EAGAIN == errno) continue;
			break;
		}

		iBufLen += i;

		// parse and see if we can find content-length to quit early
		iContentLength = FindContentLength(result, iBufLen);

		// now if we're still in header, see if we can find body
		iBodyOffset = FindBody(result, iBufLen);

	}

//fprintf(stderr, "p -- \n");

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log, "done recv @%lu\n", time(NULL));

	if (result == NULL) {    // if caller just want to send/display msgs
		if (g_fLogging & NALOG_DUMP)
			fprintf(g_log, "]\n");
	}

	close(s);
	pthread_mutex_unlock(&g_xUPnPMsg);
	return iBufLen;
}



// szSOAPMsgControlAHeaderFMT   - 4 args (ctrl_url, host/port, action, length)
// szSOAPMsgControlABodyFMT     - 2 args (action, args string)
// szSOAPMsgControlAArgumentFMT - 2 args (name/value)
static PHTTPResponse SendSOAPMsgControlAction(
	char *action,
	int argc,
	PProperty args,
	int f2Part)
{
	//char	outBuffer[65536];
	//char	outBufferBody[65536];
	//char	outBufferArgs[65536];
	char	*outBuffer = NULL;
	char	*outBufferBody = NULL;
	char	*outBufferArgs = NULL;
	char	*inBuffer = NULL;
	int		iLen;
	int		iHeaderLen;
	int		iBodyLen;
	int		iArgsLen;
	int		iResultLen;
	int		i;
	int		n;
	PHTTPResponse pResponse = NULL;


	if (!WaitUPnPFunction())
		return NULL;

	if ((outBuffer = (char *) malloc(MAX_SOAPMSGSIZE)) == NULL) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "can't malloc for outBuffer\n");
		goto cleanup;
	}
	if ((outBufferBody = (char *) malloc(MAX_SOAPMSGSIZE)) == NULL) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "can't malloc for outBufferBody\n");
		goto cleanup;
	}
	if ((outBufferArgs = (char *) malloc(MAX_SOAPMSGSIZE)) == NULL) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "can't malloc for outBufferArgs\n");
		goto cleanup;
	}
	if ((inBuffer = (char *) malloc(MAX_SOAPMSGSIZE)) == NULL) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "can't malloc for inBuffer\n");
		goto cleanup;
	}

	iArgsLen = 0;
	if (args != NULL)
		for (i=0; i<argc; i++) {
			n = 0;
			if (args[i].pszType == NULL) {
				n = sprintf(outBufferArgs + iArgsLen,
					szSOAPMsgControlAArgumentFMT,
					args[i].pszName, args[i].pszValue);
			}
			else {
				n = sprintf(outBufferArgs + iArgsLen,
					szSOAPMsgControlAArgumentFMT_t,
					args[i].pszName, args[i].pszValue, args[i].pszType);
			}
			iArgsLen += n;
		}
	outBufferArgs[iArgsLen] = '\0';

	iBodyLen = sprintf(outBufferBody, szSOAPMsgControlABodyFMT,
		action, outBufferArgs);

	iHeaderLen = sprintf(outBuffer, szSOAPMsgControlAHeaderFMT,
		g_szControlURL, g_szRouterHostPortSOAP, action, iBodyLen);

	if (f2Part) {
		DumpHex(outBuffer, iHeaderLen+1);
		DumpHex(outBufferBody, iBodyLen+1);
		iResultLen = SendTCPMsg_saddr_2part(
			outBuffer, iHeaderLen,
			outBufferBody, iBodyLen,
			inBuffer, MAX_SOAPMSGSIZE,
			&g_saddrRouterSOAP);
	}
	else {
		strcpy(outBuffer + iHeaderLen, outBufferBody);
		iLen = iHeaderLen + iBodyLen;

		DumpHex(outBuffer, iLen+1);

//strcat(outBuffer, CRLF "0" CRLF CRLF);
//iLen += 7;

		iResultLen = SendTCPMsg_saddr_parse(
			outBuffer, iLen,
			inBuffer, MAX_SOAPMSGSIZE,
			&g_saddrRouterSOAP);
	}

	if (iResultLen > 0) {
		if (iResultLen > MAX_SOAPMSGSIZE) {
			if (g_fLogging & NALOG_ALERT)
				fprintf(g_log, "result truncated..\n");
			iResultLen = MAX_SOAPMSGSIZE;
		}
		pResponse = NewHTTPResponse_sz(inBuffer, iResultLen, FALSE);
		if (pResponse != NULL) {
			PrintHTTPResponse(pResponse);
			//DeleteHTTPResponse(pResponse);
			// - return response to caller
		}
	}
	else {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "No TCP Response\n");
		//TracePrint(ELL_TRACE, "UPnP SendSOAPMsg got no TCP response (%d)\n",
//			iResultLen);
	}

cleanup:
	if (outBuffer != NULL) free(outBuffer);
	if (outBufferBody != NULL) free(outBufferBody);
	if (outBufferArgs != NULL) free(outBufferArgs);
	if (inBuffer != NULL) free(inBuffer);

	return pResponse;
}

static int FindURLBase(char *pbuf, int iLen, char *szURLBase)
{
	// non reusable XML parsing code:
	// ----------------------------------------------
	char			*p;
	int				i = 0;

	// now skip after end of this tag, then skip until controlURL tag
	p = strstr_n(pbuf, "<URLBase>", iLen);
	if (p == NULL) return -1;

	// skip to the actual stuff
	p += sizeof("<URLBase>") - 1;  // minus '\0'

	// skip white spaces (just in case)
	while (isspace(*p))
		p++;

	// copy into szURLBase
	while ((*p != '\0') && (*p != '<') && !isspace(*p)) {
		if (i++ > 1000) break;
		*szURLBase = *p;
		szURLBase++;
		p++;
	}
	*szURLBase = '\0';

	return 0;
	// ----------------------------------------------
}


static int FindDescInfo(
	char *pbuf,
	int iLen,
	const char *szParentName,
	const char *szName,
	char *szValue)
{
	char			*p;
	char			szSearch[100];
	int				iSearchLen;
	int				i = 0;

	// find the device within pbuf
	p = strstr_n(
		pbuf,
		szParentName,
		iLen);
	if (p == NULL)
		return -1;

	// adjust strlen
	iLen -= (p - pbuf);
	pbuf = p;

	// now skip after end of this tag, then skip until manufacturer tag
	iSearchLen = sprintf(szSearch, "<%s>", szName);
	p = strstr_n(pbuf, szSearch, iLen);
	if (p == NULL) return -1;
	p += iSearchLen;

	// skip white spaces (just in case)
	while (isspace(*p))
		p++;

	// copy into szValue
	while ((*p != '\0') && (*p != '<')) {
		if (i++ > 1000) break;
		*szValue = *p;
		szValue++;
		p++;
	}
	*szValue = '\0';

	return 0;
}

static int FindIGDInfo(char *pbuf, int iLen, const char *szName, char *szValue)
{
	return FindDescInfo(
		pbuf, iLen,
		"urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		szName, szValue);
}

static int FindManufacturer(char *pbuf, int iLen, char *szManuf)
{
	return FindIGDInfo(pbuf, iLen, "manufacturer", szManuf);
}

static int FindFriendlyName(char *pbuf, int iLen, char *szValue)
{
	return FindIGDInfo(pbuf, iLen, "friendlyName", szValue);
}

static int FindModelName(char *pbuf, int iLen, char *szValue)
{
	return FindIGDInfo(pbuf, iLen, "modelName", szValue);
}

static int FindModelDescription(char *pbuf, int iLen, char *szValue)
{
	return FindIGDInfo(pbuf, iLen, "modelDescription", szValue);
}

static int FindWANIPInfo(char *pbuf, int iLen, const char *szName, char *szValue)
{
	return FindDescInfo(
		pbuf, iLen,
		"urn:schemas-upnp-org:service:WANIPConnection:1",
		szName, szValue);
}

static int FindControlURL(char *pbuf, int iLen, char *szControlURL)
{
	return FindWANIPInfo(pbuf, iLen, "controlURL", szControlURL);
}

static int FindEventURL(char *pbuf, int iLen, char *szEventURL)
{
	return FindWANIPInfo(pbuf, iLen, "eventSubURL", szEventURL);
}

static int FindRouterInfo(char *inBuffer, int iLen)
{
	if (FindManufacturer(inBuffer, iLen, g_szManufacturer) != 0)
		g_szManufacturer[0] = '\0';

	if (FindFriendlyName(inBuffer, iLen, g_szFriendlyName) != 0)
		g_szFriendlyName[0] = '\0';

	if (FindModelName(inBuffer, iLen, g_szModelName) != 0)
		g_szModelName[0] = '\0';

	if (FindModelDescription(inBuffer, iLen, g_szModelDescription) != 0)
		g_szModelDescription[0] = '\0';

//TracePrint(ELL_TRACE,
//	"UPnP Router Info:\n"
//	" - manufacturer   [%s]\n"
//	" - friendly name  [%s]\n"
//	" - model name     [%s]\n"
//	" - model desc     [%s]\n",
//	g_szManufacturer, g_szFriendlyName, g_szModelName, g_szModelDescription);

	return 0;
}

static void ParseURL(
	const char *szBuf, char *pszHostPort,
	struct sockaddr_in *psaddr, char *pszPath)
{
	char			buf[1024];
	char			*p;
	char			*q;
	unsigned short	port;

	strcpy(buf, szBuf);

	p = buf;
	if (0 == strncmp(p, "http://", 7))
		p += 7;

	q = strchr(p, '/');

	if (pszPath) {
		if (NULL == q) {
			pszPath[0] = '/';
			pszPath[1] = '\0';
		}
		else  {
			strcpy(pszPath, q);
			*q = '\0';
		}
	}

	// find the port separetor
	q = strchr(p, ':');
	if (NULL == q)
		port = 80;
	else {
		port = atoi(q + 1);
		// HTTP's by default port 80, so don't have it in the "Host:" header
		if (80 == port) *q = '\0';
	}

	if (pszHostPort) strcpy(pszHostPort, p);

	if (NULL != q) *q = '\0';

	if (NULL != psaddr) {
		psaddr->sin_family = AF_INET;
		psaddr->sin_addr.s_addr = inet_addr(p);
		psaddr->sin_port = htons(port);
	}
#if 0
//TracePrint(ELL_TRACE, "ParseURL [%s] -> [%s][%s] %lu.%lu.%lu.%lu:%u\n",
	szBuf,
	pszHostPort?pszHostPort:"",
	pszPath?pszPath:"",
	(psaddr->sin_addr.s_addr >> 24) & 0xff,
	(psaddr->sin_addr.s_addr >> 16) & 0xff,
	(psaddr->sin_addr.s_addr >> 8) & 0xff,
	(psaddr->sin_addr.s_addr >> 0) & 0xff,
	psaddr->sin_port);
#endif
}

static void GetDeviceDescription(void)
{
	char		*outBuffer = NULL;
	char		*inBuffer = NULL;
	int			iBufLen;
	int			iLen;
	char		szURLBase[1024];
	char		szControlURL[1024];
	char		szEventURL[1024];

	if (!g_fUPnPEnabled) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "GetDeviceDescription: upnp not enabled\n");
		return;
	}

	if ((outBuffer = (char *) malloc(MAX_SOAPMSGSIZE)) == NULL) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "can't malloc for outBuffer\n");
		goto cleanup;
	}
	if ((inBuffer = (char *) malloc(MAX_SOAPMSGSIZE)) == NULL) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "can't malloc for inBuffer\n");
		goto cleanup;
	}

	iBufLen = sprintf(outBuffer, szSSDPMsgDescribeDeviceFMT, g_szNATDevDescURL,
		g_szRouterHostPortDesc);

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log, "Describe Device: [%s]\n", outBuffer);
	iLen = SendTCPMsg_saddr_parse(outBuffer, iBufLen, inBuffer, MAX_SOAPMSGSIZE,
		&g_saddrRouterDesc);

	g_fControlURLSet = FALSE;

	if (FindControlURL(inBuffer, iLen, szControlURL) != 0) {
		if (g_fLogging & NALOG_ERROR)
			fprintf(g_log, "GetDeviceDesc: can't find control URL\n");
		goto cleanup;
	}

	// start modifying global
	pthread_mutex_lock(&g_xUPnP);

	{
		// now see if there's the URLBase
		if (FindURLBase(inBuffer, iLen, szURLBase) != 0) {
			// not there?  try default numbers from device description
			memcpy(&g_saddrRouterBase, &g_saddrRouterDesc,
				sizeof(g_saddrRouterBase));
			strcpy(g_szRouterHostPortBase, g_szRouterHostPortDesc);
		}
		else {
			ParseURL(szURLBase,
				g_szRouterHostPortBase, &g_saddrRouterBase, NULL);

			if ((strlen(g_szRouterHostPortBase) == 0) ||
				(g_saddrRouterBase.sin_addr.s_addr == INADDR_NONE)) {
				memcpy(&g_saddrRouterBase, &g_saddrRouterDesc,
					sizeof(g_saddrRouterBase));
				strcpy(g_szRouterHostPortBase, g_szRouterHostPortDesc);
			}
		}
	}

	ParseURL(szControlURL,
		g_szRouterHostPortSOAP, &g_saddrRouterSOAP, g_szControlURL);
	if ((strlen(g_szRouterHostPortSOAP) == 0) ||
		(g_saddrRouterSOAP.sin_addr.s_addr == INADDR_NONE)) {
		memcpy(&g_saddrRouterSOAP, &g_saddrRouterBase,
			sizeof(g_saddrRouterSOAP));
		strcpy(g_szRouterHostPortSOAP, g_szRouterHostPortBase);
	}


////TracePrint(ELL_TRACE, "UPnP Control URL set to[%s][%s]...\n",
//	g_szRouterHostPortSOAP, g_szControlURL);

	g_fControlURLSet = TRUE;
	gettimeofday(&g_tvLastUpdateTime, NULL);
	pthread_cond_broadcast(&g_condUPnPControlURL);

	if (g_fLogging & NALOG_INFO1)
		fprintf(g_log, "Got Device Description\n");

	// find router info
	FindRouterInfo(inBuffer, iLen);

	if (FindEventURL(inBuffer, iLen, szEventURL) != 0) {
		szEventURL[0] = '\0';
	}
	else {
		ParseURL(szEventURL,
			g_szRouterHostPortEvent, &g_saddrRouterEvent, g_szEventURL);
		if ((strlen(g_szRouterHostPortEvent) == 0) ||
			(g_saddrRouterEvent.sin_addr.s_addr == INADDR_NONE)) {
			memcpy(&g_saddrRouterEvent, &g_saddrRouterBase,
				sizeof(g_saddrRouterEvent));
			strcpy(g_szRouterHostPortEvent, g_szRouterHostPortBase);
		}

		EventInit();
	}

cleanup:
	if (outBuffer != NULL) free(outBuffer);
	if (inBuffer != NULL) free(inBuffer);

	pthread_mutex_unlock(&g_xUPnP);
}


static void GetIPByName(char *hostname, unsigned long *ip_ret)
{
	unsigned long ip;

	ip = inet_addr(hostname);
	if (ip == INADDR_NONE) {
		struct hostent *pHEnt;
		pHEnt = gethostbyname(hostname);
		if (pHEnt == NULL) {
			if (g_fLogging & NALOG_ALERT)
				fprintf(g_log, "Can't translate [%s] to IP...\n", hostname);
			g_dwLocalIP = htonl(INADDR_ANY);
			return;
		}
		ip = ntohl(*(unsigned long *)(pHEnt->h_addr));
		if (g_fLogging & NALOG_INFO1)
			fprintf(g_log, "hostname [%s] to ip: %ld.%ld.%ld.%ld\n",
				hostname,
				(ip >> 24) & 0xff,
				(ip >> 16) & 0xff,
				(ip >> 8) & 0xff,
				(ip >> 0) & 0xff);
	}
	*ip_ret = ip;
}

static void SetLocalIP()
{
	PIPINFO pIPInfo = NULL;
	int count = GetIPInfo(&pIPInfo);
	if (NULL != pIPInfo)
	{
		// choose first non IPV6 address
		// iterate through array and set port information
		int				i;
		unsigned long	dwFirst = 0;
		for(i = 0; i < count; i++)
		{
			if (!(pIPInfo[i].iFlags & ISIPV6) &&
				(strncmp(pIPInfo[i].szIfName, "ppp", 3) != 0))
			{
				unsigned long	dwTemp;

				memcpy(&dwTemp, pIPInfo[i].abIP, sizeof(unsigned long));

				if (0 != GetNATIPNetmask(dwTemp)) {
					g_dwLocalIP = dwTemp;
					break;
				}

				if (0 == dwFirst)
					dwFirst = dwTemp;
			}
		}
		if (i == count)
			g_dwLocalIP = dwFirst;
		FreeIPInfo(pIPInfo);
	}

}

static int FindTagContent(const char *text, const char *tagname, char *buf)
{
	char	*p;
	// parse the xml
	p = strstr(text, tagname);
	if (p == NULL) {
		if (g_fLogging & NALOG_INFO0)
			fprintf(g_log, "FindTagContent: can't find %s\n", tagname);
		return NA_E_PARSE_ERROR;
	}

	if (sscanf(p, "%*[^>]> %[^ <] <", buf) < 1) {
		if (g_fLogging & NALOG_INFO0)
			fprintf(g_log, "FindTagContent: Can't parse tag %s\n", tagname);
		return NA_E_PARSE_ERROR;
	}

	return NA_E_SUCCESS;
}

mStatus LNT_UnmapPort(mDNSIPPort PubPort, mDNSBool tcp)
{
	//int				iLen;
	char			szEPort[10];
	//char			szRemoteHost[1024];
	//unsigned		long dwIP;
	Property		propArgs[3];
	PHTTPResponse	resp;
    unsigned short port = PubPort.NotAnInteger;
    int protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;
	sprintf(szEPort, "%u", port);

	bzero(propArgs, sizeof(propArgs));
	propArgs[0].pszName = "NewRemoteHost";
	propArgs[0].pszValue = "";
	propArgs[0].pszType = "string";
	propArgs[1].pszName = "NewExternalPort";
	propArgs[1].pszValue = szEPort;
	propArgs[1].pszType = "ui2";
	propArgs[2].pszName = "NewProtocol";
	if (protocol == IPPROTO_TCP) {
		propArgs[2].pszValue = "TCP";
	}
	else if (protocol == IPPROTO_UDP) {
		propArgs[2].pszValue = "UDP";
	}
	else {
		return -1;
	}
	propArgs[2].pszType = "string";

	resp = SendSOAPMsgControlAction(
		"DeletePortMapping", 3, propArgs, FALSE);
	if (resp == NULL) {
		return mStatus_NATTraversal;
	}

	if (strcmp(resp->pszStatus, "200") != 0) {
		DeleteHTTPResponse(resp);
		return mStatus_NATTraversal;
	}

	DeleteHTTPResponse(resp);
	return mStatus_NoError;
}


static int GetMappingUnused(unsigned short eport, int protocol);

extern mStatus LNT_MapPort(mDNSIPPort priv, mDNSIPPort pub, mDNSBool tcp)
{
	char			szEPort[6];
	char			szIPort[6];
	unsigned		long dwIP;
	char			szLocalIP[30];
	char			descr[40];
	Property		propArgs[8];
	PHTTPResponse	resp;
    unsigned short iport = priv.NotAnInteger;
    unsigned short eport = pub.NotAnInteger;
    int protocol = tcp ? IPPROTO_TCP : IPPROTO_UDP;


	if (NA_E_EXISTS == GetMappingUnused(eport, protocol))
		return mStatus_AlreadyRegistered;

	//DeletePortMapping(eport, protocol);

	sprintf(szEPort, "%u", eport);

	sprintf(szIPort, "%u", iport);

	dwIP = g_dwLocalIP;
	sprintf(szLocalIP, "%u.%u.%u.%u",
		(unsigned int)((dwIP >> 24) & 0xff),
		(unsigned int)((dwIP >> 16) & 0xff),
		(unsigned int)((dwIP >> 8) & 0xff),
		(unsigned int)((dwIP >> 0) & 0xff));

	bzero(propArgs, sizeof(propArgs));
	propArgs[0].pszName = "NewRemoteHost";
	propArgs[0].pszValue = "";
	propArgs[0].pszType = "string";
	propArgs[1].pszName = "NewExternalPort";
	propArgs[1].pszValue = szEPort;
	propArgs[1].pszType = "ui2";
	propArgs[2].pszName = "NewProtocol";
	if (protocol == IPPROTO_TCP) {
		propArgs[2].pszValue = "TCP";
	}
	else if (protocol == IPPROTO_UDP) {
		propArgs[2].pszValue = "UDP";
	}
	else {
		return mStatus_BadParamErr;
	}
	propArgs[2].pszType = "string";
	propArgs[3].pszName = "NewInternalPort";
	propArgs[3].pszValue = szIPort;
	propArgs[3].pszType = "ui2";
	propArgs[4].pszName = "NewInternalClient";
	propArgs[4].pszValue = szLocalIP;
	propArgs[4].pszType = "string";
	propArgs[5].pszName = "NewEnabled";
	propArgs[5].pszValue = "1";
	propArgs[5].pszType = "boolean";
	propArgs[6].pszName = "NewPortMappingDescription";
	sprintf(descr, "iC%u", eport);
	//propArgs[6].pszValue = "V";
	propArgs[6].pszValue = descr;
	propArgs[6].pszType = "string";
	propArgs[7].pszName = "NewLeaseDuration";
	propArgs[7].pszValue = "0";
	propArgs[7].pszType = "ui4";

	resp = SendSOAPMsgControlAction(
		"AddPortMapping", 8, propArgs, FALSE);

	if (resp == NULL) {
		return mStatus_NATTraversal;
	}

	if (strcmp(resp->pszStatus, "200") != 0) {
		DeleteHTTPResponse(resp);
		return mStatus_NATTraversal;
	}

	DeleteHTTPResponse(resp);
	return mStatus_NoError;
}

static int GetMappingUnused(unsigned short eport, int protocol)
{
	char			buf[1024];
	char			szPort[10];
	Property		propArgs[3];
	PHTTPResponse	resp;
	unsigned long	ip = 0;

	sprintf( szPort, "%u", eport);

	bzero(&propArgs, sizeof(propArgs));
	propArgs[0].pszName = "NewRemoteHost";
	propArgs[0].pszValue = "";
	propArgs[0].pszType = "string";
	propArgs[1].pszName = "NewExternalPort";
	propArgs[1].pszValue = szPort;
	propArgs[1].pszType = "ui2";
	propArgs[2].pszName = "NewProtocol";
	if (protocol == IPPROTO_TCP) {
		propArgs[2].pszValue = "TCP";
	}
	else if (protocol == IPPROTO_UDP) {
		propArgs[2].pszValue = "UDP";
	}
	else {
		return NA_E_INVALID_PARAMETER;
	}
	propArgs[2].pszType = "string";

	resp = SendSOAPMsgControlAction(
		"GetSpecificPortMappingEntry", 3, propArgs, FALSE);
	if (resp != NULL) {
		if ((strcmp(resp->pszStatus, "200") == 0) &&
			(FindTagContent(resp->pszBody, "NewInternalClient", buf) == 0))
		{
			GetIPByName(buf, &ip);
			if (ip == g_dwLocalIP) {
				// (perhaps we let it go?)
				DeleteHTTPResponse(resp);
				return NA_E_SUCCESS;
			}
			else {
				DeleteHTTPResponse(resp);
				return NA_E_EXISTS;
			}
		}
		DeleteHTTPResponse(resp);
	}

	return NA_E_SUCCESS;
}

mStatus LNT_GetPublicIP(mDNSOpaque32 *IpPtr)
{
	char			buf[1024];
	PHTTPResponse	resp;
	static struct timeval	tvLastGoodIP = {0,0};
	static unsigned long	dwLastGoodIP;
	struct timeval			tv;
	unsigned long *ip       = (unsigned long *)IpPtr;
	if (ip == NULL) return mStatus_BadParamErr;

	gettimeofday(&tv, NULL);
	GetTimeElapsed(&tvLastGoodIP, &tv, &tv);
	if (tv.tv_sec < 4)
	{
		return dwLastGoodIP;
	}

	resp = SendSOAPMsgControlAction(
		"GetExternalIPAddress", 0, NULL, FALSE);

	if (resp == NULL)
		return mStatus_NATTraversal;

	if (FindTagContent(resp->pszBody, "NewExternalIPAddress", buf) == 0) {
		if (g_fLogging & NALOG_INFO1)
			fprintf(g_log, "Mapped remote host = %s\n", buf);
		*ip = inet_addr(buf);
		DeleteHTTPResponse(resp);

		gettimeofday(&tvLastGoodIP, NULL);
		dwLastGoodIP = *ip;

		return mStatus_NoError;
	}

	DeleteHTTPResponse(resp);
	return mStatus_NATTraversal;
}

static void SendDiscoveryMsg()
{
	// do it twice to avoid lost packet
	//SendUDPMsg(szSSDPMsgDiscoverNAT);
	SendUDPMsg(szSSDPMsgDiscoverRoot);
	SendUDPMsg(szSSDPMsgDiscoverIGD);
	SendUDPMsg(szSSDPMsgDiscoverNAT);
}

// Set up threads for upnp responses, etc.
int LegacyNATInit(void)
{
	//pthread_t		UDPthread;
	pthread_attr_t	attr;
	int				iRet;
	//struct timeval	tv;

	static int		fFirstInitLocks = TRUE;
	FILE *log = NULL;	
	
	g_fLogging = 0;
	g_log = stderr;

	SetLocalIP();

	g_fQuit = FALSE;

	if (fFirstInitLocks)
	{
		// init locks
		if (pthread_mutex_init(&g_xUPnP, NULL)) {
			if (g_fLogging & NALOG_ERROR)
				fprintf(log, "UpnpInit - mutex init failed\n");
			return NA_E_INTERNAL_ERROR;
		}
		if (pthread_cond_init(&g_condUPnP, NULL)) {
			pthread_mutex_destroy(&g_xUPnP);
			if (g_fLogging & NALOG_ERROR)
				fprintf(log, "UpnpInit - cond init failed\n");
			return NA_E_INTERNAL_ERROR;
		}
		if (pthread_cond_init(&g_condUPnPControlURL, NULL)) {
			pthread_mutex_destroy(&g_xUPnP);
			pthread_cond_destroy(&g_condUPnP);
			if (g_fLogging & NALOG_ERROR)
				fprintf(log, "UpnpInit - cond init failed\n");
			return NA_E_INTERNAL_ERROR;
		}
		if (pthread_mutex_init(&g_xUPnPMsg, NULL)) {
			pthread_mutex_destroy(&g_xUPnP);
			pthread_cond_destroy(&g_condUPnP);
			pthread_cond_destroy(&g_condUPnPControlURL);
			if (g_fLogging & NALOG_ERROR)
				fprintf(log, "UpnpInit - mutex init failed\n");
			return NA_E_INTERNAL_ERROR;
		}

		fFirstInitLocks = FALSE;
	}

	if (g_fFirstInit)
	{
		// initialize UDP socket for SSDP
		g_sUDP = SSDPListen();
		g_sUDPCancel = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP); // sock to signal canccelation to UDP thread
		if (g_sUDP < 0 || g_sUDPCancel < 0) {
			if (g_fLogging & NALOG_ERROR)
				fprintf(log, "UpnpInit - Failed to init multicast socket.\n");
			return NA_E_INTERNAL_ERROR;
		}

		// make UDP thread
		pthread_attr_init(&attr);
		iRet = pthread_create(&g_UDPthread, &attr, UDPProc, log);
		if (iRet != 0) {
			g_fFirstInit = TRUE;		// so we'll redo this part next time
			close(g_sUDP);
			g_sUDP = -1;
			if (g_fLogging & NALOG_ERROR)
				fprintf(log, "UpnpInit - pthread create failed (%d)\n", iRet);
			return NA_E_THREAD_ERROR;
		}

		// set this to FALSE only if first call succeeded
		g_fFirstInit = FALSE;

		//TracePrint(ELL_TRACE, "UPnP init passed\n");

		//tv.tv_sec = 0;
		//tv.tv_usec = 20000;   // wait 20ms for thread/udp/multicast init
		//select(0, 0, 0, 0, &tv);
	}

	// send discovery message
	SendDiscoveryMsg();

	return NA_E_SUCCESS;
}

int LegacyNATDestroy()
{
    void *UDPThreadRetVal; 
	g_fQuit = TRUE;
	if (g_sTCPCancel >= 0) close(g_sTCPCancel);
	if (g_sUDPCancel >= 0) close(g_sUDPCancel);
	pthread_join(g_UDPthread, &UDPThreadRetVal);
	g_sTCPCancel = -1;
	g_sUDPCancel = -1;
	g_fFirstInit = TRUE;
	g_fUPnPEnabled = FALSE;
	g_fControlURLSet = FALSE;
	return NA_E_SUCCESS;
}
