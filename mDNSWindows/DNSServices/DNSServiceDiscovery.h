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

$Log: DNSServiceDiscovery.h,v $
Revision 1.2  2003/08/20 07:06:34  bradley
Update to APSL 2.0. Updated change history to match other mDNSResponder files.

Revision 1.1  2003/08/20 06:04:45  bradley
Platform-neutral DNSServices-based emulation layer for the Mac OS X DNSServiceDiscovery API.
		
*/

//---------------------------------------------------------------------------------------------------------------------------
/*!	@header		DNSServiceDiscovery
	
	@abstract	DNSServiceDiscovery emulation using DNSServices.
*/

#ifndef	__DNS_SERVICE_DISCOVERY__
#define	__DNS_SERVICE_DISCOVERY__

#include	<stddef.h>

#if( __MACH__ )

	#include	<mach/mach_types.h>

	#include	<sys/types.h>
	#include	<sys/socket.h>
	#include	<sys/cdefs.h>
	
	#include	<netinet/in.h>

#elif( defined( __MWERKS__ ) )

	#include	<stdint.h>
	
#elif( defined( _MSC_VER ) )

	typedef signed char			int8_t;		// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef unsigned char		uint8_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef signed short		int16_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef unsigned short		uint16_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef signed long			int32_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef unsigned long		uint32_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	
#endif

#ifdef	__cplusplus
	extern "C" {
#endif

// Note: The following is mostly copied from DNSServiceDiscovery.h.

// Compatibility types.

#if( !__MACH__ )
	typedef int		mach_port_t;
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	dns_service_discovery_ref

	@abstract	Reference to a DNS Service Discovery object.
*/

typedef struct _dns_service_discovery_t *		dns_service_discovery_ref;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSServiceRegistrationReplyErrorType

	@abstract	Error codes.
*/

typedef enum
{
    kDNSServiceDiscoveryWaiting				= 1,
    kDNSServiceDiscoveryNoError				= 0,
	
	// mDNS Error codes are in the range
	// FFFE FF00 (-65792) to FFFE FFFF (-65537)
	
    kDNSServiceDiscoveryUnknownErr			= -65537,		// 0xFFFE FFFF
    kDNSServiceDiscoveryNoSuchNameErr		= -65538,
    kDNSServiceDiscoveryNoMemoryErr			= -65539,
    kDNSServiceDiscoveryBadParamErr			= -65540,
    kDNSServiceDiscoveryBadReferenceErr		= -65541,
    kDNSServiceDiscoveryBadStateErr			= -65542,
    kDNSServiceDiscoveryBadFlagsErr			= -65543,
    kDNSServiceDiscoveryUnsupportedErr		= -65544,
    kDNSServiceDiscoveryNotInitializedErr	= -65545,
    kDNSServiceDiscoveryNoCache				= -65546,
    kDNSServiceDiscoveryAlreadyRegistered	= -65547,
    kDNSServiceDiscoveryNameConflict		= -65548,
    kDNSServiceDiscoveryInvalid				= -65549,
    kDNSServiceDiscoveryMemFree				= -65792		// 0xFFFE FF00
    
}	DNSServiceRegistrationReplyErrorType;

typedef uint32_t DNSRecordReference;

//---------------------------------------------------------------------------------------------------------------------------
/*!
	@function	DNSServiceResolver_handleReply
	
	@param		replyMsg	The Mach message.
	
	@description
	
	This function should be called with the Mach message sent to the port returned by the call to DNSServiceResolverResolve. 
	The reply message will be interpreted and will result in a call to the specified callout function.
*/

void	DNSServiceDiscovery_handleReply( void *replyMsg );

/* Service Registration */

typedef void (*DNSServiceRegistrationReply) (
    DNSServiceRegistrationReplyErrorType 		errorCode,
    void										*context
);

/*!
@function DNSServiceRegistrationCreate
    @description Register a named service with DNS Service Discovery
    @param name The name of this service instance (e.g. "Steve's Printer")
    @param regtype The service type (e.g. "_printer._tcp." -- see
        RFC 2782 (DNS SRV) and <http://www.iana.org/assignments/port-numbers>)
    @param domain The domain in which to register the service (e.g. "apple.com.")
    @param port The local port on which this service is being offered (in network byte order)
    @param txtRecord Optional protocol-specific additional information
    @param callBack The DNSServiceRegistrationReply function to be called
    @param context A user specified context which will be passed to the callout function.
    @result A dns_registration_t
*/
dns_service_discovery_ref DNSServiceRegistrationCreate
(
    const char 		*name,
    const char 		*regtype,
    const char 		*domain,
    uint16_t		port,
    const char 		*txtRecord,
    DNSServiceRegistrationReply callBack,
    void		*context
);

/***************************************************************************/
/*   DNS Domain Enumeration   */

typedef enum
{
    DNSServiceDomainEnumerationReplyAddDomain,			// Domain found
    DNSServiceDomainEnumerationReplyAddDomainDefault,		// Domain found (and should be selected by default)
    DNSServiceDomainEnumerationReplyRemoveDomain,			// Domain has been removed from network
} DNSServiceDomainEnumerationReplyResultType;

typedef enum
{
    DNSServiceDiscoverReplyFlagsFinished,
    DNSServiceDiscoverReplyFlagsMoreComing,
} DNSServiceDiscoveryReplyFlags;

typedef void (*DNSServiceDomainEnumerationReply) (
    DNSServiceDomainEnumerationReplyResultType 			resultType,		// One of DNSServiceDomainEnumerationReplyResultType
    const char  						*replyDomain,
    DNSServiceDiscoveryReplyFlags 		flags,			// DNS Service Discovery reply flags information
    void								*context		
);

/*!
    @function DNSServiceDomainEnumerationCreate
    @description Asynchronously create a DNS Domain Enumerator
    @param registrationDomains A boolean indicating whether you are looking
        for recommended registration domains
        (e.g. equivalent to the AppleTalk zone list in the AppleTalk Control Panel)
        or recommended browsing domains
        (e.g. equivalent to the AppleTalk zone list in the Chooser).
    @param callBack The function to be called when domains are found or removed
    @param context A user specified context which will be passed to the callout function.
    @result A dns_registration_t
*/
dns_service_discovery_ref DNSServiceDomainEnumerationCreate
(
    int 		registrationDomains,
    DNSServiceDomainEnumerationReply	callBack,
    void		*context
);

/***************************************************************************/
/*   DNS Service Browser   */

typedef enum
{
    DNSServiceBrowserReplyAddInstance,	// Instance of service found
    DNSServiceBrowserReplyRemoveInstance	// Instance has been removed from network
} DNSServiceBrowserReplyResultType;

typedef void (*DNSServiceBrowserReply) (
    DNSServiceBrowserReplyResultType 			resultType,		// One of DNSServiceBrowserReplyResultType
    const char  	*replyName,
    const char  	*replyType,
    const char  	*replyDomain,
    DNSServiceDiscoveryReplyFlags 				flags,			// DNS Service Discovery reply flags information
    void			*context
);

/*!
    @function DNSServiceBrowserCreate
    @description Asynchronously create a DNS Service browser
    @param regtype The type of service
    @param domain The domain in which to find the service
    @param callBack The function to be called when service instances are found or removed
    @param context A user specified context which will be passed to the callout function.
    @result A dns_registration_t
*/
dns_service_discovery_ref DNSServiceBrowserCreate
(
    const char 		*regtype,
    const char 		*domain,
    DNSServiceBrowserReply	callBack,
    void		*context
);

/***************************************************************************/
/* Resolver requests */

typedef void (*DNSServiceResolverReply) (
    struct sockaddr 	*interfaceAddr,		// Needed for scoped addresses like link-local
    struct sockaddr 	*address,
    const char 			*txtRecord,
    DNSServiceDiscoveryReplyFlags 				flags,			// DNS Service Discovery reply flags information
    void				*context
);

/*!
@function DNSServiceResolverResolve
    @description Resolved a named instance of a service to its address, port, and
        (optionally) other demultiplexing information contained in the TXT record.
    @param name The name of the service instance
    @param regtype The type of service
    @param domain The domain in which to find the service
    @param callBack The DNSServiceResolverReply function to be called when the specified
        address has been resolved.
    @param context A user specified context which will be passed to the callout function.
    @result A dns_registration_t
*/

dns_service_discovery_ref DNSServiceResolverResolve
(
    const char 		*name,
    const char 		*regtype,
    const char 		*domain,
    DNSServiceResolverReply callBack,
    void		*context
);

/***************************************************************************/
/* Mach port accessor and deallocation */

/*!
    @function DNSServiceDiscoveryMachPort
    @description Returns the mach port for a dns_service_discovery_ref
    @param registration A dns_service_discovery_ref as returned from DNSServiceRegistrationCreate
    @result A mach reply port which will be sent messages as appropriate.
        These messages should be passed to the DNSServiceDiscovery_handleReply
        function.  A NULL value indicates that no address was
        specified or some other error occurred which prevented the
        resolution from being started.
*/
mach_port_t DNSServiceDiscoveryMachPort(dns_service_discovery_ref dnsServiceDiscovery);

/*!
    @function DNSServiceDiscoveryDeallocate
    @description Deallocates the DNS Service Discovery type / closes the connection to the server
    @param dnsServiceDiscovery A dns_service_discovery_ref as returned from a creation or enumeration call
    @result void
*/
void DNSServiceDiscoveryDeallocate(dns_service_discovery_ref dnsServiceDiscovery);

/***************************************************************************/
/* Registration updating */


/*!
    @function DNSServiceRegistrationAddRecord
    @description Request that the mDNS Responder add the DNS Record of a specific type
    @param dnsServiceDiscovery A dns_service_discovery_ref as returned from a DNSServiceRegistrationCreate call
    @param rrtype A standard DNS Resource Record Type, from http://www.iana.org/assignments/dns-parameters
    @param rdlen Length of the data
    @param rdata Opaque binary Resource Record data, up to 64 kB.
    @param ttl time to live for the added record.
    @result DNSRecordReference An opaque reference that can be passed to the update and remove record calls.  If an error occurs, this value will be zero or negative
*/
DNSRecordReference DNSServiceRegistrationAddRecord(dns_service_discovery_ref dnsServiceDiscovery, uint16_t rrtype, uint16_t rdlen, const char *rdata, uint32_t ttl);

/*!
    @function DNSServiceRegistrationUpdateRecord
    @description Request that the mDNS Responder add the DNS Record of a specific type
    @param dnsServiceDiscovery A dns_service_discovery_ref as returned from a DNSServiceRegistrationCreate call
    @param dnsRecordReference A dnsRecordReference as returned from a DNSServiceRegistrationAddRecord call
    @param rdlen Length of the data
    @param rdata Opaque binary Resource Record data, up to 64 kB.
    @param ttl time to live for the updated record.
    @result DNSServiceRegistrationReplyErrorType If an error occurs, this value will be non zero
*/
DNSServiceRegistrationReplyErrorType DNSServiceRegistrationUpdateRecord(dns_service_discovery_ref ref, DNSRecordReference reference, uint16_t rdlen, const char *rdata, uint32_t ttl);

/*!
    @function DNSServiceRegistrationRemoveRecord
    @description Request that the mDNS Responder remove the DNS Record(s) of a specific type
    @param dnsServiceDiscovery A dns_service_discovery_ref as returned from a DNSServiceRegistrationCreate call
    @param dnsRecordReference A dnsRecordReference as returned from a DNSServiceRegistrationAddRecord call
    @result DNSServiceRegistrationReplyErrorType If an error occurs, this value will be non zero
*/

DNSServiceRegistrationReplyErrorType DNSServiceRegistrationRemoveRecord(dns_service_discovery_ref ref, DNSRecordReference reference);

#ifdef	__cplusplus
	}
#endif

#endif	// __DNS_SERVICE_DISCOVERY__
