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

$Log: DNSServiceDiscovery.c,v $
Revision 1.2  2003/08/20 07:06:34  bradley
Update to APSL 2.0. Updated change history to match other mDNSResponder files.

Revision 1.1  2003/08/20 06:04:45  bradley
Platform-neutral DNSServices-based emulation layer for the Mac OS X DNSServiceDiscovery API.
		
*/

#include	<stddef.h>
#include	<stdlib.h>
#include	<string.h>

#if( macintosh || __MACH__ )

	#include	<sys/types.h>
	#include	<sys/socket.h>
	#include	<netinet/in.h>
	
#elif( defined( _MSC_VER ) || defined( __MWERKS__ ) )
	
	#pragma warning( disable:4054 )		// Disable "type cast : from function pointer to data pointer".
	#pragma warning( disable:4055 )		// Disable "type cast : from data pointer to function pointer".
	#pragma warning( disable:4127 )		// Disable "conditional expression is constant" warning for debug macros.
	#pragma warning( disable:4152 )		// Disable "nonstandard extension, function/data pointer conversion in expression".

	#define	WIN32_LEAN_AND_MEAN			// Needed to avoid redefinitions by Windows interfaces.
	
	#include	<winsock2.h>
	
#endif

#include	"mDNSClientAPI.h"
#include	"mDNSPlatformFunctions.h"
#include	"DNSServices.h"

#include	"DNSServiceDiscovery.h"

#ifdef	__cplusplus
	extern "C" {
#endif

#if 0
#pragma mark == Constants & Types ==
#endif

//===========================================================================================================================
//	Constants & Types
//===========================================================================================================================

#define DEBUG_NAME		"[DNSServiceDiscovery] "

typedef enum
{
	kDNSServiceDiscoveryObjectTypeRegistration 			= 1, 
	kDNSServiceDiscoveryObjectTypeDomainEnumeration		= 2, 
	kDNSServiceDiscoveryObjectTypeBrowser				= 3, 
	kDNSServiceDiscoveryObjectTypeResolver				= 4 

}	DNSServiceDiscoveryObjectType;

typedef struct _dns_service_discovery_t		_dns_service_discovery_t;
struct	_dns_service_discovery_t
{
	DNSServiceDiscoveryObjectType		type;
	void *								ref;
	void *								callback;
	void *								context;
};

#if 0
#pragma mark == Macros ==
#endif

//===========================================================================================================================
//	Macros
//===========================================================================================================================

// Emulate Mac OS debugging macros for non-Mac platforms.

#if( !TARGET_OS_MAC )
	#define check(assertion)
	#define check_string( assertion, cstring )
	#define check_noerr(err)
	#define check_noerr_string( error, cstring )
	#define debug_string( cstring )
	#define require( assertion, label )									do { if( !(assertion) ) goto label; } while(0)
	#define require_string( assertion, label, string )					require(assertion, label)
	#define require_quiet( assertion, label )							require( assertion, label )
	#define require_noerr( error, label )								do { if( (error) != 0 ) goto label; } while(0)
	#define require_noerr_quiet( assertion, label )						require_noerr( assertion, label )
	#define require_noerr_action( error, label, action )				do { if( (error) != 0 ) { {action;}; goto label; } } while(0)
	#define require_noerr_action_quiet( assertion, label, action )		require_noerr_action( assertion, label, action )
	#define require_action( assertion, label, action )					do { if( !(assertion) ) { {action;}; goto label; } } while(0)
	#define require_action_quiet( assertion, label, action )			require_action( assertion, label, action )
	#define require_action_string( assertion, label, action, cstring )	do { if( !(assertion) ) { {action;}; goto label; } } while(0)
#endif

#if 0
#pragma mark == Prototypes ==
#endif

//===========================================================================================================================
//	Prototypes
//===========================================================================================================================

DNS_LOCAL void
	DNSServiceRegistrationPrivateCallBack( 
		void *							inContext, 
		DNSRegistrationRef				inRef, 
		DNSStatus						inStatusCode, 
		const DNSRegistrationEvent *	inEvent );

DNS_LOCAL void
	DNSServiceDomainEnumerationPrivateCallBack( 
		void *					inContext, 
		DNSBrowserRef 			inRef, 
		DNSStatus 				inStatusCode, 
		const DNSBrowserEvent *	inEvent );

DNS_LOCAL void
	DNSServiceBrowserPrivateCallBack( 
		void *					inContext, 
		DNSBrowserRef 			inRef, 
		DNSStatus 				inStatusCode, 
		const DNSBrowserEvent *	inEvent );

DNS_LOCAL void
	DNSServiceResolverPrivateCallBack( 
		void *						inContext, 
		DNSResolverRef 				inRef, 
		DNSStatus 					inStatusCode, 
		const DNSResolverEvent *	inEvent );

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	DNSServiceRegistrationCreate
//===========================================================================================================================

dns_service_discovery_ref
	DNSServiceRegistrationCreate(
		const char *				inName,
		const char *				inType,
		const char *				inDomain,
		uint16_t					inPort,
		const char *				inTextRecord,
		DNSServiceRegistrationReply	inCallBack,
		void *						inContext )
{
	DNSStatus						err;
	dns_service_discovery_ref		result;
	dns_service_discovery_ref		obj;
	void *							txt;
	size_t							txtSize;
	DNSRegistrationRef				registration;
	
	result 	= NULL;
	txt		= NULL;
	txtSize	= 0;
	
	// Allocate and initialize the object.
	
	obj = (dns_service_discovery_ref) malloc( sizeof( *obj ) );
	require_action( obj, exit, err = kDNSNoMemoryErr );
	
	obj->type 		= kDNSServiceDiscoveryObjectTypeRegistration;
	obj->ref 		= NULL;
	obj->callback	= inCallBack;
	obj->context	= inContext;
	
	// Create the underlying registration. Build a \001-escaped text record if needed.
	
	if( inTextRecord )
	{
		err = DNSDynamicTextRecordBuildEscaped( inTextRecord, &txt, &txtSize );
		require_noerr( err, exit );
	}
	
	err = DNSRegistrationCreate( kDNSRegistrationFlagPreFormattedTextRecord, inName, inType, inDomain, inPort, txt, 
								 (DNSCount) txtSize, NULL, NULL, DNSServiceRegistrationPrivateCallBack, obj, &registration );
	require_noerr( err, exit ); 
	obj->ref = registration;
	
	// Success!
	
	result	= obj;
	obj		= NULL;
	
exit:
	if( txt )
	{
		DNSDynamicTextRecordRelease( txt );
	}
	if( obj )
	{
		DNSServiceDiscoveryDeallocate( obj );
	}
	return( result );
}

//===========================================================================================================================
//	DNSServiceRegistrationPrivateCallBack
//===========================================================================================================================

DNS_LOCAL void
	DNSServiceRegistrationPrivateCallBack( 
		void *							inContext, 
		DNSRegistrationRef				inRef, 
		DNSStatus						inStatusCode, 
		const DNSRegistrationEvent *	inEvent )
{
	dns_service_discovery_ref		obj;
	DNSServiceRegistrationReply		callback;
	
	DNS_UNUSED( inRef );
	DNS_UNUSED( inStatusCode );
	
	check( inContext );
	obj = (dns_service_discovery_ref) inContext;
	check( obj->callback );
	callback = (DNSServiceRegistrationReply) obj->callback;
	
	switch( inEvent->type )
	{
		case kDNSRegistrationEventTypeRegistered:
			debugf( DEBUG_NAME "name registered and active\n" );
			
			if( callback )
			{
				callback( kDNSServiceDiscoveryNoError, obj->context );
			}
			break;

		case kDNSRegistrationEventTypeNameCollision:
			debugf( DEBUG_NAME "name in use, please choose another name\n" );
			
			if( callback )
			{
				callback( kDNSServiceDiscoveryNameConflict, obj->context );
			}
			break;
		
		default:
			break;
	}
}

//===========================================================================================================================
//	DNSServiceRegistrationAddRecord
//===========================================================================================================================

DNSRecordReference
	DNSServiceRegistrationAddRecord( 
		dns_service_discovery_ref	inRef, 
		uint16_t 					inRRType, 
		uint16_t 					inRDLength, 
		const char *				inRData, 
		uint32_t 					inTTL )
{
	DNS_UNUSED( inRef );
	DNS_UNUSED( inRRType );
	DNS_UNUSED( inRDLength );
	DNS_UNUSED( inRData );
	DNS_UNUSED( inTTL );
	
	debugf( DEBUG_NAME "DNSServiceRegistrationAddRecord is currently not supported\n" );
	return( 0 );
}

//===========================================================================================================================
//	DNSServiceRegistrationUpdateRecord
//===========================================================================================================================

DNSServiceRegistrationReplyErrorType
	DNSServiceRegistrationUpdateRecord(
		dns_service_discovery_ref 	inRef, 
		DNSRecordReference			inRecordRef, 
		uint16_t 					inRDLength, 
		const char *				inRData, 
		uint32_t 					inTTL )
{
	DNS_UNUSED( inRef );
	DNS_UNUSED( inRecordRef );
	DNS_UNUSED( inRDLength );
	DNS_UNUSED( inRData );
	DNS_UNUSED( inTTL );
	
	debugf( DEBUG_NAME "DNSServiceRegistrationUpdateRecord is currently not supported\n" );
	return( kDNSServiceDiscoveryUnsupportedErr );
}

//===========================================================================================================================
//	DNSServiceRegistrationRemoveRecord
//===========================================================================================================================

DNSServiceRegistrationReplyErrorType
	DNSServiceRegistrationRemoveRecord( 
		dns_service_discovery_ref 	inRef, 
		DNSRecordReference 			inRecordRef )
{
	DNS_UNUSED( inRef );
	DNS_UNUSED( inRecordRef );
	
	debugf( DEBUG_NAME "DNSServiceRegistrationRemoveRecord is currently not supported\n" );
	return( kDNSServiceDiscoveryUnsupportedErr );
}

//===========================================================================================================================
//	DNSServiceDomainEnumerationCreate
//===========================================================================================================================

dns_service_discovery_ref
	DNSServiceDomainEnumerationCreate(
		int 								inRegistrationDomains,
		DNSServiceDomainEnumerationReply	inCallBack,
		void *								inContext )
{
	DNSStatus						err;
	dns_service_discovery_ref		result;
	dns_service_discovery_ref		obj;
	DNSBrowserRef					browser;
	DNSBrowserFlags					flags;
	
	result 	= NULL;
	browser	= NULL;
	
	// Allocate and initialize the object.
	
	obj = (dns_service_discovery_ref) malloc( sizeof( *obj ) );
	require_action( obj, exit, err = kDNSNoMemoryErr );
	
	obj->type 		= kDNSServiceDiscoveryObjectTypeDomainEnumeration;
	obj->ref 		= NULL;
	obj->callback	= inCallBack;
	obj->context	= inContext;
	
	// Create the underlying browser and start searching for domains.
	
	err = DNSBrowserCreate( 0, DNSServiceDomainEnumerationPrivateCallBack, obj, &browser );
	require_noerr( err, exit ); 
	obj->ref = browser;
	
	if( inRegistrationDomains )
	{
		flags = kDNSBrowserFlagRegistrationDomainsOnly;
	}
	else
	{
		flags = 0;
	}
	err = DNSBrowserStartDomainSearch( browser, flags );
	require_noerr( err, exit ); 
		
	// Success!
	
	result		= obj;
	browser		= NULL;
	obj			= NULL;
	
exit:
	if( browser )
	{
		DNSBrowserRelease( browser, 0 );
	}
	if( obj )
	{
		DNSServiceDiscoveryDeallocate( obj );
	}
	return( result );
}

//===========================================================================================================================
//	DNSServiceDomainEnumerationPrivateCallBack
//===========================================================================================================================

DNS_LOCAL void
	DNSServiceDomainEnumerationPrivateCallBack( 
		void *					inContext, 
		DNSBrowserRef 			inRef, 
		DNSStatus 				inStatusCode, 
		const DNSBrowserEvent *	inEvent )
{
	dns_service_discovery_ref				obj;
	DNSServiceDomainEnumerationReply		callback;
	
	DNS_UNUSED( inRef );
	DNS_UNUSED( inStatusCode );
	
	check( inContext );
	obj = (dns_service_discovery_ref) inContext;
	check( obj->callback );
	callback = (DNSServiceDomainEnumerationReply) obj->callback;
	
	switch( inEvent->type )
	{
		case kDNSBrowserEventTypeAddDomain:
			debugf( DEBUG_NAME "add domain \"%s\"\n", inEvent->data.addDomain.domain );
			
			if( callback )
			{
				callback( DNSServiceDomainEnumerationReplyAddDomain, inEvent->data.addDomain.domain, 
						  DNSServiceDiscoverReplyFlagsFinished, obj->context );
			}
			break;
		
		case kDNSBrowserEventTypeAddDefaultDomain:
			debugf( DEBUG_NAME "add default domain \"%s\"\n", inEvent->data.addDefaultDomain.domain );
			
			if( callback )
			{
				callback( DNSServiceDomainEnumerationReplyAddDomainDefault, inEvent->data.addDefaultDomain.domain, 
						  DNSServiceDiscoverReplyFlagsFinished, obj->context );
			}
			break;
		
		case kDNSBrowserEventTypeRemoveDomain:
			debugf( DEBUG_NAME "add default domain \"%s\"\n", inEvent->data.removeDomain.domain );
			
			if( callback )
			{
				callback( DNSServiceDomainEnumerationReplyRemoveDomain, inEvent->data.removeDomain.domain, 
						  DNSServiceDiscoverReplyFlagsFinished, obj->context );
			}
			break;
		
		default:
			break;
	}
}

//===========================================================================================================================
//	DNSServiceBrowserCreate
//===========================================================================================================================

dns_service_discovery_ref
	DNSServiceBrowserCreate(
		const char *			inType,
		const char *			inDomain,
		DNSServiceBrowserReply	inCallBack,
		void *					inContext )
{
	DNSStatus						err;
	dns_service_discovery_ref		result;
	dns_service_discovery_ref		obj;
	DNSBrowserRef					browser;
	
	result 	= NULL;
	browser	= NULL;
	
	// Allocate and initialize the object.
	
	obj = (dns_service_discovery_ref) malloc( sizeof( *obj ) );
	require_action( obj, exit, err = kDNSNoMemoryErr );
	
	obj->type 		= kDNSServiceDiscoveryObjectTypeBrowser;
	obj->ref 		= NULL;
	obj->callback	= inCallBack;
	obj->context	= inContext;
	
	// Create the underlying browser and start searching for domains.
	
	err = DNSBrowserCreate( 0, DNSServiceBrowserPrivateCallBack, obj, &browser );
	require_noerr( err, exit ); 
	obj->ref = browser;
	
	err = DNSBrowserStartServiceSearch( browser, 0, inType, inDomain );
	require_noerr( err, exit ); 
		
	// Success!
	
	result		= obj;
	browser		= NULL;
	obj			= NULL;
	
exit:
	if( browser )
	{
		DNSBrowserRelease( browser, 0 );
	}
	if( obj )
	{
		DNSServiceDiscoveryDeallocate( obj );
	}
	return( result );
}

//===========================================================================================================================
//	DNSServiceBrowserPrivateCallBack
//===========================================================================================================================

DNS_LOCAL void
	DNSServiceBrowserPrivateCallBack( 
		void *					inContext, 
		DNSBrowserRef 			inRef, 
		DNSStatus 				inStatusCode, 
		const DNSBrowserEvent *	inEvent )
{
	dns_service_discovery_ref		obj;
	DNSServiceBrowserReply			callback;
	
	DNS_UNUSED( inRef );
	DNS_UNUSED( inStatusCode );
	
	check( inContext );
	obj = (dns_service_discovery_ref) inContext;
	check( obj->callback );
	callback = (DNSServiceBrowserReply) obj->callback;
	
	switch( inEvent->type )
	{
		case kDNSBrowserEventTypeAddService:
			debugf( DEBUG_NAME "add service \"%s.%s%s\"\n", 
				  inEvent->data.addService.name, 
				  inEvent->data.addService.type, 
				  inEvent->data.addService.domain );
			
			if( callback )
			{
				callback( DNSServiceBrowserReplyAddInstance, 
						  inEvent->data.addService.name, 
						  inEvent->data.addService.type, 
						  inEvent->data.addService.domain, 
						  DNSServiceDiscoverReplyFlagsFinished, 
						  obj->context );
			}
			break;
		
		case kDNSBrowserEventTypeRemoveService:
			debugf( DEBUG_NAME "remove service \"%s.%s%s\"\n", 
				  inEvent->data.removeService.name, 
				  inEvent->data.removeService.type, 
				  inEvent->data.removeService.domain );
			
			if( callback )
			{
				callback( DNSServiceBrowserReplyRemoveInstance, 
						  inEvent->data.removeService.name, 
						  inEvent->data.removeService.type, 
						  inEvent->data.removeService.domain, 
						  DNSServiceDiscoverReplyFlagsFinished, 
						  obj->context );
			}
			break;
		
		default:
			break;
	}
}

//===========================================================================================================================
//	DNSServiceResolverResolve
//===========================================================================================================================

dns_service_discovery_ref
	DNSServiceResolverResolve(
		const char *			inName,
		const char *			inType,
		const char *			inDomain,
		DNSServiceResolverReply	inCallBack,
		void *					inContext )
{
	DNSStatus						err;
	dns_service_discovery_ref		result;
	dns_service_discovery_ref		obj;
	DNSResolverRef					resolver;
	
	result = NULL;
	
	// Allocate and initialize the object.
	
	obj = (dns_service_discovery_ref) malloc( sizeof( *obj ) );
	require_action( obj, exit, err = kDNSNoMemoryErr );
	
	obj->type 		= kDNSServiceDiscoveryObjectTypeResolver;
	obj->ref 		= NULL;
	obj->callback	= inCallBack;
	obj->context	= inContext;
	
	// Create the underlying resolver and start searching for domains.
	
	err = DNSResolverCreate( 0, inName, inType, inDomain, DNSServiceResolverPrivateCallBack, obj, NULL, &resolver );
	require_noerr( err, exit ); 
	obj->ref = resolver;
		
	// Success!
	
	result 	= obj;
	obj		= NULL;
	
exit:
	if( obj )
	{
		DNSServiceDiscoveryDeallocate( obj );
	}
	return( result );
}

//===========================================================================================================================
//	DNSServiceResolverPrivateCallBack
//===========================================================================================================================

DNS_LOCAL void
	DNSServiceResolverPrivateCallBack( 
		void *						inContext, 
		DNSResolverRef 				inRef, 
		DNSStatus 					inStatusCode, 
		const DNSResolverEvent *	inEvent )
{
	dns_service_discovery_ref		obj;
	DNSServiceResolverReply			callback;
	struct sockaddr_in				interfaceAddr;
	struct sockaddr_in				addr;
	
	DNS_UNUSED( inRef );
	DNS_UNUSED( inStatusCode );
	
	check( inContext );
	obj = (dns_service_discovery_ref) inContext;
	check( obj->callback );
	callback = (DNSServiceResolverReply) obj->callback;
	
	switch( inEvent->type )
	{
		case kDNSResolverEventTypeResolved:
			debugf( DEBUG_NAME "resolved \"%s.%s%s\"\n", 
				  inEvent->data.resolved.name, 
				  inEvent->data.resolved.type, 
				  inEvent->data.resolved.domain );
			
			memset( &interfaceAddr, 0, sizeof( interfaceAddr ) );
			interfaceAddr.sin_family		= AF_INET;
			interfaceAddr.sin_port			= 0;
			interfaceAddr.sin_addr.s_addr	= inEvent->data.resolved.interfaceIP.u.ipv4.addr.v32;
			
			memset( &addr, 0, sizeof( addr ) );
			addr.sin_family			= AF_INET;
			addr.sin_port			= inEvent->data.resolved.address.u.ipv4.port.v16;
			addr.sin_addr.s_addr	= inEvent->data.resolved.address.u.ipv4.addr.v32;
			
			if( callback )
			{
				callback( (struct sockaddr *) &interfaceAddr, (struct sockaddr *) &addr, inEvent->data.resolved.textRecord, 
						  DNSServiceDiscoverReplyFlagsFinished, obj->context );
			}
			break;
				
		default:
			break;
	}
}

//===========================================================================================================================
//	DNSServiceDiscoveryMachPort
//===========================================================================================================================

mach_port_t	DNSServiceDiscoveryMachPort( dns_service_discovery_ref inRef )
{
	DNS_UNUSED( inRef );
	
	debugf( DEBUG_NAME "DNSServiceDiscoveryMachPort is not supported\n" );
	return( 0 );
}

//===========================================================================================================================
//	DNSServiceDiscoveryDeallocate
//===========================================================================================================================

void	DNSServiceDiscoveryDeallocate( dns_service_discovery_ref inRef )
{
	_dns_service_discovery_t *		obj;
	DNSStatus						err;
	
	check( inRef );
	check( inRef->ref );
	
	obj = (_dns_service_discovery_t *) inRef;
	switch( obj->type )
	{
		case kDNSServiceDiscoveryObjectTypeRegistration:
			if( inRef->ref )
			{
				err = DNSRegistrationRelease( (DNSRegistrationRef) inRef->ref, 0 );
				check_noerr( err );
			}
			free( inRef );
			break;
		
		case kDNSServiceDiscoveryObjectTypeDomainEnumeration:
			if( inRef->ref )
			{
				err = DNSBrowserRelease( (DNSBrowserRef) inRef->ref, 0 );
				check_noerr( err );
			}
			free( inRef );
			break;
		
		case kDNSServiceDiscoveryObjectTypeBrowser:
			if( inRef->ref )
			{
				err = DNSBrowserRelease( (DNSBrowserRef) inRef->ref, 0 );
				check_noerr( err );
			}
			free( inRef );
			break;
		
		case kDNSServiceDiscoveryObjectTypeResolver:
			if( inRef->ref )
			{
				err = DNSResolverRelease( (DNSResolverRef) inRef->ref, 0 );
				check_noerr( err );
			}
			free( inRef );
			break;
		
		default:
			debugf( DEBUG_NAME "unknown object type (%d)\n", obj->type );
			break;
	}
}

//===========================================================================================================================
//	DNSServiceDiscovery_handleReply
//===========================================================================================================================

void	DNSServiceDiscovery_handleReply( void *inReplyMessage )
{
	DNS_UNUSED( inReplyMessage );
	
	debugf( DEBUG_NAME "DNSServiceDiscovery_handleReply is not supported\n" );
}

#ifdef	__cplusplus
	}
#endif
