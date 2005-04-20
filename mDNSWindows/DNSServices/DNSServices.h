/*
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
    
$Log: DNSServices.h,v $
Revision 1.11  2004/07/13 21:24:28  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.10  2004/01/30 02:56:34  bradley
Updated to support full Unicode display. Added support for all services on www.dns-sd.org.

Revision 1.9  2003/10/31 12:16:03  bradley
Added support for providing the resolved host name to the callback.

Revision 1.8  2003/08/20 06:44:24  bradley
Updated to latest internal version of the mDNSCore code: Added support for interface
specific registrations; Added support for no-such-service registrations; Added support for host
name registrations; Added support for host proxy and service proxy registrations; Added support for
registration record updates (e.g. TXT record updates); Added support for using either a single C
string TXT record, a raw, pre-formatted TXT record potentially containing multiple character string
entries, or a C-string containing a Mac OS X-style \001-delimited set of TXT record character
strings; Added support in resolve callbacks for providing both a simplified C-string for TXT records
and a ptr/size for the raw TXT record data; Added utility routines for dynamically building TXT
records from a variety of sources (\001-delimited, individual strings, etc.) and converting TXT
records to various formats for use in apps; Added utility routines to validate DNS names, DNS
service types, and TXT records; Moved to portable address representation unions (byte-stream vs host
order integer) for consistency, to avoid swapping between host and network byte order, and for IPv6
support; Removed dependence on modified mDNSCore: define structures and prototypes locally; Added
support for automatically renaming services on name conflicts; Detect and correct TXT records from
old versions of mDNS that treated a TXT record as an arbitrary block of data, but prevent other
malformed TXT records from being accepted; Added many more error codes; Added complete HeaderDoc for
all constants, structures, typedefs, macros, and functions. Various other minor cleanup and fixes.

Revision 1.7  2003/08/12 19:56:29  cheshire
Update to APSL 2.0

Revision 1.6  2003/07/02 21:20:10  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.5  2003/03/22 02:57:45  cheshire
Updated mDNSWindows to use new "mDNS_Execute" model (see "mDNSCore/Implementer Notes.txt")

Revision 1.4  2003/02/20 00:59:05  cheshire
Brought Windows code up to date so it complies with
Josh Graessley's interface changes for IPv6 support.
(Actual support for IPv6 on Windows will come later.)

Revision 1.3  2002/09/21 20:44:57  zarzycki
Added APSL info

Revision 1.2  2002/09/20 05:58:02  bradley
DNS Services for Windows

*/

//---------------------------------------------------------------------------------------------------------------------------
/*!	@header		DNSServices
	
	@abstract	DNS Services interfaces.
	
	@discussion	
	
	DNS Services provides DNS service registration, domain and service discovery, and name resolving services.
*/

#ifndef	__DNS_SERVICES__
#define	__DNS_SERVICES__

#include	<stddef.h>

#ifdef	__cplusplus
	extern "C" {
#endif

#if 0
#pragma mark == General ==
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	dns_check_compile_time
	
	@abstract	Performs a compile-time check of something such as the size of an int.
	
	@discussion	
	
	This declares a unique array with a size that is determined by dividing 1 by the result of the compile-time expression 
	passed to the macro. If the expression evaluates to 0, this expression results in a divide by zero, which is illegal 
	and generates a compile-time error.

	For example:
	
	dns_check_compile_time( sizeof( int ) == 4 );
	
	Note: This only works with compile-time expressions.
	Note: This only works in places where extern declarations are allowed (e.g. global scope).
	
	References:
	
	<http://www.jaggersoft.com/pubs/CVu11_3.html>
	<http://www.jaggersoft.com/pubs/CVu11_5.html>
	
	Note: The following macros differ from the macros on the www.jaggersoft.com web site because those versions do not
	work with GCC due to GCC allow a zero-length array. Using a divide-by-zero condition turned out to be more portable.
*/

#define	dns_check_compile_time( X )		extern int dns_unique_name[ 1 / (int)( ( X ) ) ]

#define	dns_unique_name					dns_make_name_wrapper( __LINE__ )
#define	dns_make_name_wrapper( X )		dns_make_name( X )
#define	dns_make_name( X )				dns_check_compile_time_ ## X

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	dns_check_compile_time_code
	
	@abstract	Perform a compile-time check, suitable for placement in code, of something such as the size of an int.
	
	@discussion	
	
	This creates a switch statement with an existing case for 0 and an additional case using the result of a 
	compile-time expression. A switch statement cannot have two case labels with the same constant so if the
	compile-time expression evaluates to 0, it is illegal and generates a compile-time error. If the compile-time
	expression does not evaluate to 0, the resulting value is used as the case label and it compiles without error.

	For example:
	
	dns_check_compile_time_code( sizeof( int ) == 4 );
	
	Note: This only works with compile-time expressions.
	Note: This does not work in a global scope so it must be inside a function.
	
	References:
	
	<http://www.jaggersoft.com/pubs/CVu11_3.html>
	<http://www.jaggersoft.com/pubs/CVu11_5.html>
*/

#define	dns_check_compile_time_code( X )	switch( 0 ) { case 0: case X:; }

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	DNS_LOCAL
	
	@abstract	Macro to make variables and functions static when debugging is off, but exported when debugging is on.
	
	@discussion	
	
	Rather than using "static" directly, using this macros allows you to access these variables external while 
	debugging without being penalized for production builds.
*/

#if( DEBUG )
	#define	DNS_LOCAL
#else
	#define	DNS_LOCAL	static
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	DNS_EXPORT
	
	@abstract	Macro to provide a visual clue that a variable or function is globally visible.
*/

#define	DNS_EXPORT

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	DNS_DEBUG_USE_ONLY
	@abstract	Macro to mark a variable as unused when debugging is turned off.
	@discussion	
	
	Variables are sometimes needed only for debugging. When debugging is turned off, these debug-only variables
	generate compiler warnings about unused variables. To eliminate these warnings, use the DNS_DEBUG_USE_ONLY macro 
	to indicate the variables are for debugging only.
*/

#if( DEBUG )
	#define	DNS_DEBUG_USE_ONLY( X )
#else
	#define	DNS_DEBUG_USE_ONLY( X )		(void)( X )
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	DNS_UNUSED
	@abstract	Macro to mark a variable as unused.
	@discussion	
	
	There is no universally supported pragma/attribute for indicating a variable is unused. DNS_UNUSED lets 
	indicate a variable is unused in a manner that is supported by most compilers.
*/

#define	DNS_UNUSED( X )			(void)( X )

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSUInt8

	@abstract	8-bit unsigned data type.
*/

typedef unsigned char		DNSUInt8;

dns_check_compile_time( sizeof( DNSUInt8 ) == 1 );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSUInt16

	@abstract	16-bit unsigned data type.
*/

typedef unsigned short		DNSUInt16;

dns_check_compile_time( sizeof( DNSUInt16 ) == 2 );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSUInt32

	@abstract	32-bit unsigned data type.
*/

typedef unsigned long		DNSUInt32;

dns_check_compile_time( sizeof( DNSUInt32 ) == 4 );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSSInt32

	@abstract	32-bit signed data type.
*/

typedef signed long		DNSSInt32;

dns_check_compile_time( sizeof( DNSSInt32 ) == 4 );


//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSOpaque16

	@abstract	16-bit opaque data type with 8-bit and 16-bit accessors.
*/

typedef union DNSOpaque16	DNSOpaque16;
union	DNSOpaque16
{
	DNSUInt8		v8[ 2 ];
	DNSUInt16		v16;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSOpaque32

	@abstract	32-bit opaque data type with 8-bit, 16-bit, and 32-bit accessors.
*/

typedef union DNSOpaque32	DNSOpaque32;
union	DNSOpaque32
{
	DNSUInt8		v8[ 4 ];
	DNSUInt16		v16[ 2 ];
	DNSUInt32		v32;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSOpaque128

	@abstract	128-bit opaque data type with 8-bit, 16-bit, and 32-bit accessors.
*/

typedef union DNSOpaque128	DNSOpaque128;
union	DNSOpaque128
{
	DNSUInt8		v8[ 16 ];
	DNSUInt16		v16[ 8 ];
	DNSUInt32		v32[ 4 ];
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSCount

	@abstract	Count of at least 32-bits.
*/

typedef DNSUInt32		DNSCount;

#if 0
#pragma mark == Errors ==
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSStatus

	@abstract	DNS Service status code.

	@constant	kDNSNoErr					(0)      Success. No error occurred.
	@constant	kDNSUnknownErr				(-65537) An unknown error occurred.
	@constant	kDNSNoSuchNameErr			(-65538) The name could not be found on the network.
	@constant	kDNSNoMemoryErr				(-65539) Not enough memory was available.
	@constant	kDNSBadParamErr				(-65540) A invalid or inappropriate parameter was specified.
	@constant	kDNSBadReferenceErr			(-65541) A invalid or inappropriate reference was specified.
	@constant	kDNSBadStateErr				(-65542) The current state does not allow the specified operation.
	@constant	kDNSBadFlagsErr				(-65543) An invalid, inappropriate, or unsupported flag was specified.
	@constant	kDNSUnsupportedErr			(-65544) The specified feature is not currently supported.
	@constant	kDNSNotInitializedErr		(-65545) DNS Service has not been initialized.
	@constant	kDNSNoCacheErr				(-65546) No cache was specified.
	@constant	kDNSAlreadyRegisteredErr	(-65547) Service or host name is already registered.
	@constant	kDNSNameConflictErr			(-65548) Name conflicts with another on the network.
	@constant	kDNSInvalidErr				(-65549) A general error to indicate something is invalid.
	@constant	kDNSGrowCache				(-65550) Cache needs to be grown (not used).
	@constant	kDNSIncompatibleErr			(-65551) Version is incompatible.
	
	@constant	kDNSSizeErr					(-65600) Size was too small or too big.
	@constant	kDNSMismatchErr				(-65601) A data, version, etc. mismatch occurred.
	@constant	kDNSReadErr					(-65602) Read failed.
	@constant	kDNSWriteErr				(-65603) Write failed.
	@constant	kDNSCanceledErr				(-65604) Operation was canceled.
	@constant	kDNSTimeoutErr				(-65605) Operation timed out.
	@constant	kDNSConnectionErr			(-65606) A disconnect or other connection error occurred.
	@constant	kDNSInUseErr				(-65607) Object is in use (e.g. cannot reuse active param blocks).
	@constant	kDNSNoResourcesErr			(-65608) Resources unavailable to perform the operation.
	@constant	kDNSEndingErr				(-65609) Connection, session, or something is ending.
	
	@constant	kDNSConfigChanged			(-65791) Configuration changed (not used).
	@constant	kDNSMemFree					(-65792) Memory can be freed.
*/

typedef DNSSInt32		DNSStatus;
enum
{
	kDNSNoErr					= 0, 
	
	// DNS Services error codes are in the range FFFE FF00 (-65792) to FFFE FFFF (-65537).
	
	kDNSStartErr 				= -65537, 	// 0xFFFE FFFF
	
	kDNSUnknownErr				= -65537, 
	kDNSNoSuchNameErr			= -65538, 
	kDNSNoMemoryErr				= -65539, 
	kDNSBadParamErr				= -65540, 
	kDNSBadReferenceErr			= -65541, 
	kDNSBadStateErr				= -65542, 
	kDNSBadFlagsErr				= -65543, 
	kDNSUnsupportedErr			= -65544, 
	kDNSNotInitializedErr		= -65545, 
	kDNSNoCacheErr				= -65546, 
	kDNSAlreadyRegisteredErr	= -65547, 
	kDNSNameConflictErr			= -65548, 
	kDNSInvalidErr				= -65549, 
	kDNSGrowCache				= -65550, 	// Reserved for mDNSCore
	kDNSIncompatibleErr			= -65551, 
	
	kDNSSizeErr					= -65600, 	
	kDNSMismatchErr				= -65601, 
	kDNSReadErr					= -65602, 
	kDNSWriteErr				= -65603, 
	kDNSCanceledErr				= -65604, 
	kDNSTimeoutErr				= -65605, 
	kDNSConnectionErr			= -65606, 
	kDNSInUseErr				= -65607, 
	kDNSNoResourcesErr			= -65608, 
	kDNSEndingErr				= -65609, 
	
	kDNSConfigChanged			= -65791,	// Reserved for mDNSCore
	kDNSMemFree					= -65792,	// Reserved for mDNSCore

	kDNSEndErr					= -65792	// 0xFFFE FF00
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSFlags

	@abstract	Flags used control DNS Services.
	
	@constant	kDNSFlagAdvertise
					Indicates that interfaces should be advertised on the network. Software that only performs searches 
					do not need to set this flag.
*/

typedef DNSUInt32		DNSFlags;
enum
{
	kDNSFlagAdvertise = ( 1 << 0 )
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSPort

	@abstract	UDP/TCP port for DNS services.
	
	@constant	kDNSPortInvalid
					Invalid port.
	
	@constant	kDNSPortUnicastDNS
					TCP/UDP port for normal unicast DNS (see RFC 1035).

	@constant	kDNSPortMulticastDNS
					TCP/UDP port for Multicast DNS (see <http://www.multicastdns.org/>).
*/

typedef DNSUInt16		DNSPort;
enum
{
	kDNSPortInvalid			= 0, 
	kDNSPortUnicastDNS		= 53, 
	kDNSPortMulticastDNS	= 5353
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSNetworkAddressType

	@abstract	Type of address data within a DNSNetworkAddress.
	
	@constant	kDNSNetworkAddressTypeInvalid
					Invalid type.
	
	@constant	kDNSNetworkAddressTypeIPv4
					IPv4 address data.

	@constant	kDNSNetworkAddressTypeIPv6
					IPv6 address data.
*/

typedef DNSUInt32	DNSNetworkAddressType;

#define kDNSNetworkAddressTypeInvalid		0
#define kDNSNetworkAddressTypeIPv4			4
#define kDNSNetworkAddressTypeIPv6			6
#define kDNSNetworkAddressTypeAny			0xFFFFFFFF

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSNetworkAddressIPv4

	@field		addr
					32-bit IPv4 address in network byte order.
	
	@field		port
					16-bit port number in network byte order.
*/

typedef struct	DNSNetworkAddressIPv4	DNSNetworkAddressIPv4;
struct	DNSNetworkAddressIPv4
{
	DNSOpaque32		addr;
	DNSOpaque16		port;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSNetworkAddressIPv6

	@field		addr
					128-bit IPv6 address in network byte order.
	
	@field		port
					16-bit port number in network byte order.
*/

typedef struct	DNSNetworkAddressIPv6	DNSNetworkAddressIPv6;
struct	DNSNetworkAddressIPv6
{
	DNSOpaque128		addr;
	DNSOpaque16			port;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSNetworkAddress

	@field		addressType
					Type of data contained within the address structure.
	
	@field		ipv4
					IPv4 address data.
					
	@field		reserved
					Reserved data (pads structure to allow for future growth). Unused portions must be zero.
*/

typedef struct	DNSNetworkAddress	DNSNetworkAddress;
struct	DNSNetworkAddress
{
	DNSNetworkAddressType			addressType;
	union
	{
		DNSNetworkAddressIPv4		ipv4;
		DNSNetworkAddressIPv6		ipv6;
	} u;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	kDNSLocalDomain

	@abstract	Local DNS domain name (local.).
*/

#define	kDNSLocalDomain		"local."

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSServicesInitialize
	
	@abstract	Initializes DNS Services. This must be called before DNS Services functions can be used.
	
	@param		inFlags
					Flags to control DNS Services.

	@param		inCacheEntryCount
					Number of entries in the DNS record cache. Specify 0 to use the default.
					
	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSServicesInitialize( DNSFlags inFlags, DNSCount inCacheEntryCount );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSServicesFinalize

	@abstract	Finalizes DNS Services. No DNS Services functions may be called after this function is called.
*/

void	DNSServicesFinalize( void );

#if 0
#pragma mark == Resolving ==
#endif

//===========================================================================================================================
//	Resolving
//===========================================================================================================================

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSBrowserRef

	@abstract	Reference to a DNS browser object.
	
	@discussion	
	
	A browser object is typically used by a graphical user application in a manner similar to the Macintosh "Chooser" 
	application. The application creates a browser object then starts domain and/or service searches to begin browsing.
	When domains and/or services are found, added, or removed, the application is notified via a callback routine.
*/

typedef struct	DNSBrowser *		DNSBrowserRef;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSResolverRef

	@abstract	Reference to a DNS resolver object.
		
	@discussion	
	
	A resolver object is used to resolve service names to IP addresses.
*/

typedef struct	DNSResolver *		DNSResolverRef;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSResolverFlags

	@abstract	Flags used to control resolve operations.
	
	@constant	kDNSResolverFlagOneShot
					Used to indicate the resolver object should be automatically released after the first resolve.

	@constant	kDNSResolverFlagOnlyIfUnique
					Used to indicate the resolver object should only be created if it is unique. This makes it easy for
					resolver management to be handled automatically. For example, some software needs to keep active 
					resolving operations open constantly to detect things like the IP address changing (e.g. if 
					displaying it to the user), but when a service goes away then comes back, a new resolver object 
					will often be created, leaving two resolvers for the same name.

	@constant	kDNSResolverFlagAutoReleaseByName
					Used to indicate the resolver object should be automatically released when the service name 
					that is associated with it is no longer on the network. When a service is added to the network, 
					a resolver object may be created and kept around to detect things like IP address changes. When 
					the service goes off the network, this option causes the resolver associated with that service 
					name to be automatically released.
*/

typedef DNSUInt32		DNSResolverFlags;
enum
{
	kDNSResolverFlagOneShot 			= ( 1 << 0 ), 
	kDNSResolverFlagOnlyIfUnique		= ( 1 << 1 ), 
	kDNSResolverFlagAutoReleaseByName	= ( 1 << 2 )
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSResolverEventType

	@abstract	Type of resolver event being delivered.
	
	@constant	kDNSResolverEventTypeInvalid
					Invalid event type. Here for completeness.

	@constant	kDNSResolverEventTypeRelease
					Object is being released. No additional data is associated with this event.

	@constant	kDNSResolverEventTypeResolved
					Name resolved.
*/

typedef long		DNSResolverEventType;
enum
{
	kDNSResolverEventTypeInvalid 	= 0, 
	kDNSResolverEventTypeRelease	= 1, 
	kDNSResolverEventTypeResolved	= 10
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSResolverEventResolveData

	@abstract	Data structure passed to callback routine when a resolve-related event occurs.

	@field		name
					Ptr to UTF-8 string containing the resolved name of the service.

	@field		type
					Ptr to UTF-8 string containing the resolved type of the service.

	@field		domain
					Ptr to UTF-8 string containing the resolved domain of the service.

	@field		interfaceID
					Network interface that received the event.
	
	@field		interfaceName
					Network interface that received the event. May be empty if interface is no longer available.

	@field		interfaceIP
					IP of network interface that received the event. May be invalid if interface is no longer available.
	
	@field		address
					Network address of the service. Used to communicate with the service.

	@field		textRecord
					Ptr to UTF-8 string containing any additional text information supplied by the service provider.

	@field		flags
					Flags used to augment the event data.

	@field		textRecordRaw
					Ptr to raw TXT record data. May be needed if a custom TXT record format is used.

	@field		textRecordRawSize
					Number of bytes in raw TXT record. May be needed if a custom TXT record format is used.

	@field		hostName
					Host name of the resolved service.
*/

typedef struct	DNSResolverEventResolveData		DNSResolverEventResolveData;
struct	DNSResolverEventResolveData
{
	const char *			name;
	const char *			type;
	const char *			domain;
	void *					interfaceID;
	const char *			interfaceName;
	DNSNetworkAddress		interfaceIP;
	DNSNetworkAddress		address;
	const char *			textRecord;
	DNSResolverFlags		flags;
	const void *			textRecordRaw;
	DNSCount				textRecordRawSize;
	const char *			hostName;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSResolverEvent

	@abstract	Data structure passed to callback routines when a resolver event occurs.

	@field		type
					Type of event. The type determines which portion of the data union to use. Types and data union 
					fields are named such as the data union field is the same as the event type. For example, a 
					"resolved" event type (kDNSResolverEventTypeResolved) would refer to data union field "resolved".
	
	@field		resolved
					Data associated with kDNSResolverEventTypeResolved event.
*/

typedef struct	DNSResolverEvent		DNSResolverEvent;
struct	DNSResolverEvent
{
	DNSResolverEventType				type;
	
	union
	{
		DNSResolverEventResolveData		resolved;
	
	} data;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSResolverCallBack

	@abstract	CallBack routine used to indicate a resolver event.
	
	@param		inContext
					User-supplied context for callback (specified when browser is created).

	@param		inRef
					Reference to resolver object generating the event.

	@param		inStatusCode
					Status of the event.

	@param		inEvent
					Data associated with the event.	
*/

typedef void
	( *DNSResolverCallBack )( 
		void *						inContext, 
		DNSResolverRef				inRef, 
		DNSStatus					inStatusCode, 
		const DNSResolverEvent *	inEvent );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSResolverCreate

	@abstract	Creates a resolver object and start resolving a service name.

	@param		inFlags
					Flags to control the resolving process.

	@param		inName
					Ptr to UTF-8 string containing the service name to resolve (e.g. "My Printer").
	
	@param		inType
					Ptr to UTF-8 string containing the service type of the service to resolve (e.g. "_printer._tcp").

	@param		inDomain
					Ptr to UTF-8 string containing the domain of the service to resolve (e.g. "apple.com"). Use NULL 
					to indicate the local domain.

	@param		inCallBack
					CallBack routine to call when a resolver event occurs.

	@param		inCallBackContext
					Context pointer to pass to CallBack routine when an event occurs. Not inspected by DNS Services.

	@param		inOwner
					Reference to browser object related to this resolver. If a browser object is specified and is 
					later released, this resolver object will automatically be released too. May be null.

	@param		outRef
					Ptr to receive reference to resolver object. If the kDNSResolverFlagOnlyIfUnique flag is specified 
					and there is already a resolver for the name, a NULL reference is returned in this parameter to let 
					the caller know that no resolver was created. May be null.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus
	DNSResolverCreate( 
		DNSResolverFlags		inFlags, 
		const char *			inName, 
		const char *			inType, 
		const char *			inDomain, 
		DNSResolverCallBack		inCallBack, 
		void *					inCallBackContext, 
		DNSBrowserRef			inOwner, 
		DNSResolverRef *		outRef );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSResolverRelease

	@abstract	Releases a resolver object.
	
	@param		inRef
					Reference to the resolver object to release.

	@param		inFlags
					Flags to control the release process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSResolverRelease( DNSResolverRef inRef, DNSResolverFlags inFlags );

#if 0
#pragma mark == Browsing ==
#endif

//===========================================================================================================================
//	Browsing
//===========================================================================================================================

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSBrowserFlags

	@abstract	Flags used to control browser operations.
	
	@constant	kDNSBrowserFlagRegistrationDomainsOnly
					Used to indicate the client is browsing only for domains to publish services. When the client wishes
					to publish a service, a domain browse operation would be started, with this flag specified, to find 
					the domain used to register the service. Only valid when passed to DNSBrowserStartDomainSearch.

	@constant	kDNSBrowserFlagAutoResolve
					Used to indicate discovered names should be automatically resolved. This eliminates the need to 
					manually create a resolver to get the IP address and other information. Only valid when passed to 
					DNSBrowserStartServiceSearch. When this option is used, it is important to avoid manually resolving
					names because this option causes DNS Services to automatically resolve and multiple resolvers for 
					the same name will lead to unnecessary network bandwidth usage. It is also important to note that 
					the notification behavior of the browser is otherwise not affected by this option so browser callback
					will still receive the same add/remove domain/service events it normally would.
*/

typedef DNSUInt32		DNSBrowserFlags;
enum
{
	kDNSBrowserFlagRegistrationDomainsOnly	= ( 1 << 0 ), 
	kDNSBrowserFlagAutoResolve				= ( 1 << 1 )
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSBrowserEventType

	@abstract	Type of browser event being delivered.
	
	@constant	kDNSBrowserEventTypeInvalid
					Invalid event type. Here for completeness.

	@constant	kDNSBrowserEventTypeRelease
					Object is being released. No additional data is associated with this event.
	
	@constant	kDNSBrowserEventTypeAddDomain
					Domain added/found. 

	@constant	kDNSBrowserEventTypeAddDefaultDomain
					Default domain added/found. This domain should be selected as the default.

	@constant	kDNSBrowserEventTypeRemoveDomain
					Domain removed.

	@constant	kDNSBrowserEventTypeAddService
					Service added/found.

	@constant	kDNSBrowserEventTypeRemoveService
					Service removed.

	@constant	kDNSBrowserEventTypeResolved
					Name resolved. This is only delivered if the kDNSBrowserFlagAutoResolve option is used with 
					DNSBrowserStartServiceSearch.
*/

typedef long		DNSBrowserEventType;
enum
{
	kDNSBrowserEventTypeInvalid 			= 0, 
	kDNSBrowserEventTypeRelease				= 1, 
	kDNSBrowserEventTypeAddDomain	 		= 10, 
	kDNSBrowserEventTypeAddDefaultDomain	= 11, 
	kDNSBrowserEventTypeRemoveDomain 		= 12, 
	kDNSBrowserEventTypeAddService 			= 20, 
	kDNSBrowserEventTypeRemoveService		= 21, 
	kDNSBrowserEventTypeResolved			= 30
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSBrowserEventDomainData

	@abstract	Data structure referenced by callback routines when a domain-related event occurs.

	@field		interfaceID
					Network interface that received the event.
	
	@field		interfaceName
					Network interface that received the event. May be empty if interface is no longer available.

	@field		interfaceIP
					IP of network interface that received the event. May be invalid if interface is no longer available.
	
	@field		domain
					Ptr to UTF-8 string containing the domain name. NULL if no domain name is available or applicable.

	@field		flags
					Flags used to augment the event data.
*/

typedef struct	DNSBrowserEventDomainData	DNSBrowserEventDomainData;
struct	DNSBrowserEventDomainData
{
	void *					interfaceID;
	const char *			interfaceName;
	DNSNetworkAddress		interfaceIP;
	const char *			domain;
	DNSBrowserFlags			flags;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSBrowserEventServiceData

	@abstract	Data structure passed to callback routines when a service-related event occurs.

	@field		interfaceID
					Network interface that received the event.
	
	@field		interfaceName
					Network interface that received the event. May be empty if interface is no longer available.

	@field		interfaceIP
					IP of network interface that received the event. May be invalid if interface is no longer available.
	
	@field		name
					Ptr to UTF-8 string containing the service name. NULL if no service name is available or applicable.
	
	@field		type
					Ptr to UTF-8 string containing the service type. NULL if no service type is available or applicable.

	@field		domain
					Ptr to UTF-8 string containing the domain name. NULL if no domain name is available or applicable.

	@field		flags
					Flags used to augment the event data.
*/

typedef struct	DNSBrowserEventServiceData	DNSBrowserEventServiceData;
struct	DNSBrowserEventServiceData
{
	void *					interfaceID;
	const char *			interfaceName;
	DNSNetworkAddress		interfaceIP;
	const char *			name;
	const char *			type;
	const char *			domain;
	DNSBrowserFlags			flags;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSBrowserEvent

	@abstract	Data structure passed to callback routines when a browser event occurs.

	@field		type
					Type of event. The type determines which portion of the data union to use. Types and data union 
					fields are named such as the data union field is the same as the event type. For example, an 
					"add domain" event type (kDNSBrowserEventTypeAddDomain) would refer to data union field "addDomain".
	
	@field		addDomain
					Data associated with kDNSBrowserEventTypeAddDomain event.

	@field		addDefaultDomain
					Data associated with kDNSBrowserEventTypeAddDefaultDomain event.

	@field		removeDomain
					Data associated with kDNSBrowserEventTypeRemoveDomain event.

	@field		addService
					Data associated with kDNSBrowserEventTypeAddService event.

	@field		removeService
					Data associated with kDNSBrowserEventTypeRemoveService event.

	@field		resolved
					Data associated with kDNSBrowserEventTypeResolved event.
*/

typedef struct	DNSBrowserEvent		DNSBrowserEvent;
struct	DNSBrowserEvent
{
	DNSBrowserEventType							type;
	
	union
	{
		DNSBrowserEventDomainData				addDomain;
		DNSBrowserEventDomainData				addDefaultDomain;
		DNSBrowserEventDomainData				removeDomain;
		DNSBrowserEventServiceData				addService;
		DNSBrowserEventServiceData				removeService;
		const DNSResolverEventResolveData *		resolved;
		
	} data;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSBrowserCallBack

	@abstract	CallBack routine used to indicate a browser event.
	
	@param		inContext
					User-supplied context for callback (specified when browser is created).

	@param		inRef
					Reference to browser object generating the event.

	@param		inStatusCode
					Status of the event.

	@param		inEvent
					Data associated with the event.
*/

typedef void
	( *DNSBrowserCallBack )( 
		void *					inContext, 
		DNSBrowserRef			inRef, 
		DNSStatus				inStatusCode, 
		const DNSBrowserEvent *	inEvent );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSBrowserCreate

	@abstract	Creates a browser object.
	
	@param		inFlags
					Flags to control the creation process.

	@param		inCallBack
					CallBack routine to call when a browser event occurs.

	@param		inCallBackContext
					Context pointer to pass to CallBack routine when an event occurs. Not inspected by DNS Services.

	@param		outRef
					Ptr to receive reference to the created browser object. May be null.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus
	DNSBrowserCreate( 
		DNSBrowserFlags 	inFlags, 
		DNSBrowserCallBack	inCallBack, 
		void *				inCallBackContext, 
		DNSBrowserRef *		outRef );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSBrowserRelease

	@abstract	Releases a browser object.
	
	@param		inRef
					Reference to the browser object to release.

	@param		inFlags
					Flags to control the release process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSBrowserRelease( DNSBrowserRef inRef, DNSBrowserFlags inFlags );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSBrowserStartDomainSearch

	@abstract	Starts a domain name search.
	
	@param		inRef
					Reference to browser object to start the search on.

	@param		inFlags
					Flags to control the search process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSBrowserStartDomainSearch( DNSBrowserRef inRef, DNSBrowserFlags inFlags );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSBrowserStopDomainSearch

	@abstract	Stops a domain name search.
	
	@param		inRef
					Reference to browser object to stop the search on.

	@param		inFlags
					Flags to control the stopping process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSBrowserStopDomainSearch( DNSBrowserRef inRef, DNSBrowserFlags inFlags );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSBrowserStartServiceSearch

	@abstract	Starts a service search.
	
	@param		inRef
					Reference to browser object to start the search on.

	@param		inFlags
					Flags to control the search process.

	@param		inType
					Ptr to UTF-8 string containing the service type to search for (e.g. "_printer._tcp").

	@param		inDomain
					Ptr to UTF-8 string containing the domain to search in (e.g. "apple.com"). Use NULL to indicate 
					the local domain.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus
	DNSBrowserStartServiceSearch( 
		DNSBrowserRef 		inRef, 
		DNSBrowserFlags 	inFlags, 
		const char * 		inType, 
		const char *		inDomain );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSBrowserStopServiceSearch

	@abstract	Stops a service search.
	
	@param		inRef
					Reference to browser object to stop the search on.

	@param		inFlags
					Flags to control the stopping process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSBrowserStopServiceSearch( DNSBrowserRef inRef, DNSBrowserFlags inFlags );

#if 0
#pragma mark == Registration ==
#endif

//===========================================================================================================================
//	Registration
//===========================================================================================================================

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSRegistrationRef

	@abstract	Reference to a DNS registration object.
*/

typedef struct	DNSRegistration *		DNSRegistrationRef;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSRegistrationRecordRef

	@abstract	Reference to a DNS record object.
*/

typedef struct	DNSRegistrationRecord *		DNSRegistrationRecordRef;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSRegistrationFlags

	@abstract	Flags used to control registration operations.
	
	@constant	kDNSRegistrationFlagPreFormattedTextRecord
					Text record is pre-formatted and should be used directly without interpretation.

	@constant	kDNSRegistrationFlagAutoRenameOnConflict
					Automatically uniquely rename and re-register the service when a name conflict occurs.
*/

typedef DNSUInt32		DNSRegistrationFlags;
enum
{
	kDNSRegistrationFlagPreFormattedTextRecord 	= ( 1 << 0 ), 
	kDNSRegistrationFlagAutoRenameOnConflict 	= ( 1 << 1 )
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSRecordFlags

	@abstract	Flags used to control record operations.
*/

typedef DNSUInt32		DNSRecordFlags;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSRegistrationEventType

	@abstract	Type of registration event being delivered.
	
	@constant	kDNSResolverEventTypeInvalid
					Invalid event type. Here for completeness.

	@constant	kDNSRegistrationEventTypeRelease
					Object is being released. No additional data is associated with this event.
					
	@constant	kDNSRegistrationEventTypeRegistered
					Name has been successfully registered.

	@constant	kDNSRegistrationEventTypeNameCollision
					Name collision. The registration is no longer valid. A new registration must be created if needed.
*/

typedef long		DNSRegistrationEventType;
enum
{
	kDNSRegistrationEventTypeInvalid 			= 0, 
	kDNSRegistrationEventTypeRelease 			= 1,
	kDNSRegistrationEventTypeRegistered	 		= 10, 
	kDNSRegistrationEventTypeNameCollision		= 11
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@struct		DNSRegistrationEvent

	@abstract	Data structure passed to callback routines when a registration event occurs.

	@field		type
					Type of event. The type determines which portion of the data union to use. Types and data union 
					fields are named such as the data union field is the same as the event type.
	
	@field		reserved
					Reserved for future use.
*/

typedef struct	DNSRegistrationEvent		DNSRegistrationEvent;
struct	DNSRegistrationEvent
{
	DNSRegistrationEventType		type;
	
	union
	{
		DNSUInt32					reserved;
	
	}	data;
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSRegistrationCallBack

	@abstract	CallBack routine used to indicate a registration event.
	
	@param		inContext
					User-supplied context for callback (specified when registration is created).

	@param		inRef
					Reference to registration object generating the event.

	@param		inStatusCode
					Status of the event.

	@param		inEvent
					Data associated with the event.
*/

typedef void
	( *DNSRegistrationCallBack )( 
		void *							inContext, 
		DNSRegistrationRef				inRef, 
		DNSStatus						inStatusCode, 
		const DNSRegistrationEvent *	inEvent );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSRegistrationCreate

	@abstract	Creates a registration object and publish the registration.

	@param		inFlags
					Flags to control the registration process.

	@param		inName
					Ptr to UTF-8 string containing the service name to register (e.g. "My Printer").
	
	@param		inType
					Ptr to UTF-8 string containing the service type of the service to registration (e.g. "_printer._tcp").

	@param		inDomain
					Ptr to UTF-8 string containing the domain of the service to register (e.g. "apple.com"). Use NULL 
					to indicate the local domain.
	
	@param		inPort
					TCP/UDP port where the service is being offered (e.g. 80 for an HTTP service).

	@param		inTextRecord
					Ptr to UTF-8 string containing any additional text to provide when the service is resolved.

	@param		inTextRecordSize
					Size to text record.

	@param		inHost
					Name of the host to associate with the registration. Use NULL to use the default host name.
	
	@field		inInterfaceName
					Name of an interface to restrict service registration to. Use NULL to register service on all interfaces.
					
	@param		inCallBack
					CallBack routine to call when a registration event occurs.

	@param		inCallBackContext
					Context pointer to pass to CallBack routine when an event occurs. Not inspected by DNS Services.

	@param		outRef
					Ptr to receive reference to registration object. May be null.

	@result		Error code indicating failure reason or kDNSNoErr if successful.			
*/

DNSStatus
	DNSRegistrationCreate( 
		DNSRegistrationFlags		inFlags, 
		const char *				inName, 
		const char *				inType, 
		const char *				inDomain, 
		DNSPort						inPort, 
		const void *				inTextRecord, 
		DNSCount					inTextRecordSize, 
		const char *				inHost, 
		const char *				inInterfaceName, 
		DNSRegistrationCallBack		inCallBack, 
		void *						inCallBackContext, 
		DNSRegistrationRef *		outRef );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSNoSuchServiceRegistrationCreate

	@abstract	Creates a registration object and publish the registration to assert non-existence of a particular service.

	@param		inFlags
					Flags to control the registration process.

	@param		inName
					Ptr to UTF-8 string containing the service name to register (e.g. "My Printer").
	
	@param		inType
					Ptr to UTF-8 string containing the service type of the service to registration (e.g. "_printer._tcp").

	@param		inDomain
					Ptr to UTF-8 string containing the domain of the service to register (e.g. "apple.com"). Use NULL 
					to indicate the local domain.
	
	@field		inInterfaceName
					Name of an interface to restrict service registration to. Use NULL to register service on all interfaces.
					
	@param		inCallBack
					CallBack routine to call when a registration event occurs.

	@param		inCallBackContext
					Context pointer to pass to CallBack routine when an event occurs. Not inspected by DNS Services.

	@param		outRef
					Ptr to receive reference to registration object. May be null.

	@result		Error code indicating failure reason or kDNSNoErr if successful.			
*/

DNSStatus
	DNSNoSuchServiceRegistrationCreate( 
		DNSRegistrationFlags		inFlags, 
		const char *				inName, 
		const char *				inType, 
		const char *				inDomain, 
		const char *				inInterfaceName, 
		DNSRegistrationCallBack		inCallBack, 
		void *						inCallBackContext, 
		DNSRegistrationRef *		outRef );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSRegistrationRelease

	@abstract	Releases a registration object.
	
	@param		inRef
					Reference to the registration object to release.

	@param		inFlags
					Flags to control the release process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSRegistrationRelease( DNSRegistrationRef inRef, DNSRegistrationFlags inFlags );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSRegistrationUpdate

	@abstract	Updates an individual record for a registration.
	
	@param		inRef
					Reference to the registration object to update.

	@param		inRecord
					Record to update. Use NULL for the standard TXT record.

	@param		inData
					New record data.

	@param		inSize
					Size of new record data.

	@param		inNewTTL
					New time-to-live (TTL) in seconds for the updated data (e.g. 120 for 2 minutes).

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus
	DNSRegistrationUpdate( 
		DNSRegistrationRef 			inRef, 
		DNSRecordFlags				inFlags, 
		DNSRegistrationRecordRef 	inRecord, 
		const void *				inData, 
		DNSCount					inSize, 
		DNSUInt32					inNewTTL );

#if 0
#pragma mark == Domain Registration ==
#endif

//===========================================================================================================================
//	Domain Registration
//===========================================================================================================================

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSDomainRegistrationRef

	@abstract	Reference to a DNS registration object.
*/

typedef struct	DNSDomainRegistration *		DNSDomainRegistrationRef;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSDomainRegistrationFlags

	@abstract	Flags used to control registration operations.
*/

typedef DNSUInt32		DNSDomainRegistrationFlags;
enum
{
	kDNSDomainRegistrationFlagNone = 0
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSDomainRegistrationType

	@abstract	Type of domain registration.
	
	@constant	kDNSDomainRegistrationTypeBrowse
					Registration for domain browsing.

	@constant	kDNSDomainRegistrationTypeBrowseDefault
					Registration for the domain browsing domain.
					
	@constant	kDNSDomainRegistrationTypeRegistration
					Registration for domain registration.

	@constant	kDNSDomainRegistrationTypeRegistrationDefault
					Registration for the domain registration domain.
*/

typedef DNSUInt32		DNSDomainRegistrationType;
enum
{
	kDNSDomainRegistrationTypeBrowse				= 0, 
	kDNSDomainRegistrationTypeBrowseDefault			= 1, 
	kDNSDomainRegistrationTypeRegistration			= 2, 
	kDNSDomainRegistrationTypeRegistrationDefault	= 3, 
	
	kDNSDomainRegistrationTypeMax					= 4
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSDomainRegistrationCreate

	@abstract	Creates a domain registration object and publish the domain.

	@param		inFlags
					Flags to control the registration process.

	@param		inName
					Ptr to string containing the domain name to register (e.g. "apple.com").
	
	@param		inType
					Type of domain registration.

	@param		outRef
					Ptr to receive reference to domain registration object. May be null.

	@result		Error code indicating failure reason or kDNSNoErr if successful.			
*/

DNSStatus
	DNSDomainRegistrationCreate( 
		DNSDomainRegistrationFlags		inFlags, 
		const char *					inName, 
		DNSDomainRegistrationType		inType, 
		DNSDomainRegistrationRef *		outRef );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSDomainRegistrationRelease

	@abstract	Releases a domain registration object.
	
	@param		inRef
					Reference to the domain registration object to release.

	@param		inFlags
					Flags to control the release process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSDomainRegistrationRelease( DNSDomainRegistrationRef inRef, DNSDomainRegistrationFlags inFlags );

#if 0
#pragma mark == Host Registration ==
#endif

//===========================================================================================================================
//	Host Registration
//===========================================================================================================================

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSHostRegistrationRef

	@abstract	Reference to a DNS host registration object.
*/

typedef struct	DNSHostRegistration *		DNSHostRegistrationRef;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@enum		DNSHostRegistrationFlags

	@abstract	Flags used to control registration operations.
	
	@constant	kDNSHostRegistrationFlagOnlyIfNotFound
					Only creates the object and registers the host if it was not already found in the list.

	@constant	kDNSHostRegistrationFlagAutoRenameOnConflict
					Automatically uniquely rename and re-register the host when a name conflict occurs.

*/

typedef DNSUInt32		DNSHostRegistrationFlags;
enum
{
	kDNSHostRegistrationFlagNone 					= 0, 
	kDNSHostRegistrationFlagOnlyIfNotFound 			= ( 1 << 0 ), 
	kDNSHostRegistrationFlagAutoRenameOnConflict 	= ( 1 << 1 )
};

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSHostRegistrationCallBack

	@abstract	CallBack routine used to indicate a host registration event.
	
	@param		inContext
					User-supplied context for callback (specified when browser is created).

	@param		inRef
					Reference to resolver object generating the event.

	@param		inStatusCode
					Status of the event.

	@param		inData
					Data associated with the event.	
*/

typedef void
	( *DNSHostRegistrationCallBack )( 
		void *					inContext, 
		DNSHostRegistrationRef 	inRef, 
		DNSStatus 				inStatusCode, 
		void *					inData );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSHostRegistrationCreate

	@abstract	Creates a host registration object and publishes the host.

	@param		inFlags
					Flags to control the registration process.

	@param		inName
					Name of the host to register (e.g. "My Web Server").
	
	@param		inDomain
					Domain of the host to register (e.g. "apple.com"). Use NULL to indicate the local domain.
	
	@param		inAddr
					IP address of host to register.
	
	@field		inInterfaceName
					Name of an interface to restrict registration to. Use NULL to register on all interfaces.
					
	@param		inCallBack
					CallBack routine to call when an event occurs.

	@param		inCallBackContext
					Context pointer to pass to callback routine when an event occurs. Not inspected by DNS Services.	
	
	@param		outRef
					Ptr to receive reference to host registration object. May be null.

	@result		Error code indicating failure reason or kDNSNoErr if successful.			
*/

DNSStatus
	DNSHostRegistrationCreate( 
		DNSHostRegistrationFlags	inFlags, 
		const char *				inName, 
		const char *				inDomain, 
		const DNSNetworkAddress *	inAddr, 
		const char *				inInterfaceName, 
		DNSHostRegistrationCallBack	inCallBack, 
		void *						inCallBackContext, 
		DNSHostRegistrationRef *	outRef );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSHostRegistrationRelease

	@abstract	Releases a host registration object.
	
	@param		inRef
					Reference to the host registration object to release.

	@param		inFlags
					Flags to control the release process.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSHostRegistrationRelease( DNSHostRegistrationRef inRef, DNSHostRegistrationFlags inFlags );

#if 0
#pragma mark == Utilities ==
#endif

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	kDNSTextRecordNoValue

	@abstract	Value to use when no value is desired for a name/value pair (e.g. "color" instead of "color=").
*/

#define	kDNSTextRecordNoValue		( (const void *) -1 )

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	kDNSTextRecordStringNoValue

	@abstract	Value to use when no value is desired for a name/value pair (e.g. "color" instead of "color=").
*/

#define	kDNSTextRecordStringNoValue		( (const char *) -1 )

//---------------------------------------------------------------------------------------------------------------------------
/*!	@defined	kDNSTextRecordNoValue

	@abstract	Size value to use when no value is desired for a name/value pair (e.g. "color" instead of "color=").
*/

#define	kDNSTextRecordNoSize		( (size_t) -1 )

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSDynamicTextRecordBuildEscaped

	@abstract	Builds a TXT record from a string with \001 escape sequences to separate strings within the TXT record.
	
	@param		inFormat		C-string TXT record with \001 escape sequences as record separators.
	@param		outTextRecord	Receives a ptr to a built TXT record. Must free with DNSDynamicTextRecordRelease.
	@param		outSize			Receive actual size of the built TXT record. Use NULL if you don't need the size.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
	
	@discussion
	
	A DNS TXT record consists of a packed array of length-prefixed strings with each string being up to 255 characters. 
	To allow this to be described with a null-terminated C-string, a special escape sequence of \001 is used to separate 
	individual character strings within the C-string.
	
	For example, to represent the following 3 segments "test1=1", "test2=2", and "test3=3", you would use the following:
	
	DNSUInt8 *		txt;
	size_t			size;
	
	txt = NULL;
	
	err = DNSDynamicTextRecordBuildEscaped( "test1=1\001test2=2\001test3=3", &txt, &size );
	require_noerr( err, exit );
	
	... use text record
	
exit:
	DNSDynamicTextRecordRelease( txt );
*/

DNSStatus	DNSDynamicTextRecordBuildEscaped( const char *inFormat, void *outTextRecord, size_t *outSize );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSDynamicTextRecordAppendCString

	@abstract	Appends a name/value pair with the value being a C-string to a dynamic DNS TXT record data section.
	
	@param		ioTxt			Input: Ptr to a ptr to TXT record to append to.
								Output: Receives newly allocated ptr to the new TXT record.
								Note: Use a ptr to NULL the first time this is called.
	
	@param		ioTxtSize		Input: Ptr to size of existing TXT record.
								Output: Receives new size of TXT record.
	
	@param		inName			C-string name in the name/value pair (e.g. "path" for HTTP).

	@param		inValue			C-string value in the name/value pair (e.g. "/index.html for HTTP).

	@result		Error code indicating failure reason or kDNSNoErr if successful.
	
	@discussion
	
	This can be used to easily build dynamically-resized TXT records containing multiple name/value pairs of C-strings. 
	For example, the following adds "name=Ryknow", "age=30", and "job=Musician":
	
	DNSUInt8 *		txt;
	size_t			size;
	
	txt = NULL;
	size = 0;
	
	err = DNSDynamicTextRecordAppendCString( &txt, &size, "name", "Ryknow" );
	require_noerr( err, exit );
	
	err = DNSDynamicTextRecordAppendCString( &txt, &size, "age", "30" );
	require_noerr( err, exit );
	
	err = DNSDynamicTextRecordAppendCString( &txt, &size, "job", "Musician" );
	require_noerr( err, exit );
	
	... use text record

exit:
	DNSDynamicTextRecordRelease( txt );
*/

DNSStatus	DNSDynamicTextRecordAppendCString( void *ioTxt, size_t *ioTxtSize, const char *inName, const char *inValue );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSDynamicTextRecordAppendData

	@abstract	Appends a name/value pair to a dynamic DNS TXT record data section.
	
	@param		ioTxt			Input: Ptr to a ptr to TXT record to append to.
								Output: Receives newly allocated ptr to the new TXT record.
								Note: Use a ptr to NULL the first time this is called.
	
	@param		ioTxtSize		Input: Ptr to size of existing TXT record.
								Output: Receives new size of TXT record.
	
	@param		inName			C-string name in the name/value pair (e.g. "path" for HTTP).

	@param		inValue			Value data to associate with the name. Use kDNSTextRecordNoValue for no value.

	@param		inValueSize		Size of value data. Use kDNSTextRecordNoSize for no value.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus
	DNSDynamicTextRecordAppendData( 
		void *			ioTxt, 
		size_t * 		ioTxtSize, 
		const char *	inName, 
		const void *	inValue, 
		size_t			inValueSize );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSDynamicTextRecordRelease

	@abstract	Releases a dynamically allocated TXT record.
	
	@param		inTxt	Dynamic TXT record to release.
	
	@discussion
	
	This API may only be used with TXT records generated with DNSDynamicTextRecordAppendCString and 
	DNSDynamicTextRecordAppendData.
*/

void	DNSDynamicTextRecordRelease( void *inTxt );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSTextRecordAppendCString

	@abstract	Appends a name/value pair with the value being a C-string to DNS TXT record data section.
	
	@param		inTxt			TXT record to append to.
	@param		inTxtSize		Size of existing TXT record.
	@param		inTxtMaxSize	Maximum size of TXT record (i.e. size of buffer).
	@param		inName			C-string name in the name/value pair (e.g. "path" for HTTP).
	@param		inValue			C-string value in the name/value pair (e.g. "/index.html for HTTP).
	@param		outTxtSize		Receives resulting size of TXT record. Pass NULL if not needed.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
	
	@discussion
	
	This can be used to easily build TXT records containing multiple name/value pairs of C-strings. For example, the
	following adds "name=Ryknow", "age=30", and "job=Musician":
	
	DNSUInt8		txt[ 256 ];
	size_t			size;
	
	size = 0;
	
	err = DNSTextRecordAppendCString( txt, size, sizeof( txt ), "name", "Ryknow", &size );
	require_noerr( err, exit );
	
	err = DNSTextRecordAppendCString( txt, size, sizeof( txt ), "age", "30", &size );
	require_noerr( err, exit );
	
	err = DNSTextRecordAppendCString( txt, size, sizeof( txt ), "job", "Musician", &size );
	require_noerr( err, exit );
*/

DNSStatus
	DNSTextRecordAppendCString( 
		void *			inTxt, 
		size_t 			inTxtSize, 
		size_t 			inTxtMaxSize, 
		const char *	inName, 
		const char *	inValue, 
		size_t *		outTxtSize );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSTextRecordAppendData

	@abstract	Appends a name/value pair to a DNS TXT record data section.
	
	@param		inTxt			TXT record to append to.
	@param		inTxtSize		Size of existing TXT record.
	@param		inTxtMaxSize	Maximum size of TXT record (i.e. size of buffer).
	@param		inName			C-string name in the name/value pair (e.g. "path" for HTTP).
	@param		inValue			Value data to associate with the name. Use kDNSTextRecordNoValue for no value.
	@param		inValueSize		Size of value data. Use kDNSTextRecordNoSize for no value.
	@param		outTxtSize		Receives resulting size of TXT record. Pass NULL if not needed.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus
	DNSTextRecordAppendData( 
		void *			inTxt, 
		size_t 			inTxtSize, 
		size_t 			inTxtMaxSize, 
		const char *	inName, 
		const void *	inValue, 
		size_t			inValueSize, 
		size_t *		outTxtSize );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSTextRecordEscape

	@abstract	Converts a raw TXT record into a single, null-terminated string with \001 to delimit records.
	
	@param		inTextRecord		Raw TXT record to escape.
	@param		inTextSize			Number of bytes in the raw TXT record to escape.
	@param		outEscapedString	Receives ptr to escaped, \001-delimited, null-terminated string.

	@result		Error code indicating failure reason or kDNSNoErr if successful.
*/

DNSStatus	DNSTextRecordEscape( const void *inTextRecord, size_t inTextSize, char **outEscapedString );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSNameValidate

	@abstract	Validates a DNS name for correctness.
	
	@param		inName	C-string DNS name to validate.

	@result		Error code indicating failure reason or kDNSNoErr if valid.
*/

DNSStatus	DNSNameValidate( const char *inName );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSServiceTypeValidate

	@abstract	Validates a service type for correctness.
	
	@param		inServiceType	C-string service type to validate.

	@result		Error code indicating failure reason or kDNSNoErr if valid.
*/

DNSStatus	DNSServiceTypeValidate( const char *inServiceType );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@function	DNSTextRecordValidate

	@abstract	Validates a text record for correctness and optionally builds the TXT reocrd, and returns the actual size.
	
	@param		inText			C-string TXT record to validate. Use \001 escape sequence as record separator.
	@param		inMaxSize		Maximum size of the TXT record. Use a large number if a max size is not appropriate.
	@param		outRecord		Buffer to receive built TXT record. Use NULL if you don't need a built TXT record.
	@param		outActualSize	Ptr to receive actual size of TXT record. Use NULL if you don't need the actual size.
	
	@result		Error code indicating failure reason or kDNSNoErr if valid.
	
	@discussion
		
	A DNS TXT record consists of a packed array of length-prefixed strings with each string being up to 255 characters. 
	To allow this to be described with a null-terminated C-string, a special escape sequence of \001 is used to separate 
	individual character strings within the C-string.
	
	For example, to represent the following 3 segments "test1=1", "test2=2", and "test3=3", you would use the following:
	
	"test1=1\001test2=2\001test3=3"
*/

DNSStatus	DNSTextRecordValidate( const char *inText, size_t inMaxSize, void *outRecord, size_t *outActualSize );

#ifdef	__cplusplus
	}
#endif

#endif	// __DNS_SERVICES__
