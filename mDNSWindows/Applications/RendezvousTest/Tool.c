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
	
$Log: Tool.c,v $
Revision 1.7  2003/08/20 07:06:34  bradley
Update to APSL 2.0. Updated change history to match other mDNSResponder files.

Revision 1.6  2003/08/20 06:50:55  bradley
Updated to latest internal version of the Rendezvous for Windows code: Re-did everything to support
the latest DNSServices APIs (proxies, record updates, etc.); Added support for testing the platform
neutral DNSServices-based emulation layer for the Mac OS X DNSServiceDiscovery API.

*/

#if( defined( _MSC_VER ) )
	#pragma warning( disable:4068 )			// Disable "unknown pragma" warning for "pragma unused".
	#pragma warning( disable:4127 )			// Disable "conditional expression is constant" warning for debug macros.
	#pragma warning( disable:4311 )			// Disable "type cast : pointer truncation from void *const to int".
	
	// No stdint.h with Visual C++ so emulate it here.
	
	typedef signed char			int8_t;		// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef unsigned char		uint8_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef signed short		int16_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef unsigned short		uint16_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef signed long			int32_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
	typedef unsigned long		uint32_t;	// C99 stdint.h not supported in VC++/VS.NET yet.
#else
	#include	<stdint.h>
#endif

#include	<stdio.h>
#include	<stdlib.h>

#if( __MACH__ )
	#include	<sys/types.h>
	#include	<sys/socket.h>
	#include	<netinet/in.h>
	
	#include	<signal.h>
	#include	<unistd.h>
	
	#include	<CoreServices/CoreServices.h>
#else
	#define	WIN32_LEAN_AND_MEAN

	#include	<winsock2.h>
	#include	<windows.h>
#endif

#include	"DNSServices.h"
#include	"DNSServiceDiscovery.h"

//===========================================================================================================================
//	Macros
//===========================================================================================================================

#if( !TARGET_OS_MAC )
	#define	require_action_string( X, LABEL, ACTION, STR )				\
		do 																\
		{																\
			if( !( X ) ) 												\
			{															\
				fprintf( stderr, "%s\n", ( STR ) );						\
				{ ACTION; }												\
				goto LABEL;												\
			}															\
		} while( 0 )

	#define	require_string( X, LABEL, STR )								\
		do 																\
		{																\
			if( !( X ) ) 												\
			{															\
				fprintf( stderr, "%s\n", ( STR ) );						\
				goto LABEL;												\
																		\
			}															\
		} while( 0 )

	#define	require_noerr_string( ERR, LABEL, STR )						\
		do 																\
		{																\
			if( ( ERR ) != 0 ) 											\
			{															\
				fprintf( stderr, "%s (%ld)\n", ( STR ), ( ERR ) );		\
				goto LABEL;												\
			}															\
		} while( 0 )
#endif

//===========================================================================================================================
//	Prototypes
//===========================================================================================================================

int 				main( int argc, char* argv[] );
static void			Usage( void );
static int 			ProcessArgs( int argc, char* argv[] );
static DNSStatus	ProcessPreset( int inPreset );

#if( __MACH__ )
	static void	SigIntHandler( int inSignalNumber );
#endif

#if( defined( WINVER ) )
	static BOOL WINAPI	ConsoleControlHandler( DWORD inControlEvent );
#endif

static void	BrowserCallBack( void *inContext, DNSBrowserRef inRef, DNSStatus inStatusCode, const DNSBrowserEvent *inEvent );
static void ResolverCallBack( void *inContext, DNSResolverRef inRef, DNSStatus inStatusCode, const DNSResolverEvent *inEvent );

static void
	RegistrationCallBack( 
		void *							inContext, 
		DNSRegistrationRef				inRef, 
		DNSStatus						inStatusCode, 
		const DNSRegistrationEvent *	inEvent );

static void
	HostRegistrationCallBack( 
		void *					inContext, 
		DNSHostRegistrationRef 	inRef, 
		DNSStatus 				inStatusCode, 
		void *					inData );

static void
	EmulatedBrowserCallBack(
		DNSServiceBrowserReplyResultType	inResult, 
		const char *						inName,
		const char *						inType,
		const char *						inDomain,
		DNSServiceDiscoveryReplyFlags		inFlags,
		void *								inContext );

static void
	EmulatedDomainEnumerationCallBack(
		DNSServiceDomainEnumerationReplyResultType	inResult, 
		const char *								inDomain,
		DNSServiceDiscoveryReplyFlags				inFlags,
		void *										inContext );

static void
	EmulatedResolverCallBack(
		struct sockaddr *				inInterfaceAddr, 
		struct sockaddr *				inAddr,
		const char *					inTextRecord,
		DNSServiceDiscoveryReplyFlags	inFlags, 
		void *							inContext );

static void	EmulatedRegistrationCallBack( DNSServiceRegistrationReplyErrorType inResult, void *inContext );

static char *	IPv4ToString( DNSOpaque32 inIP, char *outString );

//===========================================================================================================================
//	Globals
//===========================================================================================================================

#if( defined( WINVER ) )
	static volatile int		gQuit = 0;
#endif

static int					gPrintTXTRecords = 1;

// Presets

typedef struct	PresetData	PresetData;
struct	PresetData
{
	int			argc;
	char *		argv[ 16 ];
};

#if 0
#pragma mark == Presets ==
#endif

static const PresetData		gPresets[] = 
{
	/* 01 */	{ 2, { "rendezvous", "-bbd" } },
	/* 02 */	{ 4, { "rendezvous", "-bs",  "_airport._tcp", 		"local."  } }, 
	/* 03 */	{ 4, { "rendezvous", "-bs",  "_xserveraid._tcp", 	"local."  } }, 
	/* 04 */	{ 3, { "rendezvous", "-rdb", "apple.com" } }, 
	/* 05 */	{ 7, { "rendezvous", "-rs",  "My Fake AirPort", 	"_airport._tcp", 	"local.", 	"1234", "My Fake Info"  } }, 
	/* 06 */	{ 7, { "rendezvous", "-rs",  "My Fake Xserve RAID", "_xserveraid._tcp", "local.", 	"1234", "My Fake Info"  } }, 
	/* 07 */	{ 7, { "rendezvous", "-rs",  "My Fake Web Server", 	"_http._tcp", 		"local.",	"8080", "index.html"  } }, 
	/* 08 */	{ 9, { "rendezvous", "-rps", "www.apple.com", "17.254.0.91", "Apple Web Server", "_http._tcp", "local.", "80", "index.html"  } }, 
};

const int 					gPresetsCount = sizeof( gPresets ) / sizeof( gPresets[ 0 ] );

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	main
//===========================================================================================================================

int main( int argc, char* argv[] )
{	
	DNSStatus		err;
	
	// Set up DNS Services and install a Console Control Handler to handle things like control-c signals.
	
	err = DNSServicesInitialize( kDNSFlagAdvertise, 0 );
	require_noerr_string( err, exit, "could not initialize Rendezvous" );

#if( __MACH__ )
	signal( SIGINT, SigIntHandler );
#endif

#if( defined( WINVER ) )
	SetConsoleCtrlHandler( ConsoleControlHandler, TRUE );
#endif

	ProcessArgs( argc, argv );
		
exit:
	DNSServicesFinalize();
	return( err );
}

//===========================================================================================================================
//	Usage
//===========================================================================================================================

static void	Usage( void )
{
	fprintf( stderr, "\n" );
	fprintf( stderr, "rendezvous - Rendezvous Tool 1.0d1\n" );
	fprintf( stderr, "\n" );
	fprintf( stderr, "  -bbd                                                    'b'rowse for 'b'rowsing 'd'omains\n" );
	fprintf( stderr, "  -brd                                                    'b'rowse for 'r'egistration 'd'omains\n" );
	fprintf( stderr, "  -bs <type> <domain>                                     'b'rowse for 's'ervices\n" );
	fprintf( stderr, "  -lsi <name> <type> <domain>                             'l'ookup 's'ervice 'i'nstance\n" );
	fprintf( stderr, "  -rdb[d] <domain>                                        'r'egister 'd'omain for 'b'rowsing ['d'efault]\n" );
	fprintf( stderr, "  -rdr[d] <domain>                                        'r'egister 'd'omain for 'r'egistration ['d'efault]\n" );
	fprintf( stderr, "  -rs <name> <type> <domain> <port> <txt>                 'r'egister 's'ervice\n" );
	fprintf( stderr, "  -rps <host> <ip> <name> <type> <domain> <port> <txt>    'r'egister 'p'roxy 's'ervice\n" );
	fprintf( stderr, "  -rnss <name> <type> <domain>                            'r'egister 'n'o 's'uch 's'ervice\n" );
	
	fprintf( stderr, "  -ebs <type> <domain>                                    'e'mulated 'b'rowse for 's'ervices\n" );
	fprintf( stderr, "  -ebd <registration/browse>                              'e'mulated 'b'rowse for 'd'omains\n" );
	fprintf( stderr, "  -elsi <name> <type> <domain>                            'e'mulated 'l'ookup 's'ervice 'i'nstance\n" );
	fprintf( stderr, "  -ers <name> <type> <domain> <port> <txt>                'e'mulated 'r'egister 's'ervice\n" );
	
	fprintf( stderr, "  -h[elp]                                                 'h'elp\n" );
	fprintf( stderr, "\n" );
	
	fprintf( stderr, "  -1 Preset 1 (browse for browsing domains)    rendezvous -bbd\n" );
	fprintf( stderr, "  -2 Preset 2 (browse for AirPort)             rendezvous -bs \"_airport._tcp\" \"local.\"\n" );
	fprintf( stderr, "  -3 Preset 3 (browse for Xserve RAID)         rendezvous -bs \"_xserveraid._tcp\" \"local.\"\n" );
	fprintf( stderr, "  -4 Preset 4 (register apple.com domain)      rendezvous -rdb \"apple.com\"\n" );
	fprintf( stderr, "  -5 Preset 5 (register fake AirPort)          rendezvous -rs \"My Fake AirPort\" \"_airport._tcp\" \"local.\" 1234 \"My Fake Info\"\n" );
	fprintf( stderr, "  -6 Preset 6 (register fake Xserve RAID)      rendezvous -rs \"My Fake Xserve RAID\" \"_xserveraid._tcp\" \"local.\" 1234 \"My Fake Info\"\n" );	
	fprintf( stderr, "  -7 Preset 7 (register fake web server)       rendezvous -rs \"My Fake Web Server\" \"_http._tcp\" \"local.\" 8080 \"index.html\"\n" );
	fprintf( stderr, "\n" );
}

//===========================================================================================================================
//	ProcessArgs
//===========================================================================================================================

static int ProcessArgs( int argc, char* argv[] )
{	
	DNSStatus						err;
	int								i;
	const char *					name;
	const char *					type;
	const char *					domain;
	int								port;
	const char *					text;
	size_t							textSize;
	DNSBrowserRef					browser;
	DNSResolverFlags				resolverFlags;
	DNSDomainRegistrationType		domainType;
	const char *					label;
	const char *					host;
	const char *					ip;
	unsigned int					b[ 4 ];
	DNSNetworkAddress				addr;
	dns_service_discovery_ref		emulatedRef;
	
	// Parse the command line arguments (ignore first argument since it's just the program name).
	
	require_action_string( argc >= 2, exit, err = kDNSBadParamErr, "no arguments specified" );
	
	for( i = 1; i < argc; ++i )
	{
		if( strcmp( argv[ i ], "-bbd" ) == 0 )
		{
			// 'b'rowse for 'b'rowsing 'd'omains
			
			fprintf( stdout, "browsing for browsing domains\n" );
			
			err = DNSBrowserCreate( 0, BrowserCallBack, NULL, &browser );
			require_noerr_string( err, exit, "create browser failed" );
			
			err = DNSBrowserStartDomainSearch( browser, 0 );
			require_noerr_string( err, exit, "start domain search failed" );
		}
		else if( strcmp( argv[ i ], "-brd" ) == 0 )
		{
			// 'b'rowse for 'r'egistration 'd'omains
			
			fprintf( stdout, "browsing for registration domains\n" );
			
			err = DNSBrowserCreate( 0, BrowserCallBack, NULL, &browser );
			require_noerr_string( err, exit, "create browser failed" );
			
			err = DNSBrowserStartDomainSearch( browser, kDNSBrowserFlagRegistrationDomainsOnly );
			require_noerr_string( err, exit, "start domain search failed" );
		}
		else if( strcmp( argv[ i ], "-bs" ) == 0 )
		{
			// 'b'rowse for 's'ervices <type> <domain>
						
			require_action_string( argc > ( i + 2 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			type 	= argv[ i++ ];
			domain 	= argv[ i ];
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "browsing for \"%s.%s\"\n", type, domain );
			
			err = DNSBrowserCreate( 0, BrowserCallBack, NULL, &browser );
			require_noerr_string( err, exit, "create browser failed" );
			
			err = DNSBrowserStartServiceSearch( browser, kDNSBrowserFlagAutoResolve, type, domain );
			require_noerr_string( err, exit, "start service search failed" );
		}
		else if( strcmp( argv[ i ], "-lsi" ) == 0 )
		{
			// 'l'ookup 's'ervice 'i'nstance <name> <type> <domain>
			
			require_action_string( argc > ( i + 3 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			name 	= argv[ i++ ];
			type 	= argv[ i++ ];
			domain 	= argv[ i ];
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "resolving \"%s.%s.%s\"\n", name, type, domain );
			
			resolverFlags = kDNSResolverFlagOnlyIfUnique | 
							kDNSResolverFlagAutoReleaseByName;
			err = DNSResolverCreate( resolverFlags, name, type, domain, ResolverCallBack, 0, NULL, NULL );
			require_noerr_string( err, exit, "create resolver failed" );
		}
		else if( ( strcmp( argv[ i ], "-rdb" ) == 0 ) || ( strcmp( argv[ i ], "-rdbd" ) == 0 ) )
		{
			// 'r'egister 'd'omain for 'b'rowsing ['d'efault] <domain>
						
			require_action_string( argc > ( i + 1 ), exit, err = kDNSBadParamErr, "missing arguments" );
			if( strcmp( argv[ i ], "-rdb" ) == 0 )
			{
				domainType = kDNSDomainRegistrationTypeBrowse;
				label = "";
			}
			else
			{
				domainType = kDNSDomainRegistrationTypeBrowseDefault;
				label = "default ";
			}
			++i;
			domain = argv[ i ];
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "registering \"%s\" as %sbrowse domain\n", domain, label );
			
			err = DNSDomainRegistrationCreate( 0, domain, domainType, NULL );
			require_noerr_string( err, exit, "create domain registration failed" );
		}
		else if( ( strcmp( argv[ i ], "-rdr" ) == 0 ) || ( strcmp( argv[ i ], "-rdrd" ) == 0 ) )
		{
			// 'r'egister 'd'omain for 'r'egistration ['d'efault] <domain>
			
			require_action_string( argc > ( i + 1 ), exit, err = kDNSBadParamErr, "missing arguments" );
			if( strcmp( argv[ i ], "-rdr" ) == 0 )
			{
				domainType = kDNSDomainRegistrationTypeRegistration;
				label = "";
			}
			else
			{
				domainType = kDNSDomainRegistrationTypeRegistrationDefault;
				label = "default ";
			}
			++i;
			domain = argv[ i ];
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "registering \"%s\" as %sregistration domain\n", domain, label );
			
			err = DNSDomainRegistrationCreate( 0, domain, domainType, NULL );
			require_noerr_string( err, exit, "create domain registration failed" );
		}
		else if( strcmp( argv[ i ], "-rs" ) == 0 )
		{
			// 'r'egister 's'ervice <name> <type> <domain> <port> <txt>
						
			require_action_string( argc > ( i + 5 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			name 		= argv[ i++ ];
			type 		= argv[ i++ ];
			domain	 	= argv[ i++ ];
			port 		= atoi( argv[ i++ ] );
			text 		= argv[ i ];
			textSize	= strlen( text );
			if( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "registering service \"%s.%s.%s\" port %d text \"%s\"\n", name, type, domain, port, text );
			
			err = DNSRegistrationCreate( 0, name, type, domain, (DNSPort) port, text, (DNSCount) textSize, NULL, NULL, 
										 RegistrationCallBack, NULL, NULL );
			require_noerr_string( err, exit, "create registration failed" );
		}
		else if( strcmp( argv[ i ], "-rps" ) == 0 )
		{
			DNSHostRegistrationFlags		hostFlags;
			
			// 'r'egister 'p'roxy 's'ervice <name> <type> <domain> <port> <txt>
						
			require_action_string( argc > ( i + 7 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			host		= argv[ i++ ];
			ip			= argv[ i++ ];
			name 		= argv[ i++ ];
			type 		= argv[ i++ ];
			domain	 	= argv[ i++ ];
			port 		= atoi( argv[ i++ ] );
			text 		= argv[ i ];
			textSize	= strlen( text );
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			
			sscanf( ip, "%u.%u.%u.%u", &b[ 0 ], &b[ 1 ], &b[ 2 ], &b[ 3 ] );
			addr.addressType 		= kDNSNetworkAddressTypeIPv4;
			addr.u.ipv4.addr.v32 	= (DNSUInt32)( ( b[ 0 ] << 24 ) | ( b[ 1 ] << 16 ) | ( b[ 2 ] <<  8 ) | ( b[ 3 ] <<  0 ) );
			
			fprintf( stdout, "registering proxy service \"%s.%s.%s\" port %d text \"%s\"\n", name, type, domain, port, text );
			
			hostFlags = kDNSHostRegistrationFlagOnlyIfNotFound | kDNSHostRegistrationFlagAutoRenameOnConflict;
			err = DNSHostRegistrationCreate( hostFlags, host, domain, &addr, NULL, 
											 HostRegistrationCallBack, NULL, NULL );
			require_noerr_string( err, exit, "create host registration failed" );
			
			err = DNSRegistrationCreate( 0, name, type, domain, (DNSPort) port, text, (DNSCount) textSize, host, NULL, 
										 RegistrationCallBack, NULL, NULL );
			require_noerr_string( err, exit, "create registration failed" );			
		}
		else if( strcmp( argv[ i ], "-rnss" ) == 0 )
		{
			// 'r'egister 'n'o 's'uch 's'ervice <name> <type> <domain>
						
			require_action_string( argc > ( i + 3 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			name 		= argv[ i++ ];
			type 		= argv[ i++ ];
			domain	 	= argv[ i++ ];
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "registering no-such-service \"%s.%s.%s\"\n", name, type, domain );
			
			err = DNSNoSuchServiceRegistrationCreate( 0, name, type, domain, NULL, RegistrationCallBack, NULL, NULL );
			require_noerr_string( err, exit, "create no-such-service registration failed" );
		}
		else if( strcmp( argv[ i ], "-ebs" ) == 0 )
		{
			// 'e'mulated 'b'rowse for 's'ervices <type> <domain>
						
			require_action_string( argc > ( i + 2 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			type 	= argv[ i++ ];
			domain 	= argv[ i ];
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "emulated browsing for \"%s.%s\"\n", type, domain );
			
			emulatedRef = DNSServiceBrowserCreate( type, domain, EmulatedBrowserCallBack, NULL );
			require_action_string( emulatedRef, exit, err = kDNSUnknownErr, "create emulated browser failed" );
		}
		else if( strcmp( argv[ i ], "-ebd" ) == 0 )
		{
			int		registrationOnly;
			
			// 'e'mulated 'b'rowse for 'd'omains <registration/browse>
			
			require_action_string( argc > ( i + 1 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			type = argv[ i++ ];
			if( strcmp( type, "registration" ) == 0 )
			{
				registrationOnly = 1;
			}
			else if( strcmp( type, "browse" ) == 0 )
			{
				registrationOnly = 0;
			}
			else
			{
				require_action_string( 0, exit, err = kDNSBadParamErr, "invalid browse type" );
			}
			fprintf( stdout, "emulated browsing for %s domains\n", type );
			
			emulatedRef = DNSServiceDomainEnumerationCreate( registrationOnly, EmulatedDomainEnumerationCallBack, NULL );
			require_action_string( emulatedRef, exit, err = kDNSUnknownErr, "create emulated domain browser failed" );
		}
		else if( strcmp( argv[ i ], "-elsi" ) == 0 )
		{
			// 'e'mulated 'l'ookup 's'ervice 'i'nstance <name> <type> <domain>
			
			require_action_string( argc > ( i + 3 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			name 	= argv[ i++ ];
			type 	= argv[ i++ ];
			domain 	= argv[ i ];
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "emulated resolving \"%s.%s.%s\"\n", name, type, domain );
			
			emulatedRef = DNSServiceResolverResolve( name, type, domain, EmulatedResolverCallBack, NULL );
			require_action_string( emulatedRef, exit, err = kDNSUnknownErr, "create emulated resolver failed" );
		}
		else if( strcmp( argv[ i ], "-ers" ) == 0 )
		{
			// 'e'mulated 'r'egister 's'ervice <name> <type> <domain> <port> <txt>
						
			require_action_string( argc > ( i + 5 ), exit, err = kDNSBadParamErr, "missing arguments" );
			++i;
			name 		= argv[ i++ ];
			type 		= argv[ i++ ];
			domain	 	= argv[ i++ ];
			port 		= atoi( argv[ i++ ] );
			text 		= argv[ i ];
			textSize	= strlen( text );
			if( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) )
			{
				domain = "local.";
			}
			fprintf( stdout, "registering service \"%s.%s.%s\" port %d text \"%s\"\n", name, type, domain, port, text );
			
			emulatedRef = DNSServiceRegistrationCreate( name, type, domain, (uint16_t) port, text, 
														EmulatedRegistrationCallBack, NULL );
			require_action_string( emulatedRef, exit, err = kDNSUnknownErr, "create emulated registration failed" );
		}
		else if( ( argv[ i ][ 0 ] == '-' ) && isdigit( argv[ i ][ 1 ] ) )
		{
			// Preset
			
			ProcessPreset( atoi( &argv[ i ][ 1 ] ) );
			err = 0;
			goto exit;
		}
		else if( strcmp( argv[ i ], "-q" ) == 0 )
		{
			// Quiet (no text records)
			
			gPrintTXTRecords = 0;
		}
		else if( ( strcmp( argv[ i ], "-help" ) == 0 ) || ( strcmp( argv[ i ], "-h" ) == 0 ) )
		{
			// Help
			
			Usage();
			err = 0;
			goto exit;
		}
		else
		{
			// Unknown parameter.
			
			require_action_string( 0, exit, err = kDNSBadParamErr, "unknown parameter" );
			goto exit;
		}
	}
	
	// Run until control-C'd.
	
	#if( __MACH__ )
		CFRunLoopRun();
	#endif
	
	#if( defined( WINVER ) )
		while( !gQuit )
		{
			Sleep( 200 );
		}
	#endif
	
	err = kDNSNoErr;
	
exit:
	if( err )
	{
		Usage();
	}
	return( err );
}

//===========================================================================================================================
//	ProcessPreset
//===========================================================================================================================

static DNSStatus	ProcessPreset( int inPreset )
{
	DNSStatus		err;
	
	require_action_string( ( inPreset > 0 ) && ( inPreset <= gPresetsCount ), exit, err = kDNSBadParamErr, "invalid preset" );
	
	err = ProcessArgs( gPresets[ inPreset - 1 ].argc, (char **) gPresets[ inPreset - 1 ].argv );
	
exit:
	return( err );
}

#if( __MACH__ )
//===========================================================================================================================
//	SigIntHandler
//===========================================================================================================================

static void	SigIntHandler( int inSignalNumber )
{
	DNS_UNUSED( inSignalNumber );
	
	signal( SIGINT, SIG_DFL );
	CFRunLoopStop( CFRunLoopGetCurrent() );
}
#endif

#if( defined( WINVER ) )
//===========================================================================================================================
//	ConsoleControlHandler
//===========================================================================================================================

static BOOL WINAPI	ConsoleControlHandler( DWORD inControlEvent )
{
	BOOL		handled;
	
	handled = 0;
	switch( inControlEvent )
	{
		case CTRL_C_EVENT:
		case CTRL_BREAK_EVENT:
		case CTRL_CLOSE_EVENT:
		case CTRL_LOGOFF_EVENT:
		case CTRL_SHUTDOWN_EVENT:
			gQuit = 1;
			handled = 1;
			break;
		
		default:
			break;
	}
	return( handled );
}
#endif

//===========================================================================================================================
//	BrowserCallBack
//===========================================================================================================================

static void BrowserCallBack( void *inContext, DNSBrowserRef inRef, DNSStatus inStatusCode, const DNSBrowserEvent *inEvent )
{
	char		ifIP[ 32 ];
	char		ip[ 32 ];

	DNS_UNUSED( inContext );
	DNS_UNUSED( inRef );
	DNS_UNUSED( inStatusCode );
	
	switch( inEvent->type )
	{
		case kDNSBrowserEventTypeRelease:
			break;
			
		case kDNSBrowserEventTypeAddDomain:			
			fprintf( stdout, "domain         \"%s\" added on interface 0x%08X (%s)\n", 
					 inEvent->data.addDomain.domain, 
					 (int) inEvent->data.addDomain.interfaceID, 
					 IPv4ToString( inEvent->data.addDomain.interfaceIP.u.ipv4.addr, ifIP ) );
			break;
		
		case kDNSBrowserEventTypeAddDefaultDomain:
			fprintf( stdout, "default domain \"%s\" added on interface 0x%08X (%s)\n", 
					 inEvent->data.addDefaultDomain.domain, 
					 (int) inEvent->data.addDefaultDomain.interfaceID, 
					 IPv4ToString( inEvent->data.addDefaultDomain.interfaceIP.u.ipv4.addr, ifIP ) );
			break;
		
		case kDNSBrowserEventTypeRemoveDomain:
			fprintf( stdout, "domain         \"%s\" removed on interface 0x%08X (%s)\n", 
					 inEvent->data.removeDomain.domain, 
					 (int) inEvent->data.removeDomain.interfaceID, 
					 IPv4ToString( inEvent->data.removeDomain.interfaceIP.u.ipv4.addr, ifIP ) );
			break;
		
		case kDNSBrowserEventTypeAddService:
			fprintf( stdout, "service        \"%s.%s%s\" added on interface 0x%08X (%s)\n", 
					 inEvent->data.addService.name, 
					 inEvent->data.addService.type, 
					 inEvent->data.addService.domain, 
					 (int) inEvent->data.addService.interfaceID, 
					 IPv4ToString( inEvent->data.addService.interfaceIP.u.ipv4.addr, ifIP ) );
			break;
		
		case kDNSBrowserEventTypeRemoveService:
			fprintf( stdout, "service        \"%s.%s%s\" removed on interface 0x%08X (%s)\n", 
					 inEvent->data.removeService.name, 
					 inEvent->data.removeService.type, 
					 inEvent->data.removeService.domain, 
					 (int) inEvent->data.removeService.interfaceID, 
					 IPv4ToString( inEvent->data.removeService.interfaceIP.u.ipv4.addr, ifIP ) );
			break;
		
		case kDNSBrowserEventTypeResolved:
		{
			const uint8_t *		p;
			const uint8_t *		end;
			int					i;
			
			fprintf( stdout, "resolved       \"%s.%s%s\" to %s:%u on interface 0x%08X (%s)%s\n", 
					 inEvent->data.resolved->name, 
					 inEvent->data.resolved->type, 
					 inEvent->data.resolved->domain, 
					 IPv4ToString( inEvent->data.resolved->address.u.ipv4.addr, ip ), 
					 ( inEvent->data.resolved->address.u.ipv4.port.v8[ 0 ] << 8 ) | 
					   inEvent->data.resolved->address.u.ipv4.port.v8[ 1 ], 
					 (int) inEvent->data.resolved->interfaceID, 
					 IPv4ToString( inEvent->data.resolved->interfaceIP.u.ipv4.addr, ifIP ), 
					 ( inEvent->data.resolved->textRecordRawSize > 0 ) ? " with text:" : "" );
			
			p 	= (const uint8_t *) inEvent->data.resolved->textRecordRaw;
			end = p + inEvent->data.resolved->textRecordRawSize;
			i 	= 0;
			
			if( gPrintTXTRecords )
			{
				while( p < end )
				{
					uint8_t		size;
						
					size = *p++;
					if( ( p + size ) > end )
					{
						fprintf( stdout, "\n### MALFORMED TXT RECORD (length byte too big for record)\n\n" );
						break;
					}
					fprintf( stdout, "%5d (%3d bytes): \"%.*s\"\n", i, size, size, p );
					p += size;
					++i;
				}
				fprintf( stdout, "\n" );
			}
			break;
		}
		
		default:
			break;
	}
}

//===========================================================================================================================
//	ResolverCallBack
//===========================================================================================================================

static void ResolverCallBack( void *inContext, DNSResolverRef inRef, DNSStatus inStatusCode, const DNSResolverEvent *inEvent )
{
	char		ifIP[ 32 ];
	char		ip[ 32 ];

	DNS_UNUSED( inContext );
	DNS_UNUSED( inRef );
	DNS_UNUSED( inStatusCode );

	switch( inEvent->type )
	{
		case kDNSResolverEventTypeResolved:
		{
			const uint8_t *		p;
			const uint8_t *		end;
			int					i;
			
			fprintf( stdout, "resolved       \"%s.%s%s\" to %s:%u on interface 0x%08X (%s)%s\n", 
					 inEvent->data.resolved.name, 
					 inEvent->data.resolved.type, 
					 inEvent->data.resolved.domain, 
					 IPv4ToString( inEvent->data.resolved.address.u.ipv4.addr, ip ), 
					 ( inEvent->data.resolved.address.u.ipv4.port.v8[ 0 ] << 8 ) | 
					   inEvent->data.resolved.address.u.ipv4.port.v8[ 1 ], 
					 (int) inEvent->data.resolved.interfaceID, 
					 IPv4ToString( inEvent->data.resolved.interfaceIP.u.ipv4.addr, ifIP ), 
					 ( inEvent->data.resolved.textRecordRawSize > 0 ) ? " with text:" : "" );
			
			p 	= (const uint8_t *) inEvent->data.resolved.textRecordRaw;
			end = p + inEvent->data.resolved.textRecordRawSize;
			i 	= 0;
			
			if( gPrintTXTRecords )
			{
				while( p < end )
				{
					uint8_t		size;
					
					size = *p++;
					if( ( p + size ) > end )
					{
						fprintf( stdout, "\n### MALFORMED TXT RECORD (length byte too big for record)\n\n" );
						break;
					}
					fprintf( stdout, "%5d (%3d bytes): \"%.*s\"\n", i, size, size, p );
					p += size;
					++i;
				}
				fprintf( stdout, "\n" );
			}
			break;
		}

		case kDNSResolverEventTypeRelease:
			break;
		
		default:
			break;
	}
}

//===========================================================================================================================
//	RegistrationCallBack
//===========================================================================================================================

static void
	RegistrationCallBack( 
		void *							inContext, 
		DNSRegistrationRef				inRef, 
		DNSStatus						inStatusCode, 
		const DNSRegistrationEvent *	inEvent )
{
	DNS_UNUSED( inContext );
	DNS_UNUSED( inRef );
	DNS_UNUSED( inStatusCode );
	
	switch( inEvent->type )
	{
		case kDNSRegistrationEventTypeRelease:	
			break;
		
		case kDNSRegistrationEventTypeRegistered:
			fprintf( stdout, "name registered and active\n" );
			break;

		case kDNSRegistrationEventTypeNameCollision:
			fprintf( stdout, "name in use, please choose another name\n" );
			break;
		
		default:
			break;
	}
}

//===========================================================================================================================
//	HostRegistrationCallBack
//===========================================================================================================================

static void
	HostRegistrationCallBack( 
		void *					inContext, 
		DNSHostRegistrationRef 	inRef, 
		DNSStatus 				inStatusCode, 
		void *					inData )
{
	DNS_UNUSED( inContext );
	DNS_UNUSED( inRef );
	DNS_UNUSED( inData );
	
	if( inStatusCode == kDNSNoErr )
	{
		fprintf( stdout, "host name registered and active\n" );
	}
	else if( inStatusCode == kDNSNameConflictErr )
	{
		fprintf( stdout, "host name in use, please choose another name\n" );
	}
	else
	{
		fprintf( stdout, "unknown host registration status (%ld)\n", inStatusCode );
	}
}

//===========================================================================================================================
//	EmulatedBrowserCallBack
//===========================================================================================================================

static void
	EmulatedBrowserCallBack(
		DNSServiceBrowserReplyResultType	inResult, 
		const char *						inName,
		const char *						inType,
		const char *						inDomain,
		DNSServiceDiscoveryReplyFlags		inFlags,
		void *								inContext )
{
	DNS_UNUSED( inFlags );
	DNS_UNUSED( inContext );
	
	if( inResult == DNSServiceBrowserReplyAddInstance )
	{
		fprintf( stdout, "\"%s.%s%s\" service added emulated\n", inName, inType, inDomain );
	}
	else if( inResult == DNSServiceBrowserReplyRemoveInstance )
	{
		fprintf( stdout, "\"%s.%s%s\" service removed emulated\n", inName, inType, inDomain );
	}
	else
	{
		fprintf( stdout, "### unknown emulated browser callback result (%d)\n", inResult );
	}
}

//===========================================================================================================================
//	EmulatedDomainEnumerationCallBack
//===========================================================================================================================

static void
	EmulatedDomainEnumerationCallBack(
		DNSServiceDomainEnumerationReplyResultType	inResult, 
		const char *								inDomain,
		DNSServiceDiscoveryReplyFlags				inFlags,
		void *										inContext )
{
	DNS_UNUSED( inFlags );
	DNS_UNUSED( inContext );
	
	if( inResult == DNSServiceDomainEnumerationReplyAddDomain )
	{
		fprintf( stdout, "\"%s\" domain added emulated\n", inDomain );
	}
	else if( inResult == DNSServiceDomainEnumerationReplyAddDomainDefault )
	{
		fprintf( stdout, "\"%s\" default domain added emulated\n", inDomain );
	}
	else if( inResult == DNSServiceDomainEnumerationReplyRemoveDomain )
	{
		fprintf( stdout, "\"%s\" domain removed emulated\n", inDomain );
	}
	else
	{
		fprintf( stdout, "### unknown emulated domain enumeration callback result (%d)\n", inResult );
	}
}

//===========================================================================================================================
//	EmulatedResolverCallBack
//===========================================================================================================================

static void
	EmulatedResolverCallBack(
		struct sockaddr *				inInterfaceAddr, 
		struct sockaddr *				inAddr,
		const char *					inTextRecord,
		DNSServiceDiscoveryReplyFlags	inFlags, 
		void *							inContext )
{
	struct sockaddr_in *		ifSin4;
	struct sockaddr_in *		sin4;
	char						ifIP[ 64 ];
	char						ip[ 64 ];
	
	DNS_UNUSED( inFlags );
	DNS_UNUSED( inContext );
	
	ifSin4 	= (struct sockaddr_in *) inInterfaceAddr;
	sin4 	= (struct sockaddr_in *) inAddr;

	fprintf( stdout, "service resolved to %s:%d on interface %s with text \"%s\"\n", 
			 IPv4ToString( *( (DNSOpaque32 *) &sin4->sin_addr.s_addr ), ip ), 
			 ntohs( sin4->sin_port ), 
			 IPv4ToString( *( (DNSOpaque32 *) &ifSin4->sin_addr.s_addr ), ifIP ), 
			 inTextRecord ? inTextRecord : "" );
}

//===========================================================================================================================
//	EmulatedResolverCallBack
//===========================================================================================================================

static void	EmulatedRegistrationCallBack( DNSServiceRegistrationReplyErrorType inResult, void *inContext )
{
	DNS_UNUSED( inContext );
	
	if( inResult == kDNSServiceDiscoveryNoError )
	{
		fprintf( stdout, "service name registered successfully\n" );
	}
	else
	{
		fprintf( stdout, "service registration failed( %d)\n", inResult );
	}
}

//===========================================================================================================================
//	IPv4ToString
//===========================================================================================================================

static char *	IPv4ToString( DNSOpaque32 inIP, char *outString )
{
	sprintf( outString, "%u.%u.%u.%u", inIP.v8[ 0 ], inIP.v8[ 1 ], inIP.v8[ 2 ], inIP.v8[ 3 ] );
	return( outString );
}
