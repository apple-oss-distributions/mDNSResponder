/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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
	
$Log: Tool.c,v $
Revision 1.2  2004/07/13 21:24:28  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.1  2004/06/18 04:17:43  rpantos
Move up one level.

Revision 1.3  2004/04/09 21:03:15  bradley
Changed port numbers to use network byte order for consistency with other platforms.

Revision 1.2  2004/04/08 09:43:43  bradley
Changed callback calling conventions to __stdcall so they can be used with C# delegates.

Revision 1.1  2004/01/30 02:58:57  bradley
Test tool for the mDNSResponder Windows service.

*/

#include	<stdio.h>
#include	<stdlib.h>

#include	"CommonServices.h"
#include	"DebugServices.h"
#include	"DNSSD.h"

//===========================================================================================================================
//	Structures
//===========================================================================================================================

#define MAX_DOMAIN_LABEL 63
#define MAX_DOMAIN_NAME 255

typedef union { unsigned char b[2]; unsigned short NotAnInteger; } Opaque16;

typedef struct { u_char c[ 64]; } domainlabel;
typedef struct { u_char c[256]; } domainname;

typedef struct 
    { 
    uint16_t priority; 
    uint16_t weight; 
    uint16_t port; 
    domainname target;
    } srv_rdata;

//===========================================================================================================================
//	Prototypes
//===========================================================================================================================

int 				main( int argc, char* argv[] );
static void			Usage( void );
static int 			ProcessArgs( int argc, char* argv[] );

#if( defined( WINVER ) )
	static BOOL WINAPI	ConsoleControlHandler( DWORD inControlEvent );
#endif

static void CALLBACK_COMPAT
	EnumerateDomainsCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inDomain,  
		void *				inContext );

static void CALLBACK_COMPAT
	BrowseCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inName,  
		const char *		inType,  
		const char *		inDomain,  
		void *				inContext );

static void CALLBACK_COMPAT
	ResolveCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inFullName,  
		const char *		inHostName,  
		uint16_t			inPort, 
		uint16_t			inTXTSize, 
		const char *		inTXT, 
		void *				inContext );

static void CALLBACK_COMPAT
	RegisterCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		DNSServiceErrorType	inErrorCode,
		const char *		inName,  
		const char *		inType,  
		const char *		inDomain,  
		void *				inContext );

static void CALLBACK_COMPAT
	RecordCallBack( 
		DNSServiceRef 			inRef, 
		DNSRecordRef 			inRecordRef, 
		DNSServiceFlags 		inFlags, 
		DNSServiceErrorType 	inErrorCode, 
		void *					inContext );

static void CALLBACK_COMPAT
	QueryCallBack( 
		const DNSServiceRef 		inRef, 
		const DNSServiceFlags		inFlags, 
		const uint32_t				inInterfaceIndex, 
		const DNSServiceErrorType	inErrorCode, 
		const char *				inName, 
		const uint16_t				inRRType, 
		const uint16_t				inRRClass, 
		const uint16_t				inRDataSize, 
		const void *				inRData, 
		const uint32_t				inTTL, 
		void *						inContext );

static void	PrintRData( uint16_t inRRType, size_t inRDataSize, const uint8_t *inRData );

static char *ConvertDomainLabelToCString_withescape(const domainlabel *const label, char *ptr, char esc);
static char *ConvertDomainNameToCString_withescape(const domainname *const name, char *ptr, char esc);

//===========================================================================================================================
//	Globals
//===========================================================================================================================

#if( defined( WINVER ) )
	static volatile int		gQuit = 0;
#endif

//===========================================================================================================================
//	main
//===========================================================================================================================

int main( int argc, char *argv[] )
{
	OSStatus		err;
	
	debug_initialize( kDebugOutputTypeMetaConsole );
	debug_set_property( kDebugPropertyTagPrintLevel, kDebugLevelTrace );

	SetConsoleCtrlHandler( ConsoleControlHandler, TRUE );
	err = ProcessArgs( argc, argv );
	return( (int) err );
}

//===========================================================================================================================
//	Usage
//===========================================================================================================================

static void	Usage( void )
{
	fprintf( stderr, "\n" );
	fprintf( stderr, "DNSServiceTest 1.0d1\n" );
	fprintf( stderr, "\n" );
	fprintf( stderr, "  -server <IP>                                      Set Remote Server\n" );
	fprintf( stderr, "  -cv                                               Check Version\n" );
	fprintf( stderr, "  -bd                                               Browse for Browse Domains\n" );
	fprintf( stderr, "  -bs <type> <domain>                               Browse for Services\n" );
	fprintf( stderr, "  -rsi <name> <type> <domain>                       Resolve Service Instance\n" );
	fprintf( stderr, "  -rs <name> <type> <domain> <host> <port> <txt>    Register Service\n" );
	fprintf( stderr, "  -rr                                               Register Records\n" );
	fprintf( stderr, "  -qr <name> <type> <domain> <rrType>               Query Record\n" );
	fprintf( stderr, "  -cr <name> <type> <domain> <rrType>               Reconfirm Record\n" );
	fprintf( stderr, "  -cp <code>                                        Copy Property\n" );
	fprintf( stderr, "  -h[elp]                                           Help\n" );
	fprintf( stderr, "\n" );
}

DEBUG_LOCAL DNSServiceRef		gRef 		= NULL;
DEBUG_LOCAL DNSRecordRef		gRecordRef	= NULL;
DEBUG_LOCAL const char *		gServer		= NULL;

//===========================================================================================================================
//	ProcessArgs
//===========================================================================================================================

static int ProcessArgs( int argc, char* argv[] )
{	
	OSStatus			err;
	int					i;
	const char *		name;
	const char *		type;
	const char *		domain;
	uint16_t			port;
	const char *		host;
	const char *		txt;
	uint16_t			txtSize;
	uint8_t				txtStorage[ 256 ];
	uint32_t			ipv4;
	char				s[ 256 ];
	DNSRecordRef		records[ 10 ];
	char				fullName[ kDNSServiceMaxDomainName ];
	uint16_t			rrType;
	
	err = DNSServiceInitialize( kDNSServiceInitializeFlagsNoServerCheck, 0 );
	require_noerr( err, exit );
	
	// Parse the command line arguments (ignore first argument since it's just the program name).
	
	if( argc <= 1 )
	{
		Usage();
		err = 0;
		goto exit;
	}
	for( i = 1; i < argc; ++i )
	{
		if( strcmp( argv[ i ], "-server" ) == 0 )
		{
			require_action( argc > ( i + 1 ), exit, err = kParamErr );
			gServer = argv[ ++i ];
			
			printf( "Server set to \"%s\"\n", gServer );
		}
		else if( strcmp( argv[ i ], "-cv" ) == 0 )
		{
			// Check Version
						
			err = DNSServiceCheckVersion();
			printf( "CheckVersion: %ld\n", err );
			err = kNoErr;
			goto exit;
		}
		else if( strcmp( argv[ i ], "-bd" ) == 0 )
		{
			err = DNSServiceEnumerateDomains( &gRef, kDNSServiceFlagsBrowseDomains, 0, 
				EnumerateDomainsCallBack, NULL );
			require_noerr( err, exit );
		}
		else if( strcmp( argv[ i ], "-bs" ) == 0 )
		{
			// Browse service <type> <domain>
						
			if( argc > ( i + 2 ) )
			{
				type 	= argv[ ++i ];
				domain 	= argv[ ++i ];
			}
			else
			{
				type	= "_http._tcp";
				domain	= "";
			}
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			
			err = DNSServiceBrowse( &gRef, 0, 0, type, domain, BrowseCallBack, NULL );
			require_noerr( err, exit );
		}
		else if( strcmp( argv[ i ], "-rsi" ) == 0 )
		{
			// Resolve Service Instance <name> <type> <domain>
						
			if( argc > ( i + 3 ) )
			{
				name 	= argv[ ++i ];
				type 	= argv[ ++i ];
				domain 	= argv[ ++i ];
			}
			else
			{
				name 	= "test service";
				type	= "_http._tcp";
				domain	= "";
			}
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			
			err = DNSServiceResolve( &gRef, 0, 0, name, type, domain, ResolveCallBack, NULL );
			require_noerr( err, exit );
		}
		else if( strcmp( argv[ i ], "-rs" ) == 0 )
		{
			// Register Service <name> <type> <domain> <host> <port> <txt>
			
			if( argc > ( i + 6 ) )
			{
				name 	= argv[ ++i ];
				type 	= argv[ ++i ];
				domain 	= argv[ ++i ];
				host 	= argv[ ++i ];
				port 	= (uint16_t) atoi( argv[ ++i ] );
				txt 	= argv[ ++i ];
			}
			else
			{
				name 	= "test service";
				type	= "_http._tcp";
				domain	= "";
				host	= "";
				port	= 80;
				txt		= "My TXT Record";
			}
			if( *txt != '\0' )
			{
				txtStorage[ 0 ] = (uint8_t) strlen( txt );
				memcpy( &txtStorage[ 1 ], txt, txtStorage[ 0 ] );
				txtSize = (uint16_t)( 1 + txtStorage[ 0 ] );
				txt = (const char *) txtStorage;
			}
			else
			{
				txt = NULL;
				txtSize = 0;
			}
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			
			err = DNSServiceRegister( &gRef, 0, 0, name, type, domain, host, htons( port ), txtSize, txt, 
				RegisterCallBack, NULL );
			require_noerr( err, exit );
			
			#if( TEST_SERVICE_RECORDS )
				ipv4 = 0x11223344;
				err = DNSServiceAddRecord( gRef, &gRecordRef, 0, kDNSServiceDNSType_A, kDNSServiceDNSClass_IN, &ipv4, 60 );
				require_noerr( err, exit );
				
				Sleep( 10000 );
				
				ipv4 = 0x22334455;
				err = DNSServiceUpdateRecord( gRef, gRecordRef, 0, 4, &ipv4, 60 );
				require_noerr( err, exit );
				
				Sleep( 10000 );
				
				err = DNSServiceRemoveRecord( gRef, gRecordRef, 0 );
				require_noerr( err, exit );
				gRecordRef = NULL;
				
				Sleep( 10000 );
			#endif
		}
		else if( strcmp( argv[ i ], "-rr" ) == 0 )
		{
			// Register Records
			
			err = DNSServiceCreateConnection( &gRef );
			require_noerr( err, exit );
						
			printf( "registering 10 address records...\n" );
			ipv4 = 0x11223310;
			for( i = 0; i < 10; ++i )
			{
				sprintf( s, "testhost-%d.local.", i );
				++ipv4;
				err = DNSServiceRegisterRecord( gRef, &records[ i ], kDNSServiceFlagsUnique, 0, s, 
					kDNSServiceDNSType_A, kDNSServiceDNSClass_IN, 4, &ipv4, 60, RecordCallBack, NULL );
				check_noerr( err );
			}
			Sleep( 10000 );
			
			printf( "deregistering half of the records\n" );
			for( i = 0; i < 10; ++i )
			{
				if( i % 2 )
				{
					err = DNSServiceRemoveRecord( gRef, records[ i ], 0 );
					check_noerr( err );
					records[ i ] = NULL;
				}
			}
			Sleep( 10000 );
			
			printf( "updating the remaining records\n" );
			for( i = 0; i < 10; ++i )
			{
				if( records[ i ] )
				{
					++ipv4;
					err = DNSServiceUpdateRecord( gRef, records[ i ], 0, 4, &ipv4, 60 );
					check_noerr( err );
				}
			}
			Sleep( 10000 );
			
			printf( "deregistering all remaining records\n" );
        	DNSServiceRefDeallocate( gRef );
        	
        	Sleep( 5000 );
		}
		else if( strcmp( argv[ i ], "-qr" ) == 0 )
		{
			// Query Record <name> <type> <domain> <rrType>
						
			if( argc > ( i + 4 ) )
			{
				name 	= argv[ ++i ];
				type 	= argv[ ++i ];
				domain 	= argv[ ++i ];
				rrType	= (uint16_t) atoi( argv[ ++i ] );
			}
			else
			{
				name 	= "test";
				type	= "";
				domain	= "";
				rrType	= 1;	// Address
			}
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			err = DNSServiceConstructFullName( fullName, name, type, domain );
			require_noerr( err, exit );
			
			printf( "resolving fullname %s type %d\n", fullName, rrType );
			err = DNSServiceQueryRecord( &gRef, 0, 0, fullName, rrType, kDNSServiceDNSClass_IN, QueryCallBack, NULL );
			require_noerr( err, exit );
		}
		else if( strcmp( argv[ i ], "-cr" ) == 0 )
		{
			// Reconfirm Record <name> <type> <domain> <rrType>
			
			if( argc > ( i + 4 ) )
			{
				name 	= argv[ ++i ];
				type 	= argv[ ++i ];
				domain 	= argv[ ++i ];
				rrType	= (uint16_t) atoi( argv[ ++i ] );
			}
			else
			{
				name 	= "test";
				type	= "";
				domain	= "";
				rrType	= 1;	// Address
			}
			if( ( domain[ 0 ] == '\0' ) || ( ( domain[ 0 ] == '.' ) && ( domain[ 1 ] == '\0' ) ) )
			{
				domain = "local.";
			}
			err = DNSServiceConstructFullName( fullName, name, type, domain );
			require_noerr( err, exit );
			
			printf( "reconfirming record fullname %s type %d\n", fullName, rrType );
			ipv4 = 0x11223310;
			DNSServiceReconfirmRecord( 0, 0, fullName, rrType, kDNSServiceDNSClass_IN, 4, &ipv4 );
		}
		else if( strcmp( argv[ i ], "-cp" ) == 0 )
		{
			DNSPropertyCode		code;
			DNSPropertyData		data;
			
			// Copy Property <code>
						
			if( argc > ( i + 1 ) )
			{
				name = argv[ ++i ];
				require_action( strlen( name ) == 4, exit, err = kParamErr );
				
				code  = (DNSPropertyCode)( name[ 0 ] << 24 );
				code |= (DNSPropertyCode)( name[ 1 ] << 16 );
				code |= (DNSPropertyCode)( name[ 2 ] <<  8 );
				code |= (DNSPropertyCode)  name[ 3 ];
			}
			else
			{
				code = kDNSPropertyCodeVersion;
				name = "vers";
			}
			
			err = DNSServiceCopyProperty( code, &data );
			require_noerr( err, exit );
			
			printf( "'%s' property:\n", name );
			if( code == kDNSPropertyCodeVersion )
			{
				printf( "    clientCurrentVersion:      0x%08X\n", data.u.version.clientCurrentVersion );
				printf( "    clientOldestServerVersion: 0x%08X\n", data.u.version.clientOldestServerVersion );
				printf( "    serverCurrentVersion:      0x%08X\n", data.u.version.serverCurrentVersion );
				printf( "    serverOldestClientVersion: 0x%08X\n", data.u.version.serverOldestClientVersion );
			}
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
			
			dlog( kDebugLevelError, "unknown parameter (%s)\n", argv[ i ] );
			err = kParamErr;
			goto exit;
		}
	}
	
	// Run until control-C'd.
	
	while( !gQuit )
	{
		Sleep( 100 );
	}
	err = kNoErr;
	
exit:
	DNSServiceFinalize();
	if( err )
	{
		Usage();
	}
	return( err );
}

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

//===========================================================================================================================
//	EnumerateDomainsCallBack
//===========================================================================================================================

static void CALLBACK_COMPAT
	EnumerateDomainsCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inDomain,  
		void *				inContext )
{
	printf( "inRef:            0x%08X\n", (uintptr_t) inRef );
	printf( "inFlags:          0x%08X\n", (int) inFlags );
	printf( "inInterfaceIndex: 0x%08X\n", (int) inInterfaceIndex );
	printf( "inErrorCode:      %ld\n", inErrorCode );
	printf( "inDomain:         \"%s\"\n", inDomain ? inDomain : "<null>" );
	printf( "inContext:        0x%08X\n", (uintptr_t) inContext );
	printf( "\n" );
}

//===========================================================================================================================
//	BrowseCallBack
//===========================================================================================================================

static void CALLBACK_COMPAT
	BrowseCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inName,  
		const char *		inType,  
		const char *		inDomain,  
		void *				inContext )
{
	printf( "inRef:            0x%08X\n", (uintptr_t) inRef );
	printf( "inFlags:          0x%08X\n", (int) inFlags );
	printf( "inInterfaceIndex: 0x%08X\n", (int) inInterfaceIndex );
	printf( "inErrorCode:      %ld\n", inErrorCode );
	printf( "inName:           \"%s\"\n", inName ? inName : "<null>" );
	printf( "inType:           \"%s\"\n", inType ? inType : "<null>" );
	printf( "inDomain:         \"%s\"\n", inDomain ? inDomain : "<null>" );
	printf( "inContext:        0x%08X\n", (uintptr_t) inContext );
	printf( "\n" );
}

//===========================================================================================================================
//	ResolveCallBack
//===========================================================================================================================

static void CALLBACK_COMPAT
	ResolveCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inErrorCode,
		const char *		inFullName,  
		const char *		inHostName,  
		uint16_t			inPort, 
		uint16_t			inTXTSize, 
		const char *		inTXT, 
		void *				inContext )
{
	printf( "inRef:            0x%08X\n", (uintptr_t) inRef );
	printf( "inFlags:          0x%08X\n", (int) inFlags );
	printf( "inInterfaceIndex: 0x%08X\n", (int) inInterfaceIndex );
	printf( "inErrorCode:      %ld\n", inErrorCode );
	printf( "inFullName:       \"%s\"\n", inFullName ? inFullName : "<null>" );
	printf( "inHostName:       \"%s\"\n", inHostName ? inHostName : "<null>" );
	printf( "inPort:           %d\n", ntohs( inPort ) );
	printf( "inTXTSize:        %ld\n", inTXTSize );
	printf( "inTXT:            0x%08X\n", (uintptr_t) inTXT );
	printf( "inContext:        0x%08X\n", (uintptr_t) inContext );
	printf( "\n" );
}

//===========================================================================================================================
//	RegisterCallBack
//===========================================================================================================================

static void CALLBACK_COMPAT
	RegisterCallBack(
		DNSServiceRef		inRef,
		DNSServiceFlags		inFlags,
		DNSServiceErrorType	inErrorCode,
		const char *		inName,  
		const char *		inType,  
		const char *		inDomain,  
		void *				inContext )
{
	printf( "inRef:            0x%08X\n", (uintptr_t) inRef );
	printf( "inFlags:          0x%08X\n", (int) inFlags );
	printf( "inErrorCode:      %ld\n", inErrorCode );
	printf( "inName:           \"%s\"\n", inName ? inName : "<null>" );
	printf( "inType:           \"%s\"\n", inType ? inType : "<null>" );
	printf( "inDomain:         \"%s\"\n", inDomain ? inDomain : "<null>" );
	printf( "inContext:        0x%08X\n", (uintptr_t) inContext );
	printf( "\n" );
}

//===========================================================================================================================
//	RecordCallBack
//===========================================================================================================================

static void CALLBACK_COMPAT
	RecordCallBack( 
		DNSServiceRef 			inRef, 
		DNSRecordRef 			inRecordRef, 
		DNSServiceFlags 		inFlags, 
		DNSServiceErrorType 	inErrorCode, 
		void *					inContext )
{
	DEBUG_UNUSED( inRef );
	DEBUG_UNUSED( inRecordRef );
	DEBUG_UNUSED( inFlags );
	DEBUG_UNUSED( inContext );
	
	if( inErrorCode == kDNSServiceErr_NoError )
	{
		printf( "RecordCallBack: no errors\n" );
	}
	else
	{
		printf( "RecordCallBack: %ld error\n", inErrorCode );
	}
}

//===========================================================================================================================
//	QueryCallBack
//===========================================================================================================================

static void CALLBACK_COMPAT
	QueryCallBack( 
		const DNSServiceRef 		inRef, 
		const DNSServiceFlags		inFlags, 
		const uint32_t				inInterfaceIndex, 
		const DNSServiceErrorType	inErrorCode, 
		const char *				inName, 
		const uint16_t				inRRType, 
		const uint16_t				inRRClass, 
		const uint16_t				inRDataSize, 
		const void *				inRData, 
		const uint32_t				inTTL, 
		void *						inContext )
{
	DEBUG_UNUSED( inRef );
	DEBUG_UNUSED( inRRClass );
	DEBUG_UNUSED( inTTL );
	DEBUG_UNUSED( inContext );
	
	if( inErrorCode == kDNSServiceErr_NoError )
	{
		if( inFlags & kDNSServiceFlagsAdd )
		{
			printf( "Add" );
		}
		else
		{
			printf( "Rmv" );
		}
		if( inFlags & kDNSServiceFlagsMoreComing )
		{
			printf( "+" );
		}
		else
		{
			printf( " " );
		}
		printf(" 0x%04X %d %s rdata ", inFlags, inInterfaceIndex, inName );
		PrintRData( inRRType, (size_t) inRDataSize, (const uint8_t *) inRData );
	}
	else
	{
		printf( "QueryCallback: %ld error\n", inErrorCode );
	}
}

//===========================================================================================================================
//	PrintRData
//===========================================================================================================================

static void	PrintRData( uint16_t inRRType, size_t inRDataSize, const uint8_t *inRData )
{
	size_t				i;
	srv_rdata *			srv;
	char				s[ 1005 ];
	struct in_addr		in;
	
	switch( inRRType )
	{
		case kDNSServiceDNSType_TXT:
			
			// Print all the alphanumeric and punctuation characters
			
			for( i = 0; i < inRDataSize; ++i )
			{
				if( ( inRData[ i ] >= 32 ) && ( inRData[ i ] <= 127 ) )
				{
					printf( "%c", inRData[ i ] );
				}
			}
			printf( "\n" );
			break;
			
		case kDNSServiceDNSType_SRV:
			srv = (srv_rdata *)inRData;
			ConvertDomainNameToCString_withescape(&srv->target, s, 0);
			printf("pri=%d, w=%d, port=%d, target=%s\n", srv->priority, srv->weight, srv->port, s);
			break;
			
		case kDNSServiceDNSType_A:
			check( inRDataSize == 4 );
			memcpy( &in, inRData, sizeof( in ) );
			printf( "%s\n", inet_ntoa( in ) );
			break;
			
		case kDNSServiceDNSType_PTR:
			ConvertDomainNameToCString_withescape( (domainname *) inRData, s, 0 );
			break;
		
		case kDNSServiceDNSType_AAAA:
			check( inRDataSize == 16 );
			printf( "%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X\n",
					inRData[0], inRData[1], inRData[2], inRData[3], inRData[4], inRData[5], inRData[6], inRData[7], inRData[8], 
					inRData[9], inRData[10], inRData[11], inRData[12], inRData[13], inRData[14], inRData[15] );
			break;
		
		default:
			printf( "ERROR: I dont know how to print inRData of type %d\n", inRRType );
			return;
	}
}

static char *ConvertDomainLabelToCString_withescape(const domainlabel *const label, char *ptr, char esc)
    {
    const unsigned char *      src = label->c;                         // Domain label we're reading
    const unsigned char        len = *src++;                           // Read length of this (non-null) label
    const unsigned char *const end = src + len;                        // Work out where the label ends
    if (len > 63) return(NULL);           // If illegal label, abort
    while (src < end)                                           // While we have characters in the label
        {
        unsigned char c = *src++;
        if (esc)
            {
            if (c == '.')                                       // If character is a dot,
                *ptr++ = esc;                                   // Output escape character
            else if (c <= ' ')                                  // If non-printing ascii,
                {                                                   // Output decimal escape sequence
                *ptr++ = esc;
                *ptr++ = (char)  ('0' + (c / 100)     );
                *ptr++ = (char)  ('0' + (c /  10) % 10);
                c      = (unsigned char)('0' + (c      ) % 10);
                }
            }
        *ptr++ = (char)c;                                       // Copy the character
        }
    *ptr = 0;                                                   // Null-terminate the string
    return(ptr);                                                // and return
    }

static char *ConvertDomainNameToCString_withescape(const domainname *const name, char *ptr, char esc)
    {
    const unsigned char *src         = name->c;                        // Domain name we're reading
    const unsigned char *const max   = name->c + MAX_DOMAIN_NAME;      // Maximum that's valid

    if (*src == 0) *ptr++ = '.';                                // Special case: For root, just write a dot

    while (*src)                                                                                                        // While more characters in the domain name
        {
        if (src + 1 + *src >= max) return(NULL);
        ptr = ConvertDomainLabelToCString_withescape((const domainlabel *)src, ptr, esc);
        if (!ptr) return(NULL);
        src += 1 + *src;
        *ptr++ = '.';                                           // Write the dot after the label
        }

    *ptr++ = 0;                                                 // Null-terminate the string
    return(ptr);                                                // and return
    }
