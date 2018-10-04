/*
	Copyright (c) 2016-2018 Apple Inc. All rights reserved.
	
	dnssdutil is a command-line utility for testing the DNS-SD API.
*/

#include <CoreUtils/CommonServices.h>	// Include early.
#include <CoreUtils/AsyncConnection.h>
#include <CoreUtils/CFUtils.h>
#include <CoreUtils/CommandLineUtils.h>
#include <CoreUtils/DataBufferUtils.h>
#include <CoreUtils/DebugServices.h>
#include <CoreUtils/HTTPUtils.h>
#include <CoreUtils/JSONUtils.h>
#include <CoreUtils/LogUtils.h>
#include <CoreUtils/MiscUtils.h>
#include <CoreUtils/NetUtils.h>
#include <CoreUtils/PrintFUtils.h>
#include <CoreUtils/RandomNumberUtils.h>
#include <CoreUtils/SoftLinking.h>
#include <CoreUtils/StringUtils.h>
#include <CoreUtils/TickUtils.h>
#include <dns_sd.h>
#include <dns_sd_private.h>

#include CF_RUNTIME_HEADER

#if( TARGET_OS_DARWIN )
	#include <CFNetwork/CFHost.h>
	#include <CoreFoundation/CoreFoundation.h>
	#include <SystemConfiguration/SCPrivate.h>
	#include <dnsinfo.h>
	#include <libproc.h>
	#include <netdb.h>
	#include <pcap.h>
	#include <spawn.h>
	#include <sys/proc_info.h>
#endif

#if( TARGET_OS_POSIX )
	#include <sys/resource.h>
#endif

#if( DNSSDUTIL_INCLUDE_DNSCRYPT )
	#include "tweetnacl.h"	// TweetNaCl from <https://tweetnacl.cr.yp.to/software.html>.
#endif

//===========================================================================================================================
//	Versioning
//===========================================================================================================================

#define kDNSSDUtilNumVersion	NumVersionBuild( 2, 0, 0, kVersionStageBeta, 0 )

#if( !MDNSRESPONDER_PROJECT && !defined( DNSSDUTIL_SOURCE_VERSION ) )
	#define DNSSDUTIL_SOURCE_VERSION	"0.0.0"
#endif

//===========================================================================================================================
//	DNS-SD
//===========================================================================================================================

// DNS-SD API flag descriptors

#define kDNSServiceFlagsDescriptors		\
	"\x00" "AutoTrigger\0"				\
	"\x01" "Add\0"						\
	"\x02" "Default\0"					\
	"\x03" "NoAutoRename\0"				\
	"\x04" "Shared\0"					\
	"\x05" "Unique\0"					\
	"\x06" "BrowseDomains\0"			\
	"\x07" "RegistrationDomains\0"		\
	"\x08" "LongLivedQuery\0"			\
	"\x09" "AllowRemoteQuery\0"			\
	"\x0A" "ForceMulticast\0"			\
	"\x0B" "KnownUnique\0"				\
	"\x0C" "ReturnIntermediates\0"		\
	"\x0D" "NonBrowsable\0"				\
	"\x0E" "ShareConnection\0"			\
	"\x0F" "SuppressUnusable\0"			\
	"\x10" "Timeout\0"					\
	"\x11" "IncludeP2P\0"				\
	"\x12" "WakeOnResolve\0"			\
	"\x13" "BackgroundTrafficClass\0"	\
	"\x14" "IncludeAWDL\0"				\
	"\x15" "Validate\0"					\
	"\x16" "UnicastResponse\0"			\
	"\x17" "ValidateOptional\0"			\
	"\x18" "WakeOnlyService\0"			\
	"\x19" "ThresholdOne\0"				\
	"\x1A" "ThresholdFinder\0"			\
	"\x1B" "DenyCellular\0"				\
	"\x1C" "ServiceIndex\0"				\
	"\x1D" "DenyExpensive\0"			\
	"\x1E" "PathEvaluationDone\0"		\
	"\x00"

#define kDNSServiceProtocolDescriptors	\
	"\x00" "IPv4\0"						\
	"\x01" "IPv6\0"						\
	"\x04" "UDP\0"						\
	"\x05" "TCP\0"						\
	"\x00"

#define kBadDNSServiceRef		( (DNSServiceRef)(intptr_t) -1 )

//===========================================================================================================================
//	DNS
//===========================================================================================================================

#define kDNSPort						53
#define kDNSCompressionOffsetMax		0x3FFF
#define kDNSMaxUDPMessageSize			512
#define kDNSMaxTCPMessageSize			UINT16_MAX

#define kDomainLabelLengthMax		63
#define kDomainNameLengthMax		256

typedef struct
{
	uint8_t		id[ 2 ];
	uint8_t		flags[ 2 ];
	uint8_t		questionCount[ 2 ];
	uint8_t		answerCount[ 2 ];
	uint8_t		authorityCount[ 2 ];
	uint8_t		additionalCount[ 2 ];
	
}	DNSHeader;

#define kDNSHeaderLength		12
check_compile_time( sizeof( DNSHeader ) == kDNSHeaderLength );

#define DNSHeaderGetID( HDR )					ReadBig16( ( HDR )->id )
#define DNSHeaderGetFlags( HDR )				ReadBig16( ( HDR )->flags )
#define DNSHeaderGetQuestionCount( HDR )		ReadBig16( ( HDR )->questionCount )
#define DNSHeaderGetAnswerCount( HDR )			ReadBig16( ( HDR )->answerCount )
#define DNSHeaderGetAuthorityCount( HDR )		ReadBig16( ( HDR )->authorityCount )
#define DNSHeaderGetAdditionalCount( HDR )		ReadBig16( ( HDR )->additionalCount )

#define DNSHeaderSetID( HDR, X )					WriteBig16( ( HDR )->id, (X) )
#define DNSHeaderSetFlags( HDR, X )					WriteBig16( ( HDR )->flags, (X) )
#define DNSHeaderSetQuestionCount( HDR, X )			WriteBig16( ( HDR )->questionCount, (X) )
#define DNSHeaderSetAnswerCount( HDR, X )			WriteBig16( ( HDR )->answerCount, (X) )
#define DNSHeaderSetAuthorityCount( HDR, X )		WriteBig16( ( HDR )->authorityCount, (X) )
#define DNSHeaderSetAdditionalCount( HDR, X )		WriteBig16( ( HDR )->additionalCount, (X) )

// Single-bit DNS header fields

#define kDNSHeaderFlag_Response					( 1 << 15 )	// QR (bit 15), Query (0)/Response (1)
#define kDNSHeaderFlag_AuthAnswer				( 1 << 10 )	// AA (bit 10), Authoritative Answer
#define kDNSHeaderFlag_Truncation				( 1 <<  9 )	// TC (bit  9), TrunCation
#define kDNSHeaderFlag_RecursionDesired			( 1 <<  8 )	// RD (bit  8), Recursion Desired
#define kDNSHeaderFlag_RecursionAvailable		( 1 <<  7 )	// RA (bit  7), Recursion Available
#define kDNSHeaderFlag_Z						( 1 <<  6 )	//  Z (bit  6), Reserved (must be zero)
#define kDNSHeaderFlag_AuthenticData			( 1 <<  5 )	// AD (bit  5), Authentic Data (RFC 2535, Section 6)
#define kDNSHeaderFlag_CheckingDisabled			( 1 <<  4 )	// CD (bit  4), Checking Disabled (RFC 2535, Section 6)

// OPCODE (bits 14-11), Operation Code

#define DNSFlagsGetOpCode( FLAGS )		( ( (FLAGS) >> 11 ) & 0x0FU )
#define DNSFlagsSetOpCode( FLAGS, OPCODE ) \
	do{ (FLAGS) = ( (FLAGS) & ~0x7800U ) | ( ( (OPCODE) & 0x0FU ) << 11 ); } while( 0 )

#define kDNSOpCode_Query			0	// QUERY (standard query)
#define kDNSOpCode_InverseQuery		1	// IQUERY (inverse query)
#define kDNSOpCode_Status			2	// STATUS
#define kDNSOpCode_Notify			4	// NOTIFY
#define kDNSOpCode_Update			5	// UPDATE

// RCODE (bits 3-0), Response Code

#define DNSFlagsGetRCode( FLAGS )		( (FLAGS) & 0x0FU )
#define DNSFlagsSetRCode( FLAGS, RCODE ) \
	do{ (FLAGS) = ( (FLAGS) & ~0x000FU ) | ( (RCODE) & 0x0FU ); } while( 0 )

#define kDNSRCode_NoError				0
#define kDNSRCode_FormatError			1
#define kDNSRCode_ServerFailure			2
#define kDNSRCode_NXDomain				3
#define kDNSRCode_NotImplemented		4
#define kDNSRCode_Refused				5

typedef struct
{
	uint8_t		type[ 2 ];
	uint8_t		class[ 2 ];
	
}	DNSQuestionFixedFields;

check_compile_time( sizeof( DNSQuestionFixedFields ) == 4 );

#define DNSQuestionFixedFieldsInit( FIELDS, QTYPE, QCLASS ) \
	do { WriteBig16( (FIELDS)->type, QTYPE ); WriteBig16( (FIELDS)->class, QCLASS ); } while( 0 )

#define DNSQuestionFixedFieldsGetType( FIELDS )			ReadBig16( (FIELDS)->type )
#define DNSQuestionFixedFieldsGetClass( FIELDS )		ReadBig16( (FIELDS)->class )

typedef struct
{
	uint8_t		type[ 2 ];
	uint8_t		class[ 2 ];
	uint8_t		ttl[ 4 ];
	uint8_t		rdlength[ 2 ];
	
}	DNSRecordFixedFields;

check_compile_time( sizeof( DNSRecordFixedFields ) == 10 );

#define DNSRecordFixedFieldsInit( FIELDS, TYPE, CLASS, TTL, RDLENGTH )	\
	do																	\
	{																	\
		WriteBig16( (FIELDS)->type,		TYPE );							\
		WriteBig16( (FIELDS)->class,	CLASS );						\
		WriteBig32( (FIELDS)->ttl,		TTL );							\
		WriteBig16( (FIELDS)->rdlength,	RDLENGTH );						\
																		\
	}	while( 0 )

//===========================================================================================================================
//	mDNS
//===========================================================================================================================

#define kMDNSPort		5353

#define kDefaultMDNSMessageID		0
#define kDefaultMDNSQueryFlags		0

#define kQClassUnicastResponseBit		( 1U << 15 )
#define kRRClassCacheFlushBit			( 1U << 15 )

//===========================================================================================================================
//	Test DNS Server
//===========================================================================================================================

// IPv4 address block 203.0.113.0/24 (TEST-NET-3) is reserved for documentation. See <https://tools.ietf.org/html/rfc5737>.

#define kTestDNSServerBaseAddrV4		UINT32_C( 0xCB007100 )	// 203.0.113.0

// IPv6 address block 2001:db8::/32 is reserved for documentation. See <https://tools.ietf.org/html/rfc3849>.

#define kTestDNSServerBaseAddrV6 \
	( (const uint8_t *) "\x20\x01\x0D\xB8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" )

//===========================================================================================================================
//	Gerneral Command Options
//===========================================================================================================================

// Command option macros

#define Command( NAME, CALLBACK, SUB_OPTIONS, SHORT_HELP, IS_NOTCOMMON )											\
	CLI_COMMAND_EX( NAME, CALLBACK, SUB_OPTIONS, (IS_NOTCOMMON) ? kCLIOptionFlags_NotCommon : kCLIOptionFlags_None,	\
		(SHORT_HELP), NULL )

#define kRequiredOptionSuffix		" [REQUIRED]"

#define MultiStringOptionEx( SHORT_CHAR, LONG_NAME, VAL_PTR, VAL_COUNT_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED, LONG_HELP )	\
	CLI_OPTION_MULTI_STRING_EX( SHORT_CHAR, LONG_NAME, VAL_PTR, VAL_COUNT_PTR, ARG_HELP,									\
		(IS_REQUIRED) ? SHORT_HELP kRequiredOptionSuffix : SHORT_HELP,														\
		(IS_REQUIRED) ? kCLIOptionFlags_Required : kCLIOptionFlags_None, LONG_HELP )

#define MultiStringOption( SHORT_CHAR, LONG_NAME, VAL_PTR, VAL_COUNT_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED ) \
		MultiStringOptionEx( SHORT_CHAR, LONG_NAME, VAL_PTR, VAL_COUNT_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED, NULL )

#define IntegerOption( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED )	\
	CLI_OPTION_INTEGER_EX( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP,						\
		(IS_REQUIRED) ? SHORT_HELP kRequiredOptionSuffix : SHORT_HELP,						\
		(IS_REQUIRED) ? kCLIOptionFlags_Required : kCLIOptionFlags_None, NULL )

#define BooleanOption( SHORT_CHAR, LONG_NAME, VAL_PTR, SHORT_HELP ) \
	CLI_OPTION_BOOLEAN( (SHORT_CHAR), (LONG_NAME), (VAL_PTR), (SHORT_HELP), NULL )

#define StringOptionEx( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED, LONG_HELP )	\
	CLI_OPTION_STRING_EX( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP,										\
		(IS_REQUIRED) ? SHORT_HELP kRequiredOptionSuffix : SHORT_HELP,									\
		(IS_REQUIRED) ? kCLIOptionFlags_Required : kCLIOptionFlags_None, LONG_HELP )

#define StringOption( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED ) \
	StringOptionEx( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED, NULL )

#define CFStringOption( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP, SHORT_HELP, IS_REQUIRED )	\
	CLI_OPTION_CFSTRING_EX( SHORT_CHAR, LONG_NAME, VAL_PTR, ARG_HELP,						\
		(IS_REQUIRED) ? SHORT_HELP kRequiredOptionSuffix : SHORT_HELP,						\
		(IS_REQUIRED) ? kCLIOptionFlags_Required : kCLIOptionFlags_None, NULL )

// DNS-SD API flag options

static int		gDNSSDFlags						= 0;
static int		gDNSSDFlag_BrowseDomains		= false;
static int		gDNSSDFlag_DenyCellular			= false;
static int		gDNSSDFlag_DenyExpensive		= false;
static int		gDNSSDFlag_ForceMulticast		= false;
static int		gDNSSDFlag_IncludeAWDL			= false;
static int		gDNSSDFlag_NoAutoRename			= false;
static int		gDNSSDFlag_PathEvaluationDone	= false;
static int		gDNSSDFlag_RegistrationDomains	= false;
static int		gDNSSDFlag_ReturnIntermediates	= false;
static int		gDNSSDFlag_Shared				= false;
static int		gDNSSDFlag_SuppressUnusable		= false;
static int		gDNSSDFlag_Timeout				= false;
static int		gDNSSDFlag_UnicastResponse		= false;
static int		gDNSSDFlag_Unique				= false;
static int		gDNSSDFlag_WakeOnResolve		= false;

#define DNSSDFlagsOption()								\
	IntegerOption( 'f', "flags", &gDNSSDFlags, "flags",	\
		"DNSServiceFlags as an integer. This value is bitwise ORed with other single flag options.", false )

#define DNSSDFlagOption( SHORT_CHAR, FLAG_NAME ) \
	BooleanOption( SHORT_CHAR, # FLAG_NAME, &gDNSSDFlag_ ## FLAG_NAME, "Use kDNSServiceFlags" # FLAG_NAME "." )

#define DNSSDFlagsOption_DenyCellular()			DNSSDFlagOption( 'C', DenyCellular )
#define DNSSDFlagsOption_DenyExpensive()		DNSSDFlagOption( 'E', DenyExpensive )
#define DNSSDFlagsOption_ForceMulticast()		DNSSDFlagOption( 'M', ForceMulticast )
#define DNSSDFlagsOption_IncludeAWDL()			DNSSDFlagOption( 'A', IncludeAWDL )
#define DNSSDFlagsOption_NoAutoRename()			DNSSDFlagOption( 'N', NoAutoRename )
#define DNSSDFlagsOption_PathEvalDone()			DNSSDFlagOption( 'P', PathEvaluationDone )
#define DNSSDFlagsOption_ReturnIntermediates()	DNSSDFlagOption( 'I', ReturnIntermediates )
#define DNSSDFlagsOption_Shared()				DNSSDFlagOption( 'S', Shared )
#define DNSSDFlagsOption_SuppressUnusable()		DNSSDFlagOption( 'S', SuppressUnusable )
#define DNSSDFlagsOption_Timeout()				DNSSDFlagOption( 'T', Timeout )
#define DNSSDFlagsOption_UnicastResponse()		DNSSDFlagOption( 'U', UnicastResponse )
#define DNSSDFlagsOption_Unique()				DNSSDFlagOption( 'U', Unique )
#define DNSSDFlagsOption_WakeOnResolve()		DNSSDFlagOption( 'W', WakeOnResolve )

// Interface option

static const char *		gInterface = NULL;

#define InterfaceOption()										\
	StringOption( 'i', "interface", &gInterface, "interface",	\
		"Network interface by name or index. Use index -1 for local-only.", false )

// Connection options

#define kConnectionArg_Normal			""
#define kConnectionArgPrefix_PID		"pid:"
#define kConnectionArgPrefix_UUID		"uuid:"

static const char *		gConnectionOpt = kConnectionArg_Normal;

#define ConnectionOptions()																						\
	{ kCLIOptionType_String, 0, "connection", &gConnectionOpt, NULL, (intptr_t) kConnectionArg_Normal, "type",	\
		kCLIOptionFlags_OptionalArgument, NULL, NULL, NULL, NULL,												\
		"Specifies the type of main connection to use. See " kConnectionSection_Name " below.", NULL }

#define kConnectionSection_Name		"Connection Option"
#define kConnectionSection_Text																							\
	"The default behavior is to create a main connection with DNSServiceCreateConnection() and perform operations on\n"	\
	"the main connection using the kDNSServiceFlagsShareConnection flag. This behavior can be explicitly invoked by\n"	\
	"specifying the connection option without an argument, i.e.,\n"														\
	"\n"																												\
	"    --connection\n"																								\
	"\n"																												\
	"To instead use a delegate connection created with DNSServiceCreateDelegateConnection(), use\n"						\
	"\n"																												\
	"    --connection=pid:<PID>\n"																						\
	"\n"																												\
	"to specify the delegator by PID, or use\n"																			\
	"\n"																												\
	"    --connection=uuid:<UUID>\n"																					\
	"\n"																												\
	"to specify the delegator by UUID.\n"																				\
	"\n"																												\
	"To not use a main connection at all, but instead perform operations on their own implicit connections, use\n"		\
	"\n"																												\
	"    --no-connection\n"

#define ConnectionSection()		CLI_SECTION( kConnectionSection_Name, kConnectionSection_Text )

// Help text for record data options

#define kRDataArgPrefix_Domain			"domain:"
#define kRDataArgPrefix_File			"file:"
#define kRDataArgPrefix_HexString		"hex:"
#define kRDataArgPrefix_IPv4			"ipv4:"
#define kRDataArgPrefix_IPv6			"ipv6:"
#define kRDataArgPrefix_SRV				"srv:"
#define kRDataArgPrefix_String			"string:"
#define kRDataArgPrefix_TXT				"txt:"

#define kRecordDataSection_Name		"Record Data Arguments"
#define kRecordDataSection_Text																							\
	"A record data argument is specified in one of the following formats:\n"											\
	"\n"																												\
	"Format                        Syntax                                   Example\n"									\
	"Domain name                   domain:<domain name>                     domain:demo._test._tcp.local\n"				\
	"File containing record data   file:<file path>                         file:/path/to/rdata.bin\n"					\
	"Hexadecimal string            hex:<hex string>                         hex:c0000201 or hex:'C0 00 02 01'\n"		\
	"IPv4 address                  ipv4:<IPv4 address>                      ipv4:192.0.2.1\n"							\
	"IPv6 address                  ipv6:<IPv6 address>                      ipv6:2001:db8::1\n"							\
	"SRV record                    srv:<priority>,<weight>,<port>,<target>  srv:0,0,64206,example.local\n"				\
	"String (w/escaped hex bytes)  string:<string>                          string:'\\x09color=red'\n"					\
	"TXT record keys and values    txt:<comma-delimited keys and values>    txt:'vers=1.0,lang=en\\,es\\,fr,passreq'\n"

#define RecordDataSection()		CLI_SECTION( kRecordDataSection_Name, kRecordDataSection_Text )

//===========================================================================================================================
//	Browse Command Options
//===========================================================================================================================

static char **			gBrowse_ServiceTypes		= NULL;
static size_t			gBrowse_ServiceTypesCount	= 0;
static const char *		gBrowse_Domain				= NULL;
static int				gBrowse_DoResolve			= false;
static int				gBrowse_QueryTXT			= false;
static int				gBrowse_TimeLimitSecs		= 0;

static CLIOption		kBrowseOpts[] =
{
	InterfaceOption(),
	MultiStringOption(	't', "type",	&gBrowse_ServiceTypes, &gBrowse_ServiceTypesCount, "service type", "Service type(s), e.g., \"_ssh._tcp\".", true ),
	StringOption(		'd', "domain",	&gBrowse_Domain, "domain", "Domain in which to browse for the service type(s).", false ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	DNSSDFlagsOption_IncludeAWDL(),
	
	CLI_OPTION_GROUP( "Operation" ),
	ConnectionOptions(),
	BooleanOption(  0 , "resolve",		&gBrowse_DoResolve,		"Resolve service instances." ),
	BooleanOption(  0 , "queryTXT",		&gBrowse_QueryTXT,		"Query TXT records of service instances." ),
	IntegerOption( 'l', "timeLimit",	&gBrowse_TimeLimitSecs,	"seconds", "Specifies the max duration of the browse operation. Use '0' for no time limit.", false ),
	
	ConnectionSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	GetAddrInfo Command Options
//===========================================================================================================================

static const char *		gGetAddrInfo_Name			= NULL;
static int				gGetAddrInfo_ProtocolIPv4	= false;
static int				gGetAddrInfo_ProtocolIPv6	= false;
static int				gGetAddrInfo_OneShot		= false;
static int				gGetAddrInfo_TimeLimitSecs	= 0;

static CLIOption		kGetAddrInfoOpts[] =
{
	InterfaceOption(),
	StringOption(  'n', "name", &gGetAddrInfo_Name,			"domain name", "Domain name to resolve.", true ),
	BooleanOption(  0 , "ipv4", &gGetAddrInfo_ProtocolIPv4,	"Use kDNSServiceProtocol_IPv4." ),
	BooleanOption(  0 , "ipv6", &gGetAddrInfo_ProtocolIPv6,	"Use kDNSServiceProtocol_IPv6." ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	DNSSDFlagsOption_DenyCellular(),
	DNSSDFlagsOption_DenyExpensive(),
	DNSSDFlagsOption_PathEvalDone(),
	DNSSDFlagsOption_ReturnIntermediates(),
	DNSSDFlagsOption_SuppressUnusable(),
	DNSSDFlagsOption_Timeout(),
	
	CLI_OPTION_GROUP( "Operation" ),
	ConnectionOptions(),
	BooleanOption( 'o', "oneshot",		&gGetAddrInfo_OneShot,			"Finish after first set of results." ),
	IntegerOption( 'l', "timeLimit",	&gGetAddrInfo_TimeLimitSecs,	"seconds", "Maximum duration of the GetAddrInfo operation. Use '0' for no time limit.", false ),
	
	ConnectionSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	QueryRecord Command Options
//===========================================================================================================================

static const char *		gQueryRecord_Name			= NULL;
static const char *		gQueryRecord_Type			= NULL;
static int				gQueryRecord_OneShot		= false;
static int				gQueryRecord_TimeLimitSecs	= 0;
static int				gQueryRecord_RawRData		= false;

static CLIOption		kQueryRecordOpts[] =
{
	InterfaceOption(),
	StringOption( 'n', "name", &gQueryRecord_Name, "domain name", "Full domain name of record to query.", true ),
	StringOption( 't', "type", &gQueryRecord_Type, "record type", "Record type by name (e.g., TXT, SRV, etc.) or number.", true ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	DNSSDFlagsOption_IncludeAWDL(),
	DNSSDFlagsOption_ForceMulticast(),
	DNSSDFlagsOption_Timeout(),
	DNSSDFlagsOption_ReturnIntermediates(),
	DNSSDFlagsOption_SuppressUnusable(),
	DNSSDFlagsOption_UnicastResponse(),
	DNSSDFlagsOption_DenyCellular(),
	DNSSDFlagsOption_DenyExpensive(),
	DNSSDFlagsOption_PathEvalDone(),
	
	CLI_OPTION_GROUP( "Operation" ),
	ConnectionOptions(),
	BooleanOption( 'o', "oneshot",		&gQueryRecord_OneShot,			"Finish after first set of results." ),
	IntegerOption( 'l', "timeLimit",	&gQueryRecord_TimeLimitSecs,	"seconds", "Maximum duration of the query record operation. Use '0' for no time limit.", false ),
	BooleanOption(  0 , "raw",			&gQueryRecord_RawRData,			"Show record data as a hexdump." ),
	
	ConnectionSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	Register Command Options
//===========================================================================================================================

static const char *			gRegister_Name			= NULL;
static const char *			gRegister_Type			= NULL;
static const char *			gRegister_Domain		= NULL;
static int					gRegister_Port			= 0;
static const char *			gRegister_TXT			= NULL;
static int					gRegister_LifetimeMs	= -1;
static const char **		gAddRecord_Types		= NULL;
static size_t				gAddRecord_TypesCount	= 0;
static const char **		gAddRecord_Data			= NULL;
static size_t				gAddRecord_DataCount	= 0;
static const char **		gAddRecord_TTLs			= NULL;
static size_t				gAddRecord_TTLsCount	= 0;
static const char *			gUpdateRecord_Data		= NULL;
static int					gUpdateRecord_DelayMs	= 0;
static int					gUpdateRecord_TTL		= 0;

static CLIOption		kRegisterOpts[] =
{
	InterfaceOption(),
	StringOption(  'n', "name",		&gRegister_Name,	"service name",	"Name of service.", false ),
	StringOption(  't', "type",		&gRegister_Type,	"service type",	"Service type, e.g., \"_ssh._tcp\".", true ),
	StringOption(  'd', "domain",	&gRegister_Domain,	"domain",		"Domain in which to advertise the service.", false ),
	IntegerOption( 'p', "port",		&gRegister_Port,	"port number",	"Service's port number.", true ),
	StringOption(   0 , "txt",		&gRegister_TXT,		"record data",	"The TXT record data. See " kRecordDataSection_Name " below.", false ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	DNSSDFlagsOption_IncludeAWDL(),
	DNSSDFlagsOption_NoAutoRename(),
	
	CLI_OPTION_GROUP( "Operation" ),
	IntegerOption( 'l', "lifetime", &gRegister_LifetimeMs, "ms", "Lifetime of the service registration in milliseconds.", false ),
	
	CLI_OPTION_GROUP( "Options for updating the registered service's primary TXT record with DNSServiceUpdateRecord()\n" ),
	StringOption(  0 , "updateData",	&gUpdateRecord_Data,	"record data",	"Record data for the record update. See " kRecordDataSection_Name " below.", false ),
	IntegerOption( 0 , "updateDelay",	&gUpdateRecord_DelayMs,	"ms",			"Number of milliseconds after registration to wait before record update.", false ),
	IntegerOption( 0 , "updateTTL",		&gUpdateRecord_TTL,		"seconds",		"Time-to-live of the updated record.", false ),
	
	CLI_OPTION_GROUP( "Options for adding extra record(s) to the registered service with DNSServiceAddRecord()\n" ),
	MultiStringOption(   0 , "addType",	&gAddRecord_Types,	&gAddRecord_TypesCount,	"record type",	"Type of additional record by name (e.g., TXT, SRV, etc.) or number.", false ),
	MultiStringOptionEx( 0 , "addData",	&gAddRecord_Data,	&gAddRecord_DataCount,	"record data",	"Additional record's data. See " kRecordDataSection_Name " below.", false, NULL ),
	MultiStringOption(   0 , "addTTL",	&gAddRecord_TTLs,	&gAddRecord_TTLsCount,	"seconds",		"Time-to-live of additional record in seconds. Use '0' for default.", false ),
	
	RecordDataSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	RegisterRecord Command Options
//===========================================================================================================================

static const char *		gRegisterRecord_Name			= NULL;
static const char *		gRegisterRecord_Type			= NULL;
static const char *		gRegisterRecord_Data			= NULL;
static int				gRegisterRecord_TTL				= 0;
static int				gRegisterRecord_LifetimeMs		= -1;
static const char *		gRegisterRecord_UpdateData		= NULL;
static int				gRegisterRecord_UpdateDelayMs	= 0;
static int				gRegisterRecord_UpdateTTL		= 0;

static CLIOption		kRegisterRecordOpts[] =
{
	InterfaceOption(),
	StringOption( 'n', "name",	&gRegisterRecord_Name,	"record name",	"Fully qualified domain name of record.", true ),
	StringOption( 't', "type",	&gRegisterRecord_Type,	"record type",	"Record type by name (e.g., TXT, PTR, A) or number.", true ),
	StringOption( 'd', "data",	&gRegisterRecord_Data,	"record data",	"The record data. See " kRecordDataSection_Name " below.", false ),
	IntegerOption( 0 , "ttl",	&gRegisterRecord_TTL,	"seconds",		"Time-to-live in seconds. Use '0' for default.", false ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	DNSSDFlagsOption_IncludeAWDL(),
	DNSSDFlagsOption_Shared(),
	DNSSDFlagsOption_Unique(),
	
	CLI_OPTION_GROUP( "Operation" ),
	IntegerOption( 'l', "lifetime", &gRegisterRecord_LifetimeMs, "ms", "Lifetime of the service registration in milliseconds.", false ),
	
	CLI_OPTION_GROUP( "Options for updating the registered record with DNSServiceUpdateRecord()\n" ),
	StringOption(  0 , "updateData",	&gRegisterRecord_UpdateData,	"record data",	"Record data for the record update.", false ),
	IntegerOption( 0 , "updateDelay",	&gRegisterRecord_UpdateDelayMs,	"ms",			"Number of milliseconds after registration to wait before record update.", false ),
	IntegerOption( 0 , "updateTTL",		&gRegisterRecord_UpdateTTL,		"seconds",		"Time-to-live of the updated record.", false ),
	
	RecordDataSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	Resolve Command Options
//===========================================================================================================================

static char *		gResolve_Name			= NULL;
static char *		gResolve_Type			= NULL;
static char *		gResolve_Domain			= NULL;
static int			gResolve_TimeLimitSecs	= 0;

static CLIOption		kResolveOpts[] =
{
	InterfaceOption(),
	StringOption( 'n', "name",		&gResolve_Name,		"service name", "Name of the service instance to resolve.", true ),
	StringOption( 't', "type",		&gResolve_Type,		"service type", "Type of the service instance to resolve.", true ),
	StringOption( 'd', "domain",	&gResolve_Domain,	"domain", "Domain of the service instance to resolve.", true ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	DNSSDFlagsOption_ForceMulticast(),
	DNSSDFlagsOption_IncludeAWDL(),
	DNSSDFlagsOption_ReturnIntermediates(),
	DNSSDFlagsOption_WakeOnResolve(),
	
	CLI_OPTION_GROUP( "Operation" ),
	ConnectionOptions(),
	IntegerOption( 'l', "timeLimit", &gResolve_TimeLimitSecs, "seconds", "Maximum duration of the resolve operation. Use '0' for no time limit.", false ),
	
	ConnectionSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	Reconfirm Command Options
//===========================================================================================================================

static const char *		gReconfirmRecord_Name	= NULL;
static const char *		gReconfirmRecord_Type	= NULL;
static const char *		gReconfirmRecord_Class	= NULL;
static const char *		gReconfirmRecord_Data	= NULL;

static CLIOption		kReconfirmOpts[] =
{
	InterfaceOption(),
	StringOption( 'n', "name",	&gReconfirmRecord_Name,		"record name",	"Full name of the record to reconfirm.", true ),
	StringOption( 't', "type",	&gReconfirmRecord_Type,		"record type",	"Type of the record to reconfirm.", true ),
	StringOption( 'c', "class",	&gReconfirmRecord_Class,	"record class",	"Class of the record to reconfirm. Default class is IN.", false ),
	StringOption( 'd', "data",	&gReconfirmRecord_Data,		"record data",	"The record data. See " kRecordDataSection_Name " below.", false ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	
	RecordDataSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	getaddrinfo-POSIX Command Options
//===========================================================================================================================

static const char *		gGAIPOSIX_HostName			= NULL;
static const char *		gGAIPOSIX_ServName			= NULL;
static const char *		gGAIPOSIX_Family			= NULL;
static int				gGAIPOSIXFlag_AddrConfig	= false;
static int				gGAIPOSIXFlag_All			= false;
static int				gGAIPOSIXFlag_CanonName		= false;
static int				gGAIPOSIXFlag_NumericHost	= false;
static int				gGAIPOSIXFlag_NumericServ	= false;
static int				gGAIPOSIXFlag_Passive		= false;
static int				gGAIPOSIXFlag_V4Mapped		= false;
#if( defined( AI_V4MAPPED_CFG ) )
static int				gGAIPOSIXFlag_V4MappedCFG	= false;
#endif
#if( defined( AI_DEFAULT ) )
static int				gGAIPOSIXFlag_Default		= false;
#endif
#if( defined( AI_UNUSABLE ) )
static int				gGAIPOSIXFlag_Unusable		= false;
#endif

static CLIOption		kGetAddrInfoPOSIXOpts[] =
{
	StringOption(	'n', "hostname",			&gGAIPOSIX_HostName,		"hostname", "Domain name to resolve or an IPv4 or IPv6 address.", true ),
	StringOption(	's', "servname",			&gGAIPOSIX_ServName,		"servname", "Port number in decimal or service name from services(5).", false ),
	
	CLI_OPTION_GROUP( "Hints " ),
	StringOptionEx(	'f', "family",				&gGAIPOSIX_Family,			"address family", "Address family to use for hints ai_family field.", false,
		"\n"
		"Possible address family values are 'inet' for AF_INET, 'inet6' for AF_INET6, or 'unspec' for AF_UNSPEC. If no\n"
		"address family is specified, then AF_UNSPEC is used.\n"
		"\n" ),
	BooleanOption(   0 , "flag-addrconfig",		&gGAIPOSIXFlag_AddrConfig,	"In hints ai_flags field, set AI_ADDRCONFIG." ),
	BooleanOption(   0 , "flag-all",			&gGAIPOSIXFlag_All,			"In hints ai_flags field, set AI_ALL." ),
	BooleanOption(   0 , "flag-canonname",		&gGAIPOSIXFlag_CanonName,	"In hints ai_flags field, set AI_CANONNAME." ),
	BooleanOption(   0 , "flag-numerichost",	&gGAIPOSIXFlag_NumericHost,	"In hints ai_flags field, set AI_NUMERICHOST." ),
	BooleanOption(   0 , "flag-numericserv",	&gGAIPOSIXFlag_NumericServ,	"In hints ai_flags field, set AI_NUMERICSERV." ),
	BooleanOption(   0 , "flag-passive",		&gGAIPOSIXFlag_Passive,		"In hints ai_flags field, set AI_PASSIVE." ),
	BooleanOption(   0 , "flag-v4mapped",		&gGAIPOSIXFlag_V4Mapped,	"In hints ai_flags field, set AI_V4MAPPED." ),
#if( defined( AI_V4MAPPED_CFG ) )
	BooleanOption(   0 , "flag-v4mappedcfg",	&gGAIPOSIXFlag_V4MappedCFG,	"In hints ai_flags field, set AI_V4MAPPED_CFG." ),
#endif
#if( defined( AI_DEFAULT ) )
	BooleanOption(   0 , "flag-default",		&gGAIPOSIXFlag_Default,		"In hints ai_flags field, set AI_DEFAULT." ),
#endif
#if( defined( AI_UNUSABLE ) )
	BooleanOption(   0 , "flag-unusable",		&gGAIPOSIXFlag_Unusable,	"In hints ai_flags field, set AI_UNUSABLE." ),
#endif
	
	CLI_SECTION( "Notes", "See getaddrinfo(3) man page for more details.\n" ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	ReverseLookup Command Options
//===========================================================================================================================

static const char *		gReverseLookup_IPAddr			= NULL;
static int				gReverseLookup_OneShot			= false;
static int				gReverseLookup_TimeLimitSecs	= 0;

static CLIOption		kReverseLookupOpts[] =
{
	InterfaceOption(),
	StringOption( 'a', "address", &gReverseLookup_IPAddr, "IP address", "IPv4 or IPv6 address for which to perform a reverse IP lookup.", true ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	DNSSDFlagsOption_ForceMulticast(),
	DNSSDFlagsOption_ReturnIntermediates(),
	DNSSDFlagsOption_SuppressUnusable(),
	
	CLI_OPTION_GROUP( "Operation" ),
	ConnectionOptions(),
	BooleanOption( 'o', "oneshot",		&gReverseLookup_OneShot,		"Finish after first set of results." ),
	IntegerOption( 'l', "timeLimit",	&gReverseLookup_TimeLimitSecs,	"seconds", "Specifies the max duration of the query record operation. Use '0' for no time limit.", false ),
	
	ConnectionSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	PortMapping Command Options
//===========================================================================================================================

static int		gPortMapping_ProtocolTCP	= false;
static int		gPortMapping_ProtocolUDP	= false;
static int		gPortMapping_InternalPort	= 0;
static int		gPortMapping_ExternalPort	= 0;
static int		gPortMapping_TTL			= 0;

static CLIOption		kPortMappingOpts[] =
{
	InterfaceOption(),
	BooleanOption( 0, "tcp",			&gPortMapping_ProtocolTCP,	"Use kDNSServiceProtocol_TCP." ),
	BooleanOption( 0, "udp",			&gPortMapping_ProtocolUDP,	"Use kDNSServiceProtocol_UDP." ),
	IntegerOption( 0, "internalPort",	&gPortMapping_InternalPort,	"port number", "Internal port.", false ),
	IntegerOption( 0, "externalPort",	&gPortMapping_ExternalPort,	"port number", "Requested external port. Use '0' for any external port.", false ),
	IntegerOption( 0, "ttl",			&gPortMapping_TTL,			"seconds", "Requested TTL (renewal period) in seconds. Use '0' for a default value.", false ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption(),
	
	CLI_OPTION_GROUP( "Operation" ),
	ConnectionOptions(),
	
	ConnectionSection(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	BrowseAll Command Options
//===========================================================================================================================

static const char *		gBrowseAll_Domain				= NULL;
static char **			gBrowseAll_ServiceTypes			= NULL;
static size_t			gBrowseAll_ServiceTypesCount	= 0;
static int				gBrowseAll_BrowseTimeSecs		= 5;
static int				gBrowseAll_MaxConnectTimeSecs	= 0;

static CLIOption		kBrowseAllOpts[] =
{
	InterfaceOption(),
	StringOption(	   'd', "domain",	&gBrowseAll_Domain, "domain", "Domain in which to browse for the service.", false ),
	MultiStringOption( 't', "type",		&gBrowseAll_ServiceTypes, &gBrowseAll_ServiceTypesCount, "service type", "Service type(s), e.g., \"_ssh._tcp\". All services are browsed for if none is specified.", false ),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption_IncludeAWDL(),
	
	CLI_OPTION_GROUP( "Operation" ),
	IntegerOption( 'b', "browseTime",		&gBrowseAll_BrowseTimeSecs,		"seconds", "Amount of time to spend browsing. (Default: 5 seconds)", false ),
	IntegerOption( 'c', "maxConnectTime",	&gBrowseAll_MaxConnectTimeSecs,	"seconds", "Max duration of connection attempts. If <= 0, then no connections are attempted. (Default: 0 seconds)", false ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	GetNameInfo Command Options
//===========================================================================================================================

static void	GetNameInfoCmd( void );

static char *		gGetNameInfo_IPAddress			= NULL;
static int			gGetNameInfoFlag_DGram			= false;
static int			gGetNameInfoFlag_NameReqd		= false;
static int			gGetNameInfoFlag_NoFQDN			= false;
static int			gGetNameInfoFlag_NumericHost	= false;
static int			gGetNameInfoFlag_NumericScope	= false;
static int			gGetNameInfoFlag_NumericServ	= false;

static CLIOption		kGetNameInfoOpts[] =
{
	StringOption( 'a', "address",           &gGetNameInfo_IPAddress,        "IP address", "IPv4 or IPv6 address to use in sockaddr structure.", true ),
	
	CLI_OPTION_GROUP( "Flags" ),
	BooleanOption( 0 , "flag-dgram",        &gGetNameInfoFlag_DGram,        "Use NI_DGRAM flag." ),
	BooleanOption( 0 , "flag-namereqd",     &gGetNameInfoFlag_NameReqd,     "Use NI_NAMEREQD flag." ),
	BooleanOption( 0 , "flag-nofqdn",       &gGetNameInfoFlag_NoFQDN,       "Use NI_NOFQDN flag." ),
	BooleanOption( 0 , "flag-numerichost",  &gGetNameInfoFlag_NumericHost,  "Use NI_NUMERICHOST flag." ),
	BooleanOption( 0 , "flag-numericscope", &gGetNameInfoFlag_NumericScope, "Use NI_NUMERICSCOPE flag." ),
	BooleanOption( 0 , "flag-numericserv",  &gGetNameInfoFlag_NumericServ,  "Use NI_NUMERICSERV flag." ),
	
	CLI_SECTION( "Notes", "See getnameinfo(3) man page for more details.\n" ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	GetAddrInfoStress Command Options
//===========================================================================================================================

static int		gGAIStress_TestDurationSecs	= 0;
static int		gGAIStress_ConnectionCount	= 0;
static int		gGAIStress_DurationMinMs	= 0;
static int		gGAIStress_DurationMaxMs	= 0;
static int		gGAIStress_RequestCountMax	= 0;

static CLIOption		kGetAddrInfoStressOpts[] =
{
	InterfaceOption(),
	
	CLI_OPTION_GROUP( "Flags" ),
	DNSSDFlagsOption_ReturnIntermediates(),
	DNSSDFlagsOption_SuppressUnusable(),
	
	CLI_OPTION_GROUP( "Operation" ),
	IntegerOption( 0, "testDuration",			&gGAIStress_TestDurationSecs,	"seconds",	"Stress test duration in seconds. Use '0' for forever.", false ),
	IntegerOption( 0, "connectionCount",		&gGAIStress_ConnectionCount,	"integer",	"Number of simultaneous DNS-SD connections.", true ),
	IntegerOption( 0, "requestDurationMin",		&gGAIStress_DurationMinMs,		"ms",		"Minimum duration of DNSServiceGetAddrInfo() request in milliseconds.", true ),
	IntegerOption( 0, "requestDurationMax",		&gGAIStress_DurationMaxMs,		"ms",		"Maximum duration of DNSServiceGetAddrInfo() request in milliseconds.", true ),
	IntegerOption( 0, "consecutiveRequestMax",	&gGAIStress_RequestCountMax,	"integer",	"Maximum number of requests on a connection before restarting it.", true ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	DNSQuery Command Options
//===========================================================================================================================

static char *		gDNSQuery_Name			= NULL;
static char *		gDNSQuery_Type			= "A";
static char *		gDNSQuery_Server		= NULL;
static int			gDNSQuery_TimeLimitSecs	= 5;
static int			gDNSQuery_UseTCP		= false;
static int			gDNSQuery_Flags			= kDNSHeaderFlag_RecursionDesired;
static int			gDNSQuery_RawRData		= false;
static int			gDNSQuery_Verbose		= false;

#if( TARGET_OS_DARWIN )
	#define kDNSQueryServerOptionIsRequired		false
#else
	#define kDNSQueryServerOptionIsRequired		true
#endif

static CLIOption		kDNSQueryOpts[] =
{
	StringOption(  'n', "name",			&gDNSQuery_Name,			"name",	"Question name (QNAME) to put in DNS query message.", true ),
	StringOption(  't', "type",			&gDNSQuery_Type,			"type",	"Question type (QTYPE) to put in DNS query message. Default value is 'A'.", false ),
	StringOption(  's', "server",		&gDNSQuery_Server,			"IP address", "DNS server's IPv4 or IPv6 address.", kDNSQueryServerOptionIsRequired ),
	IntegerOption( 'l', "timeLimit",	&gDNSQuery_TimeLimitSecs,	"seconds", "Specifies query time limit. Use '-1' for no limit and '0' to exit immediately after sending.", false ),
	BooleanOption(  0 , "tcp",			&gDNSQuery_UseTCP,			"Send the DNS query via TCP instead of UDP." ),
	IntegerOption( 'f', "flags",		&gDNSQuery_Flags,			"flags", "16-bit value for DNS header flags/codes field. Default value is 0x0100 (Recursion Desired).", false ),
	BooleanOption(  0 , "raw",			&gDNSQuery_RawRData,		"Present record data as a hexdump." ),
	BooleanOption( 'v', "verbose",		&gDNSQuery_Verbose,			"Prints the DNS message to be sent to the server." ),
	CLI_OPTION_END()
};

#if( DNSSDUTIL_INCLUDE_DNSCRYPT )
//===========================================================================================================================
//	DNSCrypt Command Options
//===========================================================================================================================

static char *		gDNSCrypt_ProviderName	= NULL;
static char *		gDNSCrypt_ProviderKey	= NULL;
static char *		gDNSCrypt_Name			= NULL;
static char *		gDNSCrypt_Type			= NULL;
static char *		gDNSCrypt_Server		= NULL;
static int			gDNSCrypt_TimeLimitSecs	= 5;
static int			gDNSCrypt_RawRData		= false;
static int			gDNSCrypt_Verbose		= false;

static CLIOption		kDNSCryptOpts[] =
{
	StringOption(  'p', "providerName",	&gDNSCrypt_ProviderName,	"name", "The DNSCrypt provider name.", true ),
	StringOption(  'k', "providerKey",	&gDNSCrypt_ProviderKey,		"hex string", "The DNSCrypt provider's public signing key.", true ),
	StringOption(  'n', "name",			&gDNSCrypt_Name,			"name",	"Question name (QNAME) to put in DNS query message.", true ),
	StringOption(  't', "type",			&gDNSCrypt_Type,			"type",	"Question type (QTYPE) to put in DNS query message.", true ),
	StringOption(  's', "server",		&gDNSCrypt_Server,			"IP address", "DNS server's IPv4 or IPv6 address.", true ),
	IntegerOption( 'l', "timeLimit",	&gDNSCrypt_TimeLimitSecs,	"seconds", "Specifies query time limit. Use '-1' for no time limit and '0' to exit immediately after sending.", false ),
	BooleanOption(  0 , "raw",			&gDNSCrypt_RawRData,		"Present record data as a hexdump." ),
	BooleanOption( 'v', "verbose",		&gDNSCrypt_Verbose,			"Prints the DNS message to be sent to the server." ),
	CLI_OPTION_END()
};
#endif

//===========================================================================================================================
//	MDNSQuery Command Options
//===========================================================================================================================

static char *		gMDNSQuery_Name			= NULL;
static char *		gMDNSQuery_Type			= NULL;
static int			gMDNSQuery_SourcePort	= 0;
static int			gMDNSQuery_IsQU			= false;
static int			gMDNSQuery_RawRData		= false;
static int			gMDNSQuery_UseIPv4		= false;
static int			gMDNSQuery_UseIPv6		= false;
static int			gMDNSQuery_AllResponses	= false;
static int			gMDNSQuery_ReceiveSecs	= 1;

static CLIOption		kMDNSQueryOpts[] =
{
	StringOption(  'i', "interface",	&gInterface,				"name or index", "Network interface by name or index.", true ),
	StringOption(  'n', "name",			&gMDNSQuery_Name,			"name", "Question name (QNAME) to put in mDNS message.", true ),
	StringOption(  't', "type",			&gMDNSQuery_Type,			"type", "Question type (QTYPE) to put in mDNS message.", true ),
	IntegerOption( 'p', "sourcePort",	&gMDNSQuery_SourcePort,		"port number", "UDP source port to use when sending mDNS messages. Default is 5353 for QM questions.", false ),
	BooleanOption( 'u', "QU",			&gMDNSQuery_IsQU,			"Set the unicast-response bit, i.e., send a QU question." ),
	BooleanOption(  0 , "raw",			&gMDNSQuery_RawRData,		"Present record data as a hexdump." ),
	BooleanOption(  0 , "ipv4",			&gMDNSQuery_UseIPv4,		"Use IPv4." ),
	BooleanOption(  0 , "ipv6",			&gMDNSQuery_UseIPv6,		"Use IPv6." ),
	BooleanOption( 'a', "allResponses",	&gMDNSQuery_AllResponses,	"Print all received mDNS messages, not just those containing answers." ),
	IntegerOption( 'r', "receiveTime",	&gMDNSQuery_ReceiveSecs,	"seconds", "Amount of time to spend receiving messages after the query is sent. The default is one second. Use -1 for unlimited time.", false ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	PIDToUUID Command Options
//===========================================================================================================================

static int		gPIDToUUID_PID = 0;

static CLIOption		kPIDToUUIDOpts[] =
{
	IntegerOption( 'p', "pid", &gPIDToUUID_PID, "PID", "Process ID.", true ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	DNSServer Command Options
//===========================================================================================================================

#define kDNSServerInfoText_Intro																						\
	"The DNS server answers certain queries in the d.test. domain. Responses are dynamically generated based on the\n"	\
	"presence of special labels in the query's QNAME. There are currently seven types of special labels that can be\n"	\
	"used to generate specific responses: Alias labels, Alias-TTL labels, Count labels, Tag labels, TTL labels, the\n"	\
	"IPv4 label, and the IPv6 label.\n"

#define kDNSServerInfoText_NameExistence																				\
	"A name is considered to exist if and only if it ends in d.test., and the other labels, if\n"						\
	"any, consist of\n"																									\
	"\n"																												\
	"    1. at most one Alias or Alias-TTL label as the first label;\n"													\
	"    2. at most one Count label;\n"																					\
	"    3. zero or more Tag labels;\n"																				\
	"    4. at most one TTL label; and\n"																				\
	"    5. at most one IPv4 or IPv6 label.\n"

#define kDNSServerInfoText_ResourceRecords																				\
	"Currently, the server only provides CNAME, A, and AAAA records.\n"													\
	"\n"																												\
	"Names that exist and begin with an Alias or Alias-TTL label are aliases of canonical names, i.e., they're the\n"	\
	"names of CNAME records. See \"Alias Labels\" and \"Alias-TTL Labels\" for details.\n"								\
	"\n"																												\
	"Names that exist and have an IPv4 label have at least one A record, but no AAAA records. Names that exist and\n"	\
	"have an IPv6 label, have at least one AAAA record, but no A records. All other names that exist have at least\n"	\
	"one A record and at least one AAAA record. See \"Count Labels\" for how the number of address records for a\n"		\
	"given name is determined.\n"																						\
	"\n"																												\
	"A records contain IPv4 addresses in the 203.0.113.0/24 block, while AAAA records contain IPv6 addresses in the\n"	\
	"2001:db8::/32 block. Both of these address blocks are reserved for documentation.\n"								\
	"See <https://tools.ietf.org/html/rfc5737> and <https://tools.ietf.org/html/rfc3849>.\n"							\
	"\n"																												\
	"Unless otherwise specified, all resource records will use a default TTL. The default TTL can be set with the\n"	\
	"--defaultTTL option. See \"Alias-TTL Labels\" and \"TTL Labels\" for details on how to query for records with\n"	\
	"specific TTL values.\n"

#define kDNSServerInfoText_AliasLabel																					\
	"Alias labels are of the form \"alias\" or \"alias-N\", where N is an integer in [2 .. 2^31 - 1].\n"				\
	"\n"																												\
	"If QNAME exist and its first label is Alias label \"alias-N\", then the response will contain exactly N CNAME\n"	\
	"records:\n"																										\
	"\n"																												\
	"    1. For each i in [3 .. N], the response will contain a CNAME record whose name is identical to QNAME,\n"		\
	"       except that the first label is \"alias-i\" instead, and whose RDATA is the name of the other CNAME\n"		\
	"       record whose name has \"alias-(i - 1)\" as its first label.\n"												\
	"\n"																												\
	"    2. The response will contain a CNAME record whose name is identical to QNAME, except that the first label\n"	\
	"       is \"alias-2\" instead, and whose RDATA is the name identical to QNAME, except that the first label is\n"	\
	"       \"alias\" instead.\n"																						\
	"\n"																												\
	"    3. The response will contain a CNAME record whose name is identical to QNAME, except that the first label\n"	\
	"       is \"alias\" instead, and whose RDATA is the name identical to QNAME stripped of its first label.\n"		\
	"\n"																												\
	"If QNAME exist and its first label is Alias label \"alias\", then the response will contain a single CNAME\n"		\
	"record. The CNAME record's name will be equal to QNAME and its RDATA will be the name identical to QNAME\n"		\
	"stripped of its first label.\n"																					\
	"\n"																												\
	"Example. A response to a query with a QNAME of alias-3.count-5.d.test will contain the following CNAME\n"			\
	"records:\n"																										\
	"\n"																												\
	"    alias-4.count-5.d.test.                        60    IN CNAME alias-3.count-5.d.test.\n"						\
	"    alias-3.count-5.d.test.                        60    IN CNAME alias-2.count-5.d.test.\n"						\
	"    alias-2.count-5.d.test.                        60    IN CNAME alias.count-5.d.test.\n"							\
	"    alias.count-5.d.test.                          60    IN CNAME count-5.d.test.\n"

#define kDNSServerInfoText_AliasTTLLabel																				\
	"Alias-TTL labels are of the form \"alias-ttl-T_1[-T_2[...-T_N]]\", where each T_i is an integer in\n"				\
	"[0 .. 2^31 - 1] and N is a positive integer bounded by the size of the maximum legal label length (63 octets).\n"	\
	"\n"																												\
	"If QNAME exists and its first label is Alias-TTL label \"alias-ttl-T_1...-T_N\", then the response will contain\n"	\
	"exactly N CNAME records:\n"																						\
	"\n"																												\
	"    1. For each i in [1 .. N - 1], the response will contain a CNAME record whose name is identical to QNAME,\n"	\
	"       except that the first label is \"alias-ttl-T_i...-T_N\" instead, whose TTL value is T_i, and whose RDATA\n"	\
	"       is the name of the other CNAME record whose name has \"alias-ttl-T_(i+1)...-T_N\" as its first label.\n"	\
	"\n"																												\
	"    2. The response will contain a CNAME record whose name is identical to QNAME, except that the first label\n"	\
	"       is \"alias-ttl-T_N\", whose TTL is T_N, and whose RDATA is identical to QNAME stripped of its first\n"		\
	"       label.\n"																									\
	"\n"																												\
	"Example. A response to a query with a QNAME of alias-ttl-20-40-80.count-5.d.test will contain the following\n"		\
	"CNAME records:\n"																									\
	"\n"																												\
	"    alias-ttl-20-40-80.count-5.d.test.             20    IN CNAME alias-ttl-40-80.count-5.d.test.\n"				\
	"    alias-ttl-40-80.count-5.d.test.                40    IN CNAME alias-ttl-80.count-5.d.test.\n"					\
	"    alias-ttl-80.count-5.d.test.                   80    IN CNAME count-5.d.test.\n"

#define kDNSServerInfoText_CountLabel																					\
	"Count labels are of the form \"count-N_1\" or \"count-N_1-N_2\", where N_1 is an integer in [1 .. 255] and N_2\n"	\
	"is an integer in [N_1 .. 255].\n"																					\
	"\n"																												\
	"If QNAME exists, contains Count label \"count-N\", and has the type of address records specified by QTYPE, then\n"	\
	"the response will contain exactly N address records:\n"															\
	"\n"																												\
	"    1. For i in [1 .. N], the response will contain an address record of type QTYPE whose name is equal to\n"		\
	"       QNAME and whose RDATA is an address equal to a constant base address + i.\n"								\
	"\n"																												\
	"    2. The address records will be ordered by the address contained in RDATA in ascending order.\n"				\
	"\n"																												\
	"Example. A response to an A record query with a QNAME of alias.count-3.d.test will contain the following A\n"		\
	"records:\n"																										\
	"\n"																												\
	"    count-3.d.test.                                60    IN A     203.0.113.1\n"									\
	"    count-3.d.test.                                60    IN A     203.0.113.2\n"									\
	"    count-3.d.test.                                60    IN A     203.0.113.3\n"									\
	"\n"																												\
	"If QNAME exists, contains Count label \"count-N_1-N_2\", and has the type of address records specified by\n"		\
	"QTYPE, then the response will contain exactly N_1 address records:\n"												\
	"\n"																												\
	"    1. Each of the address records will be of type QTYPE, have name equal to QNAME, and have as its RDATA a\n"		\
	"       unique address equal to a constant base address + i, where i is a randomly chosen integer in [1 .. N_2].\n"	\
	"\n"																												\
	"    2. The order of the address records will be random.\n"															\
	"\n"																												\
	"Example. A response to a AAAA record query with a QNAME of count-3-100.ttl-20.d.test could contain the\n"			\
	"following AAAA records:\n"																							\
	"\n"																												\
	"    count-3-100.ttl-20.d.test.                     20    IN AAAA  2001:db8::c\n"									\
	"    count-3-100.ttl-20.d.test.                     20    IN AAAA  2001:db8::3a\n"									\
	"    count-3-100.ttl-20.d.test.                     20    IN AAAA  2001:db8::4f\n"									\
	"\n"																												\
	"If QNAME exists, but doesn't have the type of address records specified by QTYPE, then the response will\n"		\
	"contain no address records, regardless of whether it contains a Count label.\n"									\
	"\n"																												\
	"QNAMEs that exist, but don't have a Count label are treated as though they contain a count label equal to\n"		\
	"\"count-1\".\n"

#define kDNSServerInfoText_TagLabel																						\
	"Tag labels are labels prefixed with \"tag-\" and contain zero or more arbitrary octets after the prefix.\n"		\
	"\n"																												\
	"This type of label exists to allow testers to \"uniquify\" domain names. Tag labels can also serve as padding\n"	\
	"to increase the sizes of domain names.\n"

#define kDNSServerInfoText_TTLLabel																						\
	"TTL labels are of the form \"ttl-T\", where T is an integer in [0 .. 2^31 - 1].\n"									\
	"\n"																												\
	"If the name specified by QNAME exists, and contains TTL label \"ttl-T\", then all non-CNAME records contained\n"	\
	"in the response will have a TTL value equal to T.\n"

#define kDNSServerInfoText_IPv4Label \
	"The IPv4 label is \"ipv4\". See \"Resource Records\" for the affect of this label.\n"

#define kDNSServerInfoText_IPv6Label \
	"The IPv6 label is \"ipv6\". See \"Resource Records\" for the affect of this label.\n"

#define kDNSServerDefaultTTL		60

static int				gDNSServer_LoopbackOnly		= false;
static int				gDNSServer_Foreground		= false;
static int				gDNSServer_ResponseDelayMs	= 0;
static int				gDNSServer_DefaultTTL		= kDNSServerDefaultTTL;
#if( TARGET_OS_DARWIN )
static const char *		gDNSServer_FollowPID		= NULL;
#endif

static CLIOption		kDNSServerOpts[] =
{
	BooleanOption( 'l', "loopback",      &gDNSServer_LoopbackOnly,    "Bind to to the loopback interface." ),
	BooleanOption( 'f', "foreground",    &gDNSServer_Foreground,      "Directlog output to stdout instead of system logging." ),
	IntegerOption( 'd', "responseDelay", &gDNSServer_ResponseDelayMs, "ms", "The amount of additional delay in milliseconds to apply to responses. (default: 0)", false ),
	IntegerOption(  0 , "defaultTTL",    &gDNSServer_DefaultTTL,      "seconds", "Resource record TTL value to use when unspecified. (default: 60)", false ),
#if( TARGET_OS_DARWIN )
	StringOption(   0 , "followPID",     &gDNSServer_FollowPID,       "pid", "Exit when the process (usually the parent proccess) specified by PID exits.", false ),
#endif
	
	CLI_SECTION( "Intro",				kDNSServerInfoText_Intro ),
	CLI_SECTION( "Name Existence",		kDNSServerInfoText_NameExistence ),
	CLI_SECTION( "Resource Records",	kDNSServerInfoText_ResourceRecords ),
	CLI_SECTION( "Alias Labels",		kDNSServerInfoText_AliasLabel ),
	CLI_SECTION( "Alias-TTL Labels",	kDNSServerInfoText_AliasTTLLabel ),
	CLI_SECTION( "Count Labels",		kDNSServerInfoText_CountLabel ),
	CLI_SECTION( "Tag Labels",			kDNSServerInfoText_TagLabel ),
	CLI_SECTION( "TTL Labels",			kDNSServerInfoText_TTLLabel ),
	CLI_SECTION( "IPv4 Label",			kDNSServerInfoText_IPv4Label ),
	CLI_SECTION( "IPv6 Label",			kDNSServerInfoText_IPv6Label ),
	CLI_OPTION_END()
};

static void	DNSServerCmd( void );

//===========================================================================================================================
//	Test Command Options
//===========================================================================================================================

static const char *		gGAIPerf_TestSuite				= NULL;
static int				gGAIPerf_CallDelayMs			= 10;
static int				gGAIPerf_ServerDelayMs			= 10;
static int				gGAIPerf_DefaultIterCount		= 100;
static const char *		gGAIPerf_OutputFilePath			= NULL;
static const char *		gGAIPerf_OutputFormat			= "json";
static int				gGAIPerf_OutputAppendNewLine	= false;

static void	GAIPerfCmd( void );

#define kGAIPerfSectionTitle_TestSuiteBasic		"Test Suite \"Basic\""
#define kGAIPerfSectionText_TestSuiteBasic																					\
	"This test suite consists of the following three test cases:\n"															\
	"\n"																													\
	"Test Case #1: Resolve a domain name with\n"																			\
	"\n"																													\
	"    2 CNAME records, 4 A records, and 4 AAAA records\n"																\
	"\n"																													\
	"to its IPv4 and IPv6 addresses. Each iteration resolves a unique instance of such a domain name, which requires\n"		\
	"server queries.\n"																										\
	"\n"																													\
	"Test Case #2: Resolve a domain name with\n"																			\
	"\n"																													\
	"    2 CNAME records, 4 A records, and 4 AAAA records\n"																\
	"\n"																													\
	"to its IPv4 and IPv6 addresses. A preliminary iteration resolves a unique instance of such a domain name, which\n"		\
	"requires server queries. Each subsequent iteration resolves the same domain name as the preliminary iteration,\n"		\
	"which should ideally require no additional server queries, i.e., the results should come from the cache.\n"			\
	"\n"																													\
	"Unlike the preceding test case, this test case is concerned with DNSServiceGetAddrInfo() performance when the\n"		\
	"records of the domain name being resolved are already in the cache. Therefore, the time required to resolve the\n"		\
	"domain name in the preliminary iteration isn't counted in the performance stats.\n"									\
	"\n"																													\
	"Test Case #3: Each iteration resolves localhost to its IPv4 and IPv6 addresses.\n"

#define kGAIPerfSectionTitle_TestSuiteAdvanced		"Test Suite \"Advanced\""
#define kGAIPerfSectionText_TestSuiteAdvanced																				\
	"This test suite consists of 33 test cases. Test cases 1 through 32 can be described in the following way\n"			\
	"\n"																													\
	"Test Case #N (where N is in [1, 32] and odd): Resolve a domain name with\n"											\
	"\n"																													\
	"    N_c CNAME records, N_a A records, and N_a AAAA records\n"															\
	"\n"																													\
	"to its IPv4 and IPv6 addresses. Each iteration resolves a unique instance of such a domain name, which requires\n"		\
	"server queries.\n"																										\
	"\n"																													\
	"Test Case #N (where N is in [1, 32] and even): Resolve a domain name with\n"											\
	"\n"																													\
	"    N_c CNAME records, N_a A records, and N_a AAAA records\n"															\
	"\n"																													\
	"to its IPv4 and IPv6 addresses. A preliminary iteration resolves a unique instance of such a domain name, which\n"		\
	"requires server queries. Each subsequent iteration resolves the same domain name as the preliminary iteration,\n"		\
	"which should ideally require no additional server queries, i.e., the results should come from the cache.\n"			\
	"\n"																													\
	"Unlike the preceding test case, this test case is concerned with DNSServiceGetAddrInfo() performance when the\n"		\
	"records of the domain name being resolved are already in the cache. Therefore, the time required to resolve the\n"		\
	"domain name in the preliminary iteration isn't counted in the performance stats.\n"									\
	"\n"																													\
	"N_c and N_a take on the following values, depending on the value of N:\n"												\
	"\n"																													\
	"    N_c is 0 if N is in [1, 8].\n"																						\
	"    N_c is 1 if N is in [9, 16].\n"																					\
	"    N_c is 2 if N is in [17, 24].\n"																					\
	"    N_c is 4 if N is in [25, 32].\n"																					\
	"\n"																													\
	"    N_a is 1 if N mod 8 is 1 or 2.\n"																					\
	"    N_a is 2 if N mod 8 is 3 or 4.\n"																					\
	"    N_a is 4 if N mod 8 is 5 or 6.\n"																					\
	"    N_a is 8 if N mod 8 is 7 or 0.\n"																					\
	"\n"																													\
	"Finally,\n"																											\
	"\n"																													\
	"Test Case #33: Each iteration resolves localhost to its IPv4 and IPv6 addresses.\n"

static CLIOption		kGAIPerfOpts[] =
{
	StringOptionEx( 's', "suite",         &gGAIPerf_TestSuite,           "name", "Name of the predefined test suite to run.", true,
		"\n"
		"There are currently two predefined test suites, 'basic' and 'advanced', which are described below.\n"
		"\n"
	),
	StringOption(   'o', "output",        &gGAIPerf_OutputFilePath,      "path", "Path of the file to write test results to instead of standard output (stdout).", false ),
	StringOptionEx( 'f', "format",        &gGAIPerf_OutputFormat,        "format", "Specifies the test results output format. (default: json)", false,
		"\n"
		"Use 'json' for JavaScript Object Notation (JSON).\n"
		"Use 'xml' for property list XML version 1.0.\n"
		"Use 'binary' for property list binary version 1.0.\n"
		"\n"
	),
	BooleanOption(  'n', "appendNewline", &gGAIPerf_OutputAppendNewLine, "If the output format is JSON, output a trailing newline character." ),
	IntegerOption(   0 , "callDelay",     &gGAIPerf_CallDelayMs,         "ms", "Time to wait before calling DNSServiceGetAddrInfo() in milliseconds. (default: 10)", false ),
	IntegerOption(   0 , "responseDelay", &gGAIPerf_ServerDelayMs,       "ms", "Additional delay in milliseconds to have the test DNS server apply to responses. (default: 0)", false ),
	IntegerOption(  'i', "iterations",    &gGAIPerf_DefaultIterCount,    "count", "The default number of test case iterations. (default: 100)", false ),
	
	CLI_SECTION( kGAIPerfSectionTitle_TestSuiteBasic,		kGAIPerfSectionText_TestSuiteBasic ),
	CLI_SECTION( kGAIPerfSectionTitle_TestSuiteAdvanced,	kGAIPerfSectionText_TestSuiteAdvanced ),
	CLI_OPTION_END()
};

static CLIOption		kTestOpts[] =
{
	Command( "gaiperf", GAIPerfCmd, kGAIPerfOpts, "Run DNSServiceGetAddrInfo() performance tests.", false ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	SSDP Command Options
//===========================================================================================================================

static int				gSSDPDiscover_MX			= 1;
static const char *		gSSDPDiscover_ST			= "ssdp:all";
static int				gSSDPDiscover_ReceiveSecs	= 1;
static int				gSSDPDiscover_UseIPv4		= false;
static int				gSSDPDiscover_UseIPv6		= false;
static int				gSSDPDiscover_Verbose		= false;

static CLIOption		kSSDPDiscoverOpts[] =
{
	StringOption(  'i', "interface",	&gInterface,				"name or index", "Network interface by name or index.", true ),
	IntegerOption( 'm', "mx",			&gSSDPDiscover_MX,			"seconds", "MX value in search request, i.e., max response delay in seconds. (Default: 1 second)", false ),
	StringOption(  's', "st",			&gSSDPDiscover_ST,			"string", "ST value in search request, i.e., the search target. (Default: \"ssdp:all\")", false ),
	IntegerOption( 'r', "receiveTime",	&gSSDPDiscover_ReceiveSecs,	"seconds", "Amount of time to spend receiving responses. -1 means unlimited. (Default: 1 second)", false ),
	BooleanOption(  0 , "ipv4",			&gSSDPDiscover_UseIPv4,		"Use IPv4, i.e., multicast to 239.255.255.250:1900." ),
	BooleanOption(  0 , "ipv6",			&gSSDPDiscover_UseIPv6,		"Use IPv6, i.e., multicast to [ff02::c]:1900" ),
	BooleanOption( 'v', "verbose",		&gSSDPDiscover_Verbose,		"Prints the search request(s) that were sent." ),
	CLI_OPTION_END()
};

static void	SSDPDiscoverCmd( void );

static CLIOption		kSSDPOpts[] =
{
	Command( "discover", SSDPDiscoverCmd, kSSDPDiscoverOpts, "Crafts and multicasts an SSDP search message.", false ),
	CLI_OPTION_END()
};

#if( TARGET_OS_DARWIN )
//===========================================================================================================================
//	res_query Command Options
//===========================================================================================================================

static void	ResQueryCmd( void );

static const char *		gResQuery_Name			= NULL;
static const char *		gResQuery_Type			= NULL;
static const char *		gResQuery_Class			= NULL;
static int				gResQuery_UseLibInfo	= false;

static CLIOption		kResQueryOpts[] =
{
	StringOption( 'n', "name",		&gResQuery_Name,		"domain name",	"Full domain name of record to query.", true ),
	StringOption( 't', "type",		&gResQuery_Type,		"record type",	"Record type by name (e.g., TXT, SRV, etc.) or number.", true ),
	StringOption( 'c', "class",		&gResQuery_Class,		"record class",	"Record class by name or number. Default class is IN.", false ),
	BooleanOption( 0 , "libinfo",	&gResQuery_UseLibInfo,	"Use res_query from libinfo instead of libresolv." ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	dns_query Command Options
//===========================================================================================================================

static void ResolvDNSQueryCmd( void );

static const char *		gResolvDNSQuery_Name	= NULL;
static const char *		gResolvDNSQuery_Type	= NULL;
static const char *		gResolvDNSQuery_Class	= NULL;
static const char *		gResolvDNSQuery_Path	= NULL;

static CLIOption		kResolvDNSQueryOpts[] =
{
	StringOption( 'n', "name",	&gResolvDNSQuery_Name,	"domain name",	"Full domain name of record to query.", true ),
	StringOption( 't', "type",	&gResolvDNSQuery_Type,	"record type",	"Record type by name (e.g., TXT, SRV, etc.) or number.", true ),
	StringOption( 'c', "class",	&gResolvDNSQuery_Class,	"record class",	"Record class by name or number. Default class is IN.", false ),
	StringOption( 'p', "path",	&gResolvDNSQuery_Path,	"file path",	"The path argument to pass to dns_open() before calling dns_query(). Default value is NULL.", false ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	CFHost Command Options
//===========================================================================================================================

static void	CFHostCmd( void );

static const char *		gCFHost_Name		= NULL;
static int				gCFHost_WaitSecs	= 0;

static CLIOption		kCFHostOpts[] =
{
	StringOption(  'n', "name", &gCFHost_Name,     "hostname", "Hostname to resolve.", true ),
	IntegerOption( 'w', "wait", &gCFHost_WaitSecs, "seconds",  "Time in seconds to wait before a normal exit. (default: 0)", false ),
	CLI_OPTION_END()
};

static CLIOption		kLegacyOpts[] =
{
	Command( "res_query", ResQueryCmd,       kResQueryOpts,       "Uses res_query() from either libresolv or libinfo to query for a record.", true ),
	Command( "dns_query", ResolvDNSQueryCmd, kResolvDNSQueryOpts, "Uses dns_query() from libresolv to query for a record.", true ),
	Command( "cfhost",    CFHostCmd,         kCFHostOpts,         "Uses CFHost to resolve a hostname.", true ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	DNSConfigAdd Command Options
//===========================================================================================================================

static void	DNSConfigAddCmd( void );

static CFStringRef		gDNSConfigAdd_ID			= NULL;
static char **			gDNSConfigAdd_IPAddrArray	= NULL;
static size_t			gDNSConfigAdd_IPAddrCount	= 0;
static char **			gDNSConfigAdd_DomainArray	= NULL;
static size_t			gDNSConfigAdd_DomainCount	= 0;
static const char *		gDNSConfigAdd_Interface		= NULL;

static CLIOption		kDNSConfigAddOpts[] =
{
	CFStringOption(     0 , "id",        &gDNSConfigAdd_ID,                                      "ID", "Arbitrary ID to use for resolver entry.", true ),
	MultiStringOption( 'a', "address",   &gDNSConfigAdd_IPAddrArray, &gDNSConfigAdd_IPAddrCount, "IP address", "DNS server IP address(es). Can be specified more than once.", true ),
	MultiStringOption( 'd', "domain",    &gDNSConfigAdd_DomainArray, &gDNSConfigAdd_DomainCount, "domain", "Specific domain(s) for the resolver entry. Can be specified more than once.", false ),
	StringOption(      'i', "interface", &gDNSConfigAdd_Interface,                               "interface name", "Specific interface for the resolver entry.", false ),
	
	CLI_SECTION( "Notes", "Run 'scutil -d -v --dns' to see the current DNS configuration. See scutil(8) man page for more details.\n" ),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	DNSConfigRemove Command Options
//===========================================================================================================================

static void	DNSConfigRemoveCmd( void );

static CFStringRef		gDNSConfigRemove_ID = NULL;

static CLIOption		kDNSConfigRemoveOpts[] =
{
	CFStringOption( 0, "id", &gDNSConfigRemove_ID, "ID", "ID of resolver entry to remove.", true ),
	
	CLI_SECTION( "Notes", "Run 'scutil -d -v --dns' to see the current DNS configuration. See scutil(8) man page for more details.\n" ),
	CLI_OPTION_END()
};

static CLIOption		kDNSConfigOpts[] =
{
	Command( "add",    DNSConfigAddCmd,    kDNSConfigAddOpts,    "Add a supplemental resolver entry to the system's DNS configuration.", true ),
	Command( "remove", DNSConfigRemoveCmd, kDNSConfigRemoveOpts, "Remove a supplemental resolver entry from the system's DNS configuration.", true ),
	CLI_OPTION_END()
};
#endif	// TARGET_OS_DARWIN

//===========================================================================================================================
//	Command Table
//===========================================================================================================================

static OSStatus	VersionOptionCallback( CLIOption *inOption, const char *inArg, int inUnset );

static void	BrowseCmd( void );
static void	GetAddrInfoCmd( void );
static void	QueryRecordCmd( void );
static void	RegisterCmd( void );
static void	RegisterRecordCmd( void );
static void	ResolveCmd( void );
static void	ReconfirmCmd( void );
static void	GetAddrInfoPOSIXCmd( void );
static void	ReverseLookupCmd( void );
static void	PortMappingCmd( void );
static void	BrowseAllCmd( void );
static void	GetAddrInfoStressCmd( void );
static void	DNSQueryCmd( void );
#if( DNSSDUTIL_INCLUDE_DNSCRYPT )
static void	DNSCryptCmd( void );
#endif
static void	MDNSQueryCmd( void );
static void	PIDToUUIDCmd( void );
static void	DaemonVersionCmd( void );

static CLIOption		kGlobalOpts[] =
{
	CLI_OPTION_CALLBACK_EX( 'V', "version", VersionOptionCallback, NULL, NULL,
		kCLIOptionFlags_NoArgument | kCLIOptionFlags_GlobalOnly, "Displays the version of this tool.", NULL ),
	CLI_OPTION_HELP(),
	
	// Common commands.
	
	Command( "browse",				BrowseCmd,				kBrowseOpts,			"Uses DNSServiceBrowse() to browse for one or more service types.", false ),
	Command( "getAddrInfo",			GetAddrInfoCmd,			kGetAddrInfoOpts,		"Uses DNSServiceGetAddrInfo() to resolve a hostname to IP addresses.", false ),
	Command( "queryRecord",			QueryRecordCmd,			kQueryRecordOpts,		"Uses DNSServiceQueryRecord() to query for an arbitrary DNS record.", false ),
	Command( "register",			RegisterCmd,			kRegisterOpts,			"Uses DNSServiceRegister() to register a service.", false ),
	Command( "registerRecord",		RegisterRecordCmd,		kRegisterRecordOpts,	"Uses DNSServiceRegisterRecord() to register a record.", false ),
	Command( "resolve",				ResolveCmd,				kResolveOpts,			"Uses DNSServiceResolve() to resolve a service.", false ),
	Command( "reconfirm",			ReconfirmCmd,			kReconfirmOpts,			"Uses DNSServiceReconfirmRecord() to reconfirm a record.", false ),
	Command( "getaddrinfo-posix",	GetAddrInfoPOSIXCmd,	kGetAddrInfoPOSIXOpts,	"Uses getaddrinfo() to resolve a hostname to IP addresses.", false ),
	Command( "reverseLookup",		ReverseLookupCmd,		kReverseLookupOpts,		"Uses DNSServiceQueryRecord() to perform a reverse IP address lookup.", false ),
	Command( "portMapping",			PortMappingCmd,			kPortMappingOpts,		"Uses DNSServiceNATPortMappingCreate() to create a port mapping.", false ),
	Command( "browseAll",			BrowseAllCmd,			kBrowseAllOpts,			"Browse and resolve all (or specific) services and, optionally, attempt connections.", false ),
	
	// Uncommon commands.
	
	Command( "getnameinfo",			GetNameInfoCmd,			kGetNameInfoOpts,		"Calls getnameinfo() and prints results.", true ),
	Command( "getAddrInfoStress",	GetAddrInfoStressCmd,	kGetAddrInfoStressOpts,	"Runs DNSServiceGetAddrInfo() stress testing.", true ),
	Command( "DNSQuery",			DNSQueryCmd,			kDNSQueryOpts,			"Crafts and sends a DNS query.", true ),
#if( DNSSDUTIL_INCLUDE_DNSCRYPT )
	Command( "DNSCrypt",			DNSCryptCmd,			kDNSCryptOpts,			"Crafts and sends a DNSCrypt query.", true ),
#endif
	Command( "mDNSQuery",			MDNSQueryCmd,			kMDNSQueryOpts,			"Crafts and sends an mDNS query over the specified interface.", true ),
	Command( "pid2uuid",			PIDToUUIDCmd,			kPIDToUUIDOpts,			"Prints the UUID of a process.", true ),
	Command( "server",				DNSServerCmd,			kDNSServerOpts,			"DNS server for testing.", true ),
	Command( "test",				NULL,					kTestOpts,				"Commands for testing DNS-SD.", true ),
	Command( "ssdp",				NULL,					kSSDPOpts,				"Commands for testing Simple Service Discovery Protocol (SSDP).", true ),
#if( TARGET_OS_DARWIN )
	Command( "legacy",				NULL,					kLegacyOpts,			"Commands for legacy non-DNS-SD API.", true ),
	Command( "dnsconfig",			NULL,					kDNSConfigOpts,			"Add/remove a supplemental resolver entry to/from the system's DNS configuration.", true ),
#endif
	Command( "daemonVersion",		DaemonVersionCmd,		NULL,					"Prints the version of the DNS-SD daemon.", true ),
	
	CLI_COMMAND_HELP(),
	CLI_OPTION_END()
};

//===========================================================================================================================
//	Helper Prototypes
//===========================================================================================================================

#define kExitReason_OneShotDone				"one-shot done"
#define kExitReason_ReceivedResponse		"received response"
#define kExitReason_SIGINT					"interrupt signal"
#define kExitReason_Timeout					"timeout"
#define kExitReason_TimeLimit				"time limit"

static void	Exit( void *inContext ) ATTRIBUTE_NORETURN;

static int
	PrintFTimestampHandler(
		PrintFContext *	inContext,
		PrintFFormat *	inFormat,
		PrintFVAList *	inArgs,
		void *			inUserContext );
static int
	PrintFDNSMessageHandler(
		PrintFContext *	inContext,
		PrintFFormat *	inFormat,
		PrintFVAList *	inArgs,
		void *			inUserContext );

static DNSServiceFlags	GetDNSSDFlagsFromOpts( void );

typedef enum
{
	kConnectionType_None			= 0,
	kConnectionType_Normal			= 1,
	kConnectionType_DelegatePID		= 2,
	kConnectionType_DelegateUUID	= 3
	
}	ConnectionType;

typedef struct
{
	ConnectionType		type;
	union
	{
		int32_t			pid;
		uint8_t			uuid[ 16 ];
		
	}	delegate;
	
}	ConnectionDesc;

static OSStatus
	CreateConnectionFromArgString(
		const char *			inString,
		dispatch_queue_t		inQueue,
		DNSServiceRef *			outSDRef,
		ConnectionDesc *		outDesc );
static OSStatus			InterfaceIndexFromArgString( const char *inString, uint32_t *outIndex );
static OSStatus			RecordDataFromArgString( const char *inString, uint8_t **outDataPtr, size_t *outDataLen );
static OSStatus			RecordTypeFromArgString( const char *inString, uint16_t *outValue );
static OSStatus			RecordClassFromArgString( const char *inString, uint16_t *outValue );

#define kInterfaceNameBufLen		( Max( IF_NAMESIZE, 16 ) + 1 )

static char *			InterfaceIndexToName( uint32_t inIfIndex, char inNameBuf[ kInterfaceNameBufLen ] );
static const char *		RecordTypeToString( unsigned int inValue );

static OSStatus
	DNSMessageExtractDomainName(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inNamePtr,
		uint8_t				inBuf[ kDomainNameLengthMax ],
		const uint8_t **	outNextPtr );
static OSStatus
	DNSMessageExtractDomainNameString(
		const void *		inMsgPtr,
		size_t				inMsgLen,
		const void *		inNamePtr,
		char				inBuf[ kDNSServiceMaxDomainName ],
		const uint8_t **	outNextPtr );
static OSStatus
	DNSMessageExtractRecord(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inPtr,
		uint8_t				inNameBuf[ kDomainNameLengthMax ],
		uint16_t *			outType,
		uint16_t *			outClass,
		uint32_t *			outTTL,
		const uint8_t **	outRDataPtr,
		size_t *			outRDataLen,
		const uint8_t **	outPtr );
static OSStatus	DNSMessageGetAnswerSection( const uint8_t *inMsgPtr, size_t inMsgLen, const uint8_t **outPtr );
static OSStatus
	DNSRecordDataToString(
		const void *	inRDataPtr,
		size_t			inRDataLen,
		unsigned int	inRDataType,
		const void *	inMsgPtr,
		size_t			inMsgLen,
		char **			outString );
static OSStatus
	DomainNameAppendString(
		uint8_t			inDomainName[ kDomainNameLengthMax ],
		const char *	inString,
		uint8_t **		outEndPtr );
static Boolean	DomainNameEqual( const uint8_t *inName1, const uint8_t *inName2 );
static size_t	DomainNameLength( const uint8_t *inName );
static OSStatus
	DomainNameFromString(
		uint8_t			inDomainName[ kDomainNameLengthMax ],
		const char *	inString,
		uint8_t **		outEndPtr );
static OSStatus
	DomainNameToString(
		const uint8_t *		inDomainName,
		const uint8_t *		inEnd,
		char				inBuf[ kDNSServiceMaxDomainName ],
		const uint8_t **	outNextPtr );

static OSStatus
	DNSMessageToText(
		const uint8_t *	inMsgPtr,
		size_t			inMsgLen,
		Boolean			inIsMDNS,
		Boolean			inPrintRaw,
		char **			outText );

#define kDNSQueryMessageMaxLen		( kDNSHeaderLength + kDomainNameLengthMax + 4 )

static OSStatus
	WriteDNSQueryMessage(
		uint8_t			inMsg[ kDNSQueryMessageMaxLen ],
		uint16_t		inMsgID,
		uint16_t		inFlags,
		const char *	inQName,
		uint16_t		inQType,
		uint16_t		inQClass,
		size_t *		outMsgLen );

// Dispatch helpers

typedef void ( *DispatchHandler )( void *inContext );

static OSStatus
	DispatchSignalSourceCreate(
		int					inSignal,
		DispatchHandler		inEventHandler,
		void *				inContext,
		dispatch_source_t *	outSource );
static OSStatus
	DispatchSocketSourceCreate(
		SocketRef				inSock,
		dispatch_source_type_t	inType,
		dispatch_queue_t		inQueue,
		DispatchHandler			inEventHandler,
		DispatchHandler			inCancelHandler,
		void *					inContext,
		dispatch_source_t *		outSource );

#define DispatchReadSourceCreate( SOCK, QUEUE, EVENT_HANDLER, CANCEL_HANDLER, CONTEXT, OUT_SOURCE ) \
	DispatchSocketSourceCreate( SOCK, DISPATCH_SOURCE_TYPE_READ, QUEUE, EVENT_HANDLER, CANCEL_HANDLER, CONTEXT, OUT_SOURCE )

#define DispatchWriteSourceCreate( SOCK, QUEUE, EVENT_HANDLER, CANCEL_HANDLER, CONTEXT, OUT_SOURCE ) \
	DispatchSocketSourceCreate( SOCK, DISPATCH_SOURCE_TYPE_WRITE, QUEUE, EVENT_HANDLER, CANCEL_HANDLER, CONTEXT, OUT_SOURCE )

static OSStatus
	DispatchTimerCreate(
		dispatch_time_t		inStart,
		uint64_t			inIntervalNs,
		uint64_t			inLeewayNs,
		dispatch_queue_t	inQueue,
		DispatchHandler		inEventHandler,
		DispatchHandler		inCancelHandler,
		void *				inContext,
		dispatch_source_t *	outTimer );
static OSStatus
	DispatchProcessMonitorCreate(
		pid_t				inPID,
		unsigned long		inFlags,
		dispatch_queue_t	inQueue,
		DispatchHandler		inEventHandler,
		DispatchHandler		inCancelHandler,
		void *				inContext,
		dispatch_source_t *	outMonitor );

static const char *	ServiceTypeDescription( const char *inName );

typedef struct
{
	SocketRef		sock;			// Socket.
	void *			userContext;	// User context.
	int32_t			refCount;		// Reference count.
	
}	SocketContext;

static OSStatus			SocketContextCreate( SocketRef inSock, void * inUserContext, SocketContext **outContext );
static SocketContext *	SocketContextRetain( SocketContext *inContext );
static void				SocketContextRelease( SocketContext *inContext );
static void				SocketContextCancelHandler( void *inContext );

#define ForgetSocketContext( X )	ForgetCustom( X, SocketContextRelease )

static OSStatus		StringToInt32( const char *inString, int32_t *outValue );
static OSStatus		StringToUInt32( const char *inString, uint32_t *outValue );
static OSStatus		StringToLongLong( const char *inString, long long *outValue );
static OSStatus		StringToARecordData( const char *inString, uint8_t **outPtr, size_t *outLen );
static OSStatus		StringToAAAARecordData( const char *inString, uint8_t **outPtr, size_t *outLen );
static OSStatus		StringToDomainName( const char *inString, uint8_t **outPtr, size_t *outLen );
#if( TARGET_OS_DARWIN )
static OSStatus		GetDefaultDNSServer( sockaddr_ip *outAddr );
#endif
static OSStatus
	_ServerSocketOpenEx2( 
		int				inFamily, 
		int				inType, 
		int				inProtocol, 
		const void *	inAddr, 
		int				inPort, 
		int *			outPort, 
		int				inRcvBufSize, 
		Boolean			inNoPortReuse,
		SocketRef *		outSock );

typedef uint64_t		MicroTime64;

static MicroTime64	GetCurrentMicroTime( void );	// Gets the number of milliseconds since 1970-01-01T00:00:00Z

#define AddRmvString( X )		( ( (X) & kDNSServiceFlagsAdd ) ? "Add" : "Rmv" )
#define Unused( X )				(void)(X)

//===========================================================================================================================
//	main
//===========================================================================================================================

int	main( int argc, const char **argv )
{
	OSStatus		err;
	
	// Route DebugServices logging output to stderr.
	
	dlog_control( "DebugServices:output=file;stderr" );
	
	PrintFRegisterExtension( "du:time",   PrintFTimestampHandler,  NULL );
	PrintFRegisterExtension( "du:dnsmsg", PrintFDNSMessageHandler, NULL );
	CLIInit( argc, argv );
	err = CLIParse( kGlobalOpts, kCLIFlags_None );
	if( err ) exit( 1 );
	
	return( gExitCode );
}

//===========================================================================================================================
//	VersionOptionCallback
//===========================================================================================================================

static OSStatus	VersionOptionCallback( CLIOption *inOption, const char *inArg, int inUnset )
{
	const char *		srcVers;
#if( MDNSRESPONDER_PROJECT )
	char				srcStr[ 16 ];
#endif
	
	Unused( inOption );
	Unused( inArg );
	Unused( inUnset );
	
#if( MDNSRESPONDER_PROJECT )
	srcVers = SourceVersionToCString( _DNS_SD_H, srcStr );
#else
	srcVers = DNSSDUTIL_SOURCE_VERSION;
#endif
	FPrintF( stdout, "%s version %v (%s)\n", gProgramName, kDNSSDUtilNumVersion, srcVers );
	
	return( kEndingErr );
}

//===========================================================================================================================
//	BrowseCmd
//===========================================================================================================================

typedef struct BrowseResolveOp		BrowseResolveOp;

struct BrowseResolveOp
{
	BrowseResolveOp *		next;			// Next resolve operation in list.
	DNSServiceRef			sdRef;			// sdRef of the DNSServiceResolve or DNSServiceQueryRecord operation.
	char *					fullName;		// Full name of the service to resolve.
	uint32_t				interfaceIndex;	// Interface index of the DNSServiceResolve or DNSServiceQueryRecord operation.
};

typedef struct
{
	DNSServiceRef			mainRef;			// Main sdRef for shared connection.
	DNSServiceRef *			opRefs;				// Array of sdRefs for individual Browse operarions.
	size_t					opRefsCount;		// Count of array of sdRefs for non-shared connections.
	const char *			domain;				// Domain for DNSServiceBrowse operation(s).
	DNSServiceFlags			flags;				// Flags for DNSServiceBrowse operation(s).
	char **					serviceTypes;		// Array of service types to browse for.
	size_t					serviceTypesCount;	// Count of array of service types to browse for.
	int						timeLimitSecs;		// Time limit of DNSServiceBrowse operation in seconds.
	BrowseResolveOp *		resolveList;		// List of resolve and/or TXT record query operations.
	uint32_t				ifIndex;			// Interface index of DNSServiceBrowse operation(s).
	Boolean					printedHeader;		// True if results header has been printed.
	Boolean					doResolve;			// True if service instances are to be resolved.
	Boolean					doResolveTXTOnly;	// True if TXT records of service instances are to be queried.
	
}	BrowseContext;

static void		BrowsePrintPrologue( const BrowseContext *inContext );
static void		BrowseContextFree( BrowseContext *inContext );
static OSStatus	BrowseResolveOpCreate( const char *inFullName, uint32_t inInterfaceIndex, BrowseResolveOp **outOp );
static void		BrowseResolveOpFree( BrowseResolveOp *inOp );
static void DNSSD_API
	BrowseCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inError,
		const char *		inName,
		const char *		inRegType,
		const char *		inDomain,
		void *				inContext );
static void DNSSD_API
	BrowseResolveCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		const char *			inHostname,
		uint16_t				inPort,
		uint16_t				inTXTLen,
		const unsigned char *	inTXTPtr,
		void *					inContext );
static void DNSSD_API
	BrowseQueryRecordCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext );

static void	BrowseCmd( void )
{
	OSStatus				err;
	size_t					i;
	BrowseContext *			context			= NULL;
	dispatch_source_t		signalSource	= NULL;
	int						useMainConnection;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Create context.
	
	context = (BrowseContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->opRefs = (DNSServiceRef *) calloc( gBrowse_ServiceTypesCount, sizeof( DNSServiceRef ) );
	require_action( context->opRefs, exit, err = kNoMemoryErr );
	context->opRefsCount = gBrowse_ServiceTypesCount;
	
	// Check command parameters.
	
	if( gBrowse_TimeLimitSecs < 0 )
	{
		FPrintF( stderr, "Invalid time limit: %d seconds.\n", gBrowse_TimeLimitSecs );
		err = kParamErr;
		goto exit;
	}
	
	// Create main connection.
	
	if( gConnectionOpt )
	{
		err = CreateConnectionFromArgString( gConnectionOpt, dispatch_get_main_queue(), &context->mainRef, NULL );
		require_noerr_quiet( err, exit );
		useMainConnection = true;
	}
	else
	{
		useMainConnection = false;
	}
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	if( useMainConnection ) context->flags |= kDNSServiceFlagsShareConnection;
	
	// Get interface.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Set remaining parameters.
	
	context->serviceTypes		= gBrowse_ServiceTypes;
	context->serviceTypesCount	= gBrowse_ServiceTypesCount;
	context->domain				= gBrowse_Domain;
	context->doResolve			= gBrowse_DoResolve	? true : false;
	context->timeLimitSecs		= gBrowse_TimeLimitSecs;
	context->doResolveTXTOnly	= gBrowse_QueryTXT	? true : false;
	
	// Print prologue.
	
	BrowsePrintPrologue( context );
	
	// Start operation(s).
	
	for( i = 0; i < context->serviceTypesCount; ++i )
	{
		DNSServiceRef		sdRef;
		
		sdRef = useMainConnection ? context->mainRef : kBadDNSServiceRef;
		err = DNSServiceBrowse( &sdRef, context->flags, context->ifIndex, context->serviceTypes[ i ], context->domain,
			BrowseCallback, context );
		require_noerr( err, exit );
		
		context->opRefs[ i ] = sdRef;
		if( !useMainConnection )
		{
			err = DNSServiceSetDispatchQueue( context->opRefs[ i ], dispatch_get_main_queue() );
			require_noerr( err, exit );
		}
	}
	
	// Set time limit.
	
	if( context->timeLimitSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->timeLimitSecs ), dispatch_get_main_queue(),
			kExitReason_TimeLimit, Exit );
	}
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) BrowseContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	BrowsePrintPrologue
//===========================================================================================================================

static void	BrowsePrintPrologue( const BrowseContext *inContext )
{
	const int						timeLimitSecs	= inContext->timeLimitSecs;
	const char * const *			ptr				= (const char **) inContext->serviceTypes;
	const char * const * const		end				= (const char **) inContext->serviceTypes + inContext->serviceTypesCount;
	char							ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Flags:         %#{flags}\n",	inContext->flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:     %d (%s)\n",	(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Service types: %s",			*ptr++ );
	while( ptr < end ) FPrintF( stdout, ", %s",		*ptr++ );
	FPrintF( stdout, "\n" );
	FPrintF( stdout, "Domain:        %s\n",	inContext->domain ? inContext->domain : "<NULL> (default domains)" );
	FPrintF( stdout, "Time limit:    " );
	if( timeLimitSecs > 0 )	FPrintF( stdout, "%d second%?c\n", timeLimitSecs, timeLimitSecs != 1, 's' );
	else					FPrintF( stdout, "∞\n" );
	FPrintF( stdout, "Start time:    %{du:time}\n", NULL );
	FPrintF( stdout, "---\n" );
}

//===========================================================================================================================
//	BrowseContextFree
//===========================================================================================================================

static void	BrowseContextFree( BrowseContext *inContext )
{
	size_t		i;
	
	for( i = 0; i < inContext->opRefsCount; ++i )
	{
		DNSServiceForget( &inContext->opRefs[ i ] );
	}
	if( inContext->serviceTypes )
	{
		StringArray_Free( inContext->serviceTypes, inContext->serviceTypesCount );
		inContext->serviceTypes			= NULL;
		inContext->serviceTypesCount	= 0;
	}
	DNSServiceForget( &inContext->mainRef );
	free( inContext );
}

//===========================================================================================================================
//	BrowseResolveOpCreate
//===========================================================================================================================

static OSStatus	BrowseResolveOpCreate( const char *inFullName, uint32_t inInterfaceIndex, BrowseResolveOp **outOp )
{
	OSStatus				err;
	BrowseResolveOp *		resolveOp;
	
	resolveOp = (BrowseResolveOp *) calloc( 1, sizeof( *resolveOp ) );
	require_action( resolveOp, exit, err = kNoMemoryErr );
	
	resolveOp->fullName = strdup( inFullName );
	require_action( resolveOp->fullName, exit, err = kNoMemoryErr );
	
	resolveOp->interfaceIndex = inInterfaceIndex;
	
	*outOp = resolveOp;
	resolveOp = NULL;
	err = kNoErr;
	
exit:
	if( resolveOp ) BrowseResolveOpFree( resolveOp );
	return( err );
}

//===========================================================================================================================
//	BrowseResolveOpFree
//===========================================================================================================================

static void	BrowseResolveOpFree( BrowseResolveOp *inOp )
{
	DNSServiceForget( &inOp->sdRef );
	ForgetMem( &inOp->fullName );
	free( inOp );
}

//===========================================================================================================================
//	BrowseCallback
//===========================================================================================================================

static void DNSSD_API
	BrowseCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inError,
		const char *		inName,
		const char *		inRegType,
		const char *		inDomain,
		void *				inContext )
{
	BrowseContext * const		context = (BrowseContext *) inContext;
	OSStatus					err;
	BrowseResolveOp *			newOp = NULL;
	BrowseResolveOp **			p;
	char						fullName[ kDNSServiceMaxDomainName ];
	struct timeval				now;
	
	Unused( inSDRef );
	
	gettimeofday( &now, NULL );
	
	err = inError;
	require_noerr( err, exit );
	
	if( !context->printedHeader )
	{
		FPrintF( stdout, "%-26s  A/R Flags IF %-20s %-20s Instance Name\n", "Timestamp", "Domain", "Service Type" );
		context->printedHeader = true;
	}
	FPrintF( stdout, "%{du:time}  %-3s %5X %2d %-20s %-20s %s\n",
		&now, AddRmvString( inFlags ), inFlags, (int32_t) inInterfaceIndex, inDomain, inRegType, inName );
	
	if( !context->doResolve && !context->doResolveTXTOnly ) goto exit;
	
	err = DNSServiceConstructFullName( fullName, inName, inRegType, inDomain );
	require_noerr( err, exit );
	
	if( inFlags & kDNSServiceFlagsAdd )
	{
		DNSServiceRef		sdRef;
		DNSServiceFlags		flags;
		
		err = BrowseResolveOpCreate( fullName, inInterfaceIndex, &newOp );
		require_noerr( err, exit );
		
		if( context->mainRef )
		{
			sdRef = context->mainRef;
			flags = kDNSServiceFlagsShareConnection;
		}
		else
		{
			flags = 0;
		}
		if( context->doResolve )
		{
			err = DNSServiceResolve( &sdRef, flags, inInterfaceIndex, inName, inRegType, inDomain, BrowseResolveCallback,
				NULL );
			require_noerr( err, exit );
		}
		else
		{
			err = DNSServiceQueryRecord( &sdRef, flags, inInterfaceIndex, fullName, kDNSServiceType_TXT, kDNSServiceClass_IN,
				BrowseQueryRecordCallback, NULL );
			require_noerr( err, exit );
		}
		
		newOp->sdRef = sdRef;
		if( !context->mainRef )
		{
			err = DNSServiceSetDispatchQueue( newOp->sdRef, dispatch_get_main_queue() );
			require_noerr( err, exit );
		}
		for( p = &context->resolveList; *p; p = &( *p )->next ) {}
		*p = newOp;
		newOp = NULL;
	}
	else
	{
		BrowseResolveOp *		resolveOp;
		
		for( p = &context->resolveList; ( resolveOp = *p ) != NULL; p = &resolveOp->next )
		{
			if( ( resolveOp->interfaceIndex == inInterfaceIndex ) && ( strcasecmp( resolveOp->fullName, fullName ) == 0 ) )
			{
				break;
			}
		}
		if( resolveOp )
		{
			*p = resolveOp->next;
			BrowseResolveOpFree( resolveOp );
		}
	}
	
exit:
	if( newOp ) BrowseResolveOpFree( newOp );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	BrowseQueryRecordCallback
//===========================================================================================================================

static void DNSSD_API
	BrowseQueryRecordCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext )
{
	OSStatus			err;
	struct timeval		now;
	
	Unused( inSDRef );
	Unused( inClass );
	Unused( inTTL );
	Unused( inContext );
	
	gettimeofday( &now, NULL );
	
	err = inError;
	require_noerr( err, exit );
	require_action( inType == kDNSServiceType_TXT, exit, err = kTypeErr );
	
	FPrintF( stdout, "%{du:time}  %s %s TXT on interface %d\n    TXT: %#{txt}\n",
		&now, AddRmvString( inFlags ), inFullName, (int32_t) inInterfaceIndex, inRDataPtr, (size_t) inRDataLen );
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	BrowseResolveCallback
//===========================================================================================================================

static void DNSSD_API
	BrowseResolveCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		const char *			inHostname,
		uint16_t				inPort,
		uint16_t				inTXTLen,
		const unsigned char *	inTXTPtr,
		void *					inContext )
{
	struct timeval		now;
	char				errorStr[ 64 ];
	
	Unused( inSDRef );
	Unused( inFlags );
	Unused( inContext );
	
	gettimeofday( &now, NULL );
	
	if( inError ) SNPrintF( errorStr, sizeof( errorStr ), " error %#m", inError );
	
	FPrintF( stdout, "%{du:time}  %s can be reached at %s:%u (interface %d)%?s\n",
		&now, inFullName, inHostname, ntohs( inPort ), (int32_t) inInterfaceIndex, inError, errorStr );
	if( inTXTLen == 1 )
	{
		FPrintF( stdout, " TXT record: %#H\n", inTXTPtr, (int) inTXTLen, INT_MAX );
	}
	else
	{
		FPrintF( stdout, " TXT record: %#{txt}\n", inTXTPtr, (size_t) inTXTLen );
	}
}

//===========================================================================================================================
//	GetAddrInfoCmd
//===========================================================================================================================

typedef struct
{
	DNSServiceRef			mainRef;		// Main sdRef for shared connection.
	DNSServiceRef			opRef;			// sdRef for the DNSServiceGetAddrInfo operation.
	const char *			name;			// Hostname to resolve.
	DNSServiceFlags			flags;			// Flags argument for DNSServiceGetAddrInfo().
	DNSServiceProtocol		protocols;		// Protocols argument for DNSServiceGetAddrInfo().
	uint32_t				ifIndex;		// Interface index argument for DNSServiceGetAddrInfo().
	int						timeLimitSecs;	// Time limit for the DNSServiceGetAddrInfo() operation in seconds.
	Boolean					printedHeader;	// True if the results header has been printed.
	Boolean					oneShotMode;	// True if command is done after the first set of results (one-shot mode).
	Boolean					needIPv4;		// True if in one-shot mode and an IPv4 result is needed.
	Boolean					needIPv6;		// True if in one-shot mode and an IPv6 result is needed.
	
}	GetAddrInfoContext;

static void	GetAddrInfoPrintPrologue( const GetAddrInfoContext *inContext );
static void	GetAddrInfoContextFree( GetAddrInfoContext *inContext );
static void DNSSD_API
	GetAddrInfoCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext );

static void	GetAddrInfoCmd( void )
{
	OSStatus					err;
	DNSServiceRef				sdRef;
	GetAddrInfoContext *		context			= NULL;
	dispatch_source_t			signalSource	= NULL;
	int							useMainConnection;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Check command parameters.
	
	if( gGetAddrInfo_TimeLimitSecs < 0 )
	{
		FPrintF( stderr, "Invalid time limit: %d s.\n", gGetAddrInfo_TimeLimitSecs );
		err = kParamErr;
		goto exit;
	}
	
	// Create context.
	
	context = (GetAddrInfoContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	// Create main connection.
	
	if( gConnectionOpt )
	{
		err = CreateConnectionFromArgString( gConnectionOpt, dispatch_get_main_queue(), &context->mainRef, NULL );
		require_noerr_quiet( err, exit );
		useMainConnection = true;
	}
	else
	{
		useMainConnection = false;
	}
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	if( useMainConnection ) context->flags |= kDNSServiceFlagsShareConnection;
	
	// Get interface.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Set remaining parameters.
	
	context->name			= gGetAddrInfo_Name;
	context->timeLimitSecs	= gGetAddrInfo_TimeLimitSecs;
	if( gGetAddrInfo_ProtocolIPv4 ) context->protocols |= kDNSServiceProtocol_IPv4;
	if( gGetAddrInfo_ProtocolIPv6 ) context->protocols |= kDNSServiceProtocol_IPv6;
	if( gGetAddrInfo_OneShot )
	{
		context->oneShotMode	= true;
		context->needIPv4		= ( gGetAddrInfo_ProtocolIPv4 || !gGetAddrInfo_ProtocolIPv6 ) ? true : false;
		context->needIPv6		= ( gGetAddrInfo_ProtocolIPv6 || !gGetAddrInfo_ProtocolIPv4 ) ? true : false;
	}
	
	// Print prologue.
	
	GetAddrInfoPrintPrologue( context );
	
	// Start operation.
	
	sdRef = useMainConnection ? context->mainRef : kBadDNSServiceRef;
	err = DNSServiceGetAddrInfo( &sdRef, context->flags, context->ifIndex, context->protocols, context->name,
		GetAddrInfoCallback, context );
	require_noerr( err, exit );
	
	context->opRef = sdRef;
	if( !useMainConnection )
	{
		err = DNSServiceSetDispatchQueue( context->opRef, dispatch_get_main_queue() );
		require_noerr( err, exit );
	}
	
	// Set time limit.
	
	if( context->timeLimitSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->timeLimitSecs ), dispatch_get_main_queue(),
			kExitReason_TimeLimit, Exit );
	}
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) GetAddrInfoContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	GetAddrInfoPrintPrologue
//===========================================================================================================================

static void	GetAddrInfoPrintPrologue( const GetAddrInfoContext *inContext )
{
	const int		timeLimitSecs = inContext->timeLimitSecs;
	char			ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Flags:      %#{flags}\n",		inContext->flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:  %d (%s)\n",		(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Protocols:  %#{flags}\n",		inContext->protocols, kDNSServiceProtocolDescriptors );
	FPrintF( stdout, "Name:       %s\n",			inContext->name );
	FPrintF( stdout, "Mode:       %s\n",			inContext->oneShotMode ? "one-shot" : "continuous" );
	FPrintF( stdout, "Time limit: " );
	if( timeLimitSecs > 0 )	FPrintF( stdout, "%d second%?c\n", timeLimitSecs, timeLimitSecs != 1, 's' );
	else					FPrintF( stdout, "∞\n" );
	FPrintF( stdout, "Start time: %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
}

//===========================================================================================================================
//	GetAddrInfoContextFree
//===========================================================================================================================

static void	GetAddrInfoContextFree( GetAddrInfoContext *inContext )
{
	DNSServiceForget( &inContext->opRef );
	DNSServiceForget( &inContext->mainRef );
	free( inContext );
}

//===========================================================================================================================
//	GetAddrInfoCallback
//===========================================================================================================================

static void DNSSD_API
	GetAddrInfoCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext )
{
	GetAddrInfoContext * const		context = (GetAddrInfoContext *) inContext;
	struct timeval					now;
	OSStatus						err;
	const char *					addrStr;
	char							addrStrBuf[ kSockAddrStringMaxSize ];
	
	Unused( inSDRef );
	
	gettimeofday( &now, NULL );
	
	switch( inError )
	{
		case kDNSServiceErr_NoError:
		case kDNSServiceErr_NoSuchRecord:
			err = kNoErr;
			break;
		
		case kDNSServiceErr_Timeout:
			Exit( kExitReason_Timeout );
		
		default:
			err = inError;
			goto exit;
	}
	
	if( ( inSockAddr->sa_family != AF_INET ) && ( inSockAddr->sa_family != AF_INET6 ) )
	{
		dlogassert( "Unexpected address family: %d", inSockAddr->sa_family );
		err = kTypeErr;
		goto exit;
	}
	
	if( !inError )
	{
		err = SockAddrToString( inSockAddr, kSockAddrStringFlagsNone, addrStrBuf );
		require_noerr( err, exit );
		addrStr = addrStrBuf;
	}
	else
	{
		addrStr = ( inSockAddr->sa_family == AF_INET ) ? "No Such Record (A)" : "No Such Record (AAAA)";
	}
	
	if( !context->printedHeader )
	{
		FPrintF( stdout, "%-26s  A/R Flags IF %-32s %-38s %6s\n", "Timestamp", "Hostname", "Address", "TTL" );
		context->printedHeader = true;
	}
	FPrintF( stdout, "%{du:time}  %s %5X %2d %-32s %-38s %6u\n",
		&now, AddRmvString( inFlags ), inFlags, (int32_t) inInterfaceIndex, inHostname, addrStr, inTTL );
	
	if( context->oneShotMode )
	{
		if( inFlags & kDNSServiceFlagsAdd )
		{
			if( inSockAddr->sa_family == AF_INET )	context->needIPv4 = false;
			else									context->needIPv6 = false;
		}
		if( !( inFlags & kDNSServiceFlagsMoreComing ) && !context->needIPv4 && !context->needIPv6 )
		{
			Exit( kExitReason_OneShotDone );
		}
	}
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	QueryRecordCmd
//===========================================================================================================================

typedef struct
{
	DNSServiceRef		mainRef;		// Main sdRef for shared connection.
	DNSServiceRef		opRef;			// sdRef for the DNSServiceQueryRecord operation.
	const char *		recordName;		// Resource record name argument for DNSServiceQueryRecord().
	DNSServiceFlags		flags;			// Flags argument for DNSServiceQueryRecord().
	uint32_t			ifIndex;		// Interface index argument for DNSServiceQueryRecord().
	int					timeLimitSecs;	// Time limit for the DNSServiceQueryRecord() operation in seconds.
	uint16_t			recordType;		// Resource record type argument for DNSServiceQueryRecord().
	Boolean				printedHeader;	// True if the results header was printed.
	Boolean				oneShotMode;	// True if command is done after the first set of results (one-shot mode).
	Boolean				gotRecord;		// True if in one-shot mode and received at least one record of the desired type.
	Boolean				printRawRData;	// True if RDATA results are not to be formatted when printed.
	
}	QueryRecordContext;

static void	QueryRecordPrintPrologue( const QueryRecordContext *inContext );
static void	QueryRecordContextFree( QueryRecordContext *inContext );
static void DNSSD_API
	QueryRecordCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext );

static void	QueryRecordCmd( void )
{
	OSStatus					err;
	DNSServiceRef				sdRef;
	QueryRecordContext *		context			= NULL;
	dispatch_source_t			signalSource	= NULL;
	int							useMainConnection;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Create context.
	
	context = (QueryRecordContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	// Check command parameters.
	
	if( gQueryRecord_TimeLimitSecs < 0 )
	{
		FPrintF( stderr, "Invalid time limit: %d seconds.\n", gQueryRecord_TimeLimitSecs );
		err = kParamErr;
		goto exit;
	}
	
	// Create main connection.
	
	if( gConnectionOpt )
	{
		err = CreateConnectionFromArgString( gConnectionOpt, dispatch_get_main_queue(), &context->mainRef, NULL );
		require_noerr_quiet( err, exit );
		useMainConnection = true;
	}
	else
	{
		useMainConnection = false;
	}
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	if( useMainConnection ) context->flags |= kDNSServiceFlagsShareConnection;
	
	// Get interface.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Get record type.
	
	err = RecordTypeFromArgString( gQueryRecord_Type, &context->recordType );
	require_noerr( err, exit );
	
	// Set remaining parameters.
	
	context->recordName		= gQueryRecord_Name;
	context->timeLimitSecs	= gQueryRecord_TimeLimitSecs;
	context->oneShotMode	= gQueryRecord_OneShot	? true : false;
	context->printRawRData	= gQueryRecord_RawRData	? true : false;
	
	// Print prologue.
	
	QueryRecordPrintPrologue( context );
	
	// Start operation.
	
	sdRef = useMainConnection ? context->mainRef : kBadDNSServiceRef;
	err = DNSServiceQueryRecord( &sdRef, context->flags, context->ifIndex, context->recordName, context->recordType,
		kDNSServiceClass_IN, QueryRecordCallback, context );
	require_noerr( err, exit );
	
	context->opRef = sdRef;
	if( !useMainConnection )
	{
		err = DNSServiceSetDispatchQueue( context->opRef, dispatch_get_main_queue() );
		require_noerr( err, exit );
	}
	
	// Set time limit.
	
	if( context->timeLimitSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->timeLimitSecs ), dispatch_get_main_queue(), kExitReason_TimeLimit,
			Exit );
	}
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) QueryRecordContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	QueryRecordContextFree
//===========================================================================================================================

static void	QueryRecordContextFree( QueryRecordContext *inContext )
{
	DNSServiceForget( &inContext->opRef );
	DNSServiceForget( &inContext->mainRef );
	free( inContext );
}

//===========================================================================================================================
//	QueryRecordPrintPrologue
//===========================================================================================================================

static void	QueryRecordPrintPrologue( const QueryRecordContext *inContext )
{
	const int		timeLimitSecs = inContext->timeLimitSecs;
	char			ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Flags:       %#{flags}\n",	inContext->flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:   %d (%s)\n",		(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Name:        %s\n",			inContext->recordName );
	FPrintF( stdout, "Type:        %s (%u)\n",		RecordTypeToString( inContext->recordType ), inContext->recordType );
	FPrintF( stdout, "Mode:        %s\n",			inContext->oneShotMode ? "one-shot" : "continuous" );
	FPrintF( stdout, "Time limit:  " );
	if( timeLimitSecs > 0 )	FPrintF( stdout, "%d second%?c\n", timeLimitSecs, timeLimitSecs != 1, 's' );
	else					FPrintF( stdout, "∞\n" );
	FPrintF( stdout, "Start time:  %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
	
}

//===========================================================================================================================
//	QueryRecordCallback
//===========================================================================================================================

static void DNSSD_API
	QueryRecordCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext )
{
	QueryRecordContext * const		context		= (QueryRecordContext *) inContext;
	struct timeval					now;
	OSStatus						err;
	char *							rdataStr	= NULL;
	
	Unused( inSDRef );
	
	gettimeofday( &now, NULL );
	
	switch( inError )
	{
		case kDNSServiceErr_NoError:
		case kDNSServiceErr_NoSuchRecord:
			err = kNoErr;
			break;
		
		case kDNSServiceErr_Timeout:
			Exit( kExitReason_Timeout );
		
		default:
			err = inError;
			goto exit;
	}
	
	if( inError == kDNSServiceErr_NoSuchRecord )
	{
		ASPrintF( &rdataStr, "No Such Record" );
	}
	else
	{
		if( !context->printRawRData ) DNSRecordDataToString( inRDataPtr, inRDataLen, inType, NULL, 0, &rdataStr );
		if( !rdataStr )
		{
			ASPrintF( &rdataStr, "%#H", inRDataPtr, inRDataLen, INT_MAX );
			require_action( rdataStr, exit, err = kNoMemoryErr );
		}
	}
	
	if( !context->printedHeader )
	{
		FPrintF( stdout, "%-26s  A/R Flags IF %-32s %-5s %-5s %6s RData\n", "Timestamp", "Name", "Type", "Class", "TTL" );
		context->printedHeader = true;
	}
	FPrintF( stdout, "%{du:time}  %-3s %5X %2d %-32s %-5s %?-5s%?5u %6u %s\n",
		&now, AddRmvString( inFlags ), inFlags, (int32_t) inInterfaceIndex, inFullName, RecordTypeToString( inType ),
		( inClass == kDNSServiceClass_IN ), "IN", ( inClass != kDNSServiceClass_IN ), inClass, inTTL, rdataStr );
	
	if( context->oneShotMode )
	{
		if( ( inFlags & kDNSServiceFlagsAdd ) &&
			( ( context->recordType == kDNSServiceType_ANY ) || ( context->recordType == inType ) ) )
		{
			context->gotRecord = true;
		}
		if( !( inFlags & kDNSServiceFlagsMoreComing ) && context->gotRecord ) Exit( kExitReason_OneShotDone );
	}
	
exit:
	FreeNullSafe( rdataStr );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	RegisterCmd
//===========================================================================================================================

typedef struct
{
	DNSRecordRef		recordRef;	// Reference returned by DNSServiceAddRecord().
	uint8_t *			dataPtr;	// Record data.
	size_t				dataLen;	// Record data length.
	uint32_t			ttl;		// Record TTL value.
	uint16_t			type;		// Record type.
	
}	ExtraRecord;

typedef struct
{
	DNSServiceRef		opRef;				// sdRef for DNSServiceRegister operation.
	const char *		name;				// Service name argument for DNSServiceRegister().
	const char *		type;				// Service type argument for DNSServiceRegister().
	const char *		domain;				// Domain in which advertise the service.
	uint8_t *			txtPtr;				// Service TXT record data. (malloc'd)
	size_t				txtLen;				// Service TXT record data len.
	ExtraRecord *		extraRecords;		// Array of extra records to add to registered service.
	size_t				extraRecordsCount;	// Number of extra records.
	uint8_t *			updateTXTPtr;		// Pointer to record data for TXT record update. (malloc'd)
	size_t				updateTXTLen;		// Length of record data for TXT record update.
	uint32_t			updateTTL;			// TTL of updated TXT record.
	int					updateDelayMs;		// Post-registration TXT record update delay in milliseconds.
	DNSServiceFlags		flags;				// Flags argument for DNSServiceRegister().
	uint32_t			ifIndex;			// Interface index argument for DNSServiceRegister().
	int					lifetimeMs;			// Lifetime of the record registration in milliseconds.
	uint16_t			port;				// Service instance's port number.
	Boolean				printedHeader;		// True if results header was printed.
	Boolean				didRegister;		// True if service was registered.
	
}	RegisterContext;

static void	RegisterPrintPrologue( const RegisterContext *inContext );
static void	RegisterContextFree( RegisterContext *inContext );
static void DNSSD_API
	RegisterCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		DNSServiceErrorType	inError,
		const char *		inName,
		const char *		inType,
		const char *		inDomain,
		void *				inContext );
static void	RegisterUpdate( void *inContext );

static void	RegisterCmd( void )
{
	OSStatus				err;
	RegisterContext *		context			= NULL;
	dispatch_source_t		signalSource	= NULL;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Create context.
	
	context = (RegisterContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	// Check command parameters.
	
	if( ( gRegister_Port < 0 ) || ( gRegister_Port > UINT16_MAX ) )
	{
		FPrintF( stderr, "Port number %d is out-of-range.\n", gRegister_Port );
		err = kParamErr;
		goto exit;
	}
	
	if( ( gAddRecord_DataCount != gAddRecord_TypesCount ) || ( gAddRecord_TTLsCount != gAddRecord_TypesCount ) )
	{
		FPrintF( stderr, "There are missing additional record parameters.\n" );
		err = kParamErr;
		goto exit;
	}
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	
	// Get interface index.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Get TXT record data.
	
	if( gRegister_TXT )
	{
		err = RecordDataFromArgString( gRegister_TXT, &context->txtPtr, &context->txtLen );
		require_noerr_quiet( err, exit );
	}
	
	// Set remaining parameters.
	
	context->name		= gRegister_Name;
	context->type		= gRegister_Type;
	context->domain		= gRegister_Domain;
	context->port		= (uint16_t) gRegister_Port;
	context->lifetimeMs	= gRegister_LifetimeMs;
	
	if( gAddRecord_TypesCount > 0 )
	{
		size_t		i;
		
		context->extraRecords = (ExtraRecord *) calloc( gAddRecord_TypesCount, sizeof( ExtraRecord ) );
		require_action( context, exit, err = kNoMemoryErr );
		context->extraRecordsCount = gAddRecord_TypesCount;
		
		for( i = 0; i < gAddRecord_TypesCount; ++i )
		{
			ExtraRecord * const		extraRecord = &context->extraRecords[ i ];
			
			err = RecordTypeFromArgString( gAddRecord_Types[ i ], &extraRecord->type );
			require_noerr( err, exit );
			
			err = StringToUInt32( gAddRecord_TTLs[ i ], &extraRecord->ttl );
			if( err )
			{
				FPrintF( stderr, "Invalid TTL value: %s\n", gAddRecord_TTLs[ i ] );
				err = kParamErr;
				goto exit;
			}
			
			err = RecordDataFromArgString( gAddRecord_Data[ i ], &extraRecord->dataPtr, &extraRecord->dataLen );
			require_noerr_quiet( err, exit );
		}
	}
	
	if( gUpdateRecord_Data )
	{
		err = RecordDataFromArgString( gUpdateRecord_Data, &context->updateTXTPtr, &context->updateTXTLen );
		require_noerr_quiet( err, exit );
		
		context->updateTTL		= (uint32_t) gUpdateRecord_TTL;
		context->updateDelayMs	= gUpdateRecord_DelayMs;
	}
	
	// Print prologue.
	
	RegisterPrintPrologue( context );
	
	// Start operation.
	
	err = DNSServiceRegister( &context->opRef, context->flags, context->ifIndex, context->name, context->type,
		context->domain, NULL, htons( context->port ), (uint16_t) context->txtLen, context->txtPtr,
		RegisterCallback, context );
	ForgetMem( &context->txtPtr );
	require_noerr( err, exit );
	
	err = DNSServiceSetDispatchQueue( context->opRef, dispatch_get_main_queue() );
	require_noerr( err, exit );
	
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) RegisterContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	RegisterPrintPrologue
//===========================================================================================================================

static void	RegisterPrintPrologue( const RegisterContext *inContext )
{
	size_t		i;
	int			infinite;
	char		ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Flags:      %#{flags}\n",	inContext->flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:  %d (%s)\n",	(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Name:       %s\n",		inContext->name ? inContext->name : "<NULL>" );
	FPrintF( stdout, "Type:       %s\n",		inContext->type );
	FPrintF( stdout, "Domain:     %s\n",		inContext->domain ? inContext->domain : "<NULL> (default domains)" );
	FPrintF( stdout, "Port:       %u\n",		inContext->port );
	FPrintF( stdout, "TXT data:   %#{txt}\n",	inContext->txtPtr, inContext->txtLen );
	infinite = ( inContext->lifetimeMs < 0 ) ? true : false;
	FPrintF( stdout, "Lifetime:   %?s%?d ms\n",	infinite, "∞", !infinite, inContext->lifetimeMs );
	if( inContext->updateTXTPtr )
	{
		FPrintF( stdout, "\nUpdate record:\n" );
		FPrintF( stdout, "    Delay:    %d ms\n",	( inContext->updateDelayMs > 0 ) ? inContext->updateDelayMs : 0 );
		FPrintF( stdout, "    TTL:      %u%?s\n",
			inContext->updateTTL, inContext->updateTTL == 0, " (system will use a default value.)" );
		FPrintF( stdout, "    TXT data: %#{txt}\n",	inContext->updateTXTPtr, inContext->updateTXTLen );
	}
	if( inContext->extraRecordsCount > 0 ) FPrintF( stdout, "\n" );
	for( i = 0; i < inContext->extraRecordsCount; ++i )
	{
		const ExtraRecord *		record = &inContext->extraRecords[ i ];
		
		FPrintF( stdout, "Extra record %zu:\n",		i + 1 );
		FPrintF( stdout, "    Type:  %s (%u)\n",	RecordTypeToString( record->type ), record->type );
		FPrintF( stdout, "    TTL:   %u%?s\n",		record->ttl, record->ttl == 0, " (system will use a default value.)" );
		FPrintF( stdout, "    RData: %#H\n\n",		record->dataPtr, (int) record->dataLen, INT_MAX );
	}
	FPrintF( stdout, "Start time: %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
}

//===========================================================================================================================
//	RegisterContextFree
//===========================================================================================================================

static void	RegisterContextFree( RegisterContext *inContext )
{
	ExtraRecord *					record;
	const ExtraRecord * const		end = inContext->extraRecords + inContext->extraRecordsCount;
	
	DNSServiceForget( &inContext->opRef );
	ForgetMem( &inContext->txtPtr );
	for( record = inContext->extraRecords; record < end; ++record )
	{
		check( !record->recordRef );
		ForgetMem( &record->dataPtr );
	}
	ForgetMem( &inContext->extraRecords );
	ForgetMem( &inContext->updateTXTPtr );
	free( inContext );
}

//===========================================================================================================================
//	RegisterCallback
//===========================================================================================================================

static void DNSSD_API
	RegisterCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		DNSServiceErrorType	inError,
		const char *		inName,
		const char *		inType,
		const char *		inDomain,
		void *				inContext )
{
	RegisterContext * const		context = (RegisterContext *) inContext;
	OSStatus					err;
	struct timeval				now;
	
	Unused( inSDRef );
	
	gettimeofday( &now, NULL );
	
	if( !context->printedHeader )
	{
		FPrintF( stdout, "%-26s  A/R Flags Service\n", "Timestamp" );
		context->printedHeader = true;
	}
	FPrintF( stdout, "%{du:time}  %-3s %5X %s.%s%s %?#m\n",
		&now, AddRmvString( inFlags ), inFlags, inName, inType, inDomain, inError, inError );
	
	require_noerr_action_quiet( inError, exit, err = inError );
	
	if( !context->didRegister && ( inFlags & kDNSServiceFlagsAdd ) )
	{
		context->didRegister = true;
		if( context->updateTXTPtr )
		{
			if( context->updateDelayMs > 0 )
			{
				dispatch_after_f( dispatch_time_milliseconds( context->updateDelayMs ), dispatch_get_main_queue(),
					context, RegisterUpdate );
			}
			else
			{
				RegisterUpdate( context );
			}
		}
		if( context->extraRecordsCount > 0 )
		{
			ExtraRecord *					record;
			const ExtraRecord * const		end = context->extraRecords + context->extraRecordsCount;
			
			for( record = context->extraRecords; record < end; ++record )
			{
				err = DNSServiceAddRecord( context->opRef, &record->recordRef, 0, record->type,
					(uint16_t) record->dataLen, record->dataPtr, record->ttl );
				require_noerr( err, exit );
			}
		}
		if( context->lifetimeMs == 0 )
		{
			Exit( kExitReason_TimeLimit );
		}
		else if( context->lifetimeMs > 0 )
		{
			dispatch_after_f( dispatch_time_milliseconds( context->lifetimeMs ), dispatch_get_main_queue(),
				kExitReason_TimeLimit, Exit );
		}
	}
	err = kNoErr;
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	RegisterUpdate
//===========================================================================================================================

static void	RegisterUpdate( void *inContext )
{
	OSStatus					err;
	RegisterContext * const		context = (RegisterContext *) inContext;
	
	err = DNSServiceUpdateRecord( context->opRef, NULL, 0, (uint16_t) context->updateTXTLen, context->updateTXTPtr,
		context->updateTTL );
	require_noerr( err, exit );
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	RegisterRecordCmd
//===========================================================================================================================

typedef struct
{
	DNSServiceRef		conRef;			// sdRef to be initialized by DNSServiceCreateConnection().
	DNSRecordRef		recordRef;		// Registered record reference.
	const char *		recordName;		// Name of resource record.
	uint8_t *			dataPtr;		// Pointer to resource record data.
	size_t				dataLen;		// Length of resource record data.
	uint32_t			ttl;			// TTL value of resource record in seconds.
	uint32_t			ifIndex;		// Interface index argument for DNSServiceRegisterRecord().
	DNSServiceFlags		flags;			// Flags argument for DNSServiceRegisterRecord().
	int					lifetimeMs;		// Lifetime of the record registration in milliseconds.
	uint16_t			recordType;		// Resource record type.
	uint8_t *			updateDataPtr;	// Pointer to data for record update. (malloc'd)
	size_t				updateDataLen;	// Length of data for record update.
	uint32_t			updateTTL;		// TTL for updated record.
	int					updateDelayMs;	// Post-registration record update delay in milliseconds.
	Boolean				didRegister;	// True if the record was registered.
	
}	RegisterRecordContext;

static void	RegisterRecordPrintPrologue( const RegisterRecordContext *inContext );
static void	RegisterRecordContextFree( RegisterRecordContext *inContext );
static void DNSSD_API
	RegisterRecordCallback(
		DNSServiceRef		inSDRef,
		DNSRecordRef		inRecordRef,
		DNSServiceFlags		inFlags,
		DNSServiceErrorType	inError,
		void *				inContext );
static void	RegisterRecordUpdate( void *inContext );

static void	RegisterRecordCmd( void )
{
	OSStatus					err;
	RegisterRecordContext *		context			= NULL;
	dispatch_source_t			signalSource	= NULL;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Create context.
	
	context = (RegisterRecordContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	// Create connection.
	
	err = CreateConnectionFromArgString( gConnectionOpt, dispatch_get_main_queue(), &context->conRef, NULL );
	require_noerr_quiet( err, exit );
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	
	// Get interface.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Get record type.
	
	err = RecordTypeFromArgString( gRegisterRecord_Type, &context->recordType );
	require_noerr( err, exit );
	
	// Get record data.
	
	if( gRegisterRecord_Data )
	{
		err = RecordDataFromArgString( gRegisterRecord_Data, &context->dataPtr, &context->dataLen );
		require_noerr_quiet( err, exit );
	}
	
	// Set remaining parameters.
	
	context->recordName	= gRegisterRecord_Name;
	context->ttl		= (uint32_t) gRegisterRecord_TTL;
	context->lifetimeMs	= gRegisterRecord_LifetimeMs;
	
	// Get update data.
	
	if( gRegisterRecord_UpdateData )
	{
		err = RecordDataFromArgString( gRegisterRecord_UpdateData, &context->updateDataPtr, &context->updateDataLen );
		require_noerr_quiet( err, exit );
		
		context->updateTTL		= (uint32_t) gRegisterRecord_UpdateTTL;
		context->updateDelayMs	= gRegisterRecord_UpdateDelayMs;
	}
	
	// Print prologue.
	
	RegisterRecordPrintPrologue( context );
	
	// Start operation.
	
	err = DNSServiceRegisterRecord( context->conRef, &context->recordRef, context->flags, context->ifIndex,
		context->recordName, context->recordType, kDNSServiceClass_IN, (uint16_t) context->dataLen, context->dataPtr,
		context->ttl, RegisterRecordCallback, context );
	if( err )
	{
		FPrintF( stderr, "DNSServiceRegisterRecord() returned %#m\n", err );
		goto exit;
	}
	
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) RegisterRecordContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	RegisterRecordPrintPrologue
//===========================================================================================================================

static void	RegisterRecordPrintPrologue( const RegisterRecordContext *inContext )
{
	int			infinite;
	char		ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Flags:       %#{flags}\n",	inContext->flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:   %d (%s)\n",		(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Name:        %s\n",			inContext->recordName );
	FPrintF( stdout, "Type:        %s (%u)\n",		RecordTypeToString( inContext->recordType ), inContext->recordType );
	FPrintF( stdout, "TTL:         %u\n",			inContext->ttl );
	FPrintF( stdout, "Data:        %#H\n",			inContext->dataPtr, (int) inContext->dataLen, INT_MAX );
	infinite = ( inContext->lifetimeMs < 0 ) ? true : false;
	FPrintF( stdout, "Lifetime:    %?s%?d ms\n",	infinite, "∞", !infinite, inContext->lifetimeMs );
	if( inContext->updateDataPtr )
	{
		FPrintF( stdout, "\nUpdate record:\n" );
		FPrintF( stdout, "    Delay:    %d ms\n",	( inContext->updateDelayMs >= 0 ) ? inContext->updateDelayMs : 0 );
		FPrintF( stdout, "    TTL:      %u%?s\n",
			inContext->updateTTL, inContext->updateTTL == 0, " (system will use a default value.)" );
		FPrintF( stdout, "    RData:    %#H\n",		inContext->updateDataPtr, (int) inContext->updateDataLen, INT_MAX );
	}
	FPrintF( stdout, "Start time:  %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
}

//===========================================================================================================================
//	RegisterRecordContextFree
//===========================================================================================================================

static void	RegisterRecordContextFree( RegisterRecordContext *inContext )
{
	DNSServiceForget( &inContext->conRef );
	ForgetMem( &inContext->dataPtr );
	ForgetMem( &inContext->updateDataPtr );
	free( inContext );
}

//===========================================================================================================================
//	RegisterRecordCallback
//===========================================================================================================================

static void
	RegisterRecordCallback(
		DNSServiceRef		inSDRef,
		DNSRecordRef		inRecordRef,
		DNSServiceFlags		inFlags,
		DNSServiceErrorType	inError,
		void *				inContext )
{
	RegisterRecordContext *		context = (RegisterRecordContext *) inContext;
	struct timeval				now;
	
	Unused( inSDRef );
	Unused( inRecordRef );
	Unused( inFlags );
	Unused( context );
	
	gettimeofday( &now, NULL );
	FPrintF( stdout, "%{du:time} Record registration result (error %#m)\n", &now, inError );
	
	if( !context->didRegister && !inError )
	{
		context->didRegister = true;
		if( context->updateDataPtr )
		{
			if( context->updateDelayMs > 0 )
			{
				dispatch_after_f( dispatch_time_milliseconds( context->updateDelayMs ), dispatch_get_main_queue(),
					context, RegisterRecordUpdate );
			}
			else
			{
				RegisterRecordUpdate( context );
			}
		}
		if( context->lifetimeMs == 0 )
		{
			Exit( kExitReason_TimeLimit );
		}
		else if( context->lifetimeMs > 0 )
		{
			dispatch_after_f( dispatch_time_milliseconds( context->lifetimeMs ), dispatch_get_main_queue(),
				kExitReason_TimeLimit, Exit );
		}
	}
}

//===========================================================================================================================
//	RegisterRecordUpdate
//===========================================================================================================================

static void	RegisterRecordUpdate( void *inContext )
{
	OSStatus							err;
	RegisterRecordContext * const		context = (RegisterRecordContext *) inContext;
	
	err = DNSServiceUpdateRecord( context->conRef, context->recordRef, 0, (uint16_t) context->updateDataLen,
		context->updateDataPtr, context->updateTTL );
	require_noerr( err, exit );
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	ResolveCmd
//===========================================================================================================================

typedef struct
{
	DNSServiceRef		mainRef;		// Main sdRef for shared connections.
	DNSServiceRef		opRef;			// sdRef for the DNSServiceResolve operation.
	DNSServiceFlags		flags;			// Flags argument for DNSServiceResolve().
	const char *		name;			// Service name argument for DNSServiceResolve().
	const char *		type;			// Service type argument for DNSServiceResolve().
	const char *		domain;			// Domain argument for DNSServiceResolve().
	uint32_t			ifIndex;		// Interface index argument for DNSServiceResolve().
	int					timeLimitSecs;	// Time limit for the DNSServiceResolve operation in seconds.
	
}	ResolveContext;

static void	ResolvePrintPrologue( const ResolveContext *inContext );
static void	ResolveContextFree( ResolveContext *inContext );
static void DNSSD_API
	ResolveCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		const char *			inHostname,
		uint16_t				inPort,
		uint16_t				inTXTLen,
		const unsigned char *	inTXTPtr,
		void *					inContext );

static void	ResolveCmd( void )
{
	OSStatus				err;
	DNSServiceRef			sdRef;
	ResolveContext *		context			= NULL;
	dispatch_source_t		signalSource	= NULL;
	int						useMainConnection;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Create context.
	
	context = (ResolveContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	// Check command parameters.
	
	if( gResolve_TimeLimitSecs < 0 )
	{
		FPrintF( stderr, "Invalid time limit: %d seconds.\n", gResolve_TimeLimitSecs );
		err = kParamErr;
		goto exit;
	}
	
	// Create main connection.
	
	if( gConnectionOpt )
	{
		err = CreateConnectionFromArgString( gConnectionOpt, dispatch_get_main_queue(), &context->mainRef, NULL );
		require_noerr_quiet( err, exit );
		useMainConnection = true;
	}
	else
	{
		useMainConnection = false;
	}
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	if( useMainConnection ) context->flags |= kDNSServiceFlagsShareConnection;
	
	// Get interface index.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Set remaining parameters.
	
	context->name			= gResolve_Name;
	context->type			= gResolve_Type;
	context->domain			= gResolve_Domain;
	context->timeLimitSecs	= gResolve_TimeLimitSecs;
	
	// Print prologue.
	
	ResolvePrintPrologue( context );
	
	// Start operation.
	
	sdRef = useMainConnection ? context->mainRef : kBadDNSServiceRef;
	err = DNSServiceResolve( &sdRef, context->flags, context->ifIndex, context->name, context->type, context->domain,
		ResolveCallback, NULL );
	require_noerr( err, exit );
	
	context->opRef = sdRef;
	if( !useMainConnection )
	{
		err = DNSServiceSetDispatchQueue( context->opRef, dispatch_get_main_queue() );
		require_noerr( err, exit );
	}
	
	// Set time limit.
	
	if( context->timeLimitSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->timeLimitSecs ), dispatch_get_main_queue(),
			kExitReason_TimeLimit, Exit );
	}
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) ResolveContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	ReconfirmCmd
//===========================================================================================================================

static void	ReconfirmCmd( void )
{
	OSStatus			err;
	uint8_t *			rdataPtr = NULL;
	size_t				rdataLen = 0;
	DNSServiceFlags		flags;
	uint32_t			ifIndex;
	uint16_t			type, class;
	char				ifName[ kInterfaceNameBufLen ];
	
	// Get flags.
	
	flags = GetDNSSDFlagsFromOpts();
	
	// Get interface index.
	
	err = InterfaceIndexFromArgString( gInterface, &ifIndex );
	require_noerr_quiet( err, exit );
	
	// Get record type.
	
	err = RecordTypeFromArgString( gReconfirmRecord_Type, &type );
	require_noerr( err, exit );
	
	// Get record data.
	
	if( gReconfirmRecord_Data )
	{
		err = RecordDataFromArgString( gReconfirmRecord_Data, &rdataPtr, &rdataLen );
		require_noerr_quiet( err, exit );
	}
	
	// Get record class.
	
	if( gReconfirmRecord_Class )
	{
		err = RecordClassFromArgString( gReconfirmRecord_Class, &class );
		require_noerr( err, exit );
	}
	else
	{
		class = kDNSServiceClass_IN;
	}
	
	// Print prologue.
	
	FPrintF( stdout, "Flags:     %#{flags}\n",	flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface: %d (%s)\n",	(int32_t) ifIndex, InterfaceIndexToName( ifIndex, ifName ) );
	FPrintF( stdout, "Name:      %s\n",			gReconfirmRecord_Name );
	FPrintF( stdout, "Type:      %s (%u)\n",	RecordTypeToString( type ), type );
	FPrintF( stdout, "Class:     %s (%u)\n",	( class == kDNSServiceClass_IN ) ? "IN" : "???", class );
	FPrintF( stdout, "Data:      %#H\n",		rdataPtr, (int) rdataLen, INT_MAX );
	FPrintF( stdout, "---\n" );
	
	err = DNSServiceReconfirmRecord( flags, ifIndex, gReconfirmRecord_Name, type, class, (uint16_t) rdataLen, rdataPtr );
	FPrintF( stdout, "Error:     %#m\n", err );
	
exit:
	FreeNullSafe( rdataPtr );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	ResolvePrintPrologue
//===========================================================================================================================

static void	ResolvePrintPrologue( const ResolveContext *inContext )
{
	const int		timeLimitSecs = inContext->timeLimitSecs;
	char			ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Flags:      %#{flags}\n",		inContext->flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:  %d (%s)\n",		(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Name:       %s\n",			inContext->name );
	FPrintF( stdout, "Type:       %s\n",			inContext->type );
	FPrintF( stdout, "Domain:     %s\n",			inContext->domain );
	FPrintF( stdout, "Time limit: " );
	if( timeLimitSecs > 0 )	FPrintF( stdout, "%d second%?c\n", timeLimitSecs, timeLimitSecs != 1, 's' );
	else					FPrintF( stdout, "∞\n" );
	FPrintF( stdout, "Start time: %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
}

//===========================================================================================================================
//	ResolveContextFree
//===========================================================================================================================

static void	ResolveContextFree( ResolveContext *inContext )
{
	DNSServiceForget( &inContext->opRef );
	DNSServiceForget( &inContext->mainRef );
	free( inContext );
}

//===========================================================================================================================
//	ResolveCallback
//===========================================================================================================================

static void DNSSD_API
	ResolveCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		const char *			inHostname,
		uint16_t				inPort,
		uint16_t				inTXTLen,
		const unsigned char *	inTXTPtr,
		void *					inContext )
{
	struct timeval		now;
	char				errorStr[ 64 ];
	
	Unused( inSDRef );
	Unused( inFlags );
	Unused( inContext );
	
	gettimeofday( &now, NULL );
	
	if( inError ) SNPrintF( errorStr, sizeof( errorStr ), " error %#m", inError );
	
	FPrintF( stdout, "%{du:time}: %s can be reached at %s:%u (interface %d)%?s\n",
		&now, inFullName, inHostname, ntohs( inPort ), (int32_t) inInterfaceIndex, inError, errorStr );
	if( inTXTLen == 1 )
	{
		FPrintF( stdout, " TXT record: %#H\n", inTXTPtr, (int) inTXTLen, INT_MAX );
	}
	else
	{
		FPrintF( stdout, " TXT record: %#{txt}\n", inTXTPtr, (size_t) inTXTLen );
	}
}

//===========================================================================================================================
//	GetAddrInfoPOSIXCmd
//===========================================================================================================================

#define AddressFamilyStr( X ) (				\
	( (X) == AF_INET )		? "inet"	:	\
	( (X) == AF_INET6 )		? "inet6"	:	\
	( (X) == AF_UNSPEC )	? "unspec"	:	\
							  "???" )

typedef struct
{
    unsigned int		flag;
    const char *        str;

}   FlagStringPair;

#define CaseFlagStringify( X )		{ (X), # X }

const FlagStringPair		kGAIPOSIXFlagStringPairs[] =
{
#if( defined( AI_UNUSABLE ) )
	CaseFlagStringify( AI_UNUSABLE ),
#endif
	CaseFlagStringify( AI_NUMERICSERV ),
	CaseFlagStringify( AI_V4MAPPED ),
	CaseFlagStringify( AI_ADDRCONFIG ),
#if( defined( AI_V4MAPPED_CFG ) )
	CaseFlagStringify( AI_V4MAPPED_CFG ),
#endif
	CaseFlagStringify( AI_ALL ),
	CaseFlagStringify( AI_NUMERICHOST ),
	CaseFlagStringify( AI_CANONNAME ),
	CaseFlagStringify( AI_PASSIVE ),
	{ 0, NULL }
};

static void	GetAddrInfoPOSIXCmd( void )
{
	OSStatus					err;
	struct addrinfo				hints;
	struct timeval				now;
	const struct addrinfo *		addrInfo;
	struct addrinfo *			addrInfoList = NULL;
	const FlagStringPair *		pair;
	
	memset( &hints, 0, sizeof( hints ) );
	hints.ai_socktype = SOCK_STREAM;
	
	// Set hints address family.
	
	if( !gGAIPOSIX_Family )										hints.ai_family = AF_UNSPEC;
	else if( strcasecmp( gGAIPOSIX_Family, "inet" ) == 0 )		hints.ai_family = AF_INET;
	else if( strcasecmp( gGAIPOSIX_Family, "inet6" ) == 0 )		hints.ai_family = AF_INET6;
	else if( strcasecmp( gGAIPOSIX_Family, "unspec" ) == 0 )	hints.ai_family = AF_UNSPEC;
	else
	{
		FPrintF( stderr, "Invalid address family: %s.\n", gGAIPOSIX_Family );
		err = kParamErr;
		goto exit;
	}
	
	// Set hints flags.
	
	if( gGAIPOSIXFlag_AddrConfig )	hints.ai_flags |= AI_ADDRCONFIG;
	if( gGAIPOSIXFlag_All )			hints.ai_flags |= AI_ALL;
	if( gGAIPOSIXFlag_CanonName )	hints.ai_flags |= AI_CANONNAME;
	if( gGAIPOSIXFlag_NumericHost )	hints.ai_flags |= AI_NUMERICHOST;
	if( gGAIPOSIXFlag_NumericServ )	hints.ai_flags |= AI_NUMERICSERV;
	if( gGAIPOSIXFlag_Passive )		hints.ai_flags |= AI_PASSIVE;
	if( gGAIPOSIXFlag_V4Mapped )	hints.ai_flags |= AI_V4MAPPED;
#if( defined( AI_V4MAPPED_CFG ) )
	if( gGAIPOSIXFlag_V4MappedCFG )	hints.ai_flags |= AI_V4MAPPED_CFG;
#endif
#if( defined( AI_DEFAULT ) )
	if( gGAIPOSIXFlag_Default )		hints.ai_flags |= AI_DEFAULT;
#endif
#if( defined( AI_UNUSABLE ) )
	if( gGAIPOSIXFlag_Unusable )	hints.ai_flags |= AI_UNUSABLE;
#endif
	
	// Print prologue.
	
	FPrintF( stdout, "Hostname:       %s\n",	gGAIPOSIX_HostName );
	FPrintF( stdout, "Servname:       %s\n",	gGAIPOSIX_ServName );
	FPrintF( stdout, "Address family: %s\n",	AddressFamilyStr( hints.ai_family ) );
	FPrintF( stdout, "Flags:          0x%X < ",	hints.ai_flags );
	for( pair = kGAIPOSIXFlagStringPairs; pair->str != NULL; ++pair )
	{
		if( ( (unsigned int) hints.ai_flags ) & pair->flag ) FPrintF( stdout, "%s ", pair->str );
	}
	FPrintF( stdout, ">\n" );
	FPrintF( stdout, "Start time:     %{du:time}\n", NULL );
	FPrintF( stdout, "---\n" );
	
	// Call getaddrinfo().
	
	err = getaddrinfo( gGAIPOSIX_HostName, gGAIPOSIX_ServName, &hints, &addrInfoList );
	gettimeofday( &now, NULL );
	if( err )
	{
		FPrintF( stderr, "Error %d: %s.\n", err, gai_strerror( err ) );
	}
	else
	{
		int		addrCount = 0;
		
		for( addrInfo = addrInfoList; addrInfo; addrInfo = addrInfo->ai_next ) { ++addrCount; }
		
		FPrintF( stdout, "Addresses (%d total):\n", addrCount );
		for( addrInfo = addrInfoList; addrInfo; addrInfo = addrInfo->ai_next )
		{
			FPrintF( stdout, "%##a\n", addrInfo->ai_addr );
		}
	}
	FPrintF( stdout, "---\n" );
	FPrintF( stdout, "End time:       %{du:time}\n", &now );
	
exit:
	if( addrInfoList ) freeaddrinfo( addrInfoList );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	ReverseLookupCmd
//===========================================================================================================================

static void	ReverseLookupCmd( void )
{
	OSStatus					err;
	QueryRecordContext *		context			= NULL;
	DNSServiceRef				sdRef;
	dispatch_source_t			signalSource	= NULL;
	uint32_t					ipv4Addr;
	uint8_t						ipv6Addr[ 16 ];
	char						recordName[ ( 16 * 4 ) + 9 + 1 ];
	int							useMainConnection;
	const char *				endPtr;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Create context.
	
	context = (QueryRecordContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	// Check command parameters.
	
	if( gReverseLookup_TimeLimitSecs < 0 )
	{
		FPrintF( stderr, "Invalid time limit: %d s.\n", gReverseLookup_TimeLimitSecs );
		err = kParamErr;
		goto exit;
	}
	
	// Create main connection.
	
	if( gConnectionOpt )
	{
		err = CreateConnectionFromArgString( gConnectionOpt, dispatch_get_main_queue(), &context->mainRef, NULL );
		require_noerr_quiet( err, exit );
		useMainConnection = true;
	}
	else
	{
		useMainConnection = false;
	}
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	if( useMainConnection ) context->flags |= kDNSServiceFlagsShareConnection;
	
	// Get interface index.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Create reverse lookup record name.
	
	err = StringToIPv4Address( gReverseLookup_IPAddr, kStringToIPAddressFlagsNoPort | kStringToIPAddressFlagsNoPrefix,
		&ipv4Addr, NULL, NULL, NULL, &endPtr );
	if( err || ( *endPtr != '\0' ) )
	{
		char *		dst;
		int			i;
		
		err = StringToIPv6Address( gReverseLookup_IPAddr,
			kStringToIPAddressFlagsNoPort | kStringToIPAddressFlagsNoPrefix | kStringToIPAddressFlagsNoScope,
			ipv6Addr, NULL, NULL, NULL, &endPtr );
		if( err || ( *endPtr != '\0' ) )
		{
			FPrintF( stderr, "Invalid IP address: \"%s\".\n", gReverseLookup_IPAddr );
			err = kParamErr;
			goto exit;
		}
		dst = recordName;
		for( i = 15; i >= 0; --i )
		{
			*dst++ = kHexDigitsLowercase[ ipv6Addr[ i ] & 0x0F ];
			*dst++ = '.';
			*dst++ = kHexDigitsLowercase[ ipv6Addr[ i ] >> 4 ];
			*dst++ = '.';
		}
		strcpy( dst, "ip6.arpa." );
		check( ( strlen( recordName ) + 1 ) <= sizeof( recordName ) );
	}
	else
	{
		SNPrintF( recordName, sizeof( recordName ), "%u.%u.%u.%u.in-addr.arpa.",
			  ipv4Addr         & 0xFF,
			( ipv4Addr >>  8 ) & 0xFF,
			( ipv4Addr >> 16 ) & 0xFF,
			( ipv4Addr >> 24 ) & 0xFF );
	}
	
	// Set remaining parameters.
	
	context->recordName		= recordName;
	context->recordType		= kDNSServiceType_PTR;
	context->timeLimitSecs	= gReverseLookup_TimeLimitSecs;
	context->oneShotMode	= gReverseLookup_OneShot ? true : false;
	
	// Print prologue.
	
	QueryRecordPrintPrologue( context );
	
	// Start operation.
	
	sdRef = useMainConnection ? context->mainRef : kBadDNSServiceRef;
	err = DNSServiceQueryRecord( &sdRef, context->flags, context->ifIndex, context->recordName, context->recordType,
		kDNSServiceClass_IN, QueryRecordCallback, context );
	require_noerr( err, exit );
	
	context->opRef = sdRef;
	if( !useMainConnection )
	{
		err = DNSServiceSetDispatchQueue( context->opRef, dispatch_get_main_queue() );
		require_noerr( err, exit );
	}
	
	// Set time limit.
	
	if( context->timeLimitSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->timeLimitSecs ), dispatch_get_main_queue(),
			kExitReason_TimeLimit, Exit );
	}
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) QueryRecordContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	PortMappingCmd
//===========================================================================================================================

typedef struct
{
	DNSServiceRef			mainRef;		// Main sdRef for shared connection.
	DNSServiceRef			opRef;			// sdRef for the DNSServiceNATPortMappingCreate operation.
	DNSServiceFlags			flags;			// Flags for DNSServiceNATPortMappingCreate operation.
	uint32_t				ifIndex;		// Interface index argument for DNSServiceNATPortMappingCreate operation.
	DNSServiceProtocol		protocols;		// Protocols argument for DNSServiceNATPortMappingCreate operation.
	uint32_t				ttl;			// TTL argument for DNSServiceNATPortMappingCreate operation.
	uint16_t				internalPort;	// Internal port argument for DNSServiceNATPortMappingCreate operation.
	uint16_t				externalPort;	// External port argument for DNSServiceNATPortMappingCreate operation.
	Boolean					printedHeader;	// True if results header was printed.
	
}	PortMappingContext;

static void	PortMappingPrintPrologue( const PortMappingContext *inContext );
static void	PortMappingContextFree( PortMappingContext *inContext );
static void DNSSD_API
	PortMappingCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inError,
		uint32_t			inExternalIPv4Address,
		DNSServiceProtocol	inProtocol,
		uint16_t			inInternalPort,
		uint16_t			inExternalPort,
		uint32_t			inTTL,
		void *				inContext );

static void	PortMappingCmd( void )
{
	OSStatus					err;
	PortMappingContext *		context			= NULL;
	DNSServiceRef				sdRef;
	dispatch_source_t			signalSource	= NULL;
	int							useMainConnection;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Create context.
	
	context = (PortMappingContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	// Check command parameters.
	
	if( ( gPortMapping_InternalPort < 0 ) || ( gPortMapping_InternalPort > UINT16_MAX ) )
	{
		FPrintF( stderr, "Internal port number %d is out-of-range.\n", gPortMapping_InternalPort );
		err = kParamErr;
		goto exit;
	}
	
	if( ( gPortMapping_ExternalPort < 0 ) || ( gPortMapping_ExternalPort > UINT16_MAX ) )
	{
		FPrintF( stderr, "External port number %d is out-of-range.\n", gPortMapping_ExternalPort );
		err = kParamErr;
		goto exit;
	}
	
	// Create main connection.
	
	if( gConnectionOpt )
	{
		err = CreateConnectionFromArgString( gConnectionOpt, dispatch_get_main_queue(), &context->mainRef, NULL );
		require_noerr_quiet( err, exit );
		useMainConnection = true;
	}
	else
	{
		useMainConnection = false;
	}
	
	// Get flags.
	
	context->flags = GetDNSSDFlagsFromOpts();
	if( useMainConnection ) context->flags |= kDNSServiceFlagsShareConnection;
	
	// Get interface index.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	// Set remaining parameters.
	
	if( gPortMapping_ProtocolTCP ) context->protocols |= kDNSServiceProtocol_TCP;
	if( gPortMapping_ProtocolUDP ) context->protocols |= kDNSServiceProtocol_UDP;
	context->ttl			= (uint32_t) gPortMapping_TTL;
	context->internalPort	= (uint16_t) gPortMapping_InternalPort;
	context->externalPort	= (uint16_t) gPortMapping_ExternalPort;
	
	// Print prologue.
	
	PortMappingPrintPrologue( context );
	
	// Start operation.
	
	sdRef = useMainConnection ? context->mainRef : kBadDNSServiceRef;
	err = DNSServiceNATPortMappingCreate( &sdRef, context->flags, context->ifIndex, context->protocols,
		htons( context->internalPort ), htons( context->externalPort ), context->ttl, PortMappingCallback, context );
	require_noerr( err, exit );
	
	context->opRef = sdRef;
	if( !useMainConnection )
	{
		err = DNSServiceSetDispatchQueue( context->opRef, dispatch_get_main_queue() );
		require_noerr( err, exit );
	}
	
	dispatch_main();
	
exit:
	dispatch_source_forget( &signalSource );
	if( context ) PortMappingContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	PortMappingPrintPrologue
//===========================================================================================================================

static void	PortMappingPrintPrologue( const PortMappingContext *inContext )
{
	char		ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Flags:         %#{flags}\n",		inContext->flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:     %d (%s)\n",		(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Protocols:     %#{flags}\n",		inContext->protocols, kDNSServiceProtocolDescriptors );
	FPrintF( stdout, "Internal Port: %u\n",				inContext->internalPort );
	FPrintF( stdout, "External Port: %u\n",				inContext->externalPort );
	FPrintF( stdout, "TTL:           %u%?s\n",			inContext->ttl, !inContext->ttl,
		" (system will use a default value.)" );
	FPrintF( stdout, "Start time:    %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
	
}

//===========================================================================================================================
//	PortMappingContextFree
//===========================================================================================================================

static void	PortMappingContextFree( PortMappingContext *inContext )
{
	DNSServiceForget( &inContext->opRef );
	DNSServiceForget( &inContext->mainRef );
	free( inContext );
}

//===========================================================================================================================
//	PortMappingCallback
//===========================================================================================================================

static void DNSSD_API
	PortMappingCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inError,
		uint32_t			inExternalIPv4Address,
		DNSServiceProtocol	inProtocol,
		uint16_t			inInternalPort,
		uint16_t			inExternalPort,
		uint32_t			inTTL,
		void *				inContext )
{
	PortMappingContext * const		context = (PortMappingContext *) inContext;
	struct timeval					now;
	char							errorStr[ 128 ];
	
	Unused( inSDRef );
	Unused( inFlags );
	
	gettimeofday( &now, NULL );
	
	if( inError ) SNPrintF( errorStr, sizeof( errorStr ), " (error: %#m)", inError );
	if( !context->printedHeader )
	{
		FPrintF( stdout, "%-26s  IF %7s %15s %7s %6s Protocol\n", "Timestamp", "IntPort", "ExtAddr", "ExtPort", "TTL" );
		context->printedHeader = true;
	}
	FPrintF( stdout, "%{du:time}  %2u %7u %15.4a %7u %6u %#{flags}%?s\n",
		&now, inInterfaceIndex, ntohs( inInternalPort), &inExternalIPv4Address, ntohs( inExternalPort ), inTTL,
		inProtocol, kDNSServiceProtocolDescriptors, inError, errorStr );
}

//===========================================================================================================================
//	BrowseAllCmd
//===========================================================================================================================

typedef struct BrowseDomain			BrowseDomain;
typedef struct BrowseType			BrowseType;
typedef struct BrowseOp				BrowseOp;
typedef struct BrowseInstance		BrowseInstance;
typedef struct BrowseIPAddr			BrowseIPAddr;

typedef struct
{
	int						refCount;
	DNSServiceRef			mainRef;
	DNSServiceRef			domainsQuery;
	const char *			domain;
	BrowseDomain *			domainList;
	char **					serviceTypes;
	size_t					serviceTypesCount;
	dispatch_source_t		exitTimer;
	uint32_t				ifIndex;
	int						pendingConnectCount;
	int						browseTimeSecs;
	int						maxConnectTimeSecs;
	Boolean					includeAWDL;
	Boolean					useColoredText;
	
}	BrowseAllContext;

struct BrowseDomain
{
	BrowseDomain *			next;
	char *					name;
	DNSServiceRef			servicesQuery;
	BrowseAllContext *		context;
	BrowseType *			typeList;
};

struct BrowseType
{
	BrowseType *		next;
	char *				name;
	BrowseOp *			browseList;
};

struct BrowseOp
{
	BrowseOp *				next;
	BrowseAllContext *		context;
	DNSServiceRef			browse;
	uint64_t				startTicks;
	BrowseInstance *		instanceList;
	uint32_t				ifIndex;
	Boolean					isTCP;
};

struct BrowseInstance
{
	BrowseInstance *		next;
	BrowseAllContext *		context;
	char *					name;
	uint64_t				foundTicks;
	DNSServiceRef			resolve;
	uint64_t				resolveStartTicks;
	uint64_t				resolveDoneTicks;
	DNSServiceRef			getAddr;
	uint64_t				getAddrStartTicks;
	BrowseIPAddr *			addrList;
	uint8_t *				txtPtr;
	size_t					txtLen;
	char *					hostname;
	uint32_t				ifIndex;
	uint16_t				port;
	Boolean					isTCP;
};

typedef enum
{
	kConnectStatus_None			= 0,
	kConnectStatus_Pending		= 1,
	kConnectStatus_Succeeded	= 2,
	kConnectStatus_Failed		= 3
	
}	ConnectStatus;

struct BrowseIPAddr
{
	BrowseIPAddr *			next;
	sockaddr_ip				sip;
	int						refCount;
	BrowseAllContext *		context;
	uint64_t				foundTicks;
	AsyncConnectionRef		connection;
	ConnectStatus			connectStatus;
	CFTimeInterval			connectTimeSecs;
	OSStatus				connectError;
};

static void	BrowseAllPrintPrologue( const BrowseAllContext *inContext );
static void DNSSD_API
	BrowseAllQueryDomainsCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext );
static void DNSSD_API
	BrowseAllQueryCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext );
static void DNSSD_API
	BrowseAllBrowseCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inError,
		const char *		inName,
		const char *		inRegType,
		const char *		inDomain,
		void *				inContext );
static void DNSSD_API
	BrowseAllResolveCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		const char *			inHostname,
		uint16_t				inPort,
		uint16_t				inTXTLen,
		const unsigned char *	inTXTPtr,
		void *					inContext );
static void DNSSD_API
	BrowseAllGAICallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext );
static void		BrowseAllConnectionProgress( int inPhase, const void *inDetails, void *inArg );
static void		BrowseAllConnectionHandler( SocketRef inSock, OSStatus inError, void *inArg );
static void		BrowseAllStop( void *inContext );
static void		BrowseAllExit( void *inContext );
static OSStatus	BrowseAllAddDomain( BrowseAllContext *inContext, const char *inName );
static OSStatus	BrowseAllRemoveDomain( BrowseAllContext *inContext, const char *inName );
static void		BrowseAllContextRelease( BrowseAllContext *inContext );
static OSStatus
	BrowseAllAddServiceType(
		BrowseAllContext *	inContext,
		BrowseDomain *		inDomain,
		const char *		inName,
		uint32_t			inIfIndex,
		Boolean				inIncludeAWDL );
static OSStatus
	BrowseAllRemoveServiceType(
		BrowseAllContext *	inContext,
		BrowseDomain *		inDomain,
		const char *		inName,
		uint32_t			inIfIndex );
static OSStatus
	BrowseAllAddServiceInstance(
		BrowseAllContext *	inContext,
		BrowseOp *			inBrowse,
		const char *		inName,
		const char *		inRegType,
		const char *		inDomain,
		uint32_t			inIfIndex );
static OSStatus
	BrowseAllRemoveServiceInstance(
		BrowseAllContext *	inContext,
		BrowseOp *			inBrowse,
		const char *		inName,
		uint32_t			inIfIndex );
static OSStatus
	BrowseAllAddIPAddress(
		BrowseAllContext *		inContext,
		BrowseInstance *		inInstance,
		const struct sockaddr *	inSockAddr );
static OSStatus
	BrowseAllRemoveIPAddress(
		BrowseAllContext *		inContext,
		BrowseInstance *		inInstance,
		const struct sockaddr *	inSockAddr );
static void	BrowseDomainFree( BrowseDomain *inDomain );
static void	BrowseTypeFree( BrowseType *inType );
static void	BrowseOpFree( BrowseOp *inBrowse );
static void	BrowseInstanceFree( BrowseInstance *inInstance );
static void	BrowseIPAddrRelease( BrowseIPAddr *inAddr );
static void	BrowseIPAddrReleaseList( BrowseIPAddr *inList );

#define ForgetIPAddressList( X )		ForgetCustom( X, BrowseIPAddrReleaseList )
#define ForgetBrowseAllContext( X )		ForgetCustom( X, BrowseAllContextRelease )

#define kBrowseAllOpenFileMin		4096

static void	BrowseAllCmd( void )
{
	OSStatus				err;
	BrowseAllContext *		context = NULL;
	
	// Check command parameters.
	
	if( gBrowseAll_BrowseTimeSecs <= 0 )
	{
		FPrintF( stdout, "Invalid browse time: %d seconds.\n", gBrowseAll_BrowseTimeSecs );
		err = kParamErr;
		goto exit;
	}
	
#if( TARGET_OS_POSIX )
	// Set open file minimum.
	
	{
		struct rlimit		fdLimits;
		
		err = getrlimit( RLIMIT_NOFILE, &fdLimits );
		err = map_global_noerr_errno( err );
		require_noerr( err, exit );
		
		if( fdLimits.rlim_cur < kBrowseAllOpenFileMin )
		{
			fdLimits.rlim_cur = kBrowseAllOpenFileMin;
			err = setrlimit( RLIMIT_NOFILE, &fdLimits );
			err = map_global_noerr_errno( err );
			require_noerr( err, exit );
		}
	}
#endif
	
	context = (BrowseAllContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->refCount				= 1;
	context->domain					= gBrowseAll_Domain;
	context->serviceTypes			= gBrowseAll_ServiceTypes;
	context->serviceTypesCount		= gBrowseAll_ServiceTypesCount;
	gBrowseAll_ServiceTypes			= NULL;
	gBrowseAll_ServiceTypesCount	= 0;
	context->browseTimeSecs			= gBrowseAll_BrowseTimeSecs;
	context->maxConnectTimeSecs		= gBrowseAll_MaxConnectTimeSecs;
	context->includeAWDL			= gDNSSDFlag_IncludeAWDL ? true : false;
#if( TARGET_OS_POSIX )
	context->useColoredText			= isatty( STDOUT_FILENO ) ? true : false;
#endif
	
	err = DNSServiceCreateConnection( &context->mainRef );
	require_noerr( err, exit );
	
	err = DNSServiceSetDispatchQueue( context->mainRef, dispatch_get_main_queue() );
	require_noerr( err, exit );
	
	// Set interface index.
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	BrowseAllPrintPrologue( context );
	
	if( context->domain )
	{
		err = BrowseAllAddDomain( context, context->domain );
		require_noerr( err, exit );
	}
	else
	{
		DNSServiceRef		sdRef;
		
		sdRef = context->mainRef;
		err = DNSServiceQueryRecord( &sdRef, kDNSServiceFlagsShareConnection, kDNSServiceInterfaceIndexLocalOnly,
			"b._dns-sd._udp.local.", kDNSServiceType_PTR, kDNSServiceClass_IN, BrowseAllQueryDomainsCallback, context );
		require_noerr( err, exit );
		
		context->domainsQuery = sdRef;
	}
	
	dispatch_after_f( dispatch_time_seconds( context->browseTimeSecs ), dispatch_get_main_queue(), context, BrowseAllStop );
	dispatch_main();
	
exit:
	if( context ) BrowseAllContextRelease( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	BrowseAllPrintPrologue
//===========================================================================================================================

static void	BrowseAllPrintPrologue( const BrowseAllContext *inContext )
{
	size_t		i;
	char		ifName[ kInterfaceNameBufLen ];
	
	InterfaceIndexToName( inContext->ifIndex, ifName );
	
	FPrintF( stdout, "Interface:        %d (%s)\n",	(int32_t) inContext->ifIndex, ifName );
	FPrintF( stdout, "Service types:    ");
	if( inContext->serviceTypesCount > 0 )
	{
		FPrintF( stdout, "%s", inContext->serviceTypes[ 0 ] );
		for( i = 1; i < inContext->serviceTypesCount; ++i ) FPrintF( stdout, ", %s", inContext->serviceTypes[ i ] );
		FPrintF( stdout, "\n" );
	}
	else
	{
		FPrintF( stdout, "all services\n" );
	}
	FPrintF( stdout, "Domain:           %s\n", inContext->domain ? inContext->domain : "default domains" );
	FPrintF( stdout, "Browse time:      %d second%?c\n", inContext->browseTimeSecs, inContext->browseTimeSecs != 1, 's' );
	FPrintF( stdout, "Max connect time: %d second%?c\n",
		inContext->maxConnectTimeSecs, inContext->maxConnectTimeSecs != 1, 's' );
	FPrintF( stdout, "IncludeAWDL:      %s\n", inContext->includeAWDL ? "YES" : "NO" );
	FPrintF( stdout, "Start time:       %{du:time}\n", NULL );
	FPrintF( stdout, "---\n" );
}

//===========================================================================================================================
//	BrowseAllQueryDomainsCallback
//===========================================================================================================================

static void DNSSD_API
	BrowseAllQueryDomainsCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext )
{
	OSStatus						err;
	BrowseAllContext * const		context = (BrowseAllContext *) inContext;
	char							domainStr[ kDNSServiceMaxDomainName ];
	
	Unused( inSDRef );
	Unused( inInterfaceIndex );
	Unused( inFullName );
	Unused( inType );
	Unused( inClass );
	Unused( inTTL );
	
	err = inError;
	require_noerr( err, exit );
	
	err = DomainNameToString( inRDataPtr, ( (const uint8_t *) inRDataPtr ) + inRDataLen, domainStr, NULL );
	require_noerr( err, exit );
	
	if( inFlags & kDNSServiceFlagsAdd )
	{
		err = BrowseAllAddDomain( context, domainStr );
		if( err == kDuplicateErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	else
	{
		err = BrowseAllRemoveDomain( context, domainStr );
		if( err == kNotFoundErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	BrowseAllQueryCallback
//===========================================================================================================================

static void DNSSD_API
	BrowseAllQueryCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		uint16_t				inType,
		uint16_t				inClass,
		uint16_t				inRDataLen,
		const void *			inRDataPtr,
		uint32_t				inTTL,
		void *					inContext )
{
	OSStatus					err;
	BrowseDomain * const		domain			= (BrowseDomain *) inContext;
	const uint8_t *				firstLabel;
	const uint8_t *				secondLabel;
	char *						serviceTypeStr	= NULL;
	const uint8_t * const		end				= ( (uint8_t * ) inRDataPtr ) + inRDataLen;
	
	Unused( inSDRef );
	Unused( inFullName );
	Unused( inTTL );
	Unused( inType );
	Unused( inClass );
	
	err = inError;
	require_noerr( err, exit );
	
	check( inType	== kDNSServiceType_PTR );
	check( inClass	== kDNSServiceClass_IN );
	require_action( inRDataLen > 0, exit, err = kSizeErr );
	
	firstLabel = inRDataPtr;
	require_action_quiet( ( firstLabel + 1 + firstLabel[ 0 ] ) < end , exit, err = kUnderrunErr );
	
	secondLabel = firstLabel + 1 + firstLabel[ 0 ];
	require_action_quiet( ( secondLabel + 1 + secondLabel[ 0 ] ) < end , exit, err = kUnderrunErr );
	
	ASPrintF( &serviceTypeStr, "%#s.%#s", firstLabel, secondLabel );
	require_action( serviceTypeStr, exit, err = kNoMemoryErr );
	
	if( inFlags & kDNSServiceFlagsAdd )
	{
		err = BrowseAllAddServiceType( domain->context, domain, serviceTypeStr, inInterfaceIndex, false );
		if( err == kDuplicateErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	else
	{
		err = BrowseAllRemoveServiceType( domain->context, domain, serviceTypeStr, inInterfaceIndex );
		if( err == kNotFoundErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	
exit:
	FreeNullSafe( serviceTypeStr );
}

//===========================================================================================================================
//	BrowseAllBrowseCallback
//===========================================================================================================================

static void DNSSD_API
	BrowseAllBrowseCallback(
		DNSServiceRef		inSDRef,
		DNSServiceFlags		inFlags,
		uint32_t			inInterfaceIndex,
		DNSServiceErrorType	inError,
		const char *		inName,
		const char *		inRegType,
		const char *		inDomain,
		void *				inContext )
{
	OSStatus				err;
	BrowseOp * const		browse = (BrowseOp *) inContext;
	
	Unused( inSDRef );
	
	err = inError;
	require_noerr( err, exit );
	
	if( inFlags & kDNSServiceFlagsAdd )
	{
		err = BrowseAllAddServiceInstance( browse->context, browse, inName, inRegType, inDomain, inInterfaceIndex );
		if( err == kDuplicateErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	else
	{
		err = BrowseAllRemoveServiceInstance( browse->context, browse, inName, inInterfaceIndex );
		if( err == kNotFoundErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	
exit:
	return;
}

//===========================================================================================================================
//	BrowseAllResolveCallback
//===========================================================================================================================

static void DNSSD_API
	BrowseAllResolveCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inFullName,
		const char *			inHostname,
		uint16_t				inPort,
		uint16_t				inTXTLen,
		const unsigned char *	inTXTPtr,
		void *					inContext )
{
	OSStatus					err;
	const uint64_t				nowTicks	= UpTicks();
	BrowseInstance * const		instance	= (BrowseInstance *) inContext;
	
	Unused( inSDRef );
	Unused( inFlags );
	Unused( inInterfaceIndex );
	Unused( inFullName );
	
	err = inError;
	require_noerr( err, exit );
	
	if( !MemEqual( instance->txtPtr, instance->txtLen, inTXTPtr, inTXTLen ) )
	{
		FreeNullSafe( instance->txtPtr );
		instance->txtPtr = malloc( inTXTLen );
		require_action( instance->txtPtr, exit, err = kNoMemoryErr );
		
		memcpy( instance->txtPtr, inTXTPtr, inTXTLen );
		instance->txtLen = inTXTLen;
	}
	
	instance->port = ntohs( inPort );
	
	if( !instance->hostname || ( strcasecmp( instance->hostname, inHostname ) != 0 ) )
	{
		DNSServiceRef		sdRef;
		
		if( !instance->hostname ) instance->resolveDoneTicks = nowTicks;
		FreeNullSafe( instance->hostname );
		instance->hostname = strdup( inHostname );
		require_action( instance->hostname, exit, err = kNoMemoryErr );
		
		DNSServiceForget( &instance->getAddr );
		ForgetIPAddressList( &instance->addrList );
		
		sdRef = instance->context->mainRef;
		instance->getAddrStartTicks = UpTicks();
		err = DNSServiceGetAddrInfo( &sdRef, kDNSServiceFlagsShareConnection, instance->ifIndex,
			kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6, instance->hostname, BrowseAllGAICallback, instance );
		require_noerr( err, exit );
		
		instance->getAddr = sdRef;
	}
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	BrowseAllGAICallback
//===========================================================================================================================

static void DNSSD_API
	BrowseAllGAICallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext )
{
	OSStatus					err;
	BrowseInstance * const		instance = (BrowseInstance *) inContext;
	
	Unused( inSDRef );
	Unused( inInterfaceIndex );
	Unused( inHostname );
	Unused( inTTL );
	
	err = inError;
	require_noerr( err, exit );
	
	if( ( inSockAddr->sa_family != AF_INET ) && ( inSockAddr->sa_family != AF_INET6 ) )
	{
		dlogassert( "Unexpected address family: %d", inSockAddr->sa_family );
		goto exit;
	}
	
	if( inFlags & kDNSServiceFlagsAdd )
	{
		err = BrowseAllAddIPAddress( instance->context, instance, inSockAddr );
		if( err == kDuplicateErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	else
	{
		err = BrowseAllRemoveIPAddress( instance->context, instance, inSockAddr );
		if( err == kNotFoundErr ) err = kNoErr;
		require_noerr( err, exit );
	}
	
exit:
	return;
}

//===========================================================================================================================
//	BrowseAllConnectionProgress
//===========================================================================================================================

static void	BrowseAllConnectionProgress( int inPhase, const void *inDetails, void *inArg )
{
	BrowseIPAddr * const		addr = (BrowseIPAddr *) inArg;
	
	if( inPhase == kAsyncConnectionPhase_Connected )
	{
		const AsyncConnectedInfo * const		info = (AsyncConnectedInfo *) inDetails;
		
		addr->connectTimeSecs = info->connectSecs;
	}
}

//===========================================================================================================================
//	BrowseAllConnectionHandler
//===========================================================================================================================

static void	BrowseAllConnectionHandler( SocketRef inSock, OSStatus inError, void *inArg )
{
	BrowseIPAddr * const			addr	= (BrowseIPAddr *) inArg;
	BrowseAllContext * const		context	= addr->context;
	
	if( inError )
	{
		addr->connectStatus	= kConnectStatus_Failed;
		addr->connectError	= inError;
	}
	else
	{
		addr->connectStatus = kConnectStatus_Succeeded;
	}
	
	check( context->pendingConnectCount > 0 );
	if( --context->pendingConnectCount == 0 )
	{
		if( context->exitTimer )
		{
			dispatch_source_forget( &context->exitTimer );
			dispatch_async_f( dispatch_get_main_queue(), context, BrowseAllExit );
		}
	}
	
	ForgetSocket( &inSock );
	BrowseIPAddrRelease( addr );
}

//===========================================================================================================================
//	BrowseAllStop
//===========================================================================================================================

static void	BrowseAllStop( void *inContext )
{
	OSStatus						err;
	BrowseAllContext * const		context = (BrowseAllContext *) inContext;
	BrowseDomain *					domain;
	BrowseType *					type;
	BrowseOp *						browse;
	BrowseInstance *				instance;
	
	DNSServiceForget( &context->domainsQuery );
	for( domain = context->domainList; domain; domain = domain->next )
	{
		DNSServiceForget( &domain->servicesQuery );
		for( type = domain->typeList; type; type = type->next )
		{
			for( browse = type->browseList; browse; browse = browse->next )
			{
				DNSServiceForget( &browse->browse );
				for( instance = browse->instanceList; instance; instance = instance->next )
				{
					DNSServiceForget( &instance->resolve );
					DNSServiceForget( &instance->getAddr );
				}
			}
		}
	}
	DNSServiceForget( &context->mainRef );
	
	if( ( context->pendingConnectCount > 0 ) && ( context->maxConnectTimeSecs > 0 ) )
	{
		check( !context->exitTimer );
		err = DispatchTimerCreate( dispatch_time_seconds( context->maxConnectTimeSecs ), DISPATCH_TIME_FOREVER,
			100 * kNanosecondsPerMillisecond, NULL, BrowseAllExit, NULL, context, &context->exitTimer );
		require_noerr( err, exit );
		dispatch_resume( context->exitTimer );
	}
	else
	{
		dispatch_async_f( dispatch_get_main_queue(), context, BrowseAllExit );
	}
	err = kNoErr;
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	BrowseAllExit
//===========================================================================================================================

#define kStatusStr_CouldConnect					"connected"
#define kStatusStr_CouldConnectColored			kANSIGreen kStatusStr_CouldConnect kANSINormal
#define kStatusStr_CouldNotConnect				"could not connect"
#define kStatusStr_CouldNotConnectColored		kANSIRed kStatusStr_CouldNotConnect kANSINormal
#define kStatusStr_NoConnectionAttempted		"no connection attempted"
#define kStatusStr_Unknown						"unknown"

#define Indent( X )		( (X) * 4 ), ""

static void	BrowseAllExit( void *inContext )
{
	BrowseAllContext * const		context = (BrowseAllContext *) inContext;
	BrowseDomain *					domain;
	BrowseType *					type;
	BrowseOp *						browse;
	BrowseInstance *				instance;
	BrowseIPAddr *					addr;
	
	dispatch_source_forget( &context->exitTimer );
	
	for( domain = context->domainList; domain; domain = domain->next )
	{
		FPrintF( stdout, "%s\n\n", domain->name );
		
		for( type = domain->typeList; type; type = type->next )
		{
			const char *		desc;
			
			desc = ServiceTypeDescription( type->name );
			if( desc )	FPrintF( stdout, "%*s" "%s (%s)\n\n",	Indent( 1 ), desc, type->name );
			else		FPrintF( stdout, "%*s" "%s\n\n",		Indent( 1 ), type->name );
			
			for( browse = type->browseList; browse; browse = browse->next )
			{
				for( instance = browse->instanceList; instance; instance = instance->next )
				{
					char		ifname[ IF_NAMESIZE + 1 ];
					
					FPrintF( stdout, "%*s" "%s via ", Indent( 2 ), instance->name );
					if( instance->ifIndex == 0 )
					{
						FPrintF( stdout, "the Internet" );
					}
					else if( if_indextoname( instance->ifIndex, ifname ) )
					{
						NetTransportType		netType;
						
						SocketGetInterfaceInfo( kInvalidSocketRef, ifname, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
							&netType );
						FPrintF( stdout, "%s (%s)",
							( netType == kNetTransportType_Ethernet ) ? "ethernet" : NetTransportTypeToString( netType ),
							ifname );
					}
					else
					{
						FPrintF( stdout, "interface index %u", instance->ifIndex );
					}
					FPrintF( stdout, "\n\n" );
					
					if( instance->hostname )
					{
						char		buffer[ 256 ];
						
						SNPrintF( buffer, sizeof( buffer ), "%s:%u", instance->hostname, instance->port );
						FPrintF( stdout, "%*s" "%-51s %4llu ms\n", Indent( 3 ), buffer,
							UpTicksToMilliseconds( instance->resolveDoneTicks - instance->resolveStartTicks ) );
					}
					else
					{
						FPrintF( stdout, "%*s" "%s:%u\n", Indent( 3 ), instance->hostname, instance->port );
					}
					
					for( addr = instance->addrList; addr; addr = addr->next )
					{
						AsyncConnection_Forget( &addr->connection );
						
						if( addr->connectStatus == kConnectStatus_Pending )
						{
							addr->connectStatus	= kConnectStatus_Failed;
							addr->connectError	= kTimeoutErr;
						}
						
						FPrintF( stdout, "%*s" "%-##47a %4llu ms", Indent( 4 ),
							&addr->sip.sa, UpTicksToMilliseconds( addr->foundTicks - instance->getAddrStartTicks ) );
						if( context->maxConnectTimeSecs <= 0 )
						{
							FPrintF( stdout, "\n" );
							continue;
						}
						switch( addr->connectStatus )
						{
							case kConnectStatus_None:
								FPrintF( stdout, " (%s)\n", kStatusStr_NoConnectionAttempted );
								break;
							
							case kConnectStatus_Succeeded:
								FPrintF( stdout, " (%s in %.2f ms)\n",
									context->useColoredText ? kStatusStr_CouldConnectColored : kStatusStr_CouldConnect,
									addr->connectTimeSecs * 1000 );
								break;
							
							case kConnectStatus_Failed:
								FPrintF( stdout, " (%s: %m)\n",
									context->useColoredText ? kStatusStr_CouldNotConnectColored : kStatusStr_CouldNotConnect,
									addr->connectError );
								break;
							
							default:
								FPrintF( stdout, " (%s)\n", kStatusStr_Unknown );
								break;
						}
					}
					
					FPrintF( stdout, "\n" );
					if( instance->txtLen == 0 ) continue;
					
					FPrintF( stdout, "%*s" "TXT record:\n", Indent( 3 ) );
					if( instance->txtLen > 1 )
					{
						FPrintF( stdout, "%3{txt}", instance->txtPtr, instance->txtLen );
					}
					else
					{
						FPrintF( stdout, "%*s" "%#H\n", Indent( 3 ), instance->txtPtr, (int) instance->txtLen, INT_MAX );
					}
					FPrintF( stdout, "\n" );
				}
			}
			FPrintF( stdout, "\n" );
		}
	}
	
	while( ( domain = context->domainList ) != NULL )
	{
		context->domainList = domain->next;
		BrowseDomainFree( domain );
	}
	
	BrowseAllContextRelease( context );
	Exit( NULL );
}

//===========================================================================================================================
//	BrowseAllAddDomain
//===========================================================================================================================

static OSStatus	BrowseAllAddDomain( BrowseAllContext *inContext, const char *inName )
{
	OSStatus			err;
	BrowseDomain *		domain;
	BrowseDomain **		p;
	BrowseDomain *		newDomain = NULL;
	
	for( p = &inContext->domainList; ( domain = *p ) != NULL; p = &domain->next )
	{
		if( strcasecmp( domain->name, inName ) == 0 ) break;
	}
	require_action_quiet( !domain, exit, err = kDuplicateErr );
	
	newDomain = (BrowseDomain *) calloc( 1, sizeof( *newDomain ) );
	require_action( newDomain, exit, err = kNoMemoryErr );
	
	++inContext->refCount;
	newDomain->context = inContext;
	
	newDomain->name = strdup( inName );
	require_action( newDomain->name, exit, err = kNoMemoryErr );
	
	if( inContext->serviceTypesCount > 0 )
	{
		size_t		i;
		
		for( i = 0; i < inContext->serviceTypesCount; ++i )
		{
			err = BrowseAllAddServiceType( inContext, newDomain, inContext->serviceTypes[ i ], inContext->ifIndex,
				inContext->includeAWDL );
			if( err == kDuplicateErr ) err = kNoErr;
			require_noerr( err, exit );
		}
	}
	else
	{
		char *				recordName;
		DNSServiceFlags		flags;
		DNSServiceRef		sdRef;
		
		ASPrintF( &recordName, "_services._dns-sd._udp.%s", newDomain->name );
		require_action( recordName, exit, err = kNoMemoryErr );
		
		flags = kDNSServiceFlagsShareConnection;
		if( inContext->includeAWDL ) flags |= kDNSServiceFlagsIncludeAWDL;
		
		sdRef = newDomain->context->mainRef;
		err = DNSServiceQueryRecord( &sdRef, flags, inContext->ifIndex, recordName, kDNSServiceType_PTR, kDNSServiceClass_IN,
			BrowseAllQueryCallback, newDomain );
		free( recordName );
		require_noerr( err, exit );
		
		newDomain->servicesQuery = sdRef;
	}
	
	*p = newDomain;
	newDomain = NULL;
	err = kNoErr;
	
exit:
	if( newDomain ) BrowseDomainFree( newDomain );
	return( err );
}

//===========================================================================================================================
//	BrowseAllRemoveDomain
//===========================================================================================================================

static OSStatus	BrowseAllRemoveDomain( BrowseAllContext *inContext, const char *inName )
{
	OSStatus			err;
	BrowseDomain *		domain;
	BrowseDomain **		p;
	
	for( p = &inContext->domainList; ( domain = *p ) != NULL; p = &domain->next )
	{
		if( strcasecmp( domain->name, inName ) == 0 ) break;
	}
	
	if( domain )
	{
		*p = domain->next;
		BrowseDomainFree( domain );
		err = kNoErr;
	}
	else
	{
		err = kNotFoundErr;
	}
	
	return( err );
}

//===========================================================================================================================
//	BrowseAllContextRelease
//===========================================================================================================================

static void	BrowseAllContextRelease( BrowseAllContext *inContext )
{
	if( --inContext->refCount == 0 )
	{
		check( !inContext->domainsQuery );
		check( !inContext->domainList );
		check( !inContext->exitTimer );
		check( !inContext->pendingConnectCount );
		DNSServiceForget( &inContext->mainRef );
		if( inContext->serviceTypes )
		{
			StringArray_Free( inContext->serviceTypes, inContext->serviceTypesCount );
			inContext->serviceTypes			= NULL;
			inContext->serviceTypesCount	= 0;
		}
		free( inContext );
	}
}

//===========================================================================================================================
//	BrowseAllAddServiceType
//===========================================================================================================================

static OSStatus
	BrowseAllAddServiceType(
		BrowseAllContext *	inContext,
		BrowseDomain *		inDomain,
		const char *		inName,
		uint32_t			inIfIndex,
		Boolean				inIncludeAWDL )
{
	OSStatus			err;
	DNSServiceRef		sdRef;
	DNSServiceFlags		flags;
	BrowseType *		type;
	BrowseType **		typePtr;
	BrowseType *		newType		= NULL;
	BrowseOp *			browse;
	BrowseOp **			browsePtr;
	BrowseOp *			newBrowse	= NULL;
	
	for( typePtr = &inDomain->typeList; ( type = *typePtr ) != NULL; typePtr = &type->next )
	{
		if( strcasecmp( type->name, inName ) == 0 ) break;
	}
	if( !type )
	{
		newType = (BrowseType *) calloc( 1, sizeof( *newType ) );
		require_action( newType, exit, err = kNoMemoryErr );
		
		newType->name = strdup( inName );
		require_action( newType->name, exit, err = kNoMemoryErr );
		
		type = newType;
	}
	
	for( browsePtr = &type->browseList; ( browse = *browsePtr ) != NULL; browsePtr = &browse->next )
	{
		if( browse->ifIndex == inIfIndex ) break;
	}
	require_action_quiet( !browse, exit, err = kDuplicateErr );
	
	newBrowse = (BrowseOp *) calloc( 1, sizeof( *newBrowse ) );
	require_action( newBrowse, exit, err = kNoMemoryErr );
	
	++inContext->refCount;
	newBrowse->context	= inContext;
	newBrowse->ifIndex	= inIfIndex;
	if( stricmp_suffix( inName, "._tcp" ) == 0 ) newBrowse->isTCP = true;
	
	flags = kDNSServiceFlagsShareConnection;
	if( inIncludeAWDL ) flags |= kDNSServiceFlagsIncludeAWDL;
	
	newBrowse->startTicks = UpTicks();
	
	sdRef = inContext->mainRef;
	err = DNSServiceBrowse( &sdRef, flags, newBrowse->ifIndex, type->name, inDomain->name, BrowseAllBrowseCallback,
		newBrowse );
	require_noerr( err, exit );
	
	newBrowse->browse = sdRef;
	*browsePtr = newBrowse;
	newBrowse = NULL;
	
	if( newType )
	{
		*typePtr = newType;
		newType = NULL;
	}
	
exit:
	if( newBrowse )	BrowseOpFree( newBrowse );
	if( newType )	BrowseTypeFree( newType );
	return( err );
}

//===========================================================================================================================
//	BrowseAllRemoveServiceType
//===========================================================================================================================

static OSStatus
	BrowseAllRemoveServiceType(
		BrowseAllContext *	inContext,
		BrowseDomain *		inDomain,
		const char *		inName,
		uint32_t			inIfIndex )
{
	OSStatus			err;
	BrowseType *		type;
	BrowseType **		typePtr;
	BrowseOp *			browse;
	BrowseOp **			browsePtr;
	
	Unused( inContext );
	
	for( typePtr = &inDomain->typeList; ( type = *typePtr ) != NULL; typePtr = &type->next )
	{
		if( strcasecmp( type->name, inName ) == 0 ) break;
	}
	require_action_quiet( type, exit, err = kNotFoundErr );
	
	for( browsePtr = &type->browseList; ( browse = *browsePtr ) != NULL; browsePtr = &browse->next )
	{
		if( browse->ifIndex == inIfIndex ) break;
	}
	require_action_quiet( browse, exit, err = kNotFoundErr );
	
	*browsePtr = browse->next;
	BrowseOpFree( browse );
	if( !type->browseList )
	{
		*typePtr = type->next;
		BrowseTypeFree( type );
	}
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	BrowseAllAddServiceInstance
//===========================================================================================================================

static OSStatus
	BrowseAllAddServiceInstance(
		BrowseAllContext *	inContext,
		BrowseOp *			inBrowse,
		const char *		inName,
		const char *		inRegType,
		const char *		inDomain,
		uint32_t			inIfIndex )
{
	OSStatus				err;
	DNSServiceRef			sdRef;
	BrowseInstance *		instance;
	BrowseInstance **		p;
	const uint64_t			nowTicks	= UpTicks();
	BrowseInstance *		newInstance	= NULL;
	
	for( p = &inBrowse->instanceList; ( instance = *p ) != NULL; p = &instance->next )
	{
		if( ( instance->ifIndex == inIfIndex ) && ( strcasecmp( instance->name, inName ) == 0 ) ) break;
	}
	require_action_quiet( !instance, exit, err = kDuplicateErr );
	
	newInstance = (BrowseInstance *) calloc( 1, sizeof( *newInstance ) );
	require_action( newInstance, exit, err = kNoMemoryErr );
	
	++inContext->refCount;
	newInstance->context	= inContext;
	newInstance->foundTicks	= nowTicks;
	newInstance->ifIndex	= inIfIndex;
	newInstance->isTCP		= inBrowse->isTCP;
	
	newInstance->name = strdup( inName );
	require_action( newInstance->name, exit, err = kNoMemoryErr );
	
	sdRef = inContext->mainRef;
	newInstance->resolveStartTicks = UpTicks();
	err = DNSServiceResolve( &sdRef, kDNSServiceFlagsShareConnection, newInstance->ifIndex, inName, inRegType, inDomain,
		BrowseAllResolveCallback, newInstance );
	require_noerr( err, exit );
	
	newInstance->resolve = sdRef;
	*p = newInstance;
	newInstance = NULL;
	
exit:
	if( newInstance ) BrowseInstanceFree( newInstance );
	return( err );
}

//===========================================================================================================================
//	BrowseAllRemoveServiceInstance
//===========================================================================================================================

static OSStatus
	BrowseAllRemoveServiceInstance(
		BrowseAllContext *	inContext,
		BrowseOp *			inBrowse,
		const char *		inName,
		uint32_t			inIfIndex )
{
	OSStatus				err;
	BrowseInstance *		instance;
	BrowseInstance **		p;
	
	Unused( inContext );
	
	for( p = &inBrowse->instanceList; ( instance = *p ) != NULL; p = &instance->next )
	{
		if( ( instance->ifIndex == inIfIndex ) && ( strcasecmp( instance->name, inName ) == 0 ) ) break;
	}
	require_action_quiet( instance, exit, err = kNotFoundErr );
	
	*p = instance->next;
	BrowseInstanceFree( instance );
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	BrowseAllAddIPAddress
//===========================================================================================================================

#define kDiscardProtocolPort	9

static OSStatus
	BrowseAllAddIPAddress(
		BrowseAllContext *		inContext,
		BrowseInstance *		inInstance,
		const struct sockaddr *	inSockAddr )
{
	OSStatus			err;
	BrowseIPAddr *		addr;
	BrowseIPAddr **		p;
	const uint64_t		nowTicks	= UpTicks();
	BrowseIPAddr *		newAddr		= NULL;
	
	if( ( inSockAddr->sa_family != AF_INET ) && ( inSockAddr->sa_family != AF_INET6 ) )
	{
		dlogassert( "Unexpected address family: %d", inSockAddr->sa_family );
		err = kTypeErr;
		goto exit;
	}
	
	for( p = &inInstance->addrList; ( addr = *p ) != NULL; p = &addr->next )
	{
		if( SockAddrCompareAddr( &addr->sip, inSockAddr ) == 0 ) break;
	}
	require_action_quiet( !addr, exit, err = kDuplicateErr );
	
	newAddr = (BrowseIPAddr *) calloc( 1, sizeof( *newAddr ) );
	require_action( newAddr, exit, err = kNoMemoryErr );
	
	++inContext->refCount;
	newAddr->refCount	= 1;
	newAddr->context	= inContext;
	newAddr->foundTicks	= nowTicks;
	SockAddrCopy( inSockAddr, &newAddr->sip.sa );
	
	if( ( inContext->maxConnectTimeSecs > 0 ) && inInstance->isTCP && ( inInstance->port != kDiscardProtocolPort ) )
	{
		char		destination[ kSockAddrStringMaxSize ];
		
		err = SockAddrToString( &newAddr->sip, kSockAddrStringFlagsNoPort, destination );
		require_noerr( err, exit );
		
		err = AsyncConnection_Connect( &newAddr->connection, destination, -inInstance->port, kAsyncConnectionFlag_P2P,
			kAsyncConnectionNoTimeout, kSocketBufferSize_DontSet, kSocketBufferSize_DontSet,
			BrowseAllConnectionProgress, newAddr, BrowseAllConnectionHandler, newAddr, dispatch_get_main_queue() );
		require_noerr( err, exit );
		
		++newAddr->refCount;
		newAddr->connectStatus = kConnectStatus_Pending;
		++inContext->pendingConnectCount;
	}
	
	*p = newAddr;
	newAddr = NULL;
	err = kNoErr;
	
exit:
	if( newAddr ) BrowseIPAddrRelease( newAddr );
	return( err );
}

//===========================================================================================================================
//	BrowseAllRemoveIPAddress
//===========================================================================================================================

static OSStatus
	BrowseAllRemoveIPAddress(
		BrowseAllContext *		inContext,
		BrowseInstance *		inInstance,
		const struct sockaddr *	inSockAddr )
{
	OSStatus			err;
	BrowseIPAddr *		addr;
	BrowseIPAddr **		p;
	
	Unused( inContext );
	
	for( p = &inInstance->addrList; ( addr = *p ) != NULL; p = &addr->next )
	{
		if( SockAddrCompareAddr( &addr->sip.sa, inSockAddr ) == 0 ) break;
	}
	require_action_quiet( addr, exit, err = kNotFoundErr );
	
	*p = addr->next;
	BrowseIPAddrRelease( addr );
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	BrowseDomainFree
//===========================================================================================================================

static void	BrowseDomainFree( BrowseDomain *inDomain )
{
	BrowseType *		type;
	
	ForgetBrowseAllContext( &inDomain->context );
	ForgetMem( &inDomain->name );
	DNSServiceForget( &inDomain->servicesQuery );
	while( ( type = inDomain->typeList ) != NULL )
	{
		inDomain->typeList = type->next;
		BrowseTypeFree( type );
	}
	free( inDomain );
}

//===========================================================================================================================
//	BrowseTypeFree
//===========================================================================================================================

static void	BrowseTypeFree( BrowseType *inType )
{
	BrowseOp *		browse;
	
	ForgetMem( &inType->name );
	while( ( browse = inType->browseList ) != NULL )
	{
		inType->browseList = browse->next;
		BrowseOpFree( browse );
	}
	free( inType );
}

//===========================================================================================================================
//	BrowseOpFree
//===========================================================================================================================

static void	BrowseOpFree( BrowseOp *inBrowse )
{
	BrowseInstance *		instance;
	
	ForgetBrowseAllContext( &inBrowse->context );
	DNSServiceForget( &inBrowse->browse );
	while( ( instance = inBrowse->instanceList ) != NULL )
	{
		inBrowse->instanceList = instance->next;
		BrowseInstanceFree( instance );
	}
	free( inBrowse );
}

//===========================================================================================================================
//	BrowseInstanceFree
//===========================================================================================================================

static void	BrowseInstanceFree( BrowseInstance *inInstance )
{
	ForgetBrowseAllContext( &inInstance->context );
	ForgetMem( &inInstance->name );
	DNSServiceForget( &inInstance->resolve );
	DNSServiceForget( &inInstance->getAddr );
	ForgetMem( &inInstance->txtPtr );
	ForgetMem( &inInstance->hostname );
	ForgetIPAddressList( &inInstance->addrList );
	free( inInstance );
}

//===========================================================================================================================
//	BrowseIPAddrRelease
//===========================================================================================================================

static void BrowseIPAddrRelease( BrowseIPAddr *inAddr )
{
	AsyncConnection_Forget( &inAddr->connection );
	if( --inAddr->refCount == 0 )
	{
		ForgetBrowseAllContext( &inAddr->context );
		free( inAddr );
	}
}

//===========================================================================================================================
//	BrowseIPAddrReleaseList
//===========================================================================================================================

static void BrowseIPAddrReleaseList( BrowseIPAddr *inList )
{
	BrowseIPAddr *		addr;
	
	while( ( addr = inList ) != NULL )
	{
		inList = addr->next;
		BrowseIPAddrRelease( addr );
	}
}

//===========================================================================================================================
//	GetNameInfoCmd
//===========================================================================================================================

const FlagStringPair		kGetNameInfoFlagStringPairs[] =
{
	CaseFlagStringify( NI_NUMERICSCOPE ),
	CaseFlagStringify( NI_DGRAM ),
	CaseFlagStringify( NI_NUMERICSERV ),
	CaseFlagStringify( NI_NAMEREQD ),
	CaseFlagStringify( NI_NUMERICHOST ),
	CaseFlagStringify( NI_NOFQDN ),
	{ 0, NULL }
};

static void	GetNameInfoCmd( void )
{
	OSStatus					err;
	sockaddr_ip					sip;
	size_t						sockAddrLen;
	unsigned int				flags;
	const FlagStringPair *		pair;
	struct timeval				now;
	char						host[ NI_MAXHOST ];
	char						serv[ NI_MAXSERV ];
	
	err = StringToSockAddr( gGetNameInfo_IPAddress, &sip, sizeof( sip ), &sockAddrLen );
	check_noerr( err );
	if( err )
	{
		FPrintF( stderr, "Failed to convert \"%s\" to a sockaddr.\n", gGetNameInfo_IPAddress );
		goto exit;
	}
	
	flags = 0;
	if( gGetNameInfoFlag_DGram )		flags |= NI_DGRAM;
	if( gGetNameInfoFlag_NameReqd )		flags |= NI_NAMEREQD;
	if( gGetNameInfoFlag_NoFQDN )		flags |= NI_NOFQDN;
	if( gGetNameInfoFlag_NumericHost )	flags |= NI_NUMERICHOST;
	if( gGetNameInfoFlag_NumericScope )	flags |= NI_NUMERICSCOPE;
	if( gGetNameInfoFlag_NumericServ )	flags |= NI_NUMERICSERV;
	
	// Print prologue.
	
	FPrintF( stdout, "SockAddr:   %##a\n",	&sip.sa );
	FPrintF( stdout, "Flags:      0x%X < ",	flags );
	for( pair = kGetNameInfoFlagStringPairs; pair->str != NULL; ++pair )
	{
		if( flags & pair->flag ) FPrintF( stdout, "%s ", pair->str );
	}
	FPrintF( stdout, ">\n" );
	FPrintF( stdout, "Start time: %{du:time}\n", NULL );
	FPrintF( stdout, "---\n" );
	
	// Call getnameinfo().
	
	err = getnameinfo( &sip.sa, (socklen_t) sockAddrLen, host, (socklen_t) sizeof( host ), serv, (socklen_t) sizeof( serv ),
		(int) flags );
	gettimeofday( &now, NULL );
	if( err )
	{
		FPrintF( stderr, "Error %d: %s.\n", err, gai_strerror( err ) );
	}
	else
	{
		FPrintF( stdout, "host: %s\n", host );
		FPrintF( stdout, "serv: %s\n", serv );
	}
	FPrintF( stdout, "---\n" );
	FPrintF( stdout, "End time:   %{du:time}\n", &now );
	
exit:
	gExitCode = err ? 1 : 0;
}

//===========================================================================================================================
//	GetAddrInfoStressCmd
//===========================================================================================================================

typedef struct
{
	DNSServiceRef			mainRef;
	DNSServiceRef			sdRef;
	DNSServiceFlags			flags;
	unsigned int			interfaceIndex;
	unsigned int			connectionNumber;
	unsigned int			requestCount;
	unsigned int			requestCountMax;
	unsigned int			requestCountLimit;
	unsigned int			durationMinMs;
	unsigned int			durationMaxMs;
	
}	GAIStressContext;

static void	GetAddrInfoStressEvent( void *inContext );
static void	DNSSD_API
	GetAddrInfoStressCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext );

static void	GetAddrInfoStressCmd( void )
{
	OSStatus				err;
	GAIStressContext *		context = NULL;
	int						i;
	DNSServiceFlags			flags;
	uint32_t				ifIndex;
	char					ifName[ kInterfaceNameBufLen ];
	
	if( gGAIStress_TestDurationSecs < 0 )
	{
		FPrintF( stdout, "Invalid test duration: %d s.\n", gGAIStress_TestDurationSecs );
		err = kParamErr;
		goto exit;
	}
	if( gGAIStress_ConnectionCount <= 0 )
	{
		FPrintF( stdout, "Invalid simultaneous connection count: %d.\n", gGAIStress_ConnectionCount );
		err = kParamErr;
		goto exit;
	}
	if( gGAIStress_DurationMinMs <= 0 )
	{
		FPrintF( stdout, "Invalid minimum DNSServiceGetAddrInfo() duration: %d ms.\n", gGAIStress_DurationMinMs );
		err = kParamErr;
		goto exit;
	}
	if( gGAIStress_DurationMaxMs <= 0 )
	{
		FPrintF( stdout, "Invalid maximum DNSServiceGetAddrInfo() duration: %d ms.\n", gGAIStress_DurationMaxMs );
		err = kParamErr;
		goto exit;
	}
	if( gGAIStress_DurationMinMs > gGAIStress_DurationMaxMs )
	{
		FPrintF( stdout, "Invalid minimum and maximum DNSServiceGetAddrInfo() durations: %d ms and %d ms.\n",
			gGAIStress_DurationMinMs, gGAIStress_DurationMaxMs );
		err = kParamErr;
		goto exit;
	}
	if( gGAIStress_RequestCountMax <= 0 )
	{
		FPrintF( stdout, "Invalid maximum request count: %d.\n", gGAIStress_RequestCountMax );
		err = kParamErr;
		goto exit;
	}
	
	// Set flags.
	
	flags = GetDNSSDFlagsFromOpts();
	
	// Set interface index.
	
	err = InterfaceIndexFromArgString( gInterface, &ifIndex );
	require_noerr_quiet( err, exit );
	
	for( i = 0; i < gGAIStress_ConnectionCount; ++i )
	{
		context = (GAIStressContext *) calloc( 1, sizeof( *context ) );
		require_action( context, exit, err = kNoMemoryErr );
		
		context->flags				= flags;
		context->interfaceIndex		= ifIndex;
		context->connectionNumber	= (unsigned int)( i + 1 );
		context->requestCountMax	= (unsigned int) gGAIStress_RequestCountMax;
		context->durationMinMs		= (unsigned int) gGAIStress_DurationMinMs;
		context->durationMaxMs		= (unsigned int) gGAIStress_DurationMaxMs;
		
		dispatch_async_f( dispatch_get_main_queue(), context, GetAddrInfoStressEvent );
		context = NULL;
	}
	
	if( gGAIStress_TestDurationSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( gGAIStress_TestDurationSecs ), dispatch_get_main_queue(), NULL, Exit );
	}
	
	FPrintF( stdout, "Flags:                %#{flags}\n",	flags, kDNSServiceFlagsDescriptors );
	FPrintF( stdout, "Interface:            %d (%s)\n",		(int32_t) ifIndex, InterfaceIndexToName( ifIndex, ifName ) );
	FPrintF( stdout, "Test duration:        " );
	if( gGAIStress_TestDurationSecs == 0 )
	{
		FPrintF( stdout, "∞\n" );
	}
	else
	{
		FPrintF( stdout, "%d s\n", gGAIStress_TestDurationSecs );
	}
	FPrintF( stdout, "Connection count:     %d\n",			gGAIStress_ConnectionCount );
	FPrintF( stdout, "Request duration min: %d ms\n",		gGAIStress_DurationMinMs );
	FPrintF( stdout, "Request duration max: %d ms\n",		gGAIStress_DurationMaxMs );
	FPrintF( stdout, "Request count max:    %d\n",			gGAIStress_RequestCountMax );
	FPrintF( stdout, "Start time:           %{du:time}\n",	NULL);
	FPrintF( stdout, "---\n" );
	
	dispatch_main();
	
exit:
	FreeNullSafe( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	GetAddrInfoStressEvent
//===========================================================================================================================

#define kStressRandStrLen		5

#define kLowercaseAlphaCharSet		"abcdefghijklmnopqrstuvwxyz"

static void	GetAddrInfoStressEvent( void *inContext )
{
	GAIStressContext * const		context = (GAIStressContext *) inContext;
	OSStatus						err;
	DNSServiceRef					sdRef;
	unsigned int					nextMs;
	char							randomStr[ kStressRandStrLen + 1 ];
	char							hostname[ kStressRandStrLen + 4 + 1 ];
	Boolean							isConnectionNew	= false;
	static Boolean					printedHeader	= false;
	
	if( !context->mainRef || ( context->requestCount >= context->requestCountLimit ) )
	{
		DNSServiceForget( &context->mainRef );
		context->sdRef				= NULL;
		context->requestCount		= 0;
		context->requestCountLimit	= RandomRange( 1, context->requestCountMax );
		
		err = DNSServiceCreateConnection( &context->mainRef );
		require_noerr( err, exit );
		
		err = DNSServiceSetDispatchQueue( context->mainRef, dispatch_get_main_queue() );
		require_noerr( err, exit );
		
		isConnectionNew = true;
	}
	
	RandomString( kLowercaseAlphaCharSet, sizeof_string( kLowercaseAlphaCharSet ), 2, kStressRandStrLen, randomStr );
	SNPrintF( hostname, sizeof( hostname ), "%s.com", randomStr );
	
	nextMs = RandomRange( context->durationMinMs, context->durationMaxMs );
	
	if( !printedHeader )
	{
		FPrintF( stdout, "%-26s Conn  Hostname Dur (ms)\n", "Timestamp" );
		printedHeader = true;
	}
	FPrintF( stdout, "%{du:time} %3u%c %9s %8u\n",
		NULL, context->connectionNumber, isConnectionNew ? '*': ' ', hostname, nextMs );
	
	DNSServiceForget( &context->sdRef );
	sdRef = context->mainRef;
	err = DNSServiceGetAddrInfo( &sdRef, context->flags | kDNSServiceFlagsShareConnection, context->interfaceIndex,
		kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6, hostname, GetAddrInfoStressCallback, NULL );
	require_noerr( err, exit );
	context->sdRef = sdRef;
	
	context->requestCount++;
	
	dispatch_after_f( dispatch_time_milliseconds( nextMs ), dispatch_get_main_queue(), context, GetAddrInfoStressEvent );
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	GetAddrInfoStressCallback
//===========================================================================================================================

static void DNSSD_API
	GetAddrInfoStressCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext )
{
	Unused( inSDRef );
	Unused( inFlags );
	Unused( inInterfaceIndex );
	Unused( inError );
	Unused( inHostname );
	Unused( inSockAddr );
	Unused( inTTL );
	Unused( inContext );
}

//===========================================================================================================================
//	DNSQueryCmd
//===========================================================================================================================

typedef struct
{
	sockaddr_ip				serverAddr;
	uint64_t				sendTicks;
	uint8_t *				msgPtr;
	size_t					msgLen;
	size_t					msgOffset;
	const char *			name;
	dispatch_source_t		readSource;
	SocketRef				sock;
	int						timeLimitSecs;
	uint16_t				queryID;
	uint16_t				type;
	Boolean					haveTCPLen;
	Boolean					useTCP;
	Boolean					printRawRData;	// True if RDATA results are not to be formatted.
	uint8_t					msgBuf[ 512 ];
	
}	DNSQueryContext;

static void	DNSQueryPrintPrologue( const DNSQueryContext *inContext );
static void	DNSQueryReadHandler( void *inContext );
static void	DNSQueryCancelHandler( void *inContext );

static void	DNSQueryCmd( void )
{
	OSStatus				err;
	DNSQueryContext *		context = NULL;
	uint8_t *				msgPtr;
	size_t					msgLen, sendLen;
	
	// Check command parameters.
	
	if( gDNSQuery_TimeLimitSecs < -1 )
	{
		FPrintF( stdout, "Invalid time limit: %d seconds.\n", gDNSQuery_TimeLimitSecs );
		err = kParamErr;
		goto exit;
	}
	if( ( gDNSQuery_Flags < INT16_MIN ) || ( gDNSQuery_Flags > UINT16_MAX ) )
	{
		FPrintF( stdout, "DNS flags-and-codes value is out of the unsigned 16-bit range: 0x%08X.\n", gDNSQuery_Flags );
		err = kParamErr;
		goto exit;
	}
	
	// Create context.
	
	context = (DNSQueryContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->name			= gDNSQuery_Name;
	context->sock			= kInvalidSocketRef;
	context->timeLimitSecs	= gDNSQuery_TimeLimitSecs;
	context->queryID		= (uint16_t) Random32();
	context->useTCP			= gDNSQuery_UseTCP	 ? true : false;
	context->printRawRData	= gDNSQuery_RawRData ? true : false;
	
#if( TARGET_OS_DARWIN )
	if( gDNSQuery_Server )
#endif
	{
		err = StringToSockAddr( gDNSQuery_Server, &context->serverAddr, sizeof( context->serverAddr ), NULL );
		require_noerr( err, exit );
	}
#if( TARGET_OS_DARWIN )
	else
	{
		err = GetDefaultDNSServer( &context->serverAddr );
		require_noerr( err, exit );
	}
#endif
	if( SockAddrGetPort( &context->serverAddr ) == 0 ) SockAddrSetPort( &context->serverAddr, kDNSPort );
	
	err = RecordTypeFromArgString( gDNSQuery_Type, &context->type );
	require_noerr( err, exit );
	
	// Write query message.
	
	check_compile_time_code( sizeof( context->msgBuf ) >= ( kDNSQueryMessageMaxLen + 2 ) );
	
	msgPtr = context->useTCP ? &context->msgBuf[ 2 ] : context->msgBuf;
	err = WriteDNSQueryMessage( msgPtr, context->queryID, (uint16_t) gDNSQuery_Flags, context->name, context->type,
		kDNSServiceClass_IN, &msgLen );
	require_noerr( err, exit );
	check( msgLen <= UINT16_MAX );
	
	if( context->useTCP )
	{
		WriteBig16( context->msgBuf, msgLen );
		sendLen = 2 + msgLen;
	}
	else
	{
		sendLen = msgLen;
	}
	
	DNSQueryPrintPrologue( context );
	
	if( gDNSQuery_Verbose )
	{
		FPrintF( stdout, "DNS message to send:\n\n%{du:dnsmsg}", msgPtr, msgLen );
		FPrintF( stdout, "---\n" );
	}
	
	if( context->useTCP )
	{
		// Create TCP socket.
		
		context->sock = socket( context->serverAddr.sa.sa_family, SOCK_STREAM, IPPROTO_TCP );
		err = map_socket_creation_errno( context->sock );
		require_noerr( err, exit );
		
		err = SocketConnect( context->sock, &context->serverAddr, 5 );
		require_noerr( err, exit );
	}
	else
	{
		// Create UDP socket.
		
		err = UDPClientSocketOpen( AF_UNSPEC, &context->serverAddr, 0, -1, NULL, &context->sock );
		require_noerr( err, exit );
	}
	
	context->sendTicks = UpTicks();
	err = SocketWriteAll( context->sock, context->msgBuf, sendLen, 5 );
	require_noerr( err, exit );
	
	if( context->timeLimitSecs == 0 ) goto exit;
	
	err = DispatchReadSourceCreate( context->sock, NULL, DNSQueryReadHandler, DNSQueryCancelHandler, context,
		&context->readSource );
	require_noerr( err, exit );
	dispatch_resume( context->readSource );
	
	if( context->timeLimitSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->timeLimitSecs ), dispatch_get_main_queue(), kExitReason_Timeout,
			Exit );
	}
	dispatch_main();
	
exit:
	if( context )
	{
		dispatch_source_forget( &context->readSource );
		ForgetSocket( &context->sock );
		free( context );
	}
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	DNSQueryPrintPrologue
//===========================================================================================================================

static void	DNSQueryPrintPrologue( const DNSQueryContext *inContext )
{
	const int		timeLimitSecs = inContext->timeLimitSecs;
	
	FPrintF( stdout, "Name:        %s\n",		inContext->name );
	FPrintF( stdout, "Type:        %s (%u)\n",	RecordTypeToString( inContext->type ), inContext->type );
	FPrintF( stdout, "Server:      %##a\n",		&inContext->serverAddr );
	FPrintF( stdout, "Transport:   %s\n",		inContext->useTCP ? "TCP" : "UDP" );
	FPrintF( stdout, "Time limit:  " );
	if( timeLimitSecs >= 0 )	FPrintF( stdout, "%d second%?c\n", timeLimitSecs, timeLimitSecs != 1, 's' );
	else						FPrintF( stdout, "∞\n" );
	FPrintF( stdout, "Start time:  %{du:time}\n", NULL );
	FPrintF( stdout, "---\n" );
}

//===========================================================================================================================
//	DNSQueryReadHandler
//===========================================================================================================================

static void	DNSQueryReadHandler( void *inContext )
{
	OSStatus					err;
	struct timeval				now;
	const uint64_t				nowTicks	= UpTicks();
	DNSQueryContext * const		context		= (DNSQueryContext *) inContext;
	
	gettimeofday( &now, NULL );
	
	if( context->useTCP )
	{
		if( !context->haveTCPLen )
		{
			err = SocketReadData( context->sock, &context->msgBuf, 2, &context->msgOffset );
			if( err == EWOULDBLOCK ) { err = kNoErr; goto exit; }
			require_noerr( err, exit );
			
			context->msgOffset	= 0;
			context->msgLen		= ReadBig16( context->msgBuf );
			context->haveTCPLen	= true;
			if( context->msgLen <= sizeof( context->msgBuf ) )
			{
				context->msgPtr = context->msgBuf;
			}
			else
			{
				context->msgPtr = (uint8_t *) malloc( context->msgLen );
				require_action( context->msgPtr, exit, err = kNoMemoryErr );
			}
		}
		
		err = SocketReadData( context->sock, context->msgPtr, context->msgLen, &context->msgOffset );
		if( err == EWOULDBLOCK ) { err = kNoErr; goto exit; }
		require_noerr( err, exit );
		context->msgOffset	= 0;
		context->haveTCPLen	= false;
	}
	else
	{
		sockaddr_ip		fromAddr;
		
		context->msgPtr = context->msgBuf;
		err = SocketRecvFrom( context->sock, context->msgPtr, sizeof( context->msgBuf ), &context->msgLen, &fromAddr,
			sizeof( fromAddr ), NULL, NULL, NULL, NULL );
		require_noerr( err, exit );
		
		check( SockAddrCompareAddr( &fromAddr, &context->serverAddr ) == 0 );
	}
	
	FPrintF( stdout, "Receive time: %{du:time}\n",	&now );
	FPrintF( stdout, "Source:       %##a\n",		&context->serverAddr );
	FPrintF( stdout, "Message size: %zu\n",			context->msgLen );
	FPrintF( stdout, "RTT:          %llu ms\n\n",	UpTicksToMilliseconds( nowTicks - context->sendTicks ) );
	FPrintF( stdout, "%.*{du:dnsmsg}", context->printRawRData ? 1 : 0, context->msgPtr, context->msgLen );
	
	if( ( context->msgLen >= kDNSHeaderLength ) && ( DNSHeaderGetID( (DNSHeader *) context->msgPtr ) == context->queryID ) )
	{
		Exit( kExitReason_ReceivedResponse );
	}
	
exit:
	if( err ) dispatch_source_forget( &context->readSource );
}

//===========================================================================================================================
//	DNSQueryCancelHandler
//===========================================================================================================================

static void	DNSQueryCancelHandler( void *inContext )
{
	DNSQueryContext * const		context = (DNSQueryContext *) inContext;
	
	check( !context->readSource );
	ForgetSocket( &context->sock );
	if( context->msgPtr != context->msgBuf ) ForgetMem( &context->msgPtr );
	free( context );
	dispatch_async_f( dispatch_get_main_queue(), NULL, Exit );
}

#if( DNSSDUTIL_INCLUDE_DNSCRYPT )
//===========================================================================================================================
//	DNSCryptCmd
//===========================================================================================================================

#define kDNSCryptPort		443

#define kDNSCryptMinPadLength				8
#define kDNSCryptMaxPadLength				256
#define kDNSCryptBlockSize					64
#define kDNSCryptCertMinimumLength			124
#define kDNSCryptClientMagicLength			8
#define kDNSCryptResolverMagicLength		8
#define kDNSCryptHalfNonceLength			12
#define kDNSCryptCertMagicLength			4

check_compile_time( ( kDNSCryptHalfNonceLength * 2 ) == crypto_box_NONCEBYTES );

static const uint8_t		kDNSCryptCertMagic[ kDNSCryptCertMagicLength ] = { 'D', 'N', 'S', 'C' };
static const uint8_t		kDNSCryptResolverMagic[ kDNSCryptResolverMagicLength ] =
{
	0x72, 0x36, 0x66, 0x6e, 0x76, 0x57, 0x6a, 0x38
};

typedef struct
{
	uint8_t		certMagic[ kDNSCryptCertMagicLength ];
	uint8_t		esVersion[ 2 ];
	uint8_t		minorVersion[ 2 ];
	uint8_t		signature[ crypto_sign_BYTES ];
	uint8_t		publicKey[ crypto_box_PUBLICKEYBYTES ];
	uint8_t		clientMagic[ kDNSCryptClientMagicLength ];
	uint8_t		serial[ 4 ];
	uint8_t		startTime[ 4 ];
	uint8_t		endTime[ 4 ];
	uint8_t		extensions[ 1 ];	// Variably-sized extension data.
	
}	DNSCryptCert;

check_compile_time( offsetof( DNSCryptCert, extensions ) == kDNSCryptCertMinimumLength );

typedef struct
{
	uint8_t		clientMagic[ kDNSCryptClientMagicLength ];
	uint8_t		clientPublicKey[ crypto_box_PUBLICKEYBYTES ];
	uint8_t		clientNonce[ kDNSCryptHalfNonceLength ];
	uint8_t		poly1305MAC[ 16 ];
	
}	DNSCryptQueryHeader;

check_compile_time( sizeof( DNSCryptQueryHeader ) == 68 );
check_compile_time( sizeof( DNSCryptQueryHeader ) >= crypto_box_ZEROBYTES );
check_compile_time( ( sizeof( DNSCryptQueryHeader ) - crypto_box_ZEROBYTES + crypto_box_BOXZEROBYTES ) ==
	offsetof( DNSCryptQueryHeader, poly1305MAC ) );

typedef struct
{
	uint8_t		resolverMagic[ kDNSCryptResolverMagicLength ];
	uint8_t		clientNonce[ kDNSCryptHalfNonceLength ];
	uint8_t		resolverNonce[ kDNSCryptHalfNonceLength ];
	uint8_t		poly1305MAC[ 16 ];
	
}	DNSCryptResponseHeader;

check_compile_time( sizeof( DNSCryptResponseHeader ) == 48 );
check_compile_time( offsetof( DNSCryptResponseHeader, poly1305MAC ) >= crypto_box_BOXZEROBYTES );
check_compile_time( ( offsetof( DNSCryptResponseHeader, poly1305MAC ) - crypto_box_BOXZEROBYTES + crypto_box_ZEROBYTES ) ==
	sizeof( DNSCryptResponseHeader ) );

typedef struct
{
	sockaddr_ip				serverAddr;
	uint64_t				sendTicks;
	const char *			providerName;
	const char *			qname;
	const uint8_t *			certPtr;
	size_t					certLen;
	dispatch_source_t		readSource;
	size_t					msgLen;
	int						timeLimitSecs;
	uint16_t				queryID;
	uint16_t				qtype;
	Boolean					printRawRData;
	uint8_t					serverPublicSignKey[ crypto_sign_PUBLICKEYBYTES ];
	uint8_t					serverPublicKey[ crypto_box_PUBLICKEYBYTES ];
	uint8_t					clientPublicKey[ crypto_box_PUBLICKEYBYTES ];
	uint8_t					clientSecretKey[ crypto_box_SECRETKEYBYTES ];
	uint8_t					clientMagic[ kDNSCryptClientMagicLength ];
	uint8_t					clientNonce[ kDNSCryptHalfNonceLength ];
	uint8_t					nmKey[ crypto_box_BEFORENMBYTES ];
	uint8_t					msgBuf[ 512 ];
	
}	DNSCryptContext;

static void		DNSCryptReceiveCertHandler( void *inContext );
static void		DNSCryptReceiveResponseHandler( void *inContext );
static void		DNSCryptProceed( void *inContext );
static OSStatus	DNSCryptProcessCert( DNSCryptContext *inContext );
static OSStatus	DNSCryptBuildQuery( DNSCryptContext *inContext );
static OSStatus	DNSCryptSendQuery( DNSCryptContext *inContext );
static void		DNSCryptPrintCertificate( const DNSCryptCert *inCert, size_t inLen );

static void	DNSCryptCmd( void )
{
	OSStatus				err;
	DNSCryptContext *		context		= NULL;
	size_t					writtenBytes;
	size_t					totalBytes;
	SocketContext *			sockCtx;
	SocketRef				sock		= kInvalidSocketRef;
	const char *			ptr;
	
	// Check command parameters.
	
	if( gDNSCrypt_TimeLimitSecs < -1 )
	{
		FPrintF( stdout, "Invalid time limit: %d seconds.\n", gDNSCrypt_TimeLimitSecs );
		err = kParamErr;
		goto exit;
	}
	
	// Create context.
	
	context = (DNSCryptContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->providerName	= gDNSCrypt_ProviderName;
	context->qname			= gDNSCrypt_Name;
	context->timeLimitSecs	= gDNSCrypt_TimeLimitSecs;
	context->printRawRData	= gDNSCrypt_RawRData ? true : false;
	
	err = crypto_box_keypair( context->clientPublicKey, context->clientSecretKey );
	require_noerr( err, exit );
	
	err = HexToData( gDNSCrypt_ProviderKey, kSizeCString, kHexToData_DefaultFlags,
		context->serverPublicSignKey, sizeof( context->serverPublicSignKey ), &writtenBytes, &totalBytes, &ptr );
	if( err || ( *ptr != '\0' ) )
	{
		FPrintF( stderr, "Failed to parse public signing key hex string (%s).\n", gDNSCrypt_ProviderKey );
		goto exit;
	}
	else if( totalBytes != sizeof( context->serverPublicSignKey ) )
	{
		FPrintF( stderr, "Public signing key contains incorrect number of hex bytes (%zu != %zu)\n",
			totalBytes, sizeof( context->serverPublicSignKey ) );
		err = kSizeErr;
		goto exit;
	}
	check( writtenBytes == totalBytes );
	
	err = StringToSockAddr( gDNSCrypt_Server, &context->serverAddr, sizeof( context->serverAddr ), NULL );
	require_noerr( err, exit );
	if( SockAddrGetPort( &context->serverAddr ) == 0 ) SockAddrSetPort( &context->serverAddr, kDNSCryptPort );
	
	err = RecordTypeFromArgString( gDNSCrypt_Type, &context->qtype );
	require_noerr( err, exit );
	
	// Write query message.
	
	context->queryID = (uint16_t) Random32();
	err = WriteDNSQueryMessage( context->msgBuf, context->queryID, kDNSHeaderFlag_RecursionDesired, context->providerName,
		kDNSServiceType_TXT, kDNSServiceClass_IN, &context->msgLen );
	require_noerr( err, exit );
	
	// Create UDP socket.
	
	err = UDPClientSocketOpen( AF_UNSPEC, &context->serverAddr, 0, -1, NULL, &sock );
	require_noerr( err, exit );
	
	// Send DNS query.
	
	context->sendTicks = UpTicks();
	err = SocketWriteAll( sock, context->msgBuf, context->msgLen, 5 );
	require_noerr( err, exit );
	
	err = SocketContextCreate( sock, context, &sockCtx );
	require_noerr( err, exit );
	sock = kInvalidSocketRef;
	
	err = DispatchReadSourceCreate( sockCtx->sock, NULL, DNSCryptReceiveCertHandler, SocketContextCancelHandler, sockCtx,
		&context->readSource );
	if( err ) ForgetSocketContext( &sockCtx );
	require_noerr( err, exit );
	
	dispatch_resume( context->readSource );
	
	if( context->timeLimitSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->timeLimitSecs ), dispatch_get_main_queue(), kExitReason_Timeout,
			Exit );
	}
	dispatch_main();
	
exit:
	if( context ) free( context );
	ForgetSocket( &sock );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	DNSCryptReceiveCertHandler
//===========================================================================================================================

static void	DNSCryptReceiveCertHandler( void *inContext )
{
	OSStatus					err;
	struct timeval				now;
	const uint64_t				nowTicks	= UpTicks();
	SocketContext * const		sockCtx		= (SocketContext *) inContext;
	DNSCryptContext * const		context		= (DNSCryptContext *) sockCtx->userContext;
	const DNSHeader *			hdr;
	sockaddr_ip					fromAddr;
	const uint8_t *				ptr;
	const uint8_t *				txtPtr;
	size_t						txtLen;
	unsigned int				answerCount, i;
	uint8_t						targetName[ kDomainNameLengthMax ];
	
	gettimeofday( &now, NULL );
	
	dispatch_source_forget( &context->readSource );
	
	err = SocketRecvFrom( sockCtx->sock, context->msgBuf, sizeof( context->msgBuf ), &context->msgLen,
		&fromAddr, sizeof( fromAddr ), NULL, NULL, NULL, NULL );
	require_noerr( err, exit );
	check( SockAddrCompareAddr( &fromAddr, &context->serverAddr ) == 0 );
	
	FPrintF( stdout, "Receive time: %{du:time}\n",	&now );
	FPrintF( stdout, "Source:       %##a\n",		&context->serverAddr );
	FPrintF( stdout, "Message size: %zu\n",			context->msgLen );
	FPrintF( stdout, "RTT:          %llu ms\n\n",	UpTicksToMilliseconds( nowTicks - context->sendTicks ) );
	FPrintF( stdout, "%.*{du:dnsmsg}", context->printRawRData ? 1 : 0, context->msgBuf, context->msgLen );
	
	require_action_quiet( context->msgLen >= kDNSHeaderLength, exit, err = kSizeErr );
	
	hdr = (DNSHeader *) context->msgBuf;
	require_action_quiet( DNSHeaderGetID( hdr ) == context->queryID, exit, err = kMismatchErr );
	
	err = DNSMessageGetAnswerSection( context->msgBuf, context->msgLen, &ptr );
	require_noerr( err, exit );
	
	err = DomainNameFromString( targetName, context->providerName, NULL );
	require_noerr( err, exit );
	
	answerCount = DNSHeaderGetAnswerCount( hdr );
	for( i = 0; i < answerCount; ++i )
	{
		uint16_t		type;
		uint16_t		class;
		uint8_t			name[ kDomainNameLengthMax ];
		
		err = DNSMessageExtractRecord( context->msgBuf, context->msgLen, ptr, name, &type, &class, NULL, &txtPtr, &txtLen,
			&ptr );
		require_noerr( err, exit );
		
		if( ( type == kDNSServiceType_TXT ) && ( class == kDNSServiceClass_IN ) && DomainNameEqual( name, targetName ) )
		{
			break;
		}
	}
	
	if( txtLen < ( 1 + kDNSCryptCertMinimumLength ) )
	{
		FPrintF( stderr, "TXT record length is too short (%u < %u)\n", txtLen, kDNSCryptCertMinimumLength + 1 );
		err = kSizeErr;
		goto exit;
	}
	if( txtPtr[ 0 ] < kDNSCryptCertMinimumLength )
	{
		FPrintF( stderr, "TXT record value length is too short (%u < %u)\n", txtPtr[ 0 ], kDNSCryptCertMinimumLength );
		err = kSizeErr;
		goto exit;
	}
	
	context->certLen = txtPtr[ 0 ];
	context->certPtr = &txtPtr[ 1 ];
	
	dispatch_async_f( dispatch_get_main_queue(), context, DNSCryptProceed );
	
exit:
	if( err ) Exit( NULL );
}

//===========================================================================================================================
//	DNSCryptReceiveResponseHandler
//===========================================================================================================================

static void	DNSCryptReceiveResponseHandler( void *inContext )
{
	OSStatus						err;
	struct timeval					now;
	const uint64_t					nowTicks	= UpTicks();
	SocketContext * const			sockCtx		= (SocketContext *) inContext;
	DNSCryptContext * const			context		= (DNSCryptContext *) sockCtx->userContext;
	sockaddr_ip						fromAddr;
	DNSCryptResponseHeader *		hdr;
	const uint8_t *					end;
	uint8_t *						ciphertext;
	uint8_t *						plaintext;
	const uint8_t *					response;
	uint8_t							nonce[ crypto_box_NONCEBYTES ];
	
	gettimeofday( &now, NULL );
	
	dispatch_source_forget( &context->readSource );
	
	err = SocketRecvFrom( sockCtx->sock, context->msgBuf, sizeof( context->msgBuf ), &context->msgLen,
		&fromAddr, sizeof( fromAddr ), NULL, NULL, NULL, NULL );
	require_noerr( err, exit );
	check( SockAddrCompareAddr( &fromAddr, &context->serverAddr ) == 0 );
	
	FPrintF( stdout, "Receive time: %{du:time}\n",	&now );
	FPrintF( stdout, "Source:       %##a\n",		&context->serverAddr );
	FPrintF( stdout, "Message size: %zu\n",			context->msgLen );
	FPrintF( stdout, "RTT:          %llu ms\n\n",	UpTicksToMilliseconds( nowTicks - context->sendTicks ) );
	
	if( context->msgLen < sizeof( DNSCryptResponseHeader ) )
	{
		FPrintF( stderr, "DNSCrypt response is too short.\n" );
		err = kSizeErr;
		goto exit;
	}
	
	hdr = (DNSCryptResponseHeader *) context->msgBuf;
	
	if( memcmp( hdr->resolverMagic, kDNSCryptResolverMagic, kDNSCryptResolverMagicLength ) != 0 )
	{
		FPrintF( stderr, "DNSCrypt response resolver magic %#H != %#H\n",
			hdr->resolverMagic,		kDNSCryptResolverMagicLength, INT_MAX,
			kDNSCryptResolverMagic, kDNSCryptResolverMagicLength, INT_MAX );
		err = kValueErr;
		goto exit;
	}
	
	if( memcmp( hdr->clientNonce, context->clientNonce, kDNSCryptHalfNonceLength ) != 0 )
	{
		FPrintF( stderr, "DNSCrypt response client nonce mismatch.\n" );
		err = kValueErr;
		goto exit;
	}
	
	memcpy( nonce, hdr->clientNonce, crypto_box_NONCEBYTES );
	
	ciphertext = hdr->poly1305MAC - crypto_box_BOXZEROBYTES;
	memset( ciphertext, 0, crypto_box_BOXZEROBYTES );
	
	plaintext = (uint8_t *)( hdr + 1 ) - crypto_box_ZEROBYTES;
	check( plaintext == ciphertext );
	
	end = context->msgBuf + context->msgLen;
	
	err = crypto_box_open_afternm( plaintext, ciphertext, (size_t)( end - ciphertext ), nonce, context->nmKey );
	require_noerr( err, exit );
	
	response = plaintext + crypto_box_ZEROBYTES;
	FPrintF( stdout, "%.*{du:dnsmsg}", context->printRawRData ? 1 : 0, response, (size_t)( end - response ) );
	Exit( kExitReason_ReceivedResponse );
	
exit:
	if( err ) Exit( NULL );
}

//===========================================================================================================================
//	DNSCryptProceed
//===========================================================================================================================

static void	DNSCryptProceed( void *inContext )
{
	OSStatus					err;
	DNSCryptContext * const		context = (DNSCryptContext *) inContext;
	
	err = DNSCryptProcessCert( context );
	require_noerr_quiet( err, exit );
	
	err = DNSCryptBuildQuery( context );
	require_noerr_quiet( err, exit );
	
	err = DNSCryptSendQuery( context );
	require_noerr_quiet( err, exit );
	
exit:
	if( err ) Exit( NULL );
}

//===========================================================================================================================
//	DNSCryptProcessCert
//===========================================================================================================================

static OSStatus	DNSCryptProcessCert( DNSCryptContext *inContext )
{
	OSStatus						err;
	const DNSCryptCert * const		cert	= (DNSCryptCert *) inContext->certPtr;
	const uint8_t * const			certEnd	= inContext->certPtr + inContext->certLen;
	struct timeval					now;
	time_t							startTimeSecs, endTimeSecs;
	size_t							signedLen;
	uint8_t *						tempBuf;
	unsigned long long				tempLen;
	
	DNSCryptPrintCertificate( cert, inContext->certLen );
	
	if( memcmp( cert->certMagic, kDNSCryptCertMagic, kDNSCryptCertMagicLength ) != 0 )
	{
		FPrintF( stderr, "DNSCrypt certificate magic %#H != %#H\n",
			cert->certMagic,	kDNSCryptCertMagicLength, INT_MAX,
			kDNSCryptCertMagic, kDNSCryptCertMagicLength, INT_MAX );
		err = kValueErr;
		goto exit;
	}
	
	startTimeSecs	= (time_t) ReadBig32( cert->startTime );
	endTimeSecs		= (time_t) ReadBig32( cert->endTime );
	
	gettimeofday( &now, NULL );
	if( now.tv_sec < startTimeSecs )
	{
		FPrintF( stderr, "DNSCrypt certificate start time is in the future.\n" );
		err = kDateErr;
		goto exit;
	}
	if( now.tv_sec >= endTimeSecs )
	{
		FPrintF( stderr, "DNSCrypt certificate has expired.\n" );
		err = kDateErr;
		goto exit;
	}
	
	signedLen = (size_t)( certEnd - cert->signature );
	tempBuf = (uint8_t *) malloc( signedLen );
	require_action( tempBuf, exit, err = kNoMemoryErr );
	err = crypto_sign_open( tempBuf, &tempLen, cert->signature, signedLen, inContext->serverPublicSignKey );
	free( tempBuf );
	if( err )
	{
		FPrintF( stderr, "DNSCrypt certificate failed verification.\n" );
		err = kAuthenticationErr;
		goto exit;
	}
	
	memcpy( inContext->serverPublicKey,	cert->publicKey,	crypto_box_PUBLICKEYBYTES );
	memcpy( inContext->clientMagic,		cert->clientMagic,	kDNSCryptClientMagicLength );
	
	err = crypto_box_beforenm( inContext->nmKey, inContext->serverPublicKey, inContext->clientSecretKey );
	require_noerr( err, exit );
	
	inContext->certPtr	= NULL;
	inContext->certLen	= 0;
	inContext->msgLen	= 0;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DNSCryptBuildQuery
//===========================================================================================================================

static OSStatus	DNSCryptPadQuery( uint8_t *inMsgPtr, size_t inMsgLen, size_t inMaxLen, size_t *outPaddedLen );

static OSStatus	DNSCryptBuildQuery( DNSCryptContext *inContext )
{
	OSStatus						err;
	DNSCryptQueryHeader * const		hdr			= (DNSCryptQueryHeader *) inContext->msgBuf;
	uint8_t * const					queryPtr	= (uint8_t *)( hdr + 1 );
	size_t							queryLen;
	size_t							paddedQueryLen;
	const uint8_t * const			msgLimit	= inContext->msgBuf + sizeof( inContext->msgBuf );
	const uint8_t *					padLimit;
	uint8_t							nonce[ crypto_box_NONCEBYTES ];
	
	check_compile_time_code( sizeof( inContext->msgBuf ) >= ( sizeof( DNSCryptQueryHeader ) + kDNSQueryMessageMaxLen ) );
	
	inContext->queryID = (uint16_t) Random32();
	err = WriteDNSQueryMessage( queryPtr, inContext->queryID, kDNSHeaderFlag_RecursionDesired, inContext->qname,
		inContext->qtype, kDNSServiceClass_IN, &queryLen );
	require_noerr( err, exit );
	
	padLimit = &queryPtr[ queryLen + kDNSCryptMaxPadLength ];
	if( padLimit > msgLimit ) padLimit = msgLimit;
	
	err = DNSCryptPadQuery( queryPtr, queryLen, (size_t)( padLimit - queryPtr ), &paddedQueryLen );
	require_noerr( err, exit );
	
	memset( queryPtr - crypto_box_ZEROBYTES, 0, crypto_box_ZEROBYTES );
	RandomBytes( inContext->clientNonce, kDNSCryptHalfNonceLength );
	memcpy( nonce, inContext->clientNonce, kDNSCryptHalfNonceLength );
	memset( &nonce[ kDNSCryptHalfNonceLength ], 0, kDNSCryptHalfNonceLength );
	
	err = crypto_box_afternm( queryPtr - crypto_box_ZEROBYTES, queryPtr - crypto_box_ZEROBYTES,
		paddedQueryLen + crypto_box_ZEROBYTES, nonce, inContext->nmKey );
	require_noerr( err, exit );
	
	memcpy( hdr->clientMagic,		inContext->clientMagic,		kDNSCryptClientMagicLength );
	memcpy( hdr->clientPublicKey,	inContext->clientPublicKey,	crypto_box_PUBLICKEYBYTES );
	memcpy( hdr->clientNonce,		nonce,						kDNSCryptHalfNonceLength );
	
	inContext->msgLen = (size_t)( &queryPtr[ paddedQueryLen ] - inContext->msgBuf );
	
exit:
	return( err );
}

static OSStatus	DNSCryptPadQuery( uint8_t *inMsgPtr, size_t inMsgLen, size_t inMaxLen, size_t *outPaddedLen )
{
	OSStatus		err;
	size_t			paddedLen;
	
	require_action_quiet( ( inMsgLen + kDNSCryptMinPadLength ) <= inMaxLen, exit, err = kSizeErr );
	
	paddedLen = inMsgLen + kDNSCryptMinPadLength +
		arc4random_uniform( (uint32_t)( inMaxLen - ( inMsgLen + kDNSCryptMinPadLength ) + 1 ) );
	paddedLen += ( kDNSCryptBlockSize - ( paddedLen % kDNSCryptBlockSize ) );
	if( paddedLen > inMaxLen ) paddedLen = inMaxLen;
	
	inMsgPtr[ inMsgLen ] = 0x80;
	memset( &inMsgPtr[ inMsgLen + 1 ], 0, paddedLen - ( inMsgLen + 1 ) );
	
	if( outPaddedLen ) *outPaddedLen = paddedLen;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DNSCryptSendQuery
//===========================================================================================================================

static OSStatus	DNSCryptSendQuery( DNSCryptContext *inContext )
{
	OSStatus			err;
	SocketContext *		sockCtx;
	SocketRef			sock = kInvalidSocketRef;
	
	check( inContext->msgLen > 0 );
	check( !inContext->readSource );
	
	err = UDPClientSocketOpen( AF_UNSPEC, &inContext->serverAddr, 0, -1, NULL, &sock );
	require_noerr( err, exit );
	
	inContext->sendTicks = UpTicks();
	err = SocketWriteAll( sock, inContext->msgBuf, inContext->msgLen, 5 );
	require_noerr( err, exit );
	
	err = SocketContextCreate( sock, inContext, &sockCtx );
	require_noerr( err, exit );
	sock = kInvalidSocketRef;
	
	err = DispatchReadSourceCreate( sockCtx->sock, NULL, DNSCryptReceiveResponseHandler, SocketContextCancelHandler, sockCtx,
		&inContext->readSource );
	if( err ) ForgetSocketContext( &sockCtx );
	require_noerr( err, exit );
	
	dispatch_resume( inContext->readSource );
	
exit:
	ForgetSocket( &sock );
	return( err );
}

//===========================================================================================================================
//	DNSCryptPrintCertificate
//===========================================================================================================================

#define kCertTimeStrBufLen		32

static char *	CertTimeStr( time_t inTime, char inBuffer[ kCertTimeStrBufLen ] );

static void	DNSCryptPrintCertificate( const DNSCryptCert *inCert, size_t inLen )
{
	time_t		startTime, endTime;
	int			extLen;
	char		timeBuf[ kCertTimeStrBufLen ];
	
	check( inLen >= kDNSCryptCertMinimumLength );
	
	startTime	= (time_t) ReadBig32( inCert->startTime );
	endTime		= (time_t) ReadBig32( inCert->endTime );
	
	FPrintF( stdout, "DNSCrypt certificate (%zu bytes):\n", inLen );
	FPrintF( stdout, "Cert Magic:    %#H\n", inCert->certMagic, kDNSCryptCertMagicLength, INT_MAX );
	FPrintF( stdout, "ES Version:    %u\n",	ReadBig16( inCert->esVersion ) );
	FPrintF( stdout, "Minor Version: %u\n",	ReadBig16( inCert->minorVersion ) );
	FPrintF( stdout, "Signature:     %H\n",	inCert->signature, crypto_sign_BYTES / 2, INT_MAX );
	FPrintF( stdout, "               %H\n",	&inCert->signature[ crypto_sign_BYTES / 2 ], crypto_sign_BYTES / 2, INT_MAX );
	FPrintF( stdout, "Public Key:    %H\n", inCert->publicKey, sizeof( inCert->publicKey ), INT_MAX );
	FPrintF( stdout, "Client Magic:  %H\n", inCert->clientMagic, kDNSCryptClientMagicLength, INT_MAX );
	FPrintF( stdout, "Serial:        %u\n",	ReadBig32( inCert->serial ) );
	FPrintF( stdout, "Start Time:    %u (%s)\n", (uint32_t) startTime, CertTimeStr( startTime, timeBuf ) );
	FPrintF( stdout, "End Time:      %u (%s)\n", (uint32_t) endTime, CertTimeStr( endTime, timeBuf ) );
	
	if( inLen > kDNSCryptCertMinimumLength )
	{
		extLen = (int)( inLen - kDNSCryptCertMinimumLength );
		FPrintF( stdout, "Extensions:    %.1H\n", inCert->extensions, extLen, extLen );
	}
	FPrintF( stdout, "\n" );
}

static char *	CertTimeStr( time_t inTime, char inBuffer[ kCertTimeStrBufLen ] )
{
	struct tm *		tm;
	
	tm = localtime( &inTime );
	if( !tm )
	{
		dlogassert( "localtime() returned a NULL pointer.\n" );
		*inBuffer = '\0';
	}
	else
	{
		strftime( inBuffer, kCertTimeStrBufLen, "%a %b %d %H:%M:%S %Z %Y", tm );
	}
	
	return( inBuffer );
}

#endif	// DNSSDUTIL_INCLUDE_DNSCRYPT

//===========================================================================================================================
//	MDNSQueryCmd
//===========================================================================================================================

typedef struct
{
	const char *			qnameStr;							// Name (QNAME) of the record being queried as a C string.
	dispatch_source_t		readSourceV4;						// Read dispatch source for IPv4 socket.
	dispatch_source_t		readSourceV6;						// Read dispatch source for IPv6 socket.
	int						localPort;							// The port number to which the sockets are bound.
	int						receiveSecs;						// After send, the amount of time to spend receiving.
	uint32_t				ifIndex;							// Index of the interface over which to send the query.
	uint16_t				qtype;								// The type (QTYPE) of the record being queried.
	Boolean					isQU;								// True if the query is QU, i.e., requests unicast responses.
	Boolean					allResponses;						// True if all mDNS messages received should be printed.
	Boolean					printRawRData;						// True if RDATA should be printed as hexdumps.
	Boolean					useIPv4;							// True if the query should be sent via IPv4 multicast.
	Boolean					useIPv6;							// True if the query should be sent via IPv6 multicast.
	char					ifName[ IF_NAMESIZE + 1 ];			// Name of the interface over which to send the query.
	uint8_t					qname[ kDomainNameLengthMax ];		// Buffer to hold the QNAME in DNS label format.
	uint8_t					msgBuf[ 8940 ];						// Message buffer. 8940 is max size used by mDNSResponder.
	
}	MDNSQueryContext;

static void	MDNSQueryPrintPrologue( const MDNSQueryContext *inContext );
static void	MDNSQueryReadHandler( void *inContext );

static void	MDNSQueryCmd( void )
{
	OSStatus				err;
	MDNSQueryContext *		context;
	struct sockaddr_in		mcastAddr4;
	struct sockaddr_in6		mcastAddr6;
	SocketRef				sockV4 = kInvalidSocketRef;
	SocketRef				sockV6 = kInvalidSocketRef;
	ssize_t					n;
	const char *			ifNamePtr;
	size_t					msgLen;
	unsigned int			sendCount;
	
	// Check command parameters.
	
	if( gMDNSQuery_ReceiveSecs < -1 )
	{
		FPrintF( stdout, "Invalid receive time value: %d seconds.\n", gMDNSQuery_ReceiveSecs );
		err = kParamErr;
		goto exit;
	}
	
	context = (MDNSQueryContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->qnameStr		= gMDNSQuery_Name;
	context->receiveSecs	= gMDNSQuery_ReceiveSecs;
	context->isQU			= gMDNSQuery_IsQU		  ? true : false;
	context->allResponses	= gMDNSQuery_AllResponses ? true : false;
	context->printRawRData	= gMDNSQuery_RawRData	  ? true : false;
	context->useIPv4		= ( gMDNSQuery_UseIPv4 || !gMDNSQuery_UseIPv6 ) ? true : false;
	context->useIPv6		= ( gMDNSQuery_UseIPv6 || !gMDNSQuery_UseIPv4 ) ? true : false;
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifIndex );
	require_noerr_quiet( err, exit );
	
	ifNamePtr = if_indextoname( context->ifIndex, context->ifName );
	require_action( ifNamePtr, exit, err = kNameErr );
	
	err = RecordTypeFromArgString( gMDNSQuery_Type, &context->qtype );
	require_noerr( err, exit );
	
	// Set up IPv4 socket.
	
	if( context->useIPv4 )
	{
		err = ServerSocketOpen( AF_INET, SOCK_DGRAM, IPPROTO_UDP,
			gMDNSQuery_SourcePort ? gMDNSQuery_SourcePort : ( context->isQU ? context->localPort : kMDNSPort ),
			&context->localPort, kSocketBufferSize_DontSet, &sockV4 );
		require_noerr( err, exit );
		
		err = SocketSetMulticastInterface( sockV4, ifNamePtr, context->ifIndex );
		require_noerr( err, exit );
		
		err = setsockopt( sockV4, IPPROTO_IP, IP_MULTICAST_LOOP, (char *) &(uint8_t){ 1 }, (socklen_t) sizeof( uint8_t ) );
		err = map_socket_noerr_errno( sockV4, err );
		require_noerr( err, exit );
		
		memset( &mcastAddr4, 0, sizeof( mcastAddr4 ) );
		SIN_LEN_SET( &mcastAddr4 );
		mcastAddr4.sin_family		= AF_INET;
		mcastAddr4.sin_port			= htons( kMDNSPort );
		mcastAddr4.sin_addr.s_addr	= htonl( 0xE00000FB );	// The mDNS IPv4 multicast address is 224.0.0.251
		
		if( !context->isQU && ( context->localPort == kMDNSPort ) )
		{
			err = SocketJoinMulticast( sockV4, &mcastAddr4, ifNamePtr, context->ifIndex );
			require_noerr( err, exit );
		}
	}
	
	// Set up IPv6 socket.
	
	if( context->useIPv6 )
	{
		err = ServerSocketOpen( AF_INET6, SOCK_DGRAM, IPPROTO_UDP,
			gMDNSQuery_SourcePort ? gMDNSQuery_SourcePort : ( context->isQU ? context->localPort : kMDNSPort ),
			&context->localPort, kSocketBufferSize_DontSet, &sockV6 );
		require_noerr( err, exit );
		
		err = SocketSetMulticastInterface( sockV6, ifNamePtr, context->ifIndex );
		require_noerr( err, exit );
		
		err = setsockopt( sockV6, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *) &(int){ 1 }, (socklen_t) sizeof( int ) );
		err = map_socket_noerr_errno( sockV6, err );
		require_noerr( err, exit );
		
		memset( &mcastAddr6, 0, sizeof( mcastAddr6 ) );
		SIN6_LEN_SET( &mcastAddr6 );
		mcastAddr6.sin6_family	= AF_INET6;
		mcastAddr6.sin6_port	= htons( kMDNSPort );
		mcastAddr6.sin6_addr.s6_addr[  0 ] = 0xFF;	// mDNS IPv6 multicast address FF02::FB
		mcastAddr6.sin6_addr.s6_addr[  1 ] = 0x02;
		mcastAddr6.sin6_addr.s6_addr[ 15 ] = 0xFB;
		
		if( !context->isQU && ( context->localPort == kMDNSPort ) )
		{
			err = SocketJoinMulticast( sockV6, &mcastAddr6, ifNamePtr, context->ifIndex );
			require_noerr( err, exit );
		}
	}
	
	// Craft mDNS query message.
	
	check_compile_time_code( sizeof( context->msgBuf ) >= kDNSQueryMessageMaxLen );
	err = WriteDNSQueryMessage( context->msgBuf, kDefaultMDNSMessageID, kDefaultMDNSQueryFlags, context->qnameStr,
		context->qtype, context->isQU ? ( kDNSServiceClass_IN | kQClassUnicastResponseBit ) : kDNSServiceClass_IN, &msgLen );
	require_noerr( err, exit );
	
	// Print prologue.
	
	MDNSQueryPrintPrologue( context );
	
	// Send mDNS query message.
	
	sendCount = 0;
	if( IsValidSocket( sockV4 ) )
	{
		n = sendto( sockV4, context->msgBuf, msgLen, 0, (struct sockaddr *) &mcastAddr4, (socklen_t) sizeof( mcastAddr4 ) );
		err = map_socket_value_errno( sockV4, n == (ssize_t) msgLen, n );
		if( err )
		{
			FPrintF( stderr, "*** Failed to send query on IPv4 socket with error %#m\n", err );
			ForgetSocket( &sockV4 );
		}
		else
		{
			++sendCount;
		}
	}
	if( IsValidSocket( sockV6 ) )
	{
		n = sendto( sockV6, context->msgBuf, msgLen, 0, (struct sockaddr *) &mcastAddr6, (socklen_t) sizeof( mcastAddr6 ) );
		err = map_socket_value_errno( sockV6, n == (ssize_t) msgLen, n );
		if( err )
		{
			FPrintF( stderr, "*** Failed to send query on IPv6 socket with error %#m\n", err );
			ForgetSocket( &sockV6 );
		}
		else
		{
			++sendCount;
		}
	}
	require_action_quiet( sendCount > 0, exit, err = kUnexpectedErr );
	
	// If there's no wait period after the send, then exit.
	
	if( context->receiveSecs == 0 ) goto exit;
	
	// Create dispatch read sources for socket(s).
	
	if( IsValidSocket( sockV4 ) )
	{
		SocketContext *		sockCtx;
		
		err = SocketContextCreate( sockV4, context, &sockCtx );
		require_noerr( err, exit );
		sockV4 = kInvalidSocketRef;
		
		err = DispatchReadSourceCreate( sockCtx->sock, NULL, MDNSQueryReadHandler, SocketContextCancelHandler, sockCtx,
			&context->readSourceV4 );
		if( err ) ForgetSocketContext( &sockCtx );
		require_noerr( err, exit );
		
		dispatch_resume( context->readSourceV4 );
	}
	
	if( IsValidSocket( sockV6 ) )
	{
		SocketContext *		sockCtx;
		
		err = SocketContextCreate( sockV6, context, &sockCtx );
		require_noerr( err, exit );
		sockV6 = kInvalidSocketRef;
		
		err = DispatchReadSourceCreate( sockCtx->sock, NULL, MDNSQueryReadHandler, SocketContextCancelHandler, sockCtx,
			&context->readSourceV6 );
		if( err ) ForgetSocketContext( &sockCtx );
		require_noerr( err, exit );
		
		dispatch_resume( context->readSourceV6 );
	}
	
	if( context->receiveSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->receiveSecs ), dispatch_get_main_queue(), kExitReason_Timeout,
			Exit );
	}
	dispatch_main();
	
exit:
	ForgetSocket( &sockV4 );
	ForgetSocket( &sockV6 );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	MDNSQueryPrintPrologue
//===========================================================================================================================

static void	MDNSQueryPrintPrologue( const MDNSQueryContext *inContext )
{
	const int		receiveSecs = inContext->receiveSecs;
	
	FPrintF( stdout, "Interface:        %d (%s)\n",		(int32_t) inContext->ifIndex, inContext->ifName );
	FPrintF( stdout, "Name:             %s\n",			inContext->qnameStr );
	FPrintF( stdout, "Type:             %s (%u)\n",		RecordTypeToString( inContext->qtype ), inContext->qtype );
	FPrintF( stdout, "Class:            IN (%s)\n",		inContext->isQU ? "QU" : "QM" );
	FPrintF( stdout, "Local port:       %d\n",			inContext->localPort );
	FPrintF( stdout, "IP protocols:     %?s%?s%?s\n",
		inContext->useIPv4, "IPv4", ( inContext->useIPv4 && inContext->useIPv6 ), ", ", inContext->useIPv6, "IPv6" );
	FPrintF( stdout, "Receive duration: " );
	if( receiveSecs >= 0 )	FPrintF( stdout, "%d second%?c\n", receiveSecs, receiveSecs != 1, 's' );
	else					FPrintF( stdout, "∞\n" );
	FPrintF( stdout, "Start time:       %{du:time}\n",	NULL );
}

//===========================================================================================================================
//	MDNSQueryReadHandler
//===========================================================================================================================

static void	MDNSQueryReadHandler( void *inContext )
{
	OSStatus						err;
	struct timeval					now;
	SocketContext * const			sockCtx = (SocketContext *) inContext;
	MDNSQueryContext * const		context = (MDNSQueryContext *) sockCtx->userContext;
	size_t							msgLen;
	sockaddr_ip						fromAddr;
	Boolean							foundAnswer	= false;
	
	gettimeofday( &now, NULL );
	
	err = SocketRecvFrom( sockCtx->sock, context->msgBuf, sizeof( context->msgBuf ), &msgLen, &fromAddr,
		sizeof( fromAddr ), NULL, NULL, NULL, NULL );
	require_noerr( err, exit );
	
	if( !context->allResponses && ( msgLen >= kDNSHeaderLength ) )
	{
		const uint8_t *				ptr;
		const DNSHeader * const		hdr = (DNSHeader *) context->msgBuf;
		unsigned int				rrCount, i;
		uint16_t					type, class;
		uint8_t						name[ kDomainNameLengthMax ];
		
		err = DNSMessageGetAnswerSection( context->msgBuf, msgLen, &ptr );
		require_noerr( err, exit );
		
		if( context->qname[ 0 ] == 0 )
		{
			err = DomainNameAppendString( context->qname, context->qnameStr, NULL );
			require_noerr( err, exit );
		}
		
		rrCount = DNSHeaderGetAnswerCount( hdr ) + DNSHeaderGetAuthorityCount( hdr ) + DNSHeaderGetAdditionalCount( hdr );
		for( i = 0; i < rrCount; ++i )
		{
			err = DNSMessageExtractRecord( context->msgBuf, msgLen, ptr, name, &type, &class, NULL, NULL, NULL, &ptr );
			require_noerr( err, exit );
			
			if( ( ( context->qtype == kDNSServiceType_ANY ) || ( type == context->qtype ) ) &&
				DomainNameEqual( name, context->qname ) )
			{
				foundAnswer = true;
				break;
			}
		}
	}
	if( context->allResponses || foundAnswer )
	{
		FPrintF( stdout, "---\n" );
		FPrintF( stdout, "Receive time: %{du:time}\n",	&now );
		FPrintF( stdout, "Source:       %##a\n",		&fromAddr );
		FPrintF( stdout, "Message size: %zu\n\n%#.*{du:dnsmsg}",
			msgLen, context->printRawRData ? 1 : 0, context->msgBuf, msgLen );
	}
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	PIDToUUIDCmd
//===========================================================================================================================

static void	PIDToUUIDCmd( void )
{
	OSStatus							err;
	int									n;
	struct proc_uniqidentifierinfo		info;
	
	n = proc_pidinfo( gPIDToUUID_PID, PROC_PIDUNIQIDENTIFIERINFO, 1, &info, sizeof( info ) );
	require_action_quiet( n == (int) sizeof( info ), exit, err = kUnknownErr );
	
	FPrintF( stdout, "%#U\n", info.p_uuid );
	err = kNoErr;
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	DNSServerCmd
//===========================================================================================================================

typedef uint32_t		DNSServerEventType;
#define kDNSServerEvent_Started		1
#define kDNSServerEvent_Stopped		2

typedef struct DNSServerPrivate *		DNSServerRef;

typedef struct
{
	DNSServerRef			server;				// Reference to the DNS server.
	dispatch_source_t		sigIntSource;		// Dispatch SIGINT source.
	dispatch_source_t		sigTermSource;		// Dispatch SIGTERM source.
#if( TARGET_OS_DARWIN )
	dispatch_source_t		processMonitor;		// Process monitor source for process being followed, if any.
	pid_t					followPID;			// PID of process being followed (we exit when they exit), if any.
	Boolean					resolverRegistered;	// True if system DNS settings contains a resolver entry for server.
#endif
	Boolean					loopbackOnly;		// True if the server should be bound to the loopback interface.
	Boolean					serverStarted;		// True if the server was successfully started.
	Boolean					calledStop;			// True if the server was explicitly stopped.
	
}	DNSServerCmdContext;

typedef void ( *DNSServerEventHandler_f )( DNSServerEventType inType, void *inContext );

CFTypeID	DNSServerGetTypeID( void );
static OSStatus
	DNSServerCreate(
		dispatch_queue_t		inQueue,
		DNSServerEventHandler_f	inEventHandler,
		void *					inEventContext,
		int						inResponseDelayMs,
		Boolean					inLoopbackOnly,
		DNSServerRef *			outServer );
static void	DNSServerStart( DNSServerRef inServer );
static void	DNSServerStop( DNSServerRef inServer );

static void	DNSServerCmdContextFree( DNSServerCmdContext *inContext );
static void	DNSServerCmdEventHandler( DNSServerEventType inType, void *inContext );
static void	DNSServerCmdSigIntHandler( void *inContext );
static void	DNSServerCmdSigTermHandler( void *inContext );
#if( TARGET_OS_DARWIN )
static void	DNSServerCmdFollowedProcessHandler( void *inContext );
#endif

ulog_define_ex( "com.apple.dnssdutil", DNSServer, kLogLevelInfo, kLogFlags_None, "DNSServer", NULL );
#define ds_ulog( LEVEL, ... )		ulog( &log_category_from_name( DNSServer ), (LEVEL), __VA_ARGS__ )

static void	DNSServerCmd( void )
{
	OSStatus					err;
	DNSServerCmdContext *		context;
	
	context = (DNSServerCmdContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->loopbackOnly = gDNSServer_LoopbackOnly ? true : false;
	
#if( TARGET_OS_DARWIN )
	if( gDNSServer_FollowPID )
	{
		long long		value;
		
		err = StringToLongLong( gDNSServer_FollowPID, &value );
		if( !err && ( value < 0 ) ) err = kValueErr;
		if( err )
		{
			FPrintF( stderr, "Invalid followPID argument \"%s\".\n", gDNSServer_FollowPID );
			goto exit;
		}
		context->followPID = (pid_t) value;
		
		err = DispatchProcessMonitorCreate( context->followPID, DISPATCH_PROC_EXIT, dispatch_get_main_queue(),
			DNSServerCmdFollowedProcessHandler, NULL, context, &context->processMonitor );
		require_noerr( err, exit );
		dispatch_resume( context->processMonitor );
	}
	else
	{
		context->followPID = -1;
	}
#endif
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, DNSServerCmdSigIntHandler, context, &context->sigIntSource );
	require_noerr( err, exit );
	dispatch_resume( context->sigIntSource );
	
	signal( SIGTERM, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGTERM, DNSServerCmdSigTermHandler, context, &context->sigTermSource );
	require_noerr( err, exit );
	dispatch_resume( context->sigTermSource );
	
	if( gDNSServer_Foreground )
	{
		LogControl( "DNSServer:output=file;stdout,DNSServer:flags=time;prefix" );
	}
	
	if( ( gDNSServer_DefaultTTL < 0 ) || ( gDNSServer_DefaultTTL > INT32_MAX ) )
	{
		ds_ulog( kLogLevelError, "The default TTL %d provided by user is out-of-range. Will use %d instead.\n",
			gDNSServer_DefaultTTL, kDNSServerDefaultTTL );
		gDNSServer_DefaultTTL = kDNSServerDefaultTTL;
	}
	
	err = DNSServerCreate( dispatch_get_main_queue(), DNSServerCmdEventHandler, context, gDNSServer_ResponseDelayMs,
		context->loopbackOnly, &context->server );
	require_noerr( err, exit );
	
	DNSServerStart( context->server );
	dispatch_main();
	
exit:
	ds_ulog( kLogLevelError, "Failed to start DNS server: %#m\n", err );
	if( context ) DNSServerCmdContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	DNSServerCmdContextFree
//===========================================================================================================================

static void	DNSServerCmdContextFree( DNSServerCmdContext *inContext )
{
	ForgetCF( &inContext->server );
	dispatch_source_forget( &inContext->sigIntSource );
	dispatch_source_forget( &inContext->sigTermSource );
	dispatch_source_forget( &inContext->processMonitor );
	free( inContext );
}

//===========================================================================================================================
//	DNSServerCmdEventHandler
//===========================================================================================================================

#if( TARGET_OS_DARWIN )
static OSStatus	_DNSServerCmdRegisterResolver( void );
static OSStatus	_DNSServerCmdUnregisterResolver( void );
#endif

static void	DNSServerCmdEventHandler( DNSServerEventType inType, void *inContext )
{
	DNSServerCmdContext * const		context = (DNSServerCmdContext *) inContext;
#if( TARGET_OS_DARWIN )
	OSStatus						err;
#endif
	
	if( inType == kDNSServerEvent_Started )
	{
		context->serverStarted = true;
	#if( TARGET_OS_DARWIN )
		err = _DNSServerCmdRegisterResolver();
		if( err )
		{
			ds_ulog( kLogLevelError, "Failed to add resolver to DNS configuration for \"d.test.\" domain: %#m\n", err );
			if( context->loopbackOnly ) exit( 1 );
		}
		else
		{
			context->resolverRegistered = true;
		}
	#endif
	}
	else if( inType == kDNSServerEvent_Stopped )
	{
	#if( TARGET_OS_DARWIN )
		if( context->resolverRegistered )
		{
			err = _DNSServerCmdUnregisterResolver();
			if( err )
			{
				ds_ulog( kLogLevelError, "Failed to remove resolver from DNS configuration: %#m\n", err );
			}
			else
			{
				context->resolverRegistered = false;
			}
		}
		
		if( !context->calledStop )
		{
			ds_ulog( kLogLevelError, "The server stopped unexpectedly.\n" );
			exit( 1 );
		}
	#endif
		DNSServerCmdContextFree( context );
	}
}

#if( TARGET_OS_DARWIN )
//===========================================================================================================================
//	_DNSServerCmdRegisterResolver
//===========================================================================================================================

static OSStatus	_DNSServerCmdRegisterResolver( void )
{
	OSStatus				err;
	SCDynamicStoreRef		store;
	CFPropertyListRef		plist		= NULL;
	CFStringRef				key			= NULL;
	const uint32_t			loopbackV4	= htonl( INADDR_LOOPBACK );
	Boolean					success;
	
	store = SCDynamicStoreCreate( NULL, CFSTR( "com.apple.dnssdutil" ), NULL, NULL );
	err = map_scerror( store );
	require_noerr( err, exit );
	
	err = CFPropertyListCreateFormatted( kCFAllocatorDefault, &plist,
		"{"
			"%kO="
			"["
				"%s"
			"]"
			"%kO="
			"["
				"%.4a"
				"%.16a"
			"]"
		"}",
		kSCPropNetDNSSupplementalMatchDomains, "d.test.",
		kSCPropNetDNSServerAddresses, &loopbackV4, in6addr_loopback.s6_addr );
	require_noerr( err, exit );
	
	key = SCDynamicStoreKeyCreateNetworkServiceEntity( NULL, kSCDynamicStoreDomainState,
		CFSTR( "com.apple.dnssdutil.server" ), kSCEntNetDNS );
	require_action( key, exit, err = kUnknownErr );
	
	success = SCDynamicStoreSetValue( store, key, plist );
	require_action( success, exit, err = kUnknownErr );
	
exit:
	CFReleaseNullSafe( store );
	CFReleaseNullSafe( plist );
	CFReleaseNullSafe( key );
	return( err );
}

//===========================================================================================================================
//	_DNSServerCmdUnregisterResolver
//===========================================================================================================================

static OSStatus	_DNSServerCmdUnregisterResolver( void )
{
	OSStatus				err;
	SCDynamicStoreRef		store;
	CFStringRef				key = NULL;
	Boolean					success;
	
	store = SCDynamicStoreCreate( NULL, CFSTR( "com.apple.dnssdutil" ), NULL, NULL );
	err = map_scerror( store );
	require_noerr( err, exit );
	
	key = SCDynamicStoreKeyCreateNetworkServiceEntity( NULL, kSCDynamicStoreDomainState,
		CFSTR( "com.apple.dnssdutil.server" ), kSCEntNetDNS );
	require_action( key, exit, err = kUnknownErr );
	
	success = SCDynamicStoreRemoveValue( store, key );
	require_action( success, exit, err = kUnknownErr );
	
exit:
	CFReleaseNullSafe( store );
	CFReleaseNullSafe( key );
	return( err );
}
#endif

//===========================================================================================================================
//	DNSServerCmdSigIntHandler
//===========================================================================================================================

static void	_DNSServerCmdExternalExit( DNSServerCmdContext *inContext, int inSignal );

static void	DNSServerCmdSigIntHandler( void *inContext )
{
	_DNSServerCmdExternalExit( (DNSServerCmdContext *) inContext, SIGINT );
}

//===========================================================================================================================
//	DNSServerCmdSigTermHandler
//===========================================================================================================================

static void	DNSServerCmdSigTermHandler( void *inContext )
{
	_DNSServerCmdExternalExit( (DNSServerCmdContext *) inContext, SIGTERM );
}

#if( TARGET_OS_DARWIN )
//===========================================================================================================================
//	DNSServerCmdFollowedProcessHandler
//===========================================================================================================================

static void	DNSServerCmdFollowedProcessHandler( void *inContext )
{
	DNSServerCmdContext * const		context = (DNSServerCmdContext *) inContext;
	
	if( dispatch_source_get_data( context->processMonitor ) & DISPATCH_PROC_EXIT )
	{
		_DNSServerCmdExternalExit( context, 0 );
	}
}
#endif

//===========================================================================================================================
//	_DNSServerCmdExternalExit
//===========================================================================================================================

#define SignalNumberToString( X ) (		\
	( (X) == SIGINT )  ? "SIGINT"  :	\
	( (X) == SIGTERM ) ? "SIGTERM" :	\
						 "???" )

static void	_DNSServerCmdExternalExit( DNSServerCmdContext *inContext, int inSignal )
{
	OSStatus		err;
	
#if( TARGET_OS_DARWIN )
	if( inSignal == 0 )
	{
		ds_ulog( kLogLevelNotice, "Exiting: followed process (%lld) exited\n", (int64_t) inContext->followPID );
	}
	else
#endif
	{
		ds_ulog( kLogLevelNotice, "Exiting: received signal %d (%s)\n", inSignal, SignalNumberToString( inSignal ) );
	}
	
#if( TARGET_OS_DARWIN )
	if( inContext->resolverRegistered )
	{
		err = _DNSServerCmdUnregisterResolver();
		if( err )
		{
			ds_ulog( kLogLevelError, "Failed to remove resolver from DNS configuration: %#m\n", err );
			goto exit;
		}
		inContext->resolverRegistered = false;
	}
#endif
	if( inContext->serverStarted )
	{
		DNSServerStop( inContext->server );
		inContext->calledStop = true;
	}
	err = kNoErr;
	
exit:
	exit( err ? 1 : 0 );
}

//===========================================================================================================================
//	DNSServerCreate
//===========================================================================================================================

typedef struct DNSDelayedResponse		DNSDelayedResponse;
struct DNSDelayedResponse
{
	DNSDelayedResponse *		next;
	sockaddr_ip					clientAddr;
	uint64_t					targetTicks;
	uint8_t *					msgPtr;
	size_t						msgLen;
};

#define DNSScheduledResponseFree( X )		do { ForgetMem( &(X)->msgPtr ) ; free( X ); } while( 0 )

struct DNSServerPrivate
{
	CFRuntimeBase				base;				// CF object base.
	dispatch_queue_t			queue;				// Queue for DNS server's events.
	dispatch_source_t			readSourceUDPv4;	// Read source for IPv4 UDP socket.
	dispatch_source_t			readSourceUDPv6;	// Read source for IPv6 UDP socket.
	dispatch_source_t			readSourceTCPv4;	// Read source for IPv4 TCP socket.
	dispatch_source_t			readSourceTCPv6;	// Read source for IPv6 TCP socket.
	DNSServerEventHandler_f		eventHandler;
	void *						eventContext;
	DNSDelayedResponse *		responseList;
	int							responseDelayMs;
	dispatch_source_t			responseTimer;
	Boolean						loopbackOnly;
	Boolean						stopped;
};

CF_CLASS_DEFINE( DNSServer );

static OSStatus
	DNSServerCreate(
		dispatch_queue_t		inQueue,
		DNSServerEventHandler_f	inEventHandler,
		void *					inEventContext,
		int						inResponseDelayMs,
		Boolean					inLoopbackOnly,
		DNSServerRef *			outServer )
{
	OSStatus			err;
	DNSServerRef		obj = NULL;
	
	CF_OBJECT_CREATE( DNSServer, obj, err, exit );
	
	ReplaceDispatchQueue( &obj->queue, inQueue );
	obj->eventHandler		= inEventHandler;
	obj->eventContext		= inEventContext;
	obj->responseDelayMs	= inResponseDelayMs;
	if( inLoopbackOnly ) obj->loopbackOnly = true;
	
	*outServer = obj;
	obj = NULL;
	err = kNoErr;
	
exit:
	CFReleaseNullSafe( obj );
	return( err );
}

//===========================================================================================================================
//	_DNSServerFinalize
//===========================================================================================================================

static void	_DNSServerFinalize( CFTypeRef inObj )
{
	DNSServerRef const		me = (DNSServerRef) inObj;
	
	check( !me->readSourceUDPv4 );
	check( !me->readSourceUDPv6 );
	check( !me->readSourceTCPv4 );
	check( !me->readSourceTCPv6 );
	check( !me->responseTimer );
	dispatch_forget( &me->queue );
}

//===========================================================================================================================
//	DNSServerStart
//===========================================================================================================================

static void	_DNSServerStart( void *inContext );
static void	_DNSServerUDPReadHandler( void *inContext );
static void	_DNSServerTCPReadHandler( void *inContext );

static void	DNSServerStart( DNSServerRef me )
{
	CFRetain( me );
	dispatch_async_f( me->queue, me, _DNSServerStart );
}

static void	_DNSServerStart( void *inContext )
{
	OSStatus				err;
	DNSServerRef const		me			= (DNSServerRef) inContext;
	SocketRef				sock		= kInvalidSocketRef;
	SocketContext *			sockCtx		= NULL;
	const uint32_t			loopbackV4	= htonl( INADDR_LOOPBACK );
	
	// Create IPv4 UDP socket.
	
	err = _ServerSocketOpenEx2( AF_INET, SOCK_DGRAM, IPPROTO_UDP, me->loopbackOnly ? &loopbackV4 : NULL,
		kDNSPort, NULL, kSocketBufferSize_DontSet, me->loopbackOnly ? true : false, &sock );
	require_noerr( err, exit );
	
	// Create read source for IPv4 UDP socket.
	
	err = SocketContextCreate( sock, me, &sockCtx );
	require_noerr( err, exit );
	sock = kInvalidSocketRef;
	
	err = DispatchReadSourceCreate( sockCtx->sock, me->queue, _DNSServerUDPReadHandler, SocketContextCancelHandler, sockCtx,
		&me->readSourceUDPv4 );
	require_noerr( err, exit );
	dispatch_resume( me->readSourceUDPv4 );
	sockCtx = NULL;
	
	// Create IPv6 UDP socket.
	
	err = _ServerSocketOpenEx2( AF_INET6, SOCK_DGRAM, IPPROTO_UDP, me->loopbackOnly ? &in6addr_loopback : NULL,
		kDNSPort, NULL, kSocketBufferSize_DontSet, me->loopbackOnly ? true : false, &sock );
	require_noerr( err, exit );
	
	// Create read source for IPv6 UDP socket.
	
	err = SocketContextCreate( sock, me, &sockCtx );
	require_noerr( err, exit );
	sock = kInvalidSocketRef;
	
	err = DispatchReadSourceCreate( sockCtx->sock, me->queue, _DNSServerUDPReadHandler, SocketContextCancelHandler, sockCtx,
		&me->readSourceUDPv6 );
	require_noerr( err, exit );
	dispatch_resume( me->readSourceUDPv6 );
	sockCtx = NULL;
	
	// Create IPv4 TCP socket.
	
	err = _ServerSocketOpenEx2( AF_INET, SOCK_STREAM, IPPROTO_TCP, me->loopbackOnly ? &loopbackV4 : NULL,
		kDNSPort, NULL, kSocketBufferSize_DontSet, false, &sock );
	require_noerr( err, exit );
	
	// Create read source for IPv4 TCP socket.
	
	err = SocketContextCreate( sock, me, &sockCtx );
	require_noerr( err, exit );
	sock = kInvalidSocketRef;
	
	err = DispatchReadSourceCreate( sockCtx->sock, me->queue, _DNSServerTCPReadHandler, SocketContextCancelHandler, sockCtx,
		&me->readSourceTCPv4 );
	require_noerr( err, exit );
	dispatch_resume( me->readSourceTCPv4 );
	sockCtx = NULL;
	
	// Create IPv6 TCP socket.
	
	err = _ServerSocketOpenEx2( AF_INET6, SOCK_STREAM, IPPROTO_TCP, me->loopbackOnly ? &in6addr_loopback : NULL,
		kDNSPort, NULL, kSocketBufferSize_DontSet, false, &sock );
	require_noerr( err, exit );
	
	// Create read source for IPv6 TCP socket.
	
	err = SocketContextCreate( sock, me, &sockCtx );
	require_noerr( err, exit );
	sock = kInvalidSocketRef;
	
	err = DispatchReadSourceCreate( sockCtx->sock, me->queue, _DNSServerTCPReadHandler, SocketContextCancelHandler, sockCtx,
		&me->readSourceTCPv6 );
	require_noerr( err, exit );
	dispatch_resume( me->readSourceTCPv6 );
	sockCtx = NULL;
	
	CFRetain( me );
	if( me->eventHandler ) me->eventHandler( kDNSServerEvent_Started, me->eventContext );
	
exit:
	ForgetSocket( &sock );
	if( sockCtx ) SocketContextRelease( sockCtx );
	if( err ) DNSServerStop( me );
	CFRelease( me );
}

//===========================================================================================================================
//	DNSServerStop
//===========================================================================================================================

static void	_DNSServerStop( void *inContext );
static void	_DNSServerStop2( void *inContext );

static void	DNSServerStop( DNSServerRef me )
{
	CFRetain( me );
	dispatch_async_f( me->queue, me, _DNSServerStop );
}

static void	_DNSServerStop( void *inContext )
{
	DNSServerRef const			me = (DNSServerRef) inContext;
	DNSDelayedResponse *		resp;
	
	dispatch_source_forget( &me->readSourceUDPv4 );
	dispatch_source_forget( &me->readSourceUDPv6 );
	dispatch_source_forget( &me->readSourceTCPv4 );
	dispatch_source_forget( &me->readSourceTCPv6 );
	dispatch_source_forget( &me->responseTimer );
	
	while( ( resp = me->responseList ) != NULL )
	{
		me->responseList = resp->next;
		DNSScheduledResponseFree( resp );
	}
	
	dispatch_async_f( me->queue, me, _DNSServerStop2 );
}

static void	_DNSServerStop2( void *inContext )
{
	DNSServerRef const		me = (DNSServerRef) inContext;
	
	if( !me->stopped )
	{
		me->stopped = true;
		if( me->eventHandler ) me->eventHandler( kDNSServerEvent_Stopped, me->eventContext );
		CFRelease( me );
	}
	CFRelease( me );
}

//===========================================================================================================================
//	_DNSServerUDPReadHandler
//===========================================================================================================================

static OSStatus
	_DNSServerAnswerQuery(
		const uint8_t *	inQueryPtr,
		size_t			inQueryLen,
		Boolean			inForTCP,
		uint8_t **		outResponsePtr,
		size_t *		outResponseLen );

#define _DNSServerAnswerQueryForUDP( IN_QUERY_PTR, IN_QUERY_LEN, IN_RESPONSE_PTR, IN_RESPONSE_LEN ) \
	_DNSServerAnswerQuery( IN_QUERY_PTR, IN_QUERY_LEN, false, IN_RESPONSE_PTR, IN_RESPONSE_LEN )

#define _DNSServerAnswerQueryForTCP( IN_QUERY_PTR, IN_QUERY_LEN, IN_RESPONSE_PTR, IN_RESPONSE_LEN ) \
	_DNSServerAnswerQuery( IN_QUERY_PTR, IN_QUERY_LEN, true, IN_RESPONSE_PTR, IN_RESPONSE_LEN )

static void	_DNSServerUDPDelayedSend( void *inContext );

static void	_DNSServerUDPReadHandler( void *inContext )
{
	OSStatus					err;
	SocketContext * const		sockCtx		= (SocketContext *) inContext;
	DNSServerRef const			me			= (DNSServerRef) sockCtx->userContext;
	struct timeval				now;
	ssize_t						n;
	sockaddr_ip					clientAddr;
	socklen_t					clientAddrLen;
	uint8_t *					responsePtr	= NULL;	// malloc'd
	size_t						responseLen;
	uint8_t						msg[ 512 ];
	
	gettimeofday( &now, NULL );
	
	// Receive message.
	
	clientAddrLen = (socklen_t) sizeof( clientAddr );
	n = recvfrom( sockCtx->sock, (char *) msg, sizeof( msg ), 0, &clientAddr.sa, &clientAddrLen );
	err = map_socket_value_errno( sockCtx->sock, n >= 0, n );
	require_noerr( err, exit );
	
	ds_ulog( kLogLevelInfo, "UDP server received %zd bytes from %##a at %{du:time}.\n", n, &clientAddr, &now );
	
	if( n < kDNSHeaderLength )
	{
		ds_ulog( kLogLevelInfo, "UDP DNS message is too small (%zd < %d).\n", n, kDNSHeaderLength );
		goto exit;
	}
	
	ds_ulog( kLogLevelInfo, "UDP received message:\n\n%1{du:dnsmsg}", msg, (size_t) n );
	
	// Create response.
	
	err = _DNSServerAnswerQueryForUDP( msg, (size_t) n, &responsePtr, &responseLen );
	require_noerr_quiet( err, exit );
	
	// Schedule response.
	
	if( me->responseDelayMs > 0 )
	{
		DNSDelayedResponse *		resp;
		DNSDelayedResponse **		ptr;
		DNSDelayedResponse *		newResp;
		
		newResp = (DNSDelayedResponse *) calloc( 1, sizeof( *newResp ) );
		require_action( newResp, exit, err = kNoMemoryErr );
		
		SockAddrCopy( &clientAddr, &newResp->clientAddr );
		newResp->targetTicks	= UpTicks() + MillisecondsToUpTicks( (uint64_t) me->responseDelayMs );
		newResp->msgLen			= responseLen;
		newResp->msgPtr			= responsePtr;
		responsePtr = NULL;
		
		for( ptr = &me->responseList; ( resp = *ptr ) != NULL; ptr = &resp->next )
		{
			if( newResp->targetTicks < resp->targetTicks ) break;
		}
		
		newResp->next = resp;
		*ptr = newResp;
		
		if( me->responseList == newResp )
		{
			dispatch_source_forget( &me->responseTimer );
			
			err = DispatchTimerCreate( dispatch_time_milliseconds( me->responseDelayMs ), DISPATCH_TIME_FOREVER,
				( (uint64_t) me->responseDelayMs ) * kNanosecondsPerMillisecond / 10, me->queue,
				_DNSServerUDPDelayedSend, NULL, sockCtx, &me->responseTimer );
			require_noerr( err, exit );
			dispatch_resume( me->responseTimer );
		}
	}
	else
	{
		ds_ulog( kLogLevelInfo, "UDP sending %zu byte response:\n\n%1{du:dnsmsg}", responseLen, responsePtr, responseLen );
		
		n = sendto( sockCtx->sock, (char *) responsePtr, responseLen, 0, &clientAddr.sa, clientAddrLen );
		err = map_socket_value_errno( sockCtx->sock, n == (ssize_t) responseLen, n );
		require_noerr( err, exit );
	}
	
exit:
	FreeNullSafe( responsePtr );
	return;
}

static void	_DNSServerUDPDelayedSend( void *inContext )
{
	OSStatus					err;
	SocketContext * const		sockCtx		= (SocketContext *) inContext;
	DNSServerRef const			me			= (DNSServerRef) sockCtx->userContext;
	DNSDelayedResponse *		resp;
	ssize_t						n;
	uint64_t					nowTicks;
	DNSDelayedResponse *		freeList	= NULL;
	
	dispatch_source_forget( &me->responseTimer );
	
	nowTicks = UpTicks();
	while( ( resp = me->responseList ) != NULL )
	{
		if( resp->targetTicks > nowTicks ) break;
		me->responseList = resp->next;
		
		ds_ulog( kLogLevelInfo, "UDP sending %zu byte response (delayed):\n\n%1{du:dnsmsg}",
			resp->msgLen, resp->msgPtr, resp->msgLen );
		
		n = sendto( sockCtx->sock, (char *) resp->msgPtr, resp->msgLen, 0, &resp->clientAddr.sa,
			SockAddrGetSize( &resp->clientAddr ) );
		err = map_socket_value_errno( sockCtx->sock, n == (ssize_t) resp->msgLen, n );
		check_noerr( err );
		
		resp->next	= freeList;
		freeList	= resp;
		nowTicks = UpTicks();
	}
	
	if( ( resp = me->responseList ) != NULL )
	{
		uint64_t		remainingNs;
		
		remainingNs = UpTicksToNanoseconds( resp->targetTicks - nowTicks );
		if( remainingNs > INT64_MAX ) remainingNs = INT64_MAX;
		
		err = DispatchTimerCreate( dispatch_time( DISPATCH_TIME_NOW, (int64_t) remainingNs ), DISPATCH_TIME_FOREVER, 0,
			me->queue, _DNSServerUDPDelayedSend, NULL, sockCtx, &me->responseTimer );
		require_noerr( err, exit );
		dispatch_resume( me->responseTimer );
	}
	
exit:
	while( ( resp = freeList ) != NULL )
	{
		freeList = resp->next;
		DNSScheduledResponseFree( resp );
	}
}

//===========================================================================================================================
//	_DNSServerAnswerQuery
//===========================================================================================================================

#define kLabelPrefix_Alias			"alias"
#define kLabelPrefix_AliasTTL		"alias-ttl"
#define kLabelPrefix_Count			"count"
#define kLabelPrefix_TTL			"ttl"
#define kLabel_IPv4					"ipv4"
#define kLabel_IPv6					"ipv6"

#define kMaxAliasTTLCount		( ( kDomainLabelLengthMax - sizeof_string( kLabelPrefix_AliasTTL ) ) / 2 )

static OSStatus
	_DNSServerInitializeResponseMessage(
		DataBuffer *	inDB,
		unsigned int	inID,
		unsigned int	inFlags,
		const uint8_t *	inQName,
		unsigned int	inQType,
		unsigned int	inQClass );
static OSStatus
	_DNSServerAnswerQueryDynamically(
		const uint8_t *	inQName,
		unsigned int	inQType,
		unsigned int	inQClass,
		Boolean			inForTCP,
		DataBuffer *	inDB );

static OSStatus
	_DNSServerAnswerQuery(
		const uint8_t * const	inQueryPtr,
		const size_t			inQueryLen,
		Boolean					inForTCP,
		uint8_t **				outResponsePtr,
		size_t *				outResponseLen )
{
	OSStatus					err;
	DataBuffer					dataBuf;
	const uint8_t *				ptr;
	const uint8_t * const		queryEnd = &inQueryPtr[ inQueryLen ];
	const DNSHeader *			qhdr;
	unsigned int				msgID, qflags, qtype, qclass, rflags;
	uint8_t						qname[ kDomainNameLengthMax ];
	
	DataBuffer_Init( &dataBuf, NULL, 0, kDNSMaxTCPMessageSize );
	
	require_action_quiet( inQueryLen >= kDNSHeaderLength, exit, err = kUnderrunErr );
	
	qhdr	= (const DNSHeader *) inQueryPtr;
	msgID	= DNSHeaderGetID( qhdr );
	qflags	= DNSHeaderGetFlags( qhdr );
	
	// Minimal checking of the query message's header.
	
	if( ( qflags & kDNSHeaderFlag_Response ) ||					// The message must be a query, not a response.
		( DNSFlagsGetOpCode( qflags ) != kDNSOpCode_Query ) ||	// OPCODE must be QUERY (standard query).
		( DNSHeaderGetQuestionCount( qhdr ) != 1 ) )			// There should be a single question.
	{
		err = kRequestErr;
		goto exit;
	}
	
	// Get QNAME.
	
	ptr = (const uint8_t *) &qhdr[ 1 ];
	err = DNSMessageExtractDomainName( inQueryPtr, inQueryLen, ptr, qname, &ptr );
	require_noerr( err, exit );
	
	// Get QTYPE and QCLASS.
	
	require_action_quiet( ( queryEnd - ptr ) >= 4, exit, err = kUnderrunErr );
	qtype	= DNSQuestionFixedFieldsGetType( (const DNSQuestionFixedFields *) ptr );
	qclass	= DNSQuestionFixedFieldsGetClass( (const DNSQuestionFixedFields *) ptr );
	ptr += 4;
	
	// Create a tentative response message.
	
	rflags = kDNSHeaderFlag_Response;
	if( qflags & kDNSHeaderFlag_RecursionDesired ) rflags |= kDNSHeaderFlag_RecursionDesired;
	DNSFlagsSetOpCode( rflags, kDNSOpCode_Query );
	
	err = _DNSServerInitializeResponseMessage( &dataBuf, msgID, rflags, qname, qtype, qclass );
	require_noerr( err, exit );
	
	err = _DNSServerAnswerQueryDynamically( qname, qtype, qclass, inForTCP, &dataBuf );
	if( err )
	{
		DNSFlagsSetRCode( rflags, kDNSRCode_ServerFailure );
		err = _DNSServerInitializeResponseMessage( &dataBuf, msgID, rflags, qname, qtype, qclass );
		require_noerr( err, exit );
	}
	
	err = DataBuffer_Detach( &dataBuf, outResponsePtr, outResponseLen );
	require_noerr( err, exit );
	
exit:
	DataBuffer_Free( &dataBuf );
	return( err );
}

static OSStatus
	_DNSServerInitializeResponseMessage(
		DataBuffer *	inDB,
		unsigned int	inID,
		unsigned int	inFlags,
		const uint8_t *	inQName,
		unsigned int	inQType,
		unsigned int	inQClass )
{
	OSStatus					err;
	DNSHeader					header;
	DNSQuestionFixedFields		fields;
	
	DataBuffer_Reset( inDB );
	
	memset( &header, 0, sizeof( header ) );
	DNSHeaderSetID( &header, inID );
	DNSHeaderSetFlags( &header, inFlags );
	DNSHeaderSetQuestionCount( &header, 1 );
	
	err = DataBuffer_Append( inDB, &header, sizeof( header ) );
	require_noerr( err, exit );
	
	err = DataBuffer_Append( inDB, inQName, DomainNameLength( inQName ) );
	require_noerr( err, exit );
	
	DNSQuestionFixedFieldsInit( &fields, inQType, inQClass );
	err = DataBuffer_Append( inDB, &fields, sizeof( fields ) );
	require_noerr( err, exit );
	
exit:
	return( err );
}

static OSStatus
	_DNSServerAnswerQueryDynamically(
		const uint8_t * const	inQName,
		const unsigned int		inQType,
		const unsigned int		inQClass,
		const Boolean			inForTCP,
		DataBuffer * const		inDB )
{
	OSStatus			err;							// General-purpose error variable.
	const uint8_t *		labelPtr;						// QNAME label pointer.
	size_t				labelLen;						// QNAME label length.
	DNSHeader *			hdr;							// Response header pointer.
	unsigned int		flags;							// Response header flags.
	unsigned int		rcode;							// Response header response code.
	unsigned int		answerCount		= 0;			// Number of answers contained in response.
	int32_t				aliasCount		= -1;			// Arg from "alias" label. Valid values are in [2 .. 2^31 - 1].
	int					count			= -1;			// First arg from "count" label. Valid values are in [1 .. 255].
	int					randCount		= -1;			// Second arg from "count" label. Valid values are in [1 .. 255].
	int32_t				ttl				= -1;			// Arg from "ttl" label. Valid values are in [0 .. 2^31 - 1].
	uint32_t			aliasTTLs[ kMaxAliasTTLCount ];	// Args from "alias-ttl" label.	Valid values are in [0 .. 2^31 - 1].
	int					i;								// General-purpose array index.
	Boolean				useAliasTTLs	= false;		// True if QNAME contained a valid "alias-ttl" label.
	Boolean				nameExists		= false;		// True if name specified by QNAME exists.
	Boolean				nameHasA		= false;		// True if name specified by QNAME has an A record.
	Boolean				nameHasAAAA		= false;		// True if name specified by QNAME has a AAAA record.
	Boolean				notImplemented	= false;		// True if the kind of the query is not supported.
	Boolean				truncated		= false;		// True if the response message is truncated.
	uint8_t				namePtr[ 2 ];					// Name compression pointer.
	
	if( inQClass != kDNSServiceClass_IN )
	{
		notImplemented = true;
		goto done;
	}
	
	for( labelPtr = inQName; ( labelLen = *labelPtr ) != 0; labelPtr += ( 1 + labelLen ) )
	{
		const char * const		labelStr = (const char *) &labelPtr[ 1 ];
		const char *			next;
		long long				arg;
		int						n;
		
		require_action( labelLen <= kDomainNameLengthMax, exit, err = kUnexpectedErr );
		
		// Check if the first label is a valid alias TTL sequence label.
		
		if( ( labelPtr == inQName ) && ( strnicmp_prefix( labelStr, labelLen, kLabelPrefix_AliasTTL ) == 0 ) )
		{
			const char *			src			= &labelStr[ sizeof_string( kLabelPrefix_AliasTTL ) ];
			const char * const		end			= &labelStr[ labelLen ];
			int						argCount	= 0;
			
			while( src < end )
			{
				n = SNScanF( src, (size_t)( end - src ), "-%10lld%#n", &arg, &next );
				if( n != 1 ) break;
				if( ( arg < 0 ) || ( arg > INT32_MAX ) ) break;	// TTL must be >= 0 and <= (2^31 - 1).
				aliasTTLs[ argCount++ ] = (uint32_t) arg;
				src = next;
			}
			if( ( argCount > 0 ) && ( src == end ) )
			{
				aliasCount		= argCount;
				useAliasTTLs	= true;
				continue;
			}
		}
		
		// Check if the first label is a valid alias label.
		
		if( ( labelPtr == inQName ) && ( strnicmp_prefix( labelStr, labelLen, kLabelPrefix_Alias ) == 0 ) )
		{
			const char *			src = &labelStr[ sizeof_string( kLabelPrefix_Alias ) ];
			const char * const		end = &labelStr[ labelLen ];
			
			if( src == end )
			{
				aliasCount = 1;
				continue;
			}
			
			n = SNScanF( src, (size_t)( end - src ), "-%10lld%#n", &arg, &next );
			if( ( n == 1 ) && ( next == end ) )
			{
				if( ( arg < 2 ) || ( arg > INT32_MAX ) ) break;	// Alias count must be >= 2 and <= (2^31 - 1).
				aliasCount = (int32_t) arg;
				continue;
			}
		}
		
		// Check if the label is a valid count label.
		
		if( strnicmp_prefix( labelStr, labelLen, kLabelPrefix_Count ) == 0  )
		{
			const char *			src = &labelStr[ sizeof_string( kLabelPrefix_Count ) ];
			const char * const		end = &labelStr[ labelLen ];
			
			n = SNScanF( src, (size_t)( end - src ), "-%3lld%#n", &arg, &next );
			if( n == 1 )
			{
				if( count > 0 ) break;						// Count cannot be specified more than once.
				if( ( arg < 1 ) || ( arg > 255 ) ) break;	// Count must be >= 1 and <= 255.
				count = (int) arg;
				
				src = next;
				if( src < end )
				{
					n = SNScanF( src, (size_t)( end - src ), "-%3lld%#n", &arg, &next );
					if( ( n != 1 ) || ( next != end ) ) break;
					if( ( arg < count ) || ( arg > 255 ) ) break;	// Rand count must be >= count and <= 255.
					randCount = (int) arg;
				}
				continue;
			}
		}
		
		// Check if the label is a valid tag label.
		
		if( strnicmp_prefix( labelStr, labelLen, "tag-" ) == 0  ) continue;
		
		// Check if the label is a valid TTL label.
		
		if( strnicmp_prefix( labelStr, labelLen, kLabelPrefix_TTL ) == 0  )
		{
			const char *			src = &labelStr[ sizeof_string( kLabelPrefix_TTL ) ];
			const char * const		end = &labelStr[ labelLen ];
			
			n = SNScanF( src, (size_t)( end - src ), "-%10lld%#n", &arg, &next );
			if( ( n == 1 ) && ( next == end ) )
			{
				if( ttl >= 0 ) break;							// TTL cannot be specified more than once.
				if( ( arg < 0 ) || ( arg > INT32_MAX ) ) break;	// TTL must be >= 0 and <= (2^31 - 1).
				ttl = (int32_t) arg;
				continue;
			}
		}
		
		// Check if the label is a valid IPv4 or IPv6 label.
		
		if( MemIEqual( labelStr, labelLen, kLabel_IPv4, sizeof_string( kLabel_IPv4 ) ) )
		{
			if( nameHasA || nameHasAAAA ) break;	// Valid names have at most one IPv4 or IPv6 label.
			nameHasA = true;
			continue;
		}
		if( MemIEqual( labelStr, labelLen, kLabel_IPv6, sizeof_string( kLabel_IPv6 ) ) )
		{
			if( nameHasA || nameHasAAAA ) break;	// Valid names have at most one IPv4 or IPv6 label.
			nameHasAAAA = true;
			continue;
		}
		
		// If the remaining labels are equal to "d.test.", the name exists.
		
		if( DomainNameEqual( labelPtr, (const uint8_t *) "\x01" "d" "\x04" "test" ) ) nameExists = true;
		break;
	}
	require_quiet( nameExists, done );
	
	// Set default values for count and TTL, if those labels were present.
	
	if( count <= 0 ) count = 1;
	check( ( gDNSServer_DefaultTTL >= 0 ) && ( gDNSServer_DefaultTTL <= INT32_MAX ) );
	if( ttl < 0 ) ttl = gDNSServer_DefaultTTL;
	
	// Names that don't specify v4 or v6 have both A and AAAA records.
	
	if( !nameHasA && !nameHasAAAA )
	{
		nameHasA	= true;
		nameHasAAAA	= true;
	}
	
	check( ( count >= 1 ) && ( count <= 255 ) );
	check( ( randCount <= 0 ) || ( ( randCount >= count ) && ( randCount <= 255 ) ) );
	
	if( aliasCount > 0 )
	{
		size_t				nameOffset;
		uint8_t				rdataLabel[ 1 + kDomainLabelLengthMax + 1  ];
		
		// If aliasCount is non-zero, then the first label of QNAME is either "alias" or "alias-<N>". superPtr is a name
		// compression pointer to the second label of QNAME, i.e., the immediate superdomain name of QNAME. It's used for
		// the RDATA of CNAME records whose canonical name ends with the superdomain name. It may also be used to construct
		// CNAME record names, when the offset to the previous CNAME's RDATA doesn't fit in a compression pointer.
		
		const uint8_t		superPtr[ 2 ] = { 0xC0, (uint8_t)( kDNSHeaderLength + 1 + inQName[ 0 ] ) };
		
		// The name of the first CNAME record is equal to QNAME, so nameOffset is set to offset of QNAME.
		
		nameOffset = kDNSHeaderLength;
		
		for( i = aliasCount; i >= 1; --i )
		{
			size_t						nameLen;
			size_t						rdataLen;
			int							j;
			uint32_t					aliasTTL;
			uint8_t						nameLabel[ 1 + kDomainLabelLengthMax + 1  ];
			DNSRecordFixedFields		fields;
			
			if( nameOffset <= kDNSCompressionOffsetMax )
			{
				namePtr[ 0 ] = (uint8_t)( ( ( nameOffset >> 8 ) & 0x3F ) | 0xC0 );
				namePtr[ 1 ] = (uint8_t)(     nameOffset        & 0xFF );
				
				nameLen = sizeof( namePtr );
			}
			else
			{
				memcpy( nameLabel, rdataLabel, 1 + rdataLabel[ 0 ] );
				nameLen = 1 + nameLabel[ 0 ] + sizeof( superPtr );
			}
			
			if( i >= 2 )
			{
				char *				dst = (char *) &rdataLabel[ 1 ];
				char * const		end = (char *) &rdataLabel[ countof( rdataLabel ) ];
				
				if( useAliasTTLs )
				{
					err = SNPrintF_Add( &dst, end, kLabelPrefix_AliasTTL );
					require_noerr( err, exit );
					
					for( j = aliasCount - ( i - 1 ); j < aliasCount; ++j )
					{
						err = SNPrintF_Add( &dst, end, "-%u", aliasTTLs[ j ] );
						require_noerr( err, exit );
					}
				}
				else
				{
					err = SNPrintF_Add( &dst, end, kLabelPrefix_Alias "%?{end}-%u", i == 2, i - 1 );
					require_noerr( err, exit );
				}
				rdataLabel[ 0 ]	= (uint8_t)( dst - (char *) &rdataLabel[ 1 ] );
				rdataLen		= 1 + rdataLabel[ 0 ] + sizeof( superPtr );
			}
			else
			{
				rdataLen = sizeof( superPtr );
			}
			
			if( !inForTCP )
			{
				size_t		recordLen = nameLen + sizeof( fields ) + rdataLen;
				
				if( ( DataBuffer_GetLen( inDB ) + recordLen ) > kDNSMaxUDPMessageSize )
				{
					truncated = true;
					goto done;
				}
			}
			++answerCount;
			
			// Set CNAME record's NAME.
			
			if( nameOffset <= kDNSCompressionOffsetMax )
			{
				err = DataBuffer_Append( inDB, namePtr, sizeof( namePtr ) );
				require_noerr( err, exit );
			}
			else
			{
				err = DataBuffer_Append( inDB, nameLabel, 1 + nameLabel[ 0 ] );
				require_noerr( err, exit );
				
				err = DataBuffer_Append( inDB, superPtr, sizeof( superPtr ) );
				require_noerr( err, exit );
			}
			
			// Set CNAME record's TYPE, CLASS, TTL, and RDLENGTH.
			
			aliasTTL = useAliasTTLs ? aliasTTLs[ aliasCount - i ] : ( (uint32_t) gDNSServer_DefaultTTL );
			DNSRecordFixedFieldsInit( &fields, kDNSServiceType_CNAME, kDNSServiceClass_IN, aliasTTL, rdataLen );
			err = DataBuffer_Append( inDB, &fields, sizeof( fields ) );
			require_noerr( err, exit );
			
			// Save offset of CNAME record's RDATA, which may be used for the name of the next CNAME record.
			
			nameOffset = DataBuffer_GetLen( inDB );
			
			// Set CNAME record's RDATA.
			
			if( i >= 2 )
			{
				err = DataBuffer_Append( inDB, rdataLabel, 1 + rdataLabel[ 0 ] );
				require_noerr( err, exit );
			}
			err = DataBuffer_Append( inDB, superPtr, sizeof( superPtr ) );
			require_noerr( err, exit );
		}
		
		namePtr[ 0 ] = superPtr[ 0 ];
		namePtr[ 1 ] = superPtr[ 1 ];
	}
	else
	{
		// There are no aliases, so initialize the name compression pointer to point to QNAME.
		
		namePtr[ 0 ] = 0xC0;
		namePtr[ 1 ] = kDNSHeaderLength;
	}
	
	if( ( ( inQType == kDNSServiceType_A    ) && nameHasA    ) ||
		( ( inQType == kDNSServiceType_AAAA ) && nameHasAAAA ) )
	{
		uint8_t *					lsb;				// Pointer to the least significant byte of record data.
		size_t						recordLen;			// Length of the entire record.
		size_t						rdataLen;			// Length of record's RDATA.
		uint8_t						rdata[ 16 ];		// A buffer that's big enough for either A or AAAA RDATA.
		uint8_t						randItegers[ 255 ];	// Array for random integers in [1 .. 255].
		DNSRecordFixedFields		fields;
		
		if( inQType == kDNSServiceType_A )
		{
			rdataLen = 4;
			WriteBig32( rdata, kTestDNSServerBaseAddrV4 );
			lsb = &rdata[ 3 ];
		}
		else
		{
			rdataLen = 16;
			memcpy( rdata, kTestDNSServerBaseAddrV6, 16 );
			lsb = &rdata[ 15 ];
		}
		
		if( randCount > 0 )
		{
			// Populate the array with all integers between 1 and <randCount>, inclusive.
			
			for( i = 0; i < randCount; ++i ) randItegers[ i ] = (uint8_t)( i + 1 );
			
			// Create a contiguous subarray starting at index 0 that contains <count> randomly chosen integers between
			// 1 and <randCount>, inclusive.
			// Loop invariant 1: Array elements with indexes in [0 .. i - 1] have been randomly chosen.
			// Loop invariant 2: Array elements with indexes in [i .. randCount - 1] are candidates for being chosen.
			
			for( i = 0; i < count; ++i )
			{
				uint8_t		tmp;
				int			j;
				
				j = (int) RandomRange( i, randCount - 1 );
				if( i != j )
				{
					tmp = randItegers[ i ];
					randItegers[ i ] = randItegers[ j ];
					randItegers[ j ] = tmp;
				}
			}
		}
		
		recordLen = sizeof( namePtr ) + sizeof( fields ) + rdataLen;
		for( i = 0; i < count; ++i )
		{
			if( !inForTCP && ( ( DataBuffer_GetLen( inDB ) + recordLen ) > kDNSMaxUDPMessageSize ) )
			{
				truncated = true;
				goto done;
			}
			++answerCount;
			
			// Set record NAME.
			
			err = DataBuffer_Append( inDB, namePtr, sizeof( namePtr ) );
			require_noerr( err, exit );
			
			// Set record TYPE, CLASS, TTL, and RDLENGTH.
			
			DNSRecordFixedFieldsInit( &fields, inQType, kDNSServiceClass_IN, ttl, rdataLen );
			err = DataBuffer_Append( inDB, &fields, sizeof( fields ) );
			require_noerr( err, exit );
			
			// Set record RDATA.
			
			*lsb = ( randCount > 0 ) ? randItegers[ i ] : ( *lsb + 1 );
			
			err = DataBuffer_Append( inDB, rdata, rdataLen );
			require_noerr( err, exit );
		}
	}
	
done:
	hdr = (DNSHeader *) DataBuffer_GetPtr( inDB );
	flags = DNSHeaderGetFlags( hdr );
	if( truncated ) flags |= kDNSHeaderFlag_Truncation;
	if( notImplemented )
	{
		rcode = kDNSRCode_NotImplemented;
	}
	else
	{
		flags |= kDNSHeaderFlag_AuthAnswer;
		rcode = nameExists ? kDNSRCode_NoError : kDNSRCode_NXDomain;
	}
	DNSFlagsSetRCode( flags, rcode );
	DNSHeaderSetFlags( hdr, flags );
	DNSHeaderSetAnswerCount( hdr, answerCount );
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	_DNSServerTCPReadHandler
//===========================================================================================================================

typedef struct
{
	sockaddr_ip				clientAddr;		// Client's address.
	dispatch_source_t		readSource;		// Dispatch read source for client socket.
	dispatch_source_t		writeSource;	// Dispatch write source for client socket.
	size_t					offset;			// Offset into receive buffer.
	void *					msgPtr;			// Pointer to dynamically allocated message buffer.
	size_t					msgLen;			// Length of message buffer.
	Boolean					readSuspended;	// True if the read source is currently suspended.
	Boolean					writeSuspended;	// True if the write source is currently suspended.
	Boolean					receivedLength;	// True if receiving DNS message as opposed to the message length.
	uint8_t					lenBuf[ 2 ];	// Buffer for two-octet message length field.
	iovec_t					iov[ 2 ];		// IO vector for writing response message.
	iovec_t *				iovPtr;			// Vector pointer for SocketWriteData().
	int						iovCount;		// Vector count for SocketWriteData().
	
}	TCPConnectionContext;

static void	TCPConnectionStop( TCPConnectionContext *inContext );
static void	TCPConnectionContextFree( TCPConnectionContext *inContext );
static void	TCPConnectionReadHandler( void *inContext );
static void	TCPConnectionWriteHandler( void *inContext );

#define	TCPConnectionForget( X )		ForgetCustomEx( X, TCPConnectionStop, TCPConnectionContextFree )

static void	_DNSServerTCPReadHandler( void *inContext )
{
	OSStatus					err;
	SocketContext * const		sockCtx		= (SocketContext *) inContext;
	TCPConnectionContext *		connection;
	socklen_t					clientAddrLen;
	SocketRef					newSock		= kInvalidSocketRef;
	SocketContext *				newSockCtx	= NULL;
	
	connection = (TCPConnectionContext *) calloc( 1, sizeof( *connection ) );
	require_action( connection, exit, err = kNoMemoryErr );
	
	clientAddrLen = (socklen_t) sizeof( connection->clientAddr );
	newSock = accept( sockCtx->sock, &connection->clientAddr.sa, &clientAddrLen );
	err = map_socket_creation_errno( newSock );
	require_noerr( err, exit );
	
	err = SocketContextCreate( newSock, connection, &newSockCtx );
	require_noerr( err, exit );
	newSock = kInvalidSocketRef;
	
	err = DispatchReadSourceCreate( newSockCtx->sock, NULL, TCPConnectionReadHandler, SocketContextCancelHandler,
		newSockCtx, &connection->readSource );
	require_noerr( err, exit );
	SocketContextRetain( newSockCtx );
	dispatch_resume( connection->readSource );
	
	err = DispatchWriteSourceCreate( newSockCtx->sock, NULL, TCPConnectionWriteHandler, SocketContextCancelHandler,
		newSockCtx, &connection->writeSource );
	require_noerr( err, exit );
	SocketContextRetain( newSockCtx );
	connection->writeSuspended = true;
	connection = NULL;
	
exit:
	ForgetSocket( &newSock );
	SocketContextRelease( newSockCtx );
	TCPConnectionForget( &connection );
}

//===========================================================================================================================
//	TCPConnectionStop
//===========================================================================================================================

static void	TCPConnectionStop( TCPConnectionContext *inContext )
{
	dispatch_source_forget_ex( &inContext->readSource, &inContext->readSuspended );
	dispatch_source_forget_ex( &inContext->writeSource, &inContext->writeSuspended );
}

//===========================================================================================================================
//	TCPConnectionContextFree
//===========================================================================================================================

static void	TCPConnectionContextFree( TCPConnectionContext *inContext )
{
	check( !inContext->readSource );
	check( !inContext->writeSource );
	ForgetMem( &inContext->msgPtr );
	free( inContext );
}

//===========================================================================================================================
//	TCPConnectionReadHandler
//===========================================================================================================================

static void	TCPConnectionReadHandler( void *inContext )
{
	OSStatus					err;
	SocketContext * const		sockCtx		= (SocketContext *) inContext;
	TCPConnectionContext *		connection	= (TCPConnectionContext *) sockCtx->userContext;
	struct timeval				now;
	uint8_t *					responsePtr	= NULL;	// malloc'd
	size_t						responseLen;
	
	// Receive message length.
	
	if( !connection->receivedLength )
	{
		err = SocketReadData( sockCtx->sock, connection->lenBuf, sizeof( connection->lenBuf ), &connection->offset );
		if( err == EWOULDBLOCK ) goto exit;
		require_noerr( err, exit );
		
		connection->offset = 0;
		connection->msgLen = ReadBig16( connection->lenBuf );
		connection->msgPtr = malloc( connection->msgLen );
		require_action( connection->msgPtr, exit, err = kNoMemoryErr );
		connection->receivedLength = true;
	}
	
	// Receive message.
	
	err = SocketReadData( sockCtx->sock, connection->msgPtr, connection->msgLen, &connection->offset );
	if( err == EWOULDBLOCK ) goto exit;
	require_noerr( err, exit );
	
	gettimeofday( &now, NULL );
	dispatch_suspend( connection->readSource );
	connection->readSuspended = true;
	
	ds_ulog( kLogLevelInfo, "TCP server received %zu bytes from %##a at %{du:time}.\n",
		connection->msgLen, &connection->clientAddr, &now );
	
	if( connection->msgLen < kDNSHeaderLength )
	{
		ds_ulog( kLogLevelInfo, "TCP DNS message is too small (%zu < %d).\n", connection->msgLen, kDNSHeaderLength );
		goto exit;
	}
	
	ds_ulog( kLogLevelInfo, "TCP received message:\n\n%1{du:dnsmsg}", connection->msgPtr, connection->msgLen );
	
	// Create response.
	
	err = _DNSServerAnswerQueryForTCP( connection->msgPtr, connection->msgLen, &responsePtr, &responseLen );
	require_noerr_quiet( err, exit );
	
	// Send response.
	
	ds_ulog( kLogLevelInfo, "TCP sending %zu byte response:\n\n%1{du:dnsmsg}", responseLen, responsePtr, responseLen );
	
	free( connection->msgPtr );
	connection->msgPtr = responsePtr;
	connection->msgLen = responseLen;
	responsePtr = NULL;
	
	check( connection->msgLen <= UINT16_MAX );
	WriteBig16( connection->lenBuf, connection->msgLen );
	connection->iov[ 0 ].iov_base	= connection->lenBuf;
	connection->iov[ 0 ].iov_len	= sizeof( connection->lenBuf );
	connection->iov[ 1 ].iov_base	= connection->msgPtr;
	connection->iov[ 1 ].iov_len	= connection->msgLen;
	
	connection->iovPtr		= connection->iov;
	connection->iovCount	= 2;
	
	check( connection->writeSuspended );
	dispatch_resume( connection->writeSource );
	connection->writeSuspended = false;
	
exit:
	FreeNullSafe( responsePtr );
	if( err && ( err != EWOULDBLOCK ) ) TCPConnectionForget( &connection );
}

//===========================================================================================================================
//	TCPConnectionWriteHandler
//===========================================================================================================================

static void	TCPConnectionWriteHandler( void *inContext )
{
	OSStatus					err;
	SocketContext * const		sockCtx		= (SocketContext *) inContext;
	TCPConnectionContext *		connection	= (TCPConnectionContext *) sockCtx->userContext;
	
	err = SocketWriteData( sockCtx->sock, &connection->iovPtr, &connection->iovCount );
	if( err == EWOULDBLOCK ) goto exit;
	check_noerr( err );
	
	TCPConnectionForget( &connection );
	
exit:
	return;
}

//===========================================================================================================================
//	GAIPerfCmd
//===========================================================================================================================

#define kGAIPerfStandardTTL		( 1 * kSecondsPerHour )

typedef struct GAITesterPrivate *		GAITesterRef;
typedef struct GAITestCase				GAITestCase;

typedef uint32_t		GAITesterEventType;
#define kGAITesterEvent_Started		1
#define kGAITesterEvent_Stopped		2

typedef struct
{
	const char *		name;				// Domain name that was resolved.
	int64_t				connectionTimeUs;	// Time in microseconds that it took to create a DNS-SD connection.
	int64_t				firstTimeUs;		// Time in microseconds that it took to get the first address result.
	int64_t				timeUs;				// Time in microseconds that it took to get all expected address results.
	
}	GAITestItemResult;

typedef void ( *GAITesterEventHandler_f )( GAITesterEventType inType, void *inContext );
typedef void
	( *GAITesterResultsHandler_f )(
		const char *				inCaseTitle,
		MicroTime64					inCaseStartTime,
		MicroTime64					inCaseEndTime,
		const GAITestItemResult *	inResults,
		size_t						inResultCount,
		size_t						inItemCount,
		void *						inContext );

typedef unsigned int		GAITestAddrType;
#define kGAITestAddrType_None		0
#define kGAITestAddrType_IPv4		( 1U << 0 )
#define kGAITestAddrType_IPv6		( 1U << 1 )
#define kGAITestAddrType_Both		( kGAITestAddrType_IPv4 | kGAITestAddrType_IPv6 )

#define GAITestAddrTypeIsValid( X ) \
	( ( (X) & kGAITestAddrType_Both ) && ( ( (X) & ~kGAITestAddrType_Both ) == 0 ) )

typedef enum
{
	kGAIPerfOutputFormat_JSON	= 1,
	kGAIPerfOutputFormat_XML	= 2,
	kGAIPerfOutputFormat_Binary	= 3
	
}	GAIPerfOutputFormatType;

typedef struct
{
	GAITesterRef				tester;				// GAI tester object.
	CFMutableArrayRef			caseResults;		// Array of test case results.
	char *						outputFilePath;		// File to write test results to. If NULL, then write to stdout.
	GAIPerfOutputFormatType		outputFormat;		// Format of test results output.
	unsigned int				callDelayMs;		// Amount of time to wait before calling DNSServiceGetAddrInfo().
	unsigned int				serverDelayMs;		// Amount of additional time to have server delay its responses.
	unsigned int				defaultIterCount;	// Default test case iteration count.
	dispatch_source_t			sigIntSource;		// Dispatch source for SIGINT.
	dispatch_source_t			sigTermSource;		// Dispatch source for SIGTERM.
	Boolean						gotSignal;			// True if SIGINT or SIGTERM was caught.
	Boolean						testerStarted;		// True if the GAI tester was started.
	Boolean						appendNewLine;		// True if a newline character should be appended to JSON output.
	
}	GAIPerfContext;

static void		GAIPerfContextFree( GAIPerfContext *inContext );
static OSStatus	GAIPerfAddAdvancedTestCases( GAIPerfContext *inContext );
static OSStatus	GAIPerfAddBasicTestCases( GAIPerfContext *inContext );
static void		GAIPerfEventHandler( GAITesterEventType inType, void *inContext );
static void
	GAIPerfResultsHandler(
		const char *				inCaseTitle,
		MicroTime64					inCaseStartTime,
		MicroTime64					inCaseEndTime,
		const GAITestItemResult *	inResults,
		size_t						inResultCount,
		size_t						inItemCount,
		void *						inContext );
static void		GAIPerfSignalHandler( void *inContext );

CFTypeID		GAITesterGetTypeID( void );
static OSStatus
	GAITesterCreate(
		dispatch_queue_t	inQueue,
		int					inCallDelayMs,
		int					inServerDelayMs,
		int					inServerDefaultTTL,
		GAITesterRef *		outTester );
static void		GAITesterStart( GAITesterRef inTester );
static void		GAITesterStop( GAITesterRef inTester );
static void		GAITesterAddCase( GAITesterRef inTester, GAITestCase *inCase );
static void
	GAITesterSetEventHandler(
		GAITesterRef			inTester,
		GAITesterEventHandler_f	inEventHandler,
		void *					inEventContext );
static void
	GAITesterSetResultsHandler(
		GAITesterRef				inTester,
		GAITesterResultsHandler_f	inResultsHandler,
		void *						inResultsContext );

static OSStatus	GAITestCaseCreate( const char *inTitle, unsigned int inTimeLimitMs, GAITestCase **outSet );
static void		GAITestCaseFree( GAITestCase *inCase );
static OSStatus
	GAITestCaseAddItem(
		GAITestCase *	inCase,
		unsigned int	inAliasCount,
		unsigned int	inAddressCount,
		int				inTTL,
		GAITestAddrType	inHasAddrs,
		GAITestAddrType	inWantAddrs,
		unsigned int	inItemCount );
static OSStatus	GAITestCaseAddLocalHostItem( GAITestCase *inCase, GAITestAddrType inWantAddrs, unsigned int inItemCount );

#define kGAIPerfTestSuite_Basic			1
#define kGAIPerfTestSuite_Advanced		2

static void	GAIPerfCmd( void )
{
	OSStatus				err;
	GAIPerfContext *		context;
	int						suiteValue;
	
	context = (GAIPerfContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->caseResults = CFArrayCreateMutable( NULL, 0, &kCFTypeArrayCallBacks );
	require_action( context->caseResults, exit, err = kNoMemoryErr );
	
	context->outputFormat = (GAIPerfOutputFormatType) CLIArgToValue( "format", gGAIPerf_OutputFormat, &err,
		"json",		kGAIPerfOutputFormat_JSON,
		"xml",		kGAIPerfOutputFormat_XML,
		"binary",	kGAIPerfOutputFormat_Binary,
		NULL );
	require_noerr_quiet( err, exit );
	
	context->callDelayMs		= ( gGAIPerf_CallDelayMs >= 0 ) ? (unsigned int) gGAIPerf_CallDelayMs : 0;
	context->serverDelayMs		= ( gGAIPerf_ServerDelayMs >= 0 ) ? (unsigned int) gGAIPerf_ServerDelayMs : 0;
	context->defaultIterCount	= ( gGAIPerf_DefaultIterCount >= 0 ) ? (unsigned int) gGAIPerf_DefaultIterCount : 0;
	context->appendNewLine		= gGAIPerf_OutputAppendNewLine ? true : false;
	
	if( gGAIPerf_OutputFilePath )
	{
		context->outputFilePath = strdup( gGAIPerf_OutputFilePath );
		require_action( context->outputFilePath, exit, err = kNoMemoryErr );
	}
	
	err = GAITesterCreate( dispatch_get_main_queue(), (int) context->callDelayMs, (int) context->serverDelayMs,
		kGAIPerfStandardTTL, &context->tester );
	require_noerr( err, exit );
	
	check( gGAIPerf_TestSuite );
	suiteValue = CLIArgToValue( "suite", gGAIPerf_TestSuite, &err,
		"basic",	kGAIPerfTestSuite_Basic,
		"advanced",	kGAIPerfTestSuite_Advanced,
		NULL );
	require_noerr_quiet( err, exit );
	
	switch( suiteValue )
	{
		case kGAIPerfTestSuite_Basic:
			err = GAIPerfAddBasicTestCases( context );
			require_noerr( err, exit );
			break;
		
		case kGAIPerfTestSuite_Advanced:
			err = GAIPerfAddAdvancedTestCases( context );
			require_noerr( err, exit );
			break;
		
		default:
			err = kValueErr;
			break;
	}
	
	GAITesterSetEventHandler( context->tester, GAIPerfEventHandler, context );
	GAITesterSetResultsHandler( context->tester, GAIPerfResultsHandler, context );
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, GAIPerfSignalHandler, context, &context->sigIntSource );
	require_noerr( err, exit );
	dispatch_resume( context->sigIntSource );
	
	signal( SIGTERM, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGTERM, GAIPerfSignalHandler, context, &context->sigTermSource );
	require_noerr( err, exit );
	dispatch_resume( context->sigTermSource );
	
	GAITesterStart( context->tester );
	dispatch_main();
	
exit:
	if( context ) GAIPerfContextFree( context );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	GAIPerfContextFree
//===========================================================================================================================

static void	GAIPerfContextFree( GAIPerfContext *inContext )
{
	ForgetCF( &inContext->tester );
	ForgetCF( &inContext->caseResults );
	ForgetMem( &inContext->outputFilePath );
	dispatch_source_forget( &inContext->sigIntSource );
	dispatch_source_forget( &inContext->sigTermSource );
	free( inContext );
}

//===========================================================================================================================
//	GAIPerfAddAdvancedTestCases
//===========================================================================================================================

#define kTestCaseTitleBufferSize		128

static void
	_GAIPerfWriteTestCaseTitle(
		char			inBuffer[ kTestCaseTitleBufferSize ],
		unsigned int	inCNAMERecordCount,
		unsigned int	inARecordCount,
		unsigned int	inAAAARecordCount,
		GAITestAddrType	inRequested,
		unsigned int	inIterationCount,
		Boolean			inIterationsAreUnique );
static void
	_GAIPerfWriteLocalHostTestCaseTitle(
		char			inBuffer[ kTestCaseTitleBufferSize ],
		GAITestAddrType	inRequested,
		unsigned int	inIterationCount );
static unsigned int
	_GAIPerfTimeLimitMs(
		unsigned int	inCallDelayMs,
		unsigned int	inServerDelayMs,
		unsigned int	inIterationCount );

#define kGAIPerfAdvancedTestSuite_MaxAliasCount		4
#define kGAIPerfAdvancedTestSuite_MaxAddrCount		8

static OSStatus	GAIPerfAddAdvancedTestCases( GAIPerfContext *inContext )
{
	OSStatus			err;
	unsigned int		aliasCount, addressCount, timeLimitMs, i;
	GAITestCase *		testCase = NULL;
	char				title[ kTestCaseTitleBufferSize ];
	
	aliasCount = 0;
	while( aliasCount <= kGAIPerfAdvancedTestSuite_MaxAliasCount )
	{
		for( addressCount = 1; addressCount <= kGAIPerfAdvancedTestSuite_MaxAddrCount; addressCount *= 2 )
		{
			// Add a test case to resolve a domain name with
			//
			//     <aliasCount> CNAME records, <addressCount> A records, and <addressCount> AAAA records
			//
			// to its IPv4 and IPv6 addresses. Each iteration resolves a unique instance of such a domain name, which
			// requires server queries.
			
			_GAIPerfWriteTestCaseTitle( title, aliasCount, addressCount, addressCount, kGAITestAddrType_Both,
				inContext->defaultIterCount, true );
			
			timeLimitMs = _GAIPerfTimeLimitMs( inContext->callDelayMs, inContext->serverDelayMs,
				inContext->defaultIterCount );
			err = GAITestCaseCreate( title, timeLimitMs, &testCase );
			require_noerr( err, exit );
			
			for( i = 0; i < inContext->defaultIterCount; ++i )
			{
				err = GAITestCaseAddItem( testCase, aliasCount, addressCount, kGAIPerfStandardTTL,
					kGAITestAddrType_Both, kGAITestAddrType_Both, 1 );
				require_noerr( err, exit );
			}
			
			GAITesterAddCase( inContext->tester, testCase );
			testCase = NULL;
			
			// Add a test case to resolve a domain name with
			//
			//     <aliasCount> CNAME records, <addressCount> A records, and <addressCount> AAAA records
			//
			// to its IPv4 and IPv6 addresses. A preliminary iteration resolves a unique domain name, which requires a server
			// query. The subsequent iterations resolve the same domain name as the preliminary iteration, which should
			// ideally require no server queries, i.e., the results should come from the cache.
			
			_GAIPerfWriteTestCaseTitle( title, aliasCount, addressCount, addressCount, kGAITestAddrType_Both,
				inContext->defaultIterCount, false );
			
			timeLimitMs = _GAIPerfTimeLimitMs( inContext->callDelayMs, inContext->serverDelayMs, 1 ) +
				_GAIPerfTimeLimitMs( inContext->callDelayMs, 0, inContext->defaultIterCount );
			err = GAITestCaseCreate( title, timeLimitMs, &testCase );
			require_noerr( err, exit );
			
			err = GAITestCaseAddItem( testCase, aliasCount, addressCount, kGAIPerfStandardTTL,
				kGAITestAddrType_Both, kGAITestAddrType_Both, inContext->defaultIterCount + 1 );
			require_noerr( err, exit );
			
			GAITesterAddCase( inContext->tester, testCase );
			testCase = NULL;
		}
		
		if( aliasCount == 0 )	aliasCount  = 1;
		else					aliasCount *= 2;
	}
	
	// Finally, add a test case to resolve localhost to its IPv4 and IPv6 addresses.
	
	_GAIPerfWriteLocalHostTestCaseTitle( title, kGAITestAddrType_Both, inContext->defaultIterCount );
	
	timeLimitMs = _GAIPerfTimeLimitMs( inContext->callDelayMs, 0, inContext->defaultIterCount );
	err = GAITestCaseCreate( title, timeLimitMs, &testCase );
	require_noerr( err, exit );
	
	err = GAITestCaseAddLocalHostItem( testCase, kGAITestAddrType_Both, inContext->defaultIterCount );
	require_noerr( err, exit );
	
	GAITesterAddCase( inContext->tester, testCase );
	testCase = NULL;
	
exit:
	if( testCase ) GAITestCaseFree( testCase );
	return( err );
}

//===========================================================================================================================
//	_GAIPerfWriteTestCaseTitle
//===========================================================================================================================

#define GAITestAddrTypeToRequestKeyValue( X ) (				\
	( (X) == kGAITestAddrType_Both ) ? "ipv4\\,ipv6"	:	\
	( (X) == kGAITestAddrType_IPv4 ) ? "ipv4"			:	\
	( (X) == kGAITestAddrType_IPv6 ) ? "ipv6"			:	\
									   "" )

static void
	_GAIPerfWriteTestCaseTitle(
		char			inBuffer[ kTestCaseTitleBufferSize ],
		unsigned int	inCNAMERecordCount,
		unsigned int	inARecordCount,
		unsigned int	inAAAARecordCount,
		GAITestAddrType	inRequested,
		unsigned int	inIterationCount,
		Boolean			inIterationsAreUnique )
{
	SNPrintF( inBuffer, kTestCaseTitleBufferSize, "name=dynamic,cname=%u,a=%u,aaaa=%u,req=%s,iterations=%u%?s",
		inCNAMERecordCount, inARecordCount, inAAAARecordCount, GAITestAddrTypeToRequestKeyValue( inRequested ),
		inIterationCount, inIterationsAreUnique, ",unique" );
}

//===========================================================================================================================
//	_GAIPerfWriteLocalHostTestCaseTitle
//===========================================================================================================================

static void
	_GAIPerfWriteLocalHostTestCaseTitle(
		char			inBuffer[ kTestCaseTitleBufferSize ],
		GAITestAddrType	inRequested,
		unsigned int	inIterationCount )
{
	SNPrintF( inBuffer, kTestCaseTitleBufferSize, "name=localhost,req=%s,iterations=%u",
		GAITestAddrTypeToRequestKeyValue( inRequested ), inIterationCount );
}

//===========================================================================================================================
//	_GAIPerfTimeLimitMs
//===========================================================================================================================

static unsigned int
	_GAIPerfTimeLimitMs(
		unsigned int	inCallDelayMs,
		unsigned int	inServerDelayMs,
		unsigned int	inIterationCount )
{
	// Allow each iteration 20 ms to complete (in addition to the call and server delay times).
	
	return( ( inCallDelayMs + inServerDelayMs + 20 ) * inIterationCount );
}

//===========================================================================================================================
//	GAIPerfAddBasicTestCases
//===========================================================================================================================

#define kGAIPerfBasicTestSuite_AliasCount		2
#define kGAIPerfBasicTestSuite_AddrCount		4

static OSStatus	GAIPerfAddBasicTestCases( GAIPerfContext *inContext )
{
	OSStatus			err;
	GAITestCase *		testCase = NULL;
	char				title[ kTestCaseTitleBufferSize ];
	unsigned int		timeLimitMs, i;
	
	// Test Case #1:
	// Resolve a domain name with
	//
	//     2 CNAME records, 4 A records, and 4 AAAA records
	//
	// to its IPv4 and IPv6 addresses. Each of the iterations resolves a unique domain name, which requires server
	// queries.
	
	_GAIPerfWriteTestCaseTitle( title, kGAIPerfBasicTestSuite_AliasCount,
		kGAIPerfBasicTestSuite_AddrCount, kGAIPerfBasicTestSuite_AddrCount, kGAITestAddrType_Both,
		inContext->defaultIterCount, true );
	
	timeLimitMs = _GAIPerfTimeLimitMs( inContext->callDelayMs, inContext->serverDelayMs, inContext->defaultIterCount );
	err = GAITestCaseCreate( title, timeLimitMs, &testCase );
	require_noerr( err, exit );
	
	for( i = 0; i < inContext->defaultIterCount; ++i )
	{
		err = GAITestCaseAddItem( testCase, kGAIPerfBasicTestSuite_AliasCount, kGAIPerfBasicTestSuite_AddrCount,
			kGAIPerfStandardTTL, kGAITestAddrType_Both, kGAITestAddrType_Both, 1 );
		require_noerr( err, exit );
	}
	
	GAITesterAddCase( inContext->tester, testCase );
	testCase = NULL;
	
	// Test Case #2:
	// Resolve a domain name with
	//
	//     2 CNAME records, 4 A records, and 4 AAAA records
	//
	// to its IPv4 and IPv6 addresses. A preliminary iteration resolves a unique instance of such a domain name, which
	// requires server queries. Each of the subsequent iterations resolves the same domain name as the preliminary
	// iteration, which should ideally require no additional server queries, i.e., the results should come from the cache.
	
	_GAIPerfWriteTestCaseTitle( title, kGAIPerfBasicTestSuite_AliasCount,
		kGAIPerfBasicTestSuite_AddrCount, kGAIPerfBasicTestSuite_AddrCount, kGAITestAddrType_Both,
		inContext->defaultIterCount, false );
	
	timeLimitMs = _GAIPerfTimeLimitMs( inContext->callDelayMs, inContext->serverDelayMs, 1 ) +
		_GAIPerfTimeLimitMs( inContext->callDelayMs, 0, inContext->defaultIterCount );
	err = GAITestCaseCreate( title, timeLimitMs, &testCase );
	require_noerr( err, exit );
	
	err = GAITestCaseAddItem( testCase, kGAIPerfBasicTestSuite_AliasCount, kGAIPerfBasicTestSuite_AddrCount,
		kGAIPerfStandardTTL, kGAITestAddrType_Both, kGAITestAddrType_Both, inContext->defaultIterCount + 1 );
	require_noerr( err, exit );
	
	GAITesterAddCase( inContext->tester, testCase );
	testCase = NULL;
	
	// Test Case #3:
	// Each iteration resolves localhost to its IPv4 and IPv6 addresses.
	
	_GAIPerfWriteLocalHostTestCaseTitle( title, kGAITestAddrType_Both, inContext->defaultIterCount );
	
	timeLimitMs = _GAIPerfTimeLimitMs( inContext->callDelayMs, 0, inContext->defaultIterCount );
	err = GAITestCaseCreate( title, timeLimitMs, &testCase );
	require_noerr( err, exit );
	
	err = GAITestCaseAddLocalHostItem( testCase, kGAITestAddrType_Both, inContext->defaultIterCount );
	require_noerr( err, exit );
	
	GAITesterAddCase( inContext->tester, testCase );
	testCase = NULL;
	
exit:
	if( testCase ) GAITestCaseFree( testCase );
	return( err );
}

//===========================================================================================================================
//	GAIPerfEventHandler
//===========================================================================================================================

static void _GAIPerfOutputResultsAndExit( GAIPerfContext *inContext ) ATTRIBUTE_NORETURN;

static void	GAIPerfEventHandler( GAITesterEventType inType, void *inContext )
{
	GAIPerfContext * const		context	= (GAIPerfContext *) inContext;
	
	if( inType == kGAITesterEvent_Started )
	{
		context->testerStarted = true;
	}
	else if( inType == kGAITesterEvent_Stopped )
	{
		if( context->gotSignal ) exit( 1 );
		_GAIPerfOutputResultsAndExit( context );
	}
}

//===========================================================================================================================
//	_GAIPerfOutputResultsAndExit
//===========================================================================================================================

#define kGAIPerfResultsKey_TestCases		CFSTR( "testCases" )
#define kGAIPerfResultsKey_Info				CFSTR( "info" )

#define kGAIPerfInfoKey_CallDelay		CFSTR( "callDelayMs" )
#define kGAIPerfInfoKey_ServerDelay		CFSTR( "serverDelayMs" )

static void _GAIPerfOutputResultsAndExit( GAIPerfContext *inContext )
{
	OSStatus				err;
	CFPropertyListRef		plist	= NULL;
	CFDataRef				results	= NULL;
	FILE *					file	= NULL;
	
	err = CFPropertyListCreateFormatted( kCFAllocatorDefault, &plist,
		"{"
			"%kO=%O"
			"%kO="
			"{"
				"%kO=%lli"
				"%kO=%lli"
			"}"
		"}",
		kGAIPerfResultsKey_TestCases,	inContext->caseResults,
		kGAIPerfResultsKey_Info,
		kGAIPerfInfoKey_CallDelay,		(int64_t) inContext->callDelayMs,
		kGAIPerfInfoKey_ServerDelay,	(int64_t) inContext->serverDelayMs );
	require_noerr( err, exit );
	
	// Convert results to a specific format.
	
	switch( inContext->outputFormat )
	{
		case kGAIPerfOutputFormat_JSON:
			results = CFCreateJSONData( plist, kJSONFlags_None, NULL );
			require_action( results, exit, err = kUnknownErr );
			break;
		
		case kGAIPerfOutputFormat_XML:
			results = CFPropertyListCreateData( NULL, plist, kCFPropertyListXMLFormat_v1_0, 0, NULL );
			require_action( results, exit, err = kUnknownErr );
			break;
		
		case kGAIPerfOutputFormat_Binary:
			results = CFPropertyListCreateData( NULL, plist, kCFPropertyListBinaryFormat_v1_0, 0, NULL );
			require_action( results, exit, err = kUnknownErr );
			break;
		
		default:
			err = kValueErr;
			goto exit;
	}
	
	// Write formatted results to file or stdout.
	
	if( inContext->outputFilePath )
	{
		file = fopen( inContext->outputFilePath, "wb" );
		err = map_global_value_errno( file, file );
		require_noerr( err, exit );
	}
	else
	{
		file = stdout;
	}
	
	err = WriteANSIFile( file, CFDataGetBytePtr( results ), (size_t) CFDataGetLength( results ) );
	require_noerr( err, exit );
	
	// Write a trailing newline for JSON-formatted results if requested.
	
	if( ( inContext->outputFormat == kGAIPerfOutputFormat_JSON ) && inContext->appendNewLine )
	{
		err = WriteANSIFile( file, "\n", 1 );
		require_noerr( err, exit );
	}
	
exit:
	CFReleaseNullSafe( plist );
	CFReleaseNullSafe( results );
	if( file && ( file != stdout ) ) fclose( file );
	GAIPerfContextFree( inContext );
	exit( err ? 1 : 0 );
}

//===========================================================================================================================
//	GAIPerfResultsHandler
//===========================================================================================================================

// Keys for test case dictionary

#define kGAIPerfTestCaseKey_Title				CFSTR( "title" )
#define kGAIPerfTestCaseKey_StartTime			CFSTR( "startTimeUs" )
#define kGAIPerfTestCaseKey_EndTime				CFSTR( "endTimeUs" )
#define kGAIPerfTestCaseKey_Results				CFSTR( "results" )
#define kGAIPerfTestCaseKey_FirstStats			CFSTR( "firstStats" )
#define kGAIPerfTestCaseKey_ConnectionStats		CFSTR( "connectionStats" )
#define kGAIPerfTestCaseKey_Stats				CFSTR( "stats" )
#define kGAIPerfTestCaseKey_TimedOut			CFSTR( "timedOut" )

// Keys for test case results array entry dictionaries

#define kGAIPerfTestCaseResultKey_Name					CFSTR( "name" )
#define kGAIPerfTestCaseResultKey_ConnectionTime		CFSTR( "connectionTimeUs" )
#define kGAIPerfTestCaseResultKey_FirstTime				CFSTR( "firstTimeUs" )
#define kGAIPerfTestCaseResultKey_Time					CFSTR( "timeUs" )

// Keys for test case stats dictionaries

#define kGAIPerfTestCaseStatsKey_Count		CFSTR( "count" )
#define kGAIPerfTestCaseStatsKey_Min		CFSTR( "min" )
#define kGAIPerfTestCaseStatsKey_Max		CFSTR( "max" )
#define kGAIPerfTestCaseStatsKey_Mean		CFSTR( "mean" )
#define kGAIPerfTestCaseStatsKey_StdDev		CFSTR( "sd" )

typedef struct
{
	double		min;
	double		max;
	double		mean;
	double		stdDev;
	
}	GAIPerfStats;

#define GAIPerfStatsInit( X ) \
	do { (X)->min = DBL_MAX; (X)->max = DBL_MIN; (X)->mean = 0.0; (X)->stdDev = 0.0; } while( 0 )

static void
	GAIPerfResultsHandler(
		const char *				inCaseTitle,
		MicroTime64					inCaseStartTime,
		MicroTime64					inCaseEndTime,
		const GAITestItemResult *	inResults,
		size_t						inResultCount,
		size_t						inItemCount,
		void *						inContext )
{
	OSStatus					err;
	GAIPerfContext * const		context	= (GAIPerfContext *) inContext;
	int							namesAreDynamic, namesAreUnique;
	const char *				ptr;
	size_t						count, startIndex;
	CFMutableArrayRef			results	= NULL;
	GAIPerfStats				stats, firstStats, connStats;
	double						sum, firstSum, connSum, value, diff;
	size_t						keyValueLen, i;
	char						keyValue[ 16 ];	// Size must be at least strlen( "name=dynamic" ) + 1 bytes.
	
	// If this test case resolves the same "d.test." name in each iteration (title contains the "name=dynamic" key-value
	// pair, but not the "unique" key), then don't count the first iteration, whose purpose is to populate the cache with the
	// domain name's CNAME, A, and AAAA records.
	
	namesAreDynamic	= false;
	namesAreUnique	= false;
	ptr = inCaseTitle;
	while( ParseQuotedEscapedString( ptr, NULL, ",", keyValue, sizeof( keyValue ), &keyValueLen, NULL, &ptr ) )
	{
		if( strnicmpx( keyValue, keyValueLen, "name=dynamic" ) == 0 )
		{
			namesAreDynamic = true;
		}
		else if( strnicmpx( keyValue, keyValueLen, "unique" ) == 0 )
		{
			namesAreUnique = true;
		}
		if( namesAreDynamic && namesAreUnique ) break;
	}
	
	if( namesAreDynamic && !namesAreUnique && ( inItemCount > 0 ) )
	{
		count		= ( inResultCount > 0 ) ? ( inResultCount - 1 ) : 0;
		startIndex	= 1;
	}
	else
	{
		count		= inResultCount;
		startIndex	= 0;
	}
	
	results = CFArrayCreateMutable( NULL, (CFIndex) count, &kCFTypeArrayCallBacks );
	require_action( results, exit, err = kNoMemoryErr );
	
	GAIPerfStatsInit( &stats );
	GAIPerfStatsInit( &firstStats );
	GAIPerfStatsInit( &connStats );
	
	sum			= 0.0;
	firstSum	= 0.0;
	connSum		= 0.0;
	for( i = startIndex; i < count; ++i )
	{
		value = (double) inResults[ i ].timeUs;
		if( value < stats.min ) stats.min = value;
		if( value > stats.max ) stats.max = value;
		sum += value;
		
		value = (double) inResults[ i ].firstTimeUs;
		if( value < firstStats.min ) firstStats.min = value;
		if( value > firstStats.max ) firstStats.max = value;
		firstSum += value;
		
		value = (double) inResults[ i ].connectionTimeUs;
		if( value < connStats.min ) connStats.min = value;
		if( value > connStats.max ) connStats.max = value;
		connSum += value;
		
		err = CFPropertyListAppendFormatted( kCFAllocatorDefault, results,
			"{"
				"%kO=%s"
				"%kO=%lli"
				"%kO=%lli"
				"%kO=%lli"
			"}",
			kGAIPerfTestCaseResultKey_Name,				inResults[ i ].name,
			kGAIPerfTestCaseResultKey_ConnectionTime,	inResults[ i ].connectionTimeUs,
			kGAIPerfTestCaseResultKey_FirstTime,		inResults[ i ].firstTimeUs,
			kGAIPerfTestCaseResultKey_Time,				inResults[ i ].timeUs );
		require_noerr( err, exit );
	}
	
	if( count > 0 )
	{
		stats.mean		= sum      / count;
		firstStats.mean	= firstSum / count;
		connStats.mean	= connSum  / count;
		
		sum			= 0.0;
		firstSum	= 0.0;
		connSum		= 0.0;
		for( i = startIndex; i < count; ++i )
		{
			diff		 = stats.mean - (double) inResults[ i ].timeUs;
			sum			+= ( diff * diff );
			
			diff		 = firstStats.mean - (double) inResults[ i ].firstTimeUs;
			firstSum	+= ( diff * diff );
			
			diff		 = connStats.mean - (double) inResults[ i ].connectionTimeUs;
			connSum		+= ( diff * diff );
		}
		stats.stdDev		= sqrt( sum      / count );
		firstStats.stdDev	= sqrt( firstSum / count );
		connStats.stdDev	= sqrt( connSum  / count );
	}
	
	err = CFPropertyListAppendFormatted( kCFAllocatorDefault, context->caseResults,
		"{"
			"%kO=%s"
			"%kO=%lli"
			"%kO=%lli"
			"%kO=%O"
			"%kO="
			"{"
				"%kO=%lli"
				"%kO=%f"
				"%kO=%f"
				"%kO=%f"
				"%kO=%f"
			"}"
			"%kO="
			"{"
				"%kO=%lli"
				"%kO=%f"
				"%kO=%f"
				"%kO=%f"
				"%kO=%f"
			"}"
			"%kO="
			"{"
				"%kO=%lli"
				"%kO=%f"
				"%kO=%f"
				"%kO=%f"
				"%kO=%f"
			"}"
			"%kO=%b"
		"}",
		kGAIPerfTestCaseKey_Title,			inCaseTitle,
		kGAIPerfTestCaseKey_StartTime,		(int64_t) inCaseStartTime,
		kGAIPerfTestCaseKey_EndTime,		(int64_t) inCaseEndTime,
		kGAIPerfTestCaseKey_Results,		results,
		kGAIPerfTestCaseKey_Stats,
		kGAIPerfTestCaseStatsKey_Count,		(int64_t) count,
		kGAIPerfTestCaseStatsKey_Min,		stats.min,
		kGAIPerfTestCaseStatsKey_Max,		stats.max,
		kGAIPerfTestCaseStatsKey_Mean,		stats.mean,
		kGAIPerfTestCaseStatsKey_StdDev,	stats.stdDev,
		kGAIPerfTestCaseKey_FirstStats,
		kGAIPerfTestCaseStatsKey_Count,		(int64_t) count,
		kGAIPerfTestCaseStatsKey_Min,		firstStats.min,
		kGAIPerfTestCaseStatsKey_Max,		firstStats.max,
		kGAIPerfTestCaseStatsKey_Mean,		firstStats.mean,
		kGAIPerfTestCaseStatsKey_StdDev,	firstStats.stdDev,
		kGAIPerfTestCaseKey_ConnectionStats,
		kGAIPerfTestCaseStatsKey_Count,		(int64_t) count,
		kGAIPerfTestCaseStatsKey_Min,		connStats.min,
		kGAIPerfTestCaseStatsKey_Max,		connStats.max,
		kGAIPerfTestCaseStatsKey_Mean,		connStats.mean,
		kGAIPerfTestCaseStatsKey_StdDev,	connStats.stdDev,
		kGAIPerfTestCaseKey_TimedOut,		( inResultCount < inItemCount ) ? true : false );
	require_noerr( err, exit );
	
exit:
	CFReleaseNullSafe( results );
}

//===========================================================================================================================
//	GAIPerfSignalHandler
//===========================================================================================================================

static void	GAIPerfSignalHandler( void *inContext )
{
	GAIPerfContext * const		context = (GAIPerfContext *) inContext;
	
	context->gotSignal = true;
	if( context->tester && context->testerStarted )
	{
		GAITesterStop( context->tester );
	}
	else
	{
		exit( 1 );
	}
}

//===========================================================================================================================
//	GAITesterCreate
//===========================================================================================================================

typedef enum
{
	kGAITestConnType_UseMainConnection		= 1,
	kGAITestConnType_OwnSharedConnection	= 2
	
}	GAITestConnType;

typedef struct GAITestItem		GAITestItem;
struct GAITestItem
{
	GAITestItem *		next;				// Next test item in list.
	char *				name;				// Domain name to resolve.
	int64_t				connectionTimeUs;	// Time in microseconds that it took to create a DNS-SD connection.
	int64_t				firstTimeUs;		// Time in microseconds that it took to get the first address result.
	int64_t				timeUs;				// Time in microseconds that it took to get all expected address results.
	unsigned int		addressCount;		// Address count of the domain name, i.e., the Count label argument.
	Boolean				hasV4;				// True if the domain name has one or more IPv4 addresses.
	Boolean				hasV6;				// True if the domain name has one or more IPv6 addresses.
	Boolean				wantV4;				// True if DNSServiceGetAddrInfo() should be called to get IPv4 addresses.
	Boolean				wantV6;				// True if DNSServiceGetAddrInfo() should be called to get IPv6 addresses.
};

struct GAITestCase
{
	GAITestCase *		next;			// Next test case in list.
	GAITestItem *		itemList;		// List of test items.
	char *				title;			// Title of the test case.
	unsigned int		timeLimitMs;	// Time limit in milliseconds for the test case's completion.
};

struct GAITesterPrivate
{
	CFRuntimeBase					base;				// CF object base.
	dispatch_queue_t				queue;				// Serial work queue.
	DNSServiceRef					mainRef;			// Reference to the main shared DNS-SD connection.
	DNSServiceRef					opRef;				// Reference to the current DNSServiceGetAddrInfo operation.
	GAITestCase *					caseList;			// List of test cases.
	GAITestCase *					currentCase;		// Pointer to the current test case.
	GAITestItem *					currentItem;		// Pointer to the current test item.
	MicroTime64						caseStartTime;		// Start time of current test case in Unix time as microseconds.
	MicroTime64						caseEndTime;		// End time of current test case in Unix time as microseconds.
	Boolean							started;			// True if the tester has been successfully started.
	Boolean							stopped;			// True if the tester has been stopped.
	int								callDelayMs;		// Amount of time to wait before calling DNSServiceGetAddrInfo().
	dispatch_source_t				caseTimer;			// Timer for enforcing a test case time limits.
	pcap_t *						pcap;				// Captures traffic between mDNSResponder and test DNS server.
	pid_t							serverPID;			// PID of the test DNS server.
	int								serverDelayMs;		// Additional time to have the server delay its responses by.
	int								serverDefaultTTL;	// Default TTL for the server's records.
	GAITesterEventHandler_f			eventHandler;		// User's event handler.
	void *							eventContext;		// User's event handler context.
	GAITesterResultsHandler_f		resultsHandler;		// User's results handler.
	void *							resultsContext;		// User's results handler context.
	
	// Variables for current test item.
	
	uint64_t						bitmapV4;		// Bitmap of IPv4 results that have yet to be received.
	uint64_t						bitmapV6;		// Bitmap of IPv6 results that have yet to be received.
	uint64_t						startTicks;		// Start ticks of DNSServiceGetAddrInfo().
	uint64_t						connTicks;		// Ticks when the connection was created.
	uint64_t						firstTicks;		// Ticks when the first DNSServiceGetAddrInfo result was received.
	uint64_t						endTicks;		// Ticks when the last DNSServiceGetAddrInfo result was received.
	Boolean							gotFirstResult;	// True if the first result has been received.
};

CF_CLASS_DEFINE( GAITester );

static void		_GAITesterRun( void *inContext );
static OSStatus	_GAITesterCreatePacketCapture( pcap_t **outPCap );
static void		_GAITesterTimeout( void *inContext );
static void		_GAITesterAdvanceCurrentItem( GAITesterRef inTester );
static void		_GAITesterAdvanceCurrentSet( GAITesterRef inTester );
static void		_GAITesterInitializeCurrentTest( GAITesterRef inTester );
static void DNSSD_API
	_GAITesterGetAddrInfoCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext );
static void		_GAITesterCompleteCurrentTest( GAITesterRef inTester, Boolean inTimedOut );

#define ForgetPacketCapture( X )		ForgetCustom( X, pcap_close )

static OSStatus
	GAITestItemCreate(
		const char *	inName,
		unsigned int	inAddressCount,
		GAITestAddrType	inHasAddrs,
		GAITestAddrType	inWantAddrs,
		GAITestItem **	outItem );
static OSStatus	GAITestItemDuplicate( const GAITestItem *inItem, GAITestItem **outItem );
static void		GAITestItemFree( GAITestItem *inItem );

static OSStatus
	GAITesterCreate(
		dispatch_queue_t	inQueue,
		int					inCallDelayMs,
		int					inServerDelayMs,
		int					inServerDefaultTTL,
		GAITesterRef *		outTester )
{
	OSStatus			err;
	GAITesterRef		obj = NULL;
	
	CF_OBJECT_CREATE( GAITester, obj, err, exit );
	
	ReplaceDispatchQueue( &obj->queue, inQueue );
	obj->callDelayMs		= inCallDelayMs;
	obj->serverPID			= -1;
	obj->serverDelayMs		= inServerDelayMs;
	obj->serverDefaultTTL	= inServerDefaultTTL;
	
	*outTester = obj;
	obj = NULL;
	err = kNoErr;
	
exit:
	CFReleaseNullSafe( obj );
	return( err );
}

//===========================================================================================================================
//	_GAITesterFinalize
//===========================================================================================================================

static void	_GAITesterFinalize( CFTypeRef inObj )
{
	GAITesterRef const		me = (GAITesterRef) inObj;
	GAITestCase *			testCase;
	
	check( !me->opRef );
	check( !me->mainRef );
	check( !me->caseTimer );
	dispatch_forget( &me->queue );
	while( ( testCase = me->caseList ) != NULL )
	{
		me->caseList = testCase->next;
		GAITestCaseFree( testCase );
	}
}

//===========================================================================================================================
//	GAITesterStart
//===========================================================================================================================

static void	_GAITesterStart( void *inContext );
static void	_GAITesterStop( GAITesterRef me );

static void	GAITesterStart( GAITesterRef me )
{
	CFRetain( me );
	dispatch_async_f( me->queue, me, _GAITesterStart );
}

extern char **		environ;

static void	_GAITesterStart( void *inContext )
{
	OSStatus				err;
	GAITesterRef const		me = (GAITesterRef) inContext;
	char *					argv[ 4 ];
	char *					ptr;
	char *					end;
	char					command[ 128 ];
	
	ptr = &command[ 0 ];
	end = &command[ countof( command ) ];
	SNPrintF_Add( &ptr, end, "dnssdutil server --loopback --followPID %lld", (int64_t) getpid() );
	if( me->serverDefaultTTL >= 0 ) SNPrintF_Add( &ptr, end, " --defaultTTL %d", me->serverDefaultTTL );
	if( me->serverDelayMs    >= 0 ) SNPrintF_Add( &ptr, end, " --responseDelay %d", me->serverDelayMs );
	
	argv[ 0 ] = "/bin/sh";
	argv[ 1 ] = "-c";
	argv[ 2 ] = command;
	argv[ 3 ] = NULL;
	err = posix_spawn( &me->serverPID, argv[ 0 ], NULL, NULL, argv, environ );
	require_noerr( err, exit );
	
	me->currentCase = me->caseList;
	me->currentItem = me->currentCase ? me->currentCase->itemList : NULL;
	_GAITesterInitializeCurrentTest( me );
	
	// Hack: The first tester run is delayed for three seconds to allow the test DNS server to start up.
	// A better way to handle this is to issue an asynchronous query for something in the d.test. domain. As soon as an
	// expected response is received, the server can be considered to be up and running.
	
	CFRetain( me );
	dispatch_after_f( dispatch_time_seconds( 3 ), me->queue, me, _GAITesterRun );
	
	CFRetain( me );
	me->started = true;
	if( me->eventHandler ) me->eventHandler( kGAITesterEvent_Started, me->eventContext );
	
exit:
	if( err ) _GAITesterStop( me );
	CFRelease( me );
}

//===========================================================================================================================
//	GAITesterStop
//===========================================================================================================================

static void	_GAITesterUserStop( void *inContext );

static void	GAITesterStop( GAITesterRef me )
{
	CFRetain( me );
	dispatch_async_f( me->queue, me, _GAITesterUserStop );
}

static void	_GAITesterUserStop( void *inContext )
{
	GAITesterRef const		me = (GAITesterRef) inContext;
	
	_GAITesterStop( me );
	CFRelease( me );
}

static void	_GAITesterStop( GAITesterRef me )
{
	OSStatus		err;
	
	DNSServiceForget( &me->opRef );
	DNSServiceForget( &me->mainRef );
	ForgetPacketCapture( &me->pcap );
	dispatch_source_forget( &me->caseTimer );
	if( me->serverPID != -1 )
	{
		err = kill( me->serverPID, SIGTERM );
		err = map_global_noerr_errno( err );
		check_noerr( err );
	}
	
	if( !me->stopped )
	{
		me->stopped = true;
		if( me->eventHandler ) me->eventHandler( kGAITesterEvent_Stopped, me->eventContext );
		if( me->started ) CFRelease( me );
	}
}

//===========================================================================================================================
//	GAITesterAddCase
//===========================================================================================================================

static void	GAITesterAddCase( GAITesterRef me, GAITestCase *inCase )
{
	GAITestCase **		ptr;
	
	for( ptr = &me->caseList; *ptr != NULL; ptr = &( *ptr )->next ) {}
	*ptr = inCase;
}

//===========================================================================================================================
//	GAITesterSetEventHandler
//===========================================================================================================================

static void	GAITesterSetEventHandler( GAITesterRef me, GAITesterEventHandler_f inEventHandler, void *inEventContext )
{
	me->eventHandler = inEventHandler;
	me->eventContext = inEventContext;
}

//===========================================================================================================================
//	GAITesterSetResultsHandler
//===========================================================================================================================

static void	GAITesterSetResultsHandler( GAITesterRef me, GAITesterResultsHandler_f inResultsHandler, void *inResultsContext )
{
	me->resultsHandler = inResultsHandler;
	me->resultsContext = inResultsContext;
}

//===========================================================================================================================
//	_GAITesterRun
//===========================================================================================================================

static void	_GAITesterRun( void *inContext )
{
	OSStatus				err;
	GAITesterRef const		me		= (GAITesterRef) inContext;
	GAITestItem *			item;
	GAITestItemResult *		results	= NULL;
	
	require_action_quiet( !me->stopped, exit, err = kNoErr );
	
	for( ;; )
	{
		item = me->currentItem;
		if( item )
		{
			DNSServiceProtocol		protocols;
			
			check( !me->opRef );
			check( ( me->bitmapV4 != 0 ) || ( me->bitmapV6 != 0 ) );
			
			// Perform preliminary tasks if this is the start of a new test case.
			
			if( item == me->currentCase->itemList )
			{
				// Flush mDNSResponder's cache.
				
				err = systemf( NULL, "killall -HUP mDNSResponder" );
				require_noerr( err, exit );
				usleep( kMicrosecondsPerSecond );
				
				// Start a packet capture.
				
				check( !me->pcap );
				err = _GAITesterCreatePacketCapture( &me->pcap );
				require_noerr( err, exit );
				
				// Start the test case time limit timer.
				
				check( !me->caseTimer );
				if( me->currentCase->timeLimitMs > 0 )
				{
					const int64_t		timeLimitSecs = ( me->currentCase->timeLimitMs + 999 ) / 1000;
					
					err = DispatchTimerCreate( dispatch_time_seconds( timeLimitSecs ), DISPATCH_TIME_FOREVER,
						( (uint64_t) timeLimitSecs ) * kNanosecondsPerSecond / 10,
						me->queue, _GAITesterTimeout, NULL, me, &me->caseTimer );
					require_noerr( err, exit );
					dispatch_resume( me->caseTimer );
				}
				
				me->caseStartTime = GetCurrentMicroTime();
			}
			
			// Call DNSServiceGetAddrInfo().
			
			if( me->callDelayMs > 0 ) usleep( ( (useconds_t) me->callDelayMs ) * kMicrosecondsPerMillisecond );
			
			protocols = 0;
			if( item->wantV4 ) protocols |= kDNSServiceProtocol_IPv4;
			if( item->wantV6 ) protocols |= kDNSServiceProtocol_IPv6;
			
			check( !me->mainRef );
			me->startTicks = UpTicks();
			
			err = DNSServiceCreateConnection( &me->mainRef );
			require_noerr( err, exit );
			
			err = DNSServiceSetDispatchQueue( me->mainRef, me->queue );
			require_noerr( err, exit );
			
			me->connTicks = UpTicks();
			
			me->opRef = me->mainRef;
			err = DNSServiceGetAddrInfo( &me->opRef, kDNSServiceFlagsShareConnection | kDNSServiceFlagsReturnIntermediates,
				kDNSServiceInterfaceIndexAny, protocols, item->name, _GAITesterGetAddrInfoCallback, me );
			require_noerr( err, exit );
			break;
		}
		else
		{
			// No more test items means that this test case has completed (or timed out).
			
			me->caseEndTime = GetCurrentMicroTime();
			dispatch_source_forget( &me->caseTimer );
			ForgetPacketCapture( &me->pcap );
			
			if( me->resultsHandler )
			{
				size_t		resultCount, itemCount, i;
				int			timedOut;
				
				itemCount	= 0;
				resultCount	= 0;
				timedOut	= false;
				for( item = me->currentCase->itemList; item; item = item->next )
				{
					if( !timedOut )
					{
						if( item->timeUs < 0 )
						{
							timedOut = true;
						}
						else
						{
							++resultCount;
						}
					}
					++itemCount;
				}
				if( resultCount > 0 )
				{
					results = (GAITestItemResult *) calloc( resultCount, sizeof( *results ) );
					require_action( results, exit, err = kNoMemoryErr );
					
					item = me->currentCase->itemList;
					for( i = 0; i < resultCount; ++i )
					{
						results[ i ].name				= item->name;
						results[ i ].connectionTimeUs	= item->connectionTimeUs;
						results[ i ].firstTimeUs		= item->firstTimeUs;
						results[ i ].timeUs				= item->timeUs;
						item = item->next;
					}
				}
				me->resultsHandler( me->currentCase->title, me->caseStartTime, me->caseEndTime, results, resultCount,
					itemCount, me->resultsContext );
				ForgetMem( &results );
			}
			
			_GAITesterAdvanceCurrentSet( me );
			require_action_quiet( me->currentCase, exit, err = kEndingErr );
		}
	}
	
exit:
	FreeNullSafe( results );
	if( err ) _GAITesterStop( me );
	CFRelease( me );
}

//===========================================================================================================================
//	_GAITesterCreatePacketCapture
//===========================================================================================================================

static OSStatus	_GAITesterCreatePacketCapture( pcap_t **outPCap )
{
	OSStatus				err;
	pcap_t *				pcap;
	struct bpf_program		program;
	char					errBuf[ PCAP_ERRBUF_SIZE ];
	
	pcap = pcap_create( "lo0", errBuf );
	require_action_string( pcap, exit, err = kUnknownErr, errBuf );
	
	err = pcap_set_buffer_size( pcap, 512 * kBytesPerKiloByte );
	require_noerr_action( err, exit, err = kUnknownErr );
	
	err = pcap_set_snaplen( pcap, 512 );
	require_noerr_action( err, exit, err = kUnknownErr );
	
	err = pcap_set_immediate_mode( pcap, 0 );
	require_noerr_action_string( err, exit, err = kUnknownErr, pcap_geterr( pcap ) );
	
	err = pcap_activate( pcap );
	require_noerr_action_string( err, exit, err = kUnknownErr, pcap_geterr( pcap ) );
	
	err = pcap_setdirection( pcap, PCAP_D_INOUT );
	require_noerr_action_string( err, exit, err = kUnknownErr, pcap_geterr( pcap ) );
	
	err = pcap_setnonblock( pcap, 1, errBuf );
	require_noerr_action_string( err, exit, err = kUnknownErr, pcap_geterr( pcap ) );
	
	err = pcap_compile( pcap, &program, "udp port 53", 1, PCAP_NETMASK_UNKNOWN );
	require_noerr_action_string( err, exit, err = kUnknownErr, pcap_geterr( pcap ) );
	
	err = pcap_setfilter( pcap, &program );
	pcap_freecode( &program );
	require_noerr_action_string( err, exit, err = kUnknownErr, pcap_geterr( pcap ) );
	
	*outPCap = pcap;
	pcap = NULL;
	
exit:
	if( pcap ) pcap_close( pcap );
	return( err );
}

//===========================================================================================================================
//	_GAITesterTimeout
//===========================================================================================================================

static void	_GAITesterTimeout( void *inContext )
{
	GAITesterRef const		me = (GAITesterRef) inContext;
	
	dispatch_source_forget( &me->caseTimer );
	
	_GAITesterCompleteCurrentTest( me, true );
}

//===========================================================================================================================
//	_GAITesterAdvanceCurrentItem
//===========================================================================================================================

static void	_GAITesterAdvanceCurrentItem( GAITesterRef me )
{
	if( me->currentItem )
	{
		me->currentItem = me->currentItem->next;
		_GAITesterInitializeCurrentTest( me );
	}
}

//===========================================================================================================================
//	_GAITesterAdvanceCurrentSet
//===========================================================================================================================

static void	_GAITesterAdvanceCurrentSet( GAITesterRef me )
{
	if( me->currentCase )
	{
		me->caseStartTime	= 0;
		me->caseEndTime		= 0;
		me->currentCase		= me->currentCase->next;
		if( me->currentCase )
		{
			me->currentItem = me->currentCase->itemList;
			_GAITesterInitializeCurrentTest( me );
		}
	}
}

//===========================================================================================================================
//	_GAITesterInitializeCurrentTest
//===========================================================================================================================

static void	_GAITesterInitializeCurrentTest( GAITesterRef me )
{
	GAITestItem * const		item = me->currentItem;
	
	if( item )
	{
		check( item->addressCount > 0 );
		if( item->wantV4 )
		{
			me->bitmapV4 = item->hasV4 ? ( ( UINT64_C( 1 ) << item->addressCount ) - 1 ) : 1;
		}
		else
		{
			me->bitmapV4 = 0;
		}
		
		if( item->wantV6 )
		{
			me->bitmapV6 = item->hasV6 ? ( ( UINT64_C( 1 ) << item->addressCount ) - 1 ) : 1;
		}
		else
		{
			me->bitmapV6 = 0;
		}
		me->gotFirstResult = false;
	}
}

//===========================================================================================================================
//	_GAITesterGetAddrInfoCallback
//===========================================================================================================================

static void DNSSD_API
	_GAITesterGetAddrInfoCallback(
		DNSServiceRef			inSDRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inError,
		const char *			inHostname,
		const struct sockaddr *	inSockAddr,
		uint32_t				inTTL,
		void *					inContext )
{
	GAITesterRef const				me		= (GAITesterRef) inContext;
	GAITestItem * const				item	= me->currentItem;
	const sockaddr_ip * const		sip		= (const sockaddr_ip *) inSockAddr;
	uint64_t						nowTicks;
	uint64_t *						bitmapPtr;
	uint64_t						bitmask;
	unsigned int					addrOffset;
	
	Unused( inSDRef );
	Unused( inInterfaceIndex );
	Unused( inHostname );
	Unused( inTTL );
	
	nowTicks = UpTicks();
	
	require_quiet( inFlags & kDNSServiceFlagsAdd, exit );
	require_quiet( !inError || ( inError == kDNSServiceErr_NoSuchRecord ), exit );
	
	bitmapPtr	= NULL;
	bitmask		= 0;
	if( ( sip->sa.sa_family == AF_INET ) && item->wantV4 )
	{
		if( item->hasV4 )
		{
			if( !inError )
			{
				const uint32_t		addrV4 = ntohl( sip->v4.sin_addr.s_addr );
				
				if( strcasecmp( item->name, "localhost." ) == 0 )
				{
					if( addrV4 == INADDR_LOOPBACK )
					{
						bitmask		= 1;
						bitmapPtr	= &me->bitmapV4;
					}
				}
				else
				{
					addrOffset = addrV4 - kTestDNSServerBaseAddrV4;
					if( ( addrOffset >= 1 ) && ( addrOffset <= item->addressCount ) )
					{
						bitmask		= UINT64_C( 1 ) << ( addrOffset - 1 );
						bitmapPtr	= &me->bitmapV4;
					}
				}
			}
		}
		else if( inError == kDNSServiceErr_NoSuchRecord )
		{
			bitmask		= 1;
			bitmapPtr	= &me->bitmapV4;
		}
	}
	else if( ( sip->sa.sa_family == AF_INET6 ) && item->wantV6 )
	{
		if( item->hasV6 )
		{
			if( !inError )
			{
				const uint8_t * const		addrV6 = sip->v6.sin6_addr.s6_addr;
				
				if( strcasecmp( item->name, "localhost." ) == 0 )
				{
					if( memcmp( addrV6, in6addr_loopback.s6_addr, 16 ) == 0 )
					{
						bitmask		= 1;
						bitmapPtr	= &me->bitmapV6;
					}
				}
				else if( memcmp( addrV6, kTestDNSServerBaseAddrV6, 15 ) == 0 )
				{
					addrOffset = addrV6[ 15 ];
					if( ( addrOffset >= 1 ) && ( addrOffset <= item->addressCount ) )
					{
						bitmask		= UINT64_C( 1 ) << ( addrOffset - 1 );
						bitmapPtr	= &me->bitmapV6;
					}
				}
			}
		}
		else if( inError == kDNSServiceErr_NoSuchRecord )
		{
			bitmask		= 1;
			bitmapPtr	= &me->bitmapV6;
		}
	}
	
	if( bitmapPtr && ( *bitmapPtr & bitmask ) )
	{
		*bitmapPtr &= ~bitmask;
		if( !me->gotFirstResult )
		{
			me->firstTicks		= nowTicks;
			me->gotFirstResult	= true;
		}
		
		if( ( me->bitmapV4 == 0 ) && ( me->bitmapV6 == 0 ) )
		{
			me->endTicks = nowTicks;
			_GAITesterCompleteCurrentTest( me, false );
		}
	}
	
exit:
	return;
}

//===========================================================================================================================
//	_GAITesterCompleteCurrentTest
//===========================================================================================================================

static OSStatus
	_GAITesterGetDNSMessageFromPacket(
		const uint8_t *		inPacketPtr,
		size_t				inPacketLen,
		const uint8_t **	outMsgPtr,
		size_t *			outMsgLen );

static void	_GAITesterCompleteCurrentTest( GAITesterRef me, Boolean inTimedOut )
{
	OSStatus				err;
	GAITestItem *			item;
	struct timeval *		tsQA	= NULL;
	struct timeval *		tsQAAAA	= NULL;
	struct timeval *		tsRA	= NULL;
	struct timeval *		tsRAAAA	= NULL;
	struct timeval			timeStamps[ 4 ];
	struct timeval *		tsPtr	= &timeStamps[ 0 ];
	struct timeval *		tsQ;
	struct timeval *		tsR;
	int64_t					idleTimeUs;
	uint8_t					name[ kDomainNameLengthMax ];
	
	DNSServiceForget( &me->opRef );
	DNSServiceForget( &me->mainRef );
	
	if( inTimedOut )
	{
		for( item = me->currentItem; item; item = item->next )
		{
			item->firstTimeUs	= -1;
			item->timeUs		= -1;
		}
		me->currentItem = NULL;
		
		CFRetain( me );
		dispatch_async_f( me->queue, me, _GAITesterRun );
		return;
	}
	
	item = me->currentItem;
	err = DomainNameFromString( name, item->name, NULL );
    require_noerr( err, exit );
	
	for( ;; )
	{
		int									status;
		struct pcap_pkthdr *				pktHdr;
		const uint8_t *						packet;
		const uint8_t *						msgPtr;
		size_t								msgLen;
		const DNSHeader *					hdr;
		unsigned int						flags;
		const uint8_t *						ptr;
		const DNSQuestionFixedFields *		qfields;
		unsigned int						qtype;
		uint8_t								qname[ kDomainNameLengthMax ];
		
		status = pcap_next_ex( me->pcap, &pktHdr, &packet );
		if( status != 1 ) break;
		if( _GAITesterGetDNSMessageFromPacket( packet, pktHdr->caplen, &msgPtr, &msgLen ) != kNoErr ) continue;
		if( msgLen < kDNSHeaderLength ) continue;
		
		hdr = (const DNSHeader *) msgPtr;
		flags = DNSHeaderGetFlags( hdr );
		if( DNSFlagsGetOpCode( flags ) != kDNSOpCode_Query ) continue;
		if( DNSHeaderGetQuestionCount( hdr ) < 1 ) continue;
		
		ptr = (const uint8_t *) &hdr[ 1 ];
		if( DNSMessageExtractDomainName( msgPtr, msgLen, ptr, qname, &ptr ) != kNoErr ) continue;
		if( !DomainNameEqual( qname, name ) ) continue;
		
		qfields = (const DNSQuestionFixedFields *) ptr;
		if( DNSQuestionFixedFieldsGetClass( qfields ) != kDNSServiceClass_IN ) continue;
		
		qtype = DNSQuestionFixedFieldsGetType( qfields );
		if( item->wantV4 && ( qtype == kDNSServiceType_A ) )
		{
			if( flags & kDNSHeaderFlag_Response )
			{
				if( tsQA && !tsRA )
				{
					tsRA  = tsPtr++;
					*tsRA = pktHdr->ts;
				}
			}
			else if( !tsQA )
			{
				tsQA  = tsPtr++;
				*tsQA = pktHdr->ts;
			}
		}
		else if( item->wantV6 && ( qtype == kDNSServiceType_AAAA ) )
		{
			if( flags & kDNSHeaderFlag_Response )
			{
				if( tsQAAAA && !tsRAAAA )
				{
					tsRAAAA  = tsPtr++;
					*tsRAAAA = pktHdr->ts;
				}
			}
			else if( !tsQAAAA )
			{
				tsQAAAA  = tsPtr++;
				*tsQAAAA = pktHdr->ts;
			}
		}
	}
	
	if( tsQA && tsQAAAA )	tsQ = TIMEVAL_GT( *tsQA, *tsQAAAA ) ? tsQA : tsQAAAA;
	else					tsQ = tsQA ? tsQA : tsQAAAA;
	
	if( tsRA && tsRAAAA )	tsR = TIMEVAL_LT( *tsRA, *tsRAAAA ) ? tsRA : tsRAAAA;
	else					tsR = tsQA ? tsQA : tsQAAAA;
	
	if( tsQ && tsR )
	{
		idleTimeUs = TIMEVAL_USEC64_DIFF( *tsR, *tsQ );
		if( idleTimeUs < 0 ) idleTimeUs = 0;
	}
	else
	{
		idleTimeUs = 0;
	}
	
	item->connectionTimeUs	= (int64_t)  UpTicksToMicroseconds( me->connTicks  - me->startTicks );
	item->firstTimeUs		= (int64_t)( UpTicksToMicroseconds( me->firstTicks - me->connTicks  ) - (uint64_t) idleTimeUs );
	item->timeUs			= (int64_t)( UpTicksToMicroseconds( me->endTicks   - me->connTicks  ) - (uint64_t) idleTimeUs );
	
	_GAITesterAdvanceCurrentItem( me );
	CFRetain( me );
	dispatch_async_f( me->queue, me, _GAITesterRun );
	
exit:
	if( err ) _GAITesterStop( me );
}

//===========================================================================================================================
//	_GAITesterGetDNSMessageFromPacket
//===========================================================================================================================

#define kHeaderSizeNullLink		 4
#define kHeaderSizeIPv4Min		20
#define kHeaderSizeIPv6			40
#define kHeaderSizeUDP			 8

#define kIPProtocolUDP		0x11

static OSStatus
	_GAITesterGetDNSMessageFromPacket(
		const uint8_t *		inPacketPtr,
		size_t				inPacketLen,
		const uint8_t **	outMsgPtr,
		size_t *			outMsgLen )
{
	OSStatus					err;
	const uint8_t *				nullLink;
	uint32_t					addressFamily;
	const uint8_t *				ip;
	int							ipHeaderLen;
	int							protocol;
	const uint8_t *				msg;
	const uint8_t * const		end = &inPacketPtr[ inPacketLen ];
	
	nullLink = &inPacketPtr[ 0 ];
	require_action_quiet( ( end - nullLink ) >= kHeaderSizeNullLink, exit, err = kUnderrunErr );
	addressFamily = ReadHost32( &nullLink[ 0 ] );
	
	ip = &nullLink[ kHeaderSizeNullLink ];
	if( addressFamily == AF_INET )
	{
		require_action_quiet( ( end - ip ) >= kHeaderSizeIPv4Min, exit, err = kUnderrunErr );
		ipHeaderLen	= ( ip[ 0 ] & 0x0F ) * 4;
		protocol	=   ip[ 9 ];
	}
	else if( addressFamily == AF_INET6 )
	{
		require_action_quiet( ( end - ip ) >= kHeaderSizeIPv6, exit, err = kUnderrunErr );
		ipHeaderLen	= kHeaderSizeIPv6;
		protocol	= ip[ 6 ];
	}
	else
	{
		err = kTypeErr;
		goto exit;
	}
	require_action_quiet( protocol == kIPProtocolUDP, exit, err = kTypeErr );
	require_action_quiet( ( end - ip ) >= ( ipHeaderLen + kHeaderSizeUDP ), exit, err = kUnderrunErr );
	
	msg = &ip[ ipHeaderLen + kHeaderSizeUDP ];
	
	*outMsgPtr = msg;
	*outMsgLen = (size_t)( end - msg );
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	GAITestCaseCreate
//===========================================================================================================================

static OSStatus	GAITestCaseCreate( const char *inTitle, unsigned int inTimeLimitMs, GAITestCase **outSet )
{
	OSStatus			err;
	GAITestCase *		obj;
	
	obj = (GAITestCase *) calloc( 1, sizeof( *obj ) );
	require_action( obj, exit, err = kNoMemoryErr );
	
	obj->title = strdup( inTitle );
	require_action( obj->title, exit, err = kNoMemoryErr );
	
	obj->timeLimitMs = inTimeLimitMs;
	
	*outSet = obj;
	obj = NULL;
	err = kNoErr;
	
exit:
	if( obj ) GAITestCaseFree( obj );
	return( err );
}

//===========================================================================================================================
//	GAITestCaseFree
//===========================================================================================================================

static void	GAITestCaseFree( GAITestCase *inCase )
{
	GAITestItem *		item;
	
	while( ( item = inCase->itemList ) != NULL )
	{
		inCase->itemList = item->next;
		GAITestItemFree( item );
	}
	ForgetMem( &inCase->title );
	free( inCase );
}

//===========================================================================================================================
//	GAITestCaseAddItem
//===========================================================================================================================

// A character set of lower-case alphabet characters and digits and a string length of six allows for 36^6 = 2,176,782,336
// possible strings to use in the Tag label.

#define kUniqueStringCharSet		"abcdefghijklmnopqrstuvwxyz0123456789"
#define kUniqueStringCharSetLen		sizeof_string( kUniqueStringCharSet )
#define kUniqueStringLen			6

static OSStatus
	GAITestCaseAddItem(
		GAITestCase *	inCase,
		unsigned int	inAliasCount,
		unsigned int	inAddressCount,
		int				inTTL,
		GAITestAddrType	inHasAddrs,
		GAITestAddrType	inWantAddrs,
		unsigned int	inItemCount )
{
	OSStatus			err;
	GAITestItem *		item;
	GAITestItem *		item2;
	GAITestItem *		newItemList = NULL;
	GAITestItem **		itemPtr;
	char *				ptr;
	char *				end;
	unsigned int		i;
	char				name[ 64 ];
	char				uniqueStr[ kUniqueStringLen + 1 ];
	
	require_action_quiet( inItemCount > 0, exit, err = kNoErr );
	
	// Limit address count to 64 because we use 64-bit bitmaps for keeping track of addresses.
	
	require_action_quiet( ( inAddressCount >= 1 ) && ( inAddressCount <= 64 ), exit, err = kCountErr );
	require_action_quiet( ( inAliasCount >= 0 ) && ( inAliasCount <= INT32_MAX ), exit, err = kCountErr );
	require_action_quiet( GAITestAddrTypeIsValid( inHasAddrs ), exit, err = kValueErr );
	
	ptr = &name[ 0 ];
	end = &name[ countof( name ) ];
	
	// Add Alias label.
	
	if(      inAliasCount == 1 ) SNPrintF_Add( &ptr, end, "alias." );
	else if( inAliasCount >= 2 ) SNPrintF_Add( &ptr, end, "alias-%u.", inAliasCount );
	
	// Add Count label.
	
	SNPrintF_Add( &ptr, end, "count-%u.", inAddressCount );
	
	// Add TTL label.
	
	if( inTTL >= 0 ) SNPrintF_Add( &ptr, end, "ttl-%d.", inTTL );
	
	// Add Tag label.
	
	RandomString( kUniqueStringCharSet, kUniqueStringCharSetLen, kUniqueStringLen, kUniqueStringLen, uniqueStr );
	SNPrintF_Add( &ptr, end, "tag-%s.", uniqueStr );
	
	// Add IPv4 or IPv6 label if necessary.
	
	switch( inHasAddrs )
	{
		case kGAITestAddrType_IPv4:
			SNPrintF_Add( &ptr, end, "ipv4." );
			break;
		
		case kGAITestAddrType_IPv6:
			SNPrintF_Add( &ptr, end, "ipv6." );
			break;
	}
	
	// Add d.test. labels.
	
	SNPrintF_Add( &ptr, end, "d.test." );
	
	// Create item.
	
	err = GAITestItemCreate( name, inAddressCount, inHasAddrs, inWantAddrs, &item );
	require_noerr( err, exit );
	
	newItemList	= item;
	itemPtr		= &item->next;
	
	// Create repeat items.
	
	for( i = 1; i < inItemCount; ++i )
	{
		err = GAITestItemDuplicate( item, &item2 );
		require_noerr( err, exit );
		
		*itemPtr	= item2;
		itemPtr		= &item2->next;
	}
	
	// Append to test case's item list.
	
	for( itemPtr = &inCase->itemList; *itemPtr; itemPtr = &( *itemPtr )->next ) {}
	*itemPtr	= newItemList;
	newItemList	= NULL;
	
exit:
	while( ( item = newItemList ) != NULL )
	{
		newItemList = item->next;
		GAITestItemFree( item );
	}
	return( err );
}

//===========================================================================================================================
//	GAITestCaseAddLocalHostItem
//===========================================================================================================================

static OSStatus	GAITestCaseAddLocalHostItem( GAITestCase *inCase, GAITestAddrType inWantAddrs, unsigned int inItemCount )
{
	OSStatus			err;
	GAITestItem *		item;
	GAITestItem *		item2;
	GAITestItem *		newItemList = NULL;
	GAITestItem **		itemPtr;
	unsigned int		i;
	
	require_action_quiet( inItemCount > 1, exit, err = kNoErr );
	
	err = GAITestItemCreate( "localhost.", 1, kGAITestAddrType_Both, inWantAddrs, &item );
	require_noerr( err, exit );
	
	newItemList	= item;
	itemPtr		= &item->next;
	
	// Create repeat items.
	
	for( i = 1; i < inItemCount; ++i )
	{
		err = GAITestItemDuplicate( item, &item2 );
		require_noerr( err, exit );
		
		*itemPtr	= item2;
		itemPtr		= &item2->next;
	}
	
	for( itemPtr = &inCase->itemList; *itemPtr; itemPtr = &( *itemPtr )->next ) {}
	*itemPtr	= newItemList;
	newItemList	= NULL;
	
exit:
	while( ( item = newItemList ) != NULL )
	{
		newItemList = item->next;
		GAITestItemFree( item );
	}
	return( err );
}

//===========================================================================================================================
//	GAITestItemCreate
//===========================================================================================================================

static OSStatus
	GAITestItemCreate(
		const char *	inName,
		unsigned int	inAddressCount,
		GAITestAddrType	inHasAddrs,
		GAITestAddrType	inWantAddrs,
		GAITestItem **	outItem )
{
	OSStatus			err;
	GAITestItem *		obj = NULL;
	
	require_action_quiet( inAddressCount >= 1, exit, err = kCountErr );
	require_action_quiet( GAITestAddrTypeIsValid( inHasAddrs ), exit, err = kValueErr );
	require_action_quiet( GAITestAddrTypeIsValid( inWantAddrs ), exit, err = kValueErr );
	
	obj = (GAITestItem *) calloc( 1, sizeof( *obj ) );
	require_action( obj, exit, err = kNoMemoryErr );
	
	obj->name = strdup( inName );
	require_action( obj->name, exit, err = kNoMemoryErr );
	
	obj->addressCount	= inAddressCount;
	obj->hasV4			= ( inHasAddrs  & kGAITestAddrType_IPv4 ) ? true : false;
	obj->hasV6			= ( inHasAddrs  & kGAITestAddrType_IPv6 ) ? true : false;
	obj->wantV4			= ( inWantAddrs & kGAITestAddrType_IPv4 ) ? true : false;
	obj->wantV6			= ( inWantAddrs & kGAITestAddrType_IPv6 ) ? true : false;
	
	*outItem = obj;
	obj = NULL;
	err = kNoErr;
	
exit:
	if( obj ) GAITestItemFree( obj );
	return( err );
}

//===========================================================================================================================
//	GAITestItemDuplicate
//===========================================================================================================================

static OSStatus	GAITestItemDuplicate( const GAITestItem *inItem, GAITestItem **outItem )
{
	OSStatus			err;
	GAITestItem *		obj;
	
	obj = (GAITestItem *) calloc( 1, sizeof( *obj ) );
	require_action( obj, exit, err = kNoMemoryErr );
	
	*obj = *inItem;
	obj->next = NULL;
	if( inItem->name )
	{
		obj->name = strdup( inItem->name );
		require_action( obj->name, exit, err = kNoMemoryErr );
	}
	
	*outItem = obj;
	obj = NULL;
	err = kNoErr;
	
exit:
	if( obj ) GAITestItemFree( obj );
	return( err );
}

//===========================================================================================================================
//	GAITestItemFree
//===========================================================================================================================

static void	GAITestItemFree( GAITestItem *inItem )
{
	ForgetMem( &inItem->name );
	free( inItem );
}

//===========================================================================================================================
//	SSDPDiscoverCmd
//===========================================================================================================================

#define kSSDPPort		1900

typedef struct
{
	HTTPHeader				header;			// HTTP header object for sending and receiving.
	dispatch_source_t		readSourceV4;	// Read dispatch source for IPv4 socket.
	dispatch_source_t		readSourceV6;	// Read dispatch source for IPv6 socket.
	int						receiveSecs;	// After send, the amount of time to spend receiving.
	uint32_t				ifindex;		// Index of the interface over which to send the query.
	Boolean					useIPv4;		// True if the query should be sent via IPv4 multicast.
	Boolean					useIPv6;		// True if the query should be sent via IPv6 multicast.
	
}	SSDPDiscoverContext;

static void		SSDPDiscoverPrintPrologue( const SSDPDiscoverContext *inContext );
static void		SSDPDiscoverReadHandler( void *inContext );
static int		SocketToPortNumber( SocketRef inSock );
static OSStatus	WriteSSDPSearchRequest( HTTPHeader *inHeader, const void *inHostSA, int inMX, const char *inST );

static void	SSDPDiscoverCmd( void )
{
	OSStatus					err;
	struct timeval				now;
	SSDPDiscoverContext *		context;
	dispatch_source_t			signalSource	= NULL;
	SocketRef					sockV4			= kInvalidSocketRef;
	SocketRef					sockV6			= kInvalidSocketRef;
	ssize_t						n;
	int							sendCount;
	
	// Set up SIGINT handler.
	
	signal( SIGINT, SIG_IGN );
	err = DispatchSignalSourceCreate( SIGINT, Exit, kExitReason_SIGINT, &signalSource );
	require_noerr( err, exit );
	dispatch_resume( signalSource );
	
	// Check command parameters.
	
	if( gSSDPDiscover_ReceiveSecs < -1 )
	{
		FPrintF( stdout, "Invalid receive time: %d seconds.\n", gSSDPDiscover_ReceiveSecs );
		err = kParamErr;
		goto exit;
	}
	
	// Create context.
	
	context = (SSDPDiscoverContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->receiveSecs	= gSSDPDiscover_ReceiveSecs;
	context->useIPv4		= ( gSSDPDiscover_UseIPv4 || !gSSDPDiscover_UseIPv6 ) ? true : false;
	context->useIPv6		= ( gSSDPDiscover_UseIPv6 || !gSSDPDiscover_UseIPv4 ) ? true : false;
	
	err = InterfaceIndexFromArgString( gInterface, &context->ifindex );
	require_noerr_quiet( err, exit );
	
	// Set up IPv4 socket.
	
	if( context->useIPv4 )
	{
		int port;
		err = UDPClientSocketOpen( AF_INET, NULL, 0, -1, &port, &sockV4 );
		require_noerr( err, exit );
		
		err = SocketSetMulticastInterface( sockV4, NULL, context->ifindex );
		require_noerr( err, exit );
		
		err = setsockopt( sockV4, IPPROTO_IP, IP_MULTICAST_LOOP, (char *) &(uint8_t){ 1 }, (socklen_t) sizeof( uint8_t ) );
		err = map_socket_noerr_errno( sockV4, err );
		require_noerr( err, exit );
	}
	
	// Set up IPv6 socket.
	
	if( context->useIPv6 )
	{
		err = UDPClientSocketOpen( AF_INET6, NULL, 0, -1, NULL, &sockV6 );
		require_noerr( err, exit );
		
		err = SocketSetMulticastInterface( sockV6, NULL, context->ifindex );
		require_noerr( err, exit );
		
		err = setsockopt( sockV6, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, (char *) &(int){ 1 }, (socklen_t) sizeof( int ) );
		err = map_socket_noerr_errno( sockV6, err );
		require_noerr( err, exit );
	}
	
	// Print prologue.
	
	SSDPDiscoverPrintPrologue( context );
	
	// Send mDNS query message.
	
	sendCount = 0;
	if( IsValidSocket( sockV4 ) )
	{
		struct sockaddr_in		mcastAddr4;
		
		memset( &mcastAddr4, 0, sizeof( mcastAddr4 ) );
		SIN_LEN_SET( &mcastAddr4 );
		mcastAddr4.sin_family		= AF_INET;
		mcastAddr4.sin_port			= htons( kSSDPPort );
		mcastAddr4.sin_addr.s_addr	= htonl( 0xEFFFFFFA );	// 239.255.255.250
		
		err = WriteSSDPSearchRequest( &context->header, &mcastAddr4, gSSDPDiscover_MX, gSSDPDiscover_ST );
		require_noerr( err, exit );
		
		n = sendto( sockV4, context->header.buf, context->header.len, 0, (const struct sockaddr *) &mcastAddr4,
			(socklen_t) sizeof( mcastAddr4 ) );
		err = map_socket_value_errno( sockV4, n == (ssize_t) context->header.len, n );
		if( err )
		{
			FPrintF( stderr, "*** Failed to send query on IPv4 socket with error %#m\n", err );
			ForgetSocket( &sockV4 );
		}
		else
		{
			if( gSSDPDiscover_Verbose )
			{
				gettimeofday( &now, NULL );
				FPrintF( stdout, "---\n" );
				FPrintF( stdout, "Send time:    %{du:time}\n",	&now );
				FPrintF( stdout, "Source Port:  %d\n",			SocketToPortNumber( sockV4 ) );
				FPrintF( stdout, "Destination:  %##a\n",		&mcastAddr4 );
				FPrintF( stdout, "Message size: %zu\n",			context->header.len );
				FPrintF( stdout, "HTTP header:\n%1{text}",		context->header.buf, context->header.len );
			}
			++sendCount;
		}
	}
	
	if( IsValidSocket( sockV6 ) )
	{
		struct sockaddr_in6		mcastAddr6;
		
		memset( &mcastAddr6, 0, sizeof( mcastAddr6 ) );
		SIN6_LEN_SET( &mcastAddr6 );
		mcastAddr6.sin6_family				= AF_INET6;
		mcastAddr6.sin6_port				= htons( kSSDPPort );
		mcastAddr6.sin6_addr.s6_addr[  0 ]	= 0xFF;	// SSDP IPv6 link-local multicast address FF02::C
		mcastAddr6.sin6_addr.s6_addr[  1 ]	= 0x02;
		mcastAddr6.sin6_addr.s6_addr[ 15 ]	= 0x0C;
		
		err = WriteSSDPSearchRequest( &context->header, &mcastAddr6, gSSDPDiscover_MX, gSSDPDiscover_ST );
		require_noerr( err, exit );
		
		n = sendto( sockV6, context->header.buf, context->header.len, 0, (const struct sockaddr *) &mcastAddr6,
			(socklen_t) sizeof( mcastAddr6 ) );
		err = map_socket_value_errno( sockV6, n == (ssize_t) context->header.len, n );
		if( err )
		{
			FPrintF( stderr, "*** Failed to send query on IPv6 socket with error %#m\n", err );
			ForgetSocket( &sockV6 );
		}
		else
		{
			if( gSSDPDiscover_Verbose )
			{
				gettimeofday( &now, NULL );
				FPrintF( stdout, "---\n" );
				FPrintF( stdout, "Send time:    %{du:time}\n",	&now );
				FPrintF( stdout, "Source Port:  %d\n",			SocketToPortNumber( sockV6 ) );
				FPrintF( stdout, "Destination:  %##a\n",		&mcastAddr6 );
				FPrintF( stdout, "Message size: %zu\n",			context->header.len );
				FPrintF( stdout, "HTTP header:\n%1{text}",		context->header.buf, context->header.len );
			}
			++sendCount;
		}
	}
	require_action_quiet( sendCount > 0, exit, err = kUnexpectedErr );
	
	// If there's no wait period after the send, then exit.
	
	if( context->receiveSecs == 0 ) goto exit;
	
	// Create dispatch read sources for socket(s).
	
	if( IsValidSocket( sockV4 ) )
	{
		SocketContext *		sockCtx;
		
		err = SocketContextCreate( sockV4, context, &sockCtx );
		require_noerr( err, exit );
		sockV4 = kInvalidSocketRef;
		
		err = DispatchReadSourceCreate( sockCtx->sock, NULL, SSDPDiscoverReadHandler, SocketContextCancelHandler, sockCtx,
			&context->readSourceV4 );
		if( err ) ForgetSocketContext( &sockCtx );
		require_noerr( err, exit );
		
		dispatch_resume( context->readSourceV4 );
	}
	
	if( IsValidSocket( sockV6 ) )
	{
		SocketContext *		sockCtx;
		
		err = SocketContextCreate( sockV6, context, &sockCtx );
		require_noerr( err, exit );
		sockV6 = kInvalidSocketRef;
		
		err = DispatchReadSourceCreate( sockCtx->sock, NULL, SSDPDiscoverReadHandler, SocketContextCancelHandler, sockCtx,
			&context->readSourceV6 );
		if( err ) ForgetSocketContext( &sockCtx );
		require_noerr( err, exit );
		
		dispatch_resume( context->readSourceV6 );
	}
	
	if( context->receiveSecs > 0 )
	{
		dispatch_after_f( dispatch_time_seconds( context->receiveSecs ), dispatch_get_main_queue(), kExitReason_Timeout,
			Exit );
	}
	dispatch_main();
	
exit:
	ForgetSocket( &sockV4 );
	ForgetSocket( &sockV6 );
	dispatch_source_forget( &signalSource );
	if( err ) exit( 1 );
}

static int	SocketToPortNumber( SocketRef inSock )
{
	OSStatus		err;
	sockaddr_ip		sip;
	socklen_t		len;
	
	len = (socklen_t) sizeof( sip );
	err = getsockname( inSock, &sip.sa, &len );
	err = map_socket_noerr_errno( inSock, err );
	check_noerr( err );
	return( err ? -1 : SockAddrGetPort( &sip ) );
}

static OSStatus	WriteSSDPSearchRequest( HTTPHeader *inHeader, const void *inHostSA, int inMX, const char *inST )
{
	OSStatus		err;
	
	err = HTTPHeader_InitRequest( inHeader, "M-SEARCH", "*", "HTTP/1.1" );
	require_noerr( err, exit );
	
	err = HTTPHeader_SetField( inHeader, "Host", "%##a", inHostSA );
	require_noerr( err, exit );
	
	err = HTTPHeader_SetField( inHeader, "ST", "%s", inST ? inST : "ssdp:all" );
	require_noerr( err, exit );
	
	err = HTTPHeader_SetField( inHeader, "Man", "\"ssdp:discover\"" );
	require_noerr( err, exit );
	
	err = HTTPHeader_SetField( inHeader, "MX", "%d", inMX );
	require_noerr( err, exit );
	
	err = HTTPHeader_Commit( inHeader );
	require_noerr( err, exit );
	
exit:
	return( err );
}

//===========================================================================================================================
//	SSDPDiscoverPrintPrologue
//===========================================================================================================================

static void	SSDPDiscoverPrintPrologue( const SSDPDiscoverContext *inContext )
{
	const int				receiveSecs = inContext->receiveSecs;
	const char *			ifName;
	char					ifNameBuf[ IF_NAMESIZE + 1 ];
	NetTransportType		ifType;
	
	ifName = if_indextoname( inContext->ifindex, ifNameBuf );
	
	ifType = kNetTransportType_Undefined;
	if( ifName ) SocketGetInterfaceInfo( kInvalidSocketRef, ifName, NULL, NULL, NULL, NULL, NULL, NULL, NULL, &ifType );
	
	FPrintF( stdout, "Interface:        %s/%d/%s\n",
		ifName ? ifName : "?", inContext->ifindex, NetTransportTypeToString( ifType ) );
	FPrintF( stdout, "IP protocols:     %?s%?s%?s\n",
		inContext->useIPv4, "IPv4", ( inContext->useIPv4 && inContext->useIPv6 ), ", ", inContext->useIPv6, "IPv6" );
	FPrintF( stdout, "Receive duration: " );
	if( receiveSecs >= 0 )	FPrintF( stdout, "%d second%?c\n", receiveSecs, receiveSecs != 1, 's' );
	else					FPrintF( stdout, "∞\n" );
	FPrintF( stdout, "Start time:       %{du:time}\n", NULL );
}

//===========================================================================================================================
//	SSDPDiscoverReadHandler
//===========================================================================================================================

static void	SSDPDiscoverReadHandler( void *inContext )
{
	OSStatus						err;
	struct timeval					now;
	SocketContext * const			sockCtx	= (SocketContext *) inContext;
	SSDPDiscoverContext * const		context	= (SSDPDiscoverContext *) sockCtx->userContext;
	HTTPHeader * const				header	= &context->header;
	sockaddr_ip						fromAddr;
	size_t							msgLen;
	
	gettimeofday( &now, NULL );
	
	err = SocketRecvFrom( sockCtx->sock, header->buf, sizeof( header->buf ), &msgLen, &fromAddr, sizeof( fromAddr ),
		NULL, NULL, NULL, NULL );
	require_noerr( err, exit );
	
	FPrintF( stdout, "---\n" );
	FPrintF( stdout, "Receive time: %{du:time}\n",	&now );
	FPrintF( stdout, "Source:       %##a\n", 		&fromAddr );
	FPrintF( stdout, "Message size: %zu\n",			msgLen );
	header->len = msgLen;
	if( HTTPHeader_Validate( header ) )
	{
		FPrintF( stdout, "HTTP header:\n%1{text}", header->buf, header->len );
		if( header->extraDataLen > 0 )
		{
			FPrintF( stdout, "HTTP body: %1.1H", header->extraDataPtr, (int) header->extraDataLen, INT_MAX );
		}
	}
	else
	{
		FPrintF( stdout, "Invalid HTTP message:\n%1.1H", header->buf, (int) msgLen, INT_MAX );
		goto exit;
	}
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	HTTPHeader_Validate
//
//	Parses for the end of an HTTP header and updates the HTTPHeader structure so it's ready to parse. Returns true if valid.
//	This assumes the "buf" and "len" fields are set. The other fields are set by this function.
//
//	Note: This was copied from CoreUtils because the HTTPHeader_Validate function is currently not exported in the framework.
//===========================================================================================================================

Boolean	HTTPHeader_Validate( HTTPHeader *inHeader )
{
	const char *		src;
	const char *		end;
	
	// Check for interleaved binary data (4 byte header that begins with $). See RFC 2326 section 10.12.
	
	require( inHeader->len < sizeof( inHeader->buf ), exit );
	src = inHeader->buf;
	end = src + inHeader->len;
	if( ( ( end - src ) >= 4 ) && ( src[ 0 ] == '$' ) )
	{
		src += 4;
	}
	else
	{
		// Search for an empty line (HTTP-style header/body separator). CRLFCRLF, LFCRLF, or LFLF accepted.
		// $$$ TO DO: Start from the last search location to avoid re-searching the same data over and over.
		
		for( ;; )
		{
			while( ( src < end ) && ( src[ 0 ] != '\n' ) ) ++src;
			if( src >= end ) goto exit;
			++src;
			if( ( ( end - src ) >= 2 ) && ( src[ 0 ] == '\r' ) && ( src[ 1 ] == '\n' ) ) // CFLFCRLF or LFCRLF
			{
				src += 2;
				break;
			}
			else if( ( ( end - src ) >= 1 ) && ( src[ 0 ] == '\n' ) ) // LFLF
			{
				src += 1;
				break;
			}
		}
	}
	inHeader->extraDataPtr	= src;
	inHeader->extraDataLen	= (size_t)( end - src );
	inHeader->len			= (size_t)( src - inHeader->buf );
	return( true );
	
exit:
	return( false );
}

#if( TARGET_OS_DARWIN )
//===========================================================================================================================
//	ResQueryCmd
//===========================================================================================================================

// res_query() from libresolv is actually called res_9_query (see /usr/include/resolv.h).

SOFT_LINK_LIBRARY_EX( "/usr/lib", resolv );
SOFT_LINK_FUNCTION_EX( resolv, res_9_query,
	int,
	( const char *dname, int class, int type, u_char *answer, int anslen ),
	( dname, class, type, answer, anslen ) );

// res_query() from libinfo

SOFT_LINK_LIBRARY_EX( "/usr/lib", info );
SOFT_LINK_FUNCTION_EX( info, res_query,
	int,
	( const char *dname, int class, int type, u_char *answer, int anslen ),
	( dname, class, type, answer, anslen ) );

typedef int ( *res_query_f )( const char *dname, int class, int type, u_char *answer, int anslen );

static void	ResQueryCmd( void )
{
	OSStatus		err;
	res_query_f		res_query_ptr;
	int				n;
	uint16_t		type, class;
	uint8_t			answer[ 1024 ];
	
	// Get pointer to one of the res_query() functions.
	
	if( gResQuery_UseLibInfo )
	{
		if( !SOFT_LINK_HAS_FUNCTION( info, res_query ) )
		{
			FPrintF( stderr, "Failed to soft link res_query from libinfo.\n" );
			err = kNotFoundErr;
			goto exit;
		}
		res_query_ptr = soft_res_query;
	}
	else
	{
		if( !SOFT_LINK_HAS_FUNCTION( resolv, res_9_query ) )
		{
			FPrintF( stderr, "Failed to soft link res_query from libresolv.\n" );
			err = kNotFoundErr;
			goto exit;
		}
		res_query_ptr = soft_res_9_query;
	}
	
	// Get record type.
	
	err = RecordTypeFromArgString( gResQuery_Type, &type );
	require_noerr( err, exit );
	
	// Get record class.
	
	if( gResQuery_Class )
	{
		err = RecordClassFromArgString( gResQuery_Class, &class );
		require_noerr( err, exit );
	}
	else
	{
		class = kDNSServiceClass_IN;
	}
	
	// Print prologue.
	
	FPrintF( stdout, "Name:       %s\n",			gResQuery_Name );
	FPrintF( stdout, "Type:       %s (%u)\n",		RecordTypeToString( type ), type );
	FPrintF( stdout, "Class:      %s (%u)\n",		( class == kDNSServiceClass_IN ) ? "IN" : "???", class );
	FPrintF( stdout, "Start time: %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
	
	// Call res_query().
	
	n = res_query_ptr( gResQuery_Name, class, type, (u_char *) answer, (int) sizeof( answer ) );
	if( n < 0 )
	{
		FPrintF( stderr, "res_query() failed with error: %d (%s).\n", h_errno, hstrerror( h_errno ) );
		err = kUnknownErr;
		goto exit;
	}
	
	// Print result.
	
	FPrintF( stdout, "Message size: %d\n\n%{du:dnsmsg}", n, answer, (size_t) n );
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	ResolvDNSQueryCmd
//===========================================================================================================================

// dns_handle_t is defined as a pointer to a privately-defined struct in /usr/include/dns.h. It's defined as a void * here to
// avoid including the header file.

typedef void *		dns_handle_t;

SOFT_LINK_FUNCTION_EX( resolv, dns_open, dns_handle_t, ( const char *path ), ( path ) );
SOFT_LINK_FUNCTION_VOID_RETURN_EX( resolv, dns_free, ( dns_handle_t *dns ), ( dns ) );
SOFT_LINK_FUNCTION_EX( resolv, dns_query,
	int32_t, (
		dns_handle_t		dns,
		const char *		name,
		uint32_t			dnsclass,
		uint32_t			dnstype,
		char *				buf,
		uint32_t			len,
		struct sockaddr *	from,
		uint32_t *			fromlen ),
	( dns, name, dnsclass, dnstype, buf, len, from, fromlen ) );

static void	ResolvDNSQueryCmd( void )
{
	OSStatus			err;
	int					n;
	dns_handle_t		dns = NULL;
	uint16_t			type, class;
	sockaddr_ip			from;
	uint32_t			fromLen;
	uint8_t				answer[ 1024 ];
	
	// Make sure that the required symbols are available.
	
	if( !SOFT_LINK_HAS_FUNCTION( resolv, dns_open ) )
	{
		FPrintF( stderr, "Failed to soft link dns_open from libresolv.\n" );
		err = kNotFoundErr;
		goto exit;
	}
	
	if( !SOFT_LINK_HAS_FUNCTION( resolv, dns_free ) )
	{
		FPrintF( stderr, "Failed to soft link dns_free from libresolv.\n" );
		err = kNotFoundErr;
		goto exit;
	}
	
	if( !SOFT_LINK_HAS_FUNCTION( resolv, dns_query ) )
	{
		FPrintF( stderr, "Failed to soft link dns_query from libresolv.\n" );
		err = kNotFoundErr;
		goto exit;
	}
	
	// Get record type.
	
	err = RecordTypeFromArgString( gResolvDNSQuery_Type, &type );
	require_noerr( err, exit );
	
	// Get record class.
	
	if( gResolvDNSQuery_Class )
	{
		err = RecordClassFromArgString( gResolvDNSQuery_Class, &class );
		require_noerr( err, exit );
	}
	else
	{
		class = kDNSServiceClass_IN;
	}
	
	// Get dns handle.
	
	dns = soft_dns_open( gResolvDNSQuery_Path );
	if( !dns )
	{
		FPrintF( stderr, "dns_open( %s ) failed.\n", gResolvDNSQuery_Path );
		err = kUnknownErr;
		goto exit;
	}
	
	// Print prologue.
	
	FPrintF( stdout, "Name:       %s\n",			gResolvDNSQuery_Name );
	FPrintF( stdout, "Type:       %s (%u)\n",		RecordTypeToString( type ), type );
	FPrintF( stdout, "Class:      %s (%u)\n",		( class == kDNSServiceClass_IN ) ? "IN" : "???", class );
	FPrintF( stdout, "Path:       %s\n",			gResolvDNSQuery_Path ? gResolvDNSQuery_Name : "<NULL>" );
	FPrintF( stdout, "Start time: %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
	
	// Call dns_query().
	
	memset( &from, 0, sizeof( from ) );
	fromLen = (uint32_t) sizeof( from );
	n = soft_dns_query( dns, gResolvDNSQuery_Name, class, type, (char *) answer, (uint32_t) sizeof( answer ), &from.sa,
		&fromLen );
	if( n < 0 )
	{
		FPrintF( stderr, "dns_query() failed with error: %d (%s).\n", h_errno, hstrerror( h_errno ) );
		err = kUnknownErr;
		goto exit;
	}
	
	// Print result.
	
	FPrintF( stdout, "From:         %##a\n", &from );
	FPrintF( stdout, "Message size: %d\n\n%{du:dnsmsg}", n, answer, (size_t) n );
	
exit:
	if( dns ) soft_dns_free( dns );
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	CFHostCmd
//===========================================================================================================================

static void
	_CFHostResolveCallback(
		CFHostRef				inHost,
		CFHostInfoType			inInfoType,
		const CFStreamError *	inError,
		void *					inInfo );

static void	CFHostCmd( void )
{
	OSStatus				err;
	CFStringRef				name;
	Boolean					success;
	CFHostRef				host = NULL;
	CFHostClientContext		context;
	CFStreamError			streamErr;
	
	name = CFStringCreateWithCString( kCFAllocatorDefault, gCFHost_Name, kCFStringEncodingUTF8 );
	require_action( name, exit, err = kUnknownErr );
	
	host = CFHostCreateWithName( kCFAllocatorDefault, name );
	ForgetCF( &name );
	require_action( host, exit, err = kUnknownErr );
	
	memset( &context, 0, sizeof( context ) );
	success = CFHostSetClient( host, _CFHostResolveCallback, &context );
	require_action( success, exit, err = kUnknownErr );
	
	CFHostScheduleWithRunLoop( host, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode );
	
	// Print prologue.
	
	FPrintF( stdout, "Hostname:   %s\n",			gCFHost_Name );
	FPrintF( stdout, "Start time: %{du:time}\n",	NULL );
	FPrintF( stdout, "---\n" );
	
	success = CFHostStartInfoResolution( host, kCFHostAddresses, &streamErr );
	require_action( success, exit, err = kUnknownErr );
	err = kNoErr;
	
	CFRunLoopRun();
	
exit:
	CFReleaseNullSafe( host );
	if( err ) exit( 1 );
}

static void	_CFHostResolveCallback( CFHostRef inHost, CFHostInfoType inInfoType, const CFStreamError *inError, void *inInfo )
{
	OSStatus			err;
	struct timeval		now;
	
	gettimeofday( &now, NULL );
	
	Unused( inInfoType );
	Unused( inInfo );
	
	if( inError && ( inError->domain != 0 ) && ( inError->error ) )
	{
		err = inError->error;
		if( inError->domain == kCFStreamErrorDomainNetDB )
		{
			FPrintF( stderr, "Error %d: %s.\n", err, gai_strerror( err ) );
		}
		else
		{
			FPrintF( stderr, "Error %#m\n", err );
		}
	}
	else
	{
		CFArrayRef					addresses;
		CFIndex						count, i;
		CFDataRef					addrData;
		const struct sockaddr *		sockAddr;
		Boolean						wasResolved = false;
		
		addresses = CFHostGetAddressing( inHost, &wasResolved );
		check( wasResolved );
		
		if( addresses )
		{
			count = CFArrayGetCount( addresses );
			for( i = 0; i < count; ++i )
			{
				addrData = CFArrayGetCFDataAtIndex( addresses, i, &err );
				require_noerr( err, exit );
				
				sockAddr = (const struct sockaddr *) CFDataGetBytePtr( addrData );
				FPrintF( stdout, "%##a\n", sockAddr );
			}
		}
		err = kNoErr;
	}
	
	FPrintF( stdout, "---\n" );
	FPrintF( stdout, "End time:   %{du:time}\n", &now );
	
	if( gCFHost_WaitSecs > 0 ) sleep( (unsigned int) gCFHost_WaitSecs );
	
exit:
	exit( err ? 1 : 0 );
}

//===========================================================================================================================
//	DNSConfigAddCmd
//
//	Note: Based on ajn's supplemental test tool.
//===========================================================================================================================

static void	DNSConfigAddCmd( void )
{
	OSStatus					err;
	CFMutableDictionaryRef		dict	= NULL;
	CFMutableArrayRef			array	= NULL;
	size_t						i;
	SCDynamicStoreRef			store	= NULL;
	CFStringRef					key		= NULL;
	Boolean						success;
	
	if( geteuid() != 0 )
	{
		FPrintF( stderr, "error: This command must to be run as root.\n" );
		err = kIDErr;
		goto exit;
	}
	
	// Create dictionary.
	
	dict = CFDictionaryCreateMutable( NULL, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks );
	require_action( dict, exit, err = kNoMemoryErr );
	
	// Add DNS server IP addresses.
	
	array = CFArrayCreateMutable( NULL, (CFIndex) gDNSConfigAdd_IPAddrCount, &kCFTypeArrayCallBacks );
	require_action( array, exit, err = kNoMemoryErr );
	
	for( i = 0; i < gDNSConfigAdd_IPAddrCount; ++i )
	{
		CFStringRef		addrStr;
		
		addrStr = CFStringCreateWithCString( NULL, gDNSConfigAdd_IPAddrArray[ i ], kCFStringEncodingUTF8 );
		require_action( addrStr, exit, err = kUnknownErr );
		
		CFArrayAppendValue( array, addrStr );
		CFRelease( addrStr );
	}
	
	CFDictionarySetValue( dict, kSCPropNetDNSServerAddresses, array );
	ForgetCF( &array );
	
	// Add domains, if any.
	
	array = CFArrayCreateMutable( NULL, (CFIndex) Min( gDNSConfigAdd_DomainCount, 1 ), &kCFTypeArrayCallBacks );
	require_action( array, exit, err = kNoMemoryErr );
	
	if( gDNSConfigAdd_DomainCount > 0 )
	{
		for( i = 0; i < gDNSConfigAdd_DomainCount; ++i )
		{
			CFStringRef		domainStr;
			
			domainStr = CFStringCreateWithCString( NULL, gDNSConfigAdd_DomainArray[ i ], kCFStringEncodingUTF8 );
			require_action( domainStr, exit, err = kUnknownErr );
			
			CFArrayAppendValue( array, domainStr );
			CFRelease( domainStr );
		}
	}
	else
	{
		// There are no domains, but the domain array needs to be non-empty, so add a zero-length string to the array.
		
		CFArrayAppendValue( array, CFSTR( "" ) );
	}
	
	CFDictionarySetValue( dict, kSCPropNetDNSSupplementalMatchDomains, array );
	ForgetCF( &array );
	
	// Add interface, if any.
	
	if( gDNSConfigAdd_Interface )
	{
		err = CFDictionarySetCString( dict, kSCPropInterfaceName, gDNSConfigAdd_Interface, kSizeCString );
		require_noerr( err, exit );
		
		CFDictionarySetValue( dict, kSCPropNetDNSConfirmedServiceID, gDNSConfigAdd_ID );
	}
	
	// Set dictionary in dynamic store.
	
	store = SCDynamicStoreCreate( NULL, CFSTR( "com.apple.dnssdutil" ), NULL, NULL );
	err = map_scerror( store );
	require_noerr( err, exit );
	
	key = SCDynamicStoreKeyCreateNetworkServiceEntity( NULL, kSCDynamicStoreDomainState, gDNSConfigAdd_ID, kSCEntNetDNS );
	require_action( key, exit, err = kUnknownErr );
	
	success = SCDynamicStoreSetValue( store, key, dict );
	require_action( success, exit, err = kUnknownErr );
	
exit:
	CFReleaseNullSafe( dict );
	CFReleaseNullSafe( array );
	CFReleaseNullSafe( store );
	CFReleaseNullSafe( key );
	gExitCode = err ? 1 : 0;
}

//===========================================================================================================================
//	DNSConfigRemoveCmd
//===========================================================================================================================

static void	DNSConfigRemoveCmd( void )
{
	OSStatus				err;
	SCDynamicStoreRef		store	= NULL;
	CFStringRef				key		= NULL;
	Boolean					success;
	
	if( geteuid() != 0 )
	{
		FPrintF( stderr, "error: This command must to be run as root.\n" );
		err = kIDErr;
		goto exit;
	}
	
	store = SCDynamicStoreCreate( NULL, CFSTR( "com.apple.dnssdutil" ), NULL, NULL );
	err = map_scerror( store );
	require_noerr( err, exit );
	
	key = SCDynamicStoreKeyCreateNetworkServiceEntity( NULL, kSCDynamicStoreDomainState, gDNSConfigRemove_ID, kSCEntNetDNS );
	require_action( key, exit, err = kUnknownErr );
	
	success = SCDynamicStoreRemoveValue( store, key );
	require_action( success, exit, err = kUnknownErr );
	
exit:
	CFReleaseNullSafe( store );
	CFReleaseNullSafe( key );
	gExitCode = err ? 1 : 0;
}
#endif	// TARGET_OS_DARWIN

//===========================================================================================================================
//	DaemonVersionCmd
//===========================================================================================================================

static void	DaemonVersionCmd( void )
{
	OSStatus		err;
	uint32_t		size, version;
	char			strBuf[ 16 ];
	
	size = (uint32_t) sizeof( version );
	err = DNSServiceGetProperty( kDNSServiceProperty_DaemonVersion, &version, &size );
	require_noerr( err, exit );
	
	FPrintF( stdout, "Daemon version: %s\n", SourceVersionToCString( version, strBuf ) );
	
exit:
	if( err ) exit( 1 );
}

//===========================================================================================================================
//	Exit
//===========================================================================================================================

static void	Exit( void *inContext )
{
	const char * const		reason = (const char *) inContext;
	
	FPrintF( stdout, "---\n" );
	FPrintF( stdout, "End time:   %{du:time}\n", NULL );
	if( reason ) FPrintF( stdout, "End reason: %s\n", reason );
	exit( gExitCode );
}

//===========================================================================================================================
//	PrintFTimestampHandler
//===========================================================================================================================

static int
	PrintFTimestampHandler(
		PrintFContext *	inContext,
		PrintFFormat *	inFormat,
		PrintFVAList *	inArgs,
		void *			inUserContext )
{
	struct timeval				now;
	const struct timeval *		tv;
	struct tm *					localTime;
	size_t						len;
	int							n;
	char						dateTimeStr[ 32 ];
	
	Unused( inUserContext );
	
	tv = va_arg( inArgs->args, const struct timeval * );
	require_action_quiet( !inFormat->suppress, exit, n = 0 );
	
	if( !tv )
	{
		gettimeofday( &now, NULL );
		tv = &now;
	}
	localTime = localtime( &tv->tv_sec );
	len = strftime( dateTimeStr, sizeof( dateTimeStr ), "%Y-%m-%d %H:%M:%S", localTime );
	if( len == 0 ) dateTimeStr[ 0 ] = '\0';
	
	n = PrintFCore( inContext, "%s.%06u", dateTimeStr, (unsigned int) tv->tv_usec );
	
exit:
	return( n );
}

//===========================================================================================================================
//	PrintFDNSMessageHandler
//===========================================================================================================================

static int
	PrintFDNSMessageHandler(
		PrintFContext *	inContext,
		PrintFFormat *	inFormat,
		PrintFVAList *	inArgs,
		void *			inUserContext )
{
	OSStatus			err;
	const void *		msgPtr;
	size_t				msgLen;
	char *				text;
	int					n;
	Boolean				isMDNS;
	Boolean				printRawRData;
	
	Unused( inUserContext );
	
	msgPtr = va_arg( inArgs->args, const void * );
	msgLen = va_arg( inArgs->args, size_t );
	require_action_quiet( !inFormat->suppress, exit, n = 0 );
	
	isMDNS = ( inFormat->altForm > 0 ) ? true : false;
	if(      inFormat->precision == 0 ) printRawRData = false;
	else if( inFormat->precision == 1 ) printRawRData = true;
	else
	{
		n = PrintFCore( inContext, "<< BAD %%{du:dnsmsg} PRECISION >>" );
		goto exit;
	}
	
	err = DNSMessageToText( msgPtr, msgLen, isMDNS, printRawRData, &text );
	if( !err )
	{
		n = PrintFCore( inContext, "%*{text}", inFormat->fieldWidth, text, kSizeCString );
		free( text );
	}
	else
	{
		n = PrintFCore( inContext, "%*.1H", inFormat->fieldWidth, msgPtr, (int) msgLen, (int) msgLen );
	}
	
exit:
	return( n );
}

//===========================================================================================================================
//	GetDNSSDFlagsFromOpts
//===========================================================================================================================

static DNSServiceFlags	GetDNSSDFlagsFromOpts( void )
{
	DNSServiceFlags		flags;
	
	flags = (DNSServiceFlags) gDNSSDFlags;
	if( flags & kDNSServiceFlagsShareConnection )
	{
		FPrintF( stderr, "*** Warning: kDNSServiceFlagsShareConnection (0x%X) is explicitly set in flag parameters.\n",
			kDNSServiceFlagsShareConnection );
	}
	
	if( gDNSSDFlag_BrowseDomains )			flags |= kDNSServiceFlagsBrowseDomains;
	if( gDNSSDFlag_DenyCellular )			flags |= kDNSServiceFlagsDenyCellular;
	if( gDNSSDFlag_DenyExpensive )			flags |= kDNSServiceFlagsDenyExpensive;
	if( gDNSSDFlag_ForceMulticast )			flags |= kDNSServiceFlagsForceMulticast;
	if( gDNSSDFlag_IncludeAWDL )			flags |= kDNSServiceFlagsIncludeAWDL;
	if( gDNSSDFlag_NoAutoRename )			flags |= kDNSServiceFlagsNoAutoRename;
	if( gDNSSDFlag_PathEvaluationDone )		flags |= kDNSServiceFlagsPathEvaluationDone;
	if( gDNSSDFlag_RegistrationDomains )	flags |= kDNSServiceFlagsRegistrationDomains;
	if( gDNSSDFlag_ReturnIntermediates )	flags |= kDNSServiceFlagsReturnIntermediates;
	if( gDNSSDFlag_Shared )					flags |= kDNSServiceFlagsShared;
	if( gDNSSDFlag_SuppressUnusable )		flags |= kDNSServiceFlagsSuppressUnusable;
	if( gDNSSDFlag_Timeout )				flags |= kDNSServiceFlagsTimeout;
	if( gDNSSDFlag_UnicastResponse )		flags |= kDNSServiceFlagsUnicastResponse;
	if( gDNSSDFlag_Unique )					flags |= kDNSServiceFlagsUnique;
	if( gDNSSDFlag_WakeOnResolve )			flags |= kDNSServiceFlagsWakeOnResolve;
	
	return( flags );
}

//===========================================================================================================================
//	CreateConnectionFromArgString
//===========================================================================================================================

static OSStatus
	CreateConnectionFromArgString(
		const char *			inString,
		dispatch_queue_t		inQueue,
		DNSServiceRef *			outSDRef,
		ConnectionDesc *		outDesc )
{
	OSStatus			err;
	DNSServiceRef		sdRef = NULL;
	ConnectionType		type;
	int32_t				pid = -1;	// Initializing because the analyzer claims pid may be used uninitialized.
	uint8_t				uuid[ 16 ];
	
	if( strcasecmp( inString, kConnectionArg_Normal ) == 0 )
	{
		err = DNSServiceCreateConnection( &sdRef );
		require_noerr( err, exit );
		type = kConnectionType_Normal;
	}
	else if( stricmp_prefix( inString, kConnectionArgPrefix_PID ) == 0 )
	{
		const char * const		pidStr = inString + sizeof_string( kConnectionArgPrefix_PID );
		
		err = StringToInt32( pidStr, &pid );
		if( err )
		{
			FPrintF( stderr, "Invalid delegate connection PID value: %s\n", pidStr );
			err = kParamErr;
			goto exit;
		}
		
		memset( uuid, 0, sizeof( uuid ) );
		err = DNSServiceCreateDelegateConnection( &sdRef, pid, uuid );
		if( err )
		{
			FPrintF( stderr, "DNSServiceCreateDelegateConnection() returned %#m for PID %d\n", err, pid );
			goto exit;
		}
		type = kConnectionType_DelegatePID;
	}
	else if( stricmp_prefix( inString, kConnectionArgPrefix_UUID ) == 0 )
	{
		const char * const		uuidStr = inString + sizeof_string( kConnectionArgPrefix_UUID );
		
		check_compile_time_code( sizeof( uuid ) == sizeof( uuid_t ) );
		
		err = StringToUUID( uuidStr, kSizeCString, false, uuid );
		if( err )
		{
			FPrintF( stderr, "Invalid delegate connection UUID value: %s\n", uuidStr );
			err = kParamErr;
			goto exit;
		}
		
		err = DNSServiceCreateDelegateConnection( &sdRef, 0, uuid );
		if( err )
		{
			FPrintF( stderr, "DNSServiceCreateDelegateConnection() returned %#m for UUID %#U\n", err, uuid );
			goto exit;
		}
		type = kConnectionType_DelegateUUID;
	}
	else
	{
		FPrintF( stderr, "Unrecognized connection string \"%s\".\n", inString );
		err = kParamErr;
		goto exit;
	}
	
	err = DNSServiceSetDispatchQueue( sdRef, inQueue );
	require_noerr( err, exit );
	
	*outSDRef = sdRef;
	if( outDesc )
	{
		outDesc->type = type;
		if(      type == kConnectionType_DelegatePID )	outDesc->delegate.pid = pid;
		else if( type == kConnectionType_DelegateUUID )	memcpy( outDesc->delegate.uuid, uuid, 16 );
	}
	sdRef = NULL;
	
exit:
	if( sdRef ) DNSServiceRefDeallocate( sdRef );
	return( err );
}

//===========================================================================================================================
//	InterfaceIndexFromArgString
//===========================================================================================================================

static OSStatus	InterfaceIndexFromArgString( const char *inString, uint32_t *outIndex )
{
	OSStatus		err;
	uint32_t		ifIndex;
	
	if( inString )
	{
		ifIndex = if_nametoindex( inString );
		if( ifIndex == 0 )
		{
			err = StringToUInt32( inString, &ifIndex );
			if( err )
			{
				FPrintF( stderr, "Invalid interface value: %s\n", inString );
				err = kParamErr;
				goto exit;
			}
		}
	}
	else
	{
		ifIndex	= 0;
	}
	
	*outIndex = ifIndex;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	RecordDataFromArgString
//===========================================================================================================================

#define kRDataMaxLen		UINT16_C( 0xFFFF )

static OSStatus	StringToSRVRData( const char *inString, uint8_t **outPtr, size_t *outLen );
static OSStatus	StringToTXTRData( const char *inString, char inDelimiter, uint8_t **outPtr, size_t *outLen );

static OSStatus	RecordDataFromArgString( const char *inString, uint8_t **outDataPtr, size_t *outDataLen )
{
	OSStatus		err;
	uint8_t *		dataPtr = NULL;
	size_t			dataLen;
	
	if( 0 ) {}
	
	// Domain name
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_Domain ) == 0 )
	{
		const char * const		str = inString + sizeof_string( kRDataArgPrefix_Domain );
		
		err = StringToDomainName( str, &dataPtr, &dataLen );
		require_noerr_quiet( err, exit );
	}
	
	// File path
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_File ) == 0 )
	{
		const char * const		path = inString + sizeof_string( kRDataArgPrefix_File );
		
		err = CopyFileDataByPath( path, (char **) &dataPtr, &dataLen );
		require_noerr( err, exit );
		require_action( dataLen <= kRDataMaxLen, exit, err = kSizeErr );
	}
	
	// Hexadecimal string
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_HexString ) == 0 )
	{
		const char * const		str = inString + sizeof_string( kRDataArgPrefix_HexString );
		
		err = HexToDataCopy( str, kSizeCString, kHexToData_DefaultFlags, &dataPtr, &dataLen, NULL );
		require_noerr( err, exit );
		require_action( dataLen <= kRDataMaxLen, exit, err = kSizeErr );
	}
	
	// IPv4 address string
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_IPv4 ) == 0 )
	{
		const char * const		str = inString + sizeof_string( kRDataArgPrefix_IPv4 );
		
		err = StringToARecordData( str, &dataPtr, &dataLen );
		require_noerr_quiet( err, exit );
	}
	
	// IPv6 address string
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_IPv6 ) == 0 )
	{
		const char * const		str = inString + sizeof_string( kRDataArgPrefix_IPv6 );
		
		err = StringToAAAARecordData( str, &dataPtr, &dataLen );
		require_noerr_quiet( err, exit );
	}
	
	// SRV record
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_SRV ) == 0 )
	{
		const char * const		str = inString + sizeof_string( kRDataArgPrefix_SRV );
		
		err = StringToSRVRData( str, &dataPtr, &dataLen );
		require_noerr( err, exit );
	}
	
	// String with escaped hex and octal bytes
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_String ) == 0 )
	{
		const char * const		str = inString + sizeof_string( kRDataArgPrefix_String );
		const char * const		end = str + strlen( str );
		size_t					copiedLen;
		size_t					totalLen;
		Boolean					success;
		
		if( str < end )
		{
			success = ParseQuotedEscapedString( str, end, "", NULL, 0, NULL, &totalLen, NULL );
			require_action( success, exit, err = kParamErr );
			require_action( totalLen <= kRDataMaxLen, exit, err = kSizeErr );
			
			dataLen = totalLen;
			dataPtr = (uint8_t *) malloc( dataLen );
			require_action( dataPtr, exit, err = kNoMemoryErr );
			
			success = ParseQuotedEscapedString( str, end, "", (char *) dataPtr, dataLen, &copiedLen, NULL, NULL );
			require_action( success, exit, err = kParamErr );
			check( copiedLen == dataLen );
		}
		else
		{
			dataPtr = NULL;
			dataLen = 0;
		}
	}
	
	// TXT record
	
	else if( stricmp_prefix( inString, kRDataArgPrefix_TXT ) == 0 )
	{
		const char * const		str = inString + sizeof_string( kRDataArgPrefix_TXT );
		
		err = StringToTXTRData( str, ',', &dataPtr, &dataLen );
		require_noerr( err, exit );
	}
	
	// Unrecognized format
	
	else
	{
		FPrintF( stderr, "Unrecognized record data string \"%s\".\n", inString );
		err = kParamErr;
		goto exit;
	}
	
	err = kNoErr;
	*outDataLen = dataLen;
	*outDataPtr = dataPtr;
	dataPtr = NULL;
	
exit:
	FreeNullSafe( dataPtr );
	return( err );
}

static OSStatus	StringToSRVRData( const char *inString, uint8_t **outPtr, size_t *outLen )
{
	OSStatus			err;
	DataBuffer			dataBuf;
	const char *		ptr;
	int					i;
	uint8_t *			end;
	uint8_t				target[ kDomainNameLengthMax ];
	
	DataBuffer_Init( &dataBuf, NULL, 0, ( 3 * 2 ) + kDomainNameLengthMax );
	
	// Parse and set the priority, weight, and port values (all three are unsigned 16-bit values).
	
	ptr = inString;
	for( i = 0; i < 3; ++i )
	{
		char *		next;
		long		value;
		uint8_t		buf[ 2 ];
		
		value = strtol( ptr, &next, 0 );
		require_action_quiet( ( next != ptr ) && ( *next == ',' ), exit, err = kMalformedErr );
		require_action_quiet( ( value >= 0 ) && ( value <= UINT16_MAX ), exit, err = kRangeErr );
		ptr = next + 1;
		
		WriteBig16( buf, value );
		
		err = DataBuffer_Append( &dataBuf, buf, sizeof( buf ) );
		require_noerr( err, exit );
	}
	
	// Set the target domain name.
	
	err = DomainNameFromString( target, ptr, &end );
    require_noerr_quiet( err, exit );
	
	err = DataBuffer_Append( &dataBuf, target, (size_t)( end - target ) );
	require_noerr( err, exit );
	
	err = DataBuffer_Detach( &dataBuf, outPtr, outLen );
	require_noerr( err, exit );
	
exit:
	DataBuffer_Free( &dataBuf );
	return( err );
}

static OSStatus	StringToTXTRData( const char *inString, char inDelimiter, uint8_t **outPtr, size_t *outLen )
{
	OSStatus			err;
	DataBuffer			dataBuf;
	const char *		src;
	uint8_t				txtStr[ 256 ];	// Buffer for single TXT string: 1 length byte + up to 255 bytes of data.
	
	DataBuffer_Init( &dataBuf, NULL, 0, kRDataMaxLen );
	
	src = inString;
	for( ;; )
	{
		uint8_t *					dst = &txtStr[ 1 ];
		const uint8_t * const		lim = &txtStr[ 256 ];
		int							c;
		
		while( *src && ( *src != inDelimiter ) )
		{
			if( ( c = *src++ ) == '\\' )
			{
				require_action_quiet( *src != '\0', exit, err = kUnderrunErr );
				c = *src++;
			}
			require_action_quiet( dst < lim, exit, err = kOverrunErr );
			*dst++ = (uint8_t) c;
		}
		txtStr[ 0 ] = (uint8_t)( dst - &txtStr[ 1 ] );
		err = DataBuffer_Append( &dataBuf, txtStr, 1 + txtStr[ 0 ] );
		require_noerr( err, exit );
		
		if( *src == '\0' ) break;
		++src;
	}
	
	err = DataBuffer_Detach( &dataBuf, outPtr, outLen );
	require_noerr( err, exit );
	
exit:
	DataBuffer_Free( &dataBuf );
	return( err );
}

//===========================================================================================================================
//	RecordTypeFromArgString
//===========================================================================================================================

typedef struct
{
	uint16_t			value;	// Record type's numeric value.
	const char *		name;	// Record type's name as a string (e.g., "A", "PTR", "SRV").
	
}	RecordType;

static const RecordType		kRecordTypes[] =
{
	// Common types.
	
	{ kDNSServiceType_A,			"A" },
	{ kDNSServiceType_AAAA,			"AAAA" },
	{ kDNSServiceType_PTR,			"PTR" },
	{ kDNSServiceType_SRV,			"SRV" },
	{ kDNSServiceType_TXT,			"TXT" },
	{ kDNSServiceType_CNAME,		"CNAME" },
	{ kDNSServiceType_SOA,			"SOA" },
	{ kDNSServiceType_NSEC,			"NSEC" },
	{ kDNSServiceType_NS,			"NS" },
	{ kDNSServiceType_MX,			"MX" },
	{ kDNSServiceType_ANY,			"ANY" },
	{ kDNSServiceType_OPT,			"OPT" },
	
	// Less common types.
	
	{ kDNSServiceType_MD,			"MD" },
	{ kDNSServiceType_NS,			"NS" },
	{ kDNSServiceType_MD,			"MD" },
	{ kDNSServiceType_MF,			"MF" },
	{ kDNSServiceType_MB,			"MB" },
	{ kDNSServiceType_MG,			"MG" },
	{ kDNSServiceType_MR,			"MR" },
	{ kDNSServiceType_NULL,			"NULL" },
	{ kDNSServiceType_WKS,			"WKS" },
	{ kDNSServiceType_HINFO,		"HINFO" },
	{ kDNSServiceType_MINFO,		"MINFO" },
	{ kDNSServiceType_RP,			"RP" },
	{ kDNSServiceType_AFSDB,		"AFSDB" },
	{ kDNSServiceType_X25,			"X25" },
	{ kDNSServiceType_ISDN,			"ISDN" },
	{ kDNSServiceType_RT,			"RT" },
	{ kDNSServiceType_NSAP,			"NSAP" },
	{ kDNSServiceType_NSAP_PTR,		"NSAP_PTR" },
	{ kDNSServiceType_SIG,			"SIG" },
	{ kDNSServiceType_KEY,			"KEY" },
	{ kDNSServiceType_PX,			"PX" },
	{ kDNSServiceType_GPOS,			"GPOS" },
	{ kDNSServiceType_LOC,			"LOC" },
	{ kDNSServiceType_NXT,			"NXT" },
	{ kDNSServiceType_EID,			"EID" },
	{ kDNSServiceType_NIMLOC,		"NIMLOC" },
	{ kDNSServiceType_ATMA,			"ATMA" },
	{ kDNSServiceType_NAPTR,		"NAPTR" },
	{ kDNSServiceType_KX,			"KX" },
	{ kDNSServiceType_CERT,			"CERT" },
	{ kDNSServiceType_A6,			"A6" },
	{ kDNSServiceType_DNAME,		"DNAME" },
	{ kDNSServiceType_SINK,			"SINK" },
	{ kDNSServiceType_APL,			"APL" },
	{ kDNSServiceType_DS,			"DS" },
	{ kDNSServiceType_SSHFP,		"SSHFP" },
	{ kDNSServiceType_IPSECKEY,		"IPSECKEY" },
	{ kDNSServiceType_RRSIG,		"RRSIG" },
	{ kDNSServiceType_DNSKEY,		"DNSKEY" },
	{ kDNSServiceType_DHCID,		"DHCID" },
	{ kDNSServiceType_NSEC3,		"NSEC3" },
	{ kDNSServiceType_NSEC3PARAM,	"NSEC3PARAM" },
	{ kDNSServiceType_HIP,			"HIP" },
	{ kDNSServiceType_SPF,			"SPF" },
	{ kDNSServiceType_UINFO,		"UINFO" },
	{ kDNSServiceType_UID,			"UID" },
	{ kDNSServiceType_GID,			"GID" },
	{ kDNSServiceType_UNSPEC,		"UNSPEC" },
	{ kDNSServiceType_TKEY,			"TKEY" },
	{ kDNSServiceType_TSIG,			"TSIG" },
	{ kDNSServiceType_IXFR,			"IXFR" },
	{ kDNSServiceType_AXFR,			"AXFR" },
	{ kDNSServiceType_MAILB,		"MAILB" },
	{ kDNSServiceType_MAILA,		"MAILA" }
};

static OSStatus	RecordTypeFromArgString( const char *inString, uint16_t *outValue )
{
	OSStatus						err;
	int32_t							i32;
	const RecordType *				type;
	const RecordType * const		end = kRecordTypes + countof( kRecordTypes );
	
	for( type = kRecordTypes; type < end; ++type )
	{
		if( strcasecmp( type->name, inString ) == 0 )
		{
			*outValue = type->value;
			return( kNoErr );
		}
	}
	
	err = StringToInt32( inString, &i32 );
	require_noerr_quiet( err, exit );
	require_action_quiet( ( i32 >= 0 ) && ( i32 <= UINT16_MAX ), exit, err = kParamErr );
	
	*outValue = (uint16_t) i32;
	
exit:
	return( err );
}

//===========================================================================================================================
//	RecordClassFromArgString
//===========================================================================================================================

static OSStatus	RecordClassFromArgString( const char *inString, uint16_t *outValue )
{
	OSStatus		err;
	int32_t			i32;
	
	if( strcasecmp( inString, "IN" ) == 0 )
	{
		*outValue = kDNSServiceClass_IN;
		err = kNoErr;
		goto exit;
	}
	
	err = StringToInt32( inString, &i32 );
	require_noerr_quiet( err, exit );
	require_action_quiet( ( i32 >= 0 ) && ( i32 <= UINT16_MAX ), exit, err = kParamErr );
	
	*outValue = (uint16_t) i32;
	
exit:
	return( err );
}

//===========================================================================================================================
//	InterfaceIndexToName
//===========================================================================================================================

static char * InterfaceIndexToName( uint32_t inIfIndex, char inNameBuf[ kInterfaceNameBufLen ] )
{
	switch( inIfIndex )
	{
		case kDNSServiceInterfaceIndexAny:
			strlcpy( inNameBuf, "Any", kInterfaceNameBufLen );
			break;
		
		case kDNSServiceInterfaceIndexLocalOnly:
			strlcpy( inNameBuf, "LocalOnly", kInterfaceNameBufLen );
			break;
		
		case kDNSServiceInterfaceIndexUnicast:
			strlcpy( inNameBuf, "Unicast", kInterfaceNameBufLen );
			break;
		
		case kDNSServiceInterfaceIndexP2P:
			strlcpy( inNameBuf, "P2P", kInterfaceNameBufLen );
			break;
		
	#if( defined( kDNSServiceInterfaceIndexBLE ) )
		case kDNSServiceInterfaceIndexBLE:
			strlcpy( inNameBuf, "BLE", kInterfaceNameBufLen );
			break;
	#endif
		
		default:
		{
			const char *		name;
			
			name = if_indextoname( inIfIndex, inNameBuf );
			if( !name ) strlcpy( inNameBuf, "NO NAME", kInterfaceNameBufLen );
			break;
		}
	}
	
	return( inNameBuf );
}

//===========================================================================================================================
//	RecordTypeToString
//===========================================================================================================================

static const char *	RecordTypeToString( unsigned int inValue )
{
	const RecordType *				type;
	const RecordType * const		end = kRecordTypes + countof( kRecordTypes );
	
	for( type = kRecordTypes; type < end; ++type )
	{
		if( type->value == inValue ) return( type->name );
	}
	return( "???" );
}

//===========================================================================================================================
//	DNSMessageExtractDomainName
//===========================================================================================================================

#define IsCompressionByte( X )		( ( ( X ) & 0xC0 ) == 0xC0 )

static OSStatus
	DNSMessageExtractDomainName(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inNamePtr,
		uint8_t				inBuf[ kDomainNameLengthMax ],
		const uint8_t **	outNextPtr )
{
	OSStatus					err;
	const uint8_t *				label;
	uint8_t						labelLen;
	const uint8_t *				nextLabel;
	const uint8_t * const		msgEnd	= inMsgPtr + inMsgLen;
	uint8_t *					dst		= inBuf;
	const uint8_t * const		dstLim	= inBuf ? ( inBuf + kDomainNameLengthMax ) : NULL;
	const uint8_t *				nameEnd	= NULL;
	
	require_action( ( inNamePtr >= inMsgPtr ) && ( inNamePtr < msgEnd ), exit, err = kRangeErr );
	
	for( label = inNamePtr; ( labelLen = label[ 0 ] ) != 0; label = nextLabel )
	{
		if( labelLen <= kDomainLabelLengthMax )
		{
			nextLabel = label + 1 + labelLen;
			require_action( nextLabel < msgEnd, exit, err = kUnderrunErr );
			if( dst )
			{
				require_action( ( dstLim - dst ) > ( 1 + labelLen ), exit, err = kOverrunErr );
				memcpy( dst, label, 1 + labelLen );
				dst += ( 1 + labelLen );
			}
		}
		else if( IsCompressionByte( labelLen ) )
		{
			uint16_t		offset;
			
			require_action( ( msgEnd - label ) >= 2, exit, err = kUnderrunErr );
			if( !nameEnd )
			{
				nameEnd = label + 2;
				if( !dst ) break;
			}
			offset = (uint16_t)( ( ( label[ 0 ] & 0x3F ) << 8 ) | label[ 1 ] );
			nextLabel = inMsgPtr + offset;
			require_action( nextLabel < msgEnd, exit, err = kUnderrunErr );
			require_action( !IsCompressionByte( nextLabel[ 0 ] ), exit, err = kMalformedErr );
		}
		else
		{
			dlogassert( "Unhandled label length 0x%02X\n", labelLen );
			err = kMalformedErr;
			goto exit;
		}
	}
	
	if( dst ) *dst = 0;
	if( !nameEnd ) nameEnd = label + 1;
	
	if( outNextPtr ) *outNextPtr = nameEnd;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DNSMessageExtractDomainNameString
//===========================================================================================================================

static OSStatus
	DNSMessageExtractDomainNameString(
		const void *		inMsgPtr,
		size_t				inMsgLen,
		const void *		inNamePtr,
		char				inBuf[ kDNSServiceMaxDomainName ],
		const uint8_t **	outNextPtr )
{
	OSStatus			err;
	const uint8_t *		nextPtr;
	uint8_t				domainName[ kDomainNameLengthMax ];
	
	err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inNamePtr, domainName, &nextPtr );
	require_noerr( err, exit );
	
	err = DomainNameToString( domainName, NULL, inBuf, NULL );
	require_noerr( err, exit );
	
	if( outNextPtr ) *outNextPtr = nextPtr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DNSMessageExtractRecord
//===========================================================================================================================

typedef struct
{
	uint8_t		type[ 2 ];
	uint8_t		class[ 2 ];
	uint8_t		ttl[ 4 ];
	uint8_t		rdLength[ 2 ];
	uint8_t		rdata[ 1 ];
	
}	DNSRecordFields;

check_compile_time( offsetof( DNSRecordFields, rdata ) == 10 );

static OSStatus
	DNSMessageExtractRecord(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inPtr,
		uint8_t				inNameBuf[ kDomainNameLengthMax ],
		uint16_t *			outType,
		uint16_t *			outClass,
		uint32_t *			outTTL,
		const uint8_t **	outRDataPtr,
		size_t *			outRDataLen,
		const uint8_t **	outPtr )
{
	OSStatus					err;
	const uint8_t * const		msgEnd = inMsgPtr + inMsgLen;
	const uint8_t *				ptr;
	const DNSRecordFields *		record;
	size_t						rdLength;
	
	err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inPtr, inNameBuf, &ptr );
	require_noerr_quiet( err, exit );
	require_action_quiet( (size_t)( msgEnd - ptr ) >= offsetof( DNSRecordFields, rdata ), exit, err = kUnderrunErr );
	
	record = (DNSRecordFields *) ptr;
	rdLength = ReadBig16( record->rdLength );
	require_action_quiet( (size_t)( msgEnd - record->rdata ) >= rdLength , exit, err = kUnderrunErr );
	
	if( outType )		*outType		= ReadBig16( record->type );
	if( outClass )		*outClass		= ReadBig16( record->class );
	if( outTTL )		*outTTL			= ReadBig32( record->ttl );
	if( outRDataPtr )	*outRDataPtr	= record->rdata;
	if( outRDataLen )	*outRDataLen	= rdLength;
	if( outPtr )		*outPtr			= record->rdata + rdLength;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DNSMessageGetAnswerSection
//===========================================================================================================================

static OSStatus	DNSMessageGetAnswerSection( const uint8_t *inMsgPtr, size_t inMsgLen, const uint8_t **outPtr )
{
	OSStatus					err;
	const uint8_t * const		msgEnd	= inMsgPtr + inMsgLen;
	unsigned int				questionCount, i;
	const DNSHeader *			hdr;
	const uint8_t *				ptr;
	
	require_action_quiet( inMsgLen >= kDNSHeaderLength, exit, err = kSizeErr );
	
	hdr = (DNSHeader *) inMsgPtr;
	questionCount = DNSHeaderGetQuestionCount( hdr );
	
	ptr = (uint8_t *)( hdr + 1 );
	for( i = 0; i < questionCount; ++i )
	{
		err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, ptr, NULL, &ptr );
		require_noerr( err, exit );
		require_action_quiet( ( msgEnd - ptr ) >= 4, exit, err = kUnderrunErr );
		ptr += 4;
	}
	
	if( outPtr ) *outPtr = ptr;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DNSRecordDataToString
//===========================================================================================================================

static OSStatus
	DNSRecordDataToString(
		const void *	inRDataPtr,
		size_t			inRDataLen,
		unsigned int	inRDataType,
		const void *	inMsgPtr,
		size_t			inMsgLen,
		char **			outString )
{
	OSStatus					err;
	const uint8_t * const		rdataPtr = (uint8_t *) inRDataPtr;
	const uint8_t * const		rdataEnd = rdataPtr + inRDataLen;
	char *						rdataStr;
	const uint8_t *				ptr;
	int							n;
	char						domainNameStr[ kDNSServiceMaxDomainName ];
	
	rdataStr = NULL;
	if( inRDataType == kDNSServiceType_A )
	{
		require_action_quiet( inRDataLen == 4, exit, err = kMalformedErr );
		
		ASPrintF( &rdataStr, "%.4a", rdataPtr );
		require_action( rdataStr, exit, err = kNoMemoryErr );
	}
	else if( inRDataType == kDNSServiceType_AAAA )
	{
		require_action_quiet( inRDataLen == 16, exit, err = kMalformedErr );
		
		ASPrintF( &rdataStr, "%.16a", rdataPtr );
		require_action( rdataStr, exit, err = kNoMemoryErr );
	}
	else if( ( inRDataType == kDNSServiceType_PTR ) || ( inRDataType == kDNSServiceType_CNAME ) ||
			( inRDataType == kDNSServiceType_NS ) )
	{
		if( inMsgPtr )
		{
			err = DNSMessageExtractDomainNameString( inMsgPtr, inMsgLen, rdataPtr, domainNameStr, NULL );
			require_noerr( err, exit );
		}
		else
		{
			err = DomainNameToString( rdataPtr, rdataEnd, domainNameStr, NULL );
			require_noerr( err, exit );
		}
		
		rdataStr = strdup( domainNameStr );
		require_action( rdataStr, exit, err = kNoMemoryErr );
	}
	else if( inRDataType == kDNSServiceType_SRV )
	{
		uint16_t			priority, weight, port;
		const uint8_t *		target;
		
		require_action_quiet( ( rdataPtr + 6 ) < rdataEnd, exit, err = kMalformedErr );
		
		priority	= ReadBig16( rdataPtr );
		weight		= ReadBig16( rdataPtr + 2 );
		port		= ReadBig16( rdataPtr + 4 );
		target		= rdataPtr + 6;
		
		if( inMsgPtr )
		{
			err = DNSMessageExtractDomainNameString( inMsgPtr, inMsgLen, target, domainNameStr, NULL );
			require_noerr( err, exit );
		}
		else
		{
			err = DomainNameToString( target, rdataEnd, domainNameStr, NULL );
			require_noerr( err, exit );
		}
		
		ASPrintF( &rdataStr, "%u %u %u %s", priority, weight, port, domainNameStr );
		require_action( rdataStr, exit, err = kNoMemoryErr );
	}
	else if( inRDataType == kDNSServiceType_TXT )
	{
		require_action_quiet( inRDataLen > 0, exit, err = kMalformedErr );
		
		if( inRDataLen == 1 )
		{
			ASPrintF( &rdataStr, "%#H", rdataPtr, (int) inRDataLen, INT_MAX );
			require_action( rdataStr, exit, err = kNoMemoryErr );
		}
		else
		{
			ASPrintF( &rdataStr, "%#{txt}", rdataPtr, inRDataLen );
			require_action( rdataStr, exit, err = kNoMemoryErr );
		}
	}
	else if( inRDataType == kDNSServiceType_SOA )
	{
		uint32_t		serial, refresh, retry, expire, minimum;
		
		if( inMsgPtr )
		{
			err = DNSMessageExtractDomainNameString( inMsgPtr, inMsgLen, rdataPtr, domainNameStr, &ptr );
			require_noerr( err, exit );
			
			require_action_quiet( ptr < rdataEnd, exit, err = kMalformedErr );
			
			rdataStr = strdup( domainNameStr );
			require_action( rdataStr, exit, err = kNoMemoryErr );
			
			err = DNSMessageExtractDomainNameString( inMsgPtr, inMsgLen, ptr, domainNameStr, &ptr );
			require_noerr( err, exit );
		}
		else
		{
			err = DomainNameToString( rdataPtr, rdataEnd, domainNameStr, &ptr );
			require_noerr( err, exit );
			
			rdataStr = strdup( domainNameStr );
			require_action( rdataStr, exit, err = kNoMemoryErr );
			
			err = DomainNameToString( ptr, rdataEnd, domainNameStr, &ptr );
			require_noerr( err, exit );
		}
		
		require_action_quiet( ( ptr + 20 ) == rdataEnd, exit, err = kMalformedErr );
		
		serial	= ReadBig32( ptr );
		refresh	= ReadBig32( ptr +  4 );
		retry	= ReadBig32( ptr +  8 );
		expire	= ReadBig32( ptr + 12 );
		minimum	= ReadBig32( ptr + 16 );
		
		n = AppendPrintF( &rdataStr, " %s %u %u %u %u %u\n", domainNameStr, serial, refresh, retry, expire, minimum );
		require_action( n > 0, exit, err = kUnknownErr );
	}
	else if( inRDataType == kDNSServiceType_NSEC )
	{
		unsigned int		windowBlock, bitmapLen, i, recordType;
		const uint8_t *		bitmapPtr;
		
		if( inMsgPtr )
		{
			err = DNSMessageExtractDomainNameString( inMsgPtr, inMsgLen, rdataPtr, domainNameStr, &ptr );
			require_noerr( err, exit );
		}
		else
		{
			err = DomainNameToString( rdataPtr, rdataEnd, domainNameStr, &ptr );
			require_noerr( err, exit );
		}
		
		require_action_quiet( ptr < rdataEnd, exit, err = kMalformedErr );
		
		rdataStr = strdup( domainNameStr );
		require_action( rdataStr, exit, err = kNoMemoryErr );
		
		for( ; ptr < rdataEnd; ptr += ( 2 + bitmapLen ) )
		{
			require_action_quiet( ( ptr + 2 ) < rdataEnd, exit, err = kMalformedErr );
			
			windowBlock	= ptr[ 0 ];
			bitmapLen	= ptr[ 1 ];
			bitmapPtr	= &ptr[ 2 ];
			
			require_action_quiet( ( bitmapLen >= 1 ) && ( bitmapLen <= 32 ) , exit, err = kMalformedErr );
			require_action_quiet( ( bitmapPtr + bitmapLen ) <= rdataEnd, exit, err = kMalformedErr );
			
			for( i = 0; i < BitArray_MaxBits( bitmapLen ); ++i )
			{
				if( BitArray_GetBit( bitmapPtr, bitmapLen, i ) )
				{
					recordType = ( windowBlock * 256 ) + i;
					n = AppendPrintF( &rdataStr, " %s", RecordTypeToString( recordType ) );
					require_action( n > 0, exit, err = kUnknownErr );
				}
			}
		}
	}
	else if( inRDataType == kDNSServiceType_MX )
	{
		uint16_t			preference;
		const uint8_t *		exchange;
		
		require_action_quiet( ( rdataPtr + 2 ) < rdataEnd, exit, err = kMalformedErr );
		
		preference	= ReadBig16( rdataPtr );
		exchange	= &rdataPtr[ 2 ];
		
		if( inMsgPtr )
		{
			err = DNSMessageExtractDomainNameString( inMsgPtr, inMsgLen, exchange, domainNameStr, NULL );
			require_noerr( err, exit );
		}
		else
		{
			err = DomainNameToString( exchange, rdataEnd, domainNameStr, NULL );
			require_noerr( err, exit );
		}
		
		n = ASPrintF( &rdataStr, "%u %s", preference, domainNameStr );
		require_action( n > 0, exit, err = kUnknownErr );
	}
	else
	{
		err = kNotHandledErr;
		goto exit;
	}
	
	check( rdataStr );
	*outString = rdataStr;
	rdataStr = NULL;
	err = kNoErr;
	
exit:
	FreeNullSafe( rdataStr );
	return( err );
}

//===========================================================================================================================
//	DomainNameAppendString
//===========================================================================================================================

static OSStatus
	DomainNameAppendString(
		uint8_t			inDomainName[ kDomainNameLengthMax ],
		const char *	inString,
		uint8_t **		outEndPtr )
{
	OSStatus					err;
	const char *				src;
	uint8_t *					root;
	const uint8_t * const		nameLim = inDomainName + kDomainNameLengthMax;
	
	for( root = inDomainName; ( root < nameLim ) && *root; root += ( 1 + *root ) ) {}
	require_action_quiet( root < nameLim, exit, err = kMalformedErr );
	
	// If the string is a single dot, denoting the root domain, then there are no non-empty labels.
	
	src = inString;
	if( ( src[ 0 ] == '.' ) && ( src[ 1 ] == '\0' ) ) ++src;
	while( *src )
	{
		uint8_t * const				label		= root;
		const uint8_t * const		labelLim	= Min( &label[ 1 + kDomainLabelLengthMax ], nameLim - 1 );
		uint8_t *					dst;
		int							c;
		size_t						labelLen;
		
		dst = &label[ 1 ];
		while( *src && ( ( c = *src++ ) != '.' ) )
		{
			if( c == '\\' )
			{
				require_action_quiet( *src != '\0', exit, err = kUnderrunErr );
				c = *src++;
				if( isdigit_safe( c ) && isdigit_safe( src[ 0 ] ) && isdigit_safe( src[ 1 ] ) )
				{
					const int		decimal = ( ( c - '0' ) * 100 ) + ( ( src[ 0 ] - '0' ) * 10 ) + ( src[ 1 ] - '0' );
					
					if( decimal <= 255 )
					{
						c = decimal;
						src += 2;
					}
				}
			}
			require_action_quiet( dst < labelLim, exit, err = kOverrunErr );
			*dst++ = (uint8_t) c;
		}
		
		labelLen = (size_t)( dst - &label[ 1 ] );
		require_action_quiet( labelLen > 0, exit, err = kMalformedErr );
		
		label[ 0 ] = (uint8_t) labelLen;
		root = dst;
		*root = 0;
	}
	
	if( outEndPtr ) *outEndPtr = root + 1;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DomainNameEqual
//===========================================================================================================================

static Boolean	DomainNameEqual( const uint8_t *inName1, const uint8_t *inName2 )
{
	const uint8_t *		p1 = inName1;
	const uint8_t *		p2 = inName2;
	unsigned int		len;
	
	for( ;; )
	{
		if( ( len = *p1++ ) != *p2++ ) return( false );
		if( len == 0 ) break;
		for( ; len > 0; ++p1, ++p2, --len )
		{
			if( tolower_safe( *p1 ) != tolower_safe( *p2 ) ) return( false );
		}
	}
	return( true );
}

//===========================================================================================================================
//	DomainNameLength
//===========================================================================================================================

static size_t	DomainNameLength( const uint8_t * const inName )
{
	const uint8_t *		ptr;
	
	for( ptr = inName; *ptr != 0; ptr += ( 1 + *ptr ) ) {}
	return( (size_t)( ptr - inName ) + 1 );
}

//===========================================================================================================================
//	DomainNameFromString
//===========================================================================================================================

static OSStatus
	DomainNameFromString(
		uint8_t			inDomainName[ kDomainNameLengthMax ],
		const char *	inString,
		uint8_t **		outEndPtr )
{
	inDomainName[ 0 ] = 0;
	return( DomainNameAppendString( inDomainName, inString, outEndPtr ) );
}

//===========================================================================================================================
//	DomainNameToString
//===========================================================================================================================

static OSStatus
	DomainNameToString(
		const uint8_t *		inDomainName,
		const uint8_t *		inEnd,
		char				inBuf[ kDNSServiceMaxDomainName ],
		const uint8_t **	outNextPtr )
{
	OSStatus			err;
	const uint8_t *		label;
	uint8_t				labelLen;
	const uint8_t *		nextLabel;
	char *				dst;
	const uint8_t *		src;
	
	require_action( !inEnd || ( inDomainName < inEnd ), exit, err = kUnderrunErr );
	
	// Convert each label up until the root label, i.e., the zero-length label.
	
	dst = inBuf;
	for( label = inDomainName; ( labelLen = label[ 0 ] ) != 0; label = nextLabel )
	{
		require_action( labelLen <= kDomainLabelLengthMax, exit, err = kMalformedErr );
		
		nextLabel = &label[ 1 ] + labelLen;
		require_action( ( nextLabel - inDomainName ) < kDomainNameLengthMax, exit, err = kMalformedErr );
		require_action( !inEnd || ( nextLabel < inEnd ), exit, err = kUnderrunErr );
		
		for( src = &label[ 1 ]; src < nextLabel; ++src )
		{
			if( isprint_safe( *src ) )
			{
				if( ( *src == '.' ) || ( *src == '\\' ) ||  ( *src == ' ' ) ) *dst++ = '\\';
				*dst++ = (char) *src;
			}
			else
			{
				*dst++ = '\\';
				*dst++ = '0' + (   *src / 100 );
				*dst++ = '0' + ( ( *src /  10 ) % 10 );
				*dst++ = '0' + (   *src         % 10 );
			}
		}
		*dst++ = '.';
	}
	
	// At this point, label points to the root label.
	// If the root label was the only label, then write a dot for it.
	
	if( label == inDomainName ) *dst++ = '.';
	*dst = '\0';
	if( outNextPtr ) *outNextPtr = label + 1;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DNSMessageToText
//===========================================================================================================================

#define DNSFlagsOpCodeToString( X ) (					\
	( (X) == kDNSOpCode_Query )			? "Query"	:	\
	( (X) == kDNSOpCode_InverseQuery )	? "IQuery"	:	\
	( (X) == kDNSOpCode_Status )		? "Status"	:	\
	( (X) == kDNSOpCode_Notify )		? "Notify"	:	\
	( (X) == kDNSOpCode_Update )		? "Update"	:	\
										  "Unassigned" )

#define DNSFlagsRCodeToString( X ) (						\
	( (X) == kDNSRCode_NoError )		? "NoError"		:	\
	( (X) == kDNSRCode_FormatError )	? "FormErr"		:	\
	( (X) == kDNSRCode_ServerFailure )	? "ServFail"	:	\
	( (X) == kDNSRCode_NXDomain )		? "NXDomain"	:	\
	( (X) == kDNSRCode_NotImplemented )	? "NotImp"		:	\
	( (X) == kDNSRCode_Refused )		? "Refused"		:	\
										  "???" )

static OSStatus
	DNSMessageToText(
		const uint8_t *	inMsgPtr,
		size_t			inMsgLen,
		const Boolean	inMDNS,
		const Boolean	inPrintRaw,
		char **			outText )
{
	OSStatus					err;
	DataBuffer					dataBuf;
	size_t						len;
	const DNSHeader *			hdr;
	const uint8_t * const		msgEnd = inMsgPtr + inMsgLen;
	const uint8_t *				ptr;
	unsigned int				id, flags, opcode, rcode;
	unsigned int				questionCount, answerCount, authorityCount, additionalCount, i, totalRRCount;
	char						nameStr[ kDNSServiceMaxDomainName ];
	
	DataBuffer_Init( &dataBuf, NULL, 0, SIZE_MAX );
	#define _Append( ... )		do { err = DataBuffer_AppendF( &dataBuf, __VA_ARGS__ ); require_noerr( err, exit ); } while( 0 )
	
	require_action_quiet( inMsgLen >= kDNSHeaderLength, exit, err = kSizeErr );
	
	hdr				= (DNSHeader *) inMsgPtr;
	id				= DNSHeaderGetID( hdr );
	flags			= DNSHeaderGetFlags( hdr );
	questionCount	= DNSHeaderGetQuestionCount( hdr );
	answerCount		= DNSHeaderGetAnswerCount( hdr );
	authorityCount	= DNSHeaderGetAuthorityCount( hdr );
	additionalCount	= DNSHeaderGetAdditionalCount( hdr );
	opcode			= DNSFlagsGetOpCode( flags );
	rcode			= DNSFlagsGetRCode( flags );
	
	_Append( "ID:               0x%04X (%u)\n", id, id );
	_Append( "Flags:            0x%04X %c/%s %cAA%cTC%cRD%cRA%?s%?s %s\n",
		flags,
		( flags & kDNSHeaderFlag_Response )				? 'R' : 'Q', DNSFlagsOpCodeToString( opcode ),
		( flags & kDNSHeaderFlag_AuthAnswer )			? ' ' : '!',
		( flags & kDNSHeaderFlag_Truncation )			? ' ' : '!',
		( flags & kDNSHeaderFlag_RecursionDesired )		? ' ' : '!',
		( flags & kDNSHeaderFlag_RecursionAvailable )	? ' ' : '!',
		!inMDNS, ( flags & kDNSHeaderFlag_AuthenticData )		? " AD" : "!AD",
		!inMDNS, ( flags & kDNSHeaderFlag_CheckingDisabled )	? " CD" : "!CD",
		DNSFlagsRCodeToString( rcode ) );
	_Append( "Question count:   %u\n", questionCount );
	_Append( "Answer count:     %u\n", answerCount );
	_Append( "Authority count:  %u\n", authorityCount );
	_Append( "Additional count: %u\n", additionalCount );
	
	ptr = (const uint8_t *) &hdr[ 1 ];
	for( i = 0; i < questionCount; ++i )
	{
		unsigned int		qtype, qclass;
		Boolean				isQU;
		
		err = DNSMessageExtractDomainNameString( inMsgPtr, inMsgLen, ptr, nameStr, &ptr );
		require_noerr( err, exit );
		
		if( ( msgEnd - ptr ) < 4 )
		{
			err = kUnderrunErr;
			goto exit;
		}
		
		qtype	= DNSQuestionFixedFieldsGetType( (const DNSQuestionFixedFields *) ptr );
		qclass	= DNSQuestionFixedFieldsGetClass( (const DNSQuestionFixedFields *) ptr );
		ptr += 4;
		
		isQU = ( inMDNS && ( qclass & kQClassUnicastResponseBit ) ) ? true : false;
		if( inMDNS ) qclass &= ~kQClassUnicastResponseBit;
		
		if( i == 0 ) _Append( "\nQUESTION SECTION\n" );
		
		_Append( "%s %2s %?2s%?2u %-5s\n",
			nameStr, inMDNS ? ( isQU ? "QU" : "QM" ) : "",
			( qclass == kDNSServiceClass_IN ), "IN", ( qclass != kDNSServiceClass_IN ), qclass, RecordTypeToString( qtype ) );
	}
	
	totalRRCount = answerCount + authorityCount + additionalCount;
	for( i = 0; i < totalRRCount; ++i )
	{
		uint16_t			type;
		uint16_t			class;
		uint32_t			ttl;
		const uint8_t *		rdataPtr;
		size_t				rdataLen;
		char *				rdataStr;
		Boolean				cacheFlush;
		uint8_t				name[ kDomainNameLengthMax ];
		
		err = DNSMessageExtractRecord( inMsgPtr, inMsgLen, ptr, name, &type, &class, &ttl, &rdataPtr, &rdataLen, &ptr );
		require_noerr( err, exit );
		
		err = DomainNameToString( name, NULL, nameStr, NULL );
		require_noerr( err, exit );
		
		cacheFlush = ( inMDNS && ( class & kRRClassCacheFlushBit ) ) ? true : false;
		if( inMDNS ) class &= ~kRRClassCacheFlushBit;
		
		rdataStr = NULL;
		if( !inPrintRaw ) DNSRecordDataToString( rdataPtr, rdataLen, type, inMsgPtr, inMsgLen, &rdataStr );
		if( !rdataStr )
		{
			ASPrintF( &rdataStr, "%#H", rdataPtr, (int) rdataLen, INT_MAX );
			require_action( rdataStr, exit, err = kNoMemoryErr );
		}
		
		if(      answerCount     && ( i ==   0                              ) ) _Append( "\nANSWER SECTION\n" );
		else if( authorityCount  && ( i ==   answerCount                    ) ) _Append( "\nAUTHORITY SECTION\n" );
		else if( additionalCount && ( i == ( answerCount + authorityCount ) ) ) _Append( "\nADDITIONAL SECTION\n" );
		
		_Append( "%-42s %6u %2s %?2s%?2u %-5s %s\n",
			nameStr, ttl, cacheFlush ? "CF" : "",
			( class == kDNSServiceClass_IN ), "IN", ( class != kDNSServiceClass_IN ), class,
			RecordTypeToString( type ), rdataStr );
		free( rdataStr );
	}
	_Append( "\n" );
	
	err = DataBuffer_Append( &dataBuf, "", 1 );
	require_noerr( err, exit );
	
	err = DataBuffer_Detach( &dataBuf, (uint8_t **) outText, &len );
	require_noerr( err, exit );
	
exit:
	DataBuffer_Free( &dataBuf );
	return( err );
}

//===========================================================================================================================
//	WriteDNSQueryMessage
//===========================================================================================================================

static OSStatus
	WriteDNSQueryMessage(
		uint8_t			inMsg[ kDNSQueryMessageMaxLen ],
		uint16_t		inMsgID,
		uint16_t		inFlags,
		const char *	inQName,
		uint16_t		inQType,
		uint16_t		inQClass,
		size_t *		outMsgLen )
{
	OSStatus				err;
	DNSHeader * const		hdr = (DNSHeader *) inMsg;
	uint8_t *				ptr;
	size_t					msgLen;
	
	memset( hdr, 0, sizeof( *hdr ) );
	DNSHeaderSetID( hdr, inMsgID );
	DNSHeaderSetFlags( hdr, inFlags );
	DNSHeaderSetQuestionCount( hdr, 1 );
	
	ptr = (uint8_t *)( hdr + 1 );
	err = DomainNameFromString( ptr, inQName, &ptr );
	require_noerr_quiet( err, exit );
	
	DNSQuestionFixedFieldsInit( (DNSQuestionFixedFields *) ptr, inQType, inQClass );
	ptr += 4;
	
	msgLen = (size_t)( ptr - inMsg );
	check( msgLen <= kDNSQueryMessageMaxLen );
	
	if( outMsgLen ) *outMsgLen = msgLen;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DispatchSignalSourceCreate
//===========================================================================================================================

static OSStatus
	DispatchSignalSourceCreate(
		int					inSignal,
		DispatchHandler		inEventHandler,
		void *				inContext,
		dispatch_source_t *	outSource )
{
	OSStatus				err;
	dispatch_source_t		source;
	
	source = dispatch_source_create( DISPATCH_SOURCE_TYPE_SIGNAL, (uintptr_t) inSignal, 0, dispatch_get_main_queue() );
	require_action( source, exit, err = kUnknownErr );
	
	dispatch_set_context( source, inContext );
	dispatch_source_set_event_handler_f( source, inEventHandler );
	
	*outSource = source;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DispatchSocketSourceCreate
//===========================================================================================================================

static OSStatus
	DispatchSocketSourceCreate(
		SocketRef				inSock,
		dispatch_source_type_t	inType,
		dispatch_queue_t		inQueue,
		DispatchHandler			inEventHandler,
		DispatchHandler			inCancelHandler,
		void *					inContext,
		dispatch_source_t *		outSource )
{
	OSStatus				err;
	dispatch_source_t		source;
	
	source = dispatch_source_create( inType, (uintptr_t) inSock, 0, inQueue ? inQueue : dispatch_get_main_queue() );
	require_action( source, exit, err = kUnknownErr );
	
	dispatch_set_context( source, inContext );
	dispatch_source_set_event_handler_f( source, inEventHandler );
	dispatch_source_set_cancel_handler_f( source, inCancelHandler );
	
	*outSource = source;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DispatchTimerCreate
//===========================================================================================================================

static OSStatus
	DispatchTimerCreate(
		dispatch_time_t		inStart,
		uint64_t			inIntervalNs,
		uint64_t			inLeewayNs,
		dispatch_queue_t	inQueue,
		DispatchHandler		inEventHandler,
		DispatchHandler		inCancelHandler,
		void *				inContext,
		dispatch_source_t *	outTimer )
{
	OSStatus				err;
	dispatch_source_t		timer;
	
	timer = dispatch_source_create( DISPATCH_SOURCE_TYPE_TIMER, 0, 0, inQueue ? inQueue : dispatch_get_main_queue() );
	require_action( timer, exit, err = kUnknownErr );
	
	dispatch_source_set_timer( timer, inStart, inIntervalNs, inLeewayNs );
	dispatch_set_context( timer, inContext );
	dispatch_source_set_event_handler_f( timer, inEventHandler );
	dispatch_source_set_cancel_handler_f( timer, inCancelHandler );
	
	*outTimer = timer;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	DispatchProcessMonitorCreate
//===========================================================================================================================

static OSStatus
	DispatchProcessMonitorCreate(
		pid_t				inPID,
		unsigned long		inFlags,
		dispatch_queue_t	inQueue,
		DispatchHandler		inEventHandler,
		DispatchHandler		inCancelHandler,
		void *				inContext,
		dispatch_source_t *	outMonitor )
{
	OSStatus				err;
	dispatch_source_t		monitor;
	
	monitor = dispatch_source_create( DISPATCH_SOURCE_TYPE_PROC, (uintptr_t) inPID, inFlags,
		inQueue ? inQueue : dispatch_get_main_queue() );
	require_action( monitor, exit, err = kUnknownErr );
	
	dispatch_set_context( monitor, inContext );
	dispatch_source_set_event_handler_f( monitor, inEventHandler );
	dispatch_source_set_cancel_handler_f( monitor, inCancelHandler );
	
	*outMonitor = monitor;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	ServiceTypeDescription
//===========================================================================================================================

typedef struct
{
	const char *		name;			// Name of the service type in two-label "_service._proto" format.
	const char *		description;	// Description of the service type.
	
}	ServiceType;

// A Non-comprehensive table of DNS-SD service types

static const ServiceType		kServiceTypes[] =
{
	{ "_acp-sync._tcp",			"AirPort Base Station Sync" },
	{ "_adisk._tcp",			"Automatic Disk Discovery" },
	{ "_afpovertcp._tcp",		"Apple File Sharing" },
	{ "_airdrop._tcp",			"AirDrop" },
	{ "_airplay._tcp",			"AirPlay" },
	{ "_airport._tcp",			"AirPort Base Station" },
	{ "_daap._tcp",				"Digital Audio Access Protocol (iTunes)" },
	{ "_eppc._tcp",				"Remote AppleEvents" },
	{ "_ftp._tcp",				"File Transfer Protocol" },
	{ "_home-sharing._tcp",		"Home Sharing" },
	{ "_homekit._tcp",			"HomeKit" },
	{ "_http._tcp",				"World Wide Web HTML-over-HTTP" },
	{ "_https._tcp",			"HTTP over SSL/TLS" },
	{ "_ipp._tcp",				"Internet Printing Protocol" },
	{ "_ldap._tcp",				"Lightweight Directory Access Protocol" },
	{ "_mediaremotetv._tcp",	"Media Remote" },
	{ "_net-assistant._tcp",	"Apple Remote Desktop" },
	{ "_od-master._tcp",		"OpenDirectory Master" },
	{ "_nfs._tcp",				"Network File System" },
	{ "_presence._tcp",			"Peer-to-peer messaging / Link-Local Messaging" },
	{ "_pdl-datastream._tcp",	"Printer Page Description Language Data Stream" },
	{ "_raop._tcp",				"Remote Audio Output Protocol" },
	{ "_rfb._tcp",				"Remote Frame Buffer" },
	{ "_scanner._tcp",			"Bonjour Scanning" },
	{ "_smb._tcp",				"Server Message Block over TCP/IP" },
	{ "_sftp-ssh._tcp",			"Secure File Transfer Protocol over SSH" },
	{ "_sleep-proxy._udp",		"Sleep Proxy Server" },
	{ "_ssh._tcp",				"SSH Remote Login Protocol" },
	{ "_teleport._tcp",			"teleport" },
	{ "_tftp._tcp",				"Trivial File Transfer Protocol" },
	{ "_workstation._tcp",		"Workgroup Manager" },
	{ "_webdav._tcp",			"World Wide Web Distributed Authoring and Versioning (WebDAV)" },
	{ "_webdavs._tcp",			"WebDAV over SSL/TLS" }
};

static const char *	ServiceTypeDescription( const char *inName )
{
	const ServiceType *				serviceType;
	const ServiceType * const		end = kServiceTypes + countof( kServiceTypes );
	
	for( serviceType = kServiceTypes; serviceType < end; ++serviceType )
	{
		if( strcasecmp( inName, serviceType->name ) == 0 ) return( serviceType->description );
	}
	return( NULL );
}

//===========================================================================================================================
//	SocketContextCreate
//===========================================================================================================================

static OSStatus	SocketContextCreate( SocketRef inSock, void * inUserContext, SocketContext **outContext )
{
	OSStatus			err;
	SocketContext *		context;
	
	context = (SocketContext *) calloc( 1, sizeof( *context ) );
	require_action( context, exit, err = kNoMemoryErr );
	
	context->refCount		= 1;
	context->sock			= inSock;
	context->userContext	= inUserContext;
	
	*outContext = context;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	SocketContextRetain
//===========================================================================================================================

static SocketContext *	SocketContextRetain( SocketContext *inContext )
{
	++inContext->refCount;
	return( inContext );
}

//===========================================================================================================================
//	SocketContextRelease
//===========================================================================================================================

static void	SocketContextRelease( SocketContext *inContext )
{
	if( --inContext->refCount == 0 )
	{
		ForgetSocket( &inContext->sock );
		free( inContext );
	}
}

//===========================================================================================================================
//	SocketContextCancelHandler
//===========================================================================================================================

static void	SocketContextCancelHandler( void *inContext )
{
	SocketContextRelease( (SocketContext *) inContext );
}

//===========================================================================================================================
//	StringToInt32
//===========================================================================================================================

static OSStatus	StringToInt32( const char *inString, int32_t *outValue )
{
	OSStatus		err;
	long			value;
	char *			endPtr;
	
	value = strtol( inString, &endPtr, 0 );
	require_action_quiet( ( *endPtr == '\0' ) && ( endPtr != inString ), exit, err = kParamErr );
	require_action_quiet( ( value >= INT32_MIN ) && ( value <= INT32_MAX ), exit, err = kRangeErr );
	
	*outValue = (int32_t) value;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	StringToUInt32
//===========================================================================================================================

static OSStatus	StringToUInt32( const char *inString, uint32_t *outValue )
{
	OSStatus		err;
	uint32_t		value;
	char *			endPtr;
	
	value = (uint32_t) strtol( inString, &endPtr, 0 );
	require_action_quiet( ( *endPtr == '\0' ) && ( endPtr != inString ), exit, err = kParamErr );
	
	*outValue = value;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	StringToLongLong
//===========================================================================================================================

static OSStatus	StringToLongLong( const char *inString, long long *outValue )
{
	OSStatus		err;
	long long		value;
	char *			endPtr;
	
	set_errno_compat( 0 );
	value = strtol( inString, &endPtr, 0 );
	err = errno_compat();
	if( ( ( value == LLONG_MIN ) || ( value == LLONG_MAX ) ) && ( err == ERANGE ) ) goto exit;
	require_action_quiet( ( *endPtr == '\0' ) && ( endPtr != inString ), exit, err = kParamErr );
	
	*outValue = value;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	StringToARecordData
//===========================================================================================================================

static OSStatus	StringToARecordData( const char *inString, uint8_t **outPtr, size_t *outLen )
{
	OSStatus			err;
	uint32_t *			addrPtr;
	const size_t		addrLen = sizeof( *addrPtr );
	const char *		end;
	
	addrPtr = (uint32_t *) malloc( addrLen );
	require_action( addrPtr, exit, err = kNoMemoryErr );
	
	err = StringToIPv4Address( inString, kStringToIPAddressFlagsNoPort | kStringToIPAddressFlagsNoPrefix, addrPtr,
		NULL, NULL, NULL, &end );
	if( !err && ( *end != '\0' ) ) err = kMalformedErr;
	require_noerr_quiet( err, exit );
	
	*addrPtr = HostToBig32( *addrPtr );
	
	*outPtr = (uint8_t *) addrPtr;
	addrPtr = NULL;
	*outLen = addrLen;
	
exit:
	FreeNullSafe( addrPtr );
	return( err );
}

//===========================================================================================================================
//	StringToAAAARecordData
//===========================================================================================================================

static OSStatus	StringToAAAARecordData( const char *inString, uint8_t **outPtr, size_t *outLen )
{
	OSStatus			err;
	uint8_t *			addrPtr;
	const size_t		addrLen = 16;
	const char *		end;
	
	addrPtr = (uint8_t *) malloc( addrLen );
	require_action( addrPtr, exit, err = kNoMemoryErr );
	
	err = StringToIPv6Address( inString,
		kStringToIPAddressFlagsNoPort | kStringToIPAddressFlagsNoPrefix | kStringToIPAddressFlagsNoScope,
		addrPtr, NULL, NULL, NULL, &end );
	if( !err && ( *end != '\0' ) ) err = kMalformedErr;
	require_noerr_quiet( err, exit );
	
	*outPtr = addrPtr;
	addrPtr = NULL;
	*outLen = addrLen;
	
exit:
	FreeNullSafe( addrPtr );
	return( err );
}

//===========================================================================================================================
//	StringToDomainName
//===========================================================================================================================

static OSStatus	StringToDomainName( const char *inString, uint8_t **outPtr, size_t *outLen )
{
	OSStatus		err;
	uint8_t *		namePtr;
	size_t			nameLen;
	uint8_t *		end;
	uint8_t			nameBuf[ kDomainNameLengthMax ];
	
	err = DomainNameFromString( nameBuf, inString, &end );
	require_noerr_quiet( err, exit );
	
	nameLen = (size_t)( end - nameBuf );
	namePtr = memdup( nameBuf, nameLen );
	require_action( namePtr, exit, err = kNoMemoryErr );
	
	*outPtr = namePtr;
	namePtr = NULL;
	if( outLen ) *outLen = nameLen;
	
exit:
	return( err );
}

#if( TARGET_OS_DARWIN )
//===========================================================================================================================
//	GetDefaultDNSServer
//===========================================================================================================================

static OSStatus	GetDefaultDNSServer( sockaddr_ip *outAddr )
{
	OSStatus				err;
	dns_config_t *			config;
	struct sockaddr *		addr;
	int32_t					i;
	
	config = dns_configuration_copy();
	require_action( config, exit, err = kUnknownErr );
	
	addr = NULL;
	for( i = 0; i < config->n_resolver; ++i )
	{
		const dns_resolver_t * const		resolver = config->resolver[ i ];
		
		if( !resolver->domain && ( resolver->n_nameserver > 0 ) )
		{
			addr = resolver->nameserver[ 0 ];
			break;
		}
 	}
	require_action_quiet( addr, exit, err = kNotFoundErr );
	
	SockAddrCopy( addr, outAddr );
	err = kNoErr;
	
exit:
	if( config ) dns_configuration_free( config );
	return( err );
}
#endif

//===========================================================================================================================
//	GetCurrentMicroTime
//===========================================================================================================================

static MicroTime64	GetCurrentMicroTime( void )
{
	struct timeval		now;
	
	TIMEVAL_ZERO( now );
	gettimeofday( &now, NULL );
	
	return( (MicroTime64) TIMEVAL_USEC64( now ) );
}

//===========================================================================================================================
//	SocketWriteAll
//
//	Note: This was copied from CoreUtils because the SocketWriteAll function is currently not exported in the framework.
//===========================================================================================================================

OSStatus	SocketWriteAll( SocketRef inSock, const void *inData, size_t inSize, int32_t inTimeoutSecs )
{
	OSStatus			err;
	const uint8_t *		src;
	const uint8_t *		end;
	fd_set				writeSet;
	struct timeval		timeout;
	ssize_t				n;
	
	FD_ZERO( &writeSet );
	src = (const uint8_t *) inData;
	end = src + inSize;
	while( src < end )
	{
		FD_SET( inSock, &writeSet );
		timeout.tv_sec 	= inTimeoutSecs;
		timeout.tv_usec = 0;
		n = select( (int)( inSock + 1 ), NULL, &writeSet, NULL, &timeout );
		if( n == 0 ) { err = kTimeoutErr; goto exit; }
		err = map_socket_value_errno( inSock, n > 0, n );
		require_noerr( err, exit );
		
		n = send( inSock, (char *) src, (size_t)( end - src ), 0 );
		err = map_socket_value_errno( inSock, n >= 0, n );
		if( err == EINTR ) continue;
		require_noerr( err, exit );
		
		src += n;
	}
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	ParseIPv4Address
//
//	Warning: "inBuffer" may be modified even in error cases.
//
//	Note: This was copied from CoreUtils because the StringToIPv4Address function is currently not exported in the framework.
//===========================================================================================================================

static OSStatus	ParseIPv4Address( const char *inStr, uint8_t inBuffer[ 4 ], const char **outStr )
{
	OSStatus		err;
	uint8_t *		dst;
	int				segments;
	int				sawDigit;
	int				c;
	int				v;
	
	check( inBuffer );
	check( outStr );
	
	dst		 = inBuffer;
	*dst	 = 0;
	sawDigit = 0;
	segments = 0;
	for( ; ( c = *inStr ) != '\0'; ++inStr )
	{
		if( isdigit_safe( c ) )
		{
			v = ( *dst * 10 ) + ( c - '0' );
			require_action_quiet( v <= 255, exit, err = kRangeErr );
			*dst = (uint8_t) v;
			if( !sawDigit )
			{
				++segments;
				require_action_quiet( segments <= 4, exit, err = kOverrunErr );
				sawDigit = 1;
			}
		}
		else if( ( c == '.' ) && sawDigit )
		{
			require_action_quiet( segments < 4, exit, err = kMalformedErr );
			*++dst = 0;
			sawDigit = 0;
		}
		else
		{
			break;
		}
	}
	require_action_quiet( segments == 4, exit, err = kUnderrunErr );
	
	*outStr = inStr;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	StringToIPv4Address
//
//	Note: This was copied from CoreUtils because the StringToIPv4Address function is currently not exported in the framework.
//===========================================================================================================================

OSStatus
	StringToIPv4Address( 
		const char *			inStr, 
		StringToIPAddressFlags	inFlags, 
		uint32_t *				outIP, 
		int *					outPort, 
		uint32_t *				outSubnet, 
		uint32_t *				outRouter, 
		const char **			outStr )
{
	OSStatus			err;
	uint8_t				buf[ 4 ];
	int					c;
	uint32_t			ip;
	int					hasPort;
	int					port;
	int					hasPrefix;
	int					prefix;
	uint32_t			subnetMask;
	uint32_t			router;
	
	require_action( inStr, exit, err = kParamErr );
	
	// Parse the address-only part of the address (e.g. "1.2.3.4").
	
	err = ParseIPv4Address( inStr, buf, &inStr );
	require_noerr_quiet( err, exit );
	ip = (uint32_t)( ( buf[ 0 ] << 24 ) | ( buf[ 1 ] << 16 ) | ( buf[ 2 ] << 8 ) | buf[ 3 ] );
	c = *inStr;
	
	// Parse the port (if any).
	
	hasPort = 0;
	port    = 0;
	if( c == ':' )
	{
		require_action_quiet( !( inFlags & kStringToIPAddressFlagsNoPort ), exit, err = kUnexpectedErr );
		while( ( ( c = *( ++inStr ) ) != '\0' ) && ( ( c >= '0' ) && ( c <= '9' ) ) ) port = ( port * 10 ) + ( c - '0' );
		require_action_quiet( port <= 65535, exit, err = kRangeErr );
		hasPort = 1;
	}
	
	// Parse the prefix length (if any).
	
	hasPrefix  = 0;
	prefix     = 0;
	subnetMask = 0;
	router     = 0;
	if( c == '/' )
	{
		require_action_quiet( !( inFlags & kStringToIPAddressFlagsNoPrefix ), exit, err = kUnexpectedErr );
		while( ( ( c = *( ++inStr ) ) != '\0' ) && ( ( c >= '0' ) && ( c <= '9' ) ) ) prefix = ( prefix * 10 ) + ( c - '0' );
		require_action_quiet( ( prefix >= 0 ) && ( prefix <= 32 ), exit, err = kRangeErr );
		hasPrefix = 1;
		
		subnetMask = ( prefix > 0 ) ? ( UINT32_C( 0xFFFFFFFF ) << ( 32 - prefix ) ) : 0;
		router	   = ( ip & subnetMask ) | 1;
	}
	
	// Return the results. Only fill in port/prefix/router results if the info was found to allow for defaults.
	
	if( outIP )					 *outIP		= ip;
	if( outPort   && hasPort )	 *outPort	= port;
	if( outSubnet && hasPrefix ) *outSubnet	= subnetMask;
	if( outRouter && hasPrefix ) *outRouter	= router;
	if( outStr )				 *outStr	= inStr;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	ParseIPv6Address
//
//	Note: Parsed according to the rules specified in RFC 3513.
//	Warning: "inBuffer" may be modified even in error cases.
//
//	Note: This was copied from CoreUtils because the StringToIPv6Address function is currently not exported in the framework.
//===========================================================================================================================

static OSStatus	ParseIPv6Address( const char *inStr, int inAllowV4Mapped, uint8_t inBuffer[ 16 ], const char **outStr )
{
													// Table to map uppercase hex characters - '0' to their numeric values.
													// 0  1  2  3  4  5  6  7  8  9  :  ;  <  =  >  ?  @  A   B   C   D   E   F
	static const uint8_t		kASCIItoHexTable[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, 0, 10, 11, 12, 13, 14, 15 };
	OSStatus					err;
	const char *				ptr;
	uint8_t *					dst;
	uint8_t *					lim;
	uint8_t *					colonPtr;
	int							c;
	int							sawDigit;
	unsigned int				v;
	int							i;
	int							n;
	
	// Pre-zero the address to simplify handling of compressed addresses (e.g. "::1").
	
	for( i = 0; i < 16; ++i ) inBuffer[ i ] = 0;
	
	// Special case leading :: (e.g. "::1") to simplify processing later.
	
	if( *inStr == ':' )
	{
		++inStr;
		require_action_quiet( *inStr == ':', exit, err = kMalformedErr );
	}
	
	// Parse the address.
	
	ptr		 = inStr;
	dst		 = inBuffer;
	lim		 = dst + 16;
	colonPtr = NULL;
	sawDigit = 0;
	v		 = 0;
	while( ( ( c = *inStr++ ) != '\0' ) && ( c != '%' ) && ( c != '/' ) && ( c != ']' ) )
	{
		if(   ( c >= 'a' ) && ( c <= 'f' ) ) c -= ( 'a' - 'A' );
		if( ( ( c >= '0' ) && ( c <= '9' ) ) || ( ( c >= 'A' ) && ( c <= 'F' ) ) )
		{
			c -= '0';
			check( c < (int) countof( kASCIItoHexTable ) );
			v = ( v << 4 ) | kASCIItoHexTable[ c ];
			require_action_quiet( v <= 0xFFFF, exit, err = kRangeErr );
			sawDigit = 1;
			continue;
		}
		if( c == ':' )
		{
			ptr = inStr;
			if( !sawDigit )
			{
				require_action_quiet( !colonPtr, exit, err = kMalformedErr );
				colonPtr = dst;
				continue;
			}
			require_action_quiet( *inStr != '\0', exit, err = kUnderrunErr );
			require_action_quiet( ( dst + 2 ) <= lim, exit, err = kOverrunErr );
			*dst++ = (uint8_t)( ( v >> 8 ) & 0xFF );
			*dst++ = (uint8_t)(   v        & 0xFF );
			sawDigit = 0;
			v = 0;
			continue;
		}
		
		// Handle IPv4-mapped/compatible addresses (e.g. ::FFFF:1.2.3.4).
		
		if( inAllowV4Mapped && ( c == '.' ) && ( ( dst + 4 ) <= lim ) )
		{
			err = ParseIPv4Address( ptr, dst, &inStr );
			require_noerr_quiet( err, exit );
			dst += 4;
			sawDigit = 0;
			++inStr; // Increment because the code below expects the end to be at "inStr - 1".
		}
		break;
	}
	if( sawDigit )
	{
		require_action_quiet( ( dst + 2 ) <= lim, exit, err = kOverrunErr );
		*dst++ = (uint8_t)( ( v >> 8 ) & 0xFF );
		*dst++ = (uint8_t)(   v        & 0xFF );
	}
	check( dst <= lim );
	if( colonPtr )
	{
		require_action_quiet( dst < lim, exit, err = kOverrunErr );
		n = (int)( dst - colonPtr );
		for( i = 1; i <= n; ++i )
		{
			lim[ -i ] = colonPtr[ n - i ];
			colonPtr[ n - i ] = 0;
		}
		dst = lim;
	}
	require_action_quiet( dst == lim, exit, err = kUnderrunErr );
	
	*outStr = inStr - 1;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	ParseIPv6Scope
//
//	Note: This was copied from CoreUtils because the StringToIPv6Address function is currently not exported in the framework.
//===========================================================================================================================

static OSStatus	ParseIPv6Scope( const char *inStr, uint32_t *outScope, const char **outStr )
{
#if( TARGET_OS_POSIX )
	OSStatus			err;
	char				scopeStr[ 64 ];
	char *				dst;
	char *				lim;
	int					c;
	uint32_t			scope;
	const char *		ptr;
	
	// Copy into a local NULL-terminated string since that is what if_nametoindex expects.
	
	dst = scopeStr;
	lim = dst + ( countof( scopeStr ) - 1 );
	while( ( ( c = *inStr ) != '\0' ) && ( c != ':' ) && ( c != '/' ) && ( c != ']' ) && ( dst < lim ) )
	{
		*dst++ = *inStr++;
	}
	*dst = '\0';
	check( dst <= lim );
	
	// First try to map as a name and if that fails, treat it as a numeric scope.
	
	scope = if_nametoindex( scopeStr );
	if( scope == 0 )
	{
		for( ptr = scopeStr; ( ( c = *ptr ) >= '0' ) && ( c <= '9' ); ++ptr )
		{
			scope = ( scope * 10 ) + ( ( (uint8_t) c ) - '0' );
		}
		require_action_quiet( c == '\0', exit, err = kMalformedErr );
		require_action_quiet( ( ptr != scopeStr ) && ( ( (int)( ptr - scopeStr ) ) <= 10 ), exit, err = kMalformedErr );
	}
	
	*outScope = scope;
	*outStr   = inStr;
	err = kNoErr;
	
exit:
	return( err );
#else
	OSStatus			err;
	uint32_t			scope;
	const char *		start;
	int					c;
	
	scope = 0;
	for( start = inStr; ( ( c = *inStr ) >= '0' ) && ( c <= '9' ); ++inStr )
	{
		scope = ( scope * 10 ) + ( c - '0' );
	}
	require_action_quiet( ( inStr != start ) && ( ( (int)( inStr - start ) ) <= 10 ), exit, err = kMalformedErr );
	
	*outScope = scope;
	*outStr   = inStr;
	err = kNoErr;
	
exit:
	return( err );
#endif
}

//===========================================================================================================================
//	StringToIPv6Address
//
//	Note: This was copied from CoreUtils because the StringToIPv6Address function is currently not exported in the framework.
//===========================================================================================================================

OSStatus
	StringToIPv6Address( 
		const char *			inStr, 
		StringToIPAddressFlags	inFlags, 
		uint8_t					outIPv6[ 16 ], 
		uint32_t *				outScope, 
		int *					outPort, 
		int *					outPrefix, 
		const char **			outStr )
{
	OSStatus		err;
	uint8_t			ipv6[ 16 ];
	int				c;
	int				hasScope;
	uint32_t		scope;
	int				hasPort;
	int				port;
	int				hasPrefix;
	int				prefix;
	int				hasBracket;
	int				i;
	
	require_action( inStr, exit, err = kParamErr );
	
	if( *inStr == '[' ) ++inStr; // Skip a leading bracket for []-wrapped addresses (e.g. "[::1]:80").
	
	// Parse the address-only part of the address (e.g. "1::1").
	
	err = ParseIPv6Address( inStr, !( inFlags & kStringToIPAddressFlagsNoIPv4Mapped ), ipv6, &inStr );
	require_noerr_quiet( err, exit );
	c = *inStr;
	
	// Parse the scope, port, or prefix length.
	
	hasScope	= 0;
	scope		= 0;
	hasPort		= 0;
	port		= 0;
	hasPrefix	= 0;
	prefix		= 0;
	hasBracket	= 0;
	for( ;; )
	{
		if( c == '%' )		// Scope (e.g. "%en0" or "%5")
		{
			require_action_quiet( !hasScope, exit, err = kMalformedErr );
			require_action_quiet( !( inFlags & kStringToIPAddressFlagsNoScope ), exit, err = kUnexpectedErr );
			++inStr;
			err = ParseIPv6Scope( inStr, &scope, &inStr );
			require_noerr_quiet( err, exit );
			hasScope = 1;
			c = *inStr;
		}
		else if( c == ':' )	// Port (e.g. ":80")
		{
			require_action_quiet( !hasPort, exit, err = kMalformedErr );
			require_action_quiet( !( inFlags & kStringToIPAddressFlagsNoPort ), exit, err = kUnexpectedErr );
			while( ( ( c = *( ++inStr ) ) != '\0' ) && ( ( c >= '0' ) && ( c <= '9' ) ) ) port = ( port * 10 ) + ( c - '0' );
			require_action_quiet( port <= 65535, exit, err = kRangeErr );
			hasPort = 1;
		}
		else if( c == '/' )	// Prefix Length (e.g. "/64")
		{
			require_action_quiet( !hasPrefix, exit, err = kMalformedErr );
			require_action_quiet( !( inFlags & kStringToIPAddressFlagsNoPrefix ), exit, err = kUnexpectedErr );
			while( ( ( c = *( ++inStr ) ) != '\0' ) && ( ( c >= '0' ) && ( c <= '9' ) ) ) prefix = ( prefix * 10 ) + ( c - '0' );
			require_action_quiet( ( prefix >= 0 ) && ( prefix <= 128 ), exit, err = kRangeErr );
			hasPrefix = 1;
		}
		else if( c == ']' )
		{
			require_action_quiet( !hasBracket, exit, err = kMalformedErr );
			hasBracket = 1;
			c = *( ++inStr );
		}
		else
		{
			break;
		}
	}
	
	// Return the results. Only fill in scope/port/prefix results if the info was found to allow for defaults.
	
	if( outIPv6 )				 for( i = 0; i < 16; ++i ) outIPv6[ i ] = ipv6[ i ];
	if( outScope  && hasScope )  *outScope	= scope;
	if( outPort   && hasPort )   *outPort	= port;
	if( outPrefix && hasPrefix ) *outPrefix	= prefix;
	if( outStr )				 *outStr	= inStr;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
//	StringArray_Free
//
//	Note: This was copied from CoreUtils because the StringArray_Free function is currently not exported in the framework.
//===========================================================================================================================

void	StringArray_Free( char **inArray, size_t inCount )
{
	size_t		i;
	
	for( i = 0; i < inCount; ++i )
	{
		free( inArray[ i ] );
	}
	if( inCount > 0 ) free( inArray );
}

//===========================================================================================================================
//	ParseQuotedEscapedString
//
//	Note: This was copied from CoreUtils because it's currently not exported in the framework.
//===========================================================================================================================

Boolean
	ParseQuotedEscapedString( 
		const char *	inSrc, 
		const char *	inEnd, 
		const char *	inDelimiters, 
		char *			inBuf, 
		size_t			inMaxLen, 
		size_t *		outCopiedLen, 
		size_t *		outTotalLen, 
		const char **	outSrc )
{
	const unsigned char *		src;
	const unsigned char *		end;
	unsigned char *				dst;
	unsigned char *				lim;
	unsigned char				c;
	unsigned char				c2;
	size_t						totalLen;
	Boolean						singleQuote;
	Boolean						doubleQuote;
	
	if( inEnd == NULL ) inEnd = inSrc + strlen( inSrc );
	src = (const unsigned char *) inSrc;
	end = (const unsigned char *) inEnd;
	dst = (unsigned char *) inBuf;
	lim = dst + inMaxLen;
	while( ( src < end ) && isspace_safe( *src ) ) ++src; // Skip leading spaces.
	if( src >= end ) return( false );
	
	// Parse each argument from the string.
	//
	// See <http://resources.mpi-inf.mpg.de/departments/rg1/teaching/unixffb-ss98/quoting-guide.html> for details.
	
	totalLen = 0;
	singleQuote = false;
	doubleQuote = false;
	while( src < end )
	{
		c = *src++;
		if( singleQuote )
		{
			// Single quotes protect everything (even backslashes, newlines, etc.) except single quotes.
			
			if( c == '\'' )
			{
				singleQuote = false;
				continue;
			}
		}
		else if( doubleQuote )
		{
			// Double quotes protect everything except double quotes and backslashes. A backslash can be 
			// used to protect " or \ within double quotes. A backslash-newline pair disappears completely.
			// A backslash followed by x or X and 2 hex digits (e.g. "\x1f") is stored as that hex byte.
			// A backslash followed by 3 octal digits (e.g. "\377") is stored as that octal byte.
			// A backslash that does not precede ", \, x, X, or a newline is taken literally.
			
			if( c == '"' )
			{
				doubleQuote = false;
				continue;
			}
			else if( c == '\\' )
			{
				if( src < end )
				{
					c2 = *src;
					if( ( c2 == '"' ) || ( c2 == '\\' ) )
					{
						++src;
						c = c2;
					}
					else if( c2 == '\n' )
					{
						++src;
						continue;
					}
					else if( ( c2 == 'x' ) || ( c2 == 'X' ) )
					{
						++src;
						c = c2;
						if( ( ( end - src ) >= 2 ) && IsHexPair( src ) )
						{
							c = HexPairToByte( src );
							src += 2;
						}
					}
					else if( isoctal_safe( c2 ) )
					{
						if( ( ( end - src ) >= 3 ) && IsOctalTriple( src ) )
						{
							c = OctalTripleToByte( src );
							src += 3;
						}
					}
				}
			}
		}
		else if( strchr( inDelimiters, c ) )
		{
			break;
		}
		else if( c == '\\' )
		{
			// A backslash protects the next character, except a newline, x, X and 2 hex bytes or 3 octal bytes. 
			// A backslash followed by a newline disappears completely.
			// A backslash followed by x or X and 2 hex digits (e.g. "\x1f") is stored as that hex byte.
			// A backslash followed by 3 octal digits (e.g. "\377") is stored as that octal byte.
			
			if( src < end )
			{
				c = *src;
				if( c == '\n' )
				{
					++src;
					continue;
				}
				else if( ( c == 'x' ) || ( c == 'X' ) )
				{
					++src;
					if( ( ( end - src ) >= 2 ) && IsHexPair( src ) )
					{
						c = HexPairToByte( src );
						src += 2;
					}
				}
				else if( isoctal_safe( c ) )
				{
					if( ( ( end - src ) >= 3 ) && IsOctalTriple( src ) )
					{
						c = OctalTripleToByte( src );
						src += 3;
					}
					else
					{
						++src;
					}
				}
				else
				{
					++src;
				}
			}
		}
		else if( c == '\'' )
		{
			singleQuote = true;
			continue;
		}
		else if( c == '"' )
		{
			doubleQuote = true;
			continue;
		}
		
		if( dst < lim )
		{
			if( inBuf ) *dst = c;
			++dst;
		}
		++totalLen;
	}
	
	if( outCopiedLen )	*outCopiedLen	= (size_t)( dst - ( (unsigned char *) inBuf ) );
	if( outTotalLen )	*outTotalLen	= totalLen;
	if( outSrc )		*outSrc			= (const char *) src;
	return( true );
}

//===========================================================================================================================
//	_ServerSocketOpenEx2
//
//	Note: Based on ServerSocketOpenEx() from CoreUtils. Added parameter to not use SO_REUSEPORT.
//===========================================================================================================================

static OSStatus
	_ServerSocketOpenEx2( 
		int				inFamily, 
		int				inType, 
		int				inProtocol, 
		const void *	inAddr, 
		int				inPort, 
		int *			outPort, 
		int				inRcvBufSize, 
		Boolean			inNoPortReuse,
		SocketRef *		outSock )
{
	OSStatus		err;
	int				port;
	SocketRef		sock;
	int				name;
	int				option;
	sockaddr_ip		sip;
	socklen_t		len;
	
	port = ( inPort < 0 ) ? -inPort : inPort; // Negated port number means "try this port, but allow dynamic".
	
	sock = socket( inFamily, inType, inProtocol );
	err = map_socket_creation_errno( sock );
	require_noerr_quiet( err, exit );
	
#if( defined( SO_NOSIGPIPE ) )
	setsockopt( sock, SOL_SOCKET, SO_NOSIGPIPE, &(int){ 1 }, (socklen_t) sizeof( int ) );
#endif
	
	err = SocketMakeNonBlocking( sock );
	require_noerr( err, exit );
	
	// Set receive buffer size. This has to be done on the listening socket *before* listen is called because
	// accept does not return until after the window scale option is exchanged during the 3-way handshake. 
	// Since accept returns a new socket, the only way to use a larger window scale option is to set the buffer
	// size on the listening socket since SO_RCVBUF is inherited by the accepted socket. See UNPv1e3 Section 7.5.
	
	err = SocketSetBufferSize( sock, SO_RCVBUF, inRcvBufSize );
	check_noerr( err );
	
	// Allow port or address reuse because we may bind separate IPv4 and IPv6 sockets to the same port.
	
	if( ( inType != SOCK_DGRAM ) || !inNoPortReuse )
	{
		option = 1;
		name = ( inType == SOCK_DGRAM ) ? SO_REUSEPORT : SO_REUSEADDR;
		err = setsockopt( sock, SOL_SOCKET, name, (char *) &option, (socklen_t) sizeof( option ) );
		err = map_socket_noerr_errno( sock, err );
		require_noerr( err, exit );
	}
	
	if( inFamily == AF_INET )
	{
		// Bind to the port. If it fails, retry with a dynamic port.
		
		memset( &sip.v4, 0, sizeof( sip.v4 ) );
		SIN_LEN_SET( &sip.v4 );
		sip.v4.sin_family		= AF_INET;
		sip.v4.sin_port			= htons( (uint16_t) port );
		sip.v4.sin_addr.s_addr	= inAddr ? *( (const uint32_t *) inAddr ) : htonl( INADDR_ANY );
		err = bind( sock, &sip.sa, (socklen_t) sizeof( sip.v4 ) );
		err = map_socket_noerr_errno( sock, err );
		if( err && ( inPort < 0 ) )
		{
			sip.v4.sin_port = 0;
			err = bind( sock, &sip.sa, (socklen_t) sizeof( sip.v4 ) );
			err = map_socket_noerr_errno( sock, err );
		}
		require_noerr( err, exit );
	}
#if( defined( AF_INET6 ) )
	else if( inFamily == AF_INET6 )
	{
		// Restrict this socket to IPv6 only because we're going to use a separate socket for IPv4.
		
		option = 1;
		err = setsockopt( sock, IPPROTO_IPV6, IPV6_V6ONLY, (char *) &option, (socklen_t) sizeof( option ) );
		err = map_socket_noerr_errno( sock, err );
		require_noerr( err, exit );
		
		// Bind to the port. If it fails, retry with a dynamic port.
		
		memset( &sip.v6, 0, sizeof( sip.v6 ) );
		SIN6_LEN_SET( &sip.v6 );
		sip.v6.sin6_family	= AF_INET6;
		sip.v6.sin6_port	= htons( (uint16_t) port );
		sip.v6.sin6_addr	= inAddr ? *( (const struct in6_addr *) inAddr ) : in6addr_any;	
		err = bind( sock, &sip.sa, (socklen_t) sizeof( sip.v6 ) );
		err = map_socket_noerr_errno( sock, err );
		if( err && ( inPort < 0 ) )
		{
			sip.v6.sin6_port = 0;
			err = bind( sock, &sip.sa, (socklen_t) sizeof( sip.v6 ) );
			err = map_socket_noerr_errno( sock, err );
		}
		require_noerr( err, exit );
	}
#endif
	else
	{
		dlogassert( "Unsupported family: %d", inFamily );
		err = kUnsupportedErr;
		goto exit;
	}
	
	if( inType == SOCK_STREAM )
	{
		err = listen( sock, SOMAXCONN );
		err = map_socket_noerr_errno( sock, err );
		if( err )
		{
			err = listen( sock, 5 );
			err = map_socket_noerr_errno( sock, err );
			require_noerr( err, exit );
		}
	}
	
	if( outPort )
	{
		len = (socklen_t) sizeof( sip );
		err = getsockname( sock, &sip.sa, &len );
		err = map_socket_noerr_errno( sock, err );
		require_noerr( err, exit );
		
		*outPort = SockAddrGetPort( &sip );
	}
	*outSock = sock;
	sock = kInvalidSocketRef;
	
exit:
	ForgetSocket( &sock );
	return( err );
}

//===========================================================================================================================
//	memdup
//
//	Note: This was copied from CoreUtils because it's currently not exported in the framework.
//===========================================================================================================================

void *	memdup( const void *inPtr, size_t inLen )
{
	void *		mem;
	
	mem = malloc( ( inLen > 0 ) ? inLen : 1 ); // If inLen is 0, use 1 since malloc( 0 ) is not well defined.
	require( mem, exit );
	if( inLen > 0 ) memcpy( mem, inPtr, inLen );
	
exit:
	return( mem );
}

#if( !TARGET_OS_WINDOWS )
//===========================================================================================================================
//	memicmp
//
//	Note: This was copied from CoreUtils because it's currently not exported in the framework.
//===========================================================================================================================

int	memicmp( const void *inP1, const void *inP2, size_t inLen )
{
	const unsigned char *		p1;
	const unsigned char *		e1;
	const unsigned char *		p2;
	int							c1;
	int							c2;
	
	p1 = (const unsigned char *) inP1;
	e1 = p1 + inLen;
	p2 = (const unsigned char *) inP2;
	while( p1 < e1 )
	{
		c1 = *p1++;
		c2 = *p2++;
		c1 = tolower( c1 );
		c2 = tolower( c2 );
		if( c1 < c2 ) return( -1 );
		if( c1 > c2 ) return(  1 );
	}
	return( 0 );
}
#endif
