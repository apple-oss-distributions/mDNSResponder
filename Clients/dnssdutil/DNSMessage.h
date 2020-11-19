/*
	Copyright (c) 2016-2020 Apple Inc. All rights reserved.
*/

#ifndef	__DNSMessage_h
#define	__DNSMessage_h

#include <CoreUtils/CommonServices.h>

CU_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		DNS domain name size limits
	
	@discussion See <https://tools.ietf.org/html/rfc1035#section-2.3.4>.
*/
#define kDomainLabelLengthMax		63
#define kDomainNameLengthMax		256	// For compatibility with mDNS. See <https://tools.ietf.org/html/rfc6762#appendix-C>.

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		DNS message header
*/
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

#define kDNSHeaderFlag_Response					( 1U << 15 )	// QR (bit 15), Query (0)/Response (1)
#define kDNSHeaderFlag_AuthAnswer				( 1U << 10 )	// AA (bit 10), Authoritative Answer
#define kDNSHeaderFlag_Truncation				( 1U <<  9 )	// TC (bit  9), TrunCation
#define kDNSHeaderFlag_RecursionDesired			( 1U <<  8 )	// RD (bit  8), Recursion Desired
#define kDNSHeaderFlag_RecursionAvailable		( 1U <<  7 )	// RA (bit  7), Recursion Available
#define kDNSHeaderFlag_Z						( 1U <<  6 )	//  Z (bit  6), Reserved (must be zero)
#define kDNSHeaderFlag_AuthenticData			( 1U <<  5 )	// AD (bit  5), Authentic Data (RFC 2535, Section 6)
#define kDNSHeaderFlag_CheckingDisabled			( 1U <<  4 )	// CD (bit  4), Checking Disabled (RFC 2535, Section 6)

// OPCODE (bits 14-11), Operation Code

#define DNSFlagsGetOpCode( FLAGS )		( ( (FLAGS) >> 11 ) & 0x0FU )
#define DNSFlagsSetOpCode( FLAGS, OPCODE ) \
		do { (FLAGS) = ( (FLAGS) & ~0x7800U ) | ( ( (OPCODE) & 0x0FU ) << 11 ); } while( 0 )

#define kDNSOpCode_Query			0	// QUERY (standard query)
#define kDNSOpCode_InverseQuery		1	// IQUERY (inverse query)
#define kDNSOpCode_Status			2	// STATUS
#define kDNSOpCode_Notify			4	// NOTIFY
#define kDNSOpCode_Update			5	// UPDATE

// RCODE (bits 3-0), Response Code

#define DNSFlagsGetRCode( FLAGS )				( (FLAGS) & 0x0FU )
#define DNSFlagsSetRCode( FLAGS, RCODE ) \
	do { (FLAGS) = ( (FLAGS) & ~0x000FU ) | ( ( (unsigned int)(RCODE) ) & 0x0FU ); } while( 0 )

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		Multicast DNS Constants
*/

#define kMDNSClassUnicastResponseBit		( 1U << 15 ) // See <https://tools.ietf.org/html/rfc6762#section-18.12>.
#define kMDNSClassCacheFlushBit				( 1U << 15 ) // See <https://tools.ietf.org/html/rfc6762#section-18.13>.

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		Misc. DNS message data structures
*/

#define _DNSMessageGet8( PTR )			Read8( PTR )
#define _DNSMessageGet16( PTR )			ReadBig16( PTR )
#define _DNSMessageGet32( PTR )			ReadBig32( PTR )
#define _DNSMessageSet8( PTR, X )		Write8( PTR, X )
#define _DNSMessageSet16( PTR, X )		WriteBig16( PTR, X )
#define _DNSMessageSet32( PTR, X )		WriteBig32( PTR, X )

#define dns_fields_define_accessors( PREFIX, TYPE, FIELD, BIT_SIZE )	\
	STATIC_INLINE uint ## BIT_SIZE ## _t								\
		dns_ ## PREFIX ## _ ## TYPE ## _get_ ## FIELD (					\
			const dns_ ## PREFIX ## _ ## TYPE *	inFields )				\
	{																	\
		return _DNSMessageGet ## BIT_SIZE ( inFields->FIELD );			\
	}																	\
																		\
	STATIC_INLINE void													\
		dns_ ## PREFIX ## _ ## TYPE ## _set_ ## FIELD (					\
			dns_ ## PREFIX ## _ ## TYPE *	inFields,					\
			uint ## BIT_SIZE ## _t			inValue )					\
	{																	\
		_DNSMessageSet ## BIT_SIZE ( inFields->FIELD, inValue );		\
	}																	\
	check_compile_time( ( sizeof_field( dns_ ## PREFIX ## _ ## TYPE, FIELD ) * 8 ) == (BIT_SIZE) )

#define dns_fixed_fields_define_accessors( TYPE, FIELD, BIT_SIZE ) \
	dns_fields_define_accessors( fixed_fields, TYPE, FIELD, BIT_SIZE )

#define dns_dnskey_fields_define_accessors( TYPE, FIELD, BIT_SIZE ) \
	dns_fields_define_accessors( dnskey, TYPE, FIELD, BIT_SIZE )

#define dns_ds_fields_define_accessors( TYPE, FIELD, BIT_SIZE ) \
	dns_fields_define_accessors( ds, TYPE, FIELD, BIT_SIZE )

// DNS question fixed-length fields
// See <https://tools.ietf.org/html/rfc1035#section-4.1.2>

typedef struct
{
	uint8_t		type[ 2 ];
	uint8_t		class[ 2 ];
	
}	dns_fixed_fields_question;

check_compile_time( sizeof( dns_fixed_fields_question ) == 4 );

dns_fixed_fields_define_accessors( question, type,  16 );
dns_fixed_fields_define_accessors( question, class, 16 );

STATIC_INLINE void
	dns_fixed_fields_question_init(
		dns_fixed_fields_question *	inFields,
		uint16_t					inQType,
		uint16_t					inQClass )
{
	dns_fixed_fields_question_set_type( inFields, inQType );
	dns_fixed_fields_question_set_class( inFields, inQClass );
}

// DNS resource record fixed-length fields
// See <https://tools.ietf.org/html/rfc1035#section-4.1.3>

typedef struct
{
	uint8_t		type[ 2 ];
	uint8_t		class[ 2 ];
	uint8_t		ttl[ 4 ];
	uint8_t		rdlength[ 2 ];
	
}	dns_fixed_fields_record;

check_compile_time( sizeof( dns_fixed_fields_record ) == 10 );

dns_fixed_fields_define_accessors( record, type,     16 );
dns_fixed_fields_define_accessors( record, class,    16 );
dns_fixed_fields_define_accessors( record, ttl,      32 );
dns_fixed_fields_define_accessors( record, rdlength, 16 );

STATIC_INLINE void
	dns_fixed_fields_record_init(
		dns_fixed_fields_record *	inFields,
		uint16_t					inType,
		uint16_t					inClass,
		uint32_t					inTTL,
		uint16_t					inRDLength )
{
	dns_fixed_fields_record_set_type( inFields, inType );
	dns_fixed_fields_record_set_class( inFields, inClass );
	dns_fixed_fields_record_set_ttl( inFields, inTTL );
	dns_fixed_fields_record_set_rdlength( inFields, inRDLength );
}

// DNS SRV record data fixed-length fields
// See <https://tools.ietf.org/html/rfc2782>

typedef struct
{
	uint8_t		priority[ 2 ];
	uint8_t		weight[ 2 ];
	uint8_t		port[ 2 ];
	
}	dns_fixed_fields_srv;

check_compile_time( sizeof( dns_fixed_fields_srv ) == 6 );

dns_fixed_fields_define_accessors( srv, priority, 16 );
dns_fixed_fields_define_accessors( srv, weight,   16 );
dns_fixed_fields_define_accessors( srv, port,     16 );

STATIC_INLINE void
	dns_fixed_fields_srv_init(
		dns_fixed_fields_srv *	inFields,
		uint16_t				inPriority,
		uint16_t				inWeight,
		uint16_t				inPort )
{
	dns_fixed_fields_srv_set_priority( inFields, inPriority );
	dns_fixed_fields_srv_set_weight( inFields, inWeight );
	dns_fixed_fields_srv_set_port( inFields, inPort );
}

// DNS SOA record data fixed-length fields
// See <https://tools.ietf.org/html/rfc1035#section-3.3.13>

typedef struct
{
	uint8_t		serial[ 4 ];
	uint8_t		refresh[ 4 ];
	uint8_t		retry[ 4 ];
	uint8_t		expire[ 4 ];
	uint8_t		minimum[ 4 ];
	
}	dns_fixed_fields_soa;

check_compile_time( sizeof( dns_fixed_fields_soa ) == 20 );

dns_fixed_fields_define_accessors( soa, serial,  32 );
dns_fixed_fields_define_accessors( soa, refresh, 32 );
dns_fixed_fields_define_accessors( soa, retry,   32 );
dns_fixed_fields_define_accessors( soa, expire,  32 );
dns_fixed_fields_define_accessors( soa, minimum, 32 );

STATIC_INLINE void
	dns_fixed_fields_soa_init(
		dns_fixed_fields_soa *	inFields,
		uint32_t				inSerial,
		uint32_t				inRefresh,
		uint32_t				inRetry,
		uint32_t				inExpire,
		uint32_t				inMinimum )
{
	dns_fixed_fields_soa_set_serial( inFields, inSerial );
	dns_fixed_fields_soa_set_refresh( inFields, inRefresh );
	dns_fixed_fields_soa_set_retry( inFields, inRetry );
	dns_fixed_fields_soa_set_expire( inFields, inExpire );
	dns_fixed_fields_soa_set_minimum( inFields, inMinimum );
}

// OPT pseudo-resource record fixed-length fields without RDATA
// See <https://tools.ietf.org/html/rfc6891#section-6.1.2>

typedef struct
{
	uint8_t		name[ 1 ];
	uint8_t		type[ 2 ];
	uint8_t		udp_payload_size[ 2 ];
	uint8_t		extended_rcode[ 1 ];
	uint8_t		version[ 1 ];
	uint8_t		extended_flags[ 2 ];
	uint8_t		rdlen[ 2 ];
	
}	dns_fixed_fields_opt;

check_compile_time( sizeof( dns_fixed_fields_opt ) == 11 );

#define kDNSExtendedFlag_DNSSECOK		( 1U << 15 ) // <https://tools.ietf.org/html/rfc3225#section-3>

dns_fixed_fields_define_accessors( opt, name,              8 );
dns_fixed_fields_define_accessors( opt, type,             16 );
dns_fixed_fields_define_accessors( opt, udp_payload_size, 16 );
dns_fixed_fields_define_accessors( opt, extended_rcode,    8 );
dns_fixed_fields_define_accessors( opt, version,           8 );
dns_fixed_fields_define_accessors( opt, extended_flags,   16 );
dns_fixed_fields_define_accessors( opt, rdlen,            16 );

// OPT pseudo-resource record fixed-length fields with OPTION-CODE and OPTION-LENGTH
// See <https://tools.ietf.org/html/rfc6891#section-6.1.2>

typedef struct
{
	uint8_t		name[ 1 ];
	uint8_t		type[ 2 ];
	uint8_t		udp_payload_size[ 2 ];
	uint8_t		extended_rcode[ 1 ];
	uint8_t		version[ 1 ];
	uint8_t		extended_flags[ 2 ];
	uint8_t		rdlen[ 2 ];
	uint8_t		option_code[ 2 ];
	uint8_t		option_length[ 2 ];
	
}	dns_fixed_fields_opt1;

check_compile_time( sizeof( dns_fixed_fields_opt1 ) == 15 );

dns_fixed_fields_define_accessors( opt1, name,              8 );
dns_fixed_fields_define_accessors( opt1, type,             16 );
dns_fixed_fields_define_accessors( opt1, udp_payload_size, 16 );
dns_fixed_fields_define_accessors( opt1, extended_rcode,    8 );
dns_fixed_fields_define_accessors( opt1, version,           8 );
dns_fixed_fields_define_accessors( opt1, extended_flags,   16 );
dns_fixed_fields_define_accessors( opt1, rdlen,            16 );
dns_fixed_fields_define_accessors( opt1, option_code,      16 );
dns_fixed_fields_define_accessors( opt1, option_length,    16 );

// OPT pseudo-resource record RDATA option fixed-length fields
// See <https://tools.ietf.org/html/rfc6891#section-6.1.2>

typedef struct
{
	uint8_t		code[ 2 ];
	uint8_t		length[ 2 ];
	
}	dns_fixed_fields_option;

check_compile_time( sizeof( dns_fixed_fields_option ) == 4 );

dns_fixed_fields_define_accessors( option, code,   16 );
dns_fixed_fields_define_accessors( option, length, 16 );

// DNS DNSKEY record data fixed-length fields
// See <https://tools.ietf.org/html/rfc4034#section-2.1>

typedef struct
{
	uint8_t		flags[ 2 ];
	uint8_t		protocol[ 1 ];
	uint8_t		algorithm[ 1 ];
	
}	dns_fixed_fields_dnskey;

check_compile_time( sizeof( dns_fixed_fields_dnskey ) == 4 );

dns_fixed_fields_define_accessors( dnskey, flags,     16 );
dns_fixed_fields_define_accessors( dnskey, protocol,   8 );
dns_fixed_fields_define_accessors( dnskey, algorithm,  8 );

#define kDNSKeyFlag_ZoneKey		( 1U << ( 15 -  7 ) )	// MSB bit 7  <https://tools.ietf.org/html/rfc4034#section-2.1.1>
#define kDNSKeyFlag_SEP			( 1U << ( 15 - 15 ) )	// MSB bit 15 <https://tools.ietf.org/html/rfc4034#section-2.1.1>

#define kDNSKeyProtocol_DNSSEC		3	// Protocol value must be 3. <https://tools.ietf.org/html/rfc4034#section-2.1.2>

// DNSSEC Algoritm Numbers
// See <https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1>

#define kDNSSECAlgorithm_RSASHA1			 5	// RSA/SHA-1
#define kDNSSECAlgorithm_RSASHA256			 8	// RSA/SHA-256
#define kDNSSECAlgorithm_RSASHA512			10	// RSA/SHA-512
#define kDNSSECAlgorithm_ECDSAP256SHA256	13	// ECDSA P-256 curve/SHA-256
#define kDNSSECAlgorithm_ECDSAP384SHA384	14	// ECDSA P-384 curve/SHA-384
#define kDNSSECAlgorithm_Ed25519			15	// Ed25519

// DNS RRSIG record data fixed-length fields
// See <https://tools.ietf.org/html/rfc4034#section-3.1>

typedef struct
{
	uint8_t		type_covered[ 2 ];
	uint8_t		algorithm[ 1 ];
	uint8_t		labels[ 1 ];
	uint8_t		original_ttl[ 4 ];
	uint8_t		signature_expiration[ 4 ];
	uint8_t		signature_inception[ 4 ];
	uint8_t		key_tag[ 2 ];
	
}	dns_fixed_fields_rrsig;

check_compile_time( sizeof( dns_fixed_fields_rrsig ) == 18 );

dns_fixed_fields_define_accessors( rrsig, type_covered,         16 );
dns_fixed_fields_define_accessors( rrsig, algorithm,             8 );
dns_fixed_fields_define_accessors( rrsig, labels,                8 );
dns_fixed_fields_define_accessors( rrsig, original_ttl,         32 );
dns_fixed_fields_define_accessors( rrsig, signature_expiration, 32 );
dns_fixed_fields_define_accessors( rrsig, signature_inception,  32 );
dns_fixed_fields_define_accessors( rrsig, key_tag,              16 );

// DNS DS record data fixed-length fields
// See <https://tools.ietf.org/html/rfc4034#section-5.1>

typedef struct
{
	uint8_t		key_tag[ 2 ];
	uint8_t		algorithm[ 1 ];
	uint8_t		digest_type[ 1 ];
	
}	dns_fixed_fields_ds;

check_compile_time( sizeof( dns_fixed_fields_ds ) == 4 );

dns_fixed_fields_define_accessors( ds, key_tag,     16 );
dns_fixed_fields_define_accessors( ds, algorithm,    8 );
dns_fixed_fields_define_accessors( ds, digest_type,  8 );

#define kDSDigestType_SHA1			1	// SHA-1   <https://tools.ietf.org/html/rfc4034#appendix-A.2>
#define kDSDigestType_SHA256		2	// SHA-256 <https://tools.ietf.org/html/rfc4509#section-5>

// DNS DS record data
// See <https://tools.ietf.org/html/rfc4509#section-2.2>

typedef struct
{
	uint8_t		key_tag[ 2 ];
	uint8_t		algorithm[ 1 ];
	uint8_t		digest_type[ 1 ];
	uint8_t		digest[ 32 ];
	
}	dns_ds_sha256;

check_compile_time( sizeof( dns_ds_sha256 ) == 36 );

dns_ds_fields_define_accessors( sha256, key_tag,     16 );
dns_ds_fields_define_accessors( sha256, algorithm,    8 );
dns_ds_fields_define_accessors( sha256, digest_type,  8 );

// DNS NSEC3 record data fixed-length fields
// See <https://tools.ietf.org/html/rfc5155#section-3.2>

typedef struct
{
	uint8_t		hash_alg[ 1 ];
	uint8_t		flags[ 1 ];
	uint8_t		iterations[ 2 ];
	
}	dns_fixed_fields_nsec3;

check_compile_time( sizeof( dns_fixed_fields_nsec3 ) == 4 );

dns_fixed_fields_define_accessors( nsec3, hash_alg,    8 );
dns_fixed_fields_define_accessors( nsec3, flags,       8 );
dns_fixed_fields_define_accessors( nsec3, iterations, 16 );

// DNS SVCB record data fixed-length fields
// See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-00#section-2.2>

typedef struct
{
	uint8_t		priority[ 2 ];
	
}	dns_fixed_fields_svcb;

check_compile_time( sizeof( dns_fixed_fields_svcb ) == 2 );

dns_fixed_fields_define_accessors( svcb, priority, 16 );

typedef struct
{
	uint8_t		key[ 2 ];
	uint8_t		value_length[ 2 ];
	
}	dns_fixed_fields_svcb_param;

check_compile_time( sizeof( dns_fixed_fields_svcb_param ) == 4 );

dns_fixed_fields_define_accessors( svcb_param, key,          16 );
dns_fixed_fields_define_accessors( svcb_param, value_length, 16 );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		DNS record types
*/
// This code was autogenerated on 2020-06-30 by dns-rr-func-autogen version 1.3
// Data source URL: https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv
// Overrides: none

typedef enum
{
	kDNSRecordType_A          = 1,
	kDNSRecordType_NS         = 2,
	kDNSRecordType_MD         = 3,
	kDNSRecordType_MF         = 4,
	kDNSRecordType_CNAME      = 5,
	kDNSRecordType_SOA        = 6,
	kDNSRecordType_MB         = 7,
	kDNSRecordType_MG         = 8,
	kDNSRecordType_MR         = 9,
	kDNSRecordType_NULL       = 10,
	kDNSRecordType_WKS        = 11,
	kDNSRecordType_PTR        = 12,
	kDNSRecordType_HINFO      = 13,
	kDNSRecordType_MINFO      = 14,
	kDNSRecordType_MX         = 15,
	kDNSRecordType_TXT        = 16,
	kDNSRecordType_RP         = 17,
	kDNSRecordType_AFSDB      = 18,
	kDNSRecordType_X25        = 19,
	kDNSRecordType_ISDN       = 20,
	kDNSRecordType_RT         = 21,
	kDNSRecordType_NSAP       = 22,
	kDNSRecordType_NSAP_PTR   = 23,
	kDNSRecordType_SIG        = 24,
	kDNSRecordType_KEY        = 25,
	kDNSRecordType_PX         = 26,
	kDNSRecordType_GPOS       = 27,
	kDNSRecordType_AAAA       = 28,
	kDNSRecordType_LOC        = 29,
	kDNSRecordType_NXT        = 30,
	kDNSRecordType_EID        = 31,
	kDNSRecordType_NIMLOC     = 32,
	kDNSRecordType_SRV        = 33,
	kDNSRecordType_ATMA       = 34,
	kDNSRecordType_NAPTR      = 35,
	kDNSRecordType_KX         = 36,
	kDNSRecordType_CERT       = 37,
	kDNSRecordType_A6         = 38,
	kDNSRecordType_DNAME      = 39,
	kDNSRecordType_SINK       = 40,
	kDNSRecordType_OPT        = 41,
	kDNSRecordType_APL        = 42,
	kDNSRecordType_DS         = 43,
	kDNSRecordType_SSHFP      = 44,
	kDNSRecordType_IPSECKEY   = 45,
	kDNSRecordType_RRSIG      = 46,
	kDNSRecordType_NSEC       = 47,
	kDNSRecordType_DNSKEY     = 48,
	kDNSRecordType_DHCID      = 49,
	kDNSRecordType_NSEC3      = 50,
	kDNSRecordType_NSEC3PARAM = 51,
	kDNSRecordType_TLSA       = 52,
	kDNSRecordType_SMIMEA     = 53,
	kDNSRecordType_HIP        = 55,
	kDNSRecordType_NINFO      = 56,
	kDNSRecordType_RKEY       = 57,
	kDNSRecordType_TALINK     = 58,
	kDNSRecordType_CDS        = 59,
	kDNSRecordType_CDNSKEY    = 60,
	kDNSRecordType_OPENPGPKEY = 61,
	kDNSRecordType_CSYNC      = 62,
	kDNSRecordType_ZONEMD     = 63,
	kDNSRecordType_SVCB       = 64,
	kDNSRecordType_HTTPS      = 65,
	kDNSRecordType_SPF        = 99,
	kDNSRecordType_UINFO      = 100,
	kDNSRecordType_UID        = 101,
	kDNSRecordType_GID        = 102,
	kDNSRecordType_UNSPEC     = 103,
	kDNSRecordType_NID        = 104,
	kDNSRecordType_L32        = 105,
	kDNSRecordType_L64        = 106,
	kDNSRecordType_LP         = 107,
	kDNSRecordType_EUI48      = 108,
	kDNSRecordType_EUI64      = 109,
	kDNSRecordType_TKEY       = 249,
	kDNSRecordType_TSIG       = 250,
	kDNSRecordType_IXFR       = 251,
	kDNSRecordType_AXFR       = 252,
	kDNSRecordType_MAILB      = 253,
	kDNSRecordType_MAILA      = 254,
	kDNSRecordType_ANY        = 255,
	kDNSRecordType_URI        = 256,
	kDNSRecordType_CAA        = 257,
	kDNSRecordType_AVC        = 258,
	kDNSRecordType_DOA        = 259,
	kDNSRecordType_AMTRELAY   = 260,
	kDNSRecordType_TA         = 32768,
	kDNSRecordType_DLV        = 32769,
	kDNSRecordType_Reserved   = 65535,

}	DNSRecordType;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		DNS RCODEs
*/
// This code was autogenerated on 2020-06-15 by dns-rcode-func-autogen version 1.0
// Data source URL: https://www.iana.org/assignments/dns-parameters/dns-parameters-6.csv

typedef enum
{
	kDNSRCode_NoError   = 0,
	kDNSRCode_FormErr   = 1,
	kDNSRCode_ServFail  = 2,
	kDNSRCode_NXDomain  = 3,
	kDNSRCode_NotImp    = 4,
	kDNSRCode_Refused   = 5,
	kDNSRCode_YXDomain  = 6,
	kDNSRCode_YXRRSet   = 7,
	kDNSRCode_NXRRSet   = 8,
	kDNSRCode_NotAuth   = 9,
	kDNSRCode_NotZone   = 10,
	kDNSRCode_DSOTYPENI = 11
	
}	DNSRCode;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		DNS classes
*/

typedef enum
{
	kDNSClassType_IN = 1	// See <https://tools.ietf.org/html/rfc1035#section-3.2.4>.
	
}	DNSClassType;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		DNS EDNS0 Option Codes
*/
typedef enum
{
	kDNSEDNS0OptionCode_Padding = 12	// <https://tools.ietf.org/html/rfc7830#section-3>
	
}	DNSEDNS0OptionCode;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@group		DNS EDNS0 Option Codes
	@discussion	See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-00#section-12.1.2>.
*/
typedef enum
{
	kDNSSVCParamKey_Mandatory		= 0,
	kDNSSVCParamKey_ALPN			= 1,
	kDNSSVCParamKey_NoDefaultALPN	= 2,
	kDNSSVCParamKey_Port			= 3,
	kDNSSVCParamKey_IPv4Hint		= 4,
	kDNSSVCParamKey_ECHConfig		= 5,
	kDNSSVCParamKey_IPv6Hint		= 6,
	kDNSSVCParamKey_DOHURI			= 32768 // XXX: Apple Internal
	
}	DNSSVCParamKey;

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Extracts a domain name from a DNS message.
	
	@param		inMsgPtr		Pointer to the beginning of the DNS message containing the domain name.
	@param		inMsgLen		Length of the DNS message containing the domain name.
	@param		inPtr			Pointer to the domain name field.
	@param		outName			Buffer to write extracted domain name. (Optional)
	@param		outPtr			Gets set to point to the end of the domain name field. (Optional)
*/
OSStatus
	DNSMessageExtractDomainName(
		const uint8_t *							inMsgPtr,
		size_t									inMsgLen,
		const uint8_t *							inPtr,
		uint8_t									outName[ _Nullable kDomainNameLengthMax ],
		const uint8_t * _Nullable * _Nullable	outPtr );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Extracts a domain name from a DNS message as a C string.
	
	@param		inMsgPtr		Pointer to the beginning of the DNS message containing the domain name.
	@param		inMsgLen		Length of the DNS message containing the domain name.
	@param		inPtr			Pointer to the domain name field.
	@param		outName			Buffer to write extracted domain name. (Optional)
	@param		outPtr			Gets set to point to the end of the domain name field. (Optional)
*/
OSStatus
	DNSMessageExtractDomainNameString(
		const void *							inMsgPtr,
		size_t									inMsgLen,
		const void *							inPtr,
		char									outName[ _Nullable kDNSServiceMaxDomainName ],
		const uint8_t * _Nullable * _Nullable	outPtr );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Extracts a question from a DNS message.
	
	@param		inMsgPtr		Pointer to the beginning of the DNS message containing a question.
	@param		inMsgLen		Length of the DNS message containing the question.
	@param		inPtr			Pointer to the question.
	@param		outName			Buffer to write the question's QNAME. (Optional)
	@param		outType			Gets set to question's QTYPE value. (Optional)
	@param		outClass		Gets set to question's QCLASS value. (Optional)
	@param		outPtr			Gets set to point to the end of the question. (Optional)
*/
OSStatus
	DNSMessageExtractQuestion(
		const uint8_t *							inMsgPtr,
		size_t									inMsgLen,
		const uint8_t *							inPtr,
		uint8_t									outName[ _Nullable kDomainNameLengthMax ],
		uint16_t * _Nullable					outType,
		uint16_t * _Nullable					outClass,
		const uint8_t * _Nullable * _Nullable	outPtr );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Extracts a resource record from a DNS message.
	
	@param		inMsgPtr		Pointer to the beginning of the DNS message containing the resource record.
	@param		inMsgLen		Length of the DNS message containing the resource record.
	@param		inPtr			Pointer to the resource record.
	@param		outName			Buffer to write the resource record's NAME. (Optional)
	@param		outType			Gets set to resource record's TYPE value. (Optional)
	@param		outClass		Gets set to resource record's CLASS value. (Optional)
	@param		outTTL			Gets set to resource record's TTL value. (Optional)
	@param		outRDataPtr		Gets set to point to the resource record's RDATA. (Optional)
	@param		outRDataLen		Gets set to the resource record's RDLENGTH. (Optional)
	@param		outPtr			Gets set to point to the end of the resource record. (Optional)
*/
OSStatus
	DNSMessageExtractRecord(
		const uint8_t *							inMsgPtr,
		size_t									inMsgLen,
		const uint8_t *							inPtr,
		uint8_t									outName[ _Nullable kDomainNameLengthMax ],
		uint16_t * _Nullable					outType,
		uint16_t * _Nullable					outClass,
		uint32_t * _Nullable					outTTL,
		const uint8_t * _Nullable * _Nullable	outRDataPtr,
		size_t * _Nullable						outRDataLen,
		const uint8_t * _Nullable * _Nullable	outPtr );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Gets a DNS message's answer section, i.e., the end of the message's question section.
	
	@param		inMsgPtr		Pointer to the beginning of the DNS message.
	@param		inMsgLen		Length of the DNS message.
	@param		outPtr			Gets set to point to the start of the answer section. (Optional)
*/
OSStatus
	DNSMessageGetAnswerSection(
		const uint8_t *							inMsgPtr,
		size_t									inMsgLen,
		const uint8_t * _Nullable * _Nullable	outPtr );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Gets a DNS message's OPT record if it exists.
	
	@param		inMsgPtr		Pointer to the beginning of the DNS message.
	@param		inMsgLen		Length of the DNS message.
	@param		outOptPtr		Gets set to point to the start of the OPT record. (Optional)
	@param		outOptLen		Gets set to point to the length of the OPT record. (Optional)
*/
OSStatus
	DNSMessageGetOptRecord(
		const uint8_t *							inMsgPtr,
		size_t									inMsgLen,
		const uint8_t * _Nullable * _Nullable	outOptPtr,
		size_t * _Nullable						outOptLen );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Writes a DNS message compression label pointer.
	
	@param		inLabelPtr		Pointer to the two bytes to which to write the label pointer.
	@param		inOffset		The label pointer's offset value. This offset is relative to the start of the DNS message.
	
	@discussion	See <https://tools.ietf.org/html/rfc1035#section-4.1.4>.
*/
STATIC_INLINE void	DNSMessageWriteLabelPointer( uint8_t inLabelPtr[ STATIC_PARAM 2 ], size_t inOffset )
{
	inLabelPtr[ 0 ] = (uint8_t)( ( ( inOffset >> 8 ) & 0x3F ) | 0xC0 );
	inLabelPtr[ 1 ] = (uint8_t)(     inOffset        & 0xFF          );
}

#define kDNSCompressionOffsetMax			0x3FFF
#define kDNSCompressionPointerLength		2

//---------------------------------------------------------------------------------------------------------------------------
#define kDNSQueryMessageMaxLen		( kDNSHeaderLength + kDomainNameLengthMax + sizeof( dns_fixed_fields_question ) )

/*!	@brief		Writes a single-question DNS query message.
	
	@param		inMsgID			The query message's ID.
	@param		inFlags			The query message's flags.
	@param		inQName			The question's QNAME in label format.
	@param		inQType			The question's QTYPE.
	@param		inQClass		The question's QCLASS.
	@param		outMsg			Buffer to write DNS query message.
	@param		outLen			Gets set to the length of the DNS query message.
*/
OSStatus
	DNSMessageWriteQuery(
		uint16_t		inMsgID,
		uint16_t		inFlags,
		const uint8_t *	inQName,
		uint16_t		inQType,
		uint16_t		inQClass,
		uint8_t			outMsg[ STATIC_PARAM kDNSQueryMessageMaxLen ],
		size_t *		outLen );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Creates a collapsed version of a DNS message.
	
	@param		inMsgPtr		Pointer to the start of the DNS message.
	@param		inMsgLen		Length of the DNS message.
	@param		outMsgLen		Pointer of variable to set to the length of the collapsed DNS message.
	@param		outError		Pointer of variable to set to the error encountered by this function, if any.
	
	@result		A dynamically allocated collapsed version of the DNS message.
	
	@discussion This function creates a copy of a DNS message, except that
	
	1. All records not in the Authority and Additional sections are removed.
	2. The CNAME chain, if any, from the QNAME to the non-CNAME records is collapsed, i.e., all CNAME records are removed.
	3. All records that are not direct or indirect answers to the question are also removed.
	
	Note: Collapsing a DNS message is a non-standard operation and should be used with caution.
*/
uint8_t * _Nullable
	DNSMessageCollapse(
		const uint8_t *			inMsgPtr,
		size_t					inMsgLen,
		size_t * _Nullable		outMsgLen,
		OSStatus * _Nullable	outError );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Appends one domain name to another.
	
	@param		inName			Pointer to the target domain name.
	@param		inOtherName		Pointer to the domain name to append to the target domain name.
	@param		outEnd			Gets set to point to the new end of the domain name if the append succeeded. (Optional)
*/
OSStatus
	DomainNameAppendDomainName(
		uint8_t							inName[ STATIC_PARAM kDomainNameLengthMax ],
		const uint8_t *					inOtherName,
		uint8_t * _Nullable * _Nullable	outEnd );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Appends a C string representing a textual sequence of labels to a domain name.
	
	@param		inName			Pointer to the domain name.
	@param		inString		Pointer to textual sequence of labels as a C string.
	@param		outEnd			Gets set to point to the new end of the domain name if the append succeeded. (Optional)
*/
OSStatus
	DomainNameAppendString(
		uint8_t							inName[ STATIC_PARAM kDomainNameLengthMax ],
		const char *					inString,
		uint8_t * _Nullable * _Nullable	outEnd );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Creates a duplicate domain name.
	
	@param		inName			The domain name to duplicate.
	@param		inLower			If true, uppercase letters in the duplicate are converted to lowercase.
	@param		outNamePtr		Gets set to point to a dynamically allocated duplicate.
	@param		outNameLen		Gets set to the length of the duplicate. (Optional)
	
	@discussion	The duplicate domain name must be freed with free() when no longer needed.
*/
OSStatus
	DomainNameDupEx(
		const uint8_t *					inName,
		Boolean							inLower,
		uint8_t * _Nullable * _Nonnull	outNamePtr,
		size_t * _Nullable				outNameLen );

#define DomainNameDup( IN_NAME, OUT_NAME, OUT_LEN )				DomainNameDupEx( IN_NAME, false, OUT_NAME, OUT_LEN )
#define DomainNameDupLower( IN_NAME, OUT_NAME, OUT_LEN )		DomainNameDupEx( IN_NAME, true, OUT_NAME, OUT_LEN )

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Compares two domain names in label format for case-insensitive equality.
	
	@param		inName1		Pointer to the first domain name.
	@param		inName2		Pointer to the second domain name.
	
	@result		If the domain names are equal, returns true, otherwise, returns false.
*/
Boolean	DomainNameEqual( const uint8_t *inName1, const uint8_t *inName2 );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Converts a domain name's textual representation to a domain name in label format.
	
	@param		outName			Buffer to write the domain name in label format.
	@param		inString		Textual representation of a domain name as a C string.
	@param		outEnd			Gets set to point to the new end of the domain name if the append succeeded. (Optional)
*/
OSStatus
	DomainNameFromString(
		uint8_t							outName[ STATIC_PARAM kDomainNameLengthMax ],
		const char *					inString,
		uint8_t * _Nullable * _Nullable	outEnd );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Gets the next label in a domain name label sequence.
	
	@param		inLabel		Pointer to the current label.
	
	@result		If the current label is a root label, returns NULL. Otherwise, returns the next label.
*/
STATIC_INLINE const uint8_t *	DomainNameGetNextLabel( const uint8_t *inLabel )
{
	const int len = *inLabel;
	return ( ( len == 0 ) ? NULL : &inLabel[ 1 + len ] );
}

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Returns the length of a domain name.
	
	@param		inName		The domain name in label format.
*/
size_t	DomainNameLength( const uint8_t *inName );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Returns the number of labels that make up a domain name.
	
	@param		inName		The uncompressed domain name in label format.
	
	@result		Returns -1 if the domain name is malformed. Otherwise, returns the number of labels, not counting the root.
*/
int	DomainNameLabelCount( const uint8_t *inName );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Converts a domain name in label format to its textual representation as a C string.
	
	@param		inName		Pointer to the domain name.
	@param		inLimit		Pointer to not exceed while parsing a potentially truncated domain name. (Optional)
	@param		outString	Buffer to write the C string.
	@param		outPtr		Gets set to point to the end of the domain name. (Optional)
*/
OSStatus
	DomainNameToString(
		const uint8_t *							inName,
		const uint8_t * _Nullable				inLimit,
		char									outString[ STATIC_PARAM kDNSServiceMaxDomainName ],
		const uint8_t * _Nullable * _Nullable	outPtr );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Compares two domain name labels for case-insensitive equality.
	
	@param		inLabel1	Pointer to the first label.
	@param		inLabel2	Pointer to the second label.
	
	@result		If the label are equal, returns true. Otherwise, returns false.
*/
Boolean	DomainLabelEqual( const uint8_t *inLabel1, const uint8_t *inLabel2 );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		For a resource record type's numeric value, returns the resource record type's mnemonic as a C string.
	
	@param		inValue		A resource record type's numeric value.
	
	@result		The resource record type's mnemonic as a C string if the numeric value is recognized, otherwise, NULL.
*/
const char * _Nullable	DNSRecordTypeValueToString( int inValue );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		For a resource record type's mnemonic, returns the resource record type's numeric value.
	
	@param		inString	A resource record type's mnemonic as a C string.
	
	@result		The resource record type's numeric value if the mnemonic is recognized, otherwise, 0.
*/
uint16_t	DNSRecordTypeStringToValue( const char *inString );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		For an RCODE value, returns the corresponding RCODE mnemonic as a C string.
	
	@param		inValue		An RCODE value.
	
	@result		The mnemonic as a C string if the RCODE value is recognized. Otherwise, NULL.
*/
const char * _Nullable	DNSRCodeToString( int inValue );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		For an RCODE mnemonic, returns the corresponding RCODE value.
	
	@param		inString	An RCODE mnemonic as a C string.
	
	@result		If the mnemonic is recognized, the corresponding RCODE value (between 0 and 15, inclusive). Otherwise, -1.
*/
int	DNSRCodeFromString( const char * const inString );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@typedef	DNSMessageToStringFlags
	
	@brief		Formatting options for DNSMessageToString().
*/
typedef uint32_t		DNSMessageToStringFlags;

#define kDNSMessageToStringFlag_Null		0
#define kDNSMessageToStringFlag_MDNS		( 1U << 0 ) // Treat the message as an mDNS message as opposed to DNS.
#define kDNSMessageToStringFlag_RawRData	( 1U << 1 ) // Print record data as a hex string, i.e., no formatting.
#define kDNSMessageToStringFlag_OneLine		( 1U << 2 ) // Format the string as a single line.
#define kDNSMessageToStringFlag_Privacy		( 1U << 3 ) // Obfuscate or redact items such as domain names and IP addresses.
#define kDNSMessageToStringFlag_HeaderOnly	( 1U << 4 ) // Limit printing to just the message header.
#define kDNSMessageToStringFlag_BodyOnly	( 1U << 5 ) // Limit printing to just the message body.

#define kDNSMessageToStringFlags_None		kDNSMessageToStringFlag_Null

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Creates a textual representation of a DNS message as a C string.
	
	@param		inMsgPtr	Pointer to the beginning of the DNS message.
	@param		inMsgLen	Length of the DNS message.
	@param		inFlags		Flags that specify formatting options.
	@param		outString	Gets set to point to the dynamically allocated C string.
	
	@discussion	The created string must be freed with free() when no longer needed.
*/
OSStatus
	DNSMessageToString(
		const uint8_t *				inMsgPtr,
		size_t						inMsgLen,
		DNSMessageToStringFlags		inFlags,
		char * _Nullable * _Nonnull	outString );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Creates a textual representation of a DNS resource record's data as a C string.
	
	@param		inRDataPtr		Pointer to the beginning of record data.
	@param		inRDataLen		Length of the record data.
	@param		inRecordType	The record's numeric type.
	@param		inMsgPtr		Pointer to the beginning of the DNS message containing the resource record. (Optional)
	@param		inMsgLen		Length of the DNS message containing the resource record.
	@param		inPrivacy		If true, sensitive items, such as domain names and IP addresses, are obfuscated or redacted.
	@param		outString		Gets set to point to the dynamically allocated C string.
	
	@discussion	The created string must be freed with free() when no longer needed.
*/
OSStatus
	DNSRecordDataToStringEx(
		const void *					inRDataPtr,
		size_t							inRDataLen,
		int								inRecordType,
		const void * _Nullable			inMsgPtr,
		size_t							inMsgLen,
		Boolean							inPrivacy,
		char * _Nullable * _Nonnull		outString );

#define DNSRecordDataToString(IN_RDATA_PTR, IN_RDATA_LEN, IN_RECORD_TYPE, OUT_STRING) \
	DNSRecordDataToStringEx(IN_RDATA_PTR, IN_RDATA_LEN, IN_RECORD_TYPE, NULL, 0, false, OUT_STRING)

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Computes a DNSKEY record data's DNSSEC key tag.
	
	@param		inRDataPtr		Pointer to the beginning of the DNSKEY record data.
	@param		inRDataLen		Length of the DNSKEY record data.
	
	@discussion	Uses calculation described by <https://tools.ietf.org/html/rfc4034#appendix-B>.
*/
uint16_t	DNSComputeDNSKeyTag( const void *inRDataPtr, size_t inRDataLen );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Writes an obfuscated version of a C string to a buffer as a C string.
	
	@param		inBufPtr		Pointer to the beginning of the buffer to write the obfuscated version of the string.
	@param		inBufLen		Length of the buffer.
	@param		inString		The string to obfuscate.
	
	@result
		If the value returned is non-negative, then the value is the number of non-NUL characters that would have been
		written if the size of the buffer were unlimited. If the value returned is negative, then the function failed.
		In this case, the value returned is an error code.
	
	@discussion
		This function is useful for obfuscating domain name strings using the same type of obfuscation used by
		DNSMessageToString().
		
		If the returned value is non-negative, then, unless inBufLen is 0, the output string will be NUL-terminated.
		If inBufLen is too small, then the end of the output string will be truncated. If inBufLen is not greater than
		a non-negative return value, then the output string was truncated.
*/
int	DNSMessagePrintObfuscatedString( char *inBufPtr, size_t inBufLen, const char *inString );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Writes an obfuscated version of an IPv4 address to a buffer as a C string.
	
	@param		inBufPtr		Pointer to the beginning of the buffer to write the obfuscated version of the string.
	@param		inBufLen		Length of the buffer.
	@param		inAddr			IPv4 address in host byte order.
	
	@result
		If the value returned is non-negative, then the value is the number of non-NUL characters that would have been
		written if the size of the buffer were unlimited. If the value returned is negative, then the function failed.
		In this case, the value returned is an error code.
	
	@discussion
		This function is useful for obfuscating an IPv4 addresses using the same type of obfuscation used by
		DNSMessageToString().
		
		If the returned value is non-negative, then, unless inBufLen is 0, the output string will be NUL-terminated.
		If inBufLen is too small, then the end of the output string will be truncated. If inBufLen is not greater than
		a non-negative return value, then the output string was truncated.
*/
int	DNSMessagePrintObfuscatedIPv4Address( char *inBufPtr, size_t inBufLen, const uint32_t inAddr );

//---------------------------------------------------------------------------------------------------------------------------
/*!	@brief		Writes an obfuscated version of an IPv6 address to a buffer as a C string.
	
	@param		inBufPtr		Pointer to the beginning of the buffer to write the obfuscated version of the string.
	@param		inBufLen		Length of the buffer.
	@param		inAddr			IPv6 address as an array of 16 bytes.
	
	@result
		If the value returned is non-negative, then the value is the number of non-NUL characters that would have been
		written if the size of the buffer were unlimited. If the value returned is negative, then the function failed.
		In this case, the value returned is an error code.
	
	@discussion
		This function is useful for obfuscating an IPv6 address using the same type of obfuscation used by
		DNSMessageToString().
		
		If the returned value is non-negative, then, unless inBufLen is 0, the output string will be NUL-terminated.
		If inBufLen is too small, then the end of the output string will be truncated. If inBufLen is not greater than
		a non-negative return value, then the output string was truncated.
*/
int	DNSMessagePrintObfuscatedIPv6Address( char *inBufPtr, size_t inBufLen, const uint8_t inAddr[ STATIC_PARAM 16 ] );

__END_DECLS

CU_ASSUME_NONNULL_END

#endif // __DNSMessage_h
