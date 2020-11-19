/*
	Copyright (c) 2016-2020 Apple Inc. All rights reserved.
*/

#include "DNSMessage.h"
#include <CoreUtils/CoreUtils.h>
#include <stdlib.h>

//===========================================================================================================================
// MARK: - Local Prototypes

static Boolean	_NameIsPrivate( const char * const inDomainNameStr );
static OSStatus
	_AppendDomainNameString( DataBuffer *inDB, Boolean inPrivacy, const char *inDomainNameStr );
static OSStatus
	_AppendDomainNameStringEx( DataBuffer *inDB, const char *inSeparator, Boolean inPrivacy, const char *inDomainNameStr );
static OSStatus
	_AppendOPTRDataString(
		DataBuffer *	inDB,
		const uint8_t *	inRDataPtr,
		const uint8_t *	inRDataEnd,
		Boolean			inPrivacy );
static OSStatus
	_AppendSVCBRDataString(
		DataBuffer *	inDB,
		const uint8_t *	inRDataPtr,
		const uint8_t *	inRDataEnd,
		Boolean			inPrivacy );
static OSStatus
	_AppendIPv4Address(
		DataBuffer *	inDB,
		const char *	inSeparator,
		const uint8_t	inAddrBytes[ STATIC_PARAM 4 ],
		Boolean			inPrivacy );
static OSStatus
	_AppendIPv6Address(
		DataBuffer *	inDB,
		const char *	inSeparator,
		const uint8_t	inAddrBytes[ STATIC_PARAM 16 ],
		Boolean			inPrivacy );
static OSStatus
	_AppendIPAddress(
		DataBuffer *	inDB,
		const char *	inSeparator,
		const uint8_t *	inAddrPtr,
		int				inAddrLen,
		Boolean			inPrivacy );
static void *	_GetCULibHandle( void );
static Boolean	_MemIsAllZeros( const uint8_t *inMemPtr, size_t inMemLen );
static Boolean	_IPv4AddressIsWhitelisted( const uint8_t inAddrBytes[ STATIC_PARAM 4 ] );
static Boolean	_IPv6AddressIsWhitelisted( const uint8_t inAddrBytes[ STATIC_PARAM 16 ] );
static int
	_DNSMessagePrintObfuscatedIPAddress(
		char *			inBufPtr,
		size_t			inBufLen,
		const uint8_t *	inAddrBytes,
		size_t			inAddrLen );

//===========================================================================================================================
// MARK: - CoreUtils Framework Soft Linking

#define _DEFINE_GET_CU_SYM_ADDR( SYMBOL )								\
	static __typeof__( SYMBOL ) *	_GetCUSymAddr_ ## SYMBOL( void )	\
	{																	\
		static dispatch_once_t				sOnce = 0;					\
		static __typeof__( SYMBOL ) *		sAddr = NULL;				\
																		\
		dispatch_once( &sOnce,											\
		^{																\
			void * const handle = _GetCULibHandle();					\
			require_return( handle );									\
			sAddr = (__typeof__( SYMBOL ) *) dlsym( handle, #SYMBOL );	\
		} );															\
		return sAddr;													\
	}																	\
extern int _DNSMessageDummyVariable

_DEFINE_GET_CU_SYM_ADDR( Base64EncodeCopyEx );
_DEFINE_GET_CU_SYM_ADDR( DataBuffer_Append );
_DEFINE_GET_CU_SYM_ADDR( DataBuffer_AppendF );
_DEFINE_GET_CU_SYM_ADDR( DataBuffer_Detach );
_DEFINE_GET_CU_SYM_ADDR( DataBuffer_Free );
_DEFINE_GET_CU_SYM_ADDR( DataBuffer_Init );
_DEFINE_GET_CU_SYM_ADDR( SecondsToYMD_HMS );
_DEFINE_GET_CU_SYM_ADDR( SNPrintF );

#define _CallCUVoidFunction( NAME, UNAVAILABLE_RETURN_VALUE, ... )	\
	( likely( _GetCUSymAddr_ ## NAME() ) ?				\
		( ( ( _GetCUSymAddr_ ## NAME() )( __VA_ARGS__ ) ), kNoErr ) : ( UNAVAILABLE_RETURN_VALUE ) )

#define _CallCUFunction( NAME, UNAVAILABLE_RETURN_VALUE, ... )	\
	( likely( _GetCUSymAddr_ ## NAME() ) ?			\
		( ( _GetCUSymAddr_ ## NAME() )( __VA_ARGS__ ) ) : ( UNAVAILABLE_RETURN_VALUE ) )

#define _Base64EncodeCopyEx( ... )		_CallCUFunction( Base64EncodeCopyEx, kUnsupportedErr, __VA_ARGS__ )
#define _DataBuffer_Init( ... )			_CallCUVoidFunction( DataBuffer_Init, kUnsupportedErr, __VA_ARGS__ )
#define _DataBuffer_Free( ... )			_CallCUVoidFunction( DataBuffer_Free, kUnsupportedErr, __VA_ARGS__ )
#define _DataBuffer_Append( ... )		_CallCUFunction( DataBuffer_Append, kUnsupportedErr, __VA_ARGS__ )
#define _DataBuffer_AppendF( ... )		_CallCUFunction( DataBuffer_AppendF, kUnsupportedErr, __VA_ARGS__ )
#define _DataBuffer_Detach( ... )		_CallCUFunction( DataBuffer_Detach, kUnsupportedErr, __VA_ARGS__ )
#define _SecondsToYMD_HMS( ... )		_CallCUVoidFunction( SecondsToYMD_HMS, kUnsupportedErr, __VA_ARGS__ )
#define _SNPrintF( ... )				_CallCUFunction( SNPrintF, kUnsupportedErr, __VA_ARGS__ )

//===========================================================================================================================
// MARK: - Public Functions

#define IsCompressionByte( X )		( ( ( X ) & 0xC0 ) == 0xC0 )

OSStatus
	DNSMessageExtractDomainName(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inPtr,
		uint8_t				outName[ kDomainNameLengthMax ],
		const uint8_t **	outPtr )
{
	OSStatus					err;
	const uint8_t *				label;
	uint8_t						labelLen;
	const uint8_t *				nextLabel;
	const uint8_t * const		msgEnd	= inMsgPtr + inMsgLen;
	uint8_t *					dst		= outName;
	const uint8_t * const		dstLim	= outName ? ( outName + kDomainNameLengthMax ) : NULL;
	const uint8_t *				nameEnd	= NULL;
	
	require_action_quiet( ( inPtr >= inMsgPtr ) && ( inPtr < msgEnd ), exit, err = kRangeErr );
	
	for( label = inPtr; ( labelLen = label[ 0 ] ) != 0; label = nextLabel )
	{
		if( labelLen <= kDomainLabelLengthMax )
		{
			nextLabel = label + 1 + labelLen;
			require_action_quiet( nextLabel < msgEnd, exit, err = kUnderrunErr );
			if( dst )
			{
				require_action_quiet( ( dstLim - dst ) > ( 1 + labelLen ), exit, err = kOverrunErr );
				memcpy( dst, label, 1 + labelLen );
				dst += ( 1 + labelLen );
			}
		}
		else if( IsCompressionByte( labelLen ) )
		{
			uint16_t		offset;
			
			require_action_quiet( ( msgEnd - label ) >= 2, exit, err = kUnderrunErr );
			if( !nameEnd )
			{
				nameEnd = label + 2;
				if( !dst ) break;
			}
			offset = (uint16_t)( ( ( label[ 0 ] & 0x3F ) << 8 ) | label[ 1 ] );
			nextLabel = inMsgPtr + offset;
			require_action_quiet( nextLabel < msgEnd, exit, err = kUnderrunErr );
			require_action_quiet( !IsCompressionByte( nextLabel[ 0 ] ), exit, err = kMalformedErr );
		}
		else
		{
			err = kMalformedErr;
			goto exit;
		}
	}
	
	if( dst ) *dst = 0;
	if( !nameEnd ) nameEnd = label + 1;
	
	if( outPtr ) *outPtr = nameEnd;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================

OSStatus
	DNSMessageExtractDomainNameString(
		const void *		inMsgPtr,
		size_t				inMsgLen,
		const void *		inPtr,
		char				inBuf[ kDNSServiceMaxDomainName ],
		const uint8_t **	outPtr )
{
	OSStatus			err;
	const uint8_t *		nextPtr;
	uint8_t				domainName[ kDomainNameLengthMax ];
	
	err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inPtr, domainName, &nextPtr );
	require_noerr_quiet( err, exit );
	
	err = DomainNameToString( domainName, NULL, inBuf, NULL );
	require_noerr_quiet( err, exit );
	
	if( outPtr ) *outPtr = nextPtr;
	
exit:
	return( err );
}

//===========================================================================================================================

OSStatus
	DNSMessageExtractQuestion(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inPtr,
		uint8_t				outName[ kDomainNameLengthMax ],
		uint16_t *			outType,
		uint16_t *			outClass,
		const uint8_t **	outPtr )
{
	OSStatus								err;
	const uint8_t * const					msgEnd = &inMsgPtr[ inMsgLen ];
	const uint8_t *							ptr;
	const dns_fixed_fields_question *		fields;
	
	err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inPtr, outName, &ptr );
	require_noerr_quiet( err, exit );
	require_action_quiet( (size_t)( msgEnd - ptr ) >= sizeof( dns_fixed_fields_question ), exit, err = kUnderrunErr );
	
	fields = (const dns_fixed_fields_question *) ptr;
	if( outType )  *outType  = dns_fixed_fields_question_get_type( fields );
	if( outClass ) *outClass = dns_fixed_fields_question_get_class( fields );
	if( outPtr )   *outPtr   = (const uint8_t *) &fields[ 1 ];
	
exit:
	return( err );
}

//===========================================================================================================================

static OSStatus
	_DNSMessageExtractRecordEx(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inPtr,
		uint8_t				outName[ kDomainNameLengthMax ],
		uint16_t *			outType,
		uint16_t *			outClass,
		uint32_t *			outTTL,
		const uint8_t **	outRDataPtr,
		size_t *			outRDataLen,
		uint8_t *			inBufPtr,
		size_t				inBufLen,
		size_t *			outCopiedRDataLen,
		size_t *			outExpandedRDataLen,
		const uint8_t **	outPtr );

OSStatus
	DNSMessageExtractRecord(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t *		inPtr,
		uint8_t				outName[ kDomainNameLengthMax ],
		uint16_t *			outType,
		uint16_t *			outClass,
		uint32_t *			outTTL,
		const uint8_t **	outRDataPtr,
		size_t *			outRDataLen,
		const uint8_t **	outPtr )
{
	return( _DNSMessageExtractRecordEx( inMsgPtr, inMsgLen, inPtr, outName, outType, outClass, outTTL,
		outRDataPtr, outRDataLen, NULL, 0, NULL, NULL, outPtr ) );
}

//===========================================================================================================================

OSStatus	DNSMessageGetAnswerSection( const uint8_t *inMsgPtr, size_t inMsgLen, const uint8_t **outPtr )
{
	OSStatus				err;
	unsigned int			questionCount, i;
	const DNSHeader *		hdr;
	const uint8_t *			ptr;
	
	require_action_quiet( inMsgLen >= kDNSHeaderLength, exit, err = kSizeErr );
	
	hdr = (DNSHeader *) inMsgPtr;
	questionCount = DNSHeaderGetQuestionCount( hdr );
	
	ptr = (const uint8_t *) &hdr[ 1 ];
	for( i = 0; i < questionCount; ++i )
	{
		err = DNSMessageExtractQuestion( inMsgPtr, inMsgLen, ptr, NULL, NULL, NULL, &ptr );
		require_noerr_quiet( err, exit );
	}
	if( outPtr ) *outPtr = ptr;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================

OSStatus
	DNSMessageGetOptRecord(
		const uint8_t *		inMsgPtr,
		size_t				inMsgLen,
		const uint8_t **	outOptPtr,
		size_t *			outOptLen )
{
	OSStatus				err;
	const DNSHeader *		hdr;
	const uint8_t *			ptr;
	const uint8_t *			optPtr;
	size_t					optLen;
	uint32_t				skipCount, additionalCount, i;
	
	err = DNSMessageGetAnswerSection( inMsgPtr, inMsgLen, &ptr );
	require_noerr_quiet( err, exit );
	
	hdr = (DNSHeader *) inMsgPtr;
	skipCount = DNSHeaderGetAnswerCount( hdr ) + DNSHeaderGetAuthorityCount( hdr );
	for( i = 0; i < skipCount; ++i )
	{
		uint16_t		type;
		
		err = DNSMessageExtractRecord( inMsgPtr, inMsgLen, ptr, NULL, &type, NULL, NULL, NULL, NULL, &ptr );
		require_noerr_quiet( err, exit );
		
		// Make sure that there are no OPT records in the answer and authority sections.
		// See <https://tools.ietf.org/html/rfc6891#section-6.1.1>.
		
		require_action_quiet( type != kDNSRecordType_OPT, exit, err = kMalformedErr );
	}
	optPtr = NULL;
	optLen = 0;
	additionalCount = DNSHeaderGetAdditionalCount( hdr );
	for( i = 0; i < additionalCount; ++i )
	{
		const uint8_t *		namePtr;
		uint16_t			type;
		
		namePtr = ptr;
		err = DNSMessageExtractRecord( inMsgPtr, inMsgLen, ptr, NULL, &type, NULL, NULL, NULL, NULL, &ptr );
		require_noerr_quiet( err, exit );
		
		if( type != kDNSRecordType_OPT ) continue;
		
		// Make sure that there's only one OPT record.
		// See <https://tools.ietf.org/html/rfc6891#section-6.1.1>.
		
		require_action_quiet( !optPtr, exit, err = kMalformedErr );
		
		// The OPT record's name must be 0 (root domain).
		// See <https://tools.ietf.org/html/rfc6891#section-6.1.2>.
		
		require_action_quiet( *namePtr == 0, exit, err = kMalformedErr );
		
		optPtr = namePtr;
		optLen = (size_t)( ptr - optPtr );
		check( optLen >= sizeof( dns_fixed_fields_opt ) );
	}
	if( outOptPtr ) *outOptPtr = optPtr;
	if( outOptLen ) *outOptLen = optLen;
	
exit:
	return( err );
}

//===========================================================================================================================

OSStatus
	DNSMessageWriteQuery(
		uint16_t		inMsgID,
		uint16_t		inFlags,
		const uint8_t *	inQName,
		uint16_t		inQType,
		uint16_t		inQClass,
		uint8_t			outMsg[ STATIC_PARAM kDNSQueryMessageMaxLen ],
		size_t *		outLen )
{
	OSStatus				err;
	DNSHeader * const		hdr = (DNSHeader *) outMsg;
	uint8_t *				ptr;
	size_t					qnameLen;
	size_t					msgLen;
	
	memset( hdr, 0, sizeof( *hdr ) );
	DNSHeaderSetID( hdr, inMsgID );
	DNSHeaderSetFlags( hdr, inFlags );
	DNSHeaderSetQuestionCount( hdr, 1 );
	
	qnameLen = DomainNameLength( inQName );
	require_action_quiet( qnameLen <= kDomainNameLengthMax, exit, err = kSizeErr );
	
	ptr = (uint8_t *) &hdr[ 1 ];
	memcpy( ptr, inQName, qnameLen );
	ptr += qnameLen;
	
	dns_fixed_fields_question_init( (dns_fixed_fields_question *) ptr, inQType, inQClass );
	ptr += sizeof( dns_fixed_fields_question );
	
	msgLen = (size_t)( ptr - outMsg );
	
	if( outLen ) *outLen = msgLen;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================

uint8_t *
	DNSMessageCollapse(
		const uint8_t *	const	inMsgPtr,
		const size_t			inMsgLen,
		size_t * const			outMsgLen,
		OSStatus * const		outError )
{
	OSStatus				err;
	uint8_t *				newMsg	= NULL;
	const DNSHeader *		hdr;
	const uint8_t *			ptr;
	const uint8_t *			answerSection;
	uint8_t *				bufPtr	= NULL;
	size_t					bufLen;
	uint8_t *				dst;
	const uint8_t *			lim;
	size_t					qnameLen;
	unsigned int			questionCount, answerCount, i, j;
	uint32_t				minCNameTTL;
	uint16_t				qtype, qclass;
	uint8_t					qname[ kDomainNameLengthMax ];
	uint8_t					target[ kDomainNameLengthMax ];
	
	require_action_quiet( inMsgLen >= kDNSHeaderLength, exit, err = kSizeErr );
	
	hdr = (DNSHeader *) inMsgPtr;
	questionCount = DNSHeaderGetQuestionCount( hdr );
	require_action_quiet( questionCount == 1, exit, err = kCountErr );
	
	ptr = (const uint8_t *) &hdr[ 1 ];
	err = DNSMessageExtractQuestion( inMsgPtr, inMsgLen, ptr, qname, &qtype, &qclass, &ptr );
	require_noerr_quiet( err, exit );
	require_action_quiet( qclass == kDNSClassType_IN, exit, err = kTypeErr );
	
	qnameLen = DomainNameLength( qname );
	answerSection = ptr;
	
	// The initial target name is the QNAME.
	
	memcpy( target, qname, qnameLen );
	
	// Starting with QNAME, follow the CNAME chain, if any, to the end.
	
	minCNameTTL = UINT32_MAX;
	answerCount = DNSHeaderGetAnswerCount( hdr );
	for( i = 0; i < answerCount; ++i )
	{
		Boolean				followedCNAME;
		
		ptr = answerSection;
		followedCNAME = false;
		for( j = 0; j < answerCount; ++j )
		{
			const uint8_t *		rdataPtr;
			uint32_t			ttl;
			uint16_t			type, class;
			uint8_t				name[ kDomainNameLengthMax ];
			
			err = DNSMessageExtractRecord( inMsgPtr, inMsgLen, ptr, name, &type, &class, &ttl, &rdataPtr, NULL, &ptr );
			require_noerr_quiet( err, exit );
			
			if( type  != kDNSRecordType_CNAME )		continue;
			if( class != qclass )					continue;
			if( !DomainNameEqual( name, target ) )	continue;
			
			err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, rdataPtr, target, NULL );
			require_noerr_quiet( err, exit );
			
			minCNameTTL = Min( minCNameTTL, ttl );
			followedCNAME = true;
		}
		if( !followedCNAME ) break;
	}
	
	// The target is now either QNAME or the end of the CNAME chain if there was one.
	// Iterate over the answer section twice.
	// The first iteration determines how much space is needed in the collapsed message for answer records.
	// The second iteration writes the collapsed message.
	
	bufPtr	= NULL;
	bufLen	= kDNSHeaderLength + qnameLen + sizeof( dns_fixed_fields_question );
	dst		= NULL;
	lim		= NULL;
	for( i = 0; i < 2; ++i )
	{
		DNSHeader *			newHdr;
		unsigned int		newAnswerCount;
		
		ptr = answerSection;
		newAnswerCount = 0;
		for( j = 0; j < answerCount; ++j )
		{
			const uint8_t *					recordPtr;
			dns_fixed_fields_record *		fields;
			size_t							copiedRDataLen, expandedRDataLen;
			uint32_t						ttl;
			uint16_t						type, class;
			uint8_t							name[ kDomainNameLengthMax ];
			
			recordPtr = ptr;
			err = _DNSMessageExtractRecordEx( inMsgPtr, inMsgLen, ptr, name, &type, &class, &ttl, NULL, NULL,
				NULL, 0, NULL, &expandedRDataLen, &ptr );
			require_noerr_quiet( err, exit );
			
			if( type  != qtype )					continue;
			if( class != qclass )					continue;
			if( !DomainNameEqual( name, target ) )	continue;
			if( !bufPtr )
			{
				// Add the amount of space needed for this record.
				// Note that the record's name will be a compression pointer to the QNAME.
				
				bufLen += ( kDNSCompressionPointerLength + sizeof( *fields ) + expandedRDataLen );
			}
			else
			{
				// Write the record's name as a compression pointer to QNAME, which is located right after the header.
				
				require_action_quiet( ( lim - dst ) >= kDNSCompressionPointerLength, exit, err = kInternalErr );
				DNSMessageWriteLabelPointer( dst, kDNSHeaderLength );
				dst += kDNSCompressionPointerLength;
				
				// Write the record's fixed field values.
				
				require_action_quiet( ( (size_t)( lim - dst ) ) >= sizeof( *fields ), exit, err = kInternalErr );
				fields = (dns_fixed_fields_record *) dst;
				ttl = Min( ttl, minCNameTTL );
				dns_fixed_fields_record_init( fields, type, class, ttl, (uint16_t) expandedRDataLen );
				dst += sizeof( *fields );
				
				// Write the record's expanded RDATA.
				
				require_action_quiet( ( (size_t)( lim - dst ) ) >= expandedRDataLen, exit, err = kInternalErr );
				err = _DNSMessageExtractRecordEx( inMsgPtr, inMsgLen, recordPtr, NULL, NULL, NULL, NULL, NULL, NULL,
					dst, expandedRDataLen, &copiedRDataLen, NULL, NULL );
				require_noerr_quiet( err, exit );
				
				dst += copiedRDataLen;
				++newAnswerCount;
			}
		}
		if( !bufPtr )
		{
			dns_fixed_fields_question *		fields;
			
			// Allocate memory for the collapsed message.
			
			bufPtr = (uint8_t *) calloc( 1, bufLen );
			require_action_quiet( bufPtr, exit, err = kNoMemoryErr );
			
			dst = bufPtr;
			lim = &bufPtr[ bufLen ];
			
			// Write a tentative header based on the original header.
			
			require_action_quiet( ( (size_t)( lim - dst ) ) >= sizeof( *newHdr ), exit, err = kInternalErr );
			newHdr = (DNSHeader *) dst;
			memcpy( newHdr, hdr, sizeof( *newHdr ) );
			dst += sizeof( *newHdr );
			
			DNSHeaderSetAnswerCount( newHdr, 0 );
			DNSHeaderSetAuthorityCount( newHdr, 0 );
			DNSHeaderSetAdditionalCount( newHdr, 0 );
			
			// Write the question section.
			
			require_action_quiet( ( (size_t)( lim - dst ) ) >= qnameLen, exit, err = kInternalErr );
			memcpy( dst, qname, qnameLen );
			dst += qnameLen;
			
			require_action_quiet( ( (size_t)( lim - dst ) ) >= sizeof( *fields ), exit, err = kInternalErr );
			fields = (dns_fixed_fields_question *) dst;
			dns_fixed_fields_question_init( fields, qtype, qclass );
			dst += sizeof( *fields );
			
			DNSHeaderSetQuestionCount( newHdr, 1 );
		}
		else
		{
			// Finally, set the answer count.
			
			require_action_quiet( bufLen >= sizeof( *newHdr ), exit, err = kInternalErr );
			newHdr = (DNSHeader *) bufPtr;
			DNSHeaderSetAnswerCount( newHdr, newAnswerCount );
			break;
		}
	}
	if( outMsgLen ) *outMsgLen = (size_t)( dst - bufPtr );
	newMsg = bufPtr;
	bufPtr = NULL;
	
exit:
	if( outError ) *outError = err;
	ForgetMem( &bufPtr );
	return( newMsg );
}

//===========================================================================================================================

static OSStatus
	_DNSMessageExtractRData(
		const uint8_t *	inMsgPtr,
		size_t			inMsgLen,
		const uint8_t *	inRDataPtr,
		size_t			inRDataLen,
		unsigned int	inType,
		uint8_t *		inBufPtr,
		size_t			inBufLen,
		size_t *		outCopiedRDataLen,
		size_t *		outExpandedRDataLen );

static OSStatus
	_DNSMessageExtractRecordEx(
		const uint8_t * const	inMsgPtr,
		const size_t			inMsgLen,
		const uint8_t * const	inPtr,
		uint8_t					outName[ kDomainNameLengthMax ],
		uint16_t * const		outType,
		uint16_t * const		outClass,
		uint32_t * const		outTTL,
		const uint8_t ** const	outRDataPtr,
		size_t * const			outRDataLen,
		uint8_t * const			inBufPtr,
		const size_t			inBufLen,
		size_t * const			outCopiedRDataLen,
		size_t * const			outExpandedRDataLen,
		const uint8_t **		outPtr )
{
	OSStatus							err;
	const uint8_t * const				msgEnd = inMsgPtr + inMsgLen;
	const uint8_t *						ptr;
	const dns_fixed_fields_record *		fields;
	const uint8_t *						rdata;
	size_t								rdLength, copiedLen, expandedLen;
	uint16_t							type;
	
	err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inPtr, outName, &ptr );
	require_noerr_quiet( err, exit );
	require_action_quiet( (size_t)( msgEnd - ptr ) >= sizeof( *fields ), exit, err = kUnderrunErr );
	
	fields		= (const dns_fixed_fields_record *) ptr;
	rdata		= ptr + sizeof( *fields );
	rdLength	= dns_fixed_fields_record_get_rdlength( fields );
	require_action_quiet( (size_t)( msgEnd - rdata ) >= rdLength , exit, err = kUnderrunErr );
	
	type = dns_fixed_fields_record_get_type( fields );
	err = _DNSMessageExtractRData( inMsgPtr, inMsgLen, rdata, rdLength, type, inBufPtr, inBufLen, &copiedLen, &expandedLen );
	require_noerr_quiet( err, exit );
	
	if( outType )				*outType				= type;
	if( outClass )				*outClass				= dns_fixed_fields_record_get_class( fields );
	if( outTTL )				*outTTL					= dns_fixed_fields_record_get_ttl( fields );
	if( outRDataPtr )			*outRDataPtr			= rdata;
	if( outRDataLen )			*outRDataLen			= rdLength;
	if( outCopiedRDataLen )		*outCopiedRDataLen		= copiedLen;
	if( outExpandedRDataLen )	*outExpandedRDataLen	= expandedLen;
	if( outPtr )				*outPtr					= &rdata[ rdLength ];
	
exit:
	return( err );
}

static OSStatus
	_DNSMessageExtractRData(
		const uint8_t * const	inMsgPtr,
		const size_t			inMsgLen,
		const uint8_t * const	inRDataPtr,
		const size_t			inRDataLen,
		const unsigned int		inType,
		uint8_t * const			inBufPtr,
		const size_t			inBufLen,
		size_t * const			outCopiedRDataLen,
		size_t * const			outExpandedRDataLen )
{
	OSStatus					err;
	const uint8_t *				ptr;
	const uint8_t * const		rdataEnd = &inRDataPtr[ inRDataLen ];
	size_t						copyLen, expandedLen;
	uint8_t						name1[ kDomainNameLengthMax ];
	uint8_t						name2[ kDomainNameLengthMax ];
	
	// According to <https://tools.ietf.org/html/rfc1123#section-6.1.3.5>:
	//
	//	Compression relies on knowledge of the format of data
	//	inside a particular RR.  Hence compression must only be
	//	used for the contents of well-known, class-independent
	//	RRs, and must never be used for class-specific RRs or
	//	RR types that are not well-known.  The owner name of an
	//	RR is always eligible for compression.
	//
	// Therefore, compressed domain names in RDATA is only handled for record types from
	// <https://tools.ietf.org/html/rfc1035#section-3.3>.
	
	switch( inType )
	{
		case kDNSRecordType_CNAME:	// <https://tools.ietf.org/html/rfc1035#section-3.3.1>
		case kDNSRecordType_MB:		// <https://tools.ietf.org/html/rfc1035#section-3.3.3>
		case kDNSRecordType_MD:		// <https://tools.ietf.org/html/rfc1035#section-3.3.4>
		case kDNSRecordType_MF:		// <https://tools.ietf.org/html/rfc1035#section-3.3.5>
		case kDNSRecordType_MG:		// <https://tools.ietf.org/html/rfc1035#section-3.3.6>
		case kDNSRecordType_MR:		// <https://tools.ietf.org/html/rfc1035#section-3.3.8>
		case kDNSRecordType_NS:		// <https://tools.ietf.org/html/rfc1035#section-3.3.11>
		case kDNSRecordType_PTR:	// <https://tools.ietf.org/html/rfc1035#section-3.3.12>
		{
			// The RDATA consists of one domain name.
			
			err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inRDataPtr, name1, &ptr );
			require_noerr_quiet( err, exit );
			require_action_quiet( ptr == rdataEnd, exit, err = kMalformedErr );
			
			expandedLen	= DomainNameLength( name1 );
			copyLen		= Min( inBufLen, expandedLen );
			memcpy( inBufPtr, name1, copyLen );
			break;
		}
		case kDNSRecordType_MINFO:	// <https://tools.ietf.org/html/rfc1035#section-3.3.7>
		{
			uint8_t *					dst = inBufPtr;
			const uint8_t * const		lim = &inBufPtr[ inBufLen ];
			size_t						nameLen1, nameLen2;
			
			// The RDATA consists of two domain names.
			
			err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inRDataPtr, name1, &ptr );
			require_noerr_quiet( err, exit );
			
			err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, ptr, name2, &ptr );
			require_noerr_quiet( err, exit );
			require_action_quiet( ptr == rdataEnd, exit, err = kMalformedErr );
			
			nameLen1	= DomainNameLength( name1 );
			nameLen2	= DomainNameLength( name2 );
			expandedLen	= nameLen1 + nameLen2;
			
			copyLen = (size_t)( lim - dst );
			copyLen = Min( copyLen, nameLen1 );
			memcpy( dst, name1, copyLen );
			dst += copyLen;
			
			copyLen = (size_t)( lim - dst );
			copyLen = Min( copyLen, nameLen2 );
			memcpy( dst, name2, copyLen );
			dst += copyLen;
			
			copyLen = (size_t)( dst - inBufPtr );
			break;
		}
		case kDNSRecordType_MX:		// <https://tools.ietf.org/html/rfc1035#section-3.3.9>
		{
			uint8_t *					dst = inBufPtr;
			const uint8_t * const		lim = &inBufPtr[ inBufLen ];
			const uint8_t *				exchange;
			size_t						nameLen1;
			
			// The RDATA format is a 2-octet preference value followed by exchange, which is a domain name.
			
			require_action_quiet( inRDataLen > 2, exit, err = kMalformedErr );
			exchange = &inRDataPtr[ 2 ];
			
			err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, exchange, name1, &ptr );
			require_noerr_quiet( err, exit );
			require_action_quiet( ptr == rdataEnd, exit, err = kMalformedErr );
			
			nameLen1	= DomainNameLength( name1 );
			expandedLen	= 2 + nameLen1;
			
			copyLen = (size_t)( lim - dst );
			copyLen = Min( copyLen, 2 );
			memcpy( dst, inRDataPtr, copyLen );
			dst += copyLen;
			
			copyLen = (size_t)( lim - dst );
			copyLen = Min( copyLen, nameLen1 );
			memcpy( dst, name1, copyLen );
			dst += copyLen;
			
			copyLen = (size_t)( dst - inBufPtr );
			break;
		}
		case kDNSRecordType_SOA:	// <https://tools.ietf.org/html/rfc1035#section-3.3.13>
		{
			uint8_t *					dst = inBufPtr;
			const uint8_t * const		lim = &inBufPtr[ inBufLen ];
			size_t						nameLen1, nameLen2;
			
			// MNAME is a domain name.
			
			err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, inRDataPtr, name1, &ptr );
			require_noerr_quiet( err, exit );
			
			// RNAME is a domain name.
			
			err = DNSMessageExtractDomainName( inMsgPtr, inMsgLen, ptr, name2, &ptr );
			require_noerr_quiet( err, exit );
			
			// MNAME and RNAME are followed by fixed-sized fields.
			
			require_action_quiet( ( rdataEnd - ptr ) == sizeof( dns_fixed_fields_soa ), exit, err = kMalformedErr );
			nameLen1	= DomainNameLength( name1 );
			nameLen2	= DomainNameLength( name2 );
			expandedLen	= nameLen1 + nameLen2 + sizeof( dns_fixed_fields_soa );
			
			copyLen = (size_t)( lim - dst );
			copyLen = Min( copyLen, nameLen1 );
			memcpy( dst, name1, copyLen );
			dst += copyLen;
			
			copyLen = (size_t)( lim - dst );
			copyLen = Min( copyLen, nameLen2 );
			memcpy( dst, name2, copyLen );
			dst += copyLen;
			
			copyLen = (size_t)( lim - dst );
			copyLen = Min( copyLen, sizeof( dns_fixed_fields_soa ) );
			memcpy( dst, ptr, copyLen );
			dst += copyLen;
			
			copyLen = (size_t)( dst - inBufPtr );
			break;
		}	
		default:
		case kDNSRecordType_HINFO:	// <https://tools.ietf.org/html/rfc1035#section-3.3.2>
		case kDNSRecordType_NULL:	// <https://tools.ietf.org/html/rfc1035#section-3.3.10>
		case kDNSRecordType_TXT:	// <https://tools.ietf.org/html/rfc1035#section-3.3.14>
		{
			// The RDATA contains no compressed domain names.
			
			expandedLen	= inRDataLen;
			copyLen		= Min( inBufLen, expandedLen );
			memcpy( inBufPtr, inRDataPtr, copyLen );
			break;
		}
	}
	err = kNoErr;
	
	if( outCopiedRDataLen )		*outCopiedRDataLen		= copyLen;
	if( outExpandedRDataLen )	*outExpandedRDataLen	= expandedLen;
	
exit:
	return( err );
}

//===========================================================================================================================

OSStatus
	DomainNameAppendDomainName(
		uint8_t			inName[ STATIC_PARAM kDomainNameLengthMax ],
		const uint8_t *	inOtherName,
		uint8_t **		outEnd )
{
	OSStatus			err;
	size_t				newLen;
	const size_t		adjustedLen	= DomainNameLength( inName ) - 1; // Don't count the root label.
	const size_t		otherLen	= DomainNameLength( inOtherName );
	
	require_action_quiet( adjustedLen <= kDomainNameLengthMax, exit, err = kSizeErr );
	require_action_quiet( otherLen <= kDomainNameLengthMax, exit, err = kSizeErr );
	
	newLen = adjustedLen + otherLen;
	require_action_quiet( newLen <= kDomainNameLengthMax, exit, err = kSizeErr );
	
	memcpy( &inName[ adjustedLen ], inOtherName, otherLen );
	if( outEnd ) *outEnd = &inName[ newLen ];
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================

OSStatus
	DomainNameAppendString(
		uint8_t			inDomainName[ STATIC_PARAM kDomainNameLengthMax ],
		const char *	inString,
		uint8_t **		outEnd )
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
	if( outEnd ) *outEnd = root + 1;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================

#define _isupper_ascii( X )		( ( (X) >= 'A' ) && ( (X) <= 'Z' ) )

static void	_DomainNameLower( uint8_t *inName );

OSStatus	DomainNameDupEx( const uint8_t *inName, Boolean inLower, uint8_t **outNamePtr, size_t *outNameLen )
{
	OSStatus			err;
	uint8_t *			namePtr;
	const size_t		nameLen = DomainNameLength( inName );
	
	namePtr = (uint8_t *) malloc( nameLen );
	require_action_quiet( namePtr, exit, err = kNoMemoryErr );
	
	memcpy( namePtr, inName, nameLen );
	if( inLower ) _DomainNameLower( namePtr );
	
	*outNamePtr = namePtr;
	if( outNameLen ) *outNameLen = nameLen;
	err = kNoErr;
	
exit:
	return( err );
}

static void	_DomainNameLower( uint8_t *inName )
{
	uint8_t *		ptr;
	int				len;
	
	ptr = inName;
	while( ( len = *ptr++ ) != 0 )
	{
		while( len-- > 0 )
		{
			if( _isupper_ascii( *ptr ) ) *ptr += 32;
			++ptr;
		}
	}
}

//===========================================================================================================================

#define _tolower_ascii( X )		( _isupper_ascii( X ) ? ( (X) + 32 ) : (X) )

Boolean	DomainNameEqual( const uint8_t *inName1, const uint8_t *inName2 )
{
	const uint8_t *		p1 = inName1;
	const uint8_t *		p2 = inName2;
	if( p1 == p2 ) return( true );
	for( ;; )
	{
		int			len1	= *p1++;
		const int	len2	= *p2++;
		if( len1 != len2 )	return( false );
		if( len1 == 0 )		return( true );
		while( len1-- > 0 )
		{
			const int		c1 = *p1++;
			const int		c2 = *p2++;
			if( _tolower_ascii( c1 ) != _tolower_ascii( c2 ) ) return( false );
		}
	}
}

//===========================================================================================================================

OSStatus
	DomainNameFromString(
		uint8_t			outName[ STATIC_PARAM kDomainNameLengthMax ],
		const char *	inString,
		uint8_t **		outEnd )
{
	outName[ 0 ] = 0;
	return( DomainNameAppendString( outName, inString, outEnd ) );
}

//===========================================================================================================================

size_t	DomainNameLength( const uint8_t *inName )
{
	const uint8_t *		label;
	int					len;
	
	for( label = inName; ( len = *label ) != 0; label = &label[ 1 + len ] ) {}
	return( (size_t)( label - inName ) + 1 );
}

//===========================================================================================================================

int	DomainNameLabelCount( const uint8_t * const inName )
{
	const uint8_t *		label;
	const uint8_t *		nextLabel;
	int					labelCount, result;
	unsigned int		labelLen;
	
	labelCount = 0;
	for( label = inName; ( labelLen = *label ) != 0; label = nextLabel )
	{
		require_action_quiet( labelLen <= kDomainLabelLengthMax, exit, result = -1 );
		
		nextLabel = &label[ 1 + labelLen ];
		require_action_quiet( ( nextLabel - inName ) < kDomainNameLengthMax, exit, result = -1 );
		
		++labelCount;
	}
	result = labelCount;
	
exit:
	return( result );
}

//===========================================================================================================================

#define _isprint_ascii( X )		( ( (X) >= 32 ) && ( (X) <= 126 ) )

OSStatus
	DomainNameToString(
		const uint8_t *		inName,
		const uint8_t *		inLimit,
		char				outString[ STATIC_PARAM kDNSServiceMaxDomainName ],
		const uint8_t **	outPtr )
{
	OSStatus			err;
	const uint8_t *		label;
	uint8_t				labelLen;
	const uint8_t *		nextLabel;
	char *				dst;
	const uint8_t *		src;
	
	require_action_quiet( !inLimit || ( ( inLimit - inName ) > 0 ), exit, err = kUnderrunErr );
	
	// Convert each label up until the root label, i.e., the zero-length label.
	
	dst = outString;
	for( label = inName; ( labelLen = label[ 0 ] ) != 0; label = nextLabel )
	{
		require_action_quiet( labelLen <= kDomainLabelLengthMax, exit, err = kMalformedErr );
		
		nextLabel = &label[ 1 + labelLen ];
		require_action_quiet( ( nextLabel - inName ) < kDomainNameLengthMax, exit, err = kMalformedErr );
		require_action_quiet( !inLimit || ( nextLabel < inLimit ), exit, err = kUnderrunErr );
		
		for( src = &label[ 1 ]; src < nextLabel; ++src )
		{
			if( _isprint_ascii( *src ) )
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
	
	if( label == inName ) *dst++ = '.';
	*dst = '\0';
	if( outPtr ) *outPtr = label + 1;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================

Boolean	DomainLabelEqual( const uint8_t *inLabel1, const uint8_t *inLabel2 )
{
	const uint8_t *		p1 = inLabel1;
	const uint8_t *		p2 = inLabel2;
	if( p1 == p2 ) return( true );
	int			len1	= *p1++;
	const int	len2	= *p2++;
	if( len1 != len2 ) return( false );
	while( len1-- > 0 )
	{
		const int		c1 = *p1++;
		const int		c2 = *p2++;
		if( _tolower_ascii( c1 ) != _tolower_ascii( c2 ) ) return( false );
	}
	return( true );
}

//===========================================================================================================================
// This code was autogenerated on 2020-06-30 by dns-rr-func-autogen version 1.3
// Data source URL: https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv
// Overrides: none

const char *	DNSRecordTypeValueToString( int inValue )
{
	const char *		string;

	if( 0 ) {}
	else if( ( inValue >= 1 ) && ( inValue <= 53 ) )
	{
		static const char * const		sNames_1_53[] =
		{
			"A",            //   1
			"NS",           //   2
			"MD",           //   3
			"MF",           //   4
			"CNAME",        //   5
			"SOA",          //   6
			"MB",           //   7
			"MG",           //   8
			"MR",           //   9
			"NULL",         //  10
			"WKS",          //  11
			"PTR",          //  12
			"HINFO",        //  13
			"MINFO",        //  14
			"MX",           //  15
			"TXT",          //  16
			"RP",           //  17
			"AFSDB",        //  18
			"X25",          //  19
			"ISDN",         //  20
			"RT",           //  21
			"NSAP",         //  22
			"NSAP-PTR",     //  23
			"SIG",          //  24
			"KEY",          //  25
			"PX",           //  26
			"GPOS",         //  27
			"AAAA",         //  28
			"LOC",          //  29
			"NXT",          //  30
			"EID",          //  31
			"NIMLOC",       //  32
			"SRV",          //  33
			"ATMA",         //  34
			"NAPTR",        //  35
			"KX",           //  36
			"CERT",         //  37
			"A6",           //  38
			"DNAME",        //  39
			"SINK",         //  40
			"OPT",          //  41
			"APL",          //  42
			"DS",           //  43
			"SSHFP",        //  44
			"IPSECKEY",     //  45
			"RRSIG",        //  46
			"NSEC",         //  47
			"DNSKEY",       //  48
			"DHCID",        //  49
			"NSEC3",        //  50
			"NSEC3PARAM",   //  51
			"TLSA",         //  52
			"SMIMEA",       //  53
		};
		string = sNames_1_53[ inValue - 1 ];
	}
	else if( ( inValue >= 55 ) && ( inValue <= 65 ) )
	{
		static const char * const		sNames_55_65[] =
		{
			"HIP",          //  55
			"NINFO",        //  56
			"RKEY",         //  57
			"TALINK",       //  58
			"CDS",          //  59
			"CDNSKEY",      //  60
			"OPENPGPKEY",   //  61
			"CSYNC",        //  62
			"ZONEMD",       //  63
			"SVCB",         //  64
			"HTTPS",        //  65
		};
		string = sNames_55_65[ inValue - 55 ];
	}
	else if( ( inValue >= 99 ) && ( inValue <= 109 ) )
	{
		static const char * const		sNames_99_109[] =
		{
			"SPF",          //  99
			"UINFO",        // 100
			"UID",          // 101
			"GID",          // 102
			"UNSPEC",       // 103
			"NID",          // 104
			"L32",          // 105
			"L64",          // 106
			"LP",           // 107
			"EUI48",        // 108
			"EUI64",        // 109
		};
		string = sNames_99_109[ inValue - 99 ];
	}
	else if( ( inValue >= 249 ) && ( inValue <= 260 ) )
	{
		static const char * const		sNames_249_260[] =
		{
			"TKEY",         // 249
			"TSIG",         // 250
			"IXFR",         // 251
			"AXFR",         // 252
			"MAILB",        // 253
			"MAILA",        // 254
			"ANY",          // 255
			"URI",          // 256
			"CAA",          // 257
			"AVC",          // 258
			"DOA",          // 259
			"AMTRELAY",     // 260
		};
		string = sNames_249_260[ inValue - 249 ];
	}
	else if( ( inValue >= 32768 ) && ( inValue <= 32769 ) )
	{
		static const char * const		sNames_32768_32769[] =
		{
			"TA",           // 32768
			"DLV",          // 32769
		};
		string = sNames_32768_32769[ inValue - 32768 ];
	}
	else if( inValue == 65535 )
	{
		static const char * const		sNames_65535[] =
		{
			"Reserved",     // 65535
		};
		string = sNames_65535[ inValue - 65535 ];
	}
	else
	{
		string = NULL;
	}
	return( string );
}


//===========================================================================================================================
// This code was autogenerated on 2020-06-30 by dns-rr-func-autogen version 1.3
// Data source URL: https://www.iana.org/assignments/dns-parameters/dns-parameters-4.csv
// Overrides: none

typedef struct
{
	const char *		name;
	uint16_t			value;

}	_DNSRecordTypeItem;

static int	_DNSRecordTypeStringToValueCmp( const void *inKey, const void *inElement );

uint16_t	DNSRecordTypeStringToValue( const char *inString )
{
	// The name-value table is sorted by name in ascending lexicographical order to allow going from name to
	// value in logarithmic time via a binary search.

	static const _DNSRecordTypeItem		sTable[] =
	{
		{ "A",              1 },
		{ "A6",            38 },
		{ "AAAA",          28 },
		{ "AFSDB",         18 },
		{ "AMTRELAY",     260 },
		{ "ANY",          255 },
		{ "APL",           42 },
		{ "ATMA",          34 },
		{ "AVC",          258 },
		{ "AXFR",         252 },
		{ "CAA",          257 },
		{ "CDNSKEY",       60 },
		{ "CDS",           59 },
		{ "CERT",          37 },
		{ "CNAME",          5 },
		{ "CSYNC",         62 },
		{ "DHCID",         49 },
		{ "DLV",        32769 },
		{ "DNAME",         39 },
		{ "DNSKEY",        48 },
		{ "DOA",          259 },
		{ "DS",            43 },
		{ "EID",           31 },
		{ "EUI48",        108 },
		{ "EUI64",        109 },
		{ "GID",          102 },
		{ "GPOS",          27 },
		{ "HINFO",         13 },
		{ "HIP",           55 },
		{ "HTTPS",         65 },
		{ "IPSECKEY",      45 },
		{ "ISDN",          20 },
		{ "IXFR",         251 },
		{ "KEY",           25 },
		{ "KX",            36 },
		{ "L32",          105 },
		{ "L64",          106 },
		{ "LOC",           29 },
		{ "LP",           107 },
		{ "MAILA",        254 },
		{ "MAILB",        253 },
		{ "MB",             7 },
		{ "MD",             3 },
		{ "MF",             4 },
		{ "MG",             8 },
		{ "MINFO",         14 },
		{ "MR",             9 },
		{ "MX",            15 },
		{ "NAPTR",         35 },
		{ "NID",          104 },
		{ "NIMLOC",        32 },
		{ "NINFO",         56 },
		{ "NS",             2 },
		{ "NSAP",          22 },
		{ "NSAP-PTR",      23 },
		{ "NSEC",          47 },
		{ "NSEC3",         50 },
		{ "NSEC3PARAM",    51 },
		{ "NULL",          10 },
		{ "NXT",           30 },
		{ "OPENPGPKEY",    61 },
		{ "OPT",           41 },
		{ "PTR",           12 },
		{ "PX",            26 },
		{ "Reserved",   65535 },
		{ "RKEY",          57 },
		{ "RP",            17 },
		{ "RRSIG",         46 },
		{ "RT",            21 },
		{ "SIG",           24 },
		{ "SINK",          40 },
		{ "SMIMEA",        53 },
		{ "SOA",            6 },
		{ "SPF",           99 },
		{ "SRV",           33 },
		{ "SSHFP",         44 },
		{ "SVCB",          64 },
		{ "TA",         32768 },
		{ "TALINK",        58 },
		{ "TKEY",         249 },
		{ "TLSA",          52 },
		{ "TSIG",         250 },
		{ "TXT",           16 },
		{ "UID",          101 },
		{ "UINFO",        100 },
		{ "UNSPEC",       103 },
		{ "URI",          256 },
		{ "WKS",           11 },
		{ "X25",           19 },
		{ "ZONEMD",        63 },
	};
	const _DNSRecordTypeItem *			item;

	item = (_DNSRecordTypeItem *) bsearch( inString, sTable, sizeof( sTable ) / sizeof( sTable[ 0 ] ),
		sizeof( sTable[ 0 ] ), _DNSRecordTypeStringToValueCmp );
	return( item ? item->value : 0 );
}

static int	_DNSRecordTypeStringToValueCmp( const void *inKey, const void *inElement )
{
	const _DNSRecordTypeItem * const		item = (const _DNSRecordTypeItem *) inElement;
	return( strcasecmp( (const char *) inKey, item->name ) );
}

//===========================================================================================================================
// This code was autogenerated on 2020-06-15 by dns-rcode-func-autogen version 1.0
// Data source URL: https://www.iana.org/assignments/dns-parameters/dns-parameters-6.csv

const char *	DNSRCodeToString( const int inValue )
{
	switch( inValue )
	{
		case kDNSRCode_NoError:     return( "NoError" );
		case kDNSRCode_FormErr:     return( "FormErr" );
		case kDNSRCode_ServFail:    return( "ServFail" );
		case kDNSRCode_NXDomain:    return( "NXDomain" );
		case kDNSRCode_NotImp:      return( "NotImp" );
		case kDNSRCode_Refused:     return( "Refused" );
		case kDNSRCode_YXDomain:    return( "YXDomain" );
		case kDNSRCode_YXRRSet:     return( "YXRRSet" );
		case kDNSRCode_NXRRSet:     return( "NXRRSet" );
		case kDNSRCode_NotAuth:     return( "NotAuth" );
		case kDNSRCode_NotZone:     return( "NotZone" );
		case kDNSRCode_DSOTYPENI:   return( "DSOTYPENI" );
		default:                    return( NULL );
	}
}

//===========================================================================================================================
// This code was autogenerated on 2020-06-15 by dns-rcode-func-autogen version 1.0
// Data source URL: https://www.iana.org/assignments/dns-parameters/dns-parameters-6.csv

typedef struct
{
	const char *		name;
	int					value;
	
}	_DNSRCodeTableEntry;

static int	_DNSRCodeFromStringCmp( const void *inKey, const void *inElement );

int	DNSRCodeFromString( const char * const inString )
{
	// The name-value table is sorted by name in ascending lexicographical order to allow going from name to
	// value in logarithmic time via a binary search.
	
	static const _DNSRCodeTableEntry		sTable[] =
	{
		{ "DSOTYPENI",  kDNSRCode_DSOTYPENI },
		{ "FormErr",    kDNSRCode_FormErr   },
		{ "NoError",    kDNSRCode_NoError   },
		{ "NotAuth",    kDNSRCode_NotAuth   },
		{ "NotImp",     kDNSRCode_NotImp    },
		{ "NotZone",    kDNSRCode_NotZone   },
		{ "NXDomain",   kDNSRCode_NXDomain  },
		{ "NXRRSet",    kDNSRCode_NXRRSet   },
		{ "Refused",    kDNSRCode_Refused   },
		{ "ServFail",   kDNSRCode_ServFail  },
		{ "YXDomain",   kDNSRCode_YXDomain  },
		{ "YXRRSet",    kDNSRCode_YXRRSet   }
	};
	const _DNSRCodeTableEntry *			entry;
	
	entry = (_DNSRCodeTableEntry *) bsearch( inString, sTable, sizeof( sTable ) / sizeof( sTable[ 0 ] ),
		sizeof( sTable[ 0 ] ), _DNSRCodeFromStringCmp );
	return( entry ? entry->value : -1 );
}

static int	_DNSRCodeFromStringCmp( const void * const inKey, const void * const inElement )
{
	const _DNSRCodeTableEntry * const		entry = (const _DNSRCodeTableEntry *) inElement;
	return( strcasecmp( (const char *) inKey, entry->name ) );
}

//===========================================================================================================================
// Note: Unknown resource record types and classes are represented as text using the convention described in
// <https://tools.ietf.org/html/rfc3597#section-5>.

static const char *	_DNSOpCodeToString( int inOpCode );

typedef struct
{
	unsigned int		flag;
	const char *		desc;
	
}	_DNSHeaderFlagDesc;

static const _DNSHeaderFlagDesc		kDNSHeaderFlagsDescs[] =
{
	{ kDNSHeaderFlag_AuthAnswer,			"AA" },
	{ kDNSHeaderFlag_Truncation,			"TC" },
	{ kDNSHeaderFlag_RecursionDesired,		"RD" },
	{ kDNSHeaderFlag_RecursionAvailable,	"RA" },
	{ kDNSHeaderFlag_Z,						"Z"  },
	{ kDNSHeaderFlag_AuthenticData,			"AD" },
	{ kDNSHeaderFlag_CheckingDisabled,		"CD" },
};

OSStatus
	DNSMessageToString(
		const uint8_t *					inMsgPtr,
		size_t							inMsgLen,
		const DNSMessageToStringFlags	inFlags,
		char **							outString )
{
	OSStatus				err;
	DataBuffer				db;
	const DNSHeader *		hdr;
	const uint8_t *			ptr;
	const char *			separator;
	char *					rdataStr	= NULL;
	const char *			str;
	size_t					len;
	uint32_t				qCount, aCount, authCount, addCount, i, totalCount;
	uint8_t *				name;
	const uint8_t *			nameCur;
	uint8_t					dbBuf[ 256 ];
	char					nameStr[ kDNSServiceMaxDomainName ];
	uint8_t					nameBuf1[ kDomainNameLengthMax ];
	uint8_t					nameBuf2[ kDomainNameLengthMax ];
	const Boolean			oneLine		= ( inFlags & kDNSMessageToStringFlag_OneLine )		? true : false;
	const Boolean			isMDNS		= ( inFlags & kDNSMessageToStringFlag_MDNS )		? true : false;
	const Boolean			rawRData	= ( inFlags & kDNSMessageToStringFlag_RawRData )	? true : false;
	const Boolean			privacy		= ( inFlags & kDNSMessageToStringFlag_Privacy )		? true : false;
	const Boolean			headerOnly	= ( inFlags & kDNSMessageToStringFlag_HeaderOnly )	? true : false;
	const Boolean			bodyOnly	= ( inFlags & kDNSMessageToStringFlag_BodyOnly )	? true : false;
	
	err = _DataBuffer_Init( &db, dbBuf, sizeof( dbBuf ), SIZE_MAX );
	require_noerr_quiet( err, exit );
	#define _AppendF( ... ) \
		do { err = _DataBuffer_AppendF( &db, __VA_ARGS__ ); require_noerr_quiet( err, exit ); } while( 0 )
	
	require_action_quiet( inMsgLen >= kDNSHeaderLength, exit, err = kSizeErr );
	
	hdr			= (DNSHeader *) inMsgPtr;
	qCount		= DNSHeaderGetQuestionCount( hdr );
	aCount		= DNSHeaderGetAnswerCount( hdr );
	authCount	= DNSHeaderGetAuthorityCount( hdr );
	addCount	= DNSHeaderGetAdditionalCount( hdr );
	separator	= "";
	if( !bodyOnly )
	{
		const unsigned int		id		= DNSHeaderGetID( hdr );
		const unsigned int		flags	= DNSHeaderGetFlags( hdr );
		const int				opcode	= DNSFlagsGetOpCode( flags );
		const int				rcode	= DNSFlagsGetRCode( flags );
		
		if( oneLine )
		{
			_AppendF( "id: 0x%04X (%u), flags: 0x%04X (%c/",
				id, id, flags, ( flags & kDNSHeaderFlag_Response ) ? 'R' : 'Q' );
		}
		else
		{
			_AppendF( "ID:               0x%04X (%u)\n", id, id );
			_AppendF( "Flags:            0x%04X %c/", flags, ( flags & kDNSHeaderFlag_Response ) ? 'R' : 'Q' );
		}
		str = _DNSOpCodeToString( opcode );
		if( str )	_AppendF( "%s", str );
		else		_AppendF( "OPCODE%d", opcode );
		for( i = 0; i < countof( kDNSHeaderFlagsDescs ); ++i )
		{
			const _DNSHeaderFlagDesc * const		flagDesc = &kDNSHeaderFlagsDescs[ i ];
			
			if( flags & flagDesc->flag ) _AppendF( ", %s", flagDesc->desc );
		}
		str = DNSRCodeToString( rcode );
		if( str )	_AppendF( ", %s", str );
		else		_AppendF( ", RCODE%d", rcode );
		if( oneLine )
		{
			_AppendF( "), counts: %u/%u/%u/%u", qCount, aCount, authCount, addCount );
			separator = ", ";
		}
		else
		{
			_AppendF( "\n" );
			_AppendF( "Question count:   %u\n", qCount );
			_AppendF( "Answer count:     %u\n", aCount );
			_AppendF( "Authority count:  %u\n", authCount );
			_AppendF( "Additional count: %u\n", addCount );
		}
	}
	if( headerOnly ) goto done;
	
	ptr			= (const uint8_t *) &hdr[ 1 ];
	name		= nameBuf1;
	nameCur		= NULL;
	for( i = 0; i < qCount; ++i )
	{
		uint16_t		qtype, qclass;
		Boolean			isQU;
		
		err = DNSMessageExtractQuestion( inMsgPtr, inMsgLen, ptr, name, &qtype, &qclass, &ptr );
		require_noerr_quiet( err, exit );
		
		isQU = ( isMDNS && ( qclass & kMDNSClassUnicastResponseBit ) ) ? true : false;
		if( isMDNS ) qclass &= ~kMDNSClassUnicastResponseBit;
		if( oneLine )
		{
			_AppendF( "%s", separator );
			if( !nameCur || !DomainNameEqual( name, nameCur ) )
			{
				err = DomainNameToString( name, NULL, nameStr, NULL );
				require_noerr_quiet( err, exit );
				
				if( privacy && _NameIsPrivate( nameStr ) ) _AppendF( "%~s ", nameStr );
				else									   _AppendF( "%s ",  nameStr );
				nameCur	= name;
				name	= ( name == nameBuf1 ) ? nameBuf2 : nameBuf1;
				*name = 0;
			}
			if( qclass == kDNSClassType_IN )	_AppendF( "IN" );
			else								_AppendF( "CLASS%u", qclass );
			if( isMDNS ) _AppendF( " %s", isQU ? "QU" : "QM" );
			str = DNSRecordTypeValueToString( qtype );
			if( str )	_AppendF( " %s?", str );
			else		_AppendF( " TYPE%u?", qtype );
			separator = ", ";
		}
		else
		{
			if( i == 0 ) _AppendF( "\nQUESTION SECTION\n" );
			err = DomainNameToString( name, NULL, nameStr, NULL );
			require_noerr_quiet( err, exit );
			
			if( privacy && _NameIsPrivate( nameStr ) ) _AppendF( "%~-30s", nameStr );
			else									   _AppendF( "%-30s",  nameStr );
			_AppendF( " %2s", isMDNS ? ( isQU ? "QU" : "QM" ) : "" );
			if( qclass == kDNSClassType_IN )	_AppendF( " IN" );
			else								_AppendF( " CLASS%u", qclass );
			str = DNSRecordTypeValueToString( qtype );
			if( str )	_AppendF( " %-5s\n", str );
			else		_AppendF( " TYPE%u\n", qtype );
		}
	}
	totalCount = aCount + authCount + addCount;
	for( i = 0; i < totalCount; ++i )
	{
		const uint8_t *		rdataPtr;
		size_t				rdataLen;
		const char *		typeStr;
		uint32_t			ttl;
		uint16_t			type, class;
		Boolean				cacheFlush;
		
		err = DNSMessageExtractRecord( inMsgPtr, inMsgLen, ptr, name, &type, &class, &ttl, &rdataPtr, &rdataLen, &ptr );
		require_noerr_quiet( err, exit );
		
		err = DomainNameToString( name, NULL, nameStr, NULL );
		require_noerr_quiet( err, exit );
		
		cacheFlush = ( isMDNS && ( class & kMDNSClassCacheFlushBit ) ) ? true : false;
		if( isMDNS ) class &= ~kMDNSClassCacheFlushBit;
		
		if( oneLine ) 
		{
			_AppendF( "%s", separator );
			if( !nameCur || !DomainNameEqual( name, nameCur ) )
			{
				err = DomainNameToString( name, NULL, nameStr, NULL );
				require_noerr_quiet( err, exit );
				
				if( privacy && _NameIsPrivate( nameStr ) ) _AppendF( "%~s ", nameStr );
				else									   _AppendF( "%s ",  nameStr );
				nameCur	= name;
				name	= ( name == nameBuf1 ) ? nameBuf2 : nameBuf1;
				*name = 0;
			}
			if( type == kDNSRecordType_OPT )
			{
				if( cacheFlush ) _AppendF( "CF " );
				_AppendF( "OPT %u", class );
				if( ttl == 0 )	_AppendF( " 0" );
				else			_AppendF( " 0x%08X", ttl );
			}
			else
			{
				_AppendF( "%u", ttl );
				if( cacheFlush ) _AppendF( " CF" );
				if( class == kDNSClassType_IN )	_AppendF( " IN" );
				else							_AppendF( " CLASS%u", class );
				typeStr = DNSRecordTypeValueToString( type );
				if( typeStr )	_AppendF( " %s", typeStr );
				else			_AppendF( " TYPE%u", type );
			}
			separator = ", ";
		}
		else
		{
			if(      ( aCount    != 0 ) && ( i ==   0                    ) ) _AppendF( "\nANSWER SECTION\n" );
			else if( ( authCount != 0 ) && ( i ==   aCount               ) ) _AppendF( "\nAUTHORITY SECTION\n" );
			else if( ( addCount  != 0 ) && ( i == ( aCount + authCount ) ) ) _AppendF( "\nADDITIONAL SECTION\n" );
			
			if( type == kDNSRecordType_OPT )
			{
				if( privacy && _NameIsPrivate( nameStr ) ) _AppendF( "%~s", nameStr );
				else									   _AppendF( "%s",  nameStr );
				_AppendF( "%s OPT %u", cacheFlush ? " CF" : "", class );
				if( ttl == 0 ) _AppendF( " 0" );
				else		   _AppendF( " 0x%08X", ttl );
			}
			else
			{
				if( privacy ) _AppendF( "%~-42s", nameStr );
				else		  _AppendF( "%-42s",  nameStr );
				_AppendF( " %6u %2s", ttl, cacheFlush ? "CF" : "" );
				if( class == kDNSClassType_IN )	_AppendF( " IN" );
				else							_AppendF( " CLASS%u", class );
				typeStr = DNSRecordTypeValueToString( type );
				if( typeStr )	_AppendF( " %-5s", typeStr );
				else			_AppendF( " TYPE%u", type );
			}
		}
		if( !rawRData ) DNSRecordDataToStringEx( rdataPtr, rdataLen, type, inMsgPtr, inMsgLen, privacy, &rdataStr );
		if( rdataStr )
		{
			_AppendF( " %s", rdataStr );
			ForgetMem( &rdataStr );
		}
		else
		{
			if( privacy ) _AppendF( " [%zu B]", rdataLen );
			else		  _AppendF( " %#H", rdataPtr, (int) rdataLen, (int) rdataLen );
		}
		
		if( oneLine )
		{
			if( type == kDNSRecordType_CNAME )
			{
				if( DNSMessageExtractDomainName( inMsgPtr, inMsgLen, rdataPtr, name, NULL ) == kNoErr )
				{
					nameCur	= name;
					name	= ( name == nameBuf1 ) ? nameBuf2 : nameBuf1;
				}
				*name = 0;
			}
		}
		else
		{
			_AppendF( "\n" );
		}
	}
	#undef _AppendF
done:
	err = _DataBuffer_Append( &db, "", 1 ); // NUL terminator.
	require_noerr_quiet( err, exit );
	
	err = _DataBuffer_Detach( &db, (uint8_t **) outString, &len );
	require_noerr_quiet( err, exit );
	
exit:
	FreeNullSafe( rdataStr );
	_DataBuffer_Free( &db );
	return( err );
}

// See <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5>.

static const char *	_DNSOpCodeToString( int inOpCode )
{
	const char *		string;
	
	if( ( inOpCode >= 0 ) && ( inOpCode <= 6 ) )
	{
		static const char * const		sNames[] =
		{
			"Query",	// 0
			"IQuery",	// 1
			"Status",	// 2
			NULL,		// 3 (Unassigned)
			"Notify",	// 4
			"Update",	// 5
			"DSO",		// 6
		};
		string = sNames[ inOpCode ];
	}
	else
	{
		string = NULL;
	}
	return( string );
}

//===========================================================================================================================

static OSStatus
	_DNSRecordDataAppendTypeBitMap(
		DataBuffer *		inDB,
		const uint8_t *		inPtr,
		const uint8_t *		inEnd,
		const uint8_t **	outPtr );

OSStatus
	DNSRecordDataToStringEx(
		const void * const	inRDataPtr,
		const size_t		inRDataLen,
		const int			inRecordType,
		const void * const	inMsgPtr,
		const size_t		inMsgLen,
		const Boolean		inPrivacy,
		char ** const		outString )
{
	OSStatus					err;
	const uint8_t * const		rdataPtr	= (uint8_t *) inRDataPtr;
	const uint8_t * const		rdataEnd	= rdataPtr + inRDataLen;
	const void * const			msgPtr		= inMsgPtr;
	const uint8_t *				ptr;
	DataBuffer					db;
	size_t						len;
	uint8_t						dbBuf[ 256 ];
	char						domainNameStr[ kDNSServiceMaxDomainName ];
	
	err = _DataBuffer_Init( &db, dbBuf, sizeof( dbBuf ), SIZE_MAX );
	require_noerr_quiet( err, exit );
	
	// A Record
	
	if( inRecordType == kDNSRecordType_A )
	{
		require_action_quiet( inRDataLen == 4, exit, err = kMalformedErr );
		
		err = _AppendIPv4Address( &db, NULL, rdataPtr, inPrivacy );
		require_noerr_quiet( err, exit );
	}
	
	// AAAA Record
	
	else if( inRecordType == kDNSRecordType_AAAA )
	{
		require_action_quiet( inRDataLen == 16, exit, err = kMalformedErr );
		
		err = _AppendIPv6Address( &db, NULL, rdataPtr, inPrivacy );
		require_noerr_quiet( err, exit );
	}
	
	// PTR, CNAME, or NS Record
	
	else if( ( inRecordType == kDNSRecordType_PTR )   ||
			 ( inRecordType == kDNSRecordType_CNAME ) ||
			 ( inRecordType == kDNSRecordType_NS ) )
	{
		if( msgPtr )
		{
			err = DNSMessageExtractDomainNameString( msgPtr, inMsgLen, rdataPtr, domainNameStr, NULL );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = DomainNameToString( rdataPtr, rdataEnd, domainNameStr, NULL );
			require_noerr_quiet( err, exit );
		}
		err = _AppendDomainNameString( &db, inPrivacy, domainNameStr );
		require_noerr_quiet( err, exit );
	}
	
	// SRV Record
	
	else if( inRecordType == kDNSRecordType_SRV )
	{
		const dns_fixed_fields_srv *		fields;
		const uint8_t *						target;
		
		require_action_quiet( inRDataLen > sizeof( dns_fixed_fields_srv ), exit, err = kMalformedErr );
		
		fields = (const dns_fixed_fields_srv *) rdataPtr;
		target = (const uint8_t *) &fields[ 1 ];
		if( msgPtr )
		{
			err = DNSMessageExtractDomainNameString( msgPtr, inMsgLen, target, domainNameStr, NULL );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = DomainNameToString( target, rdataEnd, domainNameStr, NULL );
			require_noerr_quiet( err, exit );
		}
		err = _DataBuffer_AppendF( &db, "%u %u %u ",
			dns_fixed_fields_srv_get_priority( fields ),
			dns_fixed_fields_srv_get_weight( fields ),
			dns_fixed_fields_srv_get_port( fields ) );
		require_noerr_quiet( err, exit );
		
		err = _AppendDomainNameString( &db, inPrivacy, domainNameStr );
		require_noerr_quiet( err, exit );
	}
	
	// TXT or HINFO Record
	// See <https://tools.ietf.org/html/rfc1035#section-3.3.14> and <https://tools.ietf.org/html/rfc1035#section-3.3.2>.
	
	else if( ( inRecordType == kDNSRecordType_TXT ) || ( inRecordType == kDNSRecordType_HINFO ) )
	{
		require_action_quiet( inRDataLen > 0, exit, err = kMalformedErr );
		
		if( inPrivacy )
		{
			err = _DataBuffer_AppendF( &db, "[%zu B]", inRDataLen );
			require_noerr_quiet( err, exit );
		}
		else
		{
			if( inRDataLen == 1 )
			{
				err = _DataBuffer_AppendF( &db, "%#H", rdataPtr, (int) inRDataLen, (int) inRDataLen );
				require_noerr_quiet( err, exit );
			}
			else
			{
				err = _DataBuffer_AppendF( &db, "%#{txt}", rdataPtr, (size_t) inRDataLen );
				require_noerr_quiet( err, exit );
			}
		}
	}
	
	// SOA Record
	
	else if( inRecordType == kDNSRecordType_SOA )
	{
		const dns_fixed_fields_soa *		fields;
		
		// Get MNAME.
		
		if( msgPtr )
		{
			err = DNSMessageExtractDomainNameString( msgPtr, inMsgLen, rdataPtr, domainNameStr, &ptr );
			require_noerr_quiet( err, exit );
			require_action_quiet( ptr < rdataEnd, exit, err = kMalformedErr );
		}
		else
		{
			err = DomainNameToString( rdataPtr, rdataEnd, domainNameStr, &ptr );
			require_noerr_quiet( err, exit );
		}
		err = _AppendDomainNameString( &db, inPrivacy, domainNameStr );
		require_noerr_quiet( err, exit );
		
		// Get RNAME.
		
		if( msgPtr )
		{
			err = DNSMessageExtractDomainNameString( msgPtr, inMsgLen, ptr, domainNameStr, &ptr );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = DomainNameToString( ptr, rdataEnd, domainNameStr, &ptr );
			require_noerr_quiet( err, exit );
		}
		err = _AppendDomainNameStringEx( &db, " ", inPrivacy, domainNameStr );
		require_noerr_quiet( err, exit );
		
		require_action_quiet( ( rdataEnd - ptr ) == sizeof( dns_fixed_fields_soa ), exit, err = kMalformedErr );
		
		fields = (const dns_fixed_fields_soa *) ptr;
		err = _DataBuffer_AppendF( &db, " %u %u %u %u %u",
			dns_fixed_fields_soa_get_serial( fields ),
			dns_fixed_fields_soa_get_refresh( fields ),
			dns_fixed_fields_soa_get_retry( fields ),
			dns_fixed_fields_soa_get_expire( fields ),
			dns_fixed_fields_soa_get_minimum( fields ) );
		require_noerr_quiet( err, exit );
	}
	
	// NSEC Record
	
	else if( inRecordType == kDNSRecordType_NSEC )
	{
		if( msgPtr )
		{
			err = DNSMessageExtractDomainNameString( msgPtr, inMsgLen, rdataPtr, domainNameStr, &ptr );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = DomainNameToString( rdataPtr, rdataEnd, domainNameStr, &ptr );
			require_noerr_quiet( err, exit );
		}
		require_action_quiet( ptr < rdataEnd, exit, err = kMalformedErr );
		
		err = _AppendDomainNameString( &db, inPrivacy, domainNameStr );
		require_noerr_quiet( err, exit );
		
		err = _DNSRecordDataAppendTypeBitMap( &db, ptr, rdataEnd, NULL );
		require_noerr_quiet( err, exit );
	}
	
	// MX Record
	
	else if( inRecordType == kDNSRecordType_MX )
	{
		uint16_t			preference;
		const uint8_t *		exchange;
		
		require_action_quiet( ( rdataEnd - rdataPtr ) > 2, exit, err = kMalformedErr );
		
		preference	= ReadBig16( rdataPtr );
		exchange	= &rdataPtr[ 2 ];
		
		if( msgPtr )
		{
			err = DNSMessageExtractDomainNameString( msgPtr, inMsgLen, exchange, domainNameStr, NULL );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = DomainNameToString( exchange, rdataEnd, domainNameStr, NULL );
			require_noerr_quiet( err, exit );
		}
		err = _DataBuffer_AppendF( &db, "%u", preference );
		require_noerr_quiet( err, exit );
		
		err = _AppendDomainNameStringEx( &db, " ", inPrivacy, domainNameStr );
		require_noerr_quiet( err, exit );
	}
	
	// DNSKEY Record (see <https://tools.ietf.org/html/rfc4034#section-2.2>)
	
	else if( inRecordType == kDNSRecordType_DNSKEY )
	{
		const dns_fixed_fields_dnskey *		fields;
		char *								publicKeyBase64;
		
		require_action_quiet( ( (size_t)( rdataEnd - rdataPtr ) ) > sizeof( *fields ), exit, err = kMalformedErr );
		
		fields = (const dns_fixed_fields_dnskey *) rdataPtr;
		err = _DataBuffer_AppendF( &db, "%u %u %u",
			dns_fixed_fields_dnskey_get_flags( fields ),
			dns_fixed_fields_dnskey_get_protocol( fields ),
			dns_fixed_fields_dnskey_get_algorithm( fields ) );
		require_noerr_quiet( err, exit );
		
		// Public Key
		
		ptr = (const uint8_t *) &fields[ 1 ];
		publicKeyBase64 = NULL;
		err = _Base64EncodeCopyEx( ptr, (size_t)( rdataEnd - ptr ), kBase64Flags_None, &publicKeyBase64, NULL );
		require_noerr_quiet( err, exit );
		
		err = _DataBuffer_AppendF( &db, " %s", publicKeyBase64 );
		ForgetMem( &publicKeyBase64 );
		require_noerr_quiet( err, exit );
	}
	
	// RRSIG Record (see <https://tools.ietf.org/html/rfc4034#section-3.2>)
	
	else if( inRecordType == kDNSRecordType_RRSIG )
	{
		const dns_fixed_fields_rrsig *		fields;
		const char *						typeStr;
		int									year, month, day, hour, minute, second;
		char *								signatureBase64;
		
		require_action_quiet( ( (size_t)( rdataEnd - rdataPtr ) ) > sizeof( *fields ), exit, err = kMalformedErr );
		
		fields	= (const dns_fixed_fields_rrsig *) rdataPtr;
		typeStr	= DNSRecordTypeValueToString( dns_fixed_fields_rrsig_get_type_covered( fields ) );
		if( typeStr )
		{
			err = _DataBuffer_AppendF( &db, "%s", typeStr );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = _DataBuffer_AppendF( &db, "TYPE%u", dns_fixed_fields_rrsig_get_type_covered( fields ) );
			require_noerr_quiet( err, exit );
		}
		err = _DataBuffer_AppendF( &db, " %u %u %u",
			dns_fixed_fields_rrsig_get_algorithm( fields ),
			dns_fixed_fields_rrsig_get_labels( fields ),
			dns_fixed_fields_rrsig_get_original_ttl( fields ) );
		require_noerr_quiet( err, exit );
		
		year	= 0;
		month	= 0;
		day		= 0;
		hour	= 0;
		minute	= 0;
		second	= 0;
		err = _SecondsToYMD_HMS( ( INT64_C_safe( kDaysToUnixEpoch ) * kSecondsPerDay ) +
			dns_fixed_fields_rrsig_get_signature_expiration( fields ), &year, &month, &day, &hour, &minute, &second );
		require_noerr_quiet( err, exit );
		
		err = _DataBuffer_AppendF( &db, " %u%02u%02u%02u%02u%02u", year, month, day, hour, minute, second );
		require_noerr_quiet( err, exit );
		
		err = _SecondsToYMD_HMS( ( INT64_C_safe( kDaysToUnixEpoch ) * kSecondsPerDay ) +
			dns_fixed_fields_rrsig_get_signature_inception( fields ), &year, &month, &day, &hour, &minute, &second );
		require_noerr_quiet( err, exit );
		
		err = _DataBuffer_AppendF( &db, " %u%02u%02u%02u%02u%02u", year, month, day, hour, minute, second );
		require_noerr_quiet( err, exit );
		
		err = _DataBuffer_AppendF( &db, " %u", dns_fixed_fields_rrsig_get_key_tag( fields ) );
		require_noerr_quiet( err, exit );
		
		// Signer's name
		
		ptr = (const uint8_t *) &fields[ 1 ];
		err = DomainNameToString( ptr, rdataEnd, domainNameStr, &ptr );
		require_noerr_quiet( err, exit );
		
		err = _AppendDomainNameStringEx( &db, " ", inPrivacy, domainNameStr );
		require_noerr_quiet( err, exit );
		
		// Signature
		
		signatureBase64 = NULL;
		err = _Base64EncodeCopyEx( ptr, (size_t)( rdataEnd - ptr ), kBase64Flags_None, &signatureBase64, NULL );
		require_noerr_quiet( err, exit );
		
		err = _DataBuffer_AppendF( &db, " %s", signatureBase64 );
		FreeNullSafe( signatureBase64 );
		require_noerr_quiet( err, exit );
	}
	
	// NSEC3 Record (see <https://tools.ietf.org/html/rfc5155#section-3.3>)
	
	else if( inRecordType == kDNSRecordType_NSEC3 )
	{
		const dns_fixed_fields_nsec3 *		fields;
		size_t								saltLen, hashLen, rem;
		const uint8_t *						hashEnd;
		
		require_action_quiet( ( (size_t)( rdataEnd - rdataPtr ) ) > sizeof( *fields ), exit, err = kMalformedErr );
		
		fields = (const dns_fixed_fields_nsec3 *) rdataPtr;
		err = _DataBuffer_AppendF( &db, "%u %u %u",
			dns_fixed_fields_nsec3_get_hash_alg( fields ),
			dns_fixed_fields_nsec3_get_flags( fields ),
			dns_fixed_fields_nsec3_get_iterations( fields ) );
		require_noerr_quiet( err, exit );
		
		ptr = (const uint8_t *) &fields[ 1 ];
		require_action_quiet( ( rdataEnd - ptr ) >= 1, exit, err = kMalformedErr );
		
		saltLen	= *ptr++;
		require_action_quiet( ( (size_t)( rdataEnd - ptr ) ) >= saltLen, exit, err = kMalformedErr );
		err = _DataBuffer_AppendF( &db, " %.4H", ptr, (int) saltLen, (int) saltLen );
		require_noerr_quiet( err, exit );
		
		ptr += saltLen;
		require_action_quiet( ( rdataEnd - ptr ) >= 1, exit, err = kMalformedErr );
		
		hashLen = *ptr++;
		require_action_quiet( ( (size_t)( rdataEnd - ptr ) ) >= hashLen, exit, err = kMalformedErr );
		
		if( hashLen > 0 )
		{
			err = _DataBuffer_AppendF( &db, " " );
			require_noerr_quiet( err, exit );
		}
		
		// Unpadded Base 32 Encoding with Extended Hex Alphabet (see <https://tools.ietf.org/html/rfc4648#section-7>)
		// A full quantum is 40 bits, i.e., five concatenated 8-bit input groups are treated as eight concatenated 5-bit
		// groups.
		
		hashEnd = ptr + hashLen;
		while( ( rem = (size_t)( hashEnd - ptr ) ) > 0 )
		{
			uint64_t				quantum;
			size_t					encodedLen;
			char					encodedBuf[ 8 ];
			static const char		kBase32ExtendedHex[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
			
			check_compile_time_code( sizeof_string( kBase32ExtendedHex ) == 32 );
			
			quantum = 0;
			switch( rem )
			{
				default:
				case 5: quantum |=   (uint64_t)ptr[ 4 ];			// Bits 32 - 39
				case 4: quantum |= ( (uint64_t)ptr[ 3 ] ) <<  8;	// Bits 24 - 31
				case 3: quantum |= ( (uint64_t)ptr[ 2 ] ) << 16;	// Bits 16 - 23
				case 2: quantum |= ( (uint64_t)ptr[ 1 ] ) << 24;	// Bits  8 - 15
				case 1: quantum |= ( (uint64_t)ptr[ 0 ] ) << 32;	// Bits  0 -  7
			}
			ptr += ( ( rem > 5 ) ? 5 : rem );
			
			encodedLen = 0;
			switch( rem )
			{
				default:
				case 5:
					encodedBuf[ 7 ] = kBase32ExtendedHex[   quantum         & 0x1F ]; // Bits 35 - 39
					encodedLen = 8;
					
				case 4:
					encodedBuf[ 6 ] = kBase32ExtendedHex[ ( quantum >>  5 ) & 0x1F ]; // Bits 30 - 34
					encodedBuf[ 5 ] = kBase32ExtendedHex[ ( quantum >> 10 ) & 0x1F ]; // Bits 25 - 29
					if( encodedLen == 0 ) encodedLen = 7;
					
				case 3:
					encodedBuf[ 4 ] = kBase32ExtendedHex[ ( quantum >> 15 ) & 0x1F ]; // Bits 20 - 24
					if( encodedLen == 0 ) encodedLen = 5;
					
				case 2:
					encodedBuf[ 3 ] = kBase32ExtendedHex[ ( quantum >> 20 ) & 0x1F ]; // Bits 15 - 19
					encodedBuf[ 2 ] = kBase32ExtendedHex[ ( quantum >> 25 ) & 0x1F ]; // Bits 10 - 14
					if( encodedLen == 0 ) encodedLen = 4;
					
				case 1:
					encodedBuf[ 1 ] = kBase32ExtendedHex[ ( quantum >> 30 ) & 0x1F ]; // Bits 5  - 9
					encodedBuf[ 0 ] = kBase32ExtendedHex[ ( quantum >> 35 ) & 0x1F ]; // Bits 0  - 4
					if( encodedLen == 0 ) encodedLen = 2;
			}
			err = _DataBuffer_Append( &db, encodedBuf, encodedLen );
			require_noerr_quiet( err, exit );
		}
		err = _DNSRecordDataAppendTypeBitMap( &db, ptr, rdataEnd, NULL );
		require_noerr_quiet( err, exit );
	}
	
	// DS Record (see <https://tools.ietf.org/html/rfc4034#section-5.3>)
	
	else if( inRecordType == kDNSRecordType_DS )
	{
		const dns_fixed_fields_ds *		fields;
		const uint8_t *					digestPtr;
		size_t							digestLen;
		
		require_action_quiet( ( (size_t)( rdataEnd - rdataPtr ) ) >= sizeof( *fields ), exit, err = kMalformedErr );
		
		fields = (const dns_fixed_fields_ds *) rdataPtr;
		err = _DataBuffer_AppendF( &db, "%u %u %u",
			dns_fixed_fields_ds_get_key_tag( fields ),
			dns_fixed_fields_ds_get_algorithm( fields ),
			dns_fixed_fields_ds_get_digest_type( fields ) );
		require_noerr_quiet( err, exit );
		
		digestPtr = (const uint8_t *) &fields[ 1 ];
		digestLen = (size_t)( rdataEnd - digestPtr );
		if( digestLen > 0 )
		{
			err = _DataBuffer_AppendF( &db, " %.4H", digestPtr, (int) digestLen, (int) digestLen );
			require_noerr_quiet( err, exit );
		}
	}
	
	// HTTPS or SVCB Record
	
	else if( ( inRecordType == kDNSRecordType_HTTPS ) || ( inRecordType == kDNSRecordType_SVCB ) )
	{
		err = _AppendSVCBRDataString( &db, rdataPtr, rdataEnd, inPrivacy );
		require_noerr_quiet( err, exit );
	}
	
	// OPT Record (see <https://tools.ietf.org/html/rfc6891#section-6.1.2>)
	
	else if( inRecordType == kDNSRecordType_OPT )
	{
		err = _AppendOPTRDataString( &db, rdataPtr, rdataEnd, inPrivacy );
		require_noerr_quiet( err, exit );
	}
	
	// Unhandled record type
	
	else
	{
		err = kNotHandledErr;
		goto exit;
	}
	err = _DataBuffer_Append( &db, "", 1 ); // NUL terminator.
	require_noerr_quiet( err, exit );
	
	err = _DataBuffer_Detach( &db, (uint8_t **) outString, &len );
	require_noerr_quiet( err, exit );
	
exit:
	_DataBuffer_Free( &db );
	return( err );
}

static OSStatus
	_DNSRecordDataAppendTypeBitMap(
		DataBuffer *		inDB,
		const uint8_t *		inPtr,
		const uint8_t *		inEnd,
		const uint8_t **	outPtr )
{
	OSStatus			err;
	const uint8_t *		ptr = inPtr;
	int					bitmapLen;
	
	while( ( inEnd - ptr ) > 0 )
	{
		int		windowBlock, i;
		
		require_action_quiet( ( inEnd - ptr ) > 2, exit, err = kMalformedErr );
		
		windowBlock	= *ptr++;
		bitmapLen	= *ptr++;
		require_action_quiet( ( bitmapLen >= 1 ) && ( bitmapLen <= 32 ) , exit, err = kMalformedErr );
		require_action_quiet( ( inEnd - ptr ) >= bitmapLen, exit, err = kMalformedErr );
		
		for( i = 0; i < BitArray_MaxBits( bitmapLen ); ++i )
		{
			const int		windowBase = windowBlock * 256;
			
			if( BitArray_GetBit( ptr, bitmapLen, i ) )
			{
				int					recordType;
				const char *		typeStr;
				char				typeBuf[ 32 ];
				
				recordType = windowBase + i;
				typeStr = DNSRecordTypeValueToString( recordType );
				if( !typeStr )
				{
					snprintf( typeBuf, sizeof( typeBuf ), "TYPE%u", recordType );
					typeStr = typeBuf;
				}
				err = _DataBuffer_AppendF( inDB, " %s", typeStr );
				require_noerr_quiet( err, exit );
			}
		}
		ptr += bitmapLen;
	}
	if( outPtr ) *outPtr = ptr;
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================
// Based on reference implementation from <https://tools.ietf.org/html/rfc4034#appendix-B>.

uint16_t	DNSComputeDNSKeyTag( const void *inRDataPtr, size_t inRDataLen )
{
	const uint8_t * const		rdataPtr = (const uint8_t *) inRDataPtr;
	uint32_t					accumulator;
	size_t						i;
	
	accumulator = 0;
	for( i = 0; i < inRDataLen; ++i )
	{
		accumulator += ( i & 1 ) ? rdataPtr[ i ] : (uint32_t)( rdataPtr[ i ] << 8 );
	}
	accumulator += ( accumulator >> 16 ) & UINT32_C( 0xFFFF );
	return( accumulator & UINT32_C( 0xFFFF ) );
}

//===========================================================================================================================

int	DNSMessagePrintObfuscatedString( char *inBufPtr, size_t inBufLen, const char *inString )
{
	if( _NameIsPrivate( inString ) )
	{
		return( _SNPrintF( inBufPtr, inBufLen, "%~s", inString ) );
	}
	else
	{
		return( _SNPrintF( inBufPtr, inBufLen, "%s", inString ) );
	}
}

//===========================================================================================================================

int	DNSMessagePrintObfuscatedIPv4Address( char *inBufPtr, size_t inBufLen, const uint32_t inAddr )
{
	uint8_t		addrBytes[ 4 ];
	
	WriteBig32( addrBytes, inAddr );
	if( !_IPv4AddressIsWhitelisted( addrBytes ) )
	{
		return( _DNSMessagePrintObfuscatedIPAddress( inBufPtr, inBufLen, addrBytes, sizeof( addrBytes ) ) );
	}
	else
	{
		return( _SNPrintF( inBufPtr, inBufLen, "%#.4a", &inAddr ) );
	}
}

//===========================================================================================================================

int	DNSMessagePrintObfuscatedIPv6Address( char *inBufPtr, size_t inBufLen, const uint8_t inAddr[ STATIC_PARAM 16 ] )
{
	if( !_IPv6AddressIsWhitelisted( inAddr ) )
	{
		return( _DNSMessagePrintObfuscatedIPAddress( inBufPtr, inBufLen, inAddr, 16 ) );
	}
	else
	{
		return( _SNPrintF( inBufPtr, inBufLen, "%.16a", inAddr ) );
	}
}

//===========================================================================================================================
// MARK: - Helper Functions

static Boolean	_NameIsPrivate( const char * const inDomainNameStr )
{
	if( strcasecmp( inDomainNameStr, "." )				== 0 ) return( false );
	if( strcasecmp( inDomainNameStr, "ipv4only.arpa." )	== 0 ) return( false );
	return( true );
}

//===========================================================================================================================

static OSStatus
	_AppendDomainNameString(
		DataBuffer * const	inDB,
		const Boolean		inPrivacy,
		const char * const	inDomainNameStr )
{
	return( _AppendDomainNameStringEx( inDB, NULL, inPrivacy, inDomainNameStr ) );
}

//===========================================================================================================================

static OSStatus
	_AppendDomainNameStringEx(
		DataBuffer * const	inDB,
		const char * const	inSeparator,
		const Boolean		inPrivacy,
		const char * const	inDomainNameStr )
{
	OSStatus				err;
	const char * const		sep = inSeparator ? inSeparator : "";
	
	if( inPrivacy && _NameIsPrivate( inDomainNameStr ) )
	{
		err = _DataBuffer_AppendF( inDB, "%s%~s", sep, inDomainNameStr );
		require_noerr_quiet( err, exit );
	}
	else
	{
		err = _DataBuffer_AppendF( inDB, "%s%s", sep, inDomainNameStr );
		require_noerr_quiet( err, exit );
	}
	
exit:
	return( err );
}

//===========================================================================================================================

static OSStatus
	_AppendOPTRDataString(
		DataBuffer * const		inDB,
		const uint8_t * const	inRDataPtr,
		const uint8_t *	const	inRDataEnd,
		const Boolean			inPrivacy )
{
	OSStatus			err;
	const uint8_t *		ptr;
	const char *		sep;
	
	ptr = inRDataPtr;
	require_action_quiet( ptr <= inRDataEnd, exit, err = kRangeErr );
	
	sep = "";
	while( ptr < inRDataEnd )
	{
		const dns_fixed_fields_option *		fields;
		const uint8_t *						data;
		unsigned int						code, length;
		
		require_action_quiet( ( (size_t)( inRDataEnd - ptr ) ) >= sizeof( *fields ), exit, err = kUnderrunErr );
		fields = (const dns_fixed_fields_option *) ptr;
		code	= dns_fixed_fields_option_get_code( fields );
		length	= dns_fixed_fields_option_get_length( fields );
		ptr = (const uint8_t *) &fields[ 1 ];
		
		require_action_quiet( ( (size_t)( inRDataEnd - ptr ) ) >= length, exit, err = kUnderrunErr );
		data = ptr;
		ptr += length;
		
		err = _DataBuffer_AppendF( inDB, "%s{", sep );
		require_noerr_quiet( err, exit );
		
		if( code == kDNSEDNS0OptionCode_Padding )
		{
			err = _DataBuffer_AppendF( inDB, "Padding" );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = _DataBuffer_AppendF( inDB, "CODE%u", code );
			require_noerr_quiet( err, exit );
		}
		err = _DataBuffer_AppendF( inDB, ", " );
		require_noerr_quiet( err, exit );
		
		if( inPrivacy )
		{
			err = _DataBuffer_AppendF( inDB, "[%u B]", length );
			require_noerr_quiet( err, exit );
		}
		else
		{
			if( ( code == kDNSEDNS0OptionCode_Padding ) && _MemIsAllZeros( data, length ) )
			{
				err = _DataBuffer_AppendF( inDB, "<%u zero bytes>", length );
				require_noerr_quiet( err, exit );
			}
			else
			{
				err = _DataBuffer_AppendF( inDB, "'%H'", data, (int) length, (int) length );
				require_noerr_quiet( err, exit );
			}
		}
		err = _DataBuffer_AppendF( inDB, "}" );
		require_noerr_quiet( err, exit );
		
		sep = ", ";
	}
	err = kNoErr;
	
exit:
	return( err );
}

//===========================================================================================================================

static const char *	_DNSSVCBKeyToString( int inValue );

static OSStatus
	_AppendSVCBRDataString(
		DataBuffer * const		inDB,
		const uint8_t * const	inRDataPtr,
		const uint8_t *	const	inRDataEnd,
		const Boolean			inPrivacy )
{
	OSStatus							err;
	const uint8_t *						ptr;
	const char *						sep;
	const dns_fixed_fields_svcb *		fields;
	char								domainNameStr[ kDNSServiceMaxDomainName ];
	
	ptr = inRDataPtr;
	require_action_quiet( ptr <= inRDataEnd, exit, err = kRangeErr );
	require_action_quiet( ( (size_t)( inRDataEnd - ptr ) ) >= sizeof( *fields ), exit, err = kMalformedErr );
	
	// SvcFieldPriority
	
	fields = (const dns_fixed_fields_svcb *) ptr;
	err = _DataBuffer_AppendF( inDB, "%u", dns_fixed_fields_svcb_get_priority( fields ) );
	require_noerr_quiet( err, exit );
	
	// SvcDomainName
	
	ptr = (const uint8_t *) &fields[ 1 ];
	err = DomainNameToString( ptr, inRDataEnd, domainNameStr, &ptr );
	require_noerr_quiet( err, exit );
	
	err = _AppendDomainNameStringEx( inDB, " ", inPrivacy, domainNameStr );
	require_noerr_quiet( err, exit );
	
	// SvcFieldValue
	// Follows types for <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-00>
	
	while( ptr < inRDataEnd )
	{
		const dns_fixed_fields_svcb_param *		paramFields;
		const uint8_t *							limit;
		const char *							keyStr;
		int										key;
		unsigned int							valLen;
		
		require_action_quiet( ( (size_t)( inRDataEnd - ptr ) ) >= sizeof( *paramFields ), exit, err = kUnderrunErr );
		
		paramFields = (const dns_fixed_fields_svcb_param *) ptr;
		key		= dns_fixed_fields_svcb_param_get_key( paramFields );
		valLen	= dns_fixed_fields_svcb_param_get_value_length( paramFields );
		
		keyStr = _DNSSVCBKeyToString( key );
		if( keyStr )
		{
			err = _DataBuffer_AppendF( inDB, " %s=\"", keyStr );
			require_noerr_quiet( err, exit );
		}
		else
		{
			err = _DataBuffer_AppendF( inDB, " key%u=\"", key );
			require_noerr_quiet( err, exit );
		}
		ptr = (const uint8_t *) &paramFields[ 1 ];
		require_action_quiet( ( (size_t)( inRDataEnd - ptr ) ) >= valLen, exit, err = kUnderrunErr );
		
		switch( key )
		{
			case kDNSSVCParamKey_Mandatory:
			{
				// List of 16-bit keys
				// See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-6.5>.

				require_action_quiet( ( valLen % 2 ) == 0, exit, err = kMalformedErr );

				sep = NULL;
				limit = &ptr[ valLen ];
				while( ptr < limit )
				{
					int				mandatoryKey;
					const char *	mandatoryKeyStr;

					mandatoryKey = ReadBig16( ptr );
					ptr += 2;

					mandatoryKeyStr = _DNSSVCBKeyToString( mandatoryKey );
					if( sep )
					{
						err = _DataBuffer_AppendF( inDB, "%s", sep );
						require_noerr_quiet( err, exit );
					}
					if( mandatoryKeyStr )
					{
						err = _DataBuffer_AppendF( inDB, "%s", mandatoryKeyStr );
						require_noerr_quiet( err, exit );
					}
					else
					{
						err = _DataBuffer_AppendF( inDB, "key%u", mandatoryKey );
						require_noerr_quiet( err, exit );
					}
					sep = ",";
				}
				break;
			}

			case kDNSSVCParamKey_ALPN:
			{
				// Length-prefixed ALPN protocol ID octet sequences
				// See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-6.1>.
				
				sep = NULL;
				limit = &ptr[ valLen ];
				while( ptr < limit )
				{
					const uint8_t *			alpnLimit;
					const unsigned int		alpnLen = *ptr++;
					
					require_action_quiet( ( (size_t)( limit - ptr ) ) >= alpnLen, exit, err = kMalformedErr );
					
					if( sep )
					{
						err = _DataBuffer_AppendF( inDB, "%s", sep );
						require_noerr_quiet( err, exit );
					}
					for( alpnLimit = &ptr[ alpnLen ]; ptr < alpnLimit; ++ptr )
					{
						const int		c = *ptr;
						
						if( _isprint_ascii( c ) )
						{
							if( ( c == ',' ) || ( c == '\\' ) )
							{
								// Escape commas and backslashes.
								
								err = _DataBuffer_AppendF( inDB, "\\%c", c );
								require_noerr_quiet( err, exit );
							}
							else
							{
								err = _DataBuffer_AppendF( inDB, "%c", c );
								require_noerr_quiet( err, exit );
							}
						}
						else
						{
							// Use a three digit decimal escape code (\DDD) for non-printable octets.
							
							err = _DataBuffer_AppendF( inDB, "\\%03d", c );
							require_noerr_quiet( err, exit );
						}
					}
					sep = ",";
				}
				break;
			}
			case kDNSSVCParamKey_Port:
			{
				unsigned int		port;
				
				// 16-bit Integer
				// See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-6.2>.
				
				require_action_quiet( valLen == 2, exit, err = kMalformedErr );
				
				port = ReadBig16( ptr );
				ptr += valLen;
				
				err = _DataBuffer_AppendF( inDB, "%u", port );
				require_noerr_quiet( err, exit );
				break;
			}
			case kDNSSVCParamKey_IPv4Hint:
			{
				// IPv4 address list
				// See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-6.4>.
				
				require_action_quiet( ( valLen % 4 ) == 0, exit, err = kMalformedErr );
				
				sep = "";
				for( limit = &ptr[ valLen ]; ptr < limit; ptr += 4 )
				{
					err = _AppendIPv4Address( inDB, sep, ptr, inPrivacy );
					require_noerr_quiet( err, exit );
					sep = ",";
				}
				break;
			}
			case kDNSSVCParamKey_IPv6Hint:
			{
				// IPv6 address list
				// See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-6.4>.
				
				require_action_quiet( ( valLen % 16 ) == 0, exit, err = kMalformedErr );
				
				sep = "";
				for( limit = &ptr[ valLen ]; ptr < limit; ptr += 16 )
				{
					err = _AppendIPv6Address( inDB, sep, ptr, inPrivacy );
					require_noerr_quiet( err, exit );
					sep = ",";
				}
				break;
			}
			default:
			{
				// Other keys.
				// See <https://tools.ietf.org/html/draft-ietf-dnsop-svcb-https-01#section-2.1.1>.
				
				if( inPrivacy )
				{
					err = _DataBuffer_AppendF( inDB, "<%u redacted bytes>", valLen );
					require_noerr_quiet( err, exit );
					ptr += valLen;
				}
				else
				{
					for( limit = &ptr[ valLen ]; ptr < limit; ++ptr )
					{
						const int		c = *ptr;
						
						if( ( c >= 0x21 ) && ( c <= 0x7E ) )
						{
							// Visible characters are printed.
							
							switch( c )
							{
								// Escape reserved characters.
								
								case '"':
								case ';':
								case '(':
								case ')':
								case '\\':
									err = _DataBuffer_AppendF( inDB, "\\%c", c );
									require_noerr_quiet( err, exit );
									break;
								
								default:
									err = _DataBuffer_AppendF( inDB, "%c", c );
									require_noerr_quiet( err, exit );
									break;
							}
						}
						else
						{
							// Invisible characters use a three digit decimal escape code (\DDD).
							
							err = _DataBuffer_AppendF( inDB, "\\%03d", c );
							require_noerr_quiet( err, exit );
						}
					}
				}
				break;
			}
		}
		err = _DataBuffer_AppendF( inDB, "\"" );
		require_noerr_quiet( err, exit );
	}
	
exit:
	return( err );
}

static const char *	_DNSSVCBKeyToString( const int inValue )
{
	switch( inValue )
	{
		case kDNSSVCParamKey_Mandatory:		return( "mandatory" );
		case kDNSSVCParamKey_ALPN:			return( "alpn" );
		case kDNSSVCParamKey_NoDefaultALPN:	return( "no-default-alpn" );
		case kDNSSVCParamKey_Port:			return( "port" );
		case kDNSSVCParamKey_IPv4Hint:		return( "ipv4hint" );
		case kDNSSVCParamKey_ECHConfig:		return( "echconfig" );
		case kDNSSVCParamKey_IPv6Hint:		return( "ipv6hint" );
		case kDNSSVCParamKey_DOHURI:		return( "dohuri" );
		default:							return( NULL );
	}
}

//===========================================================================================================================

static OSStatus
	_AppendIPv4Address(
		DataBuffer * const	inDB,
		const char * const	inSeparator,
		const uint8_t		inAddrBytes[ STATIC_PARAM 4 ],
		const Boolean		inPrivacy )
{
	return( _AppendIPAddress( inDB, inSeparator, inAddrBytes, 4, inPrivacy && !_IPv4AddressIsWhitelisted( inAddrBytes ) ) );
}

//===========================================================================================================================

static OSStatus
	_AppendIPv6Address(
		DataBuffer * const	inDB,
		const char * const	inSeparator,
		const uint8_t		inAddrBytes[ STATIC_PARAM 16 ],
		Boolean				inPrivacy )
{
	return( _AppendIPAddress( inDB, inSeparator, inAddrBytes, 16, inPrivacy && !_IPv6AddressIsWhitelisted( inAddrBytes ) ) );
}

//===========================================================================================================================

static OSStatus
	_AppendIPAddress(
		DataBuffer *	inDB,
		const char *	inSeparator,
		const uint8_t *	inAddrPtr,
		int				inAddrLen,
		Boolean			inPrivacy )
{
	OSStatus				err;
	const char * const		sep = inSeparator ? inSeparator : "";
	
	require_action_quiet( ( inAddrLen == 4 ) || ( inAddrLen == 16 ), exit, err = kSizeErr );
	
	if( inPrivacy )
	{
		int			n;
		char		tmpBuf[ ( 16 * 2 ) + 1 ];
		
		n = _SNPrintF( tmpBuf, sizeof( tmpBuf ), "%.4H", inAddrPtr, (int) inAddrLen, (int) inAddrLen );
		require_action_quiet( n >= 0, exit, err = n );
		
		err = _DataBuffer_AppendF( inDB, "%s%~s", sep, tmpBuf );
		require_noerr_quiet( err, exit );
	}
	else
	{
		err = _DataBuffer_AppendF( inDB, "%s%.*a", sep, inAddrLen, inAddrPtr );
		require_noerr_quiet( err, exit );
	}
	
exit:
	return( err );
}

//===========================================================================================================================

static void *	_GetCULibHandle( void )
{
	static dispatch_once_t		sOnce	= 0;
	static void *				sHandle	= NULL;
	
	dispatch_once( &sOnce,
	^{
		sHandle = dlopen( "/System/Library/PrivateFrameworks/CoreUtils.framework/CoreUtils", RTLD_NOW );
	} );
	return( sHandle );
}

//===========================================================================================================================

static Boolean	_MemIsAllZeros( const uint8_t * const inMemPtr, const size_t inMemLen )
{
	require_return_value( inMemLen > 0, false );
	
	// The memcmp() call below compares two subregions of length inMemLen - 1. The first subregion starts at
	// inMemPtr, and the second subregion starts at inMemPtr + 1. The memcmp() call will return zero if for all
	// i in {0, 1, ..., inMemLen - 2}, inMemPtr[i] == inMemPtr[i + 1]. That is, memcmp() will return zero if all
	// bytes are equal. So if inMemPtr[0] == 0, and the memcmp() call returns zero, then all bytes are equal to zero.
	
	return( ( inMemPtr[ 0 ] == 0 ) && ( memcmp( inMemPtr, inMemPtr + 1, inMemLen - 1 ) == 0 ) );
}

//===========================================================================================================================

static Boolean	_IPv4AddressIsWhitelisted( const uint8_t inAddrBytes[ STATIC_PARAM 4 ] )
{
	// Whitelist the all-zeros and localhost addresses.
	
	switch( ReadBig32( inAddrBytes ) )
	{
		case 0:							// 0.0.0.0
		case UINT32_C( 0x7F000001 ):	// 127.0.0.1
			return( true );
		
		default:
			return( false );
	}
}

//===========================================================================================================================

static Boolean	_IPv6AddressIsWhitelisted( const uint8_t inAddrBytes[ STATIC_PARAM 16 ] )
{
	// Whitelist the all-zeros and localhost addresses, i.e., :: and ::1.
	
	if( ( memcmp( inAddrBytes, AllZeros16Bytes, 15 ) == 0 ) && ( ( inAddrBytes[ 15 ] == 0 ) || ( inAddrBytes[ 15 ] == 1 ) ) )
	{
		return( true );
	}
	else
	{
		return( false );
	}
}

//===========================================================================================================================

static int
	_DNSMessagePrintObfuscatedIPAddress(
		char *			inBufPtr,
		size_t			inBufLen,
		const uint8_t *	inAddrBytes,
		size_t			inAddrLen )
{
	int			n;
	char		tmpBuf[ ( 16 * 2 ) + 1 ];
	
	require_return_value( ( inAddrLen == 4 ) || ( inAddrLen == 16 ), kSizeErr );
	
	n = _SNPrintF( tmpBuf, sizeof( tmpBuf ), "%.4H", inAddrBytes, (int) inAddrLen, (int) inAddrLen );
	require_return_value( n >= 0, n );
	
	return( _SNPrintF( inBufPtr, inBufLen, "%~s", tmpBuf ) );
}
