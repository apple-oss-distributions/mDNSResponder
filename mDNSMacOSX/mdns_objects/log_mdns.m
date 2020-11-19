/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#import "DNSMessage.h"

#import <CoreUtils/CoreUtils.h>
#import <Foundation/Foundation.h>
#import <os/log_private.h>

#if !COMPILER_ARC
	#error "This file must be compiled with ARC."
#endif

//======================================================================================================================
// MARK: - Specifiers
//
//	Data Type				Specifier							Arguments							Notes
//	DNS message				%{mdns:dnsmsg}.*P					length (int), pointer (void *)		-
//	DNS message header		%{mdns:dnshdr}.*P					length (int), pointer (void *)		-
//	Error code integer		%{mdns:err}d, %{mdns:err}ld, etc.	error code (int, OSStatus, etc.)	1
//	DNS record data			%{mdns:rd.<record type>}.*P			length (int), pointer (void *)		2,3,4
//	DNS record type			%{mdns:rrtype}d						record type (int)
//	
//	Notes:
//	1. Formatting is handled by NSPrintTypedObject() from the CoreUtils framework, which handles a large variety of
//	   error codes, including errno and kDNSServiceErr_* error codes.
//	2. The DNS record data must be fully expanded, i.e., it must not contain any compressed DNS domain names.
//	3. The <record type> portion of the specifier is a case-insensitive DNS record type mnemonic, e.g., A, AAAA,
//	   DNSKEY, DS, etc.
//	4. Formatting is handled by DNSRecordDataToString(), which currently only handles a subset of record types.
//	   This subset consists of the record types most commonly encountered by mDNSResponder. This subset may grow
//	   as needed.
//	
//	The specifiers for DNSSEC record data, %{mdns:dnskey}, %{mdns:ds}, %{mdns:nsec}, %{mdns:nsec3}, and
//	%{mdns:rrsig}, have been deprecated in favor of the %{mdns:rd.<record type>} style of record data specifiers.

#define LOG_MDNS_SPECIFIER_DNS_MESSAGE			"dnsmsg"
#define LOG_MDNS_SPECIFIER_DNS_MESSAGE_HEADER	"dnshdr"
#define LOG_MDNS_SPECIFIER_ERROR				"err"
#define LOG_MDNS_SPECIFIER_RDATA_PREFIX			"rd."
#define LOG_MDNS_SPECIFIER_DNS_RECORD_TYPE		"rrtype"

//======================================================================================================================
// MARK: - Data Structures

typedef NSAttributedString *
(*log_mdns_data_formatter_f)(NSData *data);

typedef struct {
	const char *				specifier;
	log_mdns_data_formatter_f	formatter;
} log_mdns_data_formatter_item_t;

typedef NSAttributedString *
(*log_mdns_number_formatter_f)(NSNumber *number);

typedef struct {
	const char *				specifier;
	log_mdns_number_formatter_f	formatter;
} log_mdns_number_formatter_item_t;

//======================================================================================================================
// MARK: - Local Prototypes

static NSAttributedString *
_log_mdns_format_dns_message(NSData *data);

static NSAttributedString *
_log_mdns_format_dns_message_header(NSData *data);

static NSAttributedString *
_log_mdns_format_record_data(NSData *data, int record_type);

static NSAttributedString *
_log_mdns_format_err(NSNumber *number);

static NSAttributedString *
_log_mdns_format_dns_record_type(NSNumber *number);

static NSAttributedString *
_log_mdns_format_dns_message_ex(NSData *data, DNSMessageToStringFlags extra_flags);

//======================================================================================================================
// MARK: - DNS Record Data Formatters

#define LOG_MDNS_DEFINE_RDATA_FORMATTER(RECORD_TYPE)								\
	static NSAttributedString *														\
	_log_mdns_format_record_data_ ## RECORD_TYPE (NSData * const rdata)				\
	{																				\
		return _log_mdns_format_record_data(rdata, kDNSRecordType_ ## RECORD_TYPE);	\
	}																				\
	extern int _log_mdns_dummy_variable

LOG_MDNS_DEFINE_RDATA_FORMATTER(DNSKEY);
LOG_MDNS_DEFINE_RDATA_FORMATTER(DS);
LOG_MDNS_DEFINE_RDATA_FORMATTER(NSEC);
LOG_MDNS_DEFINE_RDATA_FORMATTER(NSEC3);
LOG_MDNS_DEFINE_RDATA_FORMATTER(RRSIG);

//======================================================================================================================
// MARK: - External Functions

#define LOG_MDNS_RDATA_FORMATTER_ITEM(RECORD_TYPE)	{ # RECORD_TYPE, _log_mdns_format_record_data_ ## RECORD_TYPE }

NSAttributedString *
OSLogCopyFormattedString(const char * const specifier, const id arg, __unused const os_log_type_info_t info)
{
	if ([arg isKindOfClass:[NSData class]]) {
		NSData * const data = (NSData *)arg;
		if (stricmp_prefix(specifier, LOG_MDNS_SPECIFIER_RDATA_PREFIX) == 0) {
			const char * const type_str = specifier + sizeof_string(LOG_MDNS_SPECIFIER_RDATA_PREFIX);
			const int type_value = DNSRecordTypeStringToValue(type_str);
			if (type_value != 0) {
				return _log_mdns_format_record_data(data, type_value);
			}
		} else {
			const log_mdns_data_formatter_item_t log_mdns_data_formatter_table[] = {
				{ LOG_MDNS_SPECIFIER_DNS_MESSAGE,		 _log_mdns_format_dns_message },
				{ LOG_MDNS_SPECIFIER_DNS_MESSAGE_HEADER, _log_mdns_format_dns_message_header },
				LOG_MDNS_RDATA_FORMATTER_ITEM(DNSKEY),
				LOG_MDNS_RDATA_FORMATTER_ITEM(DS),
				LOG_MDNS_RDATA_FORMATTER_ITEM(NSEC),
				LOG_MDNS_RDATA_FORMATTER_ITEM(NSEC3),
				LOG_MDNS_RDATA_FORMATTER_ITEM(RRSIG)
			};
			for (size_t i = 0; i < countof(log_mdns_data_formatter_table); ++i) {
				const log_mdns_data_formatter_item_t * const item = &log_mdns_data_formatter_table[i];
				if (strcasecmp(specifier, item->specifier) == 0) {
					return item->formatter(data);
				}
			}
		}
	} else if ([arg isKindOfClass:[NSNumber class]]) {
		const log_mdns_number_formatter_item_t log_mdns_number_formatter_table[] = {
			{ LOG_MDNS_SPECIFIER_ERROR,				_log_mdns_format_err },
			{ LOG_MDNS_SPECIFIER_DNS_RECORD_TYPE,	_log_mdns_format_dns_record_type }
		};
		NSNumber * const number = (NSNumber *)arg;
		for (size_t i = 0; i < countof(log_mdns_number_formatter_table); ++i) {
			const log_mdns_number_formatter_item_t * const item = &log_mdns_number_formatter_table[i];
			if (strcasecmp(specifier, item->specifier) == 0) {
				return item->formatter(number);
			}
		}
	}
	return nil;
}

//======================================================================================================================
// MARK: - Internal Functions

static NSAttributedString *
_log_mdns_format_dns_message(NSData * const data)
{
	return _log_mdns_format_dns_message_ex(data, kDNSMessageToStringFlag_Null);
}

//======================================================================================================================

static NSAttributedString *
_log_mdns_format_dns_message_header(NSData * const data)
{
	return _log_mdns_format_dns_message_ex(data, kDNSMessageToStringFlag_HeaderOnly);
}

//======================================================================================================================

static NSAttributedString *
_log_mdns_format_err(NSNumber * const number)
{
	return NSPrintTypedObject("err", number, NULL);
}

//======================================================================================================================

static NSAttributedString *
_log_mdns_format_dns_record_type(NSNumber * const number)
{
	unsigned long long value = [number unsignedLongLongValue];
	require_return_value(value <= INT_MAX, nil);

	NSString *nsstr;
	const char *cstr = DNSRecordTypeValueToString((int)value);
	if (cstr) {
		nsstr = [[NSString alloc] initWithFormat:@"%s", cstr];
		require_return_value(nsstr, nil);
	} else {
		nsstr = [[NSString alloc] initWithFormat:@"TYPE%u", (unsigned int)value];
		require_return_value(nsstr, nil);
	}
	return [[NSAttributedString alloc] initWithString:nsstr];
}

//======================================================================================================================

static NSAttributedString *
_log_mdns_format_record_data(NSData * const rdata, const int record_type)
{
	char *cstr = NULL;
	DNSRecordDataToString(rdata.bytes, rdata.length, record_type, &cstr);
	if (!cstr) {
		return nil;
	}
	const size_t len = strlen(cstr);
	NSString * const nsstr = [[NSString alloc] initWithBytesNoCopy:cstr length:len encoding:NSUTF8StringEncoding
		freeWhenDone:YES];
	if (!nsstr) {
		ForgetMem(&cstr);
		return nil;
	}
	return [[NSAttributedString alloc] initWithString:nsstr];
}

//======================================================================================================================

static NSAttributedString *
_log_mdns_format_dns_message_ex(NSData * const data, const DNSMessageToStringFlags extra_flags)
{
	char *msg_cstr = NULL;
	const DNSMessageToStringFlags flags = kDNSMessageToStringFlag_OneLine | extra_flags;
	DNSMessageToString(data.bytes, data.length, flags, &msg_cstr);
	require_return_value(msg_cstr, nil);

	NSString *msg_nsstr = [[NSString alloc] initWithBytesNoCopy:msg_cstr length:strlen(msg_cstr)
		encoding:NSUTF8StringEncoding freeWhenDone:YES];
	require_return_value_action(msg_nsstr, nil, ForgetMem(&msg_cstr));

	return [[NSAttributedString alloc] initWithString:msg_nsstr];
}
