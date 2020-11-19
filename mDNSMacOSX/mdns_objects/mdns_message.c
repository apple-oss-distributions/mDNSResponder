/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include "mdns_message.h"

#include "mdns_objects.h"

#include "DNSMessage.h"
#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Message Kind Definition

struct mdns_message_s {
	struct mdns_object_s	base;				// Object base.
	dispatch_data_t			msg_data;			// Underlying object for message data.
	const uint8_t *			msg_ptr;			// Pointer to first byte of message data.
	size_t					msg_len;			// Length of message.
	bool					print_body_only;	// True if only the message body should be printed in description.
};

MDNS_OBJECT_SUBKIND_DEFINE(message);

typedef const struct mdns_message_kind_s *	mdns_message_kind_t;
struct mdns_message_kind_s {
	struct mdns_kind_s	base;
	const char *		name;
};

#define MDNS_MESSAGE_SUBKIND_DEFINE(NAME)															\
	static void																						\
	_mdns_ ## NAME ## _message_finalize(mdns_ ## NAME ## _message_t message);						\
																									\
	static const struct mdns_message_kind_s _mdns_ ## NAME ## _message_kind = {						\
		.base = {																					\
			.superkind	= &_mdns_message_kind,														\
			.name		= "mdns_" # NAME "_message",												\
			.finalize	= _mdns_ ## NAME ## _message_finalize										\
		},																							\
		.name = # NAME "_message"																	\
	};																								\
																									\
	static mdns_ ## NAME ## _message_t																\
	_mdns_ ## NAME ## _message_alloc(void)															\
	{																								\
		mdns_ ## NAME ## _message_t obj;															\
		obj = mdns_ ## NAME ## _message_object_alloc(sizeof(struct mdns_ ## NAME ## _message_s));	\
		require_return_value(obj, NULL);															\
																									\
		const mdns_object_t object = (mdns_object_t)obj;											\
		object->kind = &_mdns_ ## NAME ## _message_kind.base;										\
		return obj;																					\
	}																								\
	MDNS_BASE_CHECK(NAME ## _message, message)

//======================================================================================================================
// MARK: - Query Message Kind Definition

struct mdns_query_message_s {
	struct mdns_message_s	base;				// Message object base.
	uint8_t *				qname;				// Question's QNAME.
	uint16_t				qtype;				// Question's QTYPE.
	uint16_t				qclass;				// Question's QCLASS.
	uint16_t				msg_id;				// Message ID.
	bool					set_ad_bit;			// True if the AD (authentic data) bit is to be set.
	bool					set_cd_bit;			// True if the CD (checking disabled) bit is to be set.
	bool					set_do_bit;			// True if the DO (DNSSEC OK) bit is to be set in OPT record.
	bool					use_edns0_padding;	// True if the query uses EDNS0 padding.
	bool					constructed;		// True if the message has been constructed.
};

MDNS_MESSAGE_SUBKIND_DEFINE(query);

//======================================================================================================================
// MARK: - Local Prototypes

static OSStatus
_mdns_message_init(mdns_any_message_t message, dispatch_data_t msg_data, mdns_message_init_options_t options);

static OSStatus
_mdns_message_set_msg_data(mdns_any_message_t message, dispatch_data_t msg_data);

const uint8_t *
_mdns_query_message_get_qname_safe(mdns_query_message_t query_message);

//======================================================================================================================
// MARK: - Messge Public Methods

mdns_message_t
mdns_message_create_with_dispatch_data(const dispatch_data_t data, const mdns_message_init_options_t options)
{
	mdns_message_t message = NULL;
	mdns_message_t obj = _mdns_message_alloc();
	require_quiet(obj, exit);

	const OSStatus err = _mdns_message_init(obj, data, options);
	require_noerr_quiet(err, exit);

	message = obj;
	obj = NULL;

exit:
	mdns_release_null_safe(obj);
	return message;
}

//======================================================================================================================

dispatch_data_t
mdns_message_get_dispatch_data(const mdns_message_t me)
{
	return me->msg_data;
}

//======================================================================================================================

const uint8_t *
mdns_message_get_byte_ptr(const mdns_message_t me)
{
	return me->msg_ptr;
}

//======================================================================================================================

size_t
mdns_message_get_length(const mdns_message_t me)
{
	return me->msg_len;
}

//======================================================================================================================
// MARK: - Message Private Methods

static char *
_mdns_message_copy_description(mdns_message_t me, __unused const bool debug, const bool privacy)
{
	char *description = NULL;
	if (me->msg_ptr) {
		DNSMessageToStringFlags flags = kDNSMessageToStringFlag_OneLine;
		if (me->print_body_only) {
			flags |= kDNSMessageToStringFlag_BodyOnly;
		}
		if (privacy) {
			flags |= kDNSMessageToStringFlag_Privacy;
		}
		DNSMessageToString(me->msg_ptr, me->msg_len, flags, &description);
	}
	return description;
}

//======================================================================================================================

static void
_mdns_message_finalize(const mdns_message_t me)
{
	me->msg_ptr = NULL;
	dispatch_forget(&me->msg_data);
}

//======================================================================================================================

static OSStatus
_mdns_message_init(const mdns_any_message_t any, const dispatch_data_t msg_data,
	const mdns_message_init_options_t options)
{
	const mdns_message_t me = any.message;
	if (options & mdns_message_init_option_disable_header_printing) {
		me->print_body_only = true;
	}
	return _mdns_message_set_msg_data(me, msg_data);
}

//======================================================================================================================

static OSStatus
_mdns_message_set_msg_data(const mdns_any_message_t any, const dispatch_data_t msg_data)
{
	dispatch_data_t	msg_data_new;
	const uint8_t *	msg_ptr;
	size_t			msg_len;
	if (msg_data) {
		msg_data_new = dispatch_data_create_map(msg_data, (const void **)&msg_ptr, &msg_len);
		require_return_value(msg_data_new, kNoMemoryErr);
	} else {
		msg_data_new = dispatch_data_empty;
		msg_ptr = NULL;
		msg_len = 0;
	}
	const mdns_message_t me = any.message;
	dispatch_release_null_safe(me->msg_data);
	me->msg_data = msg_data_new;
	me->msg_ptr  = msg_ptr;
	me->msg_len  = msg_len;
	return kNoErr;
}

//======================================================================================================================
// MARK: - Query Messge Public Methods

mdns_query_message_t
mdns_query_message_create(const mdns_message_init_options_t options)
{
	mdns_query_message_t message = NULL;
	mdns_query_message_t obj = _mdns_query_message_alloc();
	require_quiet(obj, exit);

	const OSStatus err = _mdns_message_init(obj, NULL, options);
	require_noerr_quiet(err, exit);

	message = obj;
	obj = NULL;

exit:
	mdns_release_null_safe(obj);
	return message;
}

//======================================================================================================================

OSStatus
mdns_query_message_set_qname(const mdns_query_message_t me, const uint8_t * const qname)
{
	require_return_value(!me->constructed, kNoErr);

	uint8_t *qname_dup = NULL;
	OSStatus err = DomainNameDup(qname, &qname_dup, NULL);
	require_noerr_quiet(err, exit);

	FreeNullSafe(me->qname);
	me->qname = qname_dup;
	qname_dup = NULL;
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

void
mdns_query_message_set_qtype(const mdns_query_message_t me, const uint16_t qtype)
{
	require_return(!me->constructed);
	me->qtype = qtype;
}

//======================================================================================================================

void
mdns_query_message_set_qclass(const mdns_query_message_t me, const uint16_t qclass)
{
	require_return(!me->constructed);
	me->qclass = qclass;
}

//======================================================================================================================

void
mdns_query_message_set_message_id(const mdns_query_message_t me, const uint16_t msg_id)
{
	require_return(!me->constructed);
	me->msg_id = msg_id;
}

//======================================================================================================================

void
mdns_query_message_set_ad_bit(const mdns_query_message_t me, const bool set)
{
	require_return(!me->constructed);
	me->set_ad_bit = set;
}

//======================================================================================================================

void
mdns_query_message_set_cd_bit(const mdns_query_message_t me, const bool set)
{
	require_return(!me->constructed);
	me->set_cd_bit = set;
}

//======================================================================================================================

void
mdns_query_message_set_do_bit(const mdns_query_message_t me, const bool set)
{
	require_return(!me->constructed);
	me->set_do_bit = set;
}

//======================================================================================================================

void
mdns_query_message_use_edns0_padding(const mdns_query_message_t me, const bool use)
{
	require_return(!me->constructed);
	me->use_edns0_padding = use;
}

//======================================================================================================================

#define MDNS_EDNS0_PADDING_OVERHEAD		 15	// Size of OPT pseudo-RR with OPTION-CODE and OPTION-LENGTH
#define MDNS_EDNS0_PADDING_BLOCK_SIZE	128	// <https://tools.ietf.org/html/rfc8467#section-4.1>

#define MDNS_QUERY_MESSAGE_BUFFER_SIZE \
	RoundUp(kDNSQueryMessageMaxLen + MDNS_EDNS0_PADDING_OVERHEAD, MDNS_EDNS0_PADDING_BLOCK_SIZE)

static OSStatus
_mdns_query_message_add_edns0_padding(uint8_t query_buf[static MDNS_QUERY_MESSAGE_BUFFER_SIZE], size_t query_len,
	bool set_do_bit, size_t *out_len);

static OSStatus
_mdns_query_message_add_edns0_dnssec_ok(uint8_t query_buf[static MDNS_QUERY_MESSAGE_BUFFER_SIZE], size_t query_len,
	size_t *out_len);

OSStatus
mdns_query_message_construct(const mdns_query_message_t me)
{
	uint16_t flags = kDNSHeaderFlag_RecursionDesired;
	if (me->set_ad_bit) {
		flags |= kDNSHeaderFlag_AuthenticData;
	}
	if (me->set_cd_bit) {
		flags |= kDNSHeaderFlag_CheckingDisabled;
	}
	uint8_t	query_buf[MDNS_QUERY_MESSAGE_BUFFER_SIZE];
	size_t	query_len;
	const uint8_t * const qname = _mdns_query_message_get_qname_safe(me);
	OSStatus err = DNSMessageWriteQuery(me->msg_id, flags, qname, me->qtype, me->qclass, query_buf, &query_len);
	require_noerr_quiet(err, exit);

	if (me->use_edns0_padding) {
		err = _mdns_query_message_add_edns0_padding(query_buf, query_len, me->set_do_bit, &query_len);
		require_noerr_quiet(err, exit);
	} else if (me->set_do_bit) {
		err = _mdns_query_message_add_edns0_dnssec_ok(query_buf, query_len, &query_len);
		require_noerr_quiet(err, exit);
	}
	dispatch_data_t query_data = dispatch_data_create(query_buf, query_len, NULL, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
	require_action_quiet(query_data, exit, err = kNoMemoryErr);

	err = _mdns_message_set_msg_data(me, query_data);
	dispatch_forget(&query_data);
	require_noerr_quiet(err, exit);

	me->constructed = true;

exit:
	return err;
}

static OSStatus
_mdns_query_message_add_edns0_padding(uint8_t query_buf[static MDNS_QUERY_MESSAGE_BUFFER_SIZE], const size_t query_len,
	const bool set_do_bit, size_t * const out_len)
{
	const size_t new_len = RoundUp(query_len + MDNS_EDNS0_PADDING_OVERHEAD, MDNS_EDNS0_PADDING_BLOCK_SIZE);
	require_return_value(new_len <= MDNS_QUERY_MESSAGE_BUFFER_SIZE, kSizeErr);

	uint8_t * const			end		= &query_buf[query_len];
	const uint8_t * const	new_end	= &query_buf[new_len];
	memset(end, 0, (size_t)(new_end - end));

	check_compile_time_code(MDNS_EDNS0_PADDING_OVERHEAD == sizeof(dns_fixed_fields_opt1));

	dns_fixed_fields_opt1 * const	pad_opt		= (dns_fixed_fields_opt1 *)end;
	const uint8_t * const			pad_start	= (const uint8_t *)&pad_opt[1];
	dns_fixed_fields_opt1_set_type(pad_opt, kDNSRecordType_OPT);
	dns_fixed_fields_opt1_set_udp_payload_size(pad_opt, 512);
	dns_fixed_fields_opt1_set_rdlen(pad_opt, (uint16_t)(new_end - pad_opt->option_code));
	dns_fixed_fields_opt1_set_option_code(pad_opt, kDNSEDNS0OptionCode_Padding);
	dns_fixed_fields_opt1_set_option_length(pad_opt, (uint16_t)(new_end - pad_start));
	if (set_do_bit) {
		dns_fixed_fields_opt1_set_extended_flags(pad_opt, kDNSExtendedFlag_DNSSECOK);
	}
	DNSHeaderSetAdditionalCount((DNSHeader *)&query_buf[0], 1);
	if (out_len) {
		*out_len = new_len;
	}
	return kNoErr;
}

static OSStatus
_mdns_query_message_add_edns0_dnssec_ok(uint8_t query_buf[static MDNS_QUERY_MESSAGE_BUFFER_SIZE],
	const size_t query_len, size_t * const out_len)
{
	dns_fixed_fields_opt *opt;
	const size_t new_len = query_len + sizeof(*opt);
	require_return_value(new_len <= MDNS_QUERY_MESSAGE_BUFFER_SIZE, kSizeErr);

	opt = (dns_fixed_fields_opt *)&query_buf[query_len];
	memset(opt, 0, sizeof(*opt));
	dns_fixed_fields_opt_set_type(opt, kDNSRecordType_OPT);
	dns_fixed_fields_opt_set_udp_payload_size(opt, 512);
	dns_fixed_fields_opt_set_extended_flags(opt, kDNSExtendedFlag_DNSSECOK);

	DNSHeaderSetAdditionalCount((DNSHeader *)&query_buf[0], 1);
	if (out_len) {
		*out_len = new_len;
	}
	return kNoErr;
}

//======================================================================================================================

const uint8_t *
mdns_query_message_get_qname(const mdns_query_message_t me)
{
	return _mdns_query_message_get_qname_safe(me);
}

//======================================================================================================================

uint16_t
mdns_query_message_get_qtype(const mdns_query_message_t me)
{
	return me->qtype;
}

//======================================================================================================================

uint16_t
mdns_query_message_get_qclass(const mdns_query_message_t me)
{
	return me->qclass;
}

//======================================================================================================================

uint16_t
mdns_query_message_get_message_id(const mdns_query_message_t me)
{
	return me->msg_id;
}

//======================================================================================================================

bool
mdns_query_message_do_bit_is_set(const mdns_query_message_t me)
{
	return me->set_do_bit;
}

//======================================================================================================================
// MARK: - Query Message Private Methods

static void
_mdns_query_message_finalize(const mdns_query_message_t me)
{
	ForgetMem(&me->qname);
}

//======================================================================================================================

const uint8_t *
_mdns_query_message_get_qname_safe(const mdns_query_message_t me)
{
	return (me->qname ? me->qname : (const uint8_t *)"");
}
