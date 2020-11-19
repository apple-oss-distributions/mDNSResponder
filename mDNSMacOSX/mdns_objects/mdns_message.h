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

#ifndef __MDNS_MESSAGE_H__
#define __MDNS_MESSAGE_H__

#include "mdns_base.h"

#include <dispatch/dispatch.h>
#include <MacTypes.h>

#define MDNS_MESSAGE_SUBKIND_DECLARE(NAME)	MDNS_DECL_SUBKIND(NAME ## _message, message)

MDNS_DECL(message);
MDNS_MESSAGE_SUBKIND_DECLARE(query);

MDNS_ASSUME_NONNULL_BEGIN

#if OS_OBJECT_USE_OBJC
	typedef mdns_message_t	mdns_any_message_t;
#else
	#if defined(__cplusplus)
		typedef void *	mdns_any_message_t;
	#else
		typedef union {
			MDNS_UNION_MEMBER(message);
			MDNS_UNION_MEMBER(query_message);
		} mdns_any_message_t __attribute__((__transparent_union__));
	#endif
#endif

/*!
 *	@typedef mdns_message_init_options_t
 *
 *	@brief
 *		Creates a DNS message object from a dispatch_data object.
 *
 *	@constant mdns_message_init_option_null
 *		Represents no option.
 *
 *	@constant mdns_message_init_option_disable_header_printing
 *		Disable message header printing in description.
 */
OS_CLOSED_OPTIONS(mdns_message_init_options, uint32_t,
	mdns_message_init_option_null						= 0,		// Null option.
	mdns_message_init_option_disable_header_printing	= (1U << 0)	// Disable message header printing in description.
);

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a DNS message object from a dispatch_data object.
 *
 *	@param data
 *		A dispatch_data object containing a DNS message in wire format.
 *
 *	@param options
 *		Message initialization options.
 *
 *	@result
 *		A new message object, or NULL if there was a lack of resources.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mdns_message_t _Nullable
mdns_message_create_with_dispatch_data(dispatch_data_t data, mdns_message_init_options_t options);

/*!
 *	@brief
 *		Gets a message's data in wire format as a dispatch_data object.
 *
 *	@param message
 *		The message.
 */
dispatch_data_t
mdns_message_get_dispatch_data(mdns_any_message_t message);

/*!
 *	@brief
 *		Returns a pointer to the first byte of a message's data in wire format.
 *
 *	@param message
 *		The message.
 */
const uint8_t * _Nullable
mdns_message_get_byte_ptr(mdns_any_message_t message);

/*!
 *	@brief
 *		Returns the length of a message's data in wire format.
 *
 *	@param message
 *		The message.
 */
size_t
mdns_message_get_length(mdns_any_message_t message);

/*!
 *	@brief
 *		Creates a DNS query message object.
 *
 *	@param options
 *		Message initialization options.
 *
 *	@result
 *		A new query message object, or NULL if there was a lack of resources.
 *
 *	@discussion
 *		A query message starts out in a mutable state. Functions such as mdns_query_message_set_qname(),
 *		mdns_query_message_set_qtype(), and mdns_query_message_set_qclass() can be used to modify the message.
 *		After all the desired modifications are made, the mdns_query_message_construct() function should be used
 *		to finalize them.
 */
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mdns_query_message_t _Nullable
mdns_query_message_create(mdns_message_init_options_t options);

/*!
 *	@brief
 *		Sets the QNAME of a query message's question.
 *
 *	@param message
 *		The query message.
 *
 *	@param qname
 *		The QNAME in wire format.
 *
 *	@result
 *		kNoErr if the QNAME was successfully set. Otherwise, an error code that indicates the error that was
 *		encountered.
 *
 *	@discussion
 *		This function has no effect on a query message that has been constructed.
 */
OSStatus
mdns_query_message_set_qname(mdns_query_message_t message, const uint8_t *qname);

/*!
 *	@brief
 *		Sets the QTYPE of a query message's question.
 *
 *	@param message
 *		The query message.
 *
 *	@param qtype
 *		The QTYPE.
 *
 *	@discussion
 *		This function has no effect on a query message that has been constructed.
 */
void
mdns_query_message_set_qtype(mdns_query_message_t message, uint16_t qtype);

/*!
 *	@brief
 *		Sets the QCLASS of a query message's question.
 *
 *	@param message
 *		The query message.
 *
 *	@param qclass
 *		The QCLASS.
 *
 *	@discussion
 *		This function has no effect on a query message that has been constructed.
 */
void
mdns_query_message_set_qclass(mdns_query_message_t message, uint16_t qclass);

/*!
 *	@brief
 *		Sets a query message's ID.
 *
 *	@param message
 *		The query message.
 *
 *	@param msg_id
 *		The message ID.
 *
 *	@discussion
 *		The default message ID is 0.
 *
 *		This function has no effect on a query message that has been constructed.
 */
void
mdns_query_message_set_message_id(mdns_query_message_t message, uint16_t msg_id);

/*!
 *	@brief
 *		Sets or clears a query message's AD (authentic data) bit.
 *
 *	@param message
 *		The query message.
 *
 *	@param set
 *		If true, the AD bit is set. If false, the AD bit is cleared.
 *
 *	@discussion
 *		The AD bit is clear by default.
 *
 *		See <https://tools.ietf.org/html/rfc6840#section-5.7>.
 *
 *		This function has no effect on a query message that has been constructed.
 */
void
mdns_query_message_set_ad_bit(mdns_query_message_t message, bool set);

/*!
 *	@brief
 *		Sets or clears a query message's CD (checking disabled) bit.
 *
 *	@param message
 *		The query message.
 *
 *	@param set
 *		If true, the CD bit is set. If false, the CD bit is cleared.
 *
 *	@discussion
 *		The CD bit is clear by default.
 *
 *		See <https://tools.ietf.org/html/rfc2535#section-6.1>.
 *
 *		This function has no effect on a query message that has been constructed.
 */
void
mdns_query_message_set_cd_bit(mdns_query_message_t message, bool set);

/*!
 *	@brief
 *		Sets or clears a query message's DO (DNSSEC OK) bit in its EDNS0 header.
 *
 *	@param message
 *		The query message.
 *
 *	@param set
 *		If true, the DO bit is set. If false, the DO bit is cleared.
 *
 *	@discussion
 *		The DO bit is clear by default.
 *
 *		See <https://tools.ietf.org/html/rfc3225#section-3>.
 *
 *		This function has no effect on a query message that has been constructed.
 */
void
mdns_query_message_set_do_bit(mdns_query_message_t message, bool set);

/*!
 *	@brief
 *		Specifies whether a query message should be constructed with EDNS0 padding.
 *
 *	@param message
 *		The query message.
 *
 *	@param use
 *		If true, EDNS0 padding will be used. If false, EDNS0 padding will not be used.
 *
 *	@discussion
 *		By default, EDNS0 padding is not used.
 *
 *		The padding strategy that will be utilized during construction is the Block-Length Padding strategy, as
 *		recommended by <https://tools.ietf.org/html/rfc8467#section-4.1>.
 *
 *		This function has no effect on a query message that has been constructed.
 */
void
mdns_query_message_use_edns0_padding(mdns_query_message_t message, bool use);

/*!
 *	@brief
 *		Constructs a query message's data in wire format.
 *
 *	@param message
 *		The query message.
 *
 *	@result
 *		kNoErr if the query message data was successfully constructed. Otherwise, an error code that indicates
 *		the error that was encountered during construction.
 *
 *	@discussion
 *		After a successful call of this function, the return values of mdns_message_get_dispatch_data(),
 *		mdns_message_get_byte_ptr(), and mdns_message_get_length() will reflect the newly constructed message
 *		data.
 *
 *		This function has no effect on a query message that has been constructed.
 */
OSStatus
mdns_query_message_construct(mdns_query_message_t message);

/*!
 *	@brief
 *		Gets a query message's question's QNAME in wire format.
 *
 *	@param message
 *		The query message.
 *
 *	@discussion
 *		The pointer returned by this function is guaranteed to be valid during the lifetime of the query message
 *		object.
 */
const uint8_t *
mdns_query_message_get_qname(mdns_query_message_t message);

/*!
 *	@brief
 *		Gets a query message's question's QTYPE value.
 *
 *	@param message
 *		The query message.
 */
uint16_t
mdns_query_message_get_qtype(mdns_query_message_t message);

/*!
 *	@brief
 *		Gets a query message's question's QCLASS value.
 *
 *	@param message
 *		The query message.
 */
uint16_t
mdns_query_message_get_qclass(mdns_query_message_t message);

/*!
 *	@brief
 *		Gets a query message's ID.
 *
 *	@param message
 *		The query message.
 */
uint16_t
mdns_query_message_get_message_id(mdns_query_message_t message);

/*!
 *	@brief
 *		Determines whether a query message's the DO bit is set.
 *
 *	@param message
 *		The query message.
 */
bool
mdns_query_message_do_bit_is_set(mdns_query_message_t message);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_MESSAGE_H__
