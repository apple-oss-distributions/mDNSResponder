/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef MRC_CACHED_LOCAL_RECORDS_INQUIRY_H
#define MRC_CACHED_LOCAL_RECORDS_INQUIRY_H

#if !defined(MRC_ALLOW_HEADER_INCLUDES) || !MRC_ALLOW_HEADER_INCLUDES
	#error "Please include <mrc/private.h> instead of this file directly."
#endif

#include <mrc/object.h>

#include <dispatch/dispatch.h>
#include <MacTypes.h>
#include <mdns/base.h>
#include <xpc/xpc.h>

MRC_DECL(cached_local_records_inquiry);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates an inquiry to get basic information about local records from the system's mDNS record cache.
 *
 *	@result
 *		A reference to the new inquiry, or NULL if creation failed due to a lack of system resources.
 *
 *	@discussion
 *		The basic information consists of the following, which is extracted from the most recent snapshot of the
 *		system's mDNS record cache:
 *
 *			1. The names of records from the local domain.
 *			2. The names and RDATA of *._device-info._tcp.local TXT records.
 *
 *		Note that this is an extremely special purpose SPI that was driven by the needs of the Data Access team,
 *		which included not generating any network traffic. In general, processes shouldn't depend on the current
 *		content of the system's record cache, but instead use the normal DNS-SD API.
 *
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_FALL_2024
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_cached_local_records_inquiry_t _Nullable
mrc_cached_local_records_inquiry_create(void);

/*!
 *	@brief
 *		Sets the queue on which an inquiry is to invoke its result handler.
 *
 *	@param inquiry
 *		The inquiry.
 *
 *	@param queue
 *		The dispatch queue.
 *
 *	@discussion
 *		A dispatch queue must be set in order for an inquiry's result handler to be invoked.
 *
 *		This function should be called before the inquiry is activated. This function has no effect on an
 *		inquiry that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_cached_local_records_inquiry_set_queue(mrc_cached_local_records_inquiry_t inquiry, dispatch_queue_t queue);

/*!
 *	@brief
 *		An inquiry result handler, which is used for passing the results of the inquiry.
 *
 *	@param record_info
 *		An XPC array of XPC dictionaries, where each dictionary describes one cached local record.
 *
 *	@param error
 *		An error code, which will be non-zero if a fatal error occurred, or zero, otherwise.
 *
 *	@discussion
 *		The dictionary contains the following values:
 *
 *		1. The first label of the record name as a string. This value can be accessed with the
 *		   mrc_cached_local_record_key_first_label key. The string doesn't contain any backslash escape
 *		   sequences except for literal backslashes, non-printing ASCII characters (ASCII code points outside of
 *		   the 0x20 - 0x7E range), and bytes that are not part of a valid UTF-8 byte sequence. Literal
 *		   backslashes are represented as "\\", while each byte of the latter two cases is represented as the
 *		   "\xHH" escape sequence, where HH is the hex value of the byte encoded as a pair of ASCII hex digits.
 *		2. The record's name as a string. This value can be accessed with the mrc_cached_local_record_key_name
 *		   key. This value is always present.
 *		3. If a TXT record belonging to a _device-info._tcp.local subdomain was present in the cache, then the
 *		   corresponding dictionary will contain the record's RDATA's text representation as a string. This
 *		   value can be accessed with the mrc_cached_local_record_key_rdata key.
 *		4. The source IPv4 or IPv6 address in text representation as a string. This value can be accessed with
 *		   the mrc_cached_local_record_key_source_address key. This value is usually present, but not guaranteed
 *		   to be present.
 */
typedef void
(^mrc_cached_local_records_inquiry_result_handler_t)(xpc_object_t _Nullable record_info, OSStatus error);

/*!
 *	@brief
 *		First label of the record name as a string with minimal backslash escape sequences.
 */
MDNS_SPI_AVAILABLE_FALL_2024
extern const char * const mrc_cached_local_record_key_first_label;

/*!
 *	@brief
 *		Record name as a string.
 */
MDNS_SPI_AVAILABLE_FALL_2024
extern const char * const mrc_cached_local_record_key_name;

/*!
 *	@brief
 *		Record RDATA's text representation as a string.
 */
MDNS_SPI_AVAILABLE_FALL_2024
extern const char * const mrc_cached_local_record_key_rdata;

/*!
 *	@brief
 *		Record's source IPv4 or IPv6 address's text representation as a string.
 */
MDNS_SPI_AVAILABLE_FALL_2024
extern const char * const mrc_cached_local_record_key_source_address;

/*!
 *	@brief
 *		Sets an inquiry's result handler.
 *
 *	@param inquiry
 *		The inquiry.
 *
 *	@param handler
 *		The result handler.
 *
 *	@discussion
 *		The result handler will never be invoked before the first call to either
 *		mrc_cached_local_records_inquiry_activate() or mrc_cached_local_records_inquiry_invalidate().
 *
 *		This function should be called before the inquiry is activated because it has no effect on an inquiry
 *		that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_cached_local_records_inquiry_set_result_handler(mrc_cached_local_records_inquiry_t inquiry,
	mrc_cached_local_records_inquiry_result_handler_t handler);

/*!
 *	@brief
 *		Activates an inquiry.
 *
 *	@param inquiry
 *		The inquiry.
 *
 *	@discussion
 *		This function has no effect on an inquiry that has already been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_cached_local_records_inquiry_activate(mrc_cached_local_records_inquiry_t inquiry);

/*!
 *	@brief
 *		Invalidates an inquiry.
 *
 *	@param inquiry
 *		The inquiry.
 *
 *	@discussion
 *		This function exists to gracefully invalidate an inquiry.
 *
 *		If the inquiry's result handler hasn't already been invoked and isn't just about to be invoked, then
 *		this function will force it to be invoked (asynchronously, of course). If the result handler has
 *		already been invoked, then calling this function is unnecessary, but harmless.
 *
 *		This function has no effect on an inquiry that has already been invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_cached_local_records_inquiry_invalidate(mrc_cached_local_records_inquiry_t inquiry);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRC_CACHED_LOCAL_RECORDS_INQUIRY_H
