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

#ifndef MRC_RECORD_CACHE_FLUSH_H
#define MRC_RECORD_CACHE_FLUSH_H

#if !defined(MRC_ALLOW_HEADER_INCLUDES) || !MRC_ALLOW_HEADER_INCLUDES
	#error "Please include <mrc/private.h> instead of this file directly."
#endif

#include <mrc/object.h>

#include <dispatch/dispatch.h>
#include <MacTypes.h>
#include <mdns/base.h>
#include <xpc/xpc.h>

MRC_DECL(record_cache_flush);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates an object that represents a record cache flush operation.
 *
 *	@result
 *		A reference to the new object, or NULL if creation failed due to a lack of system resources.
 *
 *	@discussion
 *		The conditions that must be met by a record in order to be flushed by the record cache flush can be
 *		specified by functions such as mrc_record_cache_flush_set_record_name() and
 *		mrc_record_cache_flush_set_key_tag().
 *
 *		If not using Objective-C ARC, use mrc_retain() and mrc_release() to retain and release references to the
 *		object.
 */
MDNS_SPI_AVAILABLE_FALL_2024
MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
mrc_record_cache_flush_t _Nullable
mrc_record_cache_flush_create(void);

/*!
 *	@brief
 *		Sets the dispatch queue on which a record cache flush is to invoke its result handler.
 *
 *	@param flush
 *		The record cache flush.
 *
 *	@param queue
 *		The dispatch queue.
 *
 *	@discussion
 *		A dispatch queue must be set in order for a record cache flush's result handler to be invoked.
 *
 *		This function should be called before the record cache flush is activated. This function has no effect
 *		on a record cache flush that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_record_cache_flush_set_queue(mrc_record_cache_flush_t flush, dispatch_queue_t queue);

/*!
 *	@brief
 *		Sets the name of the records to be flushed by a record cache flush.
 *
 *	@param flush
 *		The record cache flush.
 *
 *	@param record_name
 *		The record name.
 *
 *	@discussion
 *		A record matching the specified record name is a necessary condition for it to be flushed by the record
 *		cache flush.
 *
 *		This function should be called before the record cache flush is activated. This function has no effect
 *		on a record cache flush that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_record_cache_flush_set_record_name(mrc_record_cache_flush_t flush, mdns_domain_name_t record_name);

/*!
 *	@brief
 *		Sets the key tag that a record must match in order to be flushed by a record cache flush.
 *
 *	@param flush
 *		The record cache flush.
 *
 *	@param key_tag
 *		The key tag.
 *
 *	@discussion
 *		A record matching the specified key tag is a necessary condition for it to be flushed by the record
 *		cache flush.
 *
 *		This function has no effect on a record cache flush that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_record_cache_flush_set_key_tag(mrc_record_cache_flush_t flush, uint16_t key_tag);

/*!
 *	@brief
 *		Indicates how a record cache flush concluded.
 */
typedef enum {
	/*! @brief Indicates that a record cache flush was successfully carried out. */
	mrc_record_cache_flush_result_complete		= 1,
	/*! @brief Indicates that a record cache flush was not successfully carried out. */
	mrc_record_cache_flush_result_incomplete	= 2,
} mrc_record_cache_flush_result_t;

/*!
 *	@brief
 *		A block that handles the result of a record cache flush.
 *
 *	@param result
 *		The result of the record cache flush.
 *
 *	@param error
 *		An error code, which is only relevant if the result is mrc_record_cache_flush_result_incomplete.
 */
typedef void
(^mrc_record_cache_flush_result_handler_t)(mrc_record_cache_flush_result_t result, OSStatus error);

/*!
 *	@brief
 *		Sets a record cache flush's result handler.
 *
 *	@param flush
 *		The record cache flush.
 *
 *	@param handler
 *		The result handler.
 *
 *	@discussion
 *		The result handler will never be invoked before the first call to either
 *		mrc_record_cache_flush_activate() or mrc_record_cache_flush_invalidate().
 *
 *		The result handler will be submitted to the record cache flush's dispatch queue no more than once as a
 *		consequence of one of the following events, whichever occurs first:
 *
 *		1. The system daemon that manages the system's DNS record cache flushes all of the records that meet the
 *		   criteria specified by the record cache flush. If no records in the record cache meet the criteria
 *		   specified by the record cache flush, then there are no records to flush. In either case, the handler
 *		   will be invoked with mrc_record_cache_flush_result_success and a kNoErr error code.
 *
 *		2. A fatal error occurs that prevents the record cache flush from successfully completing. In this case,
 *		   the handler will be invoked with mrc_record_cache_flush_result_incomplete and a non-zero error code
 *		   that indicates the type of error that occurred.
 *
 *		3. The record cache flush is invalidated with mrc_record_cache_flush_invalidate(). In this case, the
 *		   handler will be invoked with mrc_record_cache_flush_result_incomplete and a kNoErr error code.
 *
 *		After the handler is invoked, the record cache flush's reference to the handler will be released.
 *
 *		This function should be called before the record cache flush is activated. This function has no effect
 *		on a record cache flush that has been activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_record_cache_flush_set_result_handler(mrc_record_cache_flush_t flush,
	mrc_record_cache_flush_result_handler_t handler);

/*!
 *	@brief
 *		Activates a record cache flush.
 *
 *	@param flush
 *		The record cache flush.
 *
 *	@discussion
 *		Calling this function initiates the request to the system daemon that manages the system's DNS record
 *		cache to carry out the record cache flush.
 *
 *		This function has no effect on a record cache flush that has been already activated or invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_record_cache_flush_activate(mrc_record_cache_flush_t flush);

/*!
 *	@brief
 *		Invalidates a record cache flush.
 *
 *	@param flush
 *		The record cache flush.
 *
 *	@discussion
 *		This function exists to gracefully invalidate a record cache flush that's no longer needed.
 *
 *		If the record cache flush's result handler hasn't already been invoked or its invocation isn't imminent,
 *		then this function will force it to be invoked (asynchronously and on the record cache flush's dispatch
 *		queue, of course). If the result handler has already been invoked, then calling this function is
 *		unnecessary, but harmless.
 *
 *		This function has no effect on a record cache flush that has already been invalidated.
 */
MDNS_SPI_AVAILABLE_FALL_2024
void
mrc_record_cache_flush_invalidate(mrc_record_cache_flush_t flush);

/*!
 *	@brief
 *		Invalidates and releases a record cache flush object referenced by a pointer.
 *
 *	@param OBJ_PTR
 *		The address of the pointer that either references a record cache flush object or references NULL.
 *
 *	@discussion
 *		This is a convenience macro that combines the functionality of mrc_record_cache_flush_invalidate() and
 *		mrc_forget(). If the pointer contains a non-NULL reference, then the record cache flush object
 *		referenced by the pointer is invalidated with mrc_record_cache_flush_invalidate(), then released. Also,
 *		if the pointer contains a non-NULL reference, then the pointer will be set to NULL after releasing the
 *		record cache flush object.
 */
#define mrc_record_cache_flush_forget(OBJ_PTR)	mrc_forget_with_invalidation(OBJ_PTR, record_cache_flush)

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRC_RECORD_CACHE_FLUSH_H
