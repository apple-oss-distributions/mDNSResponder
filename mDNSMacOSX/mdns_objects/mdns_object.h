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

#ifndef __MDNS_OBJECT_H__
#define __MDNS_OBJECT_H__

#include "mdns_base.h"

#include <CoreFoundation/CoreFoundation.h>

/*!
 *	@brief
 *		CFArray callbacks for mdns objects.
 */
extern const CFArrayCallBacks mdns_cfarray_callbacks;

MDNS_ASSUME_NONNULL_BEGIN

/*!
 *	@typedef	mdns_any_t
 *	@brief
 *		A pointer to an mdns object.
 */
#if OS_OBJECT_USE_OBJC
	typedef mdns_object_t	mdns_any_t;
#else
	#if defined(__cplusplus)
		typedef void *	mdns_any_t;
	#else
		#if !defined(MDNS_ANY_TYPE_INTERNAL_MEMBERS)
			#define MDNS_ANY_TYPE_INTERNAL_MEMBERS
		#endif
		typedef union {
			MDNS_UNION_MEMBER(object);
			MDNS_UNION_MEMBER(address);
			MDNS_UNION_MEMBER(dns_service);
			MDNS_UNION_MEMBER(dns_service_manager);
			MDNS_UNION_MEMBER(interface_monitor);
			MDNS_UNION_MEMBER(message);
			MDNS_UNION_MEMBER(query_message);
			MDNS_UNION_MEMBER(querier);
			MDNS_UNION_MEMBER(resolver);
			MDNS_UNION_MEMBER(set);
			MDNS_UNION_MEMBER(trust);
			MDNS_ANY_TYPE_INTERNAL_MEMBERS
		} mdns_any_t __attribute__((__transparent_union__));
	#endif
#endif

__BEGIN_DECLS

/*!
 *	@brief
 *		Increments the reference count of an mdns object.
 *
 *	@param object
 *		The mdns object.
 */
mdns_object_t
mdns_retain(mdns_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
	#undef mdns_retain
	#define mdns_retain(object)	[(object) retain]
#endif

/*!
 *	@brief
 *		Decrements the reference count of an mdns object.
 *
 *	@param object
 *		The mdns object.
 */
void
mdns_release(mdns_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
	#undef mdns_release
	#define mdns_release(object)	[(object) release]
#endif

/*!
 *	@brief
 *		Creates a human-readable description of an mdns object as a C string encoded in UTF-8.
 *
 *	@param object
 *		The mdns object.
 *
 *	@result
 *		A C string that must be freed with free(3).
 */
MDNS_WARN_RESULT
char * _Nullable
mdns_copy_description(mdns_any_t object);

/*!
 *	@brief
 *		Determines whether two mdns objects are equal.
 *
 *	@param object1
 *		The first object.
 *
 *	@param object2
 *		The second object.
 *
 *	@result
 *		Returns true if the two objects are equal, otherwise false.
 */
bool
mdns_equal(mdns_any_t object1, mdns_any_t object2);

/*!
 *	@brief
 *		Generic events that may occur during the lifetime of some mdns objects.
 *
 *	@const mdns_event_error
 *		A fatal error has occurred.
 *
 *	@const mdns_event_invalidated
 *		The object has been invalidated.
 *
 *	@const mdns_event_update
 *		Some aspect of the object has been updated.
 */
OS_CLOSED_ENUM(mdns_event, int,
	mdns_event_error		= 1,
	mdns_event_invalidated	= 2,
	mdns_event_update		= 3
);

static inline const char *
mdns_event_to_string(mdns_event_t event)
{
	switch (event) {
		case mdns_event_error:			return "Error";
		case mdns_event_invalidated:	return "Invalidated";
		default:						return "?";
	}
}

/*!
 *	@brief
 *		Generic event handler for mdns objects.
 *
 *	@param event
 *		The event.
 *
 *	@param error
 *		The error associated with a <code>mdns_event_error</code> event. This argument should be ignored for all
 *		other types of events.
 *
 *	@discussion
 *		After an <code>mdns_event_invalidated</code> event, none of the object's handlers will ever be invoked again.
 */
typedef void (^mdns_event_handler_t)(mdns_event_t event, OSStatus error);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#if OS_OBJECT_USE_OBJC && __has_feature(objc_arc)
	#define mdns_retain_arc_safe(OBJ)	(OBJ)
	#define mdns_release_arc_safe(OBJ)	do {} while (0)
#else
	#define mdns_retain_arc_safe(OBJ)	mdns_retain(OBJ)
	#define mdns_release_arc_safe(OBJ)	mdns_release(OBJ)
#endif

#define mdns_retain_null_safe(OBJ)		\
	do {								\
		if (OBJ) {						\
			mdns_retain_arc_safe(OBJ);	\
		}								\
	} while (0)							\

#define mdns_release_null_safe(OBJ)		\
	do {								\
		if (OBJ) {						\
			mdns_release_arc_safe(OBJ);	\
		}								\
	} while (0)							\

#define mdns_forget(PTR)					\
	do {									\
		if (*(PTR)) {						\
			mdns_release_arc_safe(*(PTR));	\
			*(PTR) = NULL;					\
		}									\
	} while(0)

#define mdns_replace(PTR, OBJ)				\
	do {									\
		if (OBJ) {							\
			mdns_retain_arc_safe(OBJ);		\
		}									\
		if (*(PTR)) {						\
			mdns_release_arc_safe(*(PTR));	\
		}									\
		*(PTR) = (OBJ);						\
	} while(0)

#endif	// __MDNS_OBJECT_H__
