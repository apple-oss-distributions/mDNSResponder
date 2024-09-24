/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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

#ifndef MRC_OBJECT_H
#define MRC_OBJECT_H

#if !defined(MRC_ALLOW_HEADER_INCLUDES) || !MRC_ALLOW_HEADER_INCLUDES
	#error "Please include <mrc/private.h> instead of this file directly."
#endif

#include <mrc/object_members.h>

#include <CoreFoundation/CoreFoundation.h>
#include <mdns/base.h>

#define MRC_BASE_DECL(NAME)				MDNS_COMMON_BASE_DECL(mrc_ ## NAME)
#define MRC_DECL_SUBKIND(NAME, SUPER)	MDNS_COMMON_DECL_SUBKIND(mrc_ ## NAME, mrc_ ## SUPER)
#define MRC_DECL(NAME)					MRC_DECL_SUBKIND(NAME, object)

MRC_BASE_DECL(object);

MDNS_ASSUME_NONNULL_BEGIN

/*!
 *	@typedef mrc_any_t
 *	@brief
 *		A pointer to an mrc object.
 */
#if OS_OBJECT_USE_OBJC
	typedef mrc_object_t mrc_any_t;
#else
	#if defined(__cplusplus)
		typedef void *mrc_any_t;
	#else
		typedef union {
			MRC_OBJECT_MEMBERS
		} mrc_any_t __attribute__((__transparent_union__));
	#endif
#endif

__BEGIN_DECLS

/*!
 *	@brief
 *		Increments the reference count of an mrc object.
 *
 *	@param object
 *		The mrc object.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_retain(mrc_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
	#undef mrc_retain
	#define mrc_retain(object)	(void)[(object) retain]
#endif

/*!
 *	@brief
 *		Decrements the reference count of an mrc object.
 *
 *	@param object
 *		The mrc object.
 */
MDNS_SPI_AVAILABLE_FALL_2022
void
mrc_release(mrc_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
	#undef mrc_release
	#define mrc_release(object)	[(object) release]
#endif

/*!
 *	@brief
 *		Explicitly retains an mrc object if ARC is disabled. Does nothing if ARC is enabled.
 *
 *	@param object
 *		The mrc object.
 *
 *	@discussion
 *		This is a convenience function that allows writing portable Objective-C code regardless of whether ARC
 *		is enabled or disabled.
 */
static inline void
mrc_retain_arc_safe(const mrc_any_t object)
{
#if OS_OBJECT_USE_OBJC && __has_feature(objc_arc)
	(void)object;
#else
	mrc_retain(object);
#endif
}

/*!
 *	@brief
 *		Explicitly releases an mrc object if ARC is disabled. Does nothing if ARC is enabled.
 *
 *	@param object
 *		The mrc object.
 *
 *	@discussion
 *		This is a convenience function that allows writing portable Objective-C code regardless of whether ARC
 *		is enabled or disabled.
 */
static inline void
mrc_release_arc_safe(const mrc_any_t object)
{
#if OS_OBJECT_USE_OBJC && __has_feature(objc_arc)
	(void)object;
#else
	mrc_release(object);
#endif
}

__END_DECLS

MDNS_ASSUME_NONNULL_END

#define mrc_forget(PTR)						\
	do {									\
		if (*(PTR)) {						\
			mrc_release_arc_safe(*(PTR));	\
			*(PTR) = NULL;					\
		}									\
	} while(0)

#define mrc_forget_with_invalidation(PTR, NAME)		\
	do {											\
		if (*(PTR)) {								\
			mrc_ ## NAME ## _invalidate(*(PTR));	\
			mrc_release_arc_safe(*(PTR));			\
			*(PTR) = NULL;							\
		}											\
	} while (0)

#endif	// MRC_OBJECT_H
