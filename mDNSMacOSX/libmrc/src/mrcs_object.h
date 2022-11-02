/*
 * Copyright (c) 2021-2022 Apple Inc. All rights reserved.
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

#ifndef MRCS_OBJECT_H
#define MRCS_OBJECT_H

#include "mrcs_object_members.h"

#include <CoreFoundation/CoreFoundation.h>
#include <mdns/base.h>

#define MRCS_BASE_DECL(NAME)			MDNS_COMMON_BASE_DECL(mrcs_ ## NAME)
#define MRCS_DECL_SUBKIND(NAME, SUPER)	MDNS_COMMON_DECL_SUBKIND(mrcs_ ## NAME, mrcs_ ## SUPER)
#define MRCS_DECL(NAME)					MRCS_DECL_SUBKIND(NAME, object)

MRCS_BASE_DECL(object);

MDNS_ASSUME_NONNULL_BEGIN

/*!
 *	@typedef mrcs_any_t
 *	@brief
 *		A pointer to an mrcs object.
 */
#if OS_OBJECT_USE_OBJC
	typedef mrcs_object_t	mrcs_any_t;
#else
	#if defined(__cplusplus)
		typedef void *	mrcs_any_t;
	#else
		typedef union {
			MRCS_OBJECT_MEMBERS
		} mrcs_any_t __attribute__((__transparent_union__));
	#endif
#endif

__BEGIN_DECLS

/*!
 *	@brief
 *		Increments the reference count of an mrcs object.
 *
 *	@param object
 *		The mrcs object.
 */
void
mrcs_retain(mrcs_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
	#undef mrcs_retain
	#define mrcs_retain(object)	(void)[(object) retain]
#endif

/*!
 *	@brief
 *		Decrements the reference count of an mrcs object.
 *
 *	@param object
 *		The mrcs object.
 */
void
mrcs_release(mrcs_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
	#undef mrcs_release
	#define mrcs_release(object)	[(object) release]
#endif

/*!
 *	@brief
 *		Creates a human-readable description of an mrcs object as a C string encoded in UTF-8.
 *
 *	@param object
 *		The mrcs object.
 *
 *	@result
 *		A C string that must be freed with free(3), or NULL if memory allocation failed.
 */
MDNS_WARN_RESULT
char * _Nullable
mrcs_copy_description(mrcs_any_t object);

/*!
 *	@brief
 *		Explicitly retains an mrcs object if ARC is disabled. Does nothing if ARC is enabled.
 *
 *	@param object
 *		The mrcs object.
 *
 *	@discussion
 *		This is a convenience function that allows writing portable Objective-C code regardless of whether ARC
 *		is enabled or disabled.
 */
static inline void
mrcs_retain_arc_safe(const mrcs_any_t object)
{
#if OS_OBJECT_USE_OBJC && __has_feature(objc_arc)
	(void)object;
#else
	mrcs_retain(object);
#endif
}

/*!
 *	@brief
 *		Explicitly releases an mrcs object if ARC is disabled. Does nothing if ARC is enabled.
 *
 *	@param object
 *		The mrcs object.
 *
 *	@discussion
 *		This is a convenience function that allows writing portable Objective-C code regardless of whether ARC
 *		is enabled or disabled.
 */
static inline void
mrcs_release_arc_safe(const mrcs_any_t object)
{
#if OS_OBJECT_USE_OBJC && __has_feature(objc_arc)
	(void)object;
#else
	mrcs_release(object);
#endif
}

__END_DECLS

MDNS_ASSUME_NONNULL_END

#define mrcs_forget(PTR)					\
	do {									\
		if (*(PTR)) {						\
			mrcs_release_arc_safe(*(PTR));	\
			*(PTR) = NULL;					\
		}									\
	} while(0)

#endif	// MRCS_OBJECT_H
