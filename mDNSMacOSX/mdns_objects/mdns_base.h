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

#ifndef __MDNS_BASE_H__
#define __MDNS_BASE_H__

#include <os/object.h>

#if defined(MDNS_OBJECT_FORCE_NO_OBJC) && MDNS_OBJECT_FORCE_NO_OBJC
	#define MDNS_OBJECT_USE_OBJC	0
#else
	#define MDNS_OBJECT_USE_OBJC	OS_OBJECT_USE_OBJC
#endif

#if MDNS_OBJECT_USE_OBJC
	#define MDNS_RETURNS_RETAINED			OS_OBJECT_RETURNS_RETAINED
	#define MDNS_DECL(NAME)					OS_OBJECT_DECL_SUBCLASS(mdns_ ## NAME, mdns_object)
	#define MDNS_DECL_SUBKIND(NAME, SUPER)	OS_OBJECT_DECL_SUBCLASS(mdns_ ## NAME, mdns_ ## SUPER)
	OS_OBJECT_DECL(mdns_object,);
#else
	#define MDNS_RETURNS_RETAINED
	#define MDNS_DECL(NAME)					typedef struct mdns_ ## NAME ## _s *	mdns_ ## NAME ## _t
	#define MDNS_DECL_SUBKIND(NAME, SUPER)	MDNS_DECL(NAME)
	MDNS_DECL(object);
#endif

#define MDNS_WARN_RESULT						OS_WARN_RESULT
#define MDNS_ASSUME_NONNULL_BEGIN				OS_ASSUME_NONNULL_BEGIN
#define MDNS_ASSUME_NONNULL_END					OS_ASSUME_NONNULL_END
#define MDNS_PRINTF_FORMAT(FMT_IDX, ARGS_IDX)	__attribute__((__format__ (__printf__, FMT_IDX, ARGS_IDX)))

#define MDNS_UNION_MEMBER(NAME)	struct mdns_ ## NAME ## _s *	NAME

#define mdns_forget_with_invalidation(X, NAME)	\
	do {										\
		if (*(X)) {								\
			mdns_ ## NAME ## _invalidate(*(X));	\
			mdns_release_arc_safe(*(X));		\
			*(X) = NULL;						\
		}										\
	} while (0)

#endif	// __MDNS_BASE_H__
