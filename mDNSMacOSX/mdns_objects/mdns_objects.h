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

#ifndef __MDNS_OBJECTS_H__
#define __MDNS_OBJECTS_H__

#include "mdns_private.h"

#include <os/object_private.h>

MDNS_DECL(server);
MDNS_DECL(session);

//======================================================================================================================
// MARK: - Kind Declarations

#define MDNS_OBJECT_SUBKIND_DEFINE_ABSTRACT(NAME)	_MDNS_OBJECT_SUBKIND_DEFINE_ABSTRACT(mdns_ ## NAME)
#define MDNS_OBJECT_SUBKIND_DEFINE(NAME)			_MDNS_OBJECT_SUBKIND_DEFINE(mdns_ ## NAME)
#define MDNS_OBJECT_SUBKIND_DEFINE_FULL(NAME)		_MDNS_OBJECT_SUBKIND_DEFINE_FULL(mdns_ ## NAME)
#define MDNS_OBJECT_SUBKIND_DEFINE_TEST(NAME)		_MDNS_OBJECT_SUBKIND_DEFINE_TEST(mdns_ ## NAME)

// Note: The last check checks if the base's type is equal to that of the superkind. If it's not, then the pointer
// comparison used as the argument to sizeof will cause a "comparison of distinct pointer types" warning, so long as
// the warning hasn't been disabled.

#define MDNS_BASE_CHECK(NAME, SUPER)		_MDNS_BASE_CHECK(mdns_ ## NAME, mdns_ ## SUPER)
#define _MDNS_BASE_CHECK(NAME, SUPER)															\
	check_compile_time(offsetof(struct NAME ## _s, base) == 0);									\
	check_compile_time(sizeof_field(struct NAME ## _s, base) == sizeof(struct SUPER ## _s));	\
	extern int _mdns_base_type_check[sizeof(&(((NAME ## _t)0)->base) == ((SUPER ## _t)0))]

#define _MDNS_OBJECT_SUBKIND_DEFINE_TEST(NAME, ...)			\
	static const struct mdns_kind_s _ ## NAME ## _kind = {	\
		.superkind	= &_mdns_object_kind,					\
		.name		= # NAME,								\
		__VA_ARGS__											\
	};														\
	_MDNS_OBJECT_SUBKIND_DEFINE_ALLOC(NAME)

#define _MDNS_OBJECT_SUBKIND_DEFINE_ABSTRACT(NAME)									\
	static char *																	\
	_ ## NAME ## _copy_description(NAME ## _t object, bool debug, bool privacy);	\
																					\
	static void																		\
	_ ## NAME ## _finalize(NAME ## _t object);										\
																					\
	_MDNS_OBJECT_SUBKIND_DEFINE_STRUCT(												\
		NAME,																		\
		_ ## NAME ## _copy_description,												\
		NULL,																		\
		_ ## NAME ## _finalize														\
	)

#define _MDNS_OBJECT_SUBKIND_DEFINE(NAME)		\
	_MDNS_OBJECT_SUBKIND_DEFINE_ABSTRACT(NAME);	\
	_MDNS_OBJECT_SUBKIND_DEFINE_ALLOC(NAME)

#define _MDNS_OBJECT_SUBKIND_DEFINE_FULL(NAME)										\
	static char *																	\
	_ ## NAME ## _copy_description(NAME ## _t object, bool debug, bool privacy);	\
																					\
	static bool																		\
	_ ## NAME ## _equal(NAME ## _t object1, NAME ## _t object2);					\
																					\
	static void																		\
	_ ## NAME ## _finalize(NAME ## _t object);										\
																					\
	_MDNS_OBJECT_SUBKIND_DEFINE_STRUCT(												\
		NAME,																		\
		_ ## NAME ## _copy_description,												\
		_ ## NAME ## _equal,														\
		_ ## NAME ## _finalize														\
	);																				\
	_MDNS_OBJECT_SUBKIND_DEFINE_ALLOC(NAME)

#define _MDNS_OBJECT_SUBKIND_DEFINE_STRUCT(NAME, COPY_DESCRIPTION_METHOD, EQUAL_METHOD, FINALIZE_METHOD)	\
	static const struct mdns_kind_s _ ## NAME ## _kind = {													\
		&_mdns_object_kind,																					\
		# NAME,																								\
		(COPY_DESCRIPTION_METHOD),																			\
		(EQUAL_METHOD),																						\
		(FINALIZE_METHOD)																					\
	};																										\
	_MDNS_BASE_CHECK(NAME, mdns_object)

#define _MDNS_OBJECT_SUBKIND_DEFINE_ALLOC(NAME)					\
	static NAME ## _t											\
	_ ## NAME ## _alloc(void)									\
	{															\
		NAME ## _t obj = NAME ## _object_alloc(sizeof(*obj));	\
		require_quiet(obj, exit);								\
																\
		const mdns_object_t base = (mdns_object_t)obj;			\
		base->kind = &_ ## NAME ## _kind;						\
																\
	exit:														\
		return obj;												\
	}															\
	extern int _mdns_dummy_variable

typedef char *	(*mdns_copy_description_f)(mdns_any_t object, bool debug, bool privacy);
typedef bool	(*mdns_equal_f)(mdns_any_t object1, mdns_any_t object2);
typedef void	(*mdns_finalize_f)(mdns_any_t object);

typedef const struct mdns_kind_s *	mdns_kind_t;
struct mdns_kind_s {
	mdns_kind_t				superkind;			// This kind's superkind.
	const char *			name;				// Name of this kind.
	mdns_copy_description_f	copy_description;	// Creates a textual description of an object as a UTF-8 C string.
	mdns_equal_f			equal;				// Compares two objects for equality.
	mdns_finalize_f			finalize;			// Releases object's resources right before the object is freed.
};

//======================================================================================================================
// MARK: - Object Kind Definition

struct mdns_object_s {
	_OS_OBJECT_HEADER(const void * __ptrauth_objc_isa_pointer _os_obj_isa, _os_obj_refcnt, _os_obj_xref_cnt);
	mdns_kind_t	kind;	// Pointer to an object's kind.
};

extern const struct mdns_kind_s _mdns_object_kind;

//======================================================================================================================
// MARK: - Object Private Method Declarations

char *
mdns_object_copy_description(mdns_any_t object, bool debug, bool privacy);

CFStringRef
mdns_object_copy_description_as_cfstring_ex(mdns_any_t object, bool debug, bool privacy);

#define mdns_object_copy_description_as_cfstring(OBJ) \
	mdns_object_copy_description_as_cfstring_ex(OBJ, false, false)

#define mdns_object_copy_debug_description_as_cfstring(OBJ) \
	mdns_object_copy_description_as_cfstring_ex(OBJ, true, false)

#define mdns_object_copy_redacted_description_as_cfstring(OBJ) \
	mdns_object_copy_description_as_cfstring_ex(OBJ, false, true)

void
mdns_object_finalize(mdns_any_t object);

#define MDNS_OBJECT_ALLOC_DECLARE(NAME)	\
	mdns_ ## NAME ## _t					\
	mdns_ ## NAME ## _object_alloc(size_t size)

MDNS_OBJECT_ALLOC_DECLARE(address);
MDNS_OBJECT_ALLOC_DECLARE(dns_service);
MDNS_OBJECT_ALLOC_DECLARE(dns_service_manager);
MDNS_OBJECT_ALLOC_DECLARE(interface_monitor);
MDNS_OBJECT_ALLOC_DECLARE(message);
MDNS_OBJECT_ALLOC_DECLARE(query_message);
MDNS_OBJECT_ALLOC_DECLARE(querier);
MDNS_OBJECT_ALLOC_DECLARE(resolver);
MDNS_OBJECT_ALLOC_DECLARE(server);
MDNS_OBJECT_ALLOC_DECLARE(session);
MDNS_OBJECT_ALLOC_DECLARE(set);
MDNS_OBJECT_ALLOC_DECLARE(trust);

//======================================================================================================================
// MARK: - Class Declarations

_OS_OBJECT_DECL_SUBCLASS_INTERFACE(mdns_object, object)

#endif	// __MDNS_OBJECTS_H__
