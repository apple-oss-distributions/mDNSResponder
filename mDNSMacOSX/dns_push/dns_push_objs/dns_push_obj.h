/*
 * Copyright (c) 2022-2023 Apple Inc. All rights reserved.
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

#ifndef DNS_PUSH_OBJ_H
#define DNS_PUSH_OBJ_H

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "ref_count.h"
#include "nullability.h"

//======================================================================================================================
// MARK: - DNS Push Object Kind and Subkind Helper Macros

// Define a specific DNS push object.
#define DNS_PUSH_OBJECT_DEFINE_FULL(NAME)									REF_COUNT_OBJECT_DEFINE_FULL(dns_push_obj, NAME)
#define DNS_PUSH_OBJECT_DEFINE_WITH_INIT_WITHOUT_COMPARATOR(NAME)			REF_COUNT_OBJECT_DEFINE_WITH_INIT_WITHOUT_COMPARATOR(dns_push_obj, NAME)

// Define a kind type for a DNS push object that has a subkind.
#define DNS_PUSH_OBJECT_DEFINE_KIND_TYPE_FOR_SUBKIND(NAME, ...)				REF_COUNT_OBJECT_DEFINE_KIND_TYPE_FOR_SUBKIND(dns_push_obj, NAME, __VA_ARGS__)

// Define a subkind of a DNS push object.
// Subkind with no comparator nor finalizer.
#define DNS_PUSH_OBJECT_SUBKIND_DEFINE_ABSTRUCT(SUPER, NAME, ...)				REF_COUNT_OBJECT_SUBKIND_DEFINE_ABSTRUCT(dns_push_obj, SUPER, NAME, __VA_ARGS__)
// Subkind with no finalizer, but with comparator.
#define DNS_PUSH_OBJECT_SUBKIND_DEFINE_WITHOUT_FINALIZER(SUPER, NAME, ...)		REF_COUNT_OBJECT_SUBKIND_DEFINE_WITHOUT_FINALIZER(dns_push_obj, SUPER, NAME, __VA_ARGS__)
// Subkind with finalizer, but with no comparator.
#define DNS_PUSH_OBJECT_SUBKIND_DEFINE_WITHOUT_COMPARATOR(SUPER, NAME, ...)		REF_COUNT_OBJECT_SUBKIND_DEFINE_WITHOUT_COMPARATOR(dns_push_obj, SUPER, NAME, __VA_ARGS__)
// Subkind with both finalizer and comparator.
#define DNS_PUSH_OBJECT_SUBKIND_DEFINE_FULL(SUPER, NAME, ...)					REF_COUNT_OBJECT_SUBKIND_DEFINE_FULL(dns_push_obj, SUPER, NAME, __VA_ARGS__)

// Declare all kinds and subkinds as the DNS push objects.
// Declare an object as a DNS push object.
#define DNS_PUSH_OBJECT_DECLARE_SUPPORTED_OBJECT(NAME)							REF_COUNT_OBJECT_DECLARE_SUPPORTED_OBJECT(dns_push_obj, NAME)
// Declare a subkind of object as a DNS push object.
#define DNS_PUSH_OBJECT_DECLARE_SUPPORTED_OBJECT_SUBKIND(SUPER, NAME)			REF_COUNT_OBJECT_DECLARE_SUPPORTED_OBJECT_SUBKIND(dns_push_obj, SUPER, NAME)

#define DNS_PUSH_OBJECT_TYPEDEF_OPAQUE_POINTER(NAME)							OBJECT_TYPEDEF_OPAQUE_POINTER(dns_push_obj_ ## NAME)
#define DNS_PUSH_OBJECT_SUBKIND_TYPEDEF_OPAQUE_POINTER(SUPER, NAME)				OBJECT_TYPEDEF_OPAQUE_POINTER(dns_push_obj_ ## SUPER ## _ ## NAME)

//======================================================================================================================
// MARK: - DNS Push Object Families

OBJECT_TYPEDEF_OPAQUE_POINTER(dns_push_obj);

typedef union {
	STRUCT_PTR_DECLARE(dns_push_obj);									// Declare dns_push_obj_t object family.
	DNS_PUSH_OBJECT_DECLARE_SUPPORTED_OBJECT(context);					// Declare dns_push_obj_context_t as a dns_push_obj_t object.
	DNS_PUSH_OBJECT_DECLARE_SUPPORTED_OBJECT(discovered_service_manager);
	DNS_PUSH_OBJECT_DECLARE_SUPPORTED_OBJECT(dns_question_member);		// Declare dns_push_obj_dns_question_member_t as a dns_push_obj_t object.
	DNS_PUSH_OBJECT_DECLARE_SUPPORTED_OBJECT(resource_record_member);	// Declare dns_push_obj_resource_record_member_t as a dns_push_obj_t object.
} dns_push_obj_any_t __attribute__((__transparent_union__));			// __transparent_union__ makes all object above as valid DNS push objects.

//======================================================================================================================
// MARK: - Object Methods

/*!
 *	@brief
 *		Retain a supported DNS push object by increasing the reference count by one.
 *
 *	@param dns_push_object
 *		The supported DNS push object contained in dns_push_obj_any_t union.
 *
 *	@result
 *		The retained DNS push object.
 */
dns_push_obj_t NONNULL
dns_push_obj_retain(dns_push_obj_any_t dns_push_object);

/*!
 *	@brief
 *		Release a supported DNS push object by decreasing the reference count by one. If the reference count becomes zero after releasing, the object will be
 *		finalized.
 *
 *	@param dns_push_object
 *		The supported DNS push object contained in dns_push_obj_any_t union.
 *
 *	@discussion
 *		Use <code>MDNS_DISPOSE_DNS_PUSH_OBJ()</code> provided by <code>mdns_strict.h</code> rather than the <code>dns_push_obj_release()</code>,
 *		because the macro checks the nullability of the pointer and always set the pointer to NULL after releasing.
 */
void
dns_push_obj_release(dns_push_obj_any_t dns_push_object);

/*!
 *	@brief
 *		Check if two supported DNS push objects are equal or not, based on the definition of the comparator of the object.
 *
 *	@param dns_push_object1
 *		The supported DNS push object to check the equality.
 *
 *	@param dns_push_object2
 *		The supported DNS push object to check the equality.
 *
 *	@result
 *		True if two objects have the same kind and the defined comparator indicates that they are equal, or the two objects are pointing to the same object
 *		instance. Otherwise, false.
 *
 *	@discussion
 *		If the kind of the two objects has no comparator defined, the comparator of the super kind will be used to determine their equality. Such process will
 *		continue until one available comparator is found or the root kind (NULL) is reached. If no comparator is available for the current kind, the result will be
 *		false.
 */
bool
dns_push_obj_equal(dns_push_obj_any_t dns_push_object1, dns_push_obj_any_t dns_push_object2);

/*!
 *	@brief
 *		Compare two supported DNS push objects, based on the definition of the comparator of the object.
 *
 *	@param dns_push_object1
 *		The supported DNS push object to compare.
 *
 *	@param dns_push_object2
 *		The supported DNS push object to compare.
 *
 *	@result
 *		<code>compare_result_less</code> if <code>dns_push_object1</code> is less than <code>dns_push_object2</code>.
 *		<code>compare_result_equal</code> if <code>dns_push_object1</code> is equal to <code>dns_push_object2</code>.
 *		<code>compare_result_greater</code> if <code>dns_push_object1</code> is greater than <code>dns_push_object2</code>.
 *		<code>compare_result_notequal</code> if two objects can be compared and they are not equal, but the specific order of the two objects cannot be determined.
 *		<code>compare_result_unknown</code> if two objects have different kind or no any comparator available to determine the comparison result, or any
 *			unexpected cases defined by the comparator.
 *
 *	@discussion
 *		If the kind of the two objects has no comparator defined, the comparator of the super kind will be used to determine their equality. Such process will
 *		continue until one available comparator is found or the root kind (NULL) is reached. If no comparator is available for the current kind, the result will be
 *		<code>compare_result_unknown</code>.
 *
 *		When the caller only wants know the equality of the two objects, use <code>dns_push_obj_equal()</code> instead of <code>dns_push_obj_compare()</code>
 *		because the former is faster than the latter.
 */
compare_result_t
dns_push_obj_compare(dns_push_obj_any_t dns_push_object1, dns_push_obj_any_t dns_push_object2);

#define dns_push_obj_replace(PTR, OBJ)			\
	do {										\
		if (*(PTR) == OBJ) {					\
			break;								\
		}										\
		if ((OBJ) != NULL) {					\
			dns_push_obj_retain(OBJ);			\
		}										\
		if (*(PTR)) {							\
			MDNS_DISPOSE_DNS_PUSH_OBJ(*(PTR));	\
		}										\
		*(PTR) = (OBJ);							\
	} while(0)

#define MDNS_DISPOSE_DNS_PUSH_OBJ(obj) _MDNS_STRICT_DISPOSE_TEMPLATE(obj, dns_push_obj_release)
#define dns_push_obj_forget(PTR)			\
	do {									\
		if (*(PTR)) {						\
			dns_push_obj_release(*(PTR));	\
			*(PTR) = NULL;					\
		}									\
	} while(0)

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

#endif // DNS_PUSH_OBJ
