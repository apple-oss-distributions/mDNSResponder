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

#ifndef __MDNS_MANAGED_DEFAUTS_H__
#define __MDNS_MANAGED_DEFAUTS_H__

#include "mdns_base.h"

#include <CoreFoundation/CoreFoundation.h>
#include <MacTypes.h>
#include <stdint.h>

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a defaults dictionary based on a managed defaults domain.
 *
 *	@param domain
 *		The managed defaults domain as a UTF-8 C string.
 *
 *	@param out_error
 *		Gets set to an error code that indicates the error that was encountered, if any.
 *
 *	@result
 *		A reference to a dictionary if successful. Otherwise, NULL.
 */
CFDictionaryRef _Nullable
mdns_managed_defaults_create(const char *domain, OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Gets the integer value of a key from a defaults dictionary.
 *
 *	@param defaults
 *		The defaults dictionary.
 *
 *	@param key
 *		The key.
 *
 *	@param fallback_value
 *		A fallback value to return if the key is not present in the dictionary, or if the key's value is not an
 *		integer.
 *
 *	@param out_error
 *		Gets set to an error code that indicates the error that was encountered, if any.
 *
 *	@result
 *		If the key is present in the dictionary and the key's value is an integer, then the value is returned
 *		after clamping it in the [INT_MIN, INT_MAX] range. Otherwise, the specified fallback value is returned.
 *		
 */
int
mdns_managed_defaults_get_int_clamped(CFDictionaryRef defaults, CFStringRef key, int fallback_value,
	OSStatus * _Nullable out_error);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_MANAGED_DEFAUTS_H__
