/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#include "mrcs_cf_support.h"

#include "mdns_obj.h"
#include "mrcs_object.h"

#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Local Prototypes

static const void *
_mrcs_cf_callback_retain(CFAllocatorRef allocator, const void *value);

static void
_mrcs_cf_callback_release(CFAllocatorRef allocator, const void *value);

static CFStringRef
_mrcs_cf_callback_copy_description(const void *value);

static mrcs_object_t
_mrcs_cf_const_void_pointer_to_object(const void *value);

//======================================================================================================================
// MARK: - CF Callback Structures

const CFArrayCallBacks mrcs_cfarray_callbacks = {
	.version			= 0,
	.retain				= _mrcs_cf_callback_retain,
	.release			= _mrcs_cf_callback_release,
	.copyDescription	= _mrcs_cf_callback_copy_description,
};

//======================================================================================================================
// MARK: - External Functions

bool
mrcs_cfarray_enumerate(const CFArrayRef array, const mrcs_any_applier_t applier)
{
	bool completed = false;
	const CFIndex n = CFArrayGetCount(array);
	for (CFIndex i = 0; i < n; ++i) {
		const mrcs_object_t object = _mrcs_cf_const_void_pointer_to_object(CFArrayGetValueAtIndex(array, i));
		const bool proceed = applier(object);
		if (!proceed) {
			goto exit;
		}
	}
	completed = true;

exit:
	return completed;
}

//======================================================================================================================
// MARK: - Internal Functions

static const void *
_mrcs_cf_callback_retain(__unused const CFAllocatorRef allocator, const void * const value)
{
	const mrcs_object_t object = _mrcs_cf_const_void_pointer_to_object(value);
	mrcs_retain(object);
	return object;
}

//======================================================================================================================

static void
_mrcs_cf_callback_release(__unused const CFAllocatorRef allocator, const void * const value)
{
	const mrcs_object_t object = _mrcs_cf_const_void_pointer_to_object(value);
	mrcs_release(object);
}

//======================================================================================================================

static CFStringRef
_mrcs_cf_callback_copy_description(const void * const value)
{
	const mrcs_object_t object = _mrcs_cf_const_void_pointer_to_object(value);
	return mdns_obj_copy_description_as_cfstring(object);
}

//======================================================================================================================

mrcs_object_t
_mrcs_cf_const_void_pointer_to_object(const void * const value)
{
	// CF callbacks are broken in that they use 'const void *' for the values contained in collections, so they
	// have to be unconstified when they're cast to mrcs_object_t, which is an opaque pointer type. This is a
	// necessary evil in order for callbacks that modify a value, such as the retain and release callbacks, to
	// work. Most retain and release operate by modifying an object's internal reference count, which is only
	// possible with a non-const pointer.
	CUClangWarningIgnoreBegin(-Wcast-qual);
	const mrcs_object_t object = (mrcs_object_t)value;
	CUClangWarningIgnoreEnd();
	return object;
}
