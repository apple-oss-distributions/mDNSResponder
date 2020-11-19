/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include "mdns_internal.h"
#include "mdns_object.h"

#include "mdns_objects.h"

#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Object Kind Definition

static char *
_mdns_object_copy_description(mdns_object_t object, bool debug, bool privacy);

const struct mdns_kind_s _mdns_object_kind = {
	NULL,		// No superkind.
	"object",	// Name.
	_mdns_object_copy_description,
	NULL,		// No equal method.
	NULL		// No finalize method.
};

static const void *
_mdns_cf_collection_callback_retain(CFAllocatorRef allocator, const void *object);

static void
_mdns_cf_collection_callback_release(CFAllocatorRef allocator, const void *object);

static CFStringRef
_mdns_cf_collection_callback_copy_description(const void *object);

static Boolean
_mdns_cf_collection_callback_equal(const void *object1, const void *object2);

const CFArrayCallBacks mdns_cfarray_callbacks = {
	0,												// version
	_mdns_cf_collection_callback_retain,			// retain
	_mdns_cf_collection_callback_release,			// release
	_mdns_cf_collection_callback_copy_description,	// copy description
	_mdns_cf_collection_callback_equal				// equal
};

//======================================================================================================================
// MARK: - Object Public Methods

mdns_object_t
mdns_retain(mdns_object_t me)
{
	return os_retain(me);
}

//======================================================================================================================

void
mdns_release(mdns_object_t me)
{
	os_release(me);
}

//======================================================================================================================

char *
mdns_copy_description(mdns_object_t me)
{
	return mdns_object_copy_description(me, false, false);
}

//======================================================================================================================

bool
mdns_equal(mdns_object_t me, mdns_object_t other)
{
	if (me == other) {
		return true;
	}
	if (me->kind != other->kind) {
		return false;
	}
	if (me->kind->equal) {
		return me->kind->equal(me, other);
	}
	return false;
}

//======================================================================================================================
// MARK: - Object Private Methods

static char *
_mdns_object_copy_description(mdns_object_t me, __unused bool debug, __unused bool privacy)
{
	char *description = NULL;
	asprintf(&description, "<%s: %p>", me->kind->name, (void *)me);
	return description;
}

//======================================================================================================================

char *
mdns_object_copy_description(mdns_object_t me, bool debug, bool privacy)
{
	for (mdns_kind_t kind = me->kind; kind; kind = kind->superkind) {
		if (kind->copy_description) {
			return kind->copy_description(me, debug, privacy);
		}
	}
	return NULL;
}

//======================================================================================================================

CFStringRef
mdns_object_copy_description_as_cfstring_ex(mdns_object_t me, bool debug, bool privacy)
{
	CFStringRef description = NULL;
	char *cstring = mdns_object_copy_description(me, debug, privacy);
	require_quiet(cstring, exit);

	description = CFStringCreateWithCStringNoCopy(NULL, cstring, kCFStringEncodingUTF8, kCFAllocatorMalloc);
	require_quiet(description, exit);
	cstring = NULL;

exit:
	FreeNullSafe(cstring);
	return description;
}

//======================================================================================================================

void
mdns_object_finalize(mdns_object_t me)
{
	for (mdns_kind_t kind = me->kind; kind; kind = kind->superkind) {
		if (kind->finalize) {
			kind->finalize(me);
		}
	}
}

//======================================================================================================================

static const void *
_mdns_cf_collection_callback_retain(__unused CFAllocatorRef allocator, const void *obj)
{
	mdns_retain((mdns_object_t)obj);
	return obj;
}

//======================================================================================================================

static void
_mdns_cf_collection_callback_release(__unused CFAllocatorRef allocator, const void *obj)
{
	mdns_release((mdns_object_t)obj);
}

//======================================================================================================================

static CFStringRef
_mdns_cf_collection_callback_copy_description(const void *obj)
{
	return mdns_object_copy_description_as_cfstring((mdns_object_t)obj);
}

//======================================================================================================================

static Boolean
_mdns_cf_collection_callback_equal(const void *object1, const void *object2)
{
	return mdns_equal((mdns_object_t)object1, (mdns_object_t)object2);
}
