
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

#include "mdns_xpc.h"

#include <CoreFoundation/CFXPCBridge.h>
#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Public Functions

xpc_object_t
mdns_xpc_create_dictionary_from_plist_data(const uint8_t * const bytes, const size_t length, OSStatus * const out_error)
{
	xpc_object_t dictionary = NULL;
	CFPropertyListRef plist = NULL;
	OSStatus err;
	CFDataRef data = CFDataCreate(NULL, bytes, (CFIndex)length);
	require_action_quiet(data, exit, err = kNoMemoryErr);

	plist = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, NULL);
	ForgetCF(&data);
	require_action_quiet(plist, exit, err = kFormatErr);
	require_action_quiet(CFGetTypeID(plist) == CFDictionaryGetTypeID(), exit, err = kTypeErr);

	dictionary = _CFXPCCreateXPCObjectFromCFObject(plist);
	require_action_quiet(dictionary, exit, err = kUnknownErr);

	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	ForgetCF(&plist);
	return dictionary;
}
