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

#include "mdns_managed_defaults.h"

#include "mdns_helpers.h"

#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Internals

// Managed defaults is currently only for iOS-like OSes.
#if !defined(TARGET_OS_IOS_LIKE_DEVICE)
	#error "TARGET_OS_IOS_LIKE_DEVICE is not defined"
#endif

MDNS_LOG_CATEGORY_DEFINE(managed_defaults, "managed_defaults");

//======================================================================================================================
// MARK: - Local Prototypes

#if TARGET_OS_IOS_LIKE_DEVICE
static CFURLRef
_mdns_managed_defaults_create_domain_url(const char *domain, OSStatus *out_error);

static CFReadStreamRef
_mdns_managed_defaults_create_opened_read_stream(CFURLRef url, OSStatus *out_error);

static CFDictionaryRef
_mdns_managed_defaults_create_dictionary_from_stream(CFReadStreamRef stream, OSStatus *out_error);
#endif

static int64_t
_mdns_managed_defaults_get_int64(CFDictionaryRef defaults, CFStringRef key, OSStatus *out_error);

#define _assign_null_safe(PTR, VALUE)	\
	do {								\
		if ((PTR)) {					\
			*(PTR) = (VALUE);			\
		}								\
	} while(0)

//======================================================================================================================
// MARK: - Public Functions

#if TARGET_OS_IOS_LIKE_DEVICE
CFDictionaryRef
mdns_managed_defaults_create(const char * const domain, OSStatus * const out_error)
{
	CFDictionaryRef result = NULL;
	OSStatus err, tmp_err;
	CFURLRef url = _mdns_managed_defaults_create_domain_url(domain, &tmp_err);
	require_action_quiet(url, exit, err = tmp_err; os_log_error(_mdns_managed_defaults_log(),
		"Failed to create URL -- domain: %{public}s, error: %{mdns:err}ld", domain, (long)err));

	CFReadStreamRef stream = _mdns_managed_defaults_create_opened_read_stream(url, &tmp_err);
	require_action_quiet(stream, exit, err = tmp_err; os_log_error(_mdns_managed_defaults_log(),
		"Failed to create read stream -- url: %{public}@, error: %{mdns:err}ld", url, (long)err));

	CFDictionaryRef plist = _mdns_managed_defaults_create_dictionary_from_stream(stream, &tmp_err);
	ForgetCF(&stream);
	require_action_quiet(plist, exit, err = tmp_err; os_log_error(_mdns_managed_defaults_log(),
		"Failed to create dictionary -- url: %{public}@, error: %{mdns:err}ld", url, (long)err));

	result = plist;
	err = kNoErr;

exit:
	ForgetCF(&url);
	_assign_null_safe(out_error, err);
	return result;
}
#else
CFDictionaryRef
mdns_managed_defaults_create(__unused const char * const domain, OSStatus * const out_error)
{
	os_log_info(_mdns_managed_defaults_log(), "Managed defaults is not supported on this OS");
	_assign_null_safe(out_error, kUnsupportedErr);
	return NULL;
}
#endif // TARGET_OS_IOS_LIKE_DEVICE

//======================================================================================================================

int
mdns_managed_defaults_get_int_clamped(const CFDictionaryRef defaults, const CFStringRef key, const int fallback_value,
	OSStatus * const out_error)
{
	int result;
	OSStatus err;
	const int64_t value = _mdns_managed_defaults_get_int64(defaults, key, &err);
	require_noerr_action_quiet(err, exit, result = fallback_value);

	result = (int)Clamp(value, INT_MIN, INT_MAX);

exit:
	_assign_null_safe(out_error, err);
	return result;
}

//======================================================================================================================
// MARK: - Private Functions

#if TARGET_OS_IOS_LIKE_DEVICE
static CFURLRef
_mdns_managed_defaults_create_domain_url(const char * const domain, OSStatus * const out_error)
{
	OSStatus err;
	CFURLRef result = NULL;
	char *path_cstr = NULL;
	asprintf(&path_cstr, "/Library/Managed Preferences/mobile/%s.plist", domain);
	require_action_quiet(path_cstr, exit, err = kNoMemoryErr);

	CFStringRef path = CFStringCreateWithCStringNoCopy(NULL, path_cstr, kCFStringEncodingUTF8, kCFAllocatorMalloc);
	require_action_quiet(path, exit, ForgetMem(&path_cstr); err = kNoResourcesErr);
	path_cstr = NULL;

	CFURLRef url = CFURLCreateWithFileSystemPath(kCFAllocatorDefault, path, kCFURLPOSIXPathStyle, false);
	ForgetCF(&path);
	require_action_quiet(url, exit, err = kNoResourcesErr);

	result = url;
	err = kNoErr;

exit:
	_assign_null_safe(out_error, err);
	return result;
}

//======================================================================================================================

static CFReadStreamRef
_mdns_managed_defaults_create_opened_read_stream(const CFURLRef url, OSStatus * const out_error)
{
	OSStatus err;
	CFReadStreamRef result = NULL;
	CFReadStreamRef stream = CFReadStreamCreateWithFile(kCFAllocatorDefault, url);
	require_action_quiet(stream, exit, err = kNoResourcesErr);

	const Boolean ok = CFReadStreamOpen(stream);
	require_action_quiet(ok, exit, ForgetCF(&stream); err = kOpenErr);

	result = stream;
	err = kNoErr;

exit:
	_assign_null_safe(out_error, err);
	return result;
}

//======================================================================================================================

static OSStatus
_mdns_get_cferror_code(CFErrorRef error);

static CFDictionaryRef
_mdns_managed_defaults_create_dictionary_from_stream(const CFReadStreamRef stream, OSStatus * const out_error)
{
	OSStatus err;
	CFErrorRef error = NULL;
	CFDictionaryRef result = NULL;
	CFPropertyListRef plist = CFPropertyListCreateWithStream(NULL, stream, 0, kCFPropertyListImmutable, NULL, &error);
	require_action_quiet(plist, exit, err = _mdns_get_cferror_code(error); os_log_error(_mdns_managed_defaults_log(),
		"CFPropertyListCreateWithStream failed: %{public}@", error));
	require_action_quiet(CFIsType(plist, CFDictionary), exit, ForgetCF(&plist); err = kTypeErr);

	result = plist;
	err = kNoErr;

exit:
	ForgetCF(&error);
	_assign_null_safe(out_error, err);
	return result;
}

static OSStatus
_mdns_get_cferror_code(const CFErrorRef error)
{
	return (error ? ((OSStatus)CFErrorGetCode(error)) : kUnknownErr);
}
#endif // TARGET_OS_IOS_LIKE_DEVICE

//======================================================================================================================

static int64_t
_mdns_managed_defaults_get_int64(const CFDictionaryRef defaults, const CFStringRef key, OSStatus * const out_error)
{
	OSStatus err;
	int64_t result = 0;
	const CFNumberRef number = CFDictionaryGetValue(defaults, key);
	require_action_quiet(number != NULL, exit, err = kNotFoundErr);
	require_action_quiet(CFIsType(number, CFNumber), exit, err = kTypeErr);
	require_action_quiet(!CFNumberIsFloatType(number), exit, err = kTypeErr);

	int64_t value;
	const Boolean ok = CFNumberGetValue(number, kCFNumberSInt64Type, &value);
	require_action_quiet(ok, exit, err = kUnknownErr);

	result = value;
	err = kNoErr;

exit:
	_assign_null_safe(out_error, err);
	return result;
}
