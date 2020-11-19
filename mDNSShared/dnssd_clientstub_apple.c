/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1.  Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of its
 *     contributors may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "dnssd_clientstub_apple.h"
#include "dns_sd_private.h"

#include <CoreUtils/CommonServices.h>
#include <CoreUtils/DebugServices.h>
#include <os/lock.h>

static xpc_object_t		g_defaults_dict = NULL;
static os_unfair_lock	g_defaults_lock = OS_UNFAIR_LOCK_INIT;

DNSServiceErrorType DNSSD_API
DNSServiceSetResolverDefaults(const void * const plist_data_ptr, const size_t plist_data_len, bool require_privacy)
{
	DNSServiceErrorType err;
    require_action_quiet(plist_data_len <= (32 * CUBytesPerKibiByte), exit, err = kDNSServiceErr_Invalid);

    const xpc_object_t new_dict = xpc_dictionary_create(NULL, NULL, 0);
    require_action_quiet(new_dict, exit, err = kDNSServiceErr_NoMemory);

    xpc_dictionary_set_bool(new_dict, kDNSServiceDefaultsKey_RequirePrivacy, require_privacy);
	if (plist_data_ptr && (plist_data_len > 0)) {
        xpc_dictionary_set_data(new_dict, kDNSServiceDefaultsKey_ResolverConfigPListData, plist_data_ptr,
            plist_data_len);
	}
	os_unfair_lock_lock(&g_defaults_lock);
	xpc_object_t old_dict = g_defaults_dict;
	g_defaults_dict = new_dict;
	os_unfair_lock_unlock(&g_defaults_lock);

	xpc_forget(&old_dict);
	err = kDNSServiceErr_NoError;

exit:
	return err;
}

xpc_object_t
DNSServiceGetRetainedResolverDefaults(void)
{
	os_unfair_lock_lock(&g_defaults_lock);
	const xpc_object_t dict_copy = g_defaults_dict ? xpc_retain(g_defaults_dict) : NULL;
	os_unfair_lock_unlock(&g_defaults_lock);
	return dict_copy;
}
