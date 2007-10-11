/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

    Change History (most recent first):

$Log: helper-stubs.c,v $
Revision 1.5  2007/09/07 22:44:03  mcguire
<rdar://problem/5448420> Move CFUserNotification code to mDNSResponderHelper

Revision 1.4  2007/09/04 22:32:58  mcguire
<rdar://problem/5453633> BTMM: BTMM overwrites /etc/racoon/remote/anonymous.conf

Revision 1.3  2007/08/23 21:44:55  cheshire
Made code layout style consistent with existing project style; added $Log header

Revision 1.2  2007/08/18 01:02:03  mcguire
<rdar://problem/5415593> No Bonjour services are getting registered at boot

Revision 1.1  2007/08/08 22:34:58  mcguire
<rdar://problem/5197869> Security: Run mDNSResponder as user id mdnsresponder instead of root
 */

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/vm_map.h>
#include <servers/bootstrap.h>
#include <CoreFoundation/CoreFoundation.h>
#include "mDNSDebug.h"
#include "helper.h"
#include "helpermsg.h"

#define ERROR(x, y) y,
static const char *errorstring[] =
	{
	#include "helper-error.h"
	NULL
	};
#undef ERROR

static mach_port_t
getHelperPort(int retry)
	{
	static mach_port_t port = MACH_PORT_NULL;

	if (retry)
		port = MACH_PORT_NULL;
	if (port == MACH_PORT_NULL &&
	    BOOTSTRAP_SUCCESS != bootstrap_look_up(bootstrap_port,
	    kmDNSHelperServiceName, &port))
		LogMsg("%s: cannot contact helper", __func__);
	return port;
	}

const char *
mDNSHelperError(int err)
	{
	const char *p = "<unknown error>";
	if (mDNSHelperErrorBase < err && mDNSHelperErrorEnd > err)
		p = errorstring[err - mDNSHelperErrorBase - 1];
	return p;
	}


/* Ugly but handy. */
#define MACHRETRYLOOP_BEGIN(kr, retry, err, fin) for (;;) {

#define MACHRETRYLOOP_END(kr, retry, err, fin)				\
		if (KERN_SUCCESS == (kr)) break;					\
		else if (MACH_SEND_INVALID_DEST == (kr) && 0 == (retry)++) continue;	\
		else \
			{								\
			(err) = kmDNSHelperCommunicationFailed;			\
			LogMsg("%s: Mach communication failed: %s", __func__, mach_error_string(kr));				\
			goto fin;						\
			}								\
		}								\
	if (0 != (err)) { LogMsg("%s: %s", __func__, mDNSHelperError((err))); goto fin; }

int
mDNSPreferencesSetName(int key, domainlabel* old, domainlabel* new)
	{
	kern_return_t kr = KERN_FAILURE;
	int retry = 0;
	int err = 0;
	char oldname[MAX_DOMAIN_LABEL+1] = {0};
	char newname[MAX_DOMAIN_LABEL+1] = {0};
	ConvertDomainLabelToCString_unescaped(old, oldname);
	if (new) ConvertDomainLabelToCString_unescaped(new, newname);

	MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
	kr = proxy_mDNSPreferencesSetName(getHelperPort(retry), key, oldname, newname, &err);
	MACHRETRYLOOP_END(kr, retry, err, fin);

fin:
	return err;
	}

int
mDNSDynamicStoreSetConfig(int key, CFPropertyListRef value)
	{
	CFWriteStreamRef stream = NULL;
	CFDataRef bytes = NULL;
	kern_return_t kr = KERN_FAILURE;
	int retry = 0;
	int err = 0;

	if (NULL == (stream = CFWriteStreamCreateWithAllocatedBuffers(NULL,
	    NULL)))
		{
		err = kmDNSHelperCreationFailed;
		LogMsg("%s: CFWriteStreamCreateWithAllocatedBuffers failed",
			__func__);
		goto fin;
		}
	CFWriteStreamOpen(stream);
	if (0 == CFPropertyListWriteToStream(value, stream,
	    kCFPropertyListBinaryFormat_v1_0, NULL))
		{
		err = kmDNSHelperPListWriteFailed;
		LogMsg("%s: CFPropertyListWriteToStream failed", __func__);
		goto fin;
		}
	if (NULL == (bytes = CFWriteStreamCopyProperty(stream,
	    kCFStreamPropertyDataWritten)))
		{
		err = kmDNSHelperCreationFailed;
		LogMsg("%s: CFWriteStreamCopyProperty failed", __func__);
		goto fin;
		}
	CFWriteStreamClose(stream);
	CFRelease(stream);
	stream = NULL;
	MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
	kr = proxy_mDNSDynamicStoreSetConfig(getHelperPort(retry), key,
	    (vm_offset_t)CFDataGetBytePtr(bytes),
	    CFDataGetLength(bytes), &err);
	MACHRETRYLOOP_END(kr, retry, err, fin);

fin:
	if (NULL != stream)
		{
		CFWriteStreamClose(stream);
		CFRelease(stream);
		}
	if (NULL != bytes)
		CFRelease(bytes);
	return err;
	}

int
mDNSKeychainGetSecrets(CFArrayRef *result)
	{
	CFPropertyListRef plist = NULL;
	CFDataRef bytes = NULL;
	kern_return_t kr = KERN_FAILURE;
	unsigned int numsecrets = 0;
	void *secrets = NULL;
	mach_msg_type_number_t secretsCnt = 0;
	int retry = 0;
	int err = 0;


	MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
	kr = proxy_mDNSKeychainGetSecrets(getHelperPort(retry),
	    &numsecrets, (vm_offset_t *)&secrets, &secretsCnt, &err);
	MACHRETRYLOOP_END(kr, retry, err, fin);
	if (0 == numsecrets)
		goto fin;
	if (NULL == (bytes = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault,
	    secrets, secretsCnt, kCFAllocatorNull)))
		{
		err = kmDNSHelperCreationFailed;
		LogMsg("%s: CFDataCreateWithBytesNoCopy failed", __func__);
		goto fin;
		}
	if (NULL == (plist = CFPropertyListCreateFromXMLData(
	    kCFAllocatorDefault, bytes, kCFPropertyListImmutable, NULL)))
		{
		err = kmDNSHelperInvalidPList;
		LogMsg("%s: CFPropertyListCreateFromXMLData failed", __func__);
		goto fin;
		}
	if (CFArrayGetTypeID() != CFGetTypeID(plist))
		{
		err = kmDNSHelperTypeError;
		LogMsg("%s: Unexpected result type", __func__);
		CFRelease(plist);
		plist = NULL;
		goto fin;
		}
	*result = (CFArrayRef)plist;

fin:
	if (NULL != bytes)
		CFRelease(bytes);
	if (NULL != secrets)
		vm_deallocate(mach_task_self(), (vm_offset_t)secrets,
		    secretsCnt);
	return err;
	}

int
mDNSAutoTunnelInterfaceUpDown(int updown, v6addr_t address)
	{
	kern_return_t kr = KERN_SUCCESS;
	int retry = 0;
	int err = 0;

	MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
	kr = proxy_mDNSAutoTunnelInterfaceUpDown(getHelperPort(retry),
	    updown, address, &err);
	MACHRETRYLOOP_END(kr, retry, err, fin);

fin:
	return err;
	}

int
mDNSConfigureServer(int updown, const char *keydata)
	{
	kern_return_t kr = KERN_SUCCESS;
	int retry = 0;
	int err = 0;

	MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
	kr = proxy_mDNSConfigureServer(getHelperPort(retry), updown, keydata, &err);
	MACHRETRYLOOP_END(kr, retry, err, fin);

fin:
	return err;
	}

int
mDNSAutoTunnelSetKeys(int replacedelete, v6addr_t local_inner,
    v4addr_t local_outer, short local_port, v6addr_t remote_inner,
    v4addr_t remote_outer, short remote_port, const char *keydata)
	{
	kern_return_t kr = KERN_SUCCESS;
	const char *p = NULL;
	int retry = 0;
	int err = 0;

	if (kmDNSAutoTunnelSetKeysReplace == replacedelete)
		p = keydata;
	else
		p = "";
	MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
	kr = proxy_mDNSAutoTunnelSetKeys(getHelperPort(retry), replacedelete,
	    local_inner, local_outer, local_port, remote_inner, remote_outer,
	    remote_port, keydata, &err);
	MACHRETRYLOOP_END(kr, retry, err, fin);

fin:
	return err;
	}
