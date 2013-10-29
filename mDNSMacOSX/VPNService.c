/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2013 Apple Computer, Inc. All rights reserved.
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
 */
#include "mDNSMacOSX.h"
#include <SystemConfiguration/VPNAppLayerPrivate.h>

mDNSexport mDNSs32 mDNSPlatformGetServiceID(mDNS *const m, DNSQuestion *q)
{
    (void) m;
    int sid;

    if (q->pid)
    {
        sid = VPNAppLayerGetMatchingServiceIdentifier(q->pid, NULL);
    }
    else
    {
        sid = VPNAppLayerGetMatchingServiceIdentifier(0, q->uuid);
    }
    LogInfo("mDNSPlatformGetServiceID: returning %d for %##s (%s)", sid, q->qname.c, DNSTypeName(q->qtype));
    return sid;
}
