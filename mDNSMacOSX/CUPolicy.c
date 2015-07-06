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
#include <network/config.h>

#if TARGET_OS_IPHONE

mDNSexport void CUPInit(mDNS *const m)
{
    
    m->p->handle = cellular_usage_policy_create_client();
    if (!m->p->handle)
    {
        LogMsg("CUPInit: cellular_usage_policy_create_client failed");
    }
}

mDNSexport mDNSBool mDNSPlatformAllowPID(mDNS *const m, DNSQuestion *q)
{
    // Currently the policy applies only for DNS requests sent over cellular interface
    if (m->p->handle && q->qDNSServer && q->qDNSServer->cellIntf)
    {
        mDNSBool allowed;
        if (q->pid)
        {
            allowed = (mDNSBool) cellular_usage_policy_is_data_allowed_for_pid(m->p->handle, q->pid);
            if (!allowed)
            {
                xpc_object_t pidx = xpc_uint64_create(q->pid);
                if (pidx)
                {
                    network_config_cellular_blocked_notify(pidx, NULL, NULL);
                    LogInfo("mDNSPlaformAllowPID: Notified PID(%d) for %##s (%s)", q->pid, q->qname.c, DNSTypeName(q->qtype));
                    xpc_release(pidx);
                }
            }
        }
        else
        {
           xpc_object_t uuidx = xpc_uuid_create(q->uuid);
           if (uuidx)
           {
               allowed = (mDNSBool) cellular_usage_policy_is_data_allowed_for_uuid(m->p->handle, uuidx);
               if (!allowed)
               {
                   network_config_cellular_blocked_notify(NULL, uuidx, NULL);
                   LogInfo("mDNSPlaformAllowPID: Notified UUID for %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
               }
               xpc_release(uuidx);
           }
           else
           {
               allowed = false;
           }
       }
        return allowed;
    }
    else
    {
        return mDNStrue;
    }
}

#else // TARGET_OS_IPHONE

mDNSexport void CUPInit(mDNS *const m)
{
    (void)m; //unused
}

mDNSexport mDNSBool mDNSPlatformAllowPID(mDNS *const m, DNSQuestion *q)
{
    (void)m;    //unused
    (void)q;    //unused
    //LogMsg("mDNSPlatformAllowPID: %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
    return mDNStrue;
}

#endif // TARGET_OS_IPHONE

