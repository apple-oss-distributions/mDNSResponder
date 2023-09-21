/*
 * Copyright (c) 2013-2023 Apple Inc. All rights reserved.
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

#include "mDNSMacOSX.h"
#include <mdns/system.h>
#include <nw/private.h>

#include "dns_sd_internal.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
#include "QuerierSupport.h"
#endif

#include "mdns_strict.h"

#define _nw_forget(PTR)         \
    do                          \
    {                           \
        if (*(PTR))             \
        {                       \
            nw_release(*(PTR)); \
            *(PTR) = NULL;      \
        }                       \
    } while (0)

//Gets the DNSPolicy from NW PATH EVALUATOR
mDNSexport void mDNSPlatformGetDNSRoutePolicy(DNSQuestion *q)
{
    nw_endpoint_t host = NULL;
    nw_parameters_t parameters = NULL;
    nw_path_evaluator_t evaluator = NULL;
    nw_path_t path = NULL;
    mDNSBool isBlocked = mDNSfalse;
    q->ServiceID = -1; // initialize the ServiceID to default value of -1

    // Return for non-unicast DNS queries, or invalid PID.
    if (mDNSOpaque16IsZero(q->TargetQID) || (q->pid < 0))
    {
        goto exit;
    }

    mDNSs32 service_id;
    mDNSu32 client_ifindex, dnspol_ifindex;
    mDNSBool isUUIDSet;

    char unenc_name[MAX_ESCAPED_DOMAIN_NAME];
    ConvertDomainNameToCString(&q->qname, unenc_name);

    host = nw_endpoint_create_host(unenc_name, "0");
    if (host == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[Q%u] mDNSPlatformGetDNSRoutePolicy: Query for " PRI_DM_NAME " (" PUB_S "), PID[%d], EUID[%d], ServiceID[%d]"
            " host is NULL",
            mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), q->pid, q->euid, q->ServiceID);
        goto exit;
    }
    parameters = nw_parameters_create();
    if (parameters == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[Q%u] mDNSPlatformGetDNSRoutePolicy: Query for " PRI_DM_NAME " (" PUB_S "), PID[%d], EUID[%d], ServiceID[%d]"
            " parameters is NULL",
            mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), q->pid, q->euid, q->ServiceID);
        goto exit;
    }
#if TARGET_OS_WATCH
    static xpc_object_t prohibited_interface_subtypes = NULL;
    // Companion interface on watchOS does not support DNS, so we don't want path evalution to return it to us.
    if (prohibited_interface_subtypes == NULL)
    {
        prohibited_interface_subtypes = xpc_array_create(NULL, 0);
        if (prohibited_interface_subtypes != NULL)
        {
            xpc_array_set_uint64(prohibited_interface_subtypes, XPC_ARRAY_APPEND, nw_interface_subtype_companion);
        }
    }
    if (prohibited_interface_subtypes == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_UDNS, MDNS_LOG_ERROR,
                  "mDNSPlatformGetDNSRoutePolicy: DNS Route Policy: prohibited_interface_subtypes returned by xpc_array_create() is NULL");
    }
    else
    {
        nw_parameters_set_prohibited_interface_subtypes(parameters, prohibited_interface_subtypes);
    }
#endif // TARGET_OS_WATCH

    // Check for all the special (negative) internal value interface indices before initializing client_ifindex
    if (   (q->InterfaceID == mDNSInterface_Any)
        || (q->InterfaceID == mDNSInterface_LocalOnly)
        || (q->InterfaceID == mDNSInterfaceMark)
        || (q->InterfaceID == mDNSInterface_P2P)
        || (q->InterfaceID == mDNSInterface_BLE)
        || (q->InterfaceID == uDNSInterfaceMark))
    {
        client_ifindex = 0;
    }
    else
    {
        client_ifindex = (mDNSu32)(uintptr_t)q->InterfaceID;
    }

    if (client_ifindex > 0)
    {
        nw_interface_t client_intf = nw_interface_create_with_index(client_ifindex);
        if (client_intf)
        {
            nw_parameters_require_interface(parameters, client_intf);
            _nw_forget(&client_intf);
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[Q%u] mDNSPlatformGetDNSRoutePolicy: nw_interface_create_with_index() returned NULL for index %u",
                mDNSVal16(q->TargetQID), client_ifindex);
        }
    }

    nw_parameters_set_uid(parameters,(uid_t)q->euid);

    if (q->pid != 0)
    {
        nw_parameters_set_pid(parameters, q->pid);
        uuid_t uuid;
        const OSStatus err = mdns_system_pid_to_uuid(q->pid, uuid);
        if (!err)
        {
            nw_parameters_set_e_proc_uuid(parameters, uuid);
            isUUIDSet = mDNStrue;
        }
        else
        {
            debugf("mDNSPlatformGetDNSRoutePolicy: proc_pidinfo returned %ld", (long)err);
            isUUIDSet = mDNSfalse;
        }
    }
    else
    {
        nw_parameters_set_e_proc_uuid(parameters, q->uuid);
        isUUIDSet = mDNStrue;
    }

    evaluator = nw_path_create_evaluator_for_endpoint(host, parameters);
    if (evaluator == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[Q%u] mDNSPlatformGetDNSRoutePolicy: Query for " PRI_DM_NAME " (" PUB_S "), PID[%d], EUID[%d], ServiceID[%d]"
            " evaluator is NULL",
            mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), q->pid, q->euid, q->ServiceID);
        goto exit;
    }
    _nw_forget(&host);
    _nw_forget(&parameters);

    path = nw_path_evaluator_copy_path(evaluator);
    if (path == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "[Q%u] mDNSPlatformGetDNSRoutePolicy: Query for " PRI_DM_NAME " (" PUB_S "), PID[%d], EUID[%d], ServiceID[%d]"
            " path is NULL",
            mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), DNSTypeName(q->qtype), q->pid, q->euid, q->ServiceID);
        goto exit;
    }

    if (nw_path_get_status(path) == nw_path_status_satisfied)
    {
        service_id = (mDNSs32)nw_path_get_flow_divert_unit(path);
        if (service_id != 0)
        {
            q->ServiceID = service_id;
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                "[Q%u] mDNSPlatformGetDNSRoutePolicy: Query for " PRI_DM_NAME " service ID is set ->service_ID:[%d] ",
                mDNSVal16(q->TargetQID), DM_NAME_PARAM(&q->qname), service_id);
        }
        else
        {
            nw_interface_t nwpath_intf = nw_path_copy_scoped_interface(path);
            if (nwpath_intf != NULL)
            {
                // Use the new scoped interface given by NW PATH EVALUATOR
                dnspol_ifindex = nw_interface_get_index(nwpath_intf);
                q->InterfaceID = (mDNSInterfaceID)(uintptr_t)dnspol_ifindex;

                _nw_forget(&nwpath_intf);

                if (dnspol_ifindex != client_ifindex)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                        "[Q%u] mDNSPlatformGetDNSRoutePolicy: DNS Route Policy has changed the scoped ifindex from [%d] to [%d]",
                        mDNSVal16(q->TargetQID), client_ifindex, dnspol_ifindex);
                }
            }
            else
            {
                debugf("mDNSPlatformGetDNSRoutePolicy: Query for %##s (%s), PID[%d], EUID[%d], ServiceID[%d] nw_interface_t nwpath_intf is NULL ", q->qname.c, DNSTypeName(q->qtype), q->pid, q->euid, q->ServiceID);
            }
        }
    }
    else if (isUUIDSet && (nw_path_get_status(path) == nw_path_status_unsatisfied) && (nw_path_get_reason(path) != nw_path_reason_no_route))
    {
        isBlocked = mDNStrue;
    }
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    if (!isBlocked)
    {
        uuid_clear(q->ResolverUUID);
        if (path != NULL)
        {
            __block nw_resolver_config_t best_config = NULL;
            __block mDNSBool best_config_allows_failover = mDNSfalse;
            __block nw_resolver_class_t best_class = nw_resolver_class_default_direct;
            nw_path_enumerate_resolver_configs(path,
            ^bool(nw_resolver_config_t config)
            {
                const mDNSBool allows_failover = nw_resolver_config_get_allow_failover(config);
                const nw_resolver_class_t class = nw_resolver_config_get_class(config);
                if (class != nw_resolver_class_default_direct &&
                    (!allows_failover || !q->IsFailover) &&
                    (best_class == nw_resolver_class_default_direct || class < best_class))
                {
                    best_class = class;
                    best_config = config;
                    best_config_allows_failover = allows_failover;
                }
                return true;
            });
            if (best_config != NULL)
            {
                nw_resolver_config_get_identifier(best_config, q->ResolverUUID);
            }
        }
        if (!uuid_is_null(q->ResolverUUID))
        {
            Querier_RegisterPathResolver(q->ResolverUUID);
        }
    }
#endif

exit:
    _nw_forget(&host);
    _nw_forget(&parameters);
    _nw_forget(&path);
    _nw_forget(&evaluator);
    q->BlockedByPolicy = isBlocked;
}
