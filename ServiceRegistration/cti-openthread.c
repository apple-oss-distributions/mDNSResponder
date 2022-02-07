/* cti-openthread.c
 *
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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
 *
 * This code adds border router support to 3rd party HomeKit Routers as part of Apple’s commitment to the CHIP project.
 *
 * Concise Thread Interface implementation
 */

#define _GNU_SOURCE 1
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "cti-proto.h"
#include "cti-server.h"
#include "cti-openthread.h"

#include <syslog.h>
#include <openthread/config.h>
#include <openthread/server.h>
#include <openthread/border_router.h>
#include <openthread/instance.h>
#include <openthread/thread.h>
#include <openthread/platform/misc.h>
#include <openthread/openthread-system.h>

otInstance* gInstance = NULL;
void handleThreadStateChanged(uint32_t flags, void UNUSED *context);

#define SuccessOrFailure(eval)                      \
    do                                              \
    {                                               \
        if (!(eval))                                \
        {                                           \
            return kCTIStatus_UnknownError;         \
        }                                           \
    } while (false)

// OT accessorys and mutators
//    Implementions of the getters and setters called by cti-server
int ctiAddService( uint32_t enterprise_number,
                   const uint8_t* service_data,
                   size_t service_data_length,
                   const uint8_t* server_data,
                   size_t server_data_length){

    otError error = OT_ERROR_NONE;
    otServiceConfig serviceCfg;

    if ( !gInstance) {
        return kCTIStatus_UnknownError;
    }

    if (service_data_length > sizeof(serviceCfg.mServiceData) ||
        server_data_length > sizeof(serviceCfg.mServerConfig.mServerData)) {
        return kCTIStatus_BadParam;
    }

    serviceCfg.mEnterpriseNumber = enterprise_number;
    memcpy(serviceCfg.mServiceData, service_data, service_data_length);
    serviceCfg.mServiceDataLength = service_data_length;
    memcpy(serviceCfg.mServerConfig.mServerData, server_data, server_data_length);
    serviceCfg.mServerConfig.mServerDataLength = server_data_length;
    serviceCfg.mServerConfig.mStable = true;

    error = otServerAddService(gInstance, &serviceCfg);

    if (error != OT_ERROR_NONE) {
        syslog(LOG_INFO, "Failed to add service: %d", error);
        return kCTIStatus_UnknownError;
    }
    error = otBorderRouterRegister(gInstance);
    if (error != OT_ERROR_NONE) {
        syslog(LOG_INFO, "Failed to push service: %d", error);
        return kCTIStatus_UnknownError;
    }

    return kCTIStatus_NoError;
}

int ctiRemoveService( uint32_t enterprise_number,
                      const uint8_t *service_data,
                      size_t service_data_length){

    if ( !gInstance){
        return kCTIStatus_UnknownError;
    }

    otError error = otServerRemoveService(gInstance,
                                          enterprise_number,
                                          service_data,
                                          service_data_length);
    if (error != OT_ERROR_NONE) {
        syslog(LOG_INFO, "Failed to remove service %d", enterprise_number);
        return kCTIStatus_UnknownError;
    }
    error = otBorderRouterRegister(gInstance);
    if (error != OT_ERROR_NONE) {
        syslog(LOG_INFO, "Failed to push service: %d", error);
        return kCTIStatus_UnknownError;
    }
    return kCTIStatus_NoError;
}

int ctiRetrieveServiceList(cti_connection_t connection, int UNUSED event)
{
    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;
    otServiceConfig config;
    if ( !gInstance){
        return kCTIStatus_UnknownError;
    }

    uint16_t numServices = 0;
    uint16_t totalSize = 0;
    // Walk through the list and calculate the number and size of services
    while (otNetDataGetNextService(gInstance, &iterator, &config) == OT_ERROR_NONE) {
        numServices++;

        // We will send the data back in this order:
        totalSize += sizeof(config.mEnterpriseNumber);   // Enterprise Num
        totalSize += sizeof(config.mServiceDataLength);  // Size of the service data
        totalSize += config.mServiceDataLength;         // The actual service data bytes
        totalSize += sizeof(config.mServerConfig.mServerDataLength);  // Size of the server data
        totalSize += config.mServerConfig.mServerDataLength;         // The actual server data bytes
    }

    totalSize += sizeof(numServices);

    // Message:
    // Num Services in List
    //    For each Service:
    //      Enterprise number
    //      Service Data Length
    //      Service Data
    //      Server Data Length
    //      Server Data
    SuccessOrFailure( cti_connection_message_create(connection, kCTIMessageType_ServiceEvent, totalSize) );

    // Indicate the number of services in the vector
    SuccessOrFailure(cti_connection_u8_put(connection, numServices));

    iterator = OT_NETWORK_DATA_ITERATOR_INIT;

    int i = 0;
    while ((otNetDataGetNextService(gInstance, &iterator, &config) == OT_ERROR_NONE) && i < numServices) {
        SuccessOrFailure(cti_connection_u32_put(connection, config.mEnterpriseNumber));
        SuccessOrFailure(cti_connection_data_put(connection, config.mServiceData, config.mServiceDataLength));
        SuccessOrFailure(cti_connection_data_put(connection,
                                                 config.mServerConfig.mServerData,
                                                 config.mServerConfig.mServerDataLength));
    }

    SuccessOrFailure( cti_connection_message_send(connection) );

    return kCTIStatus_NoError;
}

int ctiAddMeshPrefix(struct in6_addr *prefix, size_t prefix_length, bool on_mesh, bool preferred, bool slaac, bool stable)
{
    otError error = OT_ERROR_NONE;
    if ( !gInstance){
        return kCTIStatus_UnknownError;
    }
    otBorderRouterConfig borderRouterConfig;
    memset(&borderRouterConfig, 0, sizeof(borderRouterConfig));

    if ( prefix_length > 64) {
        return kCTIStatus_BadParam;
    }
    memcpy(borderRouterConfig.mPrefix.mPrefix.mFields.m8, prefix, sizeof(*prefix));

    borderRouterConfig.mPrefix.mLength = prefix_length;
    borderRouterConfig.mStable = stable;
    borderRouterConfig.mPreference = OT_ROUTE_PREFERENCE_MED; // Can also be high or low.
    borderRouterConfig.mPreferred = preferred;
    borderRouterConfig.mSlaac = slaac;
    borderRouterConfig.mOnMesh = on_mesh;
    borderRouterConfig.mStable = stable;
    borderRouterConfig.mConfigure = false;
    borderRouterConfig.mDefaultRoute = true;
    borderRouterConfig.mDhcp = false;

    error = otBorderRouterAddOnMeshPrefix(gInstance, &borderRouterConfig);
    if (error != OT_ERROR_NONE) {
        return kCTIStatus_UnknownError;
    }
    error = otBorderRouterRegister(gInstance);
    if (error != OT_ERROR_NONE) {
        syslog(LOG_INFO, "Failed to push service: %d", error);
        return kCTIStatus_UnknownError;
    }

    return kCTIStatus_NoError;
}

int ctiRemoveMeshPrefix(struct in6_addr *prefix, size_t prefix_length){

    if (!gInstance){
        return kCTIStatus_UnknownError;
    }

    otIp6Prefix ip6Prefix;
    memset(&ip6Prefix, 0, sizeof(ip6Prefix));

    if (prefix_length > 64) {
        return kCTIStatus_BadParam;
    }
    memcpy(ip6Prefix.mPrefix.mFields.m8, prefix, sizeof(*prefix));
    ip6Prefix.mLength = prefix_length;
    otError error = otBorderRouterRemoveOnMeshPrefix(gInstance, &ip6Prefix);
    if (error != OT_ERROR_NONE && error != OT_ERROR_NOT_FOUND) {
        return kCTIStatus_UnknownError;
    }
    error = otBorderRouterRegister(gInstance);
    if (error != OT_ERROR_NONE) {
        syslog(LOG_INFO, "Failed to push service: %d", error);
        return kCTIStatus_UnknownError;
    }
    return kCTIStatus_NoError;
}

int ctiRetrievePrefixList(cti_connection_t connection, int UNUSED event)
{
    if (!gInstance){
        return kCTIStatus_UnknownError;
    }
    otBorderRouterConfig config;
    otNetworkDataIterator iterator = OT_NETWORK_DATA_ITERATOR_INIT;

    uint16_t numPrefixes = 0;
    int totalSize = 0;
    do {
        int error = otNetDataGetNextOnMeshPrefix(gInstance, &iterator, &config);
        if (error != OT_ERROR_NONE) {
            if (error != OT_ERROR_NOT_FOUND) {
                syslog(LOG_ERR, "ctiRetrievePrefixList: otBorderRouterGetNextRoute: %d", error);
                return kCTIStatus_UnknownError;
            }
            break;
        }
        numPrefixes++;
        totalSize += 1;  // 1 byte stability / source flag.
        totalSize += sizeof (config.mPrefix.mLength);
        totalSize +=  config.mPrefix.mLength; // size of the prefix
    } while (1);

    // Message:
    // Num prefixes in List
    //    For each prefix:
    //      flags
    //      prefix length
    //      prefix
    SuccessOrFailure( cti_connection_message_create(connection, kCTIMessageType_PrefixEvent, totalSize) );

    // Indicate the number of services in the vector
    SuccessOrFailure(cti_connection_u16_put(connection, numPrefixes));

    iterator = OT_NETWORK_DATA_ITERATOR_INIT;

    int i = 0;
    while (i < numPrefixes)
    {
        int error = otNetDataGetNextOnMeshPrefix(gInstance, &iterator, &config);
        if (error != OT_ERROR_NONE) {
            if (error != OT_ERROR_NOT_FOUND) {
                syslog(LOG_ERR, "ctiRetrievePrefixList: otBorderRouterGetNextRoute: %d", error);
            }
            break;
        }
        // DJC Note:  Shouldn't be possible for the items in the Thread Network data to have changed
        // between above count and now, but I'm paranoid and assumptions rot over time.
        uint16_t flags = 0;
        flags |= config.mDefaultRoute ? 0 : kCTIFlag_NCP;
        flags |= config.mStable ? kCTIFlag_Stable : 0;

        SuccessOrFailure(cti_connection_u16_put(connection, flags));
        SuccessOrFailure(cti_connection_u8_put(connection, config.mPrefix.mLength));
        SuccessOrFailure(cti_connection_data_put(connection, config.mPrefix.mPrefix.mFields.m8, 8));
    }

    SuccessOrFailure( cti_connection_message_send(connection) );
    return kCTIStatus_NoError;
}

int ctiRetrievePartitionId(cti_connection_t connection, int UNUSED event)
{
    uint32_t partitionId = otThreadGetPartitionId(gInstance);
    SuccessOrFailure(cti_connection_message_create(connection, kCTIMessageType_PartitionEvent, sizeof(partitionId)));
    SuccessOrFailure(cti_connection_u32_put(connection, partitionId));
    SuccessOrFailure(cti_connection_message_send(connection));
    return kCTIStatus_NoError;
}

int ctiRetrieveTunnel(cti_connection_t connection){
    const char *interfaceName = "wpan0";
    uint32_t interfaceIndex = 0;
#if defined(OPENTHREAD_CONFIG_PLATFORM_NETIF_ENABLE) && OPENTHREAD_CONFIG_PLATFORM_NETIF_ENABLE
    otError error = otPlatGetNetif(gInstance, &interfaceName, &interfaceIndex);
    if (error != OT_ERROR_NONE) {
        return kCTIStatus_UnknownError;
    }
#endif
    (void)interfaceIndex;
    SuccessOrFailure(cti_connection_message_create(connection,
                                                   kCTIMessageType_TunnelNameResponse,
                                                   2 + strlen(interfaceName)));
    SuccessOrFailure(cti_connection_string_put(connection, interfaceName));
    SuccessOrFailure(cti_connection_message_send(connection));
    return kCTIStatus_NoError;
}

/*  This will return one of the following:
 *      OT_DEVICE_ROLE_DISABLED = 0, ///< The Thread stack is disabled.
 *      OT_DEVICE_ROLE_DETACHED = 1, ///< Not currently participating in a Thread network/partition.
 *      OT_DEVICE_ROLE_CHILD    = 2, ///< The Thread Child role.
 *      OT_DEVICE_ROLE_ROUTER   = 3, ///< The Thread Router role.
 *      OT_DEVICE_ROLE_LEADER   = 4, ///< The Thread Leader role.
 * Note:  Disabled = "OFF", Detached = "Associating", Others = "Associated"
 */
int
ctiRetrieveNodeType(cti_connection_t connection, int event)
{
    otDeviceRole role = otThreadGetDeviceRole(gInstance);
    uint8_t datum;
    int event_type;

    if (event == CTI_EVENT_ROLE) {
        event_type = kCTIMessageType_RoleEvent;
        switch(role) {
        default:
        case OT_DEVICE_ROLE_DISABLED:
        case OT_DEVICE_ROLE_DETACHED:
            datum = kCTI_NetworkNodeType_Unknown;
            break;
        case OT_DEVICE_ROLE_CHILD:
            datum = kCTI_NetworkNodeType_EndDevice;
            break;
        case OT_DEVICE_ROLE_ROUTER:
            datum = kCTI_NetworkNodeType_Router;
            break;
        case OT_DEVICE_ROLE_LEADER:
            datum = kCTI_NetworkNodeType_Leader;
            break;
        }
    } else {
        event_type = kCTIMessageType_StateEvent;
        switch(role) {
        default:
        case OT_DEVICE_ROLE_DISABLED:
            datum = kCTI_NCPState_Offline;
            break;
        case OT_DEVICE_ROLE_DETACHED:
            datum = kCTI_NCPState_Associating;
            break;
        case OT_DEVICE_ROLE_CHILD:
        case OT_DEVICE_ROLE_ROUTER:
        case OT_DEVICE_ROLE_LEADER:
            datum = kCTI_NCPState_Associated;
            break;
        }
    }
    if (cti_connection_message_create(connection, event_type, 1) &&
        cti_connection_u8_put(connection, datum) &&
        cti_connection_message_send(connection)) {
    }
    return 0;
}

void
handleThreadStateChanged(uint32_t flags, void UNUSED *context)
{
    syslog(LOG_INFO, "handleThreadStateChanged: flags = %" PRIx32, flags);

    if ( !gInstance){
        return;
    }

    syslog(LOG_INFO, "Thread state changed, flag: %d", flags );
    if ( flags & OT_CHANGED_THREAD_ROLE)
    {
        syslog(LOG_INFO, "    Thread Role changed.  Notify registered clients" );
        cti_notify_event(CTI_EVENT_ROLE, ctiRetrieveNodeType);
        cti_notify_event(CTI_EVENT_STATE, ctiRetrieveNodeType);
    }
    if ( flags & OT_CHANGED_THREAD_NETDATA)
    {
        syslog(LOG_INFO, "    Thread Netdata changed.  Notify registered clients" );
        cti_notify_event(CTI_EVENT_SERVICE, ctiRetrieveServiceList);
        cti_notify_event(CTI_EVENT_PREFIX, ctiRetrievePrefixList);

    }
    if ( flags & OT_CHANGED_THREAD_PARTITION_ID)
    {
        syslog(LOG_INFO, "    Thread Partition ID changed.  Notify registered clients" );
        cti_notify_event(CTI_EVENT_PARTITION_ID, ctiRetrievePartitionId);
    }
}

// Functions to be called by ot-daemon's main:
// Called from main after InitInstance()
void otCtiServerInit(otInstance*  aInstance){
    gInstance = aInstance;
    otError error = otSetStateChangedCallback(gInstance, handleThreadStateChanged, NULL);
    if(error != OT_ERROR_NONE && error != OT_ERROR_ALREADY) {
        syslog(LOG_INFO, "otCtiServerInit: otSetStateChangedCallback: Unable to register: %d", error);
    }

    cti_init();
}

// Called in main's idle loop after FD Prep.
void otCtiServerUpdate(otInstance* aInstance, otSysMainloopContext *aMainloop){
    int nfds = 0;
    gInstance = aInstance;
    // Note:  This will not compile as it requires a change to cti_fd_init's arg list since
    // ot-daemon's make does not allow unused arguments.
    cti_fd_init(&nfds, &aMainloop->mReadFdSet);
    if (aMainloop->mMaxFd < nfds){
        aMainloop->mMaxFd = nfds;
    }
}

// Called in main loop after a successful otSysMainloopPoll
void otCtiServerProcess(otInstance* aInstance, otSysMainloopContext *aMainloop){
    gInstance = aInstance;
    // Note: this will not compile as it is as it removes unused args in cti_fd_process
    cti_fd_process(&aMainloop->mReadFdSet);
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
