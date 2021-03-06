/*
 * Copyright (c) 2007-2021 Apple Inc. All rights reserved.
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

#ifndef H_HELPER_H
#define H_HELPER_H

#include "helper/client.h"

#include <CoreFoundation/CoreFoundation.h>
#include <os/log.h>
#include <TargetConditionals.h>

#define kHelperService "com.apple.mDNSResponder_Helper"

#define kHelperMode             "HelperMode"
#define kHelperReplyStatus      "HelperReplyStatusToClient"
#define kHelperErrCode          "HelperErrorCodefromCall"

#define kPrefsNameKey  "PreferencesNameKey"
#define kPrefsOldName  "PreferencesOldName"
#define kPrefsNewName  "PreferencesNewName"

#if TARGET_OS_OSX
    #define MDNSRESPONDER_HELPER_NOTIFIES_USER_OF_NAME_CHANGES 1
#else
    #define MDNSRESPONDER_HELPER_NOTIFIES_USER_OF_NAME_CHANGES 0
#endif

extern int mDNSHelperLogEnabled;

extern os_log_t  log_handle;

typedef enum
{
    bpf_request = 1,
    set_name = 2,
    p2p_packetfilter = 3,
    user_notify = 4,
    power_req = 5,
    send_wakepkt = 6,
    set_localaddr_cacheentry = 7,
    send_keepalive = 8,
    retreive_tcpinfo = 9,
    keychain_getsecrets = 10,
} HelperModes;

typedef enum
{
    kHelperReply_ACK = 0,
} HelperReplyStatusCodes;


typedef enum
{
    kHelperErr_NoErr = 0,
    kHelperErr_DefaultErr = -1,
    kHelperErr_NotConnected = -2,
    kHelperErr_NoResponse = -3,
    kHelperErr_UndefinedMode = -4,
    kHelperErr_ApiErr = -5,
    kHelperErr_InvalidTunnelSetKeysOperation = -6,
    kHelperErr_InvalidNetworkAddress = -7,
    kHelperErr_ResultTooLarge = -8,
    kHelperErr_RacoonConfigCreationFailed = -9,
    kHelperErr_IPsecPolicySocketCreationFailed = -10,
    kHelperErr_IPsecPolicyCreationFailed = -11,
    kHelperErr_IPsecPolicySetFailed = -12,
    kHelperErr_IPsecRemoveSAFailed = -13,
    kHelperErr_IPsecDisabled = -14,
    kHelperErr_RoutingSocketCreationFailed = -15,
    kHelperErr_RouteDeletionFailed = -16,
    kHelperErr_RouteAdditionFailed = -17,
    kHelperErr_RacoonStartFailed = -18,
    kHelperErr_RacoonNotificationFailed = -19,
    kHelperErr_ParamErr = -20,
} HelperErrorCodes;


enum mDNSPreferencesSetNameKey
{
    kmDNSComputerName = 1,
    kmDNSLocalHostName
};

enum mDNSUpDown
{
    kmDNSUp = 1,
    kmDNSDown
};

// helper parses the system keychain and returns the information to mDNSResponder.
// It returns four attributes. Attributes are defined after how they show up in
// keychain access utility (the actual attribute name to retrieve these are different).
enum mDNSKeyChainAttributes
{
    kmDNSKcWhere,   // Where
    kmDNSKcAccount, // Account
    kmDNSKcKey,     // Key
    kmDNSKcName     // Name
};

#include "mDNSEmbeddedAPI.h"
#include "helpermsg-types.h"

extern const char *mDNSHelperError(int errornum);

extern mStatus mDNSHelperInit(void);


extern void mDNSRequestBPF(dispatch_queue_t queue, mhc_bpf_open_result_handler_t handler);
extern int  mDNSPowerSleepSystem(void);
extern int  mDNSSetLocalAddressCacheEntry(mDNSu32 ifindex, int family, const v6addr_t ip, const ethaddr_t eth);
extern void mDNSNotify(const char *title, const char *msg);     // Both strings are UTF-8 text
extern void mDNSPreferencesSetName(int key, domainlabel *old, domainlabel *new);
extern int  mDNSKeychainGetSecrets(CFArrayRef *secrets);
extern void mDNSSendWakeupPacket(unsigned ifid, char *eth_addr, char *ip_addr, int iteration);
extern void mDNSSendKeepalive(const v6addr_t sadd, const v6addr_t dadd, uint16_t lport, uint16_t rport, unsigned seq, unsigned ack, uint16_t win);

extern void RequestBPF(void);
extern void PreferencesSetName(int key, const char* old, const char* new);
extern void UserNotify(const char *title, const char *msg);     // Both strings are UTF-8 text
extern int  PowerSleepSystem(void);
extern void SendWakeupPacket(unsigned int ifid, const char *eth_addr, const char *ip_addr, int iteration);
extern void SetLocalAddressCacheEntry(uint32_t ifindex, int family, const v6addr_t ip, const ethaddr_t eth, int *err);
extern void SendKeepalive(const v6addr_t sadd6, const v6addr_t dadd6, uint16_t lport, uint16_t rport, uint32_t seq, uint32_t ack, uint16_t win);
extern void KeychainGetSecrets(__unused unsigned int *numsecrets,__unused unsigned long *secrets, __unused unsigned int *secretsCnt, __unused int *err);
extern int  HelperAutoTunnelSetKeys(int replacedelete, const v6addr_t loc_inner, const v6addr_t loc_outer6, uint16_t loc_port, const v6addr_t rmt_inner,
                            const v6addr_t rmt_outer6, uint16_t rmt_port, const char *id, int *err);
extern void helper_exit(void);

#endif /* H_HELPER_H */
