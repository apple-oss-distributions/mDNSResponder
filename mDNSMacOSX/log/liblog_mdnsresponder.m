/*
 * Copyright (c) 2019-2024 Apple Inc. All rights reserved.
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

#import <AssertMacros.h>
#import <arpa/inet.h>
#import <CoreUtils/CoreUtils.h>
#import <DeviceToDeviceManager/DeviceToDeviceManager.h>
#import <Foundation/Foundation.h>
#import <mdns/DNSMessage.h>
#import <mdns/general.h>
#import "mDNSDebugShared.h"
#import <net/net_kev.h>
#import <os/log_private.h>
#import "mdns_strict.h"

#if !COMPILER_ARC
    #error "This file must be compiled with ARC."
#endif

//======================================================================================================================
// MARK: - Specifiers
//
//  Use                             Specifier                           Arguments                               Notes
//  D2D service change event        %{mdnsresponder:d2d_service_event}d event (D2DServiceEvent)
//  DNS scope type                  %{mdnsresponder:dns_scope_type}d    scope type (ScopeType)
//  Domain name                     %{mdnsresponder:domain_name}.*P     length (int), pointer (void *)
//  Domain label                    %{mdnsresponder:domain_label}.*P    length (int), pointer (void *)
//  Hexadecimal bytes               %{mdnsresponder:hex_sequence}.*P    length (int), pointer (void *)
//  IP address                      %{mdnsresponder:ip_addr}.20P        pointer (mDNSAddr *)
//  Data-Link event                 %{mdnsresponder:kev_dl_event}d      event (uint32_t)
//  MAC address                     %{mdnsresponder:mac_addr}.6P        pointer (mDNSEthAddr *)
//  Name hash and type in packet    %{mdnsresponder:mdns_name_hash_type_bytes}  length (int), pointer (void *)
//  Network change event flags      %{mdnsresponder:net_change_flags}d  flags (mDNSNetworkChangeEventFlags_t)

//======================================================================================================================
// MARK: - Data Structures

// os_log(OS_LOG_DEFAULT, "IP Address(IPv4/IPv6): %{mdnsresponder:ip_addr}.20P", <the address of mDNSAddr structure>);
typedef struct
{
    int32_t type;
    union
    {
        uint8_t v4[4];
        uint8_t v6[16];
    } ip;
} mDNSAddrCompat;

// Definition imported from mDNSEmbeddedAPI.h
typedef enum
{
    kScopeNone         = 0, // DNS server used by unscoped questions.
    kScopeInterfaceID  = 1, // Scoped DNS server used only by scoped questions.
    kScopeServiceID    = 2  // Service specific DNS server used only by questions have a matching serviceID.
} ScopeType;

//======================================================================================================================
// MARK: - Helpers

// MDNS Mutable Attribute String
#define MDNSAS(str) [[NSAttributedString alloc] initWithString:(str)]
#define MDNSASWithFormat(format, ...) MDNSAS(([[NSString alloc] initWithFormat:format, ##__VA_ARGS__]))

static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringmDNSIPAddr(id value)
{
    NSAttributedString * nsa_str;
    NSData *data;
    NSString *str;

    require_action_quiet([(NSObject *)value isKindOfClass:[NSData class]], exit,
        nsa_str = MDNSASWithFormat(@"<fail decode - data type> %@", [(NSObject *)value description]));

    data = (NSData *)value;
    if (data.bytes == NULL || data.length == 0) {
        nsa_str = MDNSAS(@"<NULL IP ADDRESS>");
        goto exit;
    }

    mDNSAddrCompat addr;
    require_quiet(data.length == sizeof(addr), exit);
    memcpy(&addr, data.bytes, sizeof(addr));

    if (addr.type == 0) {
        nsa_str = MDNSAS(@"<UNSPECIFIED IP ADDRESS>");
        goto exit;
    }

    str = NSPrintF("%#a", &addr);
    require_action_quiet(str != nil, exit, nsa_str = MDNSAS(@"<Could not create NSString>"));

    nsa_str = MDNSAS(str);
    require_action_quiet(nsa_str != nil, exit, nsa_str = MDNSAS(@"<Could not create NSAttributedString>"));

exit:
    return nsa_str;
}

//======================================================================================================================
// MARK: - Internal Functions

// os_log(OS_LOG_DEFAULT, "MAC Address: %{mdnsresponder:mac_addr}.6P", <the address of 6-byte MAC address>);
#define MAC_ADDRESS_LEN 6
static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringmDNSMACAddr(id value)
{
    NSAttributedString * nsa_str;
    NSData *data;
    NSString *str;

    require_action_quiet([(NSObject *)value isKindOfClass:[NSData class]], exit,
        nsa_str = MDNSASWithFormat(@"<fail decode - data type> %@", [(NSObject *)value description]));

    data = (NSData *)value;
    if (data.bytes == NULL || data.length == 0) {
        nsa_str = MDNSAS(@"<NULL MAC ADDRESS>");
        goto exit;
    }

    require_action_quiet(data.length == MAC_ADDRESS_LEN, exit,
        nsa_str = MDNSASWithFormat(@"<fail decode - size> %zu != %d", (size_t)data.length, MAC_ADDRESS_LEN));

    str = NSPrintF("%.6a", data.bytes);
    require_action_quiet(str != nil, exit, nsa_str = MDNSAS(@"<Could not create NSString>"));

    nsa_str = MDNSAS(str);
    require_action_quiet(nsa_str != nil, exit, nsa_str = MDNSAS(@"<Could not create NSAttributedString>"));

exit:
    return nsa_str;
}

// os_log(OS_LOG_DEFAULT, "Domain Name: %{mdnsresponder:domain_name}.*P", <the address of domainname structure>);
static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringmDNSLabelSequenceName(id value)
{
    NSAttributedString * nsa_str;
    NSData *data;
    NSString *str;

    require_action_quiet([(NSObject *)value isKindOfClass:[NSData class]], exit,
        nsa_str = MDNSASWithFormat(@"<fail decode - data type> %@", [(NSObject *)value description]));

    data = (NSData *)value;
    if (data.bytes == NULL || data.length == 0) {
        nsa_str = MDNSAS(@"<NULL DOMAIN NAME>");
        goto exit;
    }

    const uint8_t * const name  = (const uint8_t *)data.bytes;
    const uint8_t * const limit = name + data.length;
    char cstr[kDNSServiceMaxDomainName];
    const OSStatus err = DomainNameToString(name, limit, cstr, NULL);
    require_noerr_quiet(err, exit);

    str = @(cstr);
    require_quiet(str != nil, exit);

    nsa_str = MDNSAS(str);
    require_action_quiet(nsa_str != nil, exit, nsa_str = MDNSAS(@"<Could not create NSAttributedString>"));

exit:
    return nsa_str;
}

// os_log(OS_LOG_DEFAULT, "Domain Name: %{mdnsresponder:domain_label}.*P", <the length of the label>,
//     <the address of the domain label>);
static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringmDNSLabel(id value)
{
    NSAttributedString * nsa_str;
    NSData *data;
    size_t label_length;
    NSString *str;

    require_action_quiet([(NSObject *)value isKindOfClass:[NSData class]], exit,
        nsa_str = MDNSASWithFormat(@"<failed to decode - invalid data type: %@>", [(NSObject *)value description]));

    data = (NSData *)value;
    mdns_require_action_quiet(data.bytes != NULL && data.length > 0, exit, nsa_str = MDNSAS(@"<NULL DOMAIN LABEL>"));

    label_length = ((uint8_t *)data.bytes)[0];
    require_action_quiet((label_length <= kDomainLabelLengthMax) && (data.length == (1 + label_length)), exit,
        nsa_str = MDNSASWithFormat(@"failed to decode - invalid domain label length - "
            "data length: %lu, label length: %lu", (unsigned long)data.length, label_length));

    // Enough space for the domain label and a root label.
    uint8_t name[1 + kDomainLabelLengthMax + 1];
    memcpy(name, data.bytes, data.length);
    name[data.length] = 0;
    char cstr[kDNSServiceMaxDomainName];
    const OSStatus err = DomainNameToString(name, NULL, cstr, NULL);
    require_noerr_quiet(err, exit);

    const size_t len = strlen(cstr);
    if (len > 0) {
        // Remove trailing root dot.
        cstr[len - 1] = '\0';
    }
    str = @(cstr);
    require_quiet(str != nil, exit);

    nsa_str = MDNSAS(str);
    require_action_quiet(nsa_str != nil, exit, nsa_str = MDNSAS(@"<Could not create NSAttributedString>"));

exit:
    return nsa_str;
}

// os_log(OS_LOG_DEFAULT, "Hex Sequence: %{mdnsresponder:hex_sequence}.*P",
//     <the length of the hex length>, <the address of hex data>);
static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringHexSequence(id value)
{
    NSAttributedString * nsa_str;
    NSData *data;

    require_action_quiet([(NSObject *)value isKindOfClass:[NSData class]], exit,
        nsa_str = MDNSASWithFormat(@"<failed to decode - invalid data type: %@>", [(NSObject *)value description]));

    data = (NSData *)value;
    require_action_quiet(data.bytes != NULL, exit, nsa_str = MDNSASWithFormat(@"<failed to decode - NIL data >"));

    nsa_str = NSPrintTypedObject("hex", data, NULL);

exit:
    return nsa_str;
}

static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringMDNSNameHashTypeBytes(id value)
{
    NSMutableString *nsstr = [[NSMutableString alloc] initWithCapacity:0];
    require_return_value(nsstr, nil);

    NSAttributedString * nsa_str;
    NSData *data;

    require_action_quiet([(NSObject *)value isKindOfClass:[NSData class]], exit,
        nsa_str = MDNSASWithFormat(@"<failed to decode - invalid data type: %@>", [(NSObject *)value description]));

    data = (NSData *)value;
    require_action_quiet(data.bytes != NULL, exit, nsa_str = MDNSASWithFormat(@"<failed to decode - NIL data >"));

    const uint8_t * const bytes = data.bytes;
    const size_t length = data.length;

    const size_t pair_bytes_len = sizeof(uint32_t) + sizeof(uint16_t);

    const char *sep = "";
    for (size_t i = 0, count = length / pair_bytes_len; i < count; i++) {
        const uint8_t *ptr = bytes + (pair_bytes_len * i);
        const uint32_t nameHash = ReadBig32(ptr);
        ptr += 4;
        const uint16_t type = ReadBig16(ptr);
        const char * const type_str = DNSRecordTypeValueToString(type);
        if (type_str) {
            [nsstr appendFormat:@"%s(%x %s)", sep, nameHash, type_str];
        } else {
            [nsstr appendFormat:@"%s(%x TYPE%u)", sep, nameHash, type];
        }
        sep = " ";
    }
    nsa_str = MDNSAS(nsstr);

exit:
    return nsa_str;
}

struct MDNSOLFormatters {
    const char *type;
    NS_RETURNS_RETAINED NSAttributedString *(*function)(id);
};

//======================================================================================================================

static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringD2DServiceEvent(const id value)
{
    NSString *nsstr;
    const NSNumber *number;
    mdns_require_action_quiet([(NSObject *)value isKindOfClass:[NSNumber class]], exit, nsstr = nil);

    number = (const NSNumber *)value;
    switch ([number longLongValue])
    {
    #define CASE_TO_NSSTR(s) case s: nsstr = @(#s); break
        CASE_TO_NSSTR(D2DServiceFound);
        CASE_TO_NSSTR(D2DServiceLost);
        CASE_TO_NSSTR(D2DServiceResolved);
        CASE_TO_NSSTR(D2DServiceRetained);
        CASE_TO_NSSTR(D2DServiceReleased);
        CASE_TO_NSSTR(D2DServicePeerLost);
        default:
            nsstr = nil;
            break;
    #undef CASE_TO_NSSTR
    }

exit:
    return MDNSAS(nsstr);
}

//======================================================================================================================

static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringDNSScopeType(const id value)
{
    NSString *nsstr;
    const NSNumber *number;
    mdns_require_action_quiet([(NSObject *)value isKindOfClass:[NSNumber class]], exit, nsstr = nil);

    number = (const NSNumber *)value;
    switch ([number longLongValue])
    {
        case kScopeNone:
            nsstr = @"Unscoped";
            break;
        case kScopeInterfaceID:
            nsstr = @"Interface scoped";
            break;
        case kScopeServiceID:
            nsstr = @"Service scoped";
            break;
        default:
            nsstr = nil;
            break;
    }

exit:
    return MDNSAS(nsstr);
}

//======================================================================================================================

typedef struct MDNSNetworkChangeEventFlagDescription_s MDNSNetworkChangeEventFlagDescription_t;
struct MDNSNetworkChangeEventFlagDescription_s {
    const char *                    desc;
    mDNSNetworkChangeEventFlags_t   flags;
};

static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringNetworkChangeEventFlag(const id value)
{
    NSMutableString *nsstr = [[NSMutableString alloc] initWithCapacity:0];
    const NSNumber *number;
    mdns_require_quiet([(NSObject *)value isKindOfClass:[NSNumber class]], exit);

    number = (const NSNumber *)value;
    const unsigned long long opts = [number unsignedLongLongValue];

#define _item(FLG, DESC) {.flags = (FLG), .desc = (DESC)}
    const MDNSNetworkChangeEventFlagDescription_t descriptions[] = {
        _item(mDNSNetworkChangeEventFlag_LocalHostname,  "local-hostname"),
        _item(mDNSNetworkChangeEventFlag_ComputerName,   "computer-name"),
        _item(mDNSNetworkChangeEventFlag_DNS,            "dns"),
        _item(mDNSNetworkChangeEventFlag_DynamicDNS,     "dynamic-dns/set-key-chain-timer"),
        _item(mDNSNetworkChangeEventFlag_IPv4LL,         "service-configured-for-v4-linklocal"),
        _item(mDNSNetworkChangeEventFlag_P2PLike,        "P2P/IFEF_DIRECTLINK/IFEF_AWDL/car-play"),
    };
#undef _item
    const char *prefix = "";
    [nsstr appendFormat:@"0x%llX {", opts];
    for (size_t i = 0; i < countof(descriptions); i++) {
        const MDNSNetworkChangeEventFlagDescription_t * const desc = &descriptions[i];
        if (opts & desc->flags) {
            [nsstr appendFormat:@"%s%s", prefix, desc->desc];
            prefix = ", ";
        }
    }
    [nsstr appendString:@"}"];

exit:
    return MDNSAS(nsstr);
}

//======================================================================================================================

typedef struct KEVDataLinkEventDescription_s KEVDataLinkEventDescription_t;
struct KEVDataLinkEventDescription_s {
    const char *    desc;
    uint32_t        event;
};

static NS_RETURNS_RETAINED NSAttributedString *
MDNSOLCopyFormattedStringDataLinkEvent(const id value)
{
    NSString *nsstr = @"";
    const NSNumber *number;
    mdns_require_quiet([(NSObject *)value isKindOfClass:[NSNumber class]], exit);

    number = (const NSNumber *)value;
    const unsigned long long event = [number unsignedLongLongValue];
    mdns_require_quiet(event >= KEV_DL_SIFFLAGS && event <= KEV_DL_LOW_POWER_MODE_CHANGED, exit);

    const uint32_t dl_event = (uint32_t)event;
    switch (dl_event) {
    #define CASE_TO_STR(EVENT) case EVENT: nsstr = @(#EVENT); break
        CASE_TO_STR(KEV_DL_SIFFLAGS);
        CASE_TO_STR(KEV_DL_SIFMETRICS);
        CASE_TO_STR(KEV_DL_SIFMTU);
        CASE_TO_STR(KEV_DL_SIFPHYS);
        CASE_TO_STR(KEV_DL_SIFMEDIA);
        CASE_TO_STR(KEV_DL_SIFGENERIC);
        CASE_TO_STR(KEV_DL_ADDMULTI);
        CASE_TO_STR(KEV_DL_DELMULTI);
        CASE_TO_STR(KEV_DL_IF_ATTACHED);
        CASE_TO_STR(KEV_DL_IF_DETACHING);
        CASE_TO_STR(KEV_DL_IF_DETACHED);
        CASE_TO_STR(KEV_DL_LINK_OFF);
        CASE_TO_STR(KEV_DL_LINK_ON);
        CASE_TO_STR(KEV_DL_PROTO_ATTACHED);
        CASE_TO_STR(KEV_DL_PROTO_DETACHED);
        CASE_TO_STR(KEV_DL_LINK_ADDRESS_CHANGED);
        CASE_TO_STR(KEV_DL_WAKEFLAGS_CHANGED);
        CASE_TO_STR(KEV_DL_IF_IDLE_ROUTE_REFCNT);
        CASE_TO_STR(KEV_DL_IFCAP_CHANGED);
        CASE_TO_STR(KEV_DL_LINK_QUALITY_METRIC_CHANGED);
        CASE_TO_STR(KEV_DL_NODE_PRESENCE);
        CASE_TO_STR(KEV_DL_NODE_ABSENCE);
        CASE_TO_STR(KEV_DL_PRIMARY_ELECTED);
        CASE_TO_STR(KEV_DL_ISSUES);
        CASE_TO_STR(KEV_DL_IFDELEGATE_CHANGED);
        CASE_TO_STR(KEV_DL_AWDL_UNRESTRICTED);
        CASE_TO_STR(KEV_DL_RRC_STATE_CHANGED);
        CASE_TO_STR(KEV_DL_QOS_MODE_CHANGED);
        CASE_TO_STR(KEV_DL_LOW_POWER_MODE_CHANGED);
        default:
            nsstr = @"<Unknown Data-Link event>";
            break;
    #undef CASE_TO_STR
    }

exit:
    return MDNSAS(nsstr);
}

//======================================================================================================================
// MARK: - External Functions

NS_RETURNS_RETAINED
NSAttributedString *
OSLogCopyFormattedString(const char *type, id value, __unused os_log_type_info_t info)
{
    NSAttributedString *nsa_str = nil;
    static const struct MDNSOLFormatters formatters[] = {
        { .type = "d2d_service_event",          .function = MDNSOLCopyFormattedStringD2DServiceEvent },
        { .type = "dns_scope_type",             .function = MDNSOLCopyFormattedStringDNSScopeType },
        { .type = "domain_name",                .function = MDNSOLCopyFormattedStringmDNSLabelSequenceName },
        { .type = "domain_label",               .function = MDNSOLCopyFormattedStringmDNSLabel },
        { .type = "hex_sequence",               .function = MDNSOLCopyFormattedStringHexSequence },
        { .type = "ip_addr",                    .function = MDNSOLCopyFormattedStringmDNSIPAddr },
        { .type = "kev_dl_event",               .function = MDNSOLCopyFormattedStringDataLinkEvent },
        { .type = "mac_addr",                   .function = MDNSOLCopyFormattedStringmDNSMACAddr },
        { .type = "mdns_name_hash_type_bytes",  .function = MDNSOLCopyFormattedStringMDNSNameHashTypeBytes },
        { .type = "net_change_flags",           .function = MDNSOLCopyFormattedStringNetworkChangeEventFlag },
    };

    for (int i = 0; i < (int)(sizeof(formatters) / sizeof(formatters[0])); i++) {
        if (strcmp(type, formatters[i].type) == 0) {
            nsa_str = formatters[i].function(value);
        }
    }

    return nsa_str;
}
