/*
 * Copyright (c) 2019-2023 Apple Inc. All rights reserved.
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

#import <Foundation/Foundation.h>
#import <arpa/inet.h>
#import <os/log_private.h>
#import <AssertMacros.h>
#import <CoreUtils/CoreUtils.h>
#import <mdns/DNSMessage.h>
#import "mdns_strict.h"

#if !COMPILER_ARC
    #error "This file must be compiled with ARC."
#endif

// MDNS Mutable Attribute String
#define MDNSAS(str) [[NSAttributedString alloc] initWithString:(str)]
#define MDNSASWithFormat(format, ...) MDNSAS(([[NSString alloc] initWithFormat:format, ##__VA_ARGS__]))

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
    label_length = ((uint8_t *)data.bytes)[0];
    require_action_quiet(data.bytes != NULL && data.length != 0, exit,
        nsa_str = MDNSASWithFormat(@"failed to decoded - malformed domain label"));

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
    for (size_t i = 0, count = length / pair_bytes_len; i < count; i++)
    {
        const uint8_t *ptr = bytes + (pair_bytes_len * i);
        const uint32_t nameHash = ReadBig32(ptr);
        ptr += 4;
        const uint16_t type = ReadBig16(ptr);
        [nsstr appendFormat:@"%s(%x %s)", sep, nameHash, DNSRecordTypeValueToString(type)];
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

NS_RETURNS_RETAINED
NSAttributedString *
OSLogCopyFormattedString(const char *type, id value, __unused os_log_type_info_t info)
{
    NSAttributedString *nsa_str = nil;
    static const struct MDNSOLFormatters formatters[] = {
        { .type = "ip_addr",                    .function = MDNSOLCopyFormattedStringmDNSIPAddr },
        { .type = "mac_addr",                   .function = MDNSOLCopyFormattedStringmDNSMACAddr },
        { .type = "domain_name",                .function = MDNSOLCopyFormattedStringmDNSLabelSequenceName },
        { .type = "domain_label",               .function = MDNSOLCopyFormattedStringmDNSLabel},
        { .type = "hex_sequence",               .function = MDNSOLCopyFormattedStringHexSequence},
        { .type = "mdns_name_hash_type_bytes",  .function = MDNSOLCopyFormattedStringMDNSNameHashTypeBytes},
    };

    for (int i = 0; i < (int)(sizeof(formatters) / sizeof(formatters[0])); i++) {
        if (strcmp(type, formatters[i].type) == 0) {
            nsa_str = formatters[i].function(value);
        }
    }

    return nsa_str;
}
