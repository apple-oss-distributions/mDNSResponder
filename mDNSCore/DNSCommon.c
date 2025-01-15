/* -*- Mode: C; tab-width: 4; c-file-style: "bsd"; c-basic-offset: 4; fill-column: 108; indent-tabs-mode: nil; -*-
 *
 * Copyright (c) 2002-2024 Apple Inc. All rights reserved.
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

#ifndef STANDALONE
// Set mDNS_InstantiateInlines to tell mDNSEmbeddedAPI.h to instantiate inline functions, if necessary
#define mDNS_InstantiateInlines 1
#include "DNSCommon.h"
#include "DebugServices.h"

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
#include "discover_resolver.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)
#include "dns_push_discovery.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "dnssec_obj_rr_ds.h"   // For dnssec_obj_rr_ds_t.
#include "dnssec_mdns_core.h"   // For DNSSEC-related operation on mDNSCore structures.
#include "rdata_parser.h"       // For DNSSEC-related records parsing.
#include "base_encoding.h"      // For base64 encoding.
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, OS_UNFAIR_LOCK)
#include <os/lock.h> // For os_unfair_lock.
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
#include "system_utilities.h" //For is_apple_internal_build().
#endif

// Disable certain benign warnings with Microsoft compilers
#if (defined(_MSC_VER))
// Disable "conditional expression is constant" warning for debug macros.
// Otherwise, this generates warnings for the perfectly natural construct "while(1)"
// If someone knows a variant way of writing "while(1)" that doesn't generate warning messages, please let us know
    #pragma warning(disable:4127)
// Disable "array is too small to include a terminating null character" warning
// -- domain labels have an initial length byte, not a terminating null character
    #pragma warning(disable:4295)
#endif

// ***************************************************************************
// MARK: - Program Constants

#include "mdns_strict.h"

mDNSexport const mDNSInterfaceID mDNSInterface_Any       = 0;
mDNSexport const mDNSInterfaceID mDNSInterfaceMark       = (mDNSInterfaceID)-1;
mDNSexport const mDNSInterfaceID mDNSInterface_LocalOnly = (mDNSInterfaceID)-2;
mDNSexport const mDNSInterfaceID mDNSInterface_P2P       = (mDNSInterfaceID)-3;
mDNSexport const mDNSInterfaceID uDNSInterfaceMark       = (mDNSInterfaceID)-4;
mDNSexport const mDNSInterfaceID mDNSInterface_BLE       = (mDNSInterfaceID)-5;

// Note: Microsoft's proposed "Link Local Multicast Name Resolution Protocol" (LLMNR) is essentially a limited version of
// Multicast DNS, using the same packet formats, naming syntax, and record types as Multicast DNS, but on a different UDP
// port and multicast address, which means it won't interoperate with the existing installed base of Multicast DNS responders.
// LLMNR uses IPv4 multicast address 224.0.0.252, IPv6 multicast address FF02::0001:0003, and UDP port 5355.
// Uncomment the appropriate lines below to build a special Multicast DNS responder for testing interoperability
// with Microsoft's LLMNR client code.

#define   DiscardPortAsNumber               9
#define   SSHPortAsNumber                  22
#define   UnicastDNSPortAsNumber           53
#define   SSDPPortAsNumber               1900
#define   IPSECPortAsNumber              4500
#define   NSIPCPortAsNumber              5030       // Port used for dnsextd to talk to local nameserver bound to loopback
#define   NATPMPAnnouncementPortAsNumber 5350
#define   NATPMPPortAsNumber             5351
#define   DNSEXTPortAsNumber             5352       // Port used for end-to-end DNS operations like LLQ, Updates with Leases, etc.
#define   MulticastDNSPortAsNumber       5353
#define   LoopbackIPCPortAsNumber        5354
//#define MulticastDNSPortAsNumber       5355		// LLMNR
#define   PrivateDNSPortAsNumber         5533

mDNSexport const mDNSIPPort DiscardPort            = { { DiscardPortAsNumber            >> 8, DiscardPortAsNumber            & 0xFF } };
mDNSexport const mDNSIPPort SSHPort                = { { SSHPortAsNumber                >> 8, SSHPortAsNumber                & 0xFF } };
mDNSexport const mDNSIPPort UnicastDNSPort         = { { UnicastDNSPortAsNumber         >> 8, UnicastDNSPortAsNumber         & 0xFF } };
mDNSexport const mDNSIPPort SSDPPort               = { { SSDPPortAsNumber               >> 8, SSDPPortAsNumber               & 0xFF } };
mDNSexport const mDNSIPPort IPSECPort              = { { IPSECPortAsNumber              >> 8, IPSECPortAsNumber              & 0xFF } };
mDNSexport const mDNSIPPort NSIPCPort              = { { NSIPCPortAsNumber              >> 8, NSIPCPortAsNumber              & 0xFF } };
mDNSexport const mDNSIPPort NATPMPAnnouncementPort = { { NATPMPAnnouncementPortAsNumber >> 8, NATPMPAnnouncementPortAsNumber & 0xFF } };
mDNSexport const mDNSIPPort NATPMPPort             = { { NATPMPPortAsNumber             >> 8, NATPMPPortAsNumber             & 0xFF } };
mDNSexport const mDNSIPPort DNSEXTPort             = { { DNSEXTPortAsNumber             >> 8, DNSEXTPortAsNumber             & 0xFF } };
mDNSexport const mDNSIPPort MulticastDNSPort       = { { MulticastDNSPortAsNumber       >> 8, MulticastDNSPortAsNumber       & 0xFF } };
mDNSexport const mDNSIPPort LoopbackIPCPort        = { { LoopbackIPCPortAsNumber        >> 8, LoopbackIPCPortAsNumber        & 0xFF } };
mDNSexport const mDNSIPPort PrivateDNSPort         = { { PrivateDNSPortAsNumber         >> 8, PrivateDNSPortAsNumber         & 0xFF } };

mDNSexport const OwnerOptData zeroOwner         = { 0, 0, { { 0 } }, { { 0 } }, { { 0 } } };

mDNSexport const mDNSIPPort zeroIPPort        = { { 0 } };
mDNSexport const mDNSv4Addr zerov4Addr        = { { 0 } };
mDNSexport const mDNSv6Addr zerov6Addr        = { { 0 } };
mDNSexport const mDNSEthAddr zeroEthAddr       = { { 0 } };
mDNSexport const mDNSv4Addr onesIPv4Addr      = { { 255, 255, 255, 255 } };
mDNSexport const mDNSv6Addr onesIPv6Addr      = { { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255 } };
mDNSexport const mDNSEthAddr onesEthAddr       = { { 255, 255, 255, 255, 255, 255 } };
mDNSexport const mDNSAddr zeroAddr          = { mDNSAddrType_None, {{{ 0 }}} };

mDNSexport const mDNSv4Addr AllDNSAdminGroup   = { { 239, 255, 255, 251 } };
mDNSexport const mDNSv4Addr AllHosts_v4        = { { 224,   0,   0,   1 } };  // For NAT-PMP & PCP Annoucements
mDNSexport const mDNSv6Addr AllHosts_v6        = { { 0xFF,0x02,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01 } };
mDNSexport const mDNSv6Addr NDP_prefix         = { { 0xFF,0x02,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01, 0xFF,0x00,0x00,0xFB } };  // FF02:0:0:0:0:1:FF00::/104
mDNSexport const mDNSEthAddr AllHosts_v6_Eth    = { { 0x33, 0x33, 0x00, 0x00, 0x00, 0x01 } };
mDNSexport const mDNSAddr AllDNSLinkGroup_v4 = { mDNSAddrType_IPv4, { { { 224,   0,   0, 251 } } } };
//mDNSexport const mDNSAddr  AllDNSLinkGroup_v4 = { mDNSAddrType_IPv4, { { { 224,   0,   0, 252 } } } }; // LLMNR
mDNSexport const mDNSAddr AllDNSLinkGroup_v6 = { mDNSAddrType_IPv6, { { { 0xFF,0x02,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0xFB } } } };
//mDNSexport const mDNSAddr  AllDNSLinkGroup_v6 = { mDNSAddrType_IPv6, { { { 0xFF,0x02,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00, 0x00,0x01,0x00,0x03 } } } }; // LLMNR

mDNSexport const mDNSOpaque16 zeroID          = { { 0, 0 } };
mDNSexport const mDNSOpaque16 onesID          = { { 255, 255 } };
mDNSexport const mDNSOpaque16 QueryFlags      = { { kDNSFlag0_QR_Query    | kDNSFlag0_OP_StdQuery,                0 } };
mDNSexport const mDNSOpaque16 uQueryFlags     = { { kDNSFlag0_QR_Query    | kDNSFlag0_OP_StdQuery | kDNSFlag0_RD, 0 } };
mDNSexport const mDNSOpaque16 ResponseFlags   = { { kDNSFlag0_QR_Response | kDNSFlag0_OP_StdQuery | kDNSFlag0_AA, 0 } };
mDNSexport const mDNSOpaque16 UpdateReqFlags  = { { kDNSFlag0_QR_Query    | kDNSFlag0_OP_Update,                  0 } };
mDNSexport const mDNSOpaque16 UpdateRespFlags = { { kDNSFlag0_QR_Response | kDNSFlag0_OP_Update,                  0 } };

mDNSexport const mDNSOpaque64  zeroOpaque64     = { { 0 } };
mDNSexport const mDNSOpaque128 zeroOpaque128    = { { 0 } };

extern mDNS mDNSStorage;

// ***************************************************************************
// MARK: - General Utility Functions

mDNSexport void CacheRecordSetResponseFlags(CacheRecord *const cr, const mDNSOpaque16 responseFlags)
{
    cr->responseFlags = responseFlags;
    cr->resrec.rcode  = cr->responseFlags.b[1] & kDNSFlag1_RC_Mask;
}

mDNSexport void mDNSCoreResetRecord(mDNS *const m)
{
    m->rec.r.resrec.RecordType = 0; // Clear RecordType to show we're not still using it
    CacheRecordSetResponseFlags(&m->rec.r, zeroID);
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    MDNS_DISPOSE_DNSSEC_OBJ(m->rec.r.resrec.dnssec);
#endif
}

// return true for RFC1918 private addresses
mDNSexport mDNSBool mDNSv4AddrIsRFC1918(const mDNSv4Addr * const addr)
{
    return ((addr->b[0] == 10) ||                                 // 10/8 prefix
            (addr->b[0] == 172 && (addr->b[1] & 0xF0) == 16) ||   // 172.16/12
            (addr->b[0] == 192 && addr->b[1] == 168));            // 192.168/16
}

mDNSexport const char *DNSScopeToString(mDNSu32 scope)
{
    switch (scope)
    {
        case kScopeNone:
            return "Unscoped";
        case kScopeInterfaceID:
            return "InterfaceScoped";
        case kScopeServiceID:
            return "ServiceScoped";
        default:
            return "Unknown";
    }
}

mDNSexport void mDNSAddrMapIPv4toIPv6(mDNSv4Addr* in, mDNSv6Addr* out)
{
    out->l[0] = 0;
    out->l[1] = 0;
    out->w[4] = 0;
    out->w[5] = 0xffff;
    out->b[12] = in->b[0];
    out->b[13] = in->b[1];
    out->b[14] = in->b[2];
    out->b[15] = in->b[3];
}

mDNSexport mDNSBool mDNSAddrIPv4FromMappedIPv6(mDNSv6Addr *in, mDNSv4Addr* out)
{
    if (in->l[0] != 0 || in->l[1] != 0 || in->w[4] != 0 || in->w[5] != 0xffff)
        return mDNSfalse;

    out->NotAnInteger = in->l[3];
    return mDNStrue;
}

NetworkInterfaceInfo *FirstInterfaceForID(mDNS *const m, const mDNSInterfaceID InterfaceID)
{
    NetworkInterfaceInfo *intf = m->HostInterfaces;
    while (intf && intf->InterfaceID != InterfaceID) intf = intf->next;
    return(intf);
}

NetworkInterfaceInfo *FirstIPv4LLInterfaceForID(mDNS *const m, const mDNSInterfaceID InterfaceID)
{
    NetworkInterfaceInfo *intf;

    if (!InterfaceID)
        return mDNSNULL;

    // Note: We don't check for InterfaceActive, as the active interface could be IPv6 and
    // we still want to find the first IPv4 Link-Local interface
    for (intf = m->HostInterfaces; intf; intf = intf->next)
    {
        if (intf->InterfaceID == InterfaceID &&
            intf->ip.type == mDNSAddrType_IPv4 && mDNSv4AddressIsLinkLocal(&intf->ip.ip.v4))
        {
            debugf("FirstIPv4LLInterfaceForID: found LL interface with address %.4a", &intf->ip.ip.v4);
            return intf;
        }
    }
    return (mDNSNULL);
}

mDNSexport char *InterfaceNameForID(mDNS *const m, const mDNSInterfaceID InterfaceID)
{
    NetworkInterfaceInfo *intf = FirstInterfaceForID(m, InterfaceID);
    return(intf ? intf->ifname : mDNSNULL);
}

mDNSexport const char *InterfaceNameForIDOrEmptyString(const mDNSInterfaceID InterfaceID)
{
    const char *const ifName = InterfaceNameForID(&mDNSStorage, InterfaceID);
    return (ifName ? ifName : "");
}

mDNSexport NetworkInterfaceInfo *GetFirstActiveInterface(NetworkInterfaceInfo *intf)
{
    while (intf && !intf->InterfaceActive) intf = intf->next;
    return(intf);
}

mDNSexport mDNSInterfaceID GetNextActiveInterfaceID(const NetworkInterfaceInfo *intf)
{
    const NetworkInterfaceInfo *next = GetFirstActiveInterface(intf->next);
    if (next) return(next->InterfaceID);else return(mDNSNULL);
}

mDNSexport mDNSu32 NumCacheRecordsForInterfaceID(const mDNS *const m, mDNSInterfaceID id)
{
    mDNSu32 slot, used = 0;
    CacheGroup *cg;
    const CacheRecord *rr;
    FORALL_CACHERECORDS(slot, cg, rr)
    {
        if (rr->resrec.InterfaceID == id)
            used++;
    }
    return(used);
}

mDNSexport char *DNSTypeName(mDNSu16 rrtype)
{
    switch (rrtype)
    {
    case kDNSType_A:    return("Addr");
    case kDNSType_NS:   return("NS");
    case kDNSType_CNAME: return("CNAME");
    case kDNSType_SOA:  return("SOA");
    case kDNSType_NULL: return("NULL");
    case kDNSType_PTR:  return("PTR");
    case kDNSType_HINFO: return("HINFO");
    case kDNSType_TXT:  return("TXT");
    case kDNSType_AAAA: return("AAAA");
    case kDNSType_SRV:  return("SRV");
    case kDNSType_OPT:  return("OPT");
    case kDNSType_NSEC: return("NSEC");
    case kDNSType_NSEC3: return("NSEC3");
    case kDNSType_NSEC3PARAM: return("NSEC3PARAM");
    case kDNSType_TSIG: return("TSIG");
    case kDNSType_RRSIG: return("RRSIG");
    case kDNSType_DNSKEY: return("DNSKEY");
    case kDNSType_DS: return("DS");
    case kDNSType_SVCB: return("SVCB");
    case kDNSType_HTTPS: return("HTTPS");
    case kDNSType_TSR: return("TSR");
    case kDNSQType_ANY: return("ANY");
    default:            {
        static char buffer[16];
        mDNS_snprintf(buffer, sizeof(buffer), "TYPE%d", rrtype);
        return(buffer);
    }
    }
}

mDNSexport const char *mStatusDescription(mStatus error)
{
    const char *error_description;
    switch (error) {
        case mStatus_NoError:
            error_description = "mStatus_NoError";
            break;
        case mStatus_BadParamErr:
            error_description = "mStatus_BadParamErr";
            break;

        default:
            error_description = "mStatus_UnknownDescription";
            break;
    }

    return error_description;
}

mDNSexport mDNSu32 swap32(mDNSu32 x)
{
    mDNSu8 *ptr = (mDNSu8 *)&x;
    return (mDNSu32)((mDNSu32)ptr[0] << 24 | (mDNSu32)ptr[1] << 16 | (mDNSu32)ptr[2] << 8 | ptr[3]);
}

mDNSexport mDNSu16 swap16(mDNSu16 x)
{
    mDNSu8 *ptr = (mDNSu8 *)&x;
    return (mDNSu16)((mDNSu16)ptr[0] << 8 | ptr[1]);
}

mDNSlocal void PrintTypeBitmap(const mDNSu8 *bmap, int bitmaplen, char *const buffer, mDNSu32 length)
{
    int win, wlen, type;

    while (bitmaplen > 0)
    {
        int i;

        if (bitmaplen < 3)
        {
            LogMsg("PrintTypeBitmap: malformed bitmap, bitmaplen %d short", bitmaplen);
            break;
        }

        win = *bmap++;
        wlen = *bmap++;
        bitmaplen -= 2;
        if (bitmaplen < wlen || wlen < 1 || wlen > 32)
        {
            LogInfo("PrintTypeBitmap: malformed nsec, bitmaplen %d wlen %d", bitmaplen, wlen);
            break;
        }
        if (win < 0 || win >= 256)
        {
            LogInfo("PrintTypeBitmap: malformed nsec, bad window win %d", win);
            break;
        }
        type = win * 256;
        for (i = 0; i < wlen * 8; i++)
        {
            if (bmap[i>>3] & (128 >> (i&7)))
                length += mDNS_snprintf(buffer+length, (MaxMsg - 1) - length, "%s ", DNSTypeName(type + i));
        }
        bmap += wlen;
        bitmaplen -= wlen;
    }
}

#define TXT_RECORD_SEPARATOR '|'

mDNSlocal mDNSu8 mDNSLengthOfFirstUTF8Character(const mDNSu8 *bytes, mDNSu32 len);

mDNSlocal const mDNSu8 *mDNSLocateFirstByteToEscape(const mDNSu8 *const bytes, const mDNSu32 bytesLen)
{
    for (const mDNSu8 *ptr = bytes, *const end = bytes + bytesLen; ptr < end;)
    {
        const mDNSu8 utf8CharacterLen = mDNSLengthOfFirstUTF8Character(ptr, (mDNSu32)(end - ptr));
        if (utf8CharacterLen == 0)
        {
            return ptr;
        }
        else if (utf8CharacterLen == 1)
        {
            const char ch = *ptr;
            if ((ch == '\\') || (ch == TXT_RECORD_SEPARATOR) || !mDNSIsPrintASCII(ch))
            {
                return ptr;
            }
        }
        ptr += utf8CharacterLen;
    }
    return mDNSNULL;
}

mDNSlocal mDNSu32 putTXTRRCharacterString(char *const buffer, const mDNSu32 bufferLen, const mDNSu8 *const bytes,
    const mDNSu32 bytesLen, const mDNSBool addSeparator, mDNSBool *const outTruncated)
{
    mDNSBool truncated = mDNSfalse;
    mDNSu32 nWrites = 0;

    if (addSeparator)
    {
        require_action_quiet(bufferLen > 1, exit, truncated = mDNStrue);
        nWrites = mDNS_snprintf(buffer, bufferLen, "%c", TXT_RECORD_SEPARATOR);
    }

    for (const mDNSu8 *ptr = bytes, *const end = bytes + bytesLen; ptr < end;)
    {
        const mDNSu32 remainingLen = (mDNSu32)(end - ptr);
        const mDNSu8 *const firstByteToEscape = mDNSLocateFirstByteToEscape(ptr, remainingLen);

        // [ptr ... firstByteToEscape ... end]
        // The bytes between [ptr, firstByteToEscape) are directly-printable.
        const mDNSu32 normalBytesLenToPrint = (firstByteToEscape ? ((mDNSu32)(firstByteToEscape - ptr)) : remainingLen);
        // Print UTF-8 characters in [ptr, firstByteToEscape).
        if (normalBytesLenToPrint > 0)
        {
            const mDNSu32 currentNWrites = mDNS_snprintf(buffer + nWrites, bufferLen - nWrites, "%.*s",
                normalBytesLenToPrint, ptr);
            nWrites += currentNWrites;
            require_action_quiet(currentNWrites == normalBytesLenToPrint, exit, truncated = mDNStrue);
        }

        if (firstByteToEscape)
        {
            // Print the *firstByteToEscape if it exists.
            const mDNSu8 byteToEscape = *firstByteToEscape;

            if ((byteToEscape == '\\') || (byteToEscape == TXT_RECORD_SEPARATOR))
            {
                // One escape character `\\`, one character being escaped, one `\0`.
                require_action_quiet((bufferLen - nWrites) >= 3, exit, truncated = mDNStrue);
                nWrites += mDNS_snprintf(buffer + nWrites, bufferLen - nWrites, "\\%c", byteToEscape);
            }
            else
            {
                // Two-byte hex prefix `\\x`, Two-byte hex value "HH" , one '\0'.
                require_action_quiet((bufferLen - nWrites) >= 5, exit, truncated = mDNStrue);
                nWrites += mDNS_snprintf(buffer + nWrites, bufferLen - nWrites, "\\x%02X", byteToEscape);
            }
            ptr = firstByteToEscape + 1;
        }
        else
        {
            // firstByteToEscape is NULL means that the remaining characters are printable.
            ptr += remainingLen;
        }
    }

exit:
    if (outTruncated)
    {
        *outTruncated = truncated;
    }
    return nWrites;
}

mDNSlocal char *GetTXTRRDisplayString(const mDNSu8 *const rdata, const mDNSu32 rdLen, char *const buffer,
    const mDNSu32 bufferLen)
{
    mDNSu32 currentLen = 0;
#define RESERVED_BUFFER_LENGTH 5 // " <C>", " <T>" or " <M>" plus '\0'
    require_quiet(bufferLen >= RESERVED_BUFFER_LENGTH, exit);

    mDNSu32 adjustedBufferLen = bufferLen - RESERVED_BUFFER_LENGTH;

    mDNSu32 characterStringLen;
    mDNSBool malformed = mDNSfalse;
    mDNSBool truncated = mDNSfalse;
    mDNSBool addSeparator = mDNSfalse;
    for (const mDNSu8 *src = rdata, *const end = rdata + rdLen; src < end && !truncated; src += characterStringLen)
    {
        characterStringLen = *src++;

        if (((mDNSu32)(end - src)) < characterStringLen)
        {
            malformed = mDNStrue;
            break;
        }

        currentLen += putTXTRRCharacterString((buffer + currentLen), (adjustedBufferLen - currentLen), src,
            characterStringLen, addSeparator, &truncated);
        addSeparator = mDNStrue;
    }

    const char statusCode = (malformed ? 'M' : (truncated ? 'T' : 'C'));
    currentLen += mDNS_snprintf((buffer + currentLen), (bufferLen - currentLen), " <%c>", statusCode);

exit:
    return buffer + currentLen;
}

// Note slight bug: this code uses the rdlength from the ResourceRecord object, to display
// the rdata from the RDataBody object. Sometimes this could be the wrong length -- but as
// long as this routine is only used for debugging messages, it probably isn't a big problem.
mDNSexport char *GetRRDisplayString_rdb(const ResourceRecord *const rr, const RDataBody *const rd1, char *const buffer)
{
    const RDataBody2 *const rd = (const RDataBody2 *)rd1;
    #define RemSpc (MaxMsg-1-length)
    char *ptr = buffer;
    mDNSu32 length = mDNS_snprintf(buffer, MaxMsg-1, "%4d %##s %s ", rr->rdlength, rr->name->c, DNSTypeName(rr->rrtype));
    if (rr->RecordType == kDNSRecordTypePacketNegative) return(buffer);
    if (!rr->rdlength && rr->rrtype != kDNSType_OPT) { mDNS_snprintf(buffer+length, RemSpc, "<< ZERO RDATA LENGTH >>"); return(buffer); }

    switch (rr->rrtype)
    {
    case kDNSType_A:    mDNS_snprintf(buffer+length, RemSpc, "%.4a", &rd->ipv4);          break;

    case kDNSType_NS:       // Same as PTR
    case kDNSType_CNAME:    // Same as PTR
    case kDNSType_PTR:  mDNS_snprintf(buffer+length, RemSpc, "%##s", rd->name.c);       break;

    case kDNSType_SOA:  mDNS_snprintf(buffer+length, RemSpc, "%##s %##s %d %d %d %d %d",
                                      rd->soa.mname.c, rd->soa.rname.c,
                                      rd->soa.serial, rd->soa.refresh, rd->soa.retry, rd->soa.expire, rd->soa.min);
        break;

    case kDNSType_HINFO:    // Display this the same as TXT (show all constituent strings)
    case kDNSType_TXT:
        GetTXTRRDisplayString(rd->txt.c, rr->rdlength, buffer + length, RemSpc);
        break;

    case kDNSType_AAAA: mDNS_snprintf(buffer+length, RemSpc, "%.16a", &rd->ipv6);       break;
    case kDNSType_SRV:  mDNS_snprintf(buffer+length, RemSpc, "%u %u %u %##s",
                                      rd->srv.priority, rd->srv.weight, mDNSVal16(rd->srv.port), rd->srv.target.c); break;
    case kDNSType_TSR:  mDNS_snprintf(buffer+length, RemSpc, "%d", rd1->tsr_value);       break;

    case kDNSType_OPT:  {
        const rdataOPT *opt;
        const rdataOPT *const end = (const rdataOPT *)&rd->data[rr->rdlength];
        length += mDNS_snprintf(buffer+length, RemSpc, "Max %d", rr->rrclass);
        for (opt = &rd->opt[0]; opt < end; opt++)
        {
            switch(opt->opt)
            {
            case kDNSOpt_LLQ:
                length += mDNS_snprintf(buffer+length, RemSpc, " LLQ");
                length += mDNS_snprintf(buffer+length, RemSpc, " Vers %d",     opt->u.llq.vers);
                length += mDNS_snprintf(buffer+length, RemSpc, " Op %d",       opt->u.llq.llqOp);
                length += mDNS_snprintf(buffer+length, RemSpc, " Err/Port %d", opt->u.llq.err);
                length += mDNS_snprintf(buffer+length, RemSpc, " ID %08X%08X", opt->u.llq.id.l[0], opt->u.llq.id.l[1]);
                length += mDNS_snprintf(buffer+length, RemSpc, " Lease %d",    opt->u.llq.llqlease);
                break;
            case kDNSOpt_Lease:
                length += mDNS_snprintf(buffer+length, RemSpc, " Lease %d",    opt->u.updatelease);
                break;
            case kDNSOpt_Owner:
                length += mDNS_snprintf(buffer+length, RemSpc, " Owner");
                length += mDNS_snprintf(buffer+length, RemSpc, " Vers %d",     opt->u.owner.vers);
                length += mDNS_snprintf(buffer+length, RemSpc, " Seq %3d", (mDNSu8)opt->u.owner.seq);                           // Display as unsigned
                length += mDNS_snprintf(buffer+length, RemSpc, " MAC %.6a",    opt->u.owner.HMAC.b);
                if (opt->optlen >= DNSOpt_OwnerData_ID_Wake_Space-4)
                {
                    length += mDNS_snprintf(buffer+length, RemSpc, " I-MAC %.6a", opt->u.owner.IMAC.b);
                    if (opt->optlen > DNSOpt_OwnerData_ID_Wake_Space-4)
                        length += mDNS_snprintf(buffer+length, RemSpc, " Password %.6a", opt->u.owner.password.b);
                }
                break;
            case kDNSOpt_Trace:
                length += mDNS_snprintf(buffer+length, RemSpc, " Trace");
                length += mDNS_snprintf(buffer+length, RemSpc, " Platform %d",    opt->u.tracer.platf);
                length += mDNS_snprintf(buffer+length, RemSpc, " mDNSVers %d",    opt->u.tracer.mDNSv);
                break;
            case kDNSOpt_TSR:
                length += mDNS_snprintf(buffer+length, RemSpc, " TSR");
                length += mDNS_snprintf(buffer+length, RemSpc, " Tm %d", opt->u.tsr.timeStamp);
                length += mDNS_snprintf(buffer+length, RemSpc, " Hk %x", opt->u.tsr.hostkeyHash);
                length += mDNS_snprintf(buffer+length, RemSpc, " Ix %u", opt->u.tsr.recIndex);
                break;
            default:
                length += mDNS_snprintf(buffer+length, RemSpc, " Unknown %d",  opt->opt);
                break;
            }
        }
    }
    break;

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    case kDNSType_DS: {
        // See <https://datatracker.ietf.org/doc/html/rfc4034#section-5.3> for DS RR Presentation Format.

        dnssec_error_t err;
        dnssec_obj_rr_ds_t ds = mDNSNULL;
        char *ds_rdata_description = mDNSNULL;

        ds = dnssec_obj_rr_ds_create(rr->name->c, rr->rrclass, rr->rdata->u.data, rr->rdlength, false, &err);
        if (err != DNSSEC_ERROR_NO_ERROR)
        {
            goto ds_exit;
        }

        ds_rdata_description = dnssec_obj_rr_copy_rdata_rfc_description(ds, &err);
        if (err != DNSSEC_ERROR_NO_ERROR)
        {
            goto ds_exit;
        }

        mDNS_snprintf(buffer + length, RemSpc, "%s", ds_rdata_description);

    ds_exit:
        MDNS_DISPOSE_DNSSEC_OBJ(ds);
        mDNSPlatformMemFree(ds_rdata_description);
    }
    break;

    case kDNSType_RRSIG: {
        // See <https://datatracker.ietf.org/doc/html/rfc4034#section-3.2> for RRSIG RR Presentation Format.

        dnssec_error_t err;
        dnssec_obj_rr_rrsig_t rrsig = NULL;
        char *rrsig_rdata_description = mDNSNULL;

        rrsig = dnssec_obj_rr_rrsig_create(rr->name->c, rr->rdata->u.data, rr->rdlength, false, &err);
        if (err != DNSSEC_ERROR_NO_ERROR) {
            goto rrsig_exit;
        }

        rrsig_rdata_description = dnssec_obj_rr_copy_rdata_rfc_description(rrsig, &err);
        if (err != DNSSEC_ERROR_NO_ERROR)
        {
            goto rrsig_exit;
        }

        mDNS_snprintf(buffer + length, RemSpc, "%s", rrsig_rdata_description);

    rrsig_exit:
        MDNS_DISPOSE_DNSSEC_OBJ(rrsig);
		mDNSPlatformMemFree(rrsig_rdata_description);
    }
    break;
#endif

    case kDNSType_NSEC: {
        const domainname *next = (const domainname *)rd->data;
        int len, bitmaplen;
        const mDNSu8 *bmap;
        len = DomainNameLength(next);
        bitmaplen = rr->rdlength - len;
        bmap = (const mDNSu8 *)((const mDNSu8 *)next + len);

        if (UNICAST_NSEC(rr))
            length += mDNS_snprintf(buffer+length, RemSpc, "%##s ", next->c);
        PrintTypeBitmap(bmap, bitmaplen, buffer, length);

    }
    break;

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    case kDNSType_DNSKEY: {
        // See <https://datatracker.ietf.org/doc/html/rfc4034#section-2.2> for DNSKEY RR Presentation Format.

        dnssec_error_t err;
        dnssec_obj_rr_dnskey_t dnskey = mDNSNULL;
        char *dnskey_rdata_description = mDNSNULL;

        dnskey = dnssec_obj_rr_dnskey_create(rr->name->c, rr->rrclass, rr->rdata->u.data, rr->rdlength, false, &err);
        if (err != DNSSEC_ERROR_NO_ERROR) {
            goto dnskey_exit;
        }

        dnskey_rdata_description = dnssec_obj_rr_copy_rdata_rfc_description(dnskey, &err);
        if (err != DNSSEC_ERROR_NO_ERROR) {
            goto dnskey_exit;
        }

        mDNS_snprintf(buffer + length, RemSpc, "%s", dnskey_rdata_description);

    dnskey_exit:
        MDNS_DISPOSE_DNSSEC_OBJ(dnskey);
        mDNSPlatformMemFree(dnskey_rdata_description);
    }
    break;
#endif

    default:            mDNS_snprintf(buffer+length, RemSpc, "RDLen %d: %.*s", rr->rdlength, rr->rdlength, rd->data);
        // Really should scan buffer to check if text is valid UTF-8 and only replace with dots if not
        for (ptr = buffer; *ptr; ptr++) if (*ptr < ' ') *ptr = '.';
        break;
    }

    return(buffer);
}

#if MDNSRESPONDER_SUPPORTS(APPLE, OS_LOG)

mDNSexport const mDNSu8 *GetPrintableRDataBytes(mDNSu8 *const outBuffer, const mDNSu32 bufferLen,
	const mDNSu16 recordType, const mDNSu8 * const rdata, const mDNSu32 rdataLen)
{
	const mDNSu32 totalLen = rdataLen + 2;
	mdns_require_return_value(bufferLen >= totalLen, mDNSNULL);

	outBuffer[0] = (mDNSu8)((recordType >> 8) & 0xFF);
	outBuffer[1] = (mDNSu8)((recordType     ) & 0xFF);
	mDNSPlatformMemCopy(&outBuffer[2], rdata, (mDNSu32)rdataLen);

	return outBuffer;
}

#endif

// See comments in mDNSEmbeddedAPI.h
#if _PLATFORM_HAS_STRONG_PRNG_
#define mDNSRandomNumber mDNSPlatformRandomNumber
#else
mDNSlocal mDNSu32 mDNSRandomFromSeed(mDNSu32 seed)
{
    return seed * 21 + 1;
}

mDNSlocal mDNSu32 mDNSMixRandomSeed(mDNSu32 seed, mDNSu8 iteration)
{
    return iteration ? mDNSMixRandomSeed(mDNSRandomFromSeed(seed), --iteration) : seed;
}

mDNSlocal mDNSu32 mDNSRandomNumber()
{
    static mDNSBool seeded = mDNSfalse;
    static mDNSu32 seed = 0;
    if (!seeded)
    {
        seed = mDNSMixRandomSeed(mDNSPlatformRandomSeed(), 100);
        seeded = mDNStrue;
    }
    return (seed = mDNSRandomFromSeed(seed));
}
#endif // ! _PLATFORM_HAS_STRONG_PRNG_

mDNSexport mDNSu32 mDNSRandom(mDNSu32 max)      // Returns pseudo-random result from zero to max inclusive
{
    mDNSu32 ret = 0;
    mDNSu32 mask = 1;

    while (mask < max) mask = (mask << 1) | 1;

    do ret = mDNSRandomNumber() & mask;
    while (ret > max);

    return ret;
}

// See <https://datatracker.ietf.org/doc/html/draft-eastlake-fnv-19#section-5>
#define MDNSRESPONDER_FNV_32_BIT_OFFSET_BASIS   ((mDNSu32)0x811C9DC5)
#define MDNSRESPONDER_FNV_32_BIT_PRIME          ((mDNSu32)0x01000193)

mDNSexport mDNSu32 mDNS_NonCryptoHashUpdateBytes(const mDNSNonCryptoHash algorithm, const mDNSu32 previousHash,
    const mDNSu8 *const bytes, const mDNSu32 len)
{
    mDNSu32 hash = previousHash;

    switch (algorithm) {
        case mDNSNonCryptoHash_FNV1a:
        {
            for (mDNSu32 i = 0; i < len; i++)
            {
                hash ^= bytes[i];
                hash *= MDNSRESPONDER_FNV_32_BIT_PRIME;
            }
        }
            break;
        case mDNSNonCryptoHash_SDBM: // See <http://www.cse.yorku.ca/~oz/hash.html>
        {
            for (mDNSu32 i = 0; i < len; i++)
            {
                // hash(i) = hash(i - 1) * 65599 + byte
                hash = bytes[i] + (hash << 6) + (hash << 16) - hash;
            }
        }
            break;
        MDNS_COVERED_SWITCH_DEFAULT:
            break;
    }

    return hash;
}

mDNSexport mDNSu32 mDNS_NonCryptoHash(const mDNSNonCryptoHash algorithm, const mDNSu8 *const bytes, const mDNSu32 len)
{
    switch (algorithm) {
        case mDNSNonCryptoHash_FNV1a:
            return mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_FNV1a, MDNSRESPONDER_FNV_32_BIT_OFFSET_BASIS, bytes,
                len);
        case mDNSNonCryptoHash_SDBM:
            return mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_SDBM, 0, bytes, len);
        MDNS_COVERED_SWITCH_DEFAULT:
            return 0;
    }
}

mDNSexport mDNSu32 mDNS_DomainNameFNV1aHash(const domainname *const name)
{
    mDNSu32 hash = MDNSRESPONDER_FNV_32_BIT_OFFSET_BASIS;
    const mDNSu32 len = DomainNameLength(name);
    const mDNSu8 *const data = name->c;
    for (mDNSu32 i = 0; i < len; ++i)
    {
        hash ^= mDNSASCIITolower(data[i]);
        hash *= MDNSRESPONDER_FNV_32_BIT_PRIME;
    }
    return hash;
}

mDNSexport mDNSs32 mDNSGetTimeOfDay(struct timeval *const tv, struct timezone *const tz)
{
    return gettimeofday(tv, tz);
}

mDNSexport mDNSBool mDNSSameAddress(const mDNSAddr *ip1, const mDNSAddr *ip2)
{
    if (ip1->type == ip2->type)
    {
        switch (ip1->type)
        {
        case mDNSAddrType_None: return(mDNStrue);      // Empty addresses have no data and are therefore always equal
        case mDNSAddrType_IPv4: return (mDNSBool)(mDNSSameIPv4Address(ip1->ip.v4, ip2->ip.v4));
        case mDNSAddrType_IPv6: return (mDNSBool)(mDNSSameIPv6Address(ip1->ip.v6, ip2->ip.v6));
        default:
            break;
        }
    }
    return(mDNSfalse);
}

mDNSexport mDNSBool mDNSAddrIsDNSMulticast(const mDNSAddr *ip)
{
    switch(ip->type)
    {
    case mDNSAddrType_IPv4: return (mDNSBool)(mDNSSameIPv4Address(ip->ip.v4, AllDNSLinkGroup_v4.ip.v4));
    case mDNSAddrType_IPv6: return (mDNSBool)(mDNSSameIPv6Address(ip->ip.v6, AllDNSLinkGroup_v6.ip.v6));
    default: return(mDNSfalse);
    }
}

mDNSlocal mDNSBool mDNSByteInRange(const mDNSu8 byte, const mDNSu8 min, const mDNSu8 max)
{
    return ((byte >= min) && (byte <= max));
}

mDNSlocal mDNSBool mDNSisUTF8Tail(const mDNSu8 byte)
{
    // 0x80-0xBF is a common byte range for various well-formed UTF-8 byte sequences.
    return mDNSByteInRange(byte, 0x80, 0xBF);
}

mDNSlocal mDNSBool mDNSBytesStartWithWellFormedUTF8OneByteSequence(const mDNSu8 *const bytes, const mDNSu32 len)
{
    // From Table 3-7. Well-Formed UTF-8 Byte Sequences of <https://www.unicode.org/versions/Unicode15.0.0/ch03.pdf>:
    //
    //     Code Points    | First Byte
    //     ---------------+------------
    //     U+0000..U+007F | 00..7F

    return ((len >= 1) && mDNSByteInRange(bytes[0], 0x00, 0x7F));
}

mDNSlocal mDNSBool mDNSBytesStartWithWellFormedUTF8TwoByteSequence(const mDNSu8 *const bytes, const mDNSu32 len)
{
    // From Table 3-7. Well-Formed UTF-8 Byte Sequences of <https://www.unicode.org/versions/Unicode15.0.0/ch03.pdf>:
    //
    //     Code Points    | First Byte | Second Byte
    //     ---------------+------------+-------------
    //     U+0080..U+07FF | C2..DF     | 80..BF

    return ((len >= 2) && mDNSByteInRange(bytes[0], 0xC2, 0xDF) && mDNSisUTF8Tail(bytes[1]));
}

mDNSlocal mDNSBool mDNSBytesStartWithWellFormedUTF8ThreeByteSequence(const mDNSu8 *const bytes, const mDNSu32 len)
{
    // From Table 3-7. Well-Formed UTF-8 Byte Sequences of <https://www.unicode.org/versions/Unicode15.0.0/ch03.pdf>:
    //
    //     Code Points    | First Byte | Second Byte | Third Byte
    //     ---------------+------------+-------------+------------
    //     U+0800..U+0FFF | E0         | A0..BF      | 80..BF
    //     U+1000..U+CFFF | E1..EC     | 80..BF      | 80..BF
    //     U+D000..U+D7FF | ED         | 80..9F      | 80..BF
    //     U+E000..U+FFFF | EE..EF     | 80..BF      | 80..BF

    if ((len >= 3) && mDNSisUTF8Tail(bytes[2]))
    {
        if (bytes[0] == 0xE0)
        {
            if (mDNSByteInRange(bytes[1], 0xA0, 0xBF))
            {
                return mDNStrue;
            }
        }
        else if (mDNSByteInRange(bytes[0], 0xE1, 0xEC) || mDNSByteInRange(bytes[0], 0xEE, 0xEF))
        {
            if (mDNSisUTF8Tail(bytes[1]))
            {
                return mDNStrue;
            }
        }
        else if (bytes[0] == 0xED)
        {
            if (mDNSByteInRange(bytes[1], 0x80, 0x9F))
            {
                return mDNStrue;
            }
        }
    }
    return mDNSfalse;
}

mDNSlocal mDNSBool mDNSBytesStartWithWellFormedUTF8FourByteSequence(const mDNSu8 *const bytes, const mDNSu32 len)
{
    // From Table 3-7. Well-Formed UTF-8 Byte Sequences of <https://www.unicode.org/versions/Unicode15.0.0/ch03.pdf>:
    //
    //     Code Points        | First Byte | Second Byte | Third Byte | Fourth Byte
    //     -------------------+------------+-------------+------------+-------------
    //     U+10000..U+3FFFF   | F0         | 90..BF      | 80..BF     | 80..BF
    //     U+40000..U+FFFFF   | F1..F3     | 80..BF      | 80..BF     | 80..BF
    //     U+100000..U+10FFFF | F4         | 80..8F      | 80..BF     | 80..BF

    if ((len >= 4) && mDNSisUTF8Tail(bytes[2]) && mDNSisUTF8Tail(bytes[3]))
    {
        if (bytes[0] == 0xF0)
        {
            if (mDNSByteInRange(bytes[1], 0x90, 0xBF))
            {
                return mDNStrue;
            }
        }
        else if (mDNSByteInRange(bytes[0], 0xF1, 0xF3))
        {
            if (mDNSisUTF8Tail(bytes[1]))
            {
                return mDNStrue;
            }
        }
        else if (bytes[0] == 0xF4)
        {
            if (mDNSByteInRange(bytes[1], 0x80, 0x8F))
            {
                return mDNStrue;
            }
        }
    }
    return mDNSfalse;
}

mDNSlocal mDNSu8 mDNSLengthOfFirstUTF8Character(const mDNSu8 *const bytes, const mDNSu32 len)
{
    if (mDNSBytesStartWithWellFormedUTF8OneByteSequence(bytes, len))
    {
        return 1;
    }
    else if (mDNSBytesStartWithWellFormedUTF8TwoByteSequence(bytes, len))
    {
        return 2;
    }
    else if (mDNSBytesStartWithWellFormedUTF8ThreeByteSequence(bytes, len))
    {
        return 3;
    }
    else if (mDNSBytesStartWithWellFormedUTF8FourByteSequence(bytes, len))
    {
        return 4;
    }
    else
    {
        return 0;
    }
}

mDNSlocal const mDNSu8 *mDNSLocateFirstMalformedUTF8Byte(const mDNSu8 *const bytes, const mDNSu32 byteLen)
{
    for (const mDNSu8 *ptr = bytes, *const end = bytes + byteLen; ptr < end;)
    {
        const mDNSu32 utf8CharacterLen = mDNSLengthOfFirstUTF8Character(ptr, (mDNSu32)(end - ptr));
        if (utf8CharacterLen == 0)
        {
            return ptr;
        }
        ptr += utf8CharacterLen;
    }
    return mDNSNULL;
}

mDNSlocal mDNSBool mDNSAreUTF8Bytes(const mDNSu8 *const bytes, const mDNSu32 len)
{
    return (mDNSLocateFirstMalformedUTF8Byte(bytes, len) == mDNSNULL);
}

mDNSexport mDNSBool mDNSAreUTF8String(const char *const str)
{
    return mDNSAreUTF8Bytes((const mDNSu8 *)str, mDNSPlatformStrLen(str));
}

mDNSexport mDNSu32 GetEffectiveTTL(const uDNS_LLQType LLQType, mDNSu32 ttl)      // TTL in seconds
{
    if      (LLQType == uDNS_LLQ_Entire) ttl = kLLQ_DefLease;
    else if (LLQType == uDNS_LLQ_Events)
    {
        // If the TTL is -1 for uDNS LLQ event packet, that means "remove"
        if (ttl == 0xFFFFFFFF) ttl = 0;
        else ttl = kLLQ_DefLease;
    }
    else    // else not LLQ (standard uDNS response)
    {
        // The TTL is already capped to a maximum value in GetLargeResourceRecord, but just to be extra safe we
        // also do this check here to make sure we can't get overflow below when we add a quarter to the TTL
        if (ttl > 0x60000000UL / mDNSPlatformOneSecond) ttl = 0x60000000UL / mDNSPlatformOneSecond;

        ttl = RRAdjustTTL(ttl);

        // For mDNS, TTL zero means "delete this record"
        // For uDNS, TTL zero means: this data is true at this moment, but don't cache it.
        // For the sake of network efficiency, we impose a minimum effective TTL of 15 seconds.
        // This means that we'll do our 80, 85, 90, 95% queries at 12.00, 12.75, 13.50, 14.25 seconds
        // respectively, and then if we get no response, delete the record from the cache at 15 seconds.
        // This gives the server up to three seconds to respond between when we send our 80% query at 12 seconds
        // and when we delete the record at 15 seconds. Allowing cache lifetimes less than 15 seconds would
        // (with the current code) result in the server having even less than three seconds to respond
        // before we deleted the record and reported a "remove" event to any active questions.
        // Furthermore, with the current code, if we were to allow a TTL of less than 2 seconds
        // then things really break (e.g. we end up making a negative cache entry).
        // In the future we may want to revisit this and consider properly supporting non-cached (TTL=0) uDNS answers.
        if (ttl < 15) ttl = 15;
    }

    return ttl;
}

// ***************************************************************************
// MARK: - Domain Name Utility Functions


mDNSexport mDNSBool SameDomainLabel(const mDNSu8 *a, const mDNSu8 *b)
{
    int i;
    const int len = *a++;

    if (len > MAX_DOMAIN_LABEL)
    { debugf("Malformed label (too long)"); return(mDNSfalse); }

    if (len != *b++) return(mDNSfalse);
    for (i=0; i<len; i++)
    {
        mDNSu8 ac = *a++;
        mDNSu8 bc = *b++;
        if (mDNSIsUpperCase(ac)) ac += 'a' - 'A';
        if (mDNSIsUpperCase(bc)) bc += 'a' - 'A';
        if (ac != bc) return(mDNSfalse);
    }
    return(mDNStrue);
}


mDNSexport mDNSBool SameDomainName(const domainname *const d1, const domainname *const d2)
{
    return(SameDomainNameBytes(d1->c, d2->c));
}

mDNSexport mDNSBool SameDomainNameBytes(const mDNSu8 *const d1, const mDNSu8 *const d2)
{
    const mDNSu8 *      a   = d1;
    const mDNSu8 *      b   = d2;
    const mDNSu8 *const max = d1 + MAX_DOMAIN_NAME; // Maximum that's valid

    while (*a || *b)
    {
        if (a + 1 + *a >= max)
        { debugf("Malformed domain name (more than 256 characters)"); return(mDNSfalse); }
        if (!SameDomainLabel(a, b)) return(mDNSfalse);
        a += 1 + *a;
        b += 1 + *b;
    }

    return(mDNStrue);
}

mDNSexport mDNSBool SameDomainNameCS(const domainname *const d1, const domainname *const d2)
{
    mDNSu16 l1 = DomainNameLength(d1);
    mDNSu16 l2 = DomainNameLength(d2);
    return(l1 <= MAX_DOMAIN_NAME && l1 == l2 && mDNSPlatformMemSame(d1, d2, l1));
}

mDNSexport mDNSBool IsSubdomain(const domainname *const subdomain, const domainname *const domain)
{
    mDNSBool isSubdomain = mDNSfalse;
    const int subdomainLabelCount = CountLabels(subdomain);
    const int domainLabelCount = CountLabels(domain);

    if (subdomainLabelCount >= domainLabelCount)
    {
        const domainname *const parentDomain = SkipLeadingLabels(subdomain, subdomainLabelCount - domainLabelCount);
        isSubdomain = SameDomainName(parentDomain, domain);
    }

    return isSubdomain;
}

mDNSexport mDNSBool IsLocalDomain(const domainname *d)
{
    // Domains that are defined to be resolved via link-local multicast are:
    // local., 254.169.in-addr.arpa., and {8,9,A,B}.E.F.ip6.arpa.
    static const domainname *nL = (const domainname*)"\x5" "local";
    static const domainname *nR = (const domainname*)"\x3" "254" "\x3" "169"         "\x7" "in-addr" "\x4" "arpa";
    static const domainname *n8 = (const domainname*)"\x1" "8"   "\x1" "e" "\x1" "f" "\x3" "ip6"     "\x4" "arpa";
    static const domainname *n9 = (const domainname*)"\x1" "9"   "\x1" "e" "\x1" "f" "\x3" "ip6"     "\x4" "arpa";
    static const domainname *nA = (const domainname*)"\x1" "a"   "\x1" "e" "\x1" "f" "\x3" "ip6"     "\x4" "arpa";
    static const domainname *nB = (const domainname*)"\x1" "b"   "\x1" "e" "\x1" "f" "\x3" "ip6"     "\x4" "arpa";

    const domainname *d1, *d2, *d3, *d4, *d5;   // Top-level domain, second-level domain, etc.
    d1 = d2 = d3 = d4 = d5 = mDNSNULL;
    while (d->c[0])
    {
        d5 = d4; d4 = d3; d3 = d2; d2 = d1; d1 = d;
        d = (const domainname*)(d->c + 1 + d->c[0]);
    }

    if (d1 && SameDomainName(d1, nL)) return(mDNStrue);
    if (d4 && SameDomainName(d4, nR)) return(mDNStrue);
    if (d5 && SameDomainName(d5, n8)) return(mDNStrue);
    if (d5 && SameDomainName(d5, n9)) return(mDNStrue);
    if (d5 && SameDomainName(d5, nA)) return(mDNStrue);
    if (d5 && SameDomainName(d5, nB)) return(mDNStrue);
    return(mDNSfalse);
}

mDNSexport mDNSBool IsRootDomain(const domainname *const d)
{
    return (d->c[0] == 0);
}

mDNSexport const mDNSu8 *LastLabel(const domainname *d)
{
    const mDNSu8 *p = d->c;
    while (d->c[0])
    {
        p = d->c;
        d = (const domainname*)(d->c + 1 + d->c[0]);
    }
    return(p);
}

// Returns length of a domain name INCLUDING the byte for the final null label
// e.g. for the root label "." it returns one
// For the FQDN "com." it returns 5 (length byte, three data bytes, final zero)
// Legal results are 1 (just root label) to 256 (MAX_DOMAIN_NAME)
// If the given domainname is invalid, result is 257 (MAX_DOMAIN_NAME+1)
mDNSexport mDNSu16 DomainNameLengthLimit(const domainname *const name, const mDNSu8 *const limit)
{
    return(DomainNameBytesLength(name->c, limit));
}

mDNSexport mDNSu16 DomainNameBytesLength(const mDNSu8 *const name, const mDNSu8 *const limit)
{
    const mDNSu8 *src = name;
    while ((!limit || (src < limit)) && src && (*src <= MAX_DOMAIN_LABEL))
    {
        if (*src == 0) return((mDNSu16)(src - name + 1));
        src += 1 + *src;
    }
    return(MAX_DOMAIN_NAME+1);
}

mDNSexport mDNSu8 DomainLabelLength(const domainlabel *const label)
{
    return label->c[0];
}

// CompressedDomainNameLength returns the length of a domain name INCLUDING the byte
// for the final null label, e.g. for the root label "." it returns one.
// E.g. for the FQDN "foo.com." it returns 9
// (length, three data bytes, length, three more data bytes, final zero).
// In the case where a parent domain name is provided, and the given name is a child
// of that parent, CompressedDomainNameLength returns the length of the prefix portion
// of the child name, plus TWO bytes for the compression pointer.
// E.g. for the name "foo.com." with parent "com.", it returns 6
// (length, three data bytes, two-byte compression pointer).
mDNSexport mDNSu16 CompressedDomainNameLength(const domainname *const name, const domainname *parent)
{
    const mDNSu8 *src = name->c;
    if (parent && parent->c[0] == 0) parent = mDNSNULL;
    while (*src)
    {
        if (*src > MAX_DOMAIN_LABEL) return(MAX_DOMAIN_NAME+1);
        if (parent && SameDomainName((const domainname *)src, parent)) return((mDNSu16)(src - name->c + 2));
        src += 1 + *src;
        if (src - name->c >= MAX_DOMAIN_NAME) return(MAX_DOMAIN_NAME+1);
    }
    return((mDNSu16)(src - name->c + 1));
}

// CountLabels() returns number of labels in name, excluding final root label
// (e.g. for "apple.com." CountLabels returns 2.)
mDNSexport int CountLabels(const domainname *d)
{
    int count = 0;
    const mDNSu8 *ptr;
    for (ptr = d->c; *ptr; ptr = ptr + ptr[0] + 1) count++;
    return count;
}

// SkipLeadingLabels skips over the first 'skip' labels in the domainname,
// returning a pointer to the suffix with 'skip' labels removed.
mDNSexport const domainname *SkipLeadingLabels(const domainname *d, int skip)
{
    while (skip > 0 && d->c[0]) { d = (const domainname *)(d->c + 1 + d->c[0]); skip--; }
    return(d);
}

// AppendLiteralLabelString appends a single label to an existing (possibly empty) domainname.
// The C string contains the label as-is, with no escaping, etc.
// Any dots in the name are literal dots, not label separators
// If successful, AppendLiteralLabelString returns a pointer to the next unused byte
// in the domainname bufer (i.e. the next byte after the terminating zero).
// If unable to construct a legal domain name (i.e. label more than 63 bytes, or total more than 256 bytes)
// AppendLiteralLabelString returns mDNSNULL.
mDNSexport mDNSu8 *AppendLiteralLabelString(domainname *const name, const char *cstr)
{
    mDNSu8       *      ptr  = name->c + DomainNameLength(name) - 1;    // Find end of current name
    const mDNSu8 *const lim1 = name->c + MAX_DOMAIN_NAME - 1;           // Limit of how much we can add (not counting final zero)
    const mDNSu8 *const lim2 = ptr + 1 + MAX_DOMAIN_LABEL;
    const mDNSu8 *const lim  = (lim1 < lim2) ? lim1 : lim2;
    mDNSu8       *lengthbyte = ptr++;                                   // Record where the length is going to go

    while (*cstr && ptr < lim) *ptr++ = (mDNSu8)*cstr++;    // Copy the data
    *lengthbyte = (mDNSu8)(ptr - lengthbyte - 1);           // Fill in the length byte
    *ptr++ = 0;                                             // Put the null root label on the end
    if (*cstr) return(mDNSNULL);                            // Failure: We didn't successfully consume all input
    else return(ptr);                                       // Success: return new value of ptr
}

// AppendDNSNameString appends zero or more labels to an existing (possibly empty) domainname.
// The C string is in conventional DNS syntax:
// Textual labels, escaped as necessary using the usual DNS '\' notation, separated by dots.
// If successful, AppendDNSNameString returns a pointer to the next unused byte
// in the domainname bufer (i.e. the next byte after the terminating zero).
// If unable to construct a legal domain name (i.e. label more than 63 bytes, or total more than 256 bytes)
// AppendDNSNameString returns mDNSNULL.
mDNSexport mDNSu8 *AppendDNSNameString(domainname *const name, const char *cstring)
{
    const char   *     cstr = cstring;
    mDNSu8       *      ptr = name->c + DomainNameLength(name) - 1; // Find end of current name
    const mDNSu8 *const lim = name->c + MAX_DOMAIN_NAME - 1;        // Limit of how much we can add (not counting final zero)
    if (cstr[0] == '.' && cstr[1] == '\0') cstr++;                  // If the domain to be appended is root domain, skip it.
    while (*cstr && ptr < lim)                                      // While more characters, and space to put them...
    {
        mDNSu8 *lengthbyte = ptr++;                                 // Record where the length is going to go
        if (*cstr == '.') { LogMsg("AppendDNSNameString: Illegal empty label in name \"%s\"", cstring); return(mDNSNULL); }
        while (*cstr && *cstr != '.' && ptr < lim)                  // While we have characters in the label...
        {
            mDNSu8 c = (mDNSu8)*cstr++;                             // Read the character
            if (c == '\\')                                          // If escape character, check next character
            {
                if (*cstr == '\0') break;                           // If this is the end of the string, then break
                c = (mDNSu8)*cstr++;                                // Assume we'll just take the next character
                if (mDNSIsDigit(cstr[-1]) && mDNSIsDigit(cstr[0]) && mDNSIsDigit(cstr[1]))
                {                                                   // If three decimal digits,
                    int v0 = cstr[-1] - '0';                        // then interpret as three-digit decimal
                    int v1 = cstr[ 0] - '0';
                    int v2 = cstr[ 1] - '0';
                    int val = v0 * 100 + v1 * 10 + v2;
                    if (val <= 255) { c = (mDNSu8)val; cstr += 2; } // If valid three-digit decimal value, use it
                }
            }
            *ptr++ = c;                                             // Write the character
        }
        if (*cstr == '.') cstr++;                                   // Skip over the trailing dot (if present)
        if (ptr - lengthbyte - 1 > MAX_DOMAIN_LABEL)                // If illegal label, abort
            return(mDNSNULL);
        *lengthbyte = (mDNSu8)(ptr - lengthbyte - 1);               // Fill in the length byte
    }

    *ptr++ = 0;                                                     // Put the null root label on the end
    if (*cstr) return(mDNSNULL);                                    // Failure: We didn't successfully consume all input
    else return(ptr);                                               // Success: return new value of ptr
}

// AppendDomainLabel appends a single label to a name.
// If successful, AppendDomainLabel returns a pointer to the next unused byte
// in the domainname bufer (i.e. the next byte after the terminating zero).
// If unable to construct a legal domain name (i.e. label more than 63 bytes, or total more than 256 bytes)
// AppendDomainLabel returns mDNSNULL.
mDNSexport mDNSu8 *AppendDomainLabel(domainname *const name, const domainlabel *const label)
{
    int i;
    mDNSu8 *ptr = name->c + DomainNameLength(name) - 1;

    // Check label is legal
    if (label->c[0] > MAX_DOMAIN_LABEL) return(mDNSNULL);

    // Check that ptr + length byte + data bytes + final zero does not exceed our limit
    if (ptr + 1 + label->c[0] + 1 > name->c + MAX_DOMAIN_NAME) return(mDNSNULL);

    for (i=0; i<=label->c[0]; i++) *ptr++ = label->c[i];    // Copy the label data
    *ptr++ = 0;                             // Put the null root label on the end
    return(ptr);
}

mDNSexport mDNSu8 *AppendDomainName(domainname *const name, const domainname *const append)
{
    mDNSu8       *      ptr = name->c + DomainNameLength(name) - 1; // Find end of current name
    const mDNSu8 *const lim = name->c + MAX_DOMAIN_NAME - 1;        // Limit of how much we can add (not counting final zero)
    const mDNSu8 *      src = append->c;
    while (src[0])
    {
        int i;
        if (ptr + 1 + src[0] > lim) return(mDNSNULL);
        for (i=0; i<=src[0]; i++) *ptr++ = src[i];
        *ptr = 0;   // Put the null root label on the end
        src += i;
    }
    return(ptr);
}

// MakeDomainLabelFromLiteralString makes a single domain label from a single literal C string (with no escaping).
// If successful, MakeDomainLabelFromLiteralString returns mDNStrue.
// If unable to convert the whole string to a legal domain label (i.e. because length is more than 63 bytes) then
// MakeDomainLabelFromLiteralString makes a legal domain label from the first 63 bytes of the string and returns mDNSfalse.
// In some cases silently truncated oversized names to 63 bytes is acceptable, so the return result may be ignored.
// In other cases silent truncation may not be acceptable, so in those cases the calling function needs to check the return result.
mDNSexport mDNSBool MakeDomainLabelFromLiteralString(domainlabel *const label, const char *cstr)
{
    mDNSu8       *      ptr   = label->c + 1;                       // Where we're putting it
    const mDNSu8 *const limit = label->c + 1 + MAX_DOMAIN_LABEL;    // The maximum we can put
    while (*cstr && ptr < limit) *ptr++ = (mDNSu8)*cstr++;          // Copy the label
    label->c[0] = (mDNSu8)(ptr - label->c - 1);                     // Set the length byte
    return(*cstr == 0);                                             // Return mDNStrue if we successfully consumed all input
}

// MakeDomainNameFromDNSNameString makes a native DNS-format domainname from a C string.
// The C string is in conventional DNS syntax:
// Textual labels, escaped as necessary using the usual DNS '\' notation, separated by dots.
// If successful, MakeDomainNameFromDNSNameString returns a pointer to the next unused byte
// in the domainname bufer (i.e. the next byte after the terminating zero).
// If unable to construct a legal domain name (i.e. label more than 63 bytes, or total more than 256 bytes)
// MakeDomainNameFromDNSNameString returns mDNSNULL.
mDNSexport mDNSu8 *MakeDomainNameFromDNSNameString(domainname *const name, const char *cstr)
{
    name->c[0] = 0;                                 // Make an empty domain name
    return(AppendDNSNameString(name, cstr));        // And then add this string to it
}

mDNSexport char *ConvertDomainLabelToCString_withescape(const domainlabel *const label, char *ptr, char esc)
{
    const mDNSu8 *      src = label->c;                         // Domain label we're reading
    const mDNSu8 len = *src++;                                  // Read length of this (non-null) label
    const mDNSu8 *const end = src + len;                        // Work out where the label ends
    if (len > MAX_DOMAIN_LABEL) return(mDNSNULL);               // If illegal label, abort
    while (src < end)                                           // While we have characters in the label
    {
        mDNSu8 c = *src++;
        if (esc)
        {
            if (c == '.' || c == esc)                           // If character is a dot or the escape character
                *ptr++ = esc;                                   // Output escape character
            else if (c <= ' ')                                  // If non-printing ascii,
            {                                                   // Output decimal escape sequence
                *ptr++ = esc;
                *ptr++ = (char)  ('0' + (c / 100)     );
                *ptr++ = (char)  ('0' + (c /  10) % 10);
                c      = (mDNSu8)('0' + (c      ) % 10);
            }
        }
        *ptr++ = (char)c;                                       // Copy the character
    }
    *ptr = 0;                                                   // Null-terminate the string
    return(ptr);                                                // and return
}

// Note: To guarantee that there will be no possible overrun, cstr must be at least MAX_ESCAPED_DOMAIN_NAME (1009 bytes)
mDNSexport char *ConvertDomainNameToCString_withescape(const domainname *const name, char *ptr, char esc)
{
    const mDNSu8 *src         = name->c;                            // Domain name we're reading
    const mDNSu8 *const max   = name->c + MAX_DOMAIN_NAME;          // Maximum that's valid

    if (*src == 0) *ptr++ = '.';                                    // Special case: For root, just write a dot

    while (*src)                                                    // While more characters in the domain name
    {
        if (src + 1 + *src >= max) return(mDNSNULL);
        ptr = ConvertDomainLabelToCString_withescape((const domainlabel *)src, ptr, esc);
        if (!ptr) return(mDNSNULL);
        src += 1 + *src;
        *ptr++ = '.';                                               // Write the dot after the label
    }

    *ptr++ = 0;                                                     // Null-terminate the string
    return(ptr);                                                    // and return
}

// RFC 1034 rules:
// Host names must start with a letter, end with a letter or digit,
// and have as interior characters only letters, digits, and hyphen.
// This was subsequently modified in RFC 1123 to allow the first character to be either a letter or a digit

mDNSexport void ConvertUTF8PstringToRFC1034HostLabel(const mDNSu8 UTF8Name[], domainlabel *const hostlabel)
{
    const mDNSu8 *      src  = &UTF8Name[1];
    const mDNSu8 *const end  = &UTF8Name[1] + UTF8Name[0];
    mDNSu8 *      ptr  = &hostlabel->c[1];
    const mDNSu8 *const lim  = &hostlabel->c[1] + MAX_DOMAIN_LABEL;
    while (src < end)
    {
        // Delete apostrophes from source name
        if (src[0] == '\'') { src++; continue; }        // Standard straight single quote
        if (src + 2 < end && src[0] == 0xE2 && src[1] == 0x80 && src[2] == 0x99)
        { src += 3; continue; }     // Unicode curly apostrophe
        if (ptr < lim)
        {
            if (mDNSValidHostChar(*src, (ptr > &hostlabel->c[1]), (src < end-1))) *ptr++ = *src;
            else if (ptr > &hostlabel->c[1] && ptr[-1] != '-') *ptr++ = '-';
        }
        src++;
    }
    while (ptr > &hostlabel->c[1] && ptr[-1] == '-') ptr--; // Truncate trailing '-' marks
    hostlabel->c[0] = (mDNSu8)(ptr - &hostlabel->c[1]);
}

mDNSexport mDNSu8 *ConstructServiceName(domainname *const fqdn,
                                        const domainlabel *name, const domainname *type, const domainname *const domain)
{
    int i, len;
    mDNSu8 *dst = fqdn->c;
    const mDNSu8 *src;
    const char *errormsg;

    // In the case where there is no name (and ONLY in that case),
    // a single-label subtype is allowed as the first label of a three-part "type"
    if (!name)
    {
        const mDNSu8 *s0 = type->c;
        if (s0[0] && s0[0] < 0x40)      // If legal first label (at least one character, and no more than 63)
        {
            const mDNSu8 * s1 = s0 + 1 + s0[0];
            if (s1[0] && s1[0] < 0x40)  // and legal second label (at least one character, and no more than 63)
            {
                const mDNSu8 *s2 = s1 + 1 + s1[0];
                if (s2[0] && s2[0] < 0x40 && s2[1+s2[0]] == 0)  // and we have three and only three labels
                {
                    static const mDNSu8 SubTypeLabel[5] = mDNSSubTypeLabel;
                    src = s0;                                   // Copy the first label
                    len = *src;
                    for (i=0; i <= len;                      i++) *dst++ = *src++;
                    for (i=0; i < (int)sizeof(SubTypeLabel); i++) *dst++ = SubTypeLabel[i];
                    type = (const domainname *)s1;

                    // Special support to enable the DNSServiceBrowse call made by Bonjour Browser
                    // For these queries, we retract the "._sub" we just added between the subtype and the main type
                    // Remove after Bonjour Browser is updated to use DNSServiceQueryRecord instead of DNSServiceBrowse
                    if (SameDomainName((const domainname*)s0, (const domainname*)"\x09_services\x07_dns-sd\x04_udp"))
                        dst -= sizeof(SubTypeLabel);
                }
            }
        }
    }

    if (name && name->c[0])
    {
        src = name->c;                                  // Put the service name into the domain name
        len = *src;
        if (len >= 0x40) { errormsg = "Service instance name too long"; goto fail; }
        for (i=0; i<=len; i++) *dst++ = *src++;
    }
    else
        name = (domainlabel*)"";    // Set this up to be non-null, to avoid errors if we have to call LogMsg() below

    src = type->c;                                      // Put the service type into the domain name
    len = *src;
    if (len < 2 || len > 16)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Bad service type in " PRI_DM_LABEL "." PRI_DM_NAME PRI_DM_NAME" Application protocol name must be "
            "underscore plus 1-15 characters. See <http://www.dns-sd.org/ServiceTypes.html>",
            DM_LABEL_PARAM(name), DM_NAME_PARAM(type), DM_NAME_PARAM(domain));
    }
    if (len < 2 || len >= 0x40 || (len > 16 && !SameDomainName(domain, &localdomain))) return(mDNSNULL);
    if (src[1] != '_') { errormsg = "Application protocol name must begin with underscore"; goto fail; }
    for (i=2; i<=len; i++)
    {
        // Letters and digits are allowed anywhere
        if (mDNSIsLetter(src[i]) || mDNSIsDigit(src[i])) continue;
        // Hyphens are only allowed as interior characters
        // Underscores are not supposed to be allowed at all, but for backwards compatibility with some old products we do allow them,
        // with the same rule as hyphens
        if ((src[i] == '-' || src[i] == '_') && i > 2 && i < len)
        {
            continue;
        }
        errormsg = "Application protocol name must contain only letters, digits, and hyphens";
        goto fail;
    }
    for (i=0; i<=len; i++) *dst++ = *src++;

    len = *src;
    if (!ValidTransportProtocol(src)) { errormsg = "Transport protocol name must be _udp or _tcp"; goto fail; }
    for (i=0; i<=len; i++) *dst++ = *src++;

    if (*src) { errormsg = "Service type must have only two labels"; goto fail; }

    *dst = 0;
    if (!domain->c[0]) { errormsg = "Service domain must be non-empty"; goto fail; }
    if (SameDomainName(domain, (const domainname*)"\x05" "local" "\x04" "arpa"))
    { errormsg = "Illegal domain \"local.arpa.\" Use \"local.\" (or empty string)"; goto fail; }
    dst = AppendDomainName(fqdn, domain);
    if (!dst) { errormsg = "Service domain too long"; goto fail; }
    return(dst);

fail:
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "ConstructServiceName: " PUB_S ": " PRI_DM_LABEL "." PRI_DM_NAME PRI_DM_NAME , errormsg,
        DM_LABEL_PARAM(name), DM_NAME_PARAM(type), DM_NAME_PARAM(domain));
    return(mDNSNULL);
}

// A service name has the form: instance.application-protocol.transport-protocol.domain
// DeconstructServiceName is currently fairly forgiving: It doesn't try to enforce character
// set or length limits for the protocol names, and the final domain is allowed to be empty.
// However, if the given FQDN doesn't contain at least three labels,
// DeconstructServiceName will reject it and return mDNSfalse.
mDNSexport mDNSBool DeconstructServiceName(const domainname *const fqdn,
                                           domainlabel *const name, domainname *const type, domainname *const domain)
{
    int i, len;
    const mDNSu8 *src = fqdn->c;
    const mDNSu8 *max = fqdn->c + MAX_DOMAIN_NAME;
    mDNSu8 *dst;

    dst = name->c;                                      // Extract the service name
    len = *src;
    if (!len)         { debugf("DeconstructServiceName: FQDN empty!");                             return(mDNSfalse); }
    if (len >= 0x40)  { debugf("DeconstructServiceName: Instance name too long");                  return(mDNSfalse); }
    for (i=0; i<=len; i++) *dst++ = *src++;

    dst = type->c;                                      // Extract the service type
    len = *src;
    if (!len)         { debugf("DeconstructServiceName: FQDN contains only one label!");           return(mDNSfalse); }
    if (len >= 0x40)  { debugf("DeconstructServiceName: Application protocol name too long");      return(mDNSfalse); }
    if (src[1] != '_') { debugf("DeconstructServiceName: No _ at start of application protocol");   return(mDNSfalse); }
    for (i=0; i<=len; i++) *dst++ = *src++;

    len = *src;
    if (!len)         { debugf("DeconstructServiceName: FQDN contains only two labels!");          return(mDNSfalse); }
    if (!ValidTransportProtocol(src))
    { debugf("DeconstructServiceName: Transport protocol must be _udp or _tcp"); return(mDNSfalse); }
    for (i=0; i<=len; i++) *dst++ = *src++;
    *dst++ = 0;                                         // Put terminator on the end of service type

    dst = domain->c;                                    // Extract the service domain
    while (*src)
    {
        len = *src;
        if (len >= 0x40)
        { debugf("DeconstructServiceName: Label in service domain too long"); return(mDNSfalse); }
        if (src + 1 + len + 1 >= max)
        { debugf("DeconstructServiceName: Total service domain too long"); return(mDNSfalse); }
        for (i=0; i<=len; i++) *dst++ = *src++;
    }
    *dst++ = 0;     // Put the null root label on the end

    return(mDNStrue);
}

mDNSexport mStatus DNSNameToLowerCase(domainname *d, domainname *result)
{
    const mDNSu8 *a = d->c;
    mDNSu8 *b = result->c;
    const mDNSu8 *const max = d->c + MAX_DOMAIN_NAME;
    int i, len;

    while (*a)
    {
        if (a + 1 + *a >= max)
        {
            LogMsg("DNSNameToLowerCase: ERROR!! Malformed Domain name");
            return mStatus_BadParamErr;
        }
        len = *a++;
        *b++ = len;
        for (i = 0; i < len; i++)
        {
            mDNSu8 ac = *a++;
            if (mDNSIsUpperCase(ac)) ac += 'a' - 'A';
            *b++ = ac;
        }
    }
    *b = 0;

    return mStatus_NoError;
}

// Notes on UTF-8:
// 0xxxxxxx represents a 7-bit ASCII value from 0x00 to 0x7F
// 10xxxxxx is a continuation byte of a multi-byte character
// 110xxxxx is the first byte of a 2-byte character (11 effective bits; values 0x     80 - 0x     800-1)
// 1110xxxx is the first byte of a 3-byte character (16 effective bits; values 0x    800 - 0x   10000-1)
// 11110xxx is the first byte of a 4-byte character (21 effective bits; values 0x  10000 - 0x  200000-1)
// 111110xx is the first byte of a 5-byte character (26 effective bits; values 0x 200000 - 0x 4000000-1)
// 1111110x is the first byte of a 6-byte character (31 effective bits; values 0x4000000 - 0x80000000-1)
//
// UTF-16 surrogate pairs are used in UTF-16 to encode values larger than 0xFFFF.
// Although UTF-16 surrogate pairs are not supposed to appear in legal UTF-8, we want to be defensive
// about that too. (See <http://www.unicode.org/faq/utf_bom.html#34>, "What are surrogates?")
// The first of pair is a UTF-16 value in the range 0xD800-0xDBFF (11101101 1010xxxx 10xxxxxx in UTF-8),
// and the second    is a UTF-16 value in the range 0xDC00-0xDFFF (11101101 1011xxxx 10xxxxxx in UTF-8).

mDNSexport mDNSu32 TruncateUTF8ToLength(mDNSu8 *string, mDNSu32 length, mDNSu32 max)
{
    if (length > max)
    {
        mDNSu8 c1 = string[max];                                        // First byte after cut point
        mDNSu8 c2 = (max+1 < length) ? string[max+1] : (mDNSu8)0xB0;    // Second byte after cut point
        length = max;   // Trim length down
        while (length > 0)
        {
            // Check if the byte right after the chop point is a UTF-8 continuation byte,
            // or if the character right after the chop point is the second of a UTF-16 surrogate pair.
            // If so, then we continue to chop more bytes until we get to a legal chop point.
            mDNSBool continuation    = ((c1 & 0xC0) == 0x80);
            mDNSBool secondsurrogate = (c1 == 0xED && (c2 & 0xF0) == 0xB0);
            if (!continuation && !secondsurrogate) break;
            c2 = c1;
            c1 = string[--length];
        }
        // Having truncated characters off the end of our string, also cut off any residual white space
        while (length > 0 && string[length-1] <= ' ') length--;
    }
    return(length);
}

// Returns true if a rich text label ends in " (nnn)", or if an RFC 1034
// name ends in "-nnn", where n is some decimal number.
mDNSexport mDNSBool LabelContainsSuffix(const domainlabel *const name, const mDNSBool RichText)
{
    mDNSu16 l = name->c[0];

    if (RichText)
    {
        if (l < 4) return mDNSfalse;                            // Need at least " (2)"
        if (name->c[l--] != ')') return mDNSfalse;              // Last char must be ')'
        if (!mDNSIsDigit(name->c[l])) return mDNSfalse;         // Preceeded by a digit
        l--;
        while (l > 2 && mDNSIsDigit(name->c[l])) l--;           // Strip off digits
        return (name->c[l] == '(' && name->c[l - 1] == ' ');
    }
    else
    {
        if (l < 2) return mDNSfalse;                            // Need at least "-2"
        if (!mDNSIsDigit(name->c[l])) return mDNSfalse;         // Last char must be a digit
        l--;
        while (l > 2 && mDNSIsDigit(name->c[l])) l--;           // Strip off digits
        return (name->c[l] == '-');
    }
}

// removes an auto-generated suffix (appended on a name collision) from a label.  caller is
// responsible for ensuring that the label does indeed contain a suffix.  returns the number
// from the suffix that was removed.
mDNSexport mDNSu32 RemoveLabelSuffix(domainlabel *name, mDNSBool RichText)
{
    mDNSu32 val = 0, multiplier = 1;

    // Chop closing parentheses from RichText suffix
    if (RichText && name->c[0] >= 1 && name->c[name->c[0]] == ')') name->c[0]--;

    // Get any existing numerical suffix off the name
    while (mDNSIsDigit(name->c[name->c[0]]))
    { val += (name->c[name->c[0]] - '0') * multiplier; multiplier *= 10; name->c[0]--; }

    // Chop opening parentheses or dash from suffix
    if (RichText)
    {
        if (name->c[0] >= 2 && name->c[name->c[0]] == '(' && name->c[name->c[0]-1] == ' ') name->c[0] -= 2;
    }
    else
    {
        if (name->c[0] >= 1 && name->c[name->c[0]] == '-') name->c[0] -= 1;
    }

    return(val);
}

// appends a numerical suffix to a label, with the number following a whitespace and enclosed
// in parentheses (rich text) or following two consecutive hyphens (RFC 1034 domain label).
mDNSexport void AppendLabelSuffix(domainlabel *const name, mDNSu32 val, const mDNSBool RichText)
{
    mDNSu32 divisor = 1, chars = 2; // Shortest possible RFC1034 name suffix is 2 characters ("-2")
    if (RichText) chars = 4;        // Shortest possible RichText suffix is 4 characters (" (2)")

    // Truncate trailing spaces from RichText names
    if (RichText) while (name->c[name->c[0]] == ' ') name->c[0]--;

    while (divisor < 0xFFFFFFFFUL/10 && val >= divisor * 10) { divisor *= 10; chars++; }

    name->c[0] = (mDNSu8) TruncateUTF8ToLength(name->c+1, name->c[0], MAX_DOMAIN_LABEL - chars);

    if (RichText) { name->c[++name->c[0]] = ' '; name->c[++name->c[0]] = '('; }
    else          { name->c[++name->c[0]] = '-'; }

    while (divisor)
    {
        name->c[++name->c[0]] = (mDNSu8)('0' + val / divisor);
        val     %= divisor;
        divisor /= 10;
    }

    if (RichText) name->c[++name->c[0]] = ')';
}

mDNSexport void IncrementLabelSuffix(domainlabel *name, mDNSBool RichText)
{
    mDNSu32 val = 0;

    if (LabelContainsSuffix(name, RichText))
        val = RemoveLabelSuffix(name, RichText);

    // If no existing suffix, start by renaming "Foo" as "Foo (2)" or "Foo-2" as appropriate.
    // If existing suffix in the range 2-9, increment it.
    // If we've had ten conflicts already, there are probably too many hosts trying to use the same name,
    // so add a random increment to improve the chances of finding an available name next time.
    if      (val == 0) val = 2;
    else if (val < 10) val++;
    else val += 1 + mDNSRandom(99);

    AppendLabelSuffix(name, val, RichText);
}

// ***************************************************************************
// MARK: - Resource Record Utility Functions

// Set up a AuthRecord with sensible default values.
// These defaults may be overwritten with new values before mDNS_Register is called
mDNSexport void mDNS_SetupResourceRecord(AuthRecord *rr, RData *RDataStorage, mDNSInterfaceID InterfaceID,
                                         mDNSu16 rrtype, mDNSu32 ttl, mDNSu8 RecordType, AuthRecType artype, mDNSRecordCallback Callback, void *Context)
{
    //
    // LocalOnly auth record can be created with LocalOnly InterfaceID or a valid InterfaceID.
    // Most of the applications normally create with LocalOnly InterfaceID and we store them as
    // such, so that we can deliver the response to questions that specify LocalOnly InterfaceID.
    // LocalOnly resource records can also be created with valid InterfaceID which happens today
    // when we create LocalOnly records for /etc/hosts.

    if (InterfaceID == mDNSInterface_LocalOnly && artype != AuthRecordLocalOnly)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNS_SetupResourceRecord: ERROR!! Mismatch LocalOnly record InterfaceID %p called with artype %d",
            InterfaceID, artype);
    }
    else if (InterfaceID == mDNSInterface_P2P && artype != AuthRecordP2P)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNS_SetupResourceRecord: ERROR!! Mismatch P2P record InterfaceID %p called with artype %d",
            InterfaceID, artype);
    }
    else if (!InterfaceID && (artype == AuthRecordP2P || artype == AuthRecordLocalOnly))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNS_SetupResourceRecord: ERROR!! Mismatch InterfaceAny record InterfaceID %p called with artype %d",
            InterfaceID, artype);
    }

    // Don't try to store a TTL bigger than we can represent in platform time units
    if (ttl > 0x7FFFFFFFUL / mDNSPlatformOneSecond)
        ttl = 0x7FFFFFFFUL / mDNSPlatformOneSecond;
    else if (ttl == 0)      // And Zero TTL is illegal
        ttl = DefaultTTLforRRType(rrtype);

    // Field Group 1: The actual information pertaining to this resource record
    rr->resrec.RecordType        = RecordType;
    rr->resrec.InterfaceID       = InterfaceID;
    rr->resrec.name              = &rr->namestorage;
    rr->resrec.rrtype            = rrtype;
    rr->resrec.rrclass           = kDNSClass_IN;
    rr->resrec.rroriginalttl     = ttl;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    rr->resrec.metadata          = NULL;
#else
    rr->resrec.rDNSServer        = mDNSNULL;
#endif
//	rr->resrec.rdlength          = MUST set by client and/or in mDNS_Register_internal
//	rr->resrec.rdestimate        = set in mDNS_Register_internal
//	rr->resrec.rdata             = MUST be set by client

    if (RDataStorage)
        rr->resrec.rdata = RDataStorage;
    else
    {
        rr->resrec.rdata = &rr->rdatastorage;
        rr->resrec.rdata->MaxRDLength = sizeof(RDataBody);
    }

    // Field Group 2: Persistent metadata for Authoritative Records
    rr->Additional1       = mDNSNULL;
    rr->Additional2       = mDNSNULL;
    rr->DependentOn       = mDNSNULL;
    rr->RRSet             = 0;
    rr->RecordCallback    = Callback;
    rr->RecordContext     = Context;

    rr->AutoTarget        = Target_Manual;
    rr->AllowRemoteQuery  = mDNSfalse;
    rr->ForceMCast        = mDNSfalse;

    rr->WakeUp            = zeroOwner;
    rr->AddressProxy      = zeroAddr;
    rr->TimeRcvd          = 0;
    rr->TimeExpire        = 0;
    rr->ARType            = artype;
    rr->AuthFlags         = 0;

    // Field Group 3: Transient state for Authoritative Records (set in mDNS_Register_internal)
    // Field Group 4: Transient uDNS state for Authoritative Records (set in mDNS_Register_internal)

    // For now, until the uDNS code is fully integrated, it's helpful to zero the uDNS state fields here too, just in case
    // (e.g. uDNS_RegisterService short-circuits the usual mDNS_Register_internal record registration calls, so a bunch
    // of fields don't get set up properly. In particular, if we don't zero rr->QueuedRData then the uDNS code crashes.)
    rr->state             = regState_Zero;
    rr->uselease          = 0;
    rr->expire            = 0;
    rr->Private           = 0;
    rr->updateid          = zeroID;
    rr->zone              = rr->resrec.name;
    rr->nta               = mDNSNULL;
    rr->tcp               = mDNSNULL;
    rr->OrigRData         = 0;
    rr->OrigRDLen         = 0;
    rr->InFlightRData     = 0;
    rr->InFlightRDLen     = 0;
    rr->QueuedRData       = 0;
    rr->QueuedRDLen       = 0;
    mDNSPlatformMemZero(&rr->NATinfo, sizeof(rr->NATinfo));
    rr->SRVChanged = mDNSfalse;
    rr->mState = mergeState_Zero;

    rr->namestorage.c[0]  = 0;      // MUST be set by client before calling mDNS_Register()
}

mDNSexport void mDNS_SetupQuestion(DNSQuestion *const q, const mDNSInterfaceID InterfaceID, const domainname *const name,
                                   const mDNSu16 qtype, mDNSQuestionCallback *const callback, void *const context)
{
    q->InterfaceID         = InterfaceID;
    q->flags               = 0;
    AssignDomainName(&q->qname, name);
    q->qtype               = qtype;
    q->qclass              = kDNSClass_IN;
    q->LongLived           = mDNSfalse;
    q->ExpectUnique        = (qtype != kDNSType_PTR);
    q->ForceMCast          = mDNSfalse;
    q->ReturnIntermed      = mDNSfalse;
    q->SuppressUnusable    = mDNSfalse;
    q->AppendSearchDomains = 0;
    q->TimeoutQuestion     = 0;
    q->WakeOnResolve       = 0;
    q->UseBackgroundTraffic = mDNSfalse;
    q->ProxyQuestion       = 0;
    q->pid                 = mDNSPlatformGetPID();
    q->euid                = 0;
    q->BlockedByPolicy     = mDNSfalse;
    q->ServiceID           = -1;
    q->QuestionCallback    = callback;
    q->QuestionContext     = context;
}

mDNSexport mDNSu32 RDataHashValue(const ResourceRecord *const rr)
{
    int len = rr->rdlength;
    const RDataBody2 *const rdb = (RDataBody2 *)rr->rdata->u.data;
    const mDNSu8 *ptr = rdb->data;
    mDNSu32 sum = 0;

    switch(rr->rrtype)
    {
    case kDNSType_NS:
    case kDNSType_MD:
    case kDNSType_MF:
    case kDNSType_CNAME:
    case kDNSType_MB:
    case kDNSType_MG:
    case kDNSType_MR:
    case kDNSType_PTR:
    case kDNSType_NSAP_PTR:
    case kDNSType_DNAME: return DomainNameHashValue(&rdb->name);

    case kDNSType_SOA:   return rdb->soa.serial  +
               rdb->soa.refresh +
               rdb->soa.retry   +
               rdb->soa.expire  +
               rdb->soa.min     +
               DomainNameHashValue(&rdb->soa.mname) +
               DomainNameHashValue(&rdb->soa.rname);

    case kDNSType_MX:
    case kDNSType_AFSDB:
    case kDNSType_RT:
    case kDNSType_KX:    return DomainNameHashValue(&rdb->mx.exchange);

    case kDNSType_MINFO:
    case kDNSType_RP:    return DomainNameHashValue(&rdb->rp.mbox)   + DomainNameHashValue(&rdb->rp.txt);

    case kDNSType_PX:    return DomainNameHashValue(&rdb->px.map822) + DomainNameHashValue(&rdb->px.mapx400);

    case kDNSType_SRV:   return DomainNameHashValue(&rdb->srv.target);

    case kDNSType_OPT:   return 0;      // OPT is a pseudo-RR container structure; makes no sense to compare

    case kDNSType_NSEC: {
        int dlen;
        dlen = DomainNameLength(&rdb->name);
        sum = DomainNameHashValue(&rdb->name);
        ptr += dlen;
        len -= dlen;
        fallthrough();
        /* FALLTHROUGH */
    }

    default:
    {
        int i;
        for (i=0; i+1 < len; i+=2)
        {
            sum += (((mDNSu32)(ptr[i])) << 8) | ptr[i+1];
            sum = (sum<<3) | (sum>>29);
        }
        if (i < len)
        {
            sum += ((mDNSu32)(ptr[i])) << 8;
        }
        return(sum);
    }
    }
}

// r1 has to be a full ResourceRecord including rrtype and rdlength
// r2 is just a bare RDataBody, which MUST be the same rrtype and rdlength as r1
mDNSexport mDNSBool SameRDataBody(const ResourceRecord *const r1, const RDataBody *const r2, DomainNameComparisonFn *samename)
{
    const RDataBody2 *const b1 = (RDataBody2 *)r1->rdata->u.data;
    const RDataBody2 *const b2 = (const RDataBody2 *)r2;
    switch(r1->rrtype)
    {
    case kDNSType_NS:
    case kDNSType_MD:
    case kDNSType_MF:
    case kDNSType_CNAME:
    case kDNSType_MB:
    case kDNSType_MG:
    case kDNSType_MR:
    case kDNSType_PTR:
    case kDNSType_NSAP_PTR:
    case kDNSType_DNAME: return(SameDomainName(&b1->name, &b2->name));

    case kDNSType_SOA:  return (mDNSBool)(   b1->soa.serial   == b2->soa.serial             &&
                                             b1->soa.refresh  == b2->soa.refresh            &&
                                             b1->soa.retry    == b2->soa.retry              &&
                                             b1->soa.expire   == b2->soa.expire             &&
                                             b1->soa.min      == b2->soa.min                &&
                                             samename(&b1->soa.mname, &b2->soa.mname) &&
                                             samename(&b1->soa.rname, &b2->soa.rname));

    case kDNSType_MX:
    case kDNSType_AFSDB:
    case kDNSType_RT:
    case kDNSType_KX:   return (mDNSBool)(   b1->mx.preference == b2->mx.preference &&
                                             samename(&b1->mx.exchange, &b2->mx.exchange));

    case kDNSType_MINFO:
    case kDNSType_RP:   return (mDNSBool)(   samename(&b1->rp.mbox, &b2->rp.mbox) &&
                                             samename(&b1->rp.txt,  &b2->rp.txt));

    case kDNSType_PX:   return (mDNSBool)(   b1->px.preference == b2->px.preference          &&
                                             samename(&b1->px.map822,  &b2->px.map822) &&
                                             samename(&b1->px.mapx400, &b2->px.mapx400));

    case kDNSType_SRV:  return (mDNSBool)(   b1->srv.priority == b2->srv.priority       &&
                                             b1->srv.weight   == b2->srv.weight         &&
                                             mDNSSameIPPort(b1->srv.port, b2->srv.port) &&
                                             samename(&b1->srv.target, &b2->srv.target));

    case kDNSType_OPT:  return mDNSfalse;       // OPT is a pseudo-RR container structure; makes no sense to compare
    case kDNSType_NSEC: {
        // If the "nxt" name changes in case, we want to delete the old
        // and store just the new one. If the caller passes in SameDomainCS for "samename",
        // we would return "false" when the only change between the two rdata is the case
        // change in "nxt".
        //
        // Note: rdlength of both the RData are same (ensured by the caller) and hence we can
        // use just r1->rdlength below

        int dlen1 = DomainNameLength(&b1->name);
        int dlen2 = DomainNameLength(&b2->name);
        return (mDNSBool)(dlen1 == dlen2 &&
                          samename(&b1->name, &b2->name) &&
                          mDNSPlatformMemSame(b1->data + dlen1, b2->data + dlen2, r1->rdlength - dlen1));
    }

    default:            return(mDNSPlatformMemSame(b1->data, b2->data, r1->rdlength));
    }
}

mDNSexport mDNSBool BitmapTypeCheck(const mDNSu8 *bmap, int bitmaplen, mDNSu16 type)
{
    int win, wlen;
    int wintype;

    // The window that this type belongs to. NSEC has 256 windows that
    // comprises of 256 types.
    wintype = type >> 8;

    while (bitmaplen > 0)
    {
        if (bitmaplen < 3)
        {
            LogInfo("BitmapTypeCheck: malformed nsec, bitmaplen %d short", bitmaplen);
            return mDNSfalse;
        }

        win = *bmap++;
        wlen = *bmap++;
        bitmaplen -= 2;
        if (bitmaplen < wlen || wlen < 1 || wlen > 32)
        {
            LogInfo("BitmapTypeCheck: malformed nsec, bitmaplen %d wlen %d, win %d", bitmaplen, wlen, win);
            return mDNSfalse;
        }
        if (win < 0 || win >= 256)
        {
            LogInfo("BitmapTypeCheck: malformed nsec, wlen %d", wlen);
            return mDNSfalse;
        }
        if (win == wintype)
        {
            // First byte in the window serves 0 to 7, the next one serves 8 to 15 and so on.
            // Calculate the right byte offset first.
            int boff = (type & 0xff ) >> 3;
            if (wlen <= boff)
                return mDNSfalse;
            // The last three bits values 0 to 7 corresponds to bit positions
            // within the byte.
            return (bmap[boff] & (0x80 >> (type & 7)));
        }
        else
        {
            // If the windows are ordered, then we could check to see
            // if wintype > win and then return early.
            bmap += wlen;
            bitmaplen -= wlen;
        }
    }
    return mDNSfalse;
}

// Don't call this function if the resource record is not NSEC. It will return false
// which means that the type does not exist.
mDNSexport mDNSBool RRAssertsExistence(const ResourceRecord *const rr, mDNSu16 type)
{
    const RDataBody2 *const rdb = (RDataBody2 *)rr->rdata->u.data;
    const mDNSu8 *nsec = rdb->data;
    int len, bitmaplen;
    const mDNSu8 *bmap;

    if (rr->rrtype != kDNSType_NSEC) return mDNSfalse;

    len = DomainNameLength(&rdb->name);

    bitmaplen = rr->rdlength - len;
    bmap = nsec + len;
    return (BitmapTypeCheck(bmap, bitmaplen, type));
}

// Don't call this function if the resource record is not NSEC. It will return false
// which means that the type exists.
mDNSexport mDNSBool RRAssertsNonexistence(const ResourceRecord *const rr, mDNSu16 type)
{
    if (rr->rrtype != kDNSType_NSEC) return mDNSfalse;

    return !RRAssertsExistence(rr, type);
}

mDNSexport mDNSBool RRTypeAnswersQuestionType(const ResourceRecord *const rr, const mDNSu16 qtype,
    const RRTypeAnswersQuestionTypeFlags flags)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    // This checks if the record is what the question requires:
    // 1. If the question does not enable DNSSEC, either "DNSSEC to be validated" nor "DNSSEC validated" record answers it.
    // 2. If the question enables DNSSEC, and it is not a duplicate question, it needs both "DNSSEC to be validated" nor "DNSSEC validated" records:
    //    a. Get "DNSSEC to be validated" to do DNSSEC validation.
    //    b. Get "DNSSEC validated" to return to the client.
    // 3. If the question enables DNSSEC, and it is a duplicate question, it only needs "DNSSEC validated" records:
    //    a. Does not need "DNSSEC to be validated" because the non-duplicate question will do the validation.
    //    b. Get "DNSSEC validated" to return to the client.
    const mDNSBool requiresRRToValidate = ((flags & kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRToValidate) != 0);
    const mDNSBool requiresValidatedRR = ((flags & kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRValidated) != 0);
    if (!resource_record_answers_dnssec_question_request_type(rr, requiresRRToValidate, requiresValidatedRR))
    {
        return mDNSfalse;
    }
#else
    (void) flags;
#endif

    // OPT should not answer any questions.
    if (rr->rrtype == kDNSType_OPT)
    {
        return mDNSfalse;
    }

    // CNAME answers any questions, except negative CNAME. (this function is not responsible to check that)
    if (rr->rrtype == kDNSType_CNAME)
    {
        return mDNStrue;
    }

    // The most usual case where the record type matches the question type.
    if (rr->rrtype == qtype)
    {
        return mDNStrue;
    }

    // If question asks for any DNS record type, then any record type can answer this question.
    if (qtype == kDNSQType_ANY)
    {
        return mDNStrue;
    }

    // If the mDNS NSEC record asserts the nonexistence of the question type, then it answers the question type
    // negatively.
    if (MULTICAST_NSEC(rr) && RRAssertsNonexistence(rr, qtype))
    {
        return mDNStrue;
    }

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    // The type covered of RRSIG should match the non-duplicate DNSSEC question type, because RRSIG will be used by it
    // to do DNSSEC validation.
    if (resource_record_as_rrsig_answers_dnssec_question_type(rr, qtype))
    {
        return mDNStrue;
    }
#endif

    return mDNSfalse;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
mDNSlocal mDNSBool RRMatchesQuestionService(const ResourceRecord *const rr, const DNSQuestion *const q)
{
    return mdns_cache_metadata_get_dns_service(rr->metadata) == q->dnsservice;
}
#endif

mDNSlocal mDNSBool RRIsResolvedBymDNS(const ResourceRecord *const rr)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    if (mdns_cache_metadata_get_dns_service(rr->metadata))
    {
        return mDNSfalse;
    }
#endif
    return (rr->InterfaceID != 0);
}

// ResourceRecordAnswersQuestion returns mDNStrue if the given resource record is a valid answer to the given question.
// SameNameRecordAnswersQuestion is the same, except it skips the expensive SameDomainName() call.
// SameDomainName() is generally cheap when the names don't match, but expensive when they do match,
// because it has to check all the way to the end of the names to be sure.
// In cases where we know in advance that the names match it's especially advantageous to skip the
// SameDomainName() call because that's precisely the time when it's most expensive and least useful.

mDNSlocal mDNSBool SameNameRecordAnswersQuestion(const ResourceRecord *const rr, mDNSBool isAuthRecord, const DNSQuestion *const q)
{
    // LocalOnly/P2P questions can be answered with AuthRecordAny in this function. LocalOnly/P2P records
    // are handled in LocalOnlyRecordAnswersQuestion
    if (LocalOnlyOrP2PInterface(rr->InterfaceID))
    {
        LogMsg("SameNameRecordAnswersQuestion: ERROR!! called with LocalOnly ResourceRecord %p, Question %p", rr->InterfaceID, q->InterfaceID);
        return mDNSfalse;
    }
    if (q->Suppressed && (!q->ForceCNAMEFollows || (rr->rrtype != kDNSType_CNAME)))
        return mDNSfalse;

    if (rr->InterfaceID &&
        q->InterfaceID && q->InterfaceID != mDNSInterface_LocalOnly &&
        rr->InterfaceID != q->InterfaceID) return(mDNSfalse);

#if MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)
    if (DNSQuestionUsesMDNSAlternativeService(q))
    {
        if (!RRMatchesQuestionService(rr, q))
        {
            return mDNSfalse;
        }
    }
    else
#endif
    {
        const mDNSBool resolvedBymDNS = RRIsResolvedBymDNS(rr);
        mDNSBool ismDNSQuestion = mDNSOpaque16IsZero(q->TargetQID);

        // If the record is resolved via the non-mDNS channel, the server or service used should match.
        if (!isAuthRecord && !resolvedBymDNS)
        {
            if (ismDNSQuestion)
            {
                return mDNSfalse;
            }
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
            if (!RRMatchesQuestionService(rr, q)) return(mDNSfalse);
#else
            const mDNSu32 idr = rr->rDNSServer ? rr->rDNSServer->resGroupID : 0;
            const mDNSu32 idq = q->qDNSServer ? q->qDNSServer->resGroupID : 0;
            if (idr != idq) return(mDNSfalse);
#endif
        }

        // mDNS records can only be used to answer mDNS questions.
        if (resolvedBymDNS && !ismDNSQuestion)
        {
            return mDNSfalse;
        }
    }

    // CNAME answers question of any type and a negative cache record should not prevent us from querying other
    // valid types at the same name.
    if (rr->rrtype == kDNSType_CNAME && rr->RecordType == kDNSRecordTypePacketNegative && rr->rrtype != q->qtype)
         return mDNSfalse;

    // RR type CNAME matches any query type. QTYPE ANY matches any RR type. QCLASS ANY matches any RR class.
    RRTypeAnswersQuestionTypeFlags flags = kRRTypeAnswersQuestionTypeFlagsNone;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    // Primary DNSSEC requestor is the non-duplicate DNSSEC question that does the DNSSEC validation, therefore, it needs
    // the "DNSSEC to be validated" record. (It is also DNSSEC requestor, see below)
    if (dns_question_is_primary_dnssec_requestor(q))
    {
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRToValidate;
    }
    // DNSSEC requestor is the DNSSEC question that needs DNSSEC validated result.
    if (dns_question_is_dnssec_requestor(q))
    {
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRValidated;
    }
#endif

    const mDNSBool typeMatches = RRTypeAnswersQuestionType(rr, q->qtype, flags);
    if (!typeMatches)
    {
        return(mDNSfalse);
    }

    if (rr->rrclass != q->qclass && q->qclass != kDNSQClass_ANY) return(mDNSfalse);


    return(mDNStrue);
}

mDNSexport mDNSBool SameNameCacheRecordAnswersQuestion(const CacheRecord *const cr, const DNSQuestion *const q)
{
    return SameNameRecordAnswersQuestion(&cr->resrec, mDNSfalse, q);
}

mDNSlocal mDNSBool RecordAnswersQuestion(const ResourceRecord *const rr, mDNSBool isAuthRecord, const DNSQuestion *const q)
{
    if (!SameNameRecordAnswersQuestion(rr, isAuthRecord, q))
        return mDNSfalse;

    return(rr->namehash == q->qnamehash && SameDomainName(rr->name, &q->qname));
}

mDNSexport mDNSBool ResourceRecordAnswersQuestion(const ResourceRecord *const rr, const DNSQuestion *const q)
{
    return RecordAnswersQuestion(rr, mDNSfalse, q);
}

mDNSexport mDNSBool AuthRecordAnswersQuestion(const AuthRecord *const ar, const DNSQuestion *const q)
{
    return RecordAnswersQuestion(&ar->resrec, mDNStrue, q);
}

mDNSexport mDNSBool CacheRecordAnswersQuestion(const CacheRecord *const cr, const DNSQuestion *const q)
{
    return RecordAnswersQuestion(&cr->resrec, mDNSfalse, q);
}

// We have a separate function to handle LocalOnly AuthRecords because they can be created with
// a valid InterfaceID (e.g., scoped /etc/hosts) and can be used to answer unicast questions unlike
// multicast resource records (which has a valid InterfaceID) which can't be used to answer
// unicast questions. ResourceRecordAnswersQuestion/SameNameRecordAnswersQuestion can't tell whether
// a resource record is multicast or LocalOnly by just looking at the ResourceRecord because
// LocalOnly records are truly identified by ARType in the AuthRecord.  As P2P and LocalOnly record
// are kept in the same hash table, we use the same function to make it easy for the callers when
// they walk the hash table to answer LocalOnly/P2P questions
//
mDNSexport mDNSBool LocalOnlyRecordAnswersQuestion(AuthRecord *const ar, const DNSQuestion *const q)
{
    ResourceRecord *rr = &ar->resrec;

    // mDNSInterface_Any questions can be answered with LocalOnly/P2P records in this function. AuthRecord_Any
    // records are handled in ResourceRecordAnswersQuestion/SameNameRecordAnswersQuestion
    if (RRAny(ar))
    {
        LogMsg("LocalOnlyRecordAnswersQuestion: ERROR!! called with regular AuthRecordAny %##s", rr->name->c);
        return mDNSfalse;
    }

    // Questions with mDNSInterface_LocalOnly InterfaceID should be answered with all resource records that are
    // *local* to the machine. These include resource records that have InterfaceID set to mDNSInterface_LocalOnly,
    // mDNSInterface_Any and any other real InterfaceID. Hence, LocalOnly questions should not be checked against
    // the InterfaceID in the resource record.

    if (rr->InterfaceID &&
        q->InterfaceID != mDNSInterface_LocalOnly &&
        ((q->InterfaceID && rr->InterfaceID != q->InterfaceID) ||
        (!q->InterfaceID && !LocalOnlyOrP2PInterface(rr->InterfaceID)))) return(mDNSfalse);

    // Entries in /etc/hosts are added as LocalOnly resource records. The LocalOnly resource records
    // may have a scope e.g., fe80::1%en0. The question may be scoped or not: the InterfaceID may be set
    // to mDNSInterface_Any, mDNSInterface_LocalOnly or a real InterfaceID (scoped).
    //
    // 1) Question: Any, LocalOnly Record: no scope. This question should be answered with this record.
    //
    // 2) Question: Any, LocalOnly Record: scoped.  This question should be answered with the record because
    //    traditionally applications never specify scope e.g., getaddrinfo, but need to be able
    //    to get to /etc/hosts entries.
    //
    // 3) Question: Scoped (LocalOnly or InterfaceID), LocalOnly Record: no scope. This is the inverse of (2).
    //    If we register a LocalOnly record, we need to answer a LocalOnly question. If the /etc/hosts has a
    //    non scoped entry, it may not make sense to answer a scoped question. But we can't tell these two
    //    cases apart. As we currently answer LocalOnly question with LocalOnly record, we continue to do so.
    //
    // 4) Question: Scoped (LocalOnly or InterfaceID), LocalOnly Record: scoped. LocalOnly questions should be
    //    answered with any resource record where as if it has a valid InterfaceID, the scope should match.
    //
    // (1) and (2) is bypassed because we check for a non-NULL InterfaceID above. For (3), the InterfaceID is NULL
    // and hence bypassed above. For (4) we bypassed LocalOnly questions and checked the scope of the record
    // against the question.
    //
    // For P2P, InterfaceIDs of the question and the record should match.

    // If ResourceRecord received via multicast, but question was unicast, then shouldn't use record to answer this question.
    // LocalOnly authoritative answers are exempt. LocalOnly authoritative answers are used for /etc/host entries.
    // We don't want a local process to be able to create a fake LocalOnly address record for "www.bigbank.com" which would then
    // cause other applications (e.g. Safari) to connect to the wrong address. The rpc to register records filters out records
    // with names that don't end in local and have mDNSInterface_LocalOnly set.
    //
    // Note: The check is bypassed for LocalOnly and for P2P it is not needed as only .local records are registered and for
    // a question to match its names, it also has to end in .local and that question can't be a unicast question (See
    // Question_uDNS macro and its usage). As P2P does not enforce .local only registrations we still make this check
    // and also makes it future proof.

    if (ar->ARType != AuthRecordLocalOnly && rr->InterfaceID && !mDNSOpaque16IsZero(q->TargetQID)) return(mDNSfalse);

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    // No local only record can answer DNSSEC question.
    if (dns_question_is_dnssec_requestor(q))
    {
        return mDNSfalse;
    }
#endif

    // RR type CNAME matches any query type. QTYPE ANY matches any RR type. QCLASS ANY matches any RR class.
    RRTypeAnswersQuestionTypeFlags flags = kRRTypeAnswersQuestionTypeFlagsNone;
    const mDNSBool typeMatches = RRTypeAnswersQuestionType(rr, q->qtype, flags);
    if (!typeMatches)
    {
        return mDNSfalse;
    }

    if (rr->rrclass != q->qclass && q->qclass != kDNSQClass_ANY) return(mDNSfalse);

    return(rr->namehash == q->qnamehash && SameDomainName(rr->name, &q->qname));
}

mDNSexport mDNSBool AnyTypeRecordAnswersQuestion(const AuthRecord *const ar, const DNSQuestion *const q)
{
    const ResourceRecord *const rr = &ar->resrec;
    // LocalOnly/P2P questions can be answered with AuthRecordAny in this function. LocalOnly/P2P records
    // are handled in LocalOnlyRecordAnswersQuestion
    if (LocalOnlyOrP2PInterface(rr->InterfaceID))
    {
        LogMsg("AnyTypeRecordAnswersQuestion: ERROR!! called with LocalOnly ResourceRecord %p, Question %p", rr->InterfaceID, q->InterfaceID);
        return mDNSfalse;
    }
    if (rr->InterfaceID &&
        q->InterfaceID && q->InterfaceID != mDNSInterface_LocalOnly &&
        rr->InterfaceID != q->InterfaceID) return(mDNSfalse);

#if MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)
    if (DNSQuestionUsesMDNSAlternativeService(q))
    {
        if (!RRMatchesQuestionService(rr, q))
        {
            return mDNSfalse;
        }
    }
    else
#endif
    {
        const mDNSBool resolvedByMDNS = RRIsResolvedBymDNS(rr);
        // Resource record received via non-mDNS channel, the server or service should match.
        // Note that Auth Records are normally setup with NULL InterfaceID and
        // both the DNSServers are assumed to be NULL in that case
        if (!resolvedByMDNS)
        {
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
            if (!RRMatchesQuestionService(rr, q)) return(mDNSfalse);
#else
            const mDNSu32 idr = rr->rDNSServer ? rr->rDNSServer->resGroupID : 0;
            const mDNSu32 idq = q->qDNSServer ? q->qDNSServer->resGroupID : 0;
            if (idr != idq) return(mDNSfalse);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, RANDOM_AWDL_HOSTNAME)
            if (!mDNSPlatformValidRecordForInterface(ar, q->InterfaceID)) return(mDNSfalse);
#endif
        }

        // mDNS records can only be used to answer mDNS questions.
        const mDNSBool isMDNSQuestion = mDNSOpaque16IsZero(q->TargetQID);
        if (resolvedByMDNS && !isMDNSQuestion)
        {
            return mDNSfalse;
        }
    }

    if (rr->rrclass != q->qclass && q->qclass != kDNSQClass_ANY) return(mDNSfalse);

    return(rr->namehash == q->qnamehash && SameDomainName(rr->name, &q->qname));
}

// This is called with both unicast resource record and multicast resource record. The question that
// received the unicast response could be the regular unicast response from a DNS server or a response
// to a mDNS QU query. The main reason we need this function is that we can't compare DNSServers between the
// question and the resource record because the resource record is not completely initialized in
// mDNSCoreReceiveResponse when this function is called.
mDNSexport mDNSBool ResourceRecordAnswersUnicastResponse(const ResourceRecord *const rr, const DNSQuestion *const q)
{
    if (q->Suppressed)
        return mDNSfalse;

    // For resource records created using multicast or DNS push, the InterfaceIDs have to match.
    if (rr->InterfaceID &&
        q->InterfaceID && rr->InterfaceID != q->InterfaceID) return(mDNSfalse);

    // If record is resolved by mDNS, but question is non-mDNS, then should not use it to answer this question.
    const mDNSBool resolvedByMDNS = RRIsResolvedBymDNS(rr);
    const mDNSBool isMDNSQuestion = mDNSOpaque16IsZero(q->TargetQID);
    if (resolvedByMDNS && !isMDNSQuestion)
    {
        return mDNSfalse;
    }

    // RR type CNAME matches any query type. QTYPE ANY matches any RR type. QCLASS ANY matches any RR class.
    RRTypeAnswersQuestionTypeFlags flags = kRRTypeAnswersQuestionTypeFlagsNone;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    // Thus routine is only used for the records received from internet. Right now, we will not receive DNSSEC validated
    // record from wire (ODoH will probably give us validated records in the future?). Therefore, we only need to check
    // if the record answers primary DNSSEC requestor and can be used for validation.
    if (dns_question_is_primary_dnssec_requestor(q))
    {
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRToValidate;
    }
#endif

    const mDNSBool typeMatches = RRTypeAnswersQuestionType(rr, q->qtype, flags);
    if (!typeMatches)
    {
        return(mDNSfalse);
    }

    if (rr->rrclass != q->qclass && q->qclass != kDNSQClass_ANY) return(mDNSfalse);

    return(rr->namehash == q->qnamehash && SameDomainName(rr->name, &q->qname));
}

mDNSexport mDNSu16 GetRDLength(const ResourceRecord *const rr, mDNSBool estimate)
{
    const RDataBody2 *const rd = (RDataBody2 *)rr->rdata->u.data;
    const domainname *const name = estimate ? rr->name : mDNSNULL;
    if (rr->rrclass == kDNSQClass_ANY) return(rr->rdlength);    // Used in update packets to mean "Delete An RRset" (RFC 2136)
    else switch (rr->rrtype)
        {
        case kDNSType_A:    return(sizeof(rd->ipv4));

        case kDNSType_NS:
        case kDNSType_CNAME:
        case kDNSType_PTR:
        case kDNSType_DNAME: return(CompressedDomainNameLength(&rd->name, name));

        case kDNSType_SOA:  return (mDNSu16)(CompressedDomainNameLength(&rd->soa.mname, name) +
                                             CompressedDomainNameLength(&rd->soa.rname, name) +
                                             5 * sizeof(mDNSOpaque32));

        case kDNSType_NULL:
        case kDNSType_TSIG:
        case kDNSType_TXT:
        case kDNSType_X25:
        case kDNSType_ISDN:
        case kDNSType_LOC:
        case kDNSType_DHCID: return(rr->rdlength); // Not self-describing, so have to just trust rdlength

        case kDNSType_HINFO: return (mDNSu16)(2 + (int)rd->data[0] + (int)rd->data[1 + (int)rd->data[0]]);

        case kDNSType_MX:
        case kDNSType_AFSDB:
        case kDNSType_RT:
        case kDNSType_KX:   return (mDNSu16)(2 + CompressedDomainNameLength(&rd->mx.exchange, name));

        case kDNSType_MINFO:
        case kDNSType_RP:   return (mDNSu16)(CompressedDomainNameLength(&rd->rp.mbox, name) +
                                             CompressedDomainNameLength(&rd->rp.txt, name));

        case kDNSType_PX:   return (mDNSu16)(2 + CompressedDomainNameLength(&rd->px.map822, name) +
                                             CompressedDomainNameLength(&rd->px.mapx400, name));

        case kDNSType_AAAA: return(sizeof(rd->ipv6));

        case kDNSType_SRV:  return (mDNSu16)(6 + CompressedDomainNameLength(&rd->srv.target, name));

        case kDNSType_OPT:  return(rr->rdlength);

        case kDNSType_NSEC:
        {
            const domainname *const next = (const domainname *)rd->data;
            const int dlen = DomainNameLength(next);
            if (MULTICAST_NSEC(rr))
            {
                return (mDNSu16)((estimate ? 2 : dlen) + rr->rdlength - dlen);
            }
            else
            {
                // Unicast NSEC does not do name compression. Therefore, we can return `rdlength` directly.
                // See [RFC 4034 4.1.1.](https://datatracker.ietf.org/doc/html/rfc4034#section-4.1.1).
                return rr->rdlength;
            }
        }

        case kDNSType_TSR: return(sizeof(rd->tsr_value));

        default:            debugf("Warning! Don't know how to get length of resource type %d", rr->rrtype);
            return(rr->rdlength);
        }
}

// When a local client registers (or updates) a record, we use this routine to do some simple validation checks
// to help reduce the risk of bogus malformed data on the network
mDNSexport mDNSBool ValidateRData(const mDNSu16 rrtype, const mDNSu16 rdlength, const RData *const rd)
{
    mDNSu16 len;

    switch(rrtype)
    {
    case kDNSType_A:    return(rdlength == sizeof(mDNSv4Addr));

    case kDNSType_NS:       // Same as PTR
    case kDNSType_MD:       // Same as PTR
    case kDNSType_MF:       // Same as PTR
    case kDNSType_CNAME:    // Same as PTR
    //case kDNSType_SOA not checked
    case kDNSType_MB:       // Same as PTR
    case kDNSType_MG:       // Same as PTR
    case kDNSType_MR:       // Same as PTR
    //case kDNSType_NULL not checked (no specified format, so always valid)
    //case kDNSType_WKS not checked
    case kDNSType_PTR:  len = DomainNameLengthLimit(&rd->u.name, rd->u.data + rdlength);
        return(len <= MAX_DOMAIN_NAME && rdlength == len);

    case kDNSType_HINFO:    // Same as TXT (roughly)
    case kDNSType_MINFO:    // Same as TXT (roughly)
    case kDNSType_TXT:  if (!rdlength) return(mDNSfalse);     // TXT record has to be at least one byte (RFC 1035)
        {
            const mDNSu8 *ptr = rd->u.txt.c;
            const mDNSu8 *end = rd->u.txt.c + rdlength;
            while (ptr < end) ptr += 1 + ptr[0];
            return (ptr == end);
        }

    case kDNSType_AAAA: return(rdlength == sizeof(mDNSv6Addr));

    case kDNSType_MX:       // Must be at least two-byte preference, plus domainname
                            // Call to DomainNameLengthLimit() implicitly enforces both requirements for us
        len = DomainNameLengthLimit(&rd->u.mx.exchange, rd->u.data + rdlength);
        return(len <= MAX_DOMAIN_NAME && rdlength == 2+len);

    case kDNSType_SRV:      // Must be at least priority+weight+port, plus domainname
                            // Call to DomainNameLengthLimit() implicitly enforces both requirements for us
        len = DomainNameLengthLimit(&rd->u.srv.target, rd->u.data + rdlength);
        return(len <= MAX_DOMAIN_NAME && rdlength == 6+len);

    //case kDNSType_NSEC not checked

    default:            return(mDNStrue);       // Allow all other types without checking
    }
}

mDNSexport const mDNSu8 * ResourceRecordGetRDataBytesPointer(const ResourceRecord *const rr,
    mDNSu8 * const bytesBuffer, const mDNSu16 bufferSize, mDNSu16 *const outRDataLen, mStatus *const outError)
{
    mStatus err;
    const mDNSu8 *rdataBytes = mDNSNULL;
    mDNSu16 rdataLen = 0;
    switch (rr->rrtype)
    {
        case kDNSType_SOA:
        case kDNSType_MX:
        case kDNSType_AFSDB:
        case kDNSType_RT:
        case kDNSType_RP:
        case kDNSType_SRV:
        case kDNSType_PX:
        case kDNSType_KX:
        case kDNSType_OPT:
        case kDNSType_NSEC:
        case kDNSType_TSR:
        {
            const mDNSu8 *const rdataBytesEnd = putRData(mDNSNULL, bytesBuffer, bytesBuffer + bufferSize, rr);
            mdns_require_action_quiet(rdataBytesEnd && (rdataBytesEnd > bytesBuffer), exit, err = mStatus_BadParamErr);

            rdataBytes = bytesBuffer;
            rdataLen = (rdataBytesEnd - bytesBuffer);
            break;
        }
        default:
            rdataBytes = rr->rdata->u.data;
            rdataLen = rr->rdlength;
            break;
    }
    err = mStatus_NoError;

exit:
    mdns_assign(outRDataLen, rdataLen);
    mdns_assign(outError, err);
    return rdataBytes;
}

// ***************************************************************************
// MARK: - DNS Message Creation Functions

mDNSexport void InitializeDNSMessage(DNSMessageHeader *h, mDNSOpaque16 id, mDNSOpaque16 flags)
{
    h->id             = id;
    h->flags          = flags;
    h->numQuestions   = 0;
    h->numAnswers     = 0;
    h->numAuthorities = 0;
    h->numAdditionals = 0;
}

#endif // !STANDALONE

mDNSexport const mDNSu8 *FindCompressionPointer(const mDNSu8 *const base, const mDNSu8 *const end, const mDNSu8 *const domname)
{
    const mDNSu8 *result = end - *domname - 1;

    if (*domname == 0) return(mDNSNULL);    // There's no point trying to match just the root label

    // This loop examines each possible starting position in packet, starting end of the packet and working backwards
    while (result >= base)
    {
        // If the length byte and first character of the label match, then check further to see
        // if this location in the packet will yield a useful name compression pointer.
        if (result[0] == domname[0] && result[1] == domname[1])
        {
            const mDNSu8 *name = domname;
            const mDNSu8 *targ = result;
            while (targ + *name < end)
            {
                // First see if this label matches
                int i;
                const mDNSu8 *pointertarget;
                for (i=0; i <= *name; i++) if (targ[i] != name[i]) break;
                if (i <= *name) break;                          // If label did not match, bail out
                targ += 1 + *name;                              // Else, did match, so advance target pointer
                name += 1 + *name;                              // and proceed to check next label
                if (*name == 0 && *targ == 0) return(result);   // If no more labels, we found a match!
                if (*name == 0) break;                          // If no more labels to match, we failed, so bail out

                // The label matched, so now follow the pointer (if appropriate) and then see if the next label matches
                if (targ[0] < 0x40) continue;                   // If length value, continue to check next label
                if (targ[0] < 0xC0) break;                      // If 40-BF, not valid
                if (targ+1 >= end) break;                       // Second byte not present!
                pointertarget = base + (((mDNSu16)(targ[0] & 0x3F)) << 8) + targ[1];
                if (targ < pointertarget) break;                // Pointertarget must point *backwards* in the packet
                if (pointertarget[0] >= 0x40) break;            // Pointertarget must point to a valid length byte
                targ = pointertarget;
            }
        }
        result--;   // We failed to match at this search position, so back up the tentative result pointer and try again
    }
    return(mDNSNULL);
}

// domainname is a fully-qualified name (i.e. assumed to be ending in a dot, even if it doesn't)
// msg points to the message we're building (pass mDNSNULL if we don't want to use compression pointers)
// end points to the end of the message so far
// ptr points to where we want to put the name
// limit points to one byte past the end of the buffer that we must not overrun
// domainname is the name to put
mDNSexport mDNSu8 *putDomainNameAsLabels(const DNSMessage *const msg,
                                         mDNSu8 *ptr, const mDNSu8 *const limit, const domainname *const name)
{
    const mDNSu8 *const base        = (const mDNSu8 *)msg;
    const mDNSu8 *      np          = name->c;
    const mDNSu8 *const max         = name->c + MAX_DOMAIN_NAME;    // Maximum that's valid
    const mDNSu8 *      pointer     = mDNSNULL;
    const mDNSu8 *const searchlimit = ptr;

    if (!ptr) { LogMsg("putDomainNameAsLabels %##s ptr is null", name->c); return(mDNSNULL); }

    if (!*np)       // If just writing one-byte root label, make sure we have space for that
    {
        if (ptr >= limit) return(mDNSNULL);
    }
    else            // else, loop through writing labels and/or a compression offset
    {
        do  {
            if (*np > MAX_DOMAIN_LABEL)
            { LogMsg("Malformed domain name %##s (label more than 63 bytes)", name->c); return(mDNSNULL); }

            // This check correctly allows for the final trailing root label:
            // e.g.
            // Suppose our domain name is exactly 256 bytes long, including the final trailing root label.
            // Suppose np is now at name->c[249], and we're about to write our last non-null label ("local").
            // We know that max will be at name->c[256]
            // That means that np + 1 + 5 == max - 1, so we (just) pass the "if" test below, write our
            // six bytes, then exit the loop, write the final terminating root label, and the domain
            // name we've written is exactly 256 bytes long, exactly at the correct legal limit.
            // If the name is one byte longer, then we fail the "if" test below, and correctly bail out.
            if (np + 1 + *np >= max)
            { LogMsg("Malformed domain name %##s (more than 256 bytes)", name->c); return(mDNSNULL); }

            if (base) pointer = FindCompressionPointer(base, searchlimit, np);
            if (pointer)                    // Use a compression pointer if we can
            {
                const mDNSu16 offset = (mDNSu16)(pointer - base);
                if (ptr+2 > limit) return(mDNSNULL);    // If we don't have two bytes of space left, give up
                *ptr++ = (mDNSu8)(0xC0 | (offset >> 8));
                *ptr++ = (mDNSu8)(        offset &  0xFF);
                return(ptr);
            }
            else                            // Else copy one label and try again
            {
                int i;
                mDNSu8 len = *np++;
                // If we don't at least have enough space for this label *plus* a terminating zero on the end, give up
                if (ptr + 1 + len >= limit) return(mDNSNULL);
                *ptr++ = len;
                for (i=0; i<len; i++) *ptr++ = *np++;
            }
        } while (*np);                      // While we've got characters remaining in the name, continue
    }

    *ptr++ = 0;     // Put the final root label
    return(ptr);
}

#ifndef STANDALONE

mDNSlocal mDNSu8 *putVal16(mDNSu8 *ptr, mDNSu16 val)
{
    ptr[0] = (mDNSu8)((val >> 8 ) & 0xFF);
    ptr[1] = (mDNSu8)((val      ) & 0xFF);
    return ptr + sizeof(mDNSOpaque16);
}

mDNSlocal mDNSu8 *putVal32(mDNSu8 *ptr, mDNSu32 val)
{
    ptr[0] = (mDNSu8)((val >> 24) & 0xFF);
    ptr[1] = (mDNSu8)((val >> 16) & 0xFF);
    ptr[2] = (mDNSu8)((val >>  8) & 0xFF);
    ptr[3] = (mDNSu8)((val      ) & 0xFF);
    return ptr + sizeof(mDNSu32);
}

// Copy the RDATA information. The actual in memory storage for the data might be bigger than what the rdlength
// says. Hence, the only way to copy out the data from a resource record is to use putRData.
// msg points to the message we're building (pass mDNSNULL for "msg" if we don't want to use compression pointers)
mDNSexport mDNSu8 *putRData(const DNSMessage *const msg, mDNSu8 *ptr, const mDNSu8 *const limit, const ResourceRecord *const rr)
{
    const RDataBody2 *const rdb = (RDataBody2 *)rr->rdata->u.data;
    switch (rr->rrtype)
    {
    case kDNSType_A:    if (rr->rdlength != 4)
        { debugf("putRData: Illegal length %d for kDNSType_A", rr->rdlength); return(mDNSNULL); }
        if (ptr + 4 > limit) return(mDNSNULL);
        *ptr++ = rdb->ipv4.b[0];
        *ptr++ = rdb->ipv4.b[1];
        *ptr++ = rdb->ipv4.b[2];
        *ptr++ = rdb->ipv4.b[3];
        return(ptr);

    case kDNSType_NS:
    case kDNSType_CNAME:
    case kDNSType_PTR:
    case kDNSType_DNAME: return(putDomainNameAsLabels(msg, ptr, limit, &rdb->name));

    case kDNSType_SOA:  ptr = putDomainNameAsLabels(msg, ptr, limit, &rdb->soa.mname);
        if (!ptr) return(mDNSNULL);
        ptr = putDomainNameAsLabels(msg, ptr, limit, &rdb->soa.rname);
        if (!ptr || ptr + 20 > limit) return(mDNSNULL);
        ptr = putVal32(ptr, rdb->soa.serial);
        ptr = putVal32(ptr, rdb->soa.refresh);
        ptr = putVal32(ptr, rdb->soa.retry);
        ptr = putVal32(ptr, rdb->soa.expire);
        ptr = putVal32(ptr, rdb->soa.min);
        return(ptr);

    case kDNSType_NULL:
    case kDNSType_HINFO:
    case kDNSType_TSIG:
    case kDNSType_TXT:
    case kDNSType_X25:
    case kDNSType_ISDN:
    case kDNSType_LOC:
    case kDNSType_DHCID: if (ptr + rr->rdlength > limit) return(mDNSNULL);
        mDNSPlatformMemCopy(ptr, rdb->data, rr->rdlength);
        return(ptr + rr->rdlength);

    case kDNSType_MX:
    case kDNSType_AFSDB:
    case kDNSType_RT:
    case kDNSType_KX:   if (ptr + 3 > limit) return(mDNSNULL);
        ptr = putVal16(ptr, rdb->mx.preference);
        return(putDomainNameAsLabels(msg, ptr, limit, &rdb->mx.exchange));

    case kDNSType_RP:   ptr = putDomainNameAsLabels(msg, ptr, limit, &rdb->rp.mbox);
        if (!ptr) return(mDNSNULL);
        ptr = putDomainNameAsLabels(msg, ptr, limit, &rdb->rp.txt);
        return(ptr);

    case kDNSType_PX:   if (ptr + 5 > limit) return(mDNSNULL);
        ptr = putVal16(ptr, rdb->px.preference);
        ptr = putDomainNameAsLabels(msg, ptr, limit, &rdb->px.map822);
        if (!ptr) return(mDNSNULL);
        ptr = putDomainNameAsLabels(msg, ptr, limit, &rdb->px.mapx400);
        return(ptr);

    case kDNSType_AAAA: if (rr->rdlength != sizeof(rdb->ipv6))
        { debugf("putRData: Illegal length %d for kDNSType_AAAA", rr->rdlength); return(mDNSNULL); }
        if (ptr + sizeof(rdb->ipv6) > limit) return(mDNSNULL);
        mDNSPlatformMemCopy(ptr, &rdb->ipv6, sizeof(rdb->ipv6));
        return(ptr + sizeof(rdb->ipv6));

    case kDNSType_SRV:  if (ptr + 7 > limit) return(mDNSNULL);
        *ptr++ = (mDNSu8)(rdb->srv.priority >> 8);
        *ptr++ = (mDNSu8)(rdb->srv.priority &  0xFF);
        *ptr++ = (mDNSu8)(rdb->srv.weight   >> 8);
        *ptr++ = (mDNSu8)(rdb->srv.weight   &  0xFF);
        *ptr++ = rdb->srv.port.b[0];
        *ptr++ = rdb->srv.port.b[1];
        return(putDomainNameAsLabels(msg, ptr, limit, &rdb->srv.target));

    case kDNSType_TSR:  {
            // tsr timestamp on wire is relative time since received.
            mDNSs32 tsr_relative = mDNSPlatformContinuousTimeSeconds() - rdb->tsr_value;
            ptr = putVal32(ptr, tsr_relative);
            return(ptr);
        }

    case kDNSType_OPT:  {
        int len = 0;
        const rdataOPT *opt;
        const rdataOPT *const end = (const rdataOPT *)&rr->rdata->u.data[rr->rdlength];
        for (opt = &rr->rdata->u.opt[0]; opt < end; opt++)
            len += DNSOpt_Data_Space(opt);
        if (ptr + len > limit)
        {
            LogMsg("ERROR: putOptRData - out of space");
            return mDNSNULL;
        }
        for (opt = &rr->rdata->u.opt[0]; opt < end; opt++)
        {
            const int space = DNSOpt_Data_Space(opt);
            ptr = putVal16(ptr, opt->opt);
            ptr = putVal16(ptr, (mDNSu16)space - 4);
            switch (opt->opt)
            {
            case kDNSOpt_LLQ:
                ptr = putVal16(ptr, opt->u.llq.vers);
                ptr = putVal16(ptr, opt->u.llq.llqOp);
                ptr = putVal16(ptr, opt->u.llq.err);
                mDNSPlatformMemCopy(ptr, opt->u.llq.id.b, 8);                          // 8-byte id
                ptr += 8;
                ptr = putVal32(ptr, opt->u.llq.llqlease);
                break;
            case kDNSOpt_Lease:
                ptr = putVal32(ptr, opt->u.updatelease);
                break;
            case kDNSOpt_Owner:
                *ptr++ = opt->u.owner.vers;
                *ptr++ = opt->u.owner.seq;
                mDNSPlatformMemCopy(ptr, opt->u.owner.HMAC.b, 6);                          // 6-byte Host identifier
                ptr += 6;
                if (space >= DNSOpt_OwnerData_ID_Wake_Space)
                {
                    mDNSPlatformMemCopy(ptr, opt->u.owner.IMAC.b, 6);                           // 6-byte interface MAC
                    ptr += 6;
                    if (space > DNSOpt_OwnerData_ID_Wake_Space)
                    {
                        mDNSPlatformMemCopy(ptr, opt->u.owner.password.b, space - DNSOpt_OwnerData_ID_Wake_Space);
                        ptr += space - DNSOpt_OwnerData_ID_Wake_Space;
                    }
                }
                break;
            case kDNSOpt_Trace:
                *ptr++ = opt->u.tracer.platf;
                ptr    = putVal32(ptr, opt->u.tracer.mDNSv);
                break;
            case kDNSOpt_TSR:
                {
                    mDNSs32 tsr_relative = mDNSPlatformContinuousTimeSeconds() - opt->u.tsr.timeStamp;
                    ptr = putVal32(ptr, tsr_relative);
                    ptr = putVal32(ptr, opt->u.tsr.hostkeyHash);
                    ptr = putVal16(ptr, opt->u.tsr.recIndex);
                }
                break;
            default:
                break;
            }
        }
        return ptr;
    }

    case kDNSType_NSEC: {
        // For NSEC records, rdlength represents the exact number of bytes
        // of in memory storage.
        const mDNSu8 *nsec = (const mDNSu8 *)rdb->data;
        const domainname *name = (const domainname *)nsec;
        const int dlen = DomainNameLength(name);
        nsec += dlen;
        // This function is called when we are sending a NSEC record as part of mDNS,
        // or to copy the data to any other buffer needed which could be a mDNS or uDNS
        // NSEC record. The only time compression is used that when we are sending it
        // in mDNS (indicated by non-NULL "msg") and hence we handle mDNS case
        // separately.
        if (MULTICAST_NSEC(rr))
        {
            mDNSu8 *save = ptr;
            int i, j, wlen;
            wlen = *(nsec + 1);
            nsec += 2;                     // Skip the window number and len

            // For our simplified use of NSEC synthetic records:
            //
            // nextname is always the record's own name,
            // the block number is always 0,
            // the count byte is a value in the range 1-32,
            // followed by the 1-32 data bytes
            //
            // Note: When we send the NSEC record in mDNS, the window size is set to 32.
            // We need to find out what the last non-NULL byte is.  If we are copying out
            // from an RDATA, we have the right length. As we need to handle both the case,
            // we loop to find the right value instead of blindly using len to copy.

            for (i=wlen; i>0; i--) if (nsec[i-1]) break;

            ptr = putDomainNameAsLabels(msg, ptr, limit, rr->name);
            if (!ptr)
            {
                goto mdns_nsec_exit;
            }
            if (i)                          // Only put a block if at least one type exists for this name
            {
                if (ptr + 2 + i > limit)
                {
                    ptr = mDNSNULL;
                    goto mdns_nsec_exit;
                }
                *ptr++ = 0;
                *ptr++ = (mDNSu8)i;
                for (j=0; j<i; j++) *ptr++ = nsec[j];
            }
        mdns_nsec_exit:
            if (!ptr)
            {
                LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEBUG,
                    "The mDNS message does not have enough space for the NSEC record, will add it to the next message (This is not an error message) -- "
                    "remaining space: %ld, NSEC name: " PRI_DM_NAME, limit - save, DM_NAME_PARAM(rr->name));
            }
            return ptr;
        }
        else
        {
            int win, wlen;
            int len = rr->rdlength - dlen;

            // Sanity check whether the bitmap is good
            while (len)
            {
                if (len < 3)
                { LogMsg("putRData: invalid length %d", len); return mDNSNULL; }

                win = *nsec++;
                wlen = *nsec++;
                len -= 2;
                if (len < wlen || wlen < 1 || wlen > 32)
                { LogMsg("putRData: invalid window length %d", wlen); return mDNSNULL; }
                if (win < 0 || win >= 256)
                { LogMsg("putRData: invalid window %d", win); return mDNSNULL; }

                nsec += wlen;
                len -= wlen;
            }
            if (ptr + rr->rdlength > limit) { LogMsg("putRData: NSEC rdlength beyond limit %##s (%s), ptr %p, rdlength %d, limit %p", rr->name->c, DNSTypeName(rr->rrtype), ptr, rr->rdlength, limit); return(mDNSNULL);}

            // No compression allowed for "nxt", just copy the data.
            mDNSPlatformMemCopy(ptr, rdb->data, rr->rdlength);
            return(ptr + rr->rdlength);
        }
    }

    default:            debugf("putRData: Warning! Writing unknown resource type %d as raw data", rr->rrtype);
        if (ptr + rr->rdlength > limit) return(mDNSNULL);
        mDNSPlatformMemCopy(ptr, rdb->data, rr->rdlength);
        return(ptr + rr->rdlength);
    }
}

#define IsUnicastUpdate(X) (!mDNSOpaque16IsZero((X)->h.id) && ((X)->h.flags.b[0] & kDNSFlag0_OP_Mask) == kDNSFlag0_OP_Update)

mDNSexport mDNSu8 *PutResourceRecordTTLWithLimit(DNSMessage *const msg, mDNSu8 *ptr, mDNSu16 *count,
    const ResourceRecord *rr, mDNSu32 ttl, const mDNSu8 *limit)
{
    mDNSu8 *endofrdata;
    mDNSu16 actualLength;
    // When sending SRV to conventional DNS server (i.e. in DNS update requests) we should not do name compression on the rdata (RFC 2782)
    const DNSMessage *const rdatacompressionbase = (IsUnicastUpdate(msg) && rr->rrtype == kDNSType_SRV) ? mDNSNULL : msg;

    if (rr->RecordType == kDNSRecordTypeUnregistered)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "Attempt to put kDNSRecordTypeUnregistered " PRI_DM_NAME " (" PUB_S ")",
            DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype));
        return(ptr);
    }

    if (!ptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "Pointer to message is NULL while filling resource record " PRI_DM_NAME " (" PUB_S ")",
            DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype));
        return(mDNSNULL);
    }

    ptr = putDomainNameAsLabels(msg, ptr, limit, rr->name);
    // If we're out-of-space, return mDNSNULL
    if (!ptr || ptr + 10 >= limit)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
            "Can't put more names into current message, will possibly put it into the next message - "
            "name: " PRI_DM_NAME " (" PUB_S "), remaining space: %ld",
            DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), (long)(limit - ptr));
        return(mDNSNULL);
    }
    ptr[0] = (mDNSu8)(rr->rrtype  >> 8);
    ptr[1] = (mDNSu8)(rr->rrtype  &  0xFF);
    ptr[2] = (mDNSu8)(rr->rrclass >> 8);
    ptr[3] = (mDNSu8)(rr->rrclass &  0xFF);
    ptr[4] = (mDNSu8)((ttl >> 24) &  0xFF);
    ptr[5] = (mDNSu8)((ttl >> 16) &  0xFF);
    ptr[6] = (mDNSu8)((ttl >>  8) &  0xFF);
    ptr[7] = (mDNSu8)( ttl        &  0xFF);
    // ptr[8] and ptr[9] filled in *after* we find out how much space the rdata takes

    endofrdata = putRData(rdatacompressionbase, ptr+10, limit, rr);
    if (!endofrdata)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
            "Can't put more rdata into current message, will possibly put it into the next message - "
            "name: " PRI_DM_NAME " (" PUB_S "), remaining space: %ld",
            DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype), (long)(limit - ptr - 10));
        return(mDNSNULL);
    }

    // Go back and fill in the actual number of data bytes we wrote
    // (actualLength can be less than rdlength when domain name compression is used)
    actualLength = (mDNSu16)(endofrdata - ptr - 10);
    ptr[8] = (mDNSu8)(actualLength >> 8);
    ptr[9] = (mDNSu8)(actualLength &  0xFF);

    if (count)
    {
        (*count)++;
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "No target count to update for " PRI_DM_NAME " (" PUB_S ")",
            DM_NAME_PARAM(rr->name), DNSTypeName(rr->rrtype));
    }
    return(endofrdata);
}

mDNSlocal mDNSu8 *putEmptyResourceRecord(DNSMessage *const msg, mDNSu8 *ptr, const mDNSu8 *const limit, mDNSu16 *count, const AuthRecord *rr)
{
    ptr = putDomainNameAsLabels(msg, ptr, limit, rr->resrec.name);
    if (!ptr || ptr + 10 > limit) return(mDNSNULL);     // If we're out-of-space, return mDNSNULL
    ptr[0] = (mDNSu8)(rr->resrec.rrtype  >> 8);             // Put type
    ptr[1] = (mDNSu8)(rr->resrec.rrtype  &  0xFF);
    ptr[2] = (mDNSu8)(rr->resrec.rrclass >> 8);             // Put class
    ptr[3] = (mDNSu8)(rr->resrec.rrclass &  0xFF);
    ptr[4] = ptr[5] = ptr[6] = ptr[7] = 0;              // TTL is zero
    ptr[8] = ptr[9] = 0;                                // RDATA length is zero
    (*count)++;
    return(ptr + 10);
}

mDNSexport mDNSu8 *putQuestion(DNSMessage *const msg, mDNSu8 *ptr, const mDNSu8 *const limit, const domainname *const name, mDNSu16 rrtype, mDNSu16 rrclass)
{
    ptr = putDomainNameAsLabels(msg, ptr, limit, name);
    if (!ptr || ptr+4 >= limit) return(mDNSNULL);           // If we're out-of-space, return mDNSNULL
    ptr[0] = (mDNSu8)(rrtype  >> 8);
    ptr[1] = (mDNSu8)(rrtype  &  0xFF);
    ptr[2] = (mDNSu8)(rrclass >> 8);
    ptr[3] = (mDNSu8)(rrclass &  0xFF);
    msg->h.numQuestions++;
    return(ptr+4);
}

// for dynamic updates
mDNSexport mDNSu8 *putZone(DNSMessage *const msg, mDNSu8 *ptr, mDNSu8 *limit, const domainname *zone, mDNSOpaque16 zoneClass)
{
    ptr = putDomainNameAsLabels(msg, ptr, limit, zone);
    if (!ptr || ptr + 4 > limit) return mDNSNULL;       // If we're out-of-space, return NULL
    *ptr++ = (mDNSu8)(kDNSType_SOA  >> 8);
    *ptr++ = (mDNSu8)(kDNSType_SOA  &  0xFF);
    *ptr++ = zoneClass.b[0];
    *ptr++ = zoneClass.b[1];
    msg->h.mDNS_numZones++;
    return ptr;
}

// for dynamic updates
mDNSexport mDNSu8 *putPrereqNameNotInUse(const domainname *const name, DNSMessage *const msg, mDNSu8 *const ptr, mDNSu8 *const end)
{
    AuthRecord prereq;
    mDNS_SetupResourceRecord(&prereq, mDNSNULL, mDNSInterface_Any, kDNSQType_ANY, kStandardTTL, 0, AuthRecordAny, mDNSNULL, mDNSNULL);
    AssignDomainName(&prereq.namestorage, name);
    prereq.resrec.rrtype = kDNSQType_ANY;
    prereq.resrec.rrclass = kDNSClass_NONE;
    return putEmptyResourceRecord(msg, ptr, end, &msg->h.mDNS_numPrereqs, &prereq);
}

// for dynamic updates
mDNSexport mDNSu8 *putDeletionRecord(DNSMessage *msg, mDNSu8 *ptr, ResourceRecord *rr)
{
    // deletion: specify record w/ TTL 0, class NONE
    const mDNSu16 origclass = rr->rrclass;
    rr->rrclass = kDNSClass_NONE;
    ptr = PutResourceRecordTTLJumbo(msg, ptr, &msg->h.mDNS_numUpdates, rr, 0);
    rr->rrclass = origclass;
    return ptr;
}

// for dynamic updates
mDNSexport mDNSu8 *putDeletionRecordWithLimit(DNSMessage *msg, mDNSu8 *ptr, ResourceRecord *rr, mDNSu8 *limit)
{
    // deletion: specify record w/ TTL 0, class NONE
    const mDNSu16 origclass = rr->rrclass;
    rr->rrclass = kDNSClass_NONE;
    ptr = PutResourceRecordTTLWithLimit(msg, ptr, &msg->h.mDNS_numUpdates, rr, 0, limit);
    rr->rrclass = origclass;
    return ptr;
}

mDNSexport mDNSu8 *putDeleteRRSetWithLimit(DNSMessage *msg, mDNSu8 *ptr, const domainname *name, mDNSu16 rrtype, mDNSu8 *limit)
{
    mDNSu16 class = kDNSQClass_ANY;

    ptr = putDomainNameAsLabels(msg, ptr, limit, name);
    if (!ptr || ptr + 10 >= limit) return mDNSNULL; // If we're out-of-space, return mDNSNULL
    ptr[0] = (mDNSu8)(rrtype  >> 8);
    ptr[1] = (mDNSu8)(rrtype  &  0xFF);
    ptr[2] = (mDNSu8)(class >> 8);
    ptr[3] = (mDNSu8)(class &  0xFF);
    ptr[4] = ptr[5] = ptr[6] = ptr[7] = 0; // zero ttl
    ptr[8] = ptr[9] = 0; // zero rdlength/rdata

    msg->h.mDNS_numUpdates++;
    return ptr + 10;
}

// for dynamic updates
mDNSexport mDNSu8 *putDeleteAllRRSets(DNSMessage *msg, mDNSu8 *ptr, const domainname *name)
{
    const mDNSu8 *limit = msg->data + AbsoluteMaxDNSMessageData;
    mDNSu16 class = kDNSQClass_ANY;
    mDNSu16 rrtype = kDNSQType_ANY;

    ptr = putDomainNameAsLabels(msg, ptr, limit, name);
    if (!ptr || ptr + 10 >= limit) return mDNSNULL; // If we're out-of-space, return mDNSNULL
    ptr[0] = (mDNSu8)(rrtype >> 8);
    ptr[1] = (mDNSu8)(rrtype &  0xFF);
    ptr[2] = (mDNSu8)(class >> 8);
    ptr[3] = (mDNSu8)(class &  0xFF);
    ptr[4] = ptr[5] = ptr[6] = ptr[7] = 0; // zero ttl
    ptr[8] = ptr[9] = 0; // zero rdlength/rdata

    msg->h.mDNS_numUpdates++;
    return ptr + 10;
}

// for dynamic updates
mDNSexport mDNSu8 *putUpdateLease(DNSMessage *msg, mDNSu8 *ptr, mDNSu32 lease)
{
    AuthRecord rr;
    mDNS_SetupResourceRecord(&rr, mDNSNULL, mDNSInterface_Any, kDNSType_OPT, kStandardTTL, kDNSRecordTypeKnownUnique, AuthRecordAny, mDNSNULL, mDNSNULL);
    rr.resrec.rrclass    = NormalMaxDNSMessageData;
    rr.resrec.rdlength   = sizeof(rdataOPT);    // One option in this OPT record
    rr.resrec.rdestimate = sizeof(rdataOPT);
    rr.resrec.rdata->u.opt[0].opt           = kDNSOpt_Lease;
    rr.resrec.rdata->u.opt[0].u.updatelease = lease;
    ptr = PutResourceRecordTTLJumbo(msg, ptr, &msg->h.numAdditionals, &rr.resrec, 0);
    if (!ptr) { LogMsg("ERROR: putUpdateLease - PutResourceRecordTTL"); return mDNSNULL; }
    return ptr;
}

// for dynamic updates
mDNSexport mDNSu8 *putUpdateLeaseWithLimit(DNSMessage *msg, mDNSu8 *ptr, mDNSu32 lease, mDNSu8 *limit)
{
    AuthRecord rr;
    mDNS_SetupResourceRecord(&rr, mDNSNULL, mDNSInterface_Any, kDNSType_OPT, kStandardTTL, kDNSRecordTypeKnownUnique, AuthRecordAny, mDNSNULL, mDNSNULL);
    rr.resrec.rrclass    = NormalMaxDNSMessageData;
    rr.resrec.rdlength   = sizeof(rdataOPT);    // One option in this OPT record
    rr.resrec.rdestimate = sizeof(rdataOPT);
    rr.resrec.rdata->u.opt[0].opt           = kDNSOpt_Lease;
    rr.resrec.rdata->u.opt[0].u.updatelease = lease;
    ptr = PutResourceRecordTTLWithLimit(msg, ptr, &msg->h.numAdditionals, &rr.resrec, 0, limit);
    if (!ptr) { LogMsg("ERROR: putUpdateLeaseWithLimit - PutResourceRecordTTLWithLimit"); return mDNSNULL; }
    return ptr;
}

// ***************************************************************************
// MARK: - DNS Message Parsing Functions

mDNSexport mDNSu32 DomainNameHashValue(const domainname *const name)
{
    mDNSu32 sum = 0;
    const mDNSu8 *c;

    for (c = name->c; c[0] != 0 && c[1] != 0; c += 2)
    {
        sum += ((mDNSIsUpperCase(c[0]) ? c[0] + 'a' - 'A' : c[0]) << 8) |
               (mDNSIsUpperCase(c[1]) ? c[1] + 'a' - 'A' : c[1]);
        sum = (sum<<3) | (sum>>29);
    }
    if (c[0]) sum += ((mDNSIsUpperCase(c[0]) ? c[0] + 'a' - 'A' : c[0]) << 8);
    return(sum);
}

mDNSexport void SetNewRData(ResourceRecord *const rr, RData *NewRData, mDNSu16 rdlength)
{
    if (NewRData)
    {
        rr->rdata    = NewRData;
        rr->rdlength = rdlength;
    }
    rr->rdlength   = GetRDLength(rr, mDNSfalse);
    rr->rdestimate = GetRDLength(rr, mDNStrue);
    rr->rdatahash  = RDataHashValue(rr);
}

mDNSexport const mDNSu8 *skipDomainName(const DNSMessage *const msg, const mDNSu8 *ptr, const mDNSu8 *const end)
{
    mDNSu16 total = 0;

    if (ptr < (const mDNSu8*)msg || ptr >= end)
    { debugf("skipDomainName: Illegal ptr not within packet boundaries"); return(mDNSNULL); }

    while (1)                       // Read sequence of labels
    {
        const mDNSu8 len = *ptr++;  // Read length of this label
        if (len == 0) return(ptr);  // If length is zero, that means this name is complete
        switch (len & 0xC0)
        {
        case 0x00:  if (ptr + len >= end)                       // Remember: expect at least one more byte for the root label
            { debugf("skipDomainName: Malformed domain name (overruns packet end)"); return(mDNSNULL); }
            if (total + 1 + len >= MAX_DOMAIN_NAME)             // Remember: expect at least one more byte for the root label
            { debugf("skipDomainName: Malformed domain name (more than 256 characters)"); return(mDNSNULL); }
            ptr += len;
            total += 1 + len;
            break;

        case 0x40:  debugf("skipDomainName: Extended EDNS0 label types 0x%X not supported", len); return(mDNSNULL);
        case 0x80:  debugf("skipDomainName: Illegal label length 0x%X", len); return(mDNSNULL);
        case 0xC0:  if (ptr + 1 > end)                          // Skip the two-byte name compression pointer.
            { debugf("skipDomainName: Malformed compression pointer (overruns packet end)"); return(mDNSNULL); }
            return(ptr + 1);
        default:
            break;
        }
    }
}

// Routine to fetch an FQDN from the DNS message, following compression pointers if necessary.
mDNSexport const mDNSu8 *getDomainName(const DNSMessage *const msg, const mDNSu8 *ptr, const mDNSu8 *const end,
                                       domainname *const name)
{
    const mDNSu8 *nextbyte = mDNSNULL;                  // Record where we got to before we started following pointers
    mDNSu8       *np = name->c;                         // Name pointer
    const mDNSu8 *const limit = np + MAX_DOMAIN_NAME;   // Limit so we don't overrun buffer

    if (ptr < (const mDNSu8*)msg || ptr >= end)
    { debugf("getDomainName: Illegal ptr not within packet boundaries"); return(mDNSNULL); }

    *np = 0;                        // Tentatively place the root label here (may be overwritten if we have more labels)

    while (1)                       // Read sequence of labels
    {
		int i;
		mDNSu16 offset;
        const mDNSu8 len = *ptr++;  // Read length of this label
        if (len == 0) break;        // If length is zero, that means this name is complete
        switch (len & 0xC0)
        {

        case 0x00:  if (ptr + len >= end)           // Remember: expect at least one more byte for the root label
            { debugf("getDomainName: Malformed domain name (overruns packet end)"); return(mDNSNULL); }
            if (np + 1 + len >= limit)              // Remember: expect at least one more byte for the root label
            { debugf("getDomainName: Malformed domain name (more than 256 characters)"); return(mDNSNULL); }
            *np++ = len;
            for (i=0; i<len; i++) *np++ = *ptr++;
            *np = 0;                // Tentatively place the root label here (may be overwritten if we have more labels)
            break;

        case 0x40:  debugf("getDomainName: Extended EDNS0 label types 0x%X not supported in name %##s", len, name->c);
            return(mDNSNULL);

        case 0x80:  debugf("getDomainName: Illegal label length 0x%X in domain name %##s", len, name->c); return(mDNSNULL);

        case 0xC0:  if (ptr >= end)
            { debugf("getDomainName: Malformed compression label (overruns packet end)"); return(mDNSNULL); }
            offset = (mDNSu16)((((mDNSu16)(len & 0x3F)) << 8) | *ptr++);
            if (!nextbyte) nextbyte = ptr;              // Record where we got to before we started following pointers
            ptr = (const mDNSu8 *)msg + offset;
            if (ptr < (const mDNSu8*)msg || ptr >= end)
            { debugf("getDomainName: Illegal compression pointer not within packet boundaries"); return(mDNSNULL); }
            if (*ptr & 0xC0)
            { debugf("getDomainName: Compression pointer must point to real label"); return(mDNSNULL); }
            break;

        default:
            break;
        }
    }

    if (nextbyte) return(nextbyte);
    else return(ptr);
}

mDNSexport const mDNSu8 *skipResourceRecord(const DNSMessage *msg, const mDNSu8 *ptr, const mDNSu8 *end)
{
    mDNSu16 pktrdlength;

    ptr = skipDomainName(msg, ptr, end);
    if (!ptr) { debugf("skipResourceRecord: Malformed RR name"); return(mDNSNULL); }

    if (ptr + 10 > end) { debugf("skipResourceRecord: Malformed RR -- no type/class/ttl/len!"); return(mDNSNULL); }
    pktrdlength = (mDNSu16)((mDNSu16)ptr[8] <<  8 | ptr[9]);
    ptr += 10;
    if (ptr + pktrdlength > end) { debugf("skipResourceRecord: RDATA exceeds end of packet"); return(mDNSNULL); }

    return(ptr + pktrdlength);
}

// Sanity check whether the NSEC/NSEC3 bitmap is good
mDNSlocal const mDNSu8 *SanityCheckBitMap(const mDNSu8 *bmap, const mDNSu8 *end, int len)
{
    int win, wlen;

    while (bmap < end)
    {
        if (len < 3)
        {
            LogInfo("SanityCheckBitMap: invalid length %d", len);
            return mDNSNULL;
        }

        win = *bmap++;
        wlen = *bmap++;
        len -= 2;
        if (len < wlen || wlen < 1 || wlen > 32)
        {
            LogInfo("SanityCheckBitMap: invalid window length %d", wlen);
            return mDNSNULL;
        }
        if (win < 0 || win >= 256)
        {
            LogInfo("SanityCheckBitMap: invalid window %d", win);
            return mDNSNULL;
        }

        bmap += wlen;
        len -= wlen;
    }
    return (const mDNSu8 *)bmap;
}

mDNSlocal mDNSBool AssignDomainNameWithLimit(domainname *const dst, const domainname *src, const mDNSu8 *const end)
{
    const mDNSu32 len = DomainNameLengthLimit(src, end);
    if ((len >= 1) && (len <= MAX_DOMAIN_NAME))
    {
        mDNSPlatformMemCopy(dst->c, src->c, len);
        return mDNStrue;
    }
    else
    {
        dst->c[0] = 0;
        return mDNSfalse;
    }
}

// This function is called with "msg" when we receive a DNS message and needs to parse a single resource record
// pointed to by "ptr". Some resource records like SOA, SRV are converted to host order and also expanded
// (domainnames are expanded to 256 bytes) when stored in memory.
//
// This function can also be called with "NULL" msg to parse a single resource record pointed to by ptr.
// The caller can do this only if the names in the resource records are not compressed and validity of the
// resource record has already been done before.
mDNSexport mDNSBool SetRData(const DNSMessage *const msg, const mDNSu8 *ptr, const mDNSu8 *end, ResourceRecord *const rr,
    const mDNSu16 rdlength)
{
    RDataBody2 *const rdb = (RDataBody2 *)&rr->rdata->u;

    switch (rr->rrtype)
    {
    case kDNSType_A:
        if (rdlength != sizeof(mDNSv4Addr))
            goto fail;
        rdb->ipv4.b[0] = ptr[0];
        rdb->ipv4.b[1] = ptr[1];
        rdb->ipv4.b[2] = ptr[2];
        rdb->ipv4.b[3] = ptr[3];
        break;

    case kDNSType_NS:
    case kDNSType_MD:
    case kDNSType_MF:
    case kDNSType_CNAME:
    case kDNSType_MB:
    case kDNSType_MG:
    case kDNSType_MR:
    case kDNSType_PTR:
    case kDNSType_NSAP_PTR:
    case kDNSType_DNAME:
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->name);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->name, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->name);
        }
        if (ptr != end)
        {
            debugf("SetRData: Malformed CNAME/PTR RDATA name");
            goto fail;
        }
        break;

    case kDNSType_SOA:
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->soa.mname);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->soa.mname, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->soa.mname);
        }
        if (!ptr)
        {
            debugf("SetRData: Malformed SOA RDATA mname");
            goto fail;
        }
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->soa.rname);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->soa.rname, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->soa.rname);
        }
        if (!ptr)
        {
            debugf("SetRData: Malformed SOA RDATA rname");
            goto fail;
        }
        if (ptr + 0x14 != end)
        {
            debugf("SetRData: Malformed SOA RDATA");
            goto fail;
        }
        rdb->soa.serial  = (mDNSs32) ((mDNSs32)ptr[0x00] << 24 | (mDNSs32)ptr[0x01] << 16 | (mDNSs32)ptr[0x02] << 8 | ptr[0x03]);
        rdb->soa.refresh = (mDNSu32) ((mDNSu32)ptr[0x04] << 24 | (mDNSu32)ptr[0x05] << 16 | (mDNSu32)ptr[0x06] << 8 | ptr[0x07]);
        rdb->soa.retry   = (mDNSu32) ((mDNSu32)ptr[0x08] << 24 | (mDNSu32)ptr[0x09] << 16 | (mDNSu32)ptr[0x0A] << 8 | ptr[0x0B]);
        rdb->soa.expire  = (mDNSu32) ((mDNSu32)ptr[0x0C] << 24 | (mDNSu32)ptr[0x0D] << 16 | (mDNSu32)ptr[0x0E] << 8 | ptr[0x0F]);
        rdb->soa.min     = (mDNSu32) ((mDNSu32)ptr[0x10] << 24 | (mDNSu32)ptr[0x11] << 16 | (mDNSu32)ptr[0x12] << 8 | ptr[0x13]);
        break;

    case kDNSType_HINFO:
    // See https://tools.ietf.org/html/rfc1035#section-3.3.2 for HINFO RDATA format.
    {
        // HINFO should contain RDATA.
        if (end <= ptr || rdlength != (mDNSu32)(end - ptr))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                "SetRData: Malformed HINFO RDATA - invalid RDATA length: %u", rdlength);
            goto fail;
        }

        const mDNSu8 *currentPtr = ptr;
        // CPU character string length should be less than the RDATA length.
        mDNSu32 cpuCharacterStrLength = currentPtr[0];
        if (1 + cpuCharacterStrLength >= (mDNSu32)(end - currentPtr))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                "SetRData: Malformed HINFO RDATA - CPU character string goes out of boundary");
            goto fail;
        }
        currentPtr += 1 + cpuCharacterStrLength;

        // OS character string should end at the RDATA ending.
        mDNSu32 osCharacterStrLength = currentPtr[0];
        if (1 + osCharacterStrLength != (mDNSu32)(end - currentPtr))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
                "SetRData: Malformed HINFO RDATA - OS character string does not end at the RDATA ending");
            goto fail;
        }

        // Copy the validated RDATA.
        rr->rdlength = rdlength;
        mDNSPlatformMemCopy(rdb->data, ptr, rdlength);
        break;
    }
    case kDNSType_NULL:
    case kDNSType_TXT:
    case kDNSType_X25:
    case kDNSType_ISDN:
    case kDNSType_LOC:
    case kDNSType_DHCID:
	case kDNSType_SVCB:
	case kDNSType_HTTPS:
        rr->rdlength = rdlength;
        mDNSPlatformMemCopy(rdb->data, ptr, rdlength);
        break;

    case kDNSType_MX:
    case kDNSType_AFSDB:
    case kDNSType_RT:
    case kDNSType_KX:
        // Preference + domainname
        if (rdlength < 3)
            goto fail;
        rdb->mx.preference = (mDNSu16)((mDNSu16)ptr[0] <<  8 | ptr[1]);
        ptr += 2;
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->mx.exchange);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->mx.exchange, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->mx.exchange);
        }
        if (ptr != end)
        {
            debugf("SetRData: Malformed MX name");
            goto fail;
        }
        break;

    case kDNSType_MINFO:
    case kDNSType_RP:
        // Domainname + domainname
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->rp.mbox);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->rp.mbox, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->rp.mbox);
        }
        if (!ptr)
        {
            debugf("SetRData: Malformed RP mbox");
            goto fail;
        }
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->rp.txt);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->rp.txt, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->rp.txt);
        }
        if (ptr != end)
        {
            debugf("SetRData: Malformed RP txt");
            goto fail;
        }
        break;

    case kDNSType_PX:
        // Preference + domainname + domainname
        if (rdlength < 4)
            goto fail;
        rdb->px.preference = (mDNSu16)((mDNSu16)ptr[0] <<  8 | ptr[1]);
        ptr += 2;
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->px.map822);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->px.map822, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->px.map822);
        }
        if (!ptr)
        {
            debugf("SetRData: Malformed PX map822");
            goto fail;
        }
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->px.mapx400);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->px.mapx400, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->px.mapx400);
        }
        if (ptr != end)
        {
            debugf("SetRData: Malformed PX mapx400");
            goto fail;
        }
        break;

    case kDNSType_AAAA:
        if (rdlength != sizeof(mDNSv6Addr))
            goto fail;
        mDNSPlatformMemCopy(&rdb->ipv6, ptr, sizeof(rdb->ipv6));
        break;

    case kDNSType_SRV:
        // Priority + weight + port + domainname
        if (rdlength < 7)
            goto fail;
        rdb->srv.priority = (mDNSu16)((mDNSu16)ptr[0] <<  8 | ptr[1]);
        rdb->srv.weight   = (mDNSu16)((mDNSu16)ptr[2] <<  8 | ptr[3]);
        rdb->srv.port.b[0] = ptr[4];
        rdb->srv.port.b[1] = ptr[5];
        ptr += 6;
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &rdb->srv.target);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&rdb->srv.target, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&rdb->srv.target);
        }
        if (ptr != end)
        {
            debugf("SetRData: Malformed SRV RDATA name");
            goto fail;
        }
        break;

    case kDNSType_NAPTR:
    {
        int savelen, len;
        domainname name;
        mDNSu32 namelen;
        const mDNSu8 *orig = ptr;

        // Make sure the data is parseable and within the limits.
        //
        // Fixed length: Order, preference (4 bytes)
        // Variable length: flags, service, regexp, domainname

        if (rdlength < 8)
            goto fail;
        // Order, preference.
        ptr += 4;
        // Parse flags, Service and Regexp
        // length in the first byte does not include the length byte itself
        len = *ptr + 1;
        ptr += len;
        if (ptr >= end)
        {
            LogInfo("SetRData: Malformed NAPTR flags");
            goto fail;
        }

        // Service
        len = *ptr + 1;
        ptr += len;
        if (ptr >= end)
        {
            LogInfo("SetRData: Malformed NAPTR service");
            goto fail;
        }

        // Regexp
        len = *ptr + 1;
        ptr += len;
        if (ptr >= end)
        {
            LogInfo("SetRData: Malformed NAPTR regexp");
            goto fail;
        }

        savelen = (int)(ptr - orig);

        // RFC 2915 states that name compression is not allowed for this field. But RFC 3597
        // states that for NAPTR we should decompress. We make sure that we store the full
        // name rather than the compressed name
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &name);
            namelen = DomainNameLength(&name);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&name, (const domainname *)ptr, end))
            {
                goto fail;
            }
            namelen = DomainNameLength(&name);
            ptr += namelen;
        }
        if (ptr != end)
        {
            LogInfo("SetRData: Malformed NAPTR RDATA name");
            goto fail;
        }

        rr->rdlength = savelen + namelen;
        // The uncompressed size should not exceed the limits
        if (rr->rdlength > MaximumRDSize)
        {
            LogInfo("SetRData: Malformed NAPTR rdlength %d, rr->rdlength %d, "
                    "bmaplen %d, name %##s", rdlength, rr->rdlength, name.c);
            goto fail;
        }
        mDNSPlatformMemCopy(rdb->data, orig, savelen);
        mDNSPlatformMemCopy(rdb->data + savelen, name.c, namelen);
        break;
    }
    case kDNSType_OPT:  {
        const mDNSu8 * const dataend = &rr->rdata->u.data[rr->rdata->MaxRDLength];
        rdataOPT *opt = rr->rdata->u.opt;
        rr->rdlength = 0;
        while ((ptr < end) && ((dataend - ((const mDNSu8 *)opt)) >= ((mDNSs32)sizeof(*opt))))
        {
            const rdataOPT *const currentopt = opt;
            if (ptr + 4 > end) { LogInfo("SetRData: OPT RDATA ptr + 4 > end"); goto fail; }
            opt->opt    = (mDNSu16)((mDNSu16)ptr[0] <<  8 | ptr[1]);
            opt->optlen = (mDNSu16)((mDNSu16)ptr[2] <<  8 | ptr[3]);
            ptr += 4;
            if (ptr + opt->optlen > end) { LogInfo("SetRData: ptr + opt->optlen > end"); goto fail; }
            switch (opt->opt)
            {
            case kDNSOpt_LLQ:
                if (opt->optlen == DNSOpt_LLQData_Space - 4)
                {
                    opt->u.llq.vers  = (mDNSu16)((mDNSu16)ptr[0] <<  8 | ptr[1]);
                    opt->u.llq.llqOp = (mDNSu16)((mDNSu16)ptr[2] <<  8 | ptr[3]);
                    opt->u.llq.err   = (mDNSu16)((mDNSu16)ptr[4] <<  8 | ptr[5]);
                    mDNSPlatformMemCopy(opt->u.llq.id.b, ptr+6, 8);
                    opt->u.llq.llqlease = (mDNSu32) ((mDNSu32)ptr[14] << 24 | (mDNSu32)ptr[15] << 16 | (mDNSu32)ptr[16] << 8 | ptr[17]);
                    if (opt->u.llq.llqlease > 0x70000000UL / mDNSPlatformOneSecond)
                        opt->u.llq.llqlease = 0x70000000UL / mDNSPlatformOneSecond;
                    opt++;
                }
                break;
            case kDNSOpt_Lease:
                if (opt->optlen == DNSOpt_LeaseData_Space - 4)
                {
                    opt->u.updatelease = (mDNSu32) ((mDNSu32)ptr[0] << 24 | (mDNSu32)ptr[1] << 16 | (mDNSu32)ptr[2] << 8 | ptr[3]);
                    if (opt->u.updatelease > 0x70000000UL / mDNSPlatformOneSecond)
                        opt->u.updatelease = 0x70000000UL / mDNSPlatformOneSecond;
                    opt++;
                }
                break;
            case kDNSOpt_Owner:
                if (ValidOwnerLength(opt->optlen))
                {
                    opt->u.owner.vers = ptr[0];
                    opt->u.owner.seq  = ptr[1];
                    mDNSPlatformMemCopy(opt->u.owner.HMAC.b, ptr+2, 6);                         // 6-byte MAC address
                    mDNSPlatformMemCopy(opt->u.owner.IMAC.b, ptr+2, 6);                         // 6-byte MAC address
                    opt->u.owner.password = zeroEthAddr;
                    if (opt->optlen >= DNSOpt_OwnerData_ID_Wake_Space-4)
                    {
                        mDNSPlatformMemCopy(opt->u.owner.IMAC.b, ptr+8, 6);                     // 6-byte MAC address
                        // This mDNSPlatformMemCopy is safe because the ValidOwnerLength(opt->optlen) check above
                        // ensures that opt->optlen is no more than DNSOpt_OwnerData_ID_Wake_PW6_Space - 4
                        if (opt->optlen > DNSOpt_OwnerData_ID_Wake_Space-4)
                            mDNSPlatformMemCopy(opt->u.owner.password.b, ptr+14, opt->optlen - (DNSOpt_OwnerData_ID_Wake_Space-4));
                    }
                    opt++;
                }
                break;
            case kDNSOpt_Trace:
                if (opt->optlen == DNSOpt_TraceData_Space - 4)
                {
                    opt->u.tracer.platf   = ptr[0];
                    opt->u.tracer.mDNSv   = (mDNSu32) ((mDNSu32)ptr[1] << 24 | (mDNSu32)ptr[2] << 16 | (mDNSu32)ptr[3] << 8 | ptr[4]);
                    opt++;
                }
                else
                {
                    opt->u.tracer.platf   = 0xFF;
                    opt->u.tracer.mDNSv   = 0xFFFFFFFF;
                    opt++;
                }
                break;
            case kDNSOpt_TSR:
                if (opt->optlen == DNSOpt_TSRData_Space - 4)
                {
                    opt->u.tsr.timeStamp    = (mDNSs32) ((mDNSu32)ptr[0] << 24 | (mDNSu32)ptr[1] << 16 | (mDNSu32)ptr[2] << 8 | ptr[3]);
                    opt->u.tsr.hostkeyHash  = (mDNSu32) ((mDNSu32)ptr[4] << 24 | (mDNSu32)ptr[5] << 16 | (mDNSu32)ptr[6] << 8 | ptr[7]);
                    opt->u.tsr.recIndex     = (mDNSu16) ((mDNSu16)ptr[8] << 8 | ptr[9]);
                    opt++;
                }
                break;
            default:
                break;
            }
            ptr += currentopt->optlen;
        }
        rr->rdlength = (mDNSu16)((mDNSu8*)opt - rr->rdata->u.data);
        if (ptr != end) { LogInfo("SetRData: Malformed OptRdata"); goto fail; }
        break;
    }

    case kDNSType_NSEC: {
        domainname name;
        int len = rdlength;
        int bmaplen, dlen;
        const mDNSu8 *orig = ptr;
        const mDNSu8 *bmap;

        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &name);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&name, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&name);
        }
        if (!ptr)
        {
            LogInfo("SetRData: Malformed NSEC nextname");
            goto fail;
        }

        dlen = DomainNameLength(&name);

        // Multicast NSECs use name compression for this field unlike the unicast case which
        // does not use compression. And multicast case always succeeds in compression. So,
        // the rdlength includes only the compressed space in that case. So, can't
        // use the DomainNameLength of name to reduce the length here.
        len -= (ptr - orig);
        bmaplen = len;                  // Save the length of the bitmap
        bmap = ptr;
        ptr = SanityCheckBitMap(bmap, end, len);
        if (!ptr)
            goto fail;
        if (ptr != end)
        {
            LogInfo("SetRData: Malformed NSEC length not right");
            goto fail;
        }

        // Initialize the right length here. When we call SetNewRData below which in turn calls
        // GetRDLength and for NSEC case, it assumes that rdlength is intitialized
        rr->rdlength = DomainNameLength(&name) + bmaplen;

        // Do we have space after the name expansion ?
        if (rr->rdlength > MaximumRDSize)
        {
            LogInfo("SetRData: Malformed NSEC rdlength %d, rr->rdlength %d, "
                    "bmaplen %d, name %##s", rdlength, rr->rdlength, name.c);
            goto fail;
        }
        AssignDomainName(&rdb->name, &name);
        mDNSPlatformMemCopy(rdb->data + dlen, bmap, bmaplen);
        break;
    }
    case kDNSType_TKEY:
    case kDNSType_TSIG:
    {
        domainname name;
        int dlen, rlen;

        // The name should not be compressed. But we take the conservative approach
        // and uncompress the name before we store it.
        if (msg)
        {
            ptr = getDomainName(msg, ptr, end, &name);
        }
        else
        {
            if (!AssignDomainNameWithLimit(&name, (const domainname *)ptr, end))
            {
                goto fail;
            }
            ptr += DomainNameLength(&name);
        }
        if (!ptr || ptr >= end)
        {
            LogInfo("SetRData: Malformed name for TSIG/TKEY type %d", rr->rrtype);
            goto fail;
        }
        dlen = DomainNameLength(&name);
        rlen = (int)(end - ptr);
        rr->rdlength = dlen + rlen;
        if (rr->rdlength > MaximumRDSize)
        {
            LogInfo("SetRData: Malformed TSIG/TKEY rdlength %d, rr->rdlength %d, "
                    "bmaplen %d, name %##s", rdlength, rr->rdlength, name.c);
            goto fail;
        }
        AssignDomainName(&rdb->name, &name);
        mDNSPlatformMemCopy(rdb->data + dlen, ptr, rlen);
        break;
    }
    case kDNSType_TSR:
    {
        rdb->tsr_value  = (mDNSs32) ((mDNSu32)ptr[0] << 24 | (mDNSu32)ptr[1] << 16 | (mDNSu32)ptr[2] << 8 | ptr[3]);
        break;
    }
    default:
        debugf("SetRData: Warning! Reading resource type %d (%s) as opaque data",
               rr->rrtype, DNSTypeName(rr->rrtype));
        // Note: Just because we don't understand the record type, that doesn't
        // mean we fail. The DNS protocol specifies rdlength, so we can
        // safely skip over unknown records and ignore them.
        // We also grab a binary copy of the rdata anyway, since the caller
        // might know how to interpret it even if we don't.
        rr->rdlength = rdlength;
        mDNSPlatformMemCopy(rdb->data, ptr, rdlength);
        break;
    }
    return mDNStrue;
fail:
    return mDNSfalse;
}

mDNSexport const mDNSu8 *GetLargeResourceRecord(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *ptr,
                                                const mDNSu8 *end, const mDNSInterfaceID InterfaceID, mDNSu8 RecordType, LargeCacheRecord *const largecr)
{
    CacheRecord *const rr = &largecr->r;
    mDNSu16 pktrdlength;
    mDNSu32 maxttl = (!InterfaceID) ? mDNSMaximumUnicastTTLSeconds : mDNSMaximumMulticastTTLSeconds;

    if (largecr == &m->rec && m->rec.r.resrec.RecordType)
        LogFatalError("GetLargeResourceRecord: m->rec appears to be already in use for %s", CRDisplayString(m, &m->rec.r));

    rr->next              = mDNSNULL;
    rr->resrec.name       = &largecr->namestorage;

    rr->NextInKAList      = mDNSNULL;
    rr->TimeRcvd          = m ? m->timenow : 0;
    rr->DelayDelivery     = 0;
    rr->NextRequiredQuery = m ? m->timenow : 0;     // Will be updated to the real value when we call SetNextCacheCheckTimeForRecord()
#if MDNSRESPONDER_SUPPORTS(APPLE, CACHE_ANALYTICS)
    rr->LastCachedAnswerTime = 0;
#endif
    rr->CRActiveQuestion  = mDNSNULL;
    rr->UnansweredQueries = 0;
    rr->LastUnansweredTime= 0;
    rr->NextInCFList      = mDNSNULL;

    rr->resrec.InterfaceID       = InterfaceID;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    mdns_forget(&rr->resrec.metadata);
#else
    rr->resrec.rDNSServer = mDNSNULL;
#endif

    ptr = getDomainName(msg, ptr, end, &largecr->namestorage);      // Will bail out correctly if ptr is NULL
    if (!ptr) { debugf("GetLargeResourceRecord: Malformed RR name"); return(mDNSNULL); }
    rr->resrec.namehash = DomainNameHashValue(rr->resrec.name);

    if (ptr + 10 > end) { debugf("GetLargeResourceRecord: Malformed RR -- no type/class/ttl/len!"); return(mDNSNULL); }

    rr->resrec.rrtype            = (mDNSu16) ((mDNSu16)ptr[0] <<  8 | ptr[1]);
    rr->resrec.rrclass           = (mDNSu16)(((mDNSu16)ptr[2] <<  8 | ptr[3]) & kDNSClass_Mask);
    rr->resrec.rroriginalttl     = (mDNSu32) ((mDNSu32)ptr[4] << 24 | (mDNSu32)ptr[5] << 16 | (mDNSu32)ptr[6] << 8 | ptr[7]);
    if (rr->resrec.rroriginalttl > maxttl && (mDNSs32)rr->resrec.rroriginalttl != -1)
        rr->resrec.rroriginalttl = maxttl;
    // Note: We don't have to adjust m->NextCacheCheck here -- this is just getting a record into memory for
    // us to look at. If we decide to copy it into the cache, then we'll update m->NextCacheCheck accordingly.
    pktrdlength           = (mDNSu16)((mDNSu16)ptr[8] <<  8 | ptr[9]);

    // If mDNS record has cache-flush bit set, we mark it unique
    // For uDNS records, all are implicitly deemed unique (a single DNS server is always authoritative for the entire RRSet)
    if (ptr[2] & (kDNSClass_UniqueRRSet >> 8) || !InterfaceID)
        RecordType |= kDNSRecordTypePacketUniqueMask;
    ptr += 10;
    if (ptr + pktrdlength > end) { debugf("GetLargeResourceRecord: RDATA exceeds end of packet"); return(mDNSNULL); }
    end = ptr + pktrdlength;        // Adjust end to indicate the end of the rdata for this resource record

    rr->resrec.rdata = (RData*)&rr->smallrdatastorage;
    rr->resrec.rdata->MaxRDLength = MaximumRDSize;

    if (pktrdlength > MaximumRDSize)
    {
        LogInfo("GetLargeResourceRecord: %s rdata size (%d) exceeds storage (%d)",
                DNSTypeName(rr->resrec.rrtype), pktrdlength, rr->resrec.rdata->MaxRDLength);
        goto fail;
    }

    if (!RecordType) LogMsg("GetLargeResourceRecord: No RecordType for %##s", rr->resrec.name->c);

    // IMPORTANT: Any record type we understand and unpack into a structure containing domainnames needs to have corresponding
    // cases in SameRDataBody() and RDataHashValue() to do a semantic comparison (or checksum) of the structure instead of a blind
    // bitwise memory compare (or sum). This is because a domainname is a fixed size structure holding variable-length data.
    // Any bytes past the logical end of the name are undefined, and a blind bitwise memory compare may indicate that
    // two domainnames are different when semantically they are the same name and it's only the unused bytes that differ.
    if (rr->resrec.rrclass == kDNSQClass_ANY && pktrdlength == 0)   // Used in update packets to mean "Delete An RRset" (RFC 2136)
        rr->resrec.rdlength = 0;
    else if (!SetRData(msg, ptr, end, &rr->resrec, pktrdlength))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
            "GetLargeResourceRecord: SetRData failed for " PRI_DM_NAME " (" PUB_S ")",
            DM_NAME_PARAM(rr->resrec.name), DNSTypeName(rr->resrec.rrtype));
        goto fail;
    }

    SetNewRData(&rr->resrec, mDNSNULL, 0);      // Sets rdlength, rdestimate, rdatahash for us

    // Success! Now fill in RecordType to show this record contains valid data
    rr->resrec.RecordType = RecordType;
    return(end);

fail:
    // If we were unable to parse the rdata in this record, we indicate that by
    // returing a 'kDNSRecordTypePacketNegative' record with rdlength set to zero
    rr->resrec.RecordType = kDNSRecordTypePacketNegative;
    rr->resrec.rdlength   = 0;
    rr->resrec.rdestimate = 0;
    rr->resrec.rdatahash  = 0;
    return(end);
}

mDNSexport const mDNSu8 *skipQuestion(const DNSMessage *msg, const mDNSu8 *ptr, const mDNSu8 *end)
{
    ptr = skipDomainName(msg, ptr, end);
    if (!ptr) { debugf("skipQuestion: Malformed domain name in DNS question section"); return(mDNSNULL); }
    if (ptr+4 > end) { debugf("skipQuestion: Malformed DNS question section -- no query type and class!"); return(mDNSNULL); }
    return(ptr+4);
}

mDNSexport const mDNSu8 *getQuestion(const DNSMessage *msg, const mDNSu8 *ptr, const mDNSu8 *end, const mDNSInterfaceID InterfaceID,
                                     DNSQuestion *question)
{
    mDNSPlatformMemZero(question, sizeof(*question));
    question->InterfaceID = InterfaceID;
    if (!InterfaceID) question->TargetQID = onesID; // In DNSQuestions we use TargetQID as the indicator of whether it's unicast or multicast
    ptr = getDomainName(msg, ptr, end, &question->qname);
    if (!ptr) { debugf("Malformed domain name in DNS question section"); return(mDNSNULL); }
    if (ptr+4 > end) { debugf("Malformed DNS question section -- no query type and class!"); return(mDNSNULL); }

    question->qnamehash = DomainNameHashValue(&question->qname);
    question->qtype  = (mDNSu16)((mDNSu16)ptr[0] << 8 | ptr[1]);            // Get type
    question->qclass = (mDNSu16)((mDNSu16)ptr[2] << 8 | ptr[3]);            // and class
    return(ptr+4);
}

mDNSexport const mDNSu8 *LocateAnswers(const DNSMessage *const msg, const mDNSu8 *const end)
{
    int i;
    const mDNSu8 *ptr = msg->data;
    for (i = 0; i < msg->h.numQuestions && ptr; i++) ptr = skipQuestion(msg, ptr, end);
    return(ptr);
}

mDNSexport const mDNSu8 *LocateAuthorities(const DNSMessage *const msg, const mDNSu8 *const end)
{
    int i;
    const mDNSu8 *ptr = LocateAnswers(msg, end);
    for (i = 0; i < msg->h.numAnswers && ptr; i++) ptr = skipResourceRecord(msg, ptr, end);
    return(ptr);
}

mDNSexport const mDNSu8 *LocateAdditionals(const DNSMessage *const msg, const mDNSu8 *const end)
{
    int i;
    const mDNSu8 *ptr = LocateAuthorities(msg, end);
    for (i = 0; i < msg->h.numAuthorities; i++) ptr = skipResourceRecord(msg, ptr, end);
    return (ptr);
}

mDNSexport const mDNSu8 *LocateOptRR(const DNSMessage *const msg, const mDNSu8 *const end, int minsize)
{
    int i;
    const mDNSu8 *ptr = LocateAdditionals(msg, end);

    // Locate the OPT record.
    // According to RFC 2671, "One OPT pseudo-RR can be added to the additional data section of either a request or a response."
    // This implies that there may be *at most* one OPT record per DNS message, in the Additional Section,
    // but not necessarily the *last* entry in the Additional Section.
    for (i = 0; ptr && i < msg->h.numAdditionals; i++)
    {
        if (ptr + DNSOpt_Header_Space + minsize <= end &&   // Make sure we have 11+minsize bytes of data
            ptr[0] == 0                                &&   // Name must be root label
            ptr[1] == (kDNSType_OPT >> 8  )            &&   // rrtype OPT
            ptr[2] == (kDNSType_OPT & 0xFF)            &&
            ((mDNSu16)ptr[9] << 8 | (mDNSu16)ptr[10]) >= (mDNSu16)minsize)
            return(ptr);
        else
            ptr = skipResourceRecord(msg, ptr, end);
    }
    return(mDNSNULL);
}

// On success, GetLLQOptData returns pointer to storage within shared "m->rec";
// it is caller's responsibilty to clear m->rec.r.resrec.RecordType after use
// Note: An OPT RDataBody actually contains one or more variable-length rdataOPT objects packed together
// The code that currently calls this assumes there's only one, instead of iterating through the set
mDNSexport const rdataOPT *GetLLQOptData(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end)
{
    const mDNSu8 *ptr = LocateOptRR(msg, end, DNSOpt_LLQData_Space);
    if (ptr)
    {
        ptr = GetLargeResourceRecord(m, msg, ptr, end, 0, kDNSRecordTypePacketAdd, &m->rec);
        if (ptr && m->rec.r.resrec.RecordType != kDNSRecordTypePacketNegative) return(&m->rec.r.resrec.rdata->u.opt[0]);
    }
    return(mDNSNULL);
}

// Get the lease life of records in a dynamic update
mDNSexport mDNSBool GetPktLease(mDNS *const m, const DNSMessage *const msg, const mDNSu8 *const end, mDNSu32 *const lease)
{
    const mDNSu8 *ptr = LocateOptRR(msg, end, DNSOpt_LeaseData_Space);
    if (ptr)
    {
        ptr = GetLargeResourceRecord(m, msg, ptr, end, 0, kDNSRecordTypePacketAdd, &m->rec);
        if (ptr && m->rec.r.resrec.RecordType != kDNSRecordTypePacketNegative && m->rec.r.resrec.rrtype == kDNSType_OPT)
        {
            const rdataOPT *o;
            const rdataOPT *const e = (const rdataOPT *)&m->rec.r.resrec.rdata->u.data[m->rec.r.resrec.rdlength];
            for (o = &m->rec.r.resrec.rdata->u.opt[0]; o < e; o++)
                if (o->opt == kDNSOpt_Lease)
                {
                    *lease = o->u.updatelease;
                    mDNSCoreResetRecord(m);
                    return mDNStrue;
                }
        }
        mDNSCoreResetRecord(m);
    }
    return mDNSfalse;
}

#define DNS_OP_Name(X) (                              \
        (X) == kDNSFlag0_OP_StdQuery ? ""         :       \
        (X) == kDNSFlag0_OP_Iquery   ? "Iquery "  :       \
        (X) == kDNSFlag0_OP_Status   ? "Status "  :       \
        (X) == kDNSFlag0_OP_Unused3  ? "Unused3 " :       \
        (X) == kDNSFlag0_OP_Notify   ? "Notify "  :       \
        (X) == kDNSFlag0_OP_Update   ? "Update "  :       \
        (X) == kDNSFlag0_OP_DSO      ? "DSO "  : "?? " )

#define DNS_RC_Name(X) (                             \
        (X) == kDNSFlag1_RC_NoErr     ? "NoErr"    :      \
        (X) == kDNSFlag1_RC_FormErr   ? "FormErr"  :      \
        (X) == kDNSFlag1_RC_ServFail  ? "ServFail" :      \
        (X) == kDNSFlag1_RC_NXDomain  ? "NXDomain" :      \
        (X) == kDNSFlag1_RC_NotImpl   ? "NotImpl"  :      \
        (X) == kDNSFlag1_RC_Refused   ? "Refused"  :      \
        (X) == kDNSFlag1_RC_YXDomain  ? "YXDomain" :      \
        (X) == kDNSFlag1_RC_YXRRSet   ? "YXRRSet"  :      \
        (X) == kDNSFlag1_RC_NXRRSet   ? "NXRRSet"  :      \
        (X) == kDNSFlag1_RC_NotAuth   ? "NotAuth"  :      \
        (X) == kDNSFlag1_RC_NotZone   ? "NotZone"  :      \
        (X) == kDNSFlag1_RC_DSOTypeNI ? "DSOTypeNI" : "??" )

mDNSexport void mDNS_snprintf_add(char **ptr, const char *lim, const char *fmt, ...)
{
    va_list args;
    mDNSu32 buflen, n;
    char *const dst = *ptr;

    buflen = (mDNSu32)(lim - dst);
    if (buflen > 0)
    {
        va_start(args, fmt);
        n = mDNS_vsnprintf(dst, buflen, fmt, args);
        va_end(args);
        *ptr = dst + n;
    }
}

#define DNSTypeString(X) (((X) == kDNSType_A) ? "A" : DNSTypeName(X))

mDNSlocal void DNSMessageDumpToLog(const DNSMessage *const msg, const mDNSu8 *const end)
{
    domainname *name = mDNSNULL;
    const mDNSu8 *ptr = msg->data;
    domainname nameStorage[2];

    char questions[512];
    questions[0] = '\0';
    char *questions_dst = questions;
    const char *const questions_lim = &questions[512];
    for (mDNSu32 i = 0; i < msg->h.numQuestions; i++)
    {
        mDNSu16 qtype, qclass;

        name = &nameStorage[0];
        ptr = getDomainName(msg, ptr, end, name);
        if (!ptr) goto exit;

        if ((end - ptr) < 4) goto exit;
        qtype  = ReadField16(&ptr[0]);
        qclass = ReadField16(&ptr[2]);
        ptr += 4;

        mDNS_snprintf_add(&questions_dst, questions_lim, " %##s %s", name->c, DNSTypeString(qtype));
        if (qclass != kDNSClass_IN) mDNS_snprintf_add(&questions_dst, questions_lim, "/%u", qclass);
        mDNS_snprintf_add(&questions_dst, questions_lim, "?");
    }

    char rrs[512];
    rrs[0] = '\0';
    char *rrs_dst = rrs;
    const char *const rrs_lim = &rrs[512];
    const mDNSu32 rrcount = msg->h.numAnswers + msg->h.numAuthorities + msg->h.numAdditionals;
    for (mDNSu32 i = 0; i < rrcount; i++)
    {
        mDNSu16 rrtype, rrclass, rdlength;
        mDNSu32 ttl;
        int handled;
        const mDNSu8 *rdata;
        const domainname *const previousName = name;

        name = &nameStorage[(name == &nameStorage[0]) ? 1 : 0];
        ptr = getDomainName(msg, ptr, end, name);
        if (!ptr) goto exit;

        if ((end - ptr) < 10) goto exit;
        rrtype   = ReadField16(&ptr[0]);
        rrclass  = ReadField16(&ptr[2]);
        ttl      = ReadField32(&ptr[4]);
        rdlength = ReadField16(&ptr[8]);
        ptr += 10;

        if ((end - ptr) < rdlength) goto exit;
        rdata = ptr;

        if (i > 0) mDNS_snprintf_add(&rrs_dst, rrs_lim, ",");
        if (!previousName || !SameDomainName(name, previousName)) mDNS_snprintf_add(&rrs_dst, rrs_lim, " %##s", name);

        mDNS_snprintf_add(&rrs_dst, rrs_lim, " %s", DNSTypeString(rrtype));
        if (rrclass != kDNSClass_IN) mDNS_snprintf_add(&rrs_dst, rrs_lim, "/%u", rrclass);
        mDNS_snprintf_add(&rrs_dst, rrs_lim, " ");

        handled = mDNSfalse;
        switch (rrtype)
        {
            case kDNSType_A:
                if (rdlength == 4)
                {
                    mDNS_snprintf_add(&rrs_dst, rrs_lim, "%.4a", rdata);
                    handled = mDNStrue;
                }
                break;

            case kDNSType_AAAA:
                if (rdlength == 16)
                {
                    mDNS_snprintf_add(&rrs_dst, rrs_lim, "%.16a", rdata);
                    handled = mDNStrue;
                }
                break;

            case kDNSType_CNAME:
                ptr = getDomainName(msg, rdata, end, name);
                if (!ptr) goto exit;

                mDNS_snprintf_add(&rrs_dst, rrs_lim, "%##s", name);
                handled = mDNStrue;
                break;

            case kDNSType_SOA:
            {
                mDNSu32 serial, refresh, retry, expire, minimum;
                domainname *const mname = &nameStorage[0];
                domainname *const rname = &nameStorage[1];
                name = mDNSNULL;

                ptr = getDomainName(msg, rdata, end, mname);
                if (!ptr) goto exit;

                ptr = getDomainName(msg, ptr, end, rname);
                if (!ptr) goto exit;

                if ((end - ptr) < 20) goto exit;
                serial  = ReadField32(&ptr[0]);
                refresh = ReadField32(&ptr[4]);
                retry   = ReadField32(&ptr[8]);
                expire  = ReadField32(&ptr[12]);
                minimum = ReadField32(&ptr[16]);

                mDNS_snprintf_add(&rrs_dst, rrs_lim, "%##s %##s %lu %lu %lu %lu %lu", mname, rname, (unsigned long)serial,
                                  (unsigned long)refresh, (unsigned long)retry, (unsigned long)expire, (unsigned long)minimum);

                handled = mDNStrue;
                break;
            }

            default:
                break;
        }
        if (!handled) mDNS_snprintf_add(&rrs_dst, rrs_lim, "RDATA[%u]: %.*H", rdlength, rdlength, rdata);
        mDNS_snprintf_add(&rrs_dst, rrs_lim, " (%lu)", (unsigned long)ttl);
        ptr = rdata + rdlength;
    }

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
        "[Q%u] DNS " PUB_S PUB_S " (%lu) (flags %02X%02X) RCODE: " PUB_S " (%d)" PUB_S PUB_S PUB_S PUB_S PUB_S PUB_S ":"
        PRI_S " %u/%u/%u " PRI_S,
        mDNSVal16(msg->h.id),
        DNS_OP_Name(msg->h.flags.b[0] & kDNSFlag0_OP_Mask),
        (msg->h.flags.b[0] & kDNSFlag0_QR_Response) ? "Response" : "Query",
        (unsigned long)(end - (const mDNSu8 *)msg),
        msg->h.flags.b[0], msg->h.flags.b[1],
        DNS_RC_Name(msg->h.flags.b[1] & kDNSFlag1_RC_Mask),
        msg->h.flags.b[1] & kDNSFlag1_RC_Mask,
        (msg->h.flags.b[0] & kDNSFlag0_AA) ? " AA" : "",
        (msg->h.flags.b[0] & kDNSFlag0_TC) ? " TC" : "",
        (msg->h.flags.b[0] & kDNSFlag0_RD) ? " RD" : "",
        (msg->h.flags.b[1] & kDNSFlag1_RA) ? " RA" : "",
        (msg->h.flags.b[1] & kDNSFlag1_AD) ? " AD" : "",
        (msg->h.flags.b[1] & kDNSFlag1_CD) ? " CD" : "",
        questions, msg->h.numAnswers, msg->h.numAuthorities, msg->h.numAdditionals, rrs);

exit:
    return;
}

mDNSlocal mDNSBool DNSMessageIsResponse(const DNSMessage *const msg)
{
    return ((msg->h.flags.b[0] & kDNSFlag0_QR_Mask) == kDNSFlag0_QR_Response);
}

mDNSlocal mDNSBool DNSMessageIsQuery(const DNSMessage *const msg)
{
    return !DNSMessageIsResponse(msg);
}

// This function calculates and checks the hash value of the current DNS message if it matches a previous one already.
mDNSlocal void DumpMDNSPacket_CalculateAndCheckIfMsgAppearsBefore(const DNSMessage *const msg, const mDNSu8 *const end,
    const mDNSAddr *const srcaddr, const mDNSIPPort srcport, const mDNSAddr *const dstaddr, const mDNSIPPort dstport,
    const mDNSu32 ifIndex, mDNSu32 *const outMsgHash, mDNSBool *const outMsgHashSame,
    mDNSu32 *const outCompleteHash, mDNSBool *const outCompleteHashSame)
{
    // We calculate two hash values with different hash algorithms to avoid having collisions frequently.
    const mDNSu32 msgLen = sizeof(DNSMessageHeader) + (mDNSu32)(end - msg->data);
    const mDNSu32 msgHash = mDNS_NonCryptoHash(mDNSNonCryptoHash_FNV1a, msg->h.id.b, msgLen);
    const mDNSu32 msg2ndHash = mDNS_NonCryptoHash(mDNSNonCryptoHash_SDBM, msg->h.id.b, msgLen);
    mdns_assign(outMsgHash, msgHash);

    mDNSu32 completeHash = msgHash;
    mDNSu32 complete2ndHash = msg2ndHash;
    if (srcaddr != mDNSNULL)
    {
        const mDNSu8 *const bytes = srcaddr->ip.v4.b;
        const mDNSu32 len = sizeof(srcaddr->ip.v4.b);

        completeHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_FNV1a, completeHash, bytes, len);
        completeHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_FNV1a, completeHash, srcport.b,
            sizeof(srcport.b));

        complete2ndHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_SDBM, complete2ndHash, bytes, len);
        complete2ndHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_SDBM, complete2ndHash, srcport.b,
            sizeof(srcport.b));
    }
    if (dstaddr != mDNSNULL)
    {
        const mDNSu8 *const bytes = dstaddr->ip.v4.b;
        const mDNSu32 len = sizeof(dstaddr->ip.v4.b);

        completeHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_FNV1a, completeHash, bytes, len);
        completeHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_FNV1a, completeHash, dstport.b,
            sizeof(dstport.b));

        complete2ndHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_SDBM, complete2ndHash, bytes, len);
        complete2ndHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_SDBM, complete2ndHash, dstport.b,
            sizeof(dstport.b));
    }

    mDNSu8 ifIndexBytes[4];
    putVal32(ifIndexBytes, ifIndex);
    completeHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_FNV1a, completeHash, ifIndexBytes,
        sizeof(ifIndexBytes));
    complete2ndHash = mDNS_NonCryptoHashUpdateBytes(mDNSNonCryptoHash_SDBM, complete2ndHash, ifIndexBytes,
        sizeof(ifIndexBytes));
    mdns_assign(outCompleteHash, completeHash);

#define NUM_OF_SAVED_HASH_COUNT 20
    mDNSu32 i;
    mDNSu32 count;

    static mDNSu32 previousMsgHashes[NUM_OF_SAVED_HASH_COUNT] = {0};
    static mDNSu32 previousMsg2ndHashes[NUM_OF_SAVED_HASH_COUNT] = {0};
    static mDNSu32 nextMsgHashSlot = 0;
    static mDNSu32 nextMsgHashUninitializedSlot = 0;
    mdns_compile_time_check_local(mdns_countof(previousMsgHashes) == mdns_countof(previousMsg2ndHashes));

    mDNSBool msgHashSame = mDNSfalse;
    count = Min(mdns_countof(previousMsgHashes), nextMsgHashUninitializedSlot);
    for (i = 0; i < count; i++)
    {
        if (previousMsgHashes[i] == msgHash && previousMsg2ndHashes[i] == msg2ndHash)
        {
            msgHashSame = mDNStrue;
            break;
        }
    }
    if (!msgHashSame)
    {
        previousMsgHashes[nextMsgHashSlot] = msgHash;
        previousMsg2ndHashes[nextMsgHashSlot] = msg2ndHash;
        nextMsgHashSlot++;
        nextMsgHashSlot %= mdns_countof(previousMsgHashes);
        if (nextMsgHashUninitializedSlot < mdns_countof(previousMsgHashes))
        {
            nextMsgHashUninitializedSlot++;
        }
    }
    mdns_assign(outMsgHashSame, msgHashSame);

    static mDNSu32 previousCompleteHashes[NUM_OF_SAVED_HASH_COUNT] = {0};
    static mDNSu32 previousComplete2ndHashes[NUM_OF_SAVED_HASH_COUNT] = {0};
    static mDNSu32 nextCompleteHashSlot = 0;
    static mDNSu32 nextCompleteHashUninitializedSlot = 0;
    mdns_compile_time_check_local(mdns_countof(previousCompleteHashes) == mdns_countof(previousComplete2ndHashes));

    mDNSBool completeHashSame = mDNSfalse;
    count = Min(mdns_countof(previousCompleteHashes), nextCompleteHashUninitializedSlot);
    for (i = 0; i < count; i++)
    {
        if (previousCompleteHashes[i] == completeHash && previousComplete2ndHashes[i] == complete2ndHash)
        {
            completeHashSame = mDNStrue;
            break;
        }
    }
    if (!completeHashSame)
    {
        previousCompleteHashes[nextCompleteHashSlot] = completeHash;
        previousComplete2ndHashes[nextCompleteHashSlot] = complete2ndHash;
        nextCompleteHashSlot++;
        nextCompleteHashSlot %= mdns_countof(previousCompleteHashes);
        if (nextCompleteHashUninitializedSlot < mdns_countof(previousCompleteHashes))
        {
            nextCompleteHashUninitializedSlot++;
        }
    }
    mdns_assign(outCompleteHashSame, completeHashSame);
}

mDNSlocal mDNSBool DumpMDNSPacket_GetNameHashTypeClass(const DNSMessage *const msg, const mDNSu8 *ptr,
    const mDNSu8 *const end, mDNSu32 *const outNameHash, mDNSu16 *const outType, mDNSu16 *const outClass)
{
    mDNSBool found;
    domainname name;

    mdns_clang_static_analyzer_zero_mem(name.c, 1);
    ptr = getDomainName(msg, ptr, end, &name);
    mdns_require_action_quiet(ptr, exit, found = mDNSfalse);

    const mDNSu32 nameHash = mDNS_DomainNameFNV1aHash(&name);

    mdns_require_action_quiet(ptr + 4 <= end, exit, found = mDNSfalse);
    const mDNSu16 type = ReadField16(&ptr[0]);
    mDNSu16 class = ReadField16(&ptr[2]);

    const mDNSBool isMDNS = mDNSOpaque16IsZero(msg->h.id);
    if (isMDNS)
    {
        class &= kDNSClass_Mask;
    }

    mdns_assign(outNameHash, nameHash);
    mdns_assign(outType, type);
    mdns_assign(outClass, class);
    found = mDNStrue;

exit:
    return found;
}

// Each name hash/type pair contains 4-byte uint32_t hash value and 2-byte uint16_t type value, in network byte order.
#define DumpMDNSPacket_PairLen (sizeof(mDNSu32) + sizeof(mDNSu16))
// Currently, we only log the first 10 pairs.
#define DumpMDNSPacket_MaxPairCount 10
// The buffer size to hold the bytes.
#define DumpMDNSPacket_MaxBytesLen (DumpMDNSPacket_PairLen * DumpMDNSPacket_MaxPairCount)

mDNSlocal mStatus DumpMDNSPacket_GetNameHashTypeArray(const DNSMessage *const msg, const mDNSu8 *const end,
    mDNSu8 *const inOutNameHashTypeArray, const mDNSu32 maxByteCount, mDNSu32 *const outByteCount)
{
    mStatus err;
    const mDNSu8 *ptr_to_read;
    mDNSu8 *ptr_to_write = inOutNameHashTypeArray;
    mDNSu32 pairCount = 0;
    const mDNSu32 maxPairCount = maxByteCount / DumpMDNSPacket_PairLen;

    const DNSMessageHeader *const hdr = &msg->h;

    ptr_to_read = (const mDNSu8 *)msg->data;
    for (mDNSu32 i = 0; i < hdr->numQuestions && pairCount < maxPairCount; i++, pairCount++)
    {
        mDNSu32 qnameHash;
        mDNSu16 type;
        const mDNSBool found =  DumpMDNSPacket_GetNameHashTypeClass(msg, ptr_to_read, end, &qnameHash, &type, mDNSNULL);
        mdns_require_action_quiet(found, exit, err = mStatus_Invalid);

        ptr_to_write = putVal32(ptr_to_write, qnameHash);
        ptr_to_write = putVal16(ptr_to_write, type);

        ptr_to_read = skipQuestion(msg, ptr_to_read, end);
        mdns_require_action_quiet(ptr_to_read, exit, err = mStatus_Invalid);
    }

    for (mDNSu32 i = 0; i < hdr->numAnswers && pairCount < maxPairCount; i++, pairCount++)
    {
        mDNSu32 nameHash;
        mDNSu16 type;
        const mDNSBool found =  DumpMDNSPacket_GetNameHashTypeClass(msg, ptr_to_read, end, &nameHash, &type, mDNSNULL);
        mdns_require_action_quiet(found, exit, err = mStatus_Invalid);

        ptr_to_write = putVal32(ptr_to_write, nameHash);
        ptr_to_write = putVal16(ptr_to_write, type);

        ptr_to_read = skipResourceRecord(msg, ptr_to_read, end);
        mdns_require_action_quiet(ptr_to_read, exit, err = mStatus_Invalid);
    }

    for (mDNSu32 i = 0; i < hdr->numAuthorities && pairCount < maxPairCount; i++, pairCount++)
    {
        mDNSu32 nameHash;
        mDNSu16 type;
        const mDNSBool found =  DumpMDNSPacket_GetNameHashTypeClass(msg, ptr_to_read, end, &nameHash, &type, mDNSNULL);
        mdns_require_action_quiet(found, exit, err = mStatus_Invalid);

        ptr_to_write = putVal32(ptr_to_write, nameHash);
        ptr_to_write = putVal16(ptr_to_write, type);

        ptr_to_read = skipResourceRecord(msg, ptr_to_read, end);
        mdns_require_action_quiet(ptr_to_read, exit, err = mStatus_Invalid);
    }

    for (mDNSu32 i = 0; i < hdr->numAdditionals && pairCount < maxPairCount; i++, pairCount++)
    {
        mDNSu32 nameHash;
        mDNSu16 type;
        const mDNSBool found =  DumpMDNSPacket_GetNameHashTypeClass(msg, ptr_to_read, end, &nameHash, &type, mDNSNULL);
        mdns_require_action_quiet(found, exit, err = mStatus_Invalid);

        ptr_to_write = putVal32(ptr_to_write, nameHash);
        ptr_to_write = putVal16(ptr_to_write, type);

        ptr_to_read = skipResourceRecord(msg, ptr_to_read, end);
        mdns_require_action_quiet(ptr_to_read, exit, err = mStatus_Invalid);
    }

    err = mStatus_NoError;
exit:
    mdns_assign(outByteCount, pairCount * DumpMDNSPacket_PairLen);
    return err;
}

mDNSlocal void DumpMDNSPacket(const mDNSBool sent, const DNSMessage *const msg, const mDNSu8 *const end,
    const mDNSAddr *const srcaddr, const mDNSIPPort srcport, const mDNSAddr *const dstaddr, const mDNSIPPort dstport,
    const mDNSu32 ifIndex, const char *const ifName)
{
    const mDNSu32 msgLen = sizeof(DNSMessageHeader) + (mDNSu32)(end - msg->data);
    const mDNSBool query = DNSMessageIsQuery(msg);

    const mDNSBool unicastAssisted = (dstaddr && !mDNSAddrIsDNSMulticast(dstaddr) &&
        mDNSSameIPPort(dstport, MulticastDNSPort));

    mDNSu32 msgHash;            // Hash of the DNS message.
    mDNSBool sameMsg;           // If the hash matches a previous DNS message.
    mDNSu32 completeMsgHash;    // Hash of the DNS message, source address/port, destination address/port.
    mDNSBool sameCompleteMsg;   // If the hash matches a previous DNS message that is sent from the same source host to
                                // the same destination host.
    DumpMDNSPacket_CalculateAndCheckIfMsgAppearsBefore(msg, end, srcaddr, srcport, dstaddr, dstport, ifIndex, &msgHash,
        &sameMsg, &completeMsgHash, &sameCompleteMsg);

    // The header fields are already in host byte order.
    DNSMessageHeader hdr = msg->h;

    // Check if it is IPv6 or IPv4 message.
    mDNSBool ipv6Msg = mDNSfalse;
    if (srcaddr && srcaddr->type == mDNSAddrType_IPv6)
    {
        ipv6Msg = mDNStrue;
    }
    else if (dstaddr && dstaddr->type == mDNSAddrType_IPv6)
    {
        ipv6Msg = mDNStrue;
    }

#if MDNSRESPONDER_SUPPORTS(APPLE, OS_LOG)
    // The os_log specifier requires network byte order data.
    SwapDNSHeaderBytesWithHeader(&hdr);
    const mDNSu32 IDFlags = ReadField32(hdr.id.b);
    const uint64_t counts = ReadField64(&hdr.numQuestions);
    SwapDNSHeaderBytesWithHeader(&hdr);
#endif

    // Get the (Name hash, Type) bytes array from the DNS message, where name is converted to a 4-byte hash value
    // type is converted to a 2-byte value.
    mDNSu8 nameHashTypeBytes[DumpMDNSPacket_MaxBytesLen];
    mDNSu32 nameHashTypeBytesLen;
    if (!sameMsg)
    {
        // Only calculate the name hash type bytes when we have not seen this message recently.
        DumpMDNSPacket_GetNameHashTypeArray(msg, end, nameHashTypeBytes, sizeof(nameHashTypeBytes),
            &nameHashTypeBytesLen);
    }
    else
    {
        nameHashTypeBytesLen = 0;
    }

    // Note:
    // 1. There are two hash values printed for the message logging in `[Q(%x, %x)]`.
    //    a) The first value is the FNV-1a hash of the entire DNS message, the first value can be used to easily
    //       identify the same DNS message quickly.
    //    b) The second value is the FNV-1a hash of the entire DNS message, plus source address, source port,
    //       destination address, destination port and interface index. This value can be used to easily identify
    //       repetitive message transmission.
    //    c) The two hash values above are also used to avoid unnecessary duplicate logs by checking the hash values of
    //       the recent DNS message (currently recent means recent 20 messages).
    //    d) We use two separate hash algorithms to check if the message has occurred recently, but we only print
    //       FNV-1a hash values.
    // 2. For all "Send" events, we do not log destination address because it is always the corresponding multicast
    //    address, there is no need to log them over and over again.
    // 3. We print "query", "response" according to the type of the DNS message.
    // 4. If we have not seen the DNS message before, the message header, the record count section will be printed. Also
    //    the first 10 "(name hash, type)" pairs will be printed to provide more context.
    // 5. For the "Receive" event, we log source address so that we know where the query or response comes from.


    if (unicastAssisted) // unicast DNS
    {
        if (ipv6Msg)    // IPv6
        {
            if (sent)   // Send
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv6 mDNS query over unicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv6 mDNS query to " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u", msgHash, completeMsgHash, dstaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent %u-byte IPv6 mDNS query to " PRI_IP_ADDR " over unicast via " PUB_S "/%u "
                            "-- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES, msgHash,
                            completeMsgHash, msgLen, dstaddr,  ifName, ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags),
                            DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv6 mDNS response over unicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv6 mDNS response to " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u", msgHash, completeMsgHash, dstaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent %u-byte IPv6 mDNS response to " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, dstaddr, ifName, ifIndex,
                            DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
            else        // Receive
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv6 mDNS query over unicast",
                            msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv6 mDNS query from " PRI_IP_ADDR " over unicast via "
                            PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received %u-byte IPv6 mDNS query from " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, srcaddr, ifName, ifIndex,
                            DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv6 mDNS response over unicast",
                            msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv6 mDNS response from " PRI_IP_ADDR " over unicast via "
                            PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received %u-byte IPv6 mDNS response from " PRI_IP_ADDR " over unicast via "
                            PUB_S "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, srcaddr, ifName, ifIndex,
                            DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
        }
        else            // IPv4
        {
            if (sent)   // Send
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv4 mDNS query over unicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv4 mDNS query to " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u", msgHash, completeMsgHash, dstaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent %u-byte IPv4 mDNS query to " PRI_IP_ADDR " over unicast via " PUB_S "/%u "
                            "-- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES, msgHash,
                            completeMsgHash, msgLen, dstaddr,  ifName, ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags),
                            DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv4 mDNS response over unicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv4 mDNS response to " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u", msgHash, completeMsgHash, dstaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent %u-byte IPv4 mDNS response to " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, dstaddr, ifName, ifIndex,
                            DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
            else        // Receive
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv4 mDNS query over unicast",
                            msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv4 mDNS query from " PRI_IP_ADDR " over unicast via "
                            PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received %u-byte IPv4 mDNS query from " PRI_IP_ADDR " over unicast via " PUB_S
                            "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, srcaddr, ifName, ifIndex,
                            DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv4 mDNS response over unicast",
                            msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv4 mDNS response from " PRI_IP_ADDR " over unicast via "
                            PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received %u-byte IPv4 mDNS response from " PRI_IP_ADDR " over unicast via "
                            PUB_S "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, srcaddr, ifName, ifIndex,
                            DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
        }
    }
    else // multicast DNS
    {
        if (ipv6Msg)    // IPv6
        {
            if (sent)   // Send
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv6 mDNS query over multicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv6 mDNS query over multicast via " PUB_S "/%u", msgHash,
                            completeMsgHash, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent %u-byte IPv6 mDNS query over multicast via " PUB_S "/%u -- "
                            DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, ifName, ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags),
                            DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv6 mDNS response over multicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv6 mDNS response over multicast via " PUB_S "/%u", msgHash,
                            completeMsgHash, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent %u-byte IPv6 mDNS response over multicast via " PUB_S "/%u -- "
                            DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, ifName, ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags),
                            DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
            else        // Receive
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv6 mDNS query over multicast", msgHash,
                            completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv6 mDNS query from " PRI_IP_ADDR
                            " over multicast via " PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName,
                            ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received %u-byte IPv6 mDNS query from " PRI_IP_ADDR
                            " over multicast via " PUB_S "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS
                            " " MDNS_NAME_HASH_TYPE_BYTES, msgHash,
                            completeMsgHash, msgLen, srcaddr, ifName, ifIndex,
                            DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv6 mDNS response over multicast",
                            msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv6 mDNS response from " PRI_IP_ADDR
                            " over multicast via " PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName,
                            ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received %u-byte IPv6 mDNS response from " PRI_IP_ADDR
                            " over multicast via " PUB_S "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS
                            " " MDNS_NAME_HASH_TYPE_BYTES, msgHash, completeMsgHash, msgLen, srcaddr, ifName,
                            ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
        }
        else            // IPv4
        {
            if (sent)   // Send
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv4 mDNS query over multicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent a previous IPv4 mDNS query over multicast via " PUB_S "/%u", msgHash,
                            completeMsgHash, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Sent %u-byte IPv4 mDNS query over multicast via " PUB_S "/%u -- "
                            DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, ifName, ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags),
                            DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv4 mDNS response over multicast", msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent a previous IPv4 mDNS response over multicast via " PUB_S "/%u", msgHash,
                            completeMsgHash, ifName, ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Sent %u-byte IPv4 mDNS response over multicast via " PUB_S "/%u -- "
                            DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " " MDNS_NAME_HASH_TYPE_BYTES,
                            msgHash, completeMsgHash, msgLen, ifName, ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags),
                            DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
            else        // Receive
            {
                if (query)  // Query
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv4 mDNS query over multicast", msgHash,
                            completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received a previous IPv4 mDNS query from " PRI_IP_ADDR
                            " over multicast via " PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName,
                            ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[A(%x, %x)] Received %u-byte IPv4 mDNS query from " PRI_IP_ADDR " over multicast"
                            " via " PUB_S "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS " "
                            MDNS_NAME_HASH_TYPE_BYTES, msgHash, completeMsgHash, msgLen, srcaddr, ifName,
                            ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
                else        // Response
                {
                    if (sameCompleteMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv4 mDNS response over multicast",
                            msgHash, completeMsgHash);
                    }
                    else if (sameMsg)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received a previous IPv4 mDNS response from " PRI_IP_ADDR
                            " over multicast via " PUB_S "/%u", msgHash, completeMsgHash, srcaddr, ifName,
                            ifIndex);
                    }
                    else
                    {
                        LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEFAULT,
                            "[Q(%x, %x)] Received %u-byte IPv4 mDNS response from " PRI_IP_ADDR
                            " over multicast via " PUB_S "/%u -- " DNS_MSG_ID_FLAGS ", counts: " DNS_MSG_COUNTS
                            " " MDNS_NAME_HASH_TYPE_BYTES, msgHash, completeMsgHash, msgLen, srcaddr, ifName,
                            ifIndex, DNS_MSG_ID_FLAGS_PARAM(hdr, IDFlags), DNS_MSG_COUNTS_PARAM(hdr, counts),
                            MDNS_NAME_HASH_TYPE_BYTES_PARAM(nameHashTypeBytes, nameHashTypeBytesLen));
                    }
                }
            }
        }
    }
}

// Note: DumpPacket expects the packet header fields in host byte order, not network byte order
mDNSexport void DumpPacket(mStatus status, mDNSBool sent, const char *transport,
    const mDNSAddr *srcaddr, mDNSIPPort srcport,const mDNSAddr *dstaddr, mDNSIPPort dstport, const DNSMessage *const msg,
    const mDNSu8 *const end, mDNSInterfaceID interfaceID)
{
    const mDNSAddr zeroIPv4Addr = { mDNSAddrType_IPv4, {{{ 0 }}} };
    char action[32];

    if (!status) mDNS_snprintf(action, sizeof(action), sent ? "Sent" : "Received");
    else         mDNS_snprintf(action, sizeof(action), "ERROR %d %sing", status, sent ? "Send" : "Receiv");

#if __APPLE__
    const mDNSu32 interfaceIndex = IIDPrintable(interfaceID);
    const char *const interfaceName = InterfaceNameForID(&mDNSStorage, interfaceID);
#else
    const mDNSu32 interfaceIndex = mDNSPlatformInterfaceIndexfromInterfaceID(&mDNSStorage, interfaceID, mDNStrue);
    const char *const interfaceName = "interface";
#endif

    if (!mDNSOpaque16IsZero(msg->h.id))
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "[Q%u] " PUB_S " " PUB_S " DNS Message %lu bytes from "
            PRI_IP_ADDR ":%d to " PRI_IP_ADDR ":%d via " PUB_S " (%p)", mDNSVal16(msg->h.id), action, transport,
            (unsigned long)(end - (const mDNSu8 *)msg), srcaddr ? srcaddr : &zeroIPv4Addr, mDNSVal16(srcport),
            dstaddr ? dstaddr : &zeroIPv4Addr, mDNSVal16(dstport), interfaceName, interfaceID);
        DNSMessageDumpToLog(msg, end);
    }
    else
    {
        DumpMDNSPacket(sent, msg, end, srcaddr, srcport, dstaddr, dstport, interfaceIndex, interfaceName);
        if (status)
        {
            if (sent)
            {
                LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_ERROR,
                    "Sending mDNS message failed - mStatus: %d", status);
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_ERROR,
                    "Receiving mDNS message failed - mStatus: %d", status);
            }
        }
    }
}

// ***************************************************************************
// MARK: - Packet Sending Functions

// Stub definition of TCPSocket_struct so we can access flags field. (Rest of TCPSocket_struct is platform-dependent.)
struct TCPSocket_struct { mDNSIPPort port; TCPSocketFlags flags; /* ... */ };
// Stub definition of UDPSocket_struct so we can access port field. (Rest of UDPSocket_struct is platform-dependent.)
struct UDPSocket_struct { mDNSIPPort     port;  /* ... */ };

// Note: When we sign a DNS message using DNSDigest_SignMessage(), the current real-time clock value is used, which
// is why we generally defer signing until we send the message, to ensure the signature is as fresh as possible.
mDNSexport mStatus mDNSSendDNSMessage(mDNS *const m, DNSMessage *const msg, mDNSu8 *end,
                                      mDNSInterfaceID InterfaceID, TCPSocket *tcpSrc, UDPSocket *udpSrc, const mDNSAddr *dst,
                                      mDNSIPPort dstport, DomainAuthInfo *authInfo, mDNSBool useBackgroundTrafficClass)
{
    mStatus status = mStatus_NoError;
    const mDNSu16 numAdditionals = msg->h.numAdditionals;


    // Zero-length message data is okay (e.g. for a DNS Update ack, where all we need is an ID and an error code
    if (end < msg->data || end - msg->data > AbsoluteMaxDNSMessageData)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNSSendDNSMessage: invalid message %p %p %ld", msg->data, end, end - msg->data);
        return mStatus_BadParamErr;
    }

    // Put all the integer values in IETF byte-order (MSB first, LSB second)
    SwapDNSHeaderBytes(msg);

    if (authInfo) DNSDigest_SignMessage(msg, &end, authInfo, 0);    // DNSDigest_SignMessage operates on message in network byte order

#if defined(DEBUG) && DEBUG
    if (authInfo && end)
    {
        // If this is a debug build, every time when we sign the response, use the verifying function to ensure that
        // both functions work correctly.
        DNSDigest_VerifyMessage_Verify(msg, end, authInfo);
    }
#endif

    if (!end)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNSSendDNSMessage: DNSDigest_SignMessage failed");
        status = mStatus_NoMemoryErr;
    }
    else
    {
        // Send the packet on the wire
        if (!tcpSrc)
            status = mDNSPlatformSendUDP(m, msg, end, InterfaceID, udpSrc, dst, dstport, useBackgroundTrafficClass);
        else
        {
            mDNSu16 msglen = (mDNSu16)(end - (mDNSu8 *)msg);
            mDNSu8 lenbuf[2] = { (mDNSu8)(msglen >> 8), (mDNSu8)(msglen & 0xFF) };
            char *buf;
            long nsent;

            // Try to send them in one packet if we can allocate enough memory
            buf = (char *) mDNSPlatformMemAllocate(msglen + 2);
            if (buf)
            {
                buf[0] = lenbuf[0];
                buf[1] = lenbuf[1];
                mDNSPlatformMemCopy(buf+2, msg, msglen);
                nsent = mDNSPlatformWriteTCP(tcpSrc, buf, msglen+2);
                if (nsent != (msglen + 2))
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNSSendDNSMessage: write message failed %ld/%d", nsent, msglen);
                    status = mStatus_ConnFailed;
                }
                mDNSPlatformMemFree(buf);
            }
            else
            {
                nsent = mDNSPlatformWriteTCP(tcpSrc, (char*)lenbuf, 2);
                if (nsent != 2)
                {
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNSSendDNSMessage: write msg length failed %ld/%d", nsent, 2);
                    status = mStatus_ConnFailed;
                }
                else
                {
                    nsent = mDNSPlatformWriteTCP(tcpSrc, (char *)msg, msglen);
                    if (nsent != msglen)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "mDNSSendDNSMessage: write msg body failed %ld/%d", nsent, msglen);
                        status = mStatus_ConnFailed;
                    }
                }
            }
        }
    }

    // Swap the integer values back the way they were (remember that numAdditionals may have been changed by putHINFO and/or SignMessage)
    SwapDNSHeaderBytes(msg);

    char *transport = "UDP";
    mDNSIPPort portNumber = udpSrc ? udpSrc->port : MulticastDNSPort;
    if (tcpSrc)
    {
        if (tcpSrc->flags)
            transport = "TLS";
        else
            transport = "TCP";
        portNumber = tcpSrc->port;
    }
    DumpPacket(status, mDNStrue, transport, mDNSNULL, portNumber, dst, dstport, msg, end, InterfaceID);

    // put the number of additionals back the way it was
    msg->h.numAdditionals = numAdditionals;

    return(status);
}

// ***************************************************************************
// MARK: - DNSQuestion Functions

#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
mDNSBool DNSQuestionNeedsSensitiveLogging(const DNSQuestion *const q)
{
    return is_apple_internal_build() && (q->logPrivacyLevel == dnssd_log_privacy_level_private);
}
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, RUNTIME_MDNS_METRICS)
mDNSBool DNSQuestionCollectsMDNSMetric(const DNSQuestion *const q)
{
    return (!q->DuplicateOf && mDNSOpaque16IsZero(q->TargetQID));
}
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)

mDNSlocal mDNSBool DNSQuestionUsesAWDL(const DNSQuestion *const q)
{
    if (q->InterfaceID == mDNSInterface_Any)
    {
        return ((q->flags & kDNSServiceFlagsIncludeAWDL) != 0);
    }
    else
    {
        return mDNSPlatformInterfaceIsAWDL(q->InterfaceID);
    }
}

mDNSBool DNSQuestionIsEligibleForMDNSAlternativeService(const DNSQuestion *const q)
{
    // 0. The system is not in a demo mode where mDNS traffic is ensured to be lossless in a wired connection.
    // 1. The question must be an mDNS question.
    // 2. The question cannot enable resolution over AWDL.
    //    (because the resolution over mDNS alternative service is mutual exclusive with the resolution over AWDL)
    return (!is_airplay_demo_mode_enabled() && mDNSOpaque16IsZero(q->TargetQID) && !DNSQuestionUsesAWDL(q));
}

mDNSBool DNSQuestionRequestsMDNSAlternativeService(const DNSQuestion *const q)
{
    return (!mDNSOpaque16IsZero(q->TargetQID) && !Question_uDNS(q));
}

mDNSBool DNSQuestionUsesMDNSAlternativeService(const DNSQuestion *const q)
{
    return q->dnsservice && mdns_dns_service_is_mdns_alternative(q->dnsservice);
}
#endif

// ***************************************************************************
// MARK: - RR List Management & Task Management

mDNSexport void mDNS_VerifyLockState(const char *const operation, const mDNSBool checkIfLockHeld,
    const mDNSu32 mDNS_busy, const mDNSu32 mDNS_reentrancy, const char *const functionName, const mDNSu32 lineNumber)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, OS_UNFAIR_LOCK)
    static os_unfair_lock logLock = OS_UNFAIR_LOCK_INIT;
#endif
    static const char *lastLockOperator = mDNSNULL; // The name of the function that succeeded in doing lock operation last time.
    static mDNSu32 lineNumberlastLockOperator = 0; // The line number in the source code when this function gets called last time.

#define CRASH_ON_LOCK_ERROR 0
#if (CRASH_ON_LOCK_ERROR)
    // When CRASH_ON_LOCK_ERROR is set to 1, if we encounter lock error, we will make mDNSResponder crash immediately
    // to let the bug to be identified easily.
    mDNSBool lockErrorEncountered = mDNSfalse;
#endif

    if (checkIfLockHeld)
    {
        // If the lock is held by the caller, then the number of times that the lock has been grabbed should be one more
        // than the number of times that the lock has been dropped, so that only one lock is currently being held.
        if (mDNS_busy > mDNS_reentrancy + 1)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "Lock failure: Check Lock, lock was grabbed by multiple callers - "
                "caller: " PUB_S " at line %u, last successful lock holder: " PUB_S " at line %u, "
                "mDNS_busy (%u) != mDNS_reentrancy (%u).", functionName, lineNumber, lastLockOperator,
                lineNumberlastLockOperator, mDNS_busy, mDNS_reentrancy);
        #if (CRASH_ON_LOCK_ERROR)
            lockErrorEncountered = mDNStrue;
        #endif
        }
        else if (mDNS_busy < mDNS_reentrancy + 1)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "Lock failure: Check Lock, last lock dropper dropped the lock before grabbing it - "
                "caller: " PUB_S " at line %u, last lock dropper: " PUB_S " at line %u, "
                "mDNS_busy (%u) != mDNS_reentrancy (%u).", functionName, lineNumber, lastLockOperator,
                lineNumberlastLockOperator, mDNS_busy, mDNS_reentrancy);
        #if (CRASH_ON_LOCK_ERROR)
            lockErrorEncountered = mDNStrue;
        #endif
        }
    }
    else
    {
        // In non-critical section:
        // The number of times that the lock has been grabbed should be equal to the number of times that the lock has
        // been dropped, which means, no one is currently holding the real lock.
        if (mDNS_busy == mDNS_reentrancy)
        {
            switch (operation[0])
            {
                case 'L': // "Lock" (it is paired with "Unlock")
                case 'D': // "Drop Lock" (it is paired with "Reclaim Lock")
                    // Add new lock state, and we need to remember who succeeds in doing the operation because it might
                    // lead to invalid lock state.
                #if MDNSRESPONDER_SUPPORTS(APPLE, OS_UNFAIR_LOCK)
                    os_unfair_lock_lock(&logLock);
                #endif
                    lastLockOperator = functionName;
                    lineNumberlastLockOperator = lineNumber;
                #if MDNSRESPONDER_SUPPORTS(APPLE, OS_UNFAIR_LOCK)
                    os_unfair_lock_unlock(&logLock);
                #endif
                    break;

                case 'U': // "Unlock"
                case 'R': // "Reclaim Lock"
                    // Remove the previous lock state, and we can remove the name and the line number that has been
                    // saved.
                #if MDNSRESPONDER_SUPPORTS(APPLE, OS_UNFAIR_LOCK)
                    os_unfair_lock_lock(&logLock);
                #endif
                    lastLockOperator = mDNSNULL;
                    lineNumberlastLockOperator = 0;
                #if MDNSRESPONDER_SUPPORTS(APPLE, OS_UNFAIR_LOCK)
                    os_unfair_lock_unlock(&logLock);
                #endif
                case 'C': // "Check Lock"
                    // "Check Lock" operation will never change the lock state, so no need to take a note for that.
                    break;

                default:
                    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT, "Invalid lock operation - " PUB_S, operation);
                    break;
            }
        }
        else if (mDNS_busy > mDNS_reentrancy)
        {
            // If mDNS_busy is greater than mDNS_reentrancy, there is someone who has grabbed the lock. This is invalid
            // in a critical section.
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "Lock failure: " PUB_S ", last lock holder still holds the lock - "
                "caller: " PUB_S " at line %u, last successful lock holder: " PUB_S " at line %u, "
                "mDNS_busy (%u) != mDNS_reentrancy (%u).", operation, functionName, lineNumber, lastLockOperator,
                lineNumberlastLockOperator, mDNS_busy, mDNS_reentrancy);
        #if (CRASH_ON_LOCK_ERROR)
            lockErrorEncountered = mDNStrue;
        #endif
        }
        else // m->mDNS_busy < m->mDNS_reentrancy
        {
            // If mDNS_busy is less than mDNS_reentrancy, something bad happens, because no one should drop the lock
            // before grabbing it successfully. This should never heppen.
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_FAULT,
                "Lock failure: " PUB_S ", last lock dropper dropped the lock before grabbing it - "
                "caller: " PUB_S " at line %u, last lock dropper: " PUB_S " at line %u, "
                "mDNS_busy (%u) != mDNS_reentrancy (%u).", operation, functionName, lineNumber, lastLockOperator,
                lineNumberlastLockOperator, mDNS_busy, mDNS_reentrancy);
        #if (CRASH_ON_LOCK_ERROR)
            lockErrorEncountered = mDNStrue;
        #endif
        }
    }

#if (CRASH_ON_LOCK_ERROR)
    if (lockErrorEncountered)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                  "Encounter lock error, make mDNSResponder crash immediately.");
        assert(0);
    }
#endif
}

mDNSexport void mDNS_Lock_(mDNS *const m, const char *const functionName, const mDNSu32 lineNumber)
{
    // MUST grab the platform lock FIRST!
    mDNSPlatformLock(m);

    // Normally, mDNS_reentrancy is zero and so is mDNS_busy
    // However, when we call a client callback mDNS_busy is one, and we increment mDNS_reentrancy too
    // If that client callback does mDNS API calls, mDNS_reentrancy and mDNS_busy will both be one
    // If mDNS_busy != mDNS_reentrancy that's a bad sign
    mDNS_VerifyLockState("Lock", mDNSfalse, m->mDNS_busy, m->mDNS_reentrancy, functionName, lineNumber);

    // If this is an initial entry into the mDNSCore code, set m->timenow
    // else, if this is a re-entrant entry into the mDNSCore code, m->timenow should already be set
    if (m->mDNS_busy == 0)
    {
        if (m->timenow)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, PUB_S ": mDNS_Lock: m->timenow already set (%u/%u)",
                functionName, m->timenow, mDNS_TimeNow_NoLock(m));
        }

        m->timenow = mDNS_TimeNow_NoLock(m);
        if (m->timenow == 0) m->timenow = 1;
    }
    else if (m->timenow == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            PUB_S ": mDNS_Lock: m->mDNS_busy is %u but m->timenow not set", functionName, m->mDNS_busy);

        m->timenow = mDNS_TimeNow_NoLock(m);
        if (m->timenow == 0) m->timenow = 1;
    }

    if (m->timenow_last - m->timenow > 0)
    {
        m->timenow_adjust += m->timenow_last - m->timenow;
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
            PUB_S ": mDNSPlatformRawTime went backwards by %d ticks; setting correction factor to %d",
            functionName, m->timenow_last - m->timenow, m->timenow_adjust);

        m->timenow = m->timenow_last;
    }
    m->timenow_last = m->timenow;

    // Increment mDNS_busy so we'll recognise re-entrant calls
    m->mDNS_busy++;
}

mDNSlocal AuthRecord *AnyLocalRecordReady(const mDNS *const m)
{
    AuthRecord *rr;
    for (rr = m->NewLocalRecords; rr; rr = rr->next)
        if (LocalRecordReady(rr)) return rr;
    return mDNSNULL;
}

mDNSlocal mDNSs32 GetNextScheduledEvent(const mDNS *const m)
{
    mDNSs32 e = m->timenow + FutureTime;
    if (m->mDNSPlatformStatus != mStatus_NoError) return(e);
    if (m->NewQuestions)
    {
        if (m->NewQuestions->DelayAnswering) e = m->NewQuestions->DelayAnswering;
        else return(m->timenow);
    }
    if (m->NewLocalOnlyQuestions) return(m->timenow);
    if (m->NewLocalRecords && AnyLocalRecordReady(m)) return(m->timenow);
    if (m->NewLocalOnlyRecords) return(m->timenow);
    if (m->SPSProxyListChanged) return(m->timenow);
    if (m->LocalRemoveEvents) return(m->timenow);

#ifndef UNICAST_DISABLED
    if (e - m->NextuDNSEvent         > 0) e = m->NextuDNSEvent;
    if (e - m->NextScheduledNATOp    > 0) e = m->NextScheduledNATOp;
    if (m->NextSRVUpdate && e - m->NextSRVUpdate > 0) e = m->NextSRVUpdate;
#endif

    if (e - m->NextCacheCheck        > 0) e = m->NextCacheCheck;
    if (e - m->NextScheduledSPS      > 0) e = m->NextScheduledSPS;
    if (e - m->NextScheduledKA       > 0) e = m->NextScheduledKA;

#if MDNSRESPONDER_SUPPORTS(APPLE, BONJOUR_ON_DEMAND)
    if (m->NextBonjourDisableTime && (e - m->NextBonjourDisableTime > 0)) e = m->NextBonjourDisableTime;
#endif

    // Check if it is time to stop domain enumeration.
    for (const DomainEnumerationOp *op = m->domainsToDoEnumeration; op != mDNSNULL; op = op->next)
    {
        // Iterate over all types of domain enumeration.
        for (mDNSu32 type = 0; type < mDNS_DomainTypeMaxCount; type++)
        {
            if (op->enumerations[type] == mDNSNULL)
            {
                continue;
            }

            // Only check the domain enumeration that starts the stopping process.
            if (op->enumerations[type]->state != DomainEnumerationState_StopInProgress)
            {
                continue;
            }

            if (e - op->enumerations[type]->nextStopTime > 0)
            {
                e = op->enumerations[type]->nextStopTime;
            }
        }
    }

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
    const mDNSs32 nextResolverDiscoveryEvent = ResolverDiscovery_GetNextScheduledEvent();
    if (nextResolverDiscoveryEvent && (e - nextResolverDiscoveryEvent > 0)) e = nextResolverDiscoveryEvent;
#endif

    // NextScheduledSPRetry only valid when DelaySleep not set
    if (!m->DelaySleep && m->SleepLimit && e - m->NextScheduledSPRetry > 0) e = m->NextScheduledSPRetry;
    if (m->DelaySleep && e - m->DelaySleep > 0) e = m->DelaySleep;

    if (m->SuppressQueries)
    {
        if (e - m->SuppressQueries       > 0) e = m->SuppressQueries;
    }
    else
    {
        if (e - m->NextScheduledQuery    > 0) e = m->NextScheduledQuery;
        if (e - m->NextScheduledProbe    > 0) e = m->NextScheduledProbe;
    }
    if (m->SuppressResponses)
    {
        if (e - m->SuppressResponses     > 0) e = m->SuppressResponses;
    }
    else
    {
        if (e - m->NextScheduledResponse > 0) e = m->NextScheduledResponse;
    }
    if (e - m->NextScheduledStopTime > 0) e = m->NextScheduledStopTime;

    if (m->NextBLEServiceTime && (e - m->NextBLEServiceTime > 0)) e = m->NextBLEServiceTime;

#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
    if (m->NextUpdateDNSSECValidatedCache && (e - m->NextUpdateDNSSECValidatedCache > 0))
    {
        e = m->NextUpdateDNSSECValidatedCache;
    }
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, RUNTIME_MDNS_METRICS)
    if (m->NextMDNSResponseDelayReport && (e - m->NextMDNSResponseDelayReport > 0))
    {
        e = m->NextMDNSResponseDelayReport;
    }
#endif

    return(e);
}

#define LogTSE TSE++,LogMsg

mDNSexport void ShowTaskSchedulingError(mDNS *const m)
{
    int TSE = 0;
    AuthRecord *rr;
    mDNS_Lock(m);

    LogMsg("Task Scheduling Error: *** Continuously busy for more than a second");

    // Note: To accurately diagnose *why* we're busy, the debugging code here needs to mirror the logic in GetNextScheduledEvent above

    if (m->NewQuestions && (!m->NewQuestions->DelayAnswering || m->timenow - m->NewQuestions->DelayAnswering >= 0))
        LogTSE("Task Scheduling Error: NewQuestion %##s (%s)",
               m->NewQuestions->qname.c, DNSTypeName(m->NewQuestions->qtype));

    if (m->NewLocalOnlyQuestions)
        LogTSE("Task Scheduling Error: NewLocalOnlyQuestions %##s (%s)",
               m->NewLocalOnlyQuestions->qname.c, DNSTypeName(m->NewLocalOnlyQuestions->qtype));

    if (m->NewLocalRecords)
    {
        rr = AnyLocalRecordReady(m);
        if (rr) LogTSE("Task Scheduling Error: NewLocalRecords %s", ARDisplayString(m, rr));
    }

    if (m->NewLocalOnlyRecords) LogTSE("Task Scheduling Error: NewLocalOnlyRecords");

    if (m->SPSProxyListChanged) LogTSE("Task Scheduling Error: SPSProxyListChanged");

    if (m->LocalRemoveEvents) LogTSE("Task Scheduling Error: LocalRemoveEvents");

#ifndef UNICAST_DISABLED
    if (m->timenow - m->NextuDNSEvent         >= 0)
        LogTSE("Task Scheduling Error: m->NextuDNSEvent %d",         m->timenow - m->NextuDNSEvent);
    if (m->timenow - m->NextScheduledNATOp    >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledNATOp %d",    m->timenow - m->NextScheduledNATOp);
    if (m->NextSRVUpdate && m->timenow - m->NextSRVUpdate >= 0)
        LogTSE("Task Scheduling Error: m->NextSRVUpdate %d",         m->timenow - m->NextSRVUpdate);
#endif

    if (m->timenow - m->NextCacheCheck        >= 0)
        LogTSE("Task Scheduling Error: m->NextCacheCheck %d",        m->timenow - m->NextCacheCheck);
    if (m->timenow - m->NextScheduledSPS      >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledSPS %d",      m->timenow - m->NextScheduledSPS);
    if (m->timenow - m->NextScheduledKA       >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledKA %d",      m->timenow - m->NextScheduledKA);
    if (!m->DelaySleep && m->SleepLimit && m->timenow - m->NextScheduledSPRetry >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledSPRetry %d",  m->timenow - m->NextScheduledSPRetry);
    if (m->DelaySleep && m->timenow - m->DelaySleep >= 0)
        LogTSE("Task Scheduling Error: m->DelaySleep %d",            m->timenow - m->DelaySleep);

    if (m->SuppressQueries && m->timenow - m->SuppressQueries >= 0)
        LogTSE("Task Scheduling Error: m->SuppressQueries %d",       m->timenow - m->SuppressQueries);
    if (m->SuppressResponses && m->timenow - m->SuppressResponses >= 0)
        LogTSE("Task Scheduling Error: m->SuppressResponses %d",     m->timenow - m->SuppressResponses);
    if (m->timenow - m->NextScheduledQuery    >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledQuery %d",    m->timenow - m->NextScheduledQuery);
    if (m->timenow - m->NextScheduledProbe    >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledProbe %d",    m->timenow - m->NextScheduledProbe);
    if (m->timenow - m->NextScheduledResponse >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledResponse %d", m->timenow - m->NextScheduledResponse);
    if (m->timenow - m->NextScheduledStopTime >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledStopTime %d", m->timenow - m->NextScheduledStopTime);

    if (m->timenow - m->NextScheduledEvent    >= 0)
        LogTSE("Task Scheduling Error: m->NextScheduledEvent %d",    m->timenow - m->NextScheduledEvent);

    if (m->NetworkChanged && m->timenow - m->NetworkChanged >= 0)
        LogTSE("Task Scheduling Error: NetworkChanged %d",           m->timenow - m->NetworkChanged);

    if (!TSE) LogMsg("Task Scheduling Error: *** No likely causes identified");
    else LogMsg("Task Scheduling Error: *** %d potential cause%s identified (significant only if the same cause consistently appears)", TSE, TSE > 1 ? "s" : "");

    mDNS_Unlock(m);
}

mDNSexport void mDNS_Unlock_(mDNS *const m, const char *const functionName, const mDNSu32 lineNumber)
{
    // Decrement mDNS_busy
    m->mDNS_busy--;

    // Check for locking failures
    mDNS_VerifyLockState("Unlock", mDNSfalse, m->mDNS_busy, m->mDNS_reentrancy, functionName, lineNumber);

    // If this is a final exit from the mDNSCore code, set m->NextScheduledEvent and clear m->timenow
    if (m->mDNS_busy == 0)
    {
        m->NextScheduledEvent = GetNextScheduledEvent(m);
        if (m->timenow == 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, PUB_S ": mDNS_Unlock: ERROR! m->timenow aready zero",
                      functionName);
        }
        m->timenow = 0;
    }

    // MUST release the platform lock LAST!
    mDNSPlatformUnlock(m);
}

// ***************************************************************************
// MARK: - Specialized mDNS version of vsnprintf

static const struct mDNSprintf_format
{
    unsigned leftJustify : 1;
    unsigned forceSign : 1;
    unsigned zeroPad : 1;
    unsigned havePrecision : 1;
    unsigned hSize : 1;
    unsigned lSize : 1;
    char altForm;
    char sign;              // +, - or space
    unsigned int fieldWidth;
    unsigned int precision;
} mDNSprintf_format_default = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

#define kHexDigitsLowercase "0123456789abcdef"
#define kHexDigitsUppercase "0123456789ABCDEF";

mDNSexport mDNSu32 mDNS_vsnprintf(char *sbuffer, mDNSu32 buflen, const char *fmt, va_list arg)
{
    mDNSu32 nwritten = 0;
    int c;
    if (buflen == 0) return(0);
    buflen--;       // Pre-reserve one space in the buffer for the terminating null
    if (buflen == 0) goto exit;

    for (c = *fmt; c != '\0'; c = (c != '\0') ? *++fmt : c)
    {
        unsigned long n;
        int hexdump = mDNSfalse;
		if (c != '%')
        {
            *sbuffer++ = (char)c;
            if (++nwritten >= buflen) goto exit;
        }
        else
        {
            unsigned int i=0, j;
            // The mDNS Vsprintf Argument Conversion Buffer is used as a temporary holding area for
            // generating decimal numbers, hexdecimal numbers, IP addresses, domain name strings, etc.
            // The size needs to be enough for a 256-byte domain name plus some error text.
            #define mDNS_VACB_Size 300
            char mDNS_VACB[mDNS_VACB_Size];
            #define mDNS_VACB_Lim (&mDNS_VACB[mDNS_VACB_Size])
            #define mDNS_VACB_Remain(s) ((mDNSu32)(mDNS_VACB_Lim - s))
            char *s = mDNS_VACB_Lim, *digits;
            struct mDNSprintf_format F = mDNSprintf_format_default;

            while (1)   //  decode flags
            {
                c = *++fmt;
                if      (c == '-') F.leftJustify = 1;
                else if (c == '+') F.forceSign = 1;
                else if (c == ' ') F.sign = ' ';
                else if (c == '#') F.altForm++;
                else if (c == '0') F.zeroPad = 1;
                else break;
            }

            if (c == '*')   //  decode field width
            {
                int f = va_arg(arg, int);
                if (f < 0) { f = -f; F.leftJustify = 1; }
                F.fieldWidth = (unsigned int)f;
                c = *++fmt;
            }
            else
            {
                for (; c >= '0' && c <= '9'; c = *++fmt)
                    F.fieldWidth = (10 * F.fieldWidth) + (c - '0');
            }

            if (c == '.')   //  decode precision
            {
                if ((c = *++fmt) == '*')
                { F.precision = va_arg(arg, unsigned int); c = *++fmt; }
                else for (; c >= '0' && c <= '9'; c = *++fmt)
                        F.precision = (10 * F.precision) + (c - '0');
                F.havePrecision = 1;
            }

            if (F.leftJustify) F.zeroPad = 0;

conv:
            switch (c)  //  perform appropriate conversion
            {
            case 'h':  F.hSize = 1; c = *++fmt; goto conv;
            case 'l':       // fall through
            case 'L':  F.lSize = 1; c = *++fmt; goto conv;
            case 'd':
            case 'i':  if (F.lSize) n = (unsigned long)va_arg(arg, long);
                else n = (unsigned long)va_arg(arg, int);
                if (F.hSize) n = (short) n;
                if ((long) n < 0) { n = (unsigned long)-(long)n; F.sign = '-'; }
                else if (F.forceSign) F.sign = '+';
                goto decimal;
            case 'u':  if (F.lSize) n = va_arg(arg, unsigned long);
                else n = va_arg(arg, unsigned int);
                if (F.hSize) n = (unsigned short) n;
                F.sign = 0;
                goto decimal;
decimal:    if (!F.havePrecision)
                {
                    if (F.zeroPad)
                    {
                        F.precision = F.fieldWidth;
                        if (F.sign) --F.precision;
                    }
                    if (F.precision < 1) F.precision = 1;
                }
                if (F.precision > mDNS_VACB_Size - 1)
                    F.precision = mDNS_VACB_Size - 1;
                for (i = 0; n; n /= 10, i++) *--s = (char)(n % 10 + '0');
                for (; i < F.precision; i++) *--s = '0';
                if (F.sign) { *--s = F.sign; i++; }
                break;

            case 'o':  if (F.lSize) n = va_arg(arg, unsigned long);
                else n = va_arg(arg, unsigned int);
                if (F.hSize) n = (unsigned short) n;
                if (!F.havePrecision)
                {
                    if (F.zeroPad) F.precision = F.fieldWidth;
                    if (F.precision < 1) F.precision = 1;
                }
                if (F.precision > mDNS_VACB_Size - 1)
                    F.precision = mDNS_VACB_Size - 1;
                for (i = 0; n; n /= 8, i++) *--s = (char)(n % 8 + '0');
                if (F.altForm && i && *s != '0') { *--s = '0'; i++; }
                for (; i < F.precision; i++) *--s = '0';
                break;

            case 'a':  {
                unsigned char *a = va_arg(arg, unsigned char *);
                if (!a) { static char emsg[] = "<<NULL>>"; s = emsg; i = sizeof(emsg)-1; }
                else
                {
                    s = mDNS_VACB;              // Adjust s to point to the start of the buffer, not the end
                    if (F.altForm)
                    {
                        const mDNSAddr *const ip = (const mDNSAddr *)a;
                        switch (ip->type)
                        {
                        case mDNSAddrType_IPv4: F.precision =  4; a = (unsigned char *)&ip->ip.v4; break;
                        case mDNSAddrType_IPv6: F.precision = 16; a = (unsigned char *)&ip->ip.v6; break;
                        default:
                            if (ip->type == mDNSAddrType_None)
                            {
                                i = mDNS_snprintf(mDNS_VACB, sizeof(mDNS_VACB), "<<UNSPECIFIED IP ADDRESS>>");
                            }
                            else
                            {
                                i = mDNS_snprintf(mDNS_VACB, sizeof(mDNS_VACB),
                                    "<<ERROR: %%#a used with unsupported type: %d>>", ip->type);
                            }
                            F.precision = 0;
                            break;
                        }
                    }
                    if (!F.altForm || (F.precision != 0))
                    {
                        switch (F.precision)
                        {
                        case  4: i = mDNS_snprintf(mDNS_VACB, sizeof(mDNS_VACB), "%d.%d.%d.%d",
                                                   a[0], a[1], a[2], a[3]); break;
                        case  6: i = mDNS_snprintf(mDNS_VACB, sizeof(mDNS_VACB), "%02X:%02X:%02X:%02X:%02X:%02X",
                                                   a[0], a[1], a[2], a[3], a[4], a[5]); break;
                        case 16: {
                            // Print IPv6 addresses according to RFC 5952, A Recommendation for IPv6 Address Text
                            // Representation. See <https://tools.ietf.org/html/rfc5952>.

                            int idx, runLen = 0, runStart = 0, maxRunLen = 0, maxRunStart = 0, maxRunEnd;

                            // Find the leftmost longest run of consecutive zero hextets.
                            for (idx = 0; idx < 8; ++idx)
                            {
                                const unsigned int hextet = (a[idx * 2] << 8) | a[(idx * 2) + 1];
                                if (hextet == 0)
                                {
                                    if (runLen++ == 0) runStart = idx;
                                    if (runLen > maxRunLen)
                                    {
                                        maxRunStart = runStart;
                                        maxRunLen   = runLen;
                                    }
                                }
                                else
                                {
                                    // If the number of remaining hextets is less than or equal to the length of the longest
                                    // run so far, then we've found the leftmost longest run.
                                    if ((8 - (idx + 1)) <= maxRunLen) break;
                                    runLen = 0;
                                }
                            }

                            // Compress the leftmost longest run of two or more consecutive zero hextets as "::".
                            // For each reminaing hextet, suppress zeros leading up to the least-significant nibble, which
                            // is always written, even if it's zero. Because of this requirement, it's easier to write the
                            // IPv6 address in reverse. Also, write a colon separator before each hextet except for the
                            // first one.
                            s = mDNS_VACB_Lim;
                            maxRunEnd = (maxRunLen >= 2) ? (maxRunStart + maxRunLen - 1) : -1;
                            for (idx = 7; idx >= 0; --idx)
                            {
                                if (idx == maxRunEnd)
                                {
                                    if (idx == 7) *--s = ':';
                                    idx = maxRunStart;
                                    *--s = ':';
                                }
                                else
                                {
                                    unsigned int hextet = (a[idx * 2] << 8) | a[(idx * 2) + 1];
                                    do {
                                        *--s = kHexDigitsLowercase[hextet % 16];
                                        hextet /= 16;
                                    } while (hextet);
                                    if (idx > 0) *--s = ':';
                                }
                            }
                            i = (unsigned int)(mDNS_VACB_Lim - s);
                        }
                        break;

                        default: i = mDNS_snprintf(mDNS_VACB, sizeof(mDNS_VACB), "%s", "<< ERROR: Must specify"
                                                   " address size (i.e. %.4a=IPv4, %.6a=Ethernet, %.16a=IPv6) >>"); break;
                        }
                    }
                }
            }
            break;

            case 'p':  F.havePrecision = F.lSize = 1;
                F.precision = sizeof(void*) * 2;                // 8 characters on 32-bit; 16 characters on 64-bit
                fallthrough();
            case 'X':  digits = kHexDigitsUppercase;
                goto hexadecimal;
            case 'x':  digits = kHexDigitsLowercase;
hexadecimal: if (F.lSize) n = va_arg(arg, unsigned long);
                else n = va_arg(arg, unsigned int);
                if (F.hSize) n = (unsigned short) n;
                if (!F.havePrecision)
                {
                    if (F.zeroPad)
                    {
                        F.precision = F.fieldWidth;
                        if (F.altForm) F.precision -= 2;
                    }
                    if (F.precision < 1) F.precision = 1;
                }
                if (F.precision > mDNS_VACB_Size - 1)
                    F.precision = mDNS_VACB_Size - 1;
                for (i = 0; n; n /= 16, i++) *--s = digits[n % 16];
                for (; i < F.precision; i++) *--s = '0';
#ifndef FUZZING // Pascal strings aren't supported for fuzzing
                if (F.altForm) { *--s = (char)c; *--s = '0'; i += 2; }
#endif
                break;

            case 'c':  *--s = (char)va_arg(arg, int); i = 1; break;

            case 's':  s = va_arg(arg, char *);
                if (!s) { static char emsg[] = "<<NULL>>"; s = emsg; i = sizeof(emsg)-1; }
                else switch (F.altForm)
                    {
                    case 0: i=0;
                        if (!F.havePrecision)                               // C string
                            while (s[i]) i++;
                        else
                        {
                            while ((i < F.precision) && s[i]) i++;
                            // Make sure we don't truncate in the middle of a UTF-8 character
                            // If last character we got was any kind of UTF-8 multi-byte character,
                            // then see if we have to back up.
                            // This is not as easy as the similar checks below, because
                            // here we can't assume it's safe to examine the *next* byte, so we
                            // have to confine ourselves to working only backwards in the string.
                            j = i;                      // Record where we got to
                            // Now, back up until we find first non-continuation-char
                            while (i>0 && (s[i-1] & 0xC0) == 0x80) i--;
                            // Now s[i-1] is the first non-continuation-char
                            // and (j-i) is the number of continuation-chars we found
                            if (i>0 && (s[i-1] & 0xC0) == 0xC0)                 // If we found a start-char
                            {
                                i--;                        // Tentatively eliminate this start-char as well
                                // Now (j-i) is the number of characters we're considering eliminating.
                                // To be legal UTF-8, the start-char must contain (j-i) one-bits,
                                // followed by a zero bit. If we shift it right by (7-(j-i)) bits
                                // (with sign extension) then the result has to be 0xFE.
                                // If this is right, then we reinstate the tentatively eliminated bytes.
                                if (((j-i) < 7) && (((s[i] >> (7-(j-i))) & 0xFF) == 0xFE)) i = j;
                            }
                        }
                        break;
#ifndef FUZZING // Pascal strings aren't supported for fuzzing
                    case 1: i = (unsigned char) *s++; break;                // Pascal string
#endif
                    case 2: {                                               // DNS label-sequence name
                        unsigned char *a = (unsigned char *)s;
                        s = mDNS_VACB;                  // Adjust s to point to the start of the buffer, not the end
                        if (*a == 0) *s++ = '.';                    // Special case for root DNS name
                        while (*a)
                        {
                            char buf[63*4+1];
                            if (*a > 63)
                            { s += mDNS_snprintf(s, mDNS_VACB_Remain(s), "<<INVALID LABEL LENGTH %u>>", *a); break; }
                            if (s + *a >= &mDNS_VACB[254])
                            { s += mDNS_snprintf(s, mDNS_VACB_Remain(s), "<<NAME TOO LONG>>"); break; }
                            // Need to use ConvertDomainLabelToCString to do proper escaping here,
                            // so it's clear what's a literal dot and what's a label separator
                            ConvertDomainLabelToCString((domainlabel*)a, buf);
                            s += mDNS_snprintf(s, mDNS_VACB_Remain(s), "%s.", buf);
                            a += 1 + *a;
                        }
                        i = (mDNSu32)(s - mDNS_VACB);
                        s = mDNS_VACB;                  // Reset s back to the start of the buffer
                        break;
                    }
                    default:
                        break;
                    }
                // Make sure we don't truncate in the middle of a UTF-8 character (see similar comment below)
                if (F.havePrecision && i > F.precision)
                { i = F.precision; while (i>0 && (s[i] & 0xC0) == 0x80) i--;}
                break;

            case 'H': {
                    s = va_arg(arg, char *);
                    hexdump = mDNStrue;
                }
                break;

#ifndef FUZZING
            case 'n':
                s = va_arg(arg, char *);
                if      (F.hSize) *(short *) s = (short)nwritten;
                else if (F.lSize) *(long  *) s = (long)nwritten;
                else *(int   *) s = (int)nwritten;
                continue;
#endif

            default:    s = mDNS_VACB;
                i = mDNS_snprintf(mDNS_VACB, sizeof(mDNS_VACB), "<<UNKNOWN FORMAT CONVERSION CODE %%%c>>", mDNSIsPrintASCII(c) ? c : ' ');
                break;

            case '%':  *sbuffer++ = (char)c;
                if (++nwritten >= buflen) goto exit;
                break;
            }

            if (i < F.fieldWidth && !F.leftJustify)         // Pad on the left
                do  {
                    *sbuffer++ = ' ';
                    if (++nwritten >= buflen) goto exit;
                } while (i < --F.fieldWidth);

            if (hexdump)
            {
#ifndef FUZZING
                char *dst = sbuffer;
                const char *const lim = &sbuffer[buflen - nwritten];
                if (F.havePrecision)
                {
                    for (i = 0; (i < F.precision) && (dst < lim); i++)
                    {
                        const unsigned int b = (unsigned int) *s++;
                        if (i > 0)     *dst++ = ' ';
                        if (dst < lim) *dst++ = kHexDigitsLowercase[(b >> 4) & 0xF];
                        if (dst < lim) *dst++ = kHexDigitsLowercase[ b       & 0xF];
                    }
                }
                i = (unsigned int)(dst - sbuffer);
                sbuffer = dst;
#endif
            }
            else
            {
                // Make sure we don't truncate in the middle of a UTF-8 character.
                // Note: s[i] is the first eliminated character; i.e. the next character *after* the last character of the
                // allowed output. If s[i] is a UTF-8 continuation character, then we've cut a unicode character in half,
                // so back up 'i' until s[i] is no longer a UTF-8 continuation character. (if the input was proprly
                // formed, s[i] will now be the UTF-8 start character of the multi-byte character we just eliminated).
                if (i > buflen - nwritten)
                { i = buflen - nwritten; while (i>0 && (s[i] & 0xC0) == 0x80) i--;}
                for (j=0; j<i; j++) *sbuffer++ = *s++;          // Write the converted result
            }
            nwritten += i;
            if (nwritten >= buflen) goto exit;

            for (; i < F.fieldWidth; i++)                   // Pad on the right
            {
                *sbuffer++ = ' ';
                if (++nwritten >= buflen) goto exit;
            }
        }
    }
exit:
    *sbuffer++ = 0;
    return(nwritten);
}

mDNSexport mDNSu32 mDNS_snprintf(char *sbuffer, mDNSu32 buflen, const char *fmt, ...)
{
    mDNSu32 length;

    va_list ptr;
    va_start(ptr,fmt);
    length = mDNS_vsnprintf(sbuffer, buflen, fmt, ptr);
    va_end(ptr);

    return(length);
}

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
mDNSexport mDNSu32 mDNS_GetNextResolverGroupID(void)
{
    static mDNSu32 lastID = 0;
    if (++lastID == 0) lastID = 1; // Valid resolver group IDs are non-zero.
    return(lastID);
}
#endif

#define kReverseIPv6Domain  ((const domainname *) "\x3" "ip6" "\x4" "arpa")

mDNSexport mDNSBool GetReverseIPv6Addr(const domainname *name, mDNSu8 outIPv6[16])
{
    const mDNSu8 *      ptr;
    int                 i;
    mDNSu8              ipv6[16];

    // If the name is of the form "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.ip6.arpa.", where each x
    // is a hex digit, then the sequence of 32 hex digit labels represents the nibbles of an IPv6 address in reverse order.
    // See <https://tools.ietf.org/html/rfc3596#section-2.5>.

    ptr = name->c;
    for (i = 0; i < 32; i++)
    {
        unsigned int c, nibble;
        const int j = 15 - (i / 2);
        if (*ptr++ != 1) return (mDNSfalse);                    // If this label's length is not 1, then fail.
        c = *ptr++;                                             // Get label byte.
        if (     (c >= '0') && (c <= '9')) nibble =  c - '0';   // If it's a hex digit, get its numeric value.
        else if ((c >= 'a') && (c <= 'f')) nibble = (c - 'a') + 10;
        else if ((c >= 'A') && (c <= 'F')) nibble = (c - 'A') + 10;
        else                               return (mDNSfalse);  // Otherwise, fail.
        if ((i % 2) == 0)
        {
            ipv6[j] = (mDNSu8)nibble;
        }
        else
        {
            ipv6[j] |= (mDNSu8)(nibble << 4);
        }
    }

    // The rest of the name needs to be "ip6.arpa.". If it isn't, fail.

    if (!SameDomainName((const domainname *)ptr, kReverseIPv6Domain)) return (mDNSfalse);
    if (outIPv6) mDNSPlatformMemCopy(outIPv6, ipv6, 16);
    return (mDNStrue);
}
#endif // !STANDALONE
