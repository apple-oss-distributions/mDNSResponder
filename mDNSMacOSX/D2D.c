/*
 * Copyright (c) 2002-2023 Apple Inc. All rights reserved.
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

#include "D2D.h"
#include "mDNSEmbeddedAPI.h"        // Defines the interface provided to the client layer above
#include "DNSCommon.h"
#include "mDNSMacOSX.h"             // Defines the specific types needed to run mDNS on this platform
#include "dns_sd.h"                 // For mDNSInterface_LocalOnly etc.
#include "dns_sd_internal.h"
#include "misc_utilities.h"
#include "uds_daemon.h"
#include <mdns/powerlog.h>
#include "mdns_strict.h"

#define D2DIsTransportLikeAWDL(X) ((X) == D2DAWDLTransport || (X) == D2DWiFiAwareTransport)

D2DStatus D2DInitialize(CFRunLoopRef runLoop, D2DServiceCallback serviceCallback, void* userData) __attribute__((weak_import));
D2DStatus D2DRetain(D2DServiceInstance instanceHandle, D2DTransportType transportType) __attribute__((weak_import));
D2DStatus D2DStopAdvertisingPairOnTransport(const Byte *key, const size_t keySize, const Byte *value, const size_t valueSize, D2DTransportType transport) __attribute__((weak_import));
D2DStatus D2DRelease(D2DServiceInstance instanceHandle, D2DTransportType transportType) __attribute__((weak_import));
D2DStatus D2DStartAdvertisingPairOnTransport(const Byte *key, const size_t keySize, const Byte *value, const size_t valueSize, D2DTransportType transport) __attribute__((weak_import));
D2DStatus D2DStartBrowsingForKeyOnTransport(const Byte *key, const size_t keySize, D2DTransportType transport) __attribute__((weak_import));
D2DStatus D2DStopBrowsingForKeyOnTransport(const Byte *key, const size_t keySize, D2DTransportType transport) __attribute__((weak_import));
void D2DStartResolvingPairOnTransport(const Byte *key, const size_t keySize, const Byte *value, const size_t valueSize, D2DTransportType transport) __attribute__((weak_import));
void D2DStopResolvingPairOnTransport(const Byte *key, const size_t keySize, const Byte *value, const size_t valueSize, D2DTransportType transport) __attribute__((weak_import));
D2DStatus D2DTerminate(void) __attribute__((weak_import));

#pragma mark - D2D Support

mDNSexport void D2D_start_advertising_interface(NetworkInterfaceInfo *interface)
{
    // AWDL wants the address and reverse address PTR record communicated
    // via the D2D interface layer.
    if (interface->InterfaceID == AWDLInterfaceID || interface->InterfaceID == WiFiAwareInterfaceID)
    {
        // only log if we have a valid record to start advertising
        if (interface->RR_A.resrec.RecordType || interface->RR_PTR.resrec.RecordType)
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "D2D_start_advertising_interface - ifname: " PUB_S,
                interface->ifname);
        }

        if (interface->RR_A.resrec.RecordType)
            external_start_advertising_service(&interface->RR_A.resrec, 0, 0);
        if (interface->RR_PTR.resrec.RecordType)
            external_start_advertising_service(&interface->RR_PTR.resrec, 0, 0);
    }
}

mDNSexport void D2D_stop_advertising_interface(NetworkInterfaceInfo *interface)
{
    if (interface->InterfaceID == AWDLInterfaceID || interface->InterfaceID == WiFiAwareInterfaceID)
    {
        // only log if we have a valid record to stop advertising
        if (interface->RR_A.resrec.RecordType || interface->RR_PTR.resrec.RecordType)
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "D2D_stop_advertising_interface - ifname: " PUB_S,
                interface->ifname);
        }

        if (interface->RR_A.resrec.RecordType)
            external_stop_advertising_service(&interface->RR_A.resrec, 0, 0);
        if (interface->RR_PTR.resrec.RecordType)
            external_stop_advertising_service(&interface->RR_PTR.resrec, 0, 0);
    }
}

// If record would have been advertised to the D2D plugin layer, stop that advertisement.
mDNSexport void D2D_stop_advertising_record(AuthRecord *ar)
{
    DNSServiceFlags flags = deriveD2DFlagsFromAuthRecType(ar->ARType);
    if (callExternalHelpers(ar->resrec.InterfaceID, ar->resrec.name, flags))
    {
        external_stop_advertising_service(&ar->resrec, flags, 0);
    }
}

// If record should be advertised to the D2D plugin layer, start that advertisement.
mDNSexport void D2D_start_advertising_record(AuthRecord *ar)
{
    DNSServiceFlags flags = deriveD2DFlagsFromAuthRecType(ar->ARType);
    if (callExternalHelpers(ar->resrec.InterfaceID, ar->resrec.name, flags))
    {
        external_start_advertising_service(&ar->resrec, flags, 0);
    }
}

// Name compression items for fake packet version number 1
static const mDNSu8 compression_packet_v1 = 0x01;

static DNSMessage compression_base_msg = { { {{0}}, {{0}}, 2, 1, 0, 0 }, "\x04_tcp\x05local\x00\x00\x0C\x00\x01\x04_udp\xC0\x11\x00\x0C\x00\x01" };
static mDNSu8 *const compression_limit = (mDNSu8 *) &compression_base_msg + sizeof(DNSMessage);
static mDNSu8 *const compression_lhs = (mDNSu8 *const) compression_base_msg.data + 27;

mDNSlocal void FreeD2DARElemCallback(mDNS *const m, AuthRecord *const rr, mStatus result);

typedef struct D2DRecordListElem
{
    struct D2DRecordListElem *next;
    D2DServiceInstance       instanceHandle;
    D2DTransportType         transportType;
    AuthRecord               ar;    // must be last in the structure to accomodate extra space
                                    // allocated for large records.
} D2DRecordListElem;

static D2DRecordListElem *D2DRecords = NULL; // List of records returned with D2DServiceFound events

typedef struct D2DBrowseListElem
{
    struct D2DBrowseListElem *next;
    domainname name;
    mDNSu16 type;
    unsigned int refCount;
} D2DBrowseListElem;

D2DBrowseListElem* D2DBrowseList = NULL;

mDNSlocal mDNSu8 *putVal16(mDNSu8 *ptr, mDNSu16 val)
{
    ptr[0] = (mDNSu8)((val >> 8 ) & 0xFF);
    ptr[1] = (mDNSu8)((val      ) & 0xFF);
    return ptr + sizeof(mDNSu16);
}

mDNSlocal mDNSu8 *putVal32(mDNSu8 *ptr, mDNSu32 val)
{
    ptr[0] = (mDNSu8)((val >> 24) & 0xFF);
    ptr[1] = (mDNSu8)((val >> 16) & 0xFF);
    ptr[2] = (mDNSu8)((val >>  8) & 0xFF);
    ptr[3] = (mDNSu8)((val      ) & 0xFF);
    return ptr + sizeof(mDNSu32);
}

mDNSlocal void DomainnameToLower(const domainname * const in, domainname * const out)
{
    const mDNSu8 * const start = (const mDNSu8 * const)in;
    const mDNSu8 *ptr = (const mDNSu8*)start;
    while(*ptr)
    {
        mDNSu8 c = *ptr;
        out->c[ptr-start] = *ptr;
        ptr++;
        for (; c; c--,ptr++) out->c[ptr-start] = mDNSIsUpperCase(*ptr) ? (*ptr - 'A' + 'a') : *ptr;
    }
    out->c[ptr-start] = *ptr;
}

mDNSlocal mDNSu8 * DNSNameCompressionBuildLHS(const domainname* typeDomain, mDNSu16 qtype)
{
    mDNSu8 *ptr = putDomainNameAsLabels(&compression_base_msg, compression_lhs, compression_limit, typeDomain);
    if (!ptr) return ptr;
    *ptr = (qtype >> 8) & 0xff;
    ptr += 1;
    *ptr = qtype & 0xff;
    ptr += 1;
    *ptr = compression_packet_v1;
    return ptr + 1;
}

mDNSlocal mDNSu8 * DNSNameCompressionBuildRHS(mDNSu8 *start, const ResourceRecord *const resourceRecord)
{
    return putRData(&compression_base_msg, start, compression_limit, resourceRecord);
}

mDNSlocal void PrintHelper(const char *const tag, const mDNSu8 *lhs, mDNSu16 lhs_len, const mDNSu8 *rhs, mDNSu16 rhs_len)
{
    if (mDNS_LoggingEnabled)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEBUG, PUB_S ": LHS: (%d bytes) " PRI_HEX, tag, lhs_len, HEX_PARAM(lhs, lhs_len));
        if (rhs)
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEBUG, PUB_S ": RHS: (%d bytes) " PRI_HEX, tag, rhs_len, HEX_PARAM(rhs, rhs_len));
        }
    }
}

mDNSlocal void FreeD2DARElemCallback(mDNS *const m, AuthRecord *const rr, mStatus result)
{
    (void)m;  // unused
    if (result == mStatus_MemFree)
    {
        D2DRecordListElem **ptr = &D2DRecords;
        D2DRecordListElem *tmp;
        while (*ptr && &(*ptr)->ar != rr) ptr = &(*ptr)->next;
        if (!*ptr)
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "FreeD2DARElemCallback: Could not find in D2DRecords: " PRI_S, ARDisplayString(m, rr));
            return;
        }
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "FreeD2DARElemCallback: Found in D2DRecords: " PRI_S, ARDisplayString(m, rr));
        tmp = *ptr;
        *ptr = (*ptr)->next;
        // Just because we stoppped browsing, doesn't mean we should tear down the PAN connection.
        mDNSPlatformMemFree(tmp);
    }
}

mDNSexport void external_connection_release(const domainname *instance)
{
    (void) instance;
    D2DRecordListElem *ptr = D2DRecords;

    for ( ; ptr ; ptr = ptr->next)
    {
        if ((ptr->ar.resrec.rrtype == kDNSServiceType_PTR) &&
             SameDomainName(&ptr->ar.rdatastorage.u.name, instance))
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "external_connection_release: Calling D2DRelease - "
                "instanceHandle: %p, transportType: %d", ptr->instanceHandle, ptr->transportType);
            if (D2DRelease) D2DRelease(ptr->instanceHandle, ptr->transportType);
        }
    }
}

mDNSlocal void xD2DClearCache(const domainname *regType, mDNSu16 qtype)
{
    D2DRecordListElem *ptr = D2DRecords;
    while (ptr)
    {
        D2DRecordListElem *tmp = ptr;
        ptr = ptr->next;
        if ((tmp->ar.resrec.rrtype == qtype) && SameDomainName(&tmp->ar.namestorage, regType))
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT,
                "xD2DClearCache: Clearing and deregistering cache record - "
                "name: " PRI_DM_NAME ", rrtype: " PUB_DNS_TYPE ", auth record: " PRI_S, DM_NAME_PARAM(regType),
                DNS_TYPE_PARAM(qtype), ARDisplayString(&mDNSStorage, &tmp->ar));

            mDNS_Deregister(&mDNSStorage, &tmp->ar);
            // Memory will be freed and element removed in FreeD2DARElemCallback
        }
    }
}

mDNSlocal D2DBrowseListElem ** D2DFindInBrowseList(const domainname *const name, mDNSu16 type)
{
    D2DBrowseListElem **ptr = &D2DBrowseList;

    for ( ; *ptr; ptr = &(*ptr)->next)
        if ((*ptr)->type == type && SameDomainName(&(*ptr)->name, name))
            break;

    return ptr;
}

mDNSlocal unsigned int D2DBrowseListRefCount(const domainname *const name, mDNSu16 type)
{
    D2DBrowseListElem **ptr = D2DFindInBrowseList(name, type);
    return *ptr ? (*ptr)->refCount : 0;
}

mDNSlocal void D2DBrowseListRetain(const domainname *const name, mDNSu16 type)
{
    D2DBrowseListElem **ptr = D2DFindInBrowseList(name, type);

    if (!*ptr)
    {
        *ptr = (D2DBrowseListElem *) mDNSPlatformMemAllocateClear(sizeof(**ptr));
        (*ptr)->type = type;
        AssignDomainName(&(*ptr)->name, name);
    }
    (*ptr)->refCount += 1;

    LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "D2DBrowseListRetain - "
        "name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE ", ref count: %u", DM_NAME_PARAM(&(*ptr)->name),
        DNS_TYPE_PARAM((*ptr)->type), (*ptr)->refCount);
}

// Returns true if found in list, false otherwise
mDNSlocal bool D2DBrowseListRelease(const domainname *const name, mDNSu16 type)
{
    D2DBrowseListElem **ptr = D2DFindInBrowseList(name, type);

    if (!*ptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "D2DBrowseListRelease item not found in the list - "
            "name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE, DM_NAME_PARAM(name), DNS_TYPE_PARAM(type));
        return false;
    }

    (*ptr)->refCount -= 1;

    LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "D2DBrowseListRelease - "
        "name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE ", ref count: %u", DM_NAME_PARAM(&(*ptr)->name),
        DNS_TYPE_PARAM((*ptr)->type), (*ptr)->refCount);

    if (!(*ptr)->refCount)
    {
        D2DBrowseListElem *tmp = *ptr;
        *ptr = (*ptr)->next;
        mDNSPlatformMemFree(tmp);
    }
    return true;
}

mDNSlocal mDNSBool LabelPairIsForService(const mDNSu8 *const firstLabel)
{
    // See <https://datatracker.ietf.org/doc/html/rfc6763#section-7> for more info.
    const int firstLabelLen = *firstLabel;
    if ((firstLabelLen > 0) && (firstLabel[1] == '_'))
    {
        const mDNSu8 *const secondLabel = firstLabel + 1 + firstLabelLen;
        const mDNSu8 *const protoLabelTCP = (const mDNSu8 *)"\x4" "_tcp";
        const mDNSu8 *const protoLabelUDP = (const mDNSu8 *)"\x4" "_udp";
        if (SameDomainLabel(secondLabel, protoLabelTCP) || SameDomainLabel(secondLabel, protoLabelUDP))
        {
            return mDNStrue;
        }
    }
    return mDNSfalse;
}

mDNSlocal mDNSBool DomainNameIsForBrowsing(const domainname *const name)
{
    // Check if the domain name is used for DNS-SD browsing. Specifically, check if the domain name is used for Service
    // Instance Enumeration, i.e., of the form <service>.<parent domain>, or for Selective Instance Enumeration, i.e.,
    // of the form <subtype>._sub.<service>.<parent domain>. Note that <subtype> is a single label and <service> is a
    // pair of labels starting with a service name label, followed by a protocol label, either "_tcp" or "_udp". See
    // <https://datatracker.ietf.org/doc/html/rfc6763#section-7>.
    int labelLen;
    const mDNSu8 *label3 = mDNSNULL;
    const mDNSu8 *label2 = mDNSNULL;
    for (const mDNSu8 *label1 = name->c; (labelLen = *label1) != 0; label1 += (1 + labelLen))
    {
        if (!label3 && !label2 && label1)
        {
            if (LabelPairIsForService(label1))
            {
                return mDNStrue;
            }
        }
        else if (label3 && label2 && label1)
        {
            const mDNSu8 *const subLabel  = (const mDNSu8 *)"\x4" "_sub";
            if (SameDomainLabel(label2, subLabel) && LabelPairIsForService(label1))
            {
                return mDNStrue;
            }
            break;
        }
        label3 = label2;
        label2 = label1;
    }
    return mDNSfalse;
}

mDNSlocal mStatus xD2DParseCompressedPacket(const mDNSu8 * const lhs, const mDNSu16 lhs_len, const mDNSu8 * const rhs, const mDNSu16 rhs_len, const mDNSu32 ttl, mDNSu8 ** const out_ptr)
{
    // Sanity check that key array (lhs) has one domain name, followed by the record type and single byte D2D
    // plugin protocol version number.
    // Note, we don't have a DNSMessage pointer at this point, so just pass in the lhs value as the lower bound
    // of the input bytes we are processing.  skipDomainName() does not try to follow name compression pointers,
    // so it is safe to pass it the key byte array since it will stop parsing the DNS name and return a pointer
    // to the byte after the first name compression pointer it encounters.
    const mDNSu8 *keyp = skipDomainName((const DNSMessage *const) lhs, lhs, lhs + lhs_len);

    // There should be 3 bytes remaining in a valid key,
    // two for the DNS record type, and one for the D2D protocol version number.
    if (keyp == NULL || (keyp + 3 != (lhs + lhs_len)))
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DParseCompressedPacket: Could not parse DNS name in key");
        return mStatus_Incompatible;
    }
    const mDNSu16 recordType = ((mDNSu16)(keyp[0] << 8)) | keyp[1];
    keyp += 2;   // point to D2D compression packet format version byte
    if (*keyp != compression_packet_v1)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DParseCompressedPacket: Invalid D2D packet version - "
            "version: %d", *keyp);
        return mStatus_Incompatible;
    }

    mDNSu8 *ptr = compression_lhs; // pointer to the end of our fake packet

    // Check to make sure we're not going to go past the end of the DNSMessage data
    // 7 = 2 for CLASS (-1 for our version) + 4 for TTL + 2 for RDLENGTH
    if (ptr + lhs_len - 7 + rhs_len >= compression_limit) return mStatus_NoMemoryErr;

    // Copy the LHS onto our fake wire packet
    const mDNSu8 *const recordNamePtr = ptr;
    mDNSPlatformMemCopy(ptr, lhs, lhs_len);
    ptr += lhs_len - 1;

    // Check the 'fake packet' version number, to ensure that we know how to decompress this data
    if (*ptr != compression_packet_v1) return mStatus_Incompatible;

    // two bytes of CLASS
    mDNSu8 *const recordClassPtr = ptr;
    ptr = putVal16(ptr, kDNSClass_IN | kDNSClass_UniqueRRSet);

    // four bytes of TTL
    ptr = putVal32(ptr, ttl);

    // Copy the RHS length into the RDLENGTH of our fake wire packet
    ptr = putVal16(ptr, rhs_len);

    // Copy the RHS onto our fake wire packet
    mDNSPlatformMemCopy(ptr, rhs, rhs_len);
    ptr += rhs_len;
    *out_ptr = ptr;

    domainname recordName;
    const mDNSu8 *const recordNameNextPtr = getDomainName(&compression_base_msg, recordNamePtr, compression_limit,
        &recordName);
    if (!recordNameNextPtr)
    {
        AssignConstStringDomainName(&recordName, "");
    }

    // If the record answers a DNS-SD PTR browsing query, then clear the cache-flush bit. Such records are part of a
    // shared resource record set since PTR records for instances of a given service type can come from more than one
    // mDNS responder. From <https://datatracker.ietf.org/doc/html/rfc6762#section-10.2>:
    //
    //    The cache-flush bit MUST NOT ever be set in any shared resource
    //    record.  To do so would cause all the other shared versions of this
    //    resource record with different rdata from different responders to be
    //    immediately deleted from all the caches on the network.
    if (recordType == kDNSServiceType_PTR && DomainNameIsForBrowsing(&recordName))
    {
        putVal16(recordClassPtr, kDNSClass_IN);
    }
    if (mDNS_LoggingEnabled)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DParseCompressedPacket: Our Bytes - name: " PRI_DM_NAME
            ", type: " PUB_DNS_TYPE ", TTL: %u, rdata length: %u", DM_NAME_PARAM(&recordName),
            DNS_TYPE_PARAM(recordType), ttl, rhs_len);
    }
    return mStatus_NoError;
}

mDNSlocal mStatus xD2DParse(const mDNSu8 * const lhs, const mDNSu16 lhs_len, const mDNSu8 * const rhs, const mDNSu16 rhs_len, D2DRecordListElem **D2DListp)
{
    mDNS *const m = &mDNSStorage;
    mStatus err;
    mDNSu8 *ptr;
    err = xD2DParseCompressedPacket(lhs, lhs_len, rhs, rhs_len, 120, &ptr);
    if (err != mStatus_NoError)  return err;

    const mDNSu8 *const next = GetLargeResourceRecord(m, &compression_base_msg, compression_lhs, ptr, mDNSInterface_Any, kDNSRecordTypePacketAns, &m->rec);
    if (!next || m->rec.r.resrec.RecordType == kDNSRecordTypePacketNegative)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DParse: failed to get large RR");
        mDNSCoreResetRecord(m);
        return mStatus_UnknownErr;
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DParse got record - "
            "name: " PRI_DM_NAME ", rrtype: " PUB_DNS_TYPE ", rdata: " PRI_S, DM_NAME_PARAM(m->rec.r.resrec.name),
            DNS_TYPE_PARAM(m->rec.r.resrec.rrtype), CRDisplayString(m, &m->rec.r));
    }

    *D2DListp = (D2DRecordListElem *) mDNSPlatformMemAllocateClear(sizeof(D2DRecordListElem) + (m->rec.r.resrec.rdlength <= sizeof(RDataBody) ? 0 : m->rec.r.resrec.rdlength - sizeof(RDataBody)));
    if (!*D2DListp) return mStatus_NoMemoryErr;

    AuthRecord *rr = &(*D2DListp)->ar;
    mDNS_SetupResourceRecord(rr, mDNSNULL, mDNSInterface_P2P, m->rec.r.resrec.rrtype, 7200, kDNSRecordTypeShared, AuthRecordP2P, FreeD2DARElemCallback, NULL);
    AssignDomainName(&rr->namestorage, &m->rec.namestorage);
    rr->resrec.rdlength = m->rec.r.resrec.rdlength;
    rr->resrec.rdata->MaxRDLength = m->rec.r.resrec.rdlength;
    mDNSPlatformMemCopy(rr->resrec.rdata->u.data, m->rec.r.resrec.rdata->u.data, m->rec.r.resrec.rdlength);
    rr->resrec.namehash = DomainNameHashValue(rr->resrec.name);
    SetNewRData(&rr->resrec, mDNSNULL, 0);  // Sets rr->rdatahash for us

    mDNSCoreResetRecord(m);

    return mStatus_NoError;
}

mDNSlocal void xD2DReceiveResponse(const DNSMessage *const response, const mDNSu8 *end, D2DTransportType transportType)
{
    mDNS *const m = &mDNSStorage;
    mDNS_Lock(m);
    mDNSCoreReceiveD2DResponse(m, response, end, mDNSNULL, MulticastDNSPort, &AllDNSLinkGroup_v6, MulticastDNSPort,
        (transportType == D2DAWDLTransport) ? AWDLInterfaceID : WiFiAwareInterfaceID);
    mDNS_Unlock(m);
}

mDNSexport void xD2DAddToCache(D2DStatus result, D2DServiceInstance instanceHandle, D2DTransportType transportType, const Byte *key, size_t keySize, const Byte *value, size_t valueSize)
{
    mDNS *const m = &mDNSStorage;
    if (result == kD2DSuccess)
    {
        if ( key == NULL || value == NULL || keySize == 0 || valueSize == 0)
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DAddToCache: NULL Byte * passed in or length == 0");
            return;
        }

        mStatus err;
        if (D2DIsTransportLikeAWDL(transportType))
        {
            mDNSu8 *end_ptr; // pointer to the end of our fake packet
            err = xD2DParseCompressedPacket(key, (mDNSu16)keySize, value, (mDNSu16)valueSize, kStandardTTL, &end_ptr);
            if (err != mStatus_NoError)
            {
                LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DAddToCache: xD2DParseCompressedPacket failed - "
                    "error: %d", err);
                return;
            }
            xD2DReceiveResponse(&compression_base_msg, end_ptr, transportType);
        }
        else
        {
            D2DRecordListElem *ptr = NULL;

            err = xD2DParse((const mDNSu8 * const)key, (const mDNSu16)keySize, (const mDNSu8 * const)value, (const mDNSu16)valueSize, &ptr);
            if (err)
            {
                LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DAddToCache: xD2DParse failed - "
                    "error: %d", err);
                PrintHelper(__func__, key, (mDNSu16)keySize, value, (mDNSu16)valueSize);
                if (ptr)
                    mDNSPlatformMemFree(ptr);
                return;
            }
            err = mDNS_Register(m, &ptr->ar);
            if (err)
            {
                LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DAddToCache: mDNS_Register failed - "
                    "error: %d, name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE ", auth record: " PRI_S, err,
                    DM_NAME_PARAM(ptr->ar.resrec.name), DNS_TYPE_PARAM(ptr->ar.resrec.rrtype),
                    ARDisplayString(m, &ptr->ar));
                mDNSPlatformMemFree(ptr);
                return;
            }

            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DAddToCache: mDNS_Register succeeded - "
                "name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE ", Interface ID: %p, auth record: " PRI_S,
                DM_NAME_PARAM(ptr->ar.resrec.name), DNS_TYPE_PARAM(ptr->ar.resrec.rrtype), ptr->ar.resrec.InterfaceID,
                ARDisplayString(m, &ptr->ar));

            ptr->instanceHandle = instanceHandle;
            ptr->transportType = transportType;
            ptr->next = D2DRecords;
            D2DRecords = ptr;
       }
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DAddToCache: Unexpected result - result: %d", result);
    }
}

mDNSlocal D2DRecordListElem * xD2DFindInList(const Byte *const key, const size_t keySize, const Byte *const value, const size_t valueSize)
{
    D2DRecordListElem *ptr = D2DRecords;
    D2DRecordListElem *arptr = NULL;

    if ( key == NULL || value == NULL || keySize == 0 || valueSize == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DFindInList: NULL Byte * passed in or length == 0");
        return NULL;
    }

    mStatus err = xD2DParse((const mDNSu8 *const)key, (const mDNSu16)keySize, (const mDNSu8 *const)value, (const mDNSu16)valueSize, &arptr);
    if (err)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DFindInList: xD2DParse failed - error: %d", err);
        PrintHelper(__func__, key, (mDNSu16)keySize, value, (mDNSu16)valueSize);
        if (arptr)
            mDNSPlatformMemFree(arptr);
        return NULL;
    }

    while (ptr)
    {
        if (IdenticalResourceRecord(&arptr->ar.resrec, &ptr->ar.resrec)) break;
        ptr = ptr->next;
    }

    if (!ptr)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DFindInList: Could not find in D2DRecords - "
            "name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE ", auth record: " PRI_S, DM_NAME_PARAM(arptr->ar.resrec.name),
            DNS_TYPE_PARAM(arptr->ar.resrec.rrtype), ARDisplayString(&mDNSStorage, &arptr->ar));
    }
    mDNSPlatformMemFree(arptr);
    return ptr;
}

mDNSexport void xD2DRemoveFromCache(D2DStatus result, D2DServiceInstance instanceHandle, D2DTransportType transportType, const Byte *key, size_t keySize, const Byte *value, size_t valueSize)
{
    (void)instanceHandle; // We don't care about this, yet.

    if (result == kD2DSuccess)
    {
        if (D2DIsTransportLikeAWDL(transportType))
        {
            mDNSu8 *end_ptr; // pointer to the end of our fake packet
            mStatus err = xD2DParseCompressedPacket(key, (mDNSu16)keySize, value, (mDNSu16)valueSize, 0, &end_ptr);
            if (err != mStatus_NoError)
            {
                LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DRemoveFromCache: xD2DParseCompressedPacket failed"
                    " - error: %d", err);
                return;
            }
            xD2DReceiveResponse(&compression_base_msg, end_ptr, transportType);
        }
        else
        {
            D2DRecordListElem *ptr = xD2DFindInList(key, keySize, value, valueSize);
            if (ptr)
            {
                LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DRemoveFromCache: removing record from cache - "
                    "name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE ", auth record: " PRI_S,
                    DM_NAME_PARAM(ptr->ar.resrec.name), DNS_TYPE_PARAM(ptr->ar.resrec.rrtype),
                    ARDisplayString(&mDNSStorage, &ptr->ar));
                mDNS_Deregister(&mDNSStorage, &ptr->ar);
            }
        }
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DRemoveFromCache: Unexpected result - result: %d", result);
    }
}

mDNSlocal void xD2DServiceResolved(D2DStatus result, D2DServiceInstance instanceHandle, D2DTransportType transportType, const Byte *key, size_t keySize, const Byte *value, size_t valueSize)
{
    (void)key;
    (void)keySize;
    (void)value;
    (void)valueSize;

    if (result == kD2DSuccess)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DServiceResolved: Starting up PAN connection - "
            "instanceHandle: %p", instanceHandle);

        if (D2DRetain) D2DRetain(instanceHandle, transportType);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DServiceResolved: Unexpected result - result: %d", result);
    }
}

mDNSlocal void xD2DRetainHappened(D2DStatus result, D2DServiceInstance instanceHandle, D2DTransportType transportType, const Byte *key, size_t keySize, const Byte *value, size_t valueSize)
{
    (void)instanceHandle;
    (void)transportType;
    (void)key;
    (void)keySize;
    (void)value;
    (void)valueSize;

    if (result == kD2DSuccess)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DRetainHappened: Opening up PAN connection - "
            "instanceHandle: %p", instanceHandle);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DRetainHappened: Unexpected result - result: %d", result);
    }
}

mDNSlocal void xD2DReleaseHappened(D2DStatus result, D2DServiceInstance instanceHandle, D2DTransportType transportType, const Byte *key, size_t keySize, const Byte *value, size_t valueSize)
{
    (void)instanceHandle;
    (void)transportType;
    (void)key;
    (void)keySize;
    (void)value;
    (void)valueSize;

    if (result == kD2DSuccess)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DReleaseHappened: Closing PAN connection - "
            "instanceHandle: %p", instanceHandle);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DReleaseHappened: Unexpected result - result: %d", result);
    }
}

mDNSlocal void removeCachedPeerRecords(const mDNSInterfaceID interface, const mDNSAddr *const peerAddr)
{
    mDNS *const m = &mDNSStorage;
    mDNS_Lock(m);
    mDNSu32 slot;
    const CacheGroup *cg;
    CacheRecord *cr;
    FORALL_CACHERECORDS(slot, cg, cr)
    {
        const ResourceRecord *const rr = &cr->resrec;
        if ((rr->InterfaceID == interface) && mDNSSameAddress(&cr->sourceAddress, peerAddr))
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_INFO,
                "Removing cached peer record -- peer address: " PRI_IP_ADDR ", name: " PRI_DM_NAME ", type: " PUB_DNS_TYPE,
                peerAddr, DM_NAME_PARAM(rr->name), DNS_TYPE_PARAM(rr->rrtype));
            mDNS_PurgeCacheResourceRecord(m, cr);
        }
    }
    mDNS_Unlock(m);
}

mDNSlocal void xD2DPeerLostHappened(const D2DStatus result, __unused const D2DServiceInstance instanceHandle,
    const D2DTransportType transportType, __unused const Byte *const key, __unused const size_t keySize,
    const Byte *const value, const size_t valueSize)
{
    require_quiet(result == kD2DSuccess, exit);

    // Deduce the interface based on the transport type. Currently, only AWDL and WiFiAware transports are supported.
    mDNSInterfaceID interface;
    switch (transportType)
    {
    case D2DAWDLTransport:
        interface = AWDLInterfaceID;
        break;
    case D2DWiFiAwareTransport:
        interface = WiFiAwareInterfaceID;
        break;
    case D2DBluetoothTransport:
    case D2DWifiPeerToPeerTransport:
    default:
        goto exit;
    }

    // The peer's IPv6 address is passed in value byte array as an in6_addr_t. See <rdar://98848070>.
    in6_addr_t ipv6Addr;
    require_quiet(valueSize == sizeof(ipv6Addr), exit);

    memcpy(&ipv6Addr, value, sizeof(ipv6Addr));
    const mDNSAddr peerAddr = mDNSAddr_from_in6_addr(&ipv6Addr);
    removeCachedPeerRecords(interface, &peerAddr);

exit:
    return;
}

mDNSlocal void xD2DServiceCallback(D2DServiceEvent event, D2DStatus result, D2DServiceInstance instanceHandle, D2DTransportType transportType, const Byte *key, size_t keySize, const Byte *value, size_t valueSize, void *userData)
{
    const char *eventString = "unknown";

    KQueueLock();

    if (keySize   > 0xFFFF)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DServiceCallback: keySize too large - "
            "key size: %zu", keySize);
    }
    if (valueSize > 0xFFFF)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "xD2DServiceCallback: valueSize too large - "
            "value size: %zu", valueSize);
    }

    switch (event)
    {
    case D2DServiceFound:
        eventString = "D2DServiceFound";
        break;
    case D2DServiceLost:
        eventString = "D2DServiceLost";
        break;
    case D2DServiceResolved:
        eventString = "D2DServiceResolved";
        break;
    case D2DServiceRetained:
        eventString = "D2DServiceRetained";
        break;
    case D2DServiceReleased:
        eventString = "D2DServiceReleased";
        break;
    case D2DServicePeerLost:
        eventString = "D2DServicePeerLost";
        break;
    default:
        break;
    }

    LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DServiceCallback - event: " PUB_S
        ", result: %d, instanceHandle: %p, transportType: %u, LHS: %p (%zu), RHS: %p (%zu), userData: %p",
        eventString, result, instanceHandle, transportType, key, keySize, value, valueSize, userData);
    PrintHelper(__func__, key, (mDNSu16)keySize, value, (mDNSu16)valueSize);

    switch (event)
    {
    case D2DServiceFound:
        xD2DAddToCache(result, instanceHandle, transportType, key, keySize, value, valueSize);
        break;
    case D2DServiceLost:
        xD2DRemoveFromCache(result, instanceHandle, transportType, key, keySize, value, valueSize);
        break;
    case D2DServiceResolved:
        xD2DServiceResolved(result, instanceHandle, transportType, key, keySize, value, valueSize);
        break;
    case D2DServiceRetained:
        xD2DRetainHappened(result, instanceHandle, transportType, key, keySize, value, valueSize);
        break;
    case D2DServiceReleased:
        xD2DReleaseHappened(result, instanceHandle, transportType, key, keySize, value, valueSize);
        break;
    case D2DServicePeerLost:
        xD2DPeerLostHappened(result, instanceHandle, transportType, key, keySize, value, valueSize);
        break;
    default:
        break;
    }

    // Need to tickle the main kqueue loop to potentially handle records we removed or added.
    KQueueUnlock("xD2DServiceCallback");
}

// Map interface index and flags to a specific D2D transport type or D2DTransportMax if all installed plugins should be called.
// When D2DTransportMax is returned, if a specific transport should not be called, *excludedTransportType 
// will be set to the excluded transport value, otherwise, it will be set to D2DTransportMax to include all transports.
// If the return value is not D2DTransportMax, *excludedTransportType is undefined.
//
// The following D2D plugin types are currently defined in the DeviceToDeviceManager project.
//
//  D2DBluetoothTransport:      Legacy Bluetooth Person Area Network (PAN)
//  D2DWifiPeerToPeerTransport: Deprecated transport used for first generation of AirDrop on macOS. This plugin is no
//                              longer installed and thus the DeviceToDeviceManager will simply return if called with this value.
//  D2DAWDLTransport:           AWDL transport
//  D2DWiFiAwareTransport:      NAN transport
//
// See the logic below for when a given plugin call is enabled.
// If additional D2DTransportType values are defined in the future, this routine should be refactored to just
// return a set of D2DTransportType values to simplify the logic in the call sites and support the newly defined D2DTransportType values.

mDNSlocal D2DTransportType xD2DMapToTransportType(mDNSInterfaceID InterfaceID, DNSServiceFlags flags, D2DTransportType * excludedTransportType)
{
    // Set default to deprecated plugin value.
    *excludedTransportType = D2DWifiPeerToPeerTransport;

    // Call all D2D plugins when both kDNSServiceFlagsIncludeP2P and kDNSServiceFlagsIncludeAWDL are set.
    if ((flags & kDNSServiceFlagsIncludeP2P) && (flags & kDNSServiceFlagsIncludeAWDL))
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DMapToTransportType: call all active plugins since both "
            "kDNSServiceFlagsIncludeP2P and kDNSServiceFlagsIncludeAWDL are set");
        return D2DTransportMax;
    } 
    // Call D2DBluetoothTransport plugin when only kDNSServiceFlagsIncludeP2P is set.
    else if (flags & kDNSServiceFlagsIncludeP2P)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DMapToTransportType: returning D2DBluetoothTransport since only "
            "kDNSServiceFlagsIncludeP2P is set");
        return D2DBluetoothTransport;
    }
    // Call both D2DAWDLTransport and D2DWiFiAwareTransport plugins when only kDNSServiceFlagsIncludeAWDL is set.
    else if (flags & kDNSServiceFlagsIncludeAWDL)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DMapToTransportType: call AWDL and NAN plugins since kDNSServiceFlagsIncludeAWDL is set");
        *excludedTransportType = D2DBluetoothTransport;
        return D2DTransportMax;
    }

    // Call only D2DBluetoothTransport plugin when psuedo interface mDNSInterface_P2P is used.
    if (InterfaceID == mDNSInterface_P2P)
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DMapToTransportType: returning D2DBluetoothTransport for interface index "
            "mDNSInterface_P2P");
        return D2DBluetoothTransport;
    }

    // Compare to cached AWDL interface ID.
    if (AWDLInterfaceID && (InterfaceID == AWDLInterfaceID))
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DMapToTransportType: returning D2DAWDLTransport for interface index %p", InterfaceID);
        return D2DAWDLTransport;
    }
    if (WiFiAwareInterfaceID && (InterfaceID == WiFiAwareInterfaceID))
    {
        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DMapToTransportType: returning D2DWiFiAwareTransport for interface index %p", InterfaceID);
        return D2DWiFiAwareTransport;
    }

    // Return the deprecated and no longer installed plugin value for no matches to this point since it will result
    // in no plugins being called.
    LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "xD2DMapToTransportType: no matching plugins for interface index %p", InterfaceID);
    return D2DWifiPeerToPeerTransport;
}

mDNSexport void external_start_browsing_for_service(mDNSInterfaceID InterfaceID, const domainname *const typeDomain, mDNSu16 qtype, DNSServiceFlags flags, pid_t clientPID)
{
    internal_start_browsing_for_service(InterfaceID, typeDomain, qtype, flags, clientPID);
}

mDNSexport void internal_start_browsing_for_service(mDNSInterfaceID InterfaceID, const domainname *const typeDomain, mDNSu16 qtype, DNSServiceFlags flags, pid_t clientPID)
{
    domainname lower;

    DomainnameToLower(typeDomain, &lower);

    if (!D2DBrowseListRefCount(&lower, qtype))
    {
        D2DTransportType transportType, excludedTransport;

        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "internal_start_browsing_for_service: starting browse - "
            "qname: " PRI_DM_NAME ", qtype: " PUB_DNS_TYPE, DM_NAME_PARAM(&lower), DNS_TYPE_PARAM(qtype));

        mDNSu8 *const end = DNSNameCompressionBuildLHS(&lower, qtype);
        const size_t keyLen = (size_t)(end - compression_lhs);
        PrintHelper(__func__, compression_lhs, (mDNSu16)keyLen, mDNSNULL, 0);

        transportType = xD2DMapToTransportType(InterfaceID, flags, & excludedTransport);
        if (transportType == D2DTransportMax)
        {
            D2DTransportType i;
            for (i = 0; i < D2DTransportMax; i++)
            {
                if (i == excludedTransport) continue;
                if (D2DStartBrowsingForKeyOnTransport)
                {
                    if (D2DIsTransportLikeAWDL(i))
                    {
                        mdns_powerlog_awdl_browse_start(typeDomain->c, qtype, clientPID);
                    }
                    D2DStartBrowsingForKeyOnTransport(compression_lhs, keyLen, i);
                }
            }
        }
        else
        {
            if (D2DStartBrowsingForKeyOnTransport)
            {
                if (D2DIsTransportLikeAWDL(transportType))
                {
                    mdns_powerlog_awdl_browse_start(typeDomain->c, qtype, clientPID);
                }
                D2DStartBrowsingForKeyOnTransport(compression_lhs, keyLen, transportType);
            }
        }
    }
    D2DBrowseListRetain(&lower, qtype);
}

mDNSexport void external_stop_browsing_for_service(mDNSInterfaceID InterfaceID, const domainname *const typeDomain, mDNSu16 qtype, DNSServiceFlags flags, pid_t clientPID)
{
    internal_stop_browsing_for_service(InterfaceID, typeDomain, qtype, flags, clientPID);
}

mDNSexport void internal_stop_browsing_for_service(mDNSInterfaceID InterfaceID, const domainname *const typeDomain, mDNSu16 qtype, DNSServiceFlags flags, pid_t clientPID)
{
    domainname lower;

    DomainnameToLower(typeDomain, &lower);

    // If found in list and this is the last reference to this browse, remove the key from the D2D plugins.
    if (D2DBrowseListRelease(&lower, qtype) && !D2DBrowseListRefCount(&lower, qtype))
    {
        D2DTransportType transportType, excludedTransport;

        LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "internal_stop_browsing_for_service: stopping browse - "
            "qname: " PRI_DM_NAME ", qtype: " PUB_DNS_TYPE, DM_NAME_PARAM(&lower), DNS_TYPE_PARAM(qtype));

        mDNSu8 *const end = DNSNameCompressionBuildLHS(&lower, qtype);
        const size_t keyLen = (size_t)(end - compression_lhs);
        PrintHelper(__func__, compression_lhs, (mDNSu16)keyLen, mDNSNULL, 0);

        transportType = xD2DMapToTransportType(InterfaceID, flags, & excludedTransport);
        if (transportType == D2DTransportMax)
        {
            D2DTransportType i;
            for (i = 0; i < D2DTransportMax; i++)
            {
                if (i == excludedTransport) continue;
                if (D2DStopBrowsingForKeyOnTransport)
                {
                    D2DStopBrowsingForKeyOnTransport(compression_lhs, keyLen, i);
                    if (D2DIsTransportLikeAWDL(i))
                    {
                        mdns_powerlog_awdl_browse_stop(typeDomain->c, qtype, clientPID);
                    }
                }
            }
        }
        else
        {
            if (D2DStopBrowsingForKeyOnTransport)
            {
                D2DStopBrowsingForKeyOnTransport(compression_lhs, keyLen, transportType);
                if (D2DIsTransportLikeAWDL(transportType))
                {
                    mdns_powerlog_awdl_browse_stop(typeDomain->c, qtype, clientPID);
                }
            }
        }

        // The D2D driver may not generate the D2DServiceLost event for this key after
        // the D2DStopBrowsingForKey*() call above.  So, we flush the key from the D2D 
        // record cache now.
        xD2DClearCache(&lower, qtype);
    }
}

mDNSexport void external_start_advertising_service(const ResourceRecord *const resourceRecord, DNSServiceFlags flags, pid_t clientPID)
{
    internal_start_advertising_service(resourceRecord, flags, clientPID);
}

mDNSexport void internal_start_advertising_service(const ResourceRecord *const resourceRecord, DNSServiceFlags flags, pid_t clientPID)
{
    domainname lower;
    D2DTransportType transportType, excludedTransport;
    DomainnameToLower(resourceRecord->name, &lower);

    LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "internal_start_advertising_service - "
        "name: " PRI_DM_NAME ", rrtype: " PUB_DNS_TYPE, DM_NAME_PARAM(resourceRecord->name),
        DNS_TYPE_PARAM(resourceRecord->rrtype));

    mDNSu8 *const rhs = DNSNameCompressionBuildLHS(&lower, resourceRecord->rrtype);
    const mDNSu8 *const end = DNSNameCompressionBuildRHS(rhs, resourceRecord);
    const size_t keyLen = (size_t)(rhs - compression_lhs);
    const size_t valueLen = (size_t)(end - rhs);
    PrintHelper(__func__, compression_lhs, (mDNSu16)keyLen, rhs, (mDNSu16)valueLen);

    transportType = xD2DMapToTransportType(resourceRecord->InterfaceID, flags, & excludedTransport);
    if (transportType == D2DTransportMax)
    {
        D2DTransportType i;
        for (i = 0; i < D2DTransportMax; i++)
        {
            if (i == excludedTransport) continue;
            if (D2DStartAdvertisingPairOnTransport)
            {
                if (D2DIsTransportLikeAWDL(i))
                {
                    mdns_powerlog_awdl_advertise_start(lower.c, resourceRecord->rrtype, clientPID);
                }
                D2DStartAdvertisingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, i);
            }
        }
    }
    else
    {
        if (D2DStartAdvertisingPairOnTransport)
        {
            if (D2DIsTransportLikeAWDL(transportType))
            {
                mdns_powerlog_awdl_advertise_start(lower.c, resourceRecord->rrtype, clientPID);
            }
            D2DStartAdvertisingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, transportType);
        }
    }
}

mDNSexport void external_stop_advertising_service(const ResourceRecord *const resourceRecord, DNSServiceFlags flags, pid_t clientPID)
{
    internal_stop_advertising_service(resourceRecord, flags, clientPID);
}

mDNSexport void internal_stop_advertising_service(const ResourceRecord *const resourceRecord, DNSServiceFlags flags, pid_t clientPID)
{
    domainname lower;
    D2DTransportType transportType, excludedTransport;
    DomainnameToLower(resourceRecord->name, &lower);

    LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "internal_stop_advertising_service: " PRI_S,
        RRDisplayString(&mDNSStorage, resourceRecord));

    mDNSu8 *const rhs = DNSNameCompressionBuildLHS(&lower, resourceRecord->rrtype);
    const mDNSu8 *const end = DNSNameCompressionBuildRHS(rhs, resourceRecord);
    const size_t keyLen = (size_t)(rhs - compression_lhs);
    const size_t valueLen = (size_t)(end - rhs);
    PrintHelper(__func__, compression_lhs, (mDNSu16)keyLen, rhs, (mDNSu16)valueLen);

    transportType = xD2DMapToTransportType(resourceRecord->InterfaceID, flags, & excludedTransport);
    if (transportType == D2DTransportMax)
    {
        D2DTransportType i;
        for (i = 0; i < D2DTransportMax; i++)
        {
            if (i == excludedTransport) continue;
            if (D2DStopAdvertisingPairOnTransport)
            {
                D2DStopAdvertisingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, i);
                if (D2DIsTransportLikeAWDL(i))
                {
                    mdns_powerlog_awdl_advertise_stop(lower.c, resourceRecord->rrtype, clientPID);
                }
            }
        }
    }
    else
    {
        if (D2DStopAdvertisingPairOnTransport)
        {
            D2DStopAdvertisingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, transportType);
            if (D2DIsTransportLikeAWDL(transportType))
            {
                mdns_powerlog_awdl_advertise_stop(lower.c, resourceRecord->rrtype, clientPID);
            }
        }
    }
}

mDNSexport void external_start_resolving_service(mDNSInterfaceID InterfaceID, const domainname *const fqdn, DNSServiceFlags flags, pid_t clientPID)
{
    domainname lower;
    D2DTransportType transportType, excludedTransport;
    DomainnameToLower(SkipLeadingLabels(fqdn, 1), &lower);

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "external_start_resolving_service - "
        "fqdn: " PRI_DM_NAME, DM_NAME_PARAM(fqdn));

    mDNSu8 *const rhs = DNSNameCompressionBuildLHS(&lower, kDNSType_PTR);
    const mDNSu8 *const end = putDomainNameAsLabels(&compression_base_msg, rhs, compression_limit, fqdn);
    const size_t keyLen = (size_t)(rhs - compression_lhs);
    const size_t valueLen = (size_t)(end - rhs);
    PrintHelper(__func__, compression_lhs, (mDNSu16)keyLen, rhs, (mDNSu16)valueLen);

    transportType = xD2DMapToTransportType(InterfaceID, flags, & excludedTransport);
    if (transportType == D2DTransportMax)
    {
        // Resolving over all the transports, except for excludedTransport if set.
        D2DTransportType i;
        for (i = 0; i < D2DTransportMax; i++)
        {
            if (i == excludedTransport) continue;
            if (D2DStartResolvingPairOnTransport)
            {
                if (D2DIsTransportLikeAWDL(i))
                {
                    mdns_powerlog_awdl_resolve_start(lower.c, kDNSType_PTR, clientPID);
                }
                D2DStartResolvingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, i);
            }
        }
    }
    else
    {
        // Resolving over one specific transport.
        if (D2DStartResolvingPairOnTransport)
        {
            if (D2DIsTransportLikeAWDL(transportType))
            {
                mdns_powerlog_awdl_resolve_start(lower.c, kDNSType_PTR, clientPID);
            }
            D2DStartResolvingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, transportType);
        }
    }

}

mDNSexport void external_stop_resolving_service(mDNSInterfaceID InterfaceID, const domainname *const fqdn, DNSServiceFlags flags, pid_t clientPID)
{
    domainname lower;
    D2DTransportType transportType, excludedTransport;
    DomainnameToLower(SkipLeadingLabels(fqdn, 1), &lower);

    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "external_stop_resolving_service - "
        "fqdn: " PRI_DM_NAME, DM_NAME_PARAM(fqdn));

    mDNSu8 *const rhs = DNSNameCompressionBuildLHS(&lower, kDNSType_PTR);
    const mDNSu8 *const end = putDomainNameAsLabels(&compression_base_msg, rhs, compression_limit, fqdn);
    const size_t keyLen = (size_t)(rhs - compression_lhs);
    const size_t valueLen = (size_t)(end - rhs);
    PrintHelper(__func__, compression_lhs, (mDNSu16)keyLen, rhs, (mDNSu16)valueLen);

    transportType = xD2DMapToTransportType(InterfaceID, flags, & excludedTransport);
    if (transportType == D2DTransportMax)
    {
        D2DTransportType i;
        for (i = 0; i < D2DTransportMax; i++)
        {
            if (i == excludedTransport) continue;
            if (D2DStopResolvingPairOnTransport)
            {
                D2DStopResolvingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, i);
                if (D2DIsTransportLikeAWDL(i))
                {
                    mdns_powerlog_awdl_resolve_stop(lower.c, kDNSType_PTR, clientPID);
                }
            }
        }
    }
    else
    {
        if (D2DStopResolvingPairOnTransport)
        {
            D2DStopResolvingPairOnTransport(compression_lhs, keyLen, rhs, valueLen, transportType);
            if (D2DIsTransportLikeAWDL(transportType))
            {
                mdns_powerlog_awdl_resolve_stop(lower.c, kDNSType_PTR, clientPID);
            }
        }
    }
}

mDNSexport mDNSBool callExternalHelpers(mDNSInterfaceID InterfaceID, const domainname *const domain, DNSServiceFlags flags)
{
    // Only call D2D layer routines if request applies to a D2D interface and the domain is "local".
    if (    (((InterfaceID == mDNSInterface_Any) && (flags & (kDNSServiceFlagsIncludeP2P | kDNSServiceFlagsIncludeAWDL | kDNSServiceFlagsAutoTrigger)))
            || mDNSPlatformInterfaceIsD2D(InterfaceID) || (InterfaceID == mDNSInterface_BLE))
        && IsLocalDomain(domain))
    {
        return mDNStrue;
    }
    else
        return mDNSfalse;
}

// Used to derive the original D2D specific flags specified by the client in the registration
// when we don't have access to the original flag (kDNSServiceFlags*) values.
mDNSexport mDNSu32 deriveD2DFlagsFromAuthRecType(AuthRecType authRecType)
{
    mDNSu32 flags = 0;
    if ((authRecType == AuthRecordAnyIncludeP2P) || (authRecType == AuthRecordAnyIncludeAWDLandP2P))
        flags |= kDNSServiceFlagsIncludeP2P;
    else if ((authRecType == AuthRecordAnyIncludeAWDL) || (authRecType == AuthRecordAnyIncludeAWDLandP2P))
        flags |= kDNSServiceFlagsIncludeAWDL;
    return flags;
}

void initializeD2DPlugins(mDNS *const m)
{
        // We only initialize if mDNSCore successfully initialized.
        if (D2DInitialize)
        {
            D2DStatus ds = D2DInitialize(CFRunLoopGetMain(), xD2DServiceCallback, m);
            if (ds != kD2DSuccess)
            {
                LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "D2DInitialiize failed: %d", ds);
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "D2DInitialize succeeded");
            }
        }
}

void terminateD2DPlugins(void)
{
    if (D2DTerminate)
    {
        D2DStatus ds = D2DTerminate();
        if (ds != kD2DSuccess)
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_ERROR, "D2DTerminate failed: %d", ds);
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_D2D, MDNS_LOG_DEFAULT, "D2DTerminate succeeded");
        }

    }
}

#ifdef UNIT_TEST
#pragma mark - Unit test support routines

// These unit test support routines are called from unittests/ framework
// and are not compiled for the mDNSResponder runtime code paths.

void D2D_unitTest(void)
{
}

#endif  //  UNIT_TEST
