/*
 * Copyright (c) 2007-2012 Apple Inc. All rights reserved.
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

#include <mach/mach.h>
#include <mach/mach_error.h>
#include <mach/vm_map.h>
#include <servers/bootstrap.h>
#include <IOKit/IOReturn.h>
#include <CoreFoundation/CoreFoundation.h>
#include "mDNSDebug.h"
#include "helper.h"
#include "helpermsg.h"
#include <dispatch/dispatch.h>
#include <arpa/inet.h>

//
// Implementation Notes about the HelperQueue:
//
// To prevent blocking the main queue, all communications with mDNSResponderHelper should happen on
// HelperQueue. There are a few calls which are still synchronous and needs to be handled separately
// case by case.
//
// When spawning off the work to the HelperQueue, any arguments that are pointers need to be copied
// explicitly as they may cease to exist after the call returns. From within the block that is scheduled,
// arrays defined on the stack can't be referenced and hence it is enclosed them in a struct. If the array is
// an argument to the function, the blocks can reference them as they are passed in as pointers. But care should
// be taken to copy them locally as they may cease to exist when the function returns.
//
static dispatch_queue_t HelperQueue;

#define ERROR(x, y) y,
static const char *errorstring[] =
{
    #include "helper-error.h"
    NULL
};
#undef ERROR

mDNSexport mStatus mDNSHelperInit()
{
    HelperQueue = dispatch_queue_create("com.apple.mDNSResponder.HelperQueue", NULL);
    if (HelperQueue == NULL)
    {
        LogMsg("dispatch_queue_create: Helper queue NULL");
        return mStatus_NoMemoryErr;
    }
    return mStatus_NoError;
}

static mach_port_t getHelperPort(int retry)
{
    static mach_port_t port = MACH_PORT_NULL;
    if (retry) port = MACH_PORT_NULL;
    if (port == MACH_PORT_NULL && BOOTSTRAP_SUCCESS != bootstrap_look_up(bootstrap_port, kmDNSHelperServiceName, &port))
        LogMsg("%s: cannot contact helper", __func__);
    return port;
}

const char *mDNSHelperError(int err)
{
    static const char *p = "<unknown error>";
    if (mDNSHelperErrorBase < err && mDNSHelperErrorEnd > err)
        p = errorstring[err - mDNSHelperErrorBase - 1];
    return p;
}

/* Ugly but handy. */
// We don't bother reporting kIOReturnNotReady because that error code occurs in "normal" operation
// and doesn't indicate anything unexpected that needs to be investigated

#define MACHRETRYLOOP_BEGIN(kr, retry, err, fin)                                            \
    for (;;)                                                                                \
    {
#define MACHRETRYLOOP_END(kr, retry, err, fin)                                              \
    if (KERN_SUCCESS == (kr)) break;                                                                                             \
    else if (MACH_SEND_INVALID_DEST == (kr) && 0 == (retry)++) continue;                                                                                             \
    else                                                                                \
    {                                                                               \
        (err) = kmDNSHelperCommunicationFailed;                                         \
        LogMsg("%s: Mach communication failed: %d %X %s", __func__, kr, kr, mach_error_string(kr)); \
        goto fin;                                                                       \
    }                                                                               \
    }                                                                                   \
    if (0 != (err) && kIOReturnNotReady != (err))                                           \
    { LogMsg("%s: %d 0x%X (%s)", __func__, (err), (err), mDNSHelperError(err)); goto fin; }

void mDNSPreferencesSetName(int key, domainlabel *old, domainlabel *new)
{
    struct {
        char oldname[MAX_DOMAIN_LABEL+1];
        char newname[MAX_DOMAIN_LABEL+1];
    } names;

    mDNSPlatformMemZero(names.oldname, MAX_DOMAIN_LABEL + 1);
    mDNSPlatformMemZero(names.newname, MAX_DOMAIN_LABEL + 1);

    ConvertDomainLabelToCString_unescaped(old, names.oldname);
    if (new) ConvertDomainLabelToCString_unescaped(new, names.newname);
    dispatch_async(HelperQueue, ^{

        kern_return_t kr = KERN_FAILURE;
        int retry = 0;
        int err = 0;

        LogInfo("%s: oldname %s newname %s", __func__, names.oldname, names.newname);
        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSPreferencesSetName(getHelperPort(retry), key, names.oldname, names.newname);
        MACHRETRYLOOP_END(kr, retry, err, fin);

fin:
        (void)err;
    });
}

void mDNSRequestBPF(void)
{
    dispatch_async(HelperQueue, ^{

        kern_return_t kr = KERN_FAILURE;
        int retry = 0, err = 0;
        LogInfo("%s: BPF", __func__);
        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSRequestBPF(getHelperPort(retry));
        MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
        (void)err;
    });
}

int mDNSPowerRequest(int key, int interval)
{
    kern_return_t kr = KERN_FAILURE;
    int retry = 0, err = 0;
    MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
    kr = proxy_mDNSPowerRequest(getHelperPort(retry), key, interval, &err);
    MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
    return err;
}

int mDNSSetLocalAddressCacheEntry(int ifindex, int family, const v6addr_t ip, const ethaddr_t eth)
{
    kern_return_t kr = KERN_FAILURE;
    int retry = 0, err = 0;
    MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
    kr = proxy_mDNSSetLocalAddressCacheEntry(getHelperPort(retry), ifindex, family, (uint8_t*)ip, (uint8_t*)eth, &err);
    MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
    return err;
}

void mDNSNotify(const char *title, const char *msg) // Both strings are UTF-8 text
{
    char *titleCopy = NULL;
    char *msgCopy = NULL;

    if (title)
    {
        int len = strlen(title);
        titleCopy = mDNSPlatformMemAllocate(len + 1);
        if (!titleCopy)
        {
            LogMsg("mDNSNotify: titleCopy NULL for %s", msg);
            return;
        }
        mDNSPlatformMemCopy(titleCopy, title, len);
        titleCopy[len] = 0;
    }
    if (msg)
    {
        int len = strlen(msg);
        msgCopy = mDNSPlatformMemAllocate(len + 1);
        if (!msgCopy)
        {
            LogMsg("mDNSNotify: msgCopy NULL for %s", msg);
            return;
        }
        mDNSPlatformMemCopy(msgCopy, msg, len);
        msgCopy[len] = 0;
    }
        
    dispatch_async(HelperQueue, ^{

        kern_return_t kr = KERN_FAILURE;
        int retry = 0, err = 0;

        LogInfo("%s: title %s, msg %s", __func__, titleCopy, msgCopy);

        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSNotify(getHelperPort(retry), titleCopy, msgCopy);
        MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
        if (titleCopy)
            mDNSPlatformMemFree(titleCopy);
        if (msgCopy)
            mDNSPlatformMemFree(msgCopy);
        (void)err;
    });
}

int mDNSKeychainGetSecrets(CFArrayRef *result)
{
    CFPropertyListRef plist = NULL;
    CFDataRef bytes = NULL;
    kern_return_t kr = KERN_FAILURE;
    unsigned int numsecrets = 0;
    vm_offset_t secrets = 0;
    mach_msg_type_number_t secretsCnt = 0;
    int retry = 0, err = 0;

    MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
    kr = proxy_mDNSKeychainGetSecrets(getHelperPort(retry), &numsecrets, &secrets, &secretsCnt, &err);
    MACHRETRYLOOP_END(kr, retry, err, fin);

    if (NULL == (bytes = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (void*)secrets, secretsCnt, kCFAllocatorNull)))
    {
        err = kmDNSHelperCreationFailed;
        LogMsg("%s: CFDataCreateWithBytesNoCopy failed", __func__);
        goto fin;
    }
    if (NULL == (plist = CFPropertyListCreateFromXMLData(kCFAllocatorDefault, bytes, kCFPropertyListImmutable, NULL)))
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
    if (bytes) CFRelease(bytes);
    if (secrets) vm_deallocate(mach_task_self(), secrets, secretsCnt);
    return err;
}

void mDNSConfigureServer(int updown, const char *const prefix, const domainname *const fqdn)
{
    struct
    {
        // Assume the prefix is no larger than 10 chars
        char fqdnStr[MAX_ESCAPED_DOMAIN_NAME + 10];
    } name;

    mDNSPlatformMemZero(name.fqdnStr, MAX_DOMAIN_LABEL + 10);

    if (fqdn)
    {
        mDNSPlatformStrCopy(name.fqdnStr, prefix);
        ConvertDomainNameToCString(fqdn, name.fqdnStr + mDNSPlatformStrLen(prefix));
    }

    dispatch_async(HelperQueue, ^{

        kern_return_t kr = KERN_SUCCESS;
        int retry = 0, err = 0;

        LogInfo("%s: fqdnStr %s", __func__, name.fqdnStr);

        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSConfigureServer(getHelperPort(retry), updown, name.fqdnStr);
        MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
        (void)err;

    });
}

int mDNSAutoTunnelSetKeys(int replacedelete, v6addr_t local_inner,
                          v6addr_t local_outer, short local_port, v6addr_t remote_inner,
                          v6addr_t remote_outer, short remote_port, const char* const prefix, const domainname *const fqdn)
{
    kern_return_t kr = KERN_SUCCESS;
    int retry = 0, err = 0;
    char fqdnStr[MAX_ESCAPED_DOMAIN_NAME + 10] = { 0 }; // Assume the prefix is no larger than 10 chars
    if (fqdn)
    {
        mDNSPlatformStrCopy(fqdnStr, prefix);
        ConvertDomainNameToCString(fqdn, fqdnStr + mDNSPlatformStrLen(prefix));
    }
    MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
    kr = proxy_mDNSAutoTunnelSetKeys(getHelperPort(retry), replacedelete, local_inner, local_outer, local_port, remote_inner, remote_outer, remote_port, fqdnStr, &err);
    MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
    return err;
}

void mDNSSendWakeupPacket(unsigned ifid, char *eth_addr, char *ip_addr, int iteration)
{
    char *ip_addr_copy = NULL;
    char *eth_addr_copy = NULL;

    if (eth_addr)
    {
        int len = strlen(eth_addr);
        eth_addr_copy = mDNSPlatformMemAllocate(len + 1);
        if (!eth_addr_copy)
        {
            LogMsg("mDNSSendWakeupPacket: eth_addr_copy NULL for %s", eth_addr);
            return;
        }
        mDNSPlatformMemCopy(eth_addr_copy, eth_addr, len);
        eth_addr_copy[len] = 0;
    }
    if (ip_addr)
    {
        int len = strlen(ip_addr);
        ip_addr_copy = mDNSPlatformMemAllocate(len + 1);
        if (!ip_addr_copy)
        {
            LogMsg("mDNSSendWakeupPacket: ip_addr_copy NULL for %s", ip_addr);
            return;
        }
        mDNSPlatformMemCopy(ip_addr_copy, ip_addr, len);
        ip_addr_copy[len] = 0;
    }
    dispatch_async(HelperQueue, ^{

        kern_return_t kr = KERN_SUCCESS;
        int retry = 0, err = 0;

        LogInfo("%s: Entered ethernet address %s, ip address %s", __func__, eth_addr_copy, ip_addr_copy);

        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSSendWakeupPacket(getHelperPort(retry), ifid, eth_addr_copy, ip_addr_copy, iteration);
        MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
        if (eth_addr_copy)
            mDNSPlatformMemFree(eth_addr_copy);
        if (ip_addr_copy)
            mDNSPlatformMemFree(ip_addr_copy);
        (void) err;
    });
}

void mDNSPacketFilterControl(uint32_t command, char * ifname, uint32_t count, pfArray_t portArray, pfArray_t protocolArray)
{
    struct
    {
        pfArray_t portArray;
        pfArray_t protocolArray;
    } pfa;
    char *ifnameCopy = NULL;
    
    mDNSPlatformMemCopy(pfa.portArray, portArray, sizeof(pfArray_t));
    mDNSPlatformMemCopy(pfa.protocolArray, protocolArray, sizeof(pfArray_t));
    if (ifname)
    {
        int len = strlen(ifname);
        ifnameCopy = mDNSPlatformMemAllocate(len + 1);
        if (!ifnameCopy)
        {
            LogMsg("mDNSPacketFilterControl: ifnameCopy NULL");
            return;
        }
        mDNSPlatformMemCopy(ifnameCopy, ifname, len);
        ifnameCopy[len] = 0;
    }
    dispatch_async(HelperQueue, ^{

        kern_return_t kr = KERN_SUCCESS;
        int retry = 0, err = 0;

        LogInfo("%s, ifname %s", __func__, ifnameCopy);

        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSPacketFilterControl(getHelperPort(retry), command, ifnameCopy, count, (uint16_t *)pfa.portArray, (uint16_t *)pfa.protocolArray);
        MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
        if (ifnameCopy)
            mDNSPlatformMemFree(ifnameCopy);
        (void) err;
    });
}

void mDNSSendKeepalive(v6addr_t sadd, v6addr_t dadd, uint16_t lport, uint16_t rport, unsigned seq, unsigned ack, uint16_t win)
{
    struct
    {
        v6addr_t sadd;
        v6addr_t dadd;
    } addr;

    mDNSPlatformMemCopy(addr.sadd, sadd, sizeof(v6addr_t));
    mDNSPlatformMemCopy(addr.dadd, dadd, sizeof(v6addr_t));

    dispatch_async(HelperQueue, ^{

        kern_return_t kr = KERN_FAILURE;
        int retry = 0, err = 0;
        char buf1[INET6_ADDRSTRLEN];
        char buf2[INET6_ADDRSTRLEN];

        buf1[0] = 0;
        buf2[0] = 0;

        inet_ntop(AF_INET6, addr.sadd, buf1, sizeof(buf1));
        inet_ntop(AF_INET6, addr.dadd, buf2, sizeof(buf2));
        LogInfo("%s: sadd is %s, dadd is %s", __func__, buf1, buf2);

        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSSendKeepalive(getHelperPort(retry), (uint8_t *)addr.sadd, (uint8_t *)addr.dadd, lport, rport, seq, ack, win);
        MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
        (void) err;
    });
}

int mDNSRetrieveTCPInfo(int family, v6addr_t laddr, uint16_t lport, v6addr_t raddr, uint16_t rport, uint32_t *seq, uint32_t *ack, uint16_t *win, int32_t *intfid)
{
    kern_return_t kr = KERN_FAILURE;
    int retry = 0, err = 0;
    MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
    kr = proxy_mDNSRetrieveTCPInfo(getHelperPort(retry), family, (uint8_t *)laddr, lport, (uint8_t *)raddr, rport, seq, ack, win, intfid);
    MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
    return err;
}

void mDNSGetRemoteMAC(mDNS *const m, int family, v6addr_t raddr)
{
    struct {
        v6addr_t addr;
    } dst;

    mDNSPlatformMemCopy(dst.addr, raddr, sizeof(v6addr_t));
    dispatch_async(HelperQueue, ^{
        kern_return_t        kr    = KERN_FAILURE;
        int                  retry = 0, err = 0;
        ethaddr_t            eth;
        IPAddressMACMapping *addrMapping;

        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSGetRemoteMAC(getHelperPort(retry), family, (uint8_t *)dst.addr, eth);
        MACHRETRYLOOP_END(kr, retry, err, fin);
        // If the call to get the remote MAC address succeeds, allocate and copy
        // the values and schedule a task to update the MAC address in the TCP Keepalive record.
        if (kr == KERN_SUCCESS)
        {
            addrMapping = (IPAddressMACMapping *)malloc(sizeof(IPAddressMACMapping));
            snprintf(addrMapping->ethaddr, sizeof(addrMapping->ethaddr), "%02x:%02x:%02x:%02x:%02x:%02x",
                     eth[0], eth[1], eth[2], eth[3], eth[4], eth[5]);
            if (family == AF_INET)
            {
                addrMapping->ipaddr.type = mDNSAddrType_IPv4;
                mDNSPlatformMemCopy(addrMapping->ipaddr.ip.v4.b,  dst.addr, sizeof(v6addr_t));
            }
            else
            {
                addrMapping->ipaddr.type = mDNSAddrType_IPv6;
                mDNSPlatformMemCopy(addrMapping->ipaddr.ip.v6.b,  dst.addr, sizeof(v6addr_t));
            }
            mDNSPlatformDispatchAsync(m, addrMapping, UpdateRMACCallback);
        }
fin:
            (void) err;
    });

}

void mDNSStoreSPSMACAddress(int family, v6addr_t spsaddr, char *ifname)
{
    struct {
        v6addr_t saddr;
    } addr;
    mDNSPlatformMemCopy(addr.saddr, spsaddr, sizeof(v6addr_t));

    dispatch_async(HelperQueue, ^{
        kern_return_t kr = KERN_FAILURE;
        int retry = 0, err = 0;
        MACHRETRYLOOP_BEGIN(kr, retry, err, fin);
        kr = proxy_mDNSStoreSPSMACAddress(getHelperPort(retry), family, (uint8_t *)addr.saddr, ifname);
        MACHRETRYLOOP_END(kr, retry, err, fin);
fin:
        (void)err;
    });
}
