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

// ***************************************************************************
// mDNSMacOSX.c:
// Supporting routines to run mDNS on a CFRunLoop platform
// ***************************************************************************

// For debugging, set LIST_ALL_INTERFACES to 1 to display all found interfaces,
// including ones that mDNSResponder chooses not to use.
#define LIST_ALL_INTERFACES 0

#include "mDNSEmbeddedAPI.h"        // Defines the interface provided to the client layer above
#include "DNSCommon.h"
#include "uDNS.h"
#include "mDNSMacOSX.h"             // Defines the specific types needed to run mDNS on this platform
#include "dns_sd.h"                 // For mDNSInterface_LocalOnly etc.
#include "dns_sd_internal.h"
#include "PlatformCommon.h"
#include "uds_daemon.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)
#include "dnssd_analytics.h"
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
#include "mdns_trust.h"
#include <os/feature_private.h>
#endif

#if defined(__x86_64__) && __x86_64__
#include <smmintrin.h>
#endif

#include <mdns/power.h>
#include <mdns/sockaddr.h>
#include <mdns/tcpinfo.h>
#include <stdio.h>
#include <stdarg.h>                 // For va_list support
#include <stdlib.h>                 // For arc4random
#include <net/if.h>
#include <net/if_types.h>           // For IFT_ETHER
#include <net/if_dl.h>
#include <net/bpf.h>                // For BIOCSETIF etc.
#include <sys/uio.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/event.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <time.h>                   // platform support for UTC time
#include <arpa/inet.h>              // for inet_aton
#include <pthread.h>
#include <netdb.h>                  // for getaddrinfo
#include <sys/sockio.h>             // for SIOCGIFEFLAGS
#include <notify.h>
#include <netinet/in.h>             // For IP_RECVTTL
#ifndef IP_RECVTTL
#define IP_RECVTTL 24               // bool; receive reception TTL w/dgram
#endif

#include <netinet/in_systm.h>       // For n_long, required by <netinet/ip.h> below
#include <netinet/ip.h>             // For IPTOS_LOWDELAY etc.
#include <netinet6/in6_var.h>       // For IN6_IFF_TENTATIVE etc.

#include <netinet/tcp.h>

#include "DebugServices.h"
#include "dnsinfo.h"

#include <ifaddrs.h>

#include <IOKit/IOKitLib.h>
#include <IOKit/IOMessage.h>

#include <IOKit/ps/IOPowerSources.h>
#include <IOKit/ps/IOPowerSourcesPrivate.h>
#include <IOKit/ps/IOPSKeys.h>

#include <mach/mach_error.h>
#include <mach/mach_port.h>
#include <mach/mach_time.h>
#include "helper.h"

#include <SystemConfiguration/SCPrivate.h>

#include <Security/oidsalg.h> // To include the deprecated symbol `CSSMOID_APPLE_X509_BASIC`.

// Include definition of opaque_presence_indication for KEV_DL_NODE_PRESENCE handling logic.
#include <Kernel/IOKit/apple80211/apple80211_var.h>



#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
#include "QuerierSupport.h"
#endif

#ifdef UNIT_TEST
#include "unittest.h"
#endif


#include "mrcs_server.h"
#include "mdns_strict.h"

#define mDNS_IOREG_KEY               "mDNS_KEY"
#define mDNS_IOREG_VALUE             "2009-07-30"
#if !TARGET_OS_WATCH
#define mDNS_IOREG_KA_KEY            "mDNS_Keepalive"
#endif
#define mDNS_USER_CLIENT_CREATE_TYPE 'mDNS'

#define DARK_WAKE_TIME 16 // Time we hold an idle sleep assertion for maintenance after a wake notification

// cache the InterfaceID of the AWDL interface
mDNSInterfaceID AWDLInterfaceID;
mDNSInterfaceID WiFiAwareInterfaceID;

// ***************************************************************************
// Globals

// MARK: - Globals

// By default we don't offer sleep proxy service
// If OfferSleepProxyService is set non-zero (typically via command-line switch),
// then we'll offer sleep proxy service on desktop Macs that are set to never sleep.
// We currently do not offer sleep proxy service on laptops, or on machines that are set to go to sleep.
mDNSexport int OfferSleepProxyService = 0;
mDNSexport int DisableSleepProxyClient = 0;
mDNSexport int UseInternalSleepProxy = 1;       // Set to non-zero to use internal (in-NIC) Sleep Proxy

mDNSexport int OSXVers, iOSVers;
mDNSexport int KQueueFD;

#ifndef NO_SECURITYFRAMEWORK
static CFArrayRef ServerCerts;
OSStatus SSLSetAllowAnonymousCiphers(SSLContextRef context, Boolean enable);
#endif /* NO_SECURITYFRAMEWORK */

static CFStringRef NetworkChangedKey_IPv4;
static CFStringRef NetworkChangedKey_IPv6;
static CFStringRef NetworkChangedKey_Hostnames;
static CFStringRef NetworkChangedKey_Computername;
static CFStringRef NetworkChangedKey_DNS;
static CFStringRef NetworkChangedKey_StateInterfacePrefix;
static CFStringRef NetworkChangedKey_DynamicDNS       = CFSTR("Setup:/Network/DynamicDNS");
static CFStringRef NetworkChangedKey_PowerSettings    = CFSTR("State:/IOKit/PowerManagement/CurrentSettings");

static char HINFO_HWstring_buffer[32];
static char *HINFO_HWstring = "Device";
static int HINFO_HWstring_prefixlen = 6;

mDNSexport int WatchDogReportingThreshold = 250;

dispatch_queue_t SSLqueue;


#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DOTLOCAL)
domainname ActiveDirectoryPrimaryDomain;
static int ActiveDirectoryPrimaryDomainLabelCount;
static mDNSAddr ActiveDirectoryPrimaryDomainServer;
#endif

// Don't send triggers too often. We arbitrarily limit it to three minutes.
#define DNS_TRIGGER_INTERVAL (180 * mDNSPlatformOneSecond)

const char dnsprefix[] = "dns:";

// String Array used to write list of private domains to Dynamic Store
static CFArrayRef privateDnsArray = NULL;

// ***************************************************************************
// Functions

// MARK: - Utility Functions

// We only attempt to send and receive multicast packets on interfaces that are
// (a) flagged as multicast-capable
// (b) *not* flagged as point-to-point (e.g. modem)
// Typically point-to-point interfaces are modems (including mobile-phone pseudo-modems), and we don't want
// to run up the user's bill sending multicast traffic over a link where there's only a single device at the
// other end, and that device (e.g. a modem bank) is probably not answering Multicast DNS queries anyway.


#if MDNSRESPONDER_SUPPORTS(APPLE, BONJOUR_ON_DEMAND)
#define MulticastInterface(i) ((i)->m->BonjourEnabled               && \
                              ((i)->ifa_flags & IFF_MULTICAST)      && \
                              !((i)->ifa_flags & IFF_POINTOPOINT))
#else
#define MulticastInterface(i) (((i)->ifa_flags & IFF_MULTICAST)     && \
                              !((i)->ifa_flags & IFF_POINTOPOINT))
#endif
#define SPSInterface(i)       ((i)->ifinfo.McastTxRx && !((i)->ifa_flags & IFF_LOOPBACK) && !(i)->D2DInterface)

mDNSlocal void SetNetworkChanged(mDNSs32 delay);

mDNSexport void NotifyOfElusiveBug(const char *title, const char *msg)  // Both strings are UTF-8 text
{
    // Unless ForceAlerts is defined, we only show these bug report alerts on machines that have a 17.x.x.x address
    #if !ForceAlerts
    {
        // Determine if we're at Apple (17.*.*.*)
        NetworkInterfaceInfoOSX *i;
        for (i = mDNSStorage.p->InterfaceList; i; i = i->next)
            if (i->ifinfo.ip.type == mDNSAddrType_IPv4 && i->ifinfo.ip.ip.v4.b[0] == 17)
                break;
        if (!i)
            return; // If not at Apple, don't show the alert
    }
    #endif

    LogMsg("NotifyOfElusiveBug: %s", title);
    LogMsg("NotifyOfElusiveBug: %s", msg);

    // If we display our alert early in the boot process, then it vanishes once the desktop appears.
    // To avoid this, we don't try to display alerts in the first three minutes after boot.
    if ((mDNSu32)(mDNSPlatformRawTime()) < (mDNSu32)(mDNSPlatformOneSecond * 180))
    {
        LogMsg("Suppressing notification early in boot: %d", mDNSPlatformRawTime());
        return;
    }

#ifndef NO_CFUSERNOTIFICATION
    static int notifyCount = 0; // To guard against excessive display of warning notifications
    if (notifyCount < 5)
    {
        notifyCount++;
        mDNSNotify(title, msg);
    }
#endif /* NO_CFUSERNOTIFICATION */

}

// Write a syslog message and display an alert, then if ForceAlerts is set, generate a stack trace
#if MDNS_MALLOC_DEBUGGING >= 1
mDNSexport void LogMemCorruption(const char *format, ...)
{
    char buffer[512];
    va_list ptr;
    va_start(ptr,format);
    mDNS_vsnprintf((char *)buffer, sizeof(buffer), format, ptr);
    va_end(ptr);
    LogMsg("!!!! %s !!!!", buffer);
    NotifyOfElusiveBug("Memory Corruption", buffer);
#if ForceAlerts
    *(volatile long*)0 = 0;  // Trick to crash and get a stack trace right here, if that's what we want
#endif
}
#endif

// Like LogMemCorruption above, but only display the alert if ForceAlerts is set and we're going to generate a stack trace

// Returns true if it is an AppleTV based hardware running iOS, false otherwise
mDNSlocal mDNSBool IsAppleTV(void)
{
#if TARGET_OS_TV
    return mDNStrue;
#else
    return mDNSfalse;
#endif
}

mDNSlocal struct ifaddrs *myGetIfAddrs(int refresh)
{
    static struct ifaddrs *ifa = NULL;

    if (refresh && ifa)
    {
        freeifaddrs(ifa);
        ifa = NULL;
    }

    if (ifa == NULL)
        getifaddrs(&ifa);
    return ifa;
}

mDNSlocal void DynamicStoreWrite(enum mDNSDynamicStoreSetConfigKey key, const char* subkey, uintptr_t value, signed long valueCnt)
{
    CFStringRef sckey       = NULL;
    Boolean release_sckey   = FALSE;
    CFDataRef bytes         = NULL;
    CFPropertyListRef plist = NULL;

    switch (key)
    {
        case kmDNSMulticastConfig:
            sckey = CFSTR("State:/Network/" kDNSServiceCompMulticastDNS);
            break;
        case kmDNSDynamicConfig:
            sckey = CFSTR("State:/Network/DynamicDNS");
            break;
        case kmDNSPrivateConfig:
            sckey = CFSTR("State:/Network/" kDNSServiceCompPrivateDNS);
            break;
        case kmDNSBackToMyMacConfig:
            sckey = CFSTR("State:/Network/BackToMyMac");
            break;
        case kmDNSSleepProxyServersState:
        {
            CFMutableStringRef tmp = CFStringCreateMutable(kCFAllocatorDefault, 0);
            CFStringAppend(tmp, CFSTR("State:/Network/Interface/"));
            CFStringAppendCString(tmp, subkey, kCFStringEncodingUTF8);
            CFStringAppend(tmp, CFSTR("/SleepProxyServers"));
            sckey = CFStringCreateCopy(kCFAllocatorDefault, tmp);
            release_sckey = TRUE;
            MDNS_DISPOSE_CF_OBJECT(tmp);
            break;
        }
        case kmDNSDebugState:
            sckey = CFSTR("State:/Network/mDNSResponder/DebugState");
            break;
        MDNS_COVERED_SWITCH_DEFAULT:
            LogMsg("unrecognized key %d", key);
            goto fin;
    }
    if (NULL == (bytes = CFDataCreateWithBytesNoCopy(NULL, (void *)value,
                                                     valueCnt, kCFAllocatorNull)))
    {
        LogMsg("CFDataCreateWithBytesNoCopy of value failed");
        goto fin;
    }
    if (NULL == (plist = CFPropertyListCreateWithData(NULL, bytes, kCFPropertyListImmutable, NULL, NULL)))
    {
        LogMsg("CFPropertyListCreateWithData of bytes failed");
        goto fin;
    }
    MDNS_DISPOSE_CF_OBJECT(bytes);
    SCDynamicStoreSetValue(NULL, sckey, plist);

fin:
    MDNS_DISPOSE_CF_OBJECT(bytes);
    MDNS_DISPOSE_CF_OBJECT(plist);
    if (release_sckey)
        MDNS_DISPOSE_CF_OBJECT(sckey);
}

mDNSexport void mDNSDynamicStoreSetConfig(enum mDNSDynamicStoreSetConfigKey key, const char *subkey, CFPropertyListRef value)
{
    CFPropertyListRef valueCopy;
    char *subkeyCopy  = NULL;
    if (!value)
        return;

    // We need to copy the key and value before we dispatch off the block below as the
    // caller will free the memory once we return from this function.
    valueCopy = CFPropertyListCreateDeepCopy(NULL, value, kCFPropertyListImmutable);
    if (!valueCopy)
    {
        LogMsg("mDNSDynamicStoreSetConfig: ERROR valueCopy NULL");
        return;
    }
    if (subkey)
    {
        const mDNSu32 len = (mDNSu32)strlen(subkey);
        subkeyCopy = mDNSPlatformMemAllocate(len + 1);
        if (!subkeyCopy)
        {
            LogMsg("mDNSDynamicStoreSetConfig: ERROR subkeyCopy NULL");
            MDNS_DISPOSE_CF_OBJECT(valueCopy);
            return;
        }
        mDNSPlatformMemCopy(subkeyCopy, subkey, len);
        subkeyCopy[len] = 0;
    }

    dispatch_async(dispatch_get_main_queue(), ^{
        CFWriteStreamRef stream = NULL;
        CFDataRef bytes = NULL;
        CFIndex ret;
        KQueueLock();

        if (NULL == (stream = CFWriteStreamCreateWithAllocatedBuffers(NULL, NULL)))
        {
            LogMsg("mDNSDynamicStoreSetConfig : CFWriteStreamCreateWithAllocatedBuffers failed (Object creation failed)");
            goto END;
        }
        CFWriteStreamOpen(stream);
        ret = CFPropertyListWrite(valueCopy, stream, kCFPropertyListBinaryFormat_v1_0, 0, NULL);
        if (ret == 0)
        {
            LogMsg("mDNSDynamicStoreSetConfig : CFPropertyListWriteToStream failed (Could not write property list to stream)");
            goto END;
        }
        if (NULL == (bytes = CFWriteStreamCopyProperty(stream, kCFStreamPropertyDataWritten)))
        {
            LogMsg("mDNSDynamicStoreSetConfig : CFWriteStreamCopyProperty failed (Object creation failed) ");
            goto END;
        }
        CFWriteStreamClose(stream);
        MDNS_DISPOSE_CF_OBJECT(stream);
        const UInt8 * bytes_ptr = CFDataGetBytePtr(bytes);
        DynamicStoreWrite(key, subkeyCopy ? subkeyCopy : "", (uintptr_t)bytes_ptr, CFDataGetLength(bytes));

    END:;
        CFPropertyListRef tmp = valueCopy;
        MDNS_DISPOSE_CF_OBJECT(tmp);
        if (NULL != stream)
        {
            CFWriteStreamClose(stream);
            MDNS_DISPOSE_CF_OBJECT(stream);
        }
        MDNS_DISPOSE_CF_OBJECT(bytes);
        if (subkeyCopy)
            mDNSPlatformMemFree(subkeyCopy);

        KQueueUnlock("mDNSDynamicStoreSetConfig");
    });
}

// To match *either* a v4 or v6 instance of this interface name, pass AF_UNSPEC for type
mDNSlocal NetworkInterfaceInfoOSX *SearchForInterfaceByName(const char *ifname, int type)
{
    NetworkInterfaceInfoOSX *i;
    for (i = mDNSStorage.p->InterfaceList; i; i = i->next)
        if (i->Exists && !strcmp(i->ifinfo.ifname, ifname) &&
            ((type == AF_UNSPEC                                         ) ||
             (type == AF_INET  && i->ifinfo.ip.type == mDNSAddrType_IPv4) ||
             (type == AF_INET6 && i->ifinfo.ip.type == mDNSAddrType_IPv6))) return(i);
    return(NULL);
}

mDNSlocal int myIfIndexToName(u_short ifindex, char *name)
{
    struct ifaddrs *ifa;
    for (ifa = myGetIfAddrs(0); ifa; ifa = ifa->ifa_next)
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK)
            if (((struct sockaddr_dl*)ifa->ifa_addr)->sdl_index == ifindex)
            { mdns_strlcpy(name, ifa->ifa_name, IF_NAMESIZE); return 0; }
    return -1;
}

mDNSexport NetworkInterfaceInfoOSX *IfindexToInterfaceInfoOSX(mDNSInterfaceID ifindex)
{
    mDNS *const m = &mDNSStorage;
    mDNSu32 scope_id = (mDNSu32)(uintptr_t)ifindex;
    NetworkInterfaceInfoOSX *i;

    // Don't get tricked by inactive interfaces
    for (i = m->p->InterfaceList; i; i = i->next)
        if (i->Registered && i->scope_id == scope_id) return(i);

    return mDNSNULL;
}

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
mDNSexport mdns_interface_monitor_t GetInterfaceMonitorForIndex(uint32_t ifIndex)
{
    mDNS *const m = &mDNSStorage;

    // We assume that interface should always be real interface, and should never be 0.
    if (ifIndex == 0) return NULL;

    if (!m->p->InterfaceMonitors)
    {
        m->p->InterfaceMonitors = CFArrayCreateMutable(kCFAllocatorDefault, 0, &mdns_cfarray_callbacks);
        if (!m->p->InterfaceMonitors)
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "Failed to create InterfaceMonitors array");
            return NULL;
        }
    }

    // Search for interface monitor given the interface index.
    mdns_interface_monitor_t monitor;
    for (CFIndex i = 0, n = CFArrayGetCount(m->p->InterfaceMonitors); i < n; i++)
    {
        monitor = (mdns_interface_monitor_t) CFArrayGetValueAtIndex(m->p->InterfaceMonitors, i);
        if (mdns_interface_monitor_get_interface_index(monitor) == ifIndex) return monitor;
    }

    // If we come here, it means the interface is a new interface that needs to be monitored.
    monitor = mdns_interface_monitor_create(ifIndex);
    if (!monitor)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "Failed to create an interface monitor for index %u", ifIndex);
        return NULL;
    }
    CFArrayAppendValue(m->p->InterfaceMonitors, monitor);

    // Put the monitor into serial queue.
    mdns_interface_monitor_set_queue(monitor, dispatch_get_main_queue());

    // When the interface configuration is changed, this block will be called.
    mdns_interface_monitor_set_update_handler(monitor,
    ^(mdns_interface_flags_t changeFlags)
    {
        const mdns_interface_flags_t relevantFlags =
            mdns_interface_flag_expensive   |
            mdns_interface_flag_constrained |
            mdns_interface_flag_clat46;
        if ((changeFlags & relevantFlags) == 0) return;

        KQueueLock();
        const CFRange range = CFRangeMake(0, CFArrayGetCount(m->p->InterfaceMonitors));
        if (CFArrayContainsValue(m->p->InterfaceMonitors, range, monitor))
        {
            m->p->if_interface_changed = mDNStrue;

#if MDNSRESPONDER_SUPPORTS(APPLE, OS_LOG)
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "Monitored interface changed: %@", monitor);
#endif
            // Let mDNSResponder update its network configuration.
            mDNS_Lock(m);
            SetNetworkChanged((mDNSPlatformOneSecond + 39) / 40);   // 25 ms delay
            mDNS_Unlock(m);
        }
        KQueueUnlock("interface monitor update handler");
    });

    mdns_interface_monitor_set_event_handler(monitor,
    ^(mdns_event_t event, OSStatus error)
    {
        switch (event)
        {
            case mdns_event_invalidated:
                mdns_release(monitor);
                break;

            case mdns_event_error:
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "Interface monitor for index %u error: %ld",
                    mdns_interface_monitor_get_interface_index(monitor), (long) error);
                KQueueLock();
                if (m->p->InterfaceMonitors)
                {
                    const CFRange range = CFRangeMake(0, CFArrayGetCount(m->p->InterfaceMonitors));
                    const CFIndex i = CFArrayGetFirstIndexOfValue(m->p->InterfaceMonitors, range, monitor);
                    if (i >= 0) CFArrayRemoveValueAtIndex(m->p->InterfaceMonitors, i);
                }
                KQueueUnlock("interface monitor event handler");
                mdns_interface_monitor_invalidate(monitor);
                break;

            default:
                break;
        }
    });
    mdns_interface_monitor_activate(monitor);

    return monitor;
}
#endif

mDNSexport mDNSInterfaceID mDNSPlatformInterfaceIDfromInterfaceIndex(mDNS *const m, mDNSu32 ifindex)
{
    (void) m;
    if (ifindex == kDNSServiceInterfaceIndexLocalOnly) return(mDNSInterface_LocalOnly);
    if (ifindex == kDNSServiceInterfaceIndexP2P      ) return(mDNSInterface_P2P);
    if (ifindex == kDNSServiceInterfaceIndexBLE      ) return(mDNSInterface_BLE);
    if (ifindex == kDNSServiceInterfaceIndexAny      ) return(mDNSNULL);

    NetworkInterfaceInfoOSX* ifi = IfindexToInterfaceInfoOSX((mDNSInterfaceID)(uintptr_t)ifindex);
    if (!ifi)
    {
        // Not found. Make sure our interface list is up to date, then try again.
        LogInfo("mDNSPlatformInterfaceIDfromInterfaceIndex: InterfaceID for interface index %d not found; Updating interface list", ifindex);
        mDNSMacOSXNetworkChanged();
        ifi = IfindexToInterfaceInfoOSX((mDNSInterfaceID)(uintptr_t)ifindex);
    }

    if (!ifi) return(mDNSNULL);

    return(ifi->ifinfo.InterfaceID);
}


mDNSexport mDNSu32 mDNSPlatformInterfaceIndexfromInterfaceID(mDNS *const m, mDNSInterfaceID id, mDNSBool suppressNetworkChange)
{
    NetworkInterfaceInfoOSX *i;
    if (id == mDNSInterface_Any      ) return(0);
    if (id == mDNSInterface_LocalOnly) return(kDNSServiceInterfaceIndexLocalOnly);
    if (id == mDNSInterface_P2P      ) return(kDNSServiceInterfaceIndexP2P);
    if (id == mDNSInterface_BLE      ) return(kDNSServiceInterfaceIndexBLE);

    mDNSu32 scope_id = (mDNSu32)(uintptr_t)id;

    // Don't use i->Registered here, because we DO want to find inactive interfaces, which have no Registered set
    for (i = m->p->InterfaceList; i; i = i->next)
        if (i->scope_id == scope_id) return(i->scope_id);

    // If we are supposed to suppress network change, return "id" back
    if (suppressNetworkChange) return scope_id;

    // Not found. Make sure our interface list is up to date, then try again.
    LogInfo("Interface index for InterfaceID %p not found; Updating interface list", id);
    mDNSMacOSXNetworkChanged();
    for (i = m->p->InterfaceList; i; i = i->next)
        if (i->scope_id == scope_id) return(i->scope_id);

    return(0);
}

mDNSlocal mDNSBool GetInterfaceSupportsWakeOnLANPacket(mDNSInterfaceID id)
{
    NetworkInterfaceInfoOSX *info = IfindexToInterfaceInfoOSX(id);
    if (info == NULL)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "GetInterfaceSupportsWakeOnLANPacket: Invalid interface id %p", id);
        return mDNSfalse;
    }
    else
    {
        return (info->ift_family == IFRTYPE_FAMILY_ETHERNET) ? mDNStrue : mDNSfalse;
    }
}

mDNSlocal uint32_t GetIFTFamily(const char * _Nonnull if_name, uint32_t *out_sub_family)
{
    uint32_t ift_family = IFRTYPE_FAMILY_ANY;
    if (out_sub_family)
    {
        *out_sub_family = IFRTYPE_SUBFAMILY_ANY;
    }
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s == -1)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR, "GetIFTFamily: socket() failed: " PUB_S, strerror(errno));
        return ift_family;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    mdns_strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFTYPE, (caddr_t)&ifr) == -1)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "GetIFTFamily: SIOCGIFTYPE failed: " PUB_S, strerror(errno));
    }
    else
    {
        ift_family = ifr.ifr_type.ift_family;
        if (out_sub_family)
        {
            *out_sub_family = ifr.ifr_type.ift_subfamily;
        }
    }
    close(s);
    return ift_family;
}

mDNSlocal uint32_t GetIFRFunctionalType(const char * const _Nonnull if_name)
{
    uint32_t type = IFRTYPE_FUNCTIONAL_UNKNOWN;

    const int info_socket = socket(AF_INET6, SOCK_DGRAM, 0);
    mdns_require_quiet(info_socket != -1, exit);

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    mdns_strlcpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));

    const int ioctl_ret = ioctl(info_socket, SIOCGIFFUNCTIONALTYPE, (caddr_t)&ifr);
    mdns_require_quiet(ioctl_ret != -1, exit);

    type = ifr.ifr_functional_type;

exit:
    if (info_socket != -1)
    {
        close(info_socket);
    }
    return type;
}

// MARK: - UDP & TCP send & receive


// Set traffic class for socket
mDNSlocal void setTrafficClass(int socketfd, mDNSBool useBackgroundTrafficClass)
{
    int traffic_class;

    if (useBackgroundTrafficClass)
        traffic_class = SO_TC_BK_SYS;
    else
        traffic_class = SO_TC_CTL;

    (void) setsockopt(socketfd, SOL_SOCKET, SO_TRAFFIC_CLASS, (void *)&traffic_class, sizeof(traffic_class));
}

#ifdef UNIT_TEST
UNITTEST_SETSOCKOPT
#else
mDNSlocal int mDNSPlatformGetSocktFd(void *sockCxt, mDNSTransport_Type transType, mDNSAddr_Type addrType)
{
    if (transType == mDNSTransport_UDP)
    {
        UDPSocket* sock = (UDPSocket*) sockCxt;
        return (addrType == mDNSAddrType_IPv4) ? sock->ss.sktv4 : sock->ss.sktv6;
    }
    else if (transType == mDNSTransport_TCP)
    {
        TCPSocket* sock = (TCPSocket*) sockCxt;
        return sock->fd;
    }
    else
    {
        LogInfo("mDNSPlatformGetSocktFd: invalid transport %d", transType);
        return kInvalidSocketRef;
    }
}

mDNSexport void mDNSPlatformSetSocktOpt(void *sockCxt, mDNSTransport_Type transType, mDNSAddr_Type addrType, const DNSQuestion *q)
{
    int sockfd;
    char unenc_name[MAX_ESCAPED_DOMAIN_NAME];

    // verify passed-in arguments exist and that sockfd is valid
    if (q == mDNSNULL || sockCxt == mDNSNULL || (sockfd = mDNSPlatformGetSocktFd(sockCxt, transType, addrType)) < 0)
        return;

    if (q->pid)
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_DELEGATED, &q->pid, sizeof(q->pid)) == -1)
            LogMsg("mDNSPlatformSetSocktOpt: Delegate PID failed %s for PID %d", strerror(errno), q->pid);
    }
    else
    {
        if (setsockopt(sockfd, SOL_SOCKET, SO_DELEGATED_UUID, &q->uuid, sizeof(q->uuid)) == -1)
            LogMsg("mDNSPlatformSetSocktOpt: Delegate UUID failed %s", strerror(errno));
    }

    // set the domain on the socket
    ConvertDomainNameToCString(&q->qname, unenc_name);
    if (!(ne_session_set_socket_attributes(sockfd, unenc_name, NULL)))
        LogInfo("mDNSPlatformSetSocktOpt: ne_session_set_socket_attributes()-> setting domain failed for %s", unenc_name);

    int nowake = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_NOWAKEFROMSLEEP, &nowake, sizeof(nowake)) == -1)
        LogInfo("mDNSPlatformSetSocktOpt: SO_NOWAKEFROMSLEEP failed %s", strerror(errno));
}
#endif // UNIT_TEST

// Note: If InterfaceID is NULL, it means, "send this packet through our anonymous unicast socket"
// Note: If InterfaceID is non-NULL it means, "send this packet through our port 5353 socket on the specified interface"
// OR send via our primary v4 unicast socket
// UPDATE: The UDPSocket *src parameter now allows the caller to specify the source socket
mDNSexport mStatus mDNSPlatformSendUDP(const mDNS *const m, const void *const msg, const mDNSu8 *const end,
                                       mDNSInterfaceID InterfaceID, UDPSocket *src, const mDNSAddr *dst,
                                       mDNSIPPort dstPort, mDNSBool useBackgroundTrafficClass)
{
    NetworkInterfaceInfoOSX *info = mDNSNULL;
    struct sockaddr_storage to;
    int s = -1;
    mStatus result = mStatus_NoError;
    ssize_t sentlen;
    int sendto_errno;
    const DNSMessage *const dns_msg = msg;

    if (InterfaceID)
    {
        info = IfindexToInterfaceInfoOSX(InterfaceID);
        if (info == NULL)
        {
            // We may not have registered interfaces with the "core" as we may not have
            // seen any interface notifications yet. This typically happens during wakeup
            // where we might try to send DNS requests (non-SuppressUnusable questions internal
            // to mDNSResponder) before we receive network notifications.
            LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformSendUDP: Invalid interface index %p", InterfaceID);
            return mStatus_BadParamErr;
        }
    }

    char *ifa_name = InterfaceID ? info->ifinfo.ifname : "unicast";

    if (dst->type == mDNSAddrType_IPv4)
    {
        struct sockaddr_in *sin_to = (struct sockaddr_in*)&to;
        sin_to->sin_len            = sizeof(*sin_to);
        sin_to->sin_family         = AF_INET;
        sin_to->sin_port           = dstPort.NotAnInteger;
        sin_to->sin_addr.s_addr    = dst->ip.v4.NotAnInteger;
        s = (src ? src->ss : m->p->permanentsockets).sktv4;

        if (!mDNSAddrIsDNSMulticast(dst))
        {
        #ifdef IP_BOUND_IF
            const mDNSu32 ifindex = info ? info->scope_id : IFSCOPE_NONE;
            setsockopt(s, IPPROTO_IP, IP_BOUND_IF, &ifindex, sizeof(ifindex));
        #else
            static int displayed = 0;
            if (displayed < 1000)
            {
                displayed++;
                LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "[Q%u] IP_BOUND_IF socket option not defined -- cannot specify interface for unicast packets",
                    mDNSVal16(dns_msg->h.id));
            }
        #endif
        }
        else if (info)
        {
            int err;
        #ifdef IP_MULTICAST_IFINDEX
            err = setsockopt(s, IPPROTO_IP, IP_MULTICAST_IFINDEX, &info->scope_id, sizeof(info->scope_id));
            // We get an error when we compile on a machine that supports this option and run the binary on
            // a different machine that does not support it
            if (err < 0)
            {
                if (errno != ENOPROTOOPT)
                {
                    LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_ERROR, "[Q%u] mDNSPlatformSendUDP: setsockopt: IP_MUTLTICAST_IFINDEX returned %d (" PUB_S ")",
                        mDNSVal16(dns_msg->h.id), errno, strerror(errno));
                }
                err = setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &info->ifa_v4addr, sizeof(info->ifa_v4addr));
                if (err < 0 && !m->NetworkChanged)
                {
                    LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_ERROR, "[Q%u] setsockopt - IP_MULTICAST_IF error " PRI_IPv4_ADDR " %d errno %d (" PUB_S ")",
                        mDNSVal16(dns_msg->h.id), &info->ifa_v4addr, err, errno, strerror(errno));
                }
            }
        #else
            err = setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF, &info->ifa_v4addr, sizeof(info->ifa_v4addr));
            if (err < 0 && !m->NetworkChanged)
            {
                LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_ERROR, "[Q%u] setsockopt - IP_MULTICAST_IF error " PRI_IPv4_ADDR " %d errno %d (" PUB_S ")",
                    mDNSVal16(dns_msg->h.id), &info->ifa_v4addr, err, errno, strerror(errno));
            }
        #endif
        }
    }
    else if (dst->type == mDNSAddrType_IPv6)
    {
        struct sockaddr_in6 *sin6_to = (struct sockaddr_in6*)&to;
        sin6_to->sin6_len            = sizeof(*sin6_to);
        sin6_to->sin6_family         = AF_INET6;
        sin6_to->sin6_port           = dstPort.NotAnInteger;
        sin6_to->sin6_flowinfo       = 0;
        memcpy(sin6_to->sin6_addr.s6_addr, dst->ip.v6.b, sizeof(sin6_to->sin6_addr.s6_addr));
        sin6_to->sin6_scope_id       = info ? info->scope_id : 0;
        s = (src ? src->ss : m->p->permanentsockets).sktv6;
        if (info && mDNSAddrIsDNSMulticast(dst))    // Specify outgoing interface
        {
            const int err = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_IF, &info->scope_id, sizeof(info->scope_id));
            if (err < 0)
            {
                const int setsockopt_errno = errno;
                char name[IFNAMSIZ];
                if (if_indextoname(info->scope_id, name) != NULL)
                {
                    LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_ERROR, "[Q%u] setsockopt - IPV6_MULTICAST_IF error %d errno %d (" PUB_S ")",
                        mDNSVal16(dns_msg->h.id), err, setsockopt_errno, strerror(setsockopt_errno));
                }
                else
                {
                    LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_ERROR, "[Q%u] setsockopt - IPV6_MUTLICAST_IF scopeid %d, not a valid interface",
                        mDNSVal16(dns_msg->h.id), info->scope_id);
                }
            }
        }
#ifdef IPV6_BOUND_IF
        if (info)   // Specify outgoing interface for non-multicast destination
        {
            if (!mDNSAddrIsDNSMulticast(dst))
            {
                if (info->scope_id == 0)
                {
                    LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "[Q%u] IPV6_BOUND_IF socket option not set -- info %p (" PUB_S ") scope_id is zero",
                        mDNSVal16(dns_msg->h.id), info, ifa_name);
                }
                else
                {
                    setsockopt(s, IPPROTO_IPV6, IPV6_BOUND_IF, &info->scope_id, sizeof(info->scope_id));
                }
            }
        }
#endif
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_FAULT, "[Q%u] mDNSPlatformSendUDP: dst is not an IPv4 or IPv6 address!", mDNSVal16(dns_msg->h.id));
        return mStatus_BadParamErr;
    }

    if (s >= 0)
    {
        verbosedebugf("mDNSPlatformSendUDP: sending on InterfaceID %p %5s/%ld to %#a:%d skt %d",
                      InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort), s);
    }
    else
    {
        verbosedebugf("mDNSPlatformSendUDP: NOT sending on InterfaceID %p %5s/%ld (socket of this type not available)",
                      InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort));
    }

    // Note: When sending, mDNSCore may often ask us to send both a v4 multicast packet and then a v6 multicast packet
    // If we don't have the corresponding type of socket available, then return mStatus_Invalid
    if (s < 0) return(mStatus_Invalid);

    // switch to background traffic class for this message if requested
    if (useBackgroundTrafficClass)
        setTrafficClass(s, useBackgroundTrafficClass);

    sentlen = sendto(s, msg, end - (const UInt8*)msg, 0, (struct sockaddr *)&to, to.ss_len);
    sendto_errno = (sentlen < 0) ? errno : 0;

    // set traffic class back to default value
    if (useBackgroundTrafficClass)
        setTrafficClass(s, mDNSfalse);

    if (sentlen < 0)
    {
        static int MessageCount = 0;
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_ERROR, "[Q%u] mDNSPlatformSendUDP -> sendto(%d) failed to send packet on InterfaceID %p "
            PUB_S "/%d to " PRI_IP_ADDR ":%d skt %d error %ld errno %d (" PUB_S ") %u",
            mDNSVal16(dns_msg->h.id), s, InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort), s, (long)sentlen,
            sendto_errno, strerror(sendto_errno), (mDNSu32)(m->timenow));
        if (!mDNSAddressIsAllDNSLinkGroup(dst))
        {
            if ((sendto_errno == EHOSTUNREACH) || (sendto_errno == ENETUNREACH)) return(mStatus_HostUnreachErr);
            if ((sendto_errno == EHOSTDOWN)    || (sendto_errno == ENETDOWN))    return(mStatus_TransientErr);
        }
        // Don't report EHOSTUNREACH in the first three minutes after boot
        // This is because mDNSResponder intentionally starts up early in the boot process (See <rdar://problem/3409090>)
        // but this means that sometimes it starts before configd has finished setting up the multicast routing entries.
        if (sendto_errno == EHOSTUNREACH && (mDNSu32)(mDNSPlatformRawTime()) < (mDNSu32)(mDNSPlatformOneSecond * 180)) return(mStatus_TransientErr);
        // Don't report EADDRNOTAVAIL ("Can't assign requested address") if we're in the middle of a network configuration change
        if (sendto_errno == EADDRNOTAVAIL && m->NetworkChanged) return(mStatus_TransientErr);
        if (sendto_errno == EHOSTUNREACH || sendto_errno == EADDRNOTAVAIL || sendto_errno == ENETDOWN)
        {
            LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_ERROR, "[Q%u] mDNSPlatformSendUDP sendto(%d) failed to send packet on InterfaceID %p "
                PUB_S "/%d to " PRI_IP_ADDR ":%d skt %d error %ld errno %d (" PUB_S ") %u",
                mDNSVal16(dns_msg->h.id), s, InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort), s,
                (long)sentlen, sendto_errno, strerror(sendto_errno), (mDNSu32)(m->timenow));
        }
        else
        {
            MessageCount++;
            if (MessageCount < 50) // Cap and ensure NO spamming of LogMsgs
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                    "[Q%u] mDNSPlatformSendUDP: sendto(%d) failed to send packet on InterfaceID %p " PUB_S "/%d to " PRI_IP_ADDR ":%d skt %d error %ld errno %d (" PUB_S ") %u MessageCount is %d",
                    mDNSVal16(dns_msg->h.id), s, InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort), s, (long)sentlen, sendto_errno, strerror(sendto_errno), (mDNSu32)(m->timenow), MessageCount);
            }
            else // If logging is enabled, remove the cap and log aggressively
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                    "[Q%u] mDNSPlatformSendUDP: sendto(%d) failed to send packet on InterfaceID %p " PUB_S "/%d to " PRI_IP_ADDR ":%d skt %d error %ld errno %d (" PUB_S ") %u MessageCount is %d",
                    mDNSVal16(dns_msg->h.id), s, InterfaceID, ifa_name, dst->type, dst, mDNSVal16(dstPort), s, (long)sentlen, sendto_errno, strerror(sendto_errno), (mDNSu32)(m->timenow), MessageCount);
            }
        }

        result = mStatus_UnknownErr;
    }

    return(result);
}

mDNSlocal ssize_t myrecvfrom(const int s, void *const buffer, const size_t max,
                             struct sockaddr *const from, socklen_t *const fromlen, mDNSAddr *dstaddr, char ifname[IF_NAMESIZE], mDNSu8 *ttl)
{
    static unsigned int numLogMessages = 0;
    struct iovec databuffers = { (char *)buffer, max };
    struct msghdr msg;
    ssize_t n;
    struct cmsghdr *cmPtr;
    char ancillary[1024];

    *ttl = 255;  // If kernel fails to provide TTL data (e.g. Jaguar doesn't) then assume the TTL was 255 as it should be

    // Set up the message
    msg.msg_name       = (caddr_t)from;
    msg.msg_namelen    = *fromlen;
    msg.msg_iov        = &databuffers;
    msg.msg_iovlen     = 1;
    msg.msg_control    = (caddr_t)&ancillary;
    msg.msg_controllen = sizeof(ancillary);
    msg.msg_flags      = 0;

    // Receive the data
    n = recvmsg(s, &msg, 0);
    if (n<0)
    {
        if (errno != EWOULDBLOCK && numLogMessages++ < 100) LogMsg("mDNSMacOSX.c: recvmsg(%d) returned error %d errno %d", s, n, errno);
        return(-1);
    }
    if (msg.msg_controllen < (int)sizeof(struct cmsghdr))
    {
        if (numLogMessages++ < 100) LogMsg("mDNSMacOSX.c: recvmsg(%d) returned %d msg.msg_controllen %d < sizeof(struct cmsghdr) %lu, errno %d",
                                           s, n, msg.msg_controllen, sizeof(struct cmsghdr), errno);
        return(-1);
    }
    // Note: MSG_TRUNC means the datagram was truncated, while MSG_CTRUNC means that the control data was truncated.
    // The mDNS core is capable of handling truncated DNS messages, so MSG_TRUNC isn't checked.
    if (msg.msg_flags & MSG_CTRUNC)
    {
        if (numLogMessages++ < 100) LogMsg("mDNSMacOSX.c: recvmsg(%d) msg.msg_flags & MSG_CTRUNC", s);
        return(-1);
    }

    *fromlen = msg.msg_namelen;

    // Parse each option out of the ancillary data.
    for (cmPtr = CMSG_FIRSTHDR(&msg); cmPtr; cmPtr = CMSG_NXTHDR(&msg, cmPtr))
    {
        // debugf("myrecvfrom cmsg_level %d cmsg_type %d", cmPtr->cmsg_level, cmPtr->cmsg_type);
        if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVDSTADDR)
        {
            dstaddr->type = mDNSAddrType_IPv4;
            dstaddr->ip.v4 = *(mDNSv4Addr*)CMSG_DATA(cmPtr);
            //LogMsg("mDNSMacOSX.c: recvmsg IP_RECVDSTADDR %.4a", &dstaddr->ip.v4);
        }
        if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVIF)
        {
            struct sockaddr_dl *sdl = (struct sockaddr_dl *)CMSG_DATA(cmPtr);
            if (sdl->sdl_nlen < IF_NAMESIZE)
            {
                mDNSPlatformMemCopy(ifname, sdl->sdl_data, sdl->sdl_nlen);
                ifname[sdl->sdl_nlen] = 0;
                // debugf("IP_RECVIF sdl_index %d, sdl_data %s len %d", sdl->sdl_index, ifname, sdl->sdl_nlen);
            }
        }
        if (cmPtr->cmsg_level == IPPROTO_IP && cmPtr->cmsg_type == IP_RECVTTL)
            *ttl = *(u_char*)CMSG_DATA(cmPtr);
        if (cmPtr->cmsg_level == IPPROTO_IPV6 && cmPtr->cmsg_type == IPV6_PKTINFO)
        {
            struct in6_pktinfo *ip6_info = (struct in6_pktinfo*)CMSG_DATA(cmPtr);
            dstaddr->type = mDNSAddrType_IPv6;
            dstaddr->ip.v6 = *(mDNSv6Addr*)&ip6_info->ipi6_addr;
            myIfIndexToName(ip6_info->ipi6_ifindex, ifname);
        }
        if (cmPtr->cmsg_level == IPPROTO_IPV6 && cmPtr->cmsg_type == IPV6_HOPLIMIT)
            *ttl = *(int*)CMSG_DATA(cmPtr);
    }

    return(n);
}

// What is this for, and why does it use xor instead of a simple equality check? -- SC
mDNSlocal mDNSInterfaceID FindMyInterface(const mDNSAddr *addr)
{
    NetworkInterfaceInfo *intf;

    if (addr->type == mDNSAddrType_IPv4)
    {
        for (intf = mDNSStorage.HostInterfaces; intf; intf = intf->next)
        {
            if (intf->ip.type == addr->type && intf->McastTxRx)
            {
                if ((intf->ip.ip.v4.NotAnInteger ^ addr->ip.v4.NotAnInteger) == 0)
                {
                    return(intf->InterfaceID);
                }
            }
        }
    }

    if (addr->type == mDNSAddrType_IPv6)
    {
        for (intf = mDNSStorage.HostInterfaces; intf; intf = intf->next)
        {
            if (intf->ip.type == addr->type && intf->McastTxRx)
            {
                if (((intf->ip.ip.v6.l[0] ^ addr->ip.v6.l[0]) == 0) &&
                    ((intf->ip.ip.v6.l[1] ^ addr->ip.v6.l[1]) == 0) &&
                    ((intf->ip.ip.v6.l[2] ^ addr->ip.v6.l[2]) == 0) &&
                    (((intf->ip.ip.v6.l[3] ^ addr->ip.v6.l[3]) == 0)))
                    {
                        return(intf->InterfaceID);
                    }
            }
        }
    }
    return(mDNSInterface_Any);
}

mDNSexport void myKQSocketCallBack(int s1, short filter, void *context, mDNSBool encounteredEOF)
{
    KQSocketSet *const ss = (KQSocketSet *)context;
    mDNS *const m = ss->m;
    ssize_t recvlen = -1;
    int count = 0, closed = 0, recvfrom_errno = 0;

    if (filter != EVFILT_READ)
        LogMsg("myKQSocketCallBack: Why is filter %d not EVFILT_READ (%d)?", filter, EVFILT_READ);

    if (s1 != ss->sktv4 && s1 != ss->sktv6)
    {
        LogMsg("myKQSocketCallBack: native socket %d", s1);
        LogMsg("myKQSocketCallBack: sktv4 %d sktv6 %d", ss->sktv4, ss->sktv6);
    }

    if (encounteredEOF)
    {
        LogMsg("myKQSocketCallBack: socket %d is no longer readable (EOF)", s1);
        if (s1 == ss->sktv4)
        {
            ss->sktv4EOF = mDNStrue;
            KQueueSet(ss->sktv4, EV_DELETE, EVFILT_READ, &ss->kqsv4);
        }
        else if (s1 == ss->sktv6)
        {
            ss->sktv6EOF = mDNStrue;
            KQueueSet(ss->sktv6, EV_DELETE, EVFILT_READ, &ss->kqsv6);
        }
        return;
    }

    while (!closed)
    {
        mDNSAddr senderAddr, destAddr = zeroAddr;
        mDNSIPPort senderPort;
        struct sockaddr_storage from;
        socklen_t fromlen = sizeof(from);
        char packetifname[IF_NAMESIZE] = "";
        mDNSu8 ttl;
        recvlen = myrecvfrom(s1, &m->imsg, sizeof(m->imsg), (struct sockaddr *)&from, &fromlen, &destAddr, packetifname, &ttl);
        if (recvlen < 0)
        {
            recvfrom_errno = errno;
            break;
        }

        if ((destAddr.type == mDNSAddrType_IPv4 && (destAddr.ip.v4.b[0] & 0xF0) == 0xE0) ||
            (destAddr.type == mDNSAddrType_IPv6 && (destAddr.ip.v6.b[0]         == 0xFF))) m->p->num_mcasts++;

        count++;
        if (from.ss_family == AF_INET)
        {
            struct sockaddr_in *s = (struct sockaddr_in*)&from;
            senderAddr.type = mDNSAddrType_IPv4;
            senderAddr.ip.v4.NotAnInteger = s->sin_addr.s_addr;
            senderPort.NotAnInteger = s->sin_port;
            //LogInfo("myKQSocketCallBack received IPv4 packet from %#-15a to %#-15a on skt %d %s", &senderAddr, &destAddr, s1, packetifname);
        }
        else if (from.ss_family == AF_INET6)
        {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6*)&from;
            senderAddr.type = mDNSAddrType_IPv6;
            senderAddr.ip.v6 = *(mDNSv6Addr*)&sin6->sin6_addr;
            senderPort.NotAnInteger = sin6->sin6_port;
            //LogInfo("myKQSocketCallBack received IPv6 packet from %#-15a to %#-15a on skt %d %s", &senderAddr, &destAddr, s1, packetifname);
        }
        else
        {
            LogMsg("myKQSocketCallBack from is unknown address family %d", from.ss_family);
            return;
        }

        // Note: When handling multiple packets in a batch, MUST reset InterfaceID before handling each packet
        mDNSInterfaceID InterfaceID = mDNSNULL;
        NetworkInterfaceInfoOSX *intf = m->p->InterfaceList;
        while (intf)
        {
            if (intf->Exists && !strcmp(intf->ifinfo.ifname, packetifname))
                break;
            intf = intf->next;
        }

        // When going to sleep we deregister all our interfaces, but if the machine
        // takes a few seconds to sleep we may continue to receive multicasts
        // during that time, which would confuse mDNSCoreReceive, because as far
        // as it's concerned, we should have no active interfaces any more.
        // Hence we ignore multicasts for which we can find no matching InterfaceID.
        if (intf)
            InterfaceID = intf->ifinfo.InterfaceID;
        else if (mDNSAddrIsDNSMulticast(&destAddr))
            continue;

        if (!InterfaceID)
        {
            InterfaceID = FindMyInterface(&destAddr);
        }

//      LogMsg("myKQSocketCallBack got packet from %#a to %#a on interface %#a/%s",
//          &senderAddr, &destAddr, &ss->info->ifinfo.ip, ss->info->ifinfo.ifname);

        // mDNSCoreReceive may close the socket we're reading from.  We must break out of our
        // loop when that happens, or we may try to read from an invalid FD.  We do this by
        // setting the closeFlag pointer in the socketset, so CloseSocketSet can inform us
        // if it closes the socketset.
        ss->closeFlag = &closed;

        if (ss->proxy)
        {
            m->p->UDPProxyCallback(&m->p->UDPProxy, &m->imsg.m, (unsigned char*)&m->imsg + recvlen, &senderAddr,
                senderPort, &destAddr, ss->port, InterfaceID, NULL);
        }
        else
        {
            mDNSCoreReceive(m, &m->imsg.m, (unsigned char*)&m->imsg + recvlen, &senderAddr, senderPort, &destAddr, ss->port, InterfaceID);
        }

        // if we didn't close, we can safely dereference the socketset, and should to
        // reset the closeFlag, since it points to something on the stack
        if (!closed) ss->closeFlag = mDNSNULL;
    }

    // If a client application's sockets are marked as defunct
    // sockets we have delegated to it with SO_DELEGATED will also go defunct.
    // We get an ENOTCONN error for defunct sockets and should just close the socket in that case.
    if (recvlen < 0 && recvfrom_errno == ENOTCONN)
    {
        LogInfo("myKQSocketCallBack: ENOTCONN, closing socket");
        close(s1);
        return;
    }

    if (recvlen < 0 && (recvfrom_errno != EWOULDBLOCK || count == 0))
    {
        // Something is busted here.
        // kqueue says there is a packet, but myrecvfrom says there is not.
        // Try calling select() to get another opinion.
        // Find out about other socket parameter that can help understand why select() says the socket is ready for read
        // All of this is racy, as data may have arrived after the call to select()
        static unsigned int numLogMessages = 0;
        int so_error = -1;
        int so_nread = -1;
        int fionread = -1;
        socklen_t solen;
        fd_set readfds;
        struct timeval timeout;
        int selectresult;
        FD_ZERO(&readfds);
        FD_SET(s1, &readfds);
        timeout.tv_sec  = 0;
        timeout.tv_usec = 0;
        selectresult = select(s1+1, &readfds, NULL, NULL, &timeout);
        solen = (socklen_t)sizeof(so_error);
        if (getsockopt(s1, SOL_SOCKET, SO_ERROR, &so_error, &solen) == -1)
            LogMsg("myKQSocketCallBack getsockopt(SO_ERROR) error %d", errno);
        solen = (socklen_t)sizeof(so_nread);
        if (getsockopt(s1, SOL_SOCKET, SO_NREAD, &so_nread, &solen) == -1)
            LogMsg("myKQSocketCallBack getsockopt(SO_NREAD) error %d", errno);
        if (ioctl(s1, FIONREAD, &fionread) == -1)
            LogMsg("myKQSocketCallBack ioctl(FIONREAD) error %d", errno);
        if (numLogMessages++ < 100)
            LogMsg("myKQSocketCallBack recvfrom skt %d error %d errno %d (%s) select %d (%spackets waiting) so_error %d so_nread %d fionread %d count %d",
                   s1, (int)recvlen, recvfrom_errno, strerror(recvfrom_errno), selectresult, FD_ISSET(s1, &readfds) ? "" : "*NO* ", so_error, so_nread, fionread, count);
        if (numLogMessages > 5)
            NotifyOfElusiveBug("Flaw in Kernel (select/recvfrom mismatch)",
                               "Congratulations, you've reproduced an elusive bug.\r"
                               "Please send email to radar-3387020@group.apple.com.)\r"
                               "If possible, please leave your machine undisturbed so that someone can come to investigate the problem.");

        sleep(1);       // After logging this error, rate limit so we don't flood syslog
    }
}

mDNSlocal void doTcpSocketCallback(TCPSocket *sock)
{
    mDNSBool c = !sock->connected;
    if (!sock->connected && sock->err == mStatus_NoError)
    {
        sock->connected = mDNStrue;
    }
    sock->callback(sock, sock->context, c, sock->err);
    // Note: the callback may call CloseConnection here, which frees the context structure!
}

#ifndef NO_SECURITYFRAMEWORK

mDNSlocal OSStatus tlsWriteSock(SSLConnectionRef connection, const void *data, size_t *dataLength)
{
    const ssize_t ret = send(((const TCPSocket *)connection)->fd, data, *dataLength, 0);
    if (ret >= 0 && (size_t)ret < *dataLength) { *dataLength = (size_t)ret; return(errSSLWouldBlock); }
    if (ret >= 0)                              { *dataLength = (size_t)ret; return(noErr); }
    *dataLength = 0;
    if (errno == EAGAIN                      ) return(errSSLWouldBlock);
    if (errno == ENOENT                      ) return(errSSLClosedGraceful);
    if (errno == EPIPE || errno == ECONNRESET) return(errSSLClosedAbort);
    LogMsg("ERROR: tlsWriteSock: %d error %d (%s)\n", ((const TCPSocket *)connection)->fd, errno, strerror(errno));
    return(errSSLClosedAbort);
}

mDNSlocal OSStatus tlsReadSock(SSLConnectionRef connection, void *data, size_t *dataLength)
{
    const ssize_t ret = recv(((const TCPSocket *)connection)->fd, data, *dataLength, 0);
    if (ret > 0 && (size_t)ret < *dataLength) { *dataLength = (size_t)ret; return(errSSLWouldBlock); }
    if (ret > 0)                              { *dataLength = (size_t)ret; return(noErr); }
    *dataLength = 0;
    if (ret == 0 || errno == ENOENT    ) return(errSSLClosedGraceful);
    if (            errno == EAGAIN    ) return(errSSLWouldBlock);
    if (            errno == ECONNRESET) return(errSSLClosedAbort);
    LogMsg("ERROR: tlsSockRead: error %d (%s)\n", errno, strerror(errno));
    return(errSSLClosedAbort);
}

mDNSlocal OSStatus tlsSetupSock(TCPSocket *sock, SSLProtocolSide pside, SSLConnectionType ctype)
{
    char domname_cstr[MAX_ESCAPED_DOMAIN_NAME];

    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    sock->tlsContext = SSLCreateContext(kCFAllocatorDefault, pside, ctype);
    mdns_clang_ignore_warning_end();
    if (!sock->tlsContext)
    {
        LogMsg("ERROR: tlsSetupSock: SSLCreateContext failed");
        return(mStatus_UnknownErr);
    }

    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    mStatus err = SSLSetIOFuncs(sock->tlsContext, tlsReadSock, tlsWriteSock);
    mdns_clang_ignore_warning_end();
    if (err)
    {
        LogMsg("ERROR: tlsSetupSock: SSLSetIOFuncs failed with error code: %d", err);
        goto fail;
    }

    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    err = SSLSetConnection(sock->tlsContext, (SSLConnectionRef) sock);
    mdns_clang_ignore_warning_end();
    if (err)
    {
        LogMsg("ERROR: tlsSetupSock: SSLSetConnection failed with error code: %d", err);
        goto fail;
    }

    // Set the default ciphersuite configuration
    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    err = SSLSetSessionConfig(sock->tlsContext, CFSTR("default"));
    mdns_clang_ignore_warning_end();
    if (err)
    {
        LogMsg("ERROR: tlsSetupSock: SSLSetSessionConfig failed with error code: %d", err);
        goto fail;
    }

    // We already checked for NULL in hostname and this should never happen. Hence, returning -1
    // (error not in OSStatus space) is okay.
    if (!sock->hostname || !sock->hostname->c[0])
    {
        LogMsg("ERROR: tlsSetupSock: hostname NULL");
        err = -1;
        goto fail;
    }

    ConvertDomainNameToCString(sock->hostname, domname_cstr);
    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    err = SSLSetPeerDomainName(sock->tlsContext, domname_cstr, strlen(domname_cstr));
    mdns_clang_ignore_warning_end();
    if (err)
    {
        LogMsg("ERROR: tlsSetupSock: SSLSetPeerDomainname: %s failed with error code: %d", domname_cstr, err);
        goto fail;
    }
    return(err);

fail:
    MDNS_DISPOSE_CF_OBJECT(sock->tlsContext);
    return(err);
}

#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
mDNSlocal void doSSLHandshake(TCPSocket *sock)
{
    mStatus err = SSLHandshake(sock->tlsContext);

    //Can't have multiple threads in mDNS core. When MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM is
    //defined, KQueueLock is a noop. Hence we need to serialize here
    //
    //NOTE: We just can't serialize doTcpSocketCallback alone on the main queue.
    //We need the rest of the logic also. Otherwise, we can enable the READ
    //events below, dispatch a doTcpSocketCallback on the main queue. Assume it is
    //ConnFailed which means we are going to free the tcpInfo. While it
    //is waiting to be dispatched, another read event can come into tcpKQSocketCallback
    //and potentially call doTCPCallback with error which can close the fd and free the
    //tcpInfo. Later when the thread gets dispatched it will crash because the tcpInfo
    //is already freed.

    dispatch_async(dispatch_get_main_queue(), ^{

                       LogInfo("doSSLHandshake %p: got lock", sock); // Log *after* we get the lock

                       if (sock->handshake == handshake_to_be_closed)
                       {
                           LogInfo("SSLHandshake completed after close");
                           mDNSPlatformTCPCloseConnection(sock);
                       }
                       else
                       {
                           if (sock->fd != -1) KQueueSet(sock->fd, EV_ADD, EVFILT_READ, sock->kqEntry);
                           else LogMsg("doSSLHandshake: sock->fd is -1");

                           if (err == errSSLWouldBlock)
                               sock->handshake = handshake_required;
                           else
                           {
                               if (err)
                               {
                                   LogMsg("SSLHandshake failed: %d%s", err, err == errSSLPeerInternalError ? " (server busy)" : "");
                                   MDNS_DISPOSE_CF_OBJECT(sock->tlsContext);
                               }

                               sock->err = err ? mStatus_ConnFailed : 0;
                               sock->handshake = handshake_completed;

                               LogInfo("doSSLHandshake: %p calling doTcpSocketCallback fd %d", sock, sock->fd);
                               doTcpSocketCallback(sock);
                           }
                       }

                       LogInfo("SSLHandshake %p: dropping lock for fd %d", sock, sock->fd);
                       return;
                   });
}
#else // MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
mDNSlocal void *doSSLHandshake(TCPSocket *sock)
{
    // Warning: Touching sock without the kqueue lock!
    // We're protected because sock->handshake == handshake_in_progress
    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    mStatus err = SSLHandshake(sock->tlsContext);
    mdns_clang_ignore_warning_end();

    KQueueLock();
    debugf("doSSLHandshake %p: got lock", sock); // Log *after* we get the lock

    if (sock->handshake == handshake_to_be_closed)
    {
        LogInfo("SSLHandshake completed after close");
        mDNSPlatformTCPCloseConnection(sock);
    }
    else
    {
        if (sock->fd != -1) KQueueSet(sock->fd, EV_ADD, EVFILT_READ, &sock->kqEntry);
        else LogMsg("doSSLHandshake: sock->fd is -1");

        if (err == errSSLWouldBlock)
            sock->handshake = handshake_required;
        else
        {
            if (err)
            {
                LogMsg("SSLHandshake failed: %d%s", err, err == errSSLPeerInternalError ? " (server busy)" : "");
                MDNS_DISPOSE_CF_OBJECT(sock->tlsContext);
            }

            sock->err = err ? mStatus_ConnFailed : 0;
            sock->handshake = handshake_completed;

            debugf("doSSLHandshake: %p calling doTcpSocketCallback fd %d", sock, sock->fd);
            doTcpSocketCallback(sock);
        }
    }

    debugf("SSLHandshake %p: dropping lock for fd %d", sock, sock->fd);
    KQueueUnlock("doSSLHandshake");
    return NULL;
}
#endif // MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM

mDNSlocal void spawnSSLHandshake(TCPSocket* sock)
{
    debugf("spawnSSLHandshake %p: entry", sock);

    if (sock->handshake != handshake_required) LogMsg("spawnSSLHandshake: handshake status not required: %d", sock->handshake);
    sock->handshake = handshake_in_progress;
    KQueueSet(sock->fd, EV_DELETE, EVFILT_READ, &sock->kqEntry);

    // Dispatch it on a separate queue to help avoid blocking other threads/queues, and
    // to limit the number of threads used for SSLHandshake
    dispatch_async(SSLqueue, ^{doSSLHandshake(sock);});

    debugf("spawnSSLHandshake %p: done for %d", sock, sock->fd);
}

#endif /* NO_SECURITYFRAMEWORK */

mDNSlocal void tcpKQSocketCallback(int fd, short filter, void *context, __unused mDNSBool encounteredEOF)
{
    TCPSocket *sock = context;
    sock->err = mStatus_NoError;

    //if (filter == EVFILT_READ ) LogMsg("myKQSocketCallBack: tcpKQSocketCallback %d is EVFILT_READ", filter);
    //if (filter == EVFILT_WRITE) LogMsg("myKQSocketCallBack: tcpKQSocketCallback %d is EVFILT_WRITE", filter);
    // EV_ONESHOT doesn't seem to work, so we add the filter with EV_ADD, and explicitly delete it here with EV_DELETE
    if (filter == EVFILT_WRITE)
    {
        // sock->connected gets set by doTcpSocketCallback(), which may be called from here, or may be called
        // from the TLS connect code.   If we asked for a writability test, we are connecting
        // (sock->connected == mDNSFalse).
        if (sock->connected)
        {
            LogInfo("ERROR: TCPConnectCallback called with write event when socket is connected.");
        }
        else
        {
            int result = 0;
            socklen_t len = (socklen_t)sizeof(result);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &result, &len) < 0)
            {
                LogInfo("ERROR: TCPConnectCallback - unable to get connect error: socket %d: Error %d (%s)",
                        sock->fd, errno, strerror(errno));
                sock->err = mStatus_ConnFailed;
            }
            else
            {
                if (result != 0)
                {
                    sock->err = mStatus_ConnFailed;
                    if (result == EHOSTUNREACH || result == EADDRNOTAVAIL || result == ENETDOWN)
                    {
                        LogInfo("ERROR: TCPConnectCallback - connect failed: socket %d: Error %d (%s)",
                                sock->fd, result, strerror(result));
                    }
                    else
                    {
                        LogMsg("ERROR: TCPConnectCallback - connect failed: socket %d: Error %d (%s)",
                               sock->fd, result, strerror(result));
                    }
                }
            }
        }
        KQueueSet(sock->fd, EV_DELETE, EVFILT_WRITE, &sock->kqEntry);

        // If we set the EVFILT_READ event in mDNSPlatformTCPConnect, it's possible to get a read event
        // before the write event--apparently the socket is both readable and writable once that happens,
        // even if the connect fails.   If we set it here, after we've gotten a successful connection, then
        // we shouldn't run into that problem.
        if (sock->err == mStatus_NoError &&
            KQueueSet(sock->fd, EV_ADD, EVFILT_READ, &sock->kqEntry))
        {
            // And of course if that fails, we can't use the connection even though we have it.
            LogMsg("ERROR: tcpKQSocketCallback - KQueueSet failed");
            sock->err = mStatus_TransientErr;
        }
    }

    if (sock->flags & kTCPSocketFlags_UseTLS)
    {
#ifndef NO_SECURITYFRAMEWORK
        // Don't try to set up TLS if the connect failed.
        if (sock->err == mStatus_NoError) {
            if (!sock->setup)
            {
                sock->setup = mDNStrue;

                mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
                sock->err = tlsSetupSock(sock, kSSLClientSide, kSSLStreamType);
                mdns_clang_ignore_warning_end();
                if (sock->err)
                {
                    LogMsg("ERROR: tcpKQSocketCallback: tlsSetupSock failed with error code: %d", sock->err);
                    return;
                }
            }
            if (sock->handshake == handshake_required)
            {
                spawnSSLHandshake(sock);
                return;
            }
            else if (sock->handshake == handshake_in_progress || sock->handshake == handshake_to_be_closed)
            {
                return;
            }
            else if (sock->handshake != handshake_completed)
            {
                if (!sock->err)
                    sock->err = mStatus_UnknownErr;
                LogMsg("tcpKQSocketCallback called with unexpected SSLHandshake status: %d", sock->handshake);
            }
        }
#else  /* NO_SECURITYFRAMEWORK */
        sock->err = mStatus_UnsupportedErr;
#endif /* NO_SECURITYFRAMEWORK */
    }

    doTcpSocketCallback(sock);
}

#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
mDNSexport int KQueueSet(int fd, u_short flags, short filter, KQueueEntry *const entryRef)
{
    dispatch_queue_t queue = dispatch_get_main_queue();
    dispatch_source_t source;
    if (flags == EV_DELETE)
    {
        if (filter == EVFILT_READ)
        {
            dispatch_source_cancel(entryRef->readSource);
            MDNS_DISPOSE_DISPATCH(entryRef->readSource);
            debugf("KQueueSet: source cancel for read %p, %p", entryRef->readSource, entryRef->writeSource);
        }
        else if (filter == EVFILT_WRITE)
        {
            dispatch_source_cancel(entryRef->writeSource);
            MDNS_DISPOSE_DISPATCH(entryRef->writeSource);
            debugf("KQueueSet: source cancel for write %p, %p", entryRef->readSource, entryRef->writeSource);
        }
        else
            LogMsg("KQueueSet: ERROR: Wrong filter value %d for EV_DELETE", filter);
        return 0;
    }
    if (flags != EV_ADD) LogMsg("KQueueSet: Invalid flags %d", flags);

    if (filter == EVFILT_READ)
    {
        source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, fd, 0, queue);
    }
    else if (filter == EVFILT_WRITE)
    {
        source = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, fd, 0, queue);
    }
    else
    {
        LogMsg("KQueueSet: ERROR: Wrong filter value %d for EV_ADD", filter);
        return -1;
    }
    if (!source) return -1;
    dispatch_source_set_event_handler(source, ^{

                                          mDNSs32 stime = mDNSPlatformRawTime();
                                          entryRef->KQcallback(fd, filter, entryRef->KQcontext);
                                          mDNSs32 etime = mDNSPlatformRawTime();
                                          if (etime - stime >= WatchDogReportingThreshold)
                                              LogInfo("KQEntryCallback Block: WARNING: took %dms to complete", etime - stime);

                                          // Trigger the event delivery to the application. Even though we trigger the
                                          // event completion after handling every event source, these all will hopefully
                                          // get merged
                                          TriggerEventCompletion();

                                      });
    dispatch_source_set_cancel_handler(source, ^{
                                           if (entryRef->fdClosed)
                                           {
                                               //LogMsg("CancelHandler: closing fd %d", fd);
                                               close(fd);
                                           }
                                       });
    dispatch_resume(source);
    if (filter == EVFILT_READ)
        entryRef->readSource = source;
    else
        entryRef->writeSource = source;

    return 0;
}

mDNSexport void KQueueLock()
{
}
mDNSexport void KQueueUnlock(const char const *task)
{
    (void)task; //unused
}
#else

mDNSexport int KQueueSet(int fd, u_short flags, short filter, KQueueEntry *const entryRef)
{
    struct kevent new_event;
    EV_SET(&new_event, fd, filter, flags, 0, 0, entryRef);
    return (kevent(KQueueFD, &new_event, 1, NULL, 0, NULL) < 0) ? errno : 0;
}

mDNSexport void KQueueLock(void)
{
    mDNS *const m = &mDNSStorage;
    pthread_mutex_lock(&m->p->BigMutex);
    m->p->BigMutexStartTime = mDNSPlatformRawTime();
}

mDNSexport void KQueueUnlock(const char* task)
{
    mDNS *const m = &mDNSStorage;
    mDNSs32 end = mDNSPlatformRawTime();
    if (end - m->p->BigMutexStartTime >= WatchDogReportingThreshold)
    {
        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_WARNING,
            "WARNING: " PUB_S " took %d ms to complete", task, end - m->p->BigMutexStartTime);
    }

    pthread_mutex_unlock(&m->p->BigMutex);

    char wake = 1;
    if (send(m->p->WakeKQueueLoopFD, &wake, sizeof(wake), 0) == -1)
        LogMsg("ERROR: KQueueWake: send failed with error code: %d (%s)", errno, strerror(errno));
}
#endif

mDNSexport void mDNSPlatformCloseFD(KQueueEntry *kq, int fd)
{
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
        (void) fd; //unused
    if (kq->readSource)
    {
        dispatch_source_cancel(kq->readSource);
        kq->readSource = mDNSNULL;
    }
    if (kq->writeSource)
    {
        dispatch_source_cancel(kq->writeSource);
        kq->writeSource = mDNSNULL;
    }
    // Close happens in the cancellation handler
    debugf("mDNSPlatformCloseFD: resetting sources for %d", fd);
    kq->fdClosed = mDNStrue;
#else
    (void)kq; //unused
    close(fd);
#endif
}

mDNSlocal mStatus SetupTCPSocket(TCPSocket *sock, mDNSAddr_Type addrtype, mDNSIPPort *port, mDNSBool useBackgroundTrafficClass)
{
    int skt;

    skt = -1;
    if (!mDNSPosixTCPSocketSetup(&skt, addrtype, port, &sock->port))
    {
        if (skt != -1) close(skt);
        return mStatus_UnknownErr;
    }

    // for TCP sockets, the traffic class is set once and not changed
    setTrafficClass(skt, useBackgroundTrafficClass);

    sock->fd = skt;
    sock->kqEntry.KQcallback = tcpKQSocketCallback;
    sock->kqEntry.KQcontext  = sock;
    sock->kqEntry.KQtask     = "mDNSPlatformTCPSocket";
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
    sock->kqEntry.readSource = mDNSNULL;
    sock->kqEntry.writeSource = mDNSNULL;
    sock->kqEntry.fdClosed = mDNSfalse;
#endif
    return mStatus_NoError;
}

mDNSexport TCPSocket *mDNSPlatformTCPSocket(TCPSocketFlags flags, mDNSAddr_Type addrtype, mDNSIPPort *port, domainname *hostname, mDNSBool useBackgroundTrafficClass)
{
    mStatus err;
    mDNSu32 lowWater = 16384;
    size_t len = sizeof (TCPSocket);
    if (hostname) {
        len += sizeof (domainname);
    }

    TCPSocket *sock = (TCPSocket *) callocL("TCPSocket/mDNSPlatformTCPSocket", len);
    if (!sock)
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformTCPSocket: memory allocation failure");
        return(mDNSNULL);
    }

    if (hostname)
    {
        sock->hostname = (domainname *)(sock + 1); // Allocated together so can be freed together
        debugf("mDNSPlatformTCPSocket: hostname %##s", hostname->c);
        AssignDomainName(sock->hostname, hostname);
    }

    err = SetupTCPSocket(sock, addrtype, port, useBackgroundTrafficClass);

    if (err)
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformTCPSocket: socket error %d errno %d (" PUB_S ")", sock->fd, errno, strerror(errno));
        freeL("TCPSocket/mDNSPlatformTCPSocket", sock);
        return(mDNSNULL);
    }

    if (setsockopt(sock->fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, &lowWater, sizeof lowWater) < 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformTCPSocket: TCP_NOTSENT_LOWAT returned %d", errno);
               mDNSPlatformTCPCloseConnection(sock);
        return mDNSNULL;
    }

    sock->callback          = mDNSNULL;
    sock->flags             = flags;
    sock->context           = mDNSNULL;
    sock->setup             = mDNSfalse;
    sock->connected         = mDNSfalse;
    sock->handshake         = handshake_required;
    sock->m                 =  &mDNSStorage;
    sock->err               = mStatus_NoError;

    return sock;
}

mDNSexport mStatus mDNSPlatformTCPConnect(TCPSocket *sock, const mDNSAddr *dst, mDNSOpaque16 dstport, mDNSInterfaceID InterfaceID, TCPConnectionCallback callback, void *context)
{
    mStatus err = mStatus_NoError;
    struct sockaddr_storage ss;

    sock->callback          = callback;
    sock->context           = context;
    sock->setup             = mDNSfalse;
    sock->connected         = mDNSfalse;
    sock->handshake         = handshake_required;
    sock->err               = mStatus_NoError;

    if (dst->type == mDNSAddrType_IPv4)
    {
        struct sockaddr_in *saddr = (struct sockaddr_in *)&ss;
        mDNSPlatformMemZero(saddr, sizeof(*saddr));
        saddr->sin_family      = AF_INET;
        saddr->sin_port        = dstport.NotAnInteger;
        saddr->sin_len         = sizeof(*saddr);
        saddr->sin_addr.s_addr = dst->ip.v4.NotAnInteger;
    }
    else
    {
        struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *)&ss;
        mDNSPlatformMemZero(saddr6, sizeof(*saddr6));
        saddr6->sin6_family      = AF_INET6;
        saddr6->sin6_port        = dstport.NotAnInteger;
        saddr6->sin6_len         = sizeof(*saddr6);
        saddr6->sin6_addr        = *(const struct in6_addr *)&dst->ip.v6;
    }

    // Watch for connect complete (write is ready)
    // EV_ONESHOT doesn't seem to work, so we add the filter with EV_ADD, and explicitly delete it in tcpKQSocketCallback using EV_DELETE
    if (KQueueSet(sock->fd, EV_ADD /* | EV_ONESHOT */, EVFILT_WRITE, &sock->kqEntry))
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "ERROR: mDNSPlatformTCPConnect - KQueueSet failed");
        return errno;
    }

    if (fcntl(sock->fd, F_SETFL, fcntl(sock->fd, F_GETFL, 0) | O_NONBLOCK) < 0) // set non-blocking
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "ERROR: setsockopt O_NONBLOCK - " PUB_S, strerror(errno));
        return mStatus_UnknownErr;
    }

    // We bind to the interface and all subsequent packets including the SYN will be sent out
    // on this interface
    //
    // Note: If we are in Active Directory domain, we may try TCP (if the response can't fit in
    // UDP).
    if (InterfaceID)
    {
        NetworkInterfaceInfoOSX *info = IfindexToInterfaceInfoOSX(InterfaceID);
        if (dst->type == mDNSAddrType_IPv4)
        {
        #ifdef IP_BOUND_IF
            if (info) setsockopt(sock->fd, IPPROTO_IP, IP_BOUND_IF, &info->scope_id, sizeof(info->scope_id));
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformTCPConnect: Invalid interface index %p", InterfaceID);
                return mStatus_BadParamErr;
            }
        #else
            (void)InterfaceID; // Unused
            (void)info; // Unused
        #endif
        }
        else
        {
        #ifdef IPV6_BOUND_IF
            if (info) setsockopt(sock->fd, IPPROTO_IPV6, IPV6_BOUND_IF, &info->scope_id, sizeof(info->scope_id));
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformTCPConnect: Invalid interface index %p", InterfaceID);
                return mStatus_BadParamErr;
            }
        #else
            (void)InterfaceID; // Unused
            (void)info; // Unused
        #endif
        }
    }

    // mDNSPlatformReadTCP/WriteTCP (unlike the UDP counterpart) does not provide the destination address
    // from which we can infer the destination address family. Hence we need to remember that here.
    // Instead of remembering the address family, we remember the right fd.
    sock->fd = sock->fd;
    // initiate connection wth peer
    if (connect(sock->fd, (struct sockaddr *)&ss, ss.ss_len) < 0)
    {
        if (errno == EINPROGRESS) return mStatus_ConnPending;
        if (errno == EHOSTUNREACH || errno == EADDRNOTAVAIL || errno == ENETDOWN)
        {
            LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "ERROR: mDNSPlatformTCPConnect - connect failed: socket %d: Error %d (" PUB_S ")",
                sock->fd, errno, strerror(errno));
        }
        else
        {
            LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "ERROR: mDNSPlatformTCPConnect - connect failed: socket %d: Error %d (" PUB_S ") length %d",
                sock->fd, errno, strerror(errno), ss.ss_len);
        }
        return mStatus_ConnFailed;
    }

    LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "NOTE: mDNSPlatformTCPConnect completed synchronously");
    // kQueue should notify us, but this LogMsg is to help track down if it doesn't
    // Experimentation shows that even a connection to a local listener returns EINPROGRESS, so this
    // will likely never happen.

    return err;
}

// Replace the existing socket callback with a new one, or establish a callback where none was present.
mDNSexport mStatus mDNSPlatformTCPSocketSetCallback(TCPSocket *sock, TCPConnectionCallback callback, void *context)
{
    sock->callback = callback;
    sock->context = context;

    // dnsextd currently reaches into the TCPSocket structure layer to do its own thing; this won't work for
    // any code (e.g., the Discovery Proxy or Discovery Relay) that actually uses the mDNSPlatform layer as
    // an opaque layer.   So for that code, we have this.   dnsextd should probably be platformized if it's
    // still relevant.
    if (!sock->callback) {
        // Watch for incoming data
        if (KQueueSet(sock->fd, EV_ADD, EVFILT_READ, &sock->kqEntry))
        {
            LogMsg("ERROR: mDNSPlatformTCPConnect - KQueueSet failed");
            return mStatus_UnknownErr;
        }
    }

    sock->kqEntry.KQcallback = tcpKQSocketCallback;
    sock->kqEntry.KQcontext  = sock;
    sock->kqEntry.KQtask     = "mDNSPlatformTCPSocket";
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
    sock->kqEntry.readSource = mDNSNULL;
    sock->kqEntry.writeSource = mDNSNULL;
    sock->kqEntry.fdClosed = mDNSfalse;
#endif
    return mStatus_NoError;
}

// Why doesn't mDNSPlatformTCPAccept actually call accept() ?
// mDNSPlatformTCPAccept is only called by dnsextd.c.   It's called _after_ accept has returned
// a connected socket.   The purpose appears to be to allocate and initialize the TCPSocket structure
// and set up TLS, if required for this connection.   dnsextd appears to be the only thing in mDNSResponder
// that accepts incoming TLS connections.
mDNSexport TCPSocket *mDNSPlatformTCPAccept(TCPSocketFlags flags, int fd)
{
    mStatus err = mStatus_NoError;

    TCPSocket *sock = (TCPSocket *) callocL("TCPSocket/mDNSPlatformTCPAccept", sizeof(*sock));
    if (!sock) return(mDNSNULL);

    sock->fd = fd;
    sock->flags = flags;

    if (flags & kTCPSocketFlags_UseTLS)
    {
#ifndef NO_SECURITYFRAMEWORK
        if (!ServerCerts) { LogMsg("ERROR: mDNSPlatformTCPAccept: unable to find TLS certificates"); err = mStatus_UnknownErr; goto exit; }

        mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
        err = tlsSetupSock(sock, kSSLServerSide, kSSLStreamType);
        mdns_clang_ignore_warning_end();
        if (err) { LogMsg("ERROR: mDNSPlatformTCPAccept: tlsSetupSock failed with error code: %d", err); goto exit; }

        mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
        err = SSLSetCertificate(sock->tlsContext, ServerCerts);
        mdns_clang_ignore_warning_end();
        if (err) { LogMsg("ERROR: mDNSPlatformTCPAccept: SSLSetCertificate failed with error code: %d", err); goto exit; }
#else
        err = mStatus_UnsupportedErr;
#endif /* NO_SECURITYFRAMEWORK */
    }
#ifndef NO_SECURITYFRAMEWORK
exit:
#endif

    if (err) { freeL("TCPSocket/mDNSPlatformTCPAccept", sock); return(mDNSNULL); }
    return(sock);
}

mDNSlocal void tcpListenCallback(int fd, __unused short filter, void *context, __unused mDNSBool encounteredEOF)
{
    TCPListener *listener = context;
    TCPSocket *sock;

    sock = mDNSPosixDoTCPListenCallback(fd, listener->addressType, listener->socketFlags,
                                 listener->callback, listener->context);

    if (sock != mDNSNULL)
    {
        KQueueSet(sock->fd, EV_ADD, EVFILT_READ, &sock->kqEntry);

        sock->kqEntry.KQcallback = tcpKQSocketCallback;
        sock->kqEntry.KQcontext  = sock;
        sock->kqEntry.KQtask     = "mDNSPlatformTCPListen";
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
        sock->kqEntry.readSource = mDNSNULL;
        sock->kqEntry.writeSource = mDNSNULL;
        sock->kqEntry.fdClosed = mDNSfalse;
#endif
    }
}

mDNSexport TCPListener *mDNSPlatformTCPListen(mDNSAddr_Type addrtype, mDNSIPPort *port, mDNSAddr *addr,
                                              TCPSocketFlags socketFlags, mDNSBool reuseAddr, int queueLength,
                                              TCPAcceptedCallback callback, void *context)
{
    TCPListener *ret;
    int fd = -1;

    if (!mDNSPosixTCPListen(&fd, addrtype, port, addr, reuseAddr, queueLength)) {
        if (fd != -1) {
            close(fd);
        }
        return mDNSNULL;
    }

    // Allocate a listener structure
    ret = (TCPListener *) mDNSPlatformMemAllocateClear(sizeof *ret);
    if (ret == mDNSNULL)
    {
        LogMsg("mDNSPlatformTCPListen: no memory for TCPListener struct.");
        close(fd);
        return mDNSNULL;
    }
    ret->fd = fd;
    ret->callback = callback;
    ret->context = context;
    ret->socketFlags = socketFlags;

    // Watch for incoming data
    KQueueSet(ret->fd, EV_ADD, EVFILT_READ, &ret->kqEntry);
    ret->kqEntry.KQcallback = tcpListenCallback;
    ret->kqEntry.KQcontext  = ret;
    ret->kqEntry.KQtask     = "mDNSPlatformTCPListen";
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
    ret->kqEntry.readSource = mDNSNULL;
    ret->kqEntry.writeSource = mDNSNULL;
    ret->kqEntry.fdClosed = mDNSfalse;
#endif
    return ret;
}

mDNSexport mDNSu16 mDNSPlatformGetUDPPort(UDPSocket *sock)
{
    mDNSu16 port;

    port = -1;
    if (sock)
    {
        port = sock->ss.port.NotAnInteger;
    }
    return port;
}

mDNSlocal void CloseSocketSet(KQSocketSet *ss)
{
    if (ss->sktv4 != -1)
    {
        mDNSPlatformCloseFD(&ss->kqsv4,  ss->sktv4);
        ss->sktv4 = -1;
    }
    if (ss->sktv6 != -1)
    {
        mDNSPlatformCloseFD(&ss->kqsv6,  ss->sktv6);
        ss->sktv6 = -1;
    }
    if (ss->closeFlag) *ss->closeFlag = 1;
}

mDNSexport void mDNSPlatformTCPCloseConnection(TCPSocket *sock)
{
    if (sock)
    {
#ifndef NO_SECURITYFRAMEWORK
        if (sock->tlsContext)
        {
            if (sock->handshake == handshake_in_progress) // SSLHandshake thread using this sock (esp. tlsContext)
            {
                LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformTCPCloseConnection: called while handshake in progress");
                // When we come back from SSLHandshake, we will notice that a close was here and
                // call this function again which will do the cleanup then.
                sock->handshake = handshake_to_be_closed;
                return;
            }
            mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
            SSLClose(sock->tlsContext);
            mdns_clang_ignore_warning_end();

            MDNS_DISPOSE_CF_OBJECT(sock->tlsContext);
        }
#endif /* NO_SECURITYFRAMEWORK */
        if (sock->fd != -1) {
            shutdown(sock->fd, 2);
            mDNSPlatformCloseFD(&sock->kqEntry, sock->fd);
            sock->fd = -1;
        }

        freeL("TCPSocket/mDNSPlatformTCPCloseConnection", sock);
    }
}

mDNSexport long mDNSPlatformReadTCP(TCPSocket *sock, void *buf, unsigned long buflen, mDNSBool *closed)
{
    ssize_t nread = 0;
    *closed = mDNSfalse;

    // We can get here if the caller set up a TCP connection but didn't check the status when it got the
    // callback.
    if (!sock->connected) {
        return mStatus_DefunctConnection;
    }

    if (sock->flags & kTCPSocketFlags_UseTLS)
    {
#ifndef NO_SECURITYFRAMEWORK
        if (sock->handshake == handshake_required) { LogMsg("mDNSPlatformReadTCP called while handshake required"); return 0; }
        else if (sock->handshake == handshake_in_progress) return 0;
        else if (sock->handshake != handshake_completed) LogMsg("mDNSPlatformReadTCP called with unexpected SSLHandshake status: %d", sock->handshake);

        //LogMsg("Starting SSLRead %d %X", sock->fd, fcntl(sock->fd, F_GETFL, 0));
        mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
        mStatus err = SSLRead(sock->tlsContext, buf, buflen, (size_t *)&nread);
        mdns_clang_ignore_warning_end();

        //LogMsg("SSLRead returned %d (%d) nread %d buflen %d", err, errSSLWouldBlock, nread, buflen);
        if (err == errSSLClosedGraceful) { nread = 0; *closed = mDNStrue; }
        else if (err && err != errSSLWouldBlock)
        { LogMsg("ERROR: mDNSPlatformReadTCP - SSLRead: %d", err); nread = -1; *closed = mDNStrue; }
#else
        nread = -1;
        *closed = mDNStrue;
#endif /* NO_SECURITYFRAMEWORK */
    }
    else
    {
        nread = mDNSPosixReadTCP(sock->fd, buf, buflen, closed);
    }

    return nread;
}

mDNSexport long mDNSPlatformWriteTCP(TCPSocket *sock, const char *msg, unsigned long len)
{
    long nsent;

    if (!sock->connected) {
        return mStatus_DefunctConnection;
    }

    if (sock->flags & kTCPSocketFlags_UseTLS)
    {
#ifndef NO_SECURITYFRAMEWORK
        size_t processed;
        if (sock->handshake == handshake_required) { LogMsg("mDNSPlatformWriteTCP called while handshake required"); return 0; }
        if (sock->handshake == handshake_in_progress) return 0;
        else if (sock->handshake != handshake_completed) LogMsg("mDNSPlatformWriteTCP called with unexpected SSLHandshake status: %d", sock->handshake);

        mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
        mStatus err = SSLWrite(sock->tlsContext, msg, len, &processed);
        mdns_clang_ignore_warning_end();

        if (!err) nsent = (long)processed;
        else if (err == errSSLWouldBlock) nsent = 0;
        else { LogMsg("ERROR: mDNSPlatformWriteTCP - SSLWrite returned %d", err); nsent = -1; }
#else
        nsent = -1;
#endif /* NO_SECURITYFRAMEWORK */
    }
    else
    {
        nsent = mDNSPosixWriteTCP(sock->fd, msg, len);
    }
    return nsent;
}

mDNSexport int mDNSPlatformTCPGetFD(TCPSocket *sock)
{
    return sock->fd;
}

// This function checks to see if the socket is writable.   It will be writable if the kernel TCP output
// buffer is less full than TCP_NOTSENT_LOWAT.   This should be half or less of the actual kernel buffer
// size.   This check is done in cases where data should be written if there's space, for example in the
// Discovery Relay code, where we may be receiving mDNS messages at arbitrary times, and generally there
// should be buffer space to relay them, but in exceptional cases there might not be.   In this case it's

mDNSexport mDNSBool mDNSPlatformTCPWritable(TCPSocket *sock)
{
    int kfd = kqueue();
    struct kevent kin, kout;
    int count;
    struct timespec ts;

    if (kfd < 0)
    {
        LogMsg("ERROR: kqueue failed: %m");
        return mDNSfalse;
    }
    ts.tv_sec = 0;
    ts.tv_nsec = 0;
    EV_SET(&kin, sock->fd, EVFILT_WRITE, EV_ADD, 0, 0, 0);
    count = kevent(kfd, &kin, 1, &kout, 1, &ts);
    close(kfd);
    if (count == 1 && (int)kout.ident == sock->fd && kout.filter == EVFILT_WRITE)
    {
        return mDNStrue;
    }
    return mDNSfalse;
}

// If mDNSIPPort port is non-zero, then it's a multicast socket on the specified interface
// If mDNSIPPort port is zero, then it's a randomly assigned port number, used for sending unicast queries
mDNSlocal mStatus SetupSocket(KQSocketSet *cp, const mDNSIPPort port, u_short sa_family, mDNSIPPort *const outport)
{
    int         *s        = (sa_family == AF_INET) ? &cp->sktv4 : &cp->sktv6;
    KQueueEntry *k        = (sa_family == AF_INET) ? &cp->kqsv4 : &cp->kqsv6;
    const int on = 1;
    const int twofivefive = 255;
    mStatus err = mStatus_NoError;
    char *errstr = mDNSNULL;
    const int mtu = 0;
    int saved_errno;

    cp->closeFlag = mDNSNULL;

    int skt = socket(sa_family, SOCK_DGRAM, IPPROTO_UDP);
    if (skt < 3) { if (errno != EAFNOSUPPORT) LogMsg("SetupSocket: socket error %d errno %d (%s)", skt, errno, strerror(errno));return(skt); }

    // set default traffic class
    setTrafficClass(skt, mDNSfalse);

#ifdef SO_RECV_ANYIF
    // Enable inbound packets on IFEF_AWDL interface.
    // Only done for multicast sockets, since we don't expect unicast socket operations
    // on the IFEF_AWDL interface. Operation is a no-op for other interface types.
    if (mDNSSameIPPort(port, MulticastDNSPort))
    {
        err = setsockopt(skt, SOL_SOCKET, SO_RECV_ANYIF, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - SO_RECV_ANYIF"; goto fail; }
    }
#endif // SO_RECV_ANYIF

    // ... with a shared UDP port, if it's for multicast receiving
    if (mDNSSameIPPort(port, MulticastDNSPort) || mDNSSameIPPort(port, NATPMPAnnouncementPort))
    {
        err = setsockopt(skt, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - SO_REUSEPORT"; goto fail; }
    }

    // Don't want to wake from sleep for inbound packets on the mDNS sockets
    if (mDNSSameIPPort(port, MulticastDNSPort))
    {
        int nowake = 1;
        if (setsockopt(skt, SOL_SOCKET, SO_NOWAKEFROMSLEEP, &nowake, sizeof(nowake)) == -1)
            LogInfo("SetupSocket: SO_NOWAKEFROMSLEEP failed %s", strerror(errno));
    }

    // Attribute mDNS traffic to the com.apple.datausage.dns.multicast pseduo-identifier to distinguish it from
    // other network traffic attributed to mDNSResponder.
    if (mDNSSameIPPort(port, MulticastDNSPort))
    {
        // The UUID for com.apple.datausage.dns.multicast is 979C0A62-49FE-4739-BDCB-CAC584AC832D.
        const mDNSu8 mDNSMulticastDataUsageUUID[UUID_SIZE] = {
            0x97, 0x9C, 0x0A, 0x62, 0x49, 0xFE, 0x47, 0x39, 0xBD, 0xCB, 0xCA, 0xC5, 0x84, 0xAC, 0x83, 0x2D
        };
        err = setsockopt(skt, SOL_SOCKET, SO_DELEGATED_UUID, mDNSMulticastDataUsageUUID, sizeof(mDNSMulticastDataUsageUUID));
        if (err != 0)
        {
            saved_errno = errno;
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "SetupSocket: Attributing mDNS traffic to com.apple.datausage.dns.multicast failed: " PUB_S,
                strerror(saved_errno));
        }
    }

    if (sa_family == AF_INET)
    {
        // We want to receive destination addresses
        err = setsockopt(skt, IPPROTO_IP, IP_RECVDSTADDR, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - IP_RECVDSTADDR"; goto fail; }

        // We want to receive interface identifiers
        err = setsockopt(skt, IPPROTO_IP, IP_RECVIF, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - IP_RECVIF"; goto fail; }

        // We want to receive packet TTL value so we can check it
        err = setsockopt(skt, IPPROTO_IP, IP_RECVTTL, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - IP_RECVTTL"; goto fail; }

        // Send unicast packets with TTL 255
        err = setsockopt(skt, IPPROTO_IP, IP_TTL, &twofivefive, sizeof(twofivefive));
        if (err < 0) { errstr = "setsockopt - IP_TTL"; goto fail; }

        // And multicast packets with TTL 255 too
        err = setsockopt(skt, IPPROTO_IP, IP_MULTICAST_TTL, &twofivefive, sizeof(twofivefive));
        if (err < 0) { errstr = "setsockopt - IP_MULTICAST_TTL"; goto fail; }

        // And start listening for packets
        struct sockaddr_in listening_sockaddr;
        listening_sockaddr.sin_family      = AF_INET;
        listening_sockaddr.sin_port        = port.NotAnInteger;     // Pass in opaque ID without any byte swapping
        listening_sockaddr.sin_addr.s_addr = mDNSSameIPPort(port, NATPMPAnnouncementPort) ? AllHosts_v4.NotAnInteger : 0;
        err = bind(skt, (struct sockaddr *) &listening_sockaddr, sizeof(listening_sockaddr));
        if (err) { errstr = "bind"; goto fail; }
        if (outport) outport->NotAnInteger = listening_sockaddr.sin_port;
    }
    else if (sa_family == AF_INET6)
    {
        // NAT-PMP Announcements make no sense on IPv6, and we don't support IPv6 for PCP, so bail early w/o error
        if (mDNSSameIPPort(port, NATPMPAnnouncementPort)) { if (outport) *outport = zeroIPPort; close(skt); return mStatus_NoError; }

        // We want to receive destination addresses and receive interface identifiers
        err = setsockopt(skt, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - IPV6_RECVPKTINFO"; goto fail; }

        // We want to receive packet hop count value so we can check it
        err = setsockopt(skt, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - IPV6_RECVHOPLIMIT"; goto fail; }

        // We want to receive only IPv6 packets. Without this option we get IPv4 packets too,
        // with mapped addresses of the form 0:0:0:0:0:FFFF:xxxx:xxxx, where xxxx:xxxx is the IPv4 address
        err = setsockopt(skt, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - IPV6_V6ONLY"; goto fail; }

        // Send unicast packets with TTL 255
        err = setsockopt(skt, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &twofivefive, sizeof(twofivefive));
        if (err < 0) { errstr = "setsockopt - IPV6_UNICAST_HOPS"; goto fail; }

        // And multicast packets with TTL 255 too
        err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &twofivefive, sizeof(twofivefive));
        if (err < 0) { errstr = "setsockopt - IPV6_MULTICAST_HOPS"; goto fail; }

        // Want to receive our own packets
        err = setsockopt(skt, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &on, sizeof(on));
        if (err < 0) { errstr = "setsockopt - IPV6_MULTICAST_LOOP"; goto fail; }

        // Disable default option to send mDNSv6 packets at min IPv6 MTU: RFC 3542, Sec 11
        err = setsockopt(skt, IPPROTO_IPV6, IPV6_USE_MIN_MTU, &mtu, sizeof(mtu));
        if (err < 0) // Since it is an optimization if we fail just log the err, no need to close the skt
            LogMsg("SetupSocket: setsockopt - IPV6_USE_MIN_MTU: IP6PO_MINMTU_DISABLE socket %d err %d errno %d (%s)",
                    skt, err, errno, strerror(errno));

        // And start listening for packets
        struct sockaddr_in6 listening_sockaddr6;
        mDNSPlatformMemZero(&listening_sockaddr6, sizeof(listening_sockaddr6));
        listening_sockaddr6.sin6_len         = sizeof(listening_sockaddr6);
        listening_sockaddr6.sin6_family      = AF_INET6;
        listening_sockaddr6.sin6_port        = port.NotAnInteger;       // Pass in opaque ID without any byte swapping
        listening_sockaddr6.sin6_flowinfo    = 0;
        listening_sockaddr6.sin6_addr        = in6addr_any; // Want to receive multicasts AND unicasts on this socket
        listening_sockaddr6.sin6_scope_id    = 0;
        err = bind(skt, (struct sockaddr *) &listening_sockaddr6, sizeof(listening_sockaddr6));
        if (err) { errstr = "bind"; goto fail; }
        if (outport) outport->NotAnInteger = listening_sockaddr6.sin6_port;
    }

    fcntl(skt, F_SETFL, fcntl(skt, F_GETFL, 0) | O_NONBLOCK); // set non-blocking
    fcntl(skt, F_SETFD, 1); // set close-on-exec
    *s = skt;
    k->KQcallback = myKQSocketCallBack;
    k->KQcontext  = cp;
    k->KQtask     = "UDP packet reception";
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
    k->readSource = mDNSNULL;
    k->writeSource = mDNSNULL;
    k->fdClosed = mDNSfalse;
#endif
    KQueueSet(*s, EV_ADD, EVFILT_READ, k);

    return(mStatus_NoError);

fail:
    saved_errno = errno;
    // For "bind" failures, only write log messages for our shared mDNS port, or for binding to zero
    if (strcmp(errstr, "bind") || mDNSSameIPPort(port, MulticastDNSPort) || mDNSIPPortIsZero(port))
        LogMsg("%s skt %d port %d error %d errno %d (%s)", errstr, skt, mDNSVal16(port), err, saved_errno, strerror(saved_errno));

    // If we got a "bind" failure of EADDRINUSE, inform the caller as it might need to try another random port
    if (!strcmp(errstr, "bind") && saved_errno == EADDRINUSE)
    {
        err = EADDRINUSE;
        if (mDNSSameIPPort(port, MulticastDNSPort))
            NotifyOfElusiveBug("Setsockopt SO_REUSEPORT failed",
                               "Congratulations, you've reproduced an elusive bug.\r"
                               "Please contact the current assignee of <rdar://problem/3814904>.\r"
                               "Alternatively, you can send email to radar-3387020@group.apple.com. (Note number is different.)\r"
                               "If possible, please leave your machine undisturbed so that someone can come to investigate the problem.");
    }

    mDNSPlatformCloseFD(k, skt);
    return(err);
}

mDNSexport UDPSocket *mDNSPlatformUDPSocket(const mDNSIPPort requestedport)
{
    mStatus err;
    mDNSIPPort port = requestedport;
    mDNSBool randomizePort = mDNSIPPortIsZero(requestedport);
    int i = 10000; // Try at most 10000 times to get a unique random port
    UDPSocket *p = (UDPSocket *) callocL("UDPSocket", sizeof(*p));
    if (!p) { LogMsg("mDNSPlatformUDPSocket: memory exhausted"); return(mDNSNULL); }
    p->ss.port  = zeroIPPort;
    p->ss.m     = &mDNSStorage;
    p->ss.sktv4 = -1;
    p->ss.sktv6 = -1;
    p->ss.proxy = mDNSfalse;

    do
    {
        // The kernel doesn't do cryptographically strong random port allocation, so we do it ourselves here
        if (randomizePort) port = mDNSOpaque16fromIntVal(0xC000 + mDNSRandom(0x3FFF));
        err = SetupSocket(&p->ss, port, AF_INET, &p->ss.port);
        if (!err)
        {
            err = SetupSocket(&p->ss, port, AF_INET6, &p->ss.port);
            if (err) { mDNSPlatformCloseFD(&p->ss.kqsv4, p->ss.sktv4); p->ss.sktv4 = -1; }
        }
        i--;
    } while (err == EADDRINUSE && randomizePort && i);

    if (err)
    {
        // In customer builds we don't want to log failures with port 5351, because this is a known issue
        // of failing to bind to this port when Internet Sharing has already bound to it
        // We also don't want to log about port 5350, due to a known bug when some other
        // process is bound to it.
        if (mDNSSameIPPort(requestedport, NATPMPPort) || mDNSSameIPPort(requestedport, NATPMPAnnouncementPort))
            LogInfo("mDNSPlatformUDPSocket: SetupSocket %d failed error %d errno %d (%s)", mDNSVal16(requestedport), err, errno, strerror(errno));
        else LogMsg("mDNSPlatformUDPSocket: SetupSocket %d failed error %d errno %d (%s)", mDNSVal16(requestedport), err, errno, strerror(errno));
        freeL("UDPSocket", p);
        return(mDNSNULL);
    }
    return(p);
}

#ifdef UNIT_TEST
UNITTEST_UDPCLOSE
#else
mDNSexport void mDNSPlatformUDPClose(UDPSocket *sock)
{
    CloseSocketSet(&sock->ss);
    freeL("UDPSocket", sock);
}
#endif

mDNSexport mDNSBool mDNSPlatformUDPSocketEncounteredEOF(const UDPSocket *sock)
{
    return (sock->ss.sktv4EOF || sock->ss.sktv6EOF);
}

// MARK: - BPF Raw packet sending/receiving


// MARK: - Key Management

#ifndef NO_SECURITYFRAMEWORK
mDNSlocal CFArrayRef CopyCertChain(SecIdentityRef identity)
{
    CFMutableArrayRef certChain = NULL;
    if (!identity) { LogMsg("CopyCertChain: identity is NULL"); return(NULL); }
    SecCertificateRef cert;
    OSStatus err = SecIdentityCopyCertificate(identity, &cert);
    if (err || !cert) LogMsg("CopyCertChain: SecIdentityCopyCertificate() returned %d", (int) err);
    else
    {
        SecPolicySearchRef searchRef;

        mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
        err = SecPolicySearchCreate(CSSM_CERT_X_509v3, &CSSMOID_APPLE_X509_BASIC, NULL, &searchRef);
        mdns_clang_ignore_warning_end();

       if (err || !searchRef) LogMsg("CopyCertChain: SecPolicySearchCreate() returned %d", (int) err);
        else
        {
            SecPolicyRef policy;

            mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
            err = SecPolicySearchCopyNext(searchRef, &policy);
            mdns_clang_ignore_warning_end();

            if (err || !policy) LogMsg("CopyCertChain: SecPolicySearchCopyNext() returned %d", (int) err);
            else
            {
                CFArrayRef wrappedCert = CFArrayCreate(NULL, (const void**) &cert, 1, &kCFTypeArrayCallBacks);
                if (!wrappedCert) LogMsg("CopyCertChain: wrappedCert is NULL");
                else
                {
                    SecTrustRef trust;
                    err = SecTrustCreateWithCertificates(wrappedCert, policy, &trust);
                    if (err || !trust) LogMsg("CopyCertChain: SecTrustCreateWithCertificates() returned %d", (int) err);
                    else
                    {
                        mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
                        mdns_clang_ignore_warning_begin(-Wnonnull);
                        err = SecTrustEvaluate(trust, NULL);
                        mdns_clang_ignore_warning_end();
                        mdns_clang_ignore_warning_end();
                        if (err) LogMsg("CopyCertChain: SecTrustEvaluate() returned %d", (int) err);
                        else
                        {
                            CFArrayRef rawCertChain;

                            mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
                            CSSM_TP_APPLE_EVIDENCE_INFO *statusChain = NULL;
                            err = SecTrustGetResult(trust, NULL, &rawCertChain, &statusChain);
                            mdns_clang_ignore_warning_end();

                            if (err || !rawCertChain || !statusChain) LogMsg("CopyCertChain: SecTrustGetResult() returned %d", (int) err);
                            else
                            {
                                certChain = CFArrayCreateMutableCopy(NULL, 0, rawCertChain);
                                if (!certChain) LogMsg("CopyCertChain: certChain is NULL");
                                else
                                {
                                    // Replace the SecCertificateRef at certChain[0] with a SecIdentityRef per documentation for SSLSetCertificate:
                                    // <http://devworld.apple.com/documentation/Security/Reference/secureTransportRef/index.html>
                                    CFArraySetValueAtIndex(certChain, 0, identity);
                                    // Remove root from cert chain, but keep any and all intermediate certificates that have been signed by the root certificate
                                    if (CFArrayGetCount(certChain) > 1) CFArrayRemoveValueAtIndex(certChain, CFArrayGetCount(certChain) - 1);
                                }
                                MDNS_DISPOSE_CF_OBJECT(rawCertChain);
                                // Do not free statusChain:
                                // <http://developer.apple.com/documentation/Security/Reference/certifkeytrustservices/Reference/reference.html> says:
                                // certChain: Call the CFRelease function to release this object when you are finished with it.
                                // statusChain: Do not attempt to free this pointer; it remains valid until the trust management object is released...
                            }
                        }
                        MDNS_DISPOSE_CF_OBJECT(trust);
                    }
                    MDNS_DISPOSE_CF_OBJECT(wrappedCert);
                }
                MDNS_DISPOSE_CF_OBJECT(policy);
            }
            MDNS_DISPOSE_CF_OBJECT(searchRef);
        }
        MDNS_DISPOSE_CF_OBJECT(cert);
    }
    return certChain;
}
#endif /* NO_SECURITYFRAMEWORK */

mDNSexport mStatus mDNSPlatformTLSSetupCerts(void)
{
#ifdef NO_SECURITYFRAMEWORK
    return mStatus_UnsupportedErr;
#else
    SecIdentityRef identity = nil;
    SecIdentitySearchRef srchRef = nil;
    OSStatus err;

    // search for "any" identity matching specified key use
    // In this app, we expect there to be exactly one
    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    err = SecIdentitySearchCreate(NULL, CSSM_KEYUSE_DECRYPT, &srchRef);
    mdns_clang_ignore_warning_end();
    if (err) { LogMsg("ERROR: mDNSPlatformTLSSetupCerts: SecIdentitySearchCreate returned %d", (int) err); return err; }

    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    err = SecIdentitySearchCopyNext(srchRef, &identity);
    mdns_clang_ignore_warning_end();
    if (err) { LogMsg("ERROR: mDNSPlatformTLSSetupCerts: SecIdentitySearchCopyNext returned %d", (int) err); return err; }

    if (CFGetTypeID(identity) != SecIdentityGetTypeID())
    { LogMsg("ERROR: mDNSPlatformTLSSetupCerts: SecIdentitySearchCopyNext CFTypeID failure"); return mStatus_UnknownErr; }

    // Found one. Call CopyCertChain to create the correct certificate chain.
    ServerCerts = CopyCertChain(identity);
    if (ServerCerts == nil) { LogMsg("ERROR: mDNSPlatformTLSSetupCerts: CopyCertChain error"); return mStatus_UnknownErr; }

    return mStatus_NoError;
#endif /* NO_SECURITYFRAMEWORK */
}

mDNSexport void  mDNSPlatformTLSTearDownCerts(void)
{
#ifndef NO_SECURITYFRAMEWORK
    MDNS_DISPOSE_CF_OBJECT(ServerCerts);
#endif /* NO_SECURITYFRAMEWORK */
}


mDNSlocal void mDNSDomainLabelFromCFString(CFStringRef cfs, domainlabel *const namelabel);

// This gets the text of the field currently labelled "Computer Name" in the Sharing Prefs Control Panel
mDNSlocal void GetUserSpecifiedFriendlyComputerName(domainlabel *const namelabel)
{
    CFStringEncoding encoding = kCFStringEncodingUTF8;
    CFStringRef cfs = SCDynamicStoreCopyComputerName(NULL, &encoding);

    if (cfs == mDNSNULL) {
        return;
    }

    mDNSDomainLabelFromCFString(cfs, namelabel);

    MDNS_DISPOSE_CF_OBJECT(cfs);
}

mDNSlocal void GetUserSpecifiedLocalHostName(domainlabel *const namelabel)
{
    CFStringRef cfs = SCDynamicStoreCopyLocalHostName(NULL);

    if (cfs == mDNSNULL) {
        return;
    }

    mDNSDomainLabelFromCFString(cfs, namelabel);

    MDNS_DISPOSE_CF_OBJECT(cfs);
}

mDNSlocal void mDNSDomainLabelFromCFString(CFStringRef cfs, domainlabel *const namelabel)
{
    CFIndex num_of_bytes_write = 0;
    CFStringGetBytes(cfs, CFRangeMake(0, CFStringGetLength(cfs)), kCFStringEncodingUTF8, 0, FALSE, namelabel->c + 1, sizeof(*namelabel) - 1, &num_of_bytes_write);
    namelabel->c[0] = num_of_bytes_write;
}

mDNSexport mDNSBool DictionaryIsEnabled(CFDictionaryRef dict)
{
    mDNSs32 val;
    CFNumberRef state = (CFNumberRef)CFDictionaryGetValue(dict, CFSTR("Enabled"));
    if (state == NULL) return mDNSfalse;
    if (!CFNumberGetValue(state, kCFNumberSInt32Type, &val))
    { LogMsg("ERROR: DictionaryIsEnabled - CFNumberGetValue"); return mDNSfalse; }
    return val ? mDNStrue : mDNSfalse;
}

mDNSlocal mStatus SetupAddr(mDNSAddr *ip, const struct sockaddr *const sa)
{
    if (!sa) { LogMsg("SetupAddr ERROR: NULL sockaddr"); return(mStatus_Invalid); }

    if (sa->sa_family == AF_INET)
    {
        const struct sockaddr_in *const ifa_addr = (const struct sockaddr_in *)sa;
        ip->type = mDNSAddrType_IPv4;
        ip->ip.v4.NotAnInteger = ifa_addr->sin_addr.s_addr;
        return(mStatus_NoError);
    }

    if (sa->sa_family == AF_INET6)
    {
        const struct sockaddr_in6 *const ifa_addr = (const struct sockaddr_in6 *)sa;
        ip->type = mDNSAddrType_IPv6;
        memcpy(ip->ip.v6.b, ifa_addr->sin6_addr.s6_addr, sizeof(ip->ip.v6.b));
        // Inside the BSD kernel they use a hack where they stuff the sin6->sin6_scope_id
        // value into the second word of the IPv6 link-local address, so they can just
        // pass around IPv6 address structures instead of full sockaddr_in6 structures.
        // Those hacked IPv6 addresses aren't supposed to escape the kernel in that form, but they do.
        // To work around this we always whack the second word of any IPv6 link-local address back to zero.
        if (IN6_IS_ADDR_LINKLOCAL(&ifa_addr->sin6_addr))
        {
            ip->ip.v6.w[1] = 0;
        }
        return(mStatus_NoError);
    }

    LogMsg("SetupAddr invalid sa_family %d", sa->sa_family);
    return(mStatus_Invalid);
}

mDNSlocal mDNSEthAddr GetBSSID(char *ifa_name)
{
    mDNSEthAddr eth = zeroEthAddr;

    CFStringRef entityname = CFStringCreateWithFormat(NULL, NULL, CFSTR("State:/Network/Interface/%s/AirPort"), ifa_name);
    if (entityname)
    {
        CFDictionaryRef dict = SCDynamicStoreCopyValue(NULL, entityname);
        if (dict)
        {
            CFRange range = { 0, 6 };       // Offset, length
            CFDataRef data = CFDictionaryGetValue(dict, CFSTR("BSSID"));
            if (data && CFDataGetLength(data) == 6)
                CFDataGetBytes(data, range, eth.b);
            MDNS_DISPOSE_CF_OBJECT(dict);
        }
        MDNS_DISPOSE_CF_OBJECT(entityname);
    }

    return(eth);
}

mDNSlocal int GetMAC(mDNSEthAddr *eth, u_short ifindex)
{
    struct ifaddrs *ifa;
    for (ifa = myGetIfAddrs(0); ifa; ifa = ifa->ifa_next)
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK)
        {
            const struct sockaddr_dl *const sdl = (const struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_index == ifindex)
            { mDNSPlatformMemCopy(eth->b, sdl->sdl_data + sdl->sdl_nlen, 6); return 0; }
        }
    *eth = zeroEthAddr;
    return -1;
}

#ifndef SIOCGIFWAKEFLAGS
#define SIOCGIFWAKEFLAGS _IOWR('i', 136, struct ifreq) /* get interface wake property flags */
#endif

#ifndef IF_WAKE_ON_MAGIC_PACKET
#define IF_WAKE_ON_MAGIC_PACKET 0x01
#endif

#ifndef ifr_wake_flags
#define ifr_wake_flags ifr_ifru.ifru_intval
#endif

mDNSlocal
kern_return_t
RegistryEntrySearchCFPropertyAndIOObject( io_registry_entry_t     entry,
                                          const io_name_t         plane,
                                          CFStringRef             keystr,
                                          CFTypeRef *             outProperty,
                                          io_registry_entry_t *   outEntry)
{
    kern_return_t       kr;

    IOObjectRetain(entry);
    while (entry)
    {
        CFTypeRef ref = IORegistryEntryCreateCFProperty(entry, keystr, kCFAllocatorDefault, mDNSNULL);
        if (ref)
        {
            if (outProperty) *outProperty = ref;
            else             MDNS_DISPOSE_CF_OBJECT(ref);
            break;
        }
        io_registry_entry_t parent;
        kr = IORegistryEntryGetParentEntry(entry, plane, &parent);
        if (kr != KERN_SUCCESS) parent = mDNSNULL;
        IOObjectRelease(entry);
        entry = parent;
    }
    if (!entry)          kr = kIOReturnNoDevice;
    else
    {
        if (outEntry)   *outEntry = entry;
        else            IOObjectRelease(entry);
        kr = KERN_SUCCESS;
    }
    return(kr);
}

mDNSlocal mDNSBool  CheckInterfaceSupport(NetworkInterfaceInfo *const intf, const char *key)
{
    io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, IOBSDNameMatching(kIOMainPortDefault, 0, intf->ifname));
    if (!service)
    {
        return mDNSfalse;
    }
    mDNSBool    ret    = mDNSfalse;

    CFStringRef keystr =  CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    kern_return_t kr = RegistryEntrySearchCFPropertyAndIOObject(service, kIOServicePlane, keystr, mDNSNULL, mDNSNULL);
    MDNS_DISPOSE_CF_OBJECT(keystr);
    if (kr == KERN_SUCCESS) ret = mDNStrue;
    else
    {
        io_name_t n1;
        IOObjectGetClass(service, n1);
        ret = mDNSfalse;
    }

    IOObjectRelease(service);
    return ret;
}


#if !TARGET_OS_WATCH
mDNSlocal  mDNSBool InterfaceSupportsKeepAlive(NetworkInterfaceInfo *const intf)
{
    return CheckInterfaceSupport(intf, mDNS_IOREG_KA_KEY);
}
#endif

mDNSlocal mDNSBool NetWakeInterface(NetworkInterfaceInfoOSX *i)
{
#if TARGET_OS_WATCH
    (void) i;   // unused
    return(mDNSfalse);
#else
    // We only use Sleep Proxy Service on multicast-capable interfaces, except loopback and D2D.
    if (!MulticastInterface(i) || (i->ifa_flags & IFF_LOOPBACK) || i->D2DInterface)
    {
        LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_DEBUG,
            "NetWakeInterface: returning false for " PUB_S, i->ifinfo.ifname);
        return(mDNSfalse);
    }
#if MDNSRESPONDER_SUPPORTS(APPLE, NO_NETWAKE_FOR_AP1)
    // As a workaround for ap1 being a virtual interface that shares its in-NIC sleep proxy capability with a
    // physical network interface, exclude ap1 from any in-NIC sleep proxy offloading to avoid clobbering the
    // physical interface's in-NIC sleep proxy offloading.
    if (strcmp(i->ifinfo.ifname, "ap1") == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_DEFAULT,
            "NetWakeInterface: returning false for " PUB_S, i->ifinfo.ifname);
        return(mDNSfalse);
    }
#endif

    // If the interface supports TCPKeepalive, it is capable of waking up for a magic packet
    // This check is needed since the SIOCGIFWAKEFLAGS ioctl returns wrong values for WOMP capability
    // when the power source is not AC Power.
    if (InterfaceSupportsKeepAlive(&i->ifinfo))
    {
        LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_DEFAULT,
            "NetWakeInterface: interface supports TCP Keepalive -- ifname: " PUB_S, i->ifinfo.ifname);
        return mDNStrue;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
    {
        const int socket_errno = errno;
        LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_ERROR,
            "NetWakeInterface: socket failed -- socket: %d, ifname: " PUB_S ", error: %{darwin.errno}d", s,
            i->ifinfo.ifname, socket_errno);
        return mDNSfalse;
    }

    struct ifreq ifr;
    mdns_strlcpy(ifr.ifr_name, i->ifinfo.ifname, sizeof(ifr.ifr_name));
    if (ioctl(s, SIOCGIFWAKEFLAGS, &ifr) < 0)
    {
        const int ioctl_errno = errno;
        // For some strange reason, in /usr/include/sys/errno.h, EOPNOTSUPP is defined to be
        // 102 when compiling kernel code, and 45 when compiling user-level code. Since this
        // error code is being returned from the kernel, we need to use the kernel version.
        #define KERNEL_EOPNOTSUPP 102
        if (ioctl_errno != KERNEL_EOPNOTSUPP) // "Operation not supported on socket", the expected result on Leopard and earlier
        {
            LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_ERROR,
                "NetWakeInterface: SIOCGIFWAKEFLAGS failed -- ifname: " PUB_S ", error: %{darwin.errno}d",
                i->ifinfo.ifname, ioctl_errno);
        }
        // If on Leopard or earlier, we get EOPNOTSUPP, so in that case
        // we enable WOL if this interface is not AirPort and "Wake for Network access" is turned on.
        ifr.ifr_wake_flags = (ioctl_errno == KERNEL_EOPNOTSUPP && !(i)->BSSID.l[0] && i->m->SystemWakeOnLANEnabled) ? IF_WAKE_ON_MAGIC_PACKET : 0;
    }

    close(s);

    // ifr.ifr_wake_flags = IF_WAKE_ON_MAGIC_PACKET;    // For testing with MacBook Air, using a USB dongle that doesn't actually support Wake-On-LAN

    LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_DEFAULT,
        "NetWakeInterface: interface -- ifname: " PUB_S ", address: " PRI_IP_ADDR ", supports Wake-On-Lan: " PUB_BOOL,
        i->ifinfo.ifname, &i->ifinfo.ip, BOOL_PARAM((ifr.ifr_wake_flags & IF_WAKE_ON_MAGIC_PACKET) != 0));

    return((ifr.ifr_wake_flags & IF_WAKE_ON_MAGIC_PACKET) != 0);
#endif  // TARGET_OS_WATCH
}

mDNSlocal u_int64_t getExtendedFlags(const char *ifa_name)
{
    int sockFD;
    struct ifreq ifr;

    sockFD = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockFD < 0)
    {
        LogMsg("getExtendedFlags: socket() call failed, errno = %d (%s)", errno, strerror(errno));
        return 0;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    mdns_strlcpy(ifr.ifr_name, ifa_name, sizeof(ifr.ifr_name));

    if (ioctl(sockFD, SIOCGIFEFLAGS, (caddr_t)&ifr) == -1)
    {
        LogMsg("getExtendedFlags: SIOCGIFEFLAGS failed for %s, errno = %d (%s)", ifa_name, errno, strerror(errno));
        ifr.ifr_eflags = 0;
    }

    close(sockFD);
    return ifr.ifr_eflags;
}

mDNSlocal mDNSBool isExcludedInterface(int sockFD, char * ifa_name)
{
    struct ifreq ifr;

    // llw0 interface is excluded from Bonjour discovery.
    // There currently is no interface attributed based way to identify these interfaces
    // until rdar://problem/47933782 is addressed.
    if (strncmp(ifa_name, "llw", 3) == 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEBUG, "isExcludedInterface: excluding " PUB_S, ifa_name);
        return mDNStrue;
    }

    // Coprocessor interfaces are also excluded.
    if (sockFD < 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEBUG, "isExcludedInterface: invalid socket FD passed: %d", sockFD);
        return mDNSfalse;
    }

    memset(&ifr, 0, sizeof(struct ifreq));
    mdns_strlcpy(ifr.ifr_name, ifa_name, sizeof(ifr.ifr_name));

    if (ioctl(sockFD, SIOCGIFFUNCTIONALTYPE, (caddr_t)&ifr) == -1)
    {
        const int socket_errno = errno;
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEBUG,
            "isExcludedInterface: SIOCGIFFUNCTIONALTYPE failed -- error: %{darwin.errno}d", socket_errno);
        return mDNSfalse;
    }

    if (ifr.ifr_functional_type == IFRTYPE_FUNCTIONAL_INTCOPROC)
    {
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEBUG,
            "isExcludedInterface: excluding coprocessor interface " PUB_S, ifa_name);
        return mDNStrue;
    }
    else
        return mDNSfalse;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, RUNTIME_MDNS_METRICS)
mDNSlocal mDNSBool collectsRuntimeMDNSMetricsForThisInterface(const NetworkInterfaceInfoOSX * const ifInfoOSX)
{
    const NetworkInterfaceInfo * const ifInfo = &ifInfoOSX->ifinfo;

    // Only collects mDNS metrics when the Wi-Fi interface that supports mDNS.
    // We also ignore loopback interface, because it is lossless.
    return (ifInfo->McastTxRx && (!ifInfo->Loopback) &&
            (ifInfoOSX->if_functional_type == IFRTYPE_FUNCTIONAL_WIFI_INFRA));
}
#endif

// Returns pointer to newly created NetworkInterfaceInfoOSX object, or
// pointer to already-existing NetworkInterfaceInfoOSX object found in list, or
// may return NULL if out of memory (unlikely) or parameters are invalid for some reason
// (e.g. sa_family not AF_INET or AF_INET6)

mDNSlocal NetworkInterfaceInfoOSX *AddInterfaceToList(const struct ifaddrs *ifa, const mDNSs32 utc)
{
    mDNS *const m = &mDNSStorage;
    mDNSu32 scope_id  = if_nametoindex(ifa->ifa_name);
    mDNSEthAddr bssid = GetBSSID(ifa->ifa_name);
    u_int64_t   eflags = getExtendedFlags(ifa->ifa_name);

    mDNSAddr ip, mask;
    if (SetupAddr(&ip,   ifa->ifa_addr   ) != mStatus_NoError) return(NULL);
    if (SetupAddr(&mask, ifa->ifa_netmask) != mStatus_NoError) return(NULL);

    NetworkInterfaceInfoOSX **p;
    for (p = &m->p->InterfaceList; *p; p = &(*p)->next)
    {
        if (scope_id == (*p)->scope_id &&
            mDNSSameAddress(&ip, &(*p)->ifinfo.ip) &&
            mDNSSameEthAddress(&bssid, &(*p)->BSSID))
        {
            debugf("AddInterfaceToList: Found existing interface %lu %.6a with address %#a at %p, ifname before %s, after %s", scope_id, &bssid, &ip, *p, (*p)->ifinfo.ifname, ifa->ifa_name);
            if ((*p)->Exists)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                    "Ignoring attempt to re-add interface (" PUB_S ", " PRI_IP_ADDR ") already marked as existing",
                    ifa->ifa_name, &ip);
                return(*p);
            }
            // The name should be updated to the new name so that we don't report a wrong name in our SIGINFO output.
            // When interfaces are created with same MAC address, kernel resurrects the old interface.
            // Even though the interface index is the same (which should be sufficient), when we receive a UDP packet
            // we get the corresponding name for the interface index on which the packet was received and check against
            // the InterfaceList for a matching name. So, keep the name in sync.
            mdns_strlcpy((*p)->ifinfo.ifname, ifa->ifa_name, sizeof((*p)->ifinfo.ifname));

            // Determine if multicast state has changed.
            const mDNSBool txrx = MulticastInterface(*p);
            if ((*p)->ifinfo.McastTxRx != txrx)
            {
                (*p)->ifinfo.McastTxRx = txrx;
                (*p)->Exists = MulticastStateChanged; // State change; need to deregister and reregister this interface
            }
            else
                (*p)->Exists = mDNStrue;

            // If interface was not in getifaddrs list last time we looked, but it is now, update 'AppearanceTime' for this record
            if ((*p)->LastSeen != utc) (*p)->AppearanceTime = utc;

            // If Wake-on-LAN capability of this interface has changed (e.g. because power cable on laptop has been disconnected)
            // we may need to start or stop or sleep proxy browse operation
            const mDNSBool NetWake = NetWakeInterface(*p);
            if ((*p)->ifinfo.NetWake != NetWake)
            {
                (*p)->ifinfo.NetWake = NetWake;
                // If this interface is already registered with mDNSCore, then we need to start or stop its NetWake browse on-the-fly.
                // If this interface is not already registered (i.e. it's a dormant interface we had in our list
                // from when we previously saw it) then we mustn't do that, because mDNSCore doesn't know about it yet.
                // In this case, the mDNS_RegisterInterface() call will take care of starting the NetWake browse if necessary.
                if ((*p)->Registered)
                {
                    mDNS_Lock(m);
                    if (NetWake) mDNS_ActivateNetWake_internal  (m, &(*p)->ifinfo);
                    else         mDNS_DeactivateNetWake_internal(m, &(*p)->ifinfo);
                    mDNS_Unlock(m);
                }
            }
            // Reset the flag if it has changed this time.
            (*p)->ifinfo.IgnoreIPv4LL = ((eflags & IFEF_ARPLL) != 0) ? mDNSfalse : mDNStrue;

        #if MDNSRESPONDER_SUPPORTS(APPLE, RUNTIME_MDNS_METRICS)
            if (collectsRuntimeMDNSMetricsForThisInterface(*p))
            {
                if (!(*p)->ifinfo.delayHistogram)
                {
                    (*p)->ifinfo.delayHistogram = mdns_multicast_delay_histogram_create();
                }
            }
        #endif

            return(*p);
        }
    }
    NetworkInterfaceInfoOSX *i = (NetworkInterfaceInfoOSX *) callocL("NetworkInterfaceInfoOSX", sizeof(*i));
    debugf("AddInterfaceToList: Making   new   interface %lu %.6a with address %#a at %p", scope_id, &bssid, &ip, i);
    if (!i) return(mDNSNULL);
    i->ifinfo.InterfaceID = (mDNSInterfaceID)(uintptr_t)scope_id;
    i->ifinfo.ip          = ip;
    i->ifinfo.mask        = mask;
    mdns_strlcpy(i->ifinfo.ifname, ifa->ifa_name, sizeof(i->ifinfo.ifname));
    i->ifinfo.ifname[sizeof(i->ifinfo.ifname)-1] = 0;
    // We can be configured to disable multicast advertisement, but we want to to support
    // local-only services, which need a loopback address record.
    i->ifinfo.Advertise   = m->DivertMulticastAdvertisements ? ((ifa->ifa_flags & IFF_LOOPBACK) ? mDNStrue : mDNSfalse) : m->AdvertiseLocalAddresses;
    i->ifinfo.Loopback    = ((ifa->ifa_flags & IFF_LOOPBACK) != 0) ? mDNStrue : mDNSfalse;
    i->ifinfo.IgnoreIPv4LL = ((eflags & IFEF_ARPLL) != 0) ? mDNSfalse : mDNStrue;

    // Setting DirectLink indicates we can do the optimization of skipping the probe phase
    // for the interface address records since they should be unique.
    // Unfortunately, the legacy p2p* interfaces do not set the IFEF_LOCALNET_PRIVATE
    // or IFEF_DIRECTLINK flags, so we have to match against the name.
    i->ifinfo.DirectLink = mDNSFalse;

    if (i->ifinfo.DirectLink)
        LogInfo("AddInterfaceToList: DirectLink set for %s", ifa->ifa_name);

    i->next            = mDNSNULL;
    i->m               = m;
    i->Exists          = mDNStrue;
    i->Flashing        = mDNSfalse;
    i->Occulting       = mDNSfalse;

    i->D2DInterface    = ((eflags & IFEF_LOCALNET_PRIVATE) || (strncmp(i->ifinfo.ifname, "p2p", 3) == 0)) ? mDNStrue: mDNSfalse;
    if (i->D2DInterface)
        LogInfo("AddInterfaceToList: D2DInterface set for %s", ifa->ifa_name);
    i->isAWDL          = (eflags & IFEF_AWDL)      ? mDNStrue: mDNSfalse;

    if (eflags & IFEF_AWDL)
    {
        // Set SupportsUnicastMDNSResponse false for the AWDL interface since unicast reserves
        // limited AWDL resources so we don't set the kDNSQClass_UnicastResponse bit in
        // Bonjour requests over the AWDL interface.
        i->ifinfo.SupportsUnicastMDNSResponse = mDNSfalse;
    }
    else
    {
        i->ifinfo.SupportsUnicastMDNSResponse = mDNStrue;
    }
    i->AppearanceTime  = utc;       // Brand new interface; AppearanceTime is now
    i->LastSeen        = utc;
    i->ifa_flags       = ifa->ifa_flags;
    i->scope_id        = scope_id;
    i->BSSID           = bssid;
    i->sa_family       = ifa->ifa_addr->sa_family;
    i->BPF_fd          = -1;
    i->BPF_mcfd        = -1;
    i->BPF_len         = 0;
    i->Registered      = mDNSNULL;
    i->ift_family      = GetIFTFamily(i->ifinfo.ifname, &i->ift_subfamily);
    i->if_functional_type = GetIFRFunctionalType(i->ifinfo.ifname);

    // MulticastInterface() depends on the "m" and "ifa_flags" values being initialized above.
    i->ifinfo.McastTxRx   = MulticastInterface(i);
    // Do this AFTER i->BSSID has been set up
    i->ifinfo.NetWake  = (eflags & IFEF_EXPENSIVE)? mDNSfalse :  NetWakeInterface(i);
    GetMAC(&i->ifinfo.MAC, scope_id);
    if (i->ifinfo.NetWake && !i->ifinfo.MAC.l[0])
        LogMsg("AddInterfaceToList: Bad MAC address %.6a for %d %s %#a", &i->ifinfo.MAC, scope_id, i->ifinfo.ifname, &ip);
    // Workaround: For tvOS, never prevent sleep for USB Ethernet interfaces. tvOS instantiates USB Ethernet interfaces
    // with actual IP addresses even though there aren't always physical network interfaces backing them up. This is a
    // problem because when an Apple TV wants to sleep, but has outstanding Bonjour services, the mDNS core will typically
    // not allow sleep in the absence of an in-NIC sleep proxy or remote sleep proxy. Bogus USB Ethernet interfaces
    // obviously don't have an in-NIC sleep proxy nor connectivity to a remote sleep proxy, so they shouldn't prevent sleep.
    // Since tvOS devices don't have USB ports to allow customers to plug in USB Ethernet adapters, the best we can
    // currently do to detect these problematic interfaces is check if they're USB Ethernet interfaces. Also, these bogus
    // USB Ethernet interfaces are placeholders for when a debug cable is connected, so they're used for special-case
    // Mac-to-device networks, not ordinary everyday networks that a customer device would use.
    if (IsAppleTV() && (i->ift_family == IFRTYPE_FAMILY_ETHERNET) && (i->ift_subfamily == IFRTYPE_SUBFAMILY_USB))
    {
        i->ifinfo.MustNotPreventSleep = mDNStrue;
    }

#if MDNSRESPONDER_SUPPORTS(APPLE, RUNTIME_MDNS_METRICS)
    if (collectsRuntimeMDNSMetricsForThisInterface(i))
    {
        mdns_forget(&i->ifinfo.delayHistogram);
        i->ifinfo.delayHistogram = mdns_multicast_delay_histogram_create();
    }
#endif

    *p = i;
    return(i);
}

// MARK: - Power State & Configuration Change Management

mDNSlocal mStatus ReorderInterfaceList(void)
{
    // Disable Reorder lists till <rdar://problem/30071012> is fixed to prevent spurious name conflicts
#ifdef PR_30071012_FIXED
    mDNS *const m = &mDNSStorage;
    nwi_state_t state = nwi_state_copy();

    if (state == mDNSNULL)
    {
        LogMsg("NWI State is NULL!");
        return (mStatus_Invalid);
    }

    // Get the count of interfaces
    mDNSu32 count =  nwi_state_get_interface_names(state, mDNSNULL, 0);
    if (count == 0)
    {
        LogMsg("Unable to get the ordered list of interface names");
        nwi_state_release(state);
        return (mStatus_Invalid);
    }

    // Get the ordered interface list
    int i;
    const char *names[count];
    count = nwi_state_get_interface_names(state, names, count);

    NetworkInterfaceInfo *newList = mDNSNULL;
    for (i = count-1; i >= 0; i--)
    {   // Build a new ordered interface list
        NetworkInterfaceInfo **ptr = &m->HostInterfaces;
        while (*ptr != mDNSNULL )
        {
            if (strcmp((*ptr)->ifname, names[i]) == 0)
            {
                NetworkInterfaceInfo *node = *ptr;
                *ptr = (*ptr)->next;
                node->next = newList;
                newList = node;
            }
            else
                ptr = &((*ptr)->next);
        }
    }

    // Get to the end of the list
    NetworkInterfaceInfo *newListEnd = newList;
    while (newListEnd != mDNSNULL && newListEnd->next != mDNSNULL)
        newListEnd = newListEnd->next;

    // Add any remaing interfaces to the end of the sorted list
    if (newListEnd != mDNSNULL)
        newListEnd->next  = m->HostInterfaces;

    // If we have a valid new list, point to that now
    if (newList != mDNSNULL)
        m->HostInterfaces = newList;

    nwi_state_release(state);
#endif // PR_30071012_FIXED
    return (mStatus_NoError);
}

mDNSlocal mStatus UpdateInterfaceList(mDNSs32 utc)
{
    mDNS *const m = &mDNSStorage;
    struct ifaddrs *ifa = myGetIfAddrs(0);
    char defaultname[64];
    int InfoSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (InfoSocket < 3 && errno != EAFNOSUPPORT)
        LogMsg("UpdateInterfaceList: InfoSocket error %d errno %d (%s)", InfoSocket, errno, strerror(errno));

#if !MDNSRESPONDER_SUPPORTS(APPLE, KEEP_INTERFACES_DURING_SLEEP)
    if (m->SleepState == SleepState_Sleeping) ifa = NULL;
#endif

    for (; ifa; ifa = ifa->ifa_next)
    {
#if LIST_ALL_INTERFACES
        if (ifa->ifa_addr)
        {
            if (ifa->ifa_addr->sa_family == AF_APPLETALK)
                LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d is AF_APPLETALK",
                       ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
            else if (ifa->ifa_addr->sa_family == AF_LINK)
                LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d is AF_LINK",
                       ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
            else if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_addr->sa_family != AF_INET6)
                LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d not AF_INET (2) or AF_INET6 (30)",
                       ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family);
        }
        else
            LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X ifa_addr is NOT set",
                   ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags);

        if (!(ifa->ifa_flags & IFF_UP))
            LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface not IFF_UP",
                   ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags,
                   ifa->ifa_addr ? ifa->ifa_addr->sa_family : 0);
        if (!(ifa->ifa_flags & IFF_MULTICAST))
            LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface not IFF_MULTICAST",
                   ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags,
                   ifa->ifa_addr ? ifa->ifa_addr->sa_family : 0);
        if (ifa->ifa_flags & IFF_POINTOPOINT)
            LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface IFF_POINTOPOINT",
                   ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags,
                   ifa->ifa_addr ? ifa->ifa_addr->sa_family : 0);
        if (ifa->ifa_flags & IFF_LOOPBACK)
            LogMsg("UpdateInterfaceList: %5s(%d) Flags %04X Family %2d Interface IFF_LOOPBACK",
                   ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags,
                   ifa->ifa_addr ? ifa->ifa_addr->sa_family : 0);
#endif

        if (!ifa->ifa_addr || isExcludedInterface(InfoSocket, ifa->ifa_name))
        {
            continue;
        }

        if (ifa->ifa_addr->sa_family == AF_LINK)
        {
            const struct sockaddr_dl *const sdl = (const struct sockaddr_dl *)ifa->ifa_addr;
            if (sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == sizeof(m->PrimaryMAC) && mDNSSameEthAddress(&m->PrimaryMAC, &zeroEthAddr))
            {
                mDNSPlatformMemCopy(m->PrimaryMAC.b, sdl->sdl_data + sdl->sdl_nlen, 6);
            }
            const uint64_t eflags = getExtendedFlags(ifa->ifa_name);
            if ((eflags & IFEF_AWDL) && (!AWDLInterfaceID || !WiFiAwareInterfaceID))
            {
                CFStringRef keys[] = { CFSTR(APPLE80211_REGKEY_INTERFACE_NAME) };
                CFStringRef values[] = { CFStringCreateWithCString(kCFAllocatorDefault, ifa->ifa_name, kCFStringEncodingUTF8) };
                CFDictionaryRef propertyDictionary[] = { CFDictionaryCreate(kCFAllocatorDefault, (const void **)keys, (const void **)values, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) };
                keys[0] = CFSTR(kIOPropertyMatchKey);
                CFDictionaryRef matchingService = CFDictionaryCreate(kCFAllocatorDefault, (const void **)keys, (const void **)propertyDictionary, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                io_service_t service = IOServiceGetMatchingService(kIOMainPortDefault, matchingService);
                MDNS_DISPOSE_CF_OBJECT(values[0]);
                MDNS_DISPOSE_CF_OBJECT(propertyDictionary[0]);
                if (service != MACH_PORT_NULL)
                {
                    CFStringRef role = IORegistryEntryCreateCFProperty(service, CFSTR(APPLE80211_REGKEY_VIRTUAL_IF_ROLE), kCFAllocatorDefault, 0);
                    if (role && CFGetTypeID(role) == CFStringGetTypeID())
                    {
                        if (!AWDLInterfaceID && CFStringCompare(role, CFSTR(APPLE80211_IF_ROLE_STR_AWDL), 0) == kCFCompareEqualTo)
                        {
                            AWDLInterfaceID = (mDNSInterfaceID)((uintptr_t)sdl->sdl_index);
                            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                                      "UpdateInterfaceList: AWDLInterfaceID = %lu", (unsigned long) AWDLInterfaceID);
                        }
                        if (!WiFiAwareInterfaceID && CFStringCompare(role, CFSTR(APPLE80211_IF_ROLE_STR_NAN_DISCOVERY_DATA), 0) == kCFCompareEqualTo)
                        {
                            WiFiAwareInterfaceID = (mDNSInterfaceID)((uintptr_t)sdl->sdl_index);
                            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT,
                                      "UpdateInterfaceList: WiFiAwareInstanceID = %lu", (unsigned long) WiFiAwareInterfaceID);
                        }
                    }
                    MDNS_DISPOSE_CF_OBJECT(role);
                    IOObjectRelease(service);
                }
            }
        }

        if (ifa->ifa_flags & IFF_UP)
        {
            if (ifa->ifa_addr->sa_family == AF_INET || ifa->ifa_addr->sa_family == AF_INET6)
            {
                if (!ifa->ifa_netmask)
                {
                    mDNSAddr ip;
                    SetupAddr(&ip, ifa->ifa_addr);
                    LogMsg("UpdateInterfaceList: ifa_netmask is NULL for %5s(%d) Flags %04X Family %2d %#a",
                           ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family, &ip);
                }
                // Apparently it's normal for the sa_family of an ifa_netmask to sometimes be zero, so we don't complain about that
                // <rdar://problem/5492035> getifaddrs is returning invalid netmask family for fw0 and vmnet
                else if (ifa->ifa_netmask->sa_family != ifa->ifa_addr->sa_family && ifa->ifa_netmask->sa_family != 0)
                {
                    mDNSAddr ip;
                    SetupAddr(&ip, ifa->ifa_addr);
                    LogMsg("UpdateInterfaceList: ifa_netmask for %5s(%d) Flags %04X Family %2d %#a has different family: %d",
                           ifa->ifa_name, if_nametoindex(ifa->ifa_name), ifa->ifa_flags, ifa->ifa_addr->sa_family, &ip, ifa->ifa_netmask->sa_family);
                }
                // Currently we use a few internal ones like mDNSInterfaceID_LocalOnly etc. that are negative values (0, -1, -2).
                else if ((int)if_nametoindex(ifa->ifa_name) <= 0)
                {
                    LogMsg("UpdateInterfaceList: if_nametoindex returned zero/negative value for %5s(%d)", ifa->ifa_name, if_nametoindex(ifa->ifa_name));
                }
                else
                {
                    mDNSBool addInterface = mDNStrue;
                    const sa_family_t family = ifa->ifa_addr->sa_family;
                    // Make sure ifa_netmask->sa_family is set correctly
                    // <rdar://problem/5492035> getifaddrs is returning invalid netmask family for fw0 and vmnet
                    ifa->ifa_netmask->sa_family = family;
                    switch (family)
                    {
                        case AF_INET:
                        {
                            struct sockaddr_in *const netmask = (struct sockaddr_in *)ifa->ifa_netmask;
                            // If an IPv4 address has an all-ones netmask, then it's on a /32 subnet with exactly
                            // one IPv4 address. It generally doesn't make sense to use such an IPv4 address for
                            // mDNS. These type of IPv4 addresses are usually special-purpose. For example, IPv4
                            // addresses used for 464XLAT have an all-ones netmask.
                            if (netmask->sin_addr.s_addr == 0xFFFFFFFFU)
                            {
                                addInterface = mDNSfalse;
                            }
                            break;
                        }
                        case AF_INET6:
                        {
                            int ifru_flags6 = 0;
                            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
                            if (InfoSocket >= 0)
                            {
                                struct in6_ifreq ifr6;
                                mDNSPlatformMemZero((char *)&ifr6, sizeof(ifr6));
                                mdns_strlcpy(ifr6.ifr_name, ifa->ifa_name, sizeof(ifr6.ifr_name));
                                ifr6.ifr_addr = *sin6;
                                if (ioctl(InfoSocket, SIOCGIFAFLAG_IN6, &ifr6) != -1)
                                    ifru_flags6 = ifr6.ifr_ifru.ifru_flags6;
                                verbosedebugf("%s %.16a %04X %04X", ifa->ifa_name, &sin6->sin6_addr, ifa->ifa_flags, ifru_flags6);
                            }
                            if (ifru_flags6 & (IN6_IFF_TENTATIVE | IN6_IFF_DETACHED | IN6_IFF_DEPRECATED | IN6_IFF_TEMPORARY))
                            {
                                addInterface = mDNSfalse;
                            }
                            break;
                        }
                        default:
                            break;
                    }
                    if (addInterface)
                    {
                        AddInterfaceToList(ifa, utc);
                    }
                }
            }
        }
    }

    if (InfoSocket >= 0)
        close(InfoSocket);

    mDNS_snprintf(defaultname, sizeof(defaultname), "%.*s-%02X%02X%02X%02X%02X%02X", HINFO_HWstring_prefixlen, HINFO_HWstring,
                  m->PrimaryMAC.b[0], m->PrimaryMAC.b[1], m->PrimaryMAC.b[2], m->PrimaryMAC.b[3], m->PrimaryMAC.b[4], m->PrimaryMAC.b[5]);

    // Set up the nice label
    domainlabel nicelabel;
    nicelabel.c[0] = 0;
    GetUserSpecifiedFriendlyComputerName(&nicelabel);
    if (nicelabel.c[0] == 0)
    {
        debugf("Couldn’t read user-specified Computer Name; using default “%s” instead", defaultname);
        MakeDomainLabelFromLiteralString(&nicelabel, defaultname);
    }

    // Set up the RFC 1034-compliant label
    domainlabel hostlabel;
    hostlabel.c[0] = 0;
    GetUserSpecifiedLocalHostName(&hostlabel);
    if (hostlabel.c[0] == 0)
    {
        debugf("Couldn’t read user-specified Local Hostname; using default “%s.local” instead", defaultname);
        MakeDomainLabelFromLiteralString(&hostlabel, defaultname);
    }

    // We use a case-sensitive comparison here because even though changing the capitalization
    // of the name alone is not significant to DNS, it's still a change from the user's point of view
    if (SameDomainLabelCS(m->p->usernicelabel.c, nicelabel.c))
        debugf("Usernicelabel (%#s) unchanged since last time; not changing m->nicelabel (%#s)", m->p->usernicelabel.c, m->nicelabel.c);
    else
    {
        if (m->p->usernicelabel.c[0])   // Don't show message first time through, when we first read name from prefs on boot
            LogMsg("User updated Computer Name from “%#s” to “%#s”", m->p->usernicelabel.c, nicelabel.c);
        m->p->usernicelabel = m->nicelabel = nicelabel;
    }

    if (SameDomainLabelCS(m->p->userhostlabel.c, hostlabel.c))
        debugf("Userhostlabel (%#s) unchanged since last time; not changing m->hostlabel (%#s)", m->p->userhostlabel.c, m->hostlabel.c);
    else
    {
        if (m->p->userhostlabel.c[0])   // Don't show message first time through, when we first read name from prefs on boot
            LogMsg("User updated Local Hostname from “%#s” to “%#s”", m->p->userhostlabel.c, hostlabel.c);
        m->p->userhostlabel = m->hostlabel = hostlabel;
        mDNS_SetFQDN(m);
    }

    return(mStatus_NoError);
}

// Returns number of leading one-bits in mask: 0-32 for IPv4, 0-128 for IPv6
// Returns -1 if all the one-bits are not contiguous
mDNSlocal int CountMaskBits(mDNSAddr *mask)
{
    int i = 0, bits = 0;
    int bytes = mask->type == mDNSAddrType_IPv4 ? 4 : mask->type == mDNSAddrType_IPv6 ? 16 : 0;
    while (i < bytes)
    {
        mDNSu8 b = mask->ip.v6.b[i++];
        while (b & 0x80) { bits++; b <<= 1; }
        if (b) return(-1);
    }
    while (i < bytes) if (mask->ip.v6.b[i++]) return(-1);
    return(bits);
}

mDNSlocal void mDNSGroupJoinOrLeave(const int sock, const NetworkInterfaceInfoOSX *const i, const mDNSBool join)
{
    int level;
    struct group_req gr;
    mDNSPlatformMemZero(&gr, sizeof(gr));
    gr.gr_interface = i->scope_id;
    switch (i->sa_family)
    {
        case AF_INET: {
            struct sockaddr_in *const sin = (struct sockaddr_in *)&gr.gr_group;
            sin->sin_len         = sizeof(*sin);
            sin->sin_family      = AF_INET;
            sin->sin_addr.s_addr = AllDNSLinkGroup_v4.ip.v4.NotAnInteger;
            level = IPPROTO_IP;
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, PUB_S "ing mcast group " PUB_IPv4_ADDR " on " PUB_S " (%u)",
                join ? "Join" : "Leav", &sin->sin_addr.s_addr, i->ifinfo.ifname, i->scope_id);
            break;
        }
        case AF_INET6: {
            struct sockaddr_in6 *const sin6 = (struct sockaddr_in6 *)&gr.gr_group;
            sin6->sin6_len    = sizeof(*sin6);
            sin6->sin6_family = AF_INET6;
            memcpy(sin6->sin6_addr.s6_addr, AllDNSLinkGroup_v6.ip.v6.b, sizeof(sin6->sin6_addr.s6_addr));
            level = IPPROTO_IPV6;
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, PUB_S "ing mcast group " PUB_IPv6_ADDR " on " PUB_S " (%u)",
                join ? "Join" : "Leav", sin6->sin6_addr.s6_addr, i->ifinfo.ifname, i->scope_id);
            break;
        }
        default:
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "Cannot " PUB_S " mcast group on " PUB_S " (%u) for unrecognized address family %d",
                join ? "join" : "leave", i->ifinfo.ifname, i->scope_id, i->sa_family);
            goto exit;
    }
    const int err = setsockopt(sock, level, join ? MCAST_JOIN_GROUP : MCAST_LEAVE_GROUP, &gr, sizeof(gr));
    if (err)
    {
        // When joining a group, ignore EADDRINUSE errors, which can ocur when the same group is joined twice.
        // When leaving a group, ignore EADDRNOTAVAIL errors, which can occur when an interface is no longer present.
        const int opterrno = errno;
        if ((join && (opterrno != EADDRINUSE)) || (!join && (opterrno != EADDRNOTAVAIL)))
        {
            LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                "setsockopt - IPPROTO_IP" PUB_S "/MCAST_" PUB_S "_GROUP error %d errno %d (%s) on " PUB_S " (%u)",
                (level == IPPROTO_IPV6) ? "V6" : "", join ? "JOIN" : "LEAVE", err, opterrno, strerror(opterrno),
                i->ifinfo.ifname, i->scope_id);
        }
    }

exit:
    return;
}
#define mDNSGroupJoin(SOCK, INTERFACE)  mDNSGroupJoinOrLeave(SOCK, INTERFACE, mDNStrue)
#define mDNSGroupLeave(SOCK, INTERFACE) mDNSGroupJoinOrLeave(SOCK, INTERFACE, mDNSfalse)

// Returns count of non-link local V4 addresses registered (why? -- SC)
mDNSlocal int SetupActiveInterfaces(mDNSs32 utc)
{
    mDNS *const m = &mDNSStorage;
    NetworkInterfaceInfoOSX *i;
    int count = 0;

    // Recalculate SuppressProbes time based on the current set of active interfaces.
    m->SuppressProbes = 0;
    for (i = m->p->InterfaceList; i; i = i->next)
        if (i->Exists)
        {
            NetworkInterfaceInfo *const n = &i->ifinfo;
            NetworkInterfaceInfoOSX *primary = SearchForInterfaceByName(i->ifinfo.ifname, AF_UNSPEC);

            if (i->Registered && i->Registered != primary)  // Sanity check
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                    "SetupActiveInterfaces ERROR! n->Registered %p != primary %p", i->Registered, primary);
                i->Registered = mDNSNULL;
            }

            if (!i->Registered)
            {
                InterfaceActivationSpeed activationSpeed;

                // Note: If i->Registered is set, that means we've called mDNS_RegisterInterface() for this interface,
                // so we need to make sure we call mDNS_DeregisterInterface() before disposing it.
                // If i->Registered is NOT set, then we haven't registered it and we should not try to deregister it.
                i->Registered = primary;

                // If i->LastSeen == utc, then this is a brand-new interface, just created, or an interface that never went away.
                // If i->LastSeen != utc, then this is an old interface, previously seen, that went away for (utc - i->LastSeen) seconds.
                // If the interface is an old one that went away and came back in less than a minute, then we're in a flapping scenario.
                i->Occulting = !(i->ifa_flags & IFF_LOOPBACK) && (utc - i->LastSeen > 0 && utc - i->LastSeen < 60);

                // The "p2p*" interfaces used for legacy AirDrop reuse the scope-id, MAC address and the IP address
                // every time a new interface is created. We think it is a duplicate and hence consider it
                // as flashing and occulting, that is, flapping. If an interface is marked as flapping,
                // mDNS_RegisterInterface() changes the probe delay from 1/2 second to 5 seconds and
                // logs a warning message to system.log noting frequent interface transitions.
                // The same logic applies when the IFEF_DIRECTLINK flag is set on the interface.
                if ((strncmp(i->ifinfo.ifname, "p2p", 3) == 0) || i->ifinfo.DirectLink)
                {
                    activationSpeed = FastActivation;
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_INFO,
                        "SetupActiveInterfaces: " PUB_S " DirectLink interface registering", i->ifinfo.ifname);
                }
#if MDNSRESPONDER_SUPPORTS(APPLE, SLOW_ACTIVATION)
                else if (i->Flashing && i->Occulting)
                {
                    activationSpeed = SlowActivation;
                }
#endif
                else
                {
                    activationSpeed = NormalActivation;
                }

                mDNS_RegisterInterface(m, n, activationSpeed);

                if (!mDNSAddressIsLinkLocal(&n->ip)) count++;
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "SetupActiveInterfaces: Registered " PUB_S " (%u) BSSID " PRI_MAC_ADDR " Struct addr %p, primary %p,"
                        " " PRI_IP_ADDR "/%d" PUB_S PUB_S PUB_S,
                        i->ifinfo.ifname, i->scope_id, &i->BSSID, i, primary, &n->ip, CountMaskBits(&n->mask),
                        i->Flashing        ? " (Flashing)"  : "",
                        i->Occulting       ? " (Occulting)" : "",
                        n->InterfaceActive ? " (Primary)"   : "");

                if (!n->McastTxRx)
                {
                    debugf("SetupActiveInterfaces:   No Tx/Rx on   %5s(%lu) %.6a InterfaceID %p %#a", i->ifinfo.ifname, i->scope_id, &i->BSSID, i->ifinfo.InterfaceID, &n->ip);
                }
                else
                {
                    if ((i->sa_family == AF_INET) || (i->sa_family == AF_INET6))
                    {
                        // If this is our *first* address family instance for this interface name, we need to do a leave first,
                        // before trying to join the group, to clear out stale kernel state which may be lingering.
                        // In particular, this happens with removable network interfaces like USB Ethernet adapters -- the kernel has stale state
                        // from the last time the USB Ethernet adapter was connected, and part of the kernel thinks we've already joined the group
                        // on that interface (so we get EADDRINUSE when we try to join again) but a different part of the kernel thinks we haven't
                        // joined the group (so we receive no multicasts). Doing a leave before joining seems to flush the stale state.
                        // Also, trying to make the code leave the group when the adapter is removed doesn't work either,
                        // because by the time we get the configuration change notification, the interface is already gone,
                        // so attempts to unsubscribe fail with EADDRNOTAVAIL (errno 49 "Can't assign requested address").
                        // <rdar://problem/5585972> IP_ADD_MEMBERSHIP fails for previously-connected removable interfaces
                        const int sock = (i->sa_family == AF_INET) ? m->p->permanentsockets.sktv4 : m->p->permanentsockets.sktv6;
                        if (SearchForInterfaceByName(i->ifinfo.ifname, i->sa_family) == i)
                        {
                            mDNSGroupLeave(sock, i);
                        }
                        mDNSGroupJoin(sock, i);
                    }
                }
            }
        }

    return count;
}

mDNSlocal void MarkAllInterfacesInactive(mDNSs32 utc)
{
    NetworkInterfaceInfoOSX *i;
    for (i = mDNSStorage.p->InterfaceList; i; i = i->next)
    {
        if (i->Exists) i->LastSeen = utc;
        i->Exists = mDNSfalse;
    }
}

// Returns count of non-link local V4 addresses deregistered (why? -- SC)
mDNSlocal int ClearInactiveInterfaces(mDNSs32 utc)
{
    mDNS *const m = &mDNSStorage;
    // First pass:
    // If an interface is going away, then deregister this from the mDNSCore.
    // We also have to deregister it if the primary interface that it's using for its InterfaceID is going away.
    // We have to do this because mDNSCore will use that InterfaceID when sending packets, and if the memory
    // it refers to has gone away we'll crash.
    NetworkInterfaceInfoOSX *i;
    int count = 0;
    for (i = m->p->InterfaceList; i; i = i->next)
    {
        // If this interface is no longer active, or its InterfaceID is changing, deregister it
        NetworkInterfaceInfoOSX *primary = SearchForInterfaceByName(i->ifinfo.ifname, AF_UNSPEC);
        if (i->Registered)
        {
            if (i->Exists == 0 || i->Exists == MulticastStateChanged || i->Registered != primary)
            {
                InterfaceActivationSpeed activationSpeed;

                i->Flashing = !(i->ifa_flags & IFF_LOOPBACK) && (utc - i->AppearanceTime < 60);
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                    "ClearInactiveInterfaces: Deregistering " PUB_S "(%u) " PRI_MAC_ADDR
                    " InterfaceID %p(%p), primary %p, " PRI_IP_ADDR "/%d -- "
                    "flashing: " PUB_BOOL ", occulting: " PUB_BOOL ", primary: " PUB_BOOL,
                    i->ifinfo.ifname, i->scope_id, &i->BSSID, i->ifinfo.InterfaceID, i, primary, &i->ifinfo.ip,
                    CountMaskBits(&i->ifinfo.mask), i->Flashing, i->Occulting, i->ifinfo.InterfaceActive);

                // "p2p*" interfaces used for legacy AirDrop reuse the scope-id, MAC address and the IP address
                // every time it creates a new interface. We think it is a duplicate and hence consider it
                // as flashing and occulting. The "core" does not flush the cache for this case. This leads to
                // stale data returned to the application even after the interface is removed. The application
                // then starts to send data but the new interface is not yet created.
                // The same logic applies when the IFEF_DIRECTLINK flag is set on the interface.
                if ((strncmp(i->ifinfo.ifname, "p2p", 3) == 0) || i->ifinfo.DirectLink)
                {
                    activationSpeed = FastActivation;
                    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                        "ClearInactiveInterfaces: " PUB_S " DirectLink interface deregistering", i->ifinfo.ifname);
                }
#if MDNSRESPONDER_SUPPORTS(APPLE, SLOW_ACTIVATION)
                else if (i->Flashing && i->Occulting)
                {
                    activationSpeed = SlowActivation;
                }
#endif
                else
                {
                    activationSpeed = NormalActivation;
                }
                mDNS_DeregisterInterface(m, &i->ifinfo, activationSpeed);

                if (!mDNSAddressIsLinkLocal(&i->ifinfo.ip)) count++;
                i->Registered = mDNSNULL;
                // Note: If i->Registered is set, that means we've called mDNS_RegisterInterface() for this interface,
                // so we need to make sure we call mDNS_DeregisterInterface() before disposing it.
                // If i->Registered is NOT set, then it's not registered and we should not call mDNS_DeregisterInterface() on it.

                // Caution: If we ever decide to add code here to leave the multicast group, we need to make sure that this
                // is the LAST representative of this physical interface, or we'll unsubscribe from the group prematurely.
            }
        }
    }

    // Second pass:
    // Now that everything that's going to deregister has done so, we can clean up and free the memory
    NetworkInterfaceInfoOSX **p = &m->p->InterfaceList;
    while (*p)
    {
        i = *p;
        // If no longer active, delete interface from list and free memory
        if (!i->Exists)
        {
            if (i->LastSeen == utc) i->LastSeen = utc - 1;
            const mDNSBool delete = ((utc - i->LastSeen) >= 60) ? mDNStrue : mDNSfalse;
            if (delete)
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                    "ClearInactiveInterfaces: Deleting " PUB_S "(%u) " PRI_MAC_ADDR " InterfaceID %p(%p) " PRI_IP_ADDR
                    "/%d Age %d -- primary: " PUB_BOOL, i->ifinfo.ifname, i->scope_id, &i->BSSID, i->ifinfo.InterfaceID,
                    i, &i->ifinfo.ip, CountMaskBits(&i->ifinfo.mask), utc - i->LastSeen, i->ifinfo.InterfaceActive);
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                    "ClearInactiveInterfaces: Holding " PUB_S "(%u) " PRI_MAC_ADDR " InterfaceID %p(%p) " PRI_IP_ADDR
                    "/%d Age %d -- primary: " PUB_BOOL, i->ifinfo.ifname, i->scope_id, &i->BSSID, i->ifinfo.InterfaceID,
                    i, &i->ifinfo.ip, CountMaskBits(&i->ifinfo.mask), utc - i->LastSeen, i->ifinfo.InterfaceActive);
            }

            if (delete)
            {
                *p = i->next;
            #if MDNSRESPONDER_SUPPORTS(APPLE, RUNTIME_MDNS_METRICS)
                mdns_forget(&i->ifinfo.delayHistogram);
            #endif
                freeL("NetworkInterfaceInfoOSX", i);
                continue;   // After deleting this object, don't want to do the "p = &i->next;" thing at the end of the loop
            }
        }
        p = &i->next;
    }
    return count;
}

mDNSlocal void AppendDNameListElem(DNameListElem ***List, mDNSu32 uid, domainname *name)
{
    DNameListElem *dnle = (DNameListElem*) callocL("DNameListElem/AppendDNameListElem", sizeof(*dnle));
    if (!dnle) LogMsg("ERROR: AppendDNameListElem: memory exhausted");
    else
    {
        dnle->next = mDNSNULL;
        dnle->uid  = uid;
        AssignDomainName(&dnle->name, name);
        **List = dnle;
        *List = &dnle->next;
    }
}

mDNSlocal int compare_dns_configs(const void *aa, const void *bb)
{
    const dns_resolver_t *const a = *(const dns_resolver_t *const *)aa;
    const dns_resolver_t *const b = *(const dns_resolver_t *const *)bb;

    return (a->search_order < b->search_order) ? -1 : (a->search_order == b->search_order) ? 0 : 1;
}

mDNSlocal void UpdateSearchDomainHash(MD5_CTX *sdc, char *domain, mDNSInterfaceID InterfaceID)
{
    mDNS *const m = &mDNSStorage;
    char *buf = ".";
    mDNSu32 scopeid = 0;
    char ifid_buf[16];

    if (domain)
        buf = domain;
    //
    // Hash the search domain name followed by the InterfaceID.
    // As we have scoped search domains, we also included InterfaceID. If either of them change,
    // we will detect it. Even if the order of them change, we will detect it.
    //
    // Note: We have to handle a few of these tricky cases.
    //
    // 1) Current: com, apple.com Changing to: comapple.com
    // 2) Current: a.com,b.com Changing to a.comb.com
    // 3) Current: a.com,b.com (ifid 8), Changing to a.com8b.com (ifid 8)
    // 4) Current: a.com (ifid 12), Changing to a.com1 (ifid: 2)
    //
    // There are more variants of the above. The key thing is if we include the null in each case
    // at the end of name and the InterfaceID, it will prevent a new name (which can't include
    // NULL as part of the name) to be mistakenly thought of as a old name.

    scopeid = mDNSPlatformInterfaceIndexfromInterfaceID(m, InterfaceID, mDNStrue);
    // mDNS_snprintf always null terminates
    if (mDNS_snprintf(ifid_buf, sizeof(ifid_buf), "%u", scopeid) >= sizeof(ifid_buf))
    {
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEBUG,
            "UpdateSearchDomainHash: mDNS_snprintf failed for scopeid %u", scopeid);
    }
    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEBUG, "UpdateSearchDomainHash: buf %s, ifid_buf %s", buf, ifid_buf);
    MD5_Update(sdc, buf, strlen(buf) + 1);
    MD5_Update(sdc, ifid_buf, strlen(ifid_buf) + 1);
}

mDNSlocal void FinalizeSearchDomainHash(MD5_CTX *sdc)
{
    mDNS *const m = &mDNSStorage;
    mDNSu8 md5_hash[MD5_LEN];

    MD5_Final(md5_hash, sdc);

    if (memcmp(md5_hash, m->SearchDomainsHash, MD5_LEN))
    {
        // If the hash is different, either the search domains have changed or
        // the ordering between them has changed. Restart the questions that
        // would be affected by this.
        memcpy(m->SearchDomainsHash, md5_hash, MD5_LEN);
        RetrySearchDomainQuestions(m);
    }
}

mDNSlocal void ConfigSearchDomains(dns_resolver_t *resolver, mDNSInterfaceID interfaceId, mDNSu32 scope,  MD5_CTX *sdc, uint64_t generation)
{
    int j;
    domainname d;

    if (scope == kScopeNone)
        interfaceId = mDNSInterface_Any;

#define LogRedactWithIfID(CATEGORY, LEVEL, ifID, FORMAT, ...)                       \
    do {                                                                            \
        if ((ifID) == mDNSInterface_Any)                                            \
        {                                                                           \
            LogRedact(CATEGORY, LEVEL, FORMAT, ##__VA_ARGS__);                      \
        } else {                                                                    \
            LogRedact(CATEGORY, LEVEL, FORMAT ", ifname: " PUB_S, ##__VA_ARGS__,    \
                InterfaceNameForID(&mDNSStorage, (ifID)));                          \
        }                                                                           \
    } while(0)

    if (scope == kScopeNone || scope == kScopeInterfaceID)
    {
        if (resolver->n_search > 0)
        {
            LogRedactWithIfID(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT, interfaceId,
                "ConfigSearchDomains: configuring search domains -- "
                "count: %d, scope type: " PUB_DNS_SCOPE_TYPE ", generation: %llu", resolver->n_search, scope,
                generation);
        }

        for (j = 0; j < resolver->n_search; j++)
        {
            if (MakeDomainNameFromDNSNameString(&d, resolver->search[j]) != NULL)
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                    "ConfigSearchDomains -- search domain: " PRI_DM_NAME, DM_NAME_PARAM_NONNULL(&d));

                UpdateSearchDomainHash(sdc, resolver->search[j], interfaceId);
                mDNS_AddSearchDomain_CString(resolver->search[j], interfaceId);
            }
            else
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                    "ConfigSearchDomains: An invalid search domain was detected -- index: %d, name server count: %d",
                    j,resolver->n_nameserver);
            }
        }
    }
    else
    {
        LogRedactWithIfID(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT, interfaceId,
            "ConfigSearchDomains: Ignoring search domains for interface -- scope type: " PUB_DNS_SCOPE_TYPE,
            DNS_SCOPE_TYPE_PARAM(scope));
    }
#undef LogRedactWithIfID
}

mDNSlocal mDNSInterfaceID ConfigParseInterfaceID(mDNSu32 ifindex)
{
    NetworkInterfaceInfoOSX *ni;
    mDNSInterfaceID interface;

    for (ni = mDNSStorage.p->InterfaceList; ni; ni = ni->next)
    {
        if (ni->ifinfo.InterfaceID && ni->scope_id == ifindex)
            break;
    }
    if (ni != NULL)
    {
        interface = ni->ifinfo.InterfaceID;
    }
    else
    {
        // In rare circumstances, we could potentially hit this case where we cannot parse the InterfaceID
        // (see <rdar://problem/13214785>). At this point, we still accept the DNS Config from configd
        // Note: We currently ack the whole dns configuration and not individual resolvers or DNS servers.
        // As the caller is going to ack the configuration always, we have to add all the DNS servers
        // in the configuration. Otherwise, we won't have any DNS servers up until the network change.

        LogMsg("ConfigParseInterfaceID: interface specific index %d not found (interface may not be UP)",ifindex);

        // Set the correct interface from configd before passing this to mDNS_AddDNSServer() below
        interface = (mDNSInterfaceID)(unsigned long)ifindex;
    }
    return interface;
}

mDNSlocal void ConfigNonUnicastResolver(dns_resolver_t *r)
{
    char *opt = r->options;
    domainname d;

    if (opt && !strncmp(opt, "mdns", strlen(opt)))
    {
        if (!MakeDomainNameFromDNSNameString(&d, r->domain))
        {
            LogMsg("ConfigNonUnicastResolver: config->resolver bad domain %s", r->domain);
            return;
        }
        mDNS_AddMcastResolver(&mDNSStorage, &d, mDNSInterface_Any, r->timeout);
    }
}

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
mDNSlocal void ConfigDNSServers(dns_resolver_t *r, mDNSInterfaceID interfaceID, mDNSu32 scope, mDNSu32 resGroupID)
{
    domainname domain;
    if (!r->domain || (*r->domain == '\0'))
    {
        domain.c[0] = 0;
    }
    else if (!MakeDomainNameFromDNSNameString(&domain, r->domain))
    {
        LogMsg("ConfigDNSServers: bad domain %s", r->domain);
        return;
    }
    // Parse the resolver specific attributes that affects all the DNS servers.
    const int32_t serviceID = (scope == kScopeServiceID) ? r->service_identifier : 0;

    const mdns_interface_monitor_t monitor = GetInterfaceMonitorForIndex((uint32_t)((uintptr_t)interfaceID));
    const mDNSBool isExpensive   = (monitor && mdns_interface_monitor_is_expensive(monitor))   ? mDNStrue : mDNSfalse;
    const mDNSBool isConstrained = (monitor && mdns_interface_monitor_is_constrained(monitor)) ? mDNStrue : mDNSfalse;
    const mDNSBool isCLAT46      = (monitor && mdns_interface_monitor_is_clat46(monitor))      ? mDNStrue : mDNSfalse;
    const mDNSBool usableA       = (r->flags & DNS_RESOLVER_FLAGS_REQUEST_A_RECORDS)           ? mDNStrue : mDNSfalse;
    const mDNSBool usableAAAA    = (r->flags & DNS_RESOLVER_FLAGS_REQUEST_AAAA_RECORDS)        ? mDNStrue : mDNSfalse;
    const mDNSBool isCell        = mDNSfalse;

    const mDNSIPPort port = (r->port != 0) ? mDNSOpaque16fromIntVal(r->port) : UnicastDNSPort;
    for (int32_t i = 0; i < r->n_nameserver; i++)
    {
        const int family = r->nameserver[i]->sa_family;
        if ((family != AF_INET) && (family != AF_INET6)) continue;

        mDNSAddr saddr;
        if (SetupAddr(&saddr, r->nameserver[i]))
        {
            LogMsg("ConfigDNSServers: Bad address");
            continue;
        }

        // The timeout value is for all the DNS servers in a given resolver, hence we pass
        // the timeout value only for the first DNSServer. If we don't have a value in the
        // resolver, then use the core's default value
        //
        // Note: this assumes that when the core picks a list of DNSServers for a question,
        // it takes the sum of all the timeout values for all DNS servers. By doing this, it
        // tries all the DNS servers in a specified timeout
        DNSServer *s = mDNS_AddDNSServer(&mDNSStorage, &domain, interfaceID, serviceID, &saddr, port, scope,
            (i == 0) ? (r->timeout ? r->timeout : DEFAULT_UDNS_TIMEOUT) : 0, isCell, isExpensive, isConstrained, isCLAT46,
            resGroupID, usableA, usableAAAA, mDNStrue);
        if (s)
        {
            LogInfo("ConfigDNSServers(%s): DNS server %#a:%d for domain %##s",
                DNSScopeToString(scope), &s->addr, mDNSVal16(s->port), domain.c);
        }
    }
}
#endif

// ConfigResolvers is called for different types of resolvers: Unscoped resolver, Interface scope resolver and
// Service scope resolvers. This is indicated by the scope argument.
//
// "resolver" has entries that should only be used for unscoped questions.
//
// "scoped_resolver" has entries that should only be used for Interface scoped question i.e., questions that specify an
// interface index (q->InterfaceID)
//
// "service_specific_resolver" has entries that should be used for Service scoped question i.e., questions that specify
// a service identifier (q->ServiceID)
//
mDNSlocal void ConfigResolvers(dns_config_t *config, mDNSu32 scope, mDNSBool setsearch, mDNSBool setservers, MD5_CTX *sdc)
{
    int i;
    dns_resolver_t **resolver;
    int nresolvers;
    mDNSInterfaceID interface;

    switch (scope)
    {
        case kScopeNone:
            resolver = config->resolver;
            nresolvers = config->n_resolver;
            break;
        case kScopeInterfaceID:
            resolver = config->scoped_resolver;
            nresolvers = config->n_scoped_resolver;
            break;
        case kScopeServiceID:
            resolver = config->service_specific_resolver;
            nresolvers = config->n_service_specific_resolver;
            break;
        default:
            return;
    }
    qsort(resolver, nresolvers, sizeof(dns_resolver_t*), compare_dns_configs);

    for (i = 0; i < nresolvers; i++)
    {
        dns_resolver_t *r = resolver[i];

        // ConfigResolvers -- scope type: Unscoped, resolver[6]: {domain: b.e.f.ip6.arpa, name server count: 0}
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
            "ConfigResolvers -- scope type: " PUB_DNS_SCOPE_TYPE ", resolver[%d]: {domain: " PRI_S
            ", name server count: %d}", DNS_SCOPE_TYPE_PARAM(scope), i, r->domain, r->n_nameserver);

        interface = mDNSInterface_Any;

        // Parse the interface index
        if (r->if_index != 0)
        {
            interface = ConfigParseInterfaceID(r->if_index);
        }

        if (setsearch)
        {
            ConfigSearchDomains(resolver[i], interface, scope, sdc, config->generation);

            // Parse other scoped resolvers for search lists
            if (!setservers)
                continue;
        }

        if (r->port == 5353 || r->n_nameserver == 0)
        {
            ConfigNonUnicastResolver(r);
        }
#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
        else
        {
            ConfigDNSServers(r, interface, scope, mDNS_GetNextResolverGroupID());
        }
#endif
    }
}

#if MDNSRESPONDER_SUPPORTS(APPLE, REACHABILITY_TRIGGER)
mDNSlocal mDNSBool QuestionValidForDNSTrigger(const DNSQuestion *q)
{
    if (q->Suppressed)
    {
        debugf("QuestionValidForDNSTrigger: Suppressed: %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
        return mDNSfalse;
    }
    if (mDNSOpaque16IsZero(q->TargetQID))
    {
        debugf("QuestionValidForDNSTrigger: Multicast: %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
        return mDNSfalse;
    }
    // If we answered using LocalOnly records e.g., /etc/hosts, don't consider that a valid response
    // for trigger.
    if (q->LOAddressAnswers)
    {
        debugf("QuestionValidForDNSTrigger: LocalOnly answers: %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
        return mDNSfalse;
    }
    return mDNStrue;
}

// This function is called if we are not delivering unicast answers to "A" or "AAAA" questions.
// We set our state appropriately so that if we start receiving answers, trigger the
// upper layer to retry DNS questions.
mDNSexport void mDNSPlatformUpdateDNSStatus(const DNSQuestion *q)
{
    mDNS *const m = &mDNSStorage;
    if (!QuestionValidForDNSTrigger(q))
        return;

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    // Ignore applications that start and stop queries for no reason before we ever talk
    // to any DNS server.
    if (!q->triedAllServersOnce)
    {
        LogInfo("QuestionValidForDNSTrigger: question %##s (%s) stopped too soon", q->qname.c, DNSTypeName(q->qtype));
        return;
    }
#endif
    if (q->qtype == kDNSType_A)
        m->p->v4answers = 0;
    if (q->qtype == kDNSType_AAAA)
        m->p->v6answers = 0;
    if (!m->p->v4answers || !m->p->v6answers)
    {
        LogInfo("mDNSPlatformUpdateDNSStatus: Trigger needed v4 %d, v6 %d, question %##s (%s)", m->p->v4answers, m->p->v6answers, q->qname.c,
            DNSTypeName(q->qtype));
    }
}
#endif  // MDNSRESPONDER_SUPPORTS(APPLE, REACHABILITY_TRIGGER)

mDNSlocal void AckConfigd(dns_config_t *config)
{
    mDNS_CheckLock(&mDNSStorage);

    // Acking the configuration triggers configd to reissue the reachability queries
    mDNSStorage.p->DNSTrigger = NonZeroTime(mDNSStorage.timenow);
    _dns_configuration_ack(config, "com.apple.mDNSResponder");
}

#if MDNSRESPONDER_SUPPORTS(APPLE, REACHABILITY_TRIGGER)
// If v4q is non-NULL, it means we have received some answers for "A" type questions
// If v6q is non-NULL, it means we have received some answers for "AAAA" type questions
mDNSexport void mDNSPlatformTriggerDNSRetry(const DNSQuestion *v4q, const DNSQuestion *v6q)
{
    mDNS *const m = &mDNSStorage;
    mDNSBool trigger = mDNSfalse;
    mDNSs32 timenow;

    // Don't send triggers too often.
    // If we have started delivering answers to questions, we should send a trigger
    // if the time permits. If we are delivering answers, we should set the state
    // of v4answers/v6answers to 1 and avoid sending a trigger.  But, we don't know
    // whether the answers that are being delivered currently is for configd or some
    // other application. If we set the v4answers/v6answers to 1 and not deliver a trigger,
    // then we won't deliver the trigger later when it is okay to send one as the
    // "answers" are already set to 1. Hence, don't affect the state of v4answers and
    // v6answers if we are not delivering triggers.
    mDNS_Lock(m);
    timenow = m->timenow;
    if (m->p->DNSTrigger && (timenow - m->p->DNSTrigger) < DNS_TRIGGER_INTERVAL)
    {
        if (!m->p->v4answers || !m->p->v6answers)
        {
            debugf("mDNSPlatformTriggerDNSRetry: not triggering, time since last trigger %d ms, v4ans %d, v6ans %d",
                (timenow - m->p->DNSTrigger), m->p->v4answers, m->p->v6answers);
        }
        mDNS_Unlock(m);
        return;
    }
    mDNS_Unlock(m);
    if (v4q != NULL && QuestionValidForDNSTrigger(v4q))
    {
        int old = m->p->v4answers;

        m->p->v4answers = 1;

        // If there are IPv4 answers now and previously we did not have
        // any answers, trigger a DNS change so that reachability
        // can retry the queries again.
        if (!old)
        {
            LogInfo("mDNSPlatformTriggerDNSRetry: Triggering because of IPv4, last trigger %d ms, %##s (%s)", (timenow - m->p->DNSTrigger),
                v4q->qname.c, DNSTypeName(v4q->qtype));
            trigger = mDNStrue;
        }
    }
    if (v6q != NULL && QuestionValidForDNSTrigger(v6q))
    {
        int old = m->p->v6answers;

        m->p->v6answers = 1;
        // If there are IPv6 answers now and previously we did not have
        // any answers, trigger a DNS change so that reachability
        // can retry the queries again.
        if (!old)
        {
            LogInfo("mDNSPlatformTriggerDNSRetry: Triggering because of IPv6, last trigger %d ms, %##s (%s)", (timenow - m->p->DNSTrigger),
                v6q->qname.c, DNSTypeName(v6q->qtype));
            trigger = mDNStrue;
        }
    }
    if (trigger)
    {
        dns_config_t *config = dns_configuration_copy();
        if (config)
        {
            mDNS_Lock(m);
            AckConfigd(config);
            mDNS_Unlock(m);
            dns_configuration_free(config);
        }
        else
        {
            LogMsg("mDNSPlatformTriggerDNSRetry: ERROR!! configd did not return config");
        }
    }
}
#endif  // MDNSRESPONDER_SUPPORTS(APPLE, REACHABILITY_TRIGGER)

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DOTLOCAL)
mDNSlocal void SetupActiveDirectoryDomain(dns_config_t *config)
{
    // Record the so-called "primary" domain, which we use as a hint to tell if the user is on a network set up
    // by someone using Microsoft Active Directory using "local" as a private internal top-level domain
    if (config->n_resolver && config->resolver[0]->domain && config->resolver[0]->n_nameserver &&
        config->resolver[0]->nameserver[0])
    {
        MakeDomainNameFromDNSNameString(&ActiveDirectoryPrimaryDomain, config->resolver[0]->domain);
    }
    else
    {
         ActiveDirectoryPrimaryDomain.c[0] = 0;
    }

    //MakeDomainNameFromDNSNameString(&ActiveDirectoryPrimaryDomain, "test.local");
    ActiveDirectoryPrimaryDomainLabelCount = CountLabels(&ActiveDirectoryPrimaryDomain);
    if (config->n_resolver && config->resolver[0]->n_nameserver &&
        SameDomainName(SkipLeadingLabels(&ActiveDirectoryPrimaryDomain, ActiveDirectoryPrimaryDomainLabelCount - 1), &localdomain))
    {
        SetupAddr(&ActiveDirectoryPrimaryDomainServer, config->resolver[0]->nameserver[0]);
    }
    else
    {
        AssignConstStringDomainName(&ActiveDirectoryPrimaryDomain, "");
        ActiveDirectoryPrimaryDomainLabelCount = 0;
        ActiveDirectoryPrimaryDomainServer = zeroAddr;
    }
}
#endif

mDNSlocal void SetupDDNSDomains(domainname *const fqdn, DNameListElem **RegDomains, DNameListElem **BrowseDomains)
{
    int i;
    char buf[MAX_ESCAPED_DOMAIN_NAME];  // Max legal C-string name, including terminating NULL
    domainname d;

    CFDictionaryRef ddnsdict = SCDynamicStoreCopyValue(NULL, NetworkChangedKey_DynamicDNS);
    if (ddnsdict)
    {
        if (fqdn)
        {
            CFArrayRef fqdnArray = CFDictionaryGetValue(ddnsdict, CFSTR("HostNames"));
            if (fqdnArray && CFArrayGetCount(fqdnArray) > 0)
            {
                // for now, we only look at the first array element.  if we ever support multiple configurations, we will walk the list
                CFDictionaryRef fqdnDict = CFArrayGetValueAtIndex(fqdnArray, 0);
                if (fqdnDict && DictionaryIsEnabled(fqdnDict))
                {
                    CFStringRef name = CFDictionaryGetValue(fqdnDict, CFSTR("Domain"));
                    if (name)
                    {
                        if (!CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) ||
                            !MakeDomainNameFromDNSNameString(fqdn, buf) || !fqdn->c[0])
                            LogMsg("GetUserSpecifiedDDNSConfig SCDynamicStore bad DDNS host name: %s", buf[0] ? buf : "(unknown)");
                        else
                            debugf("GetUserSpecifiedDDNSConfig SCDynamicStore DDNS host name: %s", buf);
                    }
                }
            }
        }
        if (RegDomains)
        {
            CFArrayRef regArray = CFDictionaryGetValue(ddnsdict, CFSTR("RegistrationDomains"));
            if (regArray && CFArrayGetCount(regArray) > 0)
            {
                CFDictionaryRef regDict = CFArrayGetValueAtIndex(regArray, 0);
                if (regDict && DictionaryIsEnabled(regDict))
                {
                    CFStringRef name = CFDictionaryGetValue(regDict, CFSTR("Domain"));
                    if (name)
                    {
                        if (!CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) ||
                            !MakeDomainNameFromDNSNameString(&d, buf) || !d.c[0])
                            LogMsg("GetUserSpecifiedDDNSConfig SCDynamicStore bad DDNS registration domain: %s", buf[0] ? buf : "(unknown)");
                        else
                        {
                            debugf("GetUserSpecifiedDDNSConfig SCDynamicStore DDNS registration domain: %s", buf);
                            AppendDNameListElem(&RegDomains, 0, &d);
                        }
                    }
                }
            }
        }
        if (BrowseDomains)
        {
            CFArrayRef browseArray = CFDictionaryGetValue(ddnsdict, CFSTR("BrowseDomains"));
            if (browseArray)
            {
                for (i = 0; i < CFArrayGetCount(browseArray); i++)
                {
                    CFDictionaryRef browseDict = CFArrayGetValueAtIndex(browseArray, i);
                    if (browseDict && DictionaryIsEnabled(browseDict))
                    {
                        CFStringRef name = CFDictionaryGetValue(browseDict, CFSTR("Domain"));
                        if (name)
                        {
                            if (!CFStringGetCString(name, buf, sizeof(buf), kCFStringEncodingUTF8) ||
                                !MakeDomainNameFromDNSNameString(&d, buf) || !d.c[0])
                                LogMsg("GetUserSpecifiedDDNSConfig SCDynamicStore bad DDNS browsing domain: %s", buf[0] ? buf : "(unknown)");
                            else
                            {
                                debugf("GetUserSpecifiedDDNSConfig SCDynamicStore DDNS browsing domain: %s", buf);
                                AppendDNameListElem(&BrowseDomains, 0, &d);
                            }
                        }
                    }
                }
            }
        }
        MDNS_DISPOSE_CF_OBJECT(ddnsdict);
    }
}

// Returns mDNSfalse, if it does not set the configuration i.e., if the DNS configuration did not change
mDNSexport mDNSBool mDNSPlatformSetDNSConfig(mDNSBool setservers, mDNSBool setsearch, domainname *const fqdn,
                                             DNameListElem **RegDomains, DNameListElem **BrowseDomains, mDNSBool ackConfig)
{
    mDNS *const m = &mDNSStorage;
    MD5_CTX sdc;    // search domain context

    // Need to set these here because we need to do this even if SCDynamicStoreCreate() or SCDynamicStoreCopyValue() below don't succeed
    if (fqdn         ) fqdn->c[0]      = 0;
    if (RegDomains   ) *RegDomains     = NULL;
    if (BrowseDomains) *BrowseDomains  = NULL;

    // mDNSPlatformSetDNSConfig new updates -- setservers: yes, setsearch: no, fqdn: yes, RegDomains: no, BrowseDomains: no
    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
        "mDNSPlatformSetDNSConfig new updates -- setservers: " PUB_BOOL ", setsearch: " PUB_BOOL ", fqdn: " PUB_BOOL
        ", RegDomains: " PUB_BOOL ", BrowseDomains: " PUB_BOOL, setservers, setsearch, fqdn != mDNSNULL,
        RegDomains != mDNSNULL, BrowseDomains != mDNSNULL);

    if (setsearch) MD5_Init(&sdc);

    // Add the inferred address-based configuration discovery domains
    // (should really be in core code I think, not platform-specific)
    if (setsearch)
    {
        struct ifaddrs *ifa = mDNSNULL;
        struct sockaddr_in saddr;
        mDNSPlatformMemZero(&saddr, sizeof(saddr));
        saddr.sin_len = sizeof(saddr);
        saddr.sin_family = AF_INET;
        saddr.sin_port = 0;
        saddr.sin_addr.s_addr = *(in_addr_t *)&m->Router.ip.v4;

        // Don't add any reverse-IP search domains if doing the WAB bootstrap queries would cause dial-on-demand connection initiation
        if (!AddrRequiresPPPConnection((struct sockaddr *)&saddr)) ifa =  myGetIfAddrs(1);

        while (ifa)
        {
            mDNSAddr a, n;
            char buf[64];

            if (ifa->ifa_addr->sa_family == AF_INET &&
                ifa->ifa_netmask                    &&
                !(ifa->ifa_flags & IFF_LOOPBACK)    &&
                !SetupAddr(&a, ifa->ifa_addr)       &&
                !mDNSv4AddressIsLinkLocal(&a.ip.v4)  )
            {
                // Apparently it's normal for the sa_family of an ifa_netmask to sometimes be incorrect, so we explicitly fix it here before calling SetupAddr
                // <rdar://problem/5492035> getifaddrs is returning invalid netmask family for fw0 and vmnet
                ifa->ifa_netmask->sa_family = ifa->ifa_addr->sa_family;     // Make sure ifa_netmask->sa_family is set correctly
                SetupAddr(&n, ifa->ifa_netmask);
                // Note: This is reverse order compared to a normal dotted-decimal IP address, so we can't use our customary "%.4a" format code
                mDNS_snprintf(buf, sizeof(buf), "%d.%d.%d.%d.in-addr.arpa.", a.ip.v4.b[3] & n.ip.v4.b[3],
                              a.ip.v4.b[2] & n.ip.v4.b[2],
                              a.ip.v4.b[1] & n.ip.v4.b[1],
                              a.ip.v4.b[0] & n.ip.v4.b[0]);
                UpdateSearchDomainHash(&sdc, buf, NULL);
                mDNS_AddSearchDomain_CString(buf, mDNSNULL);
            }
            ifa = ifa->ifa_next;
        }
    }

#ifndef MDNS_NO_DNSINFO
    if (setservers || setsearch)
    {
        dns_config_t *config = dns_configuration_copy();
        if (!config)
        {
            // On 10.4, calls to dns_configuration_copy() early in the boot process often fail.
            // Apparently this is expected behaviour -- "not a bug".
            // Accordingly, we suppress syslog messages for the first three minutes after boot.
            // If we are still getting failures after three minutes, then we log them.
            if ((mDNSu32)mDNSPlatformRawTime() > (mDNSu32)(mDNSPlatformOneSecond * 180))
            {
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR,
                    "mDNSPlatformSetDNSConfig Error: dns_configuration_copy returned NULL");
            }
        }
        else
        {
            //  mDNSPlatformSetDNSConfig -- config->n_resolver: 7, this config generagtion: 10267971247541, last config generation: 10267774267674, changed: yes
            LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT, "mDNSPlatformSetDNSConfig -- "
                "config->n_resolver: %d, this config generagtion: %llu, last config generation: %llu, changed: " PUB_BOOL,
                config->n_resolver, config->generation, m->p->LastConfigGeneration,
                (config->generation != m->p->LastConfigGeneration));

            // For every network change, mDNSPlatformSetDNSConfig is called twice. First,
            // to update the search domain list (in which case, the setsearch bool is set);
            // and second, to update the DNS server list (in which case, the setservers bool
            // is set). The code assumes only one of these flags, setsearch or setserver,
            // will be set when mDNSPlatformSetDNSConfig is called to handle a network change.
            // The mDNSPlatformSetDNSConfig function also assumes that ackCfg will be set
            // when setservers is set.

            // The search domains update occurs on every network change to avoid sync issues
            // that may occur if a network change happens during the processing
            // of a network change.  The dns servers update occurs when the DNS config
            // changes. The dns servers stay in sync by saving the config's generation number
            // on every update; and only updating when the generation number changes.

            // If this is a DNS server update and the configuration hasn't changed, then skip update
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
            if (setservers && m->p->LastConfigGeneration == config->generation)
#else
            if (setservers && !m->p->if_interface_changed && m->p->LastConfigGeneration == config->generation)
#endif
            {
                dns_configuration_free(config);
                SetupDDNSDomains(fqdn, RegDomains, BrowseDomains);
                return mDNSfalse;
            }
#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
            if (setservers) {
                // Must check if setservers is true, because mDNSPlatformSetDNSConfig can be called for multiple times
                // with setservers equals to false. If setservers is false, we will end up with clearing if_interface_changed
                // without really updating the server.
                m->p->if_interface_changed = mDNSfalse;
            }
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, UNICAST_DOTLOCAL)
            SetupActiveDirectoryDomain(config);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
            if (setservers) Querier_ApplyDNSConfig(config);
#endif
            ConfigResolvers(config, kScopeNone, setsearch, setservers, &sdc);
            ConfigResolvers(config, kScopeInterfaceID, setsearch, setservers, &sdc);
            ConfigResolvers(config, kScopeServiceID, setsearch, setservers, &sdc);

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
            const CFIndex n = m->p->InterfaceMonitors ? CFArrayGetCount(m->p->InterfaceMonitors) : 0;
            for (CFIndex i = n - 1; i >= 0; i--)
            {
                mdns_interface_monitor_t monitor;
                monitor = (mdns_interface_monitor_t) CFArrayGetValueAtIndex(m->p->InterfaceMonitors, i);
                const uint32_t ifIndex = mdns_interface_monitor_get_interface_index(monitor);
                DNSServer *server;
                for (server = m->DNSServers; server; server = server->next)
                {
                    if ((((uintptr_t)server->interface) == ifIndex) && !(server->flags & DNSServerFlag_Delete))
                    {
                        break;
                    }
                }
                if (!server)
                {
                    mdns_retain(monitor);
                    CFArrayRemoveValueAtIndex(m->p->InterfaceMonitors, i);
                    mdns_interface_monitor_invalidate(monitor);
                    mdns_release(monitor);
                }
            }
#endif
            // Acking provides a hint to other processes that the current DNS configuration has completed
            // its update.  When configd receives the ack, it publishes a notification.
            // Applications monitoring the notification then know when to re-issue their DNS queries
            // after a network change occurs.
            if (ackConfig)
            {
                // Note: We have to set the generation number here when we are acking.
                // For every DNS configuration change, we do the following:
                //
                // 1) Copy dns configuration, handle search domains change
                // 2) Copy dns configuration, handle dns server change
                //
                // If we update the generation number at step (1), we won't process the
                // DNS servers the second time because generation number would be the same.
                // As we ack only when we process dns servers, we set the generation number
                // during acking.
                m->p->LastConfigGeneration = config->generation;
                LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT, "mDNSPlatformSetDNSConfig: acking configuration");
                AckConfigd(config);
            }
            dns_configuration_free(config);
            if (setsearch) FinalizeSearchDomainHash(&sdc);
        }
    }
#endif // MDNS_NO_DNSINFO
    SetupDDNSDomains(fqdn, RegDomains, BrowseDomains);
    return mDNStrue;
}


mDNSexport mStatus mDNSPlatformGetPrimaryInterface(mDNSAddr *v4, mDNSAddr *v6, mDNSAddr *r)
{
    char buf[256];

    CFDictionaryRef dict = SCDynamicStoreCopyValue(NULL, NetworkChangedKey_IPv4);
    if (dict)
    {
        r->type  = mDNSAddrType_IPv4;
        r->ip.v4 = zerov4Addr;
        CFStringRef string = CFDictionaryGetValue(dict, kSCPropNetIPv4Router);
        if (string)
        {
            if (!CFStringGetCString(string, buf, 256, kCFStringEncodingUTF8))
                LogMsg("Could not convert router to CString");
            else
            {
                struct sockaddr_in saddr;
                saddr.sin_len = sizeof(saddr);
                saddr.sin_family = AF_INET;
                saddr.sin_port = 0;
                inet_aton(buf, &saddr.sin_addr);
                *(in_addr_t *)&r->ip.v4 = saddr.sin_addr.s_addr;
            }
        }
        string = CFDictionaryGetValue(dict, kSCDynamicStorePropNetPrimaryInterface);
        if (string)
        {
            mDNSBool HavePrimaryGlobalv6 = mDNSfalse;  // does the primary interface have a global v6 address?
            struct ifaddrs *ifa = myGetIfAddrs(1);
            *v4 = *v6 = zeroAddr;

            if (!CFStringGetCString(string, buf, 256, kCFStringEncodingUTF8))
            {
                LogMsg("Could not convert router to CString");
                goto exit;
            }
            // find primary interface in list
            while (ifa && (mDNSIPv4AddressIsZero(v4->ip.v4) || mDNSv4AddressIsLinkLocal(&v4->ip.v4) || !HavePrimaryGlobalv6))
            {
                if (!ifa->ifa_addr)
                {
                    LogMsg("Skip interface, %s, since ifa_addr is not set.", (ifa->ifa_name) ? ifa->ifa_name: "name not found");
                    ifa = ifa->ifa_next;
                    continue;
                }
                mDNSAddr tmp6 = zeroAddr;
                if (!strcmp(buf, ifa->ifa_name))
                {
                    if (ifa->ifa_addr->sa_family == AF_INET)
                    {
                        if (mDNSIPv4AddressIsZero(v4->ip.v4) || mDNSv4AddressIsLinkLocal(&v4->ip.v4))
                            SetupAddr(v4, ifa->ifa_addr);
                    }
                    else if (ifa->ifa_addr->sa_family == AF_INET6)
                    {
                        SetupAddr(&tmp6, ifa->ifa_addr);
                        if (tmp6.ip.v6.b[0] >> 5 == 1)   // global prefix: 001
                        {
                            HavePrimaryGlobalv6 = mDNStrue;
                            *v6 = tmp6;
                        }
                    }
                }
                else
                {
                    // We'll take a V6 address from the non-primary interface if the primary interface doesn't have a global V6 address
                    if (!HavePrimaryGlobalv6 && ifa->ifa_addr->sa_family == AF_INET6 && !v6->ip.v6.b[0])
                    {
                        SetupAddr(&tmp6, ifa->ifa_addr);
                        if (tmp6.ip.v6.b[0] >> 5 == 1)
                            *v6 = tmp6;
                    }
                }
                ifa = ifa->ifa_next;
            }
            // Note that while we advertise v6, we still require v4 (possibly NAT'd, but not link-local) because we must use
            // V4 to communicate w/ our DNS server
        }

exit:
        MDNS_DISPOSE_CF_OBJECT(dict);
    }
    return mStatus_NoError;
}

mDNSexport void mDNSPlatformDynDNSHostNameStatusChanged(const domainname *const dname, const mStatus status)
{
    LogInfo("mDNSPlatformDynDNSHostNameStatusChanged %d %##s", status, dname->c);
    char uname[MAX_ESCAPED_DOMAIN_NAME];    // Max legal C-string name, including terminating NUL
    ConvertDomainNameToCString(dname, uname);

    char *p = uname;
    while (*p)
    {
        *p = tolower(*p);
        if (!(*(p+1)) && *p == '.') *p = 0; // if last character, strip trailing dot
        p++;
    }

    // We need to make a CFDictionary called "State:/Network/DynamicDNS" containing (at present) a single entity.
    // That single entity is a CFDictionary with name "HostNames".
    // The "HostNames" CFDictionary contains a set of name/value pairs, where the each name is the FQDN
    // in question, and the corresponding value is a CFDictionary giving the state for that FQDN.
    // (At present we only support a single FQDN, so this dictionary holds just a single name/value pair.)
    // The CFDictionary for each FQDN holds (at present) a single name/value pair,
    // where the name is "Status" and the value is a CFNumber giving an errror code (with zero meaning success).

    const CFStringRef StateKeys [1] = { CFSTR("HostNames") };
    CFStringRef HostKeys  [1] = { CFStringCreateWithCString(NULL, uname, kCFStringEncodingUTF8) };
    const CFStringRef StatusKeys[1] = { CFSTR("Status") };
    if (!HostKeys[0]) LogMsg("SetDDNSNameStatus: CFStringCreateWithCString(%s) failed", uname);
    else
    {
        CFNumberRef StatusVals[1] = { CFNumberCreate(NULL, kCFNumberSInt32Type, &status) };
        if (StatusVals[0] == NULL) LogMsg("SetDDNSNameStatus: CFNumberCreate(%d) failed", status);
        else
        {
            CFDictionaryRef HostVals[1] = { CFDictionaryCreate(NULL, (void*)StatusKeys, (void*)StatusVals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) };
            if (HostVals[0])
            {
                CFDictionaryRef StateVals[1] = { CFDictionaryCreate(NULL, (void*)HostKeys, (void*)HostVals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) };
                if (StateVals[0])
                {
                    CFDictionaryRef StateDict = CFDictionaryCreate(NULL, (void*)StateKeys, (void*)StateVals, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                    if (StateDict)
                    {
                        mDNSDynamicStoreSetConfig(kmDNSDynamicConfig, mDNSNULL, StateDict);
                        MDNS_DISPOSE_CF_OBJECT(StateDict);
                    }
                    MDNS_DISPOSE_CF_OBJECT(StateVals[0]);
                }
                MDNS_DISPOSE_CF_OBJECT(HostVals[0]);
            }
            MDNS_DISPOSE_CF_OBJECT(StatusVals[0]);
        }
        MDNS_DISPOSE_CF_OBJECT(HostKeys[0]);
    }
}

// MUST be called holding the lock
mDNSlocal void SetDomainSecrets_internal(mDNS *m)
{
#ifdef NO_SECURITYFRAMEWORK
        (void) m;
    LogMsg("Note: SetDomainSecrets: no keychain support");
#else

    LogInfo("SetDomainSecrets");

    // Rather than immediately deleting all keys now, we mark them for deletion in ten seconds.
    // In the case where the user simultaneously removes their DDNS host name and the key
    // for it, this gives mDNSResponder ten seconds to gracefully delete the name from the
    // server before it loses access to the necessary key. Otherwise, we'd leave orphaned
    // address records behind that we no longer have permission to delete.
    DomainAuthInfo *ptr;
    for (ptr = m->AuthInfoList; ptr; ptr = ptr->next)
        ptr->deltime = NonZeroTime(m->timenow + mDNSPlatformOneSecond*10);

    // String Array used to write list of private domains to Dynamic Store
    CFMutableArrayRef sa = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    if (!sa) { LogMsg("SetDomainSecrets: CFArrayCreateMutable failed"); return; }
    CFIndex i;
    CFDataRef data = NULL;
    const int itemsPerEntry = 4; // domain name, key name, key value, Name value
    CFArrayRef secrets = NULL;
    int err = mDNSKeychainGetSecrets(&secrets);
    if (err || !secrets)
        LogMsg("SetDomainSecrets: mDNSKeychainGetSecrets failed error %d CFArrayRef %p", err, secrets);
    else
    {
        CFIndex ArrayCount = CFArrayGetCount(secrets);
        // Iterate through the secrets
        for (i = 0; i < ArrayCount; ++i)
        {
            int j;
            size_t offset;
            CFArrayRef entry = CFArrayGetValueAtIndex(secrets, i);
            if (CFArrayGetTypeID() != CFGetTypeID(entry) || itemsPerEntry != CFArrayGetCount(entry))
            { LogMsg("SetDomainSecrets: malformed entry %d, itemsPerEntry %d", i, itemsPerEntry); continue; }
            for (j = 0; j < CFArrayGetCount(entry); ++j)
                if (CFDataGetTypeID() != CFGetTypeID(CFArrayGetValueAtIndex(entry, j)))
                { LogMsg("SetDomainSecrets: malformed entry item %d", j); continue; }

            // The names have already been vetted by the helper, but checking them again here helps humans and automated tools verify correctness

            // Max legal domainname as C-string, including space for dnsprefix and terminating NUL
            // Get DNS domain this key is for (kmDNSKcWhere)
            char stringbuf[MAX_ESCAPED_DOMAIN_NAME + sizeof(dnsprefix)];
            data = CFArrayGetValueAtIndex(entry, kmDNSKcWhere);
            if (CFDataGetLength(data) >= (int)sizeof(stringbuf))
            { LogMsg("SetDomainSecrets: Bad kSecServiceItemAttr length %d", CFDataGetLength(data)); continue; }
            CFDataGetBytes(data, CFRangeMake(0, CFDataGetLength(data)), (UInt8 *)stringbuf);
            stringbuf[CFDataGetLength(data)] = '\0';

            offset = 0;
            if (!strncmp(stringbuf, dnsprefix, strlen(dnsprefix)))
                offset = strlen(dnsprefix);

            domainname domain;
            if (!MakeDomainNameFromDNSNameString(&domain, stringbuf + offset)) { LogMsg("SetDomainSecrets: bad key domain %s", stringbuf); continue; }

            // Get key name (kmDNSKcAccount)
            data = CFArrayGetValueAtIndex(entry, kmDNSKcAccount);
            if (CFDataGetLength(data) >= (int)sizeof(stringbuf))
            { LogMsg("SetDomainSecrets: Bad kSecAccountItemAttr length %d", CFDataGetLength(data)); continue; }
            CFDataGetBytes(data, CFRangeMake(0,CFDataGetLength(data)), (UInt8 *)stringbuf);
            stringbuf[CFDataGetLength(data)] = '\0';

            domainname keyname;
            if (!MakeDomainNameFromDNSNameString(&keyname, stringbuf)) { LogMsg("SetDomainSecrets: bad key name %s", stringbuf); continue; }

            // Get key data (kmDNSKcKey)
            data = CFArrayGetValueAtIndex(entry, kmDNSKcKey);
            if (CFDataGetLength(data) >= (int)sizeof(stringbuf))
            {
                LogMsg("SetDomainSecrets: Shared secret too long: %d", CFDataGetLength(data));
                continue;
            }
            CFDataGetBytes(data, CFRangeMake(0, CFDataGetLength(data)), (UInt8 *)stringbuf);
            stringbuf[CFDataGetLength(data)] = '\0';    // mDNS_SetSecretForDomain requires NULL-terminated C string for key

            // Get the Name of the keychain entry (kmDNSKcName) host or host:port
            // The hostname also has the port number and ":". It should take a maximum of 6 bytes.
            char hostbuf[MAX_ESCAPED_DOMAIN_NAME + 6];  // Max legal domainname as C-string, including terminating NUL
            data = CFArrayGetValueAtIndex(entry, kmDNSKcName);
            if (CFDataGetLength(data) >= (int)sizeof(hostbuf))
            {
                LogMsg("SetDomainSecrets: host:port data too long: %d", CFDataGetLength(data));
                continue;
            }
            CFDataGetBytes(data, CFRangeMake(0,CFDataGetLength(data)), (UInt8 *)hostbuf);
            hostbuf[CFDataGetLength(data)] = '\0';

            domainname hostname;
            mDNSIPPort port;
            char *hptr;
            hptr = strchr(hostbuf, ':');

            port.NotAnInteger = 0;
            if (hptr)
            {
                mDNSu8 *p;
                mDNSu16 val = 0;

                *hptr++ = '\0';
                while(hptr && *hptr != 0)
                {
                    if (*hptr < '0' || *hptr > '9')
                    { LogMsg("SetDomainSecrets: Malformed Port number %d, val %d", *hptr, val); val = 0; break;}
                    val = val * 10 + *hptr - '0';
                    hptr++;
                }
                if (!val) continue;
                p = (mDNSu8 *)&val;
                port.NotAnInteger = p[0] << 8 | p[1];
            }
            // The hostbuf is of the format dsid@hostname:port. We don't care about the dsid.
            hptr = strchr(hostbuf, '@');
            if (hptr)
                hptr++;
            else
                hptr = hostbuf;
            if (!MakeDomainNameFromDNSNameString(&hostname, hptr)) { LogMsg("SetDomainSecrets: bad host name %s", hptr); continue; }

            DomainAuthInfo *FoundInList;
            for (FoundInList = m->AuthInfoList; FoundInList; FoundInList = FoundInList->next)
                if (SameDomainName(&FoundInList->domain, &domain)) break;

            // Uncomment the line below to view the keys as they're read out of the system keychain
            // DO NOT SHIP CODE THIS WAY OR YOU'LL LEAK SECRET DATA INTO A PUBLICLY READABLE FILE!
            //LogInfo("SetDomainSecrets: domain %##s keyname %##s key %s hostname %##s port %d", &domain.c, &keyname.c, stringbuf, hostname.c, (port.b[0] << 8 | port.b[1]));
            LogInfo("SetDomainSecrets: domain %##s keyname %##s hostname %##s port %d", &domain.c, &keyname.c, hostname.c, (port.b[0] << 8 | port.b[1]));

            // If didn't find desired domain in the list, make a new entry
            ptr = FoundInList;
            if (!FoundInList)
            {
                ptr = (DomainAuthInfo*) callocL("DomainAuthInfo", sizeof(*ptr));
                if (!ptr) { LogMsg("SetDomainSecrets: No memory"); continue; }
            }

            if (mDNS_SetSecretForDomain(m, ptr, &domain, &keyname, stringbuf, &hostname, &port) == mStatus_BadParamErr)
            {
                if (!FoundInList) mDNSPlatformMemFree(ptr);     // If we made a new DomainAuthInfo here, and it turned out bad, dispose it immediately
                continue;
            }

            ConvertDomainNameToCString(&domain, stringbuf);
            CFStringRef cfs = CFStringCreateWithCString(NULL, stringbuf, kCFStringEncodingUTF8);
            if (cfs) { CFArrayAppendValue(sa, cfs); MDNS_DISPOSE_CF_OBJECT(cfs); }
        }
        MDNS_DISPOSE_CF_OBJECT(secrets);
    }

    if (!privateDnsArray || !CFEqual(privateDnsArray, sa))
    {
        MDNS_DISPOSE_CF_OBJECT(privateDnsArray);

        privateDnsArray = sa;
        CFRetain(privateDnsArray);
        mDNSDynamicStoreSetConfig(kmDNSPrivateConfig, mDNSNULL, privateDnsArray);
    }
    MDNS_DISPOSE_CF_OBJECT(sa);

    CheckSuppressUnusableQuestions(m);

#endif /* NO_SECURITYFRAMEWORK */
}

mDNSexport void SetDomainSecrets(mDNS *m)
{
#if DEBUG
    // Don't get secrets for BTMM if running in debug mode
    if (!IsDebugSocketInUse())
#endif
    SetDomainSecrets_internal(m);
}

mDNSlocal void SetLocalDomains(void)
{
    CFMutableArrayRef sa = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    if (!sa) { LogMsg("SetLocalDomains: CFArrayCreateMutable failed"); return; }

    CFArrayAppendValue(sa, CFSTR("local"));
    CFArrayAppendValue(sa, CFSTR("254.169.in-addr.arpa"));
    CFArrayAppendValue(sa, CFSTR("8.e.f.ip6.arpa"));
    CFArrayAppendValue(sa, CFSTR("9.e.f.ip6.arpa"));
    CFArrayAppendValue(sa, CFSTR("a.e.f.ip6.arpa"));
    CFArrayAppendValue(sa, CFSTR("b.e.f.ip6.arpa"));

    mDNSDynamicStoreSetConfig(kmDNSMulticastConfig, mDNSNULL, sa);
    MDNS_DISPOSE_CF_OBJECT(sa);
}

#if !MDNSRESPONDER_SUPPORTS(APPLE, NO_WAKE_FOR_NET_ACCESS)
mDNSlocal void GetCurrentPMSetting(const CFStringRef name, mDNSs32 *val)
{
    CFDictionaryRef dict = SCDynamicStoreCopyValue(NULL, NetworkChangedKey_PowerSettings);
    if (!dict)
    {
        LogSPS("GetCurrentPMSetting: Could not get IOPM CurrentSettings dict");
    }
    else
    {
        CFNumberRef number = CFDictionaryGetValue(dict, name);
        if ((number == NULL) || CFGetTypeID(number) != CFNumberGetTypeID() || !CFNumberGetValue(number, kCFNumberSInt32Type, val))
            *val = 0;
        MDNS_DISPOSE_CF_OBJECT(dict);
    }
}
#endif


mDNSlocal mDNSu8 SystemWakeForNetworkAccess(void)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, NO_WAKE_FOR_NET_ACCESS)
    LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_DEBUG, "SystemWakeForNetworkAccess: compile-time disabled");
    return ((mDNSu8)mDNS_NoWake);
#else
    mDNSs32 val = 0;
    mDNSu8  ret = (mDNSu8)mDNS_NoWake;

    if (DisableSleepProxyClient)
    {
       LogSPS("SystemWakeForNetworkAccess: Sleep Proxy Client disabled by command-line option");
       return ret;
    }

    GetCurrentPMSetting(CFSTR("Wake On LAN"), &val);

    ret = (mDNSu8)(val != 0) ? mDNS_WakeOnAC : mDNS_NoWake;


    LogSPS("SystemWakeForNetworkAccess: Wake On LAN: %d", ret);
    return ret;
#endif
}

mDNSlocal mDNSBool SystemSleepOnlyIfWakeOnLAN(void)
{
    mDNSs32 val = 0;
    // PrioritizeNetworkReachabilityOverSleep has been deprecated.
    // GetCurrentPMSetting(CFSTR("PrioritizeNetworkReachabilityOverSleep"), &val);
    // Statically set the PrioritizeNetworkReachabilityOverSleep value to 1 for AppleTV
    if (IsAppleTV())
        val = 1;
    return val != 0 ? mDNStrue : mDNSfalse;
}

mDNSlocal mDNSBool IsAppleNetwork(mDNS *const m)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    (void)m;
#else
    DNSServer *s;
    // Determine if we're on AppleNW based on DNSServer having 17.x.y.z IPv4 addr
    for (s = m->DNSServers; s; s = s->next)
    {
        if (s->addr.ip.v4.b[0] == 17)
        {
            LogInfo("IsAppleNetwork: Found 17.x.y.z DNSServer concluding that we are on AppleNW: %##s %#a", s->domain.c, &s->addr);
            return mDNStrue;
        }
    }
#endif
    return mDNSfalse;
}

// Called with KQueueLock & mDNS lock
// SetNetworkChanged is allowed to shorten (but not extend) the pause while we wait for configuration changes to settle
mDNSlocal void SetNetworkChanged(mDNSs32 delay)
{
    mDNS *const m = &mDNSStorage;
    mDNS_CheckLock(m);
    if (!m->NetworkChanged || m->NetworkChanged - NonZeroTime(m->timenow + delay) > 0)
    {
        m->NetworkChanged = NonZeroTime(m->timenow + delay);
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT, "SetNetworkChanged: Scheduling in %d ticks", delay);
    }
    else
   	{
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
            "SetNetworkChanged: *NOT* increasing delay from %d to %d", m->NetworkChanged - m->timenow, delay);
    }
}

// Called with KQueueLock & mDNS lock
mDNSlocal void SetKeyChainTimer(mDNSs32 delay)
{
    mDNS *const m = &mDNSStorage;
    // If it's not set or it needs to happen sooner than when it's currently set
    if (!m->p->KeyChainTimer || m->p->KeyChainTimer - NonZeroTime(m->timenow + delay) > 0)
    {
        m->p->KeyChainTimer = NonZeroTime(m->timenow + delay);
        LogInfo("SetKeyChainTimer: %d", delay);
    }
}

mDNSexport void mDNSMacOSXNetworkChanged(void)
{
    mDNS *const m = &mDNSStorage;
    const mDNSs32 delay = m->NetworkChanged ? mDNS_TimeNow(m) - m->NetworkChanged : 0;
    LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
        "*** Network Configuration Change *** -- network changed: " PUB_BOOL ", delay: %d ticks",
        BOOL_PARAM(m->NetworkChanged), delay);
    m->NetworkChanged = 0;       // If we received a network change event and deferred processing, we're now dealing with it

    // If we have *any* TENTATIVE IPv6 addresses, wait until they've finished configuring
    int InfoSocket = socket(AF_INET6, SOCK_DGRAM, 0);
    if (InfoSocket > 0)
    {
        mDNSBool tentative = mDNSfalse;
        struct ifaddrs *ifa = myGetIfAddrs(1);
        while (ifa)
        {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET6)
            {
                struct in6_ifreq ifr6;
                mDNSPlatformMemZero((char *)&ifr6, sizeof(ifr6));
                mdns_strlcpy(ifr6.ifr_name, ifa->ifa_name, sizeof(ifr6.ifr_name));
                ifr6.ifr_addr = *(struct sockaddr_in6 *)ifa->ifa_addr;
                // We need to check for IN6_IFF_TENTATIVE here, not IN6_IFF_NOTREADY, because
                // IN6_IFF_NOTREADY includes both IN6_IFF_TENTATIVE and IN6_IFF_DUPLICATED addresses.
                // We can expect that an IN6_IFF_TENTATIVE address will shortly become ready,
                // but an IN6_IFF_DUPLICATED address may not.
                if (ioctl(InfoSocket, SIOCGIFAFLAG_IN6, &ifr6) != -1)
                {
                    if (ifr6.ifr_ifru.ifru_flags6 & IN6_IFF_TENTATIVE)
                    {
                        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                            "*** Network Configuration Change ***  IPv6 address " PRI_IPv6_ADDR " TENTATIVE, will retry",
                            &ifr6.ifr_addr.sin6_addr);
                        tentative = mDNStrue;
                        // no need to check other interfaces if we already found out that one interface is TENTATIVE
                        break;
                    }
                }
            }
            ifa = ifa->ifa_next;
        }
        close(InfoSocket);
        if (tentative)
        {
            mDNS_Lock(m);
            SetNetworkChanged(mDNSPlatformOneSecond / 2);
            mDNS_Unlock(m);
            return;
        }
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
            "*** Network Configuration Change ***  No IPv6 address TENTATIVE, will continue");
    }

    mDNSs32 utc = mDNSPlatformUTC();
    m->SystemWakeOnLANEnabled = SystemWakeForNetworkAccess();
    m->SystemSleepOnlyIfWakeOnLAN = SystemSleepOnlyIfWakeOnLAN();
    MarkAllInterfacesInactive(utc);
    UpdateInterfaceList(utc);
    ClearInactiveInterfaces(utc);
    SetupActiveInterfaces(utc);
    ReorderInterfaceList();


    uDNS_SetupDNSConfig(m);
    mDNS_ConfigChanged(m);

    if (IsAppleNetwork(m) != mDNS_McastTracingEnabled)
    {
        mDNS_McastTracingEnabled = mDNS_McastTracingEnabled ? mDNSfalse : mDNStrue;
        LogInfo("mDNSMacOSXNetworkChanged: Multicast Tracing %s", mDNS_McastTracingEnabled ? "Enabled" : "Disabled");
        UpdateDebugState();
    }

}

// Copy the fourth slash-delimited element from either:
//   State:/Network/Interface/<bsdname>/IPv4
// or
//   Setup:/Network/Service/<servicename>/Interface
mDNSlocal CFStringRef CopyNameFromKey(CFStringRef key)
{
    CFArrayRef a;
    CFStringRef name = NULL;

    a = CFStringCreateArrayBySeparatingStrings(NULL, key, CFSTR("/"));
    if (a && CFArrayGetCount(a) == 5) name = CFRetain(CFArrayGetValueAtIndex(a, 3));
    if (a != NULL) MDNS_DISPOSE_CF_OBJECT(a);

    return name;
}

// Whether a key from a network change notification corresponds to
// an IP service that is explicitly configured for IPv4 Link Local
mDNSlocal int ChangedKeysHaveIPv4LL(CFArrayRef inkeys)
{
    CFDictionaryRef dict = NULL;
    CFMutableArrayRef a;
    const void **keys = NULL, **vals = NULL;
    CFStringRef pattern = NULL;
    CFIndex i, ic, j, jc;
    int found = 0;

    jc = CFArrayGetCount(inkeys);
    if (jc <= 0) goto done;

    a = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    if (a == NULL) goto done;

    // Setup:/Network/Service/[^/]+/Interface
    pattern = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainSetup, kSCCompAnyRegex, kSCEntNetInterface);
    if (pattern == NULL) goto done;
    CFArrayAppendValue(a, pattern);
    MDNS_DISPOSE_CF_OBJECT(pattern);

    // Setup:/Network/Service/[^/]+/IPv4
    pattern = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainSetup, kSCCompAnyRegex, kSCEntNetIPv4);
    if (pattern == NULL) goto done;
    CFArrayAppendValue(a, pattern);
    MDNS_DISPOSE_CF_OBJECT(pattern);

    dict = SCDynamicStoreCopyMultiple(NULL, NULL, a);
    MDNS_DISPOSE_CF_OBJECT(a);

    if (!dict)
    {
        goto done;
    }

    ic = CFDictionaryGetCount(dict);
    if (ic <= 0)
    {
        goto done;
    }

    vals = (const void **) mDNSPlatformMemAllocate(sizeof(void *) * (mDNSu32)ic);
    keys = (const void **) mDNSPlatformMemAllocate(sizeof(void *) * (mDNSu32)ic);
    CFDictionaryGetKeysAndValues(dict, keys, vals);

    // For each key we were given...
    for (j = 0; j < jc; j++)
    {
        CFStringRef key = CFArrayGetValueAtIndex(inkeys, j);
        CFStringRef ifname = NULL;

        char buf[256];

        // It would be nice to use a regex here
        if (!CFStringHasPrefix(key, CFSTR("State:/Network/Interface/")) || !CFStringHasSuffix(key, kSCEntNetIPv4)) continue;

        if ((ifname = CopyNameFromKey(key)) == NULL) continue;
        if (mDNS_LoggingEnabled)
        {
            if (!CFStringGetCString(ifname, buf, sizeof(buf), kCFStringEncodingUTF8)) buf[0] = 0;
        }

        // Loop over the interfaces to find matching the ifname, and see if that one has kSCValNetIPv4ConfigMethodLinkLocal
        for (i = 0; i < ic; i++)
        {
            CFDictionaryRef ipv4dict;
            CFStringRef name;
            CFStringRef serviceid;
            CFStringRef configmethod;

            if (!CFStringHasSuffix(keys[i], kSCEntNetInterface)) continue;

            if (CFDictionaryGetTypeID() != CFGetTypeID(vals[i])) continue;

            if ((name = CFDictionaryGetValue(vals[i], kSCPropNetInterfaceDeviceName)) == NULL) continue;

            if (!CFEqual(ifname, name)) continue;

            if ((serviceid = CopyNameFromKey(keys[i])) == NULL) continue;

            pattern = SCDynamicStoreKeyCreateNetworkServiceEntity(NULL, kSCDynamicStoreDomainSetup, serviceid, kSCEntNetIPv4);
            MDNS_DISPOSE_CF_OBJECT(serviceid);
            if (pattern == NULL) continue;

            ipv4dict = CFDictionaryGetValue(dict, pattern);
            MDNS_DISPOSE_CF_OBJECT(pattern);
            if (!ipv4dict || CFDictionaryGetTypeID() != CFGetTypeID(ipv4dict)) continue;

            configmethod = CFDictionaryGetValue(ipv4dict, kSCPropNetIPv4ConfigMethod);
            if (!configmethod) continue;

            if (CFEqual(configmethod, kSCValNetIPv4ConfigMethodLinkLocal)) { found++; break; }
        }

        MDNS_DISPOSE_CF_OBJECT(ifname);
    }

done:
    if (vals != NULL) mDNSPlatformMemFree(vals);
    if (keys != NULL) mDNSPlatformMemFree(keys);
    MDNS_DISPOSE_CF_OBJECT(dict);

    return found;
}

mDNSlocal mDNSNetworkChangeEventFlags_t GetNetworkChangeEventFlags(const mDNSBool c_host, const mDNSBool c_comp,
    const mDNSBool c_udns, const mDNSBool c_ddns, const mDNSBool c_v4ll, const mDNSBool c_fast)
{
    mDNSNetworkChangeEventFlags_t opts = mDNSNetworkChangeEventFlag_None;
    if (c_host)
    {
        opts |= mDNSNetworkChangeEventFlag_LocalHostname;
    }
    if (c_comp)
    {
        opts |= mDNSNetworkChangeEventFlag_ComputerName;
    }
    if (c_udns)
    {
        opts |= mDNSNetworkChangeEventFlag_DNS;
    }
    if (c_ddns)
    {
        opts |= mDNSNetworkChangeEventFlag_DynamicDNS;
    }
    if (c_v4ll)
    {
        opts |= mDNSNetworkChangeEventFlag_IPv4LL;
    }
    if (c_fast)
    {
        opts |= mDNSNetworkChangeEventFlag_P2PLike;
    }
    return opts;
}

mDNSlocal void NetworkChanged(SCDynamicStoreRef store, CFArrayRef changedKeys, void *context)
{
    (void)store;        // Parameter not used
    mDNS *const m = (mDNS *const)context;
    KQueueLock();
    mDNS_Lock(m);

    //mDNSs32 delay = mDNSPlatformOneSecond * 2;                // Start off assuming a two-second delay
    const mDNSs32 delay = (mDNSPlatformOneSecond + 39) / 40;    // 25 ms delay

    const CFIndex c = CFArrayGetCount(changedKeys);             // Count changes
    CFRange range = { 0, c };
    const int c_host = (CFArrayContainsValue(changedKeys, range, NetworkChangedKey_Hostnames   ) != 0);
    const int c_comp = (CFArrayContainsValue(changedKeys, range, NetworkChangedKey_Computername) != 0);
    const int c_udns = (CFArrayContainsValue(changedKeys, range, NetworkChangedKey_DNS         ) != 0);
    const int c_ddns = (CFArrayContainsValue(changedKeys, range, NetworkChangedKey_DynamicDNS  ) != 0);
    const int c_v4ll = ChangedKeysHaveIPv4LL(changedKeys);
    int c_fast = 0;

    // Do immediate network changed processing for "p2p*" interfaces and
    // for interfaces with the IFEF_DIRECTLINK or IFEF_AWDL flag set or association with a CarPlay
    // hosted SSID.
    {
        CFArrayRef  labels;
        CFIndex     n;
        for (CFIndex i = 0; i < c; i++)
        {
            CFStringRef key = CFArrayGetValueAtIndex(changedKeys, i);

            // Only look at keys with prefix "State:/Network/Interface/"
            if (!CFStringHasPrefix(key, NetworkChangedKey_StateInterfacePrefix))
                continue;

            // And suffix "IPv6" or "IPv4".
            if (!CFStringHasSuffix(key, kSCEntNetIPv6) && !CFStringHasSuffix(key, kSCEntNetIPv4))
                continue;

            labels = CFStringCreateArrayBySeparatingStrings(NULL, key, CFSTR("/"));
            if (labels == NULL)
                break;
            n = CFArrayGetCount(labels);

            // Interface changes will have keys of the form:
            //     State:/Network/Interface/<interfaceName>/IPv6
            // Thus five '/' seperated fields, the 4th one being the <interfaceName> string.
            if (n == 5)
            {
                char buf[256];

                // The 4th label (index = 3) should be the interface name.
                if (CFStringGetCString(CFArrayGetValueAtIndex(labels, 3), buf, sizeof(buf), kCFStringEncodingUTF8)
                    && (strstr(buf, "p2p") || (getExtendedFlags(buf) & (IFEF_DIRECTLINK | IFEF_AWDL)) || util_is_car_play(buf)))
                {
                    c_fast++;
                    MDNS_DISPOSE_CF_OBJECT(labels);
                    break;
                }
            }
            MDNS_DISPOSE_CF_OBJECT(labels);
        }
    }

    //if (c && c - c_host - c_comp - c_udns - c_ddns - c_v4ll - c_fast == 0)
    //    delay = mDNSPlatformOneSecond/10;  // If these were the only changes, shorten delay

    if (mDNS_LoggingEnabled)
    {
        CFIndex i;
        for (i=0; i<c; i++)
        {
            char buf[256];
            if (!CFStringGetCString(CFArrayGetValueAtIndex(changedKeys, i), buf, sizeof(buf), kCFStringEncodingUTF8)) buf[0] = 0;
            LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
                "*** Network Configuration Change *** SC key: " PUB_S, buf);
        }
        const mDNSNetworkChangeEventFlags_t netChangeFlags = GetNetworkChangeEventFlags(c_host, c_comp, c_udns,
            c_ddns, c_v4ll, c_fast);

        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
            "*** Network Configuration Change *** -- "
            "change count: %ld, delay: %d, flags: %{public, mdnsresponder:net_change_flags}d",
            (long)c, delay, netChangeFlags);
    }

    SetNetworkChanged(delay);

    // Other software might pick up these changes to register or browse in WAB or BTMM domains,
    // so in order for secure updates to be made to the server, make sure to read the keychain and
    // setup the DomainAuthInfo before handing the network change.
    // If we don't, then we will first try to register services in the clear, then later setup the
    // DomainAuthInfo, which is incorrect.
    if (c_ddns)
        SetKeyChainTimer(delay);

    // Don't try to call mDNSMacOSXNetworkChanged() here -- we're running on the wrong thread

    mDNS_Unlock(m);
    KQueueUnlock("NetworkChanged");
}


mDNSlocal void DynamicStoreReconnected(SCDynamicStoreRef store, void *info)
{
    mDNS *const m = (mDNS *const)info;
    (void)store;

    KQueueLock();   // serialize with KQueueLoop()

    LogInfo("DynamicStoreReconnected: Reconnected");

    // State:/Network/MulticastDNS
    SetLocalDomains();

    // State:/Network/DynamicDNS
    if (m->FQDN.c[0])
        mDNSPlatformDynDNSHostNameStatusChanged(&m->FQDN, 1);

    // Note: PrivateDNS and BackToMyMac are automatically populated when configd is restarted
    // as we receive network change notifications and thus not necessary. But we leave it here
    // so that if things are done differently in the future, this code still works.

    // State:/Network/PrivateDNS
    if (privateDnsArray)
        mDNSDynamicStoreSetConfig(kmDNSPrivateConfig, mDNSNULL, privateDnsArray);

    KQueueUnlock("DynamicStoreReconnected");
}

mDNSlocal mStatus WatchForNetworkChanges(mDNS *const m)
{
    mStatus err = -1;
    SCDynamicStoreContext context = { 0, m, NULL, NULL, NULL };
    SCDynamicStoreRef store    = SCDynamicStoreCreate(NULL, CFSTR("mDNSResponder:WatchForNetworkChanges"), NetworkChanged, &context);
    CFMutableArrayRef keys     = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);
    CFStringRef pattern1 = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv4);
    CFStringRef pattern2 = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, kSCCompAnyRegex, kSCEntNetIPv6);
    CFMutableArrayRef patterns = CFArrayCreateMutable(NULL, 0, &kCFTypeArrayCallBacks);

    if (!store) { LogMsg("SCDynamicStoreCreate failed: %s", SCErrorString(SCError())); goto error; }
    if (!keys || !pattern1 || !pattern2 || !patterns) goto error;

    CFArrayAppendValue(keys, NetworkChangedKey_IPv4);
    CFArrayAppendValue(keys, NetworkChangedKey_IPv6);
    CFArrayAppendValue(keys, NetworkChangedKey_Hostnames);
    CFArrayAppendValue(keys, NetworkChangedKey_Computername);
    CFArrayAppendValue(keys, NetworkChangedKey_DNS);
    CFArrayAppendValue(keys, NetworkChangedKey_DynamicDNS);
    CFArrayAppendValue(keys, NetworkChangedKey_PowerSettings);
    CFArrayAppendValue(patterns, pattern1);
    CFArrayAppendValue(patterns, pattern2);
    CFArrayAppendValue(patterns, CFSTR("State:/Network/Interface/[^/]+/AirPort"));
    if (!SCDynamicStoreSetNotificationKeys(store, keys, patterns))
    { LogMsg("SCDynamicStoreSetNotificationKeys failed: %s", SCErrorString(SCError())); goto error; }

#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
    if (!SCDynamicStoreSetDispatchQueue(store, dispatch_get_main_queue()))
    { LogMsg("SCDynamicStoreCreateRunLoopSource failed: %s", SCErrorString(SCError())); goto error; }
#else
    m->p->StoreRLS = SCDynamicStoreCreateRunLoopSource(NULL, store, 0);
    if (!m->p->StoreRLS) { LogMsg("SCDynamicStoreCreateRunLoopSource failed: %s", SCErrorString(SCError())); goto error; }
    CFRunLoopAddSource(CFRunLoopGetMain(), m->p->StoreRLS, kCFRunLoopDefaultMode);
#endif
    SCDynamicStoreSetDisconnectCallBack(store, DynamicStoreReconnected);
    m->p->Store = store;
    err = 0;
    goto exit;

error:
    MDNS_DISPOSE_CF_OBJECT(store);

exit:
    MDNS_DISPOSE_CF_OBJECT(patterns);
    MDNS_DISPOSE_CF_OBJECT(pattern2);
    MDNS_DISPOSE_CF_OBJECT(pattern1);
    MDNS_DISPOSE_CF_OBJECT(keys);

    return(err);
}

mDNSlocal void SysEventCallBack(int s1, short __unused filter, void *context, __unused mDNSBool encounteredEOF)
{
    mDNS *const m = (mDNS *const)context;

    mDNS_Lock(m);

    struct { struct kern_event_msg k; char extra[256]; } msg;
    ssize_t bytes = recv(s1, &msg, sizeof(msg), 0);
    if (bytes < 0)
    {
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_ERROR, "SysEventCallBack error -- error: " PUB_OS_ERR, (long)errno);
    }
    else
    {
        LogRedact(MDNS_LOG_CATEGORY_STATE, MDNS_LOG_DEFAULT,
            "SysEventCallBack -- event: %{public, mdnsresponder:kev_dl_event}d", msg.k.event_code);

        // We receive network change notifications both through configd and through SYSPROTO_EVENT socket.
        // Configd may not generate network change events for manually configured interfaces (i.e., non-DHCP)
        // always during sleep/wakeup due to some race conditions (See radar:8666757). At the same time, if
        // "Wake on Network Access" is not turned on, the notification will not have KEV_DL_WAKEFLAGS_CHANGED.
        // Hence, during wake up, if we see a KEV_DL_LINK_ON (i.e., link is UP), we trigger a network change.

        if (msg.k.event_code == KEV_DL_WAKEFLAGS_CHANGED || msg.k.event_code == KEV_DL_LINK_ON)
            SetNetworkChanged(mDNSPlatformOneSecond * 2);
    }

    mDNS_Unlock(m);
}

mDNSlocal mStatus WatchForSysEvents(mDNS *const m)
{
    m->p->SysEventNotifier = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
    if (m->p->SysEventNotifier < 0)
    { LogMsg("WatchForSysEvents: socket failed error %d errno %d (%s)", m->p->SysEventNotifier, errno, strerror(errno)); return(mStatus_NoMemoryErr); }

    struct kev_request kev_req = { KEV_VENDOR_APPLE, KEV_NETWORK_CLASS, KEV_DL_SUBCLASS };
    int err = ioctl(m->p->SysEventNotifier, SIOCSKEVFILT, &kev_req);
    if (err < 0)
    {
        LogMsg("WatchForSysEvents: SIOCSKEVFILT failed error %d errno %d (%s)", err, errno, strerror(errno));
        close(m->p->SysEventNotifier);
        m->p->SysEventNotifier = -1;
        return(mStatus_UnknownErr);
    }

    m->p->SysEventKQueue.KQcallback = SysEventCallBack;
    m->p->SysEventKQueue.KQcontext  = m;
    m->p->SysEventKQueue.KQtask     = "System Event Notifier";
    KQueueSet(m->p->SysEventNotifier, EV_ADD, EVFILT_READ, &m->p->SysEventKQueue);

    return(mStatus_NoError);
}

#ifndef NO_SECURITYFRAMEWORK
mDNSlocal OSStatus KeychainChanged(SecKeychainEvent keychainEvent, SecKeychainCallbackInfo *info, void *context)
{
    LogInfo("***   Keychain Changed   ***");
    mDNS *const m = (mDNS *const)context;
    SecKeychainRef skc;

    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    OSStatus err = SecKeychainCopyDefault(&skc);
    mdns_clang_ignore_warning_end();

    if (!err)
    {
        if (info->keychain == skc)
        {
            // For delete events, attempt to verify what item was deleted fail because the item is already gone, so we just assume they may be relevant
            mDNSBool relevant = (keychainEvent == kSecDeleteEvent);
            if (!relevant)
            {
                UInt32 tags[3] = { kSecTypeItemAttr, kSecServiceItemAttr, kSecAccountItemAttr };
                SecKeychainAttributeInfo attrInfo = { 3, tags, NULL };  // Count, array of tags, array of formats
                SecKeychainAttributeList *a = NULL;

                mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
                err = SecKeychainItemCopyAttributesAndData(info->item, &attrInfo, NULL, &a, NULL, NULL);
                mdns_clang_ignore_warning_end();

                if (!err)
                {
                    relevant = ((a->attr[0].length == 4 && (!strncasecmp(a->attr[0].data, "ddns", 4) || !strncasecmp(a->attr[0].data, "sndd", 4))) ||
                                (a->attr[1].length >= mDNSPlatformStrLen(dnsprefix) && (!strncasecmp(a->attr[1].data, dnsprefix, mDNSPlatformStrLen(dnsprefix)))));

                    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
                    SecKeychainItemFreeAttributesAndData(a, NULL);
                    mdns_clang_ignore_warning_end();
                }
            }
            if (relevant)
            {
                LogInfo("***   Keychain Changed   *** KeychainEvent=%d %s",
                        keychainEvent,
                        keychainEvent == kSecAddEvent    ? "kSecAddEvent"    :
                        keychainEvent == kSecDeleteEvent ? "kSecDeleteEvent" :
                        keychainEvent == kSecUpdateEvent ? "kSecUpdateEvent" : "<Unknown>");
                // We're running on the CFRunLoop (Mach port) thread, not the kqueue thread, so we need to grab the KQueueLock before proceeding
                KQueueLock();
                mDNS_Lock(m);

                // To not read the keychain twice: when BTMM is enabled, changes happen to the keychain
                // then the BTMM DynStore dictionary, so delay reading the keychain for a second.
                // NetworkChanged() will reset the keychain timer to fire immediately when the DynStore changes.
                //
                // In the "fixup" case where the BTMM DNS servers aren't accepting the key mDNSResponder has,
                // the DynStore dictionary won't change (because the BTMM zone won't change).  In that case,
                // a one second delay is ok, as we'll still converge to correctness, and there's no race
                // condition between the RegistrationDomain and the DomainAuthInfo.
                //
                // Lastly, non-BTMM WAB cases can use the keychain but not the DynStore, so we need to set
                // the timer here, as it will not get set by NetworkChanged().
                SetKeyChainTimer(mDNSPlatformOneSecond);

                mDNS_Unlock(m);
                KQueueUnlock("KeychainChanged");
            }
        }
        MDNS_DISPOSE_CF_OBJECT(skc);
    }

    return 0;
}
#endif

mDNSlocal void PowerOn(mDNS *const m)
{
    mDNSCoreMachineSleep(m, false);     // Will set m->SleepState = SleepState_Awake;

    if (m->p->WakeAtUTC)
    {
        long utc = mDNSPlatformUTC();
        // Need to explicitly clear any previous power requests -- they're not cleared automatically on wake
        mdns_power_cancel_all_events(kMDNSResponderID);
        if (m->p->WakeAtUTC - utc > 30)
        {
            LogSPS("PowerChanged PowerOn %d seconds early, assuming not maintenance wake", m->p->WakeAtUTC - utc);
        }
        else if (utc - m->p->WakeAtUTC > 30)
        {
            LogSPS("PowerChanged PowerOn %d seconds late, assuming not maintenance wake", utc - m->p->WakeAtUTC);
        }
        else if (IsAppleTV())
        {
            LogSPS("PowerChanged PowerOn %d seconds late, device is an AppleTV running iOS so not re-sleeping", utc - m->p->WakeAtUTC);
        }
        else
        {
            LogSPS("PowerChanged: Waking for network maintenance operations %d seconds early; re-sleeping in 20 seconds", m->p->WakeAtUTC - utc);
            m->p->RequestReSleep = mDNS_TimeNow(m) + 20 * mDNSPlatformOneSecond;
        }
    }

    // Hold on to a sleep assertion to allow mDNSResponder to perform its maintenance activities.
    // This allows for the network link to come up, DHCP to get an address, mDNS to issue queries etc.
    // We will clear this assertion as soon as we think the mainenance activities are done.
    mDNSPlatformPreventSleep(DARK_WAKE_TIME, "mDNSResponder:maintenance");

}

mDNSlocal void PowerChanged(void *refcon, io_service_t service, natural_t messageType, void *messageArgument)
{
    mDNS *const m = (mDNS *const)refcon;
    KQueueLock();
    (void)service;    // Parameter not used
    debugf("PowerChanged %X %lX", messageType, messageArgument);

    // Make sure our m->SystemWakeOnLANEnabled value correctly reflects the current system setting
    m->SystemWakeOnLANEnabled = SystemWakeForNetworkAccess();

    switch(messageType)
    {
    case kIOMessageCanSystemPowerOff:       LogSPS("PowerChanged kIOMessageCanSystemPowerOff     (no action)"); break;          // E0000240
    case kIOMessageSystemWillPowerOff:      LogSPS("PowerChanged kIOMessageSystemWillPowerOff");                                // E0000250
        mDNSCoreMachineSleep(m, true);
        if (m->SleepState == SleepState_Sleeping) mDNSMacOSXNetworkChanged();
        break;
    case kIOMessageSystemWillNotPowerOff:   LogSPS("PowerChanged kIOMessageSystemWillNotPowerOff (no action)"); break;          // E0000260
    case kIOMessageCanSystemSleep:          LogSPS("PowerChanged kIOMessageCanSystemSleep");                    break;          // E0000270
    case kIOMessageSystemWillSleep:         LogSPS("PowerChanged kIOMessageSystemWillSleep");                                   // E0000280
        mDNSCoreMachineSleep(m, true);
        break;
    case kIOMessageSystemWillNotSleep:      LogSPS("PowerChanged kIOMessageSystemWillNotSleep    (no action)"); break;          // E0000290
    case kIOMessageSystemHasPoweredOn:      LogSPS("PowerChanged kIOMessageSystemHasPoweredOn");                                // E0000300
        // If still sleeping (didn't get 'WillPowerOn' message for some reason?) wake now
        if (m->SleepState)
        {
            LogMsg("PowerChanged kIOMessageSystemHasPoweredOn: ERROR m->SleepState %d", m->SleepState);
            PowerOn(m);
        }
        // Just to be safe, schedule a mDNSMacOSXNetworkChanged(), in case we never received
        // the System Configuration Framework "network changed" event that we expect
        // to receive some time shortly after the kIOMessageSystemWillPowerOn message
        mDNS_Lock(m);
        SetNetworkChanged(mDNSPlatformOneSecond * 2);
        mDNS_Unlock(m);

        break;
    case kIOMessageSystemWillRestart:       LogSPS("PowerChanged kIOMessageSystemWillRestart     (no action)"); break;          // E0000310
    case kIOMessageSystemWillPowerOn:       LogSPS("PowerChanged kIOMessageSystemWillPowerOn");                                 // E0000320

        // Make sure our interface list is cleared to the empty state, then tell mDNSCore to wake
        if (m->SleepState != SleepState_Sleeping)
        {
            LogMsg("kIOMessageSystemWillPowerOn: ERROR m->SleepState %d", m->SleepState);
            m->SleepState = SleepState_Sleeping;
            mDNSMacOSXNetworkChanged();
        }
        PowerOn(m);
        break;
    default:                                LogSPS("PowerChanged unknown message %X", messageType); break;
    }

    if (messageType == kIOMessageSystemWillSleep)
        m->p->SleepCookie = (long)messageArgument;
    else if (messageType == kIOMessageCanSystemSleep)
        IOAllowPowerChange(m->p->PowerConnection, (long)messageArgument);

    KQueueUnlock("PowerChanged Sleep/Wake");
}

// iPhone OS doesn't currently have SnowLeopard's IO Power Management
// but it does define kIOPMAcknowledgmentOptionSystemCapabilityRequirements
#if defined(kIOPMAcknowledgmentOptionSystemCapabilityRequirements) && TARGET_OS_OSX
mDNSlocal void SnowLeopardPowerChanged(void *refcon, IOPMConnection connection, IOPMConnectionMessageToken token, IOPMSystemPowerStateCapabilities eventDescriptor)
{
    mDNS *const m = (mDNS *const)refcon;
    KQueueLock();
    LogSPS("SnowLeopardPowerChanged %X %X %X%s%s%s%s%s",
           connection, token, eventDescriptor,
           eventDescriptor & kIOPMSystemPowerStateCapabilityCPU     ? " CPU"     : "",
           eventDescriptor & kIOPMSystemPowerStateCapabilityVideo   ? " Video"   : "",
           eventDescriptor & kIOPMSystemPowerStateCapabilityAudio   ? " Audio"   : "",
           eventDescriptor & kIOPMSystemPowerStateCapabilityNetwork ? " Network" : "",
           eventDescriptor & kIOPMSystemPowerStateCapabilityDisk    ? " Disk"    : "");

    // Make sure our m->SystemWakeOnLANEnabled value correctly reflects the current system setting
    m->SystemWakeOnLANEnabled = SystemWakeForNetworkAccess();

    if (eventDescriptor & kIOPMSystemPowerStateCapabilityCPU)
    {
        // We might be in Sleeping or Transferring state. When we go from "wakeup" to "sleep" state, we don't
        // go directly to sleep state, but transfer in to the sleep state during which SleepState is set to
        // SleepState_Transferring. During that time, we might get another wakeup before we transition to Sleeping
        // state. In that case, we need to acknowledge the previous "sleep" before we acknowledge the wakeup.
        if (m->SleepLimit)
        {
            LogSPS("SnowLeopardPowerChanged: Waking up, Acking old Sleep, SleepLimit %d SleepState %d", m->SleepLimit, m->SleepState);
            IOPMConnectionAcknowledgeEvent(connection, (IOPMConnectionMessageToken)m->p->SleepCookie);
            m->SleepLimit = 0;
        }
        LogSPS("SnowLeopardPowerChanged: Waking up, Acking Wakeup, SleepLimit %d SleepState %d", m->SleepLimit, m->SleepState);
        // CPU Waking. Note: Can get this message repeatedly, as other subsystems power up or down.
        if (m->SleepState != SleepState_Awake)
        {
            PowerOn(m);
            // If the network notifications have already come before we got the wakeup, we ignored them and
            // in case we get no more, we need to trigger one.
            mDNS_Lock(m);
            SetNetworkChanged(mDNSPlatformOneSecond * 2);
            mDNS_Unlock(m);
        }
        IOPMConnectionAcknowledgeEvent(connection, token);
    }
    else
    {
        // CPU sleeping. Should not get this repeatedly -- once we're told that the CPU is halting
        // we should hear nothing more until we're told that the CPU has started executing again.
        if (m->SleepState) LogMsg("SnowLeopardPowerChanged: Sleep Error %X m->SleepState %d", eventDescriptor, m->SleepState);
        //sleep(5);
        //mDNSMacOSXNetworkChanged(m);
        mDNSCoreMachineSleep(m, true);
        //if (m->SleepState == SleepState_Sleeping) mDNSMacOSXNetworkChanged(m);
        m->p->SleepCookie = token;
    }

    KQueueUnlock("SnowLeopardPowerChanged Sleep/Wake");
}
#endif

// MARK: - /etc/hosts support

// Implementation Notes
//
// As /etc/hosts file can be huge (1000s of entries - when this comment was written, the test file had about
// 23000 entries with about 4000 duplicates), we can't use a linked list to store these entries. So, we parse
// them into a hash table. The implementation need to be able to do the following things efficiently
//
// 1. Detect duplicates e.g., two entries with "1.2.3.4 foo"
// 2. Detect whether /etc/hosts has changed and what has changed since the last read from the disk
// 3. Ability to support multiple addresses per name e.g., "1.2.3.4 foo, 2.3.4.5 foo". To support this, we
//    need to be able set the RRSet of a resource record to the first one in the list and also update when
//    one of them go away. This is needed so that the core thinks that they are all part of the same RRSet and
//    not a duplicate
// 4. Don't maintain any local state about any records registered with the core to detect changes to /etc/hosts
//
// CFDictionary is not a suitable candidate because it does not support duplicates and even if we use a custom
// "hash" function to solve this, the others are hard to solve. Hence, we share the hash (AuthHash) implementation
// of the core layer which does all of the above very efficiently

#define ETCHOSTS_BUFSIZE    1024    // Buffer size to parse a single line in /etc/hosts

mDNSexport void FreeEtcHosts(mDNS *const m, AuthRecord *rr, mStatus result)
{
    (void)m;  // unused
    (void)rr;
    (void)result;
    if (result == mStatus_MemFree)
    {
        LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "FreeEtcHosts: " PRI_S, ARDisplayString(m, rr));
        freeL("etchosts", rr);
    }
}

// Returns true on success and false on failure
mDNSlocal mDNSBool mDNSMacOSXCreateEtcHostsEntry(const domainname *domain, const struct sockaddr *sa, const domainname *cname, char *ifname, AuthHash *auth)
{
    AuthRecord *rr;
    mDNSu32 namehash;
    AuthGroup *ag;
    mDNSInterfaceID InterfaceID = mDNSInterface_LocalOnly;
    mDNSu16 rrtype;

    if (!domain)
    {
        LogMsg("mDNSMacOSXCreateEtcHostsEntry: ERROR!! name NULL");
        return mDNSfalse;
    }
    if (!sa && !cname)
    {
        LogMsg("mDNSMacOSXCreateEtcHostsEntry: ERROR!! sa and cname both NULL");
        return mDNSfalse;
    }

    if (sa && sa->sa_family != AF_INET && sa->sa_family != AF_INET6)
    {
        LogMsg("mDNSMacOSXCreateEtcHostsEntry: ERROR!! sa with bad family %d", sa->sa_family);
        return mDNSfalse;
    }


    if (ifname)
    {
        mDNSu32 ifindex = if_nametoindex(ifname);
        if (!ifindex)
        {
            LogMsg("mDNSMacOSXCreateEtcHostsEntry: hosts entry %##s with invalid ifname %s", domain->c, ifname);
            return mDNSfalse;
        }
        InterfaceID = (mDNSInterfaceID)(uintptr_t)ifindex;
    }

    if (sa)
        rrtype = (sa->sa_family == AF_INET ? kDNSType_A : kDNSType_AAAA);
    else
        rrtype = kDNSType_CNAME;

    // Check for duplicates. See whether we parsed an entry before like this ?
    namehash = DomainNameHashValue(domain);
    ag = AuthGroupForName(auth, namehash, domain);
    if (ag)
    {
        rr = ag->members;
        while (rr)
        {
            if (rr->resrec.rrtype == rrtype)
            {
                if (rrtype == kDNSType_A)
                {
                    mDNSv4Addr ip;
                    ip.NotAnInteger = ((const struct sockaddr_in*)sa)->sin_addr.s_addr;
                    if (mDNSSameIPv4Address(rr->resrec.rdata->u.ipv4, ip) && InterfaceID == rr->resrec.InterfaceID)
                    {
                        LogInfo("mDNSMacOSXCreateEtcHostsEntry: Same IPv4 address and InterfaceID for name %##s ID %d", domain->c, IIDPrintable(InterfaceID));
                        return mDNSfalse;
                    }
                }
                else if (rrtype == kDNSType_AAAA)
                {
                    mDNSv6Addr ip6;
                    ip6.l[0] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[0];
                    ip6.l[1] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[1];
                    ip6.l[2] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[2];
                    ip6.l[3] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[3];
                    if (mDNSSameIPv6Address(rr->resrec.rdata->u.ipv6, ip6) && InterfaceID == rr->resrec.InterfaceID)
                    {
                        LogInfo("mDNSMacOSXCreateEtcHostsEntry: Same IPv6 address and InterfaceID for name %##s ID %d", domain->c, IIDPrintable(InterfaceID));
                        return mDNSfalse;
                    }
                }
                else if (rrtype == kDNSType_CNAME)
                {
                    if (SameDomainName(&rr->resrec.rdata->u.name, cname))
                    {
                        LogInfo("mDNSMacOSXCreateEtcHostsEntry: Same cname %##s for name %##s", cname->c, domain->c);
                        return mDNSfalse;
                    }
                }
            }
            rr = rr->next;
        }
    }
    rr = (AuthRecord *) callocL("etchosts", sizeof(*rr));
    if (rr == NULL) return mDNSfalse;
    mDNS_SetupResourceRecord(rr, NULL, InterfaceID, rrtype, 1, kDNSRecordTypeKnownUnique, AuthRecordLocalOnly, FreeEtcHosts, NULL);
    AssignDomainName(&rr->namestorage, domain);

    if (sa)
    {
        rr->resrec.rdlength = sa->sa_family == AF_INET ? sizeof(mDNSv4Addr) : sizeof(mDNSv6Addr);
        if (sa->sa_family == AF_INET)
            rr->resrec.rdata->u.ipv4.NotAnInteger = ((const struct sockaddr_in*)sa)->sin_addr.s_addr;
        else
        {
            rr->resrec.rdata->u.ipv6.l[0] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[0];
            rr->resrec.rdata->u.ipv6.l[1] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[1];
            rr->resrec.rdata->u.ipv6.l[2] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[2];
            rr->resrec.rdata->u.ipv6.l[3] = ((const struct sockaddr_in6*)sa)->sin6_addr.__u6_addr.__u6_addr32[3];
        }
    }
    else
    {
        rr->resrec.rdlength = DomainNameLength(cname);
        rr->resrec.rdata->u.name.c[0] = 0;
        AssignDomainName(&rr->resrec.rdata->u.name, cname);
    }
    rr->resrec.namehash = DomainNameHashValue(rr->resrec.name);
    SetNewRData(&rr->resrec, mDNSNULL, 0);  // Sets rr->rdatahash for us
    LogInfo("mDNSMacOSXCreateEtcHostsEntry: Adding resource record %s ID %d", ARDisplayString(&mDNSStorage, rr), IIDPrintable(rr->resrec.InterfaceID));
    InsertAuthRecord(&mDNSStorage, auth, rr);
    return mDNStrue;
}

mDNSlocal int EtcHostsParseOneName(int start, int length, char *buffer, char **name)
{
    int i;

    *name = NULL;
    for (i = start; i < length; i++)
    {
        if (buffer[i] == '#')
            return -1;
        if (buffer[i] != ' ' && buffer[i] != ',' && buffer[i] != '\t')
        {
            *name = &buffer[i];

            // Found the start of a name, find the end and null terminate
            for (i++; i < length; i++)
            {
                if (buffer[i] == ' ' || buffer[i] == ',' || buffer[i] == '\t')
                {
                    buffer[i] = 0;
                    break;
                }
            }
            return i;
        }
    }
    return -1;
}

mDNSlocal void mDNSMacOSXParseEtcHostsLine(char *buffer, int length, AuthHash *auth)
{
    int i;
    int ifStart = 0;
    char *ifname = NULL;
    domainname name1d;
    domainname name2d;
    char *name1;
    char *name2;
    int aliasIndex;

    //Ignore leading whitespaces and tabs
    while (*buffer == ' ' || *buffer == '\t')
    {
        buffer++;
        length--;
    }

    // Find the end of the address string
    for (i = 0; i < length; i++)
    {
        if (buffer[i] == ' ' || buffer[i] == ',' || buffer[i] == '\t' || buffer[i] == '%')
        {
            if (buffer[i] == '%')
                ifStart = i + 1;
            buffer[i] = 0;
            break;
        }
    }

    // Convert the address string to an address
    struct addrinfo hints;
    bzero(&hints, sizeof(hints));
    hints.ai_flags = AI_NUMERICHOST;
    struct addrinfo *gairesults = NULL;
    if (getaddrinfo(buffer, NULL, &hints, &gairesults) != 0)
    {
        LogInfo("mDNSMacOSXParseEtcHostsLine: getaddrinfo returning null");
        return;
    }

    if (ifStart)
    {
        // Parse the interface
        ifname = &buffer[ifStart];
        for (i = ifStart + 1; i < length; i++)
        {
            if (buffer[i] == ' ' || buffer[i] == ',' || buffer[i] == '\t')
            {
                buffer[i] = 0;
                break;
            }
        }
    }

    i = EtcHostsParseOneName(i + 1, length, buffer, &name1);
    if (i == length)
    {
        // Common case (no aliases) : The entry is of the form "1.2.3.4 somehost" with no trailing white spaces/tabs etc.
        if (!MakeDomainNameFromDNSNameString(&name1d, name1))
        {
            LogMsg("mDNSMacOSXParseEtcHostsLine: ERROR!! cannot convert to domain name %s", name1);
            freeaddrinfo(gairesults);
            return;
        }
        mDNSMacOSXCreateEtcHostsEntry(&name1d, gairesults->ai_addr, mDNSNULL, ifname, auth);
    }
    else if (i != -1)
    {
        domainname first;
        // We might have some extra white spaces at the end for the common case of "1.2.3.4 somehost".
        // When we parse again below, EtchHostsParseOneName would return -1 and we will end up
        // doing the right thing.

        if (!MakeDomainNameFromDNSNameString(&first, name1))
        {
            LogMsg("mDNSMacOSXParseEtcHostsLine: ERROR!! cannot convert to domain name %s", name1);
            freeaddrinfo(gairesults);
            return;
        }
        mDNSMacOSXCreateEtcHostsEntry(&first, gairesults->ai_addr, mDNSNULL, ifname, auth);

        // /etc/hosts alias discussion:
        //
        // If the /etc/hosts has an entry like this
        //
        //  ip_address cname [aliases...]
        //  1.2.3.4    sun    star    bright
        //
        // star and bright are aliases (gethostbyname h_alias should point to these) and sun is the canonical
        // name (getaddrinfo ai_cannonname and gethostbyname h_name points to "sun")
        //
        // To achieve this, we need to add the entry like this:
        //
        // sun A 1.2.3.4
        // star CNAME sun
        // bright CNAME sun
        //
        // We store the first name we parsed in "first" and add the address (A/AAAA) record.
        // Then we parse additional names adding CNAME records till we reach the end.

        aliasIndex = 0;
        while (i < length)
        {
            // Continue to parse additional aliases until we reach end of the line and
            // for each "alias" parsed, add a CNAME record where "alias" points to the first "name".
            // See also /etc/hosts alias discussion above

            i = EtcHostsParseOneName(i + 1, length, buffer, &name2);

            if (name2)
            {
                if ((aliasIndex) && (*buffer == *name2))
                    break; // break out of the loop if we wrap around

                if (!MakeDomainNameFromDNSNameString(&name2d, name2))
                {
                    LogMsg("mDNSMacOSXParseEtcHostsLine: ERROR!! cannot convert to domain name %s", name2);
                    freeaddrinfo(gairesults);
                    return;
                }
                // Ignore if it points to itself
                if (!SameDomainName(&first, &name2d))
                {
                    if (!mDNSMacOSXCreateEtcHostsEntry(&name2d, mDNSNULL, &first, ifname, auth))
                    {
                        freeaddrinfo(gairesults);
                        return;
                    }
                }
                else
                {
                    LogInfo("mDNSMacOSXParseEtcHostsLine: Ignoring entry with same names first %##s, name2 %##s", first.c, name2d.c);
                }
                aliasIndex++;
            }
            else if (!aliasIndex)
            {
                // We have never parsed any aliases. This case happens if there
                // is just one name and some extra white spaces at the end.
                LogInfo("mDNSMacOSXParseEtcHostsLine: White space at the end of %##s", first.c);
                break;
            }
        }
    }
    freeaddrinfo(gairesults);
}

mDNSlocal void mDNSMacOSXParseEtcHosts(int fd, AuthHash *auth)
{
    mDNSBool good;
    char buf[ETCHOSTS_BUFSIZE];
    size_t len;
    FILE *fp;

    if (fd == -1) { LogInfo("mDNSMacOSXParseEtcHosts: fd is -1"); return; }

    fp = fopen("/etc/hosts", "r");
    if (!fp) { LogInfo("mDNSMacOSXParseEtcHosts: fp is NULL"); return; }

    while (1)
    {
        good = (fgets(buf, ETCHOSTS_BUFSIZE, fp) != NULL);
        if (!good) break;

        // skip comment and empty lines
        if (buf[0] == '#' || buf[0] == '\r' || buf[0] == '\n')
            continue;

        len = strlen(buf);
        if (!len) break;    // sanity check
        //Check for end of line code(mostly only \n but pre-OS X Macs could have only \r)
        if (buf[len - 1] == '\r' || buf[len - 1] == '\n')
        {
            buf[len - 1] = '\0';
            len = len - 1;
        }
        // fgets always null terminates and hence even if we have no
        // newline at the end, it is null terminated. The callee
        // (mDNSMacOSXParseEtcHostsLine) expects the length to be such that
        // buf[length] is zero and hence we decrement len to reflect that.
        if (len)
        {
            //Additional check when end of line code is 2 chars ie\r\n(DOS, other old OSes)
            //here we need to check for just \r but taking extra caution.
            if (buf[len - 1] == '\r' || buf[len - 1] == '\n')
            {
                buf[len - 1] = '\0';
                len = len - 1;
            }
        }
        if (!len) //Sanity Check: len should never be zero
        {
            LogMsg("mDNSMacOSXParseEtcHosts: Length is zero!");
            continue;
        }
        mDNSMacOSXParseEtcHostsLine(buf, (int)len, auth);
    }
    fclose(fp);
}

mDNSlocal void mDNSMacOSXUpdateEtcHosts(mDNS *const m);

mDNSlocal int mDNSMacOSXGetEtcHostsFD(void)
{
    mDNS *const m = &mDNSStorage;
#ifdef __DISPATCH_GROUP__
    // Can't do this stuff to be notified of changes in /etc/hosts if we don't have libdispatch
    static dispatch_queue_t etcq     = 0;
    static dispatch_source_t etcsrc   = 0;
    static dispatch_source_t hostssrc = 0;

    // First time through? just schedule ourselves on the main queue and we'll do the work later
    if (!etcq)
    {
        etcq = dispatch_get_main_queue();
        if (etcq)
        {
            // Do this work on the queue, not here - solves potential synchronization issues
            dispatch_async(etcq, ^{mDNSMacOSXUpdateEtcHosts(m);});
        }
        return -1;
    }

    if (hostssrc) return (int)dispatch_source_get_handle(hostssrc);
#endif

    int fd = open("/etc/hosts", O_RDONLY);

#ifdef __DISPATCH_GROUP__
    // Can't do this stuff to be notified of changes in /etc/hosts if we don't have libdispatch
    if (fd == -1)
    {
        // If the open failed and we're already watching /etc, we're done
        if (etcsrc) { LogInfo("mDNSMacOSXGetEtcHostsFD: Returning etcfd because no etchosts"); return fd; }

        // we aren't watching /etc, we should be
        fd = open("/etc", O_RDONLY);
        if (fd == -1) { LogInfo("mDNSMacOSXGetEtcHostsFD: etc does not exist"); return -1; }
        etcsrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fd, DISPATCH_VNODE_DELETE | DISPATCH_VNODE_WRITE | DISPATCH_VNODE_RENAME, etcq);
        if (etcsrc == NULL)
        {
            close(fd);
            return -1;
        }
        dispatch_source_set_event_handler(etcsrc,
                                          ^{
                                              const unsigned long flags = dispatch_source_get_data(etcsrc);
                                              LogMsg("mDNSMacOSXGetEtcHostsFD: /etc changed 0x%x", flags);
                                              if ((flags & (DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME)) != 0)
                                              {
                                                  dispatch_source_cancel(etcsrc);
                                                  MDNS_DISPOSE_DISPATCH(etcsrc);
                                                  dispatch_async(etcq, ^{mDNSMacOSXUpdateEtcHosts(m);});
                                                  return;
                                              }
                                              if ((flags & DISPATCH_VNODE_WRITE) != 0 && hostssrc == NULL)
                                              {
                                                  mDNSMacOSXUpdateEtcHosts(m);
                                              }
                                          });
        dispatch_source_set_cancel_handler(etcsrc, ^{close(fd);});
        dispatch_resume(etcsrc);

        // Try and open /etc/hosts once more now that we're watching /etc, in case we missed the creation
        fd = open("/etc/hosts", O_RDONLY | O_EVTONLY);
        if (fd == -1) { LogMsg("mDNSMacOSXGetEtcHostsFD etc hosts does not exist, watching etc"); return -1; }
    }

    // create a dispatch source to watch for changes to hosts file
    hostssrc = dispatch_source_create(DISPATCH_SOURCE_TYPE_VNODE, fd,
                                      (DISPATCH_VNODE_DELETE | DISPATCH_VNODE_WRITE | DISPATCH_VNODE_RENAME |
                                       DISPATCH_VNODE_ATTRIB | DISPATCH_VNODE_EXTEND | DISPATCH_VNODE_LINK | DISPATCH_VNODE_REVOKE), etcq);
    if (hostssrc == NULL)
    {
        close(fd);
        return -1;
    }
    dispatch_source_set_event_handler(hostssrc,
                                      ^{
                                          const unsigned long flags = dispatch_source_get_data(hostssrc);
                                          LogInfo("mDNSMacOSXGetEtcHostsFD: /etc/hosts changed 0x%x", flags);
                                          if ((flags & (DISPATCH_VNODE_DELETE | DISPATCH_VNODE_RENAME)) != 0)
                                          {
                                              dispatch_source_cancel(hostssrc);
                                              MDNS_DISPOSE_DISPATCH(hostssrc);
                                              // Bug in LibDispatch: wait a second before scheduling the block. If we schedule
                                              // the block immediately, we try to open the file and the file may not exist and may
                                              // fail to get a notification in the future. When the file does not exist and
                                              // we start to monitor the directory, on "dispatch_resume" of that source, there
                                              // is no guarantee that the file creation will be notified always because when
                                              // the dispatch_resume returns, the kevent manager may not have registered the
                                              // kevent yet but the file may have been created
                                              usleep(1000000);
                                              dispatch_async(etcq, ^{mDNSMacOSXUpdateEtcHosts(m);});
                                              return;
                                          }
                                          if ((flags & DISPATCH_VNODE_WRITE) != 0)
                                          {
                                              mDNSMacOSXUpdateEtcHosts(m);
                                          }
                                      });
    dispatch_source_set_cancel_handler(hostssrc, ^{LogInfo("mDNSMacOSXGetEtcHostsFD: Closing etchosts fd %d", fd); close(fd);});
    dispatch_resume(hostssrc);

    // Cleanup /etc source, no need to watch it if we already have /etc/hosts
    if (etcsrc)
    {
        dispatch_source_cancel(etcsrc);
        MDNS_DISPOSE_DISPATCH(etcsrc);
    }

    LogInfo("mDNSMacOSXGetEtcHostsFD: /etc/hosts being monitored, and not etc");
    return hostssrc ? (int)dispatch_source_get_handle(hostssrc) : -1;
#else
    (void)m;
    return fd;
#endif
}

// When /etc/hosts is modified, flush all the cache records as there may be local
// authoritative answers now
mDNSlocal void FlushAllCacheRecords(mDNS *const m)
{
    CacheRecord *cr;
    mDNSu32 slot;
    CacheGroup *cg;

    FORALL_CACHERECORDS(slot, cg, cr)
    {
        // Skip multicast.
        if (cr->resrec.InterfaceID) continue;

        // If resource records can answer A, AAAA or are RRSIGs that cover A/AAAA, they need to be flushed so that we
        // will never used to deliver an ADD or RMV.

        RRTypeAnswersQuestionTypeFlags flags = kRRTypeAnswersQuestionTypeFlagsNone;
    #if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
        // Here we are checking if the record should be decided on whether to deliver the remove event to the callback,
        // RRSIG that covers kDNSType_A or kDNSType_AAAA should always be checked.
        // Note that setting REQUIRES_DNSSEC_RRS to mDNStrue will not necessarily deliver the remove event for RRSIG
        // that covers kDNSType_A or kDNSType_AAAA records. It still needs to go through the "IsAnswer" process to
        // determine whether to deliver the remove event.
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRToValidate;
        flags |= kRRTypeAnswersQuestionTypeFlagsRequiresDNSSECRRValidated;
    #endif
        const mDNSBool typeMatches = RRTypeAnswersQuestionType(&cr->resrec, kDNSType_A, flags) ||
                                     RRTypeAnswersQuestionType(&cr->resrec, kDNSType_AAAA, flags);
        if (!typeMatches)
        {
            continue;
        }

        LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEFAULT, "FlushAllCacheRecords: Purging Resourcerecord - "
                  "record description: " PRI_S ".", CRDisplayString(m, cr));

        mDNS_PurgeCacheResourceRecord(m, cr);
    }
}

// Add new entries to the core. If justCheck is set, this function does not add, just returns true
mDNSlocal mDNSBool EtcHostsAddNewEntries(AuthHash *newhosts, mDNSBool justCheck)
{
    mDNS *const m = &mDNSStorage;
    AuthGroup *ag;
    mDNSu32 slot;
    AuthRecord *rr, *primary, *rrnext;
    for (slot = 0; slot < AUTH_HASH_SLOTS; slot++)
        for (ag = newhosts->rrauth_hash[slot]; ag; ag = ag->next)
        {
            primary = NULL;
            for (rr = ag->members; rr; rr = rrnext)
            {
                rrnext = rr->next;
                AuthGroup *ag1;
                AuthRecord *rr1;
                mDNSBool found = mDNSfalse;
                ag1 = AuthGroupForRecord(&m->rrauth, &rr->resrec);
                if (ag1 && ag1->members)
                {
                    if (!primary) primary = ag1->members;
                    rr1 = ag1->members;
                    while (rr1)
                    {
                        // We are not using InterfaceID in checking for duplicates. This means,
                        // if there are two addresses for a given name e.g., fe80::1%en0 and
                        // fe80::1%en1, we only add the first one. It is not clear whether
                        // this is a common case. To fix this, we also need to modify
                        // mDNS_Register_internal in how it handles duplicates. If it becomes a
                        // common case, we will fix it then.
                        if (IdenticalResourceRecord(&rr1->resrec, &rr->resrec) && rr1->resrec.InterfaceID == rr->resrec.InterfaceID)
                        {
                            LogInfo("EtcHostsAddNewEntries: Skipping, not adding %s", ARDisplayString(m, rr1));
                            found = mDNStrue;
                            break;
                        }
                        rr1 = rr1->next;
                    }
                }
                if (!found)
                {
                    if (justCheck)
                    {
                        LogInfo("EtcHostsAddNewEntries: Entry %s not registered with core yet", ARDisplayString(m, rr));
                        return mDNStrue;
                    }
                    RemoveAuthRecord(m, newhosts, rr);
                    // if there is no primary, point to self
                    rr->RRSet = (uintptr_t)(primary ? primary : rr);
                    rr->next = NULL;
                    LogInfo("EtcHostsAddNewEntries: Adding %s ID %d", ARDisplayString(m, rr), IIDPrintable(rr->resrec.InterfaceID));
                    if (mDNS_Register_internal(m, rr) != mStatus_NoError)
                        LogMsg("EtcHostsAddNewEntries: mDNS_Register failed for %s", ARDisplayString(m, rr));
                }
            }
        }
    return mDNSfalse;
}

// Delete entries from the core that are no longer needed. If justCheck is set, this function
// does not delete, just returns true
mDNSlocal mDNSBool EtcHostsDeleteOldEntries(AuthHash *newhosts, mDNSBool justCheck)
{
    mDNS *const m = &mDNSStorage;
    AuthGroup *ag;
    mDNSu32 slot;
    AuthRecord *rr, *rrnext;
    for (slot = 0; slot < AUTH_HASH_SLOTS; slot++)
        for (ag = m->rrauth.rrauth_hash[slot]; ag; ag = ag->next)
            for (rr = ag->members; rr; rr = rrnext)
            {
                mDNSBool found = mDNSfalse;
                AuthGroup *ag1;
                AuthRecord *rr1;
                rrnext = rr->next;
                if (rr->RecordCallback != FreeEtcHosts) continue;
                ag1 = AuthGroupForRecord(newhosts, &rr->resrec);
                if (ag1)
                {
                    rr1 = ag1->members;
                    while (rr1)
                    {
                        if (IdenticalResourceRecord(&rr1->resrec, &rr->resrec))
                        {
                            LogInfo("EtcHostsDeleteOldEntries: Old record %s found in new, skipping", ARDisplayString(m, rr));
                            found = mDNStrue;
                            break;
                        }
                        rr1 = rr1->next;
                    }
                }
                // there is no corresponding record in newhosts for the same name. This means
                // we should delete this from the core.
                if (!found)
                {
                    if (justCheck)
                    {
                        LogInfo("EtcHostsDeleteOldEntries: Record %s not found in new, deleting", ARDisplayString(m, rr));
                        return mDNStrue;
                    }
                    // if primary is going away, make sure that the rest of the records
                    // point to the new primary
                    if (rr == ag->members)
                    {
                        AuthRecord *new_primary = rr->next;
                        AuthRecord *r = new_primary;
                        while (r)
                        {
                            if (r->RRSet == (uintptr_t)rr)
                            {
                                LogInfo("EtcHostsDeleteOldEntries: Updating Resource Record %s to primary", ARDisplayString(m, r));
                                r->RRSet = (uintptr_t)new_primary;
                            }
                            else LogMsg("EtcHostsDeleteOldEntries: ERROR!! Resource Record %s not pointing to primary %##s", ARDisplayString(m, r), r->resrec.name);
                            r = r->next;
                        }
                    }
                    LogInfo("EtcHostsDeleteOldEntries: Deleting %s", ARDisplayString(m, rr));
                    mDNS_Deregister_internal(m, rr, mDNS_Dereg_normal);
                }
            }
    return mDNSfalse;
}

mDNSlocal void UpdateEtcHosts(mDNS *const m, void *context)
{
    AuthHash *newhosts = (AuthHash *)context;

    mDNS_CheckLock(m);

    //Delete old entries from the core if they are not present in the newhosts
    EtcHostsDeleteOldEntries(newhosts, mDNSfalse);
    // Add the new entries to the core if not already present in the core
    EtcHostsAddNewEntries(newhosts, mDNSfalse);
}

mDNSlocal void FreeNewHosts(AuthHash *newhosts)
{
    mDNSu32 slot;
    AuthGroup *ag, *agnext;
    AuthRecord *rr, *rrnext;

    for (slot = 0; slot < AUTH_HASH_SLOTS; slot++)
        for (ag = newhosts->rrauth_hash[slot]; ag; ag = agnext)
        {
            agnext = ag->next;
            for (rr = ag->members; rr; rr = rrnext)
            {
                rrnext = rr->next;
                freeL("etchosts", rr);
            }
            freeL("AuthGroups", ag);
        }
}

mDNSlocal void mDNSMacOSXUpdateEtcHosts_internal(mDNS *const m)
{
    AuthHash newhosts;

    mDNSPlatformMemZero(&newhosts, sizeof(AuthHash));

    // Get the file desecriptor (will trigger us to start watching for changes)
    int fd = mDNSMacOSXGetEtcHostsFD();
    if (fd != -1)
    {
        LogInfo("mDNSMacOSXUpdateEtcHosts: Parsing /etc/hosts fd %d", fd);
        mDNSMacOSXParseEtcHosts(fd, &newhosts);
    }
    else LogInfo("mDNSMacOSXUpdateEtcHosts: /etc/hosts is not present");

    // Optimization: Detect whether /etc/hosts changed or not.
    //
    // 1. Check to see if there are any new entries. We do this by seeing whether any entries in
    //    newhosts is already registered with core.  If we find at least one entry that is not
    //    registered with core, then it means we have work to do.
    //
    // 2. Next, we check to see if any of the entries that are registered with core is not present
    //   in newhosts. If we find at least one entry that is not present, it means we have work to
    //   do.
    //
    // Note: We may not have to hold the lock right here as KQueueLock is held which prevents any
    // other thread from running. But mDNS_Lock is needed here as we will be traversing the core
    // data structure in EtcHostsDeleteOldEntries/NewEntries which might expect the lock to be held
    // in the future and this code does not have to change.
    mDNS_Lock(m);
    // Add the new entries to the core if not already present in the core
    if (!EtcHostsAddNewEntries(&newhosts, mDNStrue))
    {
        // No new entries to add, check to see if we need to delete any old entries from the
        // core if they are not present in the newhosts
        if (!EtcHostsDeleteOldEntries(&newhosts, mDNStrue))
        {
            LogInfo("mDNSMacOSXUpdateEtcHosts: No work");
            goto exit;
        }
    }

    // This will flush the cache, stop and start the query so that the queries
    // can look at the /etc/hosts again
    //
    // Notes:
    //
    // We can't delete and free the records here. We wait for the mDNSCoreRestartAddressQueries to
    // deliver RMV events. It has to be done in a deferred way because we can't deliver RMV
    // events for local records *before* the RMV events for cache records. mDNSCoreRestartAddressQueries
    // delivers these events in the right order and then calls us back to delete them.
    //
    // Similarly, we do a deferred Registration of the record because mDNSCoreRestartAddressQueries
    // is a common function that looks at all local auth records and delivers a RMV including
    // the records that we might add here. If we deliver a ADD here, it will get a RMV and then when
    // the query is restarted, it will get another ADD. To avoid this (ADD-RMV-ADD), we defer registering
    // the record until the RMVs are delivered in mDNSCoreRestartAddressQueries after which UpdateEtcHosts
    // is called back where we do the Registration of the record. This results in RMV followed by ADD which
    // looks normal.
    mDNSCoreRestartAddressQueries(m, mDNSfalse, FlushAllCacheRecords, UpdateEtcHosts, &newhosts);

exit:
    FreeNewHosts(&newhosts);
    mDNS_Unlock(m);
}

mDNSlocal void mDNSMacOSXUpdateEtcHosts(mDNS *const m)
{
    KQueueLock();
    mDNSMacOSXUpdateEtcHosts_internal(m);
    KQueueUnlock("/etc/hosts changed");
}

// MARK: - Initialization & Teardown

CF_EXPORT CFDictionaryRef _CFCopySystemVersionDictionary(void);
CF_EXPORT const CFStringRef _kCFSystemVersionProductNameKey;
CF_EXPORT const CFStringRef _kCFSystemVersionProductVersionKey;
CF_EXPORT const CFStringRef _kCFSystemVersionBuildVersionKey;

// Major version 13 is 10.9.x
mDNSexport void mDNSMacOSXSystemBuildNumber(char *HINFO_SWstring)
{
    int major = 0, minor = 0;
    char letter = 0, prodname[256]="<Unknown>", prodvers[256]="<Unknown>", buildver[256]="<Unknown>";
    CFDictionaryRef vers = _CFCopySystemVersionDictionary();
    if (vers)
    {
        CFStringRef cfprodname = CFDictionaryGetValue(vers, _kCFSystemVersionProductNameKey);
        CFStringRef cfprodvers = CFDictionaryGetValue(vers, _kCFSystemVersionProductVersionKey);
        CFStringRef cfbuildver = CFDictionaryGetValue(vers, _kCFSystemVersionBuildVersionKey);
        if (cfprodname)
            CFStringGetCString(cfprodname, prodname, sizeof(prodname), kCFStringEncodingUTF8);
        if (cfprodvers)
            CFStringGetCString(cfprodvers, prodvers, sizeof(prodvers), kCFStringEncodingUTF8);
        if (cfbuildver && CFStringGetCString(cfbuildver, buildver, sizeof(buildver), kCFStringEncodingUTF8))
            sscanf(buildver, "%d%c%d", &major, &letter, &minor);
        MDNS_DISPOSE_CF_OBJECT(vers);
    }
    if (!major)
    {
        major = 13;
        LogMsg("Note: No Major Build Version number found; assuming 13");
    }
    if (HINFO_SWstring)
        mDNS_snprintf(HINFO_SWstring, 256, "%s %s (%s), %s", prodname, prodvers, buildver, STRINGIFY(mDNSResponderVersion));
    //LogMsg("%s %s (%s), %d %c %d", prodname, prodvers, buildver, major, letter, minor);

    // If product name starts with "M" (case insensitive), thus it the current ProductName attribute "macOS"
    // for macOS; or it matches the old ProductName attribute "Mac OS X" for macOS, we set OSXVers, else we set iOSVers.
    // Note that "& 0xDF" operation converts prodname[0] to uppercase alphabetic character, do not use it make the ASCII
    // character uppercase, since "& 0xDF" will incorrectly change the ASCII characters that are not in the A~Z, a~z
    // range. For the detail, go to https://blog.cloudflare.com/the-oldest-trick-in-the-ascii-book/
    if ((prodname[0] & 0xDF) == 'M')
        OSXVers = major;
    else
        iOSVers = major;
}

// Test to see if we're the first client running on UDP port 5353, by trying to bind to 5353 without using SO_REUSEPORT.
// If we fail, someone else got here first. That's not a big problem; we can share the port for multicast responses --
// we just need to be aware that we shouldn't expect to successfully receive unicast UDP responses.
mDNSlocal mDNSBool mDNSPlatformInit_CanReceiveUnicast(void)
{
    int err = -1;
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 3)
        LogMsg("mDNSPlatformInit_CanReceiveUnicast: socket error %d errno %d (%s)", s, errno, strerror(errno));
    else
    {
        struct sockaddr_in s5353;
        s5353.sin_family      = AF_INET;
        s5353.sin_port        = MulticastDNSPort.NotAnInteger;
        s5353.sin_addr.s_addr = 0;
        err = bind(s, (struct sockaddr *)&s5353, sizeof(s5353));
        close(s);
    }

    if (err) LogMsg("No unicast UDP responses");
    else debugf("Unicast UDP responses okay");
    return(err == 0);
}

mDNSlocal void CreatePTRRecord(const domainname *domain)
{
    AuthRecord *rr;
    const domainname *pname = (domainname *)"\x9" "localhost";

    rr = (AuthRecord *) callocL("localhosts", sizeof(*rr));
    if (rr == NULL) return;

    mDNS_SetupResourceRecord(rr, mDNSNULL, mDNSInterface_LocalOnly, kDNSType_PTR, kHostNameTTL, kDNSRecordTypeKnownUnique, AuthRecordLocalOnly, mDNSNULL, mDNSNULL);
    AssignDomainName(&rr->namestorage, domain);

    rr->resrec.rdlength = DomainNameLength(pname);
    rr->resrec.rdata->u.name.c[0] = 0;
    AssignDomainName(&rr->resrec.rdata->u.name, pname);

    rr->resrec.namehash = DomainNameHashValue(rr->resrec.name);
    SetNewRData(&rr->resrec, mDNSNULL, 0);  // Sets rr->rdatahash for us
    mDNS_Register(&mDNSStorage, rr);
}

// Setup PTR records for 127.0.0.1 and ::1. This helps answering them locally rather than relying
// on the external DNS server to answer this. Sometimes, the DNS servers don't respond in a timely
// fashion and applications depending on this e.g., telnetd, times out after 30 seconds creating
// a bad user experience. For now, we specifically create only localhosts to handle radar://9354225
//
// Note: We could have set this up while parsing the entries in /etc/hosts. But this is kept separate
// intentionally to avoid adding to the complexity of code handling /etc/hosts.
mDNSlocal void SetupLocalHostRecords(void)
{
    domainname name;

    MakeDomainNameFromDNSNameString(&name, "1.0.0.127.in-addr.arpa.");
    CreatePTRRecord(&name);

    MakeDomainNameFromDNSNameString(&name, "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.");
    CreatePTRRecord(&name);
}


// Construction of Default Browse domain list (i.e. when clients pass NULL) is as follows:
// 1) query for b._dns-sd._udp.local on LocalOnly interface
//    (.local manually generated via explicit callback)
// 2) for each search domain (from prefs pane), query for b._dns-sd._udp.<searchdomain>.
// 3) for each result from (2), register LocalOnly PTR record b._dns-sd._udp.local. -> <result>
// 4) result above should generate a callback from question in (1).  result added to global list
// 5) global list delivered to client via GetSearchDomainList()
// 6) client calls to enumerate domains now go over LocalOnly interface
//    (!!!KRS may add outgoing interface in addition)

#if MDNSRESPONDER_SUPPORTS(APPLE, IGNORE_HOSTS_FILE)
mDNSlocal mStatus RegisterLocalOnlyAddressRecord(const domainname *const name, mDNSu16 type, const void *rdata, mDNSu16 rdlength)
{
    switch(type)
    {
    case kDNSType_A:
        if (rdlength != 4) return (mStatus_BadParamErr);
        break;

    case kDNSType_AAAA:
        if (rdlength != 16) return (mStatus_BadParamErr);
        break;

    default:
        return (mStatus_BadParamErr);
    }

    AuthRecord *rr = (AuthRecord *) callocL("etchosts", sizeof(*rr));
    if (!rr) return (mStatus_NoMemoryErr);

    mDNS_SetupResourceRecord(rr, NULL, mDNSInterface_LocalOnly, type, 1, kDNSRecordTypeKnownUnique, AuthRecordLocalOnly, FreeEtcHosts, NULL);
    AssignDomainName(&rr->namestorage, name);
    mDNSPlatformMemCopy(rr->resrec.rdata->u.data, rdata, rdlength);

    const mStatus err = mDNS_Register_internal(&mDNSStorage, rr);
    if (err)
    {
        LogMsg("RegisterLocalOnlyAddressRecord: mDNS_Register error %d registering %s", err, ARDisplayString(&mDNSStorage, rr));
        freeL("etchosts", rr);
    }
    return (err);
}

mDNSlocal void RegisterLocalOnlyARecord(const domainname *const name, const mDNSv4Addr *const addr)
{
    RegisterLocalOnlyAddressRecord(name, kDNSType_A, addr->b, (mDNSu16)sizeof(mDNSv4Addr));
}

mDNSlocal void RegisterLocalOnlyAAAARecord(const domainname *const name, const mDNSv6Addr *const addr)
{
    RegisterLocalOnlyAddressRecord(name, kDNSType_AAAA, addr->b, (mDNSu16)sizeof(mDNSv6Addr));
}
#endif  // MDNSRESPONDER_SUPPORTS(APPLE, IGNORE_HOSTS_FILE)

mDNSlocal mStatus mDNSPlatformInit_setup(mDNS *const m)
{
    mStatus err;

    char HINFO_SWstring[256] = "";
    mDNSMacOSXSystemBuildNumber(HINFO_SWstring);


    err = mDNSHelperInit();
    if (err)
        return err;

    // Store mDNSResponder Platform
    if (OSXVers)
    {
        m->mDNS_plat = platform_OSX;
    }
    else if (iOSVers)
    {
        if (IsAppleTV())
            m->mDNS_plat = platform_Atv;
        else
            m->mDNS_plat = platform_iOS;
    }
    else
    {
        m->mDNS_plat = platform_NonApple;
    }

    // In 10.4, mDNSResponder is launched very early in the boot process, while other subsystems are still in the process of starting up.
    // If we can't read the user's preferences, then we sleep a bit and try again, for up to five seconds before we give up.
    int i;
    for (i=0; i<100; i++)
    {
        domainlabel testlabel;
        testlabel.c[0] = 0;
        GetUserSpecifiedLocalHostName(&testlabel);
        if (testlabel.c[0]) break;
        usleep(50000);
    }

    m->hostlabel.c[0]        = 0;

#if MDNSRESPONDER_SUPPORTS(APPLE, RANDOM_AWDL_HOSTNAME)
    GetRandomUUIDLocalHostname(&m->RandomizedHostname);
#endif
    int get_model[2] = { CTL_HW, HW_MODEL };
    size_t len_model = sizeof(HINFO_HWstring_buffer);

    // Normal Apple model names are of the form "iPhone2,1", and
    // internal code names are strings containing no commas, e.g. "N88AP".
    // We used to ignore internal code names, but Apple now uses these internal code names
    // even in released shipping products, so we no longer ignore strings containing no commas.
//  if (sysctl(get_model, 2, HINFO_HWstring_buffer, &len_model, NULL, 0) == 0 && strchr(HINFO_HWstring_buffer, ','))
    if (sysctl(get_model, 2, HINFO_HWstring_buffer, &len_model, NULL, 0) == 0)
        HINFO_HWstring = HINFO_HWstring_buffer;

    // For names of the form "iPhone2,1" we use "iPhone" as the prefix for automatic name generation.
    // For names of the form "N88AP" containg no comma, we use the entire string.
    HINFO_HWstring_prefixlen = (int)(strchr(HINFO_HWstring_buffer, ',') ? strcspn(HINFO_HWstring, "0123456789") : strlen(HINFO_HWstring));

    if (mDNSPlatformInit_CanReceiveUnicast())
        m->CanReceiveUnicastOn5353 = mDNStrue;

    mDNSu32 hlen = mDNSPlatformStrLen(HINFO_HWstring);
    mDNSu32 slen = mDNSPlatformStrLen(HINFO_SWstring);
    if (hlen + slen < 254)
    {
        m->HIHardware.c[0] = hlen;
        m->HISoftware.c[0] = slen;
        mDNSPlatformMemCopy(&m->HIHardware.c[1], HINFO_HWstring, hlen);
        mDNSPlatformMemCopy(&m->HISoftware.c[1], HINFO_SWstring, slen);
    }

    m->p->permanentsockets.port  = MulticastDNSPort;
    m->p->permanentsockets.m     = m;
    m->p->permanentsockets.sktv4 = -1;
    m->p->permanentsockets.kqsv4.KQcallback = myKQSocketCallBack;
    m->p->permanentsockets.kqsv4.KQcontext  = &m->p->permanentsockets;
    m->p->permanentsockets.kqsv4.KQtask     = "IPv4 UDP packet reception";
    m->p->permanentsockets.sktv6 = -1;
    m->p->permanentsockets.kqsv6.KQcallback = myKQSocketCallBack;
    m->p->permanentsockets.kqsv6.KQcontext  = &m->p->permanentsockets;
    m->p->permanentsockets.kqsv6.KQtask     = "IPv6 UDP packet reception";

    err = SetupSocket(&m->p->permanentsockets, MulticastDNSPort, AF_INET, mDNSNULL);
    if (err) LogMsg("mDNSPlatformInit_setup: SetupSocket(AF_INET) failed error %d errno %d (%s)", err, errno, strerror(errno));
    err = SetupSocket(&m->p->permanentsockets, MulticastDNSPort, AF_INET6, mDNSNULL);
    if (err) LogMsg("mDNSPlatformInit_setup: SetupSocket(AF_INET6) failed error %d errno %d (%s)", err, errno, strerror(errno));

    struct sockaddr_in s4;
    socklen_t n4 = sizeof(s4);
    if (getsockname(m->p->permanentsockets.sktv4, (struct sockaddr *)&s4, &n4) < 0)
        LogMsg("getsockname v4 error %d (%s)", errno, strerror(errno));
    else
        m->UnicastPort4.NotAnInteger = s4.sin_port;

    if (m->p->permanentsockets.sktv6 >= 0)
    {
        struct sockaddr_in6 s6;
        socklen_t n6 = sizeof(s6);
        if (getsockname(m->p->permanentsockets.sktv6, (struct sockaddr *)&s6, &n6) < 0) LogMsg("getsockname v6 error %d (%s)", errno, strerror(errno));
        else m->UnicastPort6.NotAnInteger = s6.sin6_port;
    }

    m->p->InterfaceList         = mDNSNULL;
#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    m->p->InterfaceMonitors     = NULL;
#endif
    m->p->userhostlabel.c[0]    = 0;
    m->p->usernicelabel.c[0]    = 0;
    m->p->prevoldnicelabel.c[0] = 0;
    m->p->prevnewnicelabel.c[0] = 0;
    m->p->prevoldhostlabel.c[0] = 0;
    m->p->prevnewhostlabel.c[0] = 0;
    m->p->NotifyUser         = 0;
    m->p->KeyChainTimer      = 0;
    m->p->WakeAtUTC          = 0;
    m->p->RequestReSleep     = 0;
    // Assume that everything is good to begin with. If something is not working,
    // we will detect that when we start sending questions.
    m->p->v4answers          = 1;
    m->p->v6answers          = 1;
    m->p->DNSTrigger         = 0;
    m->p->LastConfigGeneration = 0;
#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    m->p->if_interface_changed = mDNSfalse;
#endif

    NetworkChangedKey_IPv4         = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv4);
    NetworkChangedKey_IPv6         = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetIPv6);
    NetworkChangedKey_Hostnames    = SCDynamicStoreKeyCreateHostNames(NULL);
    NetworkChangedKey_Computername = SCDynamicStoreKeyCreateComputerName(NULL);
    NetworkChangedKey_DNS          = SCDynamicStoreKeyCreateNetworkGlobalEntity(NULL, kSCDynamicStoreDomainState, kSCEntNetDNS);
    NetworkChangedKey_StateInterfacePrefix = SCDynamicStoreKeyCreateNetworkInterfaceEntity(NULL, kSCDynamicStoreDomainState, CFSTR(""), NULL);
    if (!NetworkChangedKey_IPv4 || !NetworkChangedKey_IPv6 || !NetworkChangedKey_Hostnames || !NetworkChangedKey_Computername || !NetworkChangedKey_DNS || !NetworkChangedKey_StateInterfacePrefix)
    { LogMsg("SCDynamicStore string setup failed"); return(mStatus_NoMemoryErr); }

    err = WatchForNetworkChanges(m);
    if (err) { LogMsg("mDNSPlatformInit_setup: WatchForNetworkChanges failed %d", err); return(err); }

    err = WatchForSysEvents(m);
    if (err) { LogMsg("mDNSPlatformInit_setup: WatchForSysEvents failed %d", err); return(err); }

    mDNSs32 utc = mDNSPlatformUTC();
    m->SystemWakeOnLANEnabled = SystemWakeForNetworkAccess();
    myGetIfAddrs(1);
    UpdateInterfaceList(utc);
    SetupActiveInterfaces(utc);
    ReorderInterfaceList();

    // Explicitly ensure that our Keychain operations utilize the system domain.
#ifndef NO_SECURITYFRAMEWORK
    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    SecKeychainSetPreferenceDomain(kSecPreferencesDomainSystem);
    mdns_clang_ignore_warning_end();
#endif

    mDNS_Lock(m);
    SetDomainSecrets(m);
    SetLocalDomains();
    mDNS_Unlock(m);

#ifndef NO_SECURITYFRAMEWORK
    mdns_clang_ignore_warning_begin(-Wdeprecated-declarations);
    err = SecKeychainAddCallback(KeychainChanged, kSecAddEventMask|kSecDeleteEventMask|kSecUpdateEventMask, m);
    mdns_clang_ignore_warning_end();

    if (err) { LogMsg("mDNSPlatformInit_setup: SecKeychainAddCallback failed %d", err); return(err); }
#endif

#if !defined(kIOPMAcknowledgmentOptionSystemCapabilityRequirements) || TARGET_OS_IPHONE
    LogMsg("Note: Compiled without SnowLeopard Fine-Grained Power Management support");
#else
    IOPMConnection c;
    IOReturn iopmerr = IOPMConnectionCreate(CFSTR("mDNSResponder"), kIOPMSystemPowerStateCapabilityCPU, &c);
    if (iopmerr) LogMsg("IOPMConnectionCreate failed %d", iopmerr);
    else
    {
        iopmerr = IOPMConnectionSetNotification(c, m, SnowLeopardPowerChanged);
        if (iopmerr) LogMsg("IOPMConnectionSetNotification failed %d", iopmerr);
        else
        {
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
            IOPMConnectionSetDispatchQueue(c, dispatch_get_main_queue());
            LogInfo("IOPMConnectionSetDispatchQueue is now running");
#else
            iopmerr = IOPMConnectionScheduleWithRunLoop(c, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
            if (iopmerr) LogMsg("IOPMConnectionScheduleWithRunLoop failed %d", iopmerr);
            LogInfo("IOPMConnectionScheduleWithRunLoop is now running");
#endif /* MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM */
        }
    }
    m->p->IOPMConnection = iopmerr ? mDNSNULL : c;
    if (iopmerr) // If IOPMConnectionCreate unavailable or failed, proceed with old-style power notification code below
#endif // kIOPMAcknowledgmentOptionSystemCapabilityRequirements
    {
        m->p->PowerConnection = IORegisterForSystemPower(m, &m->p->PowerPortRef, PowerChanged, &m->p->PowerNotifier);
        if (!m->p->PowerConnection) { LogMsg("mDNSPlatformInit_setup: IORegisterForSystemPower failed"); return(-1); }
        else
        {
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
            IONotificationPortSetDispatchQueue(m->p->PowerPortRef, dispatch_get_main_queue());
#else
            CFRunLoopAddSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(m->p->PowerPortRef), kCFRunLoopDefaultMode);
#endif /* MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM */
        }
    }


    // Currently this is not defined. SSL code will eventually fix this. If it becomes
    // critical, we will define this to workaround the bug in SSL.
#ifdef __SSL_NEEDS_SERIALIZATION__
    SSLqueue = dispatch_queue_create("com.apple.mDNSResponder.SSLQueue", NULL);
#else
    SSLqueue = dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0);
#endif
    if (SSLqueue == mDNSNULL) LogMsg("dispatch_queue_create: SSL queue NULL");

#if MDNSRESPONDER_SUPPORTS(APPLE, IGNORE_HOSTS_FILE)
    // On device OSes (iOS, tvOS, watchOS, etc.), ignore /etc/hosts unless the OS is an internal build. When the /etc/hosts
    // file is ignored, LocalOnly auth records will be registered for localhost and broadcasthost addresses contained in the
    // standard /etc/hosts file:
    //
    //  127.0.0.1       localhost
    //  255.255.255.255 broadcasthost
    //  ::1             localhost

    if (!is_apple_internal_build())
    {
        const domainname *const localHostName     = (const domainname *) "\x9" "localhost";
        const domainname *const broadcastHostName = (const domainname *) "\xd" "broadcasthost";
        const mDNSv4Addr        localHostV4       = { { 127, 0, 0, 1 } };
        mDNSv6Addr              localHostV6;

        // Register localhost 127.0.0.1 A record.

        RegisterLocalOnlyARecord(localHostName, &localHostV4);

        // Register broadcasthost 255.255.255.255 A record.

        RegisterLocalOnlyARecord(broadcastHostName, &onesIPv4Addr);

        // Register localhost ::1 AAAA record.

        mDNSPlatformMemZero(&localHostV6, sizeof(localHostV6));
        localHostV6.b[15] = 1;
        RegisterLocalOnlyAAAARecord(localHostName, &localHostV6);
    }
    else
#endif
    {
        mDNSMacOSXUpdateEtcHosts_internal(m);
    }
    SetupLocalHostRecords();

#if MDNSRESPONDER_SUPPORTS(COMMON, DNS_PUSH)
    dso_transport_init();
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, ANALYTICS)
    dnssd_analytics_init();
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
    if (os_feature_enabled(mDNSResponder, bonjour_privacy))
    {
        mdns_trust_init();
   }
#endif


    return(mStatus_NoError);
}

mDNSexport mStatus mDNSPlatformInit(mDNS *const m)
{
#ifdef MDNS_NO_DNSINFO
    LogMsg("Note: Compiled without Apple-specific Split-DNS support");
#endif

    // Adding interfaces will use this flag, so set it now.
    m->DivertMulticastAdvertisements = !m->AdvertiseLocalAddresses;

#if MDNSRESPONDER_SUPPORTS(COMMON, SPS_CLIENT)
    m->SPSBrowseCallback = UpdateSPSStatus;
#endif // MDNSRESPONDER_SUPPORTS(COMMON, SPS_CLIENT)

    mStatus result = mDNSPlatformInit_setup(m);

    // We don't do asynchronous initialization on OS X, so by the time we get here the setup will already
    // have succeeded or failed -- so if it succeeded, we should just call mDNSCoreInitComplete() immediately
    if (result == mStatus_NoError)
    {
        mDNSCoreInitComplete(m, mStatus_NoError);
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
        initializeD2DPlugins(m);
#endif
    }
    return(result);
}

mDNSexport void mDNSPlatformClose(mDNS *const m)
{
    if (m->p->PowerConnection)
    {
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
        IONotificationPortSetDispatchQueue(m->p->PowerPortRef, NULL);
#else
        CFRunLoopRemoveSource(CFRunLoopGetMain(), IONotificationPortGetRunLoopSource(m->p->PowerPortRef), kCFRunLoopDefaultMode);
#endif
        // According to <http://developer.apple.com/qa/qa2004/qa1340.html>, a single call
        // to IORegisterForSystemPower creates *three* objects that need to be disposed individually:
        IODeregisterForSystemPower(&m->p->PowerNotifier);
        IOServiceClose            ( m->p->PowerConnection);
        IONotificationPortDestroy ( m->p->PowerPortRef);
        m->p->PowerConnection = 0;
    }

    if (m->p->Store)
    {
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
        if (!SCDynamicStoreSetDispatchQueue(m->p->Store, NULL))
        {
            LogRedact(MDNS_LOG_CATEGORY_NAT, MDNS_LOG_DEFAULT, "mDNSPlatformClose: SCDynamicStoreSetDispatchQueue failed");
        }
#else
        CFRunLoopRemoveSource(CFRunLoopGetMain(), m->p->StoreRLS, kCFRunLoopDefaultMode);
        CFRunLoopSourceInvalidate(m->p->StoreRLS);
        MDNS_DISPOSE_CF_OBJECT(m->p->StoreRLS);
#endif
        MDNS_DISPOSE_CF_OBJECT(m->p->Store);
    }

    if (m->p->PMRLS)
    {
        CFRunLoopRemoveSource(CFRunLoopGetMain(), m->p->PMRLS, kCFRunLoopDefaultMode);
        CFRunLoopSourceInvalidate(m->p->PMRLS);
        MDNS_DISPOSE_CF_OBJECT(m->p->PMRLS);
    }

    if (m->p->SysEventNotifier >= 0) { close(m->p->SysEventNotifier); m->p->SysEventNotifier = -1; }
#if MDNSRESPONDER_SUPPORTS(APPLE, D2D)
    terminateD2DPlugins();
#endif

    mDNSs32 utc = mDNSPlatformUTC();
    MarkAllInterfacesInactive(utc);
    ClearInactiveInterfaces(utc);
    CloseSocketSet(&m->p->permanentsockets);

#if !MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    if (m->p->InterfaceMonitors)
    {
        CFArrayRef monitors = m->p->InterfaceMonitors;
        m->p->InterfaceMonitors = NULL;
        const CFIndex n = CFArrayGetCount(monitors);
        for (CFIndex i = 0; i < n; i++)
        {
            mdns_interface_monitor_invalidate((mdns_interface_monitor_t) CFArrayGetValueAtIndex(monitors, i));
        }
        MDNS_DISPOSE_CF_OBJECT(monitors);
    }
#endif
}

// MARK: - General Platform Support Layer functions

mDNSexport mDNSu32 mDNSPlatformRandomNumber(void)
{
    return(arc4random());
}

mDNSexport mDNSs32 mDNSPlatformOneSecond = 1000;
mDNSexport mDNSu32 mDNSPlatformClockDivisor = 0;

mDNSexport mStatus mDNSPlatformTimeInit(void)
{
    // Notes: Typical values for mach_timebase_info:
    // tbi.numer = 1000 million
    // tbi.denom =   33 million
    // These are set such that (mach_absolute_time() * numer/denom) gives us nanoseconds;
    //          numer  / denom = nanoseconds per hardware clock tick (e.g. 30);
    //          denom  / numer = hardware clock ticks per nanosecond (e.g. 0.033)
    // (denom*1000000) / numer = hardware clock ticks per millisecond (e.g. 33333)
    // So: mach_absolute_time() / ((denom*1000000)/numer) = milliseconds
    //
    // Arithmetic notes:
    // tbi.denom is at least 1, and not more than 2^32-1.
    // Therefore (tbi.denom * 1000000) is at least one million, but cannot overflow a uint64_t.
    // tbi.denom is at least 1, and not more than 2^32-1.
    // Therefore clockdivisor should end up being a number roughly in the range 10^3 - 10^9.
    // If clockdivisor is less than 10^3 then that means that the native clock frequency is less than 1MHz,
    // which is unlikely on any current or future Macintosh.
    // If clockdivisor is greater than 10^9 then that means the native clock frequency is greater than 1000GHz.
    // When we ship Macs with clock frequencies above 1000GHz, we may have to update this code.
    struct mach_timebase_info tbi;
    kern_return_t result = mach_timebase_info(&tbi);
    if (result == KERN_SUCCESS) mDNSPlatformClockDivisor = (mDNSu32)(((uint64_t)tbi.denom * 1000000) / tbi.numer);
    return(result);
}

mDNSexport mDNSs32 mDNSPlatformRawTime(void)
{
    if (mDNSPlatformClockDivisor == 0) { LogMsg("mDNSPlatformRawTime called before mDNSPlatformTimeInit"); return(0); }

    static uint64_t last_mach_absolute_time = 0;
    //static uint64_t last_mach_absolute_time = 0x8000000000000000LL;   // Use this value for testing the alert display
    uint64_t this_mach_absolute_time = mach_absolute_time();
    if ((int64_t)this_mach_absolute_time - (int64_t)last_mach_absolute_time < 0)
    {
        LogMsg("mDNSPlatformRawTime: last_mach_absolute_time %08X%08X", last_mach_absolute_time);
        LogMsg("mDNSPlatformRawTime: this_mach_absolute_time %08X%08X", this_mach_absolute_time);
        // Update last_mach_absolute_time *before* calling NotifyOfElusiveBug()
        last_mach_absolute_time = this_mach_absolute_time;
        // Note: This bug happens all the time on 10.3
        NotifyOfElusiveBug("mach_absolute_time went backwards!",
                           "This error occurs from time to time, often on newly released hardware, "
                           "and usually the exact cause is different in each instance.\r\r"
                           "Please file a new Radar bug report with the title “mach_absolute_time went backwards” "
                           "and assign it to Radar Component “Kernel” Version “X”.");
    }
    last_mach_absolute_time = this_mach_absolute_time;

    return((mDNSs32)(this_mach_absolute_time / mDNSPlatformClockDivisor));
}

mDNSexport mDNSs32 mDNSPlatformContinuousTimeSeconds(void)
{
    const int clockid = CLOCK_MONOTONIC_RAW;
    struct timespec tm;
    clock_gettime(clockid, &tm);

    // We are only accurate to the second.
    return (mDNSs32)tm.tv_sec;
}

mDNSexport mDNSs32 mDNSPlatformUTC(void)
{
    return (mDNSs32)time(NULL);
}

// Locking is a no-op here, because we're single-threaded with a CFRunLoop, so we can never interrupt ourselves
mDNSexport void     mDNSPlatformLock   (const mDNS *const m) { (void)m; }
mDNSexport void     mDNSPlatformUnlock (const mDNS *const m) { (void)m; }
mDNSexport void     mDNSPlatformStrLCopy(     void *dst, const void *src, mDNSu32 dstlen) { mdns_strlcpy((char *)dst, (const char *)src, dstlen);}
mDNSexport mDNSu32  mDNSPlatformStrLen (                 const void *src)              { return((mDNSu32)strlen((const char*)src)); }
mDNSexport void     mDNSPlatformMemCopy(      void *dst, const void *src, mDNSu32 len) { memcpy(dst, src, len); }
mDNSexport mDNSBool mDNSPlatformMemSame(const void *dst, const void *src, mDNSu32 len) { return(memcmp(dst, src, len) == 0); }
mDNSexport int      mDNSPlatformMemCmp(const void *dst, const void *src, mDNSu32 len) { return(memcmp(dst, src, len)); }
mDNSexport void     mDNSPlatformMemZero(      void *dst,                  mDNSu32 len) { memset(dst, 0, len); }
mDNSexport void     mDNSPlatformQsort  (      void *base, int nel, int width, int (*compar)(const void *, const void *))
{
    qsort(base, nel, width, compar);
}
#if !MDNS_MALLOC_DEBUGGING
mDNSexport void *mDNSPlatformMemAllocate(mDNSu32 len)      { return(mallocL("mDNSPlatformMemAllocate", len)); }
mDNSexport void *mDNSPlatformMemAllocateClear(mDNSu32 len) { return(callocL("mDNSPlatformMemAllocateClear", len)); }
mDNSexport void  mDNSPlatformMemFree    (void *mem)                 { freeL("mDNSPlatformMemFree", mem); }
#endif

mDNSexport void mDNSPlatformSetAllowSleep(mDNSBool allowSleep, const char *reason)
{
    mDNS *const m = &mDNSStorage;
    if (allowSleep && m->p->IOPMAssertion)
    {
        LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_DEFAULT,
            "mDNSPlatformSetAllowSleep Destroying NoIdleSleep power assertion");
        IOPMAssertionRelease(m->p->IOPMAssertion);
        m->p->IOPMAssertion = 0;
    }
    else if (!allowSleep)
    {
#ifdef kIOPMAssertionTypeNoIdleSleep
        if (m->p->IOPMAssertion)
        {
            IOPMAssertionRelease(m->p->IOPMAssertion);
            m->p->IOPMAssertion = 0;
        }

        CFStringRef assertionName = CFStringCreateWithFormat(kCFAllocatorDefault, NULL, CFSTR("%s.%d %s"), getprogname(), getpid(), reason ? reason : "");
        IOPMAssertionCreateWithName(kIOPMAssertionTypeNoIdleSleep, kIOPMAssertionLevelOn, assertionName ? assertionName : CFSTR("mDNSResponder"), &m->p->IOPMAssertion);
        MDNS_DISPOSE_CF_OBJECT(assertionName);
        LogRedact(MDNS_LOG_CATEGORY_SPS, MDNS_LOG_DEFAULT,
            "mDNSPlatformSetAllowSleep Creating NoIdleSleep power assertion");
#endif
    }
}

mDNSexport void mDNSPlatformPreventSleep(mDNSu32 timeout, const char *reason)
{
    mDNS *const m = &mDNSStorage;
    if (m->p->IOPMAssertion)
    {
        LogSPS("Sleep Assertion is already being held. Will not attempt to get it again for %d seconds for %s", timeout, reason);
        return;
    }
#ifdef kIOPMAssertionTypeNoIdleSleep

#if TARGET_OS_IPHONE
    if (!IsAppleTV())
        return; // No need for maintenance wakes on non-AppleTV embedded devices.
#endif

    double timeoutVal = (double)timeout;
    CFStringRef str = CFStringCreateWithCString(NULL, reason, kCFStringEncodingUTF8);
    CFNumberRef Timeout_num = CFNumberCreate(NULL, kCFNumberDoubleType, &timeoutVal);
    CFMutableDictionaryRef assertionProperties = CFDictionaryCreateMutable(NULL, 0,
                                                                           &kCFTypeDictionaryKeyCallBacks,
                                                                           &kCFTypeDictionaryValueCallBacks);
    if (IsAppleTV())
        CFDictionarySetValue(assertionProperties, kIOPMAssertionTypeKey, kIOPMAssertPreventUserIdleSystemSleep);
    else
        CFDictionarySetValue(assertionProperties, kIOPMAssertionTypeKey, kIOPMAssertMaintenanceActivity);

    CFDictionarySetValue(assertionProperties, kIOPMAssertionTimeoutKey, Timeout_num);
    CFDictionarySetValue(assertionProperties, kIOPMAssertionNameKey,    str);

    IOPMAssertionCreateWithProperties(assertionProperties, (IOPMAssertionID *)&m->p->IOPMAssertion);
    MDNS_DISPOSE_CF_OBJECT(str);
    MDNS_DISPOSE_CF_OBJECT(Timeout_num);
    MDNS_DISPOSE_CF_OBJECT(assertionProperties);
    LogSPS("Got an idle sleep assertion for %d seconds for %s", timeout, reason);
#endif
}

mDNSexport void mDNSPlatformSendWakeupPacket(mDNSInterfaceID InterfaceID, char *EthAddr, char *IPAddr, int iteration)
{
    if (GetInterfaceSupportsWakeOnLANPacket(InterfaceID))
    {
        mDNSu32 ifindex;

        // Sanity check
        ifindex = mDNSPlatformInterfaceIndexfromInterfaceID(&mDNSStorage, InterfaceID, mDNStrue);
        if (ifindex <= 0)
        {
            LogMsg("mDNSPlatformSendWakeupPacket: ERROR!! Invalid InterfaceID %u", ifindex);
            return;
        }
        mDNSSendWakeupPacket(ifindex, EthAddr, IPAddr, iteration);
    }
}

mDNSexport mDNSBool mDNSPlatformInterfaceIsD2D(mDNSInterfaceID InterfaceID)
{
    NetworkInterfaceInfoOSX *info;

    if (InterfaceID == mDNSInterface_P2P)
        return mDNStrue;

    // mDNSInterface_BLE not considered a D2D interface for the purpose of this
    // routine, since it's not implemented via a D2D plugin.
    if (InterfaceID == mDNSInterface_BLE)
        return mDNSfalse;

    if (   (InterfaceID == mDNSInterface_Any)
        || (InterfaceID == mDNSInterfaceMark)
        || (InterfaceID == mDNSInterface_LocalOnly))
        return mDNSfalse;

    // Compare to cached AWDL interface ID.
    if (AWDLInterfaceID && (InterfaceID == AWDLInterfaceID))
        return mDNStrue;
    if (WiFiAwareInterfaceID && (InterfaceID == WiFiAwareInterfaceID))
        return mDNStrue;
    info = IfindexToInterfaceInfoOSX(InterfaceID);
    if (info == NULL)
    {
        // this log message can print when operations are stopped on an interface that has gone away
        LogInfo("mDNSPlatformInterfaceIsD2D: Invalid interface index %d", InterfaceID);
        return mDNSfalse;
    }

    return (mDNSBool) info->D2DInterface;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, AWDL)
mDNSexport mDNSBool mDNSPlatformInterfaceIsAWDL(const mDNSInterfaceID interfaceID)
{
    return ((
        (AWDLInterfaceID && (interfaceID == AWDLInterfaceID)) ||
        (WiFiAwareInterfaceID && (interfaceID == WiFiAwareInterfaceID))
    ) ? mDNStrue : mDNSfalse);
}
#endif

// Filter records send over P2P (D2D) type interfaces
// Filters all records on interfaces marked as a privacy risk
// Note that the terms P2P and D2D are used synonymously in the current code and comments.
mDNSexport mDNSBool mDNSPlatformValidRecordForInterface(const AuthRecord *rr, mDNSInterfaceID InterfaceID)
{
    if (InterfaceID != mDNSInterface_Any)
    {
        const NetworkInterfaceInfoOSX *const intf = IfindexToInterfaceInfoOSX(InterfaceID);
        if (intf && intf->isPrivacyRisk)
        {
            LogRedact(MDNS_LOG_CATEGORY_MDNS, MDNS_LOG_DEBUG, "mDNSPlatformValidRecordForInterface: Filtering privacy risk -- "
                "name: " PRI_DM_NAME ", ifname: " PUB_S ", ifid: %d", DM_NAME_PARAM(rr->resrec.name),
                intf->ifinfo.ifname, IIDPrintable(intf->ifinfo.InterfaceID));
            return mDNSfalse;
        }
    }

    // For an explicit match to a valid interface ID, return true.
    if (rr->resrec.InterfaceID == InterfaceID)
        return mDNStrue;

    // Only filtering records for D2D type interfaces, return true for all other interface types.
    if (!mDNSPlatformInterfaceIsD2D(InterfaceID))
        return mDNStrue;

    // If it's an AWDL interface the record must be explicitly marked to include AWDL.
    if (InterfaceID == AWDLInterfaceID || InterfaceID == WiFiAwareInterfaceID)
    {
        if (rr->ARType == AuthRecordAnyIncludeAWDL || rr->ARType == AuthRecordAnyIncludeAWDLandP2P)
            return mDNStrue;
        else
            return mDNSfalse;
    }

    // Send record if it is explicitly marked to include all other P2P type interfaces.
    if (rr->ARType == AuthRecordAnyIncludeP2P || rr->ARType == AuthRecordAnyIncludeAWDLandP2P)
        return mDNStrue;

    // Don't send the record over this interface.
    return mDNSfalse;
}

// Filter questions send over P2P (D2D) type interfaces.
mDNSexport mDNSBool mDNSPlatformValidQuestionForInterface(const DNSQuestion *const q, const NetworkInterfaceInfo *const intf)
{
    // For an explicit match to a valid interface ID, return true.
    if (q->InterfaceID == intf->InterfaceID)
        return mDNStrue;

    // Only filtering questions for D2D type interfaces
    if (!mDNSPlatformInterfaceIsD2D(intf->InterfaceID))
        return mDNStrue;

    // If it's an AWDL interface the question must be explicitly marked to include AWDL.
    if (intf->InterfaceID == AWDLInterfaceID || intf->InterfaceID == WiFiAwareInterfaceID)
    {
        if (q->flags & kDNSServiceFlagsIncludeAWDL)
            return mDNStrue;
        else
            return mDNSfalse;
    }

    // Sent question if it is explicitly marked to include all other P2P type interfaces.
    if (q->flags & kDNSServiceFlagsIncludeP2P)
        return mDNStrue;

    // Don't send the question over this interface.
    return mDNSfalse;
}

// Returns true unless record was received over the AWDL interface and
// the question was not specific to the AWDL interface or did not specify kDNSServiceInterfaceIndexAny
// with the kDNSServiceFlagsIncludeAWDL flag set.
mDNSexport mDNSBool   mDNSPlatformValidRecordForQuestion(const ResourceRecord *const rr, const DNSQuestion *const q)
{
    if (!rr->InterfaceID || (rr->InterfaceID == q->InterfaceID))
        return mDNStrue;

    if ((rr->InterfaceID == AWDLInterfaceID || rr->InterfaceID == WiFiAwareInterfaceID) && !(q->flags & kDNSServiceFlagsIncludeAWDL))
        return mDNSfalse;

    return mDNStrue;
}

// formating time to RFC 4034 format
mDNSexport void mDNSPlatformFormatTime(unsigned long te, mDNSu8 *buf, int bufsize)
{
    struct tm tmTime;
    time_t t = (time_t)te;
    // Time since epoch : strftime takes "tm". Convert seconds to "tm" using
    // gmtime_r first and then use strftime
    gmtime_r(&t, &tmTime);
    strftime((char *)buf, bufsize, "%Y%m%d%H%M%S", &tmTime);
}

mDNSexport mDNSs32 mDNSPlatformGetPID(void)
{
    return getpid();
}

// Schedule a function asynchronously on the main queue
mDNSexport void mDNSPlatformDispatchAsync(mDNS *const m, void *context, AsyncDispatchFunc func)
{
    // KQueueLock/Unlock is used for two purposes
    //
    // 1. We can't be running along with the KQueue thread and hence acquiring the lock
    //    serializes the access to the "core"
    //
    // 2. KQueueUnlock also sends a message wake up the KQueue thread which in turn wakes
    //    up and calls udsserver_idle which schedules the messages across the uds socket.
    //    If "func" delivers something to the uds socket from the dispatch thread, it will
    //    not be delivered immediately if not for the Unlock.
    dispatch_async(dispatch_get_main_queue(), ^{
        KQueueLock();
        func(m, context);
        KQueueUnlock("mDNSPlatformDispatchAsync");
#ifdef MDNSRESPONDER_USES_LIB_DISPATCH_AS_PRIMARY_EVENT_LOOP_MECHANISM
        // KQueueUnlock is a noop. Hence, we need to run kick off the idle loop
        // to handle any message that "func" might deliver.
        TriggerEventCompletion();
#endif
    });
}

// definitions for device-info record construction
#define DEVINFO_MODEL       "model="
#define DEVINFO_MODEL_LEN   sizeof_string(DEVINFO_MODEL)

#define OSX_VER         "osxvers="
#define OSX_VER_LEN     sizeof_string(OSX_VER)
#define VER_NUM_LEN     2  // 2 digits of version number added to base string

#define MODEL_RGB_COLOR       "ecolor="
#define MODEL_INDEX_COLOR     "icolor="
#define MODEL_COLOR_LEN       sizeof_string(MODEL_RGB_COLOR) // Same len as MODEL_INDEX_COLOR
#define MODEL_COLOR_VALUE_LEN sizeof_string("255,255,255")   // 'r,g,b', 'i' MAXUINT32('4294967295')

// Bytes available in TXT record for model name after subtracting space for other
// fixed size strings and their length bytes.
#define MAX_MODEL_NAME_LEN   (256 - (DEVINFO_MODEL_LEN + 1) - (OSX_VER_LEN + VER_NUM_LEN + 1) - (MODEL_COLOR_LEN + MODEL_COLOR_VALUE_LEN + 1))

// Initialize device-info TXT record contents and return total length of record data.
mDNSexport mDNSu32 initializeDeviceInfoTXT(mDNS *m, mDNSu8 *ptr)
{
    mDNSu8 *bufferStart = ptr;
    mDNSu8 len = m->HIHardware.c[0] < MAX_MODEL_NAME_LEN ? m->HIHardware.c[0] : MAX_MODEL_NAME_LEN;

    *ptr = DEVINFO_MODEL_LEN + len; // total length of DEVINFO_MODEL string plus the hardware name string
    ptr++;
    mDNSPlatformMemCopy(ptr, DEVINFO_MODEL, DEVINFO_MODEL_LEN);
    ptr += DEVINFO_MODEL_LEN;
    mDNSPlatformMemCopy(ptr, m->HIHardware.c + 1, len);
    ptr += len;

    // only include this string for OSX
    if (OSXVers)
    {
        char    ver_num[VER_NUM_LEN + 1]; // version digits + null written by snprintf
        *ptr = OSX_VER_LEN + VER_NUM_LEN; // length byte
        ptr++;
        mDNSPlatformMemCopy(ptr, OSX_VER, OSX_VER_LEN);
        ptr += OSX_VER_LEN;
        // convert version number to ASCII, add 1 for terminating null byte written by snprintf()
        // WARNING: This code assumes that OSXVers is always exactly two digits
        snprintf(ver_num, VER_NUM_LEN + 1, "%d", OSXVers);
        mDNSPlatformMemCopy(ptr, ver_num, VER_NUM_LEN);
        ptr += VER_NUM_LEN;

#define MAX_COLOR_LEN (MODEL_COLOR_VALUE_LEN + 1)
        char color[MAX_COLOR_LEN]; // Color string value + null written by snprintf
        util_enclosure_color_t color_type = util_get_enclosure_color_str(color, MAX_COLOR_LEN, &len);
        if (color_type != util_enclosure_color_none && len < MAX_COLOR_LEN)
        {
            *ptr = MODEL_COLOR_LEN + len; // length byte
            ptr++;

            if (color_type == util_enclosure_color_rgb) {
                mDNSPlatformMemCopy(ptr, MODEL_RGB_COLOR, MODEL_COLOR_LEN);
            } else {
                mDNSPlatformMemCopy(ptr, MODEL_INDEX_COLOR, MODEL_COLOR_LEN);
            }
            ptr += MODEL_COLOR_LEN;

            mDNSPlatformMemCopy(ptr, color, len);
            ptr += len;
        }
    }

    return (mDNSu32)(ptr - bufferStart);
}


#if MDNSRESPONDER_SUPPORTS(APPLE, RANDOM_AWDL_HOSTNAME)
mDNSexport void GetRandomUUIDLabel(domainlabel *label)
{
    uuid_t uuid;
    uuid_string_t uuidStr;
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuidStr);
    MakeDomainLabelFromLiteralString(label, uuidStr);
}

mDNSexport void GetRandomUUIDLocalHostname(domainname *hostname)
{
    domainlabel uuidLabel;
    GetRandomUUIDLabel(&uuidLabel);
    hostname->c[0] = 0;
    AppendDomainLabel(hostname, &uuidLabel);
    AppendLiteralLabelString(hostname, "local");
}
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_ANALYTICS) || MDNSRESPONDER_SUPPORTS(APPLE, RUNTIME_MDNS_METRICS)
mDNSexport void DNSMetricsClear(DNSMetrics *const metrics)
{
    mDNSPlatformMemZero(metrics, (mDNSu32)sizeof(*metrics));
}
#endif

mDNSlocal void EnumerateLocalRecords(const mrcs_record_applier_t applier)
{
    CFMutableSetRef excludedNames = CFSetCreateMutable(kCFAllocatorDefault, 0, &mdns_domain_name_cf_set_callbacks);
    KQueueLock();
    if (excludedNames)
    {
        // Exclude .local records that have the same name as our unique AuthRecords as well as our device-info record,
        // which is not registered as a unique record, but as an advisory record (kDNSRecordTypeAdvisory).
        for (const AuthRecord *ar = mDNSStorage.ResourceRecords; ar; ar = ar->next)
        {
            const ResourceRecord *const rr = &ar->resrec;
            if (IsSubdomain(rr->name, &localdomain))
            {
                if ((rr->RecordType & kDNSRecordTypeUniqueMask) || IsSubdomain(rr->name, &LocalDeviceInfoName))
                {
                    mdns_domain_name_t name = mdns_domain_name_create_with_labels(rr->name->c, mDNSNULL);
                    if (name)
                    {
                        CFSetAddValue(excludedNames, name);
                    }
                    mdns_forget(&name);
                }
            }
        }
    }
    mDNSu32 slot;
    const CacheGroup *cg;
    mDNS *const m = &mDNSStorage;
    FORALL_CACHEGROUPS(slot, cg)
    {
        if (cg->name && IsSubdomain(cg->name, &localdomain))
        {
            mdns_domain_name_t name = mdns_domain_name_create_with_labels(cg->name->c, mDNSNULL);
            if (name && (!excludedNames || !CFSetContainsValue(excludedNames, name)))
            {
                mDNSBool nameIsEligible = mDNSfalse;
                const mDNSBool nameIsDeviceInfo = IsSubdomain(cg->name, &LocalDeviceInfoName);
                const ResourceRecord *deviceInfoTXT = mDNSNULL;
                const mDNSAddr *bestSourceAddr = mDNSNULL;
                mDNSBool bestSourceAddrIsLinkLocal = mDNSfalse;
                for (const CacheRecord *cr = cg->members; cr; cr = cr->next)
                {
                    // A cache group name is eligible for being passed to the applier if the cache group has at least
                    // one non-NSEC cache record. The reason for this is that when our own records get deregistered,
                    // the cached copies of the records get flushed from our local cache, but the accompanying NSEC
                    // records currently do not. So we don't want to pass the names of records that have recently been
                    // deregistered by us just because of stray lone NSEC records.
                    const ResourceRecord *const rr = &cr->resrec;
                    if (rr->rrtype == kDNSType_NSEC)
                    {
                        continue;
                    }
                    nameIsEligible = mDNStrue;
                    const mDNSAddr *const sourceAddr = &cr->sourceAddress;
                    if (nameIsDeviceInfo)
                    {
                        // If the cache group name is a subdomain of _device-info._tcp.local then the caller is
                        // expecting to be provided with the RDATA of a device info TXT record with the same name. If
                        // that TXT record is found, then use the source address of the TXT record instead of the source
                        // address of a non-TXT record with the same name.
                        if ((rr->rrtype == kDNSType_TXT) && (rr->RecordType != kDNSRecordTypePacketNegative))
                        {
                            deviceInfoTXT = rr;
                            bestSourceAddr = sourceAddr;
                            break;
                        }
                    }
                    // If there are multiple source addresses from multiple records with the same name, prefer a
                    // non-link-local address since it's more specific to the local network.
                    if (!bestSourceAddr)
                    {
                        switch (sourceAddr->type)
                        {
                            case mDNSAddrType_IPv4:
                            case mDNSAddrType_IPv6:
                                bestSourceAddr = sourceAddr;
                                bestSourceAddrIsLinkLocal = mDNSAddressIsLinkLocal(bestSourceAddr);
                                break;

                            default:
                                break;
                        }
                    }
                    else
                    {
                        if (bestSourceAddrIsLinkLocal && !mDNSAddressIsLinkLocal(sourceAddr))
                        {
                            bestSourceAddr = sourceAddr;
                            bestSourceAddrIsLinkLocal = mDNSfalse;
                        }
                    }
                    if (!nameIsDeviceInfo && bestSourceAddr && !bestSourceAddrIsLinkLocal)
                    {
                        break;
                    }
                }
                if (nameIsEligible)
                {
                    sockaddr_ip sourceAddr;
                    mDNSPlatformMemZero(&sourceAddr, sizeof(sourceAddr));
                    sourceAddr.sa.sa_family = AF_UNSPEC;
                    if (bestSourceAddr)
                    {
                        switch (bestSourceAddr->type)
                        {
                            case mDNSAddrType_IPv4:
                                mdns_sockaddr_in_init(&sourceAddr.v4, mDNSVal32(bestSourceAddr->ip.v4), 0);
                                break;

                            case mDNSAddrType_IPv6:
                                mdns_sockaddr_in6_init(&sourceAddr.v6, bestSourceAddr->ip.v6.b, 0, 0);
                                break;

                            default:
                                break;
                        }
                    }
                    const mDNSu8 *const rdata = deviceInfoTXT ? deviceInfoTXT->rdata->u.txt.c : mDNSNULL;
                    const mDNSu16 rdlen = deviceInfoTXT ? deviceInfoTXT->rdlength : 0;
                    applier(mdns_domain_name_get_presentation(name), rdata, rdlen, &sourceAddr);
                }
            }
            mdns_forget(&name);
        }
    }
    KQueueUnlock("enumerate .local records");
    mdns_cf_forget(&excludedNames);
}

mDNSlocal void FlushRecordCache(const char *const recordNameStr, __unused const mDNSBool useKeyTag, __unused const mDNSu16 keyTag)
{
    domainname recordName;
    MakeDomainNameFromDNSNameString(&recordName, recordNameStr);
    mDNS *const m = &mDNSStorage;
    mDNSu32 slot;
    const CacheGroup *cg;
    KQueueLock();
    mDNS_Lock(m);
    FORALL_CACHEGROUPS(slot, cg)
    {
        if (cg->name && SameDomainName(cg->name, &recordName))
        {
            for (CacheRecord *cr = cg->members; cr; cr = cr->next)
            {
                mDNS_PurgeCacheResourceRecord(m, cr);
            }
        }
    }
    mDNS_Unlock(m);
    KQueueUnlock("FlushRecordCache");
}

mDNSlocal void FlushRecordCacheByName(const char *const recordNameStr)
{
    FlushRecordCache(recordNameStr, mDNSfalse, 0);
}

mDNSlocal void FlushRecordCacheByNameAndKeyTag(const char *const recordNameStr, const mDNSu16 keyTag)
{
    // The ability to flush cache records by both name and key tag will be implemented via
    // rdar://124590981 (Add ability to flush cache records by key tag).
    FlushRecordCache(recordNameStr, mDNStrue, keyTag);
}

const struct mrcs_server_record_cache_handlers_s kMRCServerRecordCacheHandlers =
{
    .enumerate_local_records = EnumerateLocalRecords,
    .flush_by_name = FlushRecordCacheByName,
    .flush_by_name_and_key_tag = FlushRecordCacheByNameAndKeyTag,
};

#ifdef UNIT_TEST
#include "../unittests/mdns_macosx_ut.c"
#endif
