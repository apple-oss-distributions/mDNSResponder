/*
 * Copyright (c) 2007-2022 Apple Inc. All rights reserved.
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

#include "helper.h"
#include "mDNSMacOSX.h"
#include <dispatch/dispatch.h>
#include <arpa/inet.h>
#include <xpc/private.h>
#include <Block.h>
#include <mdns/system.h>
#include "mdns_strict.h"

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


//*************************************************************************************************************
// Globals
static dispatch_queue_t HelperQueue;

static int64_t maxwait_secs = 5LL;

#define mDNSHELPER_DEBUG LogOperation

//*************************************************************************************************************
// Utility Functions

static void HelperLog(const char *prefix, xpc_object_t o)
{
    char *desc = xpc_copy_description(o);
    mDNSHELPER_DEBUG("HelperLog %s: %s", prefix, desc);
    mdns_free(desc);
}

//*************************************************************************************************************
// XPC Funcs:
//*************************************************************************************************************


mDNSlocal xpc_connection_t Create_Connection(void)
{
    xpc_connection_t connection = xpc_connection_create_mach_service(kHelperService, HelperQueue,
        XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);
    if (connection)
    {
        xpc_connection_set_event_handler(connection, ^(xpc_object_t event)
        {
            mDNSHELPER_DEBUG("Create_Connection xpc: [%s] \n", xpc_dictionary_get_string(event, XPC_ERROR_KEY_DESCRIPTION));
        });
        xpc_connection_activate(connection);
    }
    return connection;
}

mDNSlocal int SendDict_ToServer(xpc_object_t msg, xpc_object_t *out_reply)
{
    xpc_connection_t connection;
    dispatch_semaphore_t sem = NULL;
    __block xpc_object_t reply = NULL;
    __block int errorcode = kHelperErr_NoResponse;
    
    HelperLog("SendDict_ToServer Sending msg to Daemon", msg);
    
    connection = Create_Connection();
    if (!connection)
    {
        goto exit;
    }

    sem = dispatch_semaphore_create(0);
    if (!sem)
    {
        goto exit;
    }
    
    dispatch_retain(sem); // for the block below
    xpc_connection_send_message_with_reply(connection, msg, HelperQueue, ^(xpc_object_t recv_msg)
    {
        const xpc_type_t type = xpc_get_type(recv_msg);
                                               
        if (type == XPC_TYPE_DICTIONARY)
        {
            HelperLog("SendDict_ToServer Received reply msg from Daemon", recv_msg);
            uint64_t reply_status = xpc_dictionary_get_uint64(recv_msg, kHelperReplyStatus);
            errorcode = (int)xpc_dictionary_get_int64(recv_msg, kHelperErrCode);
            
            switch (reply_status)
            {
                case kHelperReply_ACK:
                    mDNSHELPER_DEBUG("NoError: successful reply");
                    break;
                default:
                    LogMsg("default: Unexpected reply from Helper");
                    break;
            }
            reply = recv_msg;
            xpc_retain(reply);
        }
        else
        {
            LogMsg("SendDict_ToServer Received unexpected reply from daemon [%s]",
                    xpc_dictionary_get_string(recv_msg, XPC_ERROR_KEY_DESCRIPTION));
            HelperLog("SendDict_ToServer Unexpected Reply contents", recv_msg);
        }
        
        dispatch_semaphore_signal(sem);
        dispatch_semaphore_t tmp = sem;
        MDNS_DISPOSE_DISPATCH(tmp);
    });
    
    if (dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, (maxwait_secs * (int64_t)NSEC_PER_SEC))) != 0)
    {
        LogMsg("SendDict_ToServer: UNEXPECTED WAIT_TIME in dispatch_semaphore_wait");

        // If we insist on using a semaphore timeout, then cancel the connection if the timeout is reached.
        // This forces the reply block to be called if a reply wasn't received to keep things serialized.
        xpc_connection_cancel(connection);
        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    }
    if (out_reply)
    {
        *out_reply = reply;
        reply = NULL;
    }
    
    mDNSHELPER_DEBUG("SendDict_ToServer returning with errorcode[%d]", errorcode);
    
exit:
    if (connection)
    {
        xpc_connection_cancel(connection);
        MDNS_DISPOSE_XPC(connection);
    }
    MDNS_DISPOSE_DISPATCH(sem);
    MDNS_DISPOSE_XPC(reply);
    return errorcode;
}

//**************************************************************************************************************

mDNSexport mStatus mDNSHelperInit(void)
{
    HelperQueue = dispatch_queue_create("com.apple.mDNSResponder.HelperQueue", NULL);
    if (HelperQueue == NULL)
    {
        LogMsg("dispatch_queue_create: Helper queue NULL");
        return mStatus_NoMemoryErr;
    }
    return mStatus_NoError;
}

void mDNSPreferencesSetName(int key, domainlabel *old, domainlabel *new)
{
    struct
    {
        char oldname[MAX_DOMAIN_LABEL+1];
        char newname[MAX_DOMAIN_LABEL+1];
    } names;

    mDNSPlatformMemZero(names.oldname, MAX_DOMAIN_LABEL + 1);
    mDNSPlatformMemZero(names.newname, MAX_DOMAIN_LABEL + 1);

    ConvertDomainLabelToCString_unescaped(old, names.oldname);
    
    if (new)
        ConvertDomainLabelToCString_unescaped(new, names.newname);

    if ((names.newname[0] != '\0') && (strcmp(names.oldname, names.newname) != 0))
    {
        if (key == kmDNSComputerName)
        {
            // Original comment regarding why the current encoding is used:
            // We want to write the new Computer Name to System Preferences, without disturbing the user-selected
            // system-wide default character set used for things like AppleTalk NBP and NETBIOS service advertising.
            // Note that this encoding is not used for the computer name, but since both are set by the same call,
            // we need to take care to set the name without changing the character set.
            const mdns_computer_name_opts_t options = mdns_computer_name_opt_keep_current_encoding;
            const OSStatus err = mdns_system_set_computer_name_with_utf8_cstring(names.newname, kMDNSResponderID, options);
            if (err)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                    "Failed to set computer name -- name: " PRI_S ", error: %ld", names.newname, (long)err);
            }
        }
        else if (key == kmDNSLocalHostName)
        {
            const OSStatus err = mdns_system_set_local_host_name_with_utf8_cstring(names.newname, kMDNSResponderID, false);
            if (err)
            {
                LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
                    "Failed to set local hostname -- name: " PRI_S ", error: %ld", names.newname, (long)err);
            }
        }
    }

#if MDNSRESPONDER_HELPER_NOTIFIES_USER_OF_NAME_CHANGES
    mDNSHELPER_DEBUG("mDNSPreferencesSetName: XPC IPC Test oldname %s newname %s", names.oldname, names.newname);
     
    // Create Dictionary To Send
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, kHelperMode, set_name);
    
    xpc_dictionary_set_uint64(dict, kPrefsNameKey, (uint64_t)key);
    xpc_dictionary_set_string(dict, kPrefsOldName, names.oldname);
    xpc_dictionary_set_string(dict, kPrefsNewName, names.newname);
    
    SendDict_ToServer(dict, NULL);
    MDNS_DISPOSE_XPC(dict);
#endif
}

void mDNSRequestBPF(const dispatch_queue_t queue, const mhc_bpf_open_result_handler_t handler)
{
    LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG, "Requesting BPF from helper");
    mhc_bpf_open(O_RDWR, queue, handler);
}

int mDNSPowerSleepSystem(void)
{
    int err_code = kHelperErr_NotConnected;
    
    // Create Dictionary To Send
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, kHelperMode, power_req);
    xpc_dictionary_set_uint64(dict, "powerreq_key", 0);
    xpc_dictionary_set_uint64(dict, "powerreq_interval", 0);
    
    err_code = SendDict_ToServer(dict, NULL);
    MDNS_DISPOSE_XPC(dict);

    mDNSHELPER_DEBUG("mDNSPowerRequest: Using XPC IPC returning error_code %d", err_code);
    return err_code;
}

int mDNSSetLocalAddressCacheEntry(mDNSu32 ifindex, int family, const v6addr_t ip, const ethaddr_t eth)
{
    int err_code = kHelperErr_NotConnected;
    
    mDNSHELPER_DEBUG("mDNSSetLocalAddressCacheEntry: Using XPC IPC calling out to Helper: ifindex is [%d] family is [%d]", ifindex, family);
    
    // Create Dictionary To Send
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, kHelperMode, set_localaddr_cacheentry);
    
    xpc_dictionary_set_uint64(dict, "slace_ifindex", ifindex);
    xpc_dictionary_set_uint64(dict, "slace_family", (uint64_t)family);
    
    xpc_dictionary_set_data(dict, "slace_ip", (const uint8_t*)ip, sizeof(v6addr_t));
    xpc_dictionary_set_data(dict, "slace_eth", (const uint8_t*)eth, sizeof(ethaddr_t));
    
    err_code = SendDict_ToServer(dict, NULL);
    MDNS_DISPOSE_XPC(dict);

    mDNSHELPER_DEBUG("mDNSSetLocalAddressCacheEntry: Using XPC IPC returning error_code %d", err_code);
    return err_code;
}


void mDNSNotify(const char *title, const char *msg) // Both strings are UTF-8 text
{
    mhc_display_notification(title, msg);
}


int mDNSKeychainGetSecrets(CFArrayRef *result)
{
    
    CFPropertyListRef plist = NULL;
    CFDataRef bytes = NULL;
    uint64_t numsecrets = 0;
    size_t secretsCnt = 0;
    int error_code = kHelperErr_NotConnected;
    xpc_object_t reply_dict = NULL;
    const void *sec = NULL;
    
    mDNSHELPER_DEBUG("mDNSKeychainGetSecrets: Using XPC IPC calling out to Helper");
    
    // Create Dictionary To Send
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, kHelperMode, keychain_getsecrets);

    SendDict_ToServer(dict, &reply_dict);
 
    if (reply_dict != NULL)
    {
        numsecrets = xpc_dictionary_get_uint64(reply_dict, "keychain_num_secrets");
        sec = xpc_dictionary_get_data(reply_dict, "keychain_secrets", &secretsCnt);
        error_code = (int)xpc_dictionary_get_int64(reply_dict,   kHelperErrCode);
    }
 
    mDNSHELPER_DEBUG("mDNSKeychainGetSecrets: Using XPC IPC calling out to Helper: numsecrets is %u, secretsCnt is %u error_code is %d",
                     (unsigned int)numsecrets, (unsigned int)secretsCnt, error_code);
     
    if (NULL == (bytes = CFDataCreateWithBytesNoCopy(kCFAllocatorDefault, (const void*)sec, (CFIndex)secretsCnt, kCFAllocatorNull)))
    {
        error_code = kHelperErr_ApiErr;
        LogMsg("mDNSKeychainGetSecrets: CFDataCreateWithBytesNoCopy failed");
        goto fin;
    }
    
    if (NULL == (plist = CFPropertyListCreateWithData(kCFAllocatorDefault, bytes, kCFPropertyListImmutable, NULL, NULL)))
    {
        error_code = kHelperErr_ApiErr;
        LogMsg("mDNSKeychainGetSecrets: CFPropertyListCreateFromXMLData failed");
        goto fin;
    }
    
    if (CFArrayGetTypeID() != CFGetTypeID(plist))
    {
        error_code = kHelperErr_ApiErr;
        LogMsg("mDNSKeychainGetSecrets: Unexpected result type");
        MDNS_DISPOSE_CF_OBJECT(plist);
        goto fin;
    }
    
    *result = (CFArrayRef)plist;
    
    
fin:
    MDNS_DISPOSE_CF_OBJECT(bytes);
    MDNS_DISPOSE_XPC(dict);
    MDNS_DISPOSE_XPC(reply_dict);

    return error_code;
}

void mDNSSendWakeupPacket(unsigned int ifid, char *eth_addr, char *ip_addr, int iteration)
{
    // (void) ip_addr; // unused
    // (void) iteration; // unused

    mDNSHELPER_DEBUG("mDNSSendWakeupPacket: Entered ethernet address[%s],ip_address[%s], interface_id[%d], iteration[%d]",
           eth_addr, ip_addr, ifid, iteration);
    
    // Create Dictionary To Send
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, kHelperMode, send_wakepkt);
    
    xpc_dictionary_set_uint64(dict, "interface_index", ifid);
    xpc_dictionary_set_string(dict, "ethernet_address", eth_addr);
    xpc_dictionary_set_string(dict, "ip_address", ip_addr);
    xpc_dictionary_set_uint64(dict, "swp_iteration", (uint64_t)iteration);
    
    SendDict_ToServer(dict, NULL);
    MDNS_DISPOSE_XPC(dict);

}

void mDNSSendKeepalive(const v6addr_t sadd, const v6addr_t dadd, uint16_t lport, uint16_t rport, uint32_t seq, uint32_t ack, uint16_t win)
{

    mDNSHELPER_DEBUG("mDNSSendKeepalive: Using XPC IPC calling out to Helper: lport is[%d] rport is[%d] seq is[%d] ack is[%d] win is[%d]",
           lport, rport, seq, ack, win);
    
    char buf1[INET6_ADDRSTRLEN];
    char buf2[INET6_ADDRSTRLEN];
    
    buf1[0] = 0;
    buf2[0] = 0;
    
    inet_ntop(AF_INET6, sadd, buf1, sizeof(buf1));
    inet_ntop(AF_INET6, dadd, buf2, sizeof(buf2));
    mDNSHELPER_DEBUG("mDNSSendKeepalive: Using XPC IPC calling out to Helper: sadd is %s, dadd is %s", buf1, buf2);
    
    // Create Dictionary To Send
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(dict, kHelperMode, send_keepalive);
    
    xpc_dictionary_set_data(dict, "send_keepalive_sadd", (const uint8_t*)sadd, sizeof(v6addr_t));
    xpc_dictionary_set_data(dict, "send_keepalive_dadd", (const uint8_t*)dadd, sizeof(v6addr_t));
    
    xpc_dictionary_set_uint64(dict, "send_keepalive_lport", lport);
    xpc_dictionary_set_uint64(dict, "send_keepalive_rport", rport);
    xpc_dictionary_set_uint64(dict, "send_keepalive_seq", seq);
    xpc_dictionary_set_uint64(dict, "send_keepalive_ack", ack);
    xpc_dictionary_set_uint64(dict, "send_keepalive_win", win);
    
    SendDict_ToServer(dict, NULL);
    MDNS_DISPOSE_XPC(dict);

}
