/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2012 Apple Inc. All rights reserved.
 *
 * PRIVATE DNSX CLIENT LIBRARY --FOR Apple Platforms ONLY OSX/iOS--
 * Resides in /usr/lib/libdns_services.dylib
 */

#include "dns_services_mdns.h"
#include "dns_xpc.h"
#include <xpc/xpc.h>
#include <Block.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

//*************************************************************************************************************
// Globals

#define connection_t xpc_connection_t

struct _DNSXConnRef_t
{
    connection_t      conn_ref;      // xpc_connection between client and daemon
    dispatch_queue_t  lib_q;         // internal queue created in library itself   
    void              *AppCallBack;  // Callback function ptr for Client
    dispatch_queue_t  client_q;      // Queue specified by client for scheduling its Callback
};

//*************************************************************************************************************
// Utility Functions

static bool LogDebugEnabled()
{
    return true;
}

static void LogDebug(const char *prefix, xpc_object_t o)
{
    if (!LogDebugEnabled()) 
        return;
    
    char *desc = xpc_copy_description(o);
    syslog(LOG_INFO, "%s: %s", prefix, desc); 
    free(desc);
}

//**************************************************************************************************************

void DNSXRefDeAlloc(DNSXConnRef connRef)
{
    if (!connRef)
    {
        syslog(LOG_WARNING, "dns_services: DNSXRefDeAlloc called with NULL DNSXConnRef");
        return;
    }

    // Schedule this work on the internal library queue
    dispatch_sync(connRef->lib_q, ^{

        xpc_release(connRef->conn_ref);
        connRef->AppCallBack = NULL;
        dispatch_release(connRef->client_q);

    });

    dispatch_release(connRef->lib_q);
    free(connRef);

    syslog(LOG_INFO, "dns_services: DNSXRefDeAlloc successfully DeAllocated connRef");

}

// Sends the Msg(Dictionary) to the Server
static DNSXErrorType SendMsgToServer(DNSXConnRef *connRef, xpc_object_t msg, bool old_conn)
{
    DNSXErrorType errx = kDNSX_NoError;

    LogDebug("dns_services: SendMsgToServer", msg);
    
    xpc_connection_set_event_handler((*connRef)->conn_ref, ^(xpc_object_t recv_msg)
    {
        xpc_type_t type = xpc_get_type(recv_msg);

        if (type == XPC_TYPE_DICTIONARY)
        {
            LogDebug("dns_services: SendMsgToServer SUCCESS CALLBACK FROM SERVER", recv_msg);
            syslog(LOG_INFO, "dns_services: Successfully Sent Msg to the Daemon");
            uint64_t daemon_status = xpc_dictionary_get_uint64(recv_msg, kDNSDaemonReply);
 
            // Schedule the AppCallBacks on the Client Specified Queue
            switch (daemon_status)
            {   
                case kDNSDaemonEngaged:
                        dispatch_async((*connRef)->client_q, ^{  
                                        ((DNSXEnableProxyReply)(*connRef)->AppCallBack)((*connRef), kDNSX_Engaged);
                                        }); 
                                        break;
                case kDNSMsgReceived:
                        dispatch_async((*connRef)->client_q, ^{
                                        ((DNSXEnableProxyReply)(*connRef)->AppCallBack)((*connRef), kDNSX_NoError);
                                        }); 
                                        break;
                default:
                        dispatch_async((*connRef)->client_q, ^{
                                        ((DNSXEnableProxyReply)(*connRef)->AppCallBack)((*connRef), kDNSX_UnknownErr);
                                        }); 
                                        break;
            }   

        }
        else
        {
            LogDebug("dns_services: SendMsgToServer UNEXPECTED CALLBACK FROM SERVER", recv_msg);
            syslog(LOG_WARNING, "dns_services: Connection failed since NO privileges to access service OR Daemon NOT Running");
            dispatch_async((*connRef)->client_q, ^{
                            ((DNSXEnableProxyReply)(*connRef)->AppCallBack)((*connRef), kDNSX_DaemonNotRunning);
                            });
        }
    });
    
    // To prevent Over-Resume of a connection
    if (!old_conn)
        xpc_connection_resume((*connRef)->conn_ref);
    xpc_connection_send_message((*connRef)->conn_ref, msg);
    if (!errx)
        syslog(LOG_INFO, "dns_services: SendMSgToServer sent Msg Dict successfully to Daemon");
    return errx;
}

// Creates a new DNSX Connection Reference(DNSXConnRef).
// If DNSXConnRef exists, you may want to use that depending on the use case
static DNSXErrorType InitConnection(DNSXConnRef *connRef, const char *servname, dispatch_queue_t clientq, void *AppCallBack)
{
    if (!connRef)
    {
        syslog(LOG_WARNING, "dns_services: InitConnection() called with NULL DNSXConnRef");
        return kDNSX_BadParam;   
    }

    *connRef = malloc(sizeof(struct _DNSXConnRef_t));
    if (!(*connRef))
    {
        syslog(LOG_WARNING, "dns_services: InitConnection() No memory to allocate");
        return kDNSX_NoMem;
    }

    // Initialize the DNSXConnRef  
    dispatch_retain(clientq);
    (*connRef)->client_q     = clientq;
    (*connRef)->AppCallBack  = AppCallBack;    
    (*connRef)->lib_q        = dispatch_queue_create("com.apple.mDNSResponder.libdns_services.q", NULL); 
    (*connRef)->conn_ref     = xpc_connection_create_mach_service(servname, (*connRef)->lib_q, XPC_CONNECTION_MACH_SERVICE_PRIVILEGED);

    syslog(LOG_INFO, "dns_services: InitConnection() successfully create a new DNSXConnRef");
    return kDNSX_NoError;
}

DNSXErrorType DNSXEnableProxy(DNSXConnRef *connRef, DNSProxyParameters proxyparam, IfIndex inIfindexArr[MaxInputIf], 
                               IfIndex outIfindex, dispatch_queue_t clientq, DNSXEnableProxyReply callBack)
{

    DNSXErrorType errx = kDNSX_NoError;
    bool old_conn = false;    

    // Sanity Checks
    if (!connRef || !callBack || !clientq)
    {
        syslog(LOG_WARNING, "dns_services: DNSXEnableProxy called with NULL DNSXConnRef OR Callback OR ClientQ parameter");
        return kDNSX_BadParam;
    }   

    // If no connRef, get it from InitConnection()
    if (!*connRef)
    {
        errx = InitConnection(connRef, kDNSProxyService, clientq, callBack);
        if (errx) // On error InitConnection() leaves *connRef set to NULL
        {
            syslog(LOG_WARNING, "dns_services: Since InitConnection() returned %d error returning w/o sending msg", errx);
            return errx;
        }
    }
    else // Client already has a valid connRef
    {
        old_conn = true;
    }

    // Create Dictionary To Send
    xpc_object_t dict = xpc_dictionary_create(NULL, NULL, 0); 
    if (!dict)
    {
        syslog(LOG_WARNING, "dns_services: DNSXEnableProxy could not create the Msg Dict To Send!");
        DNSXRefDeAlloc(*connRef);
        return kDNSX_DictError;
    }

    xpc_dictionary_set_uint64(dict, kDNSProxyParameters, proxyparam);

    xpc_dictionary_set_uint64(dict, kDNSInIfindex0,      inIfindexArr[0]);
    xpc_dictionary_set_uint64(dict, kDNSInIfindex1,      inIfindexArr[1]);
    xpc_dictionary_set_uint64(dict, kDNSInIfindex2,      inIfindexArr[2]); 
    xpc_dictionary_set_uint64(dict, kDNSInIfindex3,      inIfindexArr[3]);
    xpc_dictionary_set_uint64(dict, kDNSInIfindex4,      inIfindexArr[4]);

    xpc_dictionary_set_uint64(dict, kDNSOutIfindex,      outIfindex);
 
    errx = SendMsgToServer(connRef, dict, old_conn);
    xpc_release(dict);

    return errx; 
}

