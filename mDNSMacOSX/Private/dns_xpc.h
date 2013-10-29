/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2012 Apple Inc. All rights reserved.
 *
 * Defines the common interface between mDNSResponder and the Private ClientLibrary(libdnsprivate.dylib)
 * Uses XPC as the IPC Mechanism
 *
 */

#ifndef DNS_XPC_H
#define DNS_XPC_H

#define kDNSProxyService "com.apple.mDNSResponder.dnsproxy"

#define kDNSProxyParameters     "DNSProxyParameters"

#define kDNSInIfindex0          "InputArrayInterfaceIndex[0]"
#define kDNSInIfindex1          "InputArrayInterfaceIndex[1]"
#define kDNSInIfindex2          "InputArrayInterfaceIndex[2]"
#define kDNSInIfindex3          "InputArrayInterfaceIndex[3]"
#define kDNSInIfindex4          "InputArrayInterfaceIndex[4]"

#define kDNSOutIfindex          "OutputInterfaceIndex"

#define kDNSDaemonReply         "DaemonReplyStatusToClient"

typedef enum
{
    kDNSMsgReceived       =  0,
    kDNSDaemonEngaged 
} DaemonReplyStatusCodes;

#endif // DNS_XPC_H
