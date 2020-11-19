//
//  xpc_client_advertising_proxy.h
//  mDNSResponder
//
//  Copyright (c) 2019 Apple Inc. All rights reserved.
//

#ifndef XPC_CLIENT_ADVERTISING_PROXY_H
#define XPC_CLIENT_ADVERTISING_PROXY_H

#define kDNSAdvertisingProxyService          "com.apple.srp-mdns-proxy.proxy"
#define kDNSAdvertisingProxyCommand          "xpc-command"
#define kDNSAdvertisingProxyResponseStatus   "status"

#define kDNSAdvertisingProxyEnable           "enable"
#define kDNSAdvertisingProxyListServiceTypes "list service types"
#define kDNSAdvertisingProxyListServices     "list services"
#define kDNSAdvertisingProxyListHosts        "list hosts"
#define kDNSAdvertisingProxyGetHost          "get host"
#define kDNSAdvertisingProxyFlushEntries     "flush entries"
#define kDNSAdvertisingProxyBlockService     "block service"
#define kDNSAdvertisingProxyUnblockService   "unblock service"
#define kDNSAdvertisingProxyRegenerateULA    "regenerate ULA"

#endif /* XPC_CLIENT_ADVERTISING_PROXY_H */

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
