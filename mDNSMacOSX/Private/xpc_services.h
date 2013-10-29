/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2012 Apple Inc. All rights reserved.
 *
 *
 *
 *    File:       xpc_services.h
 *
 *    Contains:   Interfaces necessary to talk to xpc_services.c
 *
 */

#ifndef XPC_SERVICES_H
#define XPC_SERVICES_H

#include "mDNSEmbeddedAPI.h"

extern void xpc_server_init(void);
extern void xpcserver_info(mDNS *const m);

#endif // XPC_SERVICES_H
