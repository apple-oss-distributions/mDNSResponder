/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@

    Change History (most recent first):

$Log: dnssd_ipc.h,v $
Revision 1.6  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

 */

#ifndef DNSSD_IPC_H
#define DNSSD_IPC_H

#include "dns_sd.h"
#include <sys/types.h>
#include <unistd.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

//#define UDSDEBUG  // verbose debug output

// General UDS constants
#define MDNS_UDS_SERVERPATH "/var/run/mDNSResponder" 
#define LISTENQ 100
#define TXT_RECORD_INDEX -1	// record index for default text record
#define MAX_CTLPATH 256	    // longest legal control path length

// IPC data encoding constants and types
#define VERSION 1
#define IPC_FLAGS_NOREPLY 1	// set flag if no asynchronous replies are to be sent to client
#define IPC_FLAGS_REUSE_SOCKET 2 // set flag if synchronous errors are to be sent via the primary socket
                                // (if not set, first string in message buffer must be path to error socket


typedef enum
    {
    connection = 1,           // connected socket via DNSServiceConnect()
    reg_record_request,	  // reg/remove record only valid for connected sockets
    remove_record_request,
    enumeration_request,
    reg_service_request,
    browse_request,
    resolve_request,
    query_request,
    reconfirm_record_request,
    add_record_request,
    update_record_request
    } request_op_t;

typedef enum
    {
    enumeration_reply = 64,
    reg_service_reply,
    browse_reply,
    resolve_reply,
    query_reply,
    reg_record_reply
    } reply_op_t;


typedef struct ipc_msg_hdr_struct ipc_msg_hdr;


// client stub callback to process message from server and deliver results to
// client application

typedef void (*process_reply_callback)
    (
    DNSServiceRef sdr,
    ipc_msg_hdr *hdr,
    char *msg
    );

// allow 64-bit client to interoperate w/ 32-bit daemon
typedef union
    {
    void *context;
    uint32_t ptr64[2];
    } client_context_t;


typedef struct ipc_msg_hdr_struct
    {
    uint32_t version;
    uint32_t datalen;
    uint32_t flags;
    union
    	{
        request_op_t request_op;
        reply_op_t reply_op;
    	} op;
    client_context_t client_context; // context passed from client, returned by server in corresponding reply
    int reg_index;                   // identifier for a record registered via DNSServiceRegisterRecord() on a
    // socket connected by DNSServiceConnect().  Must be unique in the scope of the connection, such that and
    // index/socket pair uniquely identifies a record.  (Used to select records for removal by DNSServiceRemoveRecord())
    } ipc_msg_hdr_struct;			




// routines to write to and extract data from message buffers.
// caller responsible for bounds checking.  
// ptr is the address of the pointer to the start of the field.
// it is advanced to point to the next field, or the end of the message


void put_flags(const DNSServiceFlags flags, char **ptr);
DNSServiceFlags get_flags(char **ptr);

void put_long(const uint32_t l, char **ptr);
uint32_t get_long(char **ptr);

void put_error_code(const DNSServiceErrorType, char **ptr);
DNSServiceErrorType get_error_code(char **ptr);

int put_string(const char *str, char **ptr);
int get_string(char **ptr, char *buffer, int buflen);

void put_rdata(const int rdlen, const char *rdata, char **ptr);
char *get_rdata(char **ptr, int rdlen);  // return value is rdata pointed to by *ptr - 
                                         // rdata is not copied from buffer.

void put_short(uint16_t s, char **ptr);
uint16_t get_short(char **ptr);



#endif // DNSSD_IPC_H











