/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

$Log: dnssd_clientstub.c,v $
Revision 1.9  2003/08/15 21:30:39  cheshire
Bring up to date with LibInfo version

Revision 1.8  2003/08/13 23:54:52  ksekar
Bringing dnssd_clientstub.c up to date with Libinfo, per radar 3376640

Revision 1.7  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

 */

#include "dnssd_ipc.h"

#define CTL_PATH_PREFIX "/tmp/dnssd_clippath."
// error socket (if needed) is named "dnssd_clipath.[pid].xxx:n" where xxx are the
// last 3 digits of the time (in seconds) and n is the 6-digit microsecond time

// general utility functions
static DNSServiceRef connect_to_server(void);
DNSServiceErrorType deliver_request(void *msg, DNSServiceRef sdr, int reuse_sd);
static ipc_msg_hdr *create_hdr(int op, int *len, char **data_start, int reuse_socket);
static int my_read(int sd, char *buf, int len);
static int my_write(int sd, char *buf, int len);
static int domain_ends_in_dot(const char *dom);
// server response handlers
static void handle_query_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *msg);
static void handle_browse_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data);
static void handle_regservice_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data);
static void handle_regrecord_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data);
static void handle_enumeration_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data);
static void handle_resolve_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data);

typedef struct _DNSServiceRef_t
    {
    int sockfd;  // connected socket between client and daemon
    int op;      // request/reply_op_t
    process_reply_callback process_reply;
    void *app_callback;
    void *app_context;
    uint32_t max_index;  //largest assigned record index - 0 if no additl. recs registered
    } _DNSServiceRef_t;

typedef struct _DNSRecordRef_t
    {
    void *app_context;
    DNSServiceRegisterRecordReply app_callback;
    DNSRecordRef recref;
    int record_index;  // index is unique to the ServiceDiscoveryRef
    DNSServiceRef sdr;
    } _DNSRecordRef_t;


// exported functions

int DNSServiceRefSockFD(DNSServiceRef sdRef)
    {
    if (!sdRef) return -1;
    return sdRef->sockfd;
    }

// handle reply from server, calling application client callback.  If there is no reply
// from the daemon on the socket contained in sdRef, the call will block.
DNSServiceErrorType DNSServiceProcessResult(DNSServiceRef sdRef)
    {
    ipc_msg_hdr hdr;
    char *data;

    if (!sdRef || sdRef->sockfd < 0 || !sdRef->process_reply) 
        return kDNSServiceErr_BadReference;

    if (my_read(sdRef->sockfd, (void *)&hdr, sizeof(hdr)) < 0) 
        return kDNSServiceErr_Unknown;
    if (hdr.version != VERSION)
        return kDNSServiceErr_Incompatible;
    data = malloc(hdr.datalen);
    if (!data) return kDNSServiceErr_NoMemory;
    if (my_read(sdRef->sockfd, data, hdr.datalen) < 0) 
        return kDNSServiceErr_Unknown;
    sdRef->process_reply(sdRef, &hdr, data);
    return kDNSServiceErr_Unknown;
    }


void DNSServiceRefDeallocate(DNSServiceRef sdRef)
    {
    if (!sdRef) return;
    if (sdRef->sockfd > 0) close(sdRef->sockfd);
    free(sdRef);
    }


DNSServiceErrorType DNSServiceResolve
    (
    DNSServiceRef                       *sdRef,
    const DNSServiceFlags               flags,
    const uint32_t                      interfaceIndex,
    const char                          *name,
    const char                          *regtype,
    const char                          *domain,
    const DNSServiceResolveReply        callBack,
    void                                *context
    )
    {
    char *msg = NULL, *ptr;
    int len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;
    
    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;
    
    // calculate total message length
    len = sizeof(flags);
    len += sizeof(interfaceIndex);
    len += strlen(name) + 1;
    len += strlen(regtype) + 1;
    len += strlen(domain) + 1;

    hdr = create_hdr(resolve_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (void *)hdr;

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(name, &ptr);
    put_string(regtype, &ptr);
    put_string(domain, &ptr);
    
    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }
    sdr->op = resolve_request;
    sdr->process_reply = handle_resolve_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;
    
    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }
    
    
static void handle_resolve_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    char fullname[kDNSServiceMaxDomainName];
    char target[kDNSServiceMaxDomainName];
    uint16_t port, txtlen;
    uint32_t ifi;
    DNSServiceErrorType err;
    char *txtrecord;
    
    (void)hdr;          //unused
    
    flags = get_flags(&data);
    ifi = get_long(&data);
    err = get_error_code(&data);
    get_string(&data, fullname, kDNSServiceMaxDomainName);
    get_string(&data, target, kDNSServiceMaxDomainName);
    port = get_short(&data);
    txtlen = get_short(&data);
    txtrecord = get_rdata(&data, txtlen);
    
    ((DNSServiceResolveReply)sdr->app_callback)(sdr, flags, ifi, err, fullname, target, port, txtlen, txtrecord, sdr->app_context);
    }
    
    


DNSServiceErrorType DNSServiceQueryRecord
(
 DNSServiceRef                          *sdRef,
 const DNSServiceFlags                   flags,
 const uint32_t                         interfaceIndex,
 const char                             *name,
 const uint16_t                         rrtype,
 const uint16_t                         rrclass,
 const DNSServiceQueryRecordReply       callBack,
 void                                   *context
 )
    {
    char *msg = NULL, *ptr;
    int len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;
    
    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

    if (!name) name = "\0";

    // calculate total message length
    len = sizeof(flags);
    len += sizeof(uint32_t);  //interfaceIndex
    len += strlen(name) + 1;
    len += 2 * sizeof(uint16_t);  // rrtype, rrclass

    hdr = create_hdr(query_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (void *)hdr;

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(name, &ptr);
    put_short(rrtype, &ptr);
    put_short(rrclass, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }

    sdr->op = query_request;
    sdr->process_reply = handle_query_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;
    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }


static void handle_query_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex, ttl;
    DNSServiceErrorType errorCode;
    char name[256]; 
    uint16_t rrtype, rrclass, rdlen;
    char *rdata;
    (void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);
    (get_string(&data, name, 256) < 0);
    rrtype = get_short(&data);
    rrclass = get_short(&data);
    rdlen = get_short(&data);
    rdata = get_rdata(&data, rdlen);
    ttl = get_long(&data);
    if (!rdata) return;
    ((DNSServiceQueryRecordReply)sdr->app_callback)(sdr, flags, interfaceIndex, errorCode, name, rrtype, rrclass,
                                              rdlen, rdata, ttl, sdr->app_context);
    return;
    }

DNSServiceErrorType DNSServiceBrowse
(
 DNSServiceRef                      *sdRef,
 const DNSServiceFlags              flags,
 const uint32_t                     interfaceIndex,
 const char                         *regtype,
 const char                         *domain,
 const DNSServiceBrowseReply        callBack,
 void                               *context
 )
    {
    char *msg = NULL, *ptr;
    int len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;

    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

    if (!domain) domain = "";

    len = sizeof(flags);
    len += sizeof(interfaceIndex);
    len += strlen(regtype) + 1;
    len += strlen(domain) + 1;

    hdr = create_hdr(browse_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (char *)hdr;
    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(regtype, &ptr);
    put_string(domain, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }
    sdr->op = browse_request;
    sdr->process_reply = handle_browse_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;
    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }




static void handle_browse_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags      flags;
    uint32_t                      interfaceIndex;
    DNSServiceErrorType      errorCode;
    char replyName[256], replyType[256], replyDomain[256];
        (void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);
    get_string(&data, replyName, 256);
    get_string(&data, replyType, 256);
    get_string(&data, replyDomain, 256);
    ((DNSServiceBrowseReply)sdr->app_callback)(sdr, flags, interfaceIndex, errorCode, replyName, replyType, replyDomain, sdr->app_context);
    }


DNSServiceErrorType DNSServiceRegister
    (
    DNSServiceRef                       *sdRef,
    const DNSServiceFlags               flags,
    const uint32_t                      interfaceIndex,
    const char                          *name,         
    const char                          *regtype,  
    const char                          *domain,       
    const char                          *host,         
    const uint16_t                      port,
    const uint16_t                      txtLen,
    const void                          *txtRecord,    
    const DNSServiceRegisterReply       callBack,      
    void                                *context       
    )
    {
    char *msg = NULL, *ptr;
    int len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;

    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

    if (!name) name = "";
    if (!regtype) return kDNSServiceErr_BadParam;
    if (!domain) domain = "";
    if (!host) host = "";
    if (!txtRecord) (char *)txtRecord = "";
    
    // auto-name must also have auto-rename
    if (!name[0]  && (flags & kDNSServiceFlagsNoAutoRename))
        return kDNSServiceErr_BadParam;

    // no callback must have auto-name
    if (!callBack && name[0]) return kDNSServiceErr_BadParam;

    len = sizeof(DNSServiceFlags);
    len += sizeof(uint32_t);  // interfaceIndex
    len += strlen(name) + strlen(regtype) + strlen(domain) + strlen(host) + 4;
    len += 2 * sizeof(uint16_t);  // port, txtLen
    len += txtLen;

    hdr = create_hdr(reg_service_request, &len, &ptr, 1);
    if (!hdr) goto error;
    if (!callBack) hdr->flags |= IPC_FLAGS_NOREPLY;
    msg = (char *)hdr;
    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(name, &ptr);
    put_string(regtype, &ptr);
    put_string(domain, &ptr);
    put_string(host, &ptr);
    put_short(port, &ptr);
    put_short(txtLen, &ptr);
    put_rdata(txtLen, txtRecord, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }
        
    sdr->op = reg_service_request;
    sdr->process_reply = callBack ? handle_regservice_response : NULL;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;

    return err;
    
error:
    if (msg) free(msg);
    if (*sdRef)         { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }


static void handle_regservice_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex;
    DNSServiceErrorType errorCode;
    char name[256], regtype[256], domain[256];
        (void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);
    get_string(&data, name, 256);
    get_string(&data, regtype, 256);
    get_string(&data, domain, 256);
    ((DNSServiceRegisterReply)sdr->app_callback)(sdr, flags, errorCode, name, regtype, domain, sdr->app_context);
    }

DNSServiceErrorType DNSServiceEnumerateDomains
(
 DNSServiceRef                    *sdRef,
 const DNSServiceFlags            flags,
 const uint32_t                   interfaceIndex,
 const DNSServiceDomainEnumReply  callBack,
 void                             *context
 )
    {
    char *msg = NULL, *ptr;
    int len;
    ipc_msg_hdr *hdr;
    DNSServiceRef sdr;
    DNSServiceErrorType err;


    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = NULL;

    len = sizeof(DNSServiceFlags);
    len += sizeof(uint32_t);

    hdr = create_hdr(enumeration_request, &len, &ptr, 1);
    if (!hdr) goto error;
    msg = (void *)hdr;

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);

    sdr = connect_to_server();
    if (!sdr) goto error;
    err = deliver_request(msg, sdr, 1);
    if (err)
        {
        DNSServiceRefDeallocate(sdr);
        return err;
        }

    sdr->op = enumeration_request;
    sdr->process_reply = handle_enumeration_response;
    sdr->app_callback = callBack;
    sdr->app_context = context;
    *sdRef = sdr;
    return err;

error:
    if (msg) free(msg);
    if (*sdRef) { free(*sdRef);  *sdRef = NULL; }
    return kDNSServiceErr_Unknown;
    }


static void handle_enumeration_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex;
    DNSServiceErrorType err;
    char domain[256];
        (void)hdr;//Unused

    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    err = get_error_code(&data);
    get_string(&data, domain, 256);
    ((DNSServiceDomainEnumReply)sdr->app_callback)(sdr, flags, interfaceIndex, err, domain, sdr->app_context);
    }


DNSServiceErrorType DNSServiceCreateConnection(DNSServiceRef *sdRef)
    {
    if (!sdRef) return kDNSServiceErr_BadParam;
    *sdRef = connect_to_server();
    if (!*sdRef)
            return kDNSServiceErr_Unknown;
    (*sdRef)->op = connection;
    (*sdRef)->process_reply = handle_regrecord_response;
    return 0;
    }



static void handle_regrecord_response(DNSServiceRef sdr, ipc_msg_hdr *hdr, char *data)
    {
    DNSServiceFlags flags;
    uint32_t interfaceIndex;
    DNSServiceErrorType errorCode;
    DNSRecordRef rref = hdr->client_context.context;
    
    if (sdr->op != connection) 
        {
        rref->app_callback(rref->sdr, rref, 0, kDNSServiceErr_Unknown, rref->app_context);
        return;
        }
    flags = get_flags(&data);
    interfaceIndex = get_long(&data);
    errorCode = get_error_code(&data);

    rref->app_callback(rref->sdr, rref, flags, errorCode, rref->app_context);
    }

DNSServiceErrorType DNSServiceRegisterRecord
(
 const DNSServiceRef                    sdRef,
 DNSRecordRef                           *RecordRef,  
 const DNSServiceFlags                  flags,
 const uint32_t                         interfaceIndex,
 const char                             *fullname,
 const uint16_t                         rrtype,
 const uint16_t                         rrclass,
 const uint16_t                         rdlen,
 const void                             *rdata,
 const uint32_t                         ttl,
 const DNSServiceRegisterRecordReply    callBack,
 void                                   *context
 )
    {
    char *msg = NULL, *ptr;
    int len;
    ipc_msg_hdr *hdr = NULL;
    DNSServiceRef tmp = NULL;
    DNSRecordRef rref = NULL;
    
    if (!sdRef || sdRef->op != connection || sdRef->sockfd < 0) 
        return kDNSServiceErr_BadReference;
    *RecordRef = NULL;
    
    len = sizeof(DNSServiceFlags);
    len += 2 * sizeof(uint32_t);  // interfaceIndex, ttl
    len += 3 * sizeof(uint16_t);  // rrtype, rrclass, rdlen
    len += strlen(fullname) + 1;
    len += rdlen;

    hdr = create_hdr(reg_record_request, &len, &ptr, 0);
    if (!hdr) goto error;
    msg = (char *)hdr;
    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(fullname, &ptr);
    put_short(rrtype, &ptr);
    put_short(rrclass, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
    put_long(ttl, &ptr);

    rref = malloc(sizeof(_DNSRecordRef_t));
    if (!rref) goto error;
    rref->app_context = context;
    rref->app_callback = callBack;
    rref->record_index = sdRef->max_index++;
    rref->sdr = sdRef;
    *RecordRef = rref;
    hdr->client_context.context = rref;
    hdr->reg_index = rref->record_index;  
    
    return deliver_request(msg, sdRef, 0);

error:
    if (rref) free(rref);
    if (tmp) free(tmp);
    if (hdr) free(hdr);
    return kDNSServiceErr_Unknown;
    }

//sdRef returned by DNSServiceRegister()
DNSServiceErrorType DNSServiceAddRecord
    (
    const DNSServiceRef                 sdRef,
    DNSRecordRef                        *RecordRef,
    const DNSServiceFlags               flags,
    const uint16_t                      rrtype,
    const uint16_t                      rdlen,
    const void                          *rdata,
    const uint32_t                      ttl
    )
    {
    ipc_msg_hdr *hdr;
    int len = 0;
    char *ptr;
    DNSRecordRef rref;

    if (!sdRef || (sdRef->op != reg_service_request) || !RecordRef) 
        return kDNSServiceErr_BadReference;
    *RecordRef = NULL;
    
    len += 2 * sizeof(uint16_t);  //rrtype, rdlen
    len += rdlen;
    len += sizeof(uint32_t);
    len += sizeof(DNSServiceFlags);

    hdr = create_hdr(add_record_request, &len, &ptr, 0);
    if (!hdr) return kDNSServiceErr_Unknown;
    put_flags(flags, &ptr);
    put_short(rrtype, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
    put_long(ttl, &ptr);

    rref = malloc(sizeof(_DNSRecordRef_t));
    if (!rref) goto error;
    rref->app_context = NULL;
    rref->app_callback = NULL;
    rref->record_index = sdRef->max_index++;
    rref->sdr = sdRef;
    *RecordRef = rref;
    hdr->client_context.context = rref;
    hdr->reg_index = rref->record_index;  
    return deliver_request((char *)hdr, sdRef, 0);

error:
    if (hdr) free(hdr);
    if (rref) free(rref);
    if (*RecordRef) *RecordRef = NULL;
    return kDNSServiceErr_Unknown;
}
    

//DNSRecordRef returned by DNSServiceRegisterRecord or DNSServiceAddRecord
DNSServiceErrorType DNSServiceUpdateRecord
    (
    const DNSServiceRef                 sdRef,
    DNSRecordRef                        RecordRef,
    const DNSServiceFlags               flags,
    const uint16_t                      rdlen,
    const void                          *rdata,
    const uint32_t                      ttl
    )
    {
    ipc_msg_hdr *hdr;
    int len = 0;
    char *ptr;

    if (!sdRef || !RecordRef || !sdRef->max_index) 
        return kDNSServiceErr_BadReference;
    
    len += sizeof(uint16_t);
    len += rdlen;
    len += sizeof(uint32_t);
    len += sizeof(DNSServiceFlags);

    hdr = create_hdr(update_record_request, &len, &ptr, 0);
    if (!hdr) return kDNSServiceErr_Unknown;
    hdr->reg_index = RecordRef ? RecordRef->record_index : TXT_RECORD_INDEX;
    put_flags(flags, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
    put_long(ttl, &ptr);
    return deliver_request((char *)hdr, sdRef, 0);
    }
    


DNSServiceErrorType DNSServiceRemoveRecord
(
 const DNSServiceRef            sdRef,
 const DNSRecordRef             RecordRef,
 const DNSServiceFlags          flags
 )
    {
    ipc_msg_hdr *hdr;
    int len = 0;
    char *ptr;
    DNSServiceErrorType err;

    if (!sdRef || !RecordRef || !sdRef->max_index) 
        return kDNSServiceErr_BadReference;
    
    len += sizeof(flags);
    hdr = create_hdr(remove_record_request, &len, &ptr, 0);
    if (!hdr) return kDNSServiceErr_Unknown;
    hdr->reg_index = RecordRef->record_index;
    put_flags(flags, &ptr);
    err = deliver_request((char *)hdr, sdRef, 0);
    if (!err) free(RecordRef);
    return err;
    }


void DNSServiceReconfirmRecord
(
 const DNSServiceFlags              flags,
 const uint32_t                     interfaceIndex,
 const char                         *fullname,
 const uint16_t                     rrtype,
 const uint16_t                     rrclass,
 const uint16_t                     rdlen,
 const void                         *rdata
 )
    {
    char *ptr;
    int len;
    ipc_msg_hdr *hdr;
    DNSServiceRef tmp;

    len = sizeof(DNSServiceFlags);
    len += sizeof(uint32_t);
    len += strlen(fullname) + 1;
    len += 3 * sizeof(uint16_t);
    len += rdlen;
    tmp = connect_to_server();
    if (!tmp) return;
    hdr = create_hdr(reconfirm_record_request, &len, &ptr, 1);
    if (!hdr) return;

    put_flags(flags, &ptr);
    put_long(interfaceIndex, &ptr);
    put_string(fullname, &ptr);
    put_short(rrtype, &ptr);
    put_short(rrclass, &ptr);
    put_short(rdlen, &ptr);
    put_rdata(rdlen, rdata, &ptr);
    my_write(tmp->sockfd, (char *)hdr, len);
    DNSServiceRefDeallocate(tmp);
    }
        
        
int DNSServiceConstructFullName 
    (
    char                      *fullName,
    const char                *service,      /* may be NULL */
    const char                *regtype,
    const char                *domain
    )
    {
    int len;
    u_char c;
    char *fn = fullName;
    const char *s = service;
    const char *r = regtype;
    const char *d = domain;
    
    if (service)
        {
        while(*s)
            {
            c = *s++;
            if (c == '.' || (c == '\\')) *fn++ = '\\';          // escape dot and backslash literals
            else if (c <= ' ')                                  // escape non-printable characters
                {
                *fn++ = '\\';
                *fn++ = (char) ('0' + (c / 100));
                *fn++ = (char) ('0' + (c / 10) % 10);
                c = (u_char)('0' + (c % 10));
                }
                *fn++ = c;
            }
        *fn++ = '.';
        }

    if (!regtype) return -1;
    len = strlen(regtype);
    if (domain_ends_in_dot(regtype)) len--;
    if (len < 4) return -1;                                     // regtype must end in _udp or _tcp
    if (strncmp((regtype + len - 4), "_tcp", 4) && strncmp((regtype + len - 4), "_udp", 4)) return -1;
    while(*r)
        *fn++ = *r++;                                                                                                                                                                                        
    if (!domain_ends_in_dot(regtype)) *fn++ = '.';
                                                                                        
    if (!domain) return -1;
    len = strlen(domain);
    if (!len) return -1;
    while(*d) 
        *fn++ = *d++;                                           
    if (!domain_ends_in_dot(domain)) *fn++ = '.';
    *fn = '\0';
    return 0;
    }
        
static int domain_ends_in_dot(const char *dom)
    {
    while(*dom && *(dom + 1))
        {
        if (*dom == '\\')       // advance past escaped byte sequence
            {           
            if (*(dom + 1) >= '0' && *(dom + 1) <= '9') dom += 4;
            else dom += 2;
            }
        else dom++;             // else read one character
        }
        return (*dom == '.');
    }



    // return a connected service ref (deallocate with DNSServiceRefDeallocate)
static DNSServiceRef connect_to_server(void)
    {
    struct sockaddr_un saddr;
    DNSServiceRef sdr;

    sdr = malloc(sizeof(_DNSServiceRef_t));
    if (!sdr) return NULL;

    if ((sdr->sockfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) 
        {
        free(sdr);
        return NULL;
        }

    saddr.sun_family = AF_LOCAL;
    strcpy(saddr.sun_path, MDNS_UDS_SERVERPATH);
    if (connect(sdr->sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) < 0)
        {
        free(sdr);
        return NULL;
        }
    return sdr; 
    }




int my_write(int sd, char *buf, int len)
    {
    if (send(sd, buf, len, MSG_WAITALL) != len)   return -1;
    return 0;
    }


// read len bytes.  return 0 on success, -1 on error
int my_read(int sd, char *buf, int len)
    {
    if (recv(sd, buf, len, MSG_WAITALL) != len)  return -1;
    return 0;
    }


DNSServiceErrorType deliver_request(void *msg, DNSServiceRef sdr, int reuse_sd)
    {
    ipc_msg_hdr *hdr = msg;
    mode_t mask;
    struct sockaddr_un caddr, daddr;  // (client and daemon address structs)
    char *path = NULL;
    int listenfd = -1, errsd = -1, len;
    DNSServiceErrorType err = kDNSServiceErr_Unknown;
    
    if (!hdr || sdr->sockfd < 0) return kDNSServiceErr_Unknown;

    if (!reuse_sd) 
        {
        // setup temporary error socket
        if ((listenfd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0) 
            goto cleanup;

        bzero(&caddr, sizeof(caddr));
        caddr.sun_family = AF_LOCAL;
        caddr.sun_len = sizeof(struct sockaddr_un);
        path = (char *)msg + sizeof(ipc_msg_hdr);
        strcpy(caddr.sun_path, path);
        mask = umask(0);
        if (bind(listenfd, (struct sockaddr *)&caddr, sizeof(caddr)) < 0)
          {
            umask(mask);
            goto cleanup;
          }
        umask(mask);
        listen(listenfd, 1);
        }
        
    if (my_write(sdr->sockfd, msg, hdr->datalen + sizeof(ipc_msg_hdr)) < 0)  
        goto cleanup;
    free(msg);
    msg = NULL;

    if (reuse_sd) errsd = sdr->sockfd;
    else 
        {
        len = sizeof(daddr);
        errsd = accept(listenfd, (struct sockaddr *)&daddr, &len);
        if (errsd < 0)  goto cleanup;
        }
    
    len = recv(errsd, &err, sizeof(err), MSG_WAITALL);
    if (len != sizeof(err))
        {
        err = kDNSServiceErr_Unknown;
        }
cleanup:
    if (!reuse_sd && listenfd > 0) close(listenfd);
    if (!reuse_sd && errsd > 0) close(errsd);   
    if (!reuse_sd && path) unlink(path);
    if (msg) free(msg);
    return err;
    }
    
    
    
/* create_hdr
 *
 * allocate and initialize an ipc message header.  value of len should initially be the
 * length of the data, and is set to the value of the data plus the header.  data_start 
 * is set to point to the beginning of the data section.  reuse_socket should be non-zero
 * for calls that can receive an immediate error return value on their primary socket.
 * if zero, the path to a control socket is appended at the beginning of the message buffer.
 * data_start is set past this string.
 */
     
static ipc_msg_hdr *create_hdr(int op, int *len, char **data_start, int reuse_socket)
    {
    char *msg = NULL;
    ipc_msg_hdr *hdr;
    int datalen;
    char ctrl_path[256];
    struct timeval time;

    if (!reuse_socket)
        {
        if (gettimeofday(&time, NULL) < 0) return NULL;
        sprintf(ctrl_path, "%s%d-%.3x-%.6u", CTL_PATH_PREFIX, (int)getpid(), 
                time.tv_sec & 0xFFF, time.tv_usec);

        *len += strlen(ctrl_path) + 1;
        }
    
        
    datalen = *len;
    *len += sizeof(ipc_msg_hdr);

    // write message to buffer
    msg = malloc(*len);
    if (!msg) return NULL;

    bzero(msg, *len);
    hdr = (void *)msg;
    hdr->datalen = datalen;
    hdr->version = VERSION;
    hdr->op.request_op = op;
    if (reuse_socket) hdr->flags |= IPC_FLAGS_REUSE_SOCKET;
    *data_start = msg + sizeof(ipc_msg_hdr);
    if (!reuse_socket)  put_string(ctrl_path, data_start);
    return hdr;
    }
