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

$Log: SampleUDSClient.c,v $
Revision 1.7  2003/08/18 18:50:15  cheshire
Can now give "-lo" as first parameter, to test "local only" mode

Revision 1.6  2003/08/12 19:56:25  cheshire
Update to APSL 2.0

 */

#include <dns_sd.h>
#include <unistd.h>
#include <DNSServiceDiscovery/DNSServiceDiscovery.h> // include Mach API to ensure no conflicts exist
#include <CoreFoundation/CoreFoundation.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#define BIND_8_COMPAT 1
#include <nameser.h>
// T_SRV is not defined in older versions of nameser.h
#ifndef T_SRV
#define T_SRV 33
#endif

// constants
#define MAX_DOMAIN_LABEL 63
#define MAX_DOMAIN_NAME 255
#define MAX_CSTRING 2044


// data structure defs
typedef union { unsigned char b[2]; unsigned short NotAnInteger; } Opaque16;

typedef struct { u_char c[ 64]; } domainlabel;
typedef struct { u_char c[256]; } domainname;


typedef struct 
    { 
    uint16_t priority; 
    uint16_t weight; 
    uint16_t port; 
    domainname target;
    } srv_rdata;


// private function prototypes
static void sighdlr(int signo);
static char *ConvertDomainNameToCString_withescape(const domainname *const name, char *ptr, char esc);
static char *ConvertDomainLabelToCString_withescape(const domainlabel *const label, char *ptr, char esc);
//static void MyCallbackWrapper(CFSocketRef sr, CFSocketCallBackType t, CFDataRef dr, const void *i, void *context);
static void print_rdata(int type, int len, const u_char *rdata);
static void query_cb(const DNSServiceRef DNSServiceRef, const DNSServiceFlags flags, const u_int32_t interfaceIndex, const DNSServiceErrorType errorCode, const char *name, const u_int16_t rrtype, const u_int16_t rrclass, const u_int16_t rdlen, const void *rdata, const u_int32_t ttl, void *context);
static void resolve_cb(const DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget, uint16_t port, uint16_t txtLen, const char                          *txtRecord, void *context);
static void my_enum_cb( DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *replyDomain, void *context);
static void my_regecordcb(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags, DNSServiceErrorType errorCode, void *context);
static void browse_cb(DNSServiceRef sdr, DNSServiceFlags flags, uint32_t ifi, DNSServiceErrorType err, const char *serviceName, const char *regtype, const char *domain, void *context);


// globals
static DNSServiceRef sdr = NULL;
static uint32_t InterfaceIndex = 0;

static void regservice_cb(DNSServiceRef sdRef, DNSServiceFlags flags, DNSServiceErrorType errorCode, const char *name, const char *regtype, const char *domain, void *context)
	{
	#pragma unused (sdRef, flags, errorCode, context)
	printf("regservice_cb %s %s %s\n", name, regtype, domain);
	}

int main (int argc, char * argv[])  {
    int err, t, i;
    char *name, *type, *domain;
    DNSServiceFlags flags;
    DNSRecordRef recordrefs[10];
    char host[256];
    int ipaddr = 12345;	// random IP address
    
    char full[1024];
    
    // First parameter "-lo" means "local only"
    if (!strcmp(argv[1], "-lo")) { InterfaceIndex = -1; argv++; argc--; }
    
    if (signal(SIGINT, sighdlr) == SIG_ERR)  fprintf(stderr, "ERROR - can't catch interupt!\n");
    if (argc < 2) exit(1);

    if (!strcmp(argv[1], "-regrecord"))
        {
        err = DNSServiceCreateConnection(&sdr);
        if (err)
            {
            printf("DNSServiceCreateConnection returned %d\n", err);
            exit(1);
            }
        printf("registering 10 address records...\n");
        for (i = 0; i < 10; i++)
            {
            sprintf(host, "testhost-%d.local.", i);
            ipaddr++;
            err = DNSServiceRegisterRecord(sdr, &recordrefs[i], kDNSServiceFlagsUnique, InterfaceIndex, 
                host, 1, 1, 4, &ipaddr, 60, my_regecordcb, NULL);
            if (err) 
                {
                printf("DNSServiceRegisterRecord returned error %d\n", err);
                exit(1);
                }
            }
        printf("processing results...\n");
        for (i = 0; i < 10; i++) DNSServiceProcessResult(sdr);
        printf("deregistering half of the records\n");
        for (i = 0; i < 10; i++)
            {
            if (i % 2) 
                {
                err = DNSServiceRemoveRecord(sdr, recordrefs[i], 0);
                if (err) 
                    {
                    printf("DNSServiceRemoveRecord returned error %d\n" ,err);
                    exit(1);
                    }
                }
            }
        printf("sleeping 10...\n");
        sleep(10);
        printf("deregistering all remaining records\n");;
        DNSServiceRefDeallocate(sdr);
        printf("done.  sleeping 10..\n");
        sleep(10);
        exit(1);
        }
                
    if (!strcmp(argv[1], "-browse"))
        {
        if (argc < 3) exit(1);
        err = DNSServiceBrowse(&sdr, 0, InterfaceIndex, argv[2], NULL /*"local."*/, browse_cb, NULL);
        if (err) 
            {
            printf("DNSServiceBrowse returned error %d\n", err);
            exit(1);
            }
        while(1) DNSServiceProcessResult(sdr);
        }    
                            
    if (!strcmp(argv[1], "-enum"))
        {
        if (!strcmp(argv[2], "browse")) flags = kDNSServiceFlagsBrowseDomains;
        else if (!strcmp(argv[2], "register")) flags = kDNSServiceFlagsRegistrationDomains;
        else exit(1);
        
        err = DNSServiceEnumerateDomains(&sdr, flags, InterfaceIndex, my_enum_cb, NULL);
        if (err) 
            {
            printf("EnumerateDomains returned error %d\n", err);
            exit(1);
            }
        while(1) DNSServiceProcessResult(sdr);
        }
    if (!strcmp(argv[1], "-query"))
        {
        t = atol(argv[5]);
        err = DNSServiceConstructFullName(full, argv[2], argv[3], argv[4]);
        if (err) exit(1);
        printf("resolving fullname %s type %d\n", full, t);
        err = DNSServiceQueryRecord(&sdr, 0, 0, full, t, 1, query_cb, NULL);
        while (1) DNSServiceProcessResult(sdr);
        }

    if (!strcmp(argv[1], "-regservice"))
        {
        char *regtype = "_http._tcp";
		char txtstring[] = "\x0DMy Txt Record";
        if (argc > 2) name = argv[2];
        else name = NULL;
        if (argc > 3) regtype = argv[3];
		uint16_t PortAsNumber = 123;
        if (argc > 4) PortAsNumber = atoi(argv[4]);
		Opaque16 registerPort = { { PortAsNumber >> 8, PortAsNumber & 0xFF } };
        err = DNSServiceRegister(&sdr, 0, InterfaceIndex, name, regtype, "local.", NULL, registerPort.NotAnInteger, sizeof(txtstring)-1, txtstring, regservice_cb, NULL);
        if (err) 
            {
            printf("DNSServiceRegister returned error %d\n", err);
            exit(1);
            }
        while (1) DNSServiceProcessResult(sdr);
        }
    if (!strcmp(argv[1], "-resolve"))
        {
        name = argv[2];
        type = argv[3];
        domain = argv[4];
        err = DNSServiceResolve(&sdr, 0, InterfaceIndex, name, type, domain, resolve_cb, NULL);
        if (err) 
            {
            printf("DNSServiceResolve returned error %d\n", err);
            exit(1);
            }
        while(1) DNSServiceProcessResult(sdr);
        }
    exit(1);
    }    



// callbacks

// wrapper to make callbacks fit CFRunLoop callback signature
/*
static void MyCallbackWrapper(CFSocketRef sr, CFSocketCallBackType t, CFDataRef dr, const void *i, void *context)  
    {
    (void)sr;
    (void)t;
    (void)dr;
    (void)i;
    
    DNSServiceRef *sdr = context;
    DNSServiceDiscoveryProcessResult(*sdr);
    }
*/

static void browse_cb(DNSServiceRef sdr, DNSServiceFlags flags, uint32_t ifi, DNSServiceErrorType err, const char *serviceName, const char *regtype, const char *domain, void *context)
    {
    #pragma unused(sdr, ifi, context)
    
    if (err)
        {
        printf("Callback: error %d\n", err);
        return;
        }
    printf("BrowseCB: %s %s %s %s (%s)\n", serviceName, regtype, domain, (flags & kDNSServiceFlagsMoreComing ? "(more coming)" : ""), flags & kDNSServiceFlagsAdd ? "(ADD)" : "(REMOVE)");

    }

static void my_enum_cb( DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *replyDomain, void *context)
    {
    #pragma unused(sdRef, context)
    char *type;
    if (flags == kDNSServiceFlagsAdd) type = "add";
    else if (flags == kDNSServiceFlagsRemove) type = "remove";
    else if (flags == (kDNSServiceFlagsAdd | kDNSServiceFlagsDefault)) type = "add default";
    else type = "unknown";
    
    
    if (errorCode) printf("EnumerateDomainsCB: error code %d\n", errorCode);
    else printf("%s domain %s on interface %d\n", type, replyDomain, interfaceIndex);
    }
    
static void query_cb(const DNSServiceRef DNSServiceRef, const DNSServiceFlags flags, const u_int32_t interfaceIndex, const DNSServiceErrorType errorCode, const char *name, const u_int16_t rrtype, const u_int16_t rrclass, const u_int16_t rdlen, const void *rdata, const u_int32_t ttl, void *context) 
    {
    (void)DNSServiceRef;
    (void)flags;
    (void)interfaceIndex;
    (void)rrclass;
    (void)ttl;
    (void)context;
    
    if (errorCode)
        {
        printf("query callback: error==%d\n", errorCode);
        return;
        }
    printf("query callback - name = %s, rdata=\n", name);
    print_rdata(rrtype, rdlen, rdata);
    }
 
static void resolve_cb(const DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget, uint16_t port, uint16_t txtLen, const char *txtRecord, void *context)
    {
    int i;
    
    #pragma unused(sdRef, flags, interfaceIndex, errorCode, context, txtRecord)
    printf("Resolved %s to %s:%d (%d bytes txt data)\n", fullname, hosttarget, port, txtLen);
    printf("TXT Data:\n");
    for (i = 0; i < txtLen; i++)
        if (txtRecord[i] >= ' ') printf("%c", txtRecord[i]);
    }



static void my_regecordcb(DNSServiceRef sdRef, DNSRecordRef RecordRef, DNSServiceFlags flags, DNSServiceErrorType errorCode, void *context)
    {
    #pragma unused (sdRef, RecordRef, flags, context)
    if (errorCode) printf("regrecord CB received error %d\n", errorCode);
    else printf("regrecord callback - no errors\n");
    }


// resource record data interpretation routines
static char *ConvertDomainLabelToCString_withescape(const domainlabel *const label, char *ptr, char esc)
    {
    const u_char *      src = label->c;                         // Domain label we're reading
    const u_char        len = *src++;                           // Read length of this (non-null) label
    const u_char *const end = src + len;                        // Work out where the label ends
    if (len > MAX_DOMAIN_LABEL) return(NULL);           // If illegal label, abort
    while (src < end)                                           // While we have characters in the label
        {
        u_char c = *src++;
        if (esc)
            {
            if (c == '.')                                       // If character is a dot,
                *ptr++ = esc;                                   // Output escape character
            else if (c <= ' ')                                  // If non-printing ascii,
                {                                                   // Output decimal escape sequence
                *ptr++ = esc;
                *ptr++ = (char)  ('0' + (c / 100)     );
                *ptr++ = (char)  ('0' + (c /  10) % 10);
                c      = (u_char)('0' + (c      ) % 10);
                }
            }
        *ptr++ = (char)c;                                       // Copy the character
        }
    *ptr = 0;                                                   // Null-terminate the string
    return(ptr);                                                // and return
    }
 
static char *ConvertDomainNameToCString_withescape(const domainname *const name, char *ptr, char esc)
    {
    const u_char *src         = name->c;                        // Domain name we're reading
    const u_char *const max   = name->c + MAX_DOMAIN_NAME;      // Maximum that's valid

    if (*src == 0) *ptr++ = '.';                                // Special case: For root, just write a dot

    while (*src)                                                                                                        // While more characters in the domain name
        {
        if (src + 1 + *src >= max) return(NULL);
        ptr = ConvertDomainLabelToCString_withescape((const domainlabel *)src, ptr, esc);
        if (!ptr) return(NULL);
        src += 1 + *src;
        *ptr++ = '.';                                           // Write the dot after the label
        }

    *ptr++ = 0;                                                 // Null-terminate the string
    return(ptr);                                                // and return
    }

// print arbitrary rdata in a readable manned 
static void print_rdata(int type, int len, const u_char *rdata)
    {
    int i;
    srv_rdata *srv;
    char targetstr[MAX_CSTRING];
    struct in_addr in;
    
    switch (type)
        {
        case T_TXT:
            // print all the alphanumeric and punctuation characters
            for (i = 0; i < len; i++)
                if (rdata[i] >= 32 && rdata[i] <= 127) printf("%c", rdata[i]);
            printf("\n");
            return;
        case T_SRV:
            srv = (srv_rdata *)rdata;
            ConvertDomainNameToCString_withescape(&srv->target, targetstr, 0);
            printf("pri=%d, w=%d, port=%d, target=%s\n", srv->priority, srv->weight, srv->port, targetstr);
            return;
        case T_A:
            assert(len == 4);
            memcpy(&in, rdata, sizeof(in));
            printf("%s\n", inet_ntoa(in));
            return;
        case T_PTR:
            ConvertDomainNameToCString_withescape((domainname *)rdata, targetstr, 0);
            printf("%s\n", targetstr);
            return;
        default:
            printf("ERROR: I dont know how to print RData of type %d\n", type);
            return;
        }
    }




// signal handlers, setup/teardown, etc.
static void sighdlr(int signo)
    {
    assert(signo == SIGINT);
    fprintf(stderr, "Received sigint - deallocating serviceref and exiting\n");
    if (sdr)
        DNSServiceRefDeallocate(sdr);
    exit(1);
    }


 
 
 
 
 
