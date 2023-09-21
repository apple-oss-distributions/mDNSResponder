#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include "DNSCommon.h"

#ifdef FUZZING_SETRDATA

#ifdef JUST_FOR_REFERENCE
typedef struct
{
    DNSMessageHeader h;                     // Note: Size 12 bytes
    mDNSu8 data[AbsoluteMaxDNSMessageData]; // 40 (IPv6) + 8 (UDP) + 12 (DNS header) + 8940 (data) = 9000
} DNSMessage;

struct ResourceRecord_struct
{
    mDNSu8 RecordType;                  // See kDNSRecordTypes enum.
    mDNSu8 negativeRecordType;          // If RecordType is kDNSRecordTypePacketNegative, specifies type of negative record.
    MortalityState mortality;           // Mortality of this resource record (See MortalityState enum)
    mDNSu16 rrtype;                     // See DNS_TypeValues enum.
    mDNSu16 rrclass;                    // See DNS_ClassValues enum.
    mDNSu32 rroriginalttl;              // In seconds
    mDNSu16 rdlength;                   // Size of the raw rdata, in bytes, in the on-the-wire format
                                        // (In-memory storage may be larger, for structures containing 'holes', like SOA)
    mDNSu16 rdestimate;                 // Upper bound on on-the-wire size of rdata after name compression
    mDNSu32 namehash;                   // Name-based (i.e. case-insensitive) hash of name
    mDNSu32 rdatahash;                  // For rdata containing domain name (e.g. PTR, SRV, CNAME etc.), case-insensitive name hash
                                        // else, for all other rdata, 32-bit hash of the raw rdata
                                        // Note: This requirement is important. Various routines like AddAdditionalsToResponseList(),
                                        // ReconfirmAntecedents(), etc., use rdatahash as a pre-flight check to see
                                        // whether it's worth doing a full SameDomainName() call. If the rdatahash
                                        // is not a correct case-insensitive name hash, they'll get false negatives.
    // Grouping pointers together at the end of the structure improves the memory layout efficiency
    mDNSInterfaceID InterfaceID;        // Set if this RR is specific to one interface
                                        // For records received off the wire, InterfaceID is *always* set to the receiving interface
                                        // For our authoritative records, InterfaceID is usually zero, except for those few records
                                        // that are interface-specific (e.g. address records, especially linklocal addresses)
    domainname      *name;
    RData           *rdata;             // Pointer to storage for this rdata
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
    mdns_dns_service_t dnsservice;
    mdns_resolver_type_t protocol;
#else
    DNSServer       *rDNSServer;        // Unicast DNS server authoritative for this entry; null for multicast
#endif

};

typedef struct { mDNSu8 c[256]; } domainname;

typedef struct
{
    mDNSu16 MaxRDLength;    // Amount of storage allocated for rdata (usually sizeof(RDataBody))
    mDNSu16 padding;        // So that RDataBody is aligned on 32-bit boundary
    RDataBody u;
} RData;

#endif

// #define min(x,y) (x<y ? x : y)

int LLVMFuzzerTestOneInput(char* Data, size_t Length)
{
    if(Length < 3) {
        return 0;
    }

    // First three bytes are type and length
    // We have to use a two-byte length, since RDataBody2 is pretty big
    uint8_t recordType = (uint8_t) Data[0];
    uint16_t rdlen = *(uint16_t*)&Data[1];

    rdlen &= 0x7ff;

    Data += 3;
    Length -= 3;

    // Make sure not to go over MTU size
    if(rdlen > AbsoluteMaxDNSMessageData) {
        return 0;
    }

    // Make sure we have enough data for everything else
    if(Length < rdlen + sizeof(domainname)) {
        return 0;
    }

    // Fill the domainname with random data
    domainname *name = malloc(sizeof(*name));
    memcpy(name, Data, sizeof(*name));
    
    Data += sizeof(*name);
    Length -= sizeof(*name);

    // Allocate an RData object of variable length
    size_t rdcapacity = (rdlen > sizeof(RDataBody2)) ? rdlen : sizeof(RDataBody2);
    RData *rdata = malloc((sizeof(RData) - sizeof(RDataBody)) + rdcapacity);
    rdata->MaxRDLength = (uint16_t) rdcapacity;

    // Use a random record type
    ResourceRecord *rr = malloc(sizeof(*rr));
    rr->rrtype = recordType;
    rr->name = name;
    rr->rdata = rdata;

    // Check against the number of bytes we have
    if(Length >= rdlen) {
        // The rest of the buffer goes as input
        uint8_t *buffer = malloc(rdlen);
        uint8_t *end = (uint8_t*) buffer + rdlen;
        memcpy(buffer, Data, rdlen);

        // SetRData copies the record data out of "buffer" and into "rr.rdata"
        SetRData(0, buffer, end, rr, rdlen);

        free(buffer);
    }


    free(rr);
    free(name);
    free(rdata);
    return 0;
}
#endif
