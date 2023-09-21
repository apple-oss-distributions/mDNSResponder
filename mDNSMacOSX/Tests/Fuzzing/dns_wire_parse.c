#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include "srp.h"
#include "dns-msg.h"

#ifdef FUZZING_DNS_WIRE_PARSE
int LLVMFuzzerTestOneInput(const char* Data, const size_t Length)
{
    dns_message_t *message = 0;
    dns_wire_t wire = {0};
    unsigned len = (unsigned) Length;

    // At least one byte of data is needed
    if (Length < 1 + __builtin_offsetof(dns_wire_t, data))
        return 0;

    // Too much data
    if (Length > sizeof(wire))
        return 0;

    // Initialize the wire struct with the fuzzing data
    memcpy(&wire, Data, Length);

    // Parse!
    dns_wire_parse(&message, &wire, len);

    if(message)
        free(message);

    return 0;
}
#endif
