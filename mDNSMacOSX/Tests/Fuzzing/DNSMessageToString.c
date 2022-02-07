#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include <stddef.h>

#include <mdns/DNSMessage.h>

#ifdef FUZZING_DNSMESSAGETOSTRING
int LLVMFuzzerTestOneInput(const char* Data, const size_t Length)
{
    if(Length < 2) {
        return 0;
    }

    int flags = Data[0];
    uint8_t* copy = malloc(Length - 1);
    char* outString = NULL;

    memcpy(copy, Data+1, Length - 1);

    DNSMessageToString(copy, Length - 1, (DNSMessageToStringFlags) flags, &outString);

    free(copy);
    if(outString) {
        free(outString);
    }

    return 0;
}
#endif
