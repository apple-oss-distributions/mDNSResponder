#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <ctype.h>
#include "DNSCommon.h"

#ifdef FUZZING_MDNS_SNPRINTF

void hexdump(const void* Data, ssize_t Length) {
    const uint8_t* bytes = (const uint8_t*) Data;
    dprintf(2, "[%4d] ", Length);
    for(ssize_t i = 0; i < Length; i++) {
        dprintf(2, "%02x", bytes[i]);
    }
    dprintf(2, "\n");
}

// Large enough to be a uint64_t
const size_t numBuffers = 32;
const size_t bufferSize = 16; // Large enough to hold an IPv6 address
char **buffers[numBuffers];

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

size_t LLVMFuzzerCustomMutator(char *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    Size = LLVMFuzzerMutate((uint8_t*) Data, Size, MaxSize);

    // Ensure there is a NULL terminator somewhere in the buffer
    Data[MaxSize-3] = '\0';
    Size = strlen(Data) + 1;

    // Input values for the format buffer will be ASCII printable
    for(size_t i = 0; i < Size; i++) {
        Data[i] = Data[i] & 0x7f;
    }

    // Only have up to numBuffers format specifiers
    // XXX: Can actually only have half that amount, because e.g. %.*s consumes two values
    char* percent = Data;
    size_t i = 0;

    for(i = 0; percent && i < numBuffers / 2; i++) {
        percent = strchr(percent, '%');

        if(percent) {
            percent++;
        }
    }

    if(percent) {
        *percent = '\0';
    }

    Size = strlen(Data) + 1;

    // XXX: Due to rdar://68121985
    Data[Size++] = 0;
    return Size;
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    static int initialized = 0;

    if(initialized) {
        return 0;
    }

    for(size_t i = 0; i < numBuffers; i++) {
        buffers[i] = malloc(bufferSize);
    }

    initialized = 1;

    return 0;
}


void setup() {
    for(size_t i = 0; i < numBuffers; i++) {
        memset(&buffers[i][0], 0, bufferSize);
        memset(&buffers[i][0], 'A' + i, bufferSize-1);
    }
}

int LLVMFuzzerTestOneInput(const char* Data, const size_t Size)
{
    // For some reason, the Release build doesn't call LLVMFuzzerInitialize so
    // we do it manually here.
    LLVMFuzzerInitialize(0, NULL);

    // Skip short inputs
    if(Size < 1 || !memchr(Data, 0, Size)) {
        return 0;
    }

    // Require that there is a NULL terminator somewhere in the buffer
    // char *copy = malloc(Size);
    // memcpy(copy, Data, Size);

    // Setup printed buffers
    setup();

    // Output buffer and run snprintf
    size_t printBufferSize = 128;
    // char printBuffer[printBufferSize]; // Repro
    char* printBuffer = malloc(printBufferSize); // No repro
    mDNS_snprintf(printBuffer, printBufferSize, Data, 
                    buffers[000], buffers[001], buffers[002], buffers[003], buffers[004], buffers[005], buffers[006], buffers[007], 
                    buffers[010], buffers[011], buffers[012], buffers[013], buffers[014], buffers[015], buffers[016], buffers[017], 
                    buffers[020], buffers[021], buffers[022], buffers[023], buffers[024], buffers[025], buffers[026], buffers[027],
                    buffers[030], buffers[031], buffers[032], buffers[033], buffers[034], buffers[035], buffers[036], buffers[037]);

    free(printBuffer);
    return 0;
}
#endif
