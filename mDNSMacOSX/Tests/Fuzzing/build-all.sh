#!/usr/bin/env zsh

set -eo pipefail

# Make sure BLUEBOOK_API_KEY is set, or else we can't upload the fuzzers
if [ -z "$BLUEBOOK_API_KEY" ]; then
    echo '$BLUEBOOK_API_KEY must be set to upload fuzzers'
    exit 1
fi

# Fuzzer scripts must be run from the MacOSX directory
cd $(git rev-parse --show-toplevel)/mDNSMacOSX

# By default, build release binaries
: ${CONFIGURATION=Release}

# By default, store the built products in ./symroot
: ${SYMROOT=symroot}

# List of fuzzers to build
fuzzers=(
    DNSMessageToString
    dns_message_received
    dns_wire_parse
    icmp_callback
    mDNS_snprintf
    setrdata
)

for fuzzer in "${fuzzers[@]}"; do
    ./Tests/Fuzzing/$fuzzer.sh -configuration "$CONFIGURATION" SYMROOT="$SYMROOT/$fuzzer"
done

# Upload each fuzzer individually
find "$SYMROOT" -type f | while read bin; do
    echo "$bin"

    # Remove entitlements from the fuzzers
    codesign -f -s - "$bin"
done
