#!/usr/bin/env bash
set -x

if ! [ -f Tests/Fuzzing/fuzzer.xcconfig ]; then
    echo Script must be run from the mDNSMacOSX directory
fi

xcodebuild build -scheme mDNSNetMonitor -xcconfig Tests/Fuzzing/dns_message_received.xcconfig "$@"