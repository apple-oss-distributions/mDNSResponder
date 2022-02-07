#!/usr/bin/env bash
set -x

if ! [ -f Tests/Fuzzing/fuzzer.xcconfig ]; then
    echo Script must be run from the mDNSMacOSX directory
fi

xcodebuild -scheme mDNSNetMonitor -xcconfig Tests/Fuzzing/mDNS_snprintf.xcconfig "$@"