#!/usr/bin/env bash
set -x

if ! [ -f Tests/Fuzzing/fuzzer.xcconfig ]; then
    echo Script must be run from the mDNSMacOSX directory
fi

xcodebuild -scheme ra-tester -xcconfig Tests/Fuzzing/icmp_callback.xcconfig "$@"