#!/usr/bin/env bash
set -x

if ! [ -f Tests/Fuzzing/fuzzer.xcconfig ]; then
    echo Script must be run from the mDNSMacOSX directory
fi

xcodebuild build -scheme ra-tester -xcconfig Tests/Fuzzing/dns_wire_parse.xcconfig "$@"