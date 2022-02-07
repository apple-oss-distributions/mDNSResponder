#!/usr/bin/env zsh

# Utility functions
yell() { echo '$' "$@"; "$@" }
die() { echo "\e[31m$@" >&2; exit 1}

# Make sure BLUEBOOK_API_KEY is set, or else we can't upload the fuzzers
if [ -z "$BLUEBOOK_API_KEY" ]; then
    die '$BLUEBOOK_API_KEY must be set to upload fuzzers'
fi

# Fuzzer scripts must be run from the MacOSX directory
cd $(git rev-parse --show-toplevel)/mDNSMacOSX

# By default, build release binaries
: ${CONFIGURATION=Release}

# By default, store the built products in ./symroot
: ${SYMROOT=symroot}

# List of fuzzers to build
fuzzers=()
all_fuzzers=(
    DNSMessageToString
    dns_wire_parse
    dns_message_received
    icmp_callback
    mDNS_snprintf
    setrdata
)

# Filter the list of fuzzers
for fuzzer in "${all_fuzzers[@]}"; do
    if [ -z "$1" ] || [[ "$fuzzer" =~ "$1" ]]; then
        echo "Adding $fuzzer"
        fuzzers+=("$fuzzer")
    fi
done

# List of fuzzers on bluebook already
existing_fuzzers=(
    $(bluebook fuzzer list | sort)
)

# Build all of the fuzzers
for fuzzer in "${fuzzers[@]}"; do
    echo "Building $fuzzer"
    if ! yell "./Tests/Fuzzing/$fuzzer.sh" -configuration "$CONFIGURATION" SYMROOT="$SYMROOT/$fuzzer"; then
        die "Fuzzer $fuzzer failed to build!"
    fi
done

# Upload each fuzzer individually
for fuzzer in "${fuzzers[@]}"; do
    bin="$( find "$SYMROOT/$fuzzer/$CONFIGURATION" -type f | grep -v asan | grep -v xml | head -1)"
    bin_name=$(basename $bin)

    # Find the correct ASAN library
    asan_dylib=$( DYLD_PRINT_LIBRARIES=1 "$bin" /dev/null |& grep -E -o '/\S+/libclang_rt.asan_osx_dynamic.dylib' | head -1 )
    echo "ASAN library: $asan_dylib"

    config=$SYMROOT/$fuzzer/$CONFIGURATION/config.xml
    if [ -f $config ]; then
        rm -f $config
    fi

    test -f "$bin"

    dir=$( dirname $bin )

    echo Using ASAN dylib: $asan_dylib
    yell cp "$asan_dylib" "$dir"

    # Remove any existing config.xml
    if [ -f $dir/config.xml ]; then
        rm -f "$dir/config.xml"
    fi

    # Remove entitlements from the fuzzers
    yell codesign -f -s - "$bin"

    if [ -z "${existing_fuzzers[(r)$fuzzer]}" ]; then
        echo "Fuzzer $fuzzer does not exist yet, submitting."
        yell bluebook fuzzer submit --name "$fuzzer" --fuzzer-dir "$dir" --corpus-dir $(mktemp -d) --kind libFuzzer --driver-name "$(basename $bin)"
    else
        echo "Fuzzer $fuzzer already exists, updating tool."
        yell bluebook fuzzer update-tool --input-dir "$dir" --kind libFuzzer --driver-name="$(basename $bin)" "$fuzzer"
    fi
done
