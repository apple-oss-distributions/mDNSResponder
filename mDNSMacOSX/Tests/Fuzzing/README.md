# mDNS Fuzzer

This directory contains several fuzzers for the mDNS project in mDNSMacOSX/Tests/Fuzzing

Each fuzzer is named after the routine that it fuzzes.

* dns_wire_parse
* icmp_callback
* mDNS_snprintf

## Building

To build it, run the following command from the mDNSMacOSX directory:

```sh
$ cd mDNSMacOSX
$ Tests/Fuzzing/dns_wire_parse.sh
``` 

## Running

To make things simple, you can add the Build/Products directory to your `$PATH`.

```sh
$ OUTPUT=$(echo $HOME/Library/Developer/Xcode/DerivedData/mDNSResponder-*/Build/Products/Debug)
$ export PATH=$OUTPUT:$PATH
```

Create a `corpus` directory to store fuzzer test-cases, and an 

```sh
$ mkdir corpus
$ fuzz-dns-wire-parse corpus
```

To reproduce a crash, just pass it on the command line

```sh
$ fuzz-dns-wire-parse crash-095ab8b59498220df930c19e80fd692a1eebaf8c
```