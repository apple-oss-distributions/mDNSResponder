#!/usr/bin/env python3
# Copyright (c) 2020 Apple Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# This code parses an ADK log with MALLOC_DEBUG_LOGGING and eliminates matching alloc/free pairs.
# It then prints a list of all allocations that have not yet been freed, and the file and line
# number where they were allocated.  This can be useful for detecting leaks, although not everything
# printed will be a leak: it could just be live data.

import sys
import re

allocations = {}

alloc_re = re.compile(r"^([0-9][0-9]*\.[0-9][0-9]*)\s+[A-Za-z][A-Za-z]*\s+(0x[0-9a-f][0-9a-f]*): (malloc|strdup|calloc)\((.*)\) at (.*)$")
free_re = re.compile(r"^([0-9][0-9]*\.[0-9][0-9]*)\s+[A-Za-z][A-Za-z]*\s+(0x[0-9a-f][0-9a-f]*): (free)\((.*)\) at (.*)$")

for line in sys.stdin:
    line = line.strip()
    matches = alloc_re.match(line)
    if matches != None:
        allocations[matches.group(2)] = matches
    else:
        matches = free_re.match(line)
        if matches != None:
            if matches.group(2) in allocations:
                del allocations[matches.group(2)]
            else:
                print("mismatched free: ", line);

leaks = {}
for key, value in allocations.items():
    if value.group(5) in leaks:
        leaks[value.group(5)].append(value)
    else:
        leaks[value.group(5)] = [value]

for key in sorted(leaks.keys()):
    print("\nPossible leaks at: ", key)
    for match in leaks[key]:
        print("  ", match.group(2), " ", match.group(3), " ", match.group(4))
