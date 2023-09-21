/* -*- Mode: C; tab-width: 4 -*-
*
* Copyright (c) 2002-2015 Apple Inc. All rights reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     https://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

#ifndef __mDNSResponderLib_h
#define __mDNSResponderLib_h

#include "dns_sd.h"

#ifdef __cplusplus
extern "C" {
#endif

    int DNSSD_API DNSServiceStart();
    void DNSSD_API DNSServiceStop();

#ifdef __cplusplus
}
#endif

#endif
