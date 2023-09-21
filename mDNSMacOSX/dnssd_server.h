/*
 * Copyright (c) 2018-2020 Apple Inc. All rights reserved.
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

#ifndef __DNSSD_SERVER_H__
#define __DNSSD_SERVER_H__

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void
dnssd_server_init(void);

void
dnssd_server_idle(void);

uint32_t
dnssd_server_get_new_request_id(void);

#ifdef __cplusplus
}
#endif

#endif	// __DNSSD_SERVER_H__
