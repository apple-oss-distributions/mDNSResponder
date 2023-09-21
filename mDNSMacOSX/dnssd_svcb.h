/*
 * Copyright (c) 2020-2022 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __DNSSD_SVCB_H__
#define __DNSSD_SVCB_H__

#include "dnssd_private.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
dnssd_svcb_is_valid(const uint8_t *buffer, size_t buffer_size);

bool
dnssd_svcb_is_alias(const uint8_t *buffer, size_t buffer_size);

uint16_t
dnssd_svcb_get_priority(const uint8_t *buffer, size_t buffer_size);

bool
dnssd_svcb_service_name_is_empty(const uint8_t *buffer, size_t buffer_size);

char *
dnssd_svcb_copy_service_name_string(const uint8_t *buffer, size_t buffer_size);

const uint8_t *
dnssd_svcb_get_service_name_raw(const uint8_t *buffer, size_t buffer_size);

uint16_t
dnssd_svcb_get_port(const uint8_t *buffer, size_t buffer_size);

char *
dnssd_svcb_copy_doh_uri(const uint8_t *buffer, size_t buffer_size);

char *
dnssd_svcb_copy_doh_path(const uint8_t *buffer, size_t buffer_size);

uint8_t *
dnssd_svcb_copy_ech_config(const uint8_t *buffer, size_t buffer_size,
						   size_t *out_length);

uint8_t *
dnssd_svcb_copy_odoh_config(const uint8_t *buffer, size_t buffer_size,
							size_t *out_length);

#ifdef __BLOCKS__

typedef bool (^_dnssd_svcb_access_alpn_t)(const char *alpn);

void
dnssd_svcb_access_alpn_values(const uint8_t *buffer, size_t buffer_size,
							  DNSSD_NOESCAPE _dnssd_svcb_access_alpn_t block);

typedef bool (^_dnssd_svcb_access_address_t)(const struct sockaddr *address);

void
dnssd_svcb_access_address_hints(const uint8_t *buffer, size_t buffer_size,
								DNSSD_NOESCAPE _dnssd_svcb_access_address_t block);

#endif //  __BLOCKS__

#ifdef __cplusplus
}
#endif

#endif  // __DNSSD_SVCB_H__
