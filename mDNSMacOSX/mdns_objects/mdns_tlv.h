/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#ifndef __MDNS_TLV_H__
#define __MDNS_TLV_H__

#include "mdns_base.h"

#include <MacTypes.h>
#include <stdint.h>

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

OSStatus
mdns_tlv16_get_value(const uint8_t *start, const uint8_t *end, uint16_t type, size_t *out_length,
	const uint8_t * _Nonnull * _Nullable out_value, const uint8_t * _Nonnull * _Nullable out_ptr);

OSStatus
mdns_tlv16_set(uint8_t *dst, const uint8_t *limit, uint16_t type, uint16_t length, const uint8_t *value,
	uint8_t * _Nonnull * _Nullable out_end);

size_t
mdns_tlv16_get_required_length(const uint16_t value_length);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_TLV_H__
