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

#include "mdns_tlv.h"

#include <CoreUtils/CoreUtils.h>

//======================================================================================================================
// MARK: - Type-Length Headers

typedef struct
{
	uint8_t	type[2];
	uint8_t	length[2];
} mdns_tl16_t;

check_compile_time(sizeof(mdns_tl16_t) == 4);

//======================================================================================================================
// MARK: - Local Prototypes

static uint16_t
_mdns_tl16_get_type(const mdns_tl16_t *tl);

static uint16_t
_mdns_tl16_get_length(const mdns_tl16_t *tl);

static void
_mdns_tl16_init(mdns_tl16_t *tl, uint16_t type, uint16_t length);

//======================================================================================================================
// MARK: - Public Functions

OSStatus
mdns_tlv16_get_value(const uint8_t * const start, const uint8_t * const end, const uint16_t type,
	size_t * const out_length, const uint8_t ** const out_value, const uint8_t ** const out_ptr)
{
	OSStatus err;
	require_action_quiet(start <= end, exit, err = kRangeErr);

	const uint8_t *ptr = start;
	while ((end - ptr) > 0) {
		const mdns_tl16_t *tl;
		require_action_quiet((end - ptr) >= (ptrdiff_t)sizeof(*tl), exit, err = kUnderrunErr);

		tl = (const mdns_tl16_t *)ptr;
		const uint16_t			tlv_type	= _mdns_tl16_get_type(tl);
		const uint16_t			tlv_length	= _mdns_tl16_get_length(tl);
		const uint8_t * const	tlv_value	= (const uint8_t *)&tl[1];
		require_action_quiet((end - tlv_value) >= tlv_length, exit, err = kUnderrunErr);

		ptr = &tlv_value[tlv_length];
		if (tlv_type == type) {
			if (out_length) {
				*out_length = tlv_length;
			}
			if (out_value) {
				*out_value = tlv_value;
			}
			if (out_ptr) {
				*out_ptr = ptr;
			}
			return kNoErr;
		}
	}
	err = kNotFoundErr;

exit:
	return err;
}

//======================================================================================================================

OSStatus
mdns_tlv16_set(uint8_t * const dst, const uint8_t * const limit, const uint16_t type, const uint16_t length,
	const uint8_t * const value, uint8_t ** const out_end)
{
	OSStatus err;
	mdns_tl16_t *tl;
	require_action_quiet(!limit || ((limit - dst) >= (ptrdiff_t)(sizeof(tl) + length)), exit, err = kUnderrunErr);

	tl = (mdns_tl16_t *)dst;
	_mdns_tl16_init(tl, type, length);
	uint8_t * const dst_value = (uint8_t *)&tl[1];
	if (length > 0) {
		memcpy(dst_value, value, length);
	}
	if (out_end) {
		*out_end = &dst_value[length];
	}
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

size_t
mdns_tlv16_get_required_length(const uint16_t value_length)
{
	return (sizeof(mdns_tl16_t) + value_length);
}

//======================================================================================================================
// MARK: - Private Functions

static uint16_t
_mdns_tl16_get_type(const mdns_tl16_t * const tl)
{
	return ReadBig16(tl->type);
}

//======================================================================================================================

static uint16_t
_mdns_tl16_get_length(const mdns_tl16_t * const tl)
{
	return ReadBig16(tl->length);
}

//======================================================================================================================

static void
_mdns_tl16_init(mdns_tl16_t * const tl, const uint16_t type, const uint16_t length)
{
	WriteBig16(tl->type, type);
	WriteBig16(tl->length, length);
}
