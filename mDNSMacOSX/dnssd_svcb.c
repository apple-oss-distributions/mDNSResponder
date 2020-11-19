/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include "dnssd_svcb.h"

#include <netinet/in.h>

typedef enum
{
    dnssd_svcb_key_mandatory = 0,
    dnssd_svcb_key_alpn = 1,
    dnssd_svcb_key_no_default_alpn = 2,
    dnssd_svcb_key_port = 3,
    dnssd_svcb_key_ipv4_hint = 4,
    dnssd_svcb_key_ech_config = 5,
    dnssd_svcb_key_ipv6_hint = 6,
    dnssd_svcb_key_doh_uri = 32768,
} dnssd_svcb_key_t;

typedef bool (^_dnssd_svcb_access_value_block_t)(const void *value, size_t value_size);

uint16_t
dnssd_svcb_get_priority(const uint8_t *buffer, size_t buffer_size)
{
	if (buffer_size < sizeof(uint16_t)) {
		return 0;
	}

	const uint16_t *priority_p = (const uint16_t *)buffer;
	return (uint16_t)htons(*priority_p);
}

#define DNSSD_MAX_DOMAIN_NAME 256
#define DNSSD_MAX_DOMAIN_LABEL 63
#define DNSSD_MAX_ESCAPED_DOMAIN_NAME 1009

static bool
_dnssd_svcb_get_domain_name_length(const uint8_t *buffer, size_t buffer_size, size_t *out_name_length)
{
	const uint8_t *limit = buffer + buffer_size;
	const uint8_t *cursor = buffer;
    while (cursor != NULL && cursor < limit) {
		if (*cursor == 0) {
			*out_name_length = ((uint16_t)(cursor - buffer + 1));
			if (*out_name_length > DNSSD_MAX_DOMAIN_NAME) {
				return false;
			}
			return true;
		}
        cursor += 1 + *cursor;
    }
	return false;
}

static char *
_dnssd_svcb_convert_label_to_string(const uint8_t *source, char *string_buffer)
{
    const uint8_t length = *source++; // Read length of this (non-null) label
    const uint8_t *limit = source + length; // Work out where the label ends
	if (length > DNSSD_MAX_DOMAIN_LABEL) {
		return NULL;
	}
	while (source < limit) {
        uint8_t character = *source++;
		if (character == '.' || character == '\\') { // If character is a dot or the escape character
			*string_buffer++ = '\\'; // Output escape character
		} else if (character <= ' ') { // Output decimal escape sequence
			*string_buffer++ = '\\';
			*string_buffer++ = (char)  ('0' + (character / 100));
			*string_buffer++ = (char)  ('0' + (character / 10) % 10);
			character = (uint8_t)('0' + (character) % 10);
		}
        *string_buffer++ = (char)character; // Copy the character
    }
    *string_buffer = 0; // Null-terminate the string
    return(string_buffer); // and return
}

static char *
_dnssd_svcb_get_string_from_domain_name(const uint8_t *source, char *string_buffer)
{
    const uint8_t *limit = source + DNSSD_MAX_DOMAIN_NAME;

	if (*source == 0) {
		*string_buffer++ = '.'; // Special case: For root, just write a dot
	}

    while (*source) {
		if (source + 1 + *source >= limit) {
			return NULL;
		}
        string_buffer = _dnssd_svcb_convert_label_to_string(source, string_buffer);
		if (string_buffer == NULL) {
			return NULL;
		}
        source += 1 + *source;
        *string_buffer++ = '.'; // Write the dot after the label
    }

    *string_buffer++ = 0; // Null-terminate the string
    return string_buffer; // and return
}

char *
dnssd_svcb_copy_domain(const uint8_t *buffer, size_t buffer_size)
{
	if (buffer_size < sizeof(uint16_t)) {
		return NULL;
	}

	buffer += sizeof(uint16_t);
	buffer_size -= sizeof(uint16_t);

	size_t domain_length = 0;
	if (!_dnssd_svcb_get_domain_name_length(buffer, buffer_size, &domain_length)) {
		return NULL;
	}

	char *name_str = calloc(1, DNSSD_MAX_ESCAPED_DOMAIN_NAME);
	if (_dnssd_svcb_get_string_from_domain_name(buffer, name_str) == NULL) {
		free(name_str);
		return NULL;
	}
	return name_str;
}

static bool
_dnssd_svcb_extract_values(const uint8_t *buffer, size_t buffer_size,
						   dnssd_svcb_key_t match_key, _dnssd_svcb_access_value_block_t value_block)
{
	if (buffer_size < sizeof(uint16_t)) {
		return false;
	}

	const uint16_t *priority_p = (const uint16_t *)buffer;
	uint16_t priority = (uint16_t)htons(*priority_p);
	if (priority == 0) {
		// Alias form, no value
		return false;
	}

	buffer += sizeof(uint16_t);
	buffer_size -= sizeof(uint16_t);

	size_t domain_length = 0;
	if (!_dnssd_svcb_get_domain_name_length(buffer, buffer_size, &domain_length)) {
		return false;
	}

	buffer += domain_length;
	buffer_size -= domain_length;

	while (buffer != NULL && buffer_size >= (sizeof(uint16_t) + sizeof(uint16_t))) {
		const uint16_t *param_key_p = (const uint16_t *)buffer;
		uint16_t param_key = (uint16_t)htons(*param_key_p);

		buffer += sizeof(uint16_t);
		buffer_size -= sizeof(uint16_t);

		const uint16_t *param_value_length_p = (const uint16_t *)buffer;
		uint16_t param_value_length = (uint16_t)htons(*param_value_length_p);

		buffer += sizeof(uint16_t);
		buffer_size -= sizeof(uint16_t);

		if (param_value_length > buffer_size) {
			break;
		}

		if (match_key == param_key) {
			bool continue_looping = value_block(buffer, param_value_length);
			if (!continue_looping) {
				break;
			}
		}

		buffer += param_value_length;
		buffer_size -= param_value_length;
	}

	return true;
}

bool
dnssd_svcb_is_valid(const uint8_t *buffer, size_t buffer_size)
{
	if (buffer_size < sizeof(uint16_t)) {
		return false;
	}

	uint16_t priority = dnssd_svcb_get_priority(buffer, buffer_size);
	if (priority == 0) {
		// Alias forms don't need further validation
		return true;
	}

	__block bool invalid_mandatory_value = false;
	(void)_dnssd_svcb_extract_values(buffer, buffer_size, dnssd_svcb_key_mandatory, ^bool(const void *value, size_t value_size) {
		if (value != NULL && value_size > 0) {
			if ((value_size % sizeof(uint16_t)) != 0) {
				// Value must be a list of keys, as 16-bit integers
				invalid_mandatory_value = true;
			} else {
				const uint16_t mandatory_key_count = (uint16_t)(value_size / sizeof(uint16_t));
				for (uint16_t i = 0; i < mandatory_key_count && !invalid_mandatory_value; i++) {
					const uint16_t *param_key_p = ((const uint16_t *)value) + i;
					uint16_t param_key = (uint16_t)htons(*param_key_p);
					switch (param_key) {
						case dnssd_svcb_key_mandatory:
							// Mandatory key cannot be listed
							invalid_mandatory_value = true;
							break;
						case dnssd_svcb_key_alpn:
						case dnssd_svcb_key_no_default_alpn:
						case dnssd_svcb_key_port:
						case dnssd_svcb_key_ipv4_hint:
						case dnssd_svcb_key_ech_config:
						case dnssd_svcb_key_ipv6_hint:
						case dnssd_svcb_key_doh_uri:
							// Known keys are fine
							break;
						default:
							// Unknown mandatory key means we should ignore the record
							invalid_mandatory_value = true;
							break;
					}
				}
			}
		}
		return false;
	});
	if (invalid_mandatory_value) {
		return false;
	} else {
		return true;
	}
}

uint16_t
dnssd_svcb_get_port(const uint8_t *buffer, size_t buffer_size)
{
	__block uint16_t port = false;
	(void)_dnssd_svcb_extract_values(buffer, buffer_size, dnssd_svcb_key_port, ^bool(const void *value, size_t value_size) {
		if (value != NULL && value_size == sizeof(uint16_t)) {
			port = (uint16_t)htons(*(const uint16_t *)value);
		}
		return false;
	});
	return port;
}

char *
dnssd_svcb_copy_doh_uri(const uint8_t *buffer, size_t buffer_size)
{
	__block char *doh_uri = NULL;
	(void)_dnssd_svcb_extract_values(buffer, buffer_size, dnssd_svcb_key_doh_uri, ^bool(const void *value, size_t value_size) {
		if (value != NULL && value_size > 0) {
			asprintf(&doh_uri, "%.*s", (int)value_size, value);
		}
		return false;
	});
	return doh_uri;
}

uint8_t *
dnssd_svcb_copy_ech_config(const uint8_t *buffer, size_t buffer_size, size_t *out_length)
{
	__block uint8_t *ech_config = NULL;
	(void)_dnssd_svcb_extract_values(buffer, buffer_size, dnssd_svcb_key_ech_config, ^bool(const void *value, size_t value_size) {
		if (value != NULL && value_size > 0) {
			ech_config = calloc(1, value_size);
			*out_length = value_size;
			memcpy(ech_config, value, value_size);
		}
		return false;
	});
	return ech_config;
}

void
dnssd_svcb_access_alpn_values(const uint8_t *buffer, size_t buffer_size,
							  DNSSD_NOESCAPE _dnssd_svcb_access_alpn_t block)
{
	(void)_dnssd_svcb_extract_values(buffer, buffer_size, dnssd_svcb_key_alpn, ^bool(const void *value, size_t value_size) {
		if (value != NULL) {
			size_t value_read = 0;
			while (value_size > 0 && value_read < value_size) {
				char alpn_value[UINT8_MAX] = "";

				uint8_t alpn_length = *(const uint8_t *)value;
				value_read++;

				if (value_read + alpn_length > value_size) {
					break;
				}

				memcpy(alpn_value, ((const uint8_t *)value) + value_read, alpn_length);
				if (!block((const char *)alpn_value)) {
					break;
				}
				value_read += alpn_length;
			}
		}
		return false;
	});
}

void
dnssd_svcb_access_address_hints(const uint8_t *buffer, size_t buffer_size, DNSSD_NOESCAPE _dnssd_svcb_access_address_t block)
{
	__block bool continue_enumerating = true;
	(void)_dnssd_svcb_extract_values(buffer, buffer_size, dnssd_svcb_key_ipv4_hint, ^bool(const void *value, size_t value_size) {
		if (value != NULL && (value_size % sizeof(struct in_addr)) == 0) {
			size_t value_read = 0;
			while (value_read < value_size) {
				struct sockaddr_in v4addr;
				memset(&v4addr, 0, sizeof(v4addr));
				v4addr.sin_family = AF_INET;
				v4addr.sin_len = sizeof(v4addr);
				memcpy(&v4addr.sin_addr, ((const uint8_t *)value) + value_read, sizeof(struct in_addr));
				continue_enumerating = block((const struct sockaddr *)&v4addr);
				if (!continue_enumerating) {
					break;
				}
				value_read += sizeof(struct in_addr);
			}
		}
		return false;
	});
	if (!continue_enumerating) {
		return;
	}
	(void)_dnssd_svcb_extract_values(buffer, buffer_size, dnssd_svcb_key_ipv6_hint, ^bool(const void *value, size_t value_size) {

		if (value != NULL && (value_size % sizeof(struct in6_addr)) == 0) {
			size_t value_read = 0;
			while (value_read < value_size) {
				struct sockaddr_in6 v6addr;
				memset(&v6addr, 0, sizeof(v6addr));
				v6addr.sin6_family = AF_INET6;
				v6addr.sin6_len = sizeof(v6addr);
				memcpy(&v6addr.sin6_addr, ((const uint8_t *)value) + value_read, sizeof(struct in6_addr));
				continue_enumerating = block((const struct sockaddr *)&v6addr);
				if (!continue_enumerating) {
					break;
				}
				value_read += sizeof(struct in6_addr);
			}
		}
		return false;
	});
}
