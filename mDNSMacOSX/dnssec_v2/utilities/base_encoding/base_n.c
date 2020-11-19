//
//  base_n.c
//  mDNSResponder
//
//  Copyright (c) 2020 Apple Inc. All rights reserved.
//

#pragma mark - Includes
#include "base_n.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include <stdint.h>
#include <AssertMacros.h>
#include "dnssec_v2_log.h"

#pragma mark - Constants



#pragma mark b64_table
static const char b64_table[] = {
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
	'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
	'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
	'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
	'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', '0', '1', '2', '3',
	'4', '5', '6', '7', '8', '9', '+', '/'
};

#pragma mark b32_hex_table
static const char b32_hex_table[] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
	'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N',
	'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V'
};

#pragma mark - Macros



#define MAX_LENGTH_B64_ENCODING_DATA (SIZE_MAX * 3 / 4)
#define MAX_LENGTH_B32_HEX_ENCODING_DATA (SIZE_MAX * 5 / 8)

#pragma mark - Functions



#pragma mark - base_n_encode
char * _Nullable
base_n_encode(base_n_t base_n, const unsigned char * const _Nonnull data, size_t data_len) {
	return base_n_encode_ex(base_n, data, data_len, NULL);
}

#pragma mark - base_n_encode_ex
char * _Nullable
base_n_encode_ex(base_n_t base_n, const unsigned char * const _Nonnull data, size_t data_len, size_t * const _Nullable out_str_len) {
	char *						encoded_str			= mDNSNULL;
	const size_t				encoded_str_len		= get_base_n_encoded_str_length(base_n, data_len);
	char *						encoded_str_ptr;
	const unsigned char *		data_ptr			= data;
	const unsigned char * const data_ptr_limit		= data_ptr + data_len;
	size_t						remain;
	uint64_t					quantum;

	encoded_str = malloc(encoded_str_len + 1);
	require_quiet(encoded_str != mDNSNULL, exit);

	// ensure that the string always ends with '\0'
	encoded_str[encoded_str_len]    = '\0';
	encoded_str_ptr                 = encoded_str;

	if (out_str_len != mDNSNULL) {
		*out_str_len = encoded_str_len;
	}

	// encoding starts
	switch (base_n) {
		case DNSSEC_BASE_64: {
			for(; data_ptr < data_ptr_limit;) {
				char		encoded_buf[4];
				size_t		encoded_size = 0;

				remain	= data_ptr_limit - data_ptr;
				quantum	= 0;
				// get 24 bits from 3 bytes
				switch (remain) {
					default:
					case 3: quantum |=  (uint64_t)data_ptr[2];			// Bits 16 - 23
					case 2: quantum |= ((uint64_t)data_ptr[1]) << 8;	// Bits  8 - 15
					case 1: quantum |= ((uint64_t)data_ptr[0]) << 16;	// Bits  0 - 7
				}
				// advance the data pointer
				data_ptr += ((remain > 3) ? 3 : remain);

				// convert 24 bits to 4 characters
				switch (remain) {
					default:
					case 3:
						encoded_buf[3]	= b64_table[ quantum		& 0x3F];
						encoded_size	= 4;
					case 2:
						encoded_buf[2]	= b64_table[(quantum >>  6) & 0x3F];
						if (encoded_size == 0) encoded_size = 3;
					case 1:
						encoded_buf[1]	= b64_table[(quantum >> 12) & 0x3F];
						encoded_buf[0]	= b64_table[(quantum >> 18) & 0x3F];
						if (encoded_size == 0) encoded_size = 2;
				}

				// fill the padding with '='
				for (size_t i = encoded_size; i < sizeof(encoded_buf); i++) {
					encoded_buf[i] = '=';
				}

				// move the current encoded string chunk to the returned buffer
				memcpy(encoded_str_ptr, encoded_buf, sizeof(encoded_buf));
				encoded_str_ptr += sizeof(encoded_buf);
			}
			break;
		}
		case DNSSEC_BASE_32_HEX: {
			for(; data_ptr < data_ptr_limit;) {
				char		encoded_buf[8];
				size_t		encoded_size = 0;

				remain	= data_ptr_limit - data_ptr;
				quantum = 0;
				// get 40 bits from 8 bytes
				switch (remain) {
					default:
					case 5: quantum |=  (uint64_t)data_ptr[4];          // Bits 32 - 39
					case 4: quantum |= ((uint64_t)data_ptr[3]) << 8;    // Bits 24 - 32
					case 3: quantum |= ((uint64_t)data_ptr[2]) << 16;   // Bits 16 - 23
					case 2: quantum |= ((uint64_t)data_ptr[1]) << 24;   // Bits  8 - 15
					case 1: quantum |= ((uint64_t)data_ptr[0]) << 32;   // Bits  0 -  7
				}
				// advance the data pointer
				data_ptr += ((remain > 5) ? 5 : remain);

				// convert 40 bits to 8 characters
				switch (remain) {
					default:
					case 5:
						encoded_buf[7]	= b32_hex_table[quantum			& 0x1F];
						encoded_size = 8;
					case 4:
						encoded_buf[6]	= b32_hex_table[(quantum >>  5) & 0x1F];
						encoded_buf[5]	= b32_hex_table[(quantum >> 10) & 0x1F];
						if (encoded_size == 0) encoded_size = 7;
					case 3:
						encoded_buf[4]	= b32_hex_table[(quantum >> 15) & 0x1F];
						if (encoded_size == 0) encoded_size = 5;
					case 2:
						encoded_buf[3]	= b32_hex_table[(quantum >> 20) & 0x1F];
						encoded_buf[2]	= b32_hex_table[(quantum >> 25) & 0x1F];
						if (encoded_size == 0) encoded_size = 4;
					case 1:
						encoded_buf[1]	= b32_hex_table[(quantum >> 30) & 0x1F];
						encoded_buf[0]	= b32_hex_table[(quantum >> 35) & 0x1F];
						if (encoded_size == 0) encoded_size = 2;
				}

				// fill the padding with '='
				for (size_t i = encoded_size; i < sizeof(encoded_buf); i++) {
					encoded_buf[i] = '=';
				}

				// move the current encoded string chunk to the returned buffer
				memcpy(encoded_str_ptr, encoded_buf, sizeof(encoded_buf));
				encoded_str_ptr += sizeof(encoded_buf);
			}
			break;
		}
		default:
			// Unsupported Base N, returns empty string.
			encoded_str[0] = '\0';
			break;
	}

exit:
	return encoded_str;
}

#pragma mark - get_base_n_encoded_str_length
size_t
get_base_n_encoded_str_length(base_n_t base_n, size_t data_len) {
	size_t encoded_str_len = 0;

	switch (base_n) {
		case DNSSEC_BASE_64:
			verify_action(data_len <= MAX_LENGTH_B64_ENCODING_DATA, data_len = MAX_LENGTH_B64_ENCODING_DATA);
			encoded_str_len = (data_len + 2) / 3 * 4;
			break;
		case DNSSEC_BASE_32_HEX:
			verify_action(data_len <= MAX_LENGTH_B32_HEX_ENCODING_DATA, data_len = MAX_LENGTH_B32_HEX_ENCODING_DATA);
			encoded_str_len = (data_len + 4) / 5 * 8;
			break;
		default:
			encoded_str_len = 0;
			break;
	}

	return encoded_str_len;
}

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
