//
//  base_n.h
//  mDNSResponder
//
//  Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef base_n_h
#define base_n_h

#pragma mark - Includes
#include "mDNSEmbeddedAPI.h"
#include <stdlib.h>
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

#pragma mark base_n_t
typedef enum base_n {
	DNSSEC_BASE_64,
	DNSSEC_BASE_32_HEX
} base_n_t;

#pragma mark base_n_encode
/*!
 *	@brief
 *		Gets the Base N encoding for the binary data
 *
 *	@param base_n
 *		The base we would like to convert, currently it could be Base 64 or Base 32.
 *
 *	@param data
 *		The data that needs to be encoded.
 *
 *	@param data_len
 *		The length of the data that needs to be encoded..
 *
 *	@return
 *		This function returns a malloced string that needs to be freed by the caller.
 */
char * _Nullable
base_n_encode(base_n_t base_n, const unsigned char * _Nonnull data, size_t data_len);

#pragma mark base_n_encode_ex
/*!
 *	@brief
 *		Gets the Base N encoding for the binary data, and return the length of the encoding string.
 *
 *	@param base_n
 *		The base we would like to convert, currently it could be Base 64 or Base 32.
 *
 *	@param data
 *		The data that needs to be encoded.
 *
 *	@param data_len
 *		The length of the data that needs to be encoded.
 *
 *	@param out_str_len
 *		The output pointer to the length of the encoded string.
 *
 *	@returns
 *		This function returns a malloced string that needs to be freed by the caller, and also the length of encoded string.
 */
char * _Nullable
base_n_encode_ex(base_n_t base_n, const unsigned char * _Nonnull data, size_t data_len, size_t * const _Nullable out_str_len);

#pragma mark get_base_n_encoded_str_length
/*!
 *	@brief
 *		Gets the length of the encoded string after Base N encoding
 *
 *	@param base_n
 *		The base we would like to convert, currently it could be DNSSEC_BASE_64 or DNSSEC_BASE_32_HEX.
 *
 *	@param data_len
 *		The length of the data that needs to be encoded.
 *
 *	@discussion
 *		The length does not include the '\0'.
 */
size_t
get_base_n_encoded_str_length(base_n_t base_n, size_t data_len) ;

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)

#endif /* base_n_h */
