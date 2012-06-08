/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

// ***************************************************************************
// CryptoSupport.c
// Supporting routines for DNSSEC crypto
// ***************************************************************************

#include "mDNSEmbeddedAPI.h"
#include <CommonCrypto/CommonDigest.h>  // For Hash algorithms SHA1 etc.
#include <dispatch/dispatch.h>          // For Base32/Base64 encoding/decoding
#include <dispatch/private.h>          // dispatch_data_create_with_transform
#include "CryptoAlg.h"
#include "CryptoSupport.h"
#include "dnssec.h"

#if TARGET_OS_IPHONE
#include "SecRSAKey.h"                  // For RSA_SHA1 etc. verification
#endif

typedef struct
{
#if DISPATCH_API_VERSION >= 20111008
    dispatch_data_t encData;
    dispatch_data_t encMap;
    dispatch_data_t encNULL;
#endif
}encContext;

mDNSlocal mStatus enc_create(AlgContext *ctx)
{
    encContext *ptr;

    switch (ctx->alg)
    {
    case ENC_BASE32:
    case ENC_BASE64:
        ptr = (encContext *)mDNSPlatformMemAllocate(sizeof(encContext));
        if (!ptr) return mStatus_NoMemoryErr;
        break;
    default:
        LogMsg("enc_create: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
#if DISPATCH_API_VERSION >= 20111008
    ptr->encData = NULL;
    ptr->encMap = NULL;
    // The encoded data is not NULL terminated. So, we concatenate a null byte later when we encode and map
    // the real data.
    ptr->encNULL = dispatch_data_create("", 1, dispatch_get_global_queue(0, 0), ^{});
    if (!ptr->encNULL)
    {
        mDNSPlatformMemFree(ptr);
        return mStatus_NoMemoryErr;
    }
#endif
    ctx->context = ptr;
    return mStatus_NoError;
}

mDNSlocal mStatus enc_destroy(AlgContext *ctx)
{
    encContext *ptr = (encContext *)ctx->context;
#if DISPATCH_API_VERSION >= 20111008
    if (ptr->encData) dispatch_release(ptr->encData);
    if (ptr->encMap) dispatch_release(ptr->encMap);
    if (ptr->encNULL) dispatch_release(ptr->encNULL);
#endif
    mDNSPlatformMemFree(ptr);
    return mStatus_NoError;
}

mDNSlocal mStatus enc_add(AlgContext *ctx, void *data, mDNSu32 len)
{
    switch (ctx->alg)
    {
    case ENC_BASE32:
    case ENC_BASE64:
    {
#if DISPATCH_API_VERSION >= 20111008
        encContext *ptr = (encContext *)ctx->context;
        dispatch_data_t src_data = dispatch_data_create(data, len, dispatch_get_global_queue(0, 0), ^{});
        if (!src_data)
        {
            LogMsg("enc_add: dispatch_data_create src failed");
            return mStatus_BadParamErr;
        }
        dispatch_data_t dest_data = dispatch_data_create_with_transform(src_data, DISPATCH_DATA_FORMAT_TYPE_NONE,
                                                                        (ctx->alg == ENC_BASE32 ? DISPATCH_DATA_FORMAT_TYPE_BASE32 : DISPATCH_DATA_FORMAT_TYPE_BASE64));
        dispatch_release(src_data);
        if (!dest_data)
        {
            LogMsg("enc_add: dispatch_data_create dst failed");
            return mStatus_BadParamErr;
        }
        ptr->encData = dest_data;
#else
        (void)data;
        (void)len;
#endif
        return mStatus_NoError;
    }
    default:
        LogMsg("enc_add: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
}

mDNSlocal mDNSu8* enc_encode(AlgContext *ctx)
{
    const void *result = NULL;

    switch (ctx->alg)
    {
    case ENC_BASE32:
    case ENC_BASE64:
    {
#if DISPATCH_API_VERSION >= 20111008
        encContext *ptr = (encContext *)ctx->context;
        size_t size;
        dispatch_data_t dest_data = ptr->encData;
        dispatch_data_t data = dispatch_data_create_concat(dest_data, ptr->encNULL);

        if (!data)
        {
            LogMsg("enc_encode: cannot concatenate");
            return NULL;
        }

        dispatch_data_t map = dispatch_data_create_map(data, &result, &size);
        if (!map)
        {
            LogMsg("enc_encode: cannot create map %d", ctx->alg);
            return NULL;
        }
        dispatch_release(dest_data);
        ptr->encData = data;
        ptr->encMap = map;
#endif
        return (mDNSu8 *)result;
    }
    default:
        LogMsg("enc_encode: Unsupported algorithm %d", ctx->alg);
        return mDNSNULL;
    }
}

mDNSlocal mStatus sha_create(AlgContext *ctx)
{
    mDNSu8 *ptr;
    switch (ctx->alg)
    {
    case SHA1_DIGEST_TYPE:
        ptr = mDNSPlatformMemAllocate(sizeof(CC_SHA1_CTX));
        if (!ptr) return mStatus_NoMemoryErr;
        CC_SHA1_Init((CC_SHA1_CTX *)ptr);
        break;
    case SHA256_DIGEST_TYPE:
        ptr = mDNSPlatformMemAllocate(sizeof(CC_SHA256_CTX));
        if (!ptr) return mStatus_NoMemoryErr;
        CC_SHA256_Init((CC_SHA256_CTX *)ptr);
        break;
    default:
        LogMsg("sha_create: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
    ctx->context = ptr;
    return mStatus_NoError;
}

mDNSlocal mStatus sha_destroy(AlgContext *ctx)
{
    mDNSPlatformMemFree(ctx->context);
    return mStatus_NoError;
}

mDNSlocal mDNSu32 sha_len(AlgContext *ctx)
{
    switch (ctx->alg)
    {
    case SHA1_DIGEST_TYPE:
        return CC_SHA1_DIGEST_LENGTH;
    case SHA256_DIGEST_TYPE:
        return CC_SHA256_DIGEST_LENGTH;
    default:
        LogMsg("sha_len: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
}

mDNSlocal mStatus sha_add(AlgContext *ctx, void *data, mDNSu32 len)
{
    switch (ctx->alg)
    {
    case SHA1_DIGEST_TYPE:
        CC_SHA1_Update((CC_SHA1_CTX *)ctx->context, data, len);
        break;
    case SHA256_DIGEST_TYPE:
        CC_SHA256_Update((CC_SHA256_CTX *)ctx->context, data, len);
        break;
    default:
        LogMsg("sha_add: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
    return mStatus_NoError;
}

mDNSlocal mStatus sha_verify(AlgContext *ctx, mDNSu8 *key, mDNSu32 keylen, mDNSu8 *digestIn, mDNSu32 dlen)
{
    mDNSu8 digest[CC_SHA512_DIGEST_LENGTH];
    mDNSu32 digestLen;

    (void) key;   //unused
    (void)keylen; //unused
    switch (ctx->alg)
    {
    case SHA1_DIGEST_TYPE:
        digestLen = CC_SHA1_DIGEST_LENGTH;
        CC_SHA1_Final(digest, (CC_SHA1_CTX *)ctx->context);
        break;
    case SHA256_DIGEST_TYPE:
        digestLen = CC_SHA256_DIGEST_LENGTH;
        CC_SHA256_Final(digest, (CC_SHA256_CTX *)ctx->context);
        break;
    default:
        LogMsg("sha_verify: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
    if (dlen != digestLen)
    {
        LogMsg("sha_verify(Alg %d): digest len mismatch len %u, expected %u", ctx->alg, (unsigned int)dlen, (unsigned int)digestLen);
        return mStatus_BadParamErr;
    }
    if (!memcmp(digest, digestIn, digestLen))
        return mStatus_NoError;
    else
        return mStatus_NoAuth;
}

mDNSlocal mStatus rsa_sha_create(AlgContext *ctx)
{
    mDNSu8 *ptr;
    switch (ctx->alg)
    {
    case CRYPTO_RSA_NSEC3_SHA1:
    case CRYPTO_RSA_SHA1:
        ptr = mDNSPlatformMemAllocate(sizeof(CC_SHA1_CTX));
        if (!ptr) return mStatus_NoMemoryErr;
        CC_SHA1_Init((CC_SHA1_CTX *)ptr);
        break;
    case CRYPTO_RSA_SHA256:
        ptr = mDNSPlatformMemAllocate(sizeof(CC_SHA256_CTX));
        if (!ptr) return mStatus_NoMemoryErr;
        CC_SHA256_Init((CC_SHA256_CTX *)ptr);
        break;
    case CRYPTO_RSA_SHA512:
        ptr = mDNSPlatformMemAllocate(sizeof(CC_SHA512_CTX));
        if (!ptr) return mStatus_NoMemoryErr;
        CC_SHA512_Init((CC_SHA512_CTX *)ptr);
        break;
    default:
        LogMsg("rsa_sha_create: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
    ctx->context = ptr;
    return mStatus_NoError;
}

mDNSlocal mStatus rsa_sha_destroy(AlgContext *ctx)
{
    mDNSPlatformMemFree(ctx->context);
    return mStatus_NoError;
}

mDNSlocal mDNSu32 rsa_sha_len(AlgContext *ctx)
{
    switch (ctx->alg)
    {
    case CRYPTO_RSA_NSEC3_SHA1:
    case CRYPTO_RSA_SHA1:
        return CC_SHA1_DIGEST_LENGTH;
    case CRYPTO_RSA_SHA256:
        return CC_SHA256_DIGEST_LENGTH;
    case CRYPTO_RSA_SHA512:
        return CC_SHA512_DIGEST_LENGTH;
    default:
        LogMsg("rsa_sha_len: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
}

mDNSlocal mStatus rsa_sha_add(AlgContext *ctx, void *data, mDNSu32 len)
{
    switch (ctx->alg)
    {
    case CRYPTO_RSA_NSEC3_SHA1:
    case CRYPTO_RSA_SHA1:
        CC_SHA1_Update((CC_SHA1_CTX *)ctx->context, data, len);
        break;
    case CRYPTO_RSA_SHA256:
        CC_SHA256_Update((CC_SHA256_CTX *)ctx->context, data, len);
        break;
    case CRYPTO_RSA_SHA512:
        CC_SHA512_Update((CC_SHA512_CTX *)ctx->context, data, len);
        break;
    default:
        LogMsg("rsa_sha_add: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }
    return mStatus_NoError;
}

#if TARGET_OS_IPHONE
mDNSlocal SecKeyRef rfc3110_import(const mDNSu8 *data, const mDNSu32 len)
{
    static const int max_key_bytes = 4096 / 8;                // max DNSSEC supported modulus is 4096 bits
    static const int max_exp_bytes = 3;                       // DNSSEC supports 1 or 3 bytes for exponent
    static const int asn1_cmd_bytes = 3;                      // since there is an ASN1 SEQ and two INTs
    //static const int asn1_max_len_bytes = asn1_cmd_bytes * 3; // capped at 3 due to max payload size
    static const int asn1_max_len_bytes = 3 * 3; // capped at 3 due to max payload size
    unsigned char asn1[max_key_bytes + 1 + max_exp_bytes + asn1_cmd_bytes + asn1_max_len_bytes]; // +1 is for leading 0 for non negative asn1 number
    const mDNSu8 *modulus;
    unsigned int modulus_length;
    unsigned int exp_length;
    mDNSu32 index = 0;
    mDNSu32 asn1_length = 0;
    unsigned int i;

    // Validate Input
    if (!data)
        return NULL;

    // we have to have at least 1 byte for the length
    if (len < 1)
        return NULL;

    // Parse Modulus and Exponent
    exp_length = data[0];

    // we have to have at least len byte + size of exponent
    if (len < 1+exp_length)
        return NULL;

    // -1 is for the exp_length byte
    modulus_length = len - 1 - exp_length;

    // rfc3110 limits modulus to 4096 bits
    if (modulus_length > 512)
        return NULL;

    if (modulus_length < 1)
        return NULL;

    // add 1 to modulus length for pre-ceding 0 t make ASN1 value non-negative
    ++modulus_length;

    // 1 is to skip exp_length byte
    modulus = &data[1+exp_length];

    // 2 bytes for commands since first doesn't count
    // 2 bytes for min 1 byte length field
    asn1_length = modulus_length + exp_length + 2 + 2;

    // account for modulus length causing INT length field to grow
    if (modulus_length > 0xFF)
        asn1_length += 2;
    else if (modulus_length >= 128)
        ++asn1_length;

    // Construct ASN1 formatted public key
    // Write ASN1 SEQ byte
    asn1[index++] = 0x30;

    // Write ASN1 length for SEQ
    if (asn1_length < 128)
    {
        asn1[index++] = asn1_length & 0xFF;
    }
    else
    {
        asn1[index++] = (0x80 | ((asn1_length & 0xFF00) ? 2 : 1));
        if (asn1_length & 0xFF00)
            asn1[index++] = (asn1_length & 0xFF00) >> 8;
        asn1[index++] = asn1_length & 0xFF;
    }

    // Write ASN1 INT for modulus
    asn1[index++] = 0x02;
    // Write ASN1 length for INT
    if (modulus_length < 128)
    {
        asn1[index++] = asn1_length & 0xFF;
    }
    else
    {
        asn1[index++] = 0x80 | ((modulus_length & 0xFF00) ? 2 : 1);
        if (modulus_length & 0xFF00)
            asn1[index++] = (modulus_length & 0xFF00) >> 8;
        asn1[index++] = modulus_length & 0xFF;
    }

    // Write preceding 0 so our integer isn't negative
    asn1[index++] = 0x00;
    // Write actual modulus (-1 for preceding 0)
    memcpy(&asn1[index], (void *)modulus, modulus_length-1);
    index += modulus_length-1;

    // Write ASN1 INT for exponent
    asn1[index++] = 0x02;
    // Write ASN1 length for INT
    asn1[index++] = exp_length & 0xFF;
    // Write exponent bytes
    for (i = 1; i <= exp_length; i++)
        asn1[index++] = data[i];

    // index contains bytes written, use it for length
    return SecKeyCreateRSAPublicKey(NULL, asn1, index, kSecKeyEncodingPkcs1);
}

mDNSlocal mStatus rsa_sha_verify(AlgContext *ctx, mDNSu8 *key, mDNSu32 keylen, mDNSu8 *signature, mDNSu32 siglen)
{
    SecKeyRef keyref;
    OSStatus result;
    mDNSu8 digest[CC_SHA512_DIGEST_LENGTH];
    int digestlen;

    switch (ctx->alg)
    {
    case CRYPTO_RSA_NSEC3_SHA1:
    case CRYPTO_RSA_SHA1:
        digestlen = CC_SHA1_DIGEST_LENGTH;
        CC_SHA1_Final(digest, (CC_SHA1_CTX *)ctx->context);
        break;
    case CRYPTO_RSA_SHA256:
        digestlen = CC_SHA256_DIGEST_LENGTH;
        CC_SHA256_Final(digest, (CC_SHA256_CTX *)ctx->context);
        break;
    case CRYPTO_RSA_SHA512:
        digestlen = CC_SHA512_DIGEST_LENGTH;
        CC_SHA512_Final(digest, (CC_SHA512_CTX *)ctx->context);
        break;
    default:
        LogMsg("rsa_sha_verify: Unsupported algorithm %d", ctx->alg);
        return mStatus_BadParamErr;
    }

    keyref = rfc3110_import(key, keylen);
    if (!key)
    {
        LogMsg("rsa_sha_verify: Error decoding rfc3110 key data");
        return mStatus_NoMemoryErr;
    }
    // TBD: Use the right algorithm when the support becomes available
    result = SecKeyRawVerify(keyref, kSecPaddingPKCS1SHA1, digest, digestlen, signature, siglen);
    LogMsg("rsa_sha_verify: result: %s (%ld)", result == noErr ? "PASS" : "FAIL", result);
    if (result == noErr)
        return mStatus_NoError;
    else
        return mStatus_BadParamErr;
}
#else
mDNSlocal mStatus rsa_sha_verify(AlgContext *ctx, mDNSu8 *key, mDNSu32 keylen, mDNSu8 *signature, mDNSu32 siglen)
{
    (void)ctx;
    (void)key;
    (void)keylen;
    (void)signature;
    (void)siglen;
    return mStatus_NoError;
}
#endif

AlgFuncs sha_funcs = {sha_create, sha_destroy, sha_len, sha_add, sha_verify, mDNSNULL};
AlgFuncs rsa_sha_funcs = {rsa_sha_create, rsa_sha_destroy, rsa_sha_len, rsa_sha_add, rsa_sha_verify, mDNSNULL};
AlgFuncs enc_funcs = {enc_create, enc_destroy, mDNSNULL, enc_add, mDNSNULL, enc_encode};

mDNSexport mStatus DNSSECCryptoInit(mDNS *const m)
{
    mStatus result;

    result = DigestAlgInit(SHA1_DIGEST_TYPE, &sha_funcs);
    if (result != mStatus_NoError)
        return result;
    result = DigestAlgInit(SHA256_DIGEST_TYPE, &sha_funcs);
    if (result != mStatus_NoError)
        return result;
    result = CryptoAlgInit(CRYPTO_RSA_SHA1, &rsa_sha_funcs);
    if (result != mStatus_NoError)
        return result;
    result = CryptoAlgInit(CRYPTO_RSA_NSEC3_SHA1, &rsa_sha_funcs);
    if (result != mStatus_NoError)
        return result;
    result = CryptoAlgInit(CRYPTO_RSA_SHA256, &rsa_sha_funcs);
    if (result != mStatus_NoError)
        return result;
    result = CryptoAlgInit(CRYPTO_RSA_SHA512, &rsa_sha_funcs);
    if (result != mStatus_NoError)
        return result;
    result = EncAlgInit(ENC_BASE32, &enc_funcs);
    if (result != mStatus_NoError)
        return result;
    result = EncAlgInit(ENC_BASE64, &enc_funcs);
    if (result != mStatus_NoError)
        return result;

    m->TrustAnchors = mDNSNULL;
    m->notifyToken  = 0;
    
    return mStatus_NoError;
}
