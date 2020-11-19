/* sign.c
 *
 * Copyright (c) 2018-2019 Apple Computer, Inc. All rights reserved.
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
 *
 * DNS SIG(0) signature generation for DNSSD SRP using mbedtls.
 *
 * Functions required for loading, saving, and generating public/private keypairs, extracting the public key
 * into KEY RR data, and computing signatures.
 *
 * This is the implementation for Mac OS X.
 */


#include <stdio.h>
#include <arpa/inet.h>
#include <sys/random.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include <dns_sd.h>

#include "srp.h"
#include "srp-api.h"
#include "dns-msg.h"
#define SRP_CRYPTO_MACOS_INTERNAL
#include "srp-crypto.h"

// Key is stored in an opaque data structure, for mbedtls this is an mbedtls_pk_context.
// Function to read a public key from a KEY record
// Function to validate a signature given some data and a public key (not required on client)

// Function to free a key
void
srp_keypair_free(srp_key_t *key)
{
    free(key);
}

uint16_t
srp_random16()
{
    return arc4random_uniform(65536);
}

static void
srp_sec_error_print(const char *reason, OSStatus status)
{
    const char *utf8 = NULL;
    CFStringRef err = SecCopyErrorMessageString(status, NULL);
    if (err != NULL) {
        utf8 = CFStringGetCStringPtr(err, kCFStringEncodingUTF8);
    }
    if (utf8 != NULL) {
        ERROR(PUB_S_SRP ": " PUB_S_SRP, reason, utf8);
    } else {
        ERROR(PUB_S_SRP ": %d", reason, (int)status);
    }
    if (err != NULL) {
        CFRelease(err);
    }
}

// Function to generate a key
static srp_key_t *
srp_get_key_internal(const char *key_name, bool delete)
{
    long two56 = 256;
    srp_key_t *key = NULL;
    OSStatus status;

    CFMutableDictionaryRef key_parameters = CFDictionaryCreateMutable(NULL, 8,
                                                                      &kCFTypeDictionaryKeyCallBacks,
                                                                      &kCFTypeDictionaryValueCallBacks);
    CFMutableDictionaryRef pubkey_parameters;

    if (key_parameters != NULL) {
        CFDictionaryAddValue(key_parameters, kSecAttrIsPermanent, kCFBooleanTrue);
        CFDictionaryAddValue(key_parameters, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
        CFNumberRef num = CFNumberCreate(NULL, kCFNumberLongType, &two56);
        CFDictionaryAddValue(key_parameters, kSecAttrKeySizeInBits, num);
        CFRelease(num);
        CFStringRef str = CFStringCreateWithCString(NULL, key_name, kCFStringEncodingUTF8);
        CFDictionaryAddValue(key_parameters, kSecAttrLabel, str);
        CFRelease(str);
        CFDictionaryAddValue(key_parameters, kSecReturnRef, kCFBooleanTrue);
        CFDictionaryAddValue(key_parameters, kSecMatchLimit, kSecMatchLimitOne);
        CFDictionaryAddValue(key_parameters, kSecClass, kSecClassKey);
        pubkey_parameters = CFDictionaryCreateMutableCopy(NULL, 8, key_parameters);
        if (pubkey_parameters != NULL) {
            CFDictionaryAddValue(key_parameters, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
            CFDictionaryAddValue(pubkey_parameters, kSecAttrKeyClass, kSecAttrKeyClassPublic);
            CFDictionaryAddValue(pubkey_parameters, kSecAttrIsExtractable, kCFBooleanTrue);
            CFDictionaryAddValue(key_parameters, kSecAttrIsExtractable, kCFBooleanTrue);
#if !defined(OPEN_SOURCE) && TARGET_OS_TV
            CFDictionaryAddValue(pubkey_parameters, kSecAttrAccessible,
                                 kSecAttrAccessibleAlwaysThisDeviceOnlyPrivate);
#else
            CFDictionaryAddValue(pubkey_parameters, kSecAttrAccessible,
                                 kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
#endif
            if (delete) {
                status = SecItemDelete(key_parameters);
                if (status == errSecSuccess) {
                    status = SecItemDelete(pubkey_parameters);
                }
                key = NULL;
            } else {
                key = calloc(1, sizeof(*key));

                if (key != NULL) {
                    CFErrorRef error = NULL;

                    // See if the key is already on the keychain.
                    status = SecItemCopyMatching(key_parameters, (CFTypeRef *)&key->private);
                    if (status == errSecSuccess) {
                        status = SecItemCopyMatching(pubkey_parameters, (CFTypeRef *)&key->public);
                    } else {
                        key->private = SecKeyCreateRandomKey(key_parameters, &error);
                        if (key->private != NULL) {
                            key->public = SecKeyCopyPublicKey(key->private);
                        }
                    }
                    if (key->public == NULL || key->private == NULL) {
                        if (error != NULL) {
                            CFShow(error);
                        } else {
                            srp_sec_error_print("Failed to get key pair", status);
                        }
                        free(key);
                        key = NULL;
                    }
                }
            }
            CFRelease(key_parameters);
            CFRelease(pubkey_parameters);
        }
    }
    return key;
}

srp_key_t *
srp_get_key(const char *key_name, void *__unused os_context)
{
    return srp_get_key_internal(key_name, false);
}

// Remove an existing key
int
srp_reset_key(const char *key_name, void *__unused os_context)
{
    srp_get_key_internal(key_name, true);
    return kDNSServiceErr_NoError;
}

// void to get the length of the public key
size_t
srp_pubkey_length(srp_key_t *key)
{
    (void)key;
    return ECDSA_KEY_SIZE;
}

int
srp_key_algorithm(srp_key_t *key)
{
    (void)key;
    return dnssec_keytype_ecdsa;
}

size_t
srp_signature_length(srp_key_t *key)
{
    (void)key;
    return ECDSA_KEY_SIZE;
}

// Function to copy out the public key as binary data
int
srp_pubkey_copy(uint8_t *buf, size_t max, srp_key_t *key)
{
    CFErrorRef error = NULL;
    int ret = 0;
    CFDataRef pubkey = SecKeyCopyExternalRepresentation(key->public, &error);
    if (pubkey == NULL) {
        if (error != NULL) {
            CFShow(error);
        } else {
            ERROR("Unknown failure in SecKeyCopyExternalRepresentation");
        }
    } else {
        const uint8_t *bytes = CFDataGetBytePtr(pubkey);
        unsigned long len = CFDataGetLength(pubkey);

        // Should be 04 | X | Y
        if (bytes[0] != 4) {
            ERROR("Unexpected preamble to public key: %d", bytes[0]);
        } else if (len - 1 > max) {
            ERROR("Not enough room for public key in buffer: %ld > %zd", len - 1, max);
        } else if (len - 1 != ECDSA_KEY_SIZE) {
            ERROR("Unexpected key size %ld", len - 1);
        } else {
            memcpy(buf, bytes + 1, len - 1);
            ret = ECDSA_KEY_SIZE;
        }
        CFRelease(pubkey);
    }
    return ret;
}

// Function to generate a signature given some data and a private key
int
srp_sign(uint8_t *output, size_t max, uint8_t *message, size_t msglen,
         uint8_t *rr, size_t rdlen, srp_key_t *key)
{
    CFMutableDataRef payload = NULL;
    CFDataRef signature = NULL;
    CFErrorRef error = NULL;
    const uint8_t *bytes;
    unsigned long len;
    int ret = 0;

    typedef struct {
        SecAsn1Item r, s;
    } raw_signature_data_t;
    raw_signature_data_t raw_signature;

    ECDSA_SIG_TEMPLATE(sig_template);

    if (max < ECDSA_SHA256_SIG_SIZE) {
        ERROR("srp_sign: not enough space in output buffer (%lu) for signature (%d).",
              (unsigned long)max, ECDSA_SHA256_SIG_SIZE);
        return 0;
    }

    payload = CFDataCreateMutable(NULL, msglen + rdlen);
    if (payload == NULL) {
        ERROR("srp_sign: CFDataCreateMutable failed on length %zd", msglen + rdlen);
        return 0;
    }
    CFDataAppendBytes(payload, rr, rdlen);
    CFDataAppendBytes(payload, message, msglen);

    signature = SecKeyCreateSignature(key->private,
                                      kSecKeyAlgorithmECDSASignatureMessageX962SHA256, payload, &error);
    CFRelease(payload);
    if (error != NULL) {
        CFRelease(signature);
        CFShow(error);
        return 0;
    }
    if (signature == NULL) {
        ERROR("No error, but no signature.");
        return 0;
    }

    SecAsn1CoderRef decoder;
    OSStatus status = SecAsn1CoderCreate(&decoder);
    if (status == errSecSuccess) {
        len = CFDataGetLength(signature);
        bytes = CFDataGetBytePtr(signature);

        status = SecAsn1Decode(decoder, bytes, len, sig_template, &raw_signature);
        if (status == errSecSuccess) {
            if (raw_signature.r.Length + raw_signature.s.Length > ECDSA_SHA256_SIG_SIZE) {
                ERROR("Unexpected length %zd + %zd is not %d", raw_signature.r.Length,
                      raw_signature.s.Length, ECDSA_SHA256_SIG_SIZE);
            } else {
                unsigned long diff = ECDSA_SHA256_SIG_PART_SIZE - raw_signature.r.Length;
                if (diff > 0) {
                    memset(output, 0, diff);
                }
                memcpy(output + diff, raw_signature.r.Data, raw_signature.r.Length);
                diff = ECDSA_SHA256_SIG_PART_SIZE - raw_signature.s.Length;
                if (diff > 0) {
                    memset(output + ECDSA_SHA256_SIG_PART_SIZE, 0, diff);
                }
                memcpy(output + ECDSA_SHA256_SIG_PART_SIZE + diff, raw_signature.s.Data, raw_signature.s.Length);
                ret = 1;
            }
        }
        SecAsn1CoderRelease(decoder);
    }
    if (status != errSecSuccess) {
        srp_sec_error_print("srp_sign", status);
    }
    CFRelease(signature);
    return ret;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
