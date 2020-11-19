/* srp-tls.h
 *
 * Copyright (c) 2019 Apple Computer, Inc. All rights reserved.
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
 * TLS Shim definitions.   These entry points should in principle work for any TLS
 * library, with the addition of a single shim file, for example tls-mbedtls.c.
 */

#ifndef __SRP_TLS_H
#define __SRP_TLS_H
// Anonymous key structure, depends on the target.
typedef struct srp_key srp_key_t;

#ifdef SRP_CRYPTO_MBEDTLS_INTERNAL
#include <mbedtls/certs.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>

struct tls_context {
    struct mbedtls_ssl_context context;
    enum { handshake_in_progress, handshake_complete } state;
};
#endif // SRP_CRYPTO_MBEDTLS_INTERNAL

// tls_*.c:
bool srp_tls_init(void);
bool srp_tls_client_init(void);
bool srp_tls_server_init(const char *NULLABLE cacert_file,
			 const char *NULLABLE srvcrt_file, const char *NULLABLE server_key_file);
bool srp_tls_accept_setup(comm_t *NONNULL comm);
bool srp_tls_listen_callback(comm_t *NONNULL comm);
bool srp_tls_connect_callback(comm_t *NONNULL comm);
ssize_t srp_tls_read(comm_t *NONNULL comm, unsigned char *NONNULL buf, size_t max);
void srp_tls_context_free(comm_t *NONNULL comm);
ssize_t srp_tls_write(comm_t *NONNULL comm, struct iovec *NONNULL iov, int iov_len);

#endif // __SRP_TLS_H

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
