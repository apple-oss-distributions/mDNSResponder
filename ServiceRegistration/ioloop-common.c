/* ioloop-common.c
 *
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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
 *
 * This file contains common code shared by service registration code.
 */

//======================================================================================================================
// MARK: - Headers

//======================================================================================================================
// MARK: - Headers

#include <dns_sd.h> // for DNSServiceRef and DNSRecordRef.
#include <stdlib.h>
#include <netinet/in.h>
#include "srp.h"
#include "dns-msg.h"
#include "ioloop.h"
#include "ioloop-common.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Functions

dnssd_txn_t *NULLABLE
dnssd_txn_create_shared_(const char *const NONNULL file, const int line)
{
    DNSServiceRef service_ref = NULL;
    dnssd_txn_t *txn = NULL;

    const DNSServiceErrorType dns_err = DNSServiceCreateConnection(&service_ref);
    if (dns_err != kDNSServiceErr_NoError) {
        goto exit;
    }

    txn = ioloop_dnssd_txn_add_(service_ref, NULL, NULL, NULL, file, line);
    if (txn == NULL) {
        MDNS_DISPOSE_DNS_SERVICE_REF(service_ref);
        goto exit;
    }

exit:
    return txn;
}

//======================================================================================================================

service_connection_t *NULLABLE
service_connection_create_(dnssd_txn_t *const NONNULL shared_connection, const char *const NONNULL file, const int line)
{
    service_connection_t *const connection = mdns_calloc(1, sizeof(*connection));
    if (connection == NULL) {
        return connection;
    }

    connection->shared_connection = shared_connection;
    // Increase the reference count by one.
    ioloop_dnssd_txn_retain_(connection->shared_connection, file, line);
    // Some DNSService operations need a copy of the shared DNSServiceRef.
    connection->service_ref = shared_connection->sdref;

    // Before the DNSService operation that creates a real copy of the shared DNSServiceRef, all service_connection_t
    // is sharing the same one.
    connection->shares_service_ref = true;

    return connection;
}

//======================================================================================================================

void
service_connection_cancel_and_release_(service_connection_t *const NONNULL connection,
                                       const char *const NONNULL file, const int line)
{
    if (connection->shares_service_ref) {
        if (connection->record_ref != NULL) {
            DNSServiceRemoveRecord(connection->service_ref, connection->record_ref, 0);
        }
    } else {
        MDNS_DISPOSE_DNS_SERVICE_REF(connection->service_ref);
    }
    // Decrease the reference count by one.
    ioloop_dnssd_txn_release_(connection->shared_connection, file, line);

    service_connection_t *conn_to_free = connection;
    mdns_free(conn_to_free);
}

//======================================================================================================================

void
service_connection_set_service_ref(service_connection_t *const NONNULL connection,
                                   const DNSServiceRef NONNULL new_service_ref)
{
    connection->service_ref = new_service_ref;
    connection->shares_service_ref = false;
}

//======================================================================================================================

DNSServiceRef NONNULL
service_connection_get_service_ref(service_connection_t *const NONNULL connection)
{
    return connection->service_ref;
}

//======================================================================================================================

void
service_connection_set_record_ref(service_connection_t *const NONNULL connection,
                                  DNSRecordRef const NONNULL new_record_ref)
{
    connection->record_ref = new_record_ref;
    // connection->shares_service_ref is set to true by default.
}

//======================================================================================================================

void
service_connection_set_context(service_connection_t *const NONNULL connection, void *const NULLABLE context)
{
    connection->context = context;
}

//======================================================================================================================

void *NULLABLE
service_connection_get_context(const service_connection_t *const NONNULL connection)
{
    return connection->context;
}

//======================================================================================================================

bool
service_connection_uses_dnssd_connection(const service_connection_t *const NONNULL connection,
                                         dnssd_txn_t *const NONNULL dnssd_connection)
{
    return connection->shared_connection == dnssd_connection;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
