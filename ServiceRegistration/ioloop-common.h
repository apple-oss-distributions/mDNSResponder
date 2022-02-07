/* ioloop-common.h
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
 * This file contains structure definitions and function prototypes shared
 * by service registration code.
 */

#ifndef __IOLOOP_COMMON_H__
#define __IOLOOP_COMMON_H__

//======================================================================================================================
// MARK: - Structures

typedef struct service_connection service_connection_t;
struct service_connection {
    // The reference counted DNSServiceRef.
    dnssd_txn_t *NONNULL shared_connection;
    // The copy if the shared DNSServiceRef.
    DNSServiceRef NULLABLE service_ref;
    // Indicates whether the service_ref above is a shared DNSServiceRef or a sub DNSServiceRef of a shared DNSServiceRef.
    bool shares_service_ref;
    // If the service_ref above is a shared DNSServiceRef, then record_ref is used to remove the record, since shared one
    // is a global DNSServiceRef and cannot be used to stop DNSService operation.
    DNSRecordRef NULLABLE record_ref;
    // A customized context pointer.
    void *NULLABLE context;
};

//======================================================================================================================
// MARK: - Functions

//======================================================================================================================
// service_connection_t methods.

/*!
 *  @brief
 *      Creates a special dnssd_txn_t to share its DNSServiceRef with all service_connection_t calls.
 *
 *  @result
 *      returns the created dnssd_txn_t if no error occurs, otherwise, NULL.
 */
#define dnssd_txn_create_shared() dnssd_txn_create_shared_(__FILE__, __LINE__)
dnssd_txn_t *NULLABLE
dnssd_txn_create_shared_(const char *const NONNULL file, const int line);

/*!
 *  @brief
 *      Create a service_connection_t that shares the same DNSServiceRef with the passed in dnssd_txn_t.
 *
 *  @param shared_connection
 *      The dnssd_txn_t created by ioloop_dnssd_txn_add() that shares its DNSServiceRef with service_connection_t created by this function.
 */
#define service_connection_create(shared_conn) \
    service_connection_create_((shared_conn), __FILE__, __LINE__)
service_connection_t *NULLABLE
service_connection_create_(dnssd_txn_t *const NONNULL shared_txn, const char *const NONNULL file, const int line);

/*!
 *  @brief
 *      Cancel and release the DNSService operation created by this service_connection_t, and the object itself.
 *
 *  @param connection
 *      The service_connection_t created by service_connection_create().
 */
#define service_connection_cancel_and_release(connection) \
    service_connection_cancel_and_release_((connection), __FILE__, __LINE__)
void
service_connection_cancel_and_release_(service_connection_t *const NONNULL connection,
                                       const char *const NONNULL file, const int line);

/*!
 *  @brief
 *      Update the old DNSServiceRef with the new one.
 *
 *  @param connection
 *      The service_connection_t whose DNSServiceRef needs to be updated.
 *
 *  @param new_service_ref
 *      The new DNSServiceRef to use.
 */
void
service_connection_set_service_ref(service_connection_t *const NONNULL connection,
                                   const DNSServiceRef NONNULL new_service_ref);

/*!
 *  @brief
 *      Get the DNSServiceRef that is associated with the service_connection_t.
 *
 *  @param connection
 *      The service_connection_t that will be used to get the underline DNSServiceRef.
 *
 *  @result
 *      The underline DNSServiceRef.
 */
DNSServiceRef NONNULL
service_connection_get_service_ref(service_connection_t *const NONNULL connection);

/*!
 *  @brief
 *      Set the DNSRecordRef for service_connection_t,  it is only meaningful for the connection that uses the shared DNSServiceRef directly.
 *
 *  @param connection
 *      The service_connection_t created by service_connection_create().
 *
 *  @param record_ref
 *      The DNSRecordRef returned by DNSService operations.
 */
void
service_connection_set_record_ref(service_connection_t *const NONNULL connection,
                                  DNSRecordRef const NONNULL record_ref);

/*!
 *  @brief
 *      Set the context for service_connection_t, which can be retrieved by service_connection_get_context().
 *
 *  @param connection
 *      The service_connection_t created by service_connection_create().
 *
 *  @param context
 *      A pointer to a  customizable data that might be useful for each DNSService operation.
 */
void
service_connection_set_context(service_connection_t *const NONNULL connection, void *const NULLABLE context);

/*!
 *  @brief
 *      Set the context for service_connection_t, which is set by service_connection_set_context().
 *
 *  @param connection
 *      The service_connection_t created by service_connection_create().
 *
 *  @result
 *      A pointer to a  customizable data that might be useful for each DNSService operation.
 */
void *NULLABLE
service_connection_get_context(const service_connection_t *const NONNULL connection);

/*!
 *  @brief
 *      Check if the service_connection_t shares the same DNSServiceRef with dnssd_txn_t.
 *
 *  @param connection
 *      The service_connection_t created by service_connection_create().
 *
 *  @param dnssd_connection
 *      The dnssd_txn_t created by ioloop_dnssd_txn_add().
 */
bool
service_connection_uses_dnssd_connection(const service_connection_t *const NONNULL connection,
                                         dnssd_txn_t *const NONNULL dnssd_connection);

//======================================================================================================================

#endif // __IOLOOP_COMMON_H__
