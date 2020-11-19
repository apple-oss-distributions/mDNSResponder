/* cti_services.h
 *
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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
 * This file contains definitions for the SRP Advertising Proxy CoreThreadRadio
 * API on MacOS, which is private API used to control and manage the wpantund
 * and thereby manage the thread network.
 */

#ifndef CTI_SERVICES_H
#define CTI_SERVICES_H

#include <netinet/in.h>
#include <arpa/inet.h>
#include <dispatch/dispatch.h>
#include <xpc/xpc.h>
#include "srp.h"

#if (defined(__GNUC__) && (__GNUC__ >= 4))
#define DNS_SERVICES_EXPORT __attribute__((visibility("default")))
#else
#define DNS_SERVICES_EXPORT
#endif

// cti_connection: Opaque internal data type
typedef struct _cti_connection_t *cti_connection_t;

typedef enum
{
    kCTIStatus_NoError                   =  0,
    kCTIStatus_UnknownError              = -65537,   /* 0xFFFE FFFF */
    kCTIStatus_NoMemory                  = -65539,   /* No Memory   */
    kCTIStatus_BadParam                  = -65540,   /* Client passed invalid arg */
    kCTIStatus_DaemonNotRunning          = -65563,   /* Daemon not running */
    kCTIStatus_Disconnected              = -65569    /* XPC connection disconnected. */
} cti_status_t;

// Enum values for kWPANTUNDStateXXX (see wpan-properties.h)
typedef enum {
    kCTI_NCPState_Uninitialized,
    kCTI_NCPState_Fault,
    kCTI_NCPState_Upgrading,
    kCTI_NCPState_DeepSleep,
    kCTI_NCPState_Offline,
    kCTI_NCPState_Commissioned,
    kCTI_NCPState_Associating,
    kCTI_NCPState_CredentialsNeeded,
    kCTI_NCPState_Associated,
    kCTI_NCPState_Isolated,
    kCTI_NCPState_NetWake_Asleep,
    kCTI_NCPState_NetWake_Waking,
    kCTI_NCPState_Unknown
} cti_network_state_t;

typedef enum {
    kCTI_NetworkNodeType_Unknown,
    kCTI_NetworkNodeType_Router,
    kCTI_NetworkNodeType_EndDevice,
    kCTI_NetworkNodeType_SleepyEndDevice,
    kCTI_NetworkNodeType_NestLurker,
    kCTI_NetworkNodeType_Commissioner,
    kCTI_NetworkNodeType_Leader,
} cti_network_node_type_t;

typedef struct _cti_service {
    uint64_t enterprise_number;
    uint16_t service_type;
    uint16_t service_version;
    uint8_t *NONNULL server;
    size_t server_length;
    int ref_count;
    int flags;      // E.g., kCTIFlag_NCP
} cti_service_t;

typedef struct _cti_service_vec {
    size_t num;
    int ref_count;
    cti_service_t *NULLABLE *NONNULL services;
} cti_service_vec_t;

typedef struct _cti_prefix {
    struct in6_addr prefix;
    int prefix_length;
    int metric;
    int flags;
    int ref_count;
} cti_prefix_t;

typedef struct _cti_prefix_vec {
    size_t num;
    int ref_count;
    cti_prefix_t *NULLABLE *NONNULL prefixes;
} cti_prefix_vec_t;

// CTI flags.
#define kCTIFlag_Stable                1
#define kCTIFlag_NCP                   2

/*********************************************************************************************
 *
 *  wpantund private SPI for use in SRP Advertising Proxy
 *
 *********************************************************************************************/

/* cti_reply:
 *
 * A general reply mechanism to indicate success or failure for a cti call that doesn't
 * return any data.
 *
 * cti_reply parameters:
 *
 * context:    The context that was passed to the cti service call to which this is a callback.
 *
 * status:	   Will be kCTIStatus_NoError on success, otherwise will indicate the
 * 			   failure that occurred.
 *
 */

typedef void
(*cti_reply_t)(void *NULLABLE context, cti_status_t status);

/* cti_tunnel_reply: Callback for cti_get_tunnel_name()
 *
 * Called exactly once in response to a cti_get_tunnel_name() call, either with an error or with
 * the name of the tunnel that wpantund is using as the Thread network interface.   The invoking
 * program is responsible for releasing the connection state either during or after the callback.
 *
 * cti_reply parameters:
 *
 * context:       The context that was passed to the cti service call to which this is a callback.
 *
 * tunnel_name:   If error is kCTIStatus_NoError, this dictionary contains either the response to
 * 			      a request, or else the content of a CTI event if this is an event callback.
 *
 * status:	      Will be kCTIStatus_NoError on success, otherwise will indicate the
 * 			      failure that occurred.
 *
 */

typedef void
(*cti_tunnel_reply_t)(void *NULLABLE context, const char *NONNULL tunnel_name,
                      cti_status_t status);

/* cti_get_tunnel_name
 *
 * Get the name of the tunnel that wpantund is presenting as the Thread network interface.
 * The tunnel name is passed to the reply callback if the request succeeds; otherwise an error
 * is either returned immediately or returned to the callback.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 *
 * client_queueq:  Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating the
 *                 error that occurred. Note: A return value of kCTIStatus_NoError does not mean that the
 *                 request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_get_tunnel_name(void *NULLABLE context, cti_tunnel_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue);

/*
 * cti_service_vec_create
 *
 * creates a service array vector of specified length
 *
 * num_services:     Number of service slots available in the service vector.
 *
 * return value:     NULL, if the call failed; otherwise a service vector capable of containing the requested number of
 *                   services.
 */
cti_service_vec_t *NULLABLE
cti_service_vec_create_(size_t num_services, const char *NONNULL file, int line);
#define cti_service_vec_create(num_services) cti_service_vec_create_(num_services, __FILE__, __LINE__)

/*
 * cti_service_vec_release
 *
 * decrements the reference count on the provided service vector and, if it reaches zero, finalizes the service vector,
 * which calls cti_service_release on each service in the vector, potentially also finalizing them.
 *
 * num_services:     Number of service slots available in the service vector.
 *
 * return value:     NULL, if the call failed; otherwise a service vector capable of containing the requested number of
 *                   services.
 */

void
cti_service_vec_release_(cti_service_vec_t *NONNULL services, const char *NONNULL file, int line);
#define cti_service_vec_release(services) cti_service_vec_release_(services, __FILE__, __LINE__)

/*
 * cti_service_create
 *
 * Creates a service containing the specified information.   service and server are retained, and will be
 * freed using free() when the service object is finalized.   Caller must not retain or free these values, and
 * they must be allocated on the malloc heap.
 *
 * enterprise_number: The enterprise number for this service.
 *
 * service_type:      The service type, from the service data.
 *
 * service_version:   The service version, from the service data.
 *
 * server:            Server information for this service, stored in network byte order.   Format depends on service type.
 *
 * server_length:     Length of server information in bytes.
 *
 * flags:             Thread network status flags, e.g. NCP versue User
 *
 * return value:     NULL, if the call failed; otherwise a service object containing the specified state.
 */

cti_service_t *NULLABLE
cti_service_create_(uint64_t enterprise_number, uint16_t service_type, uint16_t service_version,
                    uint8_t *NONNULL server, size_t server_length, int flags,
                    const char *NONNULL file, int line);
#define cti_service_create(enterprise_number, service_type, service_version, server, server_length, flags) \
    cti_service_create_(enterprise_number, service_type, service_version, server, server_length, flags, \
                        __FILE__, __LINE__)

/*
 * cti_service_vec_release
 *
 * decrements the reference count on the provided service vector and, if it reaches zero, finalizes the service vector,
 * which calls cti_service_release on each service in the vector, potentially also finalizing them.
 *
 * services:         The service vector to release
 *
 * return value:     NULL, if the call failed; otherwise a service vector capable of containing the requested number of
 *                   services.
 */

void
cti_service_release_(cti_service_t *NONNULL service, const char *NONNULL file, int line);
#define cti_service_release(services) cti_service_release(service, __FILE__, __LINE__)

/* cti_service_reply: Callback from cti_get_service_list()
 *
 * Called when an error occurs during processing of the cti_get_service_list call, or when data
 * is available in response to the call.
 *
 * In the case of an error, the callback will not be called again, and the caller is responsible for
 * releasing the connection state and restarting if needed.
 *
 * The callback will be called once immediately upon success, and once again each time the service list
 * is updated.   If the callback wishes to retain either the cti_service_vec_t or any of the elements
 * of that vector, the appropriate retain function should be called; when the object is no longer needed,
 * the corresponding release call must be called.
 *
 * cti_reply parameters:
 *
 * context:           The context that was passed to the cti service call to which this is a callback.
 *
 * services:          If status is kCTIStatus_NoError, a cti_service_vec_t containing the list of services
 *                    provided in the update.
 *
 * status:	          Will be kCTIStatus_NoError if the service list request is successful, or
 *                    will indicate the failure that occurred.
 *
 */

typedef void
(*cti_service_reply_t)(void *NULLABLE context, cti_service_vec_t *NULLABLE services, cti_status_t status);

/* cti_get_service_list
 *
 * Requests wpantund to immediately send the current list of services published in the Thread network data.
 * Whenever the service list is updated, the callback will be called again with the new information.  A
 * return value of kCTIStatus_NoError means that the caller can expect the reply callback to be called at least
 * once.  Any other error status means that the request could not be sent, and the callback will never be
 * called.
 *
 * To discontinue receiving service add/remove callbacks, the calling program should call
 * cti_connection_ref_deallocate on the conn_ref returned by a successful call to get_service_list();
 *
 * ref:            A pointer to a reference to the connection is stored through ref if ref is not NULL.
 *                 When events are no longer needed, call cti_discontinue_events() on the returned pointer.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 *
 * client_queue:   Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *                 If the get_services call fails, response will be NULL and status
 *                 will indicate what went wrong.  No further callbacks can be expected
 *                 after this.   If the request succeeds, then the callback will be called
 *                 once immediately with the current service list, and then again whenever
 *                 the service list is updated.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                 the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                 that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_get_service_list(cti_connection_t NULLABLE *NULLABLE ref, void *NULLABLE context, cti_service_reply_t NONNULL callback,
                     dispatch_queue_t NONNULL client_queue);

/*
 * cti_service_vec_create
 *
 * creates a service array vector of specified length
 *
 * num_prefixes:     Number of prefix slots available in the prefix vector.
 *
 * return value:     NULL, if the call failed; otherwise a prefix vector capable of containing the requested number of
 *                   prefixes.
 */
cti_prefix_vec_t *NULLABLE
cti_prefix_vec_create_(size_t num_prefixes, const char *NONNULL file, int line);
#define cti_prefix_vec_create(num_prefixes) cti_prefix_vec_create_(num_prefixes, __FILE__, __LINE__)

/*
 * cti_prefix_vec_release
 *
 * decrements the reference count on the provided prefix vector and, if it reaches zero, finalizes the prefix vector,
 * which calls cti_prefix_release on each prefix in the vector, potentially also finalizing them.
 *
 * num_prefixes:     Number of prefix slots available in the prefix vector.
 *
 * return value:     NULL, if the call failed; otherwise a prefix vector capable of containing the requested number of
 *                   prefixes.
 */

void
cti_prefix_vec_release_(cti_prefix_vec_t *NONNULL prefixes, const char *NONNULL file, int line);
#define cti_prefix_vec_release(prefixes) cti_prefix_vec_release(prefixes, __FILE__, __LINE__)

/*
 * cti_prefix_create
 *
 * Creates a prefix containing the specified information.   prefix and server are retained, and will be
 * freed using free() when the prefix object is finalized.   Caller must not retain or free these values, and
 * they must be allocated on the malloc heap.
 *
 * enterprise_number: The enterprise number for this prefix.
 *
 * prefix_type:      The prefix type, from the prefix data.
 *
 * prefix_version:   The prefix version, from the prefix data.
 *
 * server:            Server information for this prefix, stored in network byte order.   Format depends on prefix type.
 *
 * server_length:     Length of server information in bytes.
 *
 * flags:             Thread network status flags, e.g. NCP versue User
 *
 * return value:     NULL, if the call failed; otherwise a prefix object containing the specified state.
 */

cti_prefix_t *NULLABLE
cti_prefix_create_(struct in6_addr *NONNULL prefix, int prefix_length, int metric, int flags,
                   const char *NONNULL file, int line);
#define cti_prefix_create(prefix, prefix_length, metric, flags) \
    cti_prefix_create_(prefix, prefix_length, metric, flags, __FILE__, __LINE__)

/*
 * cti_prefix_vec_release
 *
 * decrements the reference count on the provided prefix vector and, if it reaches zero, finalizes the prefix vector,
 * which calls cti_prefix_release on each prefix in the vector, potentially also finalizing them.
 *
 * prefixes:         The prefix vector to release.
 *
 * return value:     NULL, if the call failed; otherwise a prefix vector capable of containing the requested number of
 *                   prefixes.
 */

void
cti_prefix_release_(cti_prefix_t *NONNULL prefix, const char *NONNULL file, int line);
#define cti_prefix_release(prefixes) cti_prefix_release(prefix, __FILE__, __LINE__)

/* cti_prefix_reply: Callback from cti_get_prefix_list()
 *
 * Called when an error occurs during processing of the cti_get_prefix_list call, or when a prefix
 * is added or removed.
 *
 * In the case of an error, the callback will not be called again, and the caller is responsible for
 * releasing the connection state and restarting if needed.
 *
 * The callback will be called once for each prefix present on the Thread network at the time
 * get_prefix_list() is first called, and then again whenever a prefix is added or removed.
 *
 * cti_reply parameters:
 *
 * context:           The context that was passed to the cti prefix call to which this is a callback.
 *
 * prefix_vec:        If status is kCTIStatus_NoError, a vector containing all of the prefixes that were reported in
 *                    this event.
 *
 * status:	          Will be kCTIStatus_NoError if the prefix list request is successful, or
 *                    will indicate the failure that occurred.
 *
 */

typedef void
(*cti_prefix_reply_t)(void *NULLABLE context, cti_prefix_vec_t *NONNULL prefixes, cti_status_t status);

/* cti_get_prefix_list
 *
 * Requests wpantund to immediately send the current list of off-mesh prefixes configured in the Thread
 * network data.  Whenever the prefix list is updated, the callback will be called again with the new
 * information.  A return value of kCTIStatus_NoError means that the caller can expect the reply callback to be
 * called at least once.  Any other error means that the request could not be sent, and the callback will
 * never be called.
 *
 * To discontinue receiving prefix add/remove callbacks, the calling program should call
 * cti_connection_ref_deallocate on the conn_ref returned by a successful call to get_prefix_list();
 *
 * ref:            A pointer to a reference to the connection is stored through ref if ref is not NULL.
 *                 When events are no longer needed, call cti_discontinue_events() on the returned pointer.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 *
 * client_queue:   Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                 the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                 that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_get_prefix_list(cti_connection_t NULLABLE *NULLABLE ref, void *NULLABLE context, cti_prefix_reply_t NONNULL callback,
                    dispatch_queue_t NONNULL client_queue);

/* cti_state_reply: Callback from cti_get_state()
 *
 * Called when an error occurs during processing of the cti_get_state call, or when network state
 * information is available.
 *
 * In the case of an error, the callback will not be called again, and the caller is responsible for
 * releasing the connection state and restarting if needed.
 *
 * The callback will be called initially to report the network state, and subsequently whenever the
 * network state changes.
 *
 * cti_reply parameters:
 *
 * context:           The context that was passed to the cti state call to which this is a callback.
 *
 * state:             The network state.
 *
 * status:	          Will be kCTIStatus_NoError if the prefix list request is successful, or
 *                    will indicate the failure that occurred.
 *
 */

typedef void
(*cti_state_reply_t)(void *NULLABLE context, cti_network_state_t state, cti_status_t status);

/* cti_get_state
 *
 * Requests wpantund to immediately send the current state of the thread network.  Whenever the thread
 * network state changes, the callback will be called again with the new state.  A return value of
 * kCTIStatus_NoError means that the caller can expect the reply callback to be called at least once.  Any
 * other error means that the request could not be sent, and the callback will never be called.
 *
 * To discontinue receiving state change callbacks, the calling program should call
 * cti_connection_ref_deallocate on the conn_ref returned by a successful call to cti_get_state();
 *
 * ref:            A pointer to a reference to the connection is stored through ref if ref is not NULL.
 *                 When events are no longer needed, call cti_discontinue_events() on the returned pointer.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 * client_queue:   Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                 the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                 that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_get_state(cti_connection_t NULLABLE *NULLABLE ref, void *NULLABLE context, cti_state_reply_t NONNULL callback,
              dispatch_queue_t NONNULL client_queue);

/* cti_partition_id_reply: Callback from cti_get_partition_id()
 *
 * Called when an error occurs during processing of the cti_get_partition_id call, or when network partition ID
 * information is available.
 *
 * In the case of an error, the callback will not be called again, and the caller is responsible for
 * releasing the connection partition_id and restarting if needed.
 *
 * The callback will be called initially to report the network partition ID, and subsequently whenever the
 * network partition ID changes.
 *
 * cti_reply parameters:
 *
 * context:           The context that was passed to the cti prefix call to which this is a callback.
 *
 * partition_id:      The network partition ID, or -1 if it is not known.
 *
 * status:	          Will be kCTIStatus_NoError if the partition ID request is successful, or will indicate the failure
 *                    that occurred.
 *
 */

typedef void
(*cti_partition_id_reply_t)(void *NULLABLE context, int32_t partition_id, cti_status_t status);

/* cti_get_partition_id
 *
 * Requests wpantund to immediately send the current partition_id of the thread network.  Whenever the thread
 * network partition_id changes, the callback will be called again with the new partition_id.  A return value of
 * kCTIStatus_NoError means that the caller can expect the reply callback to be called at least once.  Any
 * other error means that the request could not be sent, and the callback will never be called.
 *
 * To discontinue receiving partition_id change callbacks, the calling program should call
 * cti_connection_ref_deallocate on the conn_ref returned by a successful call to cti_get_partition_id();
 *
 * ref:            A pointer to a reference to the connection is stored through ref if ref is not NULL.
 *                 When events are no longer needed, call cti_discontinue_events() on the returned pointer.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 * client_queue:   Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                 the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                 that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_get_partition_id(cti_connection_t NULLABLE *NULLABLE ref, void *NULLABLE context,
                     cti_partition_id_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue);

/* cti_network_node_type_reply: Callback from cti_get_network_node_type()
 *
 * Called when an error occurs during processing of the cti_get_network_node_type call, or when network partition ID
 * information is available.
 *
 * In the case of an error, the callback will not be called again, and the caller is responsible for releasing the
 * connection network_node_type and restarting if needed.
 *
 * The callback will be called initially to report the network partition ID, and subsequently whenever the network
 * partition ID changes.
 *
 * cti_reply parameters:
 *
 * context:           The context that was passed to the cti prefix call to which this is a callback.
 *
 * network_node_type: The network node type, kCTI_NetworkNodeType_Unknown if it is not known.
 *
 * status:	          Will be kCTIStatus_NoError if the partition ID request is successful, or will indicate the failure
 *                    that occurred.
 *
 */

typedef void
(*cti_network_node_type_reply_t)(void *NULLABLE context, cti_network_node_type_t network_node_type, cti_status_t status);

/* cti_get_network_node_type
 *
 * Requests wpantund to immediately send the current network_node_type of the thread network.  Whenever the thread
 * network network_node_type changes, the callback will be called again with the new network_node_type.  A return value of
 * kCTIStatus_NoError means that the caller can expect the reply callback to be called at least once.  Any
 * other error means that the request could not be sent, and the callback will never be called.
 *
 * To discontinue receiving network_node_type change callbacks, the calling program should call
 * cti_connection_ref_deallocate on the conn_ref returned by a successful call to cti_get_network_node_type();
 *
 * ref:            A pointer to a reference to the connection is stored through ref if ref is not NULL.
 *                 When events are no longer needed, call cti_discontinue_events() on the returned pointer.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 * client_queue:   Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                 the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                 that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_get_network_node_type(cti_connection_t NULLABLE *NULLABLE ref, void *NULLABLE context,
                          cti_network_node_type_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue);

/* cti_add_service
 *
 * Requests wpantund to add the specified service to the thread network data.  A return value of
 * kCTIStatus_NoError means that the caller can expect the reply callback to be called with a success or fail
 * status exactly one time.  Any other error means that the request could not be sent, and the callback will
 * never be called.
 *
 * context:           An anonymous pointer that will be passed along to the callback when
 *                    an event occurs.
 *
 * client_queue:      Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * callback:          CallBack function for the client that indicates success or failure.
 *
 * enterprise_number: Contains the enterprise number of the service.
 *
 * service_data:      Typically four bytes, in network byte order, the first two bytes indicate
 *                    the type of service within the enterprise' number space, and the second
 *                    two bytes indicate the version number.
 *
 * service_data_len:  The length of the service data in bytes.
 *
 * server_data:       Typically four bytes, in network byte order, the first two bytes indicate
 *                    the type of service within the enterprise' number space, and the second
 *                    two bytes indicate the version number.
 *
 * server_data_len:   The length of the service data in bytes.
 *
 * return value:      Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                    the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                    that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_add_service(void *NULLABLE context, cti_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue,
                uint32_t enterprise_number, const uint8_t *NONNULL service_data, size_t service_data_length,
                const uint8_t *NONNULL server_data, size_t server_data_length);

/* cti_remove_service
 *
 * Requests wpantund to remove the specified service from the thread network data.  A return value of
 * kCTIStatus_NoError means that the caller can expect the reply callback to be called with a success or fail
 * status exactly one time.  Any other error means that the request could not be sent, and the callback will
 * never be called.
 *
 * context:           An anonymous pointer that will be passed along to the callback when
 *                    an event occurs.
 *
 * client_queue:      Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * enterprise_number: Contains the enterprise number of the service.
 *
 * service_data:      Typically four bytes, in network byte order, the first two bytes indicate
 *                    the type of service within the enterprise' number space, and the second
 *                    two bytes indicate the version number.
 *
 * service_data_len:  The length of the service data in bytes.
 *
 * callback:          callback function for the client that indicates success or failure.
 *
 * return value:      Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                    the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                    that the request succeeded, merely that it was successfully started.
 */

DNS_SERVICES_EXPORT cti_status_t
cti_remove_service(void *NULLABLE context, cti_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue,
                   uint32_t enterprise_number, const uint8_t *NONNULL service_data,
                   size_t service_data_length);

/* cti_add_prefix
 *
 * Requests wpantund to add the specified prefix to the set of off-mesh prefixes configured on the thread
 * network.  A return value of kCTIStatus_NoError means that the caller can expect the reply callback to be
 * called with a success or fail status exactly one time.  Any other error means that the request could not
 * be sent, and the callback will never be called.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 * client_queue:   Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * prefix:         A pointer to a struct in6_addr.  Must not be reatained by the callback.
 *
 * prefix_len:     The length of the prefix in bits.
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                 the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                 that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_add_prefix(void *NULLABLE context, cti_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue,
               struct in6_addr *NONNULL prefix, int prefix_length, bool on_mesh, bool preferred, bool slaac,
               bool stable);

/* cti_remove_prefix
 *
 * Requests wpantund to remove the specified prefix from the set of off-mesh prefixes configured on the thread network.
 * A return value of kCTIStatus_NoError means that the caller can expect the reply callback to be called with a success
 * or fail status exactly one time.  Any other error means that the request could not be sent, and the callback will
 * never be called.
 *
 * context:        An anonymous pointer that will be passed along to the callback when
 *                 an event occurs.
 *
 * client_queue:   Queue the client wants to schedule the callback on (Note: Must not be NULL)
 *
 * prefix:         A pointer to a struct in6_addr.  Must not be reatained by the callback.
 *
 * prefix_len:     The length of the prefix in bits.
 *
 * callback:       CallBack function for the client that indicates success or failure.
 *
 * return value:   Returns kCTIStatus_NoError when no error otherwise returns an error code indicating
 *                 the error that occurred. Note: A return value of kCTIStatus_NoError does not mean
 *                 that the request succeeded, merely that it was successfully started.
 *
 */

DNS_SERVICES_EXPORT cti_status_t
cti_remove_prefix(void *NULLABLE context, cti_reply_t NONNULL callback, dispatch_queue_t NONNULL client_queue,
                  struct in6_addr *NONNULL prefix, int prefix_length);

/* cti_events_discontinue
 *
 * Requests that the CTI library stop delivering events on the specified connection.   The connection will have
 * been returned by a CTI library call that subscribes to events.
 */
DNS_SERVICES_EXPORT cti_status_t
cti_events_discontinue(cti_connection_t NONNULL ref);

#endif /* CTI_SERVICES_H */

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 120
// indent-tabs-mode: nil
// End:
