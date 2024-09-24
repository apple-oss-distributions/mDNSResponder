/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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

#ifndef MRCS_SERVER_H
#define MRCS_SERVER_H

#include "mrcs_dns_proxy.h"

#include <MacTypes.h>
#include <mdns/base.h>
#include <mdns/dns_service.h>
#include <Network/Network_Private.h>

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		A handler that starts a specified DNS proxy.
 *
 *	@param proxy
 *		An object that describes the DNS proxy to start.
 *
 *	@result
 *		kNoErr if the DNS proxy was successfully started. Otherwise, a non-zero error code to indicate why the
 *		DNS proxy was not started.
 */
typedef OSStatus
(*mrcs_server_dns_proxy_start_handler_f)(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		A handler that stops a specified DNS proxy.
 *
 *	@param proxy
 *		A reference to the DNS proxy to stop.
 *
 *	@result
 *		kNoErr if the DNS proxy was successfully stopped. Otherwise, a non-zero error code to indicate why the
 *		DNS proxy was not stopped.
 */
typedef OSStatus
(*mrcs_server_dns_proxy_stop_handler_f)(mrcs_dns_proxy_t proxy);

/*!
 *	@brief
 *		A handler that gets the state of all active DNS proxies in human-readable text.
 *
 *	@result
 *		The text as an allocated C string.
 */
typedef char * _Nullable
(*mrcs_server_dns_proxy_get_state_handler_f)(void);

/*!
 *	@brief
 *		A structure containing dns proxy handlers to be invoked by an mDNSResponder control server.
 */
struct mrcs_server_dns_proxy_handlers_s {
	mrcs_server_dns_proxy_start_handler_f		start;
	mrcs_server_dns_proxy_stop_handler_f		stop;
	mrcs_server_dns_proxy_get_state_handler_f	get_state;
};

typedef const struct mrcs_server_dns_proxy_handlers_s *mrcs_server_dns_proxy_handlers_t;

/*!
 *	@brief
 *		A handler that starts a DNS service registration.
 *
 *	@param definition
 *		The DNS service's definition.
 *
 *	@param connection_error_queue
 *		Dispatch queue for the connection error event handler.
 *
 *	@param connection_error_handler
 *		The connection error event handler.
 *
 *	@result
 *		A non-zero identifier for the DNS service if the registration was successful. Otherwise,
 *		MDNS_DNS_SERVICE_INVALID_ID.
 */
typedef mdns_dns_service_id_t
(*mrcs_server_dns_service_registration_start_handler_f)(mdns_any_dns_service_definition_t definition,
	dispatch_queue_t _Nullable connection_error_queue, mdns_event_handler_t _Nullable connection_error_handler);

/*!
 *	@brief
 *		A handler that stops a DNS service registration.
 *
 *	@param ident
 *		The identifier returned by a mrcs_server_dns_service_registration_start_handler_f handler when the DNS
 *		service was registered.
 */
typedef void
(*mrcs_server_dns_service_registration_stop_handler_f)(mdns_dns_service_id_t ident);

/*!
 *	@brief
 *		A structure containing dns service registration handlers to be invoked by an mDNSResponder control
 *		server.
 */
struct mrcs_server_dns_service_registration_handlers_s {
	mrcs_server_dns_service_registration_start_handler_f	start;
	mrcs_server_dns_service_registration_stop_handler_f		stop;
};

typedef const struct mrcs_server_dns_service_registration_handlers_s *mrcs_server_dns_service_registration_handlers_t;

/*!
 *	@brief
 *		A handler that starts a specified discovery proxy.
 *
 *	@param ifindex
 *		The interface index of the discovery proxy.
 *
 *	@param addresses
 *		An array of mdns_address_t objects of the discovery proxy.
 *
 *	@param domains
 *		An array of mdns_domain_name_t objects of the discovery proxy.
 *
 *	@param certificates
 *		An array of CFDataRef TLS certificates in the DER representation of an X.509 certificate, which can be
 *		used as trust anchor when doing certificate evaluation.
 *
 *	@result
 *		kNoErr if the discovery proxy was successfully started. Otherwise, a non-zero error code to indicate why
 *		the DNS proxy was not started.
 */
typedef OSStatus
(*mrcs_server_discovery_proxy_start_handler_f)(uint32_t ifindex, CFArrayRef addresses, CFArrayRef domains,
	CFArrayRef certificates);

/*!
 *	@brief
 *		A handler that stops an existing discovery proxy.
 *
 *	@result
 *		kNoErr if the discovery proxy was successfully stopped. Otherwise, a non-zero error code to indicate why
 *		the discovery proxy was not stopped.
 */
typedef OSStatus
(*mrcs_server_discovery_proxy_stop_handler_f)(void);

/*!
 *	@brief
 *		A structure containing discovery proxy handlers to be invoked an mDNSResponder control server.
 */
struct mrcs_server_discovery_proxy_handlers_s {
	mrcs_server_discovery_proxy_start_handler_f	start;
	mrcs_server_discovery_proxy_stop_handler_f	stop;
};

typedef const struct mrcs_server_discovery_proxy_handlers_s *mrcs_server_discovery_proxy_handlers_t;

/*!
 *	@brief
 *		Type of block that handles a single resource record name during an enumeration of resource record names.
 *
 *	@param name
 *		The resource record name in presentation format as a C string.
 *
 *	@param txt_rdata
 *		The record's RDATA if it's a TXT record that belongs to a subdomain of _device-info._tcp.local.
 *
 *	@param txt_rdlen
 *		The record's RDATA length if it's a TXT record that belongs to a subdomain of _device-info._tcp.local.
 *
 *	@param source_address
 *		The record's source IPv4 or IPv6 address, if available.
 */
typedef void
(^mrcs_record_applier_t)(const char *name, const uint8_t * _Nullable txt_rdata, uint16_t txt_rdlen,
	const sockaddr_ip *source_address);

/*!
 *	@brief
 *		Enumerates the .local resource records from the latest snapshot of the resource record cache.
 *
 *	@param applier
 *		Block to synchronously invoke once for each record.
 *
 *	@discussion
 *		Currently, only the record names of .local resource records and the RDATA of *._device-info._tcp.local
 *		TXT records is being divulged. Therefore, not every single .local resource record is enumerated. For
 *		example, if multiple .local resource records have the same name, the applier is invoked only once with
 *		the source address of one of the records.
 *
 *		If the record name is a subdomain of _device-info._tcp.local and at least one TXT record is present in
 *		the cache, then one of the TXT record's RDATA and RDATA length are passed to the applier along with the
 *		name of the record.
 */
typedef void
(*mrcs_server_record_cache_enumerate_local_records_f)(mrcs_record_applier_t applier);

/*!
 *	@brief
 *		Flushes all records that have a specified record name from the record cache.
 *
 *	@param record_name
 *		The record name.
 */
typedef void
(*mrcs_server_record_cache_flush_by_name_f)(const char *record_name);

/*!
 *	@brief
 *		Flushes all records that have a specified record name and key tag from the record cache.
 *
 *	@param record_name
 *		The record name.
 *
 *	@param key_tag
 *		The key tag.
 */
typedef void
(*mrcs_server_record_cache_flush_by_name_and_key_tag_f)(const char *record_name, uint16_t key_tag);

/*!
 *	@brief
 *		A structure containing handlers to be invoked by an mDNSResponder control server to directly access
 *		records from the record cache.
 */
struct mrcs_server_record_cache_handlers_s {
	mrcs_server_record_cache_enumerate_local_records_f		enumerate_local_records;
	mrcs_server_record_cache_flush_by_name_f				flush_by_name;
	mrcs_server_record_cache_flush_by_name_and_key_tag_f	flush_by_name_and_key_tag;
};

typedef const struct mrcs_server_record_cache_handlers_s *mrcs_server_record_cache_handlers_t;

/*!
 *	@brief
 *		Sets the mDNSResponder control server's DNS proxy handlers.
 *
 *	@param handlers
 *		The DNS proxy handlers.
 *
 *	@discussion
 *		This function has no effect after the server has been activated.
 */
void
mrcs_server_set_dns_proxy_handlers(mrcs_server_dns_proxy_handlers_t handlers);

/*!
 *	@brief
 *		Sets the mDNSResponder control server's DNS service registration handlers.
 *
 *	@param handlers
 *		The DNS service registration handlers.
 *
 *	@discussion
 *		This function has no effect after the server has been activated.
 */
void
mrcs_server_set_dns_service_registration_handlers(mrcs_server_dns_service_registration_handlers_t handlers);

/*!
 *	@brief
 *		Sets the mDNSResponder control server's discovery proxy handlers.
 *
 *	@param handlers
 *		The discovery proxy handlers.
 *
 *	@discussion
 *		This function has no effect after the server has been activated.
 */
void
mrcs_server_set_discovery_proxy_handlers(mrcs_server_discovery_proxy_handlers_t handlers);

/*!
 *	@brief
 *		Sets the mDNSResponder control server's record cache handlers.
 *
 *	@param handlers
 *		The record cache handlers.
 *
 *	@discussion
 *		This function has no effect after the server has been activated.
 */
void
mrcs_server_set_record_cache_handlers(mrcs_server_record_cache_handlers_t handlers);

/*!
 *	@brief
 *		Activates the mDNSResponder control server.
 */
void
mrcs_server_activate(void);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRCS_SERVER_H
