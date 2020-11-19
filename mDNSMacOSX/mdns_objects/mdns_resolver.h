/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

#ifndef __MDNS_RESOLVER_H__
#define __MDNS_RESOLVER_H__

#include "mdns_base.h"
#include "mdns_address.h"
#include "mdns_object.h"

#include <dispatch/dispatch.h>
#include <MacTypes.h>
#include <xpc/xpc.h>

MDNS_DECL(querier);
MDNS_DECL(resolver);

// Workaround for the new SVCB and HTTPS resource record types, to which some DNS servers react negatively.
#define MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND	1

OS_CLOSED_ENUM(mdns_resolver_type, int,
	mdns_resolver_type_null		= 0,
	/*! @const mdns_resolver_type_normal A resolver that uses normal DNS, i.e., DNS over UDP and TCP. */
	mdns_resolver_type_normal	= 1,
	/*! @const mdns_resolver_type_tcp A resolver that uses DNS over TCP. */
	mdns_resolver_type_tcp		= 2,
	/*! @const mdns_resolver_type_tls A resolver that uses DNS over TLS. */
	mdns_resolver_type_tls		= 3,
	/*! @const mdns_resolver_type_https A resolver that uses DNS over HTTPS. */
	mdns_resolver_type_https	= 4
);

MDNS_ASSUME_NONNULL_BEGIN

static inline const char *
mdns_resolver_type_to_string(mdns_resolver_type_t type)
{
	switch (type) {
		case mdns_resolver_type_null:		return "null";
		case mdns_resolver_type_normal:		return "normal";
		case mdns_resolver_type_tcp:		return "tcp";
		case mdns_resolver_type_tls:		return "tls";
		case mdns_resolver_type_https:		return "https";
		default:							return "<INVALID RESOLVER TYPE>";
	}
}

__BEGIN_DECLS

/*!
 *	@brief
 *		Creates a resolver object, which represents a DNS service.
 *
 *	@param type
 *		The type of resolver to create.
 *
 *	@param interface_index
 *		Index of the interface to use for network traffic to the DNS service.
 *
 *	@result
 *		A new resolver object or NULL if there was a lack of resources.
 *
 *	@discussion
 *		Generally, the servers that implement the DNS service are specified with
 *		mdns_resolver_add_server_address().
 *
 *		However, for resolvers of type mdns_resolver_type_tls and mdns_resolver_type_https, no server addresses
 *		need to be specified at all so long as a hostname is specified with mdns_resolver_set_provider_name(),
 *		and, optionally, a port number with mdns_resolver_set_port(). In this case, the system's stub resolver
 *		will be used to resolve the hostname to IP addresses.
 */
MDNS_RETURNS_RETAINED mdns_resolver_t _Nullable
mdns_resolver_create(mdns_resolver_type_t type, uint32_t interface_index, OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Specifies the queue on which to invoke the resolver's asynchronous handlers.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param queue
 *		A dispatch queue.
 *
 *	@discussion
 *		Currently, a resolver's only asynchronous handler is its event handler.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
void
mdns_resolver_set_queue(mdns_resolver_t resolver, dispatch_queue_t queue);

OS_CLOSED_ENUM(mdns_resolver_event, int,
	/*! @const mdns_resolver_event_null This value represents the absence of an event (will never be delivered). */
	mdns_resolver_event_null		= 0,
	/*! @const mdns_resolver_event_invalidated Indicates that the resolver has been invalidated. */
	mdns_resolver_event_invalidated	= 1,
	/*! @const mdns_resolver_event_connection Used to report the status of a resolver's connection. */
	mdns_resolver_event_connection	= 2
);

static inline const char *
mdns_resolver_event_to_string(const mdns_resolver_event_t event)
{
	switch (event) {
		case mdns_resolver_event_null:			return "null";
		case mdns_resolver_event_invalidated:	return "invalidated";
		case mdns_resolver_event_connection:	return "connection";
		default:								return "<invalid event value>";
	}
}

#define MDNS_RESOLVER_EVENT_CONNECTION_INFO_KEY_CANNOT_CONNECT	"cannot_connect"

/*!
 *	@brief
 *		A block for handling an asynchronous resolver event.
 *
 *	@param event
 *		Indicates the event's type.
 *
 *	@param info
 *		A dictionary whose format is specific to the event's type. The information contained in the dictionary
 *		is relevant to the event currently being handled. If the dictionary is required after the handler has
 *		finished executing, it should be retained with xpc_retain().
 */
typedef void (^mdns_resolver_event_handler_t)(mdns_resolver_event_t event, xpc_object_t _Nullable info);

/*!
 *	@brief
 *		Sets a resolver's event handler.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param handler
 *		The event handler.
 *
 *	@discussion
 *		If invoked, the event handler will be submitted to the dispatch queue specified by
 *		mdns_resolver_set_queue() for any of the following events:
 *
 *		- mdns_resolver_event_invalidated
 *			Indicates that the resolver has been completely invalidated. After this event, the event handler
 *			will never be invoked again. This event doesn't provide an info dictionary.
 *
 *		The event handler will never be invoked prior to a call to either mdns_resolver_activate() or
 *		mdns_resolver_invalidate().
 *
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
void
mdns_resolver_set_event_handler(mdns_resolver_t resolver, mdns_resolver_event_handler_t handler);

/*!
 *	@brief
 *		Specifies the "provider name" of the DNS service represented by a resolver.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param provider_name
 *		The provider name.
 *
 *	@result
 *		kNoErr if the provider name was successfully set. Otherwise, a non-zero error code.
 *
 *	@discussion
 *		The meaning of a provider name depends on the type of resolver.
 *
 *		This function is currently only meaningful for resolvers that use DNS over TLS or HTTPS, i.e., resolvers
 *		of type mdns_resolver_type_tls or mdns_resolver_type_https. For these resolvers, the provider name is
 *		the hostname used for TLS certificate authentication.
 *
 *		If no server addresses are specified with mdns_resolver_add_server_address() and the DNS service uses a
 *		port number other than the default for its type of service, then use mdns_resolver_set_port() to specify
 *		that port.
 *
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
OSStatus
mdns_resolver_set_provider_name(mdns_resolver_t resolver, const char * _Nullable provider_name);

/*!
 *	@brief
 *		Specifies the port number of the DNS service represented by a resolver.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param port
 *		The port number. A value of 0 means to use the DNS service's default port number.
 *
 *	@discussion
 *		This function is currently only meaningful for resolvers that use DNS over TLS or HTTPS, i.e., resolvers
 *		of type mdns_resolver_type_tls or mdns_resolver_type_https, and only when a hostname has been specified
 *		with mdns_resolver_set_provider_name() and no server addresses have been specified with
 *		mdns_resolver_add_server_address().
 *
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
void
mdns_resolver_set_port(mdns_resolver_t resolver, uint16_t port);

/*!
 *	@brief
 *		For resolvers that use HTTP, specifies the path part of the DNS service's URL.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param url_path
 *		The path part of the DNS service's URL.
 *
 *	@result
 *		kNoErr if the URL path was successfully set. Otherwise, a non-zero error code.
 *
 *	@discussion
 *		This function has no effect on a resolver that has been activated or invalidated.
 *
 *		This function is currently only meaningful for resolvers that use DNS over HTTPS, i.e., resolvers of type
 *		mdns_resolver_type_https.
 */
OSStatus
mdns_resolver_set_url_path(mdns_resolver_t resolver, const char * _Nullable url_path);

/*!
 *	@brief
 *		Squash CNAME chains for responses.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param squash_cnames
 *		A boolean to indicate that CNAME chains should be squashed.
 *
 *	@discussion
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
void
mdns_resolver_set_squash_cnames(mdns_resolver_t resolver, bool squash_cnames);

/*!
 *	@brief
 *		Determines whether a resolver reports DNS server responsiveness symptoms.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param enable
 *		If true, the resolver will report DNS server responsiveness symptoms. If false, it will not.
 *
 *	@discussion
 *		Symptom reporting is disabled by default.
 *
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
void
mdns_resolver_enable_symptom_reporting(mdns_resolver_t resolver, bool enable);

/*!
 *	@brief
 *		Specifies the IP address and port pair of one of the servers that implement the DNS service represented
 *		by a resolver.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param address
 *		The server's IP address and port pair. If the port number is 0, then the DNS service's default port
 *		number will be used.
 *
 *	@result
 *		kNoErr on success. Otherwise, a non-zero error code.
 *
 *	@discussion
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
OSStatus
mdns_resolver_add_server_address(mdns_resolver_t resolver, mdns_address_t address);

/*!
 *	@brief
 *		Specifies the initial datagram retransmission interval in seconds.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param interval_secs
 *		The interval in seconds.
 *
 *	@discussion
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
void
mdns_resolver_set_initial_datagram_retransmission_interval(mdns_resolver_t resolver, uint32_t interval_secs);

/*!
 *	@brief
 *		Determines whether a resolver makes an effort to reuse existing connections for queries that need to be
 *		sent over a connection.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param disable
 *		If true, disables connection reuse. If false, enables connection reuse.
 *
 *	@discussion
 *		For efficiency, connection reuse is enabled by default. If a query needs to be sent to a server via a
 *		connection (as opposed to via a datagram) and a connection to the server already exists, then that
 *		connection will be reused instead of establishing a new connection.
 *
 *		If connection reuse is disabled, then each query that needs to be sent over a connection will use its
 *		own connection.
 *
 *		This function has no effect on a resolver that has been activated or invalidated.
 */
void
mdns_resolver_disable_connection_reuse(mdns_resolver_t resolver, bool disable);

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
/*!
 *	@brief
 *		Enables or disables a workaround where a resolver's queriers will refrain from sending queries of type
 *		SVCB and HTTPS to a server if the server has been determined to not respond to queries of those types.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@param threshold
 *		If greater than zero, the workaround is enabled. Otherwise, the workaround is disabled.
 *
 *	@discussion
 *		This is a workaround for DNS servers that don't respond to SVCB and HTTPS queries and then become less
 *		responsive to queries of other types as more SVCB and HTTPS retry queries are sent.
 *
 *		The workaround is disabled by default.
 *
 *		This function has no effect on a resolver after it has been activated or invalidated.
 */
void
mdns_resolver_enable_problematic_qtype_workaround(mdns_resolver_t resolver, int threshold);
#endif

/*!
 *	@brief
 *		Activates a resolver.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@discussion
 *		Activation makes the resolver usable to its queriers.
 *
 *		This function has no effect on a resolver that has already been activated or one that has been invalidated.
 */
void
mdns_resolver_activate(mdns_resolver_t resolver);

/*!
 *	@brief
 *		Invalidates a resolver.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@discussion
 *		This function should be called when the resolver is no longer needed. When called, all outstanding
 *		queriers that were created by this resolver will asynchronously conclude with a kEndingErr error, unless
 *		a response or some other error is pending.
 *
 *		If a queue was specified with mdns_resolver_set_queue() and an event handler was specified with
 *		mdns_resolver_set_event_handler(), then an mdns_resolver_event_invalidated event will be asynchronously
 *		delivered to the event handler to indicate when the invalidation is complete.
 *
 *		This function has no effect on a resolver that has already been invalidated.
 */
void
mdns_resolver_invalidate(mdns_resolver_t resolver);

/*!
 *	@brief
 *		Determines if resolvers of a given type use encryption.
 *
 *	@param type
 *		The resolver type.
 *
 *	@result
 *		Returns true if the resolvers of the specified type use encryption. Otherwise, returns false.
 */
bool
mdns_resolver_type_uses_encryption(mdns_resolver_type_t type);

/*!
 *	@brief
 *		Creates a querier to issue queries to the DNS service represented by the resolver.
 *
 *	@param resolver
 *		The resolver.
 *
 *	@discussion
 *		A querier issues one or more queries to the DNS service represented by a resolver for a particular QNAME,
 *		QTYPE, and QCLASS triple until is gets a response.
 */
MDNS_RETURNS_RETAINED mdns_querier_t _Nullable
mdns_resolver_create_querier(mdns_resolver_t resolver, OSStatus * _Nullable out_error);

/*!
 *	@brief
 *		Specifies the queue on which to invoke the querier's result handler.
 *
 *	@param querier
 *		The querier.
 *
 *	@param queue
 *		The queue.
 *
 *	@discussion
 *		This function must be called before activating the querier.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
void
mdns_querier_set_queue(mdns_querier_t querier, dispatch_queue_t queue);

/*!
 *	@brief
 *		Defines the query, i.e., the name, type, and class of the resource record(s) to query for.
 *
 *	@param querier
 *		The querier.
 *
 *	@param qname
 *		The name of the resource record(s) to query for as a sequence of domain name labels, i.e., the querier's
 *		DNS query's QNAME value.
 *
 *	@param qtype
 *		The type of the resource record(s) to query for, i.e., the querier's DNS query's QTYPE value.
 *
 *	@param qclass
 *		The class of the resource record(s) to query for, i.e., the querier's DNS query's QCLASS value.
 *
 *	@discussion
 *		This function must be called before activating the querier.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
OSStatus
mdns_querier_set_query(mdns_querier_t querier, const uint8_t *qname, uint16_t qtype, uint16_t qclass);

/*!
 *	@brief
 *		Determines whether a querier's queries will include an OPT record in the additional section with the
 *		"DNSSEC OK" (DO) bit set.
 *
 *	@param querier
 *		The querier.
 *
 *	@param dnssec_ok
 *		If true, a querier's queries will include an OPT record in the additional section with the DO bit set.
 *
 *		If false and the querier's queries do include an OPT record in the additional section, then the DO bit
 *		will be cleared.
 *
 *	@discussion
 *		From section 3 of RFC3225 <https://tools.ietf.org/html/rfc3225#section-3>:
 *
 *			Setting the DO bit to one in a query indicates to the server that the
 *			resolver is able to accept DNSSEC security RRs.  The DO bit cleared
 *			(set to zero) indicates the resolver is unprepared to handle DNSSEC
 *			security RRs and those RRs MUST NOT be returned in the response
 *			(unless DNSSEC security RRs are explicitly queried for).
 *
 *		If an OPT record is included in a query, the default behavior is to clear the DO bit.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
void
mdns_querier_set_dnssec_ok(mdns_querier_t querier, bool dnssec_ok);

/*!
 *	@brief
 *		Determines whether a querier's queries will have the Checking Disabled (CD) bit set.
 *
 *	@param querier
 *		The querier.
 *
 *	@param checking_disabled
 *		If true, a querier's queries will have the CD bit set.
 *
 *		If false, a querier's queries will have the CD bit cleared.
 *
 *	@discussion
 *		From section 3.2.2 of RFC4035 <https://tools.ietf.org/html/rfc4035#section-3.2.2>:
 *
 *			The CD bit exists in order to allow a security-aware resolver to
 *			disable signature validation in a security-aware name server's
 *			processing of a particular query.
 *
 *		The default behavior is to clear the CD bit.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
void
mdns_querier_set_checking_disabled(mdns_querier_t querier, bool checking_disabled);

/*!
 *	@brief
 *		Sets the querier's delegator by its process identifier (PID).
 *
 *	@param querier
 *		The querier.
 *
 *	@param pid
 *		The delegator's PID.
 *
 *	@discussion
 *		This function marks the querier's datagram network traffic as belonging to the delegator.
 *
 *		If this functionality is needed, this function must be called before activating the querier.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
void
mdns_querier_set_delegator_pid(mdns_querier_t querier, pid_t pid);

/*!
 *	@brief
 *		Sets the querier's delegator by its universally unique identifier (UUID).
 *
 *	@param querier
 *		The querier.
 *
 *	@param uuid
 *		The delegator's UUID.
 *
 *	@discussion
 *		This function marks the querier's datagram network traffic as belonging to the delegator.
 *
 *		If this functionality is needed, this function must be called before activating the querier.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
void
mdns_querier_set_delegator_uuid(mdns_querier_t querier, uuid_t _Nonnull uuid);

/*!
 *	@brief
 *		Sets the querier's logging label.
 *
 *	@param querier
 *		The querier.
 *
 *	@param format
 *		The printf-style format string for the label.
 *
 *	@discussion
 *		Log messages associated with this querier will be prefixed with the specified label.
 *
 *		If this functionality is needed, this function must be called before activating the querier.
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
OSStatus
mdns_querier_set_log_label(mdns_querier_t querier, const char *format, ...) MDNS_PRINTF_FORMAT(2, 3);

/*!
 *	@typedef mdns_querier_result_type_t
 *
 *	@brief 
 *		Inidicates the type of result with which a querier concluded.
 *
 *	@const mdns_querier_result_type_null
 *		Used as a placeholder value to indicate no result. A querier will never conclude with this result type.
 *
 *	@const mdns_querier_result_type_response
 *		Indicates that a querier concluded with a response to its query.
 *
 *	@const mdns_querier_result_type_timeout
 *		Indicates that a querier concluded because it reached its current time limit before getting a response.
 *
 *	@const mdns_querier_result_type_invalidation
 *		Indicates that a querier concluded because it was invalidated before getting a response.
 *
 *	@const mdns_querier_result_type_resolver_invalidation
 *		Indicates that a querier concluded because its resolver was invalidated before getting a response.
 *
 *	@const mdns_querier_result_type_error
 *		Indicates that a querier concluded because it ran into a fatal error before getting a response.
 */
OS_CLOSED_ENUM(mdns_querier_result_type, int,
	mdns_querier_result_type_null					= 0,
	mdns_querier_result_type_response				= 1,
	mdns_querier_result_type_timeout				= 2,
	mdns_querier_result_type_invalidation			= 3,
	mdns_querier_result_type_resolver_invalidation	= 4,
	mdns_querier_result_type_error					= 5
);

static inline const char *
mdns_querier_result_type_to_string(const mdns_querier_result_type_t type)
{
	switch (type) {
		case mdns_querier_result_type_null:						return "null";
		case mdns_querier_result_type_response:					return "response";
		case mdns_querier_result_type_timeout:					return "timeout";
		case mdns_querier_result_type_invalidation:				return "invalidation";
		case mdns_querier_result_type_resolver_invalidation:	return "resolver-invalidation";
		case mdns_querier_result_type_error:					return "error";
	}
	return "<INVALID RESOLVER TYPE>";
}
typedef void
(^mdns_querier_result_handler_t)(void);

/*!
 *	@brief
 *		Sets a querier's result handler.
 *
 *	@param querier
 *		The querier.
 *
 *	@param handler
 *		The result handler.
 *
 *	@discussion
 *		The result handler will be invoked on the dispatch queue specified by
 *		mdns_querier_set_queue() and will never be invoked more than once.
 *
 *		A querier's result type can be determined with mdns_querier_get_result_type().
 *
 *		This function has no effect on a querier that has been activated or invalidated.
 */
void
mdns_querier_set_result_handler(mdns_querier_t querier, mdns_querier_result_handler_t handler);

/*!
 *	@brief
 *		Imposes a time limit on the time that a querier spends waiting for a response to its query.
 *
 *	@param querier
 *		The querier.
 *
 *	@param time_limit_ms
 *		The time limit in milliseconds.
 *
 *	@discussion
 *		This function can be called more than once to reset the current time limit.
 *
 *		If this function is called before activation, then the time limit doesn't apply until activation.
 *
 *		This function has no effect on a querier that has concluded.
 */
void
mdns_querier_set_time_limit_ms(mdns_querier_t querier, int32_t time_limit_ms);

/*!
 *	@brief
 *		Sets a user-defined identifier on a querier.
 *
 *	@param querier
 *		The querier.
 *
 *	@param user_id
 *		The identifier.
 *
 *	@discussion
 *		This function is a convenience function meant to help users in situations where a querier is associated
 *		with a numerical value. This function has no effect on a querier's operational behavior.
 *
 *		The default identifier is 0.
 *
 *		This function has no effect on a querier that has been activated.
 */
void
mdns_querier_set_user_id(mdns_querier_t querier, uint32_t user_id);

/*!
 *	@brief
 *		Activates a querier.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		This function has no effect on a querier that has already been activated or one that has been invalidated.
 */
void
mdns_querier_activate(mdns_querier_t querier);

/*!
 *	@brief
 *		Invalidates a querier.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		This function should be called when the querier is no longer needed.
 *
 *		This function has no effect on a querier that has already been invalidated.
 */
void
mdns_querier_invalidate(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets the QNAME value that a querier uses for its DNS queries.
 *
 *	@param querier
 *		The querier.
 *
 *	@result
 *		If at least one successful call was made to mdns_querier_set_query(), then this function returns a
 *		non-NULL pointer to a domain name as a sequence of labels that's equal in value to the qname argument
 *		used for the last successful call to mdns_querier_set_query(). Otherwise, NULL.
 *
 *		If the result is a non-NULL pointer, then the pointer is guaranteed to be valid until the next
 *		successful call to mdns_querier_set_query() or until all references to the querier have been released,
 *		whichever comes first.
 */
const uint8_t * _Nullable
mdns_querier_get_qname(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets the QTYPE value that a querier uses for its DNS queries.
 *
 *	@param querier
 *		The querier.
 *
 *	@result
 *		If at least one successful call was made to mdns_querier_set_query(), then this function returns a value
 *		equal to the qtype argument used for the last successful call to mdns_querier_set_query(). Otherwise, 0.
 */
uint16_t
mdns_querier_get_qtype(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets the QCLASS value that a querier uses for its DNS queries.
 *
 *	@param querier
 *		The querier.
 *
 *	@result
 *		If at least one successful call was made to mdns_querier_set_query(), then this function returns a value
 *		equal to the qclass argument used for the last successful call to mdns_querier_set_query(). Otherwise,
 *		0.
 */
uint16_t
mdns_querier_get_qclass(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets a querier's resolver type.
 *
 *	@param querier
 *		The querier.
 */
mdns_resolver_type_t
mdns_querier_get_resolver_type(mdns_querier_t querier);

/*!
 *	@brief
 *		Returns the type of result with which a querier concluded.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		This function should only be called from the result handler or after the result handler has been
 *		invoked.
 */
mdns_querier_result_type_t
mdns_querier_get_result_type(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets the current number of queries that a querier has sent.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		It's safe to call this function before a querier has concluded.
 */
uint32_t
mdns_querier_get_send_count(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets the byte-length of a querier's DNS query message.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		This function should only be called from the result handler or after the result handler has been
 *		invoked.
 */
uint32_t
mdns_querier_get_query_length(mdns_querier_t querier);

/*!
 *	@brief
 *		Returns a pointer to the first bye of a querier's DNS response message in wire format.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		This function should only be called from the result handler or after the result handler has been
 *		invoked. The pointer returned is only meaningful if the querier's result type is
 *		mdns_querier_result_type_response.
 */
const uint8_t * _Nullable
mdns_querier_get_response_ptr(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets the byte-length of a querier's DNS response message.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		This function should only be called from the result handler or after the result handler has been
 *		invoked. The length returned is only meaningful if the querier's result type is
 *		mdns_querier_result_type_response.
 */
uint32_t
mdns_querier_get_response_length(mdns_querier_t querier);

/*!
 *	@brief
 *		Returns whether or not a querier's response is fabricated.
 *
 *	@param querier
 *		The querier.
 *
 *	@result
 *		Returns true if the response is fabricated. Otherwise, false.
 *
 *	@discussion
 *		This function should only be called from the result handler or after the result handler has been
 *		invoked. The value returned is only meaningful if the querier's result type is
 *		mdns_querier_result_type_response.
 */
bool
mdns_querier_response_is_fabricated(mdns_querier_t querier);

/*!
 *	@brief
 *		Returns the fatal error encountered by a querier.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		This function should only be called from the result handler or after the result handler has been
 *		invoked. The error returned is only meaningful if the querier's result type is
 *		mdns_querier_result_type_error.
 */
OSStatus
mdns_querier_get_error(mdns_querier_t querier);

/*!
 *	@brief
 *		Gets the DNSSEC OK bit of the querier.
 *
 *	@param querier
 *		The querier.
 */
bool
mdns_querier_get_dnssec_ok(mdns_querier_t querier);

OS_CLOSED_ENUM(mdns_query_over_tcp_reason, int,
	mdns_query_over_tcp_reason_null					= 0,
	mdns_query_over_tcp_reason_truncation			= 1,
	mdns_query_over_tcp_reason_got_suspicious_reply	= 2,
	mdns_query_over_tcp_reason_in_suspicious_mode	= 3
);

/*!
 *	@brief
 *		If a querier uses a DNS53 resolver and at some point switched over to TCP to send its query, then this
 *		function returns the reason for doing so.
 *
 *	@param querier
 *		The querier.
 *
 *	@result
 *		If the querier didn't use a DNS53 resolver or used UDP exclusively, then the return value is
 *		mdns_query_over_tcp_reason_null. Otherwise, one of the other mdns_query_over_tcp_reason_t enum values.
 *
 *	@discussion
 *		This function should only be called from the result handler or after the result handler has been
 *		invoked.
 */
mdns_query_over_tcp_reason_t
mdns_querier_get_over_tcp_reason(mdns_querier_t querier);

/*!
 *	@brief
 *		Determines whether a querier has been configured to query for a DNS resource record of a given name,
 *		type, and class.
 *
 *	@param querier
 *		The querier.
 *
 *	@param qname
 *		A domain name as a sequence of domain labels.
 *
 *	@param qtype
 *		A DNS resource record type.
 *
 *	@param qclass
 *		A DNS resource record class.
 *
 *	@result
 *		Returns true if the querier was configured to query for a DNS resource record of the given name, type,
 *		and class. Otherwise, false.
 */
bool
mdns_querier_match(mdns_querier_t querier, const uint8_t *qname, int qtype, int qclass);

/*!
 *	@brief
 *		Determines whether or not a querier has concluded.
 *
 *	@param querier
 *		The querier.
 *
 *	@result
 *		Returns true if the querier has concluded. Otherwise, false.
 *
 *	@discussion
 *		Before the result handler specified by mdns_querier_set_result_handler() has been invoked, this
 *		function should only be called from the dispatch queue specified by mdns_querier_set_queue().
 */
bool
mdns_querier_has_concluded(mdns_querier_t querier);

/*!
 *	@brief
 *		Returns a querier's user-defined ID.
 *
 *	@param querier
 *		The querier.
 *
 *	@discussion
 *		The value returned is the last value set with mdns_querier_set_user_id() before activation.
 */
uint32_t
mdns_querier_get_user_id(mdns_querier_t querier);

__END_DECLS

#define mdns_querier_forget(X)	mdns_forget_with_invalidation(X, querier)
#define mdns_resolver_forget(X)	mdns_forget_with_invalidation(X, resolver)

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_RESOLVER_H__
