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

#include "mdns_internal.h"
#include "mdns_resolver.h"

#include "mdns_helpers.h"
#include "mdns_message.h"
#include "mdns_objects.h"
#include "mdns_symptoms.h"

#include "DNSMessage.h"
#include "HTTPUtilities.h"
#include <CFNetwork/CFNetworkErrors.h>
#include <CoreUtils/CoreUtils.h>
#include <ne_session.h>
#include <stdatomic.h>

//======================================================================================================================
// MARK: - Resolver Kind Definition

struct mdns_resolver_s {
	struct mdns_object_s			base;						// Object base.
	mdns_server_t					server_list;				// Dynamic list of servers that implement DNS service.
	mdns_querier_t					querier_list;				// List of active queriers.
	nw_interface_t					interface;					// If non-NULL, interface to use for network traffic.
	CFMutableArrayRef				server_array;				// Array of servers that implement DNS service.
	char *							interface_log_str;			// Logging string for network interface.
	dispatch_queue_t				user_queue;					// User's event queue.
	mdns_resolver_event_handler_t	event_handler;				// User's event handler.
	uint64_t						suspicious_mode_expiry;		// When suspicious mode expires in ticks.
	dispatch_source_t				probe_timer;				// Periodic timer for restarting probe querier.
	mdns_querier_t					probe_querier;				// Querier to detect when DNS service is usable again.
	uint32_t						probe_querier_id;			// ID number of current probe querier.
	uint32_t						initial_dgram_rtx_ms;		// Initial datagram retransmission interval in ms.
	bool							report_symptoms;			// True if this resolver should report symptoms.
	bool							squash_cnames;				// True if this resolver should squash CNAMEs.
	bool							suspicious_mode;			// True if currently in suspicious mode.
	bool							activated;					// True if resolver has been activated.
	bool							invalidated;				// True if resolver has bee invalidated.
	bool							user_activated;				// True if user called activate method.
	bool							force_no_stream_sharing;	// True to force queriers to not share stream sessions.
	bool							cannot_connect;				// True if all usable servers have connection problems.
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	unsigned int					pqw_threshold;				// Threshold value for problematic QTYPE workaround. [1]
#endif
};

// Notes:
// 1. If a server don't send prompt responses to queries for problematic QTYPEs (SVCB and HTTPS), then queries for
//    such QTYPEs will no longer be sent to that server as a workaround. Instead, a NotImp response message will be
//    fabricated. If the threshold value is zero, the workaround never goes into effect. If the threshold value is
//    greater than zero, then the value specifies the number of unique QNAME queries that must go without a prompt
//    response before the workaround goes into effect.

MDNS_OBJECT_SUBKIND_DEFINE_ABSTRACT(resolver);

typedef union {
	MDNS_UNION_MEMBER(resolver);
	MDNS_UNION_MEMBER(normal_resolver);
	MDNS_UNION_MEMBER(tcp_resolver);
	MDNS_UNION_MEMBER(tls_resolver);
	MDNS_UNION_MEMBER(https_resolver);
} mdns_any_resolver_t __attribute__((__transparent_union__));

typedef OSStatus
(*mdns_resolver_set_provider_name_f)(mdns_any_resolver_t resolver, const char *provider_name);

typedef void
(*mdns_resolver_set_port_f)(mdns_any_resolver_t resolver, uint16_t port);

typedef OSStatus
(*mdns_resolver_set_url_path_f)(mdns_any_resolver_t resolver, const char *url_path);

typedef nw_parameters_t
(*mdns_resolver_get_datagram_params_f)(mdns_any_resolver_t resolver, OSStatus *out_error);

typedef nw_parameters_t
(*mdns_resolver_get_stream_params_f)(mdns_any_resolver_t resolver, OSStatus *out_error);

typedef nw_endpoint_t
(*mdns_resolver_create_hostname_endpoint_f)(mdns_any_resolver_t resolver);

typedef const struct mdns_resolver_kind_s *	mdns_resolver_kind_t;
struct mdns_resolver_kind_s {
	struct mdns_kind_s							base;
	const char *								name;
	mdns_resolver_set_provider_name_f			set_provider_name;
	mdns_resolver_set_port_f					set_port;
	mdns_resolver_set_url_path_f				set_url_path;
	mdns_resolver_get_datagram_params_f			get_datagram_params;
	mdns_resolver_get_stream_params_f			get_stream_params;
	mdns_resolver_create_hostname_endpoint_f	create_hostname_endpoint;
	const char *								datagram_protocol_str;
	const char *								bytestream_protocol_str;
	mdns_resolver_type_t						type;
	uint16_t									default_port;
	bool										stream_only;
	bool										needs_edns0_padding;
	bool										needs_zero_ids;
	bool										suspicious_reply_defense;
	bool										no_stream_session_sharing;
};

#define MDNS_RESOLVER_SUBKIND_DECLARE(NAME)	MDNS_DECL_SUBKIND(NAME ## _resolver, resolver)
#define MDNS_RESOLVER_SUBKIND_DEFINE(NAME, ...)															\
	static void																							\
	_mdns_ ## NAME ## _resolver_finalize(mdns_ ## NAME ## _resolver_t resolver);						\
																										\
	static const struct mdns_resolver_kind_s _mdns_ ## NAME ## _resolver_kind = {						\
		.base = {																						\
			.superkind	= &_mdns_resolver_kind,															\
			.name		= "mdns_" # NAME "_resolver",													\
			.finalize	= _mdns_ ## NAME ## _resolver_finalize											\
		},																								\
		.name = # NAME "_resolver",																		\
		.type = mdns_resolver_type_ ## NAME,															\
		__VA_ARGS__																						\
	};																									\
																										\
	static mdns_resolver_t																				\
	_mdns_ ## NAME ## _resolver_alloc(void)																\
	{																									\
		mdns_resolver_t obj = mdns_resolver_object_alloc(sizeof(struct mdns_ ## NAME ## _resolver_s));	\
		require_quiet(obj, exit);																		\
																										\
		const mdns_object_t object = (mdns_object_t)obj;												\
		object->kind = &_mdns_ ## NAME ## _resolver_kind.base;											\
																										\
	exit:																								\
		return obj;																						\
	}																									\
	MDNS_BASE_CHECK(NAME ## _resolver, resolver)

#define MDNS_RESOLVER_SERVER_COUNT_MAX	32

//======================================================================================================================
// MARK: - Normal Resolver Kind Definition

// As recommended by libnetwork team, use sockets for UDP.
#if !defined(MDNS_USE_NW_CONNECTION_FOR_UDP_INSTEAD_OF_SOCKETS)
	#define MDNS_USE_NW_CONNECTION_FOR_UDP_INSTEAD_OF_SOCKETS	0
#endif

MDNS_RESOLVER_SUBKIND_DECLARE(normal);

struct mdns_normal_resolver_s {
	struct mdns_resolver_s	base;		// Resolver object base.
	nw_parameters_t			udp_params;	// UDP parameters.
	nw_parameters_t			tcp_params;	// TCP parameters.
};

static nw_parameters_t
_mdns_normal_resolver_get_datagram_params(mdns_normal_resolver_t resolver, OSStatus *out_error);

static nw_parameters_t
_mdns_normal_resolver_get_stream_params(mdns_normal_resolver_t resolver, OSStatus *out_error);

MDNS_RESOLVER_SUBKIND_DEFINE(normal,
	.get_datagram_params		= _mdns_normal_resolver_get_datagram_params,
	.get_stream_params			= _mdns_normal_resolver_get_stream_params,
	.datagram_protocol_str		= "UDP",
	.bytestream_protocol_str	= "TCP",
	.default_port				= 53,	// See <https://tools.ietf.org/html/rfc1035#section-4.2>.
	.suspicious_reply_defense	= true
);

//======================================================================================================================
// MARK: - TCP-Only Resolver Kind Definition

MDNS_RESOLVER_SUBKIND_DECLARE(tcp);

struct mdns_tcp_resolver_s {
	struct mdns_resolver_s	base;	// Resolver object base.
	nw_parameters_t			params;	// TCP parameters.
};

static nw_parameters_t
_mdns_tcp_resolver_get_stream_params(mdns_tcp_resolver_t resolver, OSStatus *out_error);

MDNS_RESOLVER_SUBKIND_DEFINE(tcp,
	.get_stream_params			= _mdns_tcp_resolver_get_stream_params,
	.bytestream_protocol_str	= "TCP",
	.default_port				= 53,	// See <https://tools.ietf.org/html/rfc1035#section-4.2.2>.
	.stream_only				= true,
);

//======================================================================================================================
// MARK: - TLS Resolver Kind Definition

MDNS_RESOLVER_SUBKIND_DECLARE(tls);

struct mdns_tls_resolver_s {
	struct mdns_resolver_s	base;		// Resolver object base.
	char *					hostname;	// Hostname to use for TLS.
	nw_parameters_t			params;		// TLS parameters.
	uint16_t				port;		// Port to use if no server addresses are specified.
};

static OSStatus
_mdns_tls_resolver_set_provider_name(mdns_tls_resolver_t resolver, const char *provider_name);

static void
_mdns_tls_resolver_set_port(mdns_tls_resolver_t resolver, uint16_t port);

static nw_parameters_t
_mdns_tls_resolver_get_stream_params(mdns_tls_resolver_t resolver, OSStatus *out_error);

static nw_endpoint_t
_mdns_tls_resolver_create_hostname_endpoint(mdns_tls_resolver_t resolver);

MDNS_RESOLVER_SUBKIND_DEFINE(tls,
	.set_provider_name			= _mdns_tls_resolver_set_provider_name,
	.set_port					= _mdns_tls_resolver_set_port,
	.get_stream_params			= _mdns_tls_resolver_get_stream_params,
	.create_hostname_endpoint	= _mdns_tls_resolver_create_hostname_endpoint,
	.bytestream_protocol_str	= "TLS",
	.default_port				= 853,	// See <https://tools.ietf.org/html/rfc7858#section-3.1>.
	.stream_only				= true,
	.needs_edns0_padding		= true
);

//======================================================================================================================
// MARK: - HTTPS Resolver Kind Definition

MDNS_RESOLVER_SUBKIND_DECLARE(https);

struct mdns_https_resolver_s {
	struct mdns_resolver_s	base;				// Resolver object base.
	char *					provider_name;		// Hostname to use for HTTPS.
	char *					url_path;			// Path to use for HTTPS queries.
	nw_parameters_t			params;				// HTTPS parameters.
	uint16_t				port;				// Port to use if no server addresses are specified.
};

static OSStatus
_mdns_https_resolver_set_provider_name(mdns_https_resolver_t resolver, const char *provider_name);

static void
_mdns_https_resolver_set_port(mdns_https_resolver_t resolver, uint16_t port);

static OSStatus
_mdns_https_resolver_set_url_path(mdns_https_resolver_t resolver, const char *url_path);

static nw_parameters_t
_mdns_https_resolver_get_stream_params(mdns_https_resolver_t resolver, OSStatus *out_error);

static nw_endpoint_t
_mdns_https_resolver_create_hostname_endpoint(mdns_https_resolver_t resolver);

MDNS_RESOLVER_SUBKIND_DEFINE(https,
	.set_provider_name			= _mdns_https_resolver_set_provider_name,
	.set_port					= _mdns_https_resolver_set_port,
	.set_url_path				= _mdns_https_resolver_set_url_path,
	.get_stream_params			= _mdns_https_resolver_get_stream_params,
	.create_hostname_endpoint	= _mdns_https_resolver_create_hostname_endpoint,
	.bytestream_protocol_str	= "HTTPS",
	.default_port				= 443,	// See <https://tools.ietf.org/html/rfc8484#section-8.1>.
	.stream_only				= true,
	.needs_edns0_padding		= true,
	.needs_zero_ids				= true,	// See <https://tools.ietf.org/html/rfc8484#section-4.1>.
	.no_stream_session_sharing	= true	// For DoH, each mdns_session uses an NSURLSessionDataTask.
);

//======================================================================================================================
// MARK: - Server Kind Definition

#define MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND	1

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
typedef struct pqw_qname_item_s pqw_qname_item_t;

struct pqw_qname_item_s {
	pqw_qname_item_t *	next;	// Next item in list.
	uint8_t *			qname;	// QNAME.
};

typedef struct {
	pqw_qname_item_t *	qname_list;		// List of unique QNAMEs whose problematic query didn't get a prompt response.
	unsigned int		qname_count;	// Current number QNAMEs on list. [1]
	unsigned int		threshold;		// The maximum number of unique QNAMEs to allow on list.
} pqw_info_t;

// Notes:
// 1. When the threshold has been reached, problematic QTYPEs will no longer be sent to the server that owns this
//    data structure.

#endif

struct mdns_server_s {
	struct mdns_object_s	base;						// Object base.
	mdns_server_t			next;						// Next server in list.
	mdns_session_t			shared_stream_session;		// Shared byte-stream connection to server.
	nw_endpoint_t			endpoint;					// Endpoint that represents server's IP address and port.
	nw_path_evaluator_t		path_evaluator;				// Path evaluator for monitoring server's reachability.
	uint64_t				penalty_expiry;				// If currently penalized, time when penalization will end.
	uint64_t				latest_session_start_ticks;	// Latest start time, in ticks, of sessions that got a response.
	uint64_t				last_stream_error_ticks;	// When stream_error_count was last incremented. [1]
	uint32_t				stream_error_count;			// Numer of errors experienced by bytestream sessions. [2,3]
	unsigned int			rank;						// Ordinal rank number of this server.
	bool					usable;						// True if the server is currently potentially usable.
	bool					penalized;					// True if the server is currently penalized.
	bool					stream_lateness;			// True if a bytestream sessions are experiencing lateness.
	bool					reported_unresponsiveness;	// True if an unresponsiveness symptom has been reported.
	bool					uses_default_port;			// True if the endpoint's port is a default port.
#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
	bool					mixes_up_responses;			// True if server mixes up A/AAAA and HTTPS/SVCB responses.
#endif
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	bool					responds_to_problematics;	// True if server responds to queries with problematic QTYPEs.
	uint16_t				test_query_qtype;			// The QTYPE that should be used for a test query.
	pqw_info_t *			pqw_info;					// Information about problematic QTYPEs.
#endif
};

// Notes:
// 1. last_stream_error_ticks is used to track bursts of errors, which can occur if multiple outstanding queriers
//    experience the same underlying error at once.
// 2. stream_error_count is incremented whenever a bystream session experiences an error, so long as
//    stream_error_count was last incremented at least one second ago.
// 3. stream_error_count is reset to zero whenever an acceptable response is received.

MDNS_OBJECT_SUBKIND_DEFINE(server);

// MDNS_SERVER_STREAM_ERROR_COUNT_THRESHOLD is the number of consecutive errors, as tracked by stream_error_count,
// that have to be experienced by bytestream sessions to a server, before the server is considered to be
// problematic (in the absence of bytestream lateness). In the absence of bytestream lateness, when the threshold
// is reached, a cannot-connect event is generated, so value should be greater than one to not overreact to the
// case where there's a one-off error and the the subsequent retry is error-free. Three consecutive errors seems
// small enough to be reactive to longer-term problems, such as a firewall that blocks connections using TCP
// resets, or a bad server certificate, but not too sensitive to transient errors.
#define MDNS_SERVER_STREAM_ERROR_COUNT_THRESHOLD	3

// MDNS_SERVER_STREAM_ERROR_BURST_WINDOW_SECS is the width of a bytestream session error burst window in seconds.
#define MDNS_SERVER_STREAM_ERROR_BURST_WINDOW_SECS	1

//======================================================================================================================
// MARK: - Delegation

OS_CLOSED_ENUM(mdns_delegation_type, int,
	mdns_delegation_type_none	= 0,	// No delegation.
	mdns_delegation_type_pid	= 1,	// Delegation by PID.
	mdns_delegation_type_uuid	= 2		// Delegation by UUID.
);

typedef struct {
	mdns_delegation_type_t	type;	// Type of delegation.
	union {
		pid_t				pid;	// Delegator's PID if type is mdns_delegation_type_pid.
		uuid_t				uuid;	// Delegator's UUID if type is mdns_delegation_type_uuid.
	} ident;						// Delegator's identifier.
} mdns_delegation_t;

//======================================================================================================================
// MARK: - Session Kind Definition

OS_CLOSED_ENUM(mdns_session_event, int,
	mdns_session_event_null				= 0,
	mdns_session_event_ready			= 1,
	mdns_session_event_lateness_warning	= 2,
	mdns_session_event_terminated		= 3
);

typedef void
(*mdns_session_handle_event_f)(mdns_session_t session, mdns_session_event_t event, OSStatus error, void *context);

typedef void
(*mdns_session_receive_f)(mdns_session_t session, dispatch_data_t response, void *context);

typedef void
(*mdns_session_finalize_context_f)(void *context);

typedef struct {
	mdns_session_handle_event_f		handle_event;
	mdns_session_receive_f			receive;
	mdns_session_finalize_context_f	finalize_context;
} mdns_session_callbacks_t;

OS_CLOSED_ENUM(mdns_session_state, int,
	mdns_session_state_nascent		= 0,
	mdns_session_state_activated	= 1,
	mdns_session_state_failed		= 2,
	mdns_session_state_done			= 3
);

struct mdns_session_s {
	struct mdns_object_s				base;				// Object base.
	mdns_session_t						next;				// Next session in list.
	mdns_server_t						server;				// Server associated with this session.
	dispatch_source_t					lateness_timer;		// Lateness timer.
	void *								context;			// User object's context for callbacks.
	const mdns_session_callbacks_t *	callbacks;			// User object's callbacks.
	uint64_t							start_ticks;		// Time, in ticks, when the session was activated.
	uint64_t							last_send_ticks;	// Time, in ticks, of the last send.
	mdns_session_state_t				state;				// Current state.
	uint32_t							lateness_time_ms;	// Time in ms after activation before lateness timer fires.
	uint32_t							receive_count;		// Number of messages received.
	bool								is_stream;			// True if session is bytestream instead of datagram.
	bool								is_ready;			// True if session is ready for sending (while activated).
};

MDNS_OBJECT_SUBKIND_DEFINE_ABSTRACT(session);

typedef union {
	MDNS_UNION_MEMBER(session);
	MDNS_UNION_MEMBER(connection_session);
	MDNS_UNION_MEMBER(udp_socket_session);
	MDNS_UNION_MEMBER(url_session);
} mdns_any_session_t __attribute__((__transparent_union__));

typedef OSStatus
(*mdns_session_initialize_f)(mdns_any_session_t session, mdns_resolver_t resolver, bool need_bytestream,
	const mdns_delegation_t *delegation, const uint8_t *qname);

typedef OSStatus
(*mdns_session_activate_f)(mdns_any_session_t session);

typedef void
(*mdns_session_invalidate_f)(mdns_any_session_t session);

typedef bool
(*mdns_session_is_ready_f)(mdns_any_session_t session);

typedef void
(*mdns_session_send_f)(mdns_any_session_t session, dispatch_data_t message, uint16_t qtype);

typedef bool
(*mdns_session_is_bytestream_f)(mdns_any_session_t session);

typedef const struct mdns_session_kind_s *	mdns_session_kind_t;
struct mdns_session_kind_s {
	struct mdns_kind_s				base;
	const char *					name;
	mdns_session_initialize_f		initialize;
	mdns_session_activate_f			activate;
	mdns_session_invalidate_f		invalidate;
	mdns_session_send_f				send;
	mdns_session_is_bytestream_f	is_bytestream_check;
	mdns_session_is_ready_f			is_ready_check;
	bool							is_bytestream;
	bool							is_always_ready;
};

#define MDNS_SESSION_SUBKIND_DECLARE(NAME)	MDNS_DECL_SUBKIND(NAME ## _session, session)
#define MDNS_SESSION_SUBKIND_DEFINE(NAME, ...)																		\
	static void																										\
	_mdns_ ## NAME ## _session_finalize(mdns_ ## NAME ## _session_t session);										\
																													\
	static OSStatus																									\
	_mdns_ ## NAME ## _session_initialize(mdns_ ## NAME ## _session_t session, mdns_resolver_t resolver,			\
		bool need_bytestream, const mdns_delegation_t *delegation, const uint8_t *qname);							\
																													\
	static OSStatus																									\
	_mdns_ ## NAME ## _session_activate(mdns_ ## NAME ## _session_t session);										\
																													\
	static void																										\
	_mdns_ ## NAME ## _session_invalidate(mdns_ ## NAME ## _session_t session);										\
																													\
	static void																										\
	_mdns_ ## NAME ## _session_send(mdns_ ## NAME ## _session_t session, dispatch_data_t message, uint16_t qtype);	\
																													\
	static const struct mdns_session_kind_s _mdns_ ## NAME ## _session_kind = {										\
		.base = {																									\
			.superkind	= &_mdns_session_kind,																		\
			.name		= "mdns_" # NAME "_session",																\
			.finalize	= _mdns_ ## NAME ## _session_finalize,														\
		},																											\
		.name			= # NAME "_session",																		\
		.initialize		= _mdns_ ## NAME ## _session_initialize,													\
		.activate		= _mdns_ ## NAME ## _session_activate,														\
		.invalidate		= _mdns_ ## NAME ## _session_invalidate,													\
		.send			= _mdns_ ## NAME ## _session_send,															\
		__VA_ARGS__																									\
	};																												\
																													\
	static mdns_session_t																							\
	_mdns_ ## NAME ## _session_alloc(void)																			\
	{																												\
		mdns_session_t obj = mdns_session_object_alloc(sizeof(struct mdns_ ## NAME ## _session_s));					\
		require_quiet(obj, exit);																					\
																													\
		const mdns_object_t object = (mdns_object_t)obj;															\
		object->kind = &_mdns_ ## NAME ## _session_kind.base;														\
																													\
	exit:																											\
		return obj;																									\
	}																												\
	MDNS_BASE_CHECK(NAME ## _session, session)

OS_CLOSED_ENUM(mdns_session_type, int,
	mdns_session_type_null			= 0,
	mdns_session_type_connection	= 1,
	mdns_session_type_udp_socket	= 2,
	mdns_session_type_url			= 3
);

//======================================================================================================================
// MARK: - Connection Session Kind Definition

MDNS_SESSION_SUBKIND_DECLARE(connection);

struct mdns_connection_session_s {
	struct mdns_session_s	base;			// Session object base.
	nw_connection_t			connection;		// Underlying connection.
	bool					is_bytestream;	// True if the session is bytestream as opposed to datagram.
};

static bool
_mdns_connection_session_is_bytestream(mdns_connection_session_t session);

MDNS_SESSION_SUBKIND_DEFINE(connection,
	.is_bytestream_check = _mdns_connection_session_is_bytestream
);

//======================================================================================================================
// MARK: - UDP Socket Session Kind Definition

// There are currently some performance problems with using connected UDP sockets and flow diverted traffic.
// When connecting a UDP socket to a flow diverted destination, the connect() call will return EINPROGRESS.
// The problem is that there's ambiguity as to when the socket is actually connected and ready for sending.
#if !defined(MDNS_USE_CONNECTED_UDP_SOCKETS)
	#define MDNS_USE_CONNECTED_UDP_SOCKETS	0
#endif

MDNS_SESSION_SUBKIND_DECLARE(udp_socket);

struct mdns_udp_socket_session_s {
	struct mdns_session_s	base;					// Session object base.
	dispatch_source_t		read_source;			// GCD read source for UDP socket.
	int						sock;					// Underlying UDP socket.
#if MDNS_USE_CONNECTED_UDP_SOCKETS
	dispatch_source_t		write_source;			// GCD write source for UDP socket. For delayed connections.
	bool					connected;				// True if the UDP socket is connected.
	bool					read_source_suspended;	// True if the GCD read source is suspended;
#else
	sockaddr_ip				server_addr;			// sockaddr containing address of server.
	socklen_t				server_addr_len;		// Length of server sockaddr.
#endif
};

#if MDNS_USE_CONNECTED_UDP_SOCKETS
static bool
_mdns_udp_socket_session_is_ready(mdns_udp_socket_session_t session);
#endif

#if MDNS_USE_CONNECTED_UDP_SOCKETS
MDNS_SESSION_SUBKIND_DEFINE(udp_socket,
	.is_bytestream		= false,
	.is_ready_check		= _mdns_udp_socket_session_is_ready
);
#else
MDNS_SESSION_SUBKIND_DEFINE(udp_socket,
	.is_bytestream		= false,
	.is_always_ready	= true
);
#endif

//======================================================================================================================
// MARK: - URL Session Kind Definition

MDNS_SESSION_SUBKIND_DECLARE(url);

struct mdns_url_session_s {
	struct mdns_session_s	base;			// Session object base.
	nw_endpoint_t			url_endpoint;	// Endpoint for URL session.
	void *					http_task;		// HTTP task object.
};

MDNS_SESSION_SUBKIND_DEFINE(url,
	.is_bytestream		= true,
	.is_always_ready	= true
);

//======================================================================================================================
// MARK: - Querier Kind Definition

struct mdns_querier_s {
	struct mdns_object_s			base;					// Object base.
	mdns_querier_t					next;					// Next querier in list.
	mdns_resolver_t					resolver;				// Resolver associated with querier.
	mdns_server_t					current_server;			// Current server being used to send datagram queries.
	dispatch_queue_t				user_queue;				// User's queue for invoking response handler.
	mdns_querier_result_handler_t	handler;				// User's result handler.
	mdns_query_message_t			query;					// Query message.
	dispatch_source_t				rtx_timer;				// Timer for scheduling datagram query retransmissions.
	mdns_session_t					dgram_session_list;		// List of datagram sessions.
	mdns_session_t					stream_session_list;	// List of bytestream sessions.
	dispatch_source_t				timeout_timer;			// Time limit timer.
	char *							log_label;				// User-specified UTF-8 prefix label to use for logging.
	mdns_message_t					response;				// Final DNS response.
	mdns_message_t					bad_rcode_response;		// DNS response received with a bad RCODE.
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	mdns_query_message_t			test_query;				// Test query to send while sending problematic QTYPE query.
	uint32_t						test_send_count;		// Total number of test queries sent.
	uint32_t						test_query_resp_bitmap;	// Bitmap for keeping track of test query responses.
#endif
	unsigned int					unanswered_query_count;	// Number of timed out dgram queries sent to current_server.
	uint32_t						rtx_interval_ms;		// Current retransmit interval for datagram queries.
	_Atomic(uint32_t)				send_count;				// Total number of queries sent.
	mdns_query_over_tcp_reason_t	over_tcp_reason;		// Reason for using TCP instead of UDP. (For DNS53 only.)
	uint32_t						will_send_bitmap;		// Bitmap for keeping track of servers that we will send to.
	uint32_t						did_send_bitmap;		// Bitmap for keeping track of servers that we did sent to.
	int32_t							time_limit_ms;			// Time limit in milliseconds.
	uint32_t						bad_rcode_bitmap;		// Bitmap for keeping track of servers that sent bad RCODEs.
	int								bad_rcode;				// RCODE of bad_rcode_response.
	uint32_t						user_id;				// User-defined identifier.
	mdns_querier_result_type_t		result_type;			// Type of result the querier concluded with.
	OSStatus						error;					// The fatal error that caused the querier to conclude.
	mdns_delegation_t				delegation;				// Querier's delegation information.
	bool							use_stream;				// True if using bytestream (instead of datagram) session.
	bool							use_shared_stream;		// True if the querier is uses a shared bytestream.
	bool							activated;				// True if the querier has been activated.
	bool							concluded;				// True if the querier has concluded.
	bool							user_activated;			// True if user called activate method.
	bool							response_is_fabricated;	// True if the response is fabricated.
};

check_compile_time((sizeof_field(struct mdns_querier_s, will_send_bitmap) * 8) <= MDNS_RESOLVER_SERVER_COUNT_MAX);
check_compile_time((sizeof_field(struct mdns_querier_s, did_send_bitmap)  * 8) <= MDNS_RESOLVER_SERVER_COUNT_MAX);
check_compile_time((sizeof_field(struct mdns_querier_s, bad_rcode_bitmap) * 8) <= MDNS_RESOLVER_SERVER_COUNT_MAX);
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
check_compile_time((sizeof_field(struct mdns_querier_s, test_query_resp_bitmap) * 8) <= MDNS_RESOLVER_SERVER_COUNT_MAX);
#endif

MDNS_OBJECT_SUBKIND_DEFINE(querier);

//======================================================================================================================
// MARK: - Local Prototypes

static dispatch_queue_t
_mdns_resolver_queue(void);

static bool
_mdns_message_is_query_response_ignoring_id(const uint8_t *msg_ptr, size_t msg_len, mdns_query_message_t query,
	uint16_t *out_id);

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
static bool
_mdns_message_is_query_response_ignoring_qtype(mdns_message_t msg, mdns_query_message_t query, uint16_t *out_qtype);
#endif

static bool
_mdns_message_is_query_response_ex(const uint8_t *msg_ptr, size_t msg_len, mdns_query_message_t query,
	uint16_t *out_id, uint16_t *out_qtype, bool ignore_qnames);

static uint64_t
_mdns_ticks_per_second(void);

static bool
_mdns_path_to_server_is_usable(nw_path_t path, bool encrypted_resolver);

static uint32_t
_mdns_rank_to_bitmask(const unsigned int rank);

static const char *
mdns_session_event_to_string(mdns_session_event_t event);

static int64_t
_mdns_ticks_diff(uint64_t t1, uint64_t t2);

static uint64_t
_mdns_ticks_to_whole_seconds(uint64_t ticks);

static uint64_t
_mdns_ticks_to_fractional_milliseconds(uint64_t ticks);

static dispatch_source_t
_mdns_resolver_create_oneshot_timer(uint32_t time_ms, unsigned int leeway_percent_numerator);

static void
_mdns_querier_activate_if_ready(mdns_querier_t querier);

static void
_mdns_querier_initiate_send(mdns_querier_t querier);

static void
_mdns_querier_start(mdns_querier_t querier);

static void
_mdns_querier_send_query(mdns_querier_t querier, mdns_session_t session);

static const char *
_mdns_querier_get_log_label(mdns_querier_t querier);

static OSStatus
_mdns_querier_reset_time_limit(mdns_querier_t querier);

static void
_mdns_querier_handle_no_response(mdns_querier_t querier);

static void
_mdns_querier_set_current_server(mdns_querier_t querier, mdns_server_t server);

static mdns_server_t
_mdns_querier_get_eligible_server(mdns_querier_t querier);

static mdns_server_t
_mdns_querier_get_unpenalized_eligible_server(mdns_querier_t querier);

static void
_mdns_querier_handle_stream_error(mdns_querier_t querier, mdns_server_t server);

static void
_mdns_querier_handle_bad_rcode(mdns_querier_t querier, mdns_message_t response, int rcode, mdns_server_t server);

static const uint8_t *
_mdns_querier_get_response_ptr_safe(mdns_querier_t querier);

static size_t
_mdns_querier_get_response_length_safe(mdns_querier_t querier);

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static void
_mdns_querier_set_test_query_got_response(mdns_querier_t querier, mdns_server_t server, bool got_response);

static bool
_mdns_querier_test_query_got_response(mdns_querier_t querier, mdns_server_t server);
#endif

static bool
_mdns_server_has_stream_problems(mdns_server_t server);

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static bool
_mdns_server_supports_qtype(mdns_server_t server, int qtype);

static void
_mdns_server_handle_lack_of_response(mdns_server_t server, mdns_querier_t querier);

static uint16_t
_mdns_server_get_test_query_qtype(mdns_server_t server);
#endif

static bool
_mdns_session_is_ready(mdns_session_t session);

static void
_mdns_session_send(mdns_session_t session, dispatch_data_t message, uint16_t qtype);

static bool
_mdns_session_is_bytestream(mdns_session_t session);

static void
_mdns_session_invalidate(mdns_session_t session);
#define mdns_session_forget(X)	ForgetCustomEx(X, _mdns_session_invalidate, mdns_release)

static void
_mdns_session_set_callbacks(mdns_session_t session, const mdns_session_callbacks_t *callbacks, void *context);

static void
_mdns_session_set_lateness_time(mdns_session_t session, uint32_t time_ms);

static OSStatus
_mdns_session_initialize(mdns_session_t session, mdns_resolver_t resolver, bool need_bytestream,
	const mdns_delegation_t *delegation, const uint8_t *qname);

static void
_mdns_session_activate(mdns_session_t session);

static nw_endpoint_t
_mdns_common_session_get_server_endpoint(mdns_any_session_t session);

static void
_mdns_common_session_invoke_ready_event_handler(mdns_any_session_t session);

static void
_mdns_common_session_invoke_receive(mdns_any_session_t session, dispatch_data_t msg);

static void
_mdns_common_session_terminate(mdns_any_session_t session, OSStatus error);

static void
_mdns_common_session_terminate_async(mdns_any_session_t session, OSStatus error);

static mdns_resolver_kind_t
_mdns_resolver_get_kind(mdns_resolver_t resolver);

static const char *
_mdns_resolver_get_bytestream_protocol_string(mdns_resolver_t resolver);

static const char *
_mdns_resolver_get_datagram_protocol_string(mdns_resolver_t resolver);

static uint16_t
_mdns_resolver_get_default_port(mdns_any_resolver_t resolver);

static bool
_mdns_resolver_is_stream_only(mdns_resolver_t resolver);

static bool
_mdns_resolver_needs_edns0_padding(mdns_resolver_t resolver);

static bool
_mdns_resolver_needs_zero_ids(mdns_resolver_t resolver);

static bool
_mdns_resolver_needs_suspicious_reply_defense(mdns_resolver_t resolver);

static bool
_mdns_resolver_no_stream_session_sharing(mdns_resolver_t resolver);

static OSStatus
_mdns_resolver_add_server_by_endpoint(mdns_resolver_t resolver, nw_endpoint_t endpoint);

static void
_mdns_resolver_activate_internal(mdns_resolver_t resolver);

static nw_parameters_t
_mdns_resolver_get_stream_params(mdns_resolver_t resolver, OSStatus *out_error);

static nw_endpoint_t
_mdns_resolver_create_hostname_endpoint(mdns_resolver_t resolver);

static nw_parameters_t
_mdns_resolver_get_datagram_params(mdns_resolver_t resolver, OSStatus *out_error);

static void
_mdns_resolver_deregister_querier(mdns_resolver_t resolver, mdns_querier_t querier);

static void
_mdns_resolver_register_querier(mdns_resolver_t resolver, mdns_querier_t querier, bool force_stream_mode);

static void
_mdns_resolver_session_handle_event(mdns_session_t session, mdns_session_event_t event, OSStatus error, void *context);

static void
_mdns_resolver_session_receive(mdns_session_t session, dispatch_data_t response, void *context);

static mdns_session_t
_mdns_resolver_create_session(mdns_resolver_t resolver, mdns_server_t server, bool need_bytestream,
	const mdns_delegation_t *delegation, const uint8_t *domain, OSStatus *out_error);

static const char *
_mdns_resolver_get_protocol_log_string(mdns_resolver_t resolver, bool for_bytestream);

static const char *
_mdns_resolver_get_interface_log_string(mdns_resolver_t resolver);

static mdns_resolver_type_t
_mdns_resolver_get_type(mdns_resolver_t resolver);

static void
_mdns_resolver_log_receive(mdns_resolver_t resolver, mdns_session_t session, mdns_message_t message, bool acceptable,
	const char *log_prefix);

static void
_mdns_resolver_handle_stream_error(mdns_resolver_t resolver, mdns_server_t server, const char *label);

static void
_mdns_resolver_handle_stream_lateness(mdns_resolver_t resolver, mdns_server_t server, uint64_t session_start_ticks,
	const char *label);

static void
_mdns_resolver_handle_stream_response(mdns_resolver_t resolver, mdns_server_t server);

static void
_mdns_resolver_check_for_problematic_servers(mdns_resolver_t resolver);

static bool
_mdns_resolver_has_usable_server_without_connection_problems(mdns_resolver_t resolver);

static void
_mdns_resolver_generate_event(mdns_any_resolver_t resolver, mdns_resolver_event_t event, xpc_object_t info);

static void
_mdns_resolver_generate_connection_event(mdns_resolver_t resolver);

static void
_mdns_resolver_log_server_problems(mdns_resolver_t resolver, mdns_server_t server, const char *label);

static bool
_mdns_resolver_uses_encryption(mdns_resolver_t resolver);

static void
_mdns_resolver_start_serverless_queries(mdns_resolver_t resolver);

static void
_mdns_resolver_start_serverless_queries_async(mdns_resolver_t resolver);

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static bool
_mdns_resolver_use_problematic_qtype_workaround(mdns_resolver_t resolver);
#endif

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
static bool
_mdns_resolver_use_mixed_up_responses_workaround(mdns_resolver_t resolver);
#endif

static bool
_mdns_querier_is_response_acceptable(mdns_querier_t querier, mdns_message_t response, bool *out_truncated,
	bool *out_suspicious, int *out_rcode);

static void
_mdns_querier_conclude(mdns_querier_t querier, mdns_querier_result_type_t result_type);

static void
_mdns_querier_conclude_async(mdns_querier_t querier, mdns_querier_result_type_t result_type);

static void
_mdns_querier_conclude_with_error(mdns_querier_t querier, OSStatus error);

static void
_mdns_querier_conclude_with_error_async(mdns_querier_t querier, OSStatus error);

static void
_mdns_querier_conclude_with_response(mdns_querier_t querier, mdns_message_t response);

static void
_mdns_querier_conclude_with_response_async(mdns_querier_t querier, mdns_message_t response, bool fabricated);

static void
_mdns_querier_conclude_ex(mdns_querier_t querier, mdns_querier_result_type_t result_type, OSStatus status,
	mdns_message_t response);

static OSStatus
_mdns_add_dns_over_bytestream_framer(nw_parameters_t params);

static nw_parameters_t
_mdns_create_udp_parameters(OSStatus *out_error);

static nw_parameters_t
_mdns_create_tcp_parameters(OSStatus *out_error);

static bool
_mdns_rcode_is_good(const int rcode);

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static bool
_mdns_qtype_is_problematic(int qtype);

static mdns_message_t
_mdns_create_empty_response_for_query(mdns_query_message_t query, int rcode, OSStatus *out_error);
#endif

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static mdns_query_message_t
_mdns_create_simple_test_query(mdns_query_message_t query, uint16_t qtype);

static bool
_mdns_message_is_adequate_test_query_response(mdns_message_t msg, mdns_query_message_t query);

static pqw_info_t *
_pqw_info_create(unsigned int threshold);

static void
_pqw_info_free(pqw_info_t *info);
#define _pqw_info_forget(X)	ForgetCustom(X, _pqw_info_free)

static bool
_pqw_info_threshold_reached(const pqw_info_t *info);

static bool
_pqw_info_can_accept_qname(const pqw_info_t *info, const uint8_t *qname);

static pqw_qname_item_t *
_pqw_qname_item_create(const uint8_t *qname, OSStatus *out_error);

static void
_pqw_qname_item_free(pqw_qname_item_t *item);
#define _pqw_qname_item_forget(X)	ForgetCustom(X, _pqw_qname_item_free)

static void
_pqw_qname_list_free(pqw_qname_item_t *list);
#define _pqw_qname_list_forget(X)	ForgetCustom(X, _pqw_qname_list_free)
#endif

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
typedef bool
(*qtype_test_f)(int qtype);

static bool
_mdns_qtype_is_address_type(int qtype);
#endif

//======================================================================================================================
// MARK: - Internals

MDNS_LOG_CATEGORY_DEFINE(resolver, "resolver");

#define MDNS_RESOLVER_CONNECTION_TIMEOUT_MS	1500

//======================================================================================================================
// MARK: - Resolver Public Methods

mdns_resolver_t
mdns_resolver_create(mdns_resolver_type_t type, uint32_t interface_index, OSStatus *out_error)
{
	mdns_resolver_t resolver = NULL;
	mdns_resolver_t obj;
	OSStatus err;
	switch (type) {
		case mdns_resolver_type_normal:
			obj = _mdns_normal_resolver_alloc();
			require_action_quiet(obj, exit, err = kNoMemoryErr);
			break;

		case mdns_resolver_type_tcp:
			obj = _mdns_tcp_resolver_alloc();
			require_action_quiet(obj, exit, err = kNoMemoryErr);
			break;

		case mdns_resolver_type_tls:
			obj = _mdns_tls_resolver_alloc();
			require_action_quiet(obj, exit, err = kNoMemoryErr);
			break;

		case mdns_resolver_type_https:
			obj = _mdns_https_resolver_alloc();
			require_action_quiet(obj, exit, err = kNoMemoryErr);
			break;

		case mdns_resolver_type_null:
		default:
			obj = NULL;
			err = kTypeErr;
			goto exit;
	}
	obj->server_array = CFArrayCreateMutable(NULL, 0, &mdns_cfarray_callbacks);
	require_action_quiet(obj->server_array, exit, err = kNoResourcesErr);

	if (interface_index != 0) {
		obj->interface = nw_interface_create_with_index(interface_index);
		require_action_quiet(obj->interface, exit, err = kUnknownErr);
	}
	resolver	= obj;
	obj			= NULL;
	err			= kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mdns_release_null_safe(obj);
	return resolver;
}

//======================================================================================================================

void
mdns_resolver_set_queue(const mdns_resolver_t me, const dispatch_queue_t queue)
{
	if (!me->user_activated) {
		dispatch_retain(queue);
		dispatch_release_null_safe(me->user_queue);
		me->user_queue = queue;
	}
}

//======================================================================================================================

void
mdns_resolver_set_event_handler(const mdns_resolver_t me, const mdns_resolver_event_handler_t handler)
{
	if (!me->user_activated) {
		const mdns_resolver_event_handler_t new_handler = handler ? Block_copy(handler) : NULL;
		if (me->event_handler) {
			Block_release(me->event_handler);
		}
		me->event_handler = new_handler;
	}
}

//======================================================================================================================

OSStatus
mdns_resolver_set_provider_name(mdns_resolver_t me, const char *provider_name)
{
	OSStatus err;
	require_action_quiet(!me->user_activated, exit, err = kAlreadyInitializedErr);

	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	if (kind->set_provider_name) {
		err = kind->set_provider_name(me, provider_name);
	} else {
		err = kNoErr;
	}

exit:
	return err;
}

//======================================================================================================================

void
mdns_resolver_set_port(const mdns_resolver_t me, const uint16_t port)
{
	if (likely(!me->user_activated)) {
		const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
		if (kind->set_port) {
			kind->set_port(me, port);
		}
	}
}

//======================================================================================================================

OSStatus
mdns_resolver_set_url_path(mdns_resolver_t me, const char *url_path)
{
	OSStatus err;
	require_action_quiet(!me->user_activated, exit, err = kAlreadyInitializedErr);

	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	if (kind->set_url_path) {
		err = kind->set_url_path(me, url_path);
	} else {
		err = kNoErr;
	}

exit:
	return err;
}

//======================================================================================================================

void
mdns_resolver_set_squash_cnames(const mdns_resolver_t me, const bool enable)
{
	if (!me->user_activated) {
		me->squash_cnames = enable ? true : false;
	}
}

//======================================================================================================================

void
mdns_resolver_enable_symptom_reporting(const mdns_resolver_t me, const bool enable)
{
	if (!me->user_activated) {
		me->report_symptoms = enable ? true : false;
	}
}

//======================================================================================================================

OSStatus
mdns_resolver_add_server_address(mdns_resolver_t me, mdns_address_t address)
{
	OSStatus err;
	require_action_quiet(!me->user_activated, exit, err = kAlreadyInitializedErr);

	sockaddr_ip sip;
	memset(&sip, 0, sizeof(sip));
	const sockaddr_ip * const addr_sip = (const sockaddr_ip *)mdns_address_get_sockaddr(address);
	const int addr_family = addr_sip->sa.sa_family;
	if (addr_family == AF_INET) {
		sip.v4 = addr_sip->v4;
		if (sip.v4.sin_port == 0) {
			sip.v4.sin_port = htons(_mdns_resolver_get_default_port(me));
		}
	} else if (addr_family == AF_INET6) {
		sip.v6 = addr_sip->v6;
		if (sip.v6.sin6_port == 0) {
			sip.v6.sin6_port = htons(_mdns_resolver_get_default_port(me));
		}
	} else {
		err = kTypeErr;
		goto exit;
	}
	nw_endpoint_t endpoint = nw_endpoint_create_address(&sip.sa);
	require_action_quiet(endpoint, exit, err = kUnknownErr);

	if (me->interface) {
		nw_endpoint_set_interface(endpoint, me->interface);
	}
	err = _mdns_resolver_add_server_by_endpoint(me, endpoint);
	nw_forget(&endpoint);

exit:
	return err;
}

//======================================================================================================================

void
mdns_resolver_set_initial_datagram_retransmission_interval(const mdns_resolver_t me, const uint32_t interval_secs)
{
	if (!me->user_activated) {
		if (interval_secs < (UINT32_MAX / kMillisecondsPerSecond)) {
			me->initial_dgram_rtx_ms = interval_secs * kMillisecondsPerSecond;
		} else {
			me->initial_dgram_rtx_ms = UINT32_MAX;
		}
	}
}

//======================================================================================================================

void
mdns_resolver_disable_connection_reuse(const mdns_resolver_t me, const bool disable)
{
	if (!me->user_activated) {
		me->force_no_stream_sharing = disable ? true : false;
	}
}

//======================================================================================================================

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
#define MDNS_RESOLVER_PQW_THRESHOLD_MAX		100
void
mdns_resolver_enable_problematic_qtype_workaround(const mdns_resolver_t me, const int threshold)
{
	require_return(!me->user_activated);
	if (threshold > 0) {
		me->pqw_threshold = Min((unsigned int)threshold, MDNS_RESOLVER_PQW_THRESHOLD_MAX);
	} else {
		me->pqw_threshold = 0;
	}
}
#endif

//======================================================================================================================

void
mdns_resolver_activate(mdns_resolver_t me)
{
	if (!me->user_activated) {
		me->user_activated = true;
		mdns_retain(me);
		dispatch_async(_mdns_resolver_queue(),
		^{
			_mdns_resolver_activate_internal(me);
			mdns_release(me);
		});
	}
}

//======================================================================================================================

static void
_mdns_resolver_invalidate_internal(mdns_resolver_t resolver);

void
mdns_resolver_invalidate(mdns_resolver_t me)
{
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_resolver_invalidate_internal(me);
		mdns_release(me);
	});
}

static void
_mdns_resolver_invalidate_internal(mdns_resolver_t me)
{
	require_return(!me->invalidated);

	me->invalidated = true;
	dispatch_source_forget(&me->probe_timer);
	mdns_querier_forget(&me->probe_querier);
	mdns_server_t server;
	while ((server = me->server_list) != NULL) {
		me->server_list = server->next;
		if (server->path_evaluator) {
			nw_path_evaluator_cancel(server->path_evaluator);
			nw_forget(&server->path_evaluator);
		}
		mdns_session_forget(&server->shared_stream_session);
	}
	mdns_querier_t querier;
	while ((querier = me->querier_list) != NULL) {
		me->querier_list = querier->next;
		_mdns_querier_conclude(querier, mdns_querier_result_type_resolver_invalidation);
		mdns_release(querier);
	}
	if (me->event_handler) {
		mdns_retain(me);
		dispatch_async(me->user_queue,
		^{
			me->event_handler(mdns_resolver_event_invalidated, NULL);
			mdns_release(me);
		});
	}
}

//======================================================================================================================

bool
mdns_resolver_type_uses_encryption(const mdns_resolver_type_t type)
{
	// Note: A default case isn't used so that the compiler can catch missing resolver types.
	switch (type) {
		case mdns_resolver_type_null:
		case mdns_resolver_type_normal:
		case mdns_resolver_type_tcp:
			return false;

		case mdns_resolver_type_tls:
		case mdns_resolver_type_https:
			return true;
	}
	return false;
}

//======================================================================================================================

mdns_querier_t
mdns_resolver_create_querier(mdns_resolver_t me, OSStatus *out_error)
{
	OSStatus err;
	mdns_querier_t querier = NULL;
	mdns_querier_t obj = _mdns_querier_alloc();
	require_action_quiet(obj, exit, err = kNoMemoryErr);

	atomic_init(&obj->send_count, 0);
	obj->resolver = me;
	mdns_retain(obj->resolver);

	obj->query = mdns_query_message_create(mdns_message_init_option_disable_header_printing);
	require_action_quiet(obj->query, exit, err = kNoResourcesErr);

	querier = obj;
	obj = NULL;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	mdns_release_null_safe(obj);
	return querier;
}

//======================================================================================================================
// MARK: - Resolver Private Methods

static void
_mdns_resolver_finalize(mdns_resolver_t me)
{
	nw_forget(&me->interface);
	ForgetMem(&me->interface_log_str);
	ForgetCF(&me->server_array);
	dispatch_forget(&me->user_queue);
	BlockForget(&me->event_handler);
}

//======================================================================================================================

static char *
_mdns_resolver_copy_description(mdns_resolver_t me, const bool debug, const bool privacy)
{
	char *				description = NULL;
	char				buffer[256];
	char *				dst = buffer;
	const char * const	lim = &buffer[countof(buffer)];
	int					n;

	*dst = '\0';
	if (debug) {
		n = mdns_snprintf_add(&dst, lim, "<%s: %p>: ", me->base.kind->name, me);
		require_quiet(n >= 0, exit);
	}
	n = mdns_snprintf_add(&dst, lim, "%s ", _mdns_resolver_get_kind(me)->name);
	require_quiet(n >= 0, exit);

	if (me->interface) {
	    const char *interface_name = nw_interface_get_name(me->interface);
		n = mdns_snprintf_add(&dst, lim, "using interface %s (%u) ",
			interface_name ? interface_name : "???", nw_interface_get_index(me->interface));
		require_quiet(n >= 0, exit);
	}
	n = mdns_snprintf_add(&dst, lim, "with servers [");
	require_quiet(n >= 0, exit);

	const char *separator = "";
	const CFIndex count = CFArrayGetCount(me->server_array);
	for (CFIndex i = 0; i < count; ++i) {
		const mdns_server_t	server = (mdns_server_t)CFArrayGetValueAtIndex(me->server_array, i);

		char * const server_desc = mdns_object_copy_description(&server->base, false, privacy);
		n = mdns_snprintf_add(&dst, lim, "%s%s", separator, server_desc ? server_desc : "<NO SERVER DESC.>");
		FreeNullSafe(server_desc);
		require_quiet(n >= 0, exit);
		separator = ", ";
	}
	n = mdns_snprintf_add(&dst, lim, "]");
	require_quiet(n >= 0, exit);

	description = strdup(buffer);

exit:
	return description;
}

//======================================================================================================================

static mdns_resolver_kind_t
_mdns_resolver_get_kind(const mdns_resolver_t me)
{
	return (mdns_resolver_kind_t)me->base.kind;
}

//======================================================================================================================

static const char *
_mdns_resolver_get_datagram_protocol_string(const mdns_resolver_t me)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	const char * const string = kind->datagram_protocol_str;
	return (string ? string : "???");
}

//======================================================================================================================

static const char *
_mdns_resolver_get_bytestream_protocol_string(const mdns_resolver_t me)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	const char * const string = kind->bytestream_protocol_str;
	return (string ? string : "???");
}

//======================================================================================================================

static uint16_t
_mdns_resolver_get_default_port(const mdns_any_resolver_t any)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(any.resolver);
	return kind->default_port;
}

//======================================================================================================================

static bool
_mdns_resolver_is_stream_only(const mdns_resolver_t me)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	return kind->stream_only;
}

//======================================================================================================================

static bool
_mdns_resolver_needs_edns0_padding(const mdns_resolver_t me)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	return kind->needs_edns0_padding;
}

//======================================================================================================================

static bool
_mdns_resolver_needs_zero_ids(const mdns_resolver_t me)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	return kind->needs_zero_ids;
}

//======================================================================================================================

static bool
_mdns_resolver_needs_suspicious_reply_defense(const mdns_resolver_t me)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	return kind->suspicious_reply_defense;
}

//======================================================================================================================

static bool
_mdns_resolver_no_stream_session_sharing(const mdns_resolver_t me)
{
	if (me->force_no_stream_sharing) {
		return true;
	}
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	return kind->no_stream_session_sharing;
}

//======================================================================================================================

static OSStatus
_mdns_resolver_add_server_by_endpoint(mdns_resolver_t me, nw_endpoint_t endpoint)
{
	OSStatus err;
	mdns_server_t server = NULL;
	const CFIndex server_count = CFArrayGetCount(me->server_array);
	require_action_quiet(server_count < MDNS_RESOLVER_SERVER_COUNT_MAX, exit, err = kCountErr);

	server = _mdns_server_alloc();
	require_action_quiet(server, exit, err = kNoMemoryErr);

	server->endpoint = endpoint;
	nw_retain(server->endpoint);

	const int default_port = _mdns_resolver_get_default_port(me);
	if ((default_port != 0) && (nw_endpoint_get_port(server->endpoint) == default_port)) {
		server->uses_default_port = true;
	}
	server->rank = ((unsigned int)server_count) + 1;
	const uint64_t one_hour_ago_ticks	= mach_continuous_time() - (kSecondsPerHour * _mdns_ticks_per_second());
	server->latest_session_start_ticks	= one_hour_ago_ticks;
	server->last_stream_error_ticks		= one_hour_ago_ticks;

	CFArrayAppendValue(me->server_array, server);
	err = kNoErr;

exit:
	mdns_release_null_safe(server);
	return err;
}

//======================================================================================================================

#define MDNS_QUERIER_INITIAL_RTX_INTERVAL_DEFAULT_MS	1000

static void
_mdns_resolver_activate_servers(mdns_resolver_t resolver);

static void
_mdns_resolver_set_up_server_path_evaluator(mdns_resolver_t resolver, mdns_server_t server);

static void
_mdns_resolver_activate_internal(const mdns_resolver_t me)
{
	require_return(!me->invalidated && !me->activated);

	me->activated = true;
	if (unlikely(me->event_handler && !me->user_queue)) {
		os_log_error(_mdns_resolver_log(), "API misuse: an event handler without a queue is useless!");
		BlockForget(&me->event_handler);
	}
	if (me->initial_dgram_rtx_ms <= 0) {
		me->initial_dgram_rtx_ms = MDNS_QUERIER_INITIAL_RTX_INTERVAL_DEFAULT_MS;
	}
	const CFIndex n = CFArrayGetCount(me->server_array);
	if (n <= 0) {
		const nw_endpoint_t endpoint = _mdns_resolver_create_hostname_endpoint(me);
		if (endpoint) {
			_mdns_resolver_add_server_by_endpoint(me, endpoint);
			nw_release(endpoint);
		}
	}
	_mdns_resolver_activate_servers(me);
	if (_mdns_resolver_is_stream_only(me)) {
		_mdns_resolver_check_for_problematic_servers(me);
	}
}

static void
_mdns_resolver_activate_servers(const mdns_resolver_t me)
{
	mdns_server_t *ptr = &me->server_list;
	const CFIndex n = CFArrayGetCount(me->server_array);
	for (CFIndex i = 0; i < n; ++i) {
		const mdns_server_t server = (mdns_server_t)CFArrayGetValueAtIndex(me->server_array, i);

		// Append server to list.
		server->next = NULL;
		*ptr = server;
		ptr = &server->next;

		// Set up a path evaluator if the server's endpoint is an IP address. The server's usability will be
		// generally based on whether the path to the IP address is satisfied. Otherwise, the endpoint is a
		// hostname that will be handled by libnetwork, i.e., it will request resolution, then deal with the
		// paths of the resulting IP addresses, so mark the server as usable.
		if (nw_endpoint_get_type(server->endpoint) == nw_endpoint_type_address) {
			_mdns_resolver_set_up_server_path_evaluator(me, server);
		} else {
			server->usable = true;
		}
		os_log(_mdns_resolver_log(), "Server %@ is %{public}susable", server, server->usable ? "" : "un");
	}
}

static void
_mdns_resolver_set_up_server_path_evaluator(const mdns_resolver_t me, const mdns_server_t server)
{
	server->path_evaluator = nw_path_create_evaluator_for_endpoint(server->endpoint, NULL);
	if (unlikely(!server->path_evaluator)) {
		os_log_error(_mdns_resolver_log(), "Failed to create path evaluator for %@", server);
		server->usable = true; // Assume that the server is usable.
		return;
	}
	// Start the server's path evaluator.
	nw_path_evaluator_set_queue(server->path_evaluator, _mdns_resolver_queue());
	mdns_retain(me);
	mdns_retain(server);
	nw_path_evaluator_set_update_handler(server->path_evaluator, _mdns_resolver_queue(),
	^(nw_path_t updated_path)
	{
		if (_mdns_path_to_server_is_usable(updated_path, _mdns_resolver_uses_encryption(me))) {
			if (!server->usable) {
				server->usable = true;
				os_log(_mdns_resolver_log(), "Server %@ is now usable", server);
				_mdns_resolver_start_serverless_queries(me);
			}
		} else {
			if (server->usable) {
				server->usable = false;
				os_log(_mdns_resolver_log(), "Server %@ is now unusable", server);
			}
		}
	});
	nw_path_evaluator_set_cancel_handler(server->path_evaluator,
	^{
		mdns_release(me);
		mdns_release(server);
	});
	nw_path_evaluator_start(server->path_evaluator);

	nw_path_t path = nw_path_evaluator_copy_path(server->path_evaluator);
	if (path) {
		if (_mdns_path_to_server_is_usable(path, _mdns_resolver_uses_encryption(me))) {
			server->usable = true;
		}
		nw_forget(&path);
	}
}

//======================================================================================================================

static nw_parameters_t
_mdns_resolver_get_datagram_params(mdns_resolver_t me, OSStatus *out_error)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	if (kind->get_datagram_params) {
		return kind->get_datagram_params(me, out_error);
	} else {
		if (out_error) {
			*out_error = kUnsupportedErr;
		}
		return NULL;
	}
}

//======================================================================================================================

static nw_parameters_t
_mdns_resolver_get_stream_params(mdns_resolver_t me, OSStatus *out_error)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	if (kind->get_stream_params) {
		return kind->get_stream_params(me, out_error);
	} else {
		if (out_error) {
			*out_error = kUnsupportedErr;
		}
		return NULL;
	}
}

//======================================================================================================================

static nw_endpoint_t
_mdns_resolver_create_hostname_endpoint(mdns_resolver_t me)
{
	const mdns_resolver_kind_t kind = _mdns_resolver_get_kind(me);
	if (kind->create_hostname_endpoint) {
		return kind->create_hostname_endpoint(me);
	} else {
		return NULL;
	}
}

//======================================================================================================================

static void
_mdns_resolver_insert_server(mdns_resolver_t me, mdns_server_t server)
{
	mdns_server_t *ptr;
	for (ptr = &me->server_list; *ptr; ptr = &(*ptr)->next) {
		if ((*ptr)->penalized || ((*ptr)->rank) > server->rank) {
			break;
		}
	}
	server->next = *ptr;
	*ptr = server;
}

//======================================================================================================================

static void
_mdns_resolver_note_responsiveness(const mdns_resolver_t me, mdns_server_t server, const bool via_stream,
	const uint64_t session_start_ticks, const int qtype)
{
	if (_mdns_ticks_diff(session_start_ticks, server->latest_session_start_ticks) > 0) {
		server->latest_session_start_ticks = session_start_ticks;
	}
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	if (!server->responds_to_problematics && _mdns_qtype_is_problematic(qtype)) {
		server->responds_to_problematics = true;
	}
#else
	(void)qtype;
#endif
	if (server->penalized) {
		mdns_server_t *ptr;
		for (ptr = &me->server_list; *ptr; ptr = &(*ptr)->next) {
			if (*ptr == server) {
				break;
			}
		}
		if (*ptr) {
			*ptr = server->next;
			server->next = NULL;
			server->penalized = false;
			os_log_info(_mdns_resolver_log(), "Unpenalizing responsive server %@", server);
			_mdns_resolver_insert_server(me, server);
		}
	}
	if (via_stream) {
		_mdns_resolver_handle_stream_response(me, server);
	}
	if (me->report_symptoms && server->reported_unresponsiveness) {
		const nw_endpoint_t endpoint = server->endpoint;
		if (nw_endpoint_get_type(endpoint) == nw_endpoint_type_address) {
			mdns_symptoms_report_responsive_server(nw_endpoint_get_address(endpoint));
			server->reported_unresponsiveness = false;
		}
	}
}

//======================================================================================================================

static void
_mdns_resolver_penalize_server_ex(mdns_resolver_t resolver, mdns_server_t server, bool unresponsive,
	mdns_querier_t querier, uint64_t last_send_ticks);

static void
_mdns_resolver_penalize_server(const mdns_resolver_t me, const mdns_server_t server)
{
	_mdns_resolver_penalize_server_ex(me, server, false, NULL, 0);
}

static void
_mdns_resolver_penalize_unresponsive_server(const mdns_resolver_t me, const mdns_server_t server,
	const mdns_querier_t querier, const uint64_t last_send_ticks)
{
	_mdns_resolver_penalize_server_ex(me, server, true, querier, last_send_ticks);
}

#define MDNS_SERVER_PENALTY_TIME_SECS	60

static void
_mdns_resolver_penalize_server_ex(const mdns_resolver_t me, const mdns_server_t server, const bool unresponsive,
	const mdns_querier_t querier, const uint64_t last_send_ticks)
{
	if (unresponsive) {
	#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
		if (_mdns_resolver_use_problematic_qtype_workaround(me) && querier) {
			_mdns_server_handle_lack_of_response(server, querier);
		}
	#endif
		if (_mdns_ticks_diff(last_send_ticks, server->latest_session_start_ticks) < 0) {
			return;
		}
	}
	mdns_server_t *ptr;
	for (ptr = &me->server_list; *ptr; ptr = &(*ptr)->next) {
		if (*ptr == server) {
			break;
		}
	}
	if (*ptr) {
		*ptr = server->next;
		server->next			= NULL;
		server->penalty_expiry	= mach_continuous_time() + (MDNS_SERVER_PENALTY_TIME_SECS * _mdns_ticks_per_second());
		server->penalized		= true;
		while (*ptr) {
			ptr = &(*ptr)->next;
		}
		*ptr = server;
	}
	os_log_info(_mdns_resolver_log(),
		"%{public}sPenalizing server %@ for " StringifyExpansion( MDNS_SERVER_PENALTY_TIME_SECS ) " seconds",
		querier ? _mdns_querier_get_log_label(querier) : "", server);
	if (unresponsive && me->report_symptoms) {
		const nw_endpoint_t endpoint = server->endpoint;
		if (nw_endpoint_get_type(endpoint) == nw_endpoint_type_address) {
			mdns_symptoms_report_unresponsive_server(nw_endpoint_get_address(endpoint));
			server->reported_unresponsiveness = true;
		}
	}
}

//======================================================================================================================

static bool
_mdns_server_is_excluded(mdns_server_t server, uint32_t exclude_bitmap);

static mdns_server_t
_mdns_resolver_get_server(const mdns_resolver_t me, const uint32_t exclude_bitmap)
{
	mdns_server_t server = me->server_list;
	if (server && !((server->rank == 1) && !server->penalized && !_mdns_server_is_excluded(server, exclude_bitmap))) {
		const uint64_t now = mach_continuous_time();
		mdns_server_t *ptr = &me->server_list;
		while ((server = *ptr) != NULL) {
			int64_t diff;
			if (server->penalized && ((diff = _mdns_ticks_diff(now, server->penalty_expiry)) >= 0)) {
				*ptr = server->next;
				server->next = NULL;
				server->penalized = false;
				_mdns_resolver_insert_server(me, server);

				os_log_info(_mdns_resolver_log(), "Unpenalizing server %@ (penalty expired %lld.%03lld seconds ago)",
					server, (long long)_mdns_ticks_to_whole_seconds((uint64_t)diff),
					(long long)_mdns_ticks_to_fractional_milliseconds((uint64_t)diff));
			} else {
				ptr = &server->next;
			}
		}
		for (server = me->server_list; server; server = server->next) {
			if (!_mdns_server_is_excluded(server, exclude_bitmap)) {
				break;
			}
		}
	}
	return server;
}

static bool
_mdns_server_is_excluded(const mdns_server_t me, const uint32_t exclude_bitmap)
{
	if (!me->usable || (exclude_bitmap & _mdns_rank_to_bitmask(me->rank))) {
		return true;
	} else {
		return false;
	}
}

//======================================================================================================================

static void
_mdns_resolver_session_handle_event(const mdns_session_t session, const mdns_session_event_t event,
	const OSStatus error, void * const context)
{
	os_log_with_type(_mdns_resolver_log(),
		((event == mdns_session_event_terminated) && error) ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_INFO,
		"Resolver session event -- type: %{public}s, error: %{mdns:err}ld",
		mdns_session_event_to_string(event), (long)error);

	const mdns_resolver_t me = (mdns_resolver_t)context;
	switch (event) {
		case mdns_session_event_ready: {
			const uint32_t bitmask = _mdns_rank_to_bitmask(session->server->rank);
			for (mdns_querier_t querier = me->querier_list; querier; querier = querier->next) {
				if (querier->use_stream && (querier->will_send_bitmap & bitmask)) {
					_mdns_querier_send_query(querier, session);
				}
			}
			break;
		}
		case mdns_session_event_terminated: {
			mdns_server_t server;
			for (server = me->server_list; server; server = server->next) {
				if (server->shared_stream_session == session) {
					break;
				}
			}
			require_quiet(server, exit);

			mdns_session_forget(&server->shared_stream_session);
			if (error || (session->receive_count == 0)) {
				_mdns_resolver_handle_stream_error(me, server, NULL);
				_mdns_resolver_penalize_server(me, server);
			}
			for (mdns_querier_t querier = me->querier_list; querier; querier = querier->next) {
				if (querier->use_stream) {
					_mdns_querier_handle_stream_error(querier, server);
				}
			}
			break;
		}
		case mdns_session_event_lateness_warning:
			_mdns_resolver_handle_stream_lateness(me, session->server, session->start_ticks, NULL);
			break;

		default:
			break;
	}

exit:
	return;
}

//======================================================================================================================

static void
_mdns_resolver_session_receive(mdns_session_t session, dispatch_data_t msg_data, void *context)
{
	const mdns_message_t msg = mdns_message_create_with_dispatch_data(msg_data,
		mdns_message_init_option_disable_header_printing);
	require_return(msg);

	const mdns_resolver_t me = (mdns_resolver_t)context;
	bool logged_msg = false;
	// The current querier might conclude while traversing the querier list, so to be safe, its next pointer is
	// saved at the beginning of the for-loop body.
	for (mdns_querier_t next, querier = me->querier_list; querier; querier = next) {
		next = querier->next;
		int rcode = 0;
		const bool acceptable = _mdns_querier_is_response_acceptable(querier, msg, NULL, NULL, &rcode);
		if (acceptable) {
			if (!logged_msg) {
				_mdns_resolver_log_receive(me, session, msg, true, _mdns_querier_get_log_label(querier));
				logged_msg = true;
			}
			_mdns_resolver_note_responsiveness(me, session->server, _mdns_session_is_bytestream(session),
				session->start_ticks, mdns_querier_get_qtype(querier));
			if (_mdns_rcode_is_good(rcode)) {
				_mdns_querier_conclude_with_response(querier, msg);
			} else {
				// Note: _mdns_querier_handle_bad_rcode() may or may not conclude the querier.
				_mdns_querier_handle_bad_rcode(querier, msg, rcode, session->server);
			}
		}
	}
	if (!logged_msg) {
		_mdns_resolver_log_receive(me, session, msg, false, NULL);
	}
	mdns_release(msg);
}

//======================================================================================================================

static bool
_mdns_resolver_is_in_suspicious_mode(mdns_resolver_t resolver);

static void
_mdns_resolver_register_querier(mdns_resolver_t me, mdns_querier_t querier, bool force_stream_mode)
{
	require_return_action(!me->invalidated,
		_mdns_querier_conclude_async(querier, mdns_querier_result_type_resolver_invalidation));

	if (_mdns_resolver_is_stream_only(me) || force_stream_mode) {
		querier->use_stream = true;
	} else if (_mdns_resolver_is_in_suspicious_mode(me)) {
		querier->use_stream = true;
		querier->over_tcp_reason = mdns_query_over_tcp_reason_in_suspicious_mode;
	} else {
		querier->use_stream = false;
	}
	querier->will_send_bitmap = 0;
	querier->did_send_bitmap  = 0;
	if (!querier->use_stream || _mdns_resolver_no_stream_session_sharing(me)) {
		querier->use_shared_stream = false;
	} else {
		querier->use_shared_stream = true;
	}
	mdns_querier_t *ptr = &me->querier_list;
	while (*ptr) {
		ptr = &(*ptr)->next;
	}
	*ptr = querier;
	mdns_retain(*ptr);
	_mdns_querier_start(querier);
}

static bool
_mdns_resolver_is_in_suspicious_mode(const mdns_resolver_t me)
{
	if (_mdns_resolver_needs_suspicious_reply_defense(me) && me->suspicious_mode) {
		int64_t diff;
		const uint64_t now = mach_continuous_time();
		if ((diff = _mdns_ticks_diff(me->suspicious_mode_expiry, now)) >= 0) {
			os_log_info(_mdns_resolver_log(),
				"Suspicious mode (%lld.%03lld seconds left): forcing query over bytestream",
				(long long)_mdns_ticks_to_whole_seconds((uint64_t)diff),
				(long long)_mdns_ticks_to_fractional_milliseconds((uint64_t)diff));
			return true;
		} else {
			me->suspicious_mode = false;
		}
	}
	return false;
}

//======================================================================================================================

static void
_mdns_forget_session_list(mdns_session_t *list_ptr);

static void
_mdns_resolver_deregister_querier(mdns_resolver_t me, mdns_querier_t querier)
{
	dispatch_source_forget(&querier->rtx_timer);

	_mdns_forget_session_list(&querier->dgram_session_list);
	_mdns_forget_session_list(&querier->stream_session_list);
	mdns_querier_t *ptr = &me->querier_list;
	while (*ptr && (*ptr != querier)) {
		ptr = &(*ptr)->next;
	}
	if (*ptr) {
		*ptr = querier->next;
		querier->next = NULL;
		mdns_release(querier);
	}
}

static void
_mdns_forget_session_list(mdns_session_t * const list_ptr)
{
	mdns_session_t list = *list_ptr;
	if (list) {
		*list_ptr = NULL;
		mdns_session_t session;
		while ((session = list) != NULL) {
			list = session->next;
			session->next = NULL;
			mdns_session_forget(&session);
		}
	}
}

//======================================================================================================================

static mdns_session_t
_mdns_resolver_create_session(const mdns_resolver_t me, const mdns_server_t server, const bool need_bytestream,
	const mdns_delegation_t * const delegation, const uint8_t * const qname, OSStatus * const out_error)
{
	mdns_session_t session = NULL;

	mdns_session_type_t session_type;
	switch (_mdns_resolver_get_type(me)) {
		case mdns_resolver_type_normal:
			if (!need_bytestream) {
			#if MDNS_USE_NW_CONNECTION_FOR_UDP_INSTEAD_OF_SOCKETS
				session_type = mdns_session_type_connection;
			#else
				session_type = mdns_session_type_udp_socket;
			#endif
			} else {
				session_type = mdns_session_type_connection;
			}
			break;

		case mdns_resolver_type_tcp:
		case mdns_resolver_type_tls:
			session_type = mdns_session_type_connection;
			break;

		case mdns_resolver_type_https:
			session_type = mdns_session_type_url;
			break;

		case mdns_resolver_type_null:
		default:
			session_type = mdns_session_type_null;
			break;
	}
	OSStatus err;
	mdns_session_t obj;
	switch (session_type) {
		case mdns_session_type_connection:
			obj = _mdns_connection_session_alloc();
			require_action_quiet(obj, exit, err = kNoMemoryErr);
			break;

		case mdns_session_type_udp_socket:
			obj = _mdns_udp_socket_session_alloc();
			require_action_quiet(obj, exit, err = kNoMemoryErr);
			break;

		case mdns_session_type_url:
			obj = _mdns_url_session_alloc();
			require_action_quiet(obj, exit, err = kNoMemoryErr);
			break;

		case mdns_session_type_null:
		default:
			obj = NULL;
			err = kTypeErr;
			goto exit;
	}
	obj->server = server;
	mdns_retain(obj->server);

	err = _mdns_session_initialize(obj, me, need_bytestream, delegation, qname);
	require_noerr_quiet(err, exit);

	const mdns_session_kind_t kind = (mdns_session_kind_t)obj->base.kind;
	obj->is_stream	= kind->is_bytestream_check ? kind->is_bytestream_check(obj) : kind->is_bytestream;
	obj->is_ready	= kind->is_ready_check      ? kind->is_ready_check(obj)      : kind->is_always_ready;
	session	= obj;
	obj = NULL;

exit:
	if (out_error) {
		*out_error = err;
	}
	mdns_release_null_safe(obj);
	return session;
}

//======================================================================================================================

#define MDNS_RESOLVER_SUSPICIOUS_MODE_DURATION_SECS	10

static void
_mdns_resolver_got_suspicious_reply(const mdns_resolver_t me)
{
	const uint64_t duration		= MDNS_RESOLVER_SUSPICIOUS_MODE_DURATION_SECS * _mdns_ticks_per_second();
	me->suspicious_mode_expiry	= mach_continuous_time() + duration;
	me->suspicious_mode			= true;

	os_log_info(_mdns_resolver_log(), "Got suspicious response, entering suspicious mode for %d seconds",
		MDNS_RESOLVER_SUSPICIOUS_MODE_DURATION_SECS);
}

//======================================================================================================================

static const char *
_mdns_resolver_get_protocol_log_string(mdns_resolver_t me, bool for_bytestream)
{
	if (for_bytestream) {
		return _mdns_resolver_get_bytestream_protocol_string(me);
	} else {
		return _mdns_resolver_get_datagram_protocol_string(me);
	}
}

//======================================================================================================================

static const char *
_mdns_resolver_get_interface_log_string(mdns_resolver_t me)
{
	if (me->interface) {
		if (!me->interface_log_str) {
			const char * const if_name = nw_interface_get_name(me->interface);
			asprintf(&me->interface_log_str, "%s/%u", if_name ? if_name : "", nw_interface_get_index(me->interface));
		}
		return (me->interface_log_str ? me->interface_log_str : "???");
	} else {
		return "any interface";
	}
}

//======================================================================================================================

static mdns_resolver_type_t
_mdns_resolver_get_type(const mdns_resolver_t me)
{
	return _mdns_resolver_get_kind(me)->type;
}

//======================================================================================================================

static void
_mdns_resolver_log_receive(const mdns_resolver_t me, const mdns_session_t session, const mdns_message_t msg,
	const bool acceptable, const char *log_prefix)
{
	const size_t msg_len = mdns_message_get_length(msg);
	os_log(_mdns_resolver_log(),
		"%{public}sReceived %{public}sacceptable %zu-byte response from %@ over %{public}s via %{public}s -- "
		"%{public,mdns:dnshdr}.*P, %@",
		log_prefix ? log_prefix : "",
		acceptable ? "" : "un",
		msg_len,
		session->server,
		_mdns_resolver_get_protocol_log_string(me, _mdns_session_is_bytestream(session)),
		_mdns_resolver_get_interface_log_string(me),
		(int)Min(msg_len, kDNSHeaderLength), mdns_message_get_byte_ptr(msg),
		msg);
}

//======================================================================================================================

static void
_mdns_resolver_handle_stream_error(const mdns_resolver_t me, const mdns_server_t server, const char * const label)
{
	require_return(_mdns_resolver_is_stream_only(me));

	const uint64_t now_ticks = mach_continuous_time();
	const uint64_t elapsed_ticks = now_ticks - server->last_stream_error_ticks;
	// In case there's a burst of errors, ignore errors outside of the burst window.
	// For example, a bunch of pending queriers may experience the same underlying error at once.
	if (elapsed_ticks >= (MDNS_SERVER_STREAM_ERROR_BURST_WINDOW_SECS * _mdns_ticks_per_second())) {
		const bool had_problems = _mdns_server_has_stream_problems(server);
		server->last_stream_error_ticks = now_ticks;
		increment_saturate(server->stream_error_count, UINT32_MAX);
		if (!had_problems && _mdns_server_has_stream_problems(server)) {
			_mdns_resolver_log_server_problems(me, server, label);
		}
	}
	_mdns_resolver_check_for_problematic_servers(me);
}

//======================================================================================================================

static void
_mdns_resolver_handle_stream_lateness(const mdns_resolver_t me, const mdns_server_t server,
	const uint64_t session_start_ticks, const char * const label)
{
	require_return(_mdns_resolver_is_stream_only(me));

	if (_mdns_ticks_diff(session_start_ticks, server->latest_session_start_ticks) > 0) {
		const bool had_problems = _mdns_server_has_stream_problems(server);
		server->stream_lateness = true;
		if (!had_problems && _mdns_server_has_stream_problems(server)) {
			_mdns_resolver_log_server_problems(me, server, label);
		}
		_mdns_resolver_check_for_problematic_servers(me);
	}
}

//======================================================================================================================

static void
_mdns_resolver_handle_stream_response(const mdns_resolver_t me, const mdns_server_t server)
{
	require_return(_mdns_resolver_is_stream_only(me));

	const bool had_problems = _mdns_server_has_stream_problems(server);
	server->stream_error_count	= 0;
	server->stream_lateness		= false;
	if (had_problems) {
		os_log(_mdns_resolver_log(), "Cleared stream problems with %{public}s server %@",
			_mdns_resolver_get_bytestream_protocol_string(me), server);
	}
	if (me->cannot_connect && _mdns_resolver_has_usable_server_without_connection_problems(me)) {
		me->cannot_connect = false;
		dispatch_source_forget(&me->probe_timer);
		mdns_querier_forget(&me->probe_querier);
		_mdns_resolver_generate_connection_event(me);
		// Some queriers may have become serverless if they backed off while the probe querier was active, so check
		// for serverless queriers, but do it asynchronously in case we're in the middle of processing a response
		// for a serverless querier.
		_mdns_resolver_start_serverless_queries_async(me);
	}
}

//======================================================================================================================

static void
_mdns_resolver_start_probe_querier(mdns_resolver_t resolver);

#define MDNS_RESOLVER_PROBE_RETRY_INTERVAL_SECS	30

static void
_mdns_resolver_check_for_problematic_servers(const mdns_resolver_t me)
{
	if (!me->probe_timer && !_mdns_resolver_has_usable_server_without_connection_problems(me)) {
		me->probe_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _mdns_resolver_queue());
		require_action_quiet(me->probe_timer, exit,
			os_log_error(_mdns_resolver_log(), "Failed to create probe timer"));

		dispatch_source_set_timer(me->probe_timer,
			_dispatch_monotonictime_after_sec(MDNS_RESOLVER_PROBE_RETRY_INTERVAL_SECS),
			MDNS_RESOLVER_PROBE_RETRY_INTERVAL_SECS * UINT64_C_safe(kNanosecondsPerSecond),
			MDNS_RESOLVER_PROBE_RETRY_INTERVAL_SECS * UINT64_C_safe(kNanosecondsPerSecond / 20));
		dispatch_source_set_event_handler(me->probe_timer,
		^{
			_mdns_resolver_start_probe_querier(me);
		});
		dispatch_activate(me->probe_timer);
		_mdns_resolver_start_probe_querier(me);
		if (!me->cannot_connect) {
			me->cannot_connect = true;
			_mdns_resolver_generate_connection_event(me);
		}
	}

exit:
	return;
}

static void
_mdns_resolver_start_probe_querier(const mdns_resolver_t me)
{
	mdns_querier_forget(&me->probe_querier);
	me->probe_querier = mdns_resolver_create_querier(me, NULL);
	require_action_quiet(me->probe_querier, exit, os_log_error(_mdns_resolver_log(), "Failed to create probe querier"));

	mdns_querier_set_log_label(me->probe_querier, "PQ%u", ++me->probe_querier_id);
	mdns_querier_set_queue(me->probe_querier, _mdns_resolver_queue());
	const uint8_t * const probe_qname = (const uint8_t *)"\x5" "apple" "\x3" "com";
	mdns_querier_set_query(me->probe_querier, probe_qname, kDNSRecordType_NS, kDNSClassType_IN);
	mdns_querier_activate(me->probe_querier);

exit:
	return;
}

//======================================================================================================================

static bool
_mdns_resolver_has_usable_server_without_connection_problems(const mdns_resolver_t me)
{
	for (mdns_server_t server = me->server_list; server; server = server->next) {
		if (server->usable && !_mdns_server_has_stream_problems(server)) {
			return true;
		}
	}
	return false;
}

//======================================================================================================================

static void
_mdns_resolver_generate_event(const mdns_any_resolver_t any, const mdns_resolver_event_t event, const xpc_object_t info)
{
	const mdns_resolver_t me = any.resolver;
	require_quiet(!me->invalidated, exit);

	if (me->event_handler) {
		mdns_retain(me);
		xpc_retain(info);
		dispatch_async(me->user_queue,
		^{
			me->event_handler(event, info);
			mdns_release(me);
			xpc_release(info);
		});
	}

exit:
	return;
}

//======================================================================================================================

static void
_mdns_resolver_generate_connection_event(const mdns_resolver_t me)
{
	const xpc_object_t _Nonnull info = xpc_dictionary_create(NULL, NULL, 0);
	xpc_dictionary_set_bool(info, MDNS_RESOLVER_EVENT_CONNECTION_INFO_KEY_CANNOT_CONNECT, me->cannot_connect);
	_mdns_resolver_generate_event(me, mdns_resolver_event_connection, info);
	xpc_release(info);
}

//======================================================================================================================

static void
_mdns_resolver_log_server_problems(const mdns_resolver_t me, const mdns_server_t server, const char * const label)
{
	os_log_error(_mdns_resolver_log(),
		"%{public}sHaving stream problems with %{public}s server %@ -- lateness: %{bool}d, error count: %u",
		label ? label : "", _mdns_resolver_get_bytestream_protocol_string(me), server, server->stream_lateness,
		server->stream_error_count);
}

//======================================================================================================================

static bool
_mdns_resolver_uses_encryption(const mdns_resolver_t me)
{
	return mdns_resolver_type_uses_encryption(_mdns_resolver_get_type(me));
}

//======================================================================================================================

static void
_mdns_resolver_start_serverless_queries(const mdns_resolver_t me)
{
	require_return(!me->invalidated);

	bool have_usable_server = false;
	for (mdns_server_t server = me->server_list; server; server = server->next) {
		if (server->usable) {
			have_usable_server = true;
			break;
		}
	}
	if (have_usable_server) {
		for (mdns_querier_t querier = me->querier_list; querier; querier = querier->next) {
			if (!querier->current_server) {
				_mdns_querier_start(querier);
			}
		}
	}
}

//======================================================================================================================

static void
_mdns_resolver_start_serverless_queries_async(const mdns_resolver_t me)
{
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_resolver_start_serverless_queries(me);
		mdns_release(me);
	});
}

//======================================================================================================================

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static bool
_mdns_resolver_use_problematic_qtype_workaround(const mdns_resolver_t me)
{
	return (me->pqw_threshold > 0);
}
#endif

//======================================================================================================================

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
static bool
_mdns_resolver_use_mixed_up_responses_workaround(const mdns_resolver_t me)
{
	return (_mdns_resolver_get_type(me) == mdns_resolver_type_normal);
}
#endif

//======================================================================================================================
// MARK: - Normal Resolver Private Methods

static void
_mdns_normal_resolver_finalize(mdns_normal_resolver_t me)
{
	nw_forget(&me->udp_params);
	nw_forget(&me->tcp_params);
}

//======================================================================================================================

static nw_parameters_t
_mdns_normal_resolver_get_datagram_params(mdns_normal_resolver_t me, OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = NULL;

	if (!me->udp_params) {
		me->udp_params = _mdns_create_udp_parameters(&err);
		require_noerr_quiet(err, exit);
	}
	params = me->udp_params;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return params;
}

//======================================================================================================================

static nw_parameters_t
_mdns_normal_resolver_get_stream_params(mdns_normal_resolver_t me, OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = NULL;

	if (!me->tcp_params) {
		me->tcp_params = _mdns_create_tcp_parameters(&err);
		require_noerr_quiet(err, exit);
	}
	params = me->tcp_params;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return params;
}

//======================================================================================================================
// MARK: - TCP-Only Resolver Private Methods

static void
_mdns_tcp_resolver_finalize(mdns_tcp_resolver_t me)
{
	nw_forget(&me->params);
}

//======================================================================================================================

static nw_parameters_t
_mdns_tcp_resolver_get_stream_params(mdns_tcp_resolver_t me, OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = NULL;
	if (!me->params) {
		me->params = _mdns_create_tcp_parameters(&err);
		require_noerr_quiet(err, exit);
	}
	params = me->params;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return params;
}

//======================================================================================================================
// MARK: - TLS Resolver Private Methods

static void
_mdns_tls_resolver_finalize(mdns_tls_resolver_t me)
{
	ForgetMem(&me->hostname);
	nw_forget(&me->params);
}

//======================================================================================================================

static OSStatus
_mdns_tls_resolver_set_provider_name(mdns_tls_resolver_t me, const char *provider_name)
{
	return mdns_replace_string(&me->hostname, provider_name);
}

//======================================================================================================================

static void
_mdns_tls_resolver_set_port(const mdns_tls_resolver_t me, const uint16_t port)
{
	me->port = port;
}

//======================================================================================================================

static nw_parameters_t
_mdns_tls_resolver_create_stream_params(mdns_tls_resolver_t me, OSStatus *out_error);

static nw_parameters_t
_mdns_tls_resolver_get_stream_params(mdns_tls_resolver_t me, OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = NULL;
	if (!me->params) {
		me->params = _mdns_tls_resolver_create_stream_params(me, &err);
		require_noerr_quiet(err, exit);
	}
	params = me->params;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return params;
}

static nw_parameters_t
_mdns_tls_resolver_create_stream_params(mdns_tls_resolver_t me, OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = NULL;
	nw_parameters_t obj;
	if (me->hostname) {
		__block bool server_name_was_set = false;
		nw_parameters_configure_protocol_block_t configure_tls = ^(nw_protocol_options_t tls_options)
		{
			const sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(tls_options);
			if (sec_options) {
				sec_protocol_options_set_tls_server_name(sec_options, me->hostname);
				sec_protocol_options_set_peer_authentication_required(sec_options, true);
				sec_release(sec_options);
				server_name_was_set = true;
			}
		};
		obj = nw_parameters_create_secure_tcp(configure_tls, NW_PARAMETERS_DEFAULT_CONFIGURATION);
		require_action_quiet(obj, exit, err = kNoResourcesErr);
		require_action_quiet(server_name_was_set, exit, err = kUnknownErr);
	} else {
		obj = nw_parameters_create_secure_tcp(NW_PARAMETERS_DEFAULT_CONFIGURATION, NW_PARAMETERS_DEFAULT_CONFIGURATION);
		require_action_quiet(obj, exit, err = kNoResourcesErr);
	}
	nw_parameters_set_indefinite(obj, false);

	err = _mdns_add_dns_over_bytestream_framer(obj);
	require_noerr_quiet(err, exit);

	params	= obj;
	obj		= NULL;

exit:
	if (out_error) {
		*out_error = err;
	}
	nw_release_null_safe(obj);
	return params;
}

//======================================================================================================================

static nw_endpoint_t
_mdns_tls_resolver_create_hostname_endpoint(mdns_tls_resolver_t me)
{
	if (me->hostname) {
		const uint16_t port = (me->port == 0) ? _mdns_resolver_get_default_port(me) : me->port;
		return nw_endpoint_create_host_with_numeric_port(me->hostname, port);
	} else {
		return NULL;
	}
}

//======================================================================================================================
// MARK: - HTTPS Resolver Private Methods

static void
_mdns_https_resolver_finalize(mdns_https_resolver_t me)
{
	ForgetMem(&me->provider_name);
	ForgetMem(&me->url_path);
	nw_forget(&me->params);
}

//======================================================================================================================

static OSStatus
_mdns_https_resolver_set_provider_name(mdns_https_resolver_t me, const char *provider_name)
{
	return mdns_replace_string(&me->provider_name, provider_name);
}

//======================================================================================================================

static void
_mdns_https_resolver_set_port(const mdns_https_resolver_t me, const uint16_t port)
{
	me->port = port;
}

//======================================================================================================================

static OSStatus
_mdns_https_resolver_set_url_path(mdns_https_resolver_t me, const char *url_path)
{
	return mdns_replace_string(&me->url_path, url_path);
}

//======================================================================================================================

static nw_parameters_t
_mdns_https_resolver_create_stream_params(mdns_https_resolver_t me, OSStatus *out_error)
{
	OSStatus err = 0;
	nw_parameters_t params = NULL;
	nw_parameters_t obj;
	if (me->provider_name) {
		__block bool server_name_was_set = false;
		nw_parameters_configure_protocol_block_t configure_tls = ^(nw_protocol_options_t tls_options)
		{
			const sec_protocol_options_t sec_options = nw_tls_copy_sec_protocol_options(tls_options);
			if (sec_options) {
				sec_protocol_options_set_tls_server_name(sec_options, me->provider_name);
				sec_protocol_options_set_peer_authentication_required(sec_options, true);
				sec_protocol_options_add_tls_application_protocol(sec_options, "h2");
				sec_release(sec_options);
				server_name_was_set = true;
			}
		};
		obj = nw_parameters_create_secure_tcp(configure_tls, NW_PARAMETERS_DEFAULT_CONFIGURATION);
		require_action_quiet(obj, exit, err = kNoResourcesErr);
		require_action_quiet(server_name_was_set, exit, err = kUnknownErr);
	} else {
		obj = nw_parameters_create_secure_tcp(NW_PARAMETERS_DEFAULT_CONFIGURATION, NW_PARAMETERS_DEFAULT_CONFIGURATION);
		require_action_quiet(obj, exit, err = kNoResourcesErr);
	}

	char *url_string = NULL;
	asprintf(&url_string, "https://%s%s", me->provider_name, me->url_path ? me->url_path : "");
	nw_parameters_set_url(obj, url_string);
	FreeNullSafe(url_string);

	nw_parameters_set_indefinite(obj, false);

	params	= obj;
	obj		= NULL;

exit:
	if (out_error) {
		*out_error = err;
	}
	nw_release_null_safe(obj);
	return params;
}

static nw_parameters_t
_mdns_https_resolver_get_stream_params(mdns_https_resolver_t me, OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = NULL;
	if (!me->params) {
		me->params = _mdns_https_resolver_create_stream_params(me, &err);
		require_noerr_quiet(err, exit);
	}
	params = me->params;
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return params;
}

//======================================================================================================================

static nw_endpoint_t
_mdns_https_resolver_create_hostname_endpoint(mdns_https_resolver_t me)
{
	if (me->provider_name) {
		const uint16_t port = (me->port == 0) ? _mdns_resolver_get_default_port(me) : me->port;
		return nw_endpoint_create_host_with_numeric_port(me->provider_name, port);
	} else {
		return NULL;
	}
}

//======================================================================================================================
// MARK: - Server Private Methods

static void
_mdns_server_finalize(mdns_server_t me)
{
	nw_forget(&me->endpoint);
	nw_forget(&me->path_evaluator);
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	_pqw_info_forget(&me->pqw_info);
#endif
}

//======================================================================================================================

static char *
_mdns_server_copy_description(mdns_server_t me, const bool debug, const bool privacy)
{
	char *				description = NULL;
	char				buffer[128];
	char *				dst = buffer;
	const char * const	lim = &buffer[countof(buffer)];
	int					n;

	*dst = '\0';
	if (debug) {
		n = mdns_snprintf_add(&dst, lim, "<%s: %p>: ", me->base.kind->name, me);
		require_quiet(n >= 0, exit);
	}
	if (privacy) {
		char strbuf[64];
		if (nw_endpoint_get_type(me->endpoint) == nw_endpoint_type_address) {
			const char *str = NULL;
			const struct sockaddr * const sa = nw_endpoint_get_address(me->endpoint);
			const int family = sa->sa_family;
			if ((family == AF_INET) || (family == AF_INET6)) {
				n = mdns_print_obfuscated_ip_address(strbuf, sizeof(strbuf), sa);
				if (n >= 0) {
					str = strbuf;
				}
			}
			if (str) {
				n = mdns_snprintf_add(&dst, lim, "%s", str);
				require_quiet(n >= 0, exit);
			} else {
				const char * const version = (family == AF_INET) ? "4" : ((family == AF_INET6) ? "6" : "?");
				n = mdns_snprintf_add(&dst, lim, "<IPv%s#%u>", version, me->rank);
				require_quiet(n >= 0, exit);
			}
		} else {
			const char *str = NULL;
			const char *hostname = nw_endpoint_get_hostname(me->endpoint);
			if (hostname) {
				n = DNSMessagePrintObfuscatedString(strbuf, sizeof(strbuf), hostname);
				if (n >= 0) {
					str = strbuf;
				}
			}
			if (str) {
				n = mdns_snprintf_add(&dst, lim, "%s", str);
				require_quiet(n >= 0, exit);
			} else {
				n = mdns_snprintf_add(&dst, lim, "<H#%u>", me->rank);
				require_quiet(n >= 0, exit);
			}
		}
		if (!me->uses_default_port) {
			n = mdns_snprintf_add(&dst, lim, ":%d", nw_endpoint_get_port(me->endpoint));
			require_quiet(n >= 0, exit);
		}
	} else {
		const char *hostname = nw_endpoint_get_hostname(me->endpoint);
		if (!hostname) {
			hostname = "<unknown>";
		}
		n = mdns_snprintf_add(&dst, lim, "%s", hostname);
		require_quiet(n >= 0, exit);

		if (!me->uses_default_port) {
			const char *sep = ":";
			if (nw_endpoint_get_type(me->endpoint) == nw_endpoint_type_address) {
				const struct sockaddr * const sa = nw_endpoint_get_address(me->endpoint);
				if (sa->sa_family == AF_INET6) {
					sep = ".";
				}
			}
			n = mdns_snprintf_add(&dst, lim, "%s%d", sep, nw_endpoint_get_port(me->endpoint));
			require_quiet(n >= 0, exit);
		}
	}
	description = strdup(buffer);

exit:
	return description;
}

//======================================================================================================================

static bool
_mdns_server_has_stream_problems(const mdns_server_t me)
{
	return (me->stream_lateness || (me->stream_error_count >= MDNS_SERVER_STREAM_ERROR_COUNT_THRESHOLD));
}

//======================================================================================================================

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static bool
_mdns_server_supports_qtype(const mdns_server_t me, const int qtype)
{
	if (_mdns_qtype_is_problematic(qtype)) {
	#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
		if (me->mixes_up_responses) {
			return false;
		}
	#endif
	#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
		if (!me->responds_to_problematics) {
			const pqw_info_t * const info = me->pqw_info;
			if (info && _pqw_info_threshold_reached(info)) {
				return false;
			}
		}
	#endif
	}
	return true;
}
#endif

//======================================================================================================================

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static void
_mdns_server_handle_lack_of_response(const mdns_server_t me, const mdns_querier_t querier)
{
	require_return(!me->responds_to_problematics);
	const int qtype = mdns_querier_get_qtype(querier);
	if (!_mdns_qtype_is_problematic(qtype) || !_mdns_querier_test_query_got_response(querier, me)) {
		return;
	}
	if (!me->pqw_info) {
		me->pqw_info = _pqw_info_create(querier->resolver->pqw_threshold);
		require_return_action(me->pqw_info, os_log_error(_mdns_resolver_log(),
			"%{public}sFailed to allocate memory for PQW info", _mdns_querier_get_log_label(querier)));
	}
	pqw_info_t * const info = me->pqw_info;
	const uint8_t * const qname = mdns_querier_get_qname(querier);
	if (_pqw_info_can_accept_qname(info, qname)) {
		if (info->qname_count < (info->threshold - 1)) {
			OSStatus create_err;
			pqw_qname_item_t *item = _pqw_qname_item_create(qname, &create_err);
			require_return_action(item, os_log_error(_mdns_resolver_log(),
				"%{public}sFailed to create PQW qname item: %{mdns:err}ld",
				_mdns_querier_get_log_label(querier), (long)create_err));

			item->next = info->qname_list;
			info->qname_list = item;
			++info->qname_count;
		} else {
			_pqw_qname_list_forget(&info->qname_list);
			info->qname_count = info->threshold;
		}
		os_log(_mdns_resolver_log(),
			"%{public}sNo response (%u/%u) from server %@ for qtype %{mdns:rrtype}d",
			_mdns_querier_get_log_label(querier), info->qname_count, info->threshold, me, qtype);
	}
}

//======================================================================================================================

static uint16_t
_mdns_server_get_test_query_qtype(const mdns_server_t me)
{
	if (me->test_query_qtype == 0) {
		uint16_t qtype = kDNSRecordType_A;
		if (nw_endpoint_get_type(me->endpoint) == nw_endpoint_type_address) {
			const struct sockaddr * const sa = nw_endpoint_get_address(me->endpoint);
			if (sa->sa_family == AF_INET6) {
				qtype = kDNSRecordType_AAAA;
			}
		}
		me->test_query_qtype = qtype;
	}
	return me->test_query_qtype;
}
#endif // MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND

//======================================================================================================================
// MARK: - Session Private Methods

static void
_mdns_session_finalize(mdns_session_t me)
{
	mdns_forget(&me->server);
	me->context = NULL;
}

//======================================================================================================================

static char *
_mdns_session_copy_description(mdns_session_t me, const bool debug, __unused const bool privacy)
{
	char *				description = NULL;
	char				buffer[128];
	char *				dst = buffer;
	const char * const	lim = &buffer[countof(buffer)];
	int					n;

	*dst = '\0';
	if (debug) {
		n = mdns_snprintf_add(&dst, lim, "<%s: %p>: ", me->base.kind->name, me);
		require_quiet(n >= 0, exit);
	}
	description = strdup(buffer);

exit:
	return description;
}

//======================================================================================================================

static void
_mdns_session_invalidate_internal(mdns_session_t session);

static void
_mdns_session_invalidate(mdns_session_t me)
{
	// Set the state to done to prevent any further callback invocations.
	me->state = mdns_session_state_done;
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_session_invalidate_internal(me);
		if (me->callbacks->finalize_context) {
			me->callbacks->finalize_context(me->context);
		}
		me->context = NULL;
		mdns_release(me);
	});
}

static void
_mdns_session_invalidate_internal(const mdns_session_t me)
{
	dispatch_source_forget(&me->lateness_timer);
	const mdns_session_kind_t kind = (mdns_session_kind_t)me->base.kind;
	if (kind->invalidate) {
		kind->invalidate(me);
	}
}

//======================================================================================================================

static bool
_mdns_session_is_ready(const mdns_session_t me)
{
	return ((me->state == mdns_session_state_activated) && me->is_ready);
}

//======================================================================================================================

static OSStatus
_mdns_session_initialize(const mdns_session_t me, const mdns_resolver_t resolver, const bool need_bytestream,
	const mdns_delegation_t * const delegation, const uint8_t * const qname)
{
	const mdns_session_kind_t kind = (mdns_session_kind_t)me->base.kind;
	if (kind->initialize) {
		return kind->initialize(me, resolver, need_bytestream, delegation, qname);
	} else {
		return kNoErr;
	}
}

//======================================================================================================================

static void
_mdns_session_activate(const mdns_session_t me)
{
	require_return(me->state == mdns_session_state_nascent);

	OSStatus err;
	if (me->lateness_time_ms > 0) {
		me->lateness_timer = _mdns_resolver_create_oneshot_timer(me->lateness_time_ms, 5);
		require_action_quiet(me->lateness_timer, exit, err = kNoResourcesErr);

		dispatch_source_set_event_handler(me->lateness_timer,
		^{
			dispatch_source_forget(&me->lateness_timer);
			if (me->state == mdns_session_state_activated) {
				if (me->callbacks->handle_event) {
					me->callbacks->handle_event(me, mdns_session_event_lateness_warning, kNoErr, me->context);
				}
			}
		});
		dispatch_activate(me->lateness_timer);
	}
	const uint64_t now_ticks = mach_continuous_time();
	me->start_ticks		= now_ticks;
	me->last_send_ticks	= now_ticks - (kSecondsPerHour * _mdns_ticks_per_second());
	const mdns_session_kind_t kind = (mdns_session_kind_t)me->base.kind;
	if (kind->activate) {
		err = kind->activate(me);
		require_noerr_quiet(err, exit);
	}
	me->state = mdns_session_state_activated;
	err = kNoErr;

exit:
	if (err) {
		me->state = mdns_session_state_failed;
		_mdns_common_session_terminate_async(me, err);
	}
}

//======================================================================================================================

static void
_mdns_session_send(const mdns_session_t me, const dispatch_data_t msg, const uint16_t qtype)
{
	if (me->state == mdns_session_state_activated) {
		me->last_send_ticks = mach_continuous_time();
		const mdns_session_kind_t kind = (mdns_session_kind_t)me->base.kind;
		if (kind->send) {
			kind->send(me, msg, qtype);
		}
	}
}

//======================================================================================================================

static bool
_mdns_session_is_bytestream(const mdns_session_t me)
{
	return me->is_stream;
}

//======================================================================================================================

static void
_mdns_session_set_callbacks(mdns_session_t me, const mdns_session_callbacks_t * const callbacks, void * const context)
{
	if (me->state == mdns_session_state_nascent) {
		me->context		= context;
		me->callbacks	= callbacks;
	}
}

//======================================================================================================================

static void
_mdns_session_set_lateness_time(const mdns_session_t me, uint32_t time_ms)
{
	require_return(me->state == mdns_session_state_nascent);
	me->lateness_time_ms = time_ms;
}

//======================================================================================================================

static void
_mdns_session_finalize_context_with_release(void * const context)
{
	mdns_release((mdns_object_t)context);
}

//======================================================================================================================
// MARK: - Session Common Subkind Methods

static nw_endpoint_t
_mdns_common_session_get_server_endpoint(const mdns_any_session_t any)
{
	const mdns_session_t me	= any.session;
	return me->server->endpoint;
}

//======================================================================================================================

static void
_mdns_common_session_invoke_ready_event_handler(const mdns_any_session_t any)
{
	const mdns_session_t me = any.session;
	if ((me->state == mdns_session_state_activated) && !me->is_ready) {
		me->is_ready = true;
		if (me->callbacks->handle_event) {
			me->callbacks->handle_event(me, mdns_session_event_ready, kNoErr, me->context);
		}
	}
}

//======================================================================================================================

static void
_mdns_common_session_invoke_receive(const mdns_any_session_t any, const dispatch_data_t msg)
{
	const mdns_session_t me = any.session;
	if (me->state == mdns_session_state_activated) {
		dispatch_source_forget(&me->lateness_timer);
		increment_saturate(me->receive_count, UINT32_MAX);
		if (me->callbacks->receive) {
			me->callbacks->receive(me, msg, me->context);
		}
	}
}

//======================================================================================================================

static void
_mdns_common_session_terminate(const mdns_any_session_t any, const OSStatus error)
{
	const mdns_session_t me = any.session;
	if (me->state != mdns_session_state_done) {
		_mdns_session_invalidate_internal(me);
		me->state = mdns_session_state_done;
		if (me->callbacks->handle_event) {
			me->callbacks->handle_event(me, mdns_session_event_terminated, error, me->context);
		}
	}
}

//======================================================================================================================

static void
_mdns_common_session_terminate_async(const mdns_any_session_t any, const OSStatus error)
{
	const mdns_session_t me = any.session;
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_common_session_terminate(me, error);
		mdns_release(me);
	});
}

//======================================================================================================================
// MARK: - Connection Session Private Methods

static void
_mdns_connection_session_finalize(__unused const mdns_connection_session_t me)
{
	// Nothing to free.
}

//======================================================================================================================

static nw_endpoint_t
_mdns_create_domain_attributed_endpoint(nw_endpoint_t original_endpoint, const uint8_t *hostname, OSStatus *out_error);

static OSStatus
_mdns_connection_session_initialize(const mdns_connection_session_t me, const mdns_resolver_t resolver,
	const bool need_bytestream, const mdns_delegation_t * const delegation, const uint8_t * const qname)
{
	OSStatus err;
	nw_parameters_t params_alt = NULL;
	nw_endpoint_t server_endpoint_alt = NULL;
	nw_parameters_t params;
	if (_mdns_resolver_is_stream_only(resolver) || need_bytestream) {
		params = _mdns_resolver_get_stream_params(resolver, &err);
		require_noerr_quiet(err, exit);

		me->is_bytestream = true;
	} else {
		params = _mdns_resolver_get_datagram_params(resolver, &err);
		require_noerr_quiet(err, exit);

		me->is_bytestream = false;
	}
	if (delegation && ((delegation->type == mdns_delegation_type_pid) ||
		(delegation->type == mdns_delegation_type_uuid))) {
		params_alt = nw_parameters_copy(params);
		require_action_quiet(params_alt, exit, err = kNoResourcesErr);

		if (delegation->type == mdns_delegation_type_pid) {
			nw_parameters_set_pid(params_alt, delegation->ident.pid);
		} else {
			nw_parameters_set_e_proc_uuid(params_alt, delegation->ident.uuid);
		}
		params = params_alt;
	}
	nw_endpoint_t server_endpoint = _mdns_common_session_get_server_endpoint(me);
	if (__builtin_available(macOS 10.16, iOS 14.0, watchOS 7.0, tvOS 14.0, *)) {
		if (qname) {
			OSStatus create_err;
			server_endpoint_alt = _mdns_create_domain_attributed_endpoint(server_endpoint, qname, &create_err);
			if (likely(server_endpoint_alt)) {
				server_endpoint = server_endpoint_alt;
			} else {
				os_log_error(_mdns_resolver_log(),
					"Failed to create domain-attributed endpoint for %@: %{mdns:err}ld",
					server_endpoint, (long)create_err);
			}
		}
	}
	me->connection = nw_connection_create(server_endpoint, params);
	require_action_quiet(me->connection, exit, err = kNoResourcesErr);

exit:
	nw_forget(&params_alt);
	nw_forget(&server_endpoint_alt);
	return err;
}

static nw_endpoint_t
_mdns_create_domain_attributed_endpoint(const nw_endpoint_t original_endpoint, const uint8_t * const domain,
	OSStatus *out_error)
{
	OSStatus err;
	nw_endpoint_t result = NULL;
	const struct sockaddr * const sa = nw_endpoint_get_address(original_endpoint);
	require_action_quiet(sa, exit, err = kTypeErr);

	nw_endpoint_t endpoint = nw_endpoint_create_address(sa);
	require_action_quiet(endpoint, exit, err = kNoResourcesErr);

	char domain_str[kDNSServiceMaxDomainName];
	err = DomainNameToString(domain, NULL, domain_str, NULL);
	require_noerr_quiet(err, exit);

	const uint16_t port = nw_endpoint_get_port(endpoint);
	nw_endpoint_t parent = nw_endpoint_create_host_with_numeric_port(domain_str, port);
	require_action_quiet(parent, exit, err = kNoResourcesErr);

	if (__builtin_available(macOS 10.16, iOS 14.0, watchOS 7.0, tvOS 14.0, *)) {
		nw_endpoint_set_parent_endpoint(endpoint, parent, false);
	}
	nw_forget(&parent);
	result = endpoint;
	endpoint = NULL;

exit:
	nw_forget(&endpoint);
	if (out_error) {
		*out_error = err;
	}
	return result;
}

//======================================================================================================================

static void
_mdns_connection_session_schedule_receive(mdns_connection_session_t session);

static OSStatus
_mdns_connection_session_activate(const mdns_connection_session_t me)
{
	mdns_retain(me);
	nw_connection_set_queue(me->connection, _mdns_resolver_queue());
	nw_connection_set_state_changed_handler(me->connection,
	^(nw_connection_state_t state, __unused nw_error_t error)
	{
		if (likely(me->connection)) {
			os_log_debug(_mdns_resolver_log(), "Connection state changed to %s for connection %@",
				nw_connection_state_to_string(state), me->connection);
			if (state == nw_connection_state_ready) {
				_mdns_common_session_invoke_ready_event_handler(me);
			} else if (state == nw_connection_state_failed) {
				_mdns_common_session_terminate(me, kConnectionErr);
			}
		}
		if (state == nw_connection_state_cancelled) {
			mdns_release(me);
		}
	});
	nw_connection_start(me->connection);
	_mdns_connection_session_schedule_receive(me);
	return kNoErr;
}

static void
_mdns_connection_session_schedule_receive(const mdns_connection_session_t me)
{
	nw_connection_receive_message(me->connection,
	^(dispatch_data_t msg, nw_content_context_t context, __unused bool is_complete, nw_error_t error)
	{
		if (likely(me->connection)) {
			if (msg) {
				_mdns_common_session_invoke_receive(me, msg);
			}
			const bool final = (context && nw_content_context_get_is_final(context)) ? true : false;
			if (final || error) {
				_mdns_common_session_terminate(me, error ? kConnectionErr : kNoErr);
			} else {
				_mdns_connection_session_schedule_receive(me);
			}
		}
	});
}

//======================================================================================================================

static void
_mdns_connection_session_invalidate(const mdns_connection_session_t me)
{
	if (me->connection) {
		nw_connection_cancel(me->connection);
		nw_forget(&me->connection);
	}
}

//======================================================================================================================

static void
_mdns_connection_session_send(const mdns_connection_session_t me, const dispatch_data_t msg, const uint16_t qtype)
{
	os_log_debug(_mdns_resolver_log(), "Sending message on connection %@", me->connection);

	__block nw_activity_t activity = NULL;
	if (qtype == kDNSRecordType_A) {
		activity = nw_activity_create(kDNSActivityDomain, kDNSActivityLabelUnicastAQuery);
	} else if (qtype == kDNSRecordType_AAAA) {
		activity = nw_activity_create(kDNSActivityDomain, kDNSActivityLabelUnicastAAAAQuery);
	}
	if (activity) {
		nw_connection_start_activity(me->connection, activity);
	}
	nw_connection_send(me->connection, msg, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
	^(const nw_error_t error)
	{
		if (activity) {
			if (me->connection) {
				nw_connection_end_activity(me->connection, activity);
			}
			nw_release(activity);
		}
		if (likely(me->connection) && error) {
			_mdns_common_session_terminate(me, kConnectionErr);
		}
	});
}

//======================================================================================================================

static bool
_mdns_connection_session_is_bytestream(const mdns_connection_session_t me)
{
	return me->is_bytestream;
}

//======================================================================================================================
// MARK: - UDP Socket Session Private Methods

static void
_mdns_udp_socket_session_finalize(const mdns_udp_socket_session_t me)
{
	_mdns_socket_forget(&me->sock);
}

//======================================================================================================================

static OSStatus
_mdns_bind_ipv6_socket_to_random_port(const int sock);

static OSStatus
_mdns_udp_socket_session_initialize(const mdns_udp_socket_session_t me, const mdns_resolver_t resolver,
	__unused const bool need_bytestream, const mdns_delegation_t * const delegation, const uint8_t * const qname)
{
	OSStatus err;
	int sock = kInvalidSocketRef;
	const struct sockaddr *dst = nw_endpoint_get_address(_mdns_common_session_get_server_endpoint(me));
	require_action_quiet((dst->sa_family == AF_INET) || (dst->sa_family == AF_INET6), exit, err = kTypeErr);

#if !MDNS_USE_CONNECTED_UDP_SOCKETS
	struct sockaddr_in dst_ipv4;
	if (dst->sa_family == AF_INET6) {
		const struct sockaddr_in6 * const sin6 = (const struct sockaddr_in6 *)dst;
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr) || IN6_IS_ADDR_V4COMPAT(&sin6->sin6_addr)) {
			memset(&dst_ipv4, 0, sizeof(dst_ipv4));
			dst_ipv4.sin_family	= AF_INET;
			SIN_LEN_SET(&dst_ipv4);
			dst_ipv4.sin_port	= sin6->sin6_port;
			memcpy(&dst_ipv4.sin_addr.s_addr, &sin6->sin6_addr.s6_addr[12], 4);
			dst = (const struct sockaddr *)&dst_ipv4;
		}
	}
#endif
	const bool ipv4 = (dst->sa_family == AF_INET);
	sock = socket(ipv4 ? AF_INET : AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	err = map_socket_creation_errno(sock);
	require_noerr_quiet(err, exit);

#define _do_setsockopt(SOCK, LEVEL, NAME, VALUE_PTR, VALUE_LEN)									\
	do {																						\
		int opt_err = setsockopt(SOCK, LEVEL, NAME, VALUE_PTR, (socklen_t)(VALUE_LEN));			\
		opt_err = map_socket_noerr_errno(SOCK, opt_err);										\
		if (unlikely(opt_err)) {																\
			os_log_error(_mdns_resolver_log(),													\
				"setsockopt() for " # LEVEL "/" # NAME " failed %{darwin.errno}d", opt_err);	\
		}																						\
	} while (0)

	const int on = 1;
	// Ensure that socket binds to a random port.
	if (ipv4) {
		_do_setsockopt(sock, SOL_SOCKET, SO_RANDOMPORT, &on, sizeof(on));
	} else {
		// Workaround for SO_RANDOMPORT not working for UDP/IPv6.
		_mdns_bind_ipv6_socket_to_random_port(sock);
	}
	_do_setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on));		// Return EPIPE instead of raising SIGPIPE.
	_do_setsockopt(sock, SOL_SOCKET, SO_NOWAKEFROMSLEEP, &on, sizeof(on));	// Don't wake from sleep on receive.
	mdns_make_socket_nonblocking(sock);
	// Restrict socket's network traffic to a particular interface.
	if (resolver->interface) {
		const uint32_t if_index = nw_interface_get_index(resolver->interface);
		if (ipv4) {
			_do_setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &if_index, sizeof(if_index));
		} else {
			_do_setsockopt(sock, IPPROTO_IPV6, IPV6_BOUND_IF, &if_index, sizeof(if_index));
		}
	}
	// If delegation info is provided, attribute outbound data to the delegator.
	if (delegation) {
		switch (delegation->type) {
			case mdns_delegation_type_pid:
				_do_setsockopt(sock, SOL_SOCKET, SO_DELEGATED, &delegation->ident.pid, sizeof(delegation->ident.pid));
				break;

			case mdns_delegation_type_uuid:
				_do_setsockopt(sock, SOL_SOCKET, SO_DELEGATED_UUID, delegation->ident.uuid,
					sizeof(delegation->ident.uuid));
				break;

			default:
			case mdns_delegation_type_none:
				break;
		}
	}
#undef _do_setsockopt
	if (qname) {
		char qname_str[kDNSServiceMaxDomainName];
		err = DomainNameToString(qname, NULL, qname_str, NULL);
		require_noerr_quiet(err, exit);

		const bool ok = ne_session_set_socket_attributes(sock, qname_str, NULL);
		if (!ok) {
			os_log_error(_mdns_resolver_log(), "ne_session_set_socket_attributes() failed for '%s'", qname_str);
		}
	}
	const socklen_t dst_len = (socklen_t)(ipv4 ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
#if MDNS_USE_CONNECTED_UDP_SOCKETS
	err = connect(sock, dst, dst_len);
	err = map_socket_noerr_errno(sock, err);
	if (!err) {
		me->connected = true;
		os_log_debug(_mdns_resolver_log(),
			"UDP socket connected to %{network:sockaddr}.*P", (int)dst_len, dst);
	} else if (err == EINPROGRESS) {
		os_log_info(_mdns_resolver_log(),
			"UDP socket connection to %{network:sockaddr}.*P is in progress", (int)dst_len, dst);
		err = kNoErr;
	} else {
		os_log_error(_mdns_resolver_log(),
			"UDP socket connection to %{network:sockaddr}.*P failed: %{darwin.errno}d", (int)dst_len, dst, (int)err);
		goto exit;
	}
#else
	memcpy(&me->server_addr, dst, dst_len);
	me->server_addr_len = dst_len;
#endif
	me->sock = sock;
	sock = kInvalidSocketRef;

exit:
	_mdns_socket_forget(&sock);
	return err;
}

static OSStatus
_mdns_bind_ipv6_socket_to_random_port(const int sock)
{
	struct sockaddr_in6 sin6;
	memset(&sin6, 0, sizeof(sin6));
	SIN6_LEN_SET(&sin6);
	sin6.sin6_family	= AF_INET6;
	sin6.sin6_addr		= in6addr_any;
	uint16_t port;
	OSStatus err;
	int tries = 0;
	// Bind to a random port in the ephemeral port range (see <https://tools.ietf.org/html/rfc6335#section-6>).
	// Note: This is the same algorithm used by mDNSResponder's MacOSX platform code for port randomization.
	do {
		port = RandomRange(0xC000U, 0xFFFFU);
		sin6.sin6_port = htons(port);
		err = bind(sock, (const struct sockaddr *)&sin6, sizeof(sin6));
		err = map_socket_noerr_errno(sock, err);
		++tries;
	} while ((err == EADDRINUSE) && (tries < 10000));
	if (err) {
		os_log_error(_mdns_resolver_log(),
			"Binding IPv6 socket to random port failed -- error: %{mdns:err}ld, tries: %d", (long)err, tries);
	} else {
		os_log_debug(_mdns_resolver_log(),
			"Binding IPv6 socket to random port succeeded -- port: %u, tries: %d", port, tries);
	}
	return err;
}

//======================================================================================================================

static void
_mdns_udp_socket_session_read_handler(void *ctx);

#if MDNS_USE_CONNECTED_UDP_SOCKETS
static void
_mdns_udp_socket_session_write_handler(void *ctx);
#endif

static void
_mdns_udp_socket_session_cancel_handler(void *ctx);

static OSStatus
_mdns_udp_socket_session_activate(const mdns_udp_socket_session_t me)
{
	OSStatus err;
	me->read_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)me->sock, 0, _mdns_resolver_queue());
	require_action_quiet(me->read_source, exit, err = kNoResourcesErr);

	mdns_retain(me);
	dispatch_set_context(me->read_source, me);
	dispatch_source_set_event_handler_f(me->read_source, _mdns_udp_socket_session_read_handler);
	dispatch_source_set_cancel_handler_f(me->read_source, _mdns_udp_socket_session_cancel_handler);
#if MDNS_USE_CONNECTED_UDP_SOCKETS
	if (me->connected) {
		dispatch_activate(me->read_source);
		me->read_source_suspended = false;
	} else {
		me->read_source_suspended = true;

		me->write_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE, (uintptr_t)me->sock, 0,
			_mdns_resolver_queue());
		require_action_quiet(me->write_source, exit, err = kNoResourcesErr);

		mdns_retain(me);
		dispatch_set_context(me->write_source, me);
		dispatch_source_set_event_handler_f(me->write_source, _mdns_udp_socket_session_write_handler);
		dispatch_source_set_cancel_handler_f(me->write_source, _mdns_udp_socket_session_cancel_handler);
		dispatch_activate(me->write_source);
	}
#else
	dispatch_activate(me->read_source);
#endif
	err = kNoErr;

exit:
	return err;
}

static void
_mdns_udp_socket_session_read_handler(void * const ctx)
{
	const mdns_udp_socket_session_t me = (mdns_udp_socket_session_t)ctx;
	uint8_t msg_buf[512];
#if MDNS_USE_CONNECTED_UDP_SOCKETS
	const ssize_t n = recv(me->sock, msg_buf, sizeof(msg_buf), 0);
#else
	sockaddr_ip	sender;
	socklen_t	sender_len = (socklen_t)sizeof(sender);
	const ssize_t n = recvfrom(me->sock, msg_buf, sizeof(msg_buf), 0, &sender.sa, &sender_len);
#endif
	const OSStatus err = map_socket_value_errno(me->sock, n >= 0, n);
	require_noerr_quiet(err, exit);

#if !MDNS_USE_CONNECTED_UDP_SOCKETS
	if (me->server_addr.sa.sa_family == AF_INET) {
		const struct sockaddr_in * const sa1 = &me->server_addr.v4;
		const struct sockaddr_in * const sa2 = &sender.v4;
		require_quiet(IN_ARE_ADDR_EQUAL(&sa1->sin_addr, &sa2->sin_addr), exit);
		require_quiet(sa1->sin_port == sa2->sin_port, exit);
	} else {
		const struct sockaddr_in6 * const sa1 = &me->server_addr.v6;
		const struct sockaddr_in6 * const sa2 = &sender.v6;
		require_quiet(IN6_ARE_ADDR_EQUAL(&sa1->sin6_addr, &sa2->sin6_addr), exit);
		require_quiet(sa1->sin6_port == sa2->sin6_port, exit);

		if (IN6_IS_ADDR_LINKLOCAL(&sa1->sin6_addr) && (sa1->sin6_scope_id != 0) &&
			(sa1->sin6_scope_id != sa2->sin6_scope_id)) {
			goto exit;
		}
	}
#endif
	dispatch_data_t msg = dispatch_data_create(msg_buf, (size_t)n, _mdns_resolver_queue(),
		DISPATCH_DATA_DESTRUCTOR_DEFAULT);
	if (msg) {
		_mdns_common_session_invoke_receive(me, msg);
		dispatch_forget(&msg);
	}

exit:
	if (err && (err != EWOULDBLOCK)) {
		_mdns_common_session_terminate(me, err);
	}
}

#if MDNS_USE_CONNECTED_UDP_SOCKETS
static void
_mdns_udp_socket_session_write_handler(void * const ctx)
{
	const mdns_udp_socket_session_t me = (mdns_udp_socket_session_t)ctx;
	dispatch_source_forget(&me->write_source);
	me->connected = true;
	os_log_info(_mdns_resolver_log(), "UDP socket connection to %@ is complete", me->base.server);
	dispatch_resume_if_suspended(me->read_source, &me->read_source_suspended);
	_mdns_common_session_invoke_ready_event_handler(me);
}
#endif

static void
_mdns_udp_socket_session_cancel_handler(void * const ctx)
{
	const mdns_udp_socket_session_t me = (mdns_udp_socket_session_t)ctx;
#if MDNS_USE_CONNECTED_UDP_SOCKETS
	if (!me->read_source && !me->write_source) {
		_mdns_socket_forget(&me->sock);
	}
#else
	_mdns_socket_forget(&me->sock);
#endif
	mdns_release(me);
}

//======================================================================================================================

static void
_mdns_udp_socket_session_invalidate(const mdns_udp_socket_session_t me)
{
#if MDNS_USE_CONNECTED_UDP_SOCKETS
	dispatch_source_forget(&me->write_source);
	dispatch_source_forget_ex(&me->read_source, &me->read_source_suspended);
#else
	dispatch_source_forget(&me->read_source);
#endif
}

//======================================================================================================================

#if MDNS_USE_CONNECTED_UDP_SOCKETS
static bool
_mdns_udp_socket_session_is_ready(const mdns_udp_socket_session_t me)
{
	return me->connected;
}
#endif

//======================================================================================================================

static void
_mdns_udp_socket_session_send(const mdns_udp_socket_session_t me, const dispatch_data_t msg,
	__unused const uint16_t qtype)
{
	const void *	msg_ptr;
	size_t			msg_len;
	dispatch_data_t	msg_map = dispatch_data_create_map(msg, &msg_ptr, &msg_len);
	require_quiet(msg_map, exit);

#if MDNS_USE_CONNECTED_UDP_SOCKETS
	const ssize_t n = send(me->sock, msg_ptr, msg_len, 0);
#else
	const ssize_t n = sendto(me->sock, msg_ptr, msg_len, 0, &me->server_addr.sa, me->server_addr_len);
#endif
	const OSStatus err = map_socket_value_errno(me->sock, n >= 0, n);
	if (err) {
		os_log_error(_mdns_resolver_log(), "sending to %@ failed: %{darwin.errno}d", me->base.server, (int)err);
	}
	require_noerr_quiet(err, exit);

exit:
	dispatch_release_null_safe(msg_map);
}

//======================================================================================================================
// MARK: - URL Session Private Methods

static void
_mdns_url_session_finalize(__unused const mdns_url_session_t me)
{
	nw_forget(&me->url_endpoint);
}

//======================================================================================================================

static OSStatus
_mdns_url_session_initialize(const mdns_url_session_t me, const mdns_resolver_t resolver,
	__unused const bool need_bytestream, __unused const mdns_delegation_t * const delegation,
	__unused const uint8_t * const qname)
{
	OSStatus err;
	const nw_parameters_t params = _mdns_resolver_get_stream_params(resolver, &err);
	require_noerr_quiet(err, exit);

	me->url_endpoint = nw_parameters_copy_url_endpoint(params);
	require_action_quiet(me->url_endpoint, exit, err = kNoResourcesErr);

exit:
	return err;
}

//======================================================================================================================

static OSStatus
_mdns_url_session_activate(__unused const mdns_url_session_t me)
{
	// Nothing to do for now.
	return kNoErr;
}

//======================================================================================================================

static void
_mdns_url_session_invalidate(const mdns_url_session_t me)
{
	if (me->http_task) {
		http_task_cancel(me->http_task);
		me->http_task = NULL;
	}
}

//======================================================================================================================

static void
_mdns_url_session_send(const mdns_url_session_t me, const dispatch_data_t msg, const uint16_t qtype)
{
	os_log_debug(_mdns_resolver_log(), "Sending message on URL %@", me->url_endpoint);

	mdns_retain(me);
	__block bool invoked = false;
	me->http_task = http_task_create_dns_query(_mdns_common_session_get_server_endpoint(me),
		nw_endpoint_get_url(me->url_endpoint), msg, qtype, false,
	^(const dispatch_data_t data, const CFErrorRef task_error) {
		if (likely(!invoked)) {
			invoked = true;
			if (likely(me->http_task)) {
				if (data) {
					_mdns_common_session_invoke_receive(me, data);
				}
				if (task_error) {
					os_log_error(_mdns_resolver_log(), "Got error %@", task_error);
					_mdns_common_session_terminate(me, (OSStatus)CFErrorGetCode(task_error));
				}
			}
			mdns_release(me);
		}
	});
	if (me->http_task) {
		http_task_start(me->http_task);
	} else {
		os_log_error(_mdns_resolver_log(), "Failed to create HTTP task");
		_mdns_common_session_terminate_async(me, kUnknownErr);
	}
}

//======================================================================================================================
// MARK: - Querier Public Methods

void
mdns_querier_set_queue(mdns_querier_t me, dispatch_queue_t queue)
{
	if (!me->user_activated || !me->user_queue)
	{
		if (queue) {
			dispatch_retain(queue);
		}
		dispatch_release_null_safe(me->user_queue);
		me->user_queue = queue;
		_mdns_querier_activate_if_ready(me);
	}
}

//======================================================================================================================

OSStatus
mdns_querier_set_query(mdns_querier_t me, const uint8_t *qname, uint16_t qtype, uint16_t qclass)
{
	OSStatus err;
	require_action_quiet(!me->user_activated || !mdns_query_message_get_qname(me->query), exit,
		err = kAlreadyInitializedErr);

	err = mdns_query_message_set_qname(me->query, qname);
	require_noerr_quiet(err, exit);

	mdns_query_message_set_qtype(me->query, qtype);
	mdns_query_message_set_qclass(me->query, qclass);

	_mdns_querier_activate_if_ready(me);
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

void
mdns_querier_set_dnssec_ok(const mdns_querier_t me, const bool set)
{
	require_return(!me->user_activated);
	mdns_query_message_set_do_bit(me->query, set);
}

//======================================================================================================================

void
mdns_querier_set_checking_disabled(const mdns_querier_t me, const bool checking_disabled)
{
	require_return(!me->user_activated);
	mdns_query_message_set_cd_bit(me->query, checking_disabled);
}

//======================================================================================================================

void
mdns_querier_set_delegator_pid(mdns_querier_t me, pid_t pid)
{
	if (!me->user_activated) {
		me->delegation.type = mdns_delegation_type_pid;
		me->delegation.ident.pid = pid;
	}
}

//======================================================================================================================

void
mdns_querier_set_delegator_uuid(mdns_querier_t me, uuid_t uuid)
{
	if (!me->user_activated) {
		me->delegation.type = mdns_delegation_type_uuid;
		uuid_copy(me->delegation.ident.uuid, uuid);
	}
}

//======================================================================================================================

void
mdns_querier_set_user_id(const mdns_querier_t me, const uint32_t user_id)
{
	require_return(!me->user_activated);
	me->user_id = user_id;
}

//======================================================================================================================

OSStatus
mdns_querier_set_log_label(const mdns_querier_t me, const char * const format, ...)
{
	require_return_value(!me->user_activated, kAlreadyInitializedErr);

	va_list args;
	va_start(args, format);
	char *inner_str = NULL;
	vasprintf(&inner_str, format, args);
	va_end(args);
	OSStatus err;
	require_action_quiet(inner_str, exit, err = kNoMemoryErr);

	char *log_label = NULL;
	asprintf(&log_label, "[%s] ", inner_str);
	require_action_quiet(log_label, exit, err = kNoMemoryErr);

	FreeNullSafe(me->log_label);
	me->log_label = log_label;
	log_label = NULL;
	err = kNoErr;

exit:
	ForgetMem(&inner_str);
	return err;
}

//======================================================================================================================

void
mdns_querier_set_result_handler(mdns_querier_t me, mdns_querier_result_handler_t handler)
{
	if (!me->user_activated) {
		const mdns_querier_result_handler_t new_handler = handler ? Block_copy(handler) : NULL;
		if (me->handler) {
			Block_release(me->handler);
		}
		me->handler = new_handler;
	}
}

//======================================================================================================================

static void
_mdns_querier_set_time_limit_ms(mdns_querier_t querier, int32_t time_limit_ms);

void
mdns_querier_set_time_limit_ms(const mdns_querier_t me, const int32_t time_limit_ms)
{
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_querier_set_time_limit_ms(me, time_limit_ms);
		mdns_release(me);
	});
}

static void
_mdns_querier_set_time_limit_ms(const mdns_querier_t me, const int32_t time_limit_ms)
{
	if (likely(!me->concluded)) {
		me->time_limit_ms = time_limit_ms;
		const OSStatus err = _mdns_querier_reset_time_limit(me);
		if (err) {
			_mdns_querier_conclude(me, err);
		}
	}
}

//======================================================================================================================

void
mdns_querier_activate(mdns_querier_t me)
{
	if (!me->user_activated) {
		me->user_activated = true;
		_mdns_querier_activate_if_ready(me);
	}
}

//======================================================================================================================

void
mdns_querier_invalidate(mdns_querier_t me)
{
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_querier_conclude(me, mdns_querier_result_type_invalidation);
		mdns_release(me);
	});
}

//======================================================================================================================

const uint8_t *
mdns_querier_get_qname(const mdns_querier_t me)
{
	return mdns_query_message_get_qname(me->query);
}

//======================================================================================================================

uint16_t
mdns_querier_get_qtype(const mdns_querier_t me)
{
	return mdns_query_message_get_qtype(me->query);
}

//======================================================================================================================

uint16_t
mdns_querier_get_qclass(const mdns_querier_t me)
{
	return mdns_query_message_get_qclass(me->query);
}

//======================================================================================================================

mdns_resolver_type_t
mdns_querier_get_resolver_type(const mdns_querier_t me)
{
	return _mdns_resolver_get_type(me->resolver);
}

//======================================================================================================================

mdns_querier_result_type_t
mdns_querier_get_result_type(const mdns_querier_t me)
{
	return me->result_type;
}

//======================================================================================================================

uint32_t
mdns_querier_get_send_count(const mdns_querier_t me)
{
	return atomic_load(&me->send_count);
}

//======================================================================================================================

uint32_t
mdns_querier_get_query_length(const mdns_querier_t me)
{
	return (uint32_t)mdns_message_get_length(me->query);
}

//======================================================================================================================

const uint8_t *
mdns_querier_get_response_ptr(const mdns_querier_t me)
{
	return _mdns_querier_get_response_ptr_safe(me);
}

//======================================================================================================================

uint32_t
mdns_querier_get_response_length(const mdns_querier_t me)
{
	return (uint32_t)_mdns_querier_get_response_length_safe(me);
}

//======================================================================================================================

bool
mdns_querier_response_is_fabricated(const mdns_querier_t me)
{
	return me->response_is_fabricated;
}

//======================================================================================================================

OSStatus
mdns_querier_get_error(const mdns_querier_t me)
{
	return me->error;
}

//======================================================================================================================

bool
mdns_querier_get_dnssec_ok(const mdns_querier_t me)
{
	return mdns_query_message_do_bit_is_set(me->query);
}

//======================================================================================================================

mdns_query_over_tcp_reason_t
mdns_querier_get_over_tcp_reason(const mdns_querier_t me)
{
	return me->over_tcp_reason;
}

//======================================================================================================================

bool
mdns_querier_match(const mdns_querier_t me, const uint8_t * const qname, const int qtype, const int qclass)
{
	if ((mdns_query_message_get_qtype(me->query) == qtype) && (mdns_query_message_get_qclass(me->query) == qclass)) {
		const uint8_t * const query_qname = mdns_query_message_get_qname(me->query);
		if (query_qname && DomainNameEqual(query_qname, qname)) {
			return true;
		}
	}
	return false;
}

//======================================================================================================================

bool
mdns_querier_has_concluded(const mdns_querier_t me)
{
	return (me->result_type != mdns_querier_result_type_null);
}

//======================================================================================================================

uint32_t
mdns_querier_get_user_id(const mdns_querier_t me)
{
	return me->user_id;
}

//======================================================================================================================
// MARK: - Querier Private Methods

static void
_mdns_querier_finalize(mdns_querier_t me)
{
	me->current_server = NULL;
	mdns_forget(&me->resolver);
	dispatch_forget(&me->user_queue);
	BlockForget(&me->handler);
	mdns_forget(&me->query);
	mdns_forget(&me->response);
	ForgetMem(&me->log_label);
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	mdns_forget(&me->test_query);
#endif
}

//======================================================================================================================

static char *
_mdns_querier_copy_description(mdns_querier_t me, const bool debug, const bool privacy)
{
	char *				description = NULL;
	char				buffer[128];
	char *				dst = buffer;
	const char * const	lim = &buffer[countof(buffer)];
	int					n;
	char				qname_str[kDNSServiceMaxDomainName];

	*dst = '\0';
	if (debug) {
		n = mdns_snprintf_add(&dst, lim, "<%s: %p>: ", me->base.kind->name, me);
		require_quiet(n >= 0, exit);
	}
	const char *qname;
	char strbuf[64];
	const uint8_t * const query_qname = mdns_query_message_get_qname(me->query);
	if (query_qname) {
		if (DomainNameToString(query_qname, NULL, qname_str, NULL) == kNoErr) {
			if (privacy) {
				n = DNSMessagePrintObfuscatedString(strbuf, sizeof(strbuf), qname_str);
				qname = (n >= 0) ? strbuf : "<REDACTED QNAME>";
			} else {
				qname = qname_str;
			}
		} else {
			qname = "<INVALID QNAME>";
		}
	} else {
		qname = "<NO QNAME>";
	}
	n = mdns_snprintf_add(&dst, lim, "%s", qname);
	require_quiet(n >= 0, exit);

	const char * const type_str = DNSRecordTypeValueToString(mdns_query_message_get_qtype(me->query));
	if (type_str) {
		n = mdns_snprintf_add(&dst, lim, " %s", type_str);
		require_quiet(n >= 0, exit);
	} else {
		n = mdns_snprintf_add(&dst, lim, " TYPE%u", mdns_query_message_get_qtype(me->query));
		require_quiet(n >= 0, exit);
	}
	if (mdns_query_message_get_qclass(me->query) == kDNSClassType_IN) {
		n = mdns_snprintf_add(&dst, lim, " IN");
		require_quiet(n >= 0, exit);
	} else {
		n = mdns_snprintf_add(&dst, lim, " CLASS%u", mdns_query_message_get_qclass(me->query));
		require_quiet(n >= 0, exit);
	}
	description = strdup(buffer);

exit:
	return description;
}

//======================================================================================================================

static void
_mdns_querier_activate(mdns_querier_t querier);

static void
_mdns_querier_activate_if_ready(mdns_querier_t me)
{
	if (me->user_activated && me->user_queue && mdns_query_message_get_qname(me->query)) {
		mdns_retain(me);
		dispatch_async(_mdns_resolver_queue(),
		^{
			_mdns_querier_activate(me);
			mdns_release(me);
		});
	}
}

static void
_mdns_querier_activate(mdns_querier_t me)
{
	require_return(!me->activated && !me->concluded);

	mdns_retain(me);
	me->activated = true;

	uint16_t msg_id;
	if (_mdns_resolver_needs_zero_ids(me->resolver)) {
		msg_id = 0;
	} else {
		msg_id = (uint16_t)RandomRange(1, UINT16_MAX);
	}
	mdns_query_message_set_message_id(me->query, msg_id);
	mdns_query_message_use_edns0_padding(me->query, _mdns_resolver_needs_edns0_padding(me->resolver) ? true : false);
	OSStatus err = mdns_query_message_construct(me->query);
	require_noerr_quiet(err, exit);

	if (me->time_limit_ms != 0) {
		err = _mdns_querier_reset_time_limit(me);
		require_noerr_quiet(err, exit);
	}
	_mdns_resolver_register_querier(me->resolver, me, false);

exit:
	if (err) {
		_mdns_querier_conclude(me, err);
	}
}

//======================================================================================================================

static void
_mdns_querier_session_handle_event(const mdns_session_t session, const mdns_session_event_t event,
	const OSStatus error, void * const context)
{
	mdns_querier_t const me = (mdns_querier_t)context;
	os_log_with_type(_mdns_resolver_log(),
		((event == mdns_session_event_terminated) && error) ? OS_LOG_TYPE_ERROR : OS_LOG_TYPE_INFO,
		"%{public}sQuerier session event -- type: %{public}s, error: %{mdns:err}ld",
		_mdns_querier_get_log_label(me), mdns_session_event_to_string(event), (long)error);

	switch (event) {
		case mdns_session_event_ready:
			_mdns_querier_send_query(me, session);
			break;

		case mdns_session_event_terminated: {
			const bool is_stream = _mdns_session_is_bytestream(session);
			mdns_session_t *ptr = is_stream ? &me->stream_session_list : &me->dgram_session_list;
			while (*ptr && (*ptr != session)) {
				ptr = &(*ptr)->next;
			}
			require_quiet(*ptr, exit);

			*ptr = session->next;
			session->next = NULL;
			mdns_session_t tmp = session;
			mdns_session_forget(&tmp);

			if (is_stream) {
				const mdns_server_t server = session->server;
				if (error || (session->receive_count == 0)) {
					_mdns_resolver_handle_stream_error(me->resolver, server, _mdns_querier_get_log_label(me));
					_mdns_resolver_penalize_server(me->resolver, server);
				}
				_mdns_querier_handle_stream_error(me, server);
			}
			break;
		}
		case mdns_session_event_lateness_warning:
			if (_mdns_session_is_bytestream(session)) {
				_mdns_resolver_handle_stream_lateness(me->resolver, session->server, session->start_ticks,
					_mdns_querier_get_log_label(me));
			}
			break;

		default:
			break;
	}

exit:
	return;
}

//======================================================================================================================

static bool
_mdns_querier_is_response_acceptable(const mdns_querier_t me, const mdns_message_t msg, bool * const out_truncated,
	bool * const out_suspicious, int * const out_rcode)
{
	bool id_match		= false;
	bool question_match	= false;
	bool acceptable		= false;
	const size_t msg_len = mdns_message_get_length(msg);
	require_quiet(msg_len >= kDNSHeaderLength, exit);

	uint16_t msg_id = 0;
	const uint8_t * const msg_ptr = mdns_message_get_byte_ptr(msg);
	question_match = _mdns_message_is_query_response_ignoring_id(msg_ptr, msg_len, me->query, &msg_id);
	require_quiet(question_match, exit);

	id_match = (msg_id == mdns_query_message_get_message_id(me->query)) ? true : false;
	if (id_match) {
		acceptable = true;
		const DNSHeader * const hdr = (const DNSHeader *)msg_ptr;
		const unsigned int flags = DNSHeaderGetFlags(hdr);
		if (out_truncated) {
			bool truncated = (flags & kDNSHeaderFlag_Truncation) ? true : false;
			if (truncated && !mdns_query_message_do_bit_is_set(me->query) && (DNSHeaderGetAnswerCount(hdr) > 0) &&
				((DNSHeaderGetAuthorityCount(hdr) > 0) || (DNSHeaderGetAdditionalCount(hdr) > 0))) {
				truncated = false;
			}
			*out_truncated = truncated;
		}
		if (out_rcode) {
			*out_rcode = DNSFlagsGetRCode(flags);
		}
	}

exit:
	if (out_suspicious) {
		*out_suspicious = (!id_match && question_match) ? true : false;
	}
	return acceptable;
}

//======================================================================================================================

static void
_mdns_querier_conclude(const mdns_querier_t me, const mdns_querier_result_type_t result_type)
{
	_mdns_querier_conclude_ex(me, result_type, 0, NULL);
}

//======================================================================================================================

static void
_mdns_querier_conclude_async(const mdns_querier_t me, const mdns_querier_result_type_t result_type)
{
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_querier_conclude(me, result_type);
		mdns_release(me);
	});
}

//======================================================================================================================

static void
_mdns_querier_conclude_with_error(const mdns_querier_t me, const OSStatus error)
{
	_mdns_querier_conclude_ex(me, mdns_querier_result_type_error, error, NULL);
}

//======================================================================================================================

static void
_mdns_querier_conclude_with_error_async(const mdns_querier_t me, const OSStatus error)
{
	mdns_retain(me);
	dispatch_async(_mdns_resolver_queue(),
	^{
		_mdns_querier_conclude_with_error(me, error);
		mdns_release(me);
	});
}

//======================================================================================================================

static void
_mdns_querier_conclude_with_response(const mdns_querier_t me, const mdns_message_t response)
{
	_mdns_querier_conclude_ex(me, mdns_querier_result_type_response, 0, response);
}

//======================================================================================================================

#define MDNS_QUERIER_RESPONSE_STATUS_FABRICATED	1

static void
_mdns_querier_conclude_with_response_async(const mdns_querier_t me, const mdns_message_t response,
	const bool fabricated)
{
	mdns_retain(me);
	mdns_retain(response);
	dispatch_async(_mdns_resolver_queue(),
	^{
		const OSStatus status = fabricated ? MDNS_QUERIER_RESPONSE_STATUS_FABRICATED : 0;
		_mdns_querier_conclude_ex(me, mdns_querier_result_type_response, status, response);
		mdns_release(me);
		mdns_release(response);
	});
}

//======================================================================================================================

static bool
_mdns_querier_postprocess_response(mdns_querier_t querier);

static void
_mdns_querier_conclude_ex(const mdns_querier_t me, const mdns_querier_result_type_t result_type, const OSStatus status,
	const mdns_message_t response)
{
	dispatch_source_forget(&me->rtx_timer);
	dispatch_source_forget(&me->timeout_timer);
	mdns_forget(&me->bad_rcode_response);

	_mdns_resolver_deregister_querier(me->resolver, me);
	require_return(!me->concluded);

	me->concluded = true;
	switch (result_type) {
		case mdns_querier_result_type_response: {
			mdns_replace(&me->response, response);
			const bool fabricated = _mdns_querier_postprocess_response(me);
			me->response_is_fabricated = fabricated || (status == MDNS_QUERIER_RESPONSE_STATUS_FABRICATED);
			if (me->response_is_fabricated) {
				os_log_info(_mdns_resolver_log(),
					"%{public}sQuerier concluded -- reason: response (fabricated)", _mdns_querier_get_log_label(me));
			} else {
				os_log_info(_mdns_resolver_log(),
					"%{public}sQuerier concluded -- reason: response", _mdns_querier_get_log_label(me));
			}
			break;
		}
		case mdns_querier_result_type_timeout:
			os_log_info(_mdns_resolver_log(),
				"%{public}sQuerier concluded -- reason: timeout", _mdns_querier_get_log_label(me));
			break;

		case mdns_querier_result_type_invalidation:
			os_log_info(_mdns_resolver_log(),
				"%{public}sQuerier concluded -- reason: invalidation", _mdns_querier_get_log_label(me));
			break;

		case mdns_querier_result_type_resolver_invalidation:
			os_log_info(_mdns_resolver_log(),
				"%{public}sQuerier concluded -- reason: resolver invalidation", _mdns_querier_get_log_label(me));
			break;

		case mdns_querier_result_type_error:
			me->error = status;
			os_log_error(_mdns_resolver_log(),
				"%{public}sQuerier concluded -- error: %{mdns:err}ld",
				_mdns_querier_get_log_label(me), (long)me->error);
			break;

		case mdns_querier_result_type_null:
			break;
	}
	if (me->user_queue) {
		const mdns_querier_result_handler_t handler = me->handler;
		me->handler = NULL;
		mdns_retain(me);
		dispatch_async(me->user_queue,
		^{
			me->result_type = result_type;
			if (handler) {
				handler();
				Block_release(handler);
			}
			mdns_release(me);
		});
	}
	if (me->activated) {
		mdns_release(me);
	}
}

static bool
_mdns_querier_postprocess_response(const mdns_querier_t me)
{
	if (!me->resolver->squash_cnames) {
		return false;
	}
	const uint8_t *resp_ptr = _mdns_querier_get_response_ptr_safe(me);
	require_return_value(resp_ptr, false);

	mdns_message_t new_msg = NULL;
	OSStatus err;
	size_t new_len;
	uint8_t *new_ptr = DNSMessageCollapse(resp_ptr, _mdns_querier_get_response_length_safe(me), &new_len, &err);
	if (new_ptr) {
		dispatch_data_t data = dispatch_data_create(new_ptr, new_len, NULL, DISPATCH_DATA_DESTRUCTOR_FREE);
		if (data) {
			new_ptr = NULL;
			new_msg = mdns_message_create_with_dispatch_data(data, mdns_message_init_option_disable_header_printing);
			dispatch_forget(&data);
			if (!new_msg) {
				err = kNoResourcesErr;
			}
		} else {
			ForgetMem(&new_ptr);
			err = kNoResourcesErr;
		}
	}
	bool fabricated;
	if (new_msg) {
		mdns_replace(&me->response, new_msg);
		mdns_forget(&new_msg);
		resp_ptr = _mdns_querier_get_response_ptr_safe(me);
		size_t resp_len = _mdns_querier_get_response_length_safe(me);
		os_log(_mdns_resolver_log(),
			"%{public}sUsing squashed response -- %{public,mdns:dnshdr}.*P, %@",
			_mdns_querier_get_log_label(me), (int)Min(resp_len, kDNSHeaderLength), resp_ptr, me->response);
		fabricated = true;
	} else {
		os_log_error(_mdns_resolver_log(),
			"%{public}sFailed to squash response -- error:%{mdns:err}ld",
			_mdns_querier_get_log_label(me), (long)err);
		fabricated = false;
	}
	return fabricated;
}

//======================================================================================================================

static void
_mdns_querier_reregister_in_stream_mode(mdns_querier_t querier);

static void
_mdns_querier_session_receive(const mdns_session_t session, const dispatch_data_t msg_data, void * const context)
{
	const mdns_querier_t me = (mdns_querier_t)context;
	const mdns_message_t msg = mdns_message_create_with_dispatch_data(msg_data,
		mdns_message_init_option_disable_header_printing);
	require_return_action(msg, _mdns_querier_conclude_with_error(me, kNoResourcesErr));

	bool truncated	= false;
	bool suspicious	= false;
	const bool is_dgram = !_mdns_session_is_bytestream(session);
	bool * const truncated_ptr = is_dgram ? &truncated : NULL;
	const bool need_suspicious_reply_defense = _mdns_resolver_needs_suspicious_reply_defense(me->resolver);
	bool * const suspicious_ptr = (need_suspicious_reply_defense && is_dgram) ? &suspicious : NULL;
	int rcode = 0;
	const bool acceptable = _mdns_querier_is_response_acceptable(me, msg, truncated_ptr, suspicious_ptr, &rcode);
	_mdns_resolver_log_receive(me->resolver, session, msg, acceptable, _mdns_querier_get_log_label(me));
	const mdns_server_t server = session->server;
	if (acceptable) {
		_mdns_resolver_note_responsiveness(me->resolver, server, !is_dgram, session->start_ticks,
			mdns_querier_get_qtype(me));
		if (_mdns_rcode_is_good(rcode)) {
			if (is_dgram && truncated) {
				me->over_tcp_reason = mdns_query_over_tcp_reason_truncation;
				_mdns_querier_reregister_in_stream_mode(me);
			} else {
				_mdns_querier_conclude_with_response(me, msg);
			}
		} else {
			// Note: _mdns_querier_handle_bad_rcode() may or may not conclude the querier.
			_mdns_querier_handle_bad_rcode(me, msg, rcode, server);
		}
	} else if (is_dgram && need_suspicious_reply_defense && suspicious) {
		me->over_tcp_reason = mdns_query_over_tcp_reason_got_suspicious_reply;
		_mdns_resolver_got_suspicious_reply(me->resolver);
		_mdns_querier_reregister_in_stream_mode(me);
#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	} else {
		bool handled_response = false;
	#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
		if (_mdns_resolver_use_problematic_qtype_workaround(me->resolver)) {
			if (me->test_query && _mdns_message_is_adequate_test_query_response(msg, me->test_query)) {
				_mdns_querier_set_test_query_got_response(me, server, true);
				_mdns_resolver_note_responsiveness(me->resolver, server, !is_dgram, session->start_ticks,
					mdns_query_message_get_qtype(me->test_query));
				handled_response = true;
			}
		}
	#endif
	#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
		if (!handled_response && _mdns_resolver_use_mixed_up_responses_workaround(me->resolver)) {
			if (!server->mixes_up_responses) {
				qtype_test_f qtype_test = NULL;
				const int qtype = mdns_querier_get_qtype(me);
				if (_mdns_qtype_is_address_type(qtype)) {
					qtype_test = _mdns_qtype_is_problematic;
				} else if (_mdns_qtype_is_problematic(qtype)) {
					qtype_test = _mdns_qtype_is_address_type;
				}
				if (qtype_test) {
					uint16_t msg_qtype = 0;
					if (_mdns_message_is_query_response_ignoring_qtype(msg, me->query, &msg_qtype)) {
						if (qtype_test(msg_qtype)) {
							server->mixes_up_responses = true;
						}
					}
				}
			}
		}
	#else
		(void)handled_response;
	#endif
#endif
	}
	mdns_release(msg);
}

static void
_mdns_querier_reregister_in_stream_mode(mdns_querier_t me)
{
	_mdns_resolver_deregister_querier(me->resolver, me);
	_mdns_resolver_register_querier(me->resolver, me, true);
}

//======================================================================================================================

static mdns_session_t
_mdns_querier_get_shared_session(mdns_querier_t querier);

static mdns_session_t
_mdns_querier_get_unshared_session(mdns_querier_t querier);

static void
_mdns_querier_initiate_send(const mdns_querier_t me)
{
	dispatch_source_forget(&me->rtx_timer);
	do {
		if (!me->current_server) {
			if (me->bad_rcode_response && !_mdns_resolver_get_server(me->resolver, me->bad_rcode_bitmap)) {
				const bool fabricated = (me->bad_rcode < 0) ? true : false;
				_mdns_querier_conclude_with_response_async(me, me->bad_rcode_response, fabricated);
				return;
			}
			_mdns_querier_set_current_server(me, _mdns_querier_get_eligible_server(me));
			if (!me->current_server) {
				os_log_debug(_mdns_resolver_log(),
					"%{public}sNo more eligible servers", _mdns_querier_get_log_label(me));
				return;
			}
		}
	#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
		bool check_qtype_support = false;
		if (0) {
	#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
		} else if (_mdns_resolver_use_mixed_up_responses_workaround(me->resolver)) {
			check_qtype_support = true;
	#endif
	#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
		} else if (_mdns_resolver_use_problematic_qtype_workaround(me->resolver)) {
			check_qtype_support = true;
	#endif
		}
		if (check_qtype_support) {
			const mdns_server_t server = me->current_server;
			const int qtype = mdns_querier_get_qtype(me);
			if (!_mdns_server_supports_qtype(server, qtype)) {
				if (0) {
			#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
				} else if (server->mixes_up_responses) {
					os_log_info(_mdns_resolver_log(),
						"%{public}sNot sending query to server %@, which mixes up responses of type %{mdns:rrtype}d",
						_mdns_querier_get_log_label(me), server, qtype);
			#endif
				} else {
					os_log_info(_mdns_resolver_log(),
						"%{public}sNot sending query to server %@, which ignores queries of type %{mdns:rrtype}d",
						_mdns_querier_get_log_label(me), server, qtype);
				}
				if (!me->bad_rcode_response) {
					OSStatus err;
					const int rcode = kDNSRCode_NotImp;
					me->bad_rcode_response = _mdns_create_empty_response_for_query(me->query, rcode, &err);
					require_return_action(me->bad_rcode_response, _mdns_querier_conclude_with_error_async(me, err));
					me->bad_rcode = -rcode;
				}
				me->bad_rcode_bitmap |= _mdns_rank_to_bitmask(server->rank);
				_mdns_querier_set_current_server(me, NULL);
			}
		}
	#endif // MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	} while (!me->current_server);

	me->rtx_timer = _mdns_resolver_create_oneshot_timer(me->rtx_interval_ms, 5);
	require_return_action(me->rtx_timer, _mdns_querier_conclude_with_error_async(me, kNoResourcesErr));

	dispatch_source_set_event_handler(me->rtx_timer,
	^{
		dispatch_source_forget(&me->rtx_timer);
		_mdns_querier_handle_no_response(me);
	});
	dispatch_activate(me->rtx_timer);

	mdns_session_t session;
	if (me->use_shared_stream) {
		session = _mdns_querier_get_shared_session(me);
	} else {
		session = _mdns_querier_get_unshared_session(me);
	}
	if (session) {
		_mdns_querier_send_query(me, session);
	}
}

#define MDNS_RESOLVER_STREAM_LATENESS_TIME_MS	(10 * kMillisecondsPerSecond)

static mdns_session_t
_mdns_querier_get_shared_session(const mdns_querier_t me)
{
	require_return_value(me->current_server, NULL);

	const mdns_server_t server = me->current_server;
	mdns_session_t session = server->shared_stream_session;
	if (!session) {
		os_log_debug(_mdns_resolver_log(),
			"%{public}sCreating shared session to %@", _mdns_querier_get_log_label(me), server);
		OSStatus err;
		session = _mdns_resolver_create_session(me->resolver, server, true, NULL, NULL, &err);
		if (likely(session)) {
			static const mdns_session_callbacks_t s_resolver_callbacks = {
				.handle_event		= _mdns_resolver_session_handle_event,
				.receive			= _mdns_resolver_session_receive,
				.finalize_context	= _mdns_session_finalize_context_with_release
			};
			mdns_retain(me->resolver);
			_mdns_session_set_callbacks(session, &s_resolver_callbacks, me->resolver);
			_mdns_session_set_lateness_time(session, MDNS_RESOLVER_STREAM_LATENESS_TIME_MS);
			_mdns_session_activate(session);
			server->shared_stream_session = session;
		} else {
			os_log_error(_mdns_resolver_log(),
				"Failed to create session to %@ for resolver: %{mdns:err}ld", server, (long)err);
			_mdns_resolver_penalize_server(me->resolver, server);
			_mdns_querier_set_current_server(me, NULL);
		}
	}
	return session;
}

static mdns_session_t
_mdns_querier_get_unshared_session(const mdns_querier_t me)
{
	require_return_value(me->current_server, NULL);

	const mdns_server_t server = me->current_server;
	mdns_session_t session;
	mdns_session_t *ptr = me->use_stream ? &me->stream_session_list : &me->dgram_session_list;
	while ((session = *ptr) != NULL) {
		if (session->server == server) {
			break;
		}
		ptr = &session->next;
	}
	if (!session) {
		os_log_debug(_mdns_resolver_log(),
			"%{public}sCreating session to %@", _mdns_querier_get_log_label(me), server);
		OSStatus err;
		session = _mdns_resolver_create_session(me->resolver, server, me->use_stream, &me->delegation,
			mdns_query_message_get_qname(me->query), &err);
		if (likely(session)) {
			static const mdns_session_callbacks_t s_querier_callbacks = {
				.handle_event		= _mdns_querier_session_handle_event,
				.receive			= _mdns_querier_session_receive,
				.finalize_context	= _mdns_session_finalize_context_with_release
			};
			mdns_retain(me);
			_mdns_session_set_callbacks(session, &s_querier_callbacks, me);
			if (me->use_stream) {
				_mdns_session_set_lateness_time(session, MDNS_RESOLVER_STREAM_LATENESS_TIME_MS);
			}
			_mdns_session_activate(session);
			*ptr = session;
		} else {
			os_log_error(_mdns_resolver_log(),
				"Failed to create session to %@ for querier: %{mdns:err}ld", server, (long)err);
			_mdns_resolver_penalize_server(me->resolver, server);
			_mdns_querier_set_current_server(me, NULL);
		}
	}
	return session;
}

//======================================================================================================================

static void
_mdns_querier_start(const mdns_querier_t me)
{
	_mdns_querier_set_current_server(me, NULL);
	if (me->use_stream) {
		me->rtx_interval_ms = MDNS_RESOLVER_CONNECTION_TIMEOUT_MS;
	} else {
		me->rtx_interval_ms = me->resolver->initial_dgram_rtx_ms;
	}
	_mdns_querier_initiate_send(me);
}

//======================================================================================================================

static void
_mdns_querier_send_query_immediate(mdns_querier_t querier, mdns_session_t session);

static void
_mdns_querier_log_query_send(mdns_querier_t querier, mdns_session_t session);

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static void
_mdns_querier_log_test_query_send(mdns_querier_t querier, mdns_session_t session);

static bool
_mdns_querier_needs_test_query(mdns_querier_t querier, mdns_server_t server);
#endif

static void
_mdns_querier_send_query(const mdns_querier_t me, const mdns_session_t session)
{
	const uint32_t bitmask = _mdns_rank_to_bitmask(session->server->rank);
	if (_mdns_session_is_ready(session)) {
		me->will_send_bitmap &= ~bitmask;
		if (_mdns_session_is_bytestream(session)) {
			if ((me->did_send_bitmap & bitmask) == 0) {
				_mdns_querier_send_query_immediate(me, session);
				me->did_send_bitmap |= bitmask;
			}
		} else {
			_mdns_querier_send_query_immediate(me, session);
			me->did_send_bitmap |= bitmask;
		}
	} else {
		me->will_send_bitmap |= bitmask;
	}
}

static void
_mdns_querier_send_query_immediate(const mdns_querier_t me, const mdns_session_t session)
{
	const uint16_t qtype = mdns_query_message_get_qtype(me->query);
	_mdns_session_send(session, mdns_message_get_dispatch_data(me->query), qtype);
	atomic_fetch_add(&me->send_count, 1);
	_mdns_querier_log_query_send(me, session);
#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	if (_mdns_resolver_use_problematic_qtype_workaround(me->resolver)) {
		const mdns_server_t server = session->server;
		if (_mdns_querier_needs_test_query(me, server)) {
			if (!me->test_query) {
				me->test_query = _mdns_create_simple_test_query(me->query, _mdns_server_get_test_query_qtype(server));
			}
			if (me->test_query) {
				_mdns_session_send(session, mdns_message_get_dispatch_data(me->test_query),
					mdns_query_message_get_qtype(me->test_query));
				++me->test_send_count;
				_mdns_querier_log_test_query_send(me, session);
			} else {
				os_log_error(_mdns_resolver_log(),
					"%{public}sFailed to create test query", _mdns_querier_get_log_label(me));
			}
		}
	}
#endif
}

static void
_mdns_querier_log_query_send(const mdns_querier_t me, const mdns_session_t session)
{
	const size_t query_len = mdns_message_get_length(me->query);
	os_log(_mdns_resolver_log(),
		"%{public}sSent %zu-byte query #%u to %@ over %{public}s via %{public}s -- %{public,mdns:dnshdr}.*P, %@",
		_mdns_querier_get_log_label(me),
		query_len,
		me->send_count,
		session->server,
		_mdns_resolver_get_protocol_log_string(me->resolver, _mdns_session_is_bytestream(session)),
		_mdns_resolver_get_interface_log_string(me->resolver),
		(int)Min(query_len, kDNSHeaderLength), mdns_message_get_byte_ptr(me->query),
		me->query);
}

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static void
_mdns_querier_log_test_query_send(const mdns_querier_t me, const mdns_session_t session)
{
	require_return(me->test_query);
	const size_t query_len = mdns_message_get_length(me->test_query);
	os_log(_mdns_resolver_log(),
		"%{public}sSent %zu-byte test query #%u to %@ over %{public}s via %{public}s -- %{public,mdns:dnshdr}.*P, %@",
		_mdns_querier_get_log_label(me),
		query_len,
		me->test_send_count,
		session->server,
		_mdns_resolver_get_protocol_log_string(me->resolver, _mdns_session_is_bytestream(session)),
		_mdns_resolver_get_interface_log_string(me->resolver),
		(int)Min(query_len, kDNSHeaderLength), mdns_message_get_byte_ptr(me->test_query),
		me->test_query);
}

static bool
_mdns_querier_needs_test_query(const mdns_querier_t me, const mdns_server_t server)
{
	if (server->responds_to_problematics) {
		return false;
	}
	const int qtype = mdns_query_message_get_qtype(me->query);
	if (!_mdns_qtype_is_problematic(qtype)) {
		return false;
	}
	if (_mdns_querier_test_query_got_response(me, server)) {
		return false;
	}
	if (server->pqw_info && !_pqw_info_can_accept_qname(server->pqw_info, mdns_query_message_get_qname(me->query))) {
		return false;
	}
	return true;
}
#endif

//======================================================================================================================

static const char *
_mdns_querier_get_log_label(const mdns_querier_t me)
{
	return (me->log_label ? me->log_label : "");
}

//======================================================================================================================

static OSStatus
_mdns_querier_reset_time_limit(const mdns_querier_t me)
{
	OSStatus err;
	require_action_quiet(!me->concluded && me->activated, exit, err = kNoErr);

	os_log_info(_mdns_resolver_log(),
		"%{public}sResetting time limit to %ld ms", _mdns_querier_get_log_label(me), (long)me->time_limit_ms);
	dispatch_source_forget(&me->timeout_timer);
	require_action_quiet(me->time_limit_ms >= 0, exit, err = kTimeoutErr);

	if (me->time_limit_ms > 0) {
		me->timeout_timer = _mdns_resolver_create_oneshot_timer((uint32_t)me->time_limit_ms, 5);
		require_action_quiet(me->timeout_timer, exit, err = kNoResourcesErr);

		dispatch_source_set_event_handler(me->timeout_timer,
		^{
			_mdns_querier_conclude(me, mdns_querier_result_type_timeout);
		});
		dispatch_activate(me->timeout_timer);
	}
	err = kNoErr;

exit:
	return err;
}

//======================================================================================================================

#define MDNS_QUERIER_UNANSWERED_QUERY_COUNT_MAX	2
#define MDNS_QUERIER_RTX_INTERVAL_MAX_MS		(120 * kMillisecondsPerSecond)

static void
_mdns_querier_handle_no_response(const mdns_querier_t me)
{
	if (me->current_server) {
		if (me->use_stream) {
			_mdns_resolver_penalize_server(me->resolver, me->current_server);
			_mdns_querier_set_current_server(me, NULL);
		} else {
			++me->unanswered_query_count;
			if (me->rtx_interval_ms <= (MDNS_QUERIER_RTX_INTERVAL_MAX_MS / 2)) {
				me->rtx_interval_ms *= 2;
			} else {
				me->rtx_interval_ms = MDNS_QUERIER_RTX_INTERVAL_MAX_MS;
			}
			if (me->unanswered_query_count >= MDNS_QUERIER_UNANSWERED_QUERY_COUNT_MAX) {
				mdns_session_t session = me->dgram_session_list;
				while (session && (session->server != me->current_server)) {
					session = session->next;
				}
				if (session) {
					const mdns_server_t server = me->current_server;
					_mdns_resolver_penalize_unresponsive_server(me->resolver, server, me, session->last_send_ticks);
				#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
					_mdns_querier_set_test_query_got_response(me, server, false);
				#endif
				}
				_mdns_querier_set_current_server(me, NULL);
			}
		}
	}
	_mdns_querier_initiate_send(me);
}

//======================================================================================================================

static void
_mdns_querier_set_current_server(const mdns_querier_t me, const mdns_server_t server)
{
	me->current_server = server;
	me->unanswered_query_count = 0;
	if (!me->use_stream && me->current_server) {
		const uint32_t bitmask = _mdns_rank_to_bitmask(me->current_server->rank);
		if ((me->did_send_bitmap & bitmask) == 0) {
			me->rtx_interval_ms = me->resolver->initial_dgram_rtx_ms;
		}
	}
}

//======================================================================================================================

static mdns_server_t
_mdns_querier_get_eligible_server(const mdns_querier_t me)
{
	uint32_t exclude_bitmap = me->bad_rcode_bitmap;
	if (me->use_stream) {
		exclude_bitmap |= me->will_send_bitmap;
		exclude_bitmap |= me->did_send_bitmap;
	}
	mdns_server_t server = _mdns_resolver_get_server(me->resolver, exclude_bitmap);
	if (server && me->resolver->probe_querier && (me != me->resolver->probe_querier)) {
		os_log(_mdns_resolver_log(),
			"%{public}sBacking off while probe querier is active", _mdns_querier_get_log_label(me));
		server = NULL;
	}
	return server;
}

//======================================================================================================================

static mdns_server_t
_mdns_querier_get_unpenalized_eligible_server(const mdns_querier_t me)
{
	const mdns_server_t server = _mdns_querier_get_eligible_server(me);
	return ((server && !server->penalized) ? server : NULL);
}

//======================================================================================================================

static void
_mdns_querier_handle_stream_error(const mdns_querier_t me, const mdns_server_t server)
{
	const uint32_t bitmask = _mdns_rank_to_bitmask(server->rank);
	me->will_send_bitmap &= ~bitmask;
	me->did_send_bitmap	 &= ~bitmask;
	if (me->current_server == server) {
		_mdns_querier_set_current_server(me, _mdns_querier_get_unpenalized_eligible_server(me));
		if (me->current_server) {
			_mdns_querier_initiate_send(me);
		}
	} else if (!me->current_server && !me->rtx_timer) {
		_mdns_querier_initiate_send(me);
	}
}

//======================================================================================================================

static void
_mdns_querier_handle_bad_rcode(const mdns_querier_t me, const mdns_message_t response, const int rcode,
	const mdns_server_t server)
{
	me->bad_rcode_bitmap |= _mdns_rank_to_bitmask(server->rank);
#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
	if (me->bad_rcode < 0) {
		mdns_forget(&me->bad_rcode_response);
		me->bad_rcode = 0;
	}
#endif
	// Save the response if it's the first bad RCODE response that's been received.
	// Only replace the saved bad RCODE response if its RCODE is Refused and the newer response's RCODE is not
	// Refused. This way, if there's a server that consistently returns Refused, its responses won't mask a bad
	// RCODE response with a potentially more informative RCODE.
	if (!me->bad_rcode_response || ((me->bad_rcode == kDNSRCode_Refused) && (rcode != kDNSRCode_Refused))) {
		mdns_replace(&me->bad_rcode_response, response);
		me->bad_rcode = rcode;
	}
	if (rcode == kDNSRCode_Refused) {
		_mdns_resolver_penalize_server(me->resolver, server);
	}
	// If there are any servers that haven't returned a bad RCODE, then move on to the next server.
	// Otherwise, conclude with the saved bad RCODE response.
	if (_mdns_resolver_get_server(me->resolver, me->bad_rcode_bitmap)) {
		if (me->current_server == server) {
			_mdns_querier_set_current_server(me, NULL);
			_mdns_querier_initiate_send(me);
		}
	} else {
		const mdns_message_t bad_rcode_response = me->bad_rcode_response;
		me->bad_rcode_response = NULL;
		_mdns_querier_conclude_with_response(me, bad_rcode_response);
		mdns_release(bad_rcode_response);
	}
}

//======================================================================================================================

static const uint8_t *
_mdns_querier_get_response_ptr_safe(const mdns_querier_t me)
{
	return (me->response ? mdns_message_get_byte_ptr(me->response) : NULL);
}

//======================================================================================================================

static size_t
_mdns_querier_get_response_length_safe(const mdns_querier_t me)
{
	return (me->response ? mdns_message_get_length(me->response) : 0);
}

//======================================================================================================================

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static void
_mdns_querier_set_test_query_got_response(const mdns_querier_t me, const mdns_server_t server, const bool got_response)
{
	const uint32_t bitmask = _mdns_rank_to_bitmask(server->rank);
	if (got_response) {
		me->test_query_resp_bitmap |= bitmask;
	} else {
		me->test_query_resp_bitmap &= ~bitmask;
	}
}

//======================================================================================================================

static bool
_mdns_querier_test_query_got_response(const mdns_querier_t me, const mdns_server_t server)
{
	return ((me->test_query_resp_bitmap & _mdns_rank_to_bitmask(server->rank)) ? true : false);
}
#endif

//======================================================================================================================
// MARK: - Helper Functions

static dispatch_queue_t
_mdns_resolver_queue(void)
{
	static dispatch_once_t	s_once	= 0;
	static dispatch_queue_t	s_queue	= NULL;

	dispatch_once(&s_once,
	^{
		s_queue = dispatch_queue_create("com.apple.mdns.resolver-queue", DISPATCH_QUEUE_SERIAL);
		http_set_resolver_queue(s_queue);
	});
	return s_queue;
}

//======================================================================================================================

static bool
_mdns_message_is_query_response_ignoring_id(const uint8_t * const msg_ptr, const size_t msg_len,
	const mdns_query_message_t query, uint16_t *out_id)
{
	uint16_t tmp_id = 0;
	return _mdns_message_is_query_response_ex(msg_ptr, msg_len, query, out_id ? out_id : &tmp_id, NULL, false);
}

//======================================================================================================================

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
static bool
_mdns_message_is_query_response_ignoring_qtype(const mdns_message_t msg, const mdns_query_message_t query,
	uint16_t * const out_qtype)
{
	uint16_t tmp_qtype = 0;
	return _mdns_message_is_query_response_ex(mdns_message_get_byte_ptr(msg), mdns_message_get_length(msg), query,
		NULL, out_qtype ? out_qtype : &tmp_qtype, false);
}
#endif

//======================================================================================================================

static bool
_mdns_message_is_query_response_ex(const uint8_t * const msg_ptr, const size_t msg_len,
	const mdns_query_message_t query, uint16_t * const out_id, uint16_t * const out_qtype, const bool ignore_qnames)
{
	require_return_value(msg_len >= kDNSHeaderLength, false);

	const DNSHeader * const hdr = (const DNSHeader *)msg_ptr;
	const uint16_t msg_id = DNSHeaderGetID(hdr);
	require_return_value(out_id || (msg_id == mdns_query_message_get_message_id(query)), false);

	const unsigned int flags = DNSHeaderGetFlags(hdr);
	require_return_value(flags & kDNSHeaderFlag_Response, false);
	require_return_value(DNSFlagsGetOpCode(flags) == kDNSOpCode_Query, false);
	require_return_value(DNSHeaderGetQuestionCount(hdr) == 1, false);

	uint16_t qtype, qclass;
	uint8_t qname[kDomainNameLengthMax];
	const uint8_t * const qptr = (const uint8_t *)&hdr[1];
	const OSStatus err = DNSMessageExtractQuestion(msg_ptr, msg_len, qptr, qname, &qtype, &qclass, NULL);
	require_return_value(!err, false);
	require_return_value(ignore_qnames || DomainNameEqual(qname, mdns_query_message_get_qname(query)), false);
	require_return_value(out_qtype || (qtype == mdns_query_message_get_qtype(query)), false);
	require_return_value(qclass == mdns_query_message_get_qclass(query), false);
	if (out_id) {
		*out_id = msg_id;
	}
	if (out_qtype) {
		*out_qtype = qtype;
	}
	return true;
}

//======================================================================================================================

static nw_parameters_t
_mdns_create_udp_parameters(OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = nw_parameters_create_secure_udp(NW_PARAMETERS_DISABLE_PROTOCOL,
		NW_PARAMETERS_DEFAULT_CONFIGURATION);
	require_action_quiet(params, exit, err = kNoResourcesErr);

	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return params;
}

//======================================================================================================================

static nw_parameters_t
_mdns_create_tcp_parameters(OSStatus *out_error)
{
	OSStatus err;
	nw_parameters_t params = nw_parameters_create_secure_tcp(NW_PARAMETERS_DISABLE_PROTOCOL,
		NW_PARAMETERS_DEFAULT_CONFIGURATION);
	require_action_quiet(params, exit, err = kNoResourcesErr);

	nw_parameters_set_indefinite(params, false);

	err = _mdns_add_dns_over_bytestream_framer(params);
	require_noerr_quiet(err, exit);

exit:
	if (err) {
		nw_forget(&params);
	}
	if (out_error) {
		*out_error = err;
	}
	return params;
}

//======================================================================================================================

static nw_protocol_definition_t
_mdns_copy_dns_over_bytestream_framer(void);

static OSStatus
_mdns_add_dns_over_bytestream_framer(nw_parameters_t params)
{
	OSStatus					err;
	nw_protocol_definition_t	framer_def	= NULL;
	nw_protocol_options_t		framer_opts	= NULL;

	nw_protocol_stack_t stack = nw_parameters_copy_default_protocol_stack(params);
	require_action_quiet(stack, exit, err = kNoResourcesErr);

	framer_def = _mdns_copy_dns_over_bytestream_framer();
	require_action_quiet(framer_def, exit, err = kNoResourcesErr);

	framer_opts = nw_framer_create_options(framer_def);
	require_action_quiet(framer_opts, exit, err = kNoResourcesErr);

	nw_protocol_stack_prepend_application_protocol(stack, framer_opts);
	err = kNoErr;

exit:
	nw_release_null_safe(stack);
	nw_release_null_safe(framer_def);
	nw_release_null_safe(framer_opts);
	return err;
}

static nw_protocol_definition_t
_mdns_create_dns_over_bytestream_framer(void);

static nw_protocol_definition_t
_mdns_copy_dns_over_bytestream_framer(void)
{
	static dispatch_once_t			s_once = 0;
	static nw_protocol_definition_t	s_framer_def = NULL;

	dispatch_once(&s_once,
	^{
		s_framer_def = _mdns_create_dns_over_bytestream_framer();
	});
	if (likely(s_framer_def)) {
		nw_retain(s_framer_def);
	}
	return s_framer_def;
}

static nw_protocol_definition_t
_mdns_create_dns_over_bytestream_framer(void)
{
	static const nw_framer_input_handler_t input_handler =
	^ size_t (nw_framer_t framer)
	{
		for (;;) {
			uint8_t length_buf[2];
			bool ok = nw_framer_parse_input(framer, sizeof(length_buf), sizeof(length_buf), length_buf,
			^ size_t (__unused uint8_t *buf_ptr, size_t buf_len, __unused bool is_complete)
			{
				return ((buf_len >= sizeof(length_buf)) ? sizeof(length_buf) : 0);
			});
			if (!ok) {
				return sizeof(length_buf);
			}
			const size_t msg_len = ReadBig16(length_buf);
			nw_framer_message_t msg = nw_framer_message_create(framer);
			ok = nw_framer_deliver_input_no_copy(framer, msg_len, msg, true);
			nw_release(msg);
			if (!ok) {
				return sizeof(length_buf);
			}
		}
	};
	static const nw_framer_output_handler_t output_handler =
	^(nw_framer_t framer, __unused nw_framer_message_t msg, size_t msg_len, __unused bool is_complete)
	{
		if (msg_len > UINT16_MAX) {
			nw_framer_mark_failed_with_error(framer, EMSGSIZE);
			return;
		}
		uint8_t length_buf[2];
		WriteBig16(length_buf, msg_len);
		nw_framer_write_output(framer, length_buf, sizeof(length_buf));
		nw_framer_write_output_no_copy(framer, msg_len);
	};
	nw_protocol_definition_t framer_def = nw_framer_create_definition("DNS over byte-stream",
		NW_FRAMER_CREATE_FLAGS_DEFAULT,
	^ nw_framer_start_result_t (nw_framer_t framer)
	{
		nw_framer_set_input_handler(framer, input_handler);
		nw_framer_set_output_handler(framer, output_handler);
		return nw_framer_start_result_ready;
	});
	return framer_def;
}

//======================================================================================================================

static uint64_t
_mdns_ticks_per_second(void)
{
	return mdns_mach_ticks_per_second();
}

//======================================================================================================================

static bool
_mdns_path_to_server_is_usable(const nw_path_t path, bool encrypted_resolver)
{
	const nw_path_status_t status = nw_path_get_status(path);
	if ((status == nw_path_status_satisfied) || (status == nw_path_status_satisfiable)) {
		return true;
	} else if (nw_path_is_per_app_vpn(path)) {
		// For Per-App VPN, assume that the path to the server is usable since such paths will only have a
		// satisfied status if the right per-app parameters are provided to the path evaluator. For VPNs, it's
		// very likely that the DNS server addresses provided by the VPN configuration are reachable, if not, then
		// the server penalization logic will kick in to favor reachable server addresses over unreachable ones.
		return true;
	} else {
		// For encrypted resolvers, it is possible to use unencrypted resolvers to synthesize IPv4 addresses
		// on NAT64 networks.
		bool nat64_eligible = false;
		if (encrypted_resolver && nw_path_has_dns(path)) {
			nw_endpoint_t endpoint = nw_path_copy_endpoint(path);
			if (endpoint != NULL && nw_endpoint_get_type(endpoint) == nw_endpoint_type_address) {
				const struct sockaddr *address = nw_endpoint_get_address(endpoint);
				if (address != NULL && address->sa_family == AF_INET) {
					nat64_eligible = true;
				}
			}
			nw_forget(&endpoint);
		}

		return nat64_eligible;
	}
}

//======================================================================================================================

static uint32_t
_mdns_rank_to_bitmask(const unsigned int rank)
{
	if ((rank >= 1) && (rank <= 32)) {
		return (UINT32_C(1) << (rank - 1));
	} else {
		return 0;
	}
}

//======================================================================================================================

static const char *
mdns_session_event_to_string(const mdns_session_event_t event)
{
	switch (event) {
		case mdns_session_event_null:				return "null";
		case mdns_session_event_ready:				return "ready";
		case mdns_session_event_lateness_warning:	return "lateness-warning";
		case mdns_session_event_terminated:			return "terminated";
		default:									return "<UNKNOWN SESSION EVENT>";
	}
}

//======================================================================================================================

static int64_t
_mdns_ticks_diff(const uint64_t t1, const uint64_t t2)
{
	return ((int64_t)(t1 - t2));
}

//======================================================================================================================

static uint64_t
_mdns_ticks_to_whole_seconds(const uint64_t ticks)
{
	return (ticks / _mdns_ticks_per_second());
}

//======================================================================================================================

static uint64_t
_mdns_ticks_to_fractional_milliseconds(const uint64_t ticks)
{
	const uint64_t remainder = ticks % _mdns_ticks_per_second();
	return ((remainder * kMillisecondsPerSecond) / _mdns_ticks_per_second());
}

//======================================================================================================================

static dispatch_source_t
_mdns_resolver_create_oneshot_timer(const uint32_t time_ms, const unsigned int leeway_percent_numerator)
{
	const dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _mdns_resolver_queue());
	require_quiet(timer, exit);

	const unsigned int	numerator = Min(leeway_percent_numerator, 100);
	const uint64_t		leeway_ns = time_ms * (numerator * (UINT64_C_safe(kNanosecondsPerMillisecond) / 100));
	dispatch_source_set_timer(timer, _dispatch_monotonictime_after_msec(time_ms), DISPATCH_TIME_FOREVER, leeway_ns);

exit:
	return timer;
}

//======================================================================================================================

static bool
_mdns_rcode_is_good(const int rcode)
{
	return ((rcode == kDNSRCode_NoError) || (rcode == kDNSRCode_NXDomain) || (rcode == kDNSRCode_NotAuth));
}

//======================================================================================================================

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static bool
_mdns_qtype_is_problematic(const int qtype)
{
	return ((qtype == kDNSRecordType_HTTPS) || (qtype == kDNSRecordType_SVCB));
}

//======================================================================================================================

static mdns_message_t
_mdns_create_empty_response_for_query(const mdns_query_message_t query, const int rcode, OSStatus * const out_error)
{
	mdns_message_t response_msg = NULL;
	OSStatus err;
	const size_t len = mdns_message_get_length(query);
	require_action_quiet(len > kDNSHeaderLength, exit, err = kInternalErr);

	uint8_t *response_ptr = malloc(len);
	require_action_quiet(response_ptr, exit, err = kNoMemoryErr);

	memcpy(response_ptr, mdns_message_get_byte_ptr(query), len);
	unsigned int flags = 0;
	flags |= kDNSHeaderFlag_Response;
	DNSFlagsSetOpCode(flags, kDNSOpCode_Query);
	flags |= kDNSHeaderFlag_RecursionDesired;
	flags |= kDNSHeaderFlag_RecursionAvailable;
	DNSFlagsSetRCode(flags, rcode);
	DNSHeaderSetFlags((DNSHeader *)response_ptr, flags);

	dispatch_data_t response_data = dispatch_data_create(response_ptr, len, NULL, DISPATCH_DATA_DESTRUCTOR_FREE);
	require_action_quiet(response_data, exit, ForgetMem(&response_ptr); err = kNoResourcesErr);
	response_ptr = NULL;

	response_msg = mdns_message_create_with_dispatch_data(response_data,
		mdns_message_init_option_disable_header_printing);
	dispatch_forget(&response_data);
	require_action_quiet(response_msg, exit, err = kNoResourcesErr);
	err = kNoErr;

exit:
	if (out_error) {
		*out_error = err;
	}
	return response_msg;
}
#endif // MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND || MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND

//======================================================================================================================

#if MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND
static mdns_query_message_t
_mdns_create_simple_test_query(const mdns_query_message_t query, const uint16_t qtype)
{
	mdns_query_message_t result = NULL;
	mdns_query_message_t test_query = mdns_query_message_create(mdns_message_init_option_disable_header_printing);
	require_quiet(test_query, exit);

	OSStatus err = mdns_query_message_set_qname(test_query, mdns_query_message_get_qname(query));
	require_noerr_quiet(err, exit);

	mdns_query_message_set_qtype(test_query, qtype);
	mdns_query_message_set_qclass(test_query, mdns_query_message_get_qclass(query));
	uint16_t msg_id = (uint16_t)RandomRange(1, UINT16_MAX);
	// Make sure that the test query's ID is different from the original query's ID.
	if (msg_id == mdns_query_message_get_message_id(query)) {
		msg_id = ~msg_id;
		if (msg_id == 0) {
			msg_id = 1;
		}
	}
	mdns_query_message_set_message_id(test_query, msg_id);
	err = mdns_query_message_construct(test_query);
	require_noerr_quiet(err, exit);

	result = test_query;
	test_query = NULL;

exit:
	mdns_forget(&test_query);
	return result;
}

//======================================================================================================================

static bool
_mdns_message_is_adequate_test_query_response(const mdns_message_t msg, const mdns_query_message_t query)
{
	return _mdns_message_is_query_response_ex(mdns_message_get_byte_ptr(msg), mdns_message_get_length(msg), query,
		NULL, NULL, true);
}

//======================================================================================================================

static pqw_info_t *
_pqw_info_create(const unsigned int threshold)
{
	pqw_info_t *info = (pqw_info_t *)calloc(1, sizeof(*info));
	require_return_value(info, NULL);
	info->threshold = threshold;
	return info;
}

//======================================================================================================================

static void
_pqw_info_free(pqw_info_t * const info)
{
	_pqw_qname_list_forget(&info->qname_list);
	free(info);
}

//======================================================================================================================

static bool
_pqw_info_threshold_reached(const pqw_info_t * const info)
{
	return ((info->qname_count < info->threshold) ? false : true);
}

//======================================================================================================================

static bool
_pqw_info_can_accept_qname(const pqw_info_t * const info, const uint8_t * const qname)
{
	if (_pqw_info_threshold_reached(info)) {
		return false;
	}
	for (const pqw_qname_item_t *item = info->qname_list; item; item = item->next) {
		if (DomainNameEqual(item->qname, qname)) {
			return false;
		}
	}
	return true;
}

//======================================================================================================================

static pqw_qname_item_t *
_pqw_qname_item_create(const uint8_t * const qname, OSStatus * const out_error)
{
	pqw_qname_item_t *result = NULL;
	OSStatus err;
	pqw_qname_item_t *item = (pqw_qname_item_t *)calloc(1, sizeof(*item));
	require_action_quiet(item, exit, err = kNoMemoryErr);

	err = DomainNameDup(qname, &item->qname, NULL);
	require_noerr_quiet(err, exit);

	result = item;
	item = NULL;

exit:
	if (out_error) {
		*out_error = err;
	}
	_pqw_qname_item_forget(&item);
	return result;
}

//======================================================================================================================

static void
_pqw_qname_item_free(pqw_qname_item_t * const item)
{
	ForgetMem(&item->qname);
	free(item);
}

//======================================================================================================================

static void
_pqw_qname_list_free(pqw_qname_item_t *list)
{
	pqw_qname_item_t *item;
	while ((item = list) != NULL) {
		list = item->next;
		_pqw_qname_item_free(item);
	}
}
#endif // MDNS_RESOLVER_PROBLEMATIC_QTYPE_WORKAROUND

//======================================================================================================================

#if MDNS_RESOLVER_MIXED_UP_RESPONSES_WORKAROUND
static bool
_mdns_qtype_is_address_type(const int qtype)
{
	return ((qtype == kDNSRecordType_A) || (qtype == kDNSRecordType_AAAA));
}
#endif
