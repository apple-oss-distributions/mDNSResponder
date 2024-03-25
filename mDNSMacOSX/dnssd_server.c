/*
 * Copyright (c) 2019-2023 Apple Inc. All rights reserved.
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

#include "dnssd_server.h"

#include "ClientRequests.h"
#include "DNSCommon.h"
#include "dnssd_xpc.h"
#include "dnssd_svcb.h"
#include "dnssd_private.h"
#include "gai_options.h"
#include "mDNSMacOSX.h"
#include "termination_reason.h"

#include <CoreUtils/CommonServices.h>
#include <CoreUtils/DebugServices.h>
#include <mach/mach_time.h>
#include <mdns/alloc.h>
#include <mdns/audit_token.h>
#include <mdns/mortality.h>
#include <mdns/resource_record.h>
#include <mdns/system.h>
#include <mdns/ticks.h>
#include <mdns/xpc.h>
#include <os/lock.h>
#include <stdatomic.h>
#include <xpc/private.h>

#include "helpers.h"

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
#include "QuerierSupport.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
#include "mdns_trust.h"
#include <os/feature_private.h>
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)
#include "resolved_cache.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
#include <mdns/signed_result.h>
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
#include "uds_daemon.h"
#include <mdns/dispatch.h>
#include <mdns/powerlog.h>
#endif

#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Kind Declarations

#define DX_STRUCT(NAME)					struct dx_ ## NAME ## _s
#define DX_KIND_DECLARE_ABSTRACT(NAME)	typedef DX_STRUCT(NAME) *	dx_ ## NAME ## _t
#define DX_KIND_DECLARE(NAME)		\
	DX_KIND_DECLARE_ABSTRACT(NAME)

// Note: The last check checks if the base's type is equal to that of the superkind. If it's not, then the pointer
// comparison used as the argument to sizeof will cause a "comparison of distinct pointer types" warning, so long as
// the warning hasn't been disabled.

#define DX_BASE_CHECK(NAME, SUPER)															\
	check_compile_time(offsetof(DX_STRUCT(NAME), base) == 0);								\
	check_compile_time(sizeof_field(DX_STRUCT(NAME), base) == sizeof(DX_STRUCT(SUPER)));	\
	extern int _dx_base_type_check[sizeof(&(((dx_ ## NAME ## _t)0)->base) == ((dx_ ## SUPER ## _t)0))]

#define DX_SUBKIND_DEFINE_ABSTRACT(NAME, SUPER, ...)		\
	static const struct dx_kind_s _dx_ ## NAME ## _kind = {	\
		.superkind = &_dx_ ## SUPER ##_kind,				\
		__VA_ARGS__											\
	};														\
	DX_BASE_CHECK(NAME, SUPER)

#define DX_SUBKIND_DEFINE(NAME, SUPER, ...)												\
	DX_SUBKIND_DEFINE_ABSTRACT(NAME, SUPER, __VA_ARGS__);								\
																						\
	static dx_ ## NAME ## _t															\
	_dx_ ## NAME ## _new(void)															\
	{																					\
		const dx_ ## NAME ## _t obj = (dx_ ## NAME ## _t)mdns_calloc(1, sizeof(*obj));	\
		require_return_value(obj, NULL);												\
																						\
		_dx_object_init(obj, &_dx_ ## NAME ## _kind);									\
		return obj;																		\
	}																					\
	extern int _dx_dummy_variable

#define DX_OBJECT_SUBKIND_DEFINE_ABSTRACT(NAME, ...)	DX_SUBKIND_DEFINE_ABSTRACT(NAME, object, __VA_ARGS__)
#define DX_OBJECT_SUBKIND_DEFINE(NAME, ...)				DX_SUBKIND_DEFINE(NAME, object, __VA_ARGS__)

DX_KIND_DECLARE_ABSTRACT(object);
DX_KIND_DECLARE(session);
DX_KIND_DECLARE_ABSTRACT(request);
DX_KIND_DECLARE(gai_request);
DX_KIND_DECLARE(gai_result);

#define DX_TRANSPARENT_UNION_MEMBER(NAME)	DX_STRUCT(NAME) *	NAME

typedef union {
	DX_TRANSPARENT_UNION_MEMBER(object);
	DX_TRANSPARENT_UNION_MEMBER(session);
	DX_TRANSPARENT_UNION_MEMBER(request);
	DX_TRANSPARENT_UNION_MEMBER(gai_request);
	DX_TRANSPARENT_UNION_MEMBER(gai_result);
} dx_any_t __attribute__((__transparent_union__));

typedef void
(*dx_init_f)(dx_any_t object);

typedef void
(*dx_invalidate_f)(dx_any_t object);

typedef void
(*dx_finalize_f)(dx_any_t object);

typedef const struct dx_kind_s *	dx_kind_t;
struct dx_kind_s {
	dx_kind_t		superkind;	// This kind's superkind. All kinds have a superkind, except the base kind.
	dx_init_f		init;		// Initializes an object.
	dx_invalidate_f	invalidate;	// Stops an object's outstanding operations, if any.
	dx_finalize_f	finalize;	// Releases object's resources right before the object is freed.
};

//======================================================================================================================
// MARK: - Object Kind Definition

struct dx_object_s {
	dx_kind_t			kind;		// The object's kind.
	_Atomic(int32_t)	ref_count;	// Reference count.
};

static void
_dx_object_init(dx_any_t object, dx_kind_t kind);

static void
_dx_retain(dx_any_t object);

static void
_dx_release(dx_any_t object);
#define _dx_forget(X)	ForgetCustom(X, _dx_release)
#define _dx_replace(PTR, OBJ)		\
	do {							\
		if (OBJ) {					\
			_dx_retain(OBJ);		\
		}							\
		if (*(PTR)) {				\
			_dx_release(*(PTR));	\
		}							\
		*(PTR) = (OBJ);				\
	} while(0)

static void
_dx_invalidate(dx_any_t object);

static const struct dx_kind_s _dx_object_kind = {
	.superkind	= NULL,
	.init		= NULL,
	.invalidate	= NULL,
	.finalize	= NULL
};

//======================================================================================================================
// MARK: - Session Kind Definition

struct dx_session_s {
	struct dx_object_s	base;						// Object base;
	dx_session_t		next;						// Next session in list.
	dx_request_t		request_list;				// List of outstanding requests.
	xpc_connection_t	connection;					// Underlying XPC connection.
	dispatch_source_t	idle_timer;					// Timer for detecting idleness.
	dispatch_source_t	keepalive_reply_timer;		// Timer for enforcing a time limit on keepalive replies.
	uint64_t			pending_send_start_ticks;	// Start time in mach ticks of the current pending send condition.
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	mdns_audit_token_t	peer_token;					// Client's audit token.
#endif
	uid_t				client_euid;				// Client's EUID.
	pid_t				client_pid;					// Client's PID.
	uint32_t			pending_send_count;			// Count of sent messages that still haven't been processed.
	char				client_name[MAXCOMLEN];		// Client's process name.
	bool				terminated;					// True if the session was prematurely ended due to a fatal error.
	bool				log_pending_send_counts;	// True if pending send counts should be logged.
};
mdns_compile_time_max_size_check(struct dx_session_s, 104);

static void
_dx_session_invalidate(dx_session_t session);

static void
_dx_session_finalize(dx_session_t session);

DX_OBJECT_SUBKIND_DEFINE(session,
	.invalidate	= _dx_session_invalidate,
	.finalize	= _dx_session_finalize
);

typedef union {
	DX_TRANSPARENT_UNION_MEMBER(request);
	DX_TRANSPARENT_UNION_MEMBER(gai_request);
} dx_any_request_t __attribute__((__transparent_union__));

//======================================================================================================================
// MARK: - Request Kind Definition

struct dx_request_s {
	struct dx_object_s		base;				// Object base.
	dx_request_t			next;				// Next request in list.
	dx_session_t			session;			// Back pointer to parent session.
	xpc_object_t			results;			// Array of pending results.
	uint64_t				command_id;			// ID to distinquish multiple commands during a session.
	uint32_t				request_id;			// Request ID, used for logging purposes.
	DNSServiceErrorType		error;				// Pending error.
	os_unfair_lock			lock;				// Lock for pending error and results array.
	bool					sent_error;			// True if the pending error has been sent to client.
};

static void
_dx_request_init(dx_request_t request);

static void
_dx_request_finalize(dx_request_t request);

DX_OBJECT_SUBKIND_DEFINE_ABSTRACT(request,
	.init		= _dx_request_init,
	.finalize	= _dx_request_finalize
);

//======================================================================================================================
// MARK: - GetAddrInfo Request Kind Definition

OS_CLOSED_OPTIONS(dx_gai_state, uint8_t,
	dx_gai_state_null						= 0,         // Default null state.
	dx_gai_state_waiting_for_a				= (1U << 0), // Currently waiting for an A result. [1]
	dx_gai_state_waiting_for_aaaa			= (1U << 1), // Currently waiting for a AAAA result. [1]
	dx_gai_state_service_allowed_failover	= (1U << 2), // Got a result from a DNS service that allows failover.
	dx_gai_state_failover_mode				= (1U << 3), // Currently avoiding DNS services that allow failover.
	dx_gai_state_avoid_suppressed_a_result	= (1U << 4), // Avoiding negative results for suppressed A queries. [2]
);

#define DX_GAI_STATE_WAITING_FOR_RESULTS (dx_gai_state_waiting_for_a | dx_gai_state_waiting_for_aaaa)

MDNS_CLANG_TREAT_WARNING_AS_ERROR_BEGIN(-Wpadded)
struct dx_gai_request_s {
	struct dx_request_s				base;					// Request object base.
	mdns_dns_service_id_t			custom_service_id;		// ID for this request's custom DNS service.
#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
	uint64_t						powerlog_start_time;	// If non-zero, time when mDNS client request started.
#endif
	GetAddrInfoClientRequest *		gai;					// Underlying GAI request.
	QueryRecordClientRequest *		query;					// Underlying SVCB/HTTPS query request.
	dx_gai_result_t					results;				// List of pending results.
	char *							hostname;				// Hostname C string to be resolved for getaddrinfo request.
	mdns_domain_name_t				last_domain_name;		// Domain name of the most recent result.
	mdns_xpc_string_t				last_tracker_hostname;	// Tracker hostname of the most recent result (XPC string).
	mdns_xpc_string_t				last_tracker_owner;		// Tracker owner of the most recent result (XPC string).
	const char *					svcb_name;				// If non-NULL, name of the SVCB/HTTPS record to query for.
	uuid_t *						resolver_uuid;			// The resolver UUID to use for UUID-scoped requests.
	xpc_object_t					cnames_a;				// Hostname's canonical names for A records (XPC array).
	xpc_object_t					cnames_aaaa;			// Hostname's canonical names for AAAA records (XPC array).
	mdns_audit_token_t				delegator_token;		// The delegator's audit token.
	xpc_object_t					fallback_dns_config;	// Fallback DNS configuration.
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
	mdns_trust_t					trust;					// Trust instance if status is mdns_trust_status_pending
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	mdns_signed_resolve_result_t	signed_resolve;			// Signed resolve result with which to sign results.
#endif
	char *							svcb_name_memory;		// Memory that was allocated for svcb_name.
	dx_gai_result_t					pending_suppresed_a;	// Pending negative result for a suppressed A query. [2]
	DNSServiceFlags					flags;					// The request's flags parameter.
	uint32_t						ifindex;				// The interface index to use for interface-scoped requests.
	DNSServiceProtocol				protocols;				// Used to specify IPv4, IPv6, or any IP address types.
	pid_t							effective_pid;			// Effective client PID.
	uint16_t						svcb_type;				// If svcb_name is non-NULL, the type for SVCB/HTTPS query.
	uuid_t							effective_uuid;			// Effective client UUID.
	dx_gai_state_t					state;					// Collection of state bits.
	mdns_gai_options_t				options;				// Additional request options.
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	dnssd_log_privacy_level_t		log_privacy_level;		// The log privacy level of this request.
#endif
	bool							cnames_a_changed;		// True if cnames_a has changed.
	bool							cnames_aaaa_changed;	// True if cnames_aaaa has changed.
	MDNS_STRUCT_PAD_64_32(1, 1);
};
MDNS_CLANG_TREAT_WARNING_AS_ERROR_END()
mdns_compile_time_max_size_check(struct dx_gai_request_s, 256);

// Notes:
// 1. If a client request specifies that DNS services that allow failover be avoided if they're unable to provide
//    at least one positive response to either the A, AAAA, or HTTPS query, then we have to wait until at least one
//    positive result is received or until all of the underlying DNSQuestions get negative results before deciding
//    whether to start providing results to the client (former case), or discarding the current list of pending
//    results and restarting the underlying DNSQuestions in failover mode (latter case).
//
// 2. There are cases where an IPv6-only network is the primary network and will inadvertently prevent the
//    resolution of IPv4-only hostnames that are in fact resolvable via a VPN's DNS service.
//
//    On IPv6-only networks it usually makes no sense to bother sending A record queries to the network's DNS
//    service because IPv4 addresses are typically unusable on such networks, or it's at least preferable to
//    connect directly to an IPv6 address instead of to an IPv4 address through an IPv4 translation mechanism, such
//    as 464XLAT. So sending A queries is wasteful. Therefore, as a matter of policy, DNS services associated with
//    IPv6-only networks are typically configured to advise against sending A queries.
//
//    As a DNSQuestion traverses the original QNAME's CNAME chain, it may end up switching over to a different DNS
//    service depending on its current QNAME and the most appropriate DNS service for that QNAME according to the
//    current DNS configuration. For example, consider a DNSQuestion that is originally for www.example.com. If
//    there's a split-tunnel corporate VPN DNS service that's responsible for resolving everything in the
//    example.com domain. If the VPN DNS service responds to a query for www.example.com with a CNAME mapping
//    www.example.com to cdn.example.net, then when the DNSQuestion is restarted for cdn.example.net, it may be
//    assigned a different DNS service, specifically if the VPN is not responsible for cdn.example.net.
//
//    Suppose that the next DNS service is for an IPv6-only network not associated with the VPN. Suppose that in
//    the public DNS there's a cdn.example.net CNAME record that points to server.example.com. Also suppose that
//    the VPN supports IPv4 and that server.example.com is an IPv4-only host. Because the IPv6-only network's DNS
//    service advises against A queries, the DNSQuestion is stuck at cdn.example.net if the DNSQuestion is
//    configured to suppress queries for unusable addresses, as is usually the case.
//
//    When a GAI request involves parallel A and AAAA DNSQuestions, the CNAME records placed in the cache as a
//    result of the unsuppressed AAAA query can help the A DNSQuestion advance to the next name in the CNAME chain
//    so that it can advance to the VPN DNS service for server.example.com for its unsuppressed A query. This is
//    only possible if the persistWhenARecordsUnusable option is set.
//
//    A caveat with the persistWhenARecordsUnusable option is that negative results that indicate that an A query
//    was suppressed will still be generated when the A DNSQuestion is parked on a DNS service that advises against
//    A queries. We want to avoid a client seeing a negative AAAA result along with a negative suppressed A result
//    as the first pair of A+AAAA results because this could lead the client to give up upon getting such a
//    negative pair when it could be the case that a more definitive A result is on the way, e.g., a positive
//    result with an IPv4 address or some other negative result, as a consequence of the A DNSQuestion advancing to
//    a DNS service for which A queries are not suppressed.

typedef xpc_object_t
(*dx_request_take_results_f)(dx_any_request_t request);

typedef void
(*dx_request_report_powerlog_progress_f)(dx_any_request_t request);

typedef const struct dx_request_kind_s * dx_request_kind_t;
struct dx_request_kind_s {
	struct dx_kind_s						base;
	dx_request_take_results_f				take_results;
	dx_request_report_powerlog_progress_f	report_powerlog_progress;
};

#define DX_REQUEST_SUBKIND_DEFINE(NAME, ...)														\
	static void																						\
	_dx_ ## NAME ## _request_invalidate(dx_ ## NAME ## _request_t request);							\
																									\
	static void																						\
	_dx_ ## NAME ## _request_finalize(dx_ ## NAME ## _request_t request);							\
																									\
	static const struct dx_request_kind_s _dx_ ## NAME ## _request_kind = {							\
		.base = {																					\
			.superkind	= &_dx_request_kind,														\
			.invalidate	= _dx_ ## NAME ## _request_invalidate,										\
			.finalize	= _dx_ ## NAME ## _request_finalize											\
		},																							\
		__VA_ARGS__																					\
	};																								\
																									\
	static dx_ ## NAME ## _request_t																\
	_dx_ ## NAME ## _request_new(void)																\
	{																								\
		dx_ ## NAME ## _request_t obj = (dx_ ## NAME ## _request_t)mdns_calloc(1, sizeof(*obj));	\
		require_return_value(obj, NULL);															\
																									\
		_dx_object_init(obj, &_dx_ ## NAME ## _request_kind.base);									\
		return obj;																					\
	}																								\
	DX_BASE_CHECK(NAME ## _request, request)

static xpc_object_t
_dx_gai_request_take_results(dx_gai_request_t request);

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
static void
_dx_gai_request_report_powerlog_progress(dx_gai_request_t request);
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
	#define DX_GAI_REQUEST_REPORT_POWERLOG_PROGRESS_FUNCTION	_dx_gai_request_report_powerlog_progress
#else
	#define DX_GAI_REQUEST_REPORT_POWERLOG_PROGRESS_FUNCTION	NULL
#endif

DX_REQUEST_SUBKIND_DEFINE(gai,
	.take_results				= _dx_gai_request_take_results,
	.report_powerlog_progress	= DX_GAI_REQUEST_REPORT_POWERLOG_PROGRESS_FUNCTION,
);

//======================================================================================================================
// MARK: - Result Kind Definition

struct dx_gai_result_s {
	struct dx_object_s				base;					// Object base.
	dx_gai_result_t					next;					// Next result in list.
	mdns_resource_record_t			record;					// Result's resource record.
	mdns_xpc_string_t				provider_name;			// The DNS service's provider name, if any.
	xpc_object_t					cname_update;			// If non-NULL, XPC array to use for a CNAME chain update.
	mdns_xpc_string_t				tracker_hostname;		// If non-NULL, tracker hostname as an XPC string.
	mdns_xpc_string_t				tracker_owner;			// If non-NULL, owner of the tracker hostname as an XPC string.
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	mdns_signed_hostname_result_t	signed_hostname;		// Signed hostname result.
#endif
	mdns_extended_dns_error_t		extended_dns_error;		// Extended DNS Error, if any.
	DNSServiceFlags					flags;					// The result's flags.
	dnssd_negative_reason_t			negative_reason;		// Reason code for negative results.
	DNSServiceErrorType				error;					// Error returned by mDNS core.
	uint32_t						ifindex;				// The interface index associated with the result.
	mdns_resolver_type_t			protocol;				// The transport protocol used to obtain the record.
	uint16_t						question_id;			// ID of DNSQuestion used to get result. Used for logging.
	unsigned						tracker_is_approved : 1;// True if the associated tracker is approved for the client.
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	unsigned						sensitive_logging : 1;	// True if hostnames and rdata should be logged sensitively.
#endif
	unsigned						tracker_can_block : 1;	// True if a request to this known tracker can be blocked.
	unsigned						__pad_bits : 5;
};
mdns_compile_time_max_size_check(struct dx_gai_result_s, 104);

static void
_dx_gai_result_finalize(dx_gai_result_t result);

DX_OBJECT_SUBKIND_DEFINE(gai_result,
	.finalize = _dx_gai_result_finalize
);

//======================================================================================================================
// MARK: - Local Prototypes

static dispatch_queue_t
_dx_server_queue(void);

static void
_dx_server_handle_new_connection(xpc_connection_t connection);

static void
_dx_server_register_session(dx_session_t session);

static void
_dx_server_deregister_session(dx_session_t session);

static void
_dx_server_check_sessions(void);

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
static void
_dx_server_report_request_progress_to_powerlog(void);
#endif

static dx_session_t
_dx_session_create(xpc_connection_t connection);

static void
_dx_session_activate(dx_session_t session);

static void
_dx_session_handle_message(dx_session_t session, xpc_object_t msg);

static DNSServiceErrorType
_dx_session_handle_getaddrinfo_command(dx_session_t session, xpc_object_t msg);

static DNSServiceErrorType
_dx_session_handle_stop_command(dx_session_t session, xpc_object_t msg);

static void
_dx_session_append_request(dx_session_t session, dx_any_request_t any);

static void
_dx_session_check(dx_session_t session, uint64_t now_ticks);

static void
_dx_session_send_message(dx_session_t session, xpc_object_t msg);

static void
_dx_session_terminate(dx_session_t session, mdns_termination_reason_t reason);

static void
_dx_session_reset_idle_timer(dx_session_t session);

static void
_dx_session_log_error(dx_session_t session, DNSServiceErrorType error);

static void
_dx_session_log_pending_send_count_increase(dx_session_t session);

static void
_dx_session_log_pending_send_count_decrease(dx_session_t session);

static void
_dx_session_log_termination(dx_session_t session, mdns_termination_reason_t reason);

static xpc_object_t
_dx_request_take_results(dx_request_t request);

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
static void
_dx_request_report_powerlog_progress(dx_request_t request);
#endif

typedef void (^dx_block_t)(void);

static void
_dx_request_locked(dx_any_request_t request, dx_block_t block);

static DNSServiceErrorType
_dx_request_get_error(dx_any_request_t request);

static bool
_dx_request_set_error(dx_any_request_t request, DNSServiceErrorType error);

static bool
_dx_request_send_pending_error(dx_any_request_t request);

static dx_gai_request_t
_dx_gai_request_create(uint64_t command_id, dx_session_t session);

static DNSServiceErrorType
_dx_gai_request_activate(dx_gai_request_t request);

static DNSServiceErrorType
_dx_gai_request_start_client_requests(dx_gai_request_t request, bool need_lock);

static DNSServiceErrorType
_dx_gai_request_parse_params(dx_gai_request_t request, xpc_object_t params);

static DNSServiceErrorType
_dx_gai_request_start_client_requests_internal(dx_gai_request_t request, GetAddrInfoClientRequestParams *gai_params,
	QueryRecordClientRequestParams *query_params, bool need_lock);

static void
_dx_gai_request_stop_client_requests(dx_gai_request_t request, bool need_lock);

static void
_dx_gai_request_restart_client_requests_in_failover_mode(dx_gai_request_t request);

static void
_dx_gai_request_append_cname(dx_gai_request_t request, int qtype, const domainname *cname, bool expired);

static xpc_object_t
_dx_gai_request_copy_cname_update(dx_gai_request_t request, int qtype);

static void
_dx_gai_request_gai_result_handler(mDNS *m, DNSQuestion *q, const ResourceRecord *answer, mDNSBool expired,
	QC_result qc_result, DNSServiceErrorType error, void *context);

static void
_dx_gai_request_query_result_handler(mDNS *m, DNSQuestion *q, const ResourceRecord *answer, mDNSBool expired,
	QC_result qc_result, DNSServiceErrorType error, void *context);

static void
_dx_gai_request_enqueue_result(dx_gai_request_t request, QC_result qc_result, const ResourceRecord *answer,
	bool answer_is_expired, const uint8_t *rdata_ptr, uint16_t rdata_len, DNSServiceErrorType error,
	const DNSQuestion *q);

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
static const uint8_t *
_dx_gai_request_get_resolver_uuid(xpc_object_t params);
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
static bool
_dx_gai_request_is_for_in_app_browser(xpc_object_t params);
#endif

static void
_dx_gai_request_log_start(dx_gai_request_t request, pid_t delegator_pid, const uuid_t delegator_uuid);

static void
_dx_gai_request_log_stop(dx_gai_request_t request);

static void
_dx_gai_request_log_error(dx_gai_request_t request, DNSServiceErrorType error);

static bool
_dx_gai_request_check_for_failover_restart(dx_gai_request_t request, const ResourceRecord *answer,
	bool answer_is_expired, bool answer_is_positive);

static void
_dx_gai_result_list_forget(dx_gai_result_t *list_ptr);

static xpc_object_t
_dx_gai_result_to_dictionary(dx_gai_result_t result);

static void
_dx_gai_result_log(dx_gai_result_t result, uint32_t request_id);

static void
_dx_kqueue_locked(const char *description, bool need_lock, dx_block_t block);

static void
_dx_replace_domain_name(mdns_domain_name_t *ptr, const domainname *name);

static bool
_dx_qc_result_is_add(QC_result qc_result);

static bool
_dx_qc_result_is_suppressed(QC_result qc_result);

static QueryRecordClientRequest *
_dx_query_record_client_request_start(const QueryRecordClientRequestParams *params,
	QueryRecordResultHandler handler, void *context, DNSServiceErrorType *out_error);

static void
_dx_query_record_client_request_forget(QueryRecordClientRequest **request_ptr);

static GetAddrInfoClientRequest *
_dx_get_addr_info_client_request_start(const GetAddrInfoClientRequestParams *params,
	QueryRecordResultHandler handler, void *context, DNSServiceErrorType *out_error);

static void
_dx_get_addr_info_client_request_forget(GetAddrInfoClientRequest **request_ptr);

//======================================================================================================================
// MARK: - Logging

MDNS_LOG_CATEGORY_DEFINE(server, "dnssd_server");

//======================================================================================================================
// MARK: - Globals

static dx_session_t	g_session_list = NULL;

//======================================================================================================================
// MARK: - Server Functions

mDNSexport void
dnssd_server_init(void)
{
	static dispatch_once_t s_once = 0;
	static xpc_connection_t s_listener = NULL;
#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
	static dispatch_source_t s_powerlog_progress_timer = NULL;
#endif
	dispatch_once(&s_once,
	^{
		s_listener = xpc_connection_create_mach_service(DNSSD_MACH_SERVICE_NAME, _dx_server_queue(),
			XPC_CONNECTION_MACH_SERVICE_LISTENER);
		xpc_connection_set_event_handler(s_listener,
		^(xpc_object_t event)
		{
			if (xpc_get_type(event) == XPC_TYPE_CONNECTION) {
				_dx_server_handle_new_connection((xpc_connection_t)event);
			}
		});
		xpc_connection_activate(s_listener);
	#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
		const uint32_t interval_ms = MDNS_MILLISECONDS_PER_HOUR;
		s_powerlog_progress_timer = mdns_dispatch_create_periodic_monotonic_timer(interval_ms, 5, _dx_server_queue());
		if (s_powerlog_progress_timer) {
			dispatch_source_set_event_handler(s_powerlog_progress_timer,
			^{
				os_log_debug(_mdns_server_log(), "periodic powerlog report timer fired");
				_dx_server_report_request_progress_to_powerlog();
			});
			dispatch_activate(s_powerlog_progress_timer);
		} else {
			os_log_fault(_mdns_server_log(), "Failed to create periodic powerlog report timer");
		}
	#endif
	});
}

//======================================================================================================================

mDNSexport void
dnssd_server_idle(void)
{
	static dispatch_once_t		s_once = 0;
	static dispatch_source_t	s_source = NULL;
	dispatch_once(&s_once,
	^{
		s_source = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_OR, 0, 0, _dx_server_queue());
		dispatch_source_set_event_handler(s_source,
		^{
			_dx_server_check_sessions();
		});
		dispatch_activate(s_source);
	});
	dispatch_source_merge_data(s_source, 1);
}

//======================================================================================================================

uint32_t
dnssd_server_get_new_request_id(void)
{
	static _Atomic(uint32_t) s_next_id = 1;
	return atomic_fetch_add(&s_next_id, 1);
}

//======================================================================================================================

static dispatch_queue_t
_dx_server_queue(void)
{
	static dispatch_once_t	once	= 0;
	static dispatch_queue_t	queue	= NULL;

	dispatch_once(&once,
	^{
		const dispatch_queue_attr_t attr = dispatch_queue_attr_make_with_qos_class(DISPATCH_QUEUE_SERIAL,
			QOS_CLASS_USER_INITIATED, 0);
		queue = dispatch_queue_create("com.apple.dnssd.server", attr);
	});
	return queue;
}

//======================================================================================================================

static void
_dx_server_handle_new_connection(const xpc_connection_t connection)
{
	dx_session_t session = _dx_session_create(connection);
	if (session) {
		_dx_session_activate(session);
		_dx_server_register_session(session);
		_dx_forget(&session);
	} else {
		const pid_t client_pid = xpc_connection_get_pid(connection);
		char client_name[MAXCOMLEN];
		client_name[0] = '\0';
		mdns_system_pid_to_name(client_pid, client_name);
		os_log_fault(_mdns_server_log(),
			"Failed to create session for connection -- client pid: %d (%{public}s)", client_pid, client_name);
		xpc_connection_cancel(connection);
	}
}

//======================================================================================================================

static void
_dx_server_register_session(dx_session_t session)
{
	dx_session_t *ptr = &g_session_list;
	while (*ptr) {
		ptr = &(*ptr)->next;
	}
	session->next = NULL;
	*ptr = session;
	_dx_retain(*ptr);
}

//======================================================================================================================

static void
_dx_server_deregister_session(dx_session_t session)
{
	dx_session_t *ptr = &g_session_list;
	while (*ptr && (*ptr != session)) {
		ptr = &(*ptr)->next;
	}
	if (*ptr) {
		*ptr = session->next;
		session->next = NULL;
		_dx_forget(&session);
	}
}

//======================================================================================================================

static void
_dx_server_check_sessions(void)
{
	if (g_session_list) {
		const uint64_t now_ticks = mach_absolute_time();
		for (dx_session_t session = g_session_list; session; session = session->next) {
			_dx_session_check(session, now_ticks);
		}
	}
}

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
static void
_dx_server_report_request_progress_to_powerlog(void)
{
	_dx_kqueue_locked("dnssd_server: report client request progress to powerlog", true,
	^{
		for (dx_session_t session = g_session_list; session; session = session->next) {
			for (dx_request_t req = session->request_list; req; req = req->next) {
				_dx_request_report_powerlog_progress(req);
			}
		}
		udsserver_report_request_progress_to_powerlog();
	});
}
#endif

//======================================================================================================================
// MARK: - Object Methods

static void
_dx_recursive_init(dx_object_t object, dx_kind_t kind);

static void
_dx_object_init(const dx_object_t me, const dx_kind_t kind)
{
	me->kind = kind;
	atomic_store_explicit(&me->ref_count, 1, memory_order_relaxed);
	_dx_recursive_init(me, me->kind);
}

static void
_dx_recursive_init(const dx_object_t me, const dx_kind_t kind)
{
	if (kind->superkind) {
		_dx_recursive_init(me, kind->superkind);
	}
	if (kind->init) {
		kind->init(me);
	}
}

//======================================================================================================================

static void
_dx_retain(const dx_any_t any)
{
	const dx_object_t me = any.object;
	atomic_fetch_add(&me->ref_count, 1);
}

//======================================================================================================================

static void
_dx_finalize(dx_object_t object);

static void
_dx_release(const dx_any_t any)
{
	dx_object_t me = any.object;
	if (atomic_fetch_sub(&me->ref_count, 1) == 1) {
		_dx_finalize(me);
		ForgetMem(&me);
	}
}

static void
_dx_finalize(const dx_object_t me)
{
	for (dx_kind_t kind = me->kind; kind; kind = kind->superkind) {
		if (kind->finalize) {
			kind->finalize(me);
		}
	}
}

//======================================================================================================================

static void
_dx_invalidate(const dx_any_t any)
{
	const dx_object_t me = any.object;
	for (dx_kind_t kind = me->kind; kind; kind = kind->superkind) {
		if (kind->invalidate) {
			kind->invalidate(me);
			return;
		}
	}
}

//======================================================================================================================
// MARK: - Session Methods

static dx_session_t
_dx_session_create(const xpc_connection_t connection)
{
	dx_session_t session = NULL;
	dx_session_t obj = _dx_session_new();
	require_quiet(obj, exit);

	obj->connection = connection;
	xpc_retain(obj->connection);
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	audit_token_t token;
	memset(&token, 0, sizeof(token));
	xpc_connection_get_audit_token(obj->connection, &token);
	obj->peer_token = mdns_audit_token_create(&token);
	require_quiet(obj->peer_token, exit);
#endif

	obj->client_pid  = xpc_connection_get_pid(obj->connection);
	obj->client_euid = xpc_connection_get_euid(obj->connection);
	mdns_system_pid_to_name(obj->client_pid, obj->client_name);
	session = obj;
	obj = NULL;

exit:
	static_analyzer_malloc_freed(obj); // Analyzer isn't aware that obj will be freed if non-NULL.
	_dx_forget(&obj);
	return session;
}

//======================================================================================================================

static void
_dx_session_activate(const dx_session_t me)
{
	_dx_retain(me);
	xpc_connection_set_target_queue(me->connection, _dx_server_queue());
	xpc_connection_set_event_handler(me->connection,
	^(const xpc_object_t event) {
		const xpc_type_t type = xpc_get_type(event);
		if (type == XPC_TYPE_DICTIONARY) {
			if (me->connection) {
				_dx_session_handle_message(me, event);
			}
		} else if (event == XPC_ERROR_CONNECTION_INVALID) {
			_dx_server_deregister_session(me);
			_dx_session_invalidate(me);
			_dx_release(me);
		} else {
			xpc_connection_forget(&me->connection);
		}
	});
	xpc_connection_activate(me->connection);
	_dx_session_reset_idle_timer(me);
}

//======================================================================================================================

static void
_dx_session_invalidate(const dx_session_t me)
{
	xpc_connection_forget(&me->connection);
	dispatch_source_forget(&me->idle_timer);
	dispatch_source_forget(&me->keepalive_reply_timer);
	dx_request_t req;
	while ((req = me->request_list) != NULL)
	{
		me->request_list = req->next;
		_dx_invalidate(req);
		_dx_release(req);
	}
}

//======================================================================================================================

static void
_dx_session_finalize(const dx_session_t me)
{
	xpc_forget(&me->connection);
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	mdns_forget(&me->peer_token);
#endif
}

//======================================================================================================================

static void
_dx_session_handle_message(const dx_session_t me, const xpc_object_t msg)
{
	DNSServiceErrorType err;
	const char * const command = dnssd_xpc_message_get_command(msg);
	require_action_quiet(command, exit, err = kDNSServiceErr_BadParam);

	if (strcmp(command, DNSSD_COMMAND_GETADDRINFO) == 0) {
		err = _dx_session_handle_getaddrinfo_command(me, msg);
	} else if (strcmp(command, DNSSD_COMMAND_STOP) == 0) {
		err = _dx_session_handle_stop_command(me, msg);
	} else {
		err = kDNSServiceErr_BadParam;
	}

exit:
	_dx_session_reset_idle_timer(me);
	xpc_object_t reply = xpc_dictionary_create_reply(msg);
	if (likely(reply)) {
		dnssd_xpc_message_set_error(reply, err);
		_dx_session_send_message(me, reply);
		xpc_forget(&reply);
	} else {
		_dx_session_terminate(me, mdns_termination_reason_client_error);
	}
}

//======================================================================================================================

static DNSServiceErrorType
_dx_session_handle_getaddrinfo_command(const dx_session_t me, const xpc_object_t msg)
{
	dx_gai_request_t req = NULL;
	bool valid;
	DNSServiceErrorType err;
	const uint64_t command_id = dnssd_xpc_message_get_id(msg, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	const xpc_object_t params = dnssd_xpc_message_get_parameters(msg);
	require_action_quiet(params, exit, err = kDNSServiceErr_BadParam);

	req = _dx_gai_request_create(command_id, me);
	require_action_quiet(req, exit, err = kDNSServiceErr_NoMemory);

	err = _dx_gai_request_parse_params(req, params);
	require_noerr_quiet(err, exit);

	err = _dx_gai_request_activate(req);
	require_noerr_quiet(err, exit);

	_dx_session_append_request(me, req);

exit:
	if (err) {
		if (req) {
			_dx_gai_request_log_error(req, err);
		} else {
			_dx_session_log_error(me, err);
		}
	}
	_dx_forget(&req);
	return err;
}

//======================================================================================================================

static DNSServiceErrorType
_dx_session_handle_stop_command(const dx_session_t me, const xpc_object_t msg)
{
	bool valid;
	DNSServiceErrorType err;
	const uint64_t command_id = dnssd_xpc_message_get_id(msg, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	dx_request_t *ptr;
	dx_request_t req;
	for (ptr = &me->request_list; (req = *ptr) != NULL; ptr = &req->next) {
		if (req->command_id == command_id) {
			break;
		}
	}
	require_action_quiet(req, exit, err = kDNSServiceErr_BadReference);

	*ptr = req->next;
	req->next = NULL;
	_dx_invalidate(req);
	_dx_forget(&req);
	err = kDNSServiceErr_NoError;

exit:
	return err;
}

//======================================================================================================================

static void
_dx_session_append_request(const dx_session_t me, const dx_any_request_t any)
{
	dx_request_t *ptr = &me->request_list;
	while (*ptr) {
		ptr = &(*ptr)->next;
	}
	const dx_request_t req = any.request;
	req->next = NULL;
	*ptr = req;
	_dx_retain(*ptr);
}

//======================================================================================================================

#define DX_SESSION_BACK_PRESSURE_TIMEOUT_SECS	5

static void
_dx_session_check(const dx_session_t me, const uint64_t now_ticks)
{
	require_return(me->connection);

	xpc_object_t results = NULL;
	mdns_termination_reason_t terminate_reason;
	if (me->pending_send_count > 0) {
		const uint64_t elapsed_secs = (now_ticks - me->pending_send_start_ticks) / mdns_mach_ticks_per_second();
		require_action_quiet(elapsed_secs < DX_SESSION_BACK_PRESSURE_TIMEOUT_SECS, exit,
			terminate_reason = mdns_termination_reason_back_pressure);
	}
	for (dx_request_t req = me->request_list; req; req = req->next) {
		results = _dx_request_take_results(req);
		if (results) {
			xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
			require_action_quiet(msg, exit, terminate_reason = mdns_termination_reason_server_error);

			dnssd_xpc_message_set_id(msg, req->command_id);
			dnssd_xpc_message_set_error(msg, kDNSServiceErr_NoError);
			dnssd_xpc_message_set_results(msg, results);
			xpc_forget(&results);
			_dx_session_send_message(me, msg);
			xpc_forget(&msg);
		}
		const bool ok = _dx_request_send_pending_error(req);
		require_action_quiet(ok, exit, terminate_reason = mdns_termination_reason_server_error);
	}
	terminate_reason = mdns_termination_reason_none;

exit:
	if (terminate_reason != mdns_termination_reason_none) {
		_dx_session_terminate(me, terminate_reason);
	}
	xpc_forget(&results);
}

//======================================================================================================================

static void
_dx_session_send_message(const dx_session_t me, const xpc_object_t msg)
{
	require_return(me->connection);

	xpc_connection_send_message(me->connection, msg);
	++me->pending_send_count;
	if (me->pending_send_count == 1) {
		me->pending_send_start_ticks = mach_absolute_time();
	} else {
		if (me->pending_send_count == 2) {
			me->log_pending_send_counts = true;
		}
		_dx_session_log_pending_send_count_increase(me);
	}
	_dx_retain(me);
	xpc_connection_send_barrier(me->connection,
	^{
		--me->pending_send_count;
		if (me->log_pending_send_counts) {
			_dx_session_log_pending_send_count_decrease(me);
		}
		if (me->pending_send_count == 0) {
			me->log_pending_send_counts = false;
		}
		_dx_release(me);
	});
}

//======================================================================================================================

static void
_dx_session_terminate(const dx_session_t me, const mdns_termination_reason_t reason)
{
	if (!me->terminated) {
		_dx_session_log_termination(me, reason);
		xpc_connection_forget(&me->connection);
		me->terminated = true;
	}
}

//======================================================================================================================

static dispatch_source_t
_dx_create_oneshot_timer(const uint32_t interval_ms, const unsigned int leeway_percent_numerator)
{
	const dispatch_source_t timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _dx_server_queue());
	require_quiet(timer, exit);

	const unsigned int numerator = Min(leeway_percent_numerator, 100);
	const uint64_t leeway_ns = interval_ms * (numerator * (UINT64_C_safe(kNanosecondsPerMillisecond) / 100));
	dispatch_source_set_timer(timer, dispatch_time_milliseconds(interval_ms), DISPATCH_TIME_FOREVER, leeway_ns);

exit:
	return timer;
}

//======================================================================================================================

#define DX_SESSION_KEEPALIVE_TIMEOUT_MS	(5 * kMillisecondsPerSecond)

static void
_dx_session_send_keepalive_message(const dx_session_t me)
{
	require_return(me->connection && !me->keepalive_reply_timer);

	static xpc_object_t s_keepalive_msg = NULL;
	if (!s_keepalive_msg) {
		s_keepalive_msg = xpc_dictionary_create_empty();
		require_return(s_keepalive_msg);

		dnssd_xpc_message_set_command(s_keepalive_msg, DNSSD_COMMAND_KEEPALIVE);
	}
	me->keepalive_reply_timer = _dx_create_oneshot_timer(DX_SESSION_KEEPALIVE_TIMEOUT_MS, 5);
	require_return(me->keepalive_reply_timer);

	_dx_retain(me);
	xpc_connection_send_message_with_reply(me->connection, s_keepalive_msg, _dx_server_queue(),
	^(xpc_object_t reply)
	{
		if (me->connection && (xpc_get_type(reply) == XPC_TYPE_DICTIONARY)) {
			dispatch_source_forget(&me->keepalive_reply_timer);
			_dx_session_reset_idle_timer(me);
		}
		_dx_release(me);
	});
	dispatch_source_set_event_handler(me->keepalive_reply_timer,
	^{
		dispatch_source_forget(&me->keepalive_reply_timer);
		_dx_session_terminate(me, mdns_termination_reason_keepalive_timeout);
	});
	dispatch_activate(me->keepalive_reply_timer);
}

//======================================================================================================================

#define DX_SESSION_IDLE_TIMEOUT_WITH_REQUESTS_MS	(1 * kSecondsPerMinute * kMillisecondsPerSecond)
#define DX_SESSION_IDLE_TIMEOUT_WITHOUT_REQUESTS_MS	(5 * kSecondsPerMinute * kMillisecondsPerSecond)

static void
_dx_session_reset_idle_timer(const dx_session_t me)
{
	require_return(!me->keepalive_reply_timer);

	dispatch_source_forget(&me->idle_timer);
	uint32_t idle_interval_ms;
	if (me->request_list) {
		idle_interval_ms = DX_SESSION_IDLE_TIMEOUT_WITH_REQUESTS_MS;
	} else {
		idle_interval_ms = DX_SESSION_IDLE_TIMEOUT_WITHOUT_REQUESTS_MS;
	}
	me->idle_timer = _dx_create_oneshot_timer(idle_interval_ms, 5);
	require_return(me->idle_timer);

	dispatch_source_set_event_handler(me->idle_timer,
	^{
		dispatch_source_forget(&me->idle_timer);
		if (me->request_list) {
			_dx_session_send_keepalive_message(me);
		} else {
			_dx_session_terminate(me, mdns_termination_reason_idle);
		}
	});
	dispatch_activate(me->idle_timer);
}

//======================================================================================================================

static bool
_dx_session_has_entitlement(const dx_session_t me, const char * const entitlement)
{
	bool entitled = false;
	if (me->connection) {
		entitled = mdns_xpc_connection_is_entitled(me->connection, entitlement);
	}
	return entitled;
}

//======================================================================================================================

static bool
_dx_session_has_delegate_entitlement(const dx_session_t me)
{
	return _dx_session_has_entitlement(me, "com.apple.private.network.socket-delegate");
}

//======================================================================================================================

static bool
_dx_session_has_prohibit_encrypted_dns_entitlement(const dx_session_t me)
{
	return _dx_session_has_entitlement(me, "com.apple.private.dnssd.prohibit-encrypted-dns");
}

//======================================================================================================================

static void
_dx_session_log_error(const dx_session_t me, const DNSServiceErrorType error)
{
	os_log_error(_mdns_server_log(),
		"XPC session error -- error: %{mdns:err}ld, client pid: %lld (%{public}s)",
		(long)error, (long long)me->client_pid, me->client_name);
}

//======================================================================================================================

static void
_dx_session_log_pending_send_count_increase(const dx_session_t me)
{
	os_log_debug(_mdns_server_log(),
		"XPC session to client with pid %lld (%{public}s) pending send count increased to %d",
		(long long)me->client_pid, me->client_name, me->pending_send_count);
}

//======================================================================================================================

static void
_dx_session_log_pending_send_count_decrease(const dx_session_t me)
{
	os_log_debug(_mdns_server_log(),
		"XPC session to client with pid %lld (%{public}s) pending send count decreased to %d",
		(long long)me->client_pid, me->client_name, me->pending_send_count);
}

//======================================================================================================================

static void
_dx_session_log_termination(const dx_session_t me, const mdns_termination_reason_t reason)
{
	os_log_with_type(_mdns_server_log(),
		(reason == mdns_termination_reason_idle) ? OS_LOG_TYPE_INFO : OS_LOG_TYPE_DEFAULT,
		"Session terminated -- reason: %{mdns:termination_reason}d, pending send count: %u, client pid: %lld "
		"(%{public}s)",
		reason, me->pending_send_count, (long long)me->client_pid, me->client_name);
}

//======================================================================================================================
// MARK: - Request Methods

static void
_dx_request_init(const dx_request_t me)
{
	me->request_id	= dnssd_server_get_new_request_id();
	me->lock		= OS_UNFAIR_LOCK_INIT;
}

//======================================================================================================================

static void
_dx_request_finalize(const dx_request_t me)
{
	_dx_forget(&me->session);
	xpc_forget(&me->results);
}

//======================================================================================================================

static xpc_object_t
_dx_request_take_results(const dx_request_t me)
{
	const dx_request_kind_t kind = (dx_request_kind_t)me->base.kind;
	if (kind->take_results) {
		return kind->take_results(me);
	} else {
		return NULL;
	}
}

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
static void
_dx_request_report_powerlog_progress(const dx_request_t me)
{
	const dx_request_kind_t kind = (dx_request_kind_t)me->base.kind;
	if (kind->report_powerlog_progress) {
		kind->report_powerlog_progress(me);
	}
}
#endif

//======================================================================================================================

static void
_dx_request_locked(const dx_any_request_t any, const dx_block_t block)
{
	const dx_request_t me = any.request;
	os_unfair_lock_lock(&me->lock);
	block();
	os_unfair_lock_unlock(&me->lock);
}

//======================================================================================================================

static DNSServiceErrorType
_dx_request_get_error(const dx_any_request_t any)
{
	const dx_request_t me = any.request;
	__block DNSServiceErrorType error;
	_dx_request_locked(me,
	^{
		error = me->error;
	});
	return error;
}

//======================================================================================================================

static bool
_dx_request_set_error(const dx_any_request_t any, const DNSServiceErrorType error)
{
	__block bool did_set = false;
	if (error) {
		const dx_request_t me = any.request;
		_dx_request_locked(me,
		^{
			if (!me->error) {
				me->error = error;
				did_set = true;
			}
		});
	}
	return did_set;
}

//======================================================================================================================

static bool
_dx_request_send_pending_error(const dx_any_request_t any)
{
	bool ok = false;
	const dx_request_t me = any.request;
	const DNSServiceErrorType error = _dx_request_get_error(me);
	if (error && !me->sent_error) {
		xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
		require_quiet(msg, exit);

		dnssd_xpc_message_set_id(msg, me->command_id);
		dnssd_xpc_message_set_error(msg, error);
		_dx_session_send_message(me->session, msg);
		xpc_forget(&msg);
		me->sent_error = true;
	}
	ok = true;

exit:
	return ok;
}

//======================================================================================================================
// MARK: - GetAddrInfo Request Methods

static dx_gai_request_t
_dx_gai_request_create(const uint64_t command_id, const dx_session_t session)
{
	dx_gai_request_t obj = _dx_gai_request_new();
	require_quiet(obj, exit);

	obj->base.command_id = command_id;
	obj->base.session    = session;
	_dx_retain(obj->base.session);

exit:
	return obj;
}

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
static DNSServiceErrorType
_dx_gai_request_trust_check(dx_gai_request_t request, bool *out_defer_start);
#endif

static DNSServiceErrorType
_dx_gai_request_activate(const dx_gai_request_t me)
{
	DNSServiceErrorType err;
	bool defer_start = false;
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
	bool privacy_check_done = false;
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	privacy_check_done = (me->signed_resolve != NULL);
#endif
	if (!privacy_check_done && os_feature_enabled(mDNSResponder, bonjour_privacy)) {
		err = _dx_gai_request_trust_check(me, &defer_start);
		require_noerr_quiet(err, exit);
	}
#endif
	if (!defer_start) {
		err = _dx_gai_request_start_client_requests(me, true);
		require_noerr_quiet(err, exit);
	}
	err = kDNSServiceErr_NoError;

exit:
	return err;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
static DNSServiceErrorType
_dx_gai_request_trust_check(const dx_gai_request_t me, bool * const out_defer_start)
{
	DNSServiceErrorType err;
	bool defer_start = false;
	const dx_session_t session = me->base.session;
    const audit_token_t *const token = mdns_audit_token_get_token(session->peer_token);
	mdns_trust_flags_t flags = mdns_trust_flags_none;
	const mdns_trust_status_t status = mdns_trust_check_getaddrinfo(*token, me->hostname, &flags);
	switch (status) {
		case mdns_trust_status_granted:
			err = kDNSServiceErr_NoError;
			break;

		case mdns_trust_status_denied:
		case mdns_trust_status_pending:
			me->trust = mdns_trust_create(*token, NULL, flags);
			require_action_quiet(me->trust, exit, err = kDNSServiceErr_NoMemory);

			_dx_retain(me);
			mdns_trust_set_queue(me->trust, _dx_server_queue());
			mdns_trust_set_event_handler(me->trust,
			^(const mdns_trust_event_t event, const mdns_trust_status_t update)
			{
				if (me->trust && (event == mdns_trust_event_result)) {
					DNSServiceErrorType handler_err;
					if (update == mdns_trust_status_granted) {
						handler_err = _dx_gai_request_start_client_requests(me, true);
					} else {
						handler_err = kDNSServiceErr_PolicyDenied;
					}
					if (handler_err && _dx_request_set_error(me, handler_err)) {
						_dx_gai_request_log_error(me, handler_err);
						_dx_request_send_pending_error(me);
					}
				}
				mdns_forget(&me->trust);
				_dx_release(me);
			});
			mdns_trust_activate(me->trust);
			defer_start = true;
			err = kDNSServiceErr_NoError;
			break;

		case mdns_trust_status_no_entitlement:
			err = kDNSServiceErr_NoAuth;
			break;

		CUClangWarningIgnoreBegin(-Wcovered-switch-default);
		default:
		CUClangWarningIgnoreEnd();
			err = kDNSServiceErr_Unknown;
			break;
	}

exit:
	if (out_defer_start) {
		*out_defer_start = defer_start;
	}
	return err;
}
#endif

//======================================================================================================================

static void
_dx_gai_request_invalidate(const dx_gai_request_t me)
{
	_dx_gai_request_log_stop(me);
	_dx_gai_request_stop_client_requests(me, true);
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	if (me->custom_service_id != MDNS_DNS_SERVICE_INVALID_ID) {
		Querier_DeregisterCustomDNSService(me->custom_service_id);
		me->custom_service_id = MDNS_DNS_SERVICE_INVALID_ID;
	}
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
	mdns_trust_forget(&me->trust);
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	mdns_forget(&me->signed_resolve);
#endif
	mdns_forget(&me->last_domain_name);
	mdns_xpc_string_forget(&me->last_tracker_hostname);
	mdns_xpc_string_forget(&me->last_tracker_owner);
}

//======================================================================================================================

static void
_dx_gai_request_finalize(const dx_gai_request_t me)
{
	_dx_gai_result_list_forget(&me->results);
	ForgetMem(&me->hostname);
	ForgetMem(&me->svcb_name_memory);
	xpc_forget(&me->cnames_a);
	xpc_forget(&me->cnames_aaaa);
	mdns_forget(&me->delegator_token);
	xpc_forget(&me->fallback_dns_config);
	ForgetMem(&me->resolver_uuid);
	_dx_forget(&me->pending_suppresed_a);
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_parse_params(const dx_gai_request_t me, const xpc_object_t params)
{
	DNSServiceErrorType err;
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	mdns_signed_resolve_result_t signed_resolve = NULL;
#endif
	const char * const hostname = dnssd_xpc_parameters_get_hostname(params);
	require_action_quiet(hostname, exit, err = kDNSServiceErr_BadParam);

	me->hostname = mdns_strdup(hostname);
	require_action_quiet(me->hostname, exit, err = kDNSServiceErr_NoMemory);

	bool valid;
	me->flags = dnssd_xpc_parameters_get_flags(params, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	me->ifindex = dnssd_xpc_parameters_get_interface_index(params, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	me->protocols = dnssd_xpc_parameters_get_protocols(params, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	const dx_session_t session = me->base.session;

	// Get delegator IDs.
	pid_t delegator_pid;
	const uint8_t *delegator_uuid;
	audit_token_t storage;
	const audit_token_t * const delegator_token = dnssd_xpc_parameters_get_delegate_audit_token(params, &storage);
	if (delegator_token) {
		me->delegator_token = mdns_audit_token_create(delegator_token);
		require_action_quiet(me->delegator_token, exit, err = kDNSServiceErr_NoMemory);
	}
	if (me->delegator_token) {
		delegator_pid  = mdns_audit_token_get_pid(me->delegator_token);
		delegator_uuid = NULL;
	} else {
		delegator_uuid = dnssd_xpc_parameters_get_delegate_uuid(params);
		if (delegator_uuid) {
			delegator_pid = 0;
		} else {
			delegator_pid = dnssd_xpc_parameters_get_delegate_pid(params, NULL);
		}
	}
	if (me->delegator_token || delegator_uuid || (delegator_pid != 0)) {
		const bool entitled = _dx_session_has_delegate_entitlement(session);
		require_action_quiet(entitled, exit, err = kDNSServiceErr_NoAuth);
	}

	// Determine effective IDs.
	// Note: The mDNS core requires that the effective PID be set to zero if the effective UUID is the primary ID.
	if (delegator_uuid) {
		uuid_copy(me->effective_uuid, delegator_uuid);
		me->effective_pid = 0;
	} else {
		uuid_clear(me->effective_uuid);
		me->effective_pid = (delegator_pid != 0) ? delegator_pid : session->client_pid;
	}

	// Determine if an SVCB or HTTPS query is necessary.
	const char * const service_scheme = dnssd_xpc_parameters_get_service_scheme(params);
	if (service_scheme) {
		if (strcasecmp(service_scheme, "_443._https") == 0) {
			me->svcb_name = me->hostname;
			me->svcb_type = kDNSType_HTTPS;
		} else {
			asprintf(&me->svcb_name_memory, "%s.%s", service_scheme, me->hostname);
			require_action_quiet(me->svcb_name_memory, exit, err = kDNSServiceErr_NoMemory);

			me->svcb_name = me->svcb_name_memory;
			me->svcb_type = kDNSType_SVCB;
		}
	}
	me->fallback_dns_config = dnssd_xpc_parameters_get_fallback_config(params);
	if (me->fallback_dns_config) {
		xpc_retain(me->fallback_dns_config);
	}
	const uint8_t * const resolver_uuid = _dx_gai_request_get_resolver_uuid(params);
	if (resolver_uuid) {
		me->resolver_uuid = (uuid_t *)mdns_memdup(resolver_uuid, sizeof(*me->resolver_uuid));
		require_action_quiet(me->resolver_uuid, exit, err = kDNSServiceErr_NoMemory);
	}
	if (dnssd_xpc_parameters_get_need_encrypted_query(params)) {
		me->options |= mdns_gai_option_need_encryption;
	}
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	if (_dx_gai_request_is_for_in_app_browser(params)) {
		me->options |= mdns_gai_option_in_app_browser;
	}
#endif
	if (dnssd_xpc_parameters_get_use_failover(params)) {
		me->options |= mdns_gai_option_use_failover;
	}
	if (me->options & mdns_gai_option_use_failover) {
		if ((me->protocols & kDNSServiceProtocol_IPv4) || !(me->protocols & kDNSServiceProtocol_IPv6)) {
			me->state |= dx_gai_state_waiting_for_a;
		}
		if ((me->protocols & kDNSServiceProtocol_IPv6) || !(me->protocols & kDNSServiceProtocol_IPv4)) {
			me->state |= dx_gai_state_waiting_for_aaaa;
		}
	}
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	me->log_privacy_level = dnssd_xpc_parameters_get_log_privacy_level(params);
#endif
	if (dnssd_xpc_parameters_get_prohibit_encrypted_dns(params)) {
		const bool entitled = _dx_session_has_prohibit_encrypted_dns_entitlement(session);
		require_action_quiet(entitled, exit, err = kDNSServiceErr_NoAuth);

		me->options |= mdns_gai_option_prohibit_encrypted_dns;
	}
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	size_t signed_data_len;
	const uint8_t * const signed_data = dnssd_xpc_parameters_get_validation_data(params, &signed_data_len);
	if (signed_data) {
		// Get signed_result data and validate
		OSStatus create_err;
		signed_resolve = mdns_signed_resolve_result_create_from_data(signed_data, signed_data_len, &create_err);
		require_action_quiet(signed_resolve, exit, err = kDNSServiceErr_Invalid; os_log_error(_mdns_server_log(),
			"[R%u] Failed to create signed resolve result from data: %{mdns:err}ld",
			me->base.request_id, (long)create_err));

		// Use signed result to verify params otherwise don't set the signed result instance to fallback to trust
		if (mdns_signed_resolve_result_contains(signed_resolve, me->hostname, me->ifindex)) {
			const bool allowed = mdns_system_is_signed_result_uuid_valid(mdns_signed_result_get_uuid(signed_resolve));
			require_action_quiet(allowed, exit, err = kDNSServiceErr_PolicyDenied; os_log_error(_mdns_server_log(),
				"[R%u] Signed result UUID revoked.", me->base.request_id));

			os_log_debug(_mdns_server_log(), "[R%u] Allowing signed result", me->base.request_id);
			me->signed_resolve = signed_resolve;
			signed_resolve = NULL;
		} else {
			os_log_error(_mdns_server_log(),
				"[R%u] Signed resolve result does not cover request -- hostname: %{private,mask.hash}s, ifindex: %u",
				me->base.request_id, me->hostname, me->ifindex);
		}
	}
#endif
	_dx_gai_request_log_start(me, delegator_pid, delegator_uuid);
	err = kDNSServiceErr_NoError;

exit:
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	mdns_forget(&signed_resolve);
#endif
	return err;
}

//======================================================================================================================

static dx_gai_result_t
_dx_gai_request_take_expired_results(dx_gai_request_t request);

static xpc_object_t
_dx_gai_request_take_results(const dx_gai_request_t me)
{
	DNSServiceErrorType err;
	xpc_object_t result_array = NULL;
	__block dx_gai_result_t result_list = NULL;
	_dx_request_locked(me,
	^{
		if (me->state & DX_GAI_STATE_WAITING_FOR_RESULTS) {
			result_list = _dx_gai_request_take_expired_results(me);
		} else {
			result_list = me->results;
			me->results = NULL;
		}
	});
	if (result_list) {
		result_array = xpc_array_create(NULL, 0);
		require_action_quiet(result_array, exit, err = kDNSServiceErr_NoMemory);

		dx_gai_result_t result;
		while ((result = result_list) != NULL) {
			xpc_object_t result_dict = _dx_gai_result_to_dictionary(result);
			require_action_quiet(result_dict, exit, err = kDNSServiceErr_NoMemory);

			_dx_gai_result_log(result, me->base.request_id);
			result_list = result->next;
			_dx_forget(&result);

			xpc_array_append_value(result_array, result_dict);
			xpc_forget(&result_dict);
		}
	}
	err = kDNSServiceErr_NoError;

exit:
	_dx_gai_result_list_forget(&result_list);
	if (err) {
		_dx_request_set_error(me, err);
	}
	return result_array;
}

static dx_gai_result_t
_dx_gai_request_take_expired_results(const dx_gai_request_t me)
{
	dx_gai_result_t expired_results = NULL;
	dx_gai_result_t *expired_ptr = &expired_results;
	dx_gai_result_t result;
	dx_gai_result_t *ptr = &me->results;
	while ((result = *ptr) != NULL) {
		if (result->flags & kDNSServiceFlagsExpiredAnswer) {
			*ptr = result->next;
			result->next = NULL;
			*expired_ptr = result;
			expired_ptr = &result->next;
		} else {
			ptr = &result->next;
		}
	}
	return expired_results;
}

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
static void
_dx_gai_request_report_powerlog_progress(const dx_gai_request_t me)
{
	if (me->powerlog_start_time != 0) {
		const mDNSBool uses_awdl = ClientRequestUsesAWDL(me->ifindex, me->flags);
		mdns_powerlog_getaddrinfo_progress(me->effective_pid, me->base.request_id, me->powerlog_start_time, uses_awdl);
	}
}
#endif

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_start_client_requests_internal(const dx_gai_request_t me,
	GetAddrInfoClientRequestParams * const gai_params, QueryRecordClientRequestParams * const query_params,
	const bool need_lock)
{
	__block DNSServiceErrorType err = kDNSServiceErr_NoError;
	_dx_kqueue_locked("dx_gai_request: starting client requests", need_lock,
	^{
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		if (me->resolver_uuid && !uuid_is_null(*me->resolver_uuid)) {
			Querier_RegisterPathResolver(*me->resolver_uuid);
		}
		if ((me->custom_service_id == MDNS_DNS_SERVICE_INVALID_ID) && me->fallback_dns_config) {
			me->custom_service_id = Querier_RegisterCustomDNSService(me->fallback_dns_config);
		}
		if (gai_params) {
			gai_params->resolverUUID	= *me->resolver_uuid;
			gai_params->customID		= me->custom_service_id;
		}
		if (query_params) {
			query_params->resolverUUID	= *me->resolver_uuid;
			query_params->customID		= me->custom_service_id;
		}
#endif
		// If present, run the query for SVCB/HTTPS first, in case the ALPN and address hints come back first.
		if (query_params && !me->query) {
			me->query = _dx_query_record_client_request_start(query_params, _dx_gai_request_query_result_handler, me,
				&err);
			require_noerr_return(err);
		}
		// Run the A/AAAA lookup.
		if (gai_params && !me->gai) {
			me->gai = _dx_get_addr_info_client_request_start(gai_params, _dx_gai_request_gai_result_handler, me, &err);
			require_noerr_return(err);
		#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
			if (me->gai) {
				const domainname *const qname = GetAddrInfoClientRequestGetQName(me->gai);
				if ((me->ifindex != kDNSServiceInterfaceIndexLocalOnly) && IsLocalDomain(qname)) {
					const mDNSBool uses_awdl = ClientRequestUsesAWDL(me->ifindex, me->flags);
					me->powerlog_start_time = mdns_powerlog_getaddrinfo_start(me->effective_pid, me->base.request_id,
						uses_awdl);
				}
			}
		#endif
		}
	});
	if (err) {
		_dx_gai_request_stop_client_requests(me, need_lock);
	}
	return err;
}

//======================================================================================================================

static void
_dx_gai_request_stop_client_requests(const dx_gai_request_t me, const bool need_lock)
{
	_dx_kqueue_locked("dx_gai_request: stopping client requests", need_lock,
	^{
		_dx_get_addr_info_client_request_forget(&me->gai);
	#if MDNSRESPONDER_SUPPORTS(APPLE, POWERLOG_MDNS_REQUESTS)
		if (me->powerlog_start_time != 0) {
			const mDNSBool uses_awdl = ClientRequestUsesAWDL(me->ifindex, me->flags);
			mdns_powerlog_getaddrinfo_stop(me->effective_pid, me->base.request_id, me->powerlog_start_time, uses_awdl);
			me->powerlog_start_time = 0;
		}
	#endif
		_dx_query_record_client_request_forget(&me->query);
	});
}

//======================================================================================================================

static void
_dx_gai_request_restart_client_requests_in_failover_mode(const dx_gai_request_t me)
{
	if (!(me->state & dx_gai_state_failover_mode)) {
		_dx_gai_request_stop_client_requests(me, false);
		os_log(_mdns_server_log(), "[R%u] getaddrinfo failover restart", me->base.request_id);
		me->state |= dx_gai_state_failover_mode;
		_dx_gai_request_start_client_requests(me, false);
	}
}

//======================================================================================================================

static xpc_object_t *
_dx_gai_request_get_cnames_ptr(const dx_gai_request_t me, const int qtype, bool ** const out_changed_ptr)
{
	xpc_object_t *cnames_ptr;
	bool *changed_ptr;
	switch (qtype) {
		case kDNSServiceType_A:
			cnames_ptr		= &me->cnames_a;
			changed_ptr		= &me->cnames_a_changed;
			break;

		case kDNSServiceType_AAAA:
			cnames_ptr		= &me->cnames_aaaa;
			changed_ptr		= &me->cnames_aaaa_changed;
			break;

		default:
			cnames_ptr		= NULL;
			changed_ptr		= NULL;
			break;
	}
	if (out_changed_ptr) {
		*out_changed_ptr = changed_ptr;
	}
	return cnames_ptr;
}

//======================================================================================================================

static void
_dx_gai_request_reset_cnames(const dx_gai_request_t me, const int qtype)
{
	bool *changed_ptr;
	xpc_object_t * const cnames_ptr = _dx_gai_request_get_cnames_ptr(me, qtype, &changed_ptr);
	require_quiet(cnames_ptr, exit);

	xpc_forget(cnames_ptr);
	*cnames_ptr = xpc_array_create_empty();
	*changed_ptr = true;

exit:
	return;
}

//======================================================================================================================

static void
_dx_gai_request_append_cname(const dx_gai_request_t me, const int qtype, const domainname * const cname,
	const bool expired)
{
	bool *changed_ptr;
	xpc_object_t * const cnames_ptr = _dx_gai_request_get_cnames_ptr(me, qtype, &changed_ptr);
	require_quiet(cnames_ptr, exit);

	const char *cname_str = NULL;
	char cname_buf[MAX_ESCAPED_DOMAIN_NAME];
	if (cname) {
		if (!ConvertDomainNameToCString(cname, cname_buf)) {
			cname_buf[0] = '\0';
		}
		cname_str = cname_buf;
	}
	_dx_request_locked(me,
	^{
		if (cname_str) {
			xpc_object_t cnames = *cnames_ptr;
			if (!cnames) {
				cnames = xpc_array_create(NULL, 0);
				*cnames_ptr = cnames;
			}
			if (cnames) {
				xpc_array_set_string(cnames, XPC_ARRAY_APPEND, cname_str);
				*changed_ptr = true;
			}
		}
	});
	if ((me->state & dx_gai_state_avoid_suppressed_a_result) && !expired) {
		// An intermediate CNAME result for the A DNSQuestion means that the last pending negative result is no
		// longer relevant, so it can be dropped.
		if (cname && (qtype == kDNSType_A)) {
			_dx_forget(&me->pending_suppresed_a);
		}
	}

exit:
	return;
}

//======================================================================================================================

static xpc_object_t
_dx_gai_request_copy_cname_update(const dx_gai_request_t me, const int qtype)
{
	__block xpc_object_t result = NULL;
	bool *changed_ptr;
	xpc_object_t * const cnames_ptr = _dx_gai_request_get_cnames_ptr(me, qtype, &changed_ptr);
	require_quiet(cnames_ptr, exit);

	_dx_request_locked(me,
	^{
		if (*changed_ptr) {
			const xpc_object_t cnames = *cnames_ptr;
			if (cnames) {
				result = xpc_copy(cnames);
			}
			*changed_ptr = false;
		}
	});

exit:
	return result;
}

//======================================================================================================================

static void
_dx_gai_request_failover_check_gai_answer(dx_gai_request_t request, const ResourceRecord *answer);

static void
_dx_gai_request_gai_result_handler(mDNS * const m, DNSQuestion * const q, const ResourceRecord * const answer,
	const mDNSBool expired, const QC_result qc_result, const DNSServiceErrorType error, void * const context)
{
	(void)m;
	bool failover_restart = false;
	const dx_gai_request_t me = (dx_gai_request_t)context;
	if (!error || (error == kDNSServiceErr_NoSuchRecord)) {
		_dx_gai_request_failover_check_gai_answer(me, answer);
		if (q->CNAMEReferrals == 0) {
			_dx_gai_request_reset_cnames(me, q->qtype);
		}
		if (answer->rrtype == kDNSServiceType_CNAME) {
			require_quiet(!error, exit);

			_dx_gai_request_append_cname(me, q->qtype, &answer->rdata->u.name, expired);
		}
		require_quiet((answer->rrtype == kDNSServiceType_A) || (answer->rrtype == kDNSServiceType_AAAA), exit);

		const uint8_t *rdata_ptr;
		uint16_t rdata_len;
		if (!error) {
			if (answer->rrtype == kDNSServiceType_A) {
				rdata_ptr = answer->rdata->u.ipv4.b;
				rdata_len = 4;
			} else {
				rdata_ptr = answer->rdata->u.ipv6.b;
				rdata_len = 16;
			}
		} else {
			rdata_ptr = NULL;
			rdata_len = 0;
		}
		failover_restart = _dx_gai_request_check_for_failover_restart(me, answer, expired, rdata_len > 0);
		if (!failover_restart) {
			_dx_gai_request_enqueue_result(me, qc_result, answer, expired, rdata_ptr, rdata_len, error, q);
		}
	} else {
		_dx_request_set_error(me, error);
	}

exit:
	if (failover_restart) {
		_dx_gai_request_restart_client_requests_in_failover_mode(me);
	}
}

static void
_dx_gai_request_failover_check_gai_answer(const dx_gai_request_t me, const ResourceRecord * const answer)
{
	if ((me->state & DX_GAI_STATE_WAITING_FOR_RESULTS) && !(me->state & dx_gai_state_service_allowed_failover)) {
		const mdns_dns_service_t dnsservice = mdns_cache_metadata_get_dns_service(answer->metadata);
		if (dnsservice && mdns_dns_service_allows_failover(dnsservice)) {
			me->state |= dx_gai_state_service_allowed_failover;
		}
	}
}

//======================================================================================================================

static void
_dx_gai_request_query_result_handler(mDNS * const m, DNSQuestion * const q, const ResourceRecord * const answer,
    const mDNSBool expired, const QC_result qc_result, const DNSServiceErrorType error, void * const context)
{
	(void)m;
	bool failover_restart = false;
	const dx_gai_request_t me = (dx_gai_request_t)context;
	if (!error || (error == kDNSServiceErr_NoSuchRecord)) {
		require_quiet((answer->rrtype == kDNSServiceType_SVCB) || (answer->rrtype == kDNSServiceType_HTTPS), exit);

		const uint8_t *rdata_ptr;
		uint16_t rdata_len;
		if (!error) {
			rdata_ptr = answer->rdata->u.data;
			rdata_len = answer->rdlength;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
			char *svcb_doh_uri = dnssd_svcb_copy_doh_uri(rdata_ptr, rdata_len);
			// Check for a valid DoH URI.
			if (svcb_doh_uri) {
				// Pass the domain to map if the record is DNSSEC signed.
				char *svcb_domain = NULL;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
				char svcb_domain_buffer[MAX_ESCAPED_DOMAIN_NAME] = "";
				if (resource_record_get_validation_result(answer) == dnssec_secure) {
					if (ConvertDomainNameToCString(answer->name, svcb_domain_buffer)) {
						svcb_domain = svcb_domain_buffer;
					}
				}
#endif
				Querier_RegisterDoHURI(svcb_doh_uri, svcb_domain);
				ForgetMem(&svcb_doh_uri);
			}
#endif
		} else {
			rdata_ptr = NULL;
			rdata_len = 0;
		}
		failover_restart = _dx_gai_request_check_for_failover_restart(me, answer, expired, rdata_len > 0);
		if (!failover_restart) {
			_dx_gai_request_enqueue_result(me, qc_result, answer, expired, rdata_ptr, rdata_len, error, q);
		}
	} else {
		_dx_request_set_error(me, error);
	}

exit:
	if (failover_restart) {
		_dx_gai_request_restart_client_requests_in_failover_mode(me);
	}
}

//======================================================================================================================

static bool
_dx_gai_request_needs_sensitive_logging(const dx_gai_request_t me)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	return (me->log_privacy_level == dnssd_log_privacy_level_private);
#else
	return false;
#endif
}

//======================================================================================================================

static void
_dx_gai_request_append_result(const dx_gai_request_t me, const dx_gai_result_t result)
{
	result->cname_update = _dx_gai_request_copy_cname_update(me, mdns_resource_record_get_type(result->record));
	_dx_request_locked(me,
	^{
		dx_gai_result_t *ptr = &me->results;
		while (*ptr) {
			ptr = &(*ptr)->next;
		}
		*ptr = result;
		_dx_retain(*ptr);
	});
}

//======================================================================================================================

static dnssd_negative_reason_t
_dx_get_negative_answer_reason(const ResourceRecord *answer, QC_result qc_result);

static void
_dx_gai_request_enqueue_result(const dx_gai_request_t me, const QC_result qc_result,
	const ResourceRecord * const answer, const bool answer_is_expired, const uint8_t * const rdata_ptr,
	const uint16_t rdata_len, const DNSServiceErrorType result_error, const DNSQuestion * const q)
{
	DNSServiceErrorType err;
	dx_gai_result_t result = NULL;
	require_action_quiet(!answer_is_expired || (rdata_len > 0), exit, err = kDNSServiceErr_NoError);

	result = _dx_gai_result_new();
	require_action_quiet(result, exit, err = kDNSServiceErr_NoMemory);

	_dx_replace_domain_name(&me->last_domain_name, answer->name);
	require_action_quiet(me->last_domain_name, exit, err = kDNSServiceErr_NoMemory);

	result->record = mdns_resource_record_create(me->last_domain_name, answer->rrtype, answer->rrclass, 0,
		rdata_ptr, rdata_len, NULL);
	require_action_quiet(result->record, exit, err = kDNSServiceErr_NoMemory);

	DNSServiceFlags flags = 0;
	const bool is_add = _dx_qc_result_is_add(qc_result);
	if (is_add) {
		flags |= kDNSServiceFlagsAdd;
		if (!q->InitialCacheMiss) {
			flags |= kDNSServiceFlagAnsweredFromCache;
		}
		if (rdata_len <= 0) {
			result->negative_reason = _dx_get_negative_answer_reason(answer, qc_result);
		}
		result->extended_dns_error = mdns_cache_metadata_get_extended_dns_error(answer->metadata);
		mdns_retain_null_safe(result->extended_dns_error);
	}
	if (answer_is_expired) {
		flags |= kDNSServiceFlagsExpiredAnswer;
	}
	extern mDNS mDNSStorage;
	result->flags       = flags;
	result->error       = result_error;
	result->ifindex     = mDNSPlatformInterfaceIndexfromInterfaceID(&mDNSStorage, answer->InterfaceID, mDNStrue);
	result->protocol    = mdns_cache_metadata_get_protocol(answer->metadata);
	result->question_id = mDNSVal16(q->TargetQID);
	const mdns_dns_service_t dnsservice = mdns_cache_metadata_get_dns_service(answer->metadata);
	if (dnsservice) {
		result->provider_name = mdns_dns_service_copy_provider_name(dnsservice);
	}
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	result->sensitive_logging = _dx_gai_request_needs_sensitive_logging(me);
#endif
	const uint16_t record_type = mdns_resource_record_get_type(result->record);
	if (is_add && !result_error) {
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
		if (me->signed_resolve && ((record_type == kDNSType_A) || (record_type == kDNSType_AAAA))) {
			OSStatus create_err;
			mdns_signed_hostname_result_t signed_hostname;
			if (record_type == kDNSType_A) {
				signed_hostname = mdns_signed_hostname_result_create_ipv4(me->signed_resolve, rdata_ptr, &create_err);
			} else {
				signed_hostname = mdns_signed_hostname_result_create_ipv6(me->signed_resolve, rdata_ptr,
					result->ifindex, &create_err);
			}
			result->signed_hostname = signed_hostname;
			if (!result->signed_hostname) {
				os_log_error(_mdns_server_log(),
					"[R%u] Failed to create IPv%d signed hostname result: %{mdns:err}ld",
					me->base.request_id, (record_type == kDNSType_A) ? 4 : 6, (long)create_err);
			}
		}
#endif
	}
#if MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)
	if (resolved_cache_is_enabled() && is_add) {
		const char *hostname = NULL;
		const char *owner = NULL;
		bool approved_domain = false;
		bool can_block_request = false;
		const tracker_state_t tracker_state = resolved_cache_get_tracker_state(q, &hostname, &owner, &approved_domain,
			&can_block_request);
		if ((tracker_state == tracker_state_known_tracker) && hostname) {
			mdns_xpc_string_recreate(&me->last_tracker_hostname, hostname);
			require_action_quiet(me->last_tracker_hostname, exit, err = kDNSServiceErr_NoMemory);

			result->tracker_hostname = me->last_tracker_hostname;
			xpc_retain(result->tracker_hostname);
			if (owner) {
				mdns_xpc_string_recreate(&me->last_tracker_owner, owner);
				require_action_quiet(me->last_tracker_owner, exit, err = kDNSServiceErr_NoMemory);

				result->tracker_owner = me->last_tracker_owner;
				mdns_xpc_string_retain(result->tracker_owner);
			}
			if (approved_domain) {
				result->tracker_is_approved = true;
			}
			if (can_block_request) {
				result->tracker_can_block = true;
			}
		}
	}
#endif
	if ((me->state & dx_gai_state_avoid_suppressed_a_result) && !answer_is_expired) {
		switch (record_type) {
			case kDNSType_A:
				if (result->negative_reason == dnssd_negative_reason_query_suppressed) {
					// Put a negative suppressed A result on hold.
					_dx_replace(&me->pending_suppresed_a, result);
					err = kDNSServiceErr_NoError;
					goto exit;
				} else {
					// Any other type of A result means that if there's a pending negative suppressed A result,
					// then it can be dropped. It also means that we no longer care about avoiding negative
					// suppressed A results.
					_dx_forget(&me->pending_suppresed_a);
					SetOrClearBits(&me->state, dx_gai_state_avoid_suppressed_a_result, false);
				}
				break;

			case kDNSType_AAAA:
				// A AAAA result means that if there's a pending negative suppressed A result, then it should no
				// longer be kept from the client. It also means that we no longer care about avoiding negative
				// suppressed A results because if the A DNSQuestion was stuck at a DNS service that suppresses A
				// queries, then it should have advanced past it by now if there was a CNAME chain to traverse
				// because the AAAA DNSQuestion just did.
				if (me->pending_suppresed_a) {
					_dx_gai_request_append_result(me, me->pending_suppresed_a);
					_dx_forget(&me->pending_suppresed_a);
				}
				SetOrClearBits(&me->state, dx_gai_state_avoid_suppressed_a_result, false);
				break;
		}
	}
	_dx_gai_request_append_result(me, result);
	err = kDNSServiceErr_NoError;

exit:
	static_analyzer_malloc_freed(result); // Analyzer isn't aware that result will be freed if non-NULL.
	_dx_forget(&result);
	if (err) {
		_dx_request_set_error(me, err);
	}
}

static dnssd_negative_reason_t
_dx_get_negative_answer_reason(const ResourceRecord * const answer, const QC_result qc_result)
{
	const mdns_dns_service_t dnsservice = mdns_cache_metadata_get_dns_service(answer->metadata);
	if (dnsservice) {
		if (_dx_qc_result_is_suppressed(qc_result)) {
			return dnssd_negative_reason_query_suppressed;
		} else {
			switch (answer->rcode) {
				case kDNSFlag1_RC_NoErr:
					return dnssd_negative_reason_no_data;

				case kDNSFlag1_RC_NXDomain:
					return dnssd_negative_reason_nxdomain;

				default:
					return dnssd_negative_reason_server_error;
			}
		}
	} else {
		if (answer->InterfaceID) {
			// A non-zero InterfaceID means that an mDNS NSEC record asserted that there's no data for the record.
			return dnssd_negative_reason_no_data;
		} else {
			return dnssd_negative_reason_no_dns_service;
		}
	}
}

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
static const uint8_t *
_dx_gai_request_get_resolver_uuid(const xpc_object_t params)
{
	const xpc_object_t resolver_uuids = dnssd_xpc_parameters_get_resolver_uuid_array(params);
	if (resolver_uuids && (xpc_array_get_count(resolver_uuids) > 0)) {
		return xpc_array_get_uuid(resolver_uuids, 0);
	} else {
		return NULL;
	}
}
#endif

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
static bool
_dx_gai_request_is_for_in_app_browser(const xpc_object_t params)
{
	const char * const account_id = dnssd_xpc_parameters_get_account_id(params);
	if (account_id && (strcmp(account_id, "com.apple.WebKit.InAppBrowser") == 0)) {
		return true;
	} else {
		return false;
	}
}
#endif

//======================================================================================================================

#define _dx_log_private_string_with_formatted_bookends(SENSITIVE, PREFIX_FMT, SUFFIX_FMT, ...)			\
	do {																								\
		if (SENSITIVE) {																				\
			os_log(_mdns_server_log(), PREFIX_FMT "%{sensitive,mask.hash}s" SUFFIX_FMT, __VA_ARGS__);	\
		} else {																						\
			os_log(_mdns_server_log(), PREFIX_FMT "%{private,mask.hash}s" SUFFIX_FMT, __VA_ARGS__);		\
		}																								\
	} while (0)

static void
_dx_gai_request_log_start(const dx_gai_request_t me, const pid_t delegator_pid, const uuid_t delegator_uuid)
{
	const dx_session_t session = me->base.session;
	const bool sensitive_logging = _dx_gai_request_needs_sensitive_logging(me);
	if (delegator_uuid) {
		_dx_log_private_string_with_formatted_bookends(sensitive_logging,
			"[R%u] getaddrinfo start -- flags: 0x%X, ifindex: %d, protocols: %u, hostname: ", /* hostname */
			", options: %{mdns:gaiopts}X, client pid: %lld (%{public}s), delegator uuid: %{public,uuid_t}.16P",
			me->base.request_id, me->flags, (int32_t)me->ifindex, me->protocols, me->hostname,
			me->options, (long long)session->client_pid, session->client_name, delegator_uuid);
	} else if (delegator_pid != 0) {
		char delegator_name[MAXCOMLEN];
		delegator_name[0] = '\0';
		mdns_system_pid_to_name(delegator_pid, delegator_name);
		_dx_log_private_string_with_formatted_bookends(sensitive_logging,
			"[R%u] getaddrinfo start -- flags: 0x%X, ifindex: %d, protocols: %u, hostname: ", /* hostname */
			", options: %{mdns:gaiopts}X, client pid: %lld (%{public}s), delegator pid: %lld (%{public}s)",
			me->base.request_id, me->flags, (int32_t)me->ifindex, me->protocols, me->hostname,
			me->options, (long long)session->client_pid, session->client_name, (long long)delegator_pid,
			delegator_name);
	} else {
		_dx_log_private_string_with_formatted_bookends(sensitive_logging,
			"[R%u] getaddrinfo start -- flags: 0x%X, ifindex: %d, protocols: %u, hostname: ", /* hostname */
			", options: %{mdns:gaiopts}X, client pid: %lld (%{public}s)",
			me->base.request_id, me->flags, (int32_t)me->ifindex, me->protocols, me->hostname,
			me->options, (long long)session->client_pid, session->client_name);
	}
}

//======================================================================================================================

static void
_dx_gai_request_log_stop(const dx_gai_request_t me)
{
	const dx_session_t session = me->base.session;
	const bool sensitive_logging = _dx_gai_request_needs_sensitive_logging(me);
	if (session->terminated) {
		_dx_log_private_string_with_formatted_bookends(sensitive_logging,
			"[R%u] getaddrinfo stop (forced) -- hostname: ", /* hostname */ ", client pid: %lld (%{public}s)",
			me->base.request_id, me->hostname, (long long)session->client_pid, session->client_name);
	} else {
		_dx_log_private_string_with_formatted_bookends(sensitive_logging,
			"[R%u] getaddrinfo stop -- hostname: ", /* hostname */ ", client pid: %lld (%{public}s)",
			me->base.request_id, me->hostname, (long long)session->client_pid, session->client_name);
	}
}

//======================================================================================================================

static void
_dx_gai_request_log_error(const dx_gai_request_t me, const DNSServiceErrorType error)
{
	const dx_session_t session = me->base.session;
	os_log_error(_mdns_server_log(),
		"[R%u] getaddrinfo error -- hostname: %{private,mask.hash}s, error: %{mdns:err}ld"", "
		"client pid: %lld (%{public}s)",
		me->base.request_id, me->hostname, (long)error, (long long)session->client_pid, session->client_name);
}

//======================================================================================================================

static bool
_dx_gai_request_involves_parallel_a_and_aaaa_questions(const dx_gai_request_t me)
{
	switch (me->protocols & (kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6)) {
		case 0:
			return true;

		case (kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6):
			return true;
	}
	return false;
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_start_client_requests(const dx_gai_request_t me, const bool need_lock)
{
	const dx_session_t session = me->base.session;

	// Set up GetAddrInfo parameters.
	GetAddrInfoClientRequestParams gai_params;
	GetAddrInfoClientRequestParamsInit(&gai_params);
	gai_params.hostnameStr				= me->hostname;
	gai_params.requestID				= me->base.request_id;
	gai_params.interfaceIndex			= me->ifindex;
	gai_params.flags					= me->flags;
	gai_params.protocols				= me->protocols;
	gai_params.effectivePID				= me->effective_pid;
	gai_params.effectiveUUID			= me->effective_uuid;
	gai_params.peerUID					= session->client_euid;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	gai_params.needEncryption			= (me->options & mdns_gai_option_need_encryption) != 0;
	gai_params.failoverMode				= (me->state & dx_gai_state_failover_mode) != 0;
	gai_params.prohibitEncryptedDNS		= (me->options & mdns_gai_option_prohibit_encrypted_dns) != 0;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	gai_params.peerToken				= session->peer_token;
	gai_params.delegatorToken			= me->delegator_token;
	gai_params.isInAppBrowserRequest	= (me->options & mdns_gai_option_in_app_browser) != 0;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	gai_params.logPrivacyLevel				= me->log_privacy_level;
#endif
	const bool will_have_parallel_a_and_aaaa = _dx_gai_request_involves_parallel_a_and_aaaa_questions(me);
	SetOrClearBits(&me->state, dx_gai_state_avoid_suppressed_a_result, will_have_parallel_a_and_aaaa);
	_dx_forget(&me->pending_suppresed_a);
	gai_params.persistWhenARecordsUnusable  = will_have_parallel_a_and_aaaa;

	// Set up QueryRecord parameters.
	QueryRecordClientRequestParams query_params;
	QueryRecordClientRequestParams *query_params_ptr = NULL;
	if (me->svcb_name) {
		QueryRecordClientRequestParamsInit(&query_params);
		query_params.requestID				= me->base.request_id;
		query_params.qnameStr				= me->svcb_name;
		query_params.interfaceIndex			= me->ifindex;
		query_params.flags					= me->flags;
		query_params.qtype					= me->svcb_type;
		query_params.qclass					= kDNSServiceClass_IN;
		query_params.effectivePID			= me->effective_pid;
		query_params.effectiveUUID			= me->effective_uuid;
		query_params.peerUID				= session->client_euid;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		query_params.needEncryption			= (me->options & mdns_gai_option_need_encryption) != 0;
		query_params.failoverMode			= (me->state & dx_gai_state_failover_mode) != 0;
		query_params.prohibitEncryptedDNS	= (me->options & mdns_gai_option_prohibit_encrypted_dns) != 0;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
		query_params.peerToken				= session->peer_token;
		query_params.delegatorToken			= me->delegator_token;
		query_params.isInAppBrowserRequest	= (me->options & mdns_gai_option_in_app_browser) != 0;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
		query_params.logPrivacyLevel		= me->log_privacy_level;
#endif
		query_params_ptr = &query_params;
	}
	return _dx_gai_request_start_client_requests_internal(me, &gai_params, query_params_ptr, need_lock);
}

//======================================================================================================================

static bool
_dx_gai_request_check_for_failover_restart(const dx_gai_request_t me, const ResourceRecord * const answer,
	const bool answer_is_expired, const bool answer_is_positive)
{
	__block bool restart = false;
	__block dx_gai_result_t free_list = NULL;
	if ((me->state & DX_GAI_STATE_WAITING_FOR_RESULTS) && !answer_is_expired) {
		_dx_request_locked(me,
		^{
			if (answer_is_positive) {
				switch (answer->rrtype) {
					case kDNSType_A:
					case kDNSType_AAAA:
					case kDNSType_HTTPS:
						me->state &= ~DX_GAI_STATE_WAITING_FOR_RESULTS;
						break;
				}
			} else {
				switch (answer->rrtype) {
					case kDNSServiceType_A:
						me->state &= ~dx_gai_state_waiting_for_a;
						break;

					case kDNSServiceType_AAAA:
						me->state &= ~dx_gai_state_waiting_for_aaaa;
						break;
				}
				const dx_gai_state_t state = me->state;
				if (!(state & DX_GAI_STATE_WAITING_FOR_RESULTS) && (state & dx_gai_state_service_allowed_failover)) {
					restart = true;
					free_list = me->results;
					me->results = NULL;
				}
			}
		});
	}
	_dx_gai_result_list_forget(&free_list);
	return restart;
}

//======================================================================================================================
// MARK: - GAI Result Methods

static void
_dx_gai_result_finalize(const dx_gai_result_t me)
{
	mdns_forget(&me->record);
	mdns_xpc_string_forget(&me->provider_name);
	xpc_forget(&me->cname_update);
	mdns_xpc_string_forget(&me->tracker_hostname);
	mdns_xpc_string_forget(&me->tracker_owner);
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	mdns_forget(&me->signed_hostname);
#endif
	mdns_forget(&me->extended_dns_error);
}

//======================================================================================================================

static void
_dx_gai_result_list_forget(dx_gai_result_t * const list_ptr)
{
	dx_gai_result_t list;
	if ((list = *list_ptr) != NULL) {
		*list_ptr = NULL;
		dx_gai_result_t result;
		while ((result = list) != NULL) {
			list = result->next;
			_dx_forget(&result);
		}
	}
}

//======================================================================================================================

static xpc_object_t
_dx_gai_result_to_dictionary(const dx_gai_result_t me)
{
	xpc_object_t result = xpc_dictionary_create(NULL, NULL, 0);
	require_return_value(result, NULL);

	dnssd_xpc_result_set_error(result, me->error);
	dnssd_xpc_result_set_flags(result, me->flags);
	dnssd_xpc_result_set_interface_index(result, me->ifindex);
	const mdns_domain_name_t name = mdns_resource_record_get_name(me->record);
	dnssd_xpc_result_set_record_name(result, mdns_domain_name_get_presentation(name));
	dnssd_xpc_result_set_record_type(result, mdns_resource_record_get_type(me->record));
	dnssd_xpc_result_set_record_protocol(result, (uint16_t)me->protocol);
	dnssd_xpc_result_set_record_class(result, mdns_resource_record_get_class(me->record));
	dnssd_xpc_result_set_record_data(result, mdns_resource_record_get_rdata_bytes_ptr(me->record),
		mdns_resource_record_get_rdata_length(me->record));
	if (me->negative_reason != dnssd_negative_reason_none) {
		dnssd_xpc_result_set_negative_reason(result, me->negative_reason);
	}
	if (me->provider_name) {
		dnssd_xpc_result_set_provider_name(result, me->provider_name);
	}
	if (me->cname_update) {
		dnssd_xpc_result_set_cname_update(result, me->cname_update);
	}
	if (me->tracker_hostname) {
		dnssd_xpc_result_set_tracker_hostname(result, me->tracker_hostname);
		if (me->tracker_owner) {
			dnssd_xpc_result_set_tracker_owner(result, me->tracker_owner);
		}
		dnssd_xpc_result_set_tracker_is_approved(result, me->tracker_is_approved);
		dnssd_xpc_result_set_tracker_can_block_request(result, me->tracker_can_block);
	}
#if MDNSRESPONDER_SUPPORTS(APPLE, SIGNED_RESULTS)
	if (me->signed_hostname) {
		size_t data_len;
		const uint8_t * const data = mdns_signed_result_get_data(me->signed_hostname, &data_len);
		if (data) {
			dnssd_xpc_result_set_validation_data(result, data, data_len);
		}
	}
#endif
	const mdns_extended_dns_error_t ede = me->extended_dns_error;
	if (ede) {
		const uint16_t code = mdns_extended_dns_error_get_code(ede);
		const mdns_xpc_string_t text = mdns_extended_dns_error_get_extra_text(ede);
		dnssd_xpc_result_set_extended_dns_error(result, code, text);
	}
	return result;
}

//======================================================================================================================

static bool
_dx_gai_result_needs_sensitive_logging(const dx_gai_result_t me)
{
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	return me->sensitive_logging;
#else
	return false;
#endif
}

//======================================================================================================================

#define _dx_log_name_and_record_with_formatted_bookends(NAME, RECORD, SENSITIVE, PREFIX_FMT, MID_FMT, SUFFIX_FMT,	\
	REQUEST_ID, QUESTION_ID, IS_ADD, IFINDEX, RRTYPE, EXPIRED)														\
	do {																											\
		const bool _sensitive = SENSITIVE;																			\
		const mdns_domain_name_t _name = NAME;																		\
		char *_sensitive_name_desc = _sensitive ? mdns_copy_private_description(_name) : NULL;						\
		const mdns_resource_record_t _record = RECORD;																\
		char *_sensitive_record_desc = _sensitive ? mdns_copy_private_description(_record) : NULL;					\
		if (_sensitive_name_desc && _sensitive_record_desc) {														\
			os_log(_mdns_server_log(), PREFIX_FMT "%{public}s" MID_FMT "%{public}s" SUFFIX_FMT,						\
				REQUEST_ID, QUESTION_ID, IS_ADD, IFINDEX, _sensitive_name_desc, RRTYPE, _sensitive_record_desc,		\
				EXPIRED);																							\
		} else {																									\
			os_log(_mdns_server_log(), PREFIX_FMT "%@" MID_FMT "%@" SUFFIX_FMT,										\
				REQUEST_ID, QUESTION_ID, IS_ADD, IFINDEX, _name, RRTYPE, _record, EXPIRED);							\
		}																											\
		ForgetMem(&_sensitive_name_desc);																			\
		ForgetMem(&_sensitive_record_desc);																			\
	} while (0)

#define _dx_log_name_with_formatted_bookends(NAME, SENSITIVE, PREFIX_FMT, SUFFIX_FMT, REQUEST_ID, QUESTION_ID,	\
	IS_ADD,	IFINDEX, RRTYPE, NEGATIVE_REASON)																	\
	do {																										\
		const mdns_domain_name_t _name = NAME;																	\
		char *_sensitive_name_desc = (SENSITIVE) ? mdns_copy_private_description(_name) : NULL;					\
		if (_sensitive_name_desc) {																				\
			os_log(_mdns_server_log(), PREFIX_FMT "%{public}s" SUFFIX_FMT,										\
				REQUEST_ID, QUESTION_ID, IS_ADD, IFINDEX, _sensitive_name_desc, RRTYPE, NEGATIVE_REASON);		\
			ForgetMem(&_sensitive_name_desc);																	\
		} else {																								\
			os_log(_mdns_server_log(), PREFIX_FMT "%@" SUFFIX_FMT,												\
				REQUEST_ID, QUESTION_ID, IS_ADD, IFINDEX, _name, RRTYPE, NEGATIVE_REASON);						\
		}																										\
	} while (0)

static void
_dx_gai_result_log(const dx_gai_result_t me, const uint32_t request_id)
{
	const bool is_add = (me->flags & kDNSServiceFlagsAdd) ? true : false;
	const mdns_domain_name_t name = me->record ? mdns_resource_record_get_name(me->record) : NULL;
	const int type = me->record ? mdns_resource_record_get_type(me->record) : 0;
	const bool sensitive_logging = _dx_gai_result_needs_sensitive_logging(me);
	if (me->record && (mdns_resource_record_get_rdata_length(me->record) > 0)) {
		const bool expired = (me->flags & kDNSServiceFlagsExpiredAnswer) != 0;
		_dx_log_name_and_record_with_formatted_bookends(name, me->record, sensitive_logging,
			"[R%u->Q%u] getaddrinfo result -- event: %{mdns:addrmv}d, ifindex: %d, name: ", /* name */
			", type: %{mdns:rrtype}d, rdata: ", /* rdata */ ", expired: %{mdns:yesno}d",
			request_id, me->question_id, is_add, me->ifindex, type, expired);
	} else {
		_dx_log_name_with_formatted_bookends(name, sensitive_logging,
			"[R%u->Q%u] getaddrinfo result -- event: %{mdns:addrmv}d, ifindex: %d, name: ", /* name */
			", type: %{mdns:rrtype}d, rdata: <none>, reason: %{mdns:nreason}d",
			request_id, me->question_id, is_add, me->ifindex, type, me->negative_reason);
	}
}

//======================================================================================================================
// MARK: - Helper Functions

static void
_dx_kqueue_locked(const char * const description, const bool need_lock, const dx_block_t block)
{
	if (need_lock) {
		KQueueLock();
		block();
		KQueueUnlock(description);
	} else {
		block();
	}
}

//======================================================================================================================

static void
_dx_replace_domain_name(mdns_domain_name_t * const ptr, const domainname * const name)
{
	const mdns_domain_name_t original = *ptr;
	if (!original || !SameDomainNameBytes(mdns_domain_name_get_labels(original), name->c)) {
		mdns_forget(ptr);
		*ptr = mdns_domain_name_create_with_labels(name->c, NULL);
	}
}

//======================================================================================================================

static bool
_dx_qc_result_is_add(const QC_result qc_result)
{
	// No default case to allow the compiler to catch missing enum values.
	switch (qc_result) {
		case QC_rmv:
			return false;

		case QC_add:
		case QC_addnocache:
		case QC_forceresponse:
		case QC_suppressed:
			break;
	}
	return true;
}

//======================================================================================================================

static bool
_dx_qc_result_is_suppressed(const QC_result qc_result)
{
	// No default case to allow the compiler to catch missing enum values.
	switch (qc_result) {
		case QC_suppressed:
			return true;

		case QC_rmv:
		case QC_add:
		case QC_addnocache:
		case QC_forceresponse:
			break;
	}
	return false;
}

//======================================================================================================================

static QueryRecordClientRequest *
_dx_query_record_client_request_start(const QueryRecordClientRequestParams * const params,
	const QueryRecordResultHandler handler, void * const context, DNSServiceErrorType * const out_error)
{
	DNSServiceErrorType err;
	QueryRecordClientRequest *query = (QueryRecordClientRequest *)mdns_calloc(1, sizeof(*query));
	mdns_require_action_quiet(query, exit, err = kDNSServiceErr_NoMemory);

	err = QueryRecordClientRequestStart(query, params, handler, context);
	if (err) {
		ForgetMem(&query);
	}

exit:
	mdns_assign(out_error, err);
	return query;
}

//======================================================================================================================

static void
_dx_query_record_client_request_forget(QueryRecordClientRequest ** const request_ptr)
{
	QueryRecordClientRequest * const query = *request_ptr;
	if (query) {
		QueryRecordClientRequestStop(query);
		ForgetMem(request_ptr);
	}
}

//======================================================================================================================

static GetAddrInfoClientRequest *
_dx_get_addr_info_client_request_start(const GetAddrInfoClientRequestParams * const params,
	const QueryRecordResultHandler handler, void * const context, DNSServiceErrorType * const out_error)
{
	DNSServiceErrorType err;
	GetAddrInfoClientRequest *gai = (GetAddrInfoClientRequest *)mdns_calloc(1, sizeof(*gai));
	mdns_require_action_quiet(gai, exit, err = kDNSServiceErr_NoMemory);

	err = GetAddrInfoClientRequestStart(gai, params, handler, context);
	if (err) {
		ForgetMem(&gai);
	}

exit:
	mdns_assign(out_error, err);
	return gai;
}

//======================================================================================================================

static void
_dx_get_addr_info_client_request_forget(GetAddrInfoClientRequest ** const request_ptr)
{
	GetAddrInfoClientRequest * const gai = *request_ptr;
	if (gai) {
		GetAddrInfoClientRequestStop(gai);
		ForgetMem(request_ptr);
	}
}
