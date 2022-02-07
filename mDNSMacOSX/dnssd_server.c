/*
 * Copyright (c) 2019-2021 Apple Inc. All rights reserved.
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

#include <bsm/libbsm.h>
#include <CoreUtils/CommonServices.h>
#include <CoreUtils/DebugServices.h>
#include <mach/mach_time.h>
#include <mdns/alloc.h>
#include <mdns/mortality.h>
#include <mdns/resource_record.h>
#include <mdns/system.h>
#include <mdns/ticks.h>
#include <net/necp.h>
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
	uint64_t			pending_send_start_ticks;	// Start time in mach ticks of the current pending send condition.
	audit_token_t		audit_token;				// Client's audit_token.
	uid_t				client_euid;				// Client's EUID.
	pid_t				client_pid;					// Client's PID.
	uint32_t			pending_send_count;			// Count of sent messages that still haven't been processed.
	uint32_t			pending_send_count_max;		// Maximum pending_send_count value.
	char				client_name[MAXCOMLEN];		// Client's process name.
	bool				has_delegate_entitlement;	// True if the client is entitled to be a delegate.
	bool				terminated;					// True if the session was prematurely ended due to a fatal error.
};

static void
_dx_session_invalidate(dx_session_t session);

DX_OBJECT_SUBKIND_DEFINE(session,
	.invalidate	= _dx_session_invalidate
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
	dx_gai_state_gai_is_active				= (1U << 0), // Underlying GAI client request is active.
	dx_gai_state_query_is_active			= (1U << 1), // Underlying SVCB/HTTPS query client request is active.
	dx_gai_state_waiting_for_a				= (1U << 2), // Currently waiting for an A result. [1]
	dx_gai_state_waiting_for_aaaa			= (1U << 3), // Currently waiting for a AAAA result. [1]
	dx_gai_state_service_allowed_failover	= (1U << 4), // Got a result from a DNS service that allows failover.
	dx_gai_state_failover_mode				= (1U << 5)  // Currently avoiding DNS services that allow failover.
);

#define DX_GAI_STATE_WAITING_FOR_RESULTS (dx_gai_state_waiting_for_a | dx_gai_state_waiting_for_aaaa)

// Notes:
// 1. If a client request specifies that DNS services that allow failover be avoided if they're unable to provide
//    at least one positive response to either the A, AAAA, or HTTPS query, then we have to wait until at least one
//    positive result is received or until all of the underlying DNSQuestions get negative results before deciding
//    whether to start providing results to the client (former case), or discarding the current list of pending
//    results and restarting the underlying DNSQuestions in failover mode (latter case).

struct dx_gai_request_s {
	struct dx_request_s			base;					// Request object base.
	GetAddrInfoClientRequest	gai;					// Underlying GAI request.
	QueryRecordClientRequest	query;					// Underlying SVCB/HTTPS query request.
	dx_gai_result_t				results;				// List of pending results.
	char *						hostname;				// Hostname C string to be resolved for getaddrinfo request.
	mdns_domain_name_t			last_domain_name;		// Domain name of the most recent result.
	xpc_object_t				last_tracker_hostname;	// Tracker hostname of the most recent result as an XPC string.
	xpc_object_t				last_tracker_owner;		// Tracker owner of the most recent result as an XPC string.
	const char *				svcb_name;				// If non-NULL, the name of the SVCB/HTTPS record to query for.
	uuid_t *					resolver_uuid;			// The resolver UUID to use for UUID-scoped requests.
	mdns_dns_service_id_t		custom_service_id;		// ID for this request's custom DNS service.
	xpc_object_t				cnames_a;				// Hostname's canonical names for A records as an XPC array.
	ssize_t						cnames_a_expire_idx;	// Index of the first expired canonical name in cnames_a.
	xpc_object_t				cnames_aaaa;			// Hostname's canonical names for AAAA records as an XPC array.
	ssize_t						cnames_aaaa_expire_idx;	// Index of the first expired canonical name in cnames_aaaa.
	audit_token_t *				delegator_audit_token;	// The delegator's audit token.
	xpc_object_t				fallback_dns_config;	// Fallback DNS configuration.
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
	mdns_trust_t				trust;					// Trust instance if status is mdns_trust_status_pending
#endif
	char *						svcb_name_memory;		// Memory that was allocated for svcb_name.
	DNSServiceFlags				flags;					// The request's flags parameter.
	uint32_t					ifindex;				// The interface index to use for interface-scoped requests.
	DNSServiceProtocol			protocols;				// Used to specify IPv4, IPv6, both, or any IP address types.
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	dnssd_log_privacy_level_t	log_privacy_level;		// The log privacy level of this request.
#endif
	pid_t						effective_pid;			// Effective client PID.
	uuid_t						effective_uuid;			// Effective client UUID.
	uint16_t					svcb_type;				// If svcb_name is non-NULL, the type for the SVCB/HTTPS query.
	dx_gai_state_t				state;					// Collection of state bits.
	mdns_gai_options_t			options;				// Additional request options.
	bool						cnames_a_changed;		// True if cnames_a has changed.
	bool						cnames_aaaa_changed;	// True if cnames_aaaa has changed.
};

check_compile_time(sizeof(struct dx_gai_request_s) <= 1544);

typedef xpc_object_t
(*dx_request_take_results_f)(dx_any_request_t request);

typedef const struct dx_request_kind_s * dx_request_kind_t;
struct dx_request_kind_s {
	struct dx_kind_s			base;
	dx_request_take_results_f	take_results;
};

#define DX_REQUEST_SUBKIND_DEFINE(NAME, ...)														\
	static void																						\
	_dx_ ## NAME ## _request_init(dx_ ## NAME ## _request_t request);								\
																									\
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

static void
_dx_gai_request_init(dx_gai_request_t request);

static xpc_object_t
_dx_gai_request_take_results(dx_gai_request_t request);

DX_REQUEST_SUBKIND_DEFINE(gai,
	.base.init		= _dx_gai_request_init,
	.take_results	= _dx_gai_request_take_results
);

//======================================================================================================================
// MARK: - Result Kind Definition

#define DNSSD_AUTHENTICATION_TAG_SIZE	32 // Defined here until an NECP header defines this length.
typedef uint8_t dx_auth_tag_t[DNSSD_AUTHENTICATION_TAG_SIZE];

struct dx_gai_result_s {
	struct dx_object_s		base;				// Object base.
	dx_gai_result_t			next;				// Next result in list.
	mdns_resource_record_t	record;				// Result's resource record.
	mdns_dns_service_t		service;			// The DNS service that was the source of the record.
	xpc_object_t			cname_update;		// If non-NULL, XPC array to use for a CNAME chain update.
	xpc_object_t			tracker_hostname;	// If non-NULL, tracker hostname as an XPC string.
	xpc_object_t			tracker_owner;		// If non-NULL, owner of the tracker hostname as an XPC string.
	dx_auth_tag_t *			auth_tag;			// Optional authentication tag for hostname+IP addresses.
	DNSServiceFlags			flags;				// The result's flags.
	dnssd_negative_reason_t	negative_reason;	// Reason code for negative results.
	DNSServiceErrorType		error;				// Error returned by mDNS core.
	uint32_t				ifindex;			// The interface index associated with the result.
	mdns_resolver_type_t	protocol;			// The transport protocol used to obtain the record.
	uint16_t				question_id;		// ID of the DNSQuestion used to get the result. For logging purposes.
	bool					tracker_is_approved;// True if the assoicated tracker is approved for the client.
};

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
_dx_session_terminate(dx_session_t session);

static void
_dx_session_log_error(dx_session_t session, DNSServiceErrorType error);

static void
_dx_session_log_pending_send_count_increase(dx_session_t session);

static void
_dx_session_log_pending_send_count_decrease(dx_session_t session);

static void
_dx_session_log_termination(dx_session_t session);

static xpc_object_t
_dx_request_take_results(dx_request_t request);

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

static xpc_object_t *
_dx_gai_request_get_cnames_ptr(dx_gai_request_t request, int qtype, bool **out_changed_ptr,
	ssize_t **out_expire_idx_ptr);

static void
_dx_gai_request_append_cname(dx_gai_request_t request, int qtype, const domainname *cname, bool expired, bool unwind);
#define _dx_gai_request_unwind_cnames_if_necessary(R, T)	_dx_gai_request_append_cname(R, T, NULL, false, true)

static xpc_object_t
_dx_gai_request_copy_cname_update(dx_gai_request_t request, int qtype);

static void
_dx_gai_request_gai_result_handler(mDNS *m, DNSQuestion *q, const ResourceRecord *answer, QC_result qc_result,
	DNSServiceErrorType error, void *context);

static void
_dx_gai_request_query_result_handler(mDNS *m, DNSQuestion *q, const ResourceRecord *answer, QC_result qc_result,
	DNSServiceErrorType error, void *context);

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

static bool
_dx_authenticate_address_rdata(uuid_t effective_uuid, const char *hostname, int type, const uint8_t *rdata,
	uint8_t out_auth_tag[STATIC_PARAM DNSSD_AUTHENTICATION_TAG_SIZE]);

static void
_dx_kqueue_locked(const char *description, bool need_lock, dx_block_t block);

static void
_dx_replace_domain_name(mdns_domain_name_t *ptr, const domainname *name);

static void
_dx_replace_xpc_string(xpc_object_t *ptr, const char *string);

static bool
_dx_qc_result_is_add(QC_result qc_result);

static bool
_dx_qc_result_is_suppressed(QC_result qc_result);

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
	static dispatch_once_t	s_once = 0;
	static xpc_connection_t	s_listener = NULL;

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
		const uint64_t now_ticks = mach_continuous_time();
		for (dx_session_t session = g_session_list; session; session = session->next) {
			_dx_session_check(session, now_ticks);
		}
	}
}

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

#define DNSSD_DELEGATE_ENTITLEMENT	"com.apple.private.network.socket-delegate"

static dx_session_t
_dx_session_create(const xpc_connection_t connection)
{
	const dx_session_t obj = _dx_session_new();
	require_quiet(obj, exit);

	obj->connection = connection;
	xpc_retain(obj->connection);
	xpc_connection_get_audit_token(obj->connection, &obj->audit_token);
	obj->client_pid  = xpc_connection_get_pid(obj->connection);
	obj->client_euid = xpc_connection_get_euid(obj->connection);
	mdns_system_pid_to_name(obj->client_pid, obj->client_name);

	xpc_object_t value = xpc_connection_copy_entitlement_value(obj->connection, DNSSD_DELEGATE_ENTITLEMENT);
	if (value) {
		if (value == XPC_BOOL_TRUE) {
			obj->has_delegate_entitlement = true;
		}
		xpc_forget(&value);
	}

exit:
	return obj;
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
}

//======================================================================================================================

static void
_dx_session_invalidate(const dx_session_t me)
{
	xpc_connection_forget(&me->connection);
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

exit:;
	xpc_object_t reply = xpc_dictionary_create_reply(msg);
	if (likely(reply)) {
		dnssd_xpc_message_set_error(reply, err);
		_dx_session_send_message(me, reply);
		xpc_forget(&reply);
	} else {
		_dx_session_terminate(me);
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
	bool terminate;
	xpc_object_t results = NULL;
	require_action_quiet(me->connection, exit, terminate = false);

	if (me->pending_send_count > 0) {
		const uint64_t elapsed_secs = (now_ticks - me->pending_send_start_ticks) / mdns_mach_ticks_per_second();
		require_action_quiet(elapsed_secs < DX_SESSION_BACK_PRESSURE_TIMEOUT_SECS, exit, terminate = true);
	}
	for (dx_request_t req = me->request_list; req; req = req->next) {
		results = _dx_request_take_results(req);
		if (results) {
			xpc_object_t msg = xpc_dictionary_create(NULL, NULL, 0);
			require_action_quiet(msg, exit, terminate = true);

			dnssd_xpc_message_set_id(msg, req->command_id);
			dnssd_xpc_message_set_error(msg, kDNSServiceErr_NoError);
			dnssd_xpc_message_set_results(msg, results);
			xpc_forget(&results);
			_dx_session_send_message(me, msg);
			xpc_forget(&msg);
		}
		const bool ok = _dx_request_send_pending_error(req);
		require_action_quiet(ok, exit, terminate = true);
	}
	terminate = false;

exit:
	if (unlikely(terminate)) {
		_dx_session_terminate(me);
	}
	xpc_forget(&results);
}

//======================================================================================================================

static void
_dx_session_send_message(const dx_session_t me, const xpc_object_t msg)
{
	require_quiet(me->connection, exit);

	xpc_connection_send_message(me->connection, msg);
	if (me->pending_send_count++ == 0) {
		me->pending_send_start_ticks = mach_continuous_time();
	} else {
		_dx_session_log_pending_send_count_increase(me);
	}
	me->pending_send_count_max = me->pending_send_count;
	_dx_retain(me);
	xpc_connection_send_barrier(me->connection,
	^{
		--me->pending_send_count;
		if (me->pending_send_count_max > 1) {
			_dx_session_log_pending_send_count_decrease(me);
		}
		if (me->pending_send_count == 0) {
			me->pending_send_count_max = 0;
		}
		_dx_release(me);
	});

exit:
	return;
}

//======================================================================================================================

static void
_dx_session_terminate(const dx_session_t me)
{
	if (!me->terminated) {
		_dx_session_log_termination(me);
		xpc_connection_forget(&me->connection);
		me->terminated = true;
	}
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
_dx_session_log_termination(const dx_session_t me)
{
	os_log_error(_mdns_server_log(),
		"XPC session termination -- pending send count: %u, pending send count max: %u, client pid: %lld (%{public}s)",
		me->pending_send_count, me->pending_send_count_max, (long long)me->client_pid, me->client_name);
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
	if (os_feature_enabled(mDNSResponder, bonjour_privacy)) {
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
	mdns_trust_flags_t flags = mdns_trust_flags_none;
	const mdns_trust_status_t status = mdns_trust_check_getaddrinfo(session->audit_token, me->hostname, &flags);
	switch (status) {
		case mdns_trust_status_granted:
			err = kDNSServiceErr_NoError;
			break;

		case mdns_trust_status_denied:
		case mdns_trust_status_pending:
			me->trust = mdns_trust_create(session->audit_token, NULL, flags);
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
_dx_gai_request_init(const dx_gai_request_t me)
{
	me->cnames_a_expire_idx    = -1;
	me->cnames_aaaa_expire_idx = -1;
}

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
	mdns_forget(&me->last_domain_name);
	xpc_forget(&me->last_tracker_hostname);
	xpc_forget(&me->last_tracker_owner);
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
	ForgetMem(&me->delegator_audit_token);
	xpc_forget(&me->fallback_dns_config);
	ForgetMem(&me->resolver_uuid);
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_parse_params(const dx_gai_request_t me, const xpc_object_t params)
{
	DNSServiceErrorType err;
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
	const audit_token_t * const delegator_audit_token = dnssd_xpc_parameters_get_delegate_audit_token(params, &storage);
	if (delegator_audit_token) {
		delegator_pid  = audit_token_to_pid(*delegator_audit_token);
		delegator_uuid = NULL;
	} else {
		delegator_uuid = dnssd_xpc_parameters_get_delegate_uuid(params);
		if (delegator_uuid) {
			delegator_pid = 0;
		} else {
			delegator_pid = dnssd_xpc_parameters_get_delegate_pid(params, NULL);
		}
	}
	if (delegator_audit_token || delegator_uuid || (delegator_pid != 0)) {
		require_action_quiet(session->has_delegate_entitlement, exit, err = kDNSServiceErr_NoAuth);
		if (delegator_audit_token) {
			me->delegator_audit_token = (audit_token_t *)mdns_memdup(delegator_audit_token,
				sizeof(*delegator_audit_token));
			require_action_quiet(me->delegator_audit_token, exit, err = kDNSServiceErr_NoMemory);
		}
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

	// Determine if authentication tags are needed.
	if (dnssd_xpc_parameters_get_need_authentication_tags(params)) {
		if (uuid_is_null(me->effective_uuid)) {
			err = mdns_system_pid_to_uuid(me->effective_pid, me->effective_uuid);
			require_noerr_action_quiet(err, exit, err = kDNSServiceErr_Unknown);
		}
		me->options |= mdns_gai_option_auth_tags;
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
	_dx_gai_request_log_start(me, delegator_pid, delegator_uuid);
	err = kDNSServiceErr_NoError;

exit:
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
		if (query_params && !(me->state & dx_gai_state_query_is_active)) {
			err = QueryRecordClientRequestStart(&me->query, query_params, _dx_gai_request_query_result_handler, me);
			require_noerr_return(err);
			me->state |= dx_gai_state_query_is_active;
		}
		// Run the A/AAAA lookup.
		if (gai_params && !(me->state & dx_gai_state_gai_is_active)) {
			err = GetAddrInfoClientRequestStart(&me->gai, gai_params, _dx_gai_request_gai_result_handler, me);
			require_noerr_return(err);
			me->state |= dx_gai_state_gai_is_active;
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
		if (me->state & dx_gai_state_gai_is_active) {
			GetAddrInfoClientRequestStop(&me->gai);
			me->state &= ~dx_gai_state_gai_is_active;
		}
		if (me->state & dx_gai_state_query_is_active) {
			QueryRecordClientRequestStop(&me->query);
			me->state &= ~dx_gai_state_query_is_active;
		}
	});
}

//======================================================================================================================

static void
_dx_gai_request_restart_client_requests_in_failover_mode(const dx_gai_request_t me)
{
	if (!(me->state & dx_gai_state_failover_mode)) {
		_dx_gai_request_stop_client_requests(me, false);
		_dx_gai_result_list_forget(&me->results);
		os_log(_mdns_server_log(), "[R%u] getaddrinfo failover restart", me->base.request_id);
		me->state |= dx_gai_state_failover_mode;
		_dx_gai_request_start_client_requests(me, false);
	}
}

//======================================================================================================================

static xpc_object_t *
_dx_gai_request_get_cnames_ptr(const dx_gai_request_t me, const int qtype, bool ** const out_changed_ptr,
	ssize_t **out_expire_idx_ptr)
{
	ssize_t *expire_idx_ptr;
	xpc_object_t *cnames_ptr;
	bool *changed_ptr;
	switch (qtype) {
		case kDNSServiceType_A:
			cnames_ptr		= &me->cnames_a;
			changed_ptr		= &me->cnames_a_changed;
			expire_idx_ptr	= &me->cnames_a_expire_idx;
			break;

		case kDNSServiceType_AAAA:
			cnames_ptr		= &me->cnames_aaaa;
			changed_ptr		= &me->cnames_aaaa_changed;
			expire_idx_ptr	= &me->cnames_aaaa_expire_idx;
			break;

		default:
			cnames_ptr		= NULL;
			expire_idx_ptr	= NULL;
			changed_ptr		= NULL;
			break;
	}
	if (out_expire_idx_ptr) {
		*out_expire_idx_ptr = expire_idx_ptr;
	}
	if (out_changed_ptr) {
		*out_changed_ptr = changed_ptr;
	}
	return cnames_ptr;
}

//======================================================================================================================

static void
_dx_gai_request_append_cname(const dx_gai_request_t me, const int qtype, const domainname * const cname,
	const bool expired, const bool unwind)
{
	bool *changed_ptr;
	ssize_t *expire_idx_ptr;
	xpc_object_t * const cnames_ptr = _dx_gai_request_get_cnames_ptr(me, qtype, &changed_ptr, &expire_idx_ptr);
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
		if (unwind) {
			const ssize_t expire_idx = *expire_idx_ptr;
			if (*cnames_ptr && (expire_idx >= 0)) {
				xpc_object_t new_cnames = xpc_array_create(NULL, 0);
				if (new_cnames && (expire_idx > 0)) {
					xpc_array_apply(*cnames_ptr,
					^ bool (const size_t index, const xpc_object_t _Nonnull value)
					{
						bool proceed = false;
						if (index < (size_t)expire_idx) {
							xpc_array_append_value(new_cnames, value);
							proceed = true;
						}
						return proceed;
					});
				}
				xpc_forget(cnames_ptr);
				*cnames_ptr		= new_cnames;
				*changed_ptr	= true;
			}
			*expire_idx_ptr = -1;
		}
		if (cname_str) {
			xpc_object_t cnames = *cnames_ptr;
			if (expired && (*expire_idx_ptr < 0)) {
				*expire_idx_ptr = cnames ? (ssize_t)xpc_array_get_count(cnames) : 0;
			}
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

exit:
	return;
}

//======================================================================================================================

static xpc_object_t
_dx_gai_request_copy_cname_update(const dx_gai_request_t me, const int qtype)
{
	__block xpc_object_t result = NULL;
	bool *changed_ptr;
	xpc_object_t * const cnames_ptr = _dx_gai_request_get_cnames_ptr(me, qtype, &changed_ptr, NULL);
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
	const QC_result qc_result, const DNSServiceErrorType error, void * const context)
{
	(void)m;
	bool failover_restart = false;
	const dx_gai_request_t me = (dx_gai_request_t)context;
	if (!error || (error == kDNSServiceErr_NoSuchRecord)) {
		_dx_gai_request_failover_check_gai_answer(me, answer);
		const bool expired = (answer->mortality == Mortality_Ghost) || (q->firstExpiredQname.c[0] != 0);
		if (answer->rrtype == kDNSServiceType_CNAME) {
			require_quiet(!error, exit);

			_dx_gai_request_append_cname(me, q->qtype, &answer->rdata->u.name, expired, q->CNAMEReferrals == 0);
		}
		require_quiet((answer->rrtype == kDNSServiceType_A) || (answer->rrtype == kDNSServiceType_AAAA), exit);

		if (q->CNAMEReferrals == 0) {
			_dx_gai_request_unwind_cnames_if_necessary(me, q->qtype);
		}
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
		if (answer->dnsservice && mdns_dns_service_allows_failover(answer->dnsservice)) {
			me->state |= dx_gai_state_service_allowed_failover;
		}
	}
}

//======================================================================================================================

static void
_dx_gai_request_query_result_handler(mDNS * const m, DNSQuestion * const q, const ResourceRecord * const answer,
	const QC_result qc_result, const DNSServiceErrorType error, void * const context)
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
				Querier_RegisterDoHURI(svcb_doh_uri, svcb_domain);
				ForgetMem(&svcb_doh_uri);
			}
#endif
		} else {
			rdata_ptr = NULL;
			rdata_len = 0;
		}
		const bool expired = (answer->mortality == Mortality_Ghost) || (q->firstExpiredQname.c[0] != 0);
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
	}
	if (answer_is_expired) {
		flags |= kDNSServiceFlagsExpiredAnswer;
	}
	extern mDNS mDNSStorage;
	result->flags       = flags;
	result->error       = result_error;
	result->ifindex     = mDNSPlatformInterfaceIndexfromInterfaceID(&mDNSStorage, answer->InterfaceID, mDNStrue);
	result->protocol    = answer->protocol;
	result->question_id = mDNSVal16(q->TargetQID);
	result->service     = answer->dnsservice;
	if (result->service) {
		mdns_retain(result->service);
	}
	const int record_type = mdns_resource_record_get_type(result->record);
	if ((me->options & mdns_gai_option_auth_tags) && is_add && !result_error) {
		uint8_t auth_tag[DNSSD_AUTHENTICATION_TAG_SIZE];
		const bool ok = _dx_authenticate_address_rdata(me->effective_uuid, me->hostname, record_type,
			mdns_resource_record_get_rdata_bytes_ptr(result->record), auth_tag);
		if (ok) {
			check_compile_time(sizeof(*result->auth_tag) == sizeof(auth_tag));
			result->auth_tag = (dx_auth_tag_t *)mdns_memdup(auth_tag, sizeof(*result->auth_tag));
		}
	}
	result->cname_update = _dx_gai_request_copy_cname_update(me, record_type);
#if MDNSRESPONDER_SUPPORTS(APPLE, TRACKER_STATE)
	if (resolved_cache_is_enabled() && is_add) {
		const char *hostname = NULL;
		const char *owner = NULL;
		bool approved_domain = false;
		const tracker_state_t tracker_state = resolved_cache_get_tracker_state(q, &hostname, &owner, &approved_domain);
		if ((tracker_state == tracker_state_known_tracker) && hostname) {
			_dx_replace_xpc_string(&me->last_tracker_hostname, hostname);
			require_action_quiet(me->last_tracker_hostname, exit, err = kDNSServiceErr_NoMemory);

			result->tracker_hostname = me->last_tracker_hostname;
			xpc_retain(result->tracker_hostname);
			if (owner) {
				_dx_replace_xpc_string(&me->last_tracker_owner, owner);
				require_action_quiet(me->last_tracker_owner, exit, err = kDNSServiceErr_NoMemory);

				result->tracker_owner = me->last_tracker_owner;
				xpc_retain(result->tracker_owner);
			}
			if (approved_domain) {
				result->tracker_is_approved = true;
			}
		}
	}
#endif
	_dx_request_locked(me,
	^{
		dx_gai_result_t *ptr = &me->results;
		while (*ptr) {
			ptr = &(*ptr)->next;
		}
		*ptr = result;
	});
	result = NULL;
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
	if (answer->dnsservice) {
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

static void
_dx_gai_request_log_start(const dx_gai_request_t me, const pid_t delegator_pid, const uuid_t delegator_uuid)
{
	const dx_session_t session = me->base.session;
	if (delegator_uuid) {
		os_log(_mdns_server_log(),
			"[R%u] getaddrinfo start -- flags: 0x%X, ifindex: %d, protocols: %u, hostname: %{private,mask.hash}s, "
			"options: %{mdns:gaiopts}X, client pid: %lld (%{public}s), delegator uuid: %{public,uuid_t}.16P",
			me->base.request_id, me->flags, (int32_t)me->ifindex, me->protocols, me->hostname, me->options,
			(long long)session->client_pid, session->client_name, delegator_uuid);
	} else if (delegator_pid != 0) {
		char delegator_name[MAXCOMLEN];
		delegator_name[0] = '\0';
		mdns_system_pid_to_name(delegator_pid, delegator_name);
		os_log(_mdns_server_log(),
			"[R%u] getaddrinfo start -- flags: 0x%X, ifindex: %d, protocols: %u, hostname: %{private,mask.hash}s, "
			"options: %{mdns:gaiopts}X, client pid: %lld (%{public}s), delegator pid: %lld (%{public}s)",
			me->base.request_id, me->flags, (int32_t)me->ifindex, me->protocols, me->hostname, me->options,
			(long long)session->client_pid, session->client_name, (long long)delegator_pid, delegator_name);
	} else {
		os_log(_mdns_server_log(),
			"[R%u] getaddrinfo start -- flags: 0x%X, ifindex: %d, protocols: %u, hostname: %{private,mask.hash}s, "
			"options: %{mdns:gaiopts}X, client pid: %lld (%{public}s)",
			me->base.request_id, me->flags, (int32_t)me->ifindex, me->protocols, me->hostname, me->options,
			(long long)session->client_pid, session->client_name);
	}
}

//======================================================================================================================

static void
_dx_gai_request_log_stop(const dx_gai_request_t me)
{
	const dx_session_t session = me->base.session;
	if (session->terminated) {
		os_log(_mdns_server_log(),
			"[R%u] getaddrinfo stop (forced) -- hostname: %{private,mask.hash}s, client pid: %lld (%{public}s)",
			me->base.request_id, me->hostname, (long long)session->client_pid, session->client_name);
	} else {
		os_log(_mdns_server_log(),
			"[R%u] getaddrinfo stop -- hostname: %{private,mask.hash}s, client pid: %lld (%{public}s)",
			me->base.request_id, me->hostname, (long long)session->client_pid, session->client_name);
	}
}

//======================================================================================================================

static void
_dx_gai_request_log_error(const dx_gai_request_t me, const DNSServiceErrorType error)
{
	const dx_session_t session = me->base.session;
	os_log_error(_mdns_server_log(),
		"[R%u] getaddrinfo error -- error: %{mdns:err}ld, client pid: %lld (%{public}s)",
		me->base.request_id, (long)error, (long long)session->client_pid, session->client_name);
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_start_client_requests(const dx_gai_request_t me, const bool need_lock)
{
	const dx_session_t session = me->base.session;

	// Set up GetAddrInfo parameters.
	GetAddrInfoClientRequestParams gai_params;
	GetAddrInfoClientRequestParamsInit(&gai_params);
	gai_params.hostnameStr		= me->hostname;
	gai_params.requestID		= me->base.request_id;
	gai_params.interfaceIndex	= me->ifindex;
	gai_params.flags			= me->flags;
	gai_params.protocols		= me->protocols;
	gai_params.effectivePID		= me->effective_pid;
	gai_params.effectiveUUID	= me->effective_uuid;
	gai_params.peerUID			= session->client_euid;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	gai_params.needEncryption	= (me->options & mdns_gai_option_need_encryption) != 0;
	gai_params.failoverMode		= (me->state & dx_gai_state_failover_mode) != 0;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	gai_params.peerAuditToken			= &session->audit_token;
	gai_params.delegatorAuditToken		= me->delegator_audit_token;
	gai_params.isInAppBrowserRequest	= (me->options & mdns_gai_option_in_app_browser) != 0;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
	gai_params.logPrivacyLevel			= me->log_privacy_level;
#endif

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
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
		query_params.peerAuditToken			= &session->audit_token;
		query_params.delegatorAuditToken	= me->delegator_audit_token;
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
	bool restart = false;
	if ((me->state & DX_GAI_STATE_WAITING_FOR_RESULTS) && !answer_is_expired) {
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
			}
		}
	}
	return restart;
}

//======================================================================================================================
// MARK: - GAI Result Methods

static void
_dx_gai_result_finalize(const dx_gai_result_t me)
{
	mdns_forget(&me->record);
	mdns_forget(&me->service);
	xpc_forget(&me->cname_update);
	xpc_forget(&me->tracker_hostname);
	xpc_forget(&me->tracker_owner);
	ForgetMem(&me->auth_tag);
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
	if (me->service) {
		const char * const provider_name = mdns_dns_service_get_provider_name(me->service);
		if (provider_name) {
			dnssd_xpc_result_set_provider_name(result, provider_name);
		}
	}
	if (me->auth_tag) {
		dnssd_xpc_result_set_authentication_tag(result, me->auth_tag, sizeof(*me->auth_tag));
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
	}
	return result;
}

//======================================================================================================================

static void
_dx_gai_result_log(const dx_gai_result_t me, const uint32_t request_id)
{
	const bool is_add = (me->flags & kDNSServiceFlagsAdd) ? true : false;
	const mdns_domain_name_t name = me->record ? mdns_resource_record_get_name(me->record) : NULL;
	const int type = me->record ? mdns_resource_record_get_type(me->record) : 0;
	if (me->record && (mdns_resource_record_get_rdata_length(me->record) > 0)) {
		const bool expired = (me->flags & kDNSServiceFlagsExpiredAnswer) != 0;
		os_log(_mdns_server_log(),
			"[R%u->Q%u] getaddrinfo result -- event: %{mdns:addrmv}d, ifindex: %d, name: %@, type: %{mdns:rrtype}d,"
			" rdata: %@, expired: %{mdns:yesno}d",
			request_id, me->question_id, is_add, me->ifindex, name, type, me->record, expired);
	} else {
		os_log(_mdns_server_log(),
			"[R%u->Q%u] getaddrinfo result -- event: %{mdns:addrmv}d, ifindex: %d, name: %@, type: %{mdns:rrtype}d,"
			" rdata: <none>, reason: %{mdns:nreason}d",
			request_id, me->question_id, is_add, me->ifindex, name, type, me->negative_reason);
	}
}

//======================================================================================================================
// MARK: - Helper Functions

typedef struct {
	struct necp_client_resolver_answer	hdr;
	uint8_t								hostname[MAX_ESCAPED_DOMAIN_NAME];
} dx_necp_answer_t;

check_compile_time(sizeof_field(dx_necp_answer_t, hdr) == offsetof(dx_necp_answer_t, hostname));

static bool
_dx_authenticate_address_rdata(uuid_t effective_uuid, const char * const hostname, const int type,
	const uint8_t * const rdata, uint8_t out_auth_tag[STATIC_PARAM DNSSD_AUTHENTICATION_TAG_SIZE])
{
	bool ok = false;
	require_quiet((type == kDNSServiceType_A) || (type == kDNSServiceType_AAAA), exit);

	dx_necp_answer_t answer;
	struct necp_client_resolver_answer * const hdr = &answer.hdr;
	memset(hdr, 0, sizeof(*hdr));
	uuid_copy(hdr->client_id, effective_uuid);

	hdr->sign_type = NECP_CLIENT_SIGN_TYPE_RESOLVER_ANSWER;
	if (type == kDNSServiceType_A) {
		hdr->address_answer.sa.sa_family	= AF_INET;
		hdr->address_answer.sa.sa_len		= sizeof(struct sockaddr_in);
		memcpy(&hdr->address_answer.sin.sin_addr.s_addr, rdata, 4);
	} else {
		hdr->address_answer.sa.sa_family	= AF_INET6;
		hdr->address_answer.sa.sa_len		= sizeof(struct sockaddr_in6);
		memcpy(hdr->address_answer.sin6.sin6_addr.s6_addr, rdata, 16);
	}
	const size_t hostname_len = strlen(hostname);
	require_quiet(hostname_len <= sizeof(answer.hostname), exit);

	hdr->hostname_length = (uint32_t)hostname_len;
	memcpy(answer.hostname, hostname, hdr->hostname_length);

	static int necp_fd = -1;
	if (necp_fd < 0) {
		necp_fd = necp_open(0);
	}
	require_quiet(necp_fd >= 0, exit);

	const int err = necp_client_action(necp_fd, NECP_CLIENT_ACTION_SIGN, (uint8_t *)&answer.hdr,
		sizeof(answer.hdr) + hdr->hostname_length, out_auth_tag, DNSSD_AUTHENTICATION_TAG_SIZE);
	require_noerr_quiet(err, exit);

	ok = true;

exit:
	return ok;
}

//======================================================================================================================

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

static void
_dx_replace_xpc_string(xpc_object_t * const ptr, const char * const string)
{
	const char * const original = *ptr ? xpc_string_get_string_ptr(*ptr) : NULL;
	if (!original || (strcmp(original, string) != 0)) {
		xpc_forget(ptr);
		*ptr = xpc_string_create(string);
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
