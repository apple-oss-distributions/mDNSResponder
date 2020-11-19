/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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
 */

#include "dnssd_server.h"

#include "ClientRequests.h"
#include "dnssd_xpc.h"
#include "dnssd_svcb.h"
#include "dnssd_private.h"
#include "mdns_helpers.h"
#include "mDNSMacOSX.h"

#include <bsm/libbsm.h>
#include <CoreUtils/CommonServices.h>
#include <CoreUtils/DebugServices.h>
#include <libproc.h>
#include <mach/mach_time.h>
#include <net/necp.h>
#include <os/lock.h>
#include <stdatomic.h>
#include <sys/proc_info.h>
#include <xpc/private.h>

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
#include "QuerierSupport.h"
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
#include "mdns_trust.h"
#include <os/feature_private.h>
#endif

//======================================================================================================================
// MARK: - Kind Declarations

#define DX_STRUCT(NAME)					struct dx_ ## NAME ## _s
#define DX_KIND_DECLARE_ABSTRACT(NAME)	typedef DX_STRUCT(NAME) *	dx_ ## NAME ## _t
#define DX_KIND_DECLARE(NAME)		\
	DX_KIND_DECLARE_ABSTRACT(NAME);	\
									\
	static dx_ ## NAME ## _t		\
	_dx_ ## NAME ## _alloc_and_init(void)

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

#define DX_SUBKIND_DEFINE(NAME, SUPER, ...)											\
	DX_SUBKIND_DEFINE_ABSTRACT(NAME, SUPER, __VA_ARGS__);							\
																					\
	static dx_ ## NAME ## _t														\
	_dx_ ## NAME ## _alloc_and_init(void)											\
	{																				\
		const dx_ ## NAME ## _t obj = (dx_ ## NAME ## _t)calloc(1, sizeof(*obj));	\
		require_quiet(obj, exit);													\
																					\
		const dx_object_t object = (dx_object_t)obj;								\
		object->ref_count	= 1;													\
		object->kind		= &_dx_ ## NAME ## _kind;								\
		_dx_init(object);															\
																					\
	exit:																			\
		return obj;																	\
	}

#define DX_OBJECT_SUBKIND_DEFINE_ABSTRACT(NAME, ...)	DX_SUBKIND_DEFINE_ABSTRACT(NAME, object, __VA_ARGS__)
#define DX_OBJECT_SUBKIND_DEFINE(NAME, ...)				DX_SUBKIND_DEFINE(NAME, object, __VA_ARGS__)
#define DX_REQUEST_SUBKIND_DEFINE(NAME, ...)			DX_SUBKIND_DEFINE(NAME, request, __VA_ARGS__)

DX_KIND_DECLARE_ABSTRACT(object);
DX_KIND_DECLARE(session);
DX_KIND_DECLARE_ABSTRACT(request);
DX_KIND_DECLARE(gai_request);

#define DX_TRANSPARENT_UNION_MEMBER(NAME)	DX_STRUCT(NAME) *	NAME

typedef union {
	DX_TRANSPARENT_UNION_MEMBER(object);
	DX_TRANSPARENT_UNION_MEMBER(session);
	DX_TRANSPARENT_UNION_MEMBER(request);
	DX_TRANSPARENT_UNION_MEMBER(gai_request);
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
_dx_init(dx_object_t object);

static void
_dx_retain(dx_any_t object);

static void
_dx_release(dx_any_t object);
#define _dx_release_null_safe(X)	\
	do {							\
		if (X) {					\
			_dx_release(X);			\
		}							\
	} while (0)
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
	struct dx_object_s	base;			// Object base.
	dx_request_t		next;			// Next request in list.
	dx_session_t		session;		// Back pointer to parent session.
	xpc_object_t		results;		// Array of pending results.
	uint64_t			command_id;		// ID to distinquish multiple commands during a session.
	uint32_t			request_id;		// Request ID, used for logging purposes.
	DNSServiceErrorType	error;			// Pending error.
	os_unfair_lock		lock;			// Lock for pending error and results array.
	bool				sent_error;		// True if the pending error has been sent to client.
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

struct dx_gai_request_s {
	struct dx_request_s			base;					// Request object base.
	GetAddrInfoClientRequest	gai;					// Underlying GAI request.
	QueryRecordClientRequest	query;					// Underlying SVCB/HTTPS query request.
	xpc_object_t				params;					// Parameter dictionary from client's message.
	xpc_object_t				hostname_obj;			// Hostname string from parameter dictionary.
	const char *				hostname;				// Hostname C string to be resolved for getaddrinfo request.
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
	mdns_trust_t				trust;					// Trust instance if status is mdns_trust_status_pending
#endif
	mdns_dns_service_id_t		custom_service_id;		// ID for this request's custom DNS service.
	xpc_object_t				cnames_a;				// Hostname's canonical names for A records as an XPC array.
	ssize_t						cnames_a_expire_idx;	// Index of the first expired canonical name in cnames_a.
	xpc_object_t				cnames_aaaa;			// Hostname's canonical names for AAAA records as an XPC array.
	ssize_t						cnames_aaaa_expire_idx;	// Index of the first expired canonical name in cnames_aaaa.
	uuid_t						effective_uuid;			// Effective client UUID for creating result auth tags.
	bool						cnames_a_changed;		// True if cnames_a has changed.
	bool						cnames_aaaa_changed;	// True if cnames_aaaa has changed.
	bool						gai_active;				// True if the GAI request is currently active.
	bool						query_active;			// True if the SVCB/HTTPS query request is currently active.
	bool						need_auth;				// True if GAI results need to be authenticated.
};

static void
_dx_gai_request_invalidate(dx_gai_request_t request);

static void
_dx_gai_request_finalize(dx_gai_request_t request);

DX_REQUEST_SUBKIND_DEFINE(gai_request,
	.invalidate	= _dx_gai_request_invalidate,
	.finalize	= _dx_gai_request_finalize
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

static void
_dx_request_append_result(dx_any_request_t request, xpc_object_t result);

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
_dx_gai_request_activate_internal(dx_gai_request_t request);

static DNSServiceErrorType
_dx_gai_request_start_client_requests(dx_gai_request_t request, GetAddrInfoClientRequestParams *gai_params,
	QueryRecordClientRequestParams *query_params, const uint8_t *resolver_uuid, xpc_object_t fallback_config);

static void
_dx_gai_request_stop_client_requests(dx_gai_request_t request);

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
_dx_gai_request_enqueue_result(dx_gai_request_t request, uint32_t if_index, const domainname *name, uint16_t type,
	uint16_t class, const uint8_t *rdata_ptr, size_t rdata_len, bool is_expired, bool is_add, bool answered_from_cache,
	DNSServiceErrorType error, dnssd_getaddrinfo_result_protocol_t protocol, const char *provider_name);

static void
_dx_gai_request_get_delegator_ids(dx_gai_request_t request, pid_t *out_delegator_pid,
	const uint8_t **out_delegator_uuid, const audit_token_t **out_delegator_audit_token, audit_token_t *storage);

static DNSServiceErrorType
_dx_gai_request_get_svcb_name_and_type(dx_gai_request_t request, const char **out_svcb_name,
	uint16_t *out_svcb_type, char **out_svcb_memory);

static DNSServiceErrorType
_dx_gai_request_set_need_authenticated_results(dx_gai_request_t request, pid_t effective_pid,
	const uuid_t effective_uuid);

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
static const uint8_t *
_dx_gai_request_get_resolver_uuid(dx_gai_request_t request);
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
static bool
_dx_gai_request_is_for_in_app_browser(dx_gai_request_t request);
#endif

static void
_dx_gai_request_log_start(dx_gai_request_t request, DNSServiceFlags flags, uint32_t if_index,
	DNSServiceProtocol protocols, pid_t delegator_pid, const uuid_t delegator_uuid);

static void
_dx_gai_request_log_stop(dx_gai_request_t request);

static void
_dx_gai_request_log_a_result(dx_gai_request_t request, uint32_t query_id, uint32_t if_index, const domainname *name,
	const uint8_t *rdata, MortalityState mortality, bool is_add_event);

static void
_dx_gai_request_log_aaaa_result(dx_gai_request_t request, uint32_t query_id, uint32_t if_index, const domainname *name,
	const uint8_t *rdata, MortalityState mortality, bool is_add);

static void
_dx_gai_request_log_svcb_result(dx_gai_request_t request, uint32_t query_id, uint32_t if_index, const domainname *name,
	const char *type_str, const uint8_t *rdata_ptr, size_t rdata_len, const ResourceRecord *answer, bool is_add_event);

static void
_dx_gai_request_log_no_such_record_result(dx_gai_request_t request, uint32_t query_id, uint32_t if_index,
	const domainname *name, const char *type_str, MortalityState mortality, bool is_add);

static void
_dx_gai_request_log_error(dx_gai_request_t request, DNSServiceErrorType error);

#define DNSSD_AUTHENTICATION_TAG_SIZE	32	// XXX: Defined as a workaround until NECP header defines this length.

static bool
_dx_authenticate_address_rdata(uuid_t effective_uuid, const char *hostname, int type, const uint8_t *rdata,
	uint8_t out_auth_tag[STATIC_PARAM DNSSD_AUTHENTICATION_TAG_SIZE]);

static char *
_dx_pid_to_name(pid_t pid, char out_name[STATIC_PARAM MAXCOMLEN]);

static void
_dx_kqueue_locked(const char *description, dx_block_t block);

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
_dx_init(const dx_object_t me)
{
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
	const dx_object_t me = any.object;
	if (atomic_fetch_sub(&me->ref_count, 1) == 1) {
		_dx_finalize(me);
		free(me);
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
	const dx_session_t obj = _dx_session_alloc_and_init();
	require_quiet(obj, exit);

	obj->connection = connection;
	xpc_retain(obj->connection);
	xpc_connection_get_audit_token(obj->connection, &obj->audit_token);
	obj->client_pid		= xpc_connection_get_pid(obj->connection);
	obj->client_euid	= xpc_connection_get_euid(obj->connection);
	_dx_pid_to_name(obj->client_pid, obj->client_name);

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

	req->params = params;
	xpc_retain(req->params);

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
	_dx_release_null_safe(req);
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
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
		"XPC session error -- error: %{mdns:err}ld, client pid: %lld (" PUB_S ")",
		(long)error, (long long)me->client_pid, me->client_name);
}

//======================================================================================================================

static void
_dx_session_log_pending_send_count_increase(const dx_session_t me)
{
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
		"XPC session to client with pid %lld (%s) pending send count increased to %d",
		(long long)me->client_pid, me->client_name, me->pending_send_count);
}

//======================================================================================================================

static void
_dx_session_log_pending_send_count_decrease(const dx_session_t me)
{
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_DEBUG,
		"XPC session to client with pid %lld (%s) pending send count decreased to %d",
		(long long)me->client_pid, me->client_name, me->pending_send_count);
}

//======================================================================================================================

static void
_dx_session_log_termination(const dx_session_t me)
{
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
		"XPC session termination -- pending send count: %u, pending send count max: %u, client pid: %lld (" PUB_S ")",
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
	__block xpc_object_t results = NULL;
	_dx_request_locked(me,
	^{
		if (me->results && (xpc_array_get_count(me->results) > 0)) {
			results = me->results;
			me->results = NULL;
		}
	});
	return results;
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

static void
_dx_request_append_result(const dx_any_request_t any, const xpc_object_t result)
{
	const dx_request_t me = any.request;
	_dx_request_locked(me,
	^{
		if (!me->results) {
			me->results = xpc_array_create(NULL, 0);
		}
		if (likely(me->results)) {
			xpc_array_append_value(me->results, result);
		} else {
			if (!me->error) {
				me->error = kDNSServiceErr_NoMemory;
			}
		}
	});
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
	dx_gai_request_t obj = _dx_gai_request_alloc_and_init();
	require_quiet(obj, exit);

	obj->base.command_id	= command_id;
	obj->base.session		= session;
	_dx_retain(obj->base.session);

	obj->cnames_a_expire_idx	= -1;
	obj->cnames_aaaa_expire_idx	= -1;

exit:
	return obj;
}

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
static DNSServiceErrorType
_dx_gai_request_trust_check(dx_gai_request_t request, bool *out_activate_deferred);
#endif

static DNSServiceErrorType
_dx_gai_request_activate(const dx_gai_request_t me)
{
	DNSServiceErrorType err;
	me->hostname_obj = dnssd_xpc_parameters_get_hostname_object(me->params);
	require_action_quiet(me->hostname_obj, exit, err = kDNSServiceErr_BadParam);

	xpc_retain(me->hostname_obj);
	me->hostname = xpc_string_get_string_ptr(me->hostname_obj);
	require_action_quiet(me->hostname, exit, err = kDNSServiceErr_Unknown);

	bool defer_activation = false;
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
	if (os_feature_enabled(mDNSResponder, bonjour_privacy)) {
		err = _dx_gai_request_trust_check(me, &defer_activation);
		require_noerr_quiet(err, exit);
	}
#endif
	if (!defer_activation) {
		err = _dx_gai_request_activate_internal(me);
		require_noerr_quiet(err, exit);
	}
	err = kDNSServiceErr_NoError;

exit:
	return err;
}

#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
static DNSServiceErrorType
_dx_gai_request_trust_check(const dx_gai_request_t me, bool * const out_defer_activation)
{
	DNSServiceErrorType err;
	bool defer_activation = false;
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
						handler_err = _dx_gai_request_activate_internal(me);
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
			defer_activation = true;
			err = kDNSServiceErr_NoError;
			break;

		case mdns_trust_status_no_entitlement:
			err = kDNSServiceErr_NoAuth;
			break;

		default:
			err = kDNSServiceErr_Unknown;
			break;
	}

exit:
	if (out_defer_activation) {
		*out_defer_activation = defer_activation;
	}
	return err;
}
#endif

//======================================================================================================================

static void
_dx_gai_request_invalidate(const dx_gai_request_t me)
{
	_dx_gai_request_log_stop(me);
	_dx_gai_request_stop_client_requests(me);
#if MDNSRESPONDER_SUPPORTS(APPLE, TRUST_ENFORCEMENT)
	mdns_trust_forget(&me->trust);
#endif
}

//======================================================================================================================

static void
_dx_gai_request_finalize(const dx_gai_request_t me)
{
	me->hostname = NULL;
	xpc_forget(&me->params);
	xpc_forget(&me->hostname_obj);
	xpc_forget(&me->cnames_a);
	xpc_forget(&me->cnames_aaaa);
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_start_client_requests(const dx_gai_request_t me, GetAddrInfoClientRequestParams * const gai_params,
	QueryRecordClientRequestParams * const query_params, const uint8_t * const resolver_uuid,
	const xpc_object_t fallback_config)
{
	__block DNSServiceErrorType err = kDNSServiceErr_NoError;
	_dx_kqueue_locked("dx_gai_request: starting client requests",
	^{
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		if (resolver_uuid && !uuid_is_null(resolver_uuid)) {
			Querier_RegisterPathResolver(resolver_uuid);
		}
		if ((me->custom_service_id == 0) && fallback_config) {
			me->custom_service_id = Querier_RegisterCustomDNSService(fallback_config);
		}
		if (gai_params) {
			gai_params->resolverUUID	= resolver_uuid;
			gai_params->customID		= me->custom_service_id;
		}
		if (query_params) {
			query_params->resolverUUID	= resolver_uuid;
			query_params->customID		= me->custom_service_id;
		}
#else
        (void)resolver_uuid;
        (void)fallback_config;
#endif
		// If present, run the query for SVCB/HTTPSSVC first, in case the ALPN and address hints come back first.
		if (query_params && !me->query_active) {
			err = QueryRecordClientRequestStart(&me->query, query_params, _dx_gai_request_query_result_handler, me);
			require_noerr_return(err);
			me->query_active = true;
		}
		// Run the A/AAAA lookup.
		if (gai_params && !me->gai_active) {
			err = GetAddrInfoClientRequestStart(&me->gai, gai_params, _dx_gai_request_gai_result_handler, me);
			require_noerr_return(err);
			me->gai_active = true;
		}
	});
	if (err) {
		_dx_gai_request_stop_client_requests(me);
	}
	return err;
}

//======================================================================================================================

static void
_dx_gai_request_stop_client_requests(const dx_gai_request_t me)
{
	_dx_kqueue_locked("dx_gai_request: stopping client requests",
	^{
		if (me->gai_active) {
			GetAddrInfoClientRequestStop(&me->gai);
			me->gai_active = false;
		}
		if (me->query_active) {
			QueryRecordClientRequestStop(&me->query);
			me->query_active = false;
		}
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		if (me->custom_service_id != 0) {
			Querier_DeregisterCustomDNSService(me->custom_service_id);
			me->custom_service_id = 0;
		}
#endif
	});
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
_dx_gai_request_gai_result_handler(mDNS * const m, DNSQuestion * const q, const ResourceRecord * const answer,
	const QC_result qc_result, const DNSServiceErrorType error, void * const context)
{
	const dx_gai_request_t me = (dx_gai_request_t)context;
	if (!error || (error == kDNSServiceErr_NoSuchRecord)) {
		const bool expired = (answer->mortality == Mortality_Ghost) ? true : false;
		if (answer->rrtype == kDNSServiceType_CNAME) {
			require_quiet(!error, exit);

			_dx_gai_request_append_cname(me, q->qtype, &answer->rdata->u.name, expired, q->CNAMEReferrals == 0);
		}
		require_quiet((answer->rrtype == kDNSServiceType_A) || (answer->rrtype == kDNSServiceType_AAAA), exit);

		if (q->CNAMEReferrals == 0) {
			_dx_gai_request_unwind_cnames_if_necessary(me, q->qtype);
		}
		const uint8_t *	rdata_ptr;
		size_t			rdata_len;
		const uint32_t query_id = mDNSVal16(q->TargetQID);
		const uint32_t if_index = mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, mDNStrue);
		const bool add_result = (qc_result != QC_rmv) ? true : false;
		if (!error) {
			if (answer->rrtype == kDNSServiceType_A) {
				rdata_ptr = answer->rdata->u.ipv4.b;
				rdata_len = 4;
				_dx_gai_request_log_a_result(me, query_id, if_index, answer->name, rdata_ptr, answer->mortality,
					add_result);
			} else {
				rdata_ptr = answer->rdata->u.ipv6.b;
				rdata_len = 16;
				_dx_gai_request_log_aaaa_result(me, query_id, if_index, answer->name, rdata_ptr, answer->mortality,
					add_result);
			}
		} else {
			rdata_ptr = NULL;
			rdata_len = 0;
			const char * const type_str = (answer->rrtype == kDNSServiceType_A) ? "A" : "AAAA";
			_dx_gai_request_log_no_such_record_result(me, query_id, if_index, answer->name, type_str, answer->mortality,
				add_result);
		}
		const bool answered_from_cache = !q->InitialCacheMiss ? true : false;
		const char *provider_name = NULL;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		if (answer->dnsservice) {
			provider_name = mdns_dns_service_get_provider_name(answer->dnsservice);
		}
		const dnssd_getaddrinfo_result_protocol_t protocol = answer->protocol;
#else
		const dnssd_getaddrinfo_result_protocol_t protocol = dnssd_getaddrinfo_result_protocol_udp;
#endif
		_dx_gai_request_enqueue_result(me, if_index, answer->name, answer->rrtype, answer->rrclass, rdata_ptr,
			rdata_len, expired, add_result, answered_from_cache, error, protocol, provider_name);
	} else {
		_dx_request_set_error(me, error);
	}

exit:
	return;
}

//======================================================================================================================

static void
_dx_gai_request_query_result_handler(mDNS * const m, DNSQuestion * const q, const ResourceRecord * const answer,
	const QC_result qc_result, const DNSServiceErrorType error, void * const context)
{
	const dx_gai_request_t me = (dx_gai_request_t)context;
	if (!error || (error == kDNSServiceErr_NoSuchRecord)) {
		require_quiet((answer->rrtype == kDNSServiceType_SVCB) || (answer->rrtype == kDNSServiceType_HTTPS), exit);

		const uint8_t *	rdata_ptr;
		size_t			rdata_len;
		const uint32_t query_id = mDNSVal16(q->TargetQID);
		const uint32_t if_index = mDNSPlatformInterfaceIndexfromInterfaceID(m, answer->InterfaceID, mDNStrue);
		const bool add_result = (qc_result != QC_rmv) ? true : false;
		const char * const type_str = (answer->rrtype == kDNSServiceType_SVCB) ? "SVCB" : "HTTPS";
		if (!error) {
			rdata_ptr = answer->rdata->u.data;
			rdata_len = answer->rdlength;

			_dx_gai_request_log_svcb_result(me, query_id, if_index, answer->name, type_str, rdata_ptr, rdata_len,
				answer, add_result);
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
			char * const svcb_doh_uri = dnssd_svcb_copy_doh_uri(rdata_ptr, rdata_len);
			// Check for a valid DoH URI.
			if (svcb_doh_uri) {
				// Pass the domain to map if the record is DNSSEC signed.
				char *svcb_domain = NULL;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
				char svcb_domain_buffer[MAX_ESCAPED_DOMAIN_NAME] = "";
				if (answer->dnssec_result == dnssec_secure) {
					if (ConvertDomainNameToCString(answer->name, svcb_domain_buffer)) {
						svcb_domain = svcb_domain_buffer;
					}
				}
#endif
				Querier_RegisterDoHURI(svcb_doh_uri, svcb_domain);
				free(svcb_doh_uri);
			}
#endif
		} else {
			rdata_ptr = NULL;
			rdata_len = 0;
			_dx_gai_request_log_no_such_record_result(me, query_id, if_index, answer->name, type_str, answer->mortality,
				add_result);
		}
		const bool answered_from_cache = !q->InitialCacheMiss ? true : false;
		const char *provider_name = NULL;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		if (answer->dnsservice) {
			provider_name = mdns_dns_service_get_provider_name(answer->dnsservice);
		}
		const dnssd_getaddrinfo_result_protocol_t protocol = answer->protocol;
#else
		const dnssd_getaddrinfo_result_protocol_t protocol = dnssd_getaddrinfo_result_protocol_udp;
#endif
		_dx_gai_request_enqueue_result(me, if_index, answer->name, answer->rrtype, answer->rrclass, rdata_ptr,
			rdata_len, answer->mortality == Mortality_Ghost, add_result, answered_from_cache, error, protocol,
			provider_name);
	} else {
		_dx_request_set_error(me, error);
	}

exit:
	return;
}

//======================================================================================================================

static void
_dx_gai_request_enqueue_result(const dx_gai_request_t me, const uint32_t if_index, const domainname * const name,
	const uint16_t type, const uint16_t class, const uint8_t * const rdata_ptr, const size_t rdata_len,
	const bool is_expired, const bool is_add, const bool answered_from_cache, const DNSServiceErrorType result_error,
	const dnssd_getaddrinfo_result_protocol_t protocol, const char * const provider_name)
{
	DNSServiceErrorType err;
	xpc_object_t result = xpc_dictionary_create(NULL, NULL, 0);
	require_action_quiet(result, exit, err = kDNSServiceErr_NoMemory);

	char name_str[MAX_ESCAPED_DOMAIN_NAME];
	if (!ConvertDomainNameToCString(name, name_str)) {
		name_str[0] = '\0';
	}
	DNSServiceFlags flags = 0;
	if (is_add) {
		flags |= kDNSServiceFlagsAdd;
		if (answered_from_cache) {
			flags |= kDNSServiceFlagAnsweredFromCache;
		}
	}
	if (is_expired) {
		flags |= kDNSServiceFlagsExpiredAnswer;
	}
	dnssd_xpc_result_set_error(result, result_error);
	dnssd_xpc_result_set_flags(result, flags);
	dnssd_xpc_result_set_interface_index(result, if_index);
	dnssd_xpc_result_set_record_name(result, name_str);
	dnssd_xpc_result_set_record_type(result, type);
	dnssd_xpc_result_set_record_protocol(result, protocol);
	dnssd_xpc_result_set_record_class(result, class);
	dnssd_xpc_result_set_record_data(result, rdata_ptr, rdata_len);
	if (provider_name) {
		dnssd_xpc_result_set_provider_name(result, provider_name);
	}
	if (me->need_auth && is_add && !result_error) {
		uint8_t auth_tag[DNSSD_AUTHENTICATION_TAG_SIZE];
		const bool ok = _dx_authenticate_address_rdata(me->effective_uuid, me->hostname, type, rdata_ptr, auth_tag);
		if (ok) {
			dnssd_xpc_result_set_authentication_tag(result, auth_tag, sizeof(auth_tag));
		}
	}
	xpc_object_t cname_update = _dx_gai_request_copy_cname_update(me, type);
	if (cname_update) {
		dnssd_xpc_result_set_cname_update(result, cname_update);
		xpc_forget(&cname_update);
	}
	_dx_request_append_result(me, result);
	xpc_forget(&result);
	err = kDNSServiceErr_NoError;

exit:
	if (err) {
		_dx_request_set_error(me, err);
	}
}

//======================================================================================================================

static void
_dx_gai_request_get_delegator_ids(const dx_gai_request_t me, pid_t * const out_delegator_pid,
	const uint8_t ** const out_delegator_uuid, const audit_token_t ** const out_delegator_audit_token,
	audit_token_t * const storage)
{
	pid_t pid;
	const uint8_t *uuid;
	const audit_token_t * const token = dnssd_xpc_parameters_get_delegate_audit_token(me->params, storage);
	if (token) {
		pid		= audit_token_to_pid(*token);
		uuid	= NULL;
	} else {
		uuid = dnssd_xpc_parameters_get_delegate_uuid(me->params);
		if (uuid) {
			pid = 0;
		} else {
			pid = dnssd_xpc_parameters_get_delegate_pid(me->params, NULL);
		}
	}
	if (out_delegator_pid) {
		*out_delegator_pid = pid;
	}
	if (out_delegator_uuid) {
		*out_delegator_uuid = uuid;
	}
	if (out_delegator_audit_token) {
		*out_delegator_audit_token = token;
	}
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_get_svcb_name_and_type(const dx_gai_request_t me, const char ** const out_svcb_name,
	uint16_t * const out_svcb_type, char ** const out_svcb_memory)
{
	DNSServiceErrorType err;
	const char *	svcb_name	= NULL;
	uint16_t		svcb_type	= 0;
	char *			svcb_memory	= NULL;
	const char * const service_scheme = dnssd_xpc_parameters_get_service_scheme(me->params);
	if (service_scheme) {
		if (strcasecmp(service_scheme, "_443._https") == 0) {
			svcb_name = me->hostname;
			svcb_type = kDNSType_HTTPS;
		} else {
			asprintf(&svcb_memory, "%s.%s", service_scheme, me->hostname);
			require_action_quiet(svcb_memory, exit, err = kDNSServiceErr_NoMemory);

			svcb_name = svcb_memory;
			svcb_type = kDNSType_SVCB;
		}
	}
	if (out_svcb_name) {
		*out_svcb_name = svcb_name;
	}
	if (out_svcb_type) {
		*out_svcb_type = svcb_type;
	}
	*out_svcb_memory = svcb_memory;
	err = kDNSServiceErr_NoError;

exit:
	return err;
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_set_need_authenticated_results(const dx_gai_request_t me, const pid_t effective_pid,
	const uuid_t effective_uuid)
{
	DNSServiceErrorType err;
	if (effective_uuid) {
		uuid_copy(me->effective_uuid, effective_uuid);
	} else {
		struct proc_uniqidentifierinfo info;
		const int n = proc_pidinfo(effective_pid, PROC_PIDUNIQIDENTIFIERINFO, 1, &info, sizeof(info));
		require_action_quiet(n == (int)sizeof(info), exit, err = kDNSServiceErr_Unknown);
		uuid_copy(me->effective_uuid, info.p_uuid);
	}
	me->need_auth = true;
	err = kDNSServiceErr_NoError;

exit:
	return err;
}

//======================================================================================================================

#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
static const uint8_t *
_dx_gai_request_get_resolver_uuid(const dx_gai_request_t me)
{
	const xpc_object_t resolver_uuids = dnssd_xpc_parameters_get_resolver_uuid_array(me->params);
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
_dx_gai_request_is_for_in_app_browser(const dx_gai_request_t me)
{
	const char * const account_id = dnssd_xpc_parameters_get_account_id(me->params);
	if (account_id && (strcmp(account_id, "com.apple.WebKit.InAppBrowser") == 0)) {
		return true;
	} else {
		return false;
	}
}
#endif

//======================================================================================================================

static void
_dx_gai_request_log_start(const dx_gai_request_t me, const DNSServiceFlags flags, const uint32_t if_index,
	const DNSServiceProtocol protocols, const pid_t delegator_pid, const uuid_t delegator_uuid)
{
	char delegator_str[64];
	if (delegator_uuid) {
		uuid_string_t delegator_uuid_str;
		uuid_unparse_lower(delegator_uuid, delegator_uuid_str);
		snprintf(delegator_str, sizeof(delegator_str), ", delegator uuid: %s", delegator_uuid_str);
	} else if (delegator_pid != 0) {
		char delegator_name[MAXCOMLEN];
		snprintf(delegator_str, sizeof(delegator_str),
			", delegator pid: %lld (%s)", (long long)delegator_pid, _dx_pid_to_name(delegator_pid, delegator_name));
	} else {
		delegator_str[0] = '\0';
	}
	char options_str[64];
	snprintf(options_str, sizeof(options_str), "%s", me->need_auth ? "A" : "");
	const dx_session_t session = me->base.session;
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
		"[R%u] getaddrinfo start -- flags: 0x%X, ifindex: %d, protocols: %u, hostname: " PRI_S ", "
		"options: {" PUB_S "}, client pid: %lld (" PUB_S ")" PUB_S,
		me->base.request_id, flags, (int32_t)if_index, protocols, me->hostname, options_str,
		(long long)session->client_pid, session->client_name, delegator_str);
}

//======================================================================================================================

static void
_dx_gai_request_log_stop(const dx_gai_request_t me)
{
	const dx_session_t session = me->base.session;
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
		"[R%u] getaddrinfo stop" PUB_S " -- hostname: " PRI_S ", client pid: %lld (" PUB_S ")",
		me->base.request_id, session->terminated ? " (forced)" : "", me->hostname, (long long)session->client_pid,
		session->client_name);
}

//======================================================================================================================

static void
_dx_gai_request_log_a_result(const dx_gai_request_t me, const uint32_t query_id, const uint32_t if_index,
	const domainname * const name, const uint8_t * const rdata, const MortalityState mortality, const bool is_add)
{
	const char * const event_str = is_add ? "add" : "rmv";
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
		"[R%u->Q%u] getaddrinfo result -- event: " PUB_S ", ifindex: %d, name: " PRI_DM_NAME ", type: A, "
		"rdata: " PRI_IPv4_ADDR " (" PUB_S ")",
		me->base.request_id, query_id, event_str, if_index, DM_NAME_PARAM(name), rdata,
		MortalityDisplayString(mortality));
}

//======================================================================================================================

static void
_dx_gai_request_log_aaaa_result(const dx_gai_request_t me, const uint32_t query_id, const uint32_t if_index,
	const domainname * const name, const uint8_t * const rdata, const MortalityState mortality, const bool is_add)
{
	const char * const event_str = is_add ? "add" : "rmv";
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
		"[R%u->Q%u] getaddrinfo result -- event: " PUB_S ", ifindex: %d, name: " PRI_DM_NAME ", type: AAAA, "
		"rdata: " PRI_IPv6_ADDR " (" PUB_S ")",
		me->base.request_id, query_id, event_str, if_index, DM_NAME_PARAM(name), rdata,
		MortalityDisplayString(mortality));
}

//======================================================================================================================

static void
_dx_gai_request_log_svcb_result(const dx_gai_request_t me, const uint32_t query_id, const uint32_t if_index,
	const domainname * const name, const char * const type_str, const uint8_t * const rdata_ptr, const size_t rdata_len,
	const ResourceRecord * const answer, const bool is_add_event)
{
	const char * const event_str = is_add_event ? "add" : "rmv";
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
	const char * const dnssec_str = (answer->dnssec_result == dnssec_secure) ? "secure" : "insecure";
#else
	const char * const dnssec_str = "insecure";
#endif
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
		"[R%u->Q%u] getaddrinfo result -- event: " PUB_S ", ifindex: %d, name: " PRI_DM_NAME ", type: " PUB_S ", "
		"rdata: " PRI_SVCB ", DNSSEC: " PUB_S " (" PUB_S ")",
		me->base.request_id, query_id, event_str, if_index, DM_NAME_PARAM(name), type_str,
		SVCB_PARAM(rdata_ptr, (int)rdata_len), dnssec_str, MortalityDisplayString(answer->mortality));
}

//======================================================================================================================

static void
_dx_gai_request_log_no_such_record_result(const dx_gai_request_t me, const uint32_t query_id, const uint32_t if_index,
	const domainname * const name, const char * const type_str, const MortalityState mortality, const bool is_add)
{
	const char * const event_str = is_add ? "add" : "rmv";
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_INFO,
		"[R%u->Q%u] getaddrinfo result -- event: " PUB_S ", ifindex: %d, name: " PRI_DM_NAME ", type: " PUB_S ", "
		"rdata: <none> (" PUB_S ")",
		me->base.request_id, query_id, event_str, if_index, DM_NAME_PARAM(name), type_str,
		MortalityDisplayString(mortality));
}

//======================================================================================================================

static void
_dx_gai_request_log_error(const dx_gai_request_t me, const DNSServiceErrorType error)
{
	const dx_session_t session = me->base.session;
	LogRedact(MDNS_LOG_CATEGORY_DEFAULT, MDNS_LOG_ERROR,
		"[R%u] getaddrinfo error -- error: %{mdns:err}ld, client pid: %lld (" PUB_S ")",
		me->base.request_id, (long)error, (long long)session->client_pid, session->client_name);
}

//======================================================================================================================

static DNSServiceErrorType
_dx_gai_request_activate_internal(const dx_gai_request_t me)
{
	char *svcb_memory = NULL;

	// Get standard parameters.
	bool valid;
	DNSServiceErrorType err;
	const DNSServiceFlags flags = dnssd_xpc_parameters_get_flags(me->params, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	const uint32_t if_index = dnssd_xpc_parameters_get_interface_index(me->params, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	const uint32_t protocols = dnssd_xpc_parameters_get_protocols(me->params, &valid);
	require_action_quiet(valid, exit, err = kDNSServiceErr_BadParam);

	const dx_session_t session = me->base.session;

	// Get delegator IDs.
	pid_t delegator_pid;
	const uint8_t *delegator_uuid;
	const audit_token_t *delegator_audit_token;
	audit_token_t storage;
	_dx_gai_request_get_delegator_ids(me, &delegator_pid, &delegator_uuid, &delegator_audit_token, &storage);
	if (delegator_audit_token || delegator_uuid || (delegator_pid != 0)) {
		require_action_quiet(session->has_delegate_entitlement, exit, err = kDNSServiceErr_NoAuth);
	}
	_dx_gai_request_log_start(me, flags, if_index, protocols, delegator_pid, delegator_uuid);

	// Determine effective IDs.
	// Note: The mDNS core requires that the effective PID be set to zero if the effective UUID is set.
	const uint8_t *	effective_uuid;
	pid_t			effective_pid;
	if (delegator_uuid) {
		effective_uuid	= delegator_uuid;
		effective_pid	= 0;
	} else {
		effective_uuid	= NULL;
		effective_pid	= (delegator_pid != 0) ? delegator_pid : session->client_pid;
	}
	const bool need_auth_tags = dnssd_xpc_parameters_get_need_authentication_tags(me->params);
	if (need_auth_tags) {
		err = _dx_gai_request_set_need_authenticated_results(me, effective_pid, effective_uuid);
		require_noerr_quiet(err, exit);
	}

	// Set up GetAddrInfo parameters.
	GetAddrInfoClientRequestParams gai_params;
	GetAddrInfoClientRequestParamsInit(&gai_params);
	gai_params.hostnameStr		= me->hostname;
	gai_params.requestID		= me->base.request_id;
	gai_params.interfaceIndex	= if_index;
	gai_params.flags			= flags;
	gai_params.protocols		= protocols;
	gai_params.effectivePID		= effective_pid;
	gai_params.effectiveUUID	= effective_uuid;
	gai_params.peerUID			= session->client_euid;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	const uint8_t * const resolver_uuid = _dx_gai_request_get_resolver_uuid(me);
	const xpc_object_t fallback_config = dnssd_xpc_parameters_get_fallback_config(me->params);
	const bool need_encryption	= dnssd_xpc_parameters_get_need_encrypted_query(me->params);
	gai_params.needEncryption	= need_encryption ? mDNStrue : mDNSfalse;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
	const bool for_in_app_browser		= _dx_gai_request_is_for_in_app_browser(me);
	gai_params.peerAuditToken			= &session->audit_token;
	gai_params.delegatorAuditToken		= delegator_audit_token;
	gai_params.isInAppBrowserRequest	= for_in_app_browser ? mDNStrue : mDNSfalse;
#endif
	// Set up QueryRecord parameters.
	QueryRecordClientRequestParams query_params;
	QueryRecordClientRequestParams *query_params_ptr = NULL;
	const char *svcb_name = NULL;
	uint16_t svcb_type = 0;
	err = _dx_gai_request_get_svcb_name_and_type(me, &svcb_name, &svcb_type, &svcb_memory);
	require_noerr_quiet(err, exit);
	if (svcb_name) {
		QueryRecordClientRequestParamsInit(&query_params);
		query_params.requestID				= me->base.request_id;
		query_params.qnameStr				= svcb_name;
		query_params.interfaceIndex			= if_index;
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
		query_params.flags					= flags | kDNSServiceFlagsEnableDNSSEC;
#else
		query_params.flags					= flags;
#endif
		query_params.qtype					= svcb_type;
		query_params.qclass					= kDNSServiceClass_IN;
		query_params.effectivePID			= effective_pid;
		query_params.effectiveUUID			= effective_uuid;
		query_params.peerUID				= session->client_euid;
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
		query_params.needEncryption			= need_encryption ? mDNStrue : mDNSfalse;
#endif
#if MDNSRESPONDER_SUPPORTS(APPLE, AUDIT_TOKEN)
		query_params.peerAuditToken			= &session->audit_token;
		query_params.delegatorAuditToken	= delegator_audit_token;
		query_params.isInAppBrowserRequest	= for_in_app_browser ? mDNStrue : mDNSfalse;
#endif
		query_params_ptr = &query_params;
	}
	// Activate request.
#if MDNSRESPONDER_SUPPORTS(APPLE, QUERIER)
	err = _dx_gai_request_start_client_requests(me, &gai_params, query_params_ptr, resolver_uuid, fallback_config);
#else
	err = _dx_gai_request_start_client_requests(me, &gai_params, query_params_ptr, NULL, NULL);
#endif
	require_noerr_quiet(err, exit);

exit:
	ForgetMem(&svcb_memory);
	return err;
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

static char *
_dx_pid_to_name(const pid_t pid, char out_name[STATIC_PARAM MAXCOMLEN])
{
	out_name[0] = '\0';
	if (pid != 0) {
		struct proc_bsdshortinfo info;
		const int n = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &info, PROC_PIDT_SHORTBSDINFO_SIZE);
		if (n == (int)sizeof(info)) {
			check_compile_time_code(sizeof(info.pbsi_comm) == MAXCOMLEN);
			strlcpy(out_name, info.pbsi_comm, MAXCOMLEN);
		}
	}
	return out_name;
}

//======================================================================================================================

static void
_dx_kqueue_locked(const char * const description, const dx_block_t block)
{
	KQueueLock();
	block();
	KQueueUnlock(description);
}
