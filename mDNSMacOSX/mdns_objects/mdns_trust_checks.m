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

#import "mDNSEmbeddedAPI.h"
#import "mdns_trust.h"
#import "mdns_trust_checks.h"
#import "mdns_helpers.h"

#if TARGET_OS_IOS && (TARGET_OS_EMBEDDED || TARGET_OS_SIMULATOR || !TARGET_OS_IOSMAC)
#define USE_IOS_LIBS	1
#else
#define USE_IOS_LIBS	0
#endif

#if USE_IOS_LIBS
#import <CoreServices/LSBundleProxy.h>
#import <CoreServices/LSDiskUsagePriv.h>
#import <CoreServices/LSApplicationRecordPriv.h>
#else
#import <CoreServices/CoreServicesPriv.h>
#import <Security/CodeSigning.h>
#endif

#import <bsm/libbsm.h>
#import <CoreAnalytics/CoreAnalytics.h>
#import <CoreUtils/DebugServices.h>
#import <NetworkExtension/NetworkExtensionPrivate.h>
#import <nw/path_evaluation.h>
#import <os/feature_private.h>
#import <xpc/private.h>
#import <stdatomic.h>

#define BROWSE_ALL_SERVICES_PRIVATE_ENTITLEMENT		"com.apple.developer.networking.multicast"
#define ON_DEMAND_ENTITLEMENT						"com.apple.developer.on-demand-install-capable"
#define TRUST_BYPASS_GAME_CENTER_SERVICE			"_gamecenter._tcp"

#define kLocalDomain  		((const domainname *) 	"\x5" "local"				)
#define kReverseIPv6Domain  ((const domainname *) 	"\x3" "ip6" 	"\x4" "arpa")
#define kReverseIPv4Domain  ((const domainname *) 	"\x7" "in-addr" "\x4" "arpa")

MDNS_LOG_CATEGORY_DEFINE(trust, "trust");

//======================================================================================================================
// MARK: - mdns_trust_check struct

typedef struct mdns_trust_check_s {
	trust_request_t						request;
	const char *						query_name;
	const char *						service_name;
	audit_token_t *						audit_token;
	trust_policy_state_t				policy_state;
	uint16_t							request_type;
	mdns_trust_flags_t					flags;
	bool								entitlement_allowed;
	bool								force_multicast;
} *mdns_trust_check_t;

//======================================================================================================================
// MARK: - Private helpers

static void
_mdns_trust_post_analytic(const mdns_trust_check_t me, const LSBundleProxy * bundle_proxy,
	const NSArray * _Nullable services)
{
	AnalyticsSendEvent(@"com.apple.network.localnetwork.check",
					   @{@"bundleID"	: bundle_proxy.bundleIdentifier,
						 @"entitlement"	: (me->flags & mdns_trust_flags_entitlement) ? @YES : @NO,
						 @"allowed"		: (me->entitlement_allowed) ? @YES : @NO,
						 @"services"	: services ?: @[],
						 @"service"		: [NSString stringWithUTF8String:me->service_name]});
}

static bool
_mdns_trust_checks_is_same_domain_name(const char *domain1, const char *domain2)
{
	domainname d1, d2;
	bool good = (MakeDomainNameFromDNSNameString(&d1, domain1) != NULL);
	require_quiet(good, exit);

	good = (MakeDomainNameFromDNSNameString(&d2, domain2) != NULL);
	require_quiet(good, exit);

	good = (SameDomainName(&d1, &d2) != mDNSfalse);

exit:
	return good;
}

static LSBundleProxy*
_mdns_trust_checks_bundle_proxy_for_app(const audit_token_t *audit_token)
{
    NSError *error;
	LSBundleProxy *bundle_proxy = nil;

	if (__builtin_available(macOS 10.15, ios 13.0, watchos 6.0, tvos 13.0, *)) {
		bundle_proxy = [LSBundleProxy bundleProxyWithAuditToken:*audit_token error:&error];
	}

	return bundle_proxy;
}

static bool
_mdns_trust_checks_is_local_address(const char * _Nonnull address)
{
	nw_endpoint_t endpoint = nw_endpoint_create_host(address, "0");
	nw_path_evaluator_t evaluator = nw_path_create_evaluator_for_endpoint(endpoint, nil);
	nw_path_t path = nw_path_evaluator_copy_path(evaluator);
	bool local_network = nw_path_is_direct(path);
	return (local_network != false);
}

static bool
_mdns_trust_checks_reverse_ipv6_to_ipv6_string(const domainname *name, char * _Nonnull addr_buffer,
	socklen_t addr_buffer_len)
{
	bool				result = false;
	const uint8_t *     ptr;
	int                 i;
	uint8_t             ipv6[16];

	// If the name is of the form "x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.x.ip6.arpa.", where
	// each x is a hex digit, then the sequence of 32 hex digit labels represents the nibbles of an IPv6 address in
	// reverse order. See <https://tools.ietf.org/html/rfc3596#section-2.5>.

	ptr = name->c;
	for (i = 0; i < 32; i++)
	{
		unsigned int c, nibble;
		const int j = 15 - (i / 2);
		require_quiet(*ptr++ == 1, exit);						// If this label's length is not 1, then fail.
		c = *ptr++;                                             // Get label byte.
		if ( (c >= '0') && (c <= '9')) {
			nibble =  c - '0';   // If it's a hex digit, get its numeric value.
		} else if ((c >= 'a') && (c <= 'f')) {
			nibble = (c - 'a') + 10;
		} else if ((c >= 'A') && (c <= 'F')) {
			nibble = (c - 'A') + 10;
		} else {
			goto exit;
		}
		if ((i % 2) == 0) {
			ipv6[j] = (uint8_t)nibble;
		} else {
			ipv6[j] |= (uint8_t)(nibble << 4);
		}
	}

	// The rest of the name needs to be "ip6.arpa.". If it isn't, fail.
	require_quiet(SameDomainName((const domainname *)ptr, kReverseIPv6Domain), exit);
	(void)inet_ntop(AF_INET6, &ipv6, addr_buffer, addr_buffer_len);
	result = true;
exit:
	return result;
}

static bool
_mdns_trust_checks_reverse_ipv4_to_ipv4_string(const domainname *name, char * _Nonnull addr_buffer,
	socklen_t addr_buffer_len)
{
	bool			result = false;
	const mDNSu8 *	ptr;
	uint8_t			ipv4[4];
	uint32_t		ipv4_addr;

	// If the name is of the form "x.x.x.x.in-addr.arpa.", where each x is a uint8

	uint8_t *		dst;
	int				segments = 0;
	bool			sawDigit = 0;
	int				c, v, label_length;

	ptr 			= name->c;
	for (int i = 1; i <= 4; i++)
	{
		dst = &ipv4[4 - i];
		*dst = 0;
		sawDigit = false;
		label_length = *ptr++;
		require_quiet((label_length >= 1) && (label_length <= 3), exit);
		for (int j = 0; j < label_length; j++) {
			c = *ptr++;                                             // Get label byte.
			require_quiet((c >= '0') && (c <= '9'), exit);
			v = (*dst * 10) + (c - '0');
			require_quiet(v <= 255, exit);
			*dst = (uint8_t) v;
			if (!sawDigit) {
				++segments;
				require_quiet(segments <= 4, exit);
				sawDigit = true;
			}
		}
		require_quiet(segments == i, exit);
	}
	require_quiet(segments == 4, exit);
	ipv4_addr = *(uint32_t*)&ipv4; 								// Already in network byte order

	// The rest of the name needs to be "ip-addr.arpa.". If it isn't, fail.
	require_quiet(SameDomainName((const domainname *)ptr, kReverseIPv4Domain), exit);
	(void)inet_ntop(AF_INET, &ipv4_addr, addr_buffer, addr_buffer_len);
	result = true;
exit:
	return result;
}

static bool
_mdns_trust_checks_should_check_query_type(const char *qname, uint16_t qtype)
{
	domainname domain;
	bool good = (MakeDomainNameFromDNSNameString(&domain, qname) != NULL);
	require_quiet(good, exit);

	bool qtype_valid = (qtype == kDNSType_PTR || qtype == kDNSQType_ANY);
	const domainname *d = &domain;

	const domainname *d1, *d2;   												// Top-level domain, second-level domain
	d1 = d2 = nil;
	while (d->c[0]) {
		d2 = d1; d1 = d;
		d = (const domainname*)(d->c + 1 + d->c[0]);
	}

	if (d1 && SameDomainName(d1, kLocalDomain)) {
		return true;
	} else if (qtype_valid && IsLocalDomain(&domain)) {
		return true;
	} else if (d2 && qtype_valid && SameDomainName(d2, kReverseIPv4Domain)) {
		char str_buffer[INET_ADDRSTRLEN];
		if (_mdns_trust_checks_reverse_ipv4_to_ipv4_string(&domain, str_buffer, sizeof(str_buffer))) {
			if (_mdns_trust_checks_is_local_address(str_buffer)) {
				return true;
			}
		}
	} else if (d2 && qtype_valid && SameDomainName(d2, kReverseIPv6Domain)) {
		char str_buffer[INET6_ADDRSTRLEN];
		if (_mdns_trust_checks_reverse_ipv6_to_ipv6_string(&domain, str_buffer, sizeof(str_buffer))) {
			if (_mdns_trust_checks_is_local_address(str_buffer)) {
				return true;
			}
		}
	}
exit:
	return false;
}

//======================================================================================================================
// MARK: - mdns_trust_checks System checks

#if USE_IOS_LIBS

static bool
_mdns_trust_checks_system_trusted_app(const LSBundleProxy *bundle_proxy)
{
	NSString * bundleid = bundle_proxy.bundleIdentifier;
	return ([bundleid hasPrefix: @"com.apple."] != NO);
}

#else // !USE_IOS_LIBS

static bool
_mdns_trust_checks_codesigned_by_apple(const LSBundleProxy *bundle_proxy)
{
    OSStatus err;
    SecRequirementRef requirement = NULL;
    SecStaticCodeRef code = NULL;

    err = SecRequirementCreateWithString(CFSTR("anchor apple"), kSecCSDefaultFlags, &requirement);
	require_noerr_quiet(err, exit);

	err = SecStaticCodeCreateWithPath((__bridge CFURLRef)bundle_proxy.bundleURL, kSecCSDefaultFlags, &code);
	require_noerr_quiet(err, exit);

    err = SecStaticCodeCheckValidity(code, kSecCSDefaultFlags, requirement);

exit:
	if (code) {
		CFRelease(code);
	}
	if (requirement) {
		CFRelease(requirement);
	}

    return (err == noErr);
}

#endif // USE_IOS_LIBS

static bool
_mdns_trust_checks_app_is_apple_internal(const LSBundleProxy *bundle_proxy)
{
#if USE_IOS_LIBS
	NSString * bundleType = bundle_proxy.bundleType;
	if ([bundleType isEqualToString:LSInternalApplicationType]	||
		[bundleType isEqualToString:LSSystemApplicationType]) {
		return true;
	} else if ([bundleType isEqualToString:LSPlugInKitType] &&
		_mdns_trust_checks_system_trusted_app(bundle_proxy)) {
		return true;
	} else {
		return false;
	}
#else // !USE_IOS_LIBS
	return _mdns_trust_checks_codesigned_by_apple(bundle_proxy);
#endif // USE_IOS_LIBS
}

static bool
_mdns_trust_checks_app_sdk_is_minimum_version(const LSBundleProxy *bundle_proxy)
{
#if TARGET_OS_OSX
	#define MIN_SDK_VERSION	"10.16"
#elif TARGET_OS_WATCH
	#define MIN_SDK_VERSION	"7.0"
#else
	#define MIN_SDK_VERSION	"14.0"
#endif
	NSString * min_vers = [NSString stringWithUTF8String:MIN_SDK_VERSION];
	NSComparisonResult compare_result = [[bundle_proxy sdkVersion] compare:min_vers options:NSNumericSearch];
	bool result = ((compare_result == NSOrderedSame) || (compare_result == NSOrderedDescending));

	return (result != false);
}

//======================================================================================================================
// MARK: - mdns_trust_checks Policy checks

static trust_policy_state_t
_mdns_trust_checks_app_is_local_network_allowed(const LSBundleProxy *bundle_proxy)
{
	bool denyMulticast = false;
	bool userPrompted = false;
	if ([NEPathController class]) {
		NSArray<NEPathRule *> *aggregateRules = [NEPathController copyAggregatePathRules];
		for (NEPathRule *pathRule in aggregateRules) {
			if ([pathRule.matchSigningIdentifier isEqualToString:bundle_proxy.bundleIdentifier]) {
#ifdef NE_PATH_RULE_SUPPORTS_DENY_MULTICAST
				denyMulticast = (pathRule.denyMulticast != NO);
#endif // NE_PATH_RULE_SUPPORTS_DENY_MULTICAST
#ifdef NE_PATH_RULE_SUPPORTS_MULTICAST_PREFERENCE_SET
				userPrompted = (pathRule.multicastPreferenceSet != NO);
#else
				userPrompted = true;
#endif // NE_PATH_RULE_SUPPORTS_MULTICAST_PREFERENCE_SET
				break;
			}
		}
	}

	trust_policy_state_t state = denyMulticast ?
									(userPrompted ? trust_policy_state_denied : trust_policy_state_pending) :
									trust_policy_state_granted;
	return state;
}

static void
_mdns_trust_checks_policy_check(const mdns_trust_check_t me, const LSBundleProxy *bundle_proxy)
{
	me->policy_state = _mdns_trust_checks_app_is_local_network_allowed(bundle_proxy);
	if (me->policy_state != trust_policy_state_granted) {
		os_log_info(_mdns_trust_log(), "Local network access to %{public}s(%{private}s) policy \'%{public}s\' for (%{public}@).",
					_mdns_trust_checks_request_to_string(me->request), me->service_name ?: me->query_name,
					_mdns_trust_checks_policy_to_string(me->policy_state), bundle_proxy.localizedShortName);
	}
}

//======================================================================================================================
// MARK: - mdns_trust_checks Entitlement checks

static bool
_mdns_trust_checks_check_on_demand_entitlement(const mdns_trust_check_t me, const LSBundleProxy *bundle_proxy)
{
	// The presense of this entitlement disallows these functions
	xpc_object_t entitlement = xpc_copy_entitlement_for_token(ON_DEMAND_ENTITLEMENT, me->audit_token);
	if (entitlement) {
		os_log_info(_mdns_trust_log(), "Entitlement \'%{public}s\' disallows request for (%{public}@)", ON_DEMAND_ENTITLEMENT, bundle_proxy.localizedShortName);
		return false;
	} else {
		return true;
	}
}

static bool
_mdns_trust_checks_check_browse_all_entitlement(const mdns_trust_check_t me)
{
	xpc_object_t entitlement = xpc_copy_entitlement_for_token(BROWSE_ALL_SERVICES_PRIVATE_ENTITLEMENT, me->audit_token);
	if (entitlement) {
		bool allowed = false;
		if (xpc_get_type(entitlement) == XPC_TYPE_BOOL) {
			allowed = (xpc_bool_get_value(entitlement) != false);
		}
		return allowed;
	} else {
		return false;
	}
}

static bool
_mdns_trust_checks_app_info_has_bonjour_service(const LSBundleProxy *bundle_proxy, const NSArray *services, const char * const service)
{
	for (NSString * next in services) {
		if (_mdns_trust_checks_is_same_domain_name(service, next.UTF8String)) {
			return true;
		}
	}

	if (_mdns_trust_checks_is_same_domain_name(service, TRUST_BYPASS_GAME_CENTER_SERVICE)) {
		return true;
	}

	os_log_error(_mdns_trust_log(), "App Info.plist(NSBonjourServices) does not allow \'%{public}s\' for (%{public}@)", service, bundle_proxy.localizedShortName);
	return false;
}

static void
_mdns_trust_checks_entitlement_check(const mdns_trust_check_t me, const LSBundleProxy *bundle_proxy)
{
	me->entitlement_allowed = _mdns_trust_checks_check_on_demand_entitlement(me, bundle_proxy);
	require_quiet(me->entitlement_allowed, exit);

	if (os_feature_enabled(mDNSResponder, bonjour_privacy)	&&
		_mdns_trust_checks_app_sdk_is_minimum_version(bundle_proxy)) {
		require_quiet(me->service_name, exit); // No service_name is allowed to skip entitlement checks
		NSArray *services = nil;
		me->entitlement_allowed = _mdns_trust_checks_check_browse_all_entitlement(me);
		if (me->entitlement_allowed) {
			me->flags |= mdns_trust_flags_entitlement;
		} else {
			//	Only check if previous is false
			services = [bundle_proxy objectForInfoDictionaryKey:@"NSBonjourServices" ofClass:[NSArray class]];
			me->entitlement_allowed = _mdns_trust_checks_app_info_has_bonjour_service(bundle_proxy, services, me->service_name);
		}
		_mdns_trust_post_analytic(me, bundle_proxy, services);
	}

exit:
	return;
}

//======================================================================================================================
// MARK: - mdns_trust_checks Internal checks

static bool
_mdns_trust_checks_should_check_trust(const mdns_trust_check_t me)
{
	bool should_check = true;

	if (me->request == trust_request_query) {
		should_check = (me->force_multicast || _mdns_trust_checks_should_check_query_type(me->query_name, me->request_type));
	} else if (me->request == trust_request_reg_service) {
		should_check = (_mdns_trust_checks_is_same_domain_name(me->service_name, TRUST_BYPASS_GAME_CENTER_SERVICE) == false);
	}

	return should_check;
}

static mdns_trust_status_t
_mdns_trust_checks_get_status(const mdns_trust_check_t me)
{
	mdns_trust_status_t status;

	if (me->entitlement_allowed) {
		if (me->policy_state == trust_policy_state_granted) {
			status = mdns_trust_status_granted;
		} else if (me->policy_state == trust_policy_state_pending) {
			status = mdns_trust_status_pending;
		} else {
			status = mdns_trust_status_denied;
		}
	} else {
		status = mdns_trust_status_no_entitlement;
	}
	return status;
}

static void
_mdns_trust_checks_perform_all_trust_checks(const mdns_trust_check_t me)
{
	LSBundleProxy *bundle_proxy = _mdns_trust_checks_bundle_proxy_for_app(me->audit_token);
	require_quiet(bundle_proxy, exit);

	bool check_more = (_mdns_trust_checks_app_is_apple_internal(bundle_proxy) == false);
	require_quiet(check_more, exit); 					// Internal always allowed

	_mdns_trust_checks_entitlement_check(me, bundle_proxy);
	check_more = (me->entitlement_allowed != false);
	require_quiet(check_more, exit);					// Continue if allowed by entitlement

	_mdns_trust_checks_policy_check(me, bundle_proxy);	//	Can interact with user so check policy last

exit:
	return;
}

//======================================================================================================================
// MARK: - mdns_trust_checks Public functions

static _Atomic bool g_is_initialized = false;

void
mdns_trust_checks_init(void)
{
	static dispatch_once_t s_once;
	dispatch_once(&s_once, ^{
		os_log_info(_mdns_trust_log(), "Initializing Launch Services -- PENDING");
		dispatch_queue_t queue = dispatch_queue_create("com.apple.dnssd.trust.init", DISPATCH_QUEUE_SERIAL_WITH_AUTORELEASE_POOL);
		dispatch_async(queue, ^{
			os_log_info(_mdns_trust_log(), "Initializing Launch Services -- START");
			if (__builtin_available(macOS 10.16, ios 14.0, watchos 7.0, tvos 14.0, *)) {
				// Issue a query to LaunchServices to ensure we only proceed after their database is built during migration
				(void)[[LSApplicationRecord alloc] initWithBundleIdentifier:@"com.apple.dummy.nonexistent" allowPlaceholder:NO error:nil];
			}
			atomic_store(&g_is_initialized, true);
			os_log_info(_mdns_trust_log(), "Initializing Launch Services -- COMPLETE");
		});
	});
}

void
mdns_trust_checks_local_network_access_policy_update(audit_token_t *audit_token, dispatch_queue_t queue,
	const char * _Nullable query, mdns_trust_flags_t flags, _mdns_trust_checks_update_handler_t handler)
{
#ifndef NE_HAS_SHOW_LOCAL_NETWORK_ALERT_FOR_APP_EXTENDED
	(void)query;
	(void)flags;
#endif
	@autoreleasepool {
		LSBundleProxy *bundle_proxy = _mdns_trust_checks_bundle_proxy_for_app(audit_token);
		__block trust_policy_state_t state = (bundle_proxy != nil) ? _mdns_trust_checks_app_is_local_network_allowed(bundle_proxy) : trust_policy_state_granted;
#ifdef NE_HAS_SHOW_LOCAL_NETWORK_ALERT_FOR_APP
		if ([NEConfigurationManager class] && state == trust_policy_state_pending) {
			os_log_info(_mdns_trust_log(), "Local network alert for (%{public}@) query(%{public}s).", bundle_proxy.localizedShortName, query ?: "local");
			NEConfigurationManager *sharedManager = [NEConfigurationManager sharedManagerForAllUsers];
			[sharedManager showLocalNetworkAlertForApp:bundle_proxy.bundleIdentifier
								   withCompletionQueue:queue
#ifdef NE_HAS_SHOW_LOCAL_NETWORK_ALERT_FOR_APP_EXTENDED
												 query:query ? [NSString stringWithUTF8String:query] : @"local"
										hasEntitlement:(flags & mdns_trust_flags_entitlement) ? YES : NO
#endif
											   handler:^(BOOL allowed) {
				state = allowed ? trust_policy_state_granted : trust_policy_state_denied;
				os_log_info(_mdns_trust_log(), "Local network alert policy status \'%{public}s\' for (%{public}@).", _mdns_trust_checks_policy_to_string(state), bundle_proxy.localizedShortName);
				handler(state);
			}];
		} else
#endif // HAVE_SHOW_LOCAL_NETWORK_ALERT_FOR_APP
		{
			if (bundle_proxy == nil) {
				os_log_info(_mdns_trust_log(), "No bundle found for local network access policy update for PID(%d).", audit_token_to_pid(*audit_token));
			}
			dispatch_async(queue, ^{
				handler(state);
			});
		}
	}
}

mdns_trust_status_t
mdns_trust_checks_check(audit_token_t *audit_token, trust_request_t request, const char * _Nullable query_name,
	const char * _Nullable service_name, uint16_t qtype, bool force_multicast, mdns_trust_flags_t * _Nullable flags)
{
	struct mdns_trust_check_s ref;
	ref.audit_token			= audit_token;
	ref.request 			= request;
	ref.query_name			= query_name;
	ref.service_name		= service_name;
	ref.request_type		= qtype;
	ref.flags				= mdns_trust_flags_none;
	ref.entitlement_allowed = true;							// Default allow
	ref.force_multicast		= force_multicast;
	ref.policy_state 		= trust_policy_state_granted;	// Default granted

	require_quiet(atomic_load(&g_is_initialized), exit);

	@autoreleasepool {
		bool check_more = (_mdns_trust_checks_should_check_trust(&ref) != false);
		require_quiet(check_more, exit);

		_mdns_trust_checks_perform_all_trust_checks(&ref);
	}

exit:
	if (flags != nil) {
		*flags = ref.flags;
	}
	return _mdns_trust_checks_get_status(&ref);
}
