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

#ifndef __DNSSD_PRIVATE_H__
#define __DNSSD_PRIVATE_H__

#include <dispatch/dispatch.h>
#include <xpc/xpc.h>
#include <dns_sd.h>
#include <os/object.h>

#if OS_OBJECT_USE_OBJC
	#define DNSSD_DECL(NAME)		OS_OBJECT_DECL_SUBCLASS(dnssd_ ## NAME, dnssd_object)
	#define DNSSD_RETURNS_RETAINED	OS_OBJECT_RETURNS_RETAINED

	OS_OBJECT_DECL(dnssd_object,);
#else
	#define DNSSD_DECL(NAME)		typedef struct dnssd_ ## NAME ## _s *	dnssd_ ## NAME ## _t
	#define DNSSD_RETURNS_RETAINED

	DNSSD_DECL(object);
#endif

#define DNSSD_ASSUME_NONNULL_BEGIN	OS_ASSUME_NONNULL_BEGIN
#define DNSSD_ASSUME_NONNULL_END	OS_ASSUME_NONNULL_END

DNSSD_DECL(getaddrinfo);
DNSSD_DECL(getaddrinfo_result);
DNSSD_DECL(cname_array);

DNSSD_ASSUME_NONNULL_BEGIN

#if OS_OBJECT_USE_OBJC
	typedef dnssd_object_t	dnssd_any_t;
#else
	#if !defined(__cplusplus)
		typedef union {
			dnssd_object_t				object;
			dnssd_getaddrinfo_t			gai;
			dnssd_getaddrinfo_result_t	gai_result;
			dnssd_cname_array_t			cname_array;
		} dnssd_any_t __attribute__((__transparent_union__));
	#else
		typedef void *	dnssd_any_t;
	#endif
#endif

#define DNSSD_MALLOC	__attribute__((__malloc__))
#define DNSSD_AVAILABLE	SPI_AVAILABLE(macos(10.15), ios(13.0), watchos(6.0), tvos(13.0))

#if __has_attribute(noescape)
#define DNSSD_NOESCAPE __attribute__((__noescape__))
#else // noescape
#define DNSSD_NOESCAPE
#endif // noescape

__BEGIN_DECLS

/*!
 *	@brief
 *		Increments the reference count of a dnssd object.
 *
 *	@param object
 *		The dnssd object.
 *
 *	@discussion
 *		Calls to dnssd_retain() must be balanced with calls to dnssd_release().
 */
DNSSD_AVAILABLE
void
dnssd_retain(dnssd_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#undef dnssd_retain
#define dnssd_retain(object)	[(object) retain]
#endif

/*!
 *	@brief
 *		Decrements the reference count of a dnssd object.
 *
 *	@param object
 *		The dnssd object.
 *
 *	@discussion
 *		Calls to dnssd_retain() must be balanced with calls to dnssd_release().
 */
DNSSD_AVAILABLE
void
dnssd_release(dnssd_any_t object);
#if OS_OBJECT_USE_OBJC_RETAIN_RELEASE
#undef dnssd_release
#define dnssd_release(object)	[(object) release]
#endif


/*!
 *	@brief
 *		Provides a textual description of a dnssd object.
 *
 *	@param object
 *		The dnssd object.
 *
 *	@result
 *		Textual description of the object as a C string.
 *
 *	@discussion
 *		The string returned by this function must be released with <code>free(3)</code>.
 */
DNSSD_AVAILABLE
DNSSD_MALLOC char * _Nullable
dnssd_copy_description(dnssd_any_t object);

/*!
 *	@brief
 *		Creates a getaddrinfo object.
 *
 *	@result
 *		A new getaddrinfo object.
 *
 *	@discussion
 *		A getaddrinfo object resolves a hostname to its IPv4 and IPv6 addresses.
 */
DNSSD_AVAILABLE
DNSSD_RETURNS_RETAINED dnssd_getaddrinfo_t _Nullable
dnssd_getaddrinfo_create(void);

/*!
 *	@brief
 *		Specifies the queue on which to invoke the getaddrinfo object's result and event blocks.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param queue
 *		A serial queue.
 *
 *	@discussion
 *		This call must be made before activating the getaddrinfo object.
 *
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_queue(dnssd_getaddrinfo_t gai, dispatch_queue_t queue);

/*!
 *	@brief
 *		Specifies the DNSServiceFlags to use for the getaddrinfo operation.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param flags
 *		Flags.
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_flags(dnssd_getaddrinfo_t gai, DNSServiceFlags flags);

#define DNSSD_GETADDRINFO_SUPPORTS_ACCOUNT_ID 1

/*!
 *	@brief
 *		Specifies the account id to use for the getaddrinfo operation.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param account_id
 *		The account id.
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
void
dnssd_getaddrinfo_set_account_id(dnssd_getaddrinfo_t gai, const char * account_id);

/*!
 *	@brief
 *		Specifies the hostname to resolve.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param hostname
 *		Hostname as a fully-qualified domain name.
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_hostname(dnssd_getaddrinfo_t gai, const char *hostname);

#define DNSSD_GETADDRINFO_SUPPORTS_SERVICE_SCHEME 1

/*!
 *	@brief
 *		Specifies the optional service scheme to resolve.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param service_scheme
 *		Service scheme as a string, such as "_443._https".
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
void
dnssd_getaddrinfo_set_service_scheme(dnssd_getaddrinfo_t gai, const char * _Nullable service_scheme);

/*!
 *	@brief
 *		Specifies the index of the interface via which to resolve the hostname.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param interface_index
 *		Interface index.
 *
 *	@discussion
 *		If <code>kDNSServiceInterfaceIndexAny</code> is used as the interface index, then special behavior applies. If
 *		the hostname is in the "local." domain, then an attempt will be made to resolve the hostname via all active
 *		mDNS-capable interfaces. If the hostname is in any other domain, then the hostname will be resolved via the
 *		primary interface.
 *
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_interface_index(dnssd_getaddrinfo_t gai, uint32_t interface_index);

/*!
 *	@brief
 *		Specifies the types of addresses to which to resolve the hostname.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param protocols
 *		Protocols.
 *
 *	@discussion
 *		Set <code>protocols</code> to <code>kDNSServiceProtocol_IPv4</code> to resolve the hostname to IPv4 addresses.
 *
 *		Set <code>protocols</code> to <code>kDNSServiceProtocol_IPv6</code> to resolve the hostname to IPv6 addresses.
 *
 *		Set <code>protocols</code> to <code>kDNSServiceProtocol_IPv4 | kDNSServiceProtocol_IPv6</code> to resolve the
 *		hostname to both IPv4 and IPv6 addresses.
 *
 *		Set <code>protocols</code> to 0 to limit resolution to addresses of protocols of which the host has routable
 *		addresses. That is, an attempt will be made to resolve the hostname to IPv4 addresses if and only if the host
 *		has a routable IPv4 address. Likewise, an attempt will be made to resolve the hostname to IPv6 addresses if and
 *		only if the host has a routable IPv6 address.
 *
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_protocols(dnssd_getaddrinfo_t gai, DNSServiceProtocol protocols);

/*!
 *	@brief
 *		Sets the process ID (PID) of the process on whose behalf the getaddrinfo operation is being performed.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param pid
 *		PID of the process being represented.
 *
 *	@discussion
 *		If a delegate PID is set, then the calling process must have the proper entitlement in order for the
 *		getaddrinfo operation to not fail with a kDNSServiceErr_NotAuth error.
 *
 *		This function is an alternative to <code>dnssd_getaddrinfo_set_delegate_uuid()</code>.
 *		This function is an alternative to <code>dnssd_getaddrinfo_set_delegate_audit_token()</code>.
 *
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_delegate_pid(dnssd_getaddrinfo_t gai, pid_t pid);

/*!
 *	@brief
 *		Sets the UUID of the process on whose behalf the getaddrinfo operation is being performed.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param uuid
 *		UUID of the process being represented.
 *
 *	@discussion
 *		If a delegate UUID is set, then the calling process must have the proper entitlement in order for the
 *		getaddrinfo operation to not fail with the <code>kDNSServiceErr_NotAuth</code> error.
 *
 *		This function is an alternative to <code>dnssd_getaddrinfo_set_delegate_pid()</code>.
 *		This function is an alternative to <code>dnssd_getaddrinfo_set_delegate_audit_token()</code>.
 *
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_delegate_uuid(dnssd_getaddrinfo_t gai, uuid_t _Nonnull uuid);

#define DNSSD_GETADDRINFO_SUPPORTS_DELEGATE_AUDIT_TOKEN 1

/*!
 *	@brief
 *		Sets the audit token of the process on whose behalf the getaddrinfo operation is being performed.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param audit_token
 *		audit token of the process being represented.
 *
 *	@discussion
 *		If a delegate audit token is set, then the calling process must have the proper entitlement in order for the
 *		getaddrinfo operation to not fail with the <code>kDNSServiceErr_NotAuth</code> error.
 *
 *		This function is an alternative to <code>dnssd_getaddrinfo_set_delegate_pid()</code>.
 *		This function is an alternative to <code>dnssd_getaddrinfo_set_delegate_uuid()</code>.
 *
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
void
dnssd_getaddrinfo_set_delegate_audit_token(dnssd_getaddrinfo_t gai, audit_token_t audit_token);

/*!
 *	@brief
 *		Specifies whether or not getaddrinfo results (of types <code>dnssd_getaddrinfo_result_type_add</code> and
 *		<code>dnssd_getaddrinfo_result_type_expired</code>) should include authentication tags from the stub resolver.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param need
 *		Pass <code>true</code> if authenticated results are needed, otherwise, pass <code>false</code>.
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_need_authenticated_results(dnssd_getaddrinfo_t gai, bool need);

#define DNSSD_GETADDRINFO_SUPPORTS_ENCRYPTED_QUERIES 1

/*!
 *	@brief
 *		Specifies whether or not getaddrinfo queries must use encrypted transports to the next DNS server.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param need
 *		Pass <code>true</code> if encrypted queries are required, otherwise, pass <code>false</code>.
 *
 *	@param fallback_config
 *		If not NULL, specify a custom resolver configuration to use if no encrypted resolver configuation is otherwise
 *		available.
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_need_encrypted_query(dnssd_getaddrinfo_t gai, bool need, _Nullable xpc_object_t fallback_config);

/*!
 *	@brief
 *		Add a resolver UUID that represents a resolver configuration registered with the system that should
 *		be applied to this resolution. Multiple UUIDs can be set.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param uuid
 *		UUID of a resolver configuration registered with the system.
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has been activated or invalidated.

 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_add_resolver_uuid(dnssd_getaddrinfo_t gai, uuid_t _Nonnull uuid);

/*!
 *	@brief
 *		Activates a getaddrinfo object.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@discussion
 *		This function has no effect on a getaddrinfo object that has already been activated or has been invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_activate(dnssd_getaddrinfo_t gai);

/*!
 *	@brief
 *		Asynchronously invalidates a getaddrinfo object.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@discussion
 *		As a result of calling this function, the getaddrinfo object's event handler will be invoked with a
 *		<code>dnssd_event_invalidated</code> event. After this, the object's event and result handlers will never be
 *		invoked again.
 *
 *		This function has no effect on a getaddrinfo object that has already been invalidated.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_invalidate(dnssd_getaddrinfo_t gai);

/*!
 *	@brief
 *		Handler for getaddrinfo results.
 *
 *	@param result_array
 *		C array of getaddrinfo results.
 *
 *	@param result_count
 *		Size of the array in terms of number of results.
 */
typedef void (^dnssd_getaddrinfo_result_handler_t)(dnssd_getaddrinfo_result_t _Nonnull * _Nonnull result_array,
												   size_t result_count);

/*!
 *	@brief
 *		Specifies a getaddrinfo object's result handler.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param handler
 *		Result handler.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_result_handler(dnssd_getaddrinfo_t gai, dnssd_getaddrinfo_result_handler_t _Nullable handler);

/*!
 *	@brief
 *		Events that can occur during the lifetime of a getaddrinfo object.
 */
typedef enum {
	/*! @const dnssd_event_error An error occurred. */
	dnssd_event_error		= 1,
	/*! @const dnssd_event_remove_all All results prior to this event are no longer valid. */
	dnssd_event_remove_all	= 2,
	/*! @const dnssd_event_invalidated The object has been invalidated. */
	dnssd_event_invalidated	= 3,
} dnssd_event_t;

/*!
 *	@brief
 *		Handler for getaddrinfo events.
 *
 *	@param event
 *		Event.
 *
 *	@param error
 *		The error associated with a <code>dnssd_event_error</code> event. Ignore for all other types of events.
 *
 *	@discussion
 *		After a <code>dnssd_event_invalidated</code> event, a getaddrinfo object's result and event handlers will never
 *		be invoked again.
 */
typedef void (^dnssd_event_handler_t)(dnssd_event_t event, DNSServiceErrorType error);

/*!
 *	@brief
 *		Sets a getaddrinfo object's event handler.
 *
 *	@param gai
 *		The getaddrinfo object.
 *
 *	@param handler
 *		Event handler.
 */
DNSSD_AVAILABLE
void
dnssd_getaddrinfo_set_event_handler(dnssd_getaddrinfo_t gai, dnssd_event_handler_t _Nullable handler);

/*!
 *	@brief
 *		Types of getaddrinfo results.
 */
typedef enum {
	/*! @const dnssd_getaddrinfo_result_type_add The contained hostname and address pair is valid. */
	dnssd_getaddrinfo_result_type_add				= 1,
	/*! @const dnssd_getaddrinfo_result_type_remove The contained hostname and address pair is no longer valid. */
	dnssd_getaddrinfo_result_type_remove			= 2,
	/*! @const dnssd_getaddrinfo_result_type_no_address The contained hostname has no address of a particular type. */
	dnssd_getaddrinfo_result_type_no_address		= 3,
	/*! @const dnssd_getaddrinfo_result_type_expired A hostname and address pair contained came from an expired cached record and may no longer be valid. */
	dnssd_getaddrinfo_result_type_expired			= 4,
	/*! @const dnssd_getaddrinfo_result_type_service_binding A hostname has associated service binding information. */
	dnssd_getaddrinfo_result_type_service_binding	= 5,
} dnssd_getaddrinfo_result_type_t;

/*!
 *	@brief
 *		Gets a getaddrinfo result's type.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		Result type.
 */
DNSSD_AVAILABLE
dnssd_getaddrinfo_result_type_t
dnssd_getaddrinfo_result_get_type(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's actual hostname.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		The getaddrinfo result's actual hostname.
 *
 *	@discussion
 *		The hostname returned by this function is the canonical name of the hostname that was requested. In other
 *		words, it's the canonical name of the hostname set with <code>dnssd_getaddrinfo_set_hostname()</code>.
 *
 *		The pointer returned by this function is valid until the getaddrinfo result is released.
 */
DNSSD_AVAILABLE
const char *
dnssd_getaddrinfo_result_get_actual_hostname(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's address.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		The getaddrinfo result's address as a sockaddr structure.
 *
 *	@discussion
 *		For getaddrinfo results of type <code>dnssd_getaddrinfo_result_type_no_address</code>, the sockaddr structure's
 *		sa_family member variable can be used to determine the type of address that the hostname lacks.
 */
DNSSD_AVAILABLE
const struct sockaddr *
dnssd_getaddrinfo_result_get_address(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's hostname.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		The getaddrinfo result's hostname.
 *
 *	@discussion
 *		The hostname returned by this function is the hostname whose resolution was requested. In other words, it's
 *		equal to the hostname set with <code>dnssd_getaddrinfo_set_hostname()</code>.
 *
 *		The pointer returned by this function is valid until the getaddrinfo result is released.
 */
DNSSD_AVAILABLE
const char *
dnssd_getaddrinfo_result_get_hostname(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets the interface index to which a getaddrinfo result pertains.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		For hostnames that were resolved via mDNS, the return value is the index of the interface via which the
 *		hostname was resolved. For hostnames that were resolved via DNS, the return value is 0.
 */
DNSSD_AVAILABLE
uint32_t
dnssd_getaddrinfo_result_get_interface_index(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's authentication tag.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@param out_length
 *		If non-NULL, gets set to the length of the authentication tag.
 *
 *	@result
 *		A pointer to the getaddrinfo result's authentication tag, if it has one. Otherwise, NULL.
 *
 *	@discussion
 *		The returned pointer, if non-NULL, is valid until the getaddrinfo result is released.
 */
DNSSD_AVAILABLE
const void * _Nullable
dnssd_getaddrinfo_result_get_authentication_tag(dnssd_getaddrinfo_result_t gai_result, size_t *_Nullable out_length);

/*!
 *	@brief
 *		Types of protocols used for getaddrinfo results.
 */
typedef enum {
	/*! @const dnssd_getaddrinfo_result_protocol_udp The answers were retrieved using UDP. */
	dnssd_getaddrinfo_result_protocol_udp		= 1,
	/*! @const dnssd_getaddrinfo_result_protocol_tcp The answers were retrieved using TCP. */
	dnssd_getaddrinfo_result_protocol_tcp		= 2,
	/*! @const dnssd_getaddrinfo_result_protocol_tls The answers were retrieved using DNS over TLS. */
	dnssd_getaddrinfo_result_protocol_tls		= 3,
	/*! @const dnssd_getaddrinfo_result_protocol_https The answers were retrieved using DNS over HTTPS. */
	dnssd_getaddrinfo_result_protocol_https		= 4,
} dnssd_getaddrinfo_result_protocol_t;

#define DNSSD_GETADDRINFO_HAS_GET_PROTOCOL 1

/*!
 *	@brief
 *		Gets a getaddrinfo result's protocol.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		Result protocol.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
dnssd_getaddrinfo_result_protocol_t
dnssd_getaddrinfo_result_get_protocol(dnssd_getaddrinfo_result_t gai_result);

#define DNSSD_GETADDRINFO_HAS_GET_PROVIDER_NAME 1

/*!
 *	@brief
 *		Gets a getaddrinfo result's DNS provider name, if applicable.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		DNS provider name.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
const char * _Nullable
dnssd_getaddrinfo_result_get_provider_name(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Checks if a getaddrinfo result has valid service binding information.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		Returns true if service binding information is valid.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
bool
dnssd_getaddrinfo_result_service_is_valid(dnssd_getaddrinfo_result_t gai_result);

#define DNSSD_GETADDRINFO_SERVICE_PRIORITY_ALIAS 0

/*!
 *	@brief
 *		Gets a getaddrinfo result's service binding priority.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		Service binding priority.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
uint16_t
dnssd_getaddrinfo_result_get_service_priority(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's service binding port.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		Service binding port.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
uint16_t
dnssd_getaddrinfo_result_get_service_port(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's service name.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		String containing the service binding name.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
const char * _Nullable
dnssd_getaddrinfo_result_get_service_name(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's associated DoH URI if present.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		String containing a DoH URI, if present.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
const char * _Nullable
dnssd_getaddrinfo_result_get_doh_uri(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets a getaddrinfo result's ECH (Encrypted Client Hello) configuration.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@param out_length
 *		If non-NULL, gets set to the length of the ECH config.
 *
 *	@result
 *		A pointer to the getaddrinfo result's ECH config, if it has one. Otherwise, NULL.
 *
 *	@discussion
 *		The returned pointer, if non-NULL, is valid until the getaddrinfo result is released.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
const void * _Nullable
dnssd_getaddrinfo_result_get_ech_config(dnssd_getaddrinfo_result_t gai_result, size_t *_Nullable out_length);

#ifdef __BLOCKS__

typedef bool (^dnssd_getaddrinfo_enumerate_alpn_values_block_t)(const char *alpn);

/*!
 *	@brief
 *		Enumerates a getaddrinfo result's service binding ALPN (application layer protocol negotiation) hints.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@param enumerator
 *		A block to invoke for each ALPN hint.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
void
dnssd_getaddrinfo_result_enumerate_alpn_values(dnssd_getaddrinfo_result_t gai_result,
											   DNSSD_NOESCAPE dnssd_getaddrinfo_enumerate_alpn_values_block_t enumerator);

typedef bool (^dnssd_getaddrinfo_enumerate_addresses_block_t)(const struct sockaddr *address);

/*!
 *	@brief
 *		Enumerates a getaddrinfo result's service address hints.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@param enumerator
 *		A block to invoke for each address hint.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
void
dnssd_getaddrinfo_result_enumerate_service_address_hints(dnssd_getaddrinfo_result_t gai_result,
														 DNSSD_NOESCAPE dnssd_getaddrinfo_enumerate_addresses_block_t enumerator);

#endif // __BLOCKS__


/*!
 *	@brief
 *		Gets the canonical names, if any, of a getaddrinfo result's hostname.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		An array containing zero or more canonical names.
 *
 *	@discussion
 *		Canonical names will not be provided for a getaddrinfo objects's results unless the
 *		<code>kDNSServiceFlagsReturnIntermediates</code> flag was set for the getaddrinfo object with
 *		<code>dnssd_getaddrinfo_set_flags()</code>.
 *
 *		The canonical names in the array are ordered in the following way. For non-empty arrays, the first
 *		canonical name in the array is the immediate canonical name of the getaddrinfo operation's hostname.
 *		For all canonical names beyond the first, a canonical name is the immediate canonical name of the
 *		canonical name that precedes it in the array.
 *
 *		For hostnames that have no canonical names, i.e., hostnames that aren't aliases, an empty array will be
 *		returned.
 *
 *		The array returned by this function is guaranteed to be valid during the lifetime of the getaddrinfo
 *		result. If the array is needed beyond the lifetime of the getaddrinfo result, then the array must be
 *		retained.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
dnssd_cname_array_t
dnssd_getaddrinfo_result_get_cnames(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Determines whether a getaddrinfo result was the product of cached DNS records, i.e., no additional DNS
 *		queries needed to be sent by mDNSResponder to provide the result.
 *
 *	@param gai_result
 *		The getaddrinfo result.
 *
 *	@result
 *		Returns <code>true</code> if the result came from cached DNS records, otherwise, returns
 *		<code>false</code>.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
bool
dnssd_getaddrinfo_result_is_from_cache(dnssd_getaddrinfo_result_t gai_result);

/*!
 *	@brief
 *		Gets the count of canonical names in a canonical name array.
 *
 *	@param cname_array
 *		The canonical name array.
 *
 *	@result
 *		The count of canonical names in the canonical name array.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
size_t
dnssd_cname_array_get_count(dnssd_cname_array_t cname_array);

/*!
 *	@brief
 *		Gets the canonical name at a specific index in a canonical name array.
 *
 *	@param cname_array
 *		The canonical name array.
 *
 *	@param index
 *		The zero-based index of the canonical name to get. The index must be no greater than the array's count,
 *		i.e., the value returned by <code>dnssd_cname_array_get_count()</code> for the array.
 *
 *	@result
 *		The canonical name at the specified index as a C string.
 *
 *	@discussion
 *		The pointer returned by this function is guaranteed to be valid until the array is released.
 */
SPI_AVAILABLE(macos(10.16), ios(14.0), watchos(7.0), tvos(14.0))
const char * _Nullable
dnssd_cname_array_get_cname(dnssd_cname_array_t cname_array, size_t index);

static inline const char *
dnssd_getaddrinfo_result_type_to_string(dnssd_getaddrinfo_result_type_t result)
{
	switch (result) {
		case dnssd_getaddrinfo_result_type_add:				return "Add";
		case dnssd_getaddrinfo_result_type_remove:			return "Remove";
		case dnssd_getaddrinfo_result_type_no_address:		return "NoAddress";
		case dnssd_getaddrinfo_result_type_expired:			return "Expired";
		case dnssd_getaddrinfo_result_type_service_binding:	return "ServiceBinding";
		default:											return "?";
	}
}

static inline const char *
dnssd_getaddrinfo_result_protocol_to_string(dnssd_getaddrinfo_result_protocol_t protocol)
{
	switch (protocol) {
		case dnssd_getaddrinfo_result_protocol_udp:		return "UDP";
		case dnssd_getaddrinfo_result_protocol_tcp:		return "TCP";
		case dnssd_getaddrinfo_result_protocol_tls:		return "TLS";
		case dnssd_getaddrinfo_result_protocol_https:	return "HTTPS";
		default:										return "?";
	}
}

static inline const char *
dnssd_event_to_string(dnssd_event_t event)
{
	switch (event) {
		case dnssd_event_remove_all:	return "RemoveAll";
		case dnssd_event_error:			return "Error";
		case dnssd_event_invalidated:	return "Invalidated";
		default:						return "?";
	}
}

__END_DECLS

DNSSD_ASSUME_NONNULL_END


#if OS_OBJECT_USE_OBJC && __has_feature(objc_arc)
	#define dnssd_retain_arc_safe(OBJ)	(OBJ)
	#define dnssd_release_arc_safe(OBJ)	do {} while (0)
#else
	#define dnssd_retain_arc_safe(OBJ)	dnssd_retain(OBJ)
	#define dnssd_release_arc_safe(OBJ)	dnssd_release(OBJ)
#endif

#define dnssd_getaddrinfo_forget(X)				\
	do {										\
		if (*(X)) {								\
			dnssd_getaddrinfo_invalidate(*(X));	\
			dnssd_release_arc_safe(*(X));		\
			*(X) = NULL;						\
		}										\
	} while (0)

#endif	// __DNSSD_PRIVATE_H__
