/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#include "mdns_powerlog.h"
#include "mdns_helpers.h"

#include "DNSMessage.h"

#include <CoreUtils/CoreUtils.h>
#include <libproc.h>
#include <os/log.h>
#include <PowerLog/PowerLog.h>
#include <SoftLinking/WeakLinking.h>
#include <sys/proc_info.h>

//======================================================================================================================
// MARK: - Weak Linking

WEAK_LINK_FORCE_IMPORT(PLLogRegisteredEvent); // The PowerLog framework isn't present in the BaseSystem

//======================================================================================================================
// MARK: - PowerLog Event Names

#define MDNS_POWERLOG_EVENT_AWDL_BROWSE_START		CFSTR("startAWDLBrowse")
#define MDNS_POWERLOG_EVENT_AWDL_BROWSE_STOP		CFSTR("stopAWDLBrowse")
#define MDNS_POWERLOG_EVENT_AWDL_ADVERTISE_START	CFSTR("startAWDLAdvertise")
#define MDNS_POWERLOG_EVENT_AWDL_ADVERTISE_STOP		CFSTR("stopAWDLAdvertise")
#define MDNS_POWERLOG_EVENT_AWDL_RESOLVE_START		CFSTR("startAWDLResolve")
#define MDNS_POWERLOG_EVENT_AWDL_RESOLVE_STOP		CFSTR("stopAWDLResolve")

//======================================================================================================================
// MARK: - PowerLog Event Dictionary Keys

#define MDNS_POWERLOG_EVENT_KEY_SERVICE_TYPE	CFSTR("service")	// String: Service name w/protocol, e.g., _ssh._tcp.
#define MDNS_POWERLOG_EVENT_KEY_RECORD_TYPE		CFSTR("recordType")	// String: Record type, e.g., PTR, SRV, A.
#define MDNS_POWERLOG_EVENT_KEY_CLIENT_PID		CFSTR("clientPID")	// Number: Client's PID.
#define MDNS_POWERLOG_EVENT_KEY_CLIENT_NAME		CFSTR("clientName")	// String: Client's process name.

//======================================================================================================================
// MARK: - Helper Prototypes

static void
_mdns_powerlog_bonjour_event(CFStringRef event_name, const uint8_t *record_name, int record_type, pid_t client_pid);

//======================================================================================================================
// MARK: - Debug Logging

// The purpose of this os_log category is to log debug messages about logging to PowerLog.
// It has nothing to do with actually logging to PowerLog.
MDNS_LOG_CATEGORY_DEFINE(powerlog, "powerlog");

//======================================================================================================================
// MARK: - External Functions

void
mdns_powerlog_awdl_browse_start(const uint8_t * const record_name, const int record_type, const pid_t client_pid)
{
	_mdns_powerlog_bonjour_event(MDNS_POWERLOG_EVENT_AWDL_BROWSE_START, record_name, record_type, client_pid);
}

//======================================================================================================================

void
mdns_powerlog_awdl_browse_stop(const uint8_t * const record_name, const int record_type, const pid_t client_pid)
{
	_mdns_powerlog_bonjour_event(MDNS_POWERLOG_EVENT_AWDL_BROWSE_STOP, record_name, record_type, client_pid);
}

//======================================================================================================================

void
mdns_powerlog_awdl_advertise_start(const uint8_t * const record_name, const int record_type, const pid_t client_pid)
{
	_mdns_powerlog_bonjour_event(MDNS_POWERLOG_EVENT_AWDL_ADVERTISE_START, record_name, record_type, client_pid);
}

//======================================================================================================================

void
mdns_powerlog_awdl_advertise_stop(const uint8_t * const record_name, const int record_type, const pid_t client_pid)
{
	_mdns_powerlog_bonjour_event(MDNS_POWERLOG_EVENT_AWDL_ADVERTISE_STOP, record_name, record_type, client_pid);
}

//======================================================================================================================

void
mdns_powerlog_awdl_resolve_start(const uint8_t * const record_name, const int record_type, const pid_t client_pid)
{
	_mdns_powerlog_bonjour_event(MDNS_POWERLOG_EVENT_AWDL_RESOLVE_START, record_name, record_type, client_pid);
}

//======================================================================================================================

void
mdns_powerlog_awdl_resolve_stop(const uint8_t * const record_name, const int record_type, const pid_t client_pid)
{
	_mdns_powerlog_bonjour_event(MDNS_POWERLOG_EVENT_AWDL_RESOLVE_STOP, record_name, record_type, client_pid);
}

//======================================================================================================================
// MARK: - Helpers

static CFDictionaryRef
_mdns_powerlog_create_event_dictionary(const uint8_t *record_name, int record_type, pid_t client_pid);

static void
_mdns_powerlog_bonjour_event(const CFStringRef event_name, const uint8_t * const record_name, const int record_type,
	const pid_t client_pid)
{
	require_quiet(PLLogRegisteredEvent, exit);

	const PLClientID plc_id = PLClientIDMDNSResponder;
	const CFDictionaryRef event_dict = _mdns_powerlog_create_event_dictionary(record_name, record_type, client_pid);
	os_log_debug(_mdns_powerlog_log(),
		"Logging to powerlog -- id: %ld, event: %@, dictionary: %@", (long)plc_id, event_name, event_dict);
	PLLogRegisteredEvent(plc_id, event_name, event_dict, NULL);
	CFReleaseNullSafe(event_dict);

exit:
	return;
}

//======================================================================================================================

static void
_mdns_powerlog_event_dictionary_add_service_type(CFMutableDictionaryRef event_dict, const uint8_t *record_name);

static void
_mdns_powerlog_event_dictionary_add_record_type(CFMutableDictionaryRef event_dict, int record_type);

static void
_mdns_powerlog_event_dictionary_add_client_info(CFMutableDictionaryRef event_dict, pid_t client_pid);

static CFDictionaryRef
_mdns_powerlog_create_event_dictionary(const uint8_t * const record_name, const int record_type,
	const pid_t client_pid)
{
	CFMutableDictionaryRef event_dict = CFDictionaryCreateMutable(NULL, 0, &kCFTypeDictionaryKeyCallBacks,
		&kCFTypeDictionaryValueCallBacks);
	require_quiet(event_dict, exit);

	_mdns_powerlog_event_dictionary_add_service_type(event_dict, record_name);
	_mdns_powerlog_event_dictionary_add_record_type(event_dict, record_type);
	_mdns_powerlog_event_dictionary_add_client_info(event_dict, client_pid);

exit:
	return event_dict;
}

//======================================================================================================================

static char *
_mdns_get_service_name_string_from_domain_name(const uint8_t *name,
	char service_name_str[static kDNSServiceMaxDomainName]);

static void
_mdns_powerlog_event_dictionary_add_service_type(const CFMutableDictionaryRef event_dict,
	const uint8_t * const record_name)
{
	char service_type[kDNSServiceMaxDomainName];
	if (_mdns_get_service_name_string_from_domain_name(record_name, service_type)) {
		CFStringRef service_type_value = CFStringCreateWithCString(NULL, service_type, kCFStringEncodingUTF8);
		if (service_type_value) {
			CFDictionaryAddValue(event_dict, MDNS_POWERLOG_EVENT_KEY_SERVICE_TYPE, service_type_value);
			ForgetCF(&service_type_value);
		}
	}
}

#define MDNS_TCP_PROTOCOL_LABEL	((const uint8_t *)"\x4" "_tcp")
#define MDNS_UDP_PROTOCOL_LABEL	((const uint8_t *)"\x4" "_udp")
#define MDNS_LOCAL_DOMAIN_NAME	((const uint8_t *)"\x5" "local")

static char *
_mdns_get_service_name_string_from_domain_name(const uint8_t * const record_name,
	char service_name_str[static kDNSServiceMaxDomainName])
{
	size_t len;
	const uint8_t *l1 = NULL;
	const uint8_t *l2 = NULL;
	const uint8_t *l3 = NULL;
	// Get the three labels leading up to the root label.
	for (const uint8_t *ptr = record_name; (len = *ptr) != 0; ptr = &ptr[1 + len]) {
		l1 = l2;
		l2 = l3;
		l3 = ptr;
	}
	// Make sure the first label begins with '_', the second label is '_tcp' or '_udp', and the third label is 'local'.
	// See <https://tools.ietf.org/html/rfc6763#section-4.1.2>.
	char *result = NULL;
	if (l1 && (l1[1] == '_') &&
		l2 && (DomainLabelEqual(l2, MDNS_TCP_PROTOCOL_LABEL) || DomainLabelEqual(l2, MDNS_UDP_PROTOCOL_LABEL)) &&
		l3 && DomainNameEqual(l3, MDNS_LOCAL_DOMAIN_NAME)) {
		uint8_t service_name[kDomainNameLengthMax];
		uint8_t *ptr = service_name;
		const uint8_t * const limit = &service_name[countof(service_name)];

		// Append service name label.
		len = 1 + l1[0];
		require_quiet(((size_t)(limit - ptr)) >= len, exit);
		memcpy(ptr, l1, len);
		ptr += len;

		// Append protocol label, i.e., '_tcp' or '_udp'.
		len = 1 + l2[0];
		require_quiet(((size_t)(limit - ptr)) >= len, exit);
		memcpy(ptr, l2, len);
		ptr += len;

		// Append root label.
		require_quiet((limit - ptr) >= 1, exit);
		*ptr = 0;

		// Convert to string.
		const OSStatus err = DomainNameToString(service_name, limit, service_name_str, NULL);
		if (!err) {
			// Remove trailing root dot.
			len = strlen(service_name_str);
			if (len > 0) {
				char * const cptr = &service_name_str[len - 1];
				if (*cptr == '.') {
					*cptr = '\0';
				}
			}
			result = service_name_str;
		}
	}

exit:
	return result;
}

//======================================================================================================================

static void
_mdns_powerlog_event_dictionary_add_record_type(const CFMutableDictionaryRef event_dict, const int record_type)
{
	char qtype_str_buf[32];
	const char *qtype_str = DNSRecordTypeValueToString(record_type);
	if (!qtype_str) {
		snprintf(qtype_str_buf, sizeof(qtype_str_buf), "TYPE%d", record_type);
		qtype_str = qtype_str_buf;
	}
	CFStringRef qtype_str_value = CFStringCreateWithCString(NULL, qtype_str, kCFStringEncodingUTF8);
	if (qtype_str_value) {
		CFDictionaryAddValue(event_dict, MDNS_POWERLOG_EVENT_KEY_RECORD_TYPE, qtype_str_value);
		ForgetCF(&qtype_str_value);
	}
}

//======================================================================================================================

static char *
_mdns_pid_to_name(pid_t pid, char name[STATIC_PARAM MAXCOMLEN]);

static void
_mdns_powerlog_event_dictionary_add_client_info(const CFMutableDictionaryRef event_dict, const pid_t client_pid)
{
	const long long client_pid_ll = client_pid;
	CFNumberRef client_pid_value = CFNumberCreate(NULL, kCFNumberLongLongType, &client_pid_ll);
	if (client_pid_value != NULL) {
		CFDictionaryAddValue(event_dict, MDNS_POWERLOG_EVENT_KEY_CLIENT_PID, client_pid_value);
		ForgetCF(&client_pid_value);
	}
	char client_name[MAXCOMLEN];
	if (_mdns_pid_to_name(client_pid, client_name)) {
		CFStringRef client_name_value = CFStringCreateWithCString(NULL, client_name, kCFStringEncodingUTF8);
		if (client_name_value) {
			CFDictionaryAddValue(event_dict, MDNS_POWERLOG_EVENT_KEY_CLIENT_NAME, client_name_value);
			ForgetCF(&client_name_value);
		}
	}
}

static char *
_mdns_pid_to_name(const pid_t pid, char name[STATIC_PARAM MAXCOMLEN])
{
	if (pid != 0) {
		struct proc_bsdshortinfo info;
		const int n = proc_pidinfo(pid, PROC_PIDT_SHORTBSDINFO, 1, &info, PROC_PIDT_SHORTBSDINFO_SIZE);
		if (n == (int)sizeof(info)) {
			strlcpy(name, info.pbsi_comm, MAXCOMLEN);
			return name;
		}
	}
	return NULL;
}
