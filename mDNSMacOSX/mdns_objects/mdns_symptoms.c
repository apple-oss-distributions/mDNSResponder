/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
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

#include "mdns_symptoms.h"

#include <CoreUtils/CoreUtils.h>
#include <SymptomReporter/SymptomReporter.h>

#define MAX_DOMAIN_NAME 256

#define SYMPTOM_REPORTER_mDNSResponder_NUMERIC_ID	101
#define SYMPTOM_REPORTER_mDNSResponder_TEXT_ID		"com.apple.mDNSResponder"

#define SYMPTOM_DNS_NO_REPLIES			 			0x00065001
#define SYMPTOM_DNS_RESUMED_RESPONDING	 			0x00065002
#define SYMPTOM_DNS_ENCRYPTED_CONNECTION_FAILURE 	0x00065004

//======================================================================================================================
// MARK: - Soft Linking

SOFT_LINK_FRAMEWORK_EX(PrivateFrameworks, SymptomReporter);
SOFT_LINK_FUNCTION_EX(SymptomReporter, symptom_framework_init,
	symptom_framework_t,
	(symptom_ident_t id, const char *originator_string),
	(id, originator_string));
SOFT_LINK_FUNCTION_EX(SymptomReporter, symptom_new,
	symptom_t,
	(symptom_framework_t framework, symptom_ident_t id),
	(framework, id));
SOFT_LINK_FUNCTION_EX(SymptomReporter, symptom_set_additional_qualifier,
	int,
	(symptom_t symptom, uint32_t qualifier_type, size_t qualifier_len, const void *qualifier_data),
	(symptom, qualifier_type, qualifier_len, qualifier_data));
SOFT_LINK_FUNCTION_EX(SymptomReporter, symptom_send,
	int,
	(symptom_t symptom),
	(symptom));

//======================================================================================================================
// MARK: - Local Helper Prototypes

static symptom_framework_t
_mdns_symptoms_get_reporter(void);

static void
_mdns_symptoms_report_dns_server_symptom(symptom_ident_t id, const struct sockaddr *address);

static void
_mdns_symptoms_report_dns_host_symptom(symptom_ident_t id, const char *host);

//======================================================================================================================
// MARK - External Functions

void
mdns_symptoms_report_unresponsive_server(const struct sockaddr *address)
{
	_mdns_symptoms_report_dns_server_symptom(SYMPTOM_DNS_NO_REPLIES, address);
}

//======================================================================================================================

void
mdns_symptoms_report_encrypted_dns_connection_failure(const char *host)
{
	_mdns_symptoms_report_dns_host_symptom(SYMPTOM_DNS_ENCRYPTED_CONNECTION_FAILURE, host);
}

//======================================================================================================================

void
mdns_symptoms_report_responsive_server(const struct sockaddr *address)
{
	_mdns_symptoms_report_dns_server_symptom(SYMPTOM_DNS_RESUMED_RESPONDING, address);
}

//======================================================================================================================
// MARK - Local Helpers

static symptom_framework_t
_mdns_symptoms_get_reporter(void)
{
	static dispatch_once_t		s_once		= 0;
	static symptom_framework_t	s_reporter	= NULL;

	dispatch_once(&s_once,
	^{
		if (SOFT_LINK_HAS_FUNCTION(SymptomReporter, symptom_framework_init)) {
			s_reporter = soft_symptom_framework_init(SYMPTOM_REPORTER_mDNSResponder_NUMERIC_ID,
				SYMPTOM_REPORTER_mDNSResponder_TEXT_ID);
		}
	});
	return s_reporter;
}

//======================================================================================================================

static void
_mdns_symptoms_report_dns_server_symptom(symptom_ident_t id, const struct sockaddr *address)
{
	const symptom_framework_t reporter = _mdns_symptoms_get_reporter();
	require_quiet(reporter, exit);

	size_t address_len;
	if (address->sa_family == AF_INET) {
		address_len = sizeof(struct sockaddr_in);
	} else if (address->sa_family == AF_INET6) {
		address_len = sizeof(struct sockaddr_in6);
	} else {
		goto exit;
	}
	const symptom_t symptom = soft_symptom_new(reporter, id);
	soft_symptom_set_additional_qualifier(symptom, 1, address_len, address);
	soft_symptom_send(symptom);

exit:
	return;
}

//======================================================================================================================

static void
_mdns_symptoms_report_dns_host_symptom(symptom_ident_t id, const char *host)
{
	const symptom_framework_t reporter = _mdns_symptoms_get_reporter();
	require_quiet(reporter, exit);

	size_t hostname_len = strnlen(host, MAX_DOMAIN_NAME);
	const symptom_t symptom = soft_symptom_new(reporter, id);
	soft_symptom_set_additional_qualifier(symptom, 2, hostname_len, host);
	soft_symptom_send(symptom);

exit:
	return;
}
