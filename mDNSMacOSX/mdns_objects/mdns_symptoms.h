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

#ifndef __MDNS_SYMPTOMS__
#define __MDNS_SYMPTOMS__

#include "mdns_base.h"

#include <MacTypes.h>
#include <mach/mach.h>	// audit_token_t
#include <sys/socket.h>

// Activity domains and labels for metrics collection.
// These are defined in "activity_registry.h" from libnetcore.
#define kDNSActivityDomain 33
#define kDNSActivityLabelUnicastAQuery 1
#define kDNSActivityLabelUnicastAAAAQuery 2
#define kDNSActivityLabelProvisioningRequest 3

MDNS_ASSUME_NONNULL_BEGIN

void
mdns_symptoms_report_unresponsive_server(const struct sockaddr *address);

void
mdns_symptoms_report_responsive_server(const struct sockaddr *address);

void
mdns_symptoms_report_encrypted_dns_connection_failure(const char *host);

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_SYMPTOMS__
