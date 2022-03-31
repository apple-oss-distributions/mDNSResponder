/*
 * Copyright (c) 2020-2022 Apple Inc. All rights reserved.
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
 *
 * This file contains the function declarations for discover_resolver.c,
 * which will be called by mDNSCore code to set up the automatic browsing
 * domain resolver.
 */

#ifndef __RESOLVER_DISCOVER_H__
#define __RESOLVER_DISCOVER_H__

#include "mDNSFeatures.h" // for MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)
#include "mdns_strict.h"

#if MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)

//======================================================================================================================
// MARK: - Headers

#include "mDNSEmbeddedAPI.h"
#include <stdbool.h>
#include "nullability.h"

//======================================================================================================================
// MARK: - Functions

/*!
 *	@brief
 *		Start the local DNS resolver discovery for the domain specified, by using reference counting to add/retain the discovery process.
 *
 *	@param domain_to_discover
 *		The domain where the local DNS resolver should be discovered.
 *
 *	@param grab_mdns_lock
 *		The boolean value of whether to grab the mDNS_Lock when doing query-related operation.
 *
 *	@result
 *		True if the function succeeds, otherwise, false.
 *
 *	@discussion
 *		When <code>resolver_discovery_add</code> is called, the discovery is not necessarily started on behalf of the caller. The discovery may have been
 *		started earlier by other caller. In which case, the same discovery activity will be retained and reused for the current caller.
 */

bool
resolver_discovery_add(const domainname * NONNULL domain_to_discover, bool grab_mdns_lock);

/*!
 *	@brief
 *		Stop the local DNS resolver discovery for the domain specified, by using reference counting to remove/release the discovery process.
 *
 *	@param domain_to_discover
 *		The domain where the local DNS resolver should be discovered.
 *
 *	@param grab_mdns_lock
 *		The boolean value of whether to grab the mDNS_Lock when doing query-related operation.
 *
 *	@result
 *		True if the function succeeds, otherwise, false.
 *
 *	@discussion
 *		When <code>resolver_discovery_remove</code> is called, the discovery is not necessarily stopped on behalf of the caller. The discovery may be still used
 *		by other callers. In which case, the discovery will not be stopped, instead, it will be removed/released with reference counting. The resolver discovery will
 *		not be stopped until the last caller of <code>resolver_discovery_add</code> calls <code>resolver_discovery_remove</code>.
 */

bool
resolver_discovery_remove(const domainname * NONNULL domain_to_discover, bool grab_mdns_lock);

bool
dns_question_requires_resolver_discovery(const DNSQuestion * NONNULL q, const domainname * NULLABLE * NONNULL out_domain);

#endif // MDNSRESPONDER_SUPPORTS(COMMON, LOCAL_DNS_RESOLVER_DISCOVERY)

#endif /* __RESOLVER_DISCOVER_H__ */
