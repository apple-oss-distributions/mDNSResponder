/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef MDNS_DEBUG_SHARED_H
#define MDNS_DEBUG_SHARED_H

#include <mdns/general.h>

MDNS_CLOSED_OPTIONS(mDNSNetworkChangeEventFlags_t, uint32_t,
	mDNSNetworkChangeEventFlag_None				= 0,
	mDNSNetworkChangeEventFlag_LocalHostname	= (1U << 0),
	mDNSNetworkChangeEventFlag_ComputerName		= (1U << 1),
	mDNSNetworkChangeEventFlag_DNS				= (1U << 2),
	mDNSNetworkChangeEventFlag_DynamicDNS		= (1U << 3),
	mDNSNetworkChangeEventFlag_IPv4LL			= (1U << 4),
	mDNSNetworkChangeEventFlag_P2PLike			= (1U << 5),
);

#endif	// MDNS_DEBUG_SHARED_H
