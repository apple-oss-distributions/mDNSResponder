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

#ifndef __MDNS_INTERNAL_H__
#define __MDNS_INTERNAL_H__

#include "mdns_base.h"

#define MDNS_ANY_TYPE_INTERNAL_MEMBERS		\
	MDNS_UNION_MEMBER(normal_resolver);		\
	MDNS_UNION_MEMBER(tcp_resolver);		\
	MDNS_UNION_MEMBER(tls_resolver);		\
	MDNS_UNION_MEMBER(https_resolver);		\
	MDNS_UNION_MEMBER(server);				\
	MDNS_UNION_MEMBER(session);				\
	MDNS_UNION_MEMBER(connection_session);	\
	MDNS_UNION_MEMBER(udp_socket_session);	\
	MDNS_UNION_MEMBER(url_session);

#endif	// __MDNS_INTERNAL_H__

