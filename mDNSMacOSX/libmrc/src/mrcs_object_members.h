/*
 * Copyright (c) 2021-2024 Apple Inc. All rights reserved.
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

#ifndef MRCS_OBJECT_MEMBERS_H
#define MRCS_OBJECT_MEMBERS_H

#include <mdns/base.h>

#define MRCS_UNION_MEMBER(NAME)	struct mrcs_ ## NAME ## _s *	_mrcs_ ## NAME

#define MRCS_OBJECT_MEMBERS									\
	MRCS_UNION_MEMBER(object);								\
	MRCS_UNION_MEMBER(dns_proxy);							\
	MRCS_UNION_MEMBER(dns_proxy_manager);					\
	MRCS_UNION_MEMBER(dns_proxy_request);					\
	MRCS_UNION_MEMBER(dns_service_registration_request);	\
	MRCS_UNION_MEMBER(session);

#endif	// MRCS_OBJECT_MEMBERS_H
