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

#ifndef MRC_OBJECT_MEMBERS_H
#define MRC_OBJECT_MEMBERS_H

#if !defined(MRC_ALLOW_HEADER_INCLUDES) || !MRC_ALLOW_HEADER_INCLUDES
	#error "Please include <mrc/private.h> instead of this file directly."
#endif

#define MRC_UNION_MEMBER(NAME)	struct mrc_ ## NAME ## _s *	_mrc_ ## NAME

#define MRC_OBJECT_MEMBERS_EXTERNAL				\
	MRC_UNION_MEMBER(object);					\
	MRC_UNION_MEMBER(dns_proxy);				\
	MRC_UNION_MEMBER(dns_proxy_parameters);		\
	MRC_UNION_MEMBER(dns_proxy_state_inquiry);	\
	MRC_UNION_MEMBER(dns_service_registration);	\
	MRC_UNION_MEMBER(enabler);

#if defined(MDNS_LIBMRC_BUILD) && MDNS_LIBMRC_BUILD
	#include "mrc_object_members_internal.h"
#else
	#define MRC_OBJECT_MEMBERS_INTERNAL
#endif

#define MRC_OBJECT_MEMBERS		\
	MRC_OBJECT_MEMBERS_EXTERNAL	\
	MRC_OBJECT_MEMBERS_INTERNAL

#endif	// MRC_OBJECT_MEMBERS_H
