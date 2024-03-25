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

#ifndef MRC_OBJECTS_H
#define MRC_OBJECTS_H

#include "mdns_objects.h"

#define MRC_OBJECT_SUBKIND_DEFINE_ABSTRACT(NAME)			MDNS_OBJ_SUBKIND_DEFINE_ABSTRACT(mrc_ ## NAME)
#define MRC_OBJECT_SUBKIND_DEFINE(NAME)						MDNS_OBJ_SUBKIND_DEFINE(mrc_ ## NAME)
#define MRC_OBJECT_SUBKIND_DEFINE_FULL(NAME)				MDNS_OBJ_SUBKIND_DEFINE_FULL(mrc_ ## NAME)
#define MRC_OBJECT_SUBKIND_DEFINE_ABSTRACT_MINIMAL_WITHOUT_ALLOC(NAME) \
	MDNS_OBJ_SUBKIND_DEFINE_ABSTRACT_MINIMAL_WITHOUT_ALLOC(mrc_ ## NAME)
#define MRC_OBJECT_SUBKIND_DEFINE_ALLOC(NAME)				MDNS_OBJ_SUBKIND_DEFINE_ALLOC(mrc_ ## NAME)
#define MRC_OBJECT_SUBKIND_DEFINE_NEW_WITH_KIND(NAME, KIND)	MDNS_OBJ_SUBKIND_DEFINE_NEW_WITH_KIND(mrc_ ## NAME, KIND)

#define MRC_BASE_CHECK(NAME, SUPER)	MDNS_OBJ_BASE_CHECK(mrc_ ## NAME, mrc_ ## SUPER)

#define MRC_CLASS(NAME)			MDNS_OBJ_CLASS(mrc_ ## NAME)
#define MRC_CLASS_DECL(NAME)	MDNS_OBJ_CLASS_DECL(mrc_ ## NAME)

#endif	// MRC_OBJECTS_H
