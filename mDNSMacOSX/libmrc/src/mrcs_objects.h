/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef MRCS_OBJECTS_H
#define MRCS_OBJECTS_H

#include "mdns_objects.h"

#define MRCS_OBJECT_SUBKIND_DEFINE_ABSTRACT(NAME)	MDNS_OBJ_SUBKIND_DEFINE_ABSTRACT(mrcs_ ## NAME)
#define MRCS_OBJECT_SUBKIND_DEFINE(NAME)			MDNS_OBJ_SUBKIND_DEFINE(mrcs_ ## NAME)
#define MRCS_OBJECT_SUBKIND_DEFINE_FULL(NAME)		MDNS_OBJ_SUBKIND_DEFINE_FULL(mrcs_ ## NAME)

#define MRCS_BASE_CHECK(NAME, SUPER)	MDNS_OBJ_BASE_CHECK(mrcs_ ## NAME, mrcs_ ## SUPER)

#define MRCS_CLASS(NAME)		MDNS_OBJ_CLASS(mrcs_ ## NAME)
#define MRCS_CLASS_DECL(NAME)	MDNS_OBJ_CLASS_DECL(mrcs_ ## NAME)

#endif	// MRCS_OBJECTS_H
