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

#ifndef __MDNS_SET_H__
#define __MDNS_SET_H__

#include "mdns_base.h"
#include "mdns_object.h"

#include <MacTypes.h>

MDNS_DECL(set);

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

MDNS_RETURNS_RETAINED MDNS_WARN_RESULT _Nullable
mdns_set_t
mdns_set_create(void);

OSStatus
mdns_set_add(mdns_set_t set, uintptr_t subset_id, mdns_any_t any);

OSStatus
mdns_set_remove(mdns_set_t set, uintptr_t subset_id, mdns_any_t any);

size_t
mdns_set_get_count(mdns_set_t set, uintptr_t subset_id);

typedef bool (^mdns_set_applier_t)(mdns_object_t object);

void
mdns_set_iterate(mdns_set_t set, uintptr_t subset_id, mdns_set_applier_t applier);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_SET_H__
