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

#include <mrc/object.h>

#include "mdns_obj.h"
#include "mrc_object_internal.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Object Public Methods

mdns_kind_t
mrc_get_kind(const mrc_object_t me)
{
	return mdns_obj_get_kind(me);
}

//======================================================================================================================

void
mrc_retain(const mrc_object_t me)
{
	mdns_obj_retain(me);
}

//======================================================================================================================

void
mrc_release(const mrc_object_t me)
{
	mdns_obj_release(me);
}
