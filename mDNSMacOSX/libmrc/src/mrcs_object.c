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

#include "mrcs_object.h"
#include "mrcs_object_internal.h"

#include "mdns_obj.h"
#include "mdns_strict.h"

//======================================================================================================================
// MARK: - Object Public Methods

mdns_kind_t
mrcs_get_kind(const mrcs_object_t me)
{
	return mdns_obj_get_kind(me);
}

//======================================================================================================================

void
mrcs_retain(const mrcs_object_t me)
{
	mdns_obj_retain(me);
}

//======================================================================================================================

void
mrcs_release(const mrcs_object_t me)
{
	mdns_obj_release(me);
}

//======================================================================================================================

char *
mrcs_copy_description(const mrcs_object_t me)
{
	return mdns_obj_copy_description(me, false, false);
}
