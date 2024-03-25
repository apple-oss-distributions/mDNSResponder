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

#ifndef MRCS_OBJECT_INTERNAL_H
#define MRCS_OBJECT_INTERNAL_H

#include <mdns/base.h>
#include <mdns/object.h>

#include "mdns_obj.h"

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Gets a reference to an object's kind.
 *
 *	@param object
 *		The object.
 *
 *	@discussion
 *		This function is meant only for object implementers.
 */
mdns_kind_t
mrcs_get_kind(mrcs_any_t object);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MRCS_OBJECT_INTERNAL_H
