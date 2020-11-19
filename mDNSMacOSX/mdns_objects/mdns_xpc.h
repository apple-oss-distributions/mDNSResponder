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

#ifndef __MDNS_XPC_H__
#define __MDNS_XPC_H__

#include "mdns_base.h"

#include <MacTypes.h>
#include <xpc/xpc.h>

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

MDNS_RETURNS_RETAINED MDNS_WARN_RESULT
xpc_object_t _Nullable
mdns_xpc_create_dictionary_from_plist_data(const uint8_t *bytes, size_t length, OSStatus * _Nullable out_error);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_XPC_H__
