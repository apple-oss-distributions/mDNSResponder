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

#ifndef MRCS_CF_SUPPORT_H
#define MRCS_CF_SUPPORT_H

#include "mrcs_object.h"

#include <mdns/base.h>
#include <CoreFoundation/CoreFoundation.h>

/*!
 *	@brief
 *		CFArray callbacks for mrcs objects.
 */
extern const CFArrayCallBacks mrcs_cfarray_callbacks;

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		The type of block that handles any kind of mrcs_object during enumeration.
 *
 *	@param object
 *		The object.
 *
 *	@result
 *		True if enumeration should continue onto the next object, if any. False if enumeration should end.
 */
typedef bool
(^mrcs_any_applier_t)(mrcs_any_t object);

/*!
 *	@brief
 *		Enumerates the mrcs_objects in a CFArray in sequential order starting with the object at index 0.
 *
 *	@param array
 *		The array.
 *
 *	@param applier
 *		Block to synchronously invoke once for each object in the array until either no objects remain or the
 *		applier returns false. Note that if the array is empty, then the applier will not be invoked.
 *
 *	@result
 *		True if the applier never returned false during enumeration. Otherwise, false.
 *
 *	@discussion
 *		This function should only be used on a CFArray that can only contain mrcs_objects. The mrcs_objects can
 *		be of any derived kind.
 */
bool
mrcs_cfarray_enumerate(CFArrayRef array, mrcs_any_applier_t applier);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// MDNS_CF_SUPPORT_H
