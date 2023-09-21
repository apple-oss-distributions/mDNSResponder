/* cti-openthread.h
 *
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * External function signatures for CTI entry points used by OpenThread main loop.
 */

#ifndef __CTI_SERVER_H__
#define __CTI_SERVER_H__ 1

#ifdef __cplusplus
extern "C" {
#endif

#include "cti-server.h"
#include "cti-common.h"
#include <openthread/instance.h>
#include <openthread/openthread-system.h>


void otCtiServerInit(otInstance *NONNULL aInstance);
void otCtiServerUpdate(otInstance *NONNULL aInstance, otSysMainloopContext *NONNULL aMainloop);
void otCtiServerProcess(otInstance* aInstance, otSysMainloopContext *aMainloop);

#ifdef __cplusplus
}
#endif

#endif // __CTI_SERVER_H__
