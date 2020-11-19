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

#ifndef __MDNS_POWERLOG_H__
#define __MDNS_POWERLOG_H__

#include "mdns_base.h"

#include <stdint.h>
#include <sys/types.h>

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

void
mdns_powerlog_awdl_browse_start(const uint8_t *record_name, int record_type, pid_t client_pid);

void
mdns_powerlog_awdl_browse_stop(const uint8_t *record_name, int record_type, pid_t client_pid);

void
mdns_powerlog_awdl_advertise_start(const uint8_t *record_name, int record_type, pid_t client_pid);

void
mdns_powerlog_awdl_advertise_stop(const uint8_t *record_name, int record_type, pid_t client_pid);

void
mdns_powerlog_awdl_resolve_start(const uint8_t *record_name, int record_type, pid_t client_pid);

void
mdns_powerlog_awdl_resolve_stop(const uint8_t *record_name, int record_type, pid_t client_pid);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif	// __MDNS_POWERLOG_H__
