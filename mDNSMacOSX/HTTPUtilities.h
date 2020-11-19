/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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
 */

#ifndef __HTTPUtilities_h
#define __HTTPUtilities_h

#include <dispatch/dispatch.h>
#include <nw/private.h>

CFStringRef
create_base64_string(dispatch_data_t message);

void
http_set_resolver_queue(dispatch_queue_t queue);

typedef void (^http_task_dns_query_response_handler_t)(dispatch_data_t data, CFErrorRef error);

void *
http_task_create_dns_query(nw_endpoint_t endpoint,
						   const char *url_string,
						   dispatch_data_t message,
                           uint16_t query_type,
						   bool use_post,
						   http_task_dns_query_response_handler_t response_handler);

void *
http_task_create_pvd_query(dispatch_queue_t queue,
						   const char *host,
						   const char *path,
						   void (^response_handler)(xpc_object_t json_object));

void
http_task_start(void *task);

void
http_task_cancel(void *task);

#endif // __HTTPUtilities_h
