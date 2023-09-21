/*
 * Copyright (c) 2022-2023 Apple Inc. All rights reserved.
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

#ifndef DNS_PUSH_DISCOVERY_H
#define DNS_PUSH_DISCOVERY_H

#include "mDNSFeatures.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

//======================================================================================================================
// MARK: - Headers

#include "mDNSEmbeddedAPI.h"

#include <stdbool.h>
#include <stdint.h>

#include "general.h"
#include "nullability.h"

//======================================================================================================================
// MARK: - Functions

MDNS_ASSUME_NONNULL_BEGIN

__BEGIN_DECLS

/*!
 *	@brief
 *		Start DNS push when a DNSQuestion that enables DNS push is started. It is responsible for setting up the required context and necessary tasks.
 *
 *	@param m
 *		The mDNStorage pointer which is used to do mDNSCore operation.
 *
 *	@param question
 *		The DNSQuestion that enables DNS push.
 *
 *	@result
 *		DNS_OBJ_ERROR_NO_ERROR if it succeeds, otherwise, the error code to indicate the error.
 */

dns_obj_error_t
dns_push_handle_question_start(mDNS *m, DNSQuestion *question);

/*!
 *	@brief
 *		Stop DNS push when a DNSQuestion that enables DNS push is stopped. It is responsible for stopping the corresponding tasks and deallocating
 *		the context.
 *
 *	@param m
 *		The mDNStorage pointer which is used to do mDNSCore operation.
 *
 *	@param question
 *		The DNSQuestion that enables DNS push.
 */
void
dns_push_handle_question_stop(mDNS *m, DNSQuestion *question);

__END_DECLS

MDNS_ASSUME_NONNULL_END

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNS_PUSH)

#endif // DNS_PUSH_DISCOVERY_H
