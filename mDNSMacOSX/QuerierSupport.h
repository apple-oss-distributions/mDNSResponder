/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

#ifndef __QUERIER_SUPPORT_H__
#define __QUERIER_SUPPORT_H__

#include "mDNSEmbeddedAPI.h"
#include "mdns_private.h"

// Threshold value for problematic QTYPE workaround.
extern int PQWorkaroundThreshold;

extern mdns_dns_service_manager_t Querier_GetDNSServiceManager(void);
extern void Querier_SetDNSServiceForQuestion(DNSQuestion *q);
extern void Querier_ApplyDNSConfig(const dns_config_t *config);
extern void Querier_HandleUnicastQuestion(DNSQuestion *q);
extern void Querier_ProcessDNSServiceChanges(void);
extern void Querier_RegisterPathResolver(const uuid_t resolverUUID);
extern mdns_dns_service_id_t Querier_RegisterCustomDNSService(xpc_object_t resolverConfigDict);
extern mdns_dns_service_id_t Querier_RegisterCustomDNSServiceWithPListData(const uint8_t *dataPtr, size_t dataLen);
extern void Querier_DeregisterCustomDNSService(mdns_dns_service_id_t ident);
extern DNSQuestion *Querier_GetDNSQuestion(mdns_querier_t querier);
extern mDNSBool Querier_ResourceRecordIsAnswer(const ResourceRecord *rr, mdns_querier_t querier);
extern mDNSBool Querier_SameNameCacheRecordIsAnswer(const CacheRecord *cr, mdns_querier_t querier);
extern void Querier_HandleStoppedDNSQuestion(DNSQuestion *q);
extern void Querier_RegisterDoHURI(const char *doh_uri, const char *domain);
extern void Querier_PrepareQuestionForCNAMERestart(DNSQuestion *q);
extern void Querier_PrepareQuestionForUnwindRestart(DNSQuestion *q);
extern void Querier_HandleSleep(void);
extern void Querier_HandleWake(void);

#endif  // __QUERIER_SUPPORT_H__
