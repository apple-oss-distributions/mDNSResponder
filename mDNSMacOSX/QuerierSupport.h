/*
 * Copyright (c) 2019-2024 Apple Inc. All rights reserved.
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
#include "mrcs_server.h"
#include <mdns/private.h>

// Threshold value for problematic QTYPE workaround.
extern int PQWorkaroundThreshold;

extern mdns_dns_service_manager_t Querier_GetDNSServiceManager(void);
extern void Querier_SetDNSServiceForQuestion(DNSQuestion *q);
extern void Querier_ApplyDNSConfig(const dns_config_t *config);
extern void Querier_HandleUnicastQuestion(DNSQuestion *q);
extern void Querier_ProcessDNSServiceChanges(mDNSBool updatePushQuestionServiceOnly);
extern void Querier_ProcessDNSServiceChangesAsync(mDNSBool updatePushQuestionServiceOnly);
extern void Querier_RegisterPathResolver(const uuid_t resolverUUID);
extern mdns_dns_service_id_t Querier_RegisterCustomDNSService(xpc_object_t resolverConfigDict);
extern mdns_dns_service_id_t Querier_RegisterCustomDNSServiceWithPListData(const uint8_t *dataPtr, size_t dataLen);
extern void Querier_DeregisterCustomDNSService(mdns_dns_service_id_t ident);
extern mdns_dns_service_id_t Querier_RegisterNativeDNSService(mdns_dns_service_definition_t dns_service_definition);
extern void Querier_DeregisterNativeDNSService(mdns_dns_service_id_t ident);
extern mdns_dns_service_id_t Querier_RegisterCustomPushDNSService(
	mdns_dns_push_service_definition_t dns_service_definition);
extern mdns_dns_service_id_t Querier_RegisterCustomPushDNSServiceWithConnectionErrorHandler(
	mdns_dns_push_service_definition_t push_service_definition, dispatch_queue_t connection_error_queue,
	mdns_event_handler_t connection_error_handler);
extern void Querier_DeregisterCustomPushDNSService(mdns_dns_service_id_t ident);

extern DNSQuestion *Querier_GetDNSQuestion(mdns_querier_t querier, mDNSBool *outIsNew);
extern mDNSBool Client_ResourceRecordIsAnswer(const ResourceRecord *rr, mdns_client_t client);
extern mDNSBool Client_SameNameCacheRecordIsAnswer(const CacheRecord *cr, mdns_client_t client);
extern void Querier_HandleStoppedDNSQuestion(DNSQuestion *q);
extern void Querier_RegisterDoHURI(const char *doh_uri, const char *domain);
extern mdns_client_t Querier_HandlePreCNAMERestart(DNSQuestion *q);
extern void Querier_HandlePostCNAMERestart(DNSQuestion *q, mdns_client_t client);
extern void Querier_HandleSleep(void);
extern void Querier_HandleWake(void);
extern mDNSBool Querier_QuestionBelongsToSelf(const DNSQuestion *q);

#if MDNSRESPONDER_SUPPORTS(APPLE, TERMINUS_ASSISTED_UNICAST_DISCOVERY)
extern mDNSBool Querier_IsMDNSAlternativeServiceAvailableForQuestion(const DNSQuestion *q);
#endif
extern mDNSBool Querier_IsCustomPushServiceAvailableForQuestion(const DNSQuestion *q);

#if MDNSRESPONDER_SUPPORTS(APPLE, DISCOVERY_PROXY_CLIENT)
extern DNSQuestion DPCBrowse;
extern mDNSBool DPCFeatureEnabled(void);
extern void DPCHandleNewQuestion(DNSQuestion *q);
extern mDNSBool DPCSuppressMDNSQuery(const DNSQuestion *q, mDNSInterfaceID interface);
extern mDNSBool DPCHaveSubscriberForRecord(mDNSInterfaceID interface, const domainname *name, mDNSu16 type, mDNSu16 class_);
extern void DPCHandleStoppedDNSQuestion(DNSQuestion *q);
extern void DPCBrowseHandler(mDNS *m, DNSQuestion *q, const ResourceRecord *answer, QC_result AddRecord);
extern void DPCHandleInterfaceDown(mDNSInterfaceID interface);
#endif

extern const struct mrcs_server_dns_service_registration_handlers_s kMRCSServerDNSServiceRegistrationHandlers;

#endif  // __QUERIER_SUPPORT_H__
