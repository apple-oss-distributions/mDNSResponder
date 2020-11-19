//
//	dnssec_v2_trust_anchor.h
//	mDNSResponder
//
//	Copyright (c) 2020 Apple Inc. All rights reserved.
//

#ifndef DNSSEC_V2_TRUST_ANCHOR_H
#define DNSSEC_V2_TRUST_ANCHOR_H

#include <stdio.h>
#include "mDNSEmbeddedAPI.h"
#if MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#include "dnssec_v2_structs.h"

mDNSexport void
initialize_trust_anchors_t(trust_anchors_t * const _Nonnull anchor, const mDNSu8 *const _Nonnull zone_name);

mDNSexport void
uninitialize_trust_anchors_t(trust_anchors_t * const _Nonnull anchor);

mDNSexport void
print_trust_anchors_t(const trust_anchors_t * const _Nonnull anchor, mDNSu8 num_of_tabs);

mDNSexport mStatus
init_and_load_trust_anchors(void);

mDNSexport trust_anchors_t * _Nullable
get_trust_anchor_with_name(const mDNSu8 * _Nonnull const name);

mDNSexport void
uninit_trust_anchors(void);

mDNSexport mDNSBool
trust_anchor_can_be_reached(dnssec_context_t * const _Nonnull context);

mDNSexport mDNSBool
trust_anchor_contains_dnskey(const trust_anchors_t * const _Nonnull anchor);

mDNSexport mDNSBool
trust_anchor_contains_ds(const trust_anchors_t * const _Nonnull anchor);

#endif // MDNSRESPONDER_SUPPORTS(APPLE, DNSSECv2)
#endif // DNSSEC_V2_TRUST_ANCHOR_H
