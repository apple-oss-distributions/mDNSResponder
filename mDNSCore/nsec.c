/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2011 Apple Computer, Inc. All rights reserved.
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

// ***************************************************************************
// nsec.c: This file contains support functions to validate NSEC records for
// NODATA and NXDOMAIN error.
// ***************************************************************************

#include "mDNSEmbeddedAPI.h"
#include "DNSCommon.h"
#include "nsec.h"

// Implementation Notes
//
// NSEC records in DNSSEC are used for authenticated denial of existence i.e., if the response to a query
// results in NXDOMAIN or NODATA error, the response also contains NSEC records in the additional section
// to prove the non-existence of the original name. In most of the cases, NSEC records don't have any
// relationship to the original name queried i.e, if they are cached based on the name like other records,
// it can't be located to prove the non-existence of the original name. Hence, we create a negative cache
// record like we do for the NXDOMAIN/NODATA error and then cache the NSEC records as part of that. Sometimes,
// NSEC records are also used for wildcard expanded answer in which case they are cached with the cache record
// that is created for the original name. NSEC records are freed when the parent cache (the record that they
// are attached to is expired).
//
// NSEC records also can be queried like any other record and hence can exist independent of the negative
// cache record. It exists as part of negative cache record only when we get a NXDOMAIN/NODATA error with
// NSEC records. When a query results in NXDOMAIN/NODATA error and needs to be validated, the NSEC
// records (and its RRSIGS) are cached as part of the negative cache record. The NSEC records that
// exist separately from the negative cache record should not be used to answer ValidationRequired/
// ValidatingResponse questions as it may not be sufficient to prove the non-existence of the name.
// The exception is when the NSEC record is looked up explicitly. See DNSSECRecordAnswersQuestion
// for more details.
//

mDNSlocal CacheRecord *NSECParentForQuestion(mDNS *const m, DNSQuestion *q)
{
    CacheGroup *cg;
    CacheRecord *cr;
    mDNSu32 slot;
    mDNSu32 namehash;

    slot = HashSlot(&q->qname);
    namehash = DomainNameHashValue(&q->qname);
    cg = CacheGroupForName(m, slot, namehash, &q->qname);
    if (!cg)
    {
        LogDNSSEC("NSECParentForQuestion: Cannot find cg for %##s (%s)", q->qname.c, DNSTypeName(q->qtype));
        return mDNSNULL;
    }
    for (cr = cg->members; cr; cr = cr->next)
        if (SameNameRecordAnswersQuestion(&cr->resrec, q))
            return cr;
    return mDNSNULL;
}

// Note: This should just call the parent callback which will free the DNSSECVerifier.
mDNSlocal void VerifyNSECCallback(mDNS *const m, DNSSECVerifier *dv, DNSSECStatus status)
{
    if (!dv->parent)
    {
        LogMsg("VerifyNSECCCallback: ERROR!! no parent DV\n");
        FreeDNSSECVerifier(m, dv);
        return;
    }
    if (dv->ac)
    {
        // Before we call the callback, we need to update the
        // parent with our AuthChain information
        AuthChainLink(dv->parent, dv->ac);
        dv->ac = mDNSNULL;
        dv->actail = &dv->ac;
    }
    dv->parent->DVCallback(m, dv->parent, status);
    // The callback we called in the previous line should recursively
    // free all the DNSSECVerifiers starting from dv->parent and above.
    // So, set that to NULL and free the "dv" itself here.
    dv->parent = mDNSNULL;
    FreeDNSSECVerifier(m, dv);
}

// If the caller provides a callback, it takes the responsibility of calling the original callback
// in "pdv" when it is done.
//
// INPUT:
//
// rr: The NSEC record that should be verified
// rv: The NSEC record can also be provided like this
// pdv: Parent DNSSECVerifier which will be called when the verification is done.
// callback:  As part of the proof, we need multiple NSEC verifications before we call the "pdv" callback in
// which case a intermediate "callback" is provided which can be used to do multiple verifications.
// ncr: The cache record where the RRSIGS are cached
//
// NSEC records and signatures are cached along with the cache record so that we can expire them all together. We can't cache
// them based on the name hash like other records as in most cases the returned NSECs has a different name than we asked for
// (except for NODATA error where the name exists but type does not exist).
//
mDNSlocal void VerifyNSEC(mDNS *const m, ResourceRecord *rr, RRVerifier *rv, DNSSECVerifier *pdv, CacheRecord *ncr,
                          DNSSECVerifierCallback callback)
{
    DNSSECVerifier *dv = mDNSNULL;
    CacheRecord **rp;
    const domainname *name;
    mDNSu16 rrtype;

    if (!rv && !rr)
    {
        LogDNSSEC("VerifyNSEC: Both rr and rv are NULL");
        goto error;
    }
    if (!pdv)
    {
        LogDNSSEC("VerifyNSEC: ERROR!! pdv is NULL");
        return;
    }
    // Remember the name and type for which we are verifying, so that when we are done processing all
    // the verifications, we can trace it back.
    //
    // Note: Currently it is not used because when the verification completes as we just
    // call the "pdv" callback which has its origName and origType.
    if (rr)
    {
        name = rr->name;
        rrtype = rr->rrtype;
    }
    else
    {
        name = &rv->name;
        rrtype = rv->rrtype;
    }

    dv = AllocateDNSSECVerifier(m, name, rrtype, pdv->q.InterfaceID, (callback ? callback : VerifyNSECCallback), mDNSNULL);
    if (!dv) { LogMsg("VerifyNSEC: mDNSPlatformMemAlloc failed"); return; }

    dv->parent = pdv;

    if (AddRRSetToVerifier(dv, rr, rv, RRVS_rr) != mStatus_NoError)
    {
        LogMsg("VerifyNSEC: ERROR!! AddRRSetToVerifier failed to add NSEC");
        goto error;
    }

    // Add the signatures after validating them
    rp = &(ncr->nsec);
    while (*rp)
    {
        if ((*rp)->resrec.rrtype == kDNSType_RRSIG)
        {
            ValidateRRSIG(dv, RRVS_rrsig, &(*rp)->resrec);
        }
        rp=&(*rp)->next;
    }

    if (!dv->rrset || !dv->rrsig)
    {
        LogMsg("VerifyNSEC: ERROR!! AddRRSetToVerifier missing rrset %p, rrsig %p", dv->rrset, dv->rrsig);
        goto error;
    }

    // Next step is to fetch the keys
    dv->next = RRVS_key;

    StartDNSSECVerification(m, dv);
    return;
error:
    pdv->DVCallback(m, pdv, DNSSEC_Indeterminate);
    if (dv)
    {
        dv->parent = mDNSNULL;
        FreeDNSSECVerifier(m, dv);
    }
    return;
}

mDNSlocal void DeleteCachedNSECS(mDNS *const m, CacheRecord *cr)
{
    CacheRecord *rp, *next;

    if (cr->nsec) LogDNSSEC("DeleteCachedNSECS: Deleting NSEC Records\n");
    for (rp = cr->nsec; rp; rp = next)
    {
        next  = rp->next;
        ReleaseCacheRecord(m, rp);
    }
    cr->nsec = mDNSNULL;
}

// Returns success if it adds the nsecs and the rrsigs to the cache record. Otherwise, it returns
// failure (mDNSfalse)
mDNSexport mDNSBool AddNSECSForCacheRecord(mDNS *const m, CacheRecord *crlist, CacheRecord *negcr, mDNSu8 rcode)
{
    CacheRecord *cr, *next;

    if (rcode != kDNSFlag1_RC_NoErr && rcode != kDNSFlag1_RC_NXDomain)
    {
        LogMsg("AddNSECSForCacheRecord: Addings nsecs for rcode %d", rcode);
        return mDNSfalse;
    }

    // Sanity check the list to see if we have anything else other than
    // NSECs and its RRSIGs
    for (cr = crlist; cr; cr = cr->next)
    {
        next = cr->next;
        if (cr->resrec.rrtype != kDNSType_NSEC && cr->resrec.rrtype != kDNSType_RRSIG)
        {
            LogMsg("AddNSECSForCacheRecord: ERROR!! Adding Wrong record %s", CRDisplayString(m, cr));
            return mDNSfalse;
        }
        if (cr->resrec.rrtype == kDNSType_RRSIG)
        {
            RDataBody2 *const rdb = (RDataBody2 *)cr->smallrdatastorage.data;
            rdataRRSig *rrsig = &rdb->rrsig;
            if (swap16(rrsig->typeCovered) != kDNSType_NSEC)
            {
                LogMsg("AddNSECSForCacheRecord:ERROR!! Adding RRSIG with Wrong type %s", CRDisplayString(m, cr));
                return mDNSfalse;
            }
        }
        LogDNSSEC("AddNSECSForCacheRecord: Found a valid record %s", CRDisplayString(m, cr));
    }
    DeleteCachedNSECS(m, negcr);
    LogDNSSEC("AddNSECSForCacheRecord: Adding NSEC Records for %s", CRDisplayString(m, negcr));
    negcr->nsec = crlist;
    negcr->rcode = rcode;
    return mDNStrue;
}

// Return the number of labels that matches starting from the right (excluding the
// root label)
mDNSlocal int CountLabelsMatch(const domainname *const d1, const domainname *const d2)
{
    int count, c1, c2;
    int match, i, skip1, skip2;

    c1 = CountLabels(d1);
    skip1 = c1 - 1;
    c2 = CountLabels(d2);
    skip2 = c2 - 1;

    // Root label always matches. And we don't include it here to
    // match CountLabels
    match = 0;

    // Compare as many labels as possible starting from the rightmost
    count = c1 < c2 ? c1 : c2;
    for (i = count; i > 0; i--)
    {
        const domainname *da, *db;

        da = SkipLeadingLabels(d1, skip1);
        db = SkipLeadingLabels(d2, skip2);
        if (!SameDomainName(da, db)) return match;
        skip1--;
        skip2--;
        match++;
    }
    return match;
}

// RFC 4034:
//
// Section 6.1:
//
// For the purposes of DNS security, owner names are ordered by treating
// individual labels as unsigned left-justified octet strings.  The
// absence of a octet sorts before a zero value octet, and uppercase
// US-ASCII letters are treated as if they were lowercase US-ASCII
// letters.
//
// To compute the canonical ordering of a set of DNS names, start by
// sorting the names according to their most significant (rightmost)
// labels.  For names in which the most significant label is identical,
// continue sorting according to their next most significant label, and
// so forth.
//
// Returns 0 if the names are same
// Returns -1 if d1 < d2
// Returns  1 if d1 > d2
//
// subdomain is set if there is at least one label match (starting from the end)
// and d1 has more labels than d2 e.g., a.b.com is a subdomain of b.com
//
mDNSlocal int DNSSECCanonicalOrder(const domainname *const d1, const domainname *const d2, int *subdomain)
{
    int count, c1, c2;
    int i, skip1, skip2;

    c1 = CountLabels(d1);
    skip1 = c1 - 1;
    c2 = CountLabels(d2);
    skip2 = c2 - 1;

    if (subdomain) *subdomain = 0;

    // Compare as many labels as possible starting from the rightmost
    count = c1 < c2 ? c1 : c2;
    for (i = count; i > 0; i--)
    {
        mDNSu8 *a, *b;
        int j, len, lena, lenb;

        a = (mDNSu8 *)SkipLeadingLabels(d1, skip1);
        b = (mDNSu8 *)SkipLeadingLabels(d2, skip2);
        lena = *a;
        lenb = *b;
        // Compare label by label. Note that "z" > "yak" because z > y, but z < za
        // (lena - lenb check below) because 'za' has two characters. Hence compare the
        // letters first and then compare the length of the label at the end.
        len = lena < lenb ? lena : lenb;
        a++; b++;
        for (j = 0; j < len; j++)
        {
            mDNSu8 ac = *a++;
            mDNSu8 bc = *b++;
            if (mDNSIsUpperCase(ac)) ac += 'a' - 'A';
            if (mDNSIsUpperCase(bc)) bc += 'a' - 'A';
            if (ac != bc)
            {
                verbosedebugf("DNSSECCanonicalOrder: returning ac %c, bc %c", ac, bc);
                return ((ac < bc) ? -1 : 1);
            }
        }
        if ((lena - lenb) != 0)
        {
            verbosedebugf("DNSSECCanonicalOrder: returning lena %d lenb %d", lena, lenb);
            return ((lena < lenb) ? -1 : 1);
        }

        // Continue with the next label
        skip1--;
        skip2--;
    }
    // We have compared label by label. Both of them are same if we are here.
    //
    // Two possibilities.
    //
    // 1) Both names have same number of labels. In that case, return zero.
    // 2) The number of labels is not same. As zero label sorts before, names
    //    with more number of labels is greater.

    // a.b.com is a subdomain of b.com
    if ((c1 > c2) && subdomain)
        *subdomain = 1;

    verbosedebugf("DNSSECCanonicalOrder: returning c1 %d c2 %d\n", c1, c2);
    if (c1 != c2)
        return ((c1 < c2) ? -1 : 1);
    else
        return 0;
}

// Empty Non-Terminal (ENT): if the qname is bigger than nsec owner's name and a
// subdomain of the nsec's nxt field, then the qname is a empty non-terminal. For
// example, if you are looking for (in RFC 4035 example zone) "y.w.example  A"
// record, if it is a ENT, then it would return
//
// x.w.example. 3600 NSEC x.y.w.example. MX RRSIG NSEC
//
// This function is normally called before checking for wildcard matches. If you
// find this NSEC, there is no need to look for a wildcard record
// that could possibly answer the question.
mDNSexport mDNSBool NSECAnswersENT(const ResourceRecord *const rr, domainname *qname)
{
    const domainname *oname = rr->name;
    const RDataBody2 *const rdb = (RDataBody2 *)rr->rdata->u.data;
    const domainname *nxt = (const domainname *)&rdb->data;
    int ret;
    int subdomain;

    // Is the owner name smaller than qname?
    ret = DNSSECCanonicalOrder(oname, qname, mDNSNULL);
    if (ret < 0)
    {
        // Is the next domain field a subdomain of qname ?
        ret = DNSSECCanonicalOrder(nxt, qname, &subdomain);
        if (subdomain)
        {
            if (ret <= 0)
            {
                LogMsg("NSECAnswersENT: ERROR!! DNSSECCanonicalOrder subdomain set "
                       " qname %##s, NSEC %##s", qname->c, rr->name->c);
            }
            return mDNStrue;
        }
    }
    return mDNSfalse;
}

mDNSlocal const domainname *NSECClosestEncloser(ResourceRecord *rr, domainname *qname)
{
    const domainname *oname = rr->name;
    const RDataBody2 *const rdb = (RDataBody2 *)rr->rdata->u.data;
    const domainname *nxt = (const domainname *)&rdb->data;
    int match1, match2;

    match1 = CountLabelsMatch(oname, qname);
    match2 = CountLabelsMatch(nxt, qname);
    // Return the closest i.e the one that matches more labels
    if (match1 > match2)
        return SkipLeadingLabels(oname, CountLabels(oname) - match1);
    else
        return SkipLeadingLabels(nxt, CountLabels(nxt) - match2);
}

// Assumption: NSEC has been validated outside of this function
//
// Does the name exist given the name and NSEC rr ?
//
// Returns -1 if it is an inappropriate nsec
// Returns 1 if the name exists
// Returns 0 if the name does not exist
//
mDNSlocal int NSECNameExists(mDNS *const m, ResourceRecord *rr, domainname *name, mDNSu16 qtype)
{
    const RDataBody2 *const rdb = (RDataBody2 *)rr->rdata->u.data;
    const domainname *nxt = (const domainname *)&rdb->data;
    const domainname *oname = rr->name; // owner name
    int ret1, subdomain1;
    int ret2, subdomain2;
    int ret3, subdomain3;

    ret1 = DNSSECCanonicalOrder(oname, name, &subdomain1);
    if (ret1 > 0)
    {
        LogDNSSEC("NSECNameExists: owner name %##s is bigger than name %##s", oname->c, name->c);
        return -1;
    }

    // Section 4.1 of draft-ietf-dnsext-dnssec-bis-updates-14:
    //
    //   Ancestor delegation NSEC or NSEC3 RRs MUST NOT be used to assume non-
    //   existence of any RRs below that zone cut, which include all RRs at
    //   that (original) owner name other than DS RRs, and all RRs below that
    //   owner name regardless of type.
    //
    // This also implies that we can't use the child side NSEC for DS question.

    if (!ret1)
    {
        mDNSBool soa = RRAssertsExistence(rr, kDNSType_SOA);
        mDNSBool ns = RRAssertsExistence(rr, kDNSType_NS);

        // We are here because the owner name is the same as "name". Make sure the
        // NSEC has the right NS and SOA bits set.
        if (ns && !soa && qtype != kDNSType_DS)
        {
            LogDNSSEC("NSECNameExists: Parent side NSEC %s can't be used for question %##s (%s)",
                      RRDisplayString(m, rr), name->c, DNSTypeName(qtype));
            return -1;
        }
        else if (ns && soa && qtype == kDNSType_DS)
        {
            LogDNSSEC("NSECNameExists: Child side NSEC %s can't be used for question %##s (%s)",
                      RRDisplayString(m, rr), name->c, DNSTypeName(qtype));
            return -1;
        }
        LogDNSSEC("NSECNameExists: owner name %##s is same as name %##s", oname->c, name->c);
        return 1;
    }

    // If the name is a.b.com and NSEC's owner name is b.com i.e., a subdomain
    // and nsec comes from the parent (NS is set and SOA is not set), then this
    // NSEC can't be used for names below the owner name.
    //
    // Similarly if DNAME is set, we can't use it here. See RFC2672-bis-dname
    // appendix.
    if (subdomain1 && (RRAssertsExistence(rr, kDNSType_DNAME) ||
                       (RRAssertsNonexistence(rr, kDNSType_SOA) && RRAssertsExistence(rr, kDNSType_NS))))
    {
        LogDNSSEC("NSECNameExists: NSEC %s comes from the parent, can't use it here",
                  RRDisplayString(m, rr));
        return -1;
    }

    // At this stage, we know that name is greater than the owner name and
    // the nsec is not from the parent side.
    //
    // Compare with the next field in the nsec.
    //
    ret2 = DNSSECCanonicalOrder(name, nxt, &subdomain2);

    // Exact match with the nsec next name
    if (!ret2)
    {
        LogDNSSEC("NSECNameExists: name %##s is same as nxt name %##s", name->c, nxt->c);
        return 1;
    }

    ret3 = DNSSECCanonicalOrder(oname, nxt, &subdomain3);

    if (!ret3)
    {
        // Pathological case of a single name in the domain. This means only the
        // apex of the zone itself exists. Nothing below it. "subdomain2" indicates
        // that name is a subdmain of "next" and hence below the zone.
        if (subdomain2)
        {
            LogDNSSEC("NSECNameExists: owner name %##s subdomain of nxt name %##s", oname->c, nxt->c);
            return 0;
        }
        else
        {
            LogDNSSEC("NSECNameExists: Single name in zone, owner name %##s is same as nxt name %##s", oname->c, nxt->c);
            return -1;
        }
    }

    if (ret3 < 0)
    {
        // Regular NSEC in the zone. Make sure that the "name" lies within
        // oname and next. oname < name and name < next
        if (ret1 < 0 && ret2 < 0)
        {
            LogDNSSEC("NSECNameExists: Normal NSEC name %##s lies within owner %##s and nxt name %##s",
                      name->c, oname->c, nxt->c);
            return 0;
        }
        else
        {
            LogDNSSEC("NSECNameExists: Normal NSEC name %##s does not lie within owner %##s and nxt name %##s",
                      name->c, oname->c, nxt->c);
            return -1;
        }
    }
    else
    {
        // Last NSEC in the zone. The "next" is pointing to the apex. All names
        // should be a subdomain of that and the name should be bigger than
        // oname
        if (ret1 < 0 && subdomain2)
        {
            LogDNSSEC("NSECNameExists: Last NSEC name %##s lies within owner %##s and nxt name %##s",
                      name->c, oname->c, nxt->c);
            return 0;
        }
        else
        {
            LogDNSSEC("NSECNameExists: Last NSEC name %##s does not lie within owner %##s and nxt name %##s",
                      name->c, oname->c, nxt->c);
            return -1;
        }
    }

    LogDNSSEC("NSECNameExists: NSEC %s did not match any case", RRDisplayString(m, rr));
    return -1;
}

// If the answer was result of a wildcard match, then this function proves
// that a proper wildcard was used to answer the question and that the
// original name does not exist
mDNSexport void WildcardAnswerProof(mDNS *const m, DNSSECVerifier *dv)
{
    CacheRecord *ncr;
    CacheRecord **rp;
    const domainname *ce;
    DNSQuestion q;

    LogDNSSEC("WildcardAnswerProof: Question %##s (%s)", dv->origName.c, DNSTypeName(dv->origType));
    //
    // RFC 4035: Section 3.1.3.3
    //
    // 1) We used a wildcard because the qname does not exist, so verify
    //    that the qname does not exist
    //
    // 2) Is the wildcard the right one ?
    //
    // Unfortunately, this is not well explained in that section. Refer to
    // RFC 5155 section 7.2.6.

    // Walk the list of nsecs we received and see if they prove that
    // the name does not exist

    mDNSPlatformMemZero(&q, sizeof(DNSQuestion));
    q.ThisQInterval = -1;
    InitializeQuestion(m, &q, dv->InterfaceID, &dv->origName, dv->origType, mDNSNULL, mDNSNULL);

    ncr = NSECParentForQuestion(m, &q);
    if (!ncr)
    {
        LogMsg("NSECWildCardProof: Can't find NSEC Parent for %##s (%s)", q.qname.c, DNSTypeName(q.qtype));
        goto error;
    }
    rp = &(ncr->nsec);
    while (*rp)
    {
        if ((*rp)->resrec.rrtype == kDNSType_NSEC)
        {
            CacheRecord *cr = *rp;
            if (!NSECNameExists(m, &cr->resrec, &dv->origName, dv->origType))
                break;
        }
        rp=&(*rp)->next;
    }
    if (!(*rp))
    {
        LogMsg("NSECWildCardProof: ERROR!! No  NSECs found for %##s (%s)", q.qname.c, DNSTypeName(q.qtype));
        goto error;
    }
    ce = NSECClosestEncloser(&((*rp)->resrec), &dv->origName);
    if (!ce)
    {
        LogMsg("NSECWildCardProof: ERROR!! Closest Encloser NULL for %##s (%s)", q.qname.c, DNSTypeName(q.qtype));
        goto error;
    }
    if (!SameDomainName(ce, dv->wildcardName))
    {
        LogMsg("NSECWildCardProof: ERROR!! Closest Encloser %##s does not match wildcard name %##s", q.qname.c, dv->wildcardName->c);
        goto error;
    }

    VerifyNSEC(m, &((*rp)->resrec), mDNSNULL, dv, ncr, mDNSNULL);
    return;
error:
    dv->DVCallback(m, dv, DNSSEC_Insecure);
}

// We have a NSEC. Need to see if it proves that NODATA exists for the given name. Note that this
// function does not prove anything as proof may require more than one NSEC and this function
// processes only one NSEC at a time.
//
// Returns mDNSfalse if the NSEC does not prove the NODATA error
// Returns mDNStrue if the NSEC proves the NODATA error
//
mDNSlocal mDNSBool NSECNoDataError(mDNS *const m, ResourceRecord *rr, domainname *name, mDNSu16 qtype, domainname **wildcard)
{
    const domainname *oname = rr->name; // owner name

    if (wildcard) *wildcard = mDNSNULL;
    // RFC 4035
    //
    // section 3.1.3.1 : Name matches. Prove that the type does not exist and also CNAME is
    // not set as in that case CNAME should have been returned ( CNAME part is mentioned in
    // section 4.3 of dnssec-bis-updates.) Without the CNAME check, a positive response can
    // be converted to a NODATA/NOERROR response.
    //
    // section 3.1.3.4 : No exact match for the name but there is a wildcard that could match
    // the name but not the type. There are two NSECs in this case. One of them is a wildcard
    // NSEC and another NSEC proving that the qname does not exist. We are called with one
    // NSEC at a time. We return what we matched and the caller should decide whether all
    // conditions are met for the proof.
    if (SameDomainName(oname, name))
    {
        mDNSBool soa = RRAssertsExistence(rr, kDNSType_SOA);
        mDNSBool ns = RRAssertsExistence(rr, kDNSType_NS);
        if (qtype != kDNSType_DS)
        {
            // For non-DS type questions, we don't want to use the parent side records to
            // answer it
            if (ns && !soa)
            {
                LogDNSSEC("NSECNoDataError: Parent side NSEC %s, can't use for child qname %##s (%s)",
                          RRDisplayString(m, rr), name->c, DNSTypeName(qtype));
                return mDNSfalse;
            }
        }
        else
        {
            if (ns && soa)
            {
                LogDNSSEC("NSECNoDataError: Child side NSEC %s, can't use for parent qname %##s (%s)",
                          RRDisplayString(m, rr), name->c, DNSTypeName(qtype));
                return mDNSfalse;
            }
        }
        if (RRAssertsExistence(rr, qtype) || RRAssertsExistence(rr, kDNSType_CNAME))
        {
            LogMsg("NSECNoDataError: ERROR!! qtype %s exists in %s", DNSTypeName(qtype), RRDisplayString(m, rr));
            return mDNSfalse;
        }
        LogDNSSEC("NSECNoDataError: qype %s does not exist in %s", DNSTypeName(qtype), RRDisplayString(m, rr));
        return mDNStrue;
    }
    else
    {
        // Name does not exist. Before we check for a wildcard match, make sure that
        // this is not an ENT.
        //
        if (NSECAnswersENT(rr, name))
        {
            LogDNSSEC("NSECNoDataError: ERROR!! name %##s exists %s", name->c, RRDisplayString(m, rr));
            return mDNSfalse;
        }

        // Wildcard check. If this is a wildcard NSEC, then check to see if we could
        // have answered the question using this wildcard and it should not have the
        // "qtype" passed in with its bitmap.
        //
        // See RFC 4592, on how wildcards are used to synthesize answers. Find the
        // closest encloser and the qname should be a subdomain i.e if the wildcard
        // is *.x.example, x.example is the closest encloser and the qname should be
        // a subdomain e.g., y.x.example or z.y.x.example and so on.
        if (oname->c[0] == 1 && oname->c[1] == '*')
        {
            int r, s;
            const domainname *ce = SkipLeadingLabels(oname, 1);

            r = DNSSECCanonicalOrder(name, ce, &s);
            if (s)
            {
                if (RRAssertsExistence(rr, qtype) || RRAssertsExistence(rr, kDNSType_CNAME))
                {
                    LogMsg("NSECNoDataError: ERROR!! qtype %s exists in wildcard %s", DNSTypeName(qtype), RRDisplayString(m, rr));
                    return mDNSfalse;
                }
                // It is odd for a wildcard to match when we are looking up DS
                // See RFC 4592
                if (qtype == kDNSType_DS)
                {
                    LogMsg("NSECNoDataError: ERROR!! DS qtype exists in wildcard %s", RRDisplayString(m, rr));
                    return mDNSfalse;
                }
                // Don't use the parent side record for this
                if (RRAssertsNonexistence(rr, kDNSType_SOA) &&
                    RRAssertsExistence(rr, kDNSType_NS))
                {
                    LogDNSSEC("NSECNoDataError: Parent side wildcard NSEC %s, can't use for child qname %##s (%s)",
                              RRDisplayString(m, rr), name->c, DNSTypeName(qtype));
                    return mDNSfalse;
                }
                *wildcard = (domainname *)ce;
                LogDNSSEC("NSECNoDataError: qtype %s does not exist in wildcard %s", DNSTypeName(qtype), RRDisplayString(m, rr));
                return mDNStrue;
            }
        }
        return mDNSfalse;
    }
}

mDNSlocal void NoDataNSECCallback(mDNS *const m, DNSSECVerifier *dv, DNSSECStatus status)
{
    RRVerifier *rv;
    DNSSECVerifier *pdv;
    CacheRecord *ncr;

    LogDNSSEC("NoDataNSECCallback: called");
    if (!dv->parent)
    {
        LogMsg("NoDataNSECCCallback: no parent DV");
        FreeDNSSECVerifier(m, dv);
        return;
    }

    if (dv->ac)
    {
        // Before we free the "dv", we need to update the
        // parent with our AuthChain information
        AuthChainLink(dv->parent, dv->ac);
        dv->ac = mDNSNULL;
        dv->actail = &dv->ac;
    }

    pdv = dv->parent;
    if (status != DNSSEC_Secure)
    {
        goto error;
    }
    if (!(pdv->flags & NSEC_PROVES_NONAME_EXISTS))
    {
        LogMsg("NoDataNSECCCallback: ERROR!! NSEC_PROVES_NONAME_EXISTS not set");
        goto error;
    }
    if (!(pdv->flags & WILDCARD_PROVES_NONAME_EXISTS))
    {
        LogMsg("NoDataNSECCCallback: ERROR!! WILDCARD_PROVES_NONAME_EXISTS not set");
        goto error;
    }

    // We don't care about the "dv" that was allocated in VerifyNSEC.
    // Get the original verifier and verify the other NSEC like we did
    // the first time.
    dv->parent = mDNSNULL;
    FreeDNSSECVerifier(m, dv);

    ncr = NSECParentForQuestion(m, &pdv->q);
    if (!ncr)
    {
        LogMsg("NoDataNSECCallback: Can't find NSEC Parent for %##s (%s)", pdv->q.qname.c, DNSTypeName(pdv->q.qtype));
        goto error;
    }

    rv = pdv->pendingNSEC;
    pdv->pendingNSEC = mDNSNULL;
    // Verify the pendingNSEC and we don't need to come back here. Let the regular
    // NSECCallback call the original callback.
    VerifyNSEC(m, mDNSNULL, rv, pdv, ncr, mDNSNULL);
    return;

error:
    dv->parent->DVCallback(m, dv->parent, status);
    dv->parent = mDNSNULL;
    FreeDNSSECVerifier(m, dv);
}

mDNSlocal void NameErrorNSECCallback(mDNS *const m, DNSSECVerifier *dv, DNSSECStatus status)
{
    RRVerifier *rv;
    DNSSECVerifier *pdv;
    CacheRecord *ncr;

    LogDNSSEC("NameErrorNSECCallback: called");
    if (!dv->parent)
    {
        LogMsg("NameErrorNSECCCallback: no parent DV");
        FreeDNSSECVerifier(m, dv);
        return;
    }

    if (dv->ac)
    {
        // Before we free the "dv", we need to update the
        // parent with our AuthChain information
        AuthChainLink(dv->parent, dv->ac);
        dv->ac = mDNSNULL;
        dv->actail = &dv->ac;
    }

    pdv = dv->parent;
    if (status != DNSSEC_Secure)
    {
        goto error;
    }
    // We don't care about the "dv" that was allocated in VerifyNSEC.
    // Get the original verifier and verify the other NSEC like we did
    // the first time.
    dv->parent = mDNSNULL;
    FreeDNSSECVerifier(m, dv);

    ncr = NSECParentForQuestion(m, &pdv->q);
    if (!ncr)
    {
        LogMsg("NameErrorNSECCallback: Can't find NSEC Parent for %##s (%s)", pdv->q.qname.c, DNSTypeName(pdv->q.qtype));
        goto error;
    }
    rv = pdv->pendingNSEC;
    pdv->pendingNSEC = mDNSNULL;
    // Verify the pendingNSEC and we don't need to come back here. Let the regular
    // NSECCallback call the original callback.
    VerifyNSEC(m, mDNSNULL, rv, pdv, ncr, mDNSNULL);
    return;

error:
    dv->parent->DVCallback(m, dv->parent, status);
    dv->parent = mDNSNULL;
    FreeDNSSECVerifier(m, dv);
}

// We get a NODATA error with no records in answer section. This proves
// that qname does not exist.
mDNSlocal void NoDataProof(mDNS *const m, DNSSECVerifier *dv, CacheRecord *ncr)
{
    CacheRecord **rp;
    domainname *wildcard = mDNSNULL;
    const domainname *ce = mDNSNULL;
    ResourceRecord *nsec_wild = mDNSNULL;
    ResourceRecord *nsec_noname = mDNSNULL;

    // NODATA Error could mean two things. The name exists with no type or there is a
    // wildcard that matches the name but no type. This is done by NSECNoDataError.
    //
    // If it is the case of wildcard, there are two NSECs. One is the wildcard NSEC and
    // the other NSEC to prove that there is no other closer match.

    wildcard = mDNSNULL;
    rp = &(ncr->nsec);
    while (*rp)
    {
        if ((*rp)->resrec.rrtype == kDNSType_NSEC)
        {
            CacheRecord *cr = *rp;
            if (NSECNoDataError(m, &cr->resrec, &dv->q.qname, dv->q.qtype, &wildcard))
            {
                if (wildcard)
                {
                    dv->flags |= WILDCARD_PROVES_NONAME_EXISTS;
                    LogDNSSEC("NoDataProof: NSEC %s proves NODATA error for %##s (%s)",
                              RRDisplayString(m, &(*rp)->resrec), dv->q.qname.c, DNSTypeName(dv->q.qtype));
                }
                else
                {
                    dv->flags |= NSEC_PROVES_NOTYPE_EXISTS;
                    LogDNSSEC("NoDataProof: NSEC %s proves NOTYPE error for %##s (%s)",
                              RRDisplayString(m, &(*rp)->resrec), dv->q.qname.c, DNSTypeName(dv->q.qtype));
                }
                nsec_wild = &cr->resrec;
            }
            if (!NSECNameExists(m, &cr->resrec, &dv->q.qname, dv->q.qtype))
            {
                LogDNSSEC("NoDataProof: NSEC %s proves that  name %##s (%s) does not exist",
                          RRDisplayString(m, &(*rp)->resrec), dv->q.qname.c, DNSTypeName(dv->q.qtype));
                // If we have a wildcard, then we should check to see if the closest
                // encloser is the same as the wildcard.
                ce = NSECClosestEncloser(&cr->resrec, &dv->q.qname);
                dv->flags |= NSEC_PROVES_NONAME_EXISTS;
                nsec_noname = &cr->resrec;
            }
        }
        rp=&(*rp)->next;
    }
    // If the type exists, then we have to verify just that NSEC
    if (!(dv->flags & NSEC_PROVES_NOTYPE_EXISTS))
    {
        // If we have a wildcard, then we should have a "ce" which matches the wildcard
        // If we don't have a wildcard, then we should have proven that the name does not
        // exist which means we would have set the "ce".
        if (wildcard && !ce)
        {
            LogMsg("NoDataProof: Cannot prove that the name %##s (%s) does not exist", dv->q.qname.c, DNSTypeName(dv->q.qtype));
            goto error;
        }
        if (wildcard && !SameDomainName(wildcard, ce))
        {
            LogMsg("NoDataProof: wildcard %##s does not match closest encloser %##s", wildcard->c, ce->c);
            goto error;
        }
    }

    if ((dv->flags & (WILDCARD_PROVES_NONAME_EXISTS|NSEC_PROVES_NONAME_EXISTS)) ==
        (WILDCARD_PROVES_NONAME_EXISTS|NSEC_PROVES_NONAME_EXISTS))
    {
        mStatus status;
        RRVerifier *r = AllocateRRVerifier(nsec_noname, &status);
        if (!r) goto error;
        // First verify wildcard NSEC and then when we are done, we
        // will verify the noname nsec
        dv->pendingNSEC = r;
        VerifyNSEC(m, nsec_wild, mDNSNULL, dv, ncr, NoDataNSECCallback);
    }
    else if ((dv->flags & WILDCARD_PROVES_NONAME_EXISTS) ||
             (dv->flags & NSEC_PROVES_NOTYPE_EXISTS))
    {
        VerifyNSEC(m, nsec_wild, mDNSNULL, dv, ncr, mDNSNULL);
    }
    else if (dv->flags & NSEC_PROVES_NONAME_EXISTS)
    {
        VerifyNSEC(m, nsec_noname, mDNSNULL, dv, ncr, mDNSNULL);
    }
    return;
error:
    LogDNSSEC("NoDataProof: Error return");
    dv->DVCallback(m, dv, DNSSEC_Insecure);
}

mDNSlocal mDNSBool NSECNoWildcard(mDNS *const m, ResourceRecord *rr, domainname *qname, mDNSu16 qtype)
{
    const domainname *ce;
    domainname wild;

    // If the query name is c.x.w.example and if the name does not exist, we should get
    // get a nsec back that looks something like this:
    //
    //      w.example NSEC a.w.example
    //
    // First, we need to get the closest encloser which in this case is w.example. Wild
    // card synthesis works by finding the closest encloser first and then look for
    // a "*" label (assuming * label does not appear in the question). If it does not
    // exists, it would return the NSEC at that name. And the wildcard name at the
    // closest encloser "*.w.example" would be covered by such an NSEC. (Appending "*"
    // makes it bigger than w.example and "* is smaller than "a" for the above NSEC)
    //
    ce = NSECClosestEncloser(rr, qname);
    if (!ce) { LogMsg("NSECNoWildcard: No closest encloser for rr %s, qname %##s (%s)", qname->c, DNSTypeName(qtype)); return mDNSfalse; }

    wild.c[0] = 1;
    wild.c[1] = '*';
    wild.c[2] = 0;
    if (!AppendDomainName(&wild, ce))
    {
        LogMsg("NSECNoWildcard: ERROR!! Can't append domainname closest encloser name %##s, qname %##s (%s)", ce->c, qname->c, DNSTypeName(qtype));
        return mDNSfalse;
    }
    if (NSECNameExists(m, rr, &wild, qtype) != 0)
    {
        LogDNSSEC("NSECNoWildcard: Wildcard name %##s exists or not valid qname %##s (%s)", wild.c, qname->c, DNSTypeName(qtype));
        return mDNSfalse;
    }
    LogDNSSEC("NSECNoWildcard: Wildcard name %##s does not exist for record %s, qname %##s (%s)", wild.c,
              RRDisplayString(m, rr), qname->c, DNSTypeName(qtype));
    return mDNStrue;
}

// We get a NXDOMAIN error with no records in answer section. This proves
// that qname does not exist.
mDNSlocal void NameErrorProof(mDNS *const m, DNSSECVerifier *dv, CacheRecord *ncr)
{
    CacheRecord **rp;
    ResourceRecord *nsec_wild = mDNSNULL;
    ResourceRecord *nsec_noname = mDNSNULL;
    mStatus status;

    // NXDOMAIN Error. We need to prove that the qname does not exist and there
    // is no wildcard that can be used to answer the question.

    rp = &(ncr->nsec);
    while (*rp)
    {
        if ((*rp)->resrec.rrtype == kDNSType_NSEC)
        {
            CacheRecord *cr = *rp;
            if (!NSECNameExists(m, &cr->resrec, &dv->q.qname, dv->q.qtype))
            {
                LogDNSSEC("NameErrorProof: NSEC %s proves name does not exist for %##s (%s)",
                          RRDisplayString(m, &(*rp)->resrec), dv->q.qname.c, DNSTypeName(dv->q.qtype));
                // If we have a wildcard, then we should check to see if the closest
                // encloser is the same as the wildcard.
                dv->flags |= NSEC_PROVES_NONAME_EXISTS;
                nsec_noname = &cr->resrec;
            }
            if (NSECNoWildcard(m, &cr->resrec, &dv->q.qname, dv->q.qtype))
            {
                dv->flags |= WILDCARD_PROVES_NONAME_EXISTS;
                nsec_wild = &cr->resrec;
                LogDNSSEC("NameErrorProof: NSEC %s proves wildcard cannot answer question for %##s (%s)",
                          RRDisplayString(m, &(*rp)->resrec), dv->q.qname.c, DNSTypeName(dv->q.qtype));
            }
        }
        rp=&(*rp)->next;
    }
    if (!nsec_noname || !nsec_wild)
    {
        LogMsg("NameErrorProof: Proof failed for %##s (%s) noname %p, wild %p", dv->q.qname.c, DNSTypeName(dv->q.qtype), nsec_noname, nsec_wild);
        goto error;
    }

    // First verify wildcard NSEC and then when we are done, we will verify the noname nsec.
    // Sometimes a single NSEC can prove both that the "qname" does not exist and a wildcard
    // could not have produced qname. These are a few examples where this can happen.
    //
    // 1. If the zone is example.com and you look up *.example.com and if there are no wildcards,
    //    you will get a NSEC back "example.com NSEC a.example.com". This proves that both the
    //    name does not exist and *.example.com also does not exist
    //
    // 2. If the zone is example.com and it has a record like this:
    //
    //					example.com NSEC d.example.com
    //
    // any name you lookup in between like a.example.com,b.example.com etc. you will get a single
    // NSEC back. In that case we just have to verify only once.
    //
    if (nsec_wild != nsec_noname)
    {
        RRVerifier *r = AllocateRRVerifier(nsec_noname, &status);
        if (!r) goto error;
        dv->pendingNSEC = r;
        VerifyNSEC(m, nsec_wild, mDNSNULL, dv, ncr, NameErrorNSECCallback);
    }
    else
    {
        VerifyNSEC(m, nsec_wild, mDNSNULL, dv, ncr, mDNSNULL);
    }
    return;
error:
    dv->DVCallback(m, dv, DNSSEC_Insecure);
}

mDNSexport void ValidateWithNSECS(mDNS *const m, DNSSECVerifier *dv, CacheRecord *cr)
{
    LogDNSSEC("ValidateWithNSECS: called for %s", CRDisplayString(m, cr));
    // "parent" is set when we are validating a NSEC. In the process of validating that
    // nsec, we encountered another NSEC. For example, we are looking up the A record for
    // www.example.com, we got an NSEC at some stage. We come here to validate the NSEC
    // the first time. While validating the NSEC we remember the original validation result
    // in the parent. But while validating the NSEC, we got another NSEC back e.g., not
    // a secure delegation i.e., we got an NSEC proving that DS does not exist. We prove
    // that again. But if we receive more NSECs after this, we stop.
    //
    if (dv->parent)
    {
        if (dv->parent->parent)
        {
            LogMsg("ValidateWithNSECS: ERROR!! dv parent is set already");
            dv->DVCallback(m, dv, DNSSEC_Indeterminate);
            return;
        }
        else
        {
            DNSSECVerifier *pdv = dv;
            dv = AllocateDNSSECVerifier(m, &pdv->q.qname, pdv->q.qtype, pdv->q.InterfaceID, VerifyNSECCallback, mDNSNULL);
            if (!dv)
            {
                LogMsg("VerifyNSEC: mDNSPlatformMemAlloc failed");
                pdv->DVCallback(m, pdv, DNSSEC_Indeterminate);
                return;
            }
            LogDNSSEC("ValidateWithNSECS: Parent set, Verifying dv %p %##s (%s)", dv, pdv->q.qname.c, DNSTypeName(pdv->q.qtype));
            dv->parent = pdv;
        }
    }
    if (cr->resrec.RecordType == kDNSRecordTypePacketNegative)
    {
        CacheRecord *neg = cr->nsec;
        while (neg)
        {
            LogDNSSEC("ValidateWithNSECS: NSECCached Record %s", CRDisplayString(m, neg));
            neg = neg->next;
        }

        if (cr->rcode == kDNSFlag1_RC_NoErr)
        {
            NoDataProof(m, dv, cr);
        }
        else if (cr->rcode == kDNSFlag1_RC_NXDomain)
        {
            NameErrorProof(m, dv, cr);
        }
        else
        {
            LogDNSSEC("ValidateWithNSECS: Rcode %d invalid", cr->rcode);
            dv->DVCallback(m, dv, DNSSEC_Insecure);
        }
    }
    else
    {
        LogMsg("ValidateWithNSECS: Not a valid cache record %s for NSEC proofs", CRDisplayString(m, cr));
        dv->DVCallback(m, dv, DNSSEC_Insecure);
        return;
    }
}
