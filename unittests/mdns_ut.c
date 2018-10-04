#include "DNSCommon.h"                  // Defines general DNS utility routines

mDNSexport mStatus mDNS_InitStorage_ut(mDNS *const m, mDNS_PlatformSupport *const p,
									   CacheEntity *rrcachestorage, mDNSu32 rrcachesize,
									   mDNSBool AdvertiseLocalAddresses, mDNSCallback *Callback, void *Context)
{
	return mDNS_InitStorage(m, p, rrcachestorage, rrcachesize, AdvertiseLocalAddresses, Callback, Context);
}
