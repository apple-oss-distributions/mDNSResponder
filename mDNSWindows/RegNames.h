/*
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@

    Change History (most recent first):
    
$Log: RegNames.h,v $
Revision 1.2  2005/10/05 18:05:28  herscher
<rdar://problem/4192011> Save Wide-Area preferences in a different spot in the registry so they don't get removed when doing an update install.

Revision 1.1  2005/03/03 02:31:37  shersche
Consolidates all registry key names and can safely be included in any component that needs it


*/

//----------------------------------------------------------------------------------------
//	Registry Constants
//----------------------------------------------------------------------------------------

#if defined(UNICODE)

#	define kServiceParametersNode				L"SOFTWARE\\Apple Computer, Inc.\\Bonjour"
#	define kServiceName							L"Bonjour Service"
#	define kServiceDynDNSBrowseDomains			L"BrowseDomains"
#	define kServiceDynDNSHostNames				L"HostNames"
#	define kServiceDynDNSRegistrationDomains	L"RegistrationDomains"
#	define kServiceDynDNSDomains				L"Domains"	// value is comma separated list of domains
#	define kServiceDynDNSEnabled				L"Enabled"
#	define kServiceDynDNSStatus					L"Status"
#	define kServiceManageLLRouting				L"ManageLLRouting"
#	define kServiceCacheEntryCount				L"CacheEntryCount"
#	define kServiceManageFirewall				L"ManageFirewall"

# else

#	define kServiceParametersNode				"SOFTWARE\\Apple Computer, Inc.\\Bonjour"
#	define kServiceName							"Bonjour Service"
#	define kServiceDynDNSBrowseDomains			"BrowseDomains"
#	define kServiceDynDNSHostNames				"HostNames"
#	define kServiceDynDNSRegistrationDomains	"RegistrationDomains"
#	define kServiceDynDNSDomains				"Domains"	// value is comma separated list of domains
#	define kServiceDynDNSEnabled				"Enabled"
#	define kServiceDynDNSStatus					"Status"
#	define kServiceManageLLRouting				"ManageLLRouting"
#	define kServiceCacheEntryCount				"CacheEntryCount"
#	define kServiceManageFirewall				"ManageFirewall"

#endif
