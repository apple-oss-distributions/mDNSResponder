/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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
    
$Log: Prefix.h,v $
Revision 1.1  2004/06/18 04:16:41  rpantos
Move up one level.

Revision 1.2  2004/04/30 02:40:23  bradley
Define DNS_SD_CLIENT_ENABLED=0 so DNSSD.c can be included without linking the client IPC code.

Revision 1.1  2004/01/30 02:58:39  bradley
mDNSResponder Windows Service. Provides global Bonjour support with an IPC interface.

*/

#ifndef __PREFIX__
#define __PREFIX__

#if( defined( _DEBUG ) )
	#define	DEBUG					1
	#define	MDNS_DEBUGMSGS			1
#else
	#define	DEBUG					0
#endif

#define	DNS_SD_CLIENT_ENABLED		0

#endif	// __PREFIX__
