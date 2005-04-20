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
    
$Log: ToolPrefixWindowsDebug.h,v $
Revision 1.1  2004/06/18 04:07:54  rpantos
Move up one level

Revision 1.3  2004/01/30 03:04:32  bradley
Updated for latest changes to mDNSWindows.

Revision 1.2  2003/08/20 07:06:34  bradley
Update to APSL 2.0. Updated change history to match other mDNSResponder files.

Revision 1.1  2003/08/20 06:01:19  bradley
Prefix files for CodeWarrior Windows builds to set compile options.
					
*/

#ifndef __TOOL_PREFIX_WINDOWS_DEBUG__
#define __TOOL_PREFIX_WINDOWS_DEBUG__

#define	DEBUG				1
#define	MDNS_DEBUGMSGS		1

#endif	// __TOOL_PREFIX_WINDOWS_DEBUG__
