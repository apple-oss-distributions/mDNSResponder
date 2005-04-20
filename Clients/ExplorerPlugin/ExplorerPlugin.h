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
    
$Log: ExplorerPlugin.h,v $
Revision 1.3  2005/01/25 18:35:38  shersche
Declare APIs for obtaining handles to resource modules

Revision 1.2  2004/07/13 21:24:21  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.1  2004/06/18 04:34:59  rpantos
Move to Clients from mDNSWindows

Revision 1.1  2004/01/30 03:01:56  bradley
Explorer Plugin to browse for DNS-SD advertised Web and FTP servers from within Internet Explorer.

*/

//===========================================================================================================================
//	Globals
//===========================================================================================================================

// {9999A076-A9E2-4c99-8A2B-632FC9429223}
DEFINE_GUID(CLSID_ExplorerBar, 
0x9999a076, 0xa9e2, 0x4c99, 0x8a, 0x2b, 0x63, 0x2f, 0xc9, 0x42, 0x92, 0x23);

extern HINSTANCE		gInstance;
extern int				gDLLRefCount;
extern HINSTANCE		GetNonLocalizedResources();
extern HINSTANCE		GetLocalizedResources();

