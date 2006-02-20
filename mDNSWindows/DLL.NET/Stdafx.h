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

$Log: Stdafx.h,v $
Revision 1.4  2005/10/19 19:50:35  herscher
Workaround a bug in the latest Microsoft Platform SDK when compiling C++ files that include (directly or indirectly) <WspiApi.h>

Revision 1.3  2005/02/05 02:40:59  cheshire
Convert newlines to Unix-style (ASCII 10)

Revision 1.2  2005/02/05 02:37:01  cheshire
Convert newlines to Unix-style (ASCII 10)

Revision 1.1  2004/06/26 04:01:22  shersche
Initial revision

 */
    
// stdafx.h : include file for standard system include files,
// or project specific include files that are used frequently,
// but are changed infrequently

#pragma once

#if !defined(_WSPIAPI_COUNTOF)
#	define _WSPIAPI_COUNTOF(_Array) (sizeof(_Array) / sizeof(_Array[0]))
#endif

#using <mscorlib.dll>
#using <System.dll>

