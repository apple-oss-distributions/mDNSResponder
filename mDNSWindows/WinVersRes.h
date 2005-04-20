/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

$Log: WinVersRes.h,v $
Revision 1.30  2005/03/07 19:18:18  shersche
<rdar://problem/4039831> Update Windows build to 1.0.0.58

Revision 1.29  2005/03/02 20:11:45  shersche
Update name

Revision 1.28  2005/03/02 03:57:51  shersche
Bump to 1.0.0.57

Revision 1.27  2005/02/23 03:12:27  shersche
Bump to 1.0.0.56

Revision 1.26  2005/02/15 23:20:18  shersche
Bump to 1.0.0.55 and update name

Revision 1.25  2005/02/10 22:35:29  cheshire
<rdar://problem/3727944> Update name

Revision 1.24  2005/02/08 23:32:24  shersche
Bump to 1.0.0.54

Revision 1.23  2005/02/02 02:08:28  shersche
Bump to version 1.0.0.53

Revision 1.22  2005/01/25 17:15:52  shersche
Bump to 1.0.0.51. Add legal copyright string.

Revision 1.21  2005/01/11 07:09:32  shersche
Bump to version 1.0.0.51

Revision 1.20  2004/12/17 01:23:24  shersche
Bump version to 1.0.0.50

Revision 1.19  2004/12/16 08:09:47  shersche
Revert version number back to 1.0.0.22

Revision 1.18  2004/12/16 02:48:10  shersche
Bump version number to 1.1.0.0

Revision 1.17  2004/10/20 15:37:46  shersche
Bump to Windows-trial-21

Revision 1.16  2004/10/12 23:51:36  cheshire
Bump version to 1.0.0.20

Revision 1.15  2004/09/21 01:15:56  shersche
bump version to 1.0.19

Revision 1.14  2004/09/16 21:27:46  shersche
Bump to version 18

Revision 1.13  2004/09/13 21:28:41  shersche
Bump version to 17

Revision 1.12  2004/08/28 00:18:01  rpantos
no message

Revision 1.11  2004/08/26 17:37:15  shersche
bump version to 1.0.0.14

Revision 1.10  2004/08/05 18:00:04  rpantos
bump to 1.0.0.13

Revision 1.9  2004/07/27 07:31:46  shersche
bump to 1.0.0.12

Revision 1.8  2004/07/22 23:28:54  shersche
bump to Version 1.0.0.11

Revision 1.7  2004/07/20 23:36:24  shersche
bump to version 1.0.0.10

Revision 1.6  2004/07/14 19:53:26  shersche
bump version to 1.0.0.9

Revision 1.5  2004/07/13 22:20:02  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.4  2004/07/09 18:04:17  shersche
bump version to 1.0.0.8

Revision 1.3  2004/06/27 17:00:15  rpantos
Cleanup.

Revision 1.2  2004/06/26 22:24:08  rpantos
Cleanup.

Revision 1.1  2004/06/26 19:17:41  rpantos
First checked in.

 */

#ifndef WINRESVERS_H
#define WINRESVERS_H

#define MASTER_PROD_NAME	"Bonjour"

// Define the product version for mDNSResponder on Windows
#define MASTER_PROD_VERS		1,0,0,58
#define MASTER_PROD_VERS_STR	"1,0,0,58"
#define MASTER_PROD_VERS_STR2	"1.0.0.58"
#define MASTER_PROD_VERS_STR3 "Explorer Plugin 1.0.0.58"

// Define the legal copyright
#define MASTER_LEGAL_COPYRIGHT "Copyright (C) 2003-2005 Apple Computer, Inc."

#endif // WINRESVERS_H
