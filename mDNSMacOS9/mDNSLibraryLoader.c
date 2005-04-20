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

$Log: mDNSLibraryLoader.c,v $
Revision 1.1  2004/03/12 21:30:26  cheshire
Build a System-Context Shared Library from mDNSCore, for the benefit of developers
like Muse Research who want to be able to use mDNS/DNS-SD from GPL-licensed code.

 */

#include <Resources.h>
#include <CodeFragments.h>
#include "ShowInitIcon.h"

extern pascal OSErr FragRegisterFileLibs(ConstFSSpecPtr fss, Boolean unregister);

extern void main(void)
	{
	OSStatus err;
	FCBPBRec fcbPB;
	FSSpec fss;

	// 1. Show our "icon march" icon
	ShowInitIcon(128, true);

	// 2. Find our FSSpec
	fss.name[0] = 0;
	fcbPB.ioNamePtr = fss.name;
	fcbPB.ioVRefNum = 0;
	fcbPB.ioRefNum = (short)CurResFile();
	fcbPB.ioFCBIndx = 0;
	err = PBGetFCBInfoSync(&fcbPB);

	// 3. Tell CFM that we're a CFM library container file	
	fss.vRefNum = fcbPB.ioFCBVRefNum;
	fss.parID = fcbPB.ioFCBParID;
	if (err == noErr) err = FragRegisterFileLibs(&fss, false);

	// 4. Now that CFM knows we're a library container, tell it to go and get our library
	if (err == noErr)
		{
		CFragConnectionID c;
		Ptr m;
		Str255 e;
		THz oldZone = GetZone();
		SetZone(SystemZone());
		err = GetSharedLibrary("\pDarwin;mDNS", kPowerPCCFragArch, kLoadCFrag, &c, &m, e);
		SetZone(oldZone);
		}
	}

// There's no CFM stub library for the FragRegisterFileLibs() call, so we'll make our own
#if __ide_target("FragRegisterFileLibsStub")
#pragma export on
pascal OSErr FragRegisterFileLibs(ConstFSSpecPtr fss, Boolean unregister)
	{
	(void)fss;			// Unused
	(void)unregister;	// Unused
	return(0);
	}
#endif
