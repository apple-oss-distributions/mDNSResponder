/*
 * Copyright (c) 1997-2004 Apple Computer, Inc. All rights reserved.
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
    
$Log: PrinterSetupWizardApp.h,v $
Revision 1.2  2005/01/25 08:52:55  shersche
<rdar://problem/3911084> Add APIs to return localizable and non-localizable resource DLL handles
Bug #: 3911084

Revision 1.1  2004/06/18 04:36:57  rpantos
First checked in


*/

#pragma once

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"		// main symbols


// CWiz97_3App:
// See Wiz97_3.cpp for the implementation of this class
//

class CPrinterSetupWizardApp : public CWinApp
{
public:
	CPrinterSetupWizardApp();

// Overrides
	public:
	virtual BOOL InitInstance();

// Implementation

	DECLARE_MESSAGE_MAP()
};


extern CPrinterSetupWizardApp	theApp;
extern HINSTANCE				GetNonLocalizedResources();
extern HINSTANCE				GetLocalizedResources();
