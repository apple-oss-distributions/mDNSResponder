/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
    
$Log: Application.h,v $
Revision 1.1  2003/08/21 02:06:47  bradley
Moved Rendezvous Browser for non-Windows CE into Windows sub-folder.

Revision 1.4  2003/08/12 19:56:28  cheshire
Update to APSL 2.0

Revision 1.3  2003/07/02 21:20:06  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.2  2002/09/21 20:44:55  zarzycki
Added APSL info

Revision 1.1  2002/09/20 06:12:51  bradley
Rendezvous Browser for Windows

*/

#if !defined(AFX_ADMIN_H__8663733F_6A15_439F_B568_F5A0125CD572__INCLUDED_)
#define AFX_ADMIN_H__8663733F_6A15_439F_B568_F5A0125CD572__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include	"stdafx.h"

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include	"Resource.h"

//===========================================================================================================================
//	Globals
//===========================================================================================================================

extern class Application		gApp;

//===========================================================================================================================
//	Application
//===========================================================================================================================

class	Application : public CWinApp
{
	public:
		
		// Creation/Deletion
		
		Application();
		
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(Application)
		public:
		virtual BOOL InitInstance();
		virtual int ExitInstance( void );
		//}}AFX_VIRTUAL
		
		//{{AFX_MSG(Application)
			// NOTE - the ClassWizard will add and remove member functions here.
			//    DO NOT EDIT what you see in these blocks of generated code !
		//}}AFX_MSG
		DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ADMIN_H__8663733F_6A15_439F_B568_F5A0125CD572__INCLUDED_)
