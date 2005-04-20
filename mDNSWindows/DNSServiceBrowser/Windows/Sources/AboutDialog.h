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
    
$Log: AboutDialog.h,v $
Revision 1.2  2004/07/13 21:24:26  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.1  2004/06/18 04:04:36  rpantos
Move up one level

Revision 1.2  2004/01/30 02:56:32  bradley
Updated to support full Unicode display. Added support for all services on www.dns-sd.org.

Revision 1.1  2003/08/21 02:06:47  bradley
Moved DNSServiceBrowser for non-Windows CE into Windows sub-folder.

Revision 1.4  2003/08/12 19:56:28  cheshire
Update to APSL 2.0

Revision 1.3  2003/07/02 21:20:06  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.2  2002/09/21 20:44:55  zarzycki
Added APSL info

Revision 1.1  2002/09/20 06:12:50  bradley
DNSServiceBrowser for Windows

*/

#if !defined(AFX_ABOUTDIALOG_H__4B8A04B2_9735_4F4A_AFCA_15F85FB3D763__INCLUDED_)
#define AFX_ABOUTDIALOG_H__4B8A04B2_9735_4F4A_AFCA_15F85FB3D763__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include	"Resource.h"

//===========================================================================================================================
//	AboutDialog
//===========================================================================================================================

class	AboutDialog : public CDialog
{
	public:
		
		// Creation/Deletion
		
		AboutDialog(CWnd* pParent = NULL);   // standard constructor
		
		//{{AFX_DATA(AboutDialog)
		enum { IDD = IDD_ABOUT_DIALOG };
			// NOTE: the ClassWizard will add data members here
		//}}AFX_DATA
		
		// ClassWizard generated virtual function overrides
		//{{AFX_VIRTUAL(AboutDialog)
		protected:
		virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
		//}}AFX_VIRTUAL

	protected:

		// Generated message map functions
		//{{AFX_MSG(AboutDialog)
		virtual BOOL OnInitDialog();
		//}}AFX_MSG
		DECLARE_MESSAGE_MAP()
};

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_ABOUTDIALOG_H__4B8A04B2_9735_4F4A_AFCA_15F85FB3D763__INCLUDED_)
