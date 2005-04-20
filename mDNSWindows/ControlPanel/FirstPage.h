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

$Log: FirstPage.h,v $
Revision 1.3  2005/03/07 18:27:42  shersche
<rdar://problem/4037940> Fix problem when ControlPanel commits changes to the browse domain list

Revision 1.2  2005/03/03 19:55:21  shersche
<rdar://problem/4034481> ControlPanel source code isn't saving CVS log info


*/

#pragma once

#include "stdafx.h"
#include "resource.h"

#include <DebugServices.h>
#include "afxwin.h"

    
//---------------------------------------------------------------------------------------------------------------------------
//	CFirstPage
//---------------------------------------------------------------------------------------------------------------------------

class CFirstPage : public CPropertyPage
{
public:
	CFirstPage();
	~CFirstPage();

protected:
	//{{AFX_DATA(CFirstPage)
	enum { IDD = IDR_APPLET_PAGE1 };
	//}}AFX_DATA

	//{{AFX_VIRTUAL(CFirstPage)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

	DECLARE_DYNCREATE(CFirstPage)

	//{{AFX_MSG(CFirstPage)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void	OnBnClickedSharedSecret();
	void			OnRegistryChanged();
private:

	afx_msg BOOL	OnSetActive();
	afx_msg void	OnOK();

	void			SetModified( BOOL bChanged = TRUE );
	void			Commit();
	
	OSStatus		CheckStatus();
	void			ShowStatus( DWORD status );

	CEdit			m_hostnameControl;
	bool			m_ignoreHostnameChange;
	bool			m_modified;
	HKEY			m_statusKey;
	HKEY			m_setupKey;
	
public:
	
	afx_msg void OnEnChangeHostname();
	CStatic m_failureIcon;
	CStatic m_successIcon;
};
