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

$Log: SecondPage.h,v $
Revision 1.3  2005/03/03 19:55:21  shersche
<rdar://problem/4034481> ControlPanel source code isn't saving CVS log info


*/

#pragma once

#include "stdafx.h"
#include "resource.h"

#include <DebugServices.h>
#include <list>


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage
//---------------------------------------------------------------------------------------------------------------------------

class CSecondPage : public CPropertyPage
{
public:
	CSecondPage();
	~CSecondPage();

protected:

	//{{AFX_DATA(CSecondPage)
	enum { IDD = IDR_APPLET_PAGE2 };
	//}}AFX_DATA

	//{{AFX_VIRTUAL(CSecondPage)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

	DECLARE_DYNCREATE(CSecondPage)

	//{{AFX_MSG(CSecondPage)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	
	afx_msg void	OnBnClickedSharedSecret();
	afx_msg void	OnBnClickedAdvertise();

	void			OnAddRegistrationDomain( CString & domain );
	void			OnRemoveRegistrationDomain( CString & domain );
	
private:
	
	typedef std::list<CString> StringList;

	afx_msg BOOL
	OnSetActive();
	
	afx_msg void
	OnOK();

	void
	EmptyComboBox
			(
			CComboBox	&	box
			);

	OSStatus
	Populate(
			CComboBox	&	box,
			HKEY			key,
			StringList	&	l
			);
	
	void
	SetModified( BOOL bChanged = TRUE );
	
	void
	Commit();

	OSStatus
	Commit( CComboBox & box, HKEY key, DWORD enabled );

	OSStatus
	CreateKey( CString & name, DWORD enabled );

	OSStatus
	RegQueryString( HKEY key, CString valueName, CString & value );

	CComboBox		m_regDomainsBox;
	CButton			m_advertiseServicesButton;
	CButton			m_sharedSecretButton;
	BOOL			m_modified;

public:
	afx_msg void OnCbnSelChange();
	afx_msg void OnCbnEditChange();
}; 
