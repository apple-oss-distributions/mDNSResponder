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

$Log: ThirdPage.h,v $
Revision 1.2  2005/03/03 19:55:21  shersche
<rdar://problem/4034481> ControlPanel source code isn't saving CVS log info


*/

#pragma once

#include "stdafx.h"
#include "resource.h"

#include <DebugServices.h>
#include <list>
#include "afxcmn.h"
#include "afxwin.h"



//---------------------------------------------------------------------------------------------------------------------------
//	CThirdPage
//---------------------------------------------------------------------------------------------------------------------------

class CThirdPage : public CPropertyPage
{
public:
	CThirdPage();
	~CThirdPage();

protected:

	//{{AFX_DATA(CThirdPage)
	enum { IDD = IDR_APPLET_PAGE3 };
	//}}AFX_DATA

	//{{AFX_VIRTUAL(CThirdPage)
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

	DECLARE_DYNCREATE(CThirdPage)

	//{{AFX_MSG(CThirdPage)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
	
private:
	
	typedef std::list<CString> StringList;

	afx_msg BOOL
	OnSetActive();
	
	afx_msg void
	OnOK();
	
	void
	SetModified( BOOL bChanged = TRUE );
	
	void
	Commit();

	BOOL			m_modified;

public:
private:
	static int CALLBACK 
	SortFunc(LPARAM lParam1, LPARAM lParam2, LPARAM lParamSort);

	CListCtrl	m_browseListCtrl;
	bool		m_initialized;
	bool		m_firstTime;

public:

	afx_msg void OnBnClickedAddBrowseDomain();
	afx_msg void OnBnClickedRemoveBrowseDomain();
	afx_msg void OnLvnItemchangedBrowseList(NMHDR *pNMHDR, LRESULT *pResult);
	CButton m_removeButton;
};


//---------------------------------------------------------------------------------------------------------------------------
//	CAddBrowseDomain
//---------------------------------------------------------------------------------------------------------------------------

class CAddBrowseDomain : public CDialog
{
	DECLARE_DYNAMIC(CAddBrowseDomain)

public:
	CAddBrowseDomain(CWnd* pParent = NULL);   // standard constructor
	virtual ~CAddBrowseDomain();

// Dialog Data
	enum { IDD = IDR_ADD_BROWSE_DOMAIN };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	virtual BOOL OnInitDialog();
	virtual void OnOK();
	DECLARE_MESSAGE_MAP()
public:
	CComboBox	m_comboBox;
	CString		m_text;
};
