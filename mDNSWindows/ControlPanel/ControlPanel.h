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

$Log: ControlPanel.h,v $
Revision 1.2  2005/03/03 19:55:21  shersche
<rdar://problem/4034481> ControlPanel source code isn't saving CVS log info


*/

    
#pragma once

#include "stdafx.h"

//---------------------------------------------------------------------------------------------------------------------------
//	CCPApplet
//---------------------------------------------------------------------------------------------------------------------------

class CCPApplet : public CCmdTarget
{
public:

	CCPApplet( UINT nResourceID, UINT nDescriptionID, CRuntimeClass* pUIClass );

	virtual ~CCPApplet();

protected:

	virtual LRESULT OnRun(CWnd* pParentWnd);
	virtual LRESULT OnStartParms(CWnd* pParentWnd, LPCTSTR lpszExtra);
	virtual LRESULT OnInquire(CPLINFO* pInfo);
	virtual LRESULT OnNewInquire(NEWCPLINFO* pInfo);
	virtual LRESULT OnSelect();
	virtual LRESULT OnStop();

	CRuntimeClass	*	m_uiClass;
	UINT				m_resourceId;
	UINT				m_descId;
	CString				m_name;
	int					m_pageNumber;
  
	friend class CCPApp;

	DECLARE_DYNAMIC(CCPApplet);
};


//---------------------------------------------------------------------------------------------------------------------------
//	CCPApp
//---------------------------------------------------------------------------------------------------------------------------

class CCPApp : public CWinApp
{
public:

	CCPApp();
	virtual ~CCPApp();

	void AddApplet( CCPApplet* pApplet );

protected:

	CList<CCPApplet*, CCPApplet*&> m_applets;

	friend LONG APIENTRY
	CPlApplet(HWND hWndCPl, UINT uMsg, LONG lParam1, LONG lParam2);

	virtual LRESULT OnCplMsg(HWND hWndCPl, UINT msg, LPARAM lp1, LPARAM lp2);
	virtual LRESULT OnInit();
	virtual LRESULT OnExit();

	DECLARE_DYNAMIC(CCPApp);
};


CCPApp * GetControlPanelApp();
