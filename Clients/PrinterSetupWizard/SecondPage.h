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
    
$Log: SecondPage.h,v $
Revision 1.7  2005/01/31 23:54:30  shersche
<rdar://problem/3947508> Start browsing when printer wizard starts. Move browsing logic from CSecondPage object to CPrinterSetupWizardSheet object.

Revision 1.6  2005/01/04 21:09:14  shersche
Fix problems in parsing text records. Fix problems in remove event handling. Ensure that the same service can't be resolved more than once.

Revision 1.5  2004/12/31 07:25:27  shersche
Tidy up printer management, and fix memory leaks when hitting 'Cancel'

Revision 1.4  2004/12/30 01:02:46  shersche
<rdar://problem/3734478> Add Printer information box that displays description and location information when printer name is selected
Bug #: 3734478

Revision 1.3  2004/12/29 18:53:38  shersche
<rdar://problem/3725106>
<rdar://problem/3737413> Added support for LPR and IPP protocols as well as support for obtaining multiple text records. Reorganized and simplified codebase.
Bug #: 3725106, 3737413

Revision 1.2  2004/09/13 21:23:42  shersche
<rdar://problem/3796483> Add moreComing argument to OnAddPrinter and OnRemovePrinter callbacks
Bug #: 3796483

Revision 1.1  2004/06/18 04:36:57  rpantos
First checked in


*/

#pragma once

#include "PrinterSetupWizardSheet.h"
#include "CommonServices.h"
#include "UtilTypes.h"
#include "afxcmn.h"
#include "dns_sd.h"
#include "afxwin.h"
#include <map>

using namespace PrinterSetupWizard;

// CSecondPage dialog

class CSecondPage : public CPropertyPage
{
	DECLARE_DYNAMIC(CSecondPage)

public:
	CSecondPage();
	virtual ~CSecondPage();

// Dialog Data
	enum { IDD = IDD_SECOND_PAGE };

protected:

	void		 InitBrowseList();
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	afx_msg BOOL OnSetCursor(CWnd * pWnd, UINT nHitTest, UINT message);
	virtual BOOL OnSetActive();
	virtual BOOL OnKillActive();

	DECLARE_MESSAGE_MAP()

public:

	HTREEITEM		m_emptyListItem;
	bool			m_selectOkay;
	CTreeCtrl		m_browseList;
	bool			m_initialized;
	bool			m_waiting;

	afx_msg void	OnTvnSelchangedBrowseList(NMHDR *pNMHDR, LRESULT *pResult);

	OSStatus
	OnAddPrinter(
			Printer		*	printer,
			bool			moreComing);

	OSStatus
	OnRemovePrinter(
			Printer		*	printer,
			bool			moreComing);

	void
	OnResolveService( Service * service );

private:

	void
	LoadTextAndDisableWindow( CString & text );
	
	void
	SetPrinterInformationState( BOOL state );

	std::string		m_selectedName;

private:

	CStatic m_printerInformation;
	CStatic m_descriptionLabel;
	CStatic m_descriptionField;
	CStatic m_locationLabel;
	CStatic m_locationField;
};
