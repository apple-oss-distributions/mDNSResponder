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
    
$Log: FirstPage.cpp,v $
Revision 1.5  2005/07/07 17:53:20  shersche
Fix problems associated with the CUPS printer workaround fix.

Revision 1.4  2005/03/16 01:41:29  shersche
<rdar://problem/3989644> Remove info icon from first page

Revision 1.3  2005/01/25 08:58:08  shersche
<rdar://problem/3911084> Load icons at run-time from resource DLLs
Bug #: 3911084

Revision 1.2  2004/07/13 20:15:04  shersche
<rdar://problem/3726363> Load large font name from resource
Bug #: 3726363

Revision 1.1  2004/06/18 04:36:57  rpantos
First checked in


*/

#include "stdafx.h"
#include "PrinterSetupWizardApp.h"
#include "PrinterSetupWizardSheet.h"
#include "FirstPage.h"

#include <DebugServices.h>


// CFirstPage dialog

IMPLEMENT_DYNAMIC(CFirstPage, CPropertyPage)
CFirstPage::CFirstPage()
	: CPropertyPage(CFirstPage::IDD)
{
	CString fontName;

	m_psp.dwFlags &= ~(PSP_HASHELP);
	m_psp.dwFlags |= PSP_DEFAULT|PSP_HIDEHEADER;

	fontName.LoadString(IDS_LARGE_FONT);

	// create the large font
	m_largeFont.CreateFont(-16, 0, 0, 0, 
		FW_BOLD, FALSE, FALSE, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, 
		CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY, DEFAULT_PITCH, fontName);
}

CFirstPage::~CFirstPage()
{
}

void CFirstPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_GREETING, m_greeting);
}


BOOL
CFirstPage::OnSetActive()
{
	CPrinterSetupWizardSheet * psheet;
	CString greetingText;

	psheet = reinterpret_cast<CPrinterSetupWizardSheet*>(GetParent());
	require_quiet( psheet, exit );   
   
	psheet->SetWizardButtons(PSWIZB_NEXT);

	m_greeting.SetFont(&m_largeFont);

	greetingText.LoadString(IDS_GREETING);
	m_greeting.SetWindowText(greetingText);

exit:

	return CPropertyPage::OnSetActive();
}


BOOL
CFirstPage::OnKillActive()
{
	CPrinterSetupWizardSheet * psheet;

	psheet = reinterpret_cast<CPrinterSetupWizardSheet*>(GetParent());
	require_quiet( psheet, exit );   
   
	psheet->SetLastPage(this);

exit:

	return CPropertyPage::OnKillActive();
}


BEGIN_MESSAGE_MAP(CFirstPage, CPropertyPage)
END_MESSAGE_MAP()


// CFirstPage message handlers
