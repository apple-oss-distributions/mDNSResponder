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
    
$Log: PrinterSetupWizardApp.cpp,v $
Revision 1.8  2005/04/13 17:43:39  shersche
<rdar://problem/4081448> Change "PrinterWizard.dll" to "PrinterWizardResources.dll"

Revision 1.7  2005/02/15 07:50:09  shersche
<rdar://problem/4007151> Update name

Revision 1.6  2005/02/10 22:35:10  cheshire
<rdar://problem/3727944> Update name

Revision 1.5  2005/01/25 18:30:02  shersche
Fix call to PathForResource() by passing in NULL as first parameter.

Revision 1.4  2005/01/25 08:54:41  shersche
<rdar://problem/3911084> Load resource DLLs at startup.
Bug #: 3911084

Revision 1.3  2004/07/13 21:24:23  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.2  2004/06/24 20:12:08  shersche
Clean up source code
Submitted by: herscher

Revision 1.1  2004/06/18 04:36:57  rpantos
First checked in


*/

#include "stdafx.h"
#include "PrinterSetupWizardApp.h"
#include "PrinterSetupWizardSheet.h"
#include "DebugServices.h"
#include "loclibrary.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

// Stash away pointers to our resource DLLs

static HINSTANCE g_nonLocalizedResources	= NULL;
static HINSTANCE g_localizedResources		= NULL;


HINSTANCE
GetNonLocalizedResources()
{
	return g_nonLocalizedResources;
}


HINSTANCE
GetLocalizedResources()
{
	return g_localizedResources;
}


// CPrinterSetupWizardApp

BEGIN_MESSAGE_MAP(CPrinterSetupWizardApp, CWinApp)
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()


// CPrinterSetupWizardApp construction

CPrinterSetupWizardApp::CPrinterSetupWizardApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}


// The one and only CPrinterSetupWizardApp object

CPrinterSetupWizardApp theApp;


// CPrinterSetupWizardApp initialization

BOOL CPrinterSetupWizardApp::InitInstance()
{
	CString		errorMessage;
	CString		errorCaption;
	wchar_t		resource[MAX_PATH];
	int			res;
	OSStatus	err = kNoErr;

	//
	// initialize the debugging framework
	//
	debug_initialize( kDebugOutputTypeWindowsDebugger, "PrinterSetupWizard", NULL );
	debug_set_property( kDebugPropertyTagPrintLevel, kDebugLevelTrace );

	// Before we load the resources, let's load the error string

	errorMessage.LoadString( IDS_REINSTALL );
	errorCaption.LoadString( IDS_REINSTALL_CAPTION );

	// Load Resources

	res = PathForResource( NULL, L"PrinterWizardResources.dll", resource, MAX_PATH );
	err = translate_errno( res != 0, kUnknownErr, kUnknownErr );
	require_noerr( err, exit );

	g_nonLocalizedResources = LoadLibrary( resource );
	translate_errno( g_nonLocalizedResources, GetLastError(), kUnknownErr );
	require_noerr( err, exit );

	res = PathForResource( NULL, L"PrinterWizardLocalized.dll", resource, MAX_PATH );
	err = translate_errno( res != 0, kUnknownErr, kUnknownErr );
	require_noerr( err, exit );

	g_localizedResources = LoadLibrary( resource );
	translate_errno( g_localizedResources, GetLastError(), kUnknownErr );
	require_noerr( err, exit );

	AfxSetResourceHandle( g_localizedResources );

	// InitCommonControls() is required on Windows XP if an application
	// manifest specifies use of ComCtl32.dll version 6 or later to enable
	// visual styles.  Otherwise, any window creation will fail.
	InitCommonControls();

	CWinApp::InitInstance();

	AfxEnableControlContainer();

	{
		CPrinterSetupWizardSheet dlg(IDS_CAPTION);

		m_pMainWnd = &dlg;

		try
		{
			INT_PTR nResponse = dlg.DoModal();
		
			if (nResponse == IDOK)
			{
				// TODO: Place code here to handle when the dialog is
				//  dismissed with OK
			}
			else if (nResponse == IDCANCEL)
			{
				// TODO: Place code here to handle when the dialog is
				//  dismissed with Cancel
			}
		}
		catch (CPrinterSetupWizardSheet::WizardException & exc)
		{
			MessageBox(NULL, exc.text, exc.caption, MB_OK|MB_ICONEXCLAMATION);
		}
	}

exit:

	if ( err )
	{
		MessageBox( NULL, errorMessage, errorCaption, MB_ICONERROR | MB_OK );
	}

	if ( g_nonLocalizedResources )
	{
		FreeLibrary( g_nonLocalizedResources );
	}

	if ( g_localizedResources )
	{
		FreeLibrary( g_localizedResources );
	}

	// Since the dialog has been closed, return FALSE so that we exit the
	//  application, rather than start the application's message pump.
	return FALSE;
}
