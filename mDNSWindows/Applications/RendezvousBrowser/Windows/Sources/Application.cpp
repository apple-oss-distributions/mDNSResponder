/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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
    
$Log: Application.cpp,v $
Revision 1.1  2003/08/21 02:06:47  bradley
Moved Rendezvous Browser for non-Windows CE into Windows sub-folder.

Revision 1.5  2003/08/12 19:56:28  cheshire
Update to APSL 2.0

Revision 1.4  2003/07/02 21:20:06  cheshire
<rdar://problem/3313413> Update copyright notices, etc., in source code comments

Revision 1.3  2002/09/21 20:44:55  zarzycki
Added APSL info

Revision 1.2  2002/09/20 08:37:34  bradley
Increased the DNS record cache from the default of 64 to 512 entries for larger networks.

Revision 1.1  2002/09/20 06:12:51  bradley
Rendezvous Browser for Windows

*/

#include	<assert.h>

#include	"DNSServices.h"

#include	"Application.h"

#include	"ChooserDialog.h"

#include	"stdafx.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//===========================================================================================================================
//	Message Map
//===========================================================================================================================

BEGIN_MESSAGE_MAP(Application, CWinApp)
	//{{AFX_MSG_MAP(Application)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	ON_COMMAND(ID_HELP, CWinApp::OnHelp)
END_MESSAGE_MAP()

//===========================================================================================================================
//	Globals
//===========================================================================================================================

Application		gApp;

//===========================================================================================================================
//	Application
//===========================================================================================================================

Application::Application( void )
{
	//
}

//===========================================================================================================================
//	InitInstance
//===========================================================================================================================

BOOL	Application::InitInstance()
{
	DNSStatus		err;
	
	// WinSock initialization.
	
	if( !AfxSocketInit() )
	{
		AfxMessageBox( IDP_SOCKETS_INIT_FAILED );
		return( FALSE );
	}

	// Standard MFC initialization.

#if( !defined( AFX_DEPRECATED ) )
	#ifdef _AFXDLL
		Enable3dControls();			// Call this when using MFC in a shared DLL
	#else
		Enable3dControlsStatic();	// Call this when linking to MFC statically
	#endif
#endif

	InitCommonControls();
	
	// Set up DNS Services.
	
	err = DNSServicesInitialize( 0, 512 );
	assert( err == kDNSNoErr );
	
	// Create the chooser dialog.
	
	ChooserDialog *		dialog;
	
	m_pMainWnd = NULL;
	dialog = new ChooserDialog;
	dialog->Create( IDD_CHOOSER_DIALOG );
	m_pMainWnd = dialog;
	dialog->ShowWindow( SW_SHOW );
	
	return( true );
}

//===========================================================================================================================
//	ExitInstance
//===========================================================================================================================

int	Application::ExitInstance( void )
{
	// Clean up DNS Services.
	
	DNSServicesFinalize();
	return( 0 );
}
