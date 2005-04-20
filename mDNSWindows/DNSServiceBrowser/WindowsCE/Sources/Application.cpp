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
    
$Log: Application.cpp,v $
Revision 1.2  2004/07/13 21:24:27  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.1  2004/06/18 04:04:37  rpantos
Move up one level

Revision 1.2  2004/01/30 02:56:33  bradley
Updated to support full Unicode display. Added support for all services on www.dns-sd.org.

Revision 1.1  2003/08/21 02:16:10  bradley
DNSServiceBrowser for HTTP services for Windows CE/PocketPC.

*/

#include	"stdafx.h"

#include	"DNSServices.h"

#include	"BrowserDialog.h"

#include	"Application.h"

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
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

//===========================================================================================================================
//	Globals
//===========================================================================================================================

Application		gApp;

//===========================================================================================================================
//	Application
//===========================================================================================================================

Application::Application()
	: CWinApp()
{
	//
}

//===========================================================================================================================
//	InitInstance
//===========================================================================================================================

BOOL Application::InitInstance()
{
	DNSStatus			err;
	BrowserDialog		dialog;
	BOOL				dnsInitialized;
	
	dnsInitialized = FALSE;
	
	err = DNSServicesInitialize( kDNSFlagAdvertise, 0 );
	if( err )
	{
		AfxMessageBox( IDP_SOCKETS_INIT_FAILED );
		goto exit;
	}
	dnsInitialized = TRUE;

	// Display the main browser dialog.
	
	m_pMainWnd = &dialog;
	dialog.DoModal();

	// Dialog has been closed. Return false to exit the app and not start the app's message pump.

exit:
	if( dnsInitialized )
	{
		DNSServicesFinalize();
	}
	return( FALSE );
}
