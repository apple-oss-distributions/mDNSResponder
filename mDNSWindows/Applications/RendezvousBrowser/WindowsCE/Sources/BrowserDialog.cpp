/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
    
$Log: BrowserDialog.cpp,v $
Revision 1.1  2003/08/21 02:16:10  bradley
Rendezvous Browser for HTTP services for Windows CE/PocketPC.

*/

#include	"stdafx.h"

#include	"Application.h"

#include	"DNSServices.h"

#include	"BrowserDialog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//===========================================================================================================================
//	Message Map
//===========================================================================================================================

BEGIN_MESSAGE_MAP(BrowserDialog, CDialog)
	//{{AFX_MSG_MAP(BrowserDialog)
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

static DWORD	UTF8StringToStringObject( const char *inUTF8, CString &inObject );

//===========================================================================================================================
//	BrowserDialog
//===========================================================================================================================

BrowserDialog::BrowserDialog( CWnd *inParent )
	: CDialog( BrowserDialog::IDD, inParent )
{
	//{{AFX_DATA_INIT(BrowserDialog)
		// NOTE: the ClassWizard will add member initialization here
	//}}AFX_DATA_INIT
	
	// Note that LoadIcon does not require a subsequent DestroyIcon in Win32.
	
	mIcon = AfxGetApp()->LoadIcon( IDR_MAINFRAME );
}

//===========================================================================================================================
//	DoDataExchange
//===========================================================================================================================

void	BrowserDialog::DoDataExchange( CDataExchange *pDX )
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(BrowserDialog)
	DDX_Control(pDX, IDC_BROWSE_LIST, mBrowserList);
	//}}AFX_DATA_MAP
}

//===========================================================================================================================
//	OnInitDialog
//===========================================================================================================================

BOOL	BrowserDialog::OnInitDialog()
{
	CString		s;
	
	CDialog::OnInitDialog();

	// Set the icon for this dialog. The framework does this automatically when the application's main window is not a dialog.
	
	SetIcon( mIcon, TRUE );		// Set big icon
	SetIcon( mIcon, FALSE );	// Set small icon
	
	CenterWindow( GetDesktopWindow() );

	// Set up the list.
	
	CRect		rect;
	
	s.LoadString( IDS_BROWSER_LIST_COLUMN_NAME );
	mBrowserList.GetWindowRect( rect );
	mBrowserList.InsertColumn( 0, s, LVCFMT_LEFT, rect.Width() - 8 );
	
	// Start browsing for services.

	DNSStatus		err;

	err = DNSBrowserCreate( 0, BrowserCallBack, this, &mBrowser );
	if( err )
	{
		AfxMessageBox( IDP_SOCKETS_INIT_FAILED );
		goto exit;
	}
	
	err = DNSBrowserStartServiceSearch( mBrowser, 0, "_http._tcp", NULL );
	if( err )
	{
		AfxMessageBox( IDP_SOCKETS_INIT_FAILED );
		goto exit;
	}
	
exit:
	return( TRUE );
}

//===========================================================================================================================
//	BrowserCallBack [static]
//===========================================================================================================================

void
	BrowserDialog::BrowserCallBack( 
		void *					inContext, 
		DNSBrowserRef			inRef, 
		DNSStatus				inStatusCode,
		const DNSBrowserEvent *	inEvent )
{
	BrowserDialog *		dialog;
	
	DNS_UNUSED( inStatusCode );
	dialog = reinterpret_cast < BrowserDialog * > ( inContext );
	
	switch( inEvent->type )
	{
		case kDNSBrowserEventTypeAddService:
			dialog->BrowserAddService( inEvent->data.addService.name );
			break;
		
		case kDNSBrowserEventTypeRemoveService:
			dialog->BrowserRemoveService( inEvent->data.removeService.name );
			break;
		
		default:
			break;
	}
}

//===========================================================================================================================
//	BrowserAddService
//===========================================================================================================================

void	BrowserDialog::BrowserAddService( const char *inName )
{
	BrowserEntry		newEntry;
	INT_PTR				n;
	INT_PTR				i;
	
	UTF8StringToStringObject( inName, newEntry.name );

	n = mBrowserEntries.GetSize();
	for( i = 0; i < n; ++i )
	{
		BrowserEntry &		entry = mBrowserEntries.ElementAt( i );

		if( entry.name.CompareNoCase( newEntry.name ) == 0 )
		{
			break;
		}
	}
	if( i >= n )
	{
		mBrowserEntries.Add( newEntry );
		mBrowserList.InsertItem( i, newEntry.name );
	}
}

//===========================================================================================================================
//	BrowserRemoveService
//===========================================================================================================================

void	BrowserDialog::BrowserRemoveService( const char *inName )
{
	BrowserEntry		newEntry;
	INT_PTR				n;
	INT_PTR				i;
	
	UTF8StringToStringObject( inName, newEntry.name );

	n = mBrowserEntries.GetSize();
	for( i = 0; i < n; ++i )
	{
		BrowserEntry &		entry = mBrowserEntries.ElementAt( i );

		if( entry.name.CompareNoCase( newEntry.name ) == 0 )
		{
			break;
		}
	}
	if( i < n )
	{
		mBrowserEntries.RemoveAt( i );
		mBrowserList.DeleteItem( i );
	}
}

#if 0
#pragma mark -
#endif

//===========================================================================================================================
//	UTF8StringToStringObject
//===========================================================================================================================

static DWORD	UTF8StringToStringObject( const char *inUTF8, CString &inObject )
{
	DWORD			err;
	int				n;
	wchar_t *		unicode;
	
	unicode = NULL;
	
	n = MultiByteToWideChar( CP_UTF8, 0, inUTF8, -1, NULL, 0 );
	if( n > 0 )
	{
		unicode = (wchar_t *) malloc( (size_t)( n * sizeof( wchar_t ) ) );
		if( !unicode ) { err = ERROR_INSUFFICIENT_BUFFER; goto exit; };
		
		n = MultiByteToWideChar( CP_UTF8, 0, inUTF8, -1, unicode, n );
		inObject = unicode;
	}
	else
	{
		inObject = "";
	}
	err = 0;
	
exit:
	if( unicode )
	{
		free( unicode );
	}
	return( err );
}
