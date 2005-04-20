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

$Log: SecondPage.cpp,v $
Revision 1.3  2005/03/03 19:55:22  shersche
<rdar://problem/4034481> ControlPanel source code isn't saving CVS log info


*/

#include "SecondPage.h"
#include "resource.h"

#include "ConfigPropertySheet.h"
#include "SharedSecret.h"

#include <WinServices.h>
    
IMPLEMENT_DYNCREATE(CSecondPage, CPropertyPage)


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::CSecondPage
//---------------------------------------------------------------------------------------------------------------------------

CSecondPage::CSecondPage()
:
	CPropertyPage(CSecondPage::IDD)
{
	//{{AFX_DATA_INIT(CSecondPage)
	//}}AFX_DATA_INIT
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::~CSecondPage
//---------------------------------------------------------------------------------------------------------------------------

CSecondPage::~CSecondPage()
{
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::DoDataExchange
//---------------------------------------------------------------------------------------------------------------------------

void CSecondPage::DoDataExchange(CDataExchange* pDX)
{
	CPropertyPage::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CSecondPage)
	//}}AFX_DATA_MAP
	DDX_Control(pDX, IDC_CHECK1, m_advertiseServicesButton);
	DDX_Control(pDX, IDC_BUTTON1, m_sharedSecretButton);
	DDX_Control(pDX, IDC_COMBO2, m_regDomainsBox);
}

BEGIN_MESSAGE_MAP(CSecondPage, CPropertyPage)
	//{{AFX_MSG_MAP(CSecondPage)
	//}}AFX_MSG_MAP
	ON_BN_CLICKED(IDC_BUTTON1, OnBnClickedSharedSecret)
	ON_BN_CLICKED(IDC_CHECK1, OnBnClickedAdvertise)
	ON_CBN_SELCHANGE(IDC_COMBO1, OnCbnSelChange)
	ON_CBN_EDITCHANGE(IDC_COMBO1, OnCbnEditChange)
	ON_CBN_EDITCHANGE(IDC_COMBO2, OnCbnEditChange)
	ON_CBN_SELCHANGE(IDC_COMBO2, OnCbnSelChange)
	
END_MESSAGE_MAP()


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::SetModified
//---------------------------------------------------------------------------------------------------------------------------

void CSecondPage::SetModified( BOOL bChanged )
{
	m_modified = bChanged;

	CPropertyPage::SetModified( bChanged );
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnSetActive
//---------------------------------------------------------------------------------------------------------------------------

BOOL
CSecondPage::OnSetActive()
{
	CConfigPropertySheet	*	psheet;
	HKEY						key = NULL;
	DWORD						dwSize;
	DWORD						enabled;
	DWORD						err;
	BOOL						b = CPropertyPage::OnSetActive();

	psheet = reinterpret_cast<CConfigPropertySheet*>(GetParent());
	require_quiet( psheet, exit );
	
	m_modified = FALSE;

	// Clear out what's there

	EmptyComboBox( m_regDomainsBox );

	// Now populate the registration domain box

	err = RegCreateKey( HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\" kServiceName L"\\Parameters\\DynDNS\\Setup\\" kServiceDynDNSRegistrationDomains, &key );
	require_noerr( err, exit );

	err = Populate( m_regDomainsBox, key, psheet->m_regDomains );
	check_noerr( err );

	dwSize = sizeof( DWORD );
	err = RegQueryValueEx( key, L"Enabled", NULL, NULL, (LPBYTE) &enabled, &dwSize );
	m_advertiseServicesButton.SetCheck( ( !err && enabled ) ? BST_CHECKED : BST_UNCHECKED );
	m_regDomainsBox.EnableWindow( ( !err && enabled ) );
	m_sharedSecretButton.EnableWindow( (!err && enabled ) );

	RegCloseKey( key );

exit:

	return b;
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnOK
//---------------------------------------------------------------------------------------------------------------------------

void
CSecondPage::OnOK()
{
	if ( m_modified )
	{
		Commit();
	}
}



//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::Commit
//---------------------------------------------------------------------------------------------------------------------------

void
CSecondPage::Commit()
{
	HKEY		key = NULL;
	DWORD		err;

	err = RegCreateKey( HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\" kServiceName L"\\Parameters\\DynDNS\\Setup\\" kServiceDynDNSRegistrationDomains, &key );
	require_noerr( err, exit );

	err = Commit( m_regDomainsBox, key, m_advertiseServicesButton.GetCheck() == BST_CHECKED );
	check_noerr( err );
	
exit:

	if ( key )
	{
		RegCloseKey( key );
	}
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::Commit
//---------------------------------------------------------------------------------------------------------------------------

OSStatus
CSecondPage::Commit( CComboBox & box, HKEY key, DWORD enabled )
{
	CString		selected;
	OSStatus	err = kNoErr;

	// Get selected text
	
	box.GetWindowText( selected );
	
	// If we haven't seen this string before, add the string to the box and
	// the registry
	
	if ( ( selected.GetLength() > 0 ) && ( box.FindStringExact( -1, selected ) == CB_ERR ) )
	{
		CString string;

		box.AddString( selected );

		err = RegQueryString( key, L"UserDefined", string );
		check_noerr( err );

		if ( string.GetLength() )
		{
			string += L"," + selected;
		}
		else
		{
			string = selected;
		}

		err = RegSetValueEx( key, L"UserDefined", 0, REG_SZ, (LPBYTE) (LPCTSTR) string, ( string.GetLength() + 1) * sizeof( TCHAR ) );
		check_noerr ( err );
	}

	// Save selected text in registry.  This will trigger mDNSResponder to setup
	// DynDNS config again

	err = RegSetValueEx( key, L"", 0, REG_SZ, (LPBYTE) (LPCTSTR) selected, ( selected.GetLength() + 1 ) * sizeof( TCHAR ) );
	check_noerr( err );

	err = RegSetValueEx( key, L"Enabled", 0, REG_DWORD, (LPBYTE) &enabled, sizeof( DWORD ) );
	check_noerr( err );

	return err;
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnBnClickedSharedSecret
//---------------------------------------------------------------------------------------------------------------------------

void CSecondPage::OnBnClickedSharedSecret()
{
	CString string;

	m_regDomainsBox.GetWindowText( string );

	CSharedSecret dlg;

	dlg.m_secretName = string;

	dlg.DoModal();
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnBnClickedAdvertise
//---------------------------------------------------------------------------------------------------------------------------

void CSecondPage::OnBnClickedAdvertise()
{
	int state;

	state = m_advertiseServicesButton.GetCheck();

	m_regDomainsBox.EnableWindow( state );
	m_sharedSecretButton.EnableWindow( state );

	SetModified( TRUE );
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnCbnSelChange
//---------------------------------------------------------------------------------------------------------------------------

void CSecondPage::OnCbnSelChange()
{
	SetModified( TRUE );
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnCbnEditChange
//---------------------------------------------------------------------------------------------------------------------------

void CSecondPage::OnCbnEditChange()
{
	SetModified( TRUE );
}



//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnAddRegistrationDomain
//---------------------------------------------------------------------------------------------------------------------------

void
CSecondPage::OnAddRegistrationDomain( CString & domain )
{
	int index = m_regDomainsBox.FindStringExact( -1, domain );

	if ( index == CB_ERR )
	{
		m_regDomainsBox.AddString( domain );
	}
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::OnRemoveRegistrationDomain
//---------------------------------------------------------------------------------------------------------------------------

void
CSecondPage::OnRemoveRegistrationDomain( CString & domain )
{
	int index = m_regDomainsBox.FindStringExact( -1, domain );

	if ( index != CB_ERR )
	{
		m_regDomainsBox.DeleteString( index );
	}
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::EmptyComboBox
//---------------------------------------------------------------------------------------------------------------------------

void
CSecondPage::EmptyComboBox( CComboBox & box )
{
	while ( box.GetCount() > 0 )
	{
		box.DeleteString( 0 );
	}
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::Populate
//---------------------------------------------------------------------------------------------------------------------------

OSStatus
CSecondPage::Populate( CComboBox & box, HKEY key, StringList & l )
{
	TCHAR		rawString[kDNSServiceMaxDomainName + 1];
	DWORD		rawStringLen;
	CString		string;
	OSStatus	err;

	err = RegQueryString( key, L"UserDefined", string );

	if ( !err && string.GetLength() )
	{
		bool done = false;

		while ( !done )
		{
			CString tok;

			tok = string.SpanExcluding( L"," );

			box.AddString( tok );

			if ( tok != string )
			{
				// Get rid of that string and comma

				string = string.Right( string.GetLength() - tok.GetLength() - 1 );
			}
			else
			{
				done = true;
			}
		}
	}

	StringList::iterator it;

	for ( it = l.begin(); it != l.end(); it++ )
	{
		if ( box.FindStringExact( -1, *it ) == CB_ERR )
		{
			box.AddString( *it );
		}
	}

	// Now look to see if there is a selected string, and if so,
	// select it

	rawString[0] = '\0';

	rawStringLen = sizeof( rawString );

	err = RegQueryValueEx( key, L"", 0, NULL, (LPBYTE) rawString, &rawStringLen );

	string = rawString;
	
	if ( !err && ( string.GetLength() != 0 ) )
	{
		// See if it's there

		if ( box.SelectString( -1, string ) == CB_ERR )
		{
			// If not, add it

			box.AddString( string );
		}

		box.SelectString( -1, string );
	}

	return err;
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::CreateKey
//---------------------------------------------------------------------------------------------------------------------------

OSStatus
CSecondPage::CreateKey( CString & name, DWORD enabled )
{
	HKEY		key = NULL;
	OSStatus	err;

	err = RegCreateKey( HKEY_LOCAL_MACHINE, (LPCTSTR) name, &key );
	require_noerr( err, exit );

	err = RegSetValueEx( key, L"Enabled", 0, REG_DWORD, (LPBYTE) &enabled, sizeof( DWORD ) );
	check_noerr( err );

exit:

	if ( key )
	{
		RegCloseKey( key );
	}

	return err;
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSecondPage::RegQueryString
//---------------------------------------------------------------------------------------------------------------------------

OSStatus
CSecondPage::RegQueryString( HKEY key, CString valueName, CString & value )
{
	TCHAR	*	string;
	DWORD		stringLen;
	int			i;
	OSStatus	err;

	stringLen	= 1024;
	string		= NULL;
	i			= 0;

	do
	{
		if ( string )
		{
			free( string );
		}

		string = (TCHAR*) malloc( stringLen );
		require_action( string, exit, err = kUnknownErr );

		err = RegQueryValueEx( key, valueName, 0, NULL, (LPBYTE) string, &stringLen );

		i++;
	}
	while ( ( err == ERROR_MORE_DATA ) && ( i < 100 ) );

	value = string;

exit:

	if ( string )
	{
		free( string );
	}

	return err;
}
