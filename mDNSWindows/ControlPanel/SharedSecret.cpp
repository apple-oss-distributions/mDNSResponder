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

$Log: SharedSecret.cpp,v $
Revision 1.2  2005/03/03 19:55:22  shersche
<rdar://problem/4034481> ControlPanel source code isn't saving CVS log info


*/

    
// SharedSecret.cpp : implementation file
//

#include "stdafx.h"
#include "SharedSecret.h"

#include <DebugServices.h>
#include <ntsecapi.h>

//---------------------------------------------------------------------------------------------------------------------------
//	Private declarations
//---------------------------------------------------------------------------------------------------------------------------

static BOOL
InitLsaString
			(
			PLSA_UNICODE_STRING	pLsaString,
			LPCWSTR				pwszString
			);

// SharedSecret dialog

IMPLEMENT_DYNAMIC(CSharedSecret, CDialog)


//---------------------------------------------------------------------------------------------------------------------------
//	CSharedSecret::CSharedSecret
//---------------------------------------------------------------------------------------------------------------------------

CSharedSecret::CSharedSecret(CWnd* pParent /*=NULL*/)
	: CDialog(CSharedSecret::IDD, pParent)
	, m_secret(_T(""))
	, m_secretName(_T(""))
{
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSharedSecret::~CSharedSecret
//---------------------------------------------------------------------------------------------------------------------------

CSharedSecret::~CSharedSecret()
{
}


//---------------------------------------------------------------------------------------------------------------------------
//	CSharedSecret::DoDataExchange
//---------------------------------------------------------------------------------------------------------------------------

void CSharedSecret::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_SECRET, m_secret);
	DDX_Text(pDX, IDC_SECRET_NAME, m_secretName);
}


BEGIN_MESSAGE_MAP(CSharedSecret, CDialog)
END_MESSAGE_MAP()



//---------------------------------------------------------------------------------------------------------------------------
//	CSharedSecret::Commit
//---------------------------------------------------------------------------------------------------------------------------

void
CSharedSecret::Commit()
{
	LSA_OBJECT_ATTRIBUTES	attrs;
	LSA_HANDLE				handle = NULL;
	NTSTATUS				res;
	LSA_UNICODE_STRING		lucKeyName;
	LSA_UNICODE_STRING		lucPrivateData;
	BOOL					ok;
	OSStatus				err;

	// If there isn't a trailing dot, add one because the mDNSResponder
	// presents names with the trailing dot.

	if ( m_secretName.ReverseFind( '.' ) != m_secretName.GetLength() )
	{
		m_secretName += '.';
	}

	// attrs are reserved, so initialize to zeroes.

	ZeroMemory(&attrs, sizeof( attrs ) );

	// Get a handle to the Policy object on the local system

	res = LsaOpenPolicy( NULL, &attrs, POLICY_ALL_ACCESS, &handle );
	err = translate_errno( res == 0, LsaNtStatusToWinError( res ), kUnknownErr );
	require_noerr( err, exit );

	// Intializing PLSA_UNICODE_STRING structures

	ok = InitLsaString( &lucKeyName, m_secretName );
	err = translate_errno( ok, errno_compat(), kUnknownErr );
	require_noerr( err, exit );

	ok = InitLsaString( &lucPrivateData, m_secret );
	err = translate_errno( ok, errno_compat(), kUnknownErr );
	require_noerr( err, exit );

	// Store the private data.

	res = LsaStorePrivateData( handle, &lucKeyName, &lucPrivateData );
	err = translate_errno( res == 0, LsaNtStatusToWinError( res ), kUnknownErr );
	require_noerr( err, exit );

exit:

	if ( handle )
	{
		LsaClose( handle );
		handle = NULL;
	}

	return;
}


//---------------------------------------------------------------------------------------------------------------------------
//	InitLsaString
//---------------------------------------------------------------------------------------------------------------------------

static BOOL
InitLsaString
		(
		PLSA_UNICODE_STRING	pLsaString,
		LPCWSTR				pwszString
		)
{
	size_t	dwLen	= 0;
	BOOL	ret		= FALSE;
	
	if ( pLsaString == NULL )
	{
		goto exit;
	}

	if ( pwszString != NULL ) 
	{
		dwLen = wcslen(pwszString);

		// String is too large
		if (dwLen > 0x7ffe)
		{
			goto exit;
		}
	}

	// Store the string.
  
	pLsaString->Buffer			= (WCHAR *) pwszString;
	pLsaString->Length			= (USHORT) dwLen * sizeof(WCHAR);
	pLsaString->MaximumLength	= (USHORT)(dwLen+1) * sizeof(WCHAR);

	ret = TRUE;

exit:

	return ret;
}
