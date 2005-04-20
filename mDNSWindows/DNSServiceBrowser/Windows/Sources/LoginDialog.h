/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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
    
$Log: LoginDialog.h,v $
Revision 1.1  2004/06/18 04:04:36  rpantos
Move up one level

Revision 1.2  2004/01/30 02:56:32  bradley
Updated to support full Unicode display. Added support for all services on www.dns-sd.org.

Revision 1.1  2003/12/25 03:47:28  bradley
Login dialog to get the username/password from the user.

*/

#ifndef	__LOGIN_DIALOG__
#define	__LOGIN_DIALOG__

#pragma once

#include	"Resource.h"

//===========================================================================================================================
//	LoginDialog
//===========================================================================================================================

class	LoginDialog : public CDialog
{
	protected:
	
		CString		mUsername;
		CString		mPassword;
		
	public:
		
		enum { IDD = IDD_LOGIN };
		
		LoginDialog( CWnd *inParent = NULL );
		
		virtual BOOL	GetLogin( CString &outUsername, CString &outPassword );
	
	protected:

		virtual BOOL	OnInitDialog( void );
		virtual void	DoDataExchange( CDataExchange *inDX );
		virtual void	OnOK( void );
		
		DECLARE_MESSAGE_MAP()
};

#endif	// __LOGIN_DIALOG__
