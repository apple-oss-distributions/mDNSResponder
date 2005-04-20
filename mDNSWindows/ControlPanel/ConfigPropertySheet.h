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

$Log: ConfigPropertySheet.h,v $
Revision 1.4  2005/03/03 19:55:21  shersche
<rdar://problem/4034481> ControlPanel source code isn't saving CVS log info


*/

#ifndef _ConfigPropertySheet_h
#define _ConfigPropertySheet_h

#include "stdafx.h"
#include "FirstPage.h"
#include "SecondPage.h"
#include "ThirdPage.h"

#include <RegNames.h>
#include <dns_sd.h>
#include <list>


//---------------------------------------------------------------------------------------------------------------------------
//	CConfigPropertySheet
//---------------------------------------------------------------------------------------------------------------------------

class CConfigPropertySheet : public CPropertySheet
{
public:

	CConfigPropertySheet();
	virtual ~CConfigPropertySheet();

	typedef std::list<CString> StringList;

	StringList	m_browseDomains;
	StringList	m_regDomains;

protected:

	CFirstPage	m_firstPage;
	CSecondPage	m_secondPage;
	CThirdPage m_thirdPage;

	//{{AFX_VIRTUAL(CConfigPropertySheet)
	//}}AFX_VIRTUAL

	DECLARE_DYNCREATE(CConfigPropertySheet)

	//{{AFX_MSG(CConfigPropertySheet)
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

	afx_msg BOOL	OnInitDialog();
	afx_msg BOOL	OnCommand( WPARAM wParam, LPARAM lParam );
	afx_msg LONG	OnDataReady( WPARAM inWParam, LPARAM inLParam );
	afx_msg LONG	OnRegistryChanged( WPARAM inWParam, LPARAM inLParam );
	void			OnEndDialog();

private:

	OSStatus
	SetupBrowsing();

	OSStatus
	TearDownBrowsing();

	OSStatus
	SetupRegistryNotifications();

	OSStatus
	TearDownRegistryNotifications();

	OSStatus
	DecodeDomainName( const char * raw, CString & decoded );

	const char*
	GetNextLabel( const char * cstr, char label[64] );

	static void DNSSD_API
	BrowseDomainsReply
				(
				DNSServiceRef			sdRef,
				DNSServiceFlags			flags,
				uint32_t				interfaceIndex,
				DNSServiceErrorType		errorCode,
				const char			*	replyDomain,
				void				*	context
				);

	static void DNSSD_API
	RegDomainsReply
				(
				DNSServiceRef			sdRef,
				DNSServiceFlags			flags,
				uint32_t				interfaceIndex,
				DNSServiceErrorType		errorCode,
				const char			*	replyDomain,
				void				*	context
				);

	// This thread will watch for registry changes

	static unsigned WINAPI
	WatchRegistry
				(
				LPVOID inParam
				);

	HKEY				m_statusKey;
	HANDLE				m_thread;
	HANDLE				m_threadExited;
	DNSServiceRef		m_browseDomainsRef;
	DNSServiceRef		m_regDomainsRef;
	CRITICAL_SECTION	m_lock;
};


#endif
