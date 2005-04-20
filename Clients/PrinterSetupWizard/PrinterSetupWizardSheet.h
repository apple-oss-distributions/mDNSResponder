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
    
$Log: PrinterSetupWizardSheet.h,v $
Revision 1.8  2005/02/08 18:53:33  shersche
Remove qtotalDefined parameter from ParseTextRecord()

Revision 1.7  2005/01/31 23:54:29  shersche
<rdar://problem/3947508> Start browsing when printer wizard starts. Move browsing logic from CSecondPage object to CPrinterSetupWizardSheet object.

Revision 1.6  2005/01/03 19:05:01  shersche
Store pointer to instance of wizard sheet so that print driver install thread sends a window message to the correct window

Revision 1.5  2004/12/29 18:53:38  shersche
<rdar://problem/3725106>
<rdar://problem/3737413> Added support for LPR and IPP protocols as well as support for obtaining multiple text records. Reorganized and simplified codebase.
Bug #: 3725106, 3737413

Revision 1.4  2004/07/13 21:24:23  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.3  2004/06/28 00:51:47  shersche
Move call to EnumPrinters out of browse callback into standalone function

Revision 1.2  2004/06/24 20:12:07  shersche
Clean up source code
Submitted by: herscher

Revision 1.1  2004/06/18 04:36:57  rpantos
First checked in


*/

#pragma once


#include "firstpage.h"
#include "secondpage.h"
#include "thirdpage.h"
#include "fourthpage.h"
#include "UtilTypes.h"
#include "dns_sd.h"
#include <stdexcept>
#include <map>

using namespace PrinterSetupWizard;

// CPrinterSetupWizardSheet

class CPrinterSetupWizardSheet : public CPropertySheet
{
	DECLARE_DYNAMIC(CPrinterSetupWizardSheet)

public:

	struct WizardException
	{
		CString	text;
		CString	caption;
	};

public:

	CPrinterSetupWizardSheet(UINT nIDCaption, CWnd* pParentWnd = NULL, UINT iSelectPage = 0);
	virtual ~CPrinterSetupWizardSheet();

	void
	SetSelectedPrinter(Printer * printer);

	Printer*
	GetSelectedPrinter();

	OSStatus
	LoadPrinterDriver(const CString & filename);

	HCURSOR
	GetCursor();

	//
	// handles end of process event
	//
	virtual LONG
	OnProcessEvent(WPARAM inWParam, LPARAM inLParam);
	
	virtual LONG
	OnSocketEvent(WPARAM inWParam, LPARAM inLParam);

	virtual BOOL
	OnCommand(WPARAM wParam, LPARAM lParam);

	virtual BOOL
	OnInitDialog();

	virtual BOOL
	OnSetCursor(CWnd * pWnd, UINT nHitTest, UINT message);

	virtual void
	OnContextMenu(CWnd * pWnd, CPoint pos);

	afx_msg void
	OnOK();

	OSStatus
	StartResolve( Printer * printer );

	OSStatus
	StopResolve( Printer * printer );

	Printers				m_printers;

	HCURSOR					m_active;
	HCURSOR					m_arrow;
	HCURSOR					m_wait;

protected:
	DECLARE_MESSAGE_MAP()
	CFirstPage		m_pgFirst;
	CSecondPage		m_pgSecond;
	CThirdPage		m_pgThird;
	CFourthPage		m_pgFourth;

	void
	OnServiceResolved(
		Service				*	service);

	void Init(void);

private:

	static void DNSSD_API
	OnBrowse(
		DNSServiceRef 			inRef,
		DNSServiceFlags 		inFlags,
		uint32_t 				inInterfaceIndex,
		DNSServiceErrorType 	inErrorCode,
		const char *			inName,	
		const char *			inType,	
		const char *			inDomain,	
		void *					inContext );

	static void DNSSD_API
	OnResolve(
		DNSServiceRef			inRef,
		DNSServiceFlags			inFlags,
		uint32_t				inInterfaceIndex,
		DNSServiceErrorType		inErrorCode,
		const char *			inFullName,	
		const char *			inHostName, 
		uint16_t 				inPort,
		uint16_t 				inTXTSize,
		const char *			inTXT,
		void *					inContext );

	static void DNSSD_API
	OnQuery(
		DNSServiceRef			inRef, 
		DNSServiceFlags			inFlags, 
		uint32_t				inInterfaceIndex, 
		DNSServiceErrorType		inErrorCode,
		const char			*	inFullName, 
		uint16_t				inRRType, 
		uint16_t				inRRClass, 
		uint16_t				inRDLen, 
		const void			*	inRData, 
		uint32_t				inTTL, 
		void				*	inContext);

	Printer*
	OnAddPrinter(
		uint32_t 				inInterfaceIndex,
		const char			*	inName,	
		const char			*	inType,	
		const char			*	inDomain,
		bool					moreComing);

	OSStatus
	OnRemovePrinter(
		Printer				*	printer,
		bool					moreComing);

	OSStatus
	OnAddService(
		Printer				*	printer,
		uint32_t 				inInterfaceIndex,
		const char			*	inName,	
		const char			*	inType,	
		const char			*	inDomain);

	OSStatus
	OnRemoveService(
		Service				*	service);

	void
	OnResolveService(
		Service				*	service );

	static bool
	OrderServiceFunc( const Service * a, const Service * b );

	static bool
	OrderQueueFunc( const Queue * q1, const Queue * q2 );

	OSStatus
	StartOperation( DNSServiceRef ref );

	OSStatus
	StopOperation( DNSServiceRef & ref );

	OSStatus
	StartBrowse();

	OSStatus
	StopBrowse();

	OSStatus
	StartResolve( Service * service );

	OSStatus
	StopResolve( Service * service );

	OSStatus
	ParseTextRecord( Service * service, uint16_t inTXTSize, const char * inTXT, CString & qname, uint32_t & qpriority );

	OSStatus
	LoadPrinterNames();

	Printer*
	Lookup( const char * name );

	OSStatus
	InstallPrinter(Printer * printer);

	OSStatus
	InstallPrinterPDLAndLPR(Printer * printer, Service * service, DWORD protocol);

	OSStatus
	InstallPrinterIPP(Printer * printer, Service * service);

	static unsigned WINAPI
	InstallDriverThread( LPVOID inParam );

	typedef std::map<CString,CString>	PrinterNameMap;
	typedef std::list<DNSServiceRef>	ServiceRefList;
	static CPrinterSetupWizardSheet	*	m_self;
	PrinterNameMap						m_printerNames;
	Printer							*	m_selectedPrinter;
	bool								m_driverThreadFinished;
	DWORD								m_driverThreadExitCode;
	ServiceRefList						m_serviceRefList;
	DNSServiceRef						m_pdlBrowser;
	DNSServiceRef						m_lprBrowser;
	DNSServiceRef						m_ippBrowser;
	DNSServiceRef						m_resolver;
};


inline Printer*
CPrinterSetupWizardSheet::GetSelectedPrinter()
{	
	return m_selectedPrinter;
}


inline HCURSOR
CPrinterSetupWizardSheet::GetCursor()
{
	return m_active;
}


// Service Types

#define	kPDLServiceType		"_pdl-datastream._tcp."
#define kLPRServiceType		"_printer._tcp."
#define kIPPServiceType		"_ipp._tcp."
