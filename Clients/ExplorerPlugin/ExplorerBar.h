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
    
$Log: ExplorerBar.h,v $
Revision 1.2  2004/07/13 21:24:21  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.1  2004/06/18 04:34:59  rpantos
Move to Clients from mDNSWindows

Revision 1.1  2004/01/30 03:01:56  bradley
Explorer Plugin to browse for DNS-SD advertised Web and FTP servers from within Internet Explorer.

*/

#ifndef	__EXPLORER_BAR__
#define	__EXPLORER_BAR__

#include	"StdAfx.h"

#include	"ExplorerBarWindow.h"
#include	"ExplorerPlugin.h"

//===========================================================================================================================
//	ExplorerBar
//===========================================================================================================================

class	ExplorerBar : public IDeskBand, 
					  public IInputObject, 
					  public IObjectWithSite, 
					  public IPersistStream,
					  public IContextMenu
{
	protected:

		DWORD					mRefCount;
		IInputObjectSite *		mSite;
		IWebBrowser2 *			mWebBrowser;
		HWND					mParentWindow;
		BOOL					mFocus;
		DWORD					mViewMode;
		DWORD					mBandID;
		ExplorerBarWindow		mWindow;
		
	public:
	
		ExplorerBar( void );
		~ExplorerBar( void );
		
		// IUnknown methods
		
		STDMETHODIMP 			QueryInterface( REFIID inID, LPVOID *outResult );
		STDMETHODIMP_( DWORD )	AddRef( void );
		STDMETHODIMP_( DWORD )	Release( void );
		
		// IOleWindow methods
		
		STDMETHOD( GetWindow )( HWND *outWindow );
		STDMETHOD( ContextSensitiveHelp )( BOOL inEnterMode );

		// IDockingWindow methods
		
		STDMETHOD( ShowDW )( BOOL inShow );
		STDMETHOD( CloseDW )( DWORD inReserved );
		STDMETHOD( ResizeBorderDW )( LPCRECT inBorder, IUnknown *inPunkSite, BOOL inReserved );
		
		// IDeskBand methods
		
		STDMETHOD( GetBandInfo )( DWORD inBandID, DWORD inViewMode, DESKBANDINFO *outInfo );
		
		// IInputObject methods
		
		STDMETHOD( UIActivateIO )( BOOL inActivate, LPMSG inMsg );
		STDMETHOD( HasFocusIO )( void );
		STDMETHOD( TranslateAcceleratorIO )( LPMSG inMsg );
		
		// IObjectWithSite methods
		
		STDMETHOD( SetSite )( IUnknown *inPunkSite );
		STDMETHOD( GetSite )( REFIID inID, LPVOID *outResult );
		
		// IPersistStream methods
		
		STDMETHOD( GetClassID )( LPCLSID outClassID );
		STDMETHOD( IsDirty )( void );
		STDMETHOD( Load )( LPSTREAM inStream );
		STDMETHOD( Save )( LPSTREAM inStream, BOOL inClearDirty );
		STDMETHOD( GetSizeMax )( ULARGE_INTEGER *outSizeMax );
		
		// IContextMenu methods
   
		STDMETHOD( QueryContextMenu )( HMENU hContextMenu, UINT iContextMenuFirstItem, UINT idCmdFirst, UINT idCmdLast, UINT uFlags );
		STDMETHOD( GetCommandString )( UINT idCmd, UINT uType, UINT* pwReserved, LPSTR pszName, UINT cchMax );
		STDMETHOD( InvokeCommand )( LPCMINVOKECOMMANDINFO lpici );

		// Other
		
		OSStatus	SetupWindow( void );
		OSStatus	GoToURL( const CString &inURL );
};

#endif	// __EXPLORER_BAR__
