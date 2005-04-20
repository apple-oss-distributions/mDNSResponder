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
    
$Log: ClassFactory.cpp,v $
Revision 1.2  2004/07/13 21:24:21  rpantos
Fix for <rdar://problem/3701120>.

Revision 1.1  2004/06/18 04:34:59  rpantos
Move to Clients from mDNSWindows

Revision 1.1  2004/01/30 03:01:56  bradley
Explorer Plugin to browse for DNS-SD advertised Web and FTP servers from within Internet Explorer.

*/

#include	"StdAfx.h"

#include	"DebugServices.h"

#include	"ExplorerBar.h"
#include	"ExplorerPlugin.h"

#include	"ClassFactory.h"

// MFC Debugging

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

//===========================================================================================================================
//	ClassFactory
//===========================================================================================================================

ClassFactory::ClassFactory( CLSID inCLSID )
{
	mCLSIDObject 	= inCLSID;
	mRefCount		= 1;
	++gDLLRefCount;
}

//===========================================================================================================================
//	~ClassFactory
//===========================================================================================================================

ClassFactory::~ClassFactory( void )
{
	check( gDLLRefCount > 0 );
	
	--gDLLRefCount;
}

#if 0
#pragma mark -
#pragma mark == IUnknown methods ==
#endif

//===========================================================================================================================
//	QueryInterface
//===========================================================================================================================

STDMETHODIMP	ClassFactory::QueryInterface( REFIID inID, LPVOID *outResult )
{
	HRESULT		err;
	
	check( outResult );
	
	if( IsEqualIID( inID, IID_IUnknown ) )
	{
		*outResult = this;
	}
	else if( IsEqualIID( inID, IID_IClassFactory ) )
	{
		*outResult = (IClassFactory *) this;
	}   
	else
	{
		*outResult = NULL;
		err = E_NOINTERFACE;
		goto exit;
	}
	
	( *( (LPUNKNOWN *) outResult ) )->AddRef();
	err = S_OK;
	
exit:
	return( err );
}                                             

//===========================================================================================================================
//	AddRef
//===========================================================================================================================

STDMETHODIMP_( DWORD )	ClassFactory::AddRef( void )
{
	return( ++mRefCount );
}

//===========================================================================================================================
//	Release
//===========================================================================================================================

STDMETHODIMP_( DWORD )	ClassFactory::Release( void )
{
	DWORD		count;
	
	count = --mRefCount;
	if( count == 0 )
	{
		delete this;
	}
	return( count );
}

#if 0
#pragma mark -
#pragma mark == IClassFactory methods ==
#endif

//===========================================================================================================================
//	CreateInstance
//===========================================================================================================================

STDMETHODIMP	ClassFactory::CreateInstance( LPUNKNOWN inUnknown, REFIID inID, LPVOID *outObject )
{
	HRESULT		err;
	LPVOID		obj;
	
	check( outObject );
	
	obj 		= NULL;
	*outObject 	= NULL;
	require_action( !inUnknown, exit, err = CLASS_E_NOAGGREGATION );
	
	// Create the object based on the CLSID.
	
	if( IsEqualCLSID( mCLSIDObject, CLSID_ExplorerBar ) )
	{
		try
		{
			obj = new ExplorerBar();
		}
		catch( ... )
		{
			// Don't let exception escape.
		}
		require_action( obj, exit, err = E_OUTOFMEMORY );
	}
	else
	{
		err = E_FAIL;
		goto exit;
	}
	
	// Query for the specified interface. Release the factory since QueryInterface retains it.
		
	err = ( (LPUNKNOWN ) obj )->QueryInterface( inID, outObject );
	( (LPUNKNOWN ) obj )->Release();
	
exit:
	return( err );
}

//===========================================================================================================================
//	LockServer
//===========================================================================================================================

STDMETHODIMP	ClassFactory::LockServer( BOOL inLock )
{
	DEBUG_UNUSED( inLock );
	
	return( E_NOTIMPL );
}
