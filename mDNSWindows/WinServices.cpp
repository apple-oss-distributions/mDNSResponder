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
    
$Log: WinServices.cpp,v $
Revision 1.1  2004/06/18 05:23:33  rpantos
First checked in


*/

#include "WinServices.h"


//===========================================================================================================================
//	UTF8StringToStringObject
//===========================================================================================================================

OSStatus	UTF8StringToStringObject( const char *inUTF8, CString &inObject )
{
	OSStatus		err;
	int				n;
	BSTR			unicode;
	
	unicode = NULL;
	
	n = MultiByteToWideChar( CP_UTF8, 0, inUTF8, -1, NULL, 0 );
	if( n > 0 )
	{
		unicode = (BSTR) malloc( (size_t)( n * sizeof( wchar_t ) ) );
		if( !unicode )
		{
			err = ERROR_INSUFFICIENT_BUFFER;
			goto exit;
		}

		n = MultiByteToWideChar( CP_UTF8, 0, inUTF8, -1, unicode, n );
		try
		{
			inObject = unicode;
		}
		catch( ... )
		{
			err = ERROR_NO_UNICODE_TRANSLATION;
			goto exit;
		}
	}
	else
	{
		inObject = "";
	}
	err = ERROR_SUCCESS;
	
exit:
	if( unicode )
	{
		free( unicode );
	}
	return( err );
}
