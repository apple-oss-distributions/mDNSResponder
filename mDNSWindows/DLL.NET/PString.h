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

$Log: PString.h,v $
Revision 1.2  2004/07/19 16:08:56  shersche
fix problems in UTF8/Unicode string translations

Revision 1.1  2004/06/26 04:01:22  shersche
Initial revision


 */
    
#pragma once

using namespace System;
using namespace System::Text;

namespace Apple
{
	__gc class PString
	{
	public:

		PString(String* string)
		{
			if (string != NULL)
			{
				Byte unicodeBytes[] = Encoding::Unicode->GetBytes(string);
				Byte utf8Bytes[] = Encoding::Convert(Encoding::Unicode, Encoding::UTF8, unicodeBytes);
				m_p = Marshal::AllocHGlobal(utf8Bytes->Length + 1);
				Byte __pin * p = &utf8Bytes[0];
				char * hBytes = static_cast<char*>(m_p.ToPointer());
				memcpy(hBytes, p, utf8Bytes->Length);
				hBytes[utf8Bytes->Length] = '\0';
			}
			else
			{
				m_p = NULL;
			}
		}

		~PString()
		{
			Marshal::FreeHGlobal(m_p);
		}

		const char*
		c_str()
		{
			if (m_p != NULL)
			{
				return static_cast<const char*>(m_p.ToPointer());
			}
			else
			{
				return NULL;
			}
		}
		
	protected:

		IntPtr m_p;
	};
}
