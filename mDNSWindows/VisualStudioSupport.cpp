/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "VisualStudioSupport.h"

#include <stdio.h>
#include <string.h>

// strlcpy
// - this implementation is taken directly from the OS X sources
//
size_t strlcpy( char * dst, const char * src, size_t dstSize )
{
	// This function returns the size of the string it _tried_ to create so that
	// callers can check for overflow themselves.  That's just the way it's defined.
	size_t		len = strlen(src);

	if (len < dstSize)
	{
		memcpy(dst, src, len + 1);
	}
	else if (dstSize != 0)
	{
		memcpy(dst, src, dstSize - 1);
		dst[dstSize - 1] = '\0';
	}

	return len;
}

// strlcat
// - this implementation is taken directly from the OS X sources
//
size_t strlcat( char * dst, const char * src, size_t dstSize )
{
	// This function returns the size of the string it _tried_ to create so that
	// callers can check for overflow themselves.  That's just the way it's defined.
	size_t		srcLen = strlen(src);
	size_t		dstLen = strnlen(dst, dstSize);

	if (dstLen == dstSize)
		return (dstSize + srcLen);

	if (srcLen < (dstSize - dstLen))
	{
		memcpy(dst + dstLen, src, srcLen + 1);
	}
	else
	{
		memcpy(dst + dstLen, src, dstSize - dstLen - 1);
		dst[dstSize - 1] = '\0';
	}

	return (dstLen + srcLen);
}
