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

#pragma once

#if defined(_MSC_VER)

// VC++ runtime library equivalents
#define strdup		_strdup
#define strcasecmp	_stricmp
#define strncasecmp	_strnicmp

#ifdef __cplusplus
extern "C" {
#endif

// strlcpy() and strlcat() are non-standard (BSD) APIs. They are safer than strncpy() and strncat()
// (especially the latter) so we implement them for Windows here.
size_t strlcpy( char * dst, const char * src, size_t dstSize );
size_t strlcat( char * dst, const char * src, size_t dstSize );

#ifdef __cplusplus
}
#endif

#endif	// defined(_MSC_VER)
