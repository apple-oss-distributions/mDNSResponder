/* -*- Mode: C; tab-width: 4 -*-
 *
 * Copyright (c) 2007 Apple Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.

    Change History (most recent first):

$Log: helpermsg-types.h,v $
Revision 1.2  2007/08/23 21:52:19  cheshire
Added License header

Revision 1.1  2007/08/08 22:34:58  mcguire
<rdar://problem/5197869> Security: Run mDNSResponder as user id mdnsresponder instead of root
 */

#ifndef H_HELPERMSG_TYPES_H
#define H_HELPERMSG_TYPES_H

#include <stdint.h>
typedef uint8_t v6addr_t[16];
typedef uint8_t v4addr_t[4];
typedef const char *string_t;

#endif /* H_HELPERMSG_TYPES_H */
