/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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
 *
 * This file is a pseudo header file for OSLogCopyFormattedString, which
 * is defined in <os/log_private.h>. this header is used for customized
 * log formatters to declare the symbol, so InstallAPI will not complain
 * about the missing header symbol when it finds the defined
 * OSLogCopyFormattedString in the source code.
 *
 * Set -extra-public-header $(SRCROOT)/pseudo_OSLogCopyFormattedString.h
 * in "Other Text-Based InstallAPI Flags" in Xcode Build Settings to use
 * this header file.
 */

#ifndef __PSEUDO_OS_LOG_COPY_FORMATTED_STRING_H__
#define __PSEUDO_OS_LOG_COPY_FORMATTED_STRING_H__

#include <Foundation/Foundation.h>
#include <os/log_private.h>

NSAttributedString *
OSLogCopyFormattedString(const char *type, id value, os_log_type_info_t info);

#endif // __PSEUDO_OS_LOG_COPY_FORMATTED_STRING_H__
