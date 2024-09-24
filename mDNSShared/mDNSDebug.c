/*
 * Copyright (c) 2003-2024 Apple Inc. All rights reserved.
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

#include <stdio.h>
#include <string.h>

#if defined(WIN32) || defined(EFI32) || defined(EFI64) || defined(EFIX64)
// Need to add Windows/EFI syslog support here
#define LOG_PID 0x01
#define LOG_CONS 0x02
#define LOG_PERROR 0x20
#else
#include <syslog.h>
#endif

#include "mDNSEmbeddedAPI.h"
#include "mdns_strict.h"

mDNSexport int mDNS_LoggingEnabled       = 0;
mDNSexport int mDNS_DebugLoggingEnabled  = 0;
mDNSexport int mDNS_PacketLoggingEnabled = 0;
mDNSexport int mDNS_McastLoggingEnabled  = 0;
mDNSexport int mDNS_McastTracingEnabled  = 0;

#if MDNS_DEBUGMSGS && defined(__APPLE__)
mDNSexport int mDNS_DebugMode = mDNStrue;
#else
mDNSexport int mDNS_DebugMode = mDNSfalse;
#endif

#if MDNSRESPONDER_SUPPORTS(APPLE, LOG_PRIVACY_LEVEL)
mDNSexport int gNumOfSensitiveLoggingEnabledQuestions = 0;
mDNSexport int gSensitiveLoggingEnabled = 0;
#endif

// Note, this uses mDNS_vsnprintf instead of standard "vsnprintf", because mDNS_vsnprintf knows
// how to print special data types like IP addresses and length-prefixed domain names
#if MDNS_DEBUGMSGS > 1
mDNSexport void verbosedebugf_(const char *format, ...)
{
    char buffer[512];
    va_list args;
    va_start(args, format);
    mDNS_vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    mDNSPlatformWriteDebugMsg(buffer);
}
#endif

// Log message with default "mDNSResponder" ident string at the start
#if MDNSRESPONDER_SUPPORTS(APPLE, OS_LOG)
mDNSlocal void LogMsgWithLevelv(os_log_t category, os_log_type_t level, const char *format, va_list args)
{
    char buffer[512];
    mDNS_vsnprintf(buffer, (mDNSu32)sizeof(buffer), format, args);
    os_log_with_type(category ? category : mDNSLogCategory_Default, level, "%{private}s", buffer);
}
#else
mDNSlocal void LogMsgWithLevelv(const char *category, mDNSLogLevel_t level, const char *format, va_list args)
{
    // Do not print the logs if the log category is MDNS_LOG_CATEGORY_DISABLED.
    if (strcmp(category, MDNS_LOG_CATEGORY_DISABLED) == 0)
    {
        return;
    }

    char buffer[512];
    char *dst = buffer;
    const char *const lim = &buffer[512];
    if (category) mDNS_snprintf_add(&dst, lim, "%s: ", category);
    mDNS_vsnprintf(dst, (mDNSu32)(lim - dst), format, args);
    mDNSPlatformWriteLogMsg(ProgramName, buffer, level);
}
#endif

#define LOG_HELPER_BODY(CATEGORY, LEVEL) \
    { \
        va_list args; \
        va_start(args,format); \
        LogMsgWithLevelv(CATEGORY, LEVEL, format, args); \
        va_end(args); \
    }

// see mDNSDebug.h
#if !MDNS_HAS_VA_ARG_MACROS
void LogMsg_(const char *format, ...)       LOG_HELPER_BODY(NULL, MDNS_LOG_DEFAULT)
void LogOperation_(const char *format, ...) LOG_HELPER_BODY(NULL, MDNS_LOG_DEFAULT)
void LogSPS_(const char *format, ...)       LOG_HELPER_BODY(NULL, MDNS_LOG_DEFAULT)
void LogInfo_(const char *format, ...)      LOG_HELPER_BODY(NULL, MDNS_LOG_DEFAULT)
void LogDebug_(const char *format, ...)     LOG_HELPER_BODY(NULL, MDNS_LOG_DEBUG)
#endif

#if MDNS_DEBUGMSGS
void debugf_(const char *format, ...)       LOG_HELPER_BODY(NULL, MDNS_LOG_DEBUG)
#endif

// Log message with default "mDNSResponder" ident string at the start
mDNSexport void LogMsgWithLevel(mDNSLogCategory_t category, mDNSLogLevel_t level, const char *format, ...)
LOG_HELPER_BODY(category, level)

mDNSexport void LogToFD(int fd, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    (void)fd;
    LogMsgWithLevelv(NULL, MDNS_LOG_DEFAULT, format, args);
    va_end(args);
}
