/* srp.h
 *
 * Copyright (c) 2018 Apple Computer, Inc. All rights reserved.
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
 *
 * Service Registration Protocol common definitions
 */

#ifndef __SRP_H
#define __SRP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>
#ifdef POSIX_BUILD
#include <limits.h>
#include <sys/param.h>
#endif
#include "srp-features.h"           // for feature flags

#ifdef __clang__
#define NULLABLE _Nullable
#define NONNULL _Nonnull
#define UNUSED __unused
#else
#define NULLABLE
#define NONNULL
#define UNUSED __attribute__((unused))
#ifdef POSIX_BUILD
#else
#define SRP_CRYPTO_MBEDTLS 1
#endif // POSIX_BUILD
#endif

#define INT64_HEX_STRING_MAX 17     // Maximum size of an int64_t printed as hex, including NUL termination

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-zero-variadic-macro-arguments"
#endif
//======================================================================================================================

#ifdef __clang__
#pragma clang diagnostic pop
#endif

#include "srp-log.h"                // For log functions

#ifdef DEBUG_VERBOSE
#ifdef __clang__
#define FILE_TRIM(x) (strrchr(x, '/') + 1)
#else
#define FILE_TRIM(x) (x)
#endif

#ifdef __clang_analyzer__
#define RELEASE_BASE(x, finalize, file, line) \
    finalize(x)
#else
#define RELEASE_BASE(x, finalize, file, line)                                 \
    do {                                                                      \
        if ((x)->ref_count == 0) {                                            \
            FAULT("ALLOC: release after finalize at %2.2d: %p (%10s): %s:%d", \
                  (x)->ref_count, (void *)(x), # x, FILE_TRIM(file), line);   \
        } else {                                                              \
            INFO("ALLOC: release at %2.2d: %p (%10s): %s:%d",                 \
                 (x)->ref_count, (void *)(x), # x, FILE_TRIM(file), line);    \
            --(x)->ref_count;                                                 \
            if ((x)->ref_count == 0) {                                        \
                INFO("ALLOC:      finalize: %p (%10s): %s:%d",                \
                     (void *)(x), # x, FILE_TRIM(file), line);                \
                finalize(x);                                                  \
            }                                                                 \
        }                                                                     \
    } while (0)
#endif // __clang_analyzer__
#define RETAIN_BASE(x, file, line)                                            \
    do {                                                                      \
        INFO("ALLOC:  retain at %2.2d: %p (%10s): %s:%d",                     \
             (x)->ref_count, (void *)(x), # x, FILE_TRIM(file), line);        \
        ++(x)->ref_count;                                                     \
    } while (0)
#define RELEASE(x, finalize) RELEASE_BASE(x, finalize, file, line)
#define RETAIN(x) RETAIN_BASE(x, file, line)
#define RELEASE_HERE(x, finalize) RELEASE_BASE(x, finalize, __FILE__, __LINE__)
#define RETAIN_HERE(x) RETAIN_BASE(x, __FILE__, __LINE__)
#else
#ifdef __clang_analyzer__
#define RELEASE(x, finalize) finalize(x)
#define RELEASE_HERE(x, finalize) finalize(x)
#define RETAIN(x)
#define RETAIN_HERE(x)
#else
#define RELEASE(x, finalize) do {    \
        if (--(x)->ref_count == 0) { \
            finalize(x);             \
            (void)file; (void)line;  \
        }                            \
    } while (0)
#define RETAIN(x) do {          \
        (x)->ref_count++;       \
        (void)file; (void)line; \
    } while (0)
#define RELEASE_HERE(x, finalize) do {    \
        if (--(x)->ref_count == 0) {      \
            finalize(x);                  \
        }                                 \
    } while (0)
#define RETAIN_HERE(x) ((x)->ref_count++)
#endif
#endif // DEBUG_VERBOSE

#define THREAD_ENTERPRISE_NUMBER ((uint64_t)44970)
#define THREAD_SRP_SERVER_OPTION 0x5d
#define THREAD_PREF_ID_OPTION    0x9d

#define IS_SRP_SERVICE(service) \
    ((cti_service)->enterprise_number == THREAD_ENTERPRISE_NUMBER &&    \
     (cti_service)->service_type == THREAD_SRP_SERVER_OPTION &&         \
     (cti_service)->service_version == 1 &&                             \
     (cti_service)->server_length == 18)
#define IS_PREF_ID_SERVICE(service) \
    ((cti_service)->enterprise_number == THREAD_ENTERPRISE_NUMBER &&    \
     (cti_service)->service_type == THREAD_PREF_ID_OPTION &&            \
     (cti_service)->service_version == 1 &&                             \
     (cti_service)->server_length == 9)

#ifdef MALLOC_DEBUG_LOGGING
void *debug_malloc(size_t len, const char *file, int line);
void *debug_calloc(size_t count, size_t len, const char *file, int line);
char *debug_strdup(const char *s, const char *file, int line);
void debug_free(void *p, const char *file, int line);

#define malloc(x) debug_malloc(x, __FILE__, __LINE__)
#define calloc(c, y) debug_calloc(c, y, __FILE__, __LINE__)
#define strdup(s) debug_strdup(s, __FILE__, __LINE__)
#define free(p) debug_free(p, __FILE__, __LINE__)
#endif

typedef struct srp_key srp_key_t;

/*!
 *  @brief
 *      Check the required condition, if the required condition is not met go to the label specified.
 *
 *  @param ASSERTION
 *      The condition that must be met before continue.
 *
 *  @param EXCEPTION_LABEL
 *      The label to go to when the required condition ASSERTION is not met.
 *
 *  @param ACTION
 *      The extra action to take before go to the EXCEPTION_LABEL label when ASSERTION is not met.
 *
 *  @discussion
 *      Example:
 *      require_action_quiet(
 *          foo == NULL, // required to be true
 *          exit, // if not met goto label
 *          ret = -1;  ERROR("foo should not be NULL") // before exiting
 *      ) ;
 */
#ifndef require_action_quiet
    #define require_action_quiet(ASSERTION, EXCEPTION_LABEL, ACTION)    \
        do {                                                            \
            if (__builtin_expect(!(ASSERTION), 0))                      \
            {                                                           \
                {                                                       \
                    ACTION;                                             \
                }                                                       \
                goto EXCEPTION_LABEL;                                   \
            }                                                           \
        } while(0)
#endif // #ifndef require_action

#ifndef require_quiet
    #define require_quiet(ASSERTION, EXCEPTION_LABEL)                   \
        do {                                                            \
            if (__builtin_expect(!(ASSERTION), 0))                      \
            {                                                           \
                goto EXCEPTION_LABEL;                                   \
            }                                                           \
        } while(0)
#endif // #ifndef require_action

/*!
 *  @brief
 *      Check the required condition, if the required condition is not met go to the label specified.
 *
 *  @param ASSERTION
 *      The condition that must be met before continue.
 *
 *  @param EXCEPTION_LABEL
 *      The label to go to when the required condition ASSERTION is not met.
 *
 *  @param ACTION
 *      The extra action to take before go to the EXCEPTION_LABEL label when ASSERTION is not met.
 *
 *  @discussion
 *      Example:
 *      require_action(
 *          foo == NULL, // required to be true
 *          exit, // if not met goto label
 *          ret = -1;  ERROR("foo should not be NULL") // before exiting
 *      ) ;
 */
#ifndef require_action
    #define require_action(ASSERTION, EXCEPTION_LABEL, ACTION)    \
        do {                                                            \
            if (__builtin_expect(!(ASSERTION), 0))                      \
            {                                                           \
                {                                                       \
                    ACTION;                                             \
                }                                                       \
                goto EXCEPTION_LABEL;                                   \
            }                                                           \
        } while(0)
#endif // #ifndef require_action

/*!
 *  @brief
 *      Check the required condition, if the required condition is not met, do the ACTION. It is usually used as DEBUG macro.
 *
 *  @param ASSERTION
 *      The condition that must be met before continue.
 *
 *  @param ACTION
 *      The extra action to take when ASSERTION is not met.
 *
 *  @discussion
 *      Example:
 *      verify_action(
 *          foo == NULL, // required to be true
 *          ERROR("foo should not be NULL")  // action to take if required is false
 *      ) ;
 */
#undef verify_action
#define verify_action(ASSERTION, ACTION)                                \
    if (__builtin_expect(!(ASSERTION), 0)) {                            \
        ACTION;                                                         \
    }                                                                   \
    else do {} while (0)

#ifdef __cplusplus
} // extern "C"
#endif

#endif // __SRP_H

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
