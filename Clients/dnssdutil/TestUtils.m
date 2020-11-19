//
//  TestUtils.m
//  mDNSResponder
//
//  Copyright (c) 2019 Apple Inc. All rights reserved.
//

#import "TestUtils.h"

#import <dlfcn.h>
#import <XCTest/XCTest.h>

#if TARGET_OS_OSX
#define XCTest_Framework_Runtime_Path       "/AppleInternal/Developer/Library/Frameworks/XCTest.framework/XCTest"
#else
#define XCTest_Framework_Runtime_Path       "/Developer/Library/Frameworks/XCTest.framework/XCTest"
#endif

//===========================================================================================================================
//    XCTest Utils
//===========================================================================================================================
static bool _load_xctest_framework()
{
    bool loaded = (NSClassFromString(@"XCTestSuite") != nil);
    static void *s_xctest_handle;
    if (!loaded) {
        s_xctest_handle = dlopen(XCTest_Framework_Runtime_Path, RTLD_LAZY | RTLD_LOCAL);
        loaded = (NSClassFromString(@"XCTestSuite") != nil);
        if (!loaded) {
            fprintf(stderr, "%s Failed to load XCTest framework from: %s\n", __FUNCTION__, XCTest_Framework_Runtime_Path);
        }
    }
    return loaded;
}

//===========================================================================================================================
//    Main Test Running
//===========================================================================================================================

bool run_xctest_named(const char *classname)
{
    bool result = false;
    if (_load_xctest_framework()) {
        NSString *name = [NSString stringWithUTF8String:classname];
        NSBundle *testBundle = [NSBundle bundleWithPath:@"/AppleInternal/XCTests/com.apple.mDNSResponder/Tests.xctest"];
        [testBundle load];

        XCTestSuite *compiledSuite = [NSClassFromString(@"XCTestSuite") testSuiteForTestCaseWithName: name];
        if (compiledSuite.tests.count) {
            [compiledSuite runTest];
            XCTestRun *testRun = compiledSuite.testRun;
            result = (testRun.hasSucceeded != NO);
        } else {
            fprintf(stderr, "%s Test class %s not found\n", __FUNCTION__, classname);
        }
    }
    return result;
}

bool audit_token_for_pid(pid_t pid, const audit_token_t *token)
{
    kern_return_t err;
    task_t task;
    mach_msg_type_number_t info_size = TASK_AUDIT_TOKEN_COUNT;

    err = task_for_pid(mach_task_self(), pid, &task);
    if (err != KERN_SUCCESS) {
        return false;
    }

    err = task_info(task, TASK_AUDIT_TOKEN, (integer_t *) token, &info_size);
    if (err != KERN_SUCCESS) {
        return false;
    }

    return true;
}
