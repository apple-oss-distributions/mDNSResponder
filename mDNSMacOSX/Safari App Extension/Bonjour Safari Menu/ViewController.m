/*
 *
 * Copyright (c) 2017-2024 Apple Inc. All rights reserved.
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
 */

#import "ViewController.h"

#import <SafariServices/SafariServices.h>
#import <WebKit/WebKit.h>

static NSString * const extensionBundleIdentifier = @"com.apple.mDNSResponder.bonjourmenu.extension";

@interface ViewController () <WKNavigationDelegate, WKScriptMessageHandler>

@property (nonatomic) IBOutlet WKWebView *webView;

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    self.webView.navigationDelegate = self;

    [self.webView.configuration.userContentController addScriptMessageHandler:self name:@"controller"];

    NSURL *load_url = [NSBundle.mainBundle URLForResource:@"Main" withExtension:@"html"];
    NSURL *res_url = NSBundle.mainBundle.resourceURL;
    [self.webView loadFileURL: load_url allowingReadAccessToURL:res_url];
}

- (void)webView:(WKWebView *)webView didFinishNavigation:(WKNavigation *)navigation {
    [SFSafariExtensionManager getStateOfSafariExtensionWithIdentifier:extensionBundleIdentifier completionHandler:^(SFSafariExtensionState *state, NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            if (!state) {
                NSLog(@"Could not get SFSafariExtensionState %@", error);
                return;
            }

            NSString *isExtensionEnabledAsString = state.isEnabled ? @"true" : @"false";
            if (@available(macOS 13, *)) {
                [webView evaluateJavaScript:[NSString stringWithFormat:@"show(%@, true)", isExtensionEnabledAsString] completionHandler:nil];
            } else {
                [webView evaluateJavaScript:[NSString stringWithFormat:@"show(%@, false)", isExtensionEnabledAsString] completionHandler:nil];
            }
        });
    }];
}

- (void)userContentController:(WKUserContentController *)userContentController didReceiveScriptMessage:(WKScriptMessage *)message {
    if (![((NSString *)message.body) isEqualToString:@"open-preferences"])
        return;

    [SFSafariApplication showPreferencesForExtensionWithIdentifier:extensionBundleIdentifier completionHandler:^(NSError *error) {
        dispatch_async(dispatch_get_main_queue(), ^{
            [NSApplication.sharedApplication terminate:nil];
        });
    }];
}

@end
