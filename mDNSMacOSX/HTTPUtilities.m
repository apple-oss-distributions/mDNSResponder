/*
 * Copyright (c) 2019-2020 Apple Inc. All rights reserved.
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

#import <TargetConditionals.h>

// _createDispatchData in NSData_Private.h requires either
// DEPLOYMENT_TARGET_EMBEDDED or DEPLOYMENT_TARGET_MACOSX.
// We define them here, rather than in our project file.

#if TARGET_OS_IPHONE
// DEPLOYMENT_TARGET_EMBEDDED covers both embedded and simulator
#  ifndef DEPLOYMENT_TARGET_EMBEDDED
#    define DEPLOYMENT_TARGET_EMBEDDED 1
#  endif // DEPLOYMENT_TARGET_EMBEDDED
#else // TARGET_OS_IPHONE
#  ifndef DEPLOYMENT_TARGET_MACOSX
#    define DEPLOYMENT_TARGET_MACOSX 1
#  endif // DEPLOYMENT_TARGET_MACOSX
#endif // TARGET_OS_IPHONE

#import <Foundation/NSData_Private.h>
#import <CFNetwork/CFNSURLConnection.h>
#import <nw/private.h>

#import "mdns_symptoms.h"
#import "DNSMessage.h"
#import "HTTPUtilities.h"
#import <CoreFoundation/CFXPCBridge.h>
#import "DNSHeuristics.h"
#import <Foundation/Foundation.h>
#import <os/log.h>

static NSURLSession *
shared_session(dispatch_queue_t queue)
{
	static NSURLSession *session = nil;
	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		@autoreleasepool {
			// Disable AppSSO (process-wide) before any use of URLSession
			[NSURLSession _disableAppSSO];

			// Create (and configure) the NSURLSessionConfiguration
			NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration ephemeralSessionConfiguration];

			// Disable HTTP Cookies
			configuration.HTTPCookieStorage = nil;

			// Disable HTTP Cache
			configuration.URLCache = nil;

			// Disable Credential Storage
			configuration.URLCredentialStorage = nil;

			if (@available(macOS 10.16, iOS 14.0, watchOS 7.0, tvOS 14.0, *)) {
				// Disable ATS (process-wide) before any use of URLSession
				[NSURLSession _disableATS];

				// Disable reachability lookups
				configuration._allowsReachabilityCheck = NO;
			}

			configuration._suppressedAutoAddedHTTPHeaders = [NSSet setWithObjects:@"User-Agent", nil];
			configuration._allowsTLSSessionTickets = YES;
			configuration._allowsTCPFastOpen = YES;

			NSOperationQueue *operationQueue = [[NSOperationQueue alloc] init];
			operationQueue.underlyingQueue = queue;
			session = [NSURLSession sessionWithConfiguration:configuration
													delegate:nil
											   delegateQueue:operationQueue];
		}
	});
	return session;
}

CFStringRef
create_base64_string(dispatch_data_t message)
{
	@autoreleasepool {
		NSString *base64String = [((NSData *)message) base64EncodedStringWithOptions:0];
		base64String = [base64String stringByReplacingOccurrencesOfString:@"/"
																withString:@"_"];
		base64String = [base64String stringByReplacingOccurrencesOfString:@"+"
															   withString:@"-"];
		return (__bridge_retained CFStringRef)base64String;
	}
}

void
http_set_resolver_queue(dispatch_queue_t queue)
{
	@autoreleasepool {
		// Set up session
		(void)shared_session(queue);
	}
}

void *
http_task_create_dns_query(nw_endpoint_t endpoint, const char *urlString, dispatch_data_t message, uint16_t query_type, bool use_post, http_task_dns_query_response_handler_t response_handler)
{
	@autoreleasepool {
		NSURLSession *session = shared_session(nil);
		NSMutableURLRequest *request = nil;
		if (use_post) {
			request = [[NSMutableURLRequest alloc] initWithURL:(NSURL *)[[NSURL alloc] initWithString:(NSString *)@(urlString)]];
			request.HTTPMethod = @"POST";
			request.HTTPBody = (NSData *)message;
		} else {
			NSString *base64String = [((NSData *)message) base64EncodedStringWithOptions:0];
			base64String = [base64String stringByReplacingOccurrencesOfString:@"/"
																	withString:@"_"];
			base64String = [base64String stringByReplacingOccurrencesOfString:@"+"
																   withString:@"-"];
			base64String = [base64String stringByReplacingOccurrencesOfString:@"="
																   withString:@""];
			NSString *urlWithQuery = [NSString stringWithFormat:@"%s?dns=%@", urlString, base64String];
			request = [[NSMutableURLRequest alloc] initWithURL:(NSURL *)[[NSURL alloc] initWithString:urlWithQuery]];
			request.HTTPMethod = @"GET";
		}
		[request setValue:@"application/dns-message" forHTTPHeaderField:@"accept"];
		[request setValue:@"application/dns-message" forHTTPHeaderField:@"content-type"];

		__block nw_activity_t activity = nil;
		switch (query_type) {
			case kDNSRecordType_A: {
				activity = nw_activity_create(kDNSActivityDomain, kDNSActivityLabelUnicastAQuery);
				break;
			}
			case kDNSRecordType_AAAA: {
				activity = nw_activity_create(kDNSActivityDomain, kDNSActivityLabelUnicastAAAAQuery);
				break;
			}
			default: {
				// Don't mark any activity for non-address queries.
				break;
			}
		}

		if (activity != nil) {
			nw_activity_activate(activity);
		}

		NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request
		completionHandler:^(NSData *data,
							__unused NSURLResponse *response,
							NSError *error) {
			if (activity != nil) {
				if (error != nil) {
					nw_activity_complete_with_reason(activity, nw_activity_completion_reason_failure);
				} else {
					nw_activity_complete_with_reason(activity, nw_activity_completion_reason_success);
				}
			}

			if (error != nil) {
				// If we did not receive a response from the server, report a failure.
				// Any HTTP response, even one with a 50x failure, will yield a nil error.
				// Any other error, such as a TCP-level or TLS-level failure, will manifest
				// in a non-nil error. We only care about non-HTTP errors here.

				// Some NSURLSession errors are also ignored here, such as when a task
				// is cancelled (a common occurrence due to the client behavior) or the
				// connection failed due to no network.
				const bool errorIsWhitelisted = ([error.domain isEqualToString:NSURLErrorDomain] &&
												 (error.code == NSURLErrorCancelled ||
												  error.code == NSURLErrorNotConnectedToInternet));
				const bool errorIsTimeout = ([error.domain isEqualToString:NSURLErrorDomain] &&
											 error.code == NSURLErrorTimedOut);
				if (!errorIsWhitelisted) {
					dns_heuristics_report_resolution_failure([request URL], errorIsTimeout);
				}
			} else {
				dns_heuristics_report_resolution_success();
			}

			dispatch_data_t dispatch_data = [data _createDispatchData];
			response_handler(dispatch_data, (__bridge CFErrorRef)error);
		}];

		if (@available(macOS 10.16, iOS 14.0, watchOS 7.0, tvOS 14.0, *)) {
			dataTask._hostOverride = endpoint;
		}

		if (dataTask && activity != nil) {
			dataTask._nw_activity = activity;
		}

		return (__bridge_retained void *)dataTask;
	}
}

void *
http_task_create_pvd_query(dispatch_queue_t queue, const char *host, const char *path, void (^response_handler)(xpc_object_t json_object))
{
	@autoreleasepool {
		NSURLSession *session = shared_session(nil);
		NSString *pvdURL = [NSString stringWithFormat:@"https://%s/.well-known/pvd%s", host, path];
		NSMutableURLRequest *request = [[NSMutableURLRequest alloc] initWithURL:(NSURL *)[[NSURL alloc] initWithString:pvdURL]];
		request.HTTPMethod = @"GET";
		[request setValue:@"application/pvd+json" forHTTPHeaderField:@"accept"];
		[request setValue:@"application/pvd+json" forHTTPHeaderField:@"content-type"];

		__block nw_activity_t activity = nw_activity_create(kDNSActivityDomain, kDNSActivityLabelProvisioningRequest);
		if (activity != nil) {
			nw_activity_activate(activity);
		}

		NSURLSessionDataTask *dataTask = [session dataTaskWithRequest:request
		completionHandler:^(NSData *data,
							__unused NSURLResponse *response,
							__unused NSError *error) {
			dispatch_async(queue, ^{
				if (data == nil) {
					nw_activity_complete_with_reason(activity, nw_activity_completion_reason_failure);
					response_handler(nil);
				} else {
					NSDictionary *dictionary = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:nil];
					if ([dictionary isKindOfClass:[NSDictionary class]]) {
						xpc_object_t xpc_dictionary = _CFXPCCreateXPCObjectFromCFObject((__bridge CFDictionaryRef)dictionary);

						// Convert "expires" to "seconds-remaining"
						NSString *expires = dictionary[@"expires"];
						NSNumber *secondsRemaining = dictionary[@"seconds-remaining"];

						if (xpc_dictionary != nil &&
							[expires isKindOfClass:[NSString class]] && secondsRemaining == nil) {
							NSDateFormatter *dateFormatter = [[NSDateFormatter alloc] init];
							[dateFormatter setTimeZone:[NSTimeZone timeZoneForSecondsFromGMT:0]];
							[dateFormatter setLocale:[NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"]];
							[dateFormatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ss'Z'"];
							[dateFormatter setFormatterBehavior:NSDateFormatterBehaviorDefault];

							NSDate *date = [dateFormatter dateFromString:expires];

							NSTimeInterval secondsFromNowFloat = date.timeIntervalSinceNow;
							uint64_t secondsFromNow = (uint64_t)secondsFromNowFloat;

							xpc_dictionary_set_uint64(xpc_dictionary, "seconds-remaining", secondsFromNow);
						} else if (xpc_dictionary != nil && secondsRemaining != nil) {
							uint64_t secondsFromNow = (uint64_t)secondsRemaining.unsignedLongLongValue;
							xpc_dictionary_set_uint64(xpc_dictionary, "seconds-remaining", secondsFromNow);
						}

						nw_activity_complete_with_reason(activity, nw_activity_completion_reason_success);
						response_handler(xpc_dictionary);
					} else {
						nw_activity_complete_with_reason(activity, nw_activity_completion_reason_failure);
						response_handler(nil);
					}
				}
			});
		}];

		if (dataTask && activity != nil) {
			dataTask._nw_activity = nw_activity_create(kDNSActivityDomain, kDNSActivityLabelProvisioningRequest);
		}

		return (__bridge_retained void *)dataTask;
	}
}

void
http_task_start(void *task)
{
	@autoreleasepool {
		NSURLSessionDataTask *dataTask = (__bridge NSURLSessionDataTask *)task;
		[dataTask resume];
	}
}

void
http_task_cancel(void *task)
{
	@autoreleasepool {
		NSURLSessionDataTask *dataTask = (__bridge_transfer NSURLSessionDataTask *)task;
		[dataTask cancel];
		dataTask = nil;
	}
}
