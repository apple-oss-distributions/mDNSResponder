/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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

$Log: HAAutomounter.m,v $
Revision 1.4  2003/08/12 19:55:08  cheshire
Update to APSL 2.0

 */

#import "HAAutomounter.h"

#import <AppKit/AppKit.h>

#include <sys/types.h>
#include "arpa/inet.h"
#include <netinet/in.h>

@implementation HAAutomounter

- (id)init
{
    self = [super init];

    browser = [[NSNetServiceBrowser alloc] init];

    [browser setDelegate:self];

    [browser searchForServicesOfType:@"_mountme._tcp." inDomain:@""];
    
    [browser scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode: NSDefaultRunLoopMode];

    return self;
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didFindService:(NSNetService *)aNetService moreComing:(BOOL)moreComing
{
    if (resolver) {
        [resolver release];
    }

    resolver = [[NSNetService alloc] initWithDomain:[aNetService domain] type:[aNetService type] name:[aNetService name]];
    [resolver setDelegate:self];
    [resolver scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode: NSDefaultRunLoopMode];

    [resolver resolve];
}


- (void)netServiceDidResolveAddress:(NSNetService *)sender;
{
    if ([[sender addresses] count]) {
    
        // URL mount the volume
        NSData *addr = [[sender addresses] objectAtIndex:0];
        struct sockaddr_in *address = CFDataGetBytePtr((CFDataRef)addr);
        NSString *ipAddr = [NSString stringWithCString:inet_ntoa(((struct in_addr)((struct sockaddr_in *)address)->sin_addr))];
        int port = ((struct sockaddr_in *)address)->sin_port;
        NSArray *txtArray = [[sender protocolSpecificInformation] componentsSeparatedByString:@","];

        if ([txtArray count] == 3) {
            NSString *user = [txtArray objectAtIndex:0];
            NSString *password = [txtArray objectAtIndex:1];
            NSString *share = [txtArray objectAtIndex:2];
    
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"afp://%@:%@@%@:%d/%@", user, password, ipAddr, port, share]]];
        } else {
            NSLog(@"incompatible format for txt record, s/b user,password,share");
        }

    } else {
        NSLog(@"No address %@", sender);
    }
}

- (void)netServiceBrowser:(NSNetServiceBrowser *)aNetServiceBrowser didRemoveService:(NSNetService *)aNetService moreComing:(BOOL)moreComing
{
    // unmount the volume
}


@end
