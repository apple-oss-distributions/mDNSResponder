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

$Log: DNSServiceReg.m,v $
Revision 1.13  2003/08/12 19:55:07  cheshire
Update to APSL 2.0

 */

#import "RegistrationController.h"

#include <DNSServiceDiscovery/DNSServiceDiscovery.h>

void reg_reply (
                int 		errorCode,
                void		*context
                )
{
    // registration reply
    printf("Got a reply from the server with error %d\n", errorCode);
    return;
}

void
MyHandleMachMessage ( CFMachPortRef port, void * msg, CFIndex size, void * info )
{
    DNSServiceDiscovery_handleReply(msg);
}

@implementation RegistrationController

- (void)registerDefaults
{
    NSMutableDictionary *regDict = [NSMutableDictionary dictionary];

    NSArray *typeArray   = [NSArray arrayWithObjects:@"_ftp._tcp.",    @"_ssh._tcp.",  @"_tftp._tcp.",        @"_http._tcp.",      @"_printer._tcp.",  @"_afpovertcp._tcp.",         nil];
    NSArray *nameArray   = [NSArray arrayWithObjects:@"My ftp Server", @"My Computer", @"Testing Boot Image", @"A Web Server",     @"Steve’s Printer", @"Company AppleShare Server", nil];
    NSArray *portArray   = [NSArray arrayWithObjects:@"21",            @"22",          @"69",                 @"80",               @"515",             @"548",                       nil];
    NSArray *domainArray = [NSArray arrayWithObjects:@"",              @"",            @"",                   @"",                 @"",                @"",                          nil];
    NSArray *textArray   = [NSArray arrayWithObjects:@"",              @"",            @"image=mybootimage",  @"path=/index.html", @"rn=lpt1",         @"Vol=Public",                nil];

    [regDict setObject:typeArray forKey:@"SrvTypeKeys"];
    [regDict setObject:nameArray forKey:@"SrvNameKeys"];
    [regDict setObject:portArray forKey:@"SrvPortKeys"];
    [regDict setObject:domainArray forKey:@"SrvDomainKeys"];
    [regDict setObject:textArray forKey:@"SrvTextKeys"];

    [[NSUserDefaults standardUserDefaults] registerDefaults:regDict];
}

- (id)init
{
    srvtypeKeys = [[NSMutableArray array] retain];	//Define arrays for Type, Domain, and Name
    srvnameKeys = [[NSMutableArray array] retain];
    srvportKeys = [[NSMutableArray array] retain];
    srvdomainKeys = [[NSMutableArray array] retain];
    srvtextKeys = [[NSMutableArray array] retain];

    registeredDict = [[NSMutableDictionary alloc] init];
    
    [self registerDefaults];
    return [super init];
}

- (void)awakeFromNib				//BrowserController startup procedure
{
    [srvtypeKeys addObjectsFromArray:[[NSUserDefaults standardUserDefaults] arrayForKey:@"SrvTypeKeys"]];
    [srvnameKeys addObjectsFromArray:[[NSUserDefaults standardUserDefaults] arrayForKey:@"SrvNameKeys"]];
    [srvportKeys addObjectsFromArray:[[NSUserDefaults standardUserDefaults] arrayForKey:@"SrvPortKeys"]];
    [srvdomainKeys addObjectsFromArray:[[NSUserDefaults standardUserDefaults] arrayForKey:@"SrvDomainKeys"]];
    [srvtextKeys addObjectsFromArray:[[NSUserDefaults standardUserDefaults] arrayForKey:@"SrvTextKeys"]];

    [serviceDisplayTable reloadData];				//Reload (redraw) data in fields

}



 - (IBAction)registerService:(id)sender
{
    int selectedRow = [serviceDisplayTable selectedRow];
    CFRunLoopSourceRef	rls;
    uint16_t	registerPort;
    CFMachPortRef           cfMachPort;
    CFMachPortContext       context;
    Boolean                 shouldFreeInfo;
    dns_service_discovery_ref 	dns_client;
    mach_port_t port;

    if (selectedRow < 0) {
        return;
    }

    context.version                 = 1;
    context.info                    = 0;
    context.retain                  = NULL;
    context.release                 = NULL;
    context.copyDescription 	    = NULL;

    registerPort = [[srvportKeys objectAtIndex:selectedRow] intValue];
    
    dns_client = DNSServiceRegistrationCreate
        (
            [[srvnameKeys objectAtIndex:selectedRow] UTF8String],
            [[srvtypeKeys objectAtIndex:selectedRow] UTF8String],
            [[srvdomainKeys objectAtIndex:selectedRow] UTF8String],
            registerPort,
            [[srvtextKeys objectAtIndex:selectedRow] UTF8String],
            reg_reply,
            nil
            );
            
    port = DNSServiceDiscoveryMachPort(dns_client);

    if (port) {

        //printf("port is %d\n", port);

        cfMachPort = CFMachPortCreateWithPort ( kCFAllocatorDefault, port, ( CFMachPortCallBack ) MyHandleMachMessage,&context,&shouldFreeInfo );

        rls = CFMachPortCreateRunLoopSource(NULL, cfMachPort, 0);
        CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
        CFRelease(rls);
        [registeredDict setObject:[NSNumber numberWithUnsignedInt:(unsigned int)dns_client] forKey:[srvtypeKeys objectAtIndex:selectedRow]];
    } else {
        printf("Could not obtain client port\n");
    }

}

- (IBAction)unregisterService:(id)sender
{
    int selectedRow = [serviceDisplayTable selectedRow];
    NSString *key = [srvtypeKeys objectAtIndex:selectedRow];

    NSNumber *refPtr = [registeredDict objectForKey:key];
    dns_service_discovery_ref ref = (dns_service_discovery_ref)[refPtr unsignedIntValue];

    if (ref) {
        DNSServiceDiscoveryDeallocate(ref);
        [registeredDict removeObjectForKey:key];
    }
}

-(void)tableView:(NSTableView *)theTableView setObjectValue:(id)object forTableColumn:(NSTableColumn *)tableColumn row:(int)row
{
    if (row<0) return;
}

- (int)numberOfRowsInTableView:(NSTableView *)theTableView	//Begin mandatory TableView methods
{
    return [srvtypeKeys count];
}

- (id)tableView:(NSTableView *)theTableView objectValueForTableColumn:(NSTableColumn *)theColumn row:(int)rowIndex
{
    if (theColumn == typeColumn) {
        return [srvtypeKeys objectAtIndex:rowIndex];
    }
    if (theColumn == nameColumn) {
        return [srvnameKeys objectAtIndex:rowIndex];
    }
    if (theColumn == portColumn) {
        return [srvportKeys objectAtIndex:rowIndex];
    }
    if (theColumn == domainColumn) {
        return [srvdomainKeys objectAtIndex:rowIndex];
    }
    if (theColumn == textColumn) {
        return [srvtextKeys objectAtIndex:rowIndex];
    }
    
    return(0);
}						//End of mandatory TableView methods

- (IBAction)removeSelected:(id)sender
{
    // remove the selected row and force a refresh

    int selectedRow = [serviceDisplayTable selectedRow];

    if (selectedRow) {

        [srvtypeKeys removeObjectAtIndex:selectedRow];
        [srvnameKeys removeObjectAtIndex:selectedRow];
        [srvportKeys removeObjectAtIndex:selectedRow];
        [srvdomainKeys removeObjectAtIndex:selectedRow];
        [srvtextKeys removeObjectAtIndex:selectedRow];

        [[NSUserDefaults standardUserDefaults] setObject:srvtypeKeys forKey:@"SrvTypeKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvnameKeys forKey:@"SrvNameKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvportKeys forKey:@"SrvPortKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvdomainKeys forKey:@"SrvDomainKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvtextKeys forKey:@"SrvTextKeys"];
        
        [serviceDisplayTable reloadData];
    }
}

- (IBAction)addNewService:(id)sender
{
    // add new entries from the edit fields to the arrays for the defaults

    if ([[serviceTypeField stringValue] length] && [[serviceNameField stringValue] length] && [[serviceDomainField stringValue] length]&& [[servicePortField stringValue] length]) {
        [srvtypeKeys addObject:[serviceTypeField stringValue]];
        [srvnameKeys addObject:[serviceNameField stringValue]];
        [srvportKeys addObject:[servicePortField stringValue]];
        [srvdomainKeys addObject:[serviceDomainField stringValue]];
        [srvtextKeys addObject:[serviceTextField stringValue]];

        [[NSUserDefaults standardUserDefaults] setObject:srvtypeKeys forKey:@"SrvTypeKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvnameKeys forKey:@"SrvNameKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvportKeys forKey:@"SrvPortKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvdomainKeys forKey:@"SrvDomainKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvtextKeys forKey:@"SrvTextKeys"];

        [serviceDisplayTable reloadData];
    } else {
        NSBeep();
    }

}



@end
