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

$Log: DNSServiceBrowser.m,v $
Revision 1.18  2003/08/12 19:55:07  cheshire
Update to APSL 2.0

 */

#import "BrowserController.h"

#include "arpa/inet.h"

void
MyHandleMachMessage ( CFMachPortRef port, void * msg, CFIndex size, void * info )
{
    DNSServiceDiscovery_handleReply(msg);
}

void browse_reply (
                   DNSServiceBrowserReplyResultType 	resultType,		// One of DNSServiceBrowserReplyResultType
                   const char  	*replyName,
                   const char  	*replyType,
                   const char  	*replyDomain,
                   DNSServiceDiscoveryReplyFlags 	flags,			// DNS Service Discovery reply flags information
                   void	*context
                   )
{
    [[NSApp delegate] updateBrowseWithResult:resultType name:[NSString stringWithUTF8String:replyName] type:[NSString stringWithUTF8String:replyType] domain:[NSString stringWithUTF8String:replyDomain] flags:flags];
    return;
}

void enum_reply (
                 DNSServiceDomainEnumerationReplyResultType 	resultType,
                 const char  	*replyDomain,
                 DNSServiceDiscoveryReplyFlags 	flags,
                 void	*context
                 )
{
    [[NSApp delegate] updateEnumWithResult:resultType domain:[NSString stringWithUTF8String:replyDomain] flags:flags];

    return;
}

void resolve_reply (
                    struct sockaddr 	*interface,
                    struct sockaddr 	*address,
                    const char 		*txtRecord,
                    DNSServiceDiscoveryReplyFlags 		flags,
                    void		*context
                    )
{
    [[NSApp delegate] resolveClientWithInterface:interface address:address txtRecord:[NSString stringWithUTF8String:txtRecord]];

    return;
}

@implementation BrowserController		//Begin implementation of BrowserController methods

- (void)registerDefaults
{
    NSMutableDictionary *regDict = [NSMutableDictionary dictionary];

    NSArray *typeArray = [NSArray arrayWithObjects:@"_ftp._tcp.",          @"_tftp._tcp.",
												   @"_ssh._tcp.",          @"_telnet._tcp.",
												   @"_http._tcp.",
												   @"_printer._tcp.",      @"_ipp._tcp.",
												   @"_ichat._tcp.",        @"_eppc._tcp.",
												   @"_afpovertcp._tcp.",   @"_afpovertcp._tcp.",   @"_MacOSXDupSuppress._tcp.", nil];
    NSArray *nameArray = [NSArray arrayWithObjects:@"File Transfer (ftp)", @"Trivial File Transfer (tftp)",
	                                               @"Secure Shell (ssh)",  @"Telnet",
	                                               @"Web Server (http)",
	                                               @"LPR Printer",         @"IPP Printer",
												   @"iChat",               @"Remote AppleEvents",
												   @"AppleShare Server",   @"SMB File Server",     @"Mystery Service", nil];

    [regDict setObject:typeArray forKey:@"SrvTypeKeys"];
    [regDict setObject:nameArray forKey:@"SrvNameKeys"];

    [[NSUserDefaults standardUserDefaults] registerDefaults:regDict];
}


- (id)init
{
    [self registerDefaults];

    browse_client = nil;

    return [super init];
}

- (void)awakeFromNib				//BrowserController startup procedure
{
    SrvType=NULL;
    Domain=NULL;
    srvtypeKeys = [NSMutableArray array];	//Define arrays for Type, Domain, and Name
    srvnameKeys = [NSMutableArray array];

    domainKeys = [NSMutableArray array];
    [domainKeys retain];

    nameKeys = [NSMutableArray array];
    [nameKeys retain];

    [srvtypeKeys retain];				//Keep arrays in memory until BrowserController closes
    [srvnameKeys retain];				//Keep arrays in memory until BrowserController closes
    [typeField setDataSource:self];		//Set application fields' data source to BrowserController
    [typeField sizeLastColumnToFit];		//and set column sizes to use their whole table's width.
    [nameField setDataSource:self];
    [nameField sizeLastColumnToFit];
    [domainField setDataSource:self];
    [domainField sizeLastColumnToFit];

    [nameField setDoubleAction:@selector(connect:)];

    //[srvtypeKeys addObject:@"_ftp._tcp."];	//Add supported protocols and domains to their
    //[srvnameKeys addObject:@"File Transfer (ftp)"];
    //[srvtypeKeys addObject:@"_printer._tcp."];		//respective arrays
    //[srvnameKeys addObject:@"Printer (lpr)"];
    //[srvtypeKeys addObject:@"_http._tcp."];		//respective arrays
    //[srvnameKeys addObject:@"Web Server (http)"];
    //[srvtypeKeys addObject:@"_afp._tcp."];		//respective arrays
    //[srvnameKeys addObject:@"AppleShare Server (afp)"];

    [ipAddressField setStringValue:@""];
    [portField setStringValue:@""];
    [textField setStringValue:@""];

    [srvtypeKeys addObjectsFromArray:[[NSUserDefaults standardUserDefaults] arrayForKey:@"SrvTypeKeys"]];
    [srvnameKeys addObjectsFromArray:[[NSUserDefaults standardUserDefaults] arrayForKey:@"SrvNameKeys"]];


    [typeField reloadData];				//Reload (redraw) data in fields
    [domainField reloadData];

    [self loadDomains:self];

}

- (void)dealloc						//Deallocation method
{
    [srvtypeKeys release];
    [srvnameKeys release];
    [nameKeys release];
    [domainKeys release];
}

-(void)tableView:(NSTableView *)theTableView setObjectValue:(id)object forTableColumn:(NSTableColumn *)tableColumn row:(int)row
{
    if (row<0) return;
}

- (int)numberOfRowsInTableView:(NSTableView *)theTableView	//Begin mandatory TableView methods
{
    if (theTableView == typeField)
    {
        return [srvnameKeys count];
    }
    if (theTableView == domainField)
    {
        return [domainKeys count];
    }
    if (theTableView == nameField)
    {
        return [nameKeys count];
    }
    if (theTableView == serviceDisplayTable)
    {
        return [srvnameKeys count];
    }
    return 0;
}

- (id)tableView:(NSTableView *)theTableView objectValueForTableColumn:(NSTableColumn *)theColumn row:(int)rowIndex
{
    if (theTableView == typeField)
    {
        return [srvnameKeys objectAtIndex:rowIndex];
    }
    if (theTableView == domainField)
    {
        return [domainKeys objectAtIndex:rowIndex];
    }
    if (theTableView == nameField)
    {
        return [[nameKeys sortedArrayUsingSelector:@selector(compare:)] objectAtIndex:rowIndex];
    }
    if (theTableView == serviceDisplayTable)
    {
        if (theColumn == typeColumn) {
            return [srvtypeKeys objectAtIndex:rowIndex];
        }
        if (theColumn == nameColumn) {
            return [srvnameKeys objectAtIndex:rowIndex];
        }
        return 0;
    }
    else
        return(0);
}						//End of mandatory TableView methods

- (IBAction)handleTypeClick:(id)sender		//Handle clicks for Type
{
    int index=[sender selectedRow];				//Find index of selected row
    if (index==-1) return;					//Error checking
    SrvType = [srvtypeKeys objectAtIndex:index];		//Save desired Type
    SrvName = [srvnameKeys objectAtIndex:index];		//Save desired Type

    [ipAddressField setStringValue:@""];
    [portField setStringValue:@""];
    [textField setStringValue:@""];

    [self update:SrvType Domain:Domain];		//If Type and Domain are set, update records
}

- (IBAction)handleDomainClick:(id)sender			//Handle clicks for Domain
{
    int index=[sender selectedRow];				//Find index of selected row
    if (index==-1) return;					//Error checking
    Domain = [domainKeys objectAtIndex:index];			//Save desired Domain

    [ipAddressField setStringValue:@""];
    [portField setStringValue:@""];
    [textField setStringValue:@""];

    if (SrvType!=NULL) [self update:SrvType Domain:Domain];	//If Type and Domain are set, update records
}

- (IBAction)handleNameClick:(id)sender				//Handle clicks for Name
{
    int index=[sender selectedRow];				//Find index of selected row
    if (index==-1) return;					//Error checking
    Name=[[nameKeys sortedArrayUsingSelector:@selector(compare:)] objectAtIndex:index];			//Save desired name

    {
        CFMachPortRef           cfMachPort;
        CFMachPortContext       context;
        Boolean                 shouldFreeInfo;
        dns_service_discovery_ref 	dns_client;
        mach_port_t			port;
        CFRunLoopSourceRef		rls;

        context.version                 = 1;
        context.info                    = 0;
        context.retain                  = NULL;
        context.release                 = NULL;
        context.copyDescription 	    = NULL;

		[ipAddressField setStringValue:@"?"];
		[portField setStringValue:@"?"];
		[textField setStringValue:@"?"];
        // start an enumerator on the local server
        dns_client = DNSServiceResolverResolve
            (
             (char *)[Name UTF8String],
             (char *)[SrvType UTF8String],
             (char *)(Domain?[Domain UTF8String]:""),
             resolve_reply,
             nil
             );

        port = DNSServiceDiscoveryMachPort(dns_client);

        if (port) {
            cfMachPort = CFMachPortCreateWithPort ( kCFAllocatorDefault, port, ( CFMachPortCallBack ) MyHandleMachMessage,&context,&shouldFreeInfo );

            /* Create and add a run loop source for the port */
            rls = CFMachPortCreateRunLoopSource(NULL, cfMachPort, 0);
            CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
            CFRelease(rls);
        } else {
            printf("Could not obtain client port\n");
            return;
        }
    }
}

- (IBAction)loadDomains:(id)sender
{
    CFMachPortRef           cfMachPort;
    CFMachPortContext       context;
    Boolean                 shouldFreeInfo;
    dns_service_discovery_ref 	dns_client;
    mach_port_t			port;
    CFRunLoopSourceRef		rls;

    context.version                 = 1;
    context.info                    = 0;
    context.retain                  = NULL;
    context.release                 = NULL;
    context.copyDescription 	    = NULL;

    // start an enumerator on the local server
    dns_client =  DNSServiceDomainEnumerationCreate
        (
         0,
         enum_reply,
         nil
         );

    port = DNSServiceDiscoveryMachPort(dns_client);

    if (port) {
        cfMachPort = CFMachPortCreateWithPort ( kCFAllocatorDefault, port, ( CFMachPortCallBack ) MyHandleMachMessage,&context,&shouldFreeInfo );

        /* Create and add a run loop source for the port */
        rls = CFMachPortCreateRunLoopSource(NULL, cfMachPort, 0);
        CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
        CFRelease(rls);
    } else {
        printf("Could not obtain client port\n");
        return;
    }
}

- (IBAction)update:theType Domain:theDomain;		//The Big Kahuna: Fetch PTR records and update application
{
    const char * DomainC;
    const char * TypeC=[theType UTF8String];		//Type in C string format

    if (theDomain) {
        DomainC = [theDomain UTF8String];	//Domain in C string format
    } else {
        DomainC = "";
    }

    [nameKeys removeAllObjects];	//Get rid of displayed records if we're going to go get new ones
    [nameField reloadData];		//Reload (redraw) names to show the old data is gone

    // get rid of the previous browser if one exists
    if (browse_client) {
        DNSServiceDiscoveryDeallocate(browse_client);
        browse_client = nil;
    }

    // now create a browser to return the values for the nameField ...
    {
        CFMachPortRef           cfMachPort;
        CFMachPortContext       context;
        Boolean                 shouldFreeInfo;
        mach_port_t			port;
        CFRunLoopSourceRef		rls;

        context.version                 = 1;
        context.info                    = 0;
        context.retain                  = NULL;
        context.release                 = NULL;
        context.copyDescription 	    = NULL;

        // start an enumerator on the local server
        browse_client = DNSServiceBrowserCreate
            (
             (char *)TypeC,
             (char *)DomainC,
             browse_reply,
             nil
             );

        port = DNSServiceDiscoveryMachPort(browse_client);

        if (port) {
            cfMachPort = CFMachPortCreateWithPort ( kCFAllocatorDefault, port, ( CFMachPortCallBack ) MyHandleMachMessage,&context,&shouldFreeInfo );

            /* Create and add a run loop source for the port */
            rls = CFMachPortCreateRunLoopSource(NULL, cfMachPort, 0);
            CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
            CFRelease(rls);
        } else {
            printf("Could not obtain client port\n");
            return;
        }
    }

}


- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication //Quit when main window is closed
{
    return YES;
}

- (BOOL)windowShouldClose:(NSWindow *)sender	//Save domains to our domain file when quitting
{
    [domainField reloadData];
    return YES;
}

- (void)updateEnumWithResult:(int)resultType domain:(NSString *)domain flags:(int)flags
{
    // new domain received
    if (DNSServiceDomainEnumerationReplyAddDomain == resultType || DNSServiceDomainEnumerationReplyAddDomainDefault == resultType) {
        // add the domain to the list
        [domainKeys addObject:domain];
    } else {
        // remove the domain from the list
        NSEnumerator *dmnEnum = [domainKeys objectEnumerator];
        NSString *aDomain = nil;

        while (aDomain = [dmnEnum nextObject]) {
            if ([aDomain isEqualToString:domain]) {
                [domainKeys removeObject:domain];
                break;
            }
        }
    }
    // update the domain table
    [domainField reloadData];
    return;
}



- (void)updateBrowseWithResult:(int)type name:(NSString *)name type:(NSString *)resulttype domain:(NSString *)domain flags:(int)flags
{

    //NSLog(@"Received result %@ %@ %@ %d", name, resulttype, domain, type);

    if (([domain isEqualToString:Domain] || [domain isEqualToString:@"local."]) && [resulttype isEqualToString:SrvType]) {

        if (type == DNSServiceBrowserReplyRemoveInstance) {
            if ([nameKeys containsObject:name]) {
                [nameKeys removeObject:name];
            }
        }
        if (type == DNSServiceBrowserReplyAddInstance) {
            if (![nameKeys containsObject:name]) {
                [nameKeys addObject:name];
            }
        }

		// If not expecting any more data, then reload (redraw) Name TableView with newly found data
		if ((flags & kDNSServiceDiscoveryMoreRepliesImmediately) == 0)
			[nameField reloadData];
    }
    return;
}

- (void)resolveClientWithInterface:(struct sockaddr *)interface address:(struct sockaddr *)address txtRecord:(NSString *)txtRecord
{
	if (address->sa_family != AF_INET) return; // For now we only handle IPv4
    //printf("interface length = %d, port = %d, family = %d, address = %s\n", ((struct sockaddr_in *)interface)->sin_len, ((struct sockaddr_in *)interface)->sin_port, ((struct sockaddr_in *)interface)->sin_family, inet_ntoa(((struct in_addr)((struct sockaddr_in *)interface)->sin_addr)));
    //printf("address length = %d, port = %d, family = %d, address = %s\n", ((struct sockaddr_in *)address)->sin_len, ((struct sockaddr_in *)address)->sin_port, ((struct sockaddr_in *)address)->sin_family, inet_ntoa(((struct in_addr)((struct sockaddr_in *)address)->sin_addr)));
    NSString *ipAddr = [NSString stringWithCString:inet_ntoa(((struct in_addr)((struct sockaddr_in *)address)->sin_addr))];
    int port = ((struct sockaddr_in *)address)->sin_port;

    [ipAddressField setStringValue:ipAddr];
    [portField setIntValue:port];
    [textField setStringValue:txtRecord];

    return;
}

- (void)connect:(id)sender
{
    NSString *ipAddr = [ipAddressField stringValue];
    int port = [portField intValue];
    NSString *txtRecord = [textField stringValue];

    if (!txtRecord) txtRecord = @"";

    if (!ipAddr || !port) return;

    if      ([SrvType isEqualToString:@"_ftp._tcp."])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"ftp://%@:%d/",    ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_tftp._tcp."])       [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"tftp://%@:%d/",   ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_ssh._tcp."])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"ssh://%@:%d/",    ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_telnet._tcp."])     [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"telnet://%@:%d/", ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_http._tcp."])       [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"http://%@:%d",    ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_printer._tcp."])    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"lpr://%@:%d/",    ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_ipp._tcp."])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"ipp://%@:%d/",    ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_afpovertcp._tcp."]) [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"afp://%@:%d/",    ipAddr, port]]];
    else if ([SrvType isEqualToString:@"_smb._tcp."])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"smb://%@:%d/",    ipAddr, port]]];

    return;
}

- (IBAction)handleTableClick:(id)sender
{
    //populate the text fields
}

- (IBAction)removeSelected:(id)sender
{
    // remove the selected row and force a refresh

    int selectedRow = [serviceDisplayTable selectedRow];

    if (selectedRow) {

        [srvtypeKeys removeObjectAtIndex:selectedRow];
        [srvnameKeys removeObjectAtIndex:selectedRow];

        [[NSUserDefaults standardUserDefaults] setObject:srvtypeKeys forKey:@"SrvTypeKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvnameKeys forKey:@"SrvNameKeys"];

        [typeField reloadData];
        [serviceDisplayTable reloadData];
    }
}

- (IBAction)addNewService:(id)sender
{
    // add new entries from the edit fields to the arrays for the defaults

    if ([[serviceTypeField stringValue] length] && [[serviceNameField stringValue] length]) {
        [srvtypeKeys addObject:[serviceTypeField stringValue]];
        [srvnameKeys addObject:[serviceNameField stringValue]];

        [[NSUserDefaults standardUserDefaults] setObject:srvtypeKeys forKey:@"SrvTypeKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvnameKeys forKey:@"SrvNameKeys"];

        [typeField reloadData];
        [serviceDisplayTable reloadData];
    }

}



@end