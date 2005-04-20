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
Revision 1.30  2005/01/27 17:46:16  cheshire
Added comment

Revision 1.29  2004/06/04 20:58:36  cheshire
Move DNSServiceBrowser from mDNSMacOSX directory to Clients directory

Revision 1.28  2004/05/18 23:51:26  cheshire
Tidy up all checkin comments to use consistent "<rdar://problem/xxxxxxx>" format for bug numbers

Revision 1.27  2003/11/19 18:49:48  rpantos
<rdar://problem/3282283>: couple of little tweaks to previous checkin

Revision 1.26  2003/11/07 19:35:20  rpantos
<rdar://problem/3282283>/6: Display multiple IP addresses. Connect using host rather than IP addr.

Revision 1.25  2003/10/29 05:16:54  rpantos
Checkpoint: transition from DNSServiceDiscovery.h to dns_sd.h

Revision 1.24  2003/10/28 02:25:45  rpantos
<rdar://problem/3282283>/9,10: Cancel pending resolve when focus changes or service disappears.

Revision 1.23  2003/10/28 01:29:15  rpantos
<rdar://problem/3282283>/4,5: Restructure a bit to make arrow keys work & views behave better.

Revision 1.22  2003/10/28 01:23:27  rpantos
<rdar://problem/3282283>/11: Bail if mDNS cannot be initialized at startup.

Revision 1.21  2003/10/28 01:19:45  rpantos
<rdar://problem/3282283>/3,11: Do not put a trailing '.' on service names. Handle PATH for HTTP txtRecords.

Revision 1.20  2003/10/28 01:13:49  rpantos
<rdar://problem/3282283>/2: Remove filter when displaying browse results.

Revision 1.19  2003/10/28 01:10:14  rpantos
<rdar://problem/3282283>/1: Change 'compare' to 'caseInsensitiveCompare' to fix sort order.

Revision 1.18  2003/08/12 19:55:07  cheshire
Update to APSL 2.0

 */

#include <arpa/inet.h>
#include <netdb.h>
#include <nameser.h>
#include <sys/select.h>

#import <Cocoa/Cocoa.h>
#import <DNSServiceDiscovery/DNSServiceDiscovery.h>

#include <netinet/in.h>
#include "dns_sd.h"

@class		ServiceController;  // holds state corresponding to outstanding DNSServiceRef

@interface BrowserController : NSObject
{
    IBOutlet id domainField;
    IBOutlet id nameField;
    IBOutlet id typeField;

    IBOutlet id serviceDisplayTable;
    IBOutlet id typeColumn;
    IBOutlet id nameColumn;
    IBOutlet id serviceTypeField;
    IBOutlet id serviceNameField;

    IBOutlet id hostField;
    IBOutlet id ipAddressField;
    IBOutlet id ip6AddressField;
    IBOutlet id portField;
    IBOutlet id textField;
    
    NSMutableArray *srvtypeKeys;
    NSMutableArray *srvnameKeys;
    NSMutableArray *domainKeys;
    NSMutableArray *nameKeys;
    NSString *Domain;
    NSString *SrvType;
    NSString *SrvName;
    NSString *Name;

	ServiceController			*fDomainBrowser;
	ServiceController			*fServiceBrowser;
	ServiceController			*fServiceResolver;
	ServiceController			*fAddressResolver;

}

- (IBAction)handleDomainClick:(id)sender;
- (IBAction)handleNameClick:(id)sender;
- (IBAction)handleTypeClick:(id)sender;
- (void)notifyTypeSelectionChange:(NSNotification*)note;
- (void)notifyNameSelectionChange:(NSNotification*)note;

- (IBAction)connect:(id)sender;

- (IBAction)handleTableClick:(id)sender;
- (IBAction)removeSelected:(id)sender;
- (IBAction)addNewService:(id)sender;

- (IBAction)update:(NSString *)Type Domain:(NSString *)Domain;
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication *)theApplication;
- (IBAction)loadDomains:(id)sender;

- (void)updateBrowseWithResult:(DNSServiceFlags)flags name:(NSString *)name type:(NSString *)resulttype domain:(NSString *)domain;
- (void)updateEnumWithResult:(DNSServiceFlags)flags domain:(NSString *)domain;
- (void)resolveClientWitHost:(NSString *)host port:(uint16_t)port interfaceIndex:(uint32_t)interface txtRecord:(const char*)txtRecord txtLen:(uint16_t)txtLen;
- (void)updateAddress:(uint16_t)rrtype addr:(const void *)buff addrLen:(uint16_t)addrLen 
						host:(const char*) host interfaceIndex:(uint32_t)interface more:(boolean_t)moreToCome;

- (void)_cancelPendingResolve;
- (void)_clearResolvedInfo;

@end

// The ServiceController manages cleanup of DNSServiceRef & runloop info for an outstanding request
@interface ServiceController : NSObject
{
	DNSServiceRef			fServiceRef;
	CFSocketRef				fSocketRef;
	CFRunLoopSourceRef		fRunloopSrc;
}

- (id) initWithServiceRef:(DNSServiceRef) ref;
- (boolean_t) addToCurrentRunLoop;
- (DNSServiceRef) serviceRef;
- (void) dealloc;

@end // interface ServiceController


static void	ProcessSockData( CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info)
// CFRunloop callback that notifies dns_sd when new data appears on a DNSServiceRef's socket.
{
	DNSServiceRef		serviceRef = (DNSServiceRef) info;
	DNSServiceErrorType err = DNSServiceProcessResult( serviceRef);
	if ( err != kDNSServiceErr_NoError)
		printf( "DNSServiceProcessResult() returned an error! %d\n", err);
}

static void DomainEnumReply( DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, 
							DNSServiceErrorType errorCode, const char *replyDomain, void *context )
// Report newly-discovered domains to the BrowserController.
{
	if ( errorCode == kDNSServiceErr_NoError) {
		BrowserController   *pSelf = (BrowserController*) context;
		[pSelf updateEnumWithResult:flags domain:[NSString stringWithUTF8String:replyDomain]];
	} else {
		printf( "DomainEnumReply got an error! %d\n", errorCode);
	}
}

static void	ServiceBrowseReply( DNSServiceRef sdRef, DNSServiceFlags servFlags, uint32_t interfaceIndex, DNSServiceErrorType errorCode, 
								const char *serviceName, const char *regtype, const char *replyDomain, void *context )
// Report newly-discovered services to the BrowserController.
{
	if ( errorCode == kDNSServiceErr_NoError) {
		BrowserController   *pSelf = (BrowserController*) context;
		[pSelf updateBrowseWithResult:servFlags name:[NSString stringWithUTF8String:serviceName] 
								type:[NSString stringWithUTF8String:regtype] domain:[NSString stringWithUTF8String:replyDomain]];
	} else {
		printf( "ServiceBrowseReply got an error! %d\n", errorCode);
	}
}

static void ServiceResolveReply( DNSServiceRef sdRef, DNSServiceFlags flags, uint32_t interfaceIndex, 
								DNSServiceErrorType errorCode, const char *fullname, const char *hosttarget, uint16_t port, 
								uint16_t txtLen, const char *txtRecord, void *context )
// Pass along resolved service info to the BrowserController.
{
	if ( errorCode == kDNSServiceErr_NoError) {
		BrowserController   *pSelf = (BrowserController*) context;
		[pSelf resolveClientWitHost:[NSString stringWithUTF8String:hosttarget] port:port interfaceIndex:interfaceIndex txtRecord:txtRecord txtLen:txtLen];
	} else {
		printf( "ServiceResolveReply got an error! %d\n", errorCode);
	}
}

static void	QueryRecordReply( DNSServiceRef DNSServiceRef, DNSServiceFlags flags, uint32_t interfaceIndex, 
								DNSServiceErrorType errorCode, const char *fullname, uint16_t rrtype, uint16_t rrclass, 
								uint16_t rdlen, const void *rdata, uint32_t ttl, void *context )
// DNSServiceQueryRecord callback used to look up IP addresses.
{
	BrowserController   *pBrowser = (BrowserController*) context;

	[pBrowser updateAddress:rrtype addr:rdata addrLen:rdlen host:fullname interfaceIndex:interfaceIndex 
						more:((flags & kDNSServiceFlagsMoreComing) != 0)];
}


@implementation BrowserController		//Begin implementation of BrowserController methods

- (void)registerDefaults
{
    NSMutableDictionary *regDict = [NSMutableDictionary dictionary];

    NSArray *typeArray = [NSArray arrayWithObjects:@"_ftp._tcp",          @"_tftp._tcp",
												   @"_ssh._tcp",          @"_telnet._tcp",
												   @"_http._tcp",
												   @"_printer._tcp",      @"_ipp._tcp",
												   @"_ichat._tcp",        @"_eppc._tcp",
												   @"_afpovertcp._tcp",   @"_afpovertcp._tcp",   @"_MacOSXDupSuppress._tcp", nil];
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

	fDomainBrowser = nil;
    fServiceBrowser = nil;
	fServiceResolver = nil;
	fAddressResolver = nil;

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
    [typeField sizeLastColumnToFit];    //Set column sizes to use their whole table's width.
    [nameField sizeLastColumnToFit];
    [domainField sizeLastColumnToFit];
//  (self is specified as the NSTableViews' data source in the nib)

    [nameField setDoubleAction:@selector(connect:)];

    // Listen for table selection changes
    [[NSNotificationCenter defaultCenter]   addObserver:self selector:@selector(notifyTypeSelectionChange:) 
                                            name:NSTableViewSelectionDidChangeNotification object:typeField];
    [[NSNotificationCenter defaultCenter]   addObserver:self selector:@selector(notifyNameSelectionChange:) 
                                            name:NSTableViewSelectionDidChangeNotification object:nameField];

    //[srvtypeKeys addObject:@"_ftp._tcp"];	//Add supported protocols and domains to their
    //[srvnameKeys addObject:@"File Transfer (ftp)"];
    //[srvtypeKeys addObject:@"_printer._tcp"];		//respective arrays
    //[srvnameKeys addObject:@"Printer (lpr)"];
    //[srvtypeKeys addObject:@"_http._tcp"];		//respective arrays
    //[srvnameKeys addObject:@"Web Server (http)"];
    //[srvtypeKeys addObject:@"_afp._tcp"];		//respective arrays
    //[srvnameKeys addObject:@"AppleShare Server (afp)"];

	[self _clearResolvedInfo];

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
        return [[nameKeys sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)] objectAtIndex:rowIndex];
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
    // 3282283: No longer used - update happens in notifyTypeSelectionChange
}


- (IBAction)handleDomainClick:(id)sender			//Handle clicks for Domain
{
    int index=[sender selectedRow];				//Find index of selected row
    if (index==-1) return;					//Error checking
    Domain = [domainKeys objectAtIndex:index];			//Save desired Domain

    [self _cancelPendingResolve];

    if (SrvType!=NULL) [self update:SrvType Domain:Domain];	//If Type and Domain are set, update records
}

- (IBAction)handleNameClick:(id)sender				//Handle clicks for Name
{
    // 3282283: No longer used - update happens in notifyNameSelectionChange
}

- (void)notifyTypeSelectionChange:(NSNotification*)note
/* Called when the selection of the Type table changes */
{
    int index=[[note object] selectedRow];  //Find index of selected row
    if (index==-1) return;					//Error checking
    SrvType = [srvtypeKeys objectAtIndex:index];		//Save desired Type
    SrvName = [srvnameKeys objectAtIndex:index];		//Save desired Type

    [self _cancelPendingResolve];

    [self update:SrvType Domain:Domain];		//If Type and Domain are set, update records
}

- (void)notifyNameSelectionChange:(NSNotification*)note
/* Called when the selection of the Name table changes */
{
    int index=[[note object] selectedRow];  //Find index of selected row

    [self _cancelPendingResolve];           // Cancel any pending Resolve for any table selection change

    if (index==-1) {
		Name = nil;		// Name may no longer point to a list member
		return;
	}
    Name=[[nameKeys sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)] objectAtIndex:index];			//Save desired name

	[self _clearResolvedInfo];

	DNSServiceRef		serviceRef;
	DNSServiceErrorType err;
	err = DNSServiceResolve ( &serviceRef, (DNSServiceFlags) 0, 0, (char *)[Name UTF8String], (char *)[SrvType UTF8String], 
							(char *)(Domain?[Domain UTF8String]:""), ServiceResolveReply, self);
	if ( kDNSServiceErr_NoError == err) {
		fServiceResolver = [[ServiceController alloc] initWithServiceRef:serviceRef];
		[fServiceResolver addToCurrentRunLoop];
	}
}

- (IBAction)loadDomains:(id)sender
{
    DNSServiceErrorType err;
	DNSServiceRef		serviceRef;

	err = DNSServiceEnumerateDomains( &serviceRef, kDNSServiceFlagsBrowseDomains, 0, DomainEnumReply, self);
	if ( kDNSServiceErr_NoError == err) {
		fDomainBrowser = [[ServiceController alloc] initWithServiceRef:serviceRef];
		[fDomainBrowser addToCurrentRunLoop];
	}
   else {
        NSAlert *alert = [NSAlert alertWithMessageText:@"Could not connect to mDNSResponder!"
                        defaultButton:@"Quit" alternateButton:nil otherButton:nil informativeTextWithFormat:
                        @"Check to see if mDNSResponder is still running."];
        if ( alert != NULL)
            [alert runModal];
        exit( err);
    }
}

- (IBAction)update:theType Domain:theDomain;		//The Big Kahuna: Fetch PTR records and update application
{
    const char * DomainC;
    const char * TypeC=[theType UTF8String];		//Type in C string format

    DNSServiceErrorType err = kDNSServiceErr_NoError;

    if (theDomain) {
        DomainC = [theDomain UTF8String];	//Domain in C string format
    } else {
        DomainC = "";
    }

    [nameKeys removeAllObjects];	//Get rid of displayed records if we're going to go get new ones
    [nameField reloadData];		//Reload (redraw) names to show the old data is gone

    // get rid of the previous browser if one exists
    if ( fServiceBrowser != nil) {
		[fServiceBrowser release];
        fServiceBrowser = nil;
    }

    // now create a browser to return the values for the nameField ...
	DNSServiceRef		serviceRef;
	err = DNSServiceBrowse( &serviceRef, (DNSServiceFlags) 0, 0, TypeC, DomainC, ServiceBrowseReply, self);
	if ( kDNSServiceErr_NoError == err) {
		fServiceBrowser = [[ServiceController alloc] initWithServiceRef:serviceRef];
		[fServiceBrowser addToCurrentRunLoop];
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

- (void)updateEnumWithResult:(DNSServiceFlags)flags domain:(NSString *)domain
{
    if ( ( flags & kDNSServiceFlagsAdd) != 0) {    // new domain received
        // add the domain to the list
        [domainKeys addObject:domain];
    } else if (!(flags & kDNSServiceFlagsAdd)) {
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

	// Terminate the enumeration once the last domain is delivered.
	if ( ( flags & kDNSServiceFlagsMoreComing) == 0) {
		[fDomainBrowser release];
		fDomainBrowser = nil;
	}

	// At some point, we may want to support a TableView for domain browsing. For now, just pick first domain that comes up.
	if ( Domain == nil)
		Domain = [domain retain];

    return;
}



- (void)updateBrowseWithResult:(DNSServiceFlags)flags name:(NSString *)name type:(NSString *)resulttype domain:(NSString *)domain
{

    //NSLog(@"Received result %@ %@ %@ %d", name, resulttype, domain, type);

    if (!(flags & kDNSServiceFlagsAdd)) {
        if ([nameKeys containsObject:name]) {
            [nameKeys removeObject:name];

            // 3282283: Cancel pending browse if object goes away.
            if ( [name isEqualToString:Name])
                [nameField deselectAll:self];
        }
    }
	else if ( ( flags & kDNSServiceFlagsAdd) != 0) {
        if (![nameKeys containsObject:name]) {
            [nameKeys addObject:name];
        }
    }

    // If not expecting any more data, then reload (redraw) Name TableView with newly found data
    if ((flags & kDNSServiceFlagsMoreComing) == 0)
        [nameField reloadData];
    return;
}

- (void)resolveClientWitHost:(NSString *)host port:(uint16_t)port interfaceIndex:(uint32_t)interface 
							txtRecord:(const char*)txtRecord txtLen:(uint16_t)txtLen
/* Display resolved information about the selected service. */
{
	DNSServiceErrorType err;
	DNSServiceRef		serviceRef;

	// Start an async lookup for IPv4 & IPv6 addresses
	if ( fAddressResolver != nil) {
		[fAddressResolver release];
		fAddressResolver = nil;
	}
	err = DNSServiceQueryRecord( &serviceRef, (DNSServiceFlags) 0, interface, [host UTF8String], 
								ns_t_a, ns_c_in, QueryRecordReply, self);
	if ( err == kDNSServiceErr_NoError) {
		fAddressResolver = [[ServiceController alloc] initWithServiceRef:serviceRef];
		[fAddressResolver addToCurrentRunLoop];
	}

    [hostField setStringValue:host];
    [portField setIntValue:port];

	// kind of a hack: munge txtRecord so it's human-readable
	if ( txtLen > 0) {
		char	*readableText = (char*) malloc( txtLen);
		if ( readableText != nil) {
			ByteCount   index, subStrLen;
			memcpy( readableText, txtRecord, txtLen);
			for ( index=0; index < txtLen - 1; index += subStrLen + 1) {
				subStrLen = readableText[ index];
				readableText[ index] = '\n';
			}
			[textField setStringValue:[NSString stringWithCString:&readableText[1] length:txtLen - 1]];
			free( readableText);
		}
	}
}

- (void)updateAddress:(uint16_t)rrtype  addr:(const void *)buff addrLen:(uint16_t)addrLen 
						host:(const char*) host interfaceIndex:(uint32_t)interface more:(boolean_t)moreToCome
/* Update address field(s) with info obtained by fAddressResolver. */
{
	if ( rrtype == ns_t_a) {		// IPv4
		char	addrBuff[256];
		inet_ntop( AF_INET, buff, addrBuff, sizeof addrBuff);
		strcat( addrBuff, " ");
		[ipAddressField setStringValue:[NSString stringWithFormat:@"%@%s", [ipAddressField stringValue], addrBuff]];

		if ( !moreToCome) {
			[fAddressResolver release];
			fAddressResolver = nil;
	
			// After we find v4 we look for v6
			DNSServiceRef		serviceRef;
			DNSServiceErrorType err;
			err = DNSServiceQueryRecord( &serviceRef, (DNSServiceFlags) 0, interface, host, 
									ns_t_aaaa, ns_c_in, QueryRecordReply, self);
			if ( err == kDNSServiceErr_NoError) {
				fAddressResolver = [[ServiceController alloc] initWithServiceRef:serviceRef];
				[fAddressResolver addToCurrentRunLoop];
			}
		}
	}
	else if ( rrtype == ns_t_aaaa)  // IPv6
	{
		char	addrBuff[256];
		inet_ntop( AF_INET6, buff, addrBuff, sizeof addrBuff);
		strcat( addrBuff, " ");
		[ip6AddressField setStringValue:[NSString stringWithFormat:@"%@%s", [ip6AddressField stringValue], addrBuff]];

		if ( !moreToCome) {
			[fAddressResolver release];
			fAddressResolver = nil;
		}
	}
}


- (void)connect:(id)sender
{
    NSString *host = [hostField stringValue];
    int port = [portField intValue];
    NSString *txtRecord = [textField stringValue];

    if (!txtRecord) txtRecord = @"";

    if (!host || !port) return;

    if ([SrvType isEqualToString:@"_http._tcp"])
    {
        NSString    *pathDelim = @"path=";
		NSRange		where;

        // If the TXT record specifies a path, extract it.
		where = [txtRecord rangeOfString:pathDelim options:NSCaseInsensitiveSearch];
        if ( where.length)
        {
			NSRange		targetRange = { where.location + where.length, [txtRecord length] - where.location - where.length };
			NSRange		endDelim = [txtRecord rangeOfString:@"\n" options:kNilOptions range:targetRange];
			
			if ( endDelim.length)   // if a delimiter was found, truncate the target range
				targetRange.length = endDelim.location - targetRange.location;

            NSString    *path = [txtRecord substringWithRange:targetRange];
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"http://%@:%d%@", host, port, path]]];
        }
        else
            [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"http://%@:%d", host, port]]];
    }
    else if ([SrvType isEqualToString:@"_ftp._tcp"])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"ftp://%@:%d/",    host, port]]];
    else if ([SrvType isEqualToString:@"_tftp._tcp"])       [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"tftp://%@:%d/",   host, port]]];
    else if ([SrvType isEqualToString:@"_ssh._tcp"])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"ssh://%@:%d/",    host, port]]];
    else if ([SrvType isEqualToString:@"_telnet._tcp"])     [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"telnet://%@:%d/", host, port]]];
    else if ([SrvType isEqualToString:@"_printer._tcp"])    [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"lpr://%@:%d/",    host, port]]];
    else if ([SrvType isEqualToString:@"_ipp._tcp"])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"ipp://%@:%d/",    host, port]]];
    else if ([SrvType isEqualToString:@"_afpovertcp._tcp"]) [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"afp://%@:%d/",    host, port]]];
    else if ([SrvType isEqualToString:@"_smb._tcp"])        [[NSWorkspace sharedWorkspace] openURL:[NSURL URLWithString:[NSString stringWithFormat:@"smb://%@:%d/",    host, port]]];

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
    NSString  *newType = [serviceTypeField stringValue];
    NSString  *newName = [serviceNameField stringValue];

    // 3282283: trim trailing '.' from service type field
    if ([newType length] && [newType hasSuffix:@"."])
        newType = [newType substringToIndex:[newType length] - 1];

    if ([newType length] && [newName length]) {
        [srvtypeKeys addObject:newType];
        [srvnameKeys addObject:newName];

        [[NSUserDefaults standardUserDefaults] setObject:srvtypeKeys forKey:@"SrvTypeKeys"];
        [[NSUserDefaults standardUserDefaults] setObject:srvnameKeys forKey:@"SrvNameKeys"];

        [typeField reloadData];
        [serviceDisplayTable reloadData];
    }
}

- (void)_cancelPendingResolve
// If there a a Resolve outstanding, cancel it.
{
	if ( fAddressResolver != nil) {
		[fAddressResolver release];
		fAddressResolver = nil;
	}

	if ( fServiceResolver != nil) {
		[fServiceResolver release];
		fServiceResolver = nil;
	}

	[self _clearResolvedInfo];
}

- (void)_clearResolvedInfo
// Erase the display of resolved info.
{
	[hostField setStringValue:@""];
	[ipAddressField setStringValue:@""];
	[ip6AddressField setStringValue:@""];
	[portField setStringValue:@""];
	[textField setStringValue:@""];
}

@end // implementation BrowserController


@implementation ServiceController : NSObject
{
	DNSServiceRef			fServiceRef;
	CFSocketRef				fSocketRef;
	CFRunLoopSourceRef		fRunloopSrc;
}

- (id) initWithServiceRef:(DNSServiceRef) ref
{
	[super init];
	fServiceRef = ref;
	return self;
}

- (boolean_t) addToCurrentRunLoop
/* Add the service to the current runloop. Returns non-zero on success. */
{
	CFSocketContext			ctx = { 1, (void*) fServiceRef, nil, nil, nil };

	fSocketRef = CFSocketCreateWithNative( kCFAllocatorDefault, DNSServiceRefSockFD( fServiceRef), 
										kCFSocketReadCallBack, ProcessSockData, &ctx);
	if ( fSocketRef != nil)
		fRunloopSrc = CFSocketCreateRunLoopSource( kCFAllocatorDefault, fSocketRef, 1);
	if ( fRunloopSrc != nil)
		CFRunLoopAddSource( CFRunLoopGetCurrent(), fRunloopSrc, kCFRunLoopDefaultMode);
	else
		printf("Could not listen to runloop socket\n");

	return fRunloopSrc != nil;
}

- (DNSServiceRef) serviceRef
{
	return fServiceRef;
}

- (void) dealloc
/* Remove service from runloop, deallocate service and associated resources */
{
	if ( fSocketRef != nil) {
		CFSocketInvalidate( fSocketRef);		// Note: Also closes the underlying socket
		CFRelease( fSocketRef);
	}

	if ( fRunloopSrc != nil) {
		CFRunLoopRemoveSource( CFRunLoopGetCurrent(), fRunloopSrc, kCFRunLoopDefaultMode);
		CFRelease( fRunloopSrc);
	}

	DNSServiceRefDeallocate( fServiceRef);

	[super dealloc];
}

@end // implementation ServiceController

int main(int argc, const char *argv[])
{
    return NSApplicationMain(argc, argv);
}
