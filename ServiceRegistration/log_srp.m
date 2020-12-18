//
//  log_srp.m
//  log_srp
//

#import <CoreUtils/CoreUtils.h>
#import <Foundation/Foundation.h>
#import <os/log_private.h>
#import <arpa/inet.h>
#import "DNSMessage.h"

// Attribute string macro
#define AStr(str) [[NSAttributedString alloc] initWithString:(str)]
#define AStrWithFormat(format, ...) AStr(([[NSString alloc] initWithFormat:format, __VA_ARGS__]))

typedef struct srp_os_log_formatter srp_os_log_formatter_t;
struct srp_os_log_formatter {
	const char * const type;
	NS_RETURNS_RETAINED NSAttributedString *(*function)(id);
};

static NS_RETURNS_RETAINED NSAttributedString *
srp_os_log_copy_formatted_string_ipv6_addr_segment(id value)
{
#define PREFIX_CLASS_MAX_LENGTH 6 // 6 is for <space>(ULA) or <space>(LUA) or <space>(GUA)
	NSData *data;
	const uint8_t * addr_data;
	NSAttributedString * a_str;
	char buf[INET6_ADDRSTRLEN + PREFIX_CLASS_MAX_LENGTH];
	char *delimiter;
	char *ptr;
	char *ptr_limit;
	NSString *ns_str;

	buf[sizeof(buf) - 1] = '\0';

	// The passing data should be NSData type.
	require_action([(NSObject *)value isKindOfClass:[NSData class]], exit,
		a_str = AStrWithFormat(@"<failed to decode - invalid data type: %@>", [(NSObject *)value description]));

	data = (NSData *)value;
	// The passing data must have valid length.
#define IPv6_ADDR_SIZE 16
	require_action(data.bytes != nil && data.length > 0 && data.length <= IPv6_ADDR_SIZE, exit,
		a_str = AStrWithFormat(@"<failed to decode - NIL or invalid data length: %lu>", (unsigned long)data.length));

	addr_data = data.bytes;
	delimiter = "";
	ptr = buf;
	ptr_limit = buf + sizeof(buf);
	for (size_t i = 0; i < data.length; i++) {
        size_t remaining = (size_t)(ptr_limit - ptr);
        int result = snprintf(ptr, remaining, "%s%02x", delimiter, addr_data[i]);
        require_action(result > 0 && result < remaining, exit,
            a_str = AStrWithFormat(@"<failed to decode - snprintf: result: %ld remain: %lu>", i, remaining));
        ptr += result;
		if ((i + 1) % 2 == 0) {
			delimiter = ":";
		} else {
			delimiter = "";
		}
	}

	ns_str = @(buf);
	a_str = AStr(ns_str != nil ? ns_str : nil);
exit:
	return a_str;
}

static NS_RETURNS_RETAINED NSAttributedString *
srp_os_log_copy_formatted_string_domain_name(id value)
{
	NSData *data;
	NSAttributedString *a_str;
	char buf[kDNSServiceMaxDomainName];
	OSStatus ret;
	NSString *ns_str;

	// The passing data should be NSData type.
	require_action([(NSObject *)value isKindOfClass:[NSData class]], exit,
		a_str = AStrWithFormat(@"<failed to decode - invalid data type: %@>", [(NSObject *)value description]));

	data = (NSData *)value;
	// NULL pointer is allowed.
	require_action_quiet(data.bytes != nil, exit, a_str = AStr(@"<null>"));

	// The passing data must have valid length.
	require_action(data.length > 0 && data.length <= kDomainNameLengthMax, exit,
		a_str = AStrWithFormat(@"<failed to decode - NIL or invalid data length: %lu>", (unsigned long)data.length));

	buf[kDNSServiceMaxDomainName - 1] = '\0';
	ret = DomainNameToString((const uint8_t *)data.bytes, ((const uint8_t *) data.bytes) + data.length, buf, NULL);
	require_action(ret == kNoErr, exit, a_str = AStr(@"Malformed Domain Name"));

	ns_str = @(buf);
	a_str = AStr(ns_str != nil ? ns_str : nil);
exit:
	return a_str;
}

static NS_RETURNS_RETAINED NSAttributedString *
srp_os_log_copy_formatted_string_mac_addr(id value)
{
	NSData *data;
	NSAttributedString *a_str;
#define MaxMACAddrStrLen 18 // 17 plus '\0'
	char buf[MaxMACAddrStrLen];
	OSStatus ret;
	NSString *ns_str;
	const uint8_t *mac_addr = NULL;

	buf[MaxMACAddrStrLen - 1] = '\0';

	// The passing data should be NSData type.
	require_action([(NSObject *)value isKindOfClass:[NSData class]], exit,
		a_str = AStrWithFormat(@"<failed to decode - invalid data type: %@>", [(NSObject *)value description]));

	data = (NSData *)value;
#define MACAddressLen 6
	require_action(data.bytes != nil && data.length == MACAddressLen, exit,
		a_str = AStrWithFormat(@"<failed to decode - NIL or invalid data length: %lu>", (unsigned long)data.length));

	mac_addr = (const uint8_t *)data.bytes;
	ret = snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

	require_action(ret > 0, exit, a_str = AStr(@"<failed to decode - MAC address conversion failed>"));

	ns_str = @(buf);
	a_str = AStr(ns_str != nil ? ns_str : nil);
exit:
	return a_str;
}

NS_RETURNS_RETAINED
NSAttributedString *
OSLogCopyFormattedString(const char *type, id value, __unused os_log_type_info_t info)
{
	NSAttributedString *result_str = nil;

	static const srp_os_log_formatter_t formatters[] = {
		{.type = "in6_addr_segment", .function = srp_os_log_copy_formatted_string_ipv6_addr_segment},
		{.type = "domain_name", .function = srp_os_log_copy_formatted_string_domain_name},
		{.type = "mac_addr", .function = srp_os_log_copy_formatted_string_mac_addr},
	};

	for (size_t i = 0; i < countof(formatters); i++) {
		if (strcmp(type, formatters[i].type) != 0) {
			continue;
		}

		result_str = formatters[i].function(value);
		break;
	}

	return result_str;
}
