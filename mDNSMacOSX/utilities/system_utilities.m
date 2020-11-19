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

#import "system_utilities.h"
#import <os/variant_private.h> // os_variant_has_internal_diagnostics
#import <TargetConditionals.h>

#if TARGET_OS_OSX
#import <UniformTypeIdentifiers/UniformTypeIdentifiersPriv.h>
#import <IOKit/platform/IOPlatformSupportPrivate.h>
#endif // TARGET_OS_OSX

bool IsAppleInternalBuild(void)
{
	return (os_variant_has_internal_diagnostics("com.apple.mDNSResponder") != false);
}

#if TARGET_OS_OSX
util_enclosure_color_t
util_get_enclosure_color_str(char * const out_str, uint8_t len, uint8_t *out_size)
{
	util_enclosure_color_t color_type = util_enclosure_color_none;
	if (@available(macOS 11.0, iOS 14.0, watchOS 7.0, tvOS 14.0, *)) {
		UTHardwareColor enclosureColor;
		if (_UTHardwareColorGetCurrentEnclosureColor(&enclosureColor)) {
			switch (enclosureColor.type) {
				case UTHardwareColorTypeRGB: {
					int size = snprintf(out_str, len, "%u,%u,%u",
										enclosureColor.rgb.r, enclosureColor.rgb.g, enclosureColor.rgb.b);
					if (size < len) {
						color_type = util_enclosure_color_rgb;
						*out_size = size;
					}
					break;
				}
				case UTHardwareColorTypeIndexed: {
					int size = snprintf(out_str, len, "%i", enclosureColor.index);
					if (size < len) {
						color_type = util_enclosure_color_index;
						*out_size = size;
					}
					break;
				}
				default:
					*out_size = 0;
					break;
			}
		}
	} else {
		uint8_t   red      = 0;
		uint8_t   green    = 0;
		uint8_t   blue     = 0;

		IOReturn rGetDeviceColor = IOPlatformGetDeviceColor(kIOPlatformDeviceEnclosureColorKey,
																&red, &green, &blue);
		if (kIOReturnSuccess == rGetDeviceColor)
		{
			int size = snprintf(out_str, len, "%u,%u,%u", red, green, blue);
			if (size < len) {
				color_type = util_enclosure_color_rgb;
				*out_size = size;
			}
		}
	}
	return color_type;
}
#else // TARGET_OS_OSX
util_enclosure_color_t
util_get_enclosure_color_str(char * const __unused out_str, uint8_t __unused len, uint8_t * __unused out_size)
{
	return util_enclosure_color_none;
}
#endif // TARGET_OS_OSX
