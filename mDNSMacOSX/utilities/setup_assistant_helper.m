/*
* Copyright (c) 2020 Apple Inc. All rights reserved.
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

#import "setup_assistant_helper.h"

#import <SoftLinking/SoftLinking.h>

#if TARGET_OS_OSX

#import <SetupAssistantFramework/SAUserSetupState.h>
#import <SystemConfiguration/SystemConfiguration.h>

SOFT_LINK_FRAMEWORK(PrivateFrameworks, SetupAssistantFramework)
SOFT_LINK_CLASS(SetupAssistantFramework, SAUserSetupState)

#endif // TARGET_OS_OSX

#if TARGET_OS_OSX
static uid_t s_last_uid = 0;
static void
_update_console_user_id(void)
{
	CFStringRef userName = SCDynamicStoreCopyConsoleUser(NULL, &s_last_uid, NULL);
	if (userName) {
		CFRelease(userName);
	}
}
#endif // TARGET_OS_OSX

buddy_state_t
assistant_helper_get_buddy_state(void)
{
#if TARGET_OS_OSX
	buddy_state_t buddy_state = buddy_state_indeterminate;
	_update_console_user_id();
	SAUserSetupStateEnum state = [SAUserSetupState getSetupStateForUser:s_last_uid];
	switch (state) {
		case SAUserSetupStateSetupDone:
			buddy_state = buddy_state_done;
			break;

		case SAUserSetupStateSetupUser:
		case SAUserSetupStateSetupInProcess:
			buddy_state = buddy_state_in_process;
			break;

		case SAUserSetupStateIndeterminate:
		default:
			buddy_state = buddy_state_indeterminate;
			break;
	}
	return buddy_state;
#else
	return buddy_state_done;
#endif // TARGET_OS_OSX
}

void
assistant_helper_notify_when_buddy_done(buddy_done_handler_t handler)
{
#if TARGET_OS_OSX
    [SAUserSetupState notifyWhenUserIsSetup:s_last_uid withCompletionBlock:handler];
#else
	(void)handler;
#endif // TARGET_OS_OSX
}

