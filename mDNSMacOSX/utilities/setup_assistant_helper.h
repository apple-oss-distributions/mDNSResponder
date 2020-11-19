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

#ifndef SETUP_ASSISTANT_HELPER_H
#define SETUP_ASSISTANT_HELPER_H

#include <stdbool.h>
#include <os/base.h>

__BEGIN_DECLS

OS_ASSUME_NONNULL_BEGIN

OS_CLOSED_ENUM(buddy_state, int,
	buddy_state_indeterminate 		= 0,
	buddy_state_in_process			= 1,
	buddy_state_done				= 2
);

static inline const char *
buddy_state_to_string(buddy_state_t state)
{
	switch (state) {
		case buddy_state_indeterminate:	return "indeterminate";
		case buddy_state_in_process:	return "in_process";
		case buddy_state_done:			return "done";
		default:						return "<INVALID STATE>";
	}
}

buddy_state_t
assistant_helper_get_buddy_state(void);

typedef void
(^buddy_done_handler_t)(void);

void
assistant_helper_notify_when_buddy_done(buddy_done_handler_t handler);

OS_ASSUME_NONNULL_END

__END_DECLS

#endif // __ASetupAssistantHelperDotH__
