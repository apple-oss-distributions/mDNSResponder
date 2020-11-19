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

#ifndef SYSTEM_UTILITIES_H
#define SYSTEM_UTILITIES_H

#include <stdbool.h>
#include <stdint.h>
#include <os/base.h>

__BEGIN_DECLS
OS_ASSUME_NONNULL_BEGIN

bool IsAppleInternalBuild(void);

OS_CLOSED_ENUM(util_enclosure_color, int,
	util_enclosure_color_none			= 0,	//	No enclosure color available
	util_enclosure_color_rgb			= 1,	//	Enclosure color is rgb value 	"int,int,int"
	util_enclosure_color_index			= 2		//	Enclosure color is index value 	"int"
);

/**
	\brief Get the enclosure color of the current device, if available.

	\param out_str On success, the enclosure color of the current
	 device as a string. On failure, the value is unspecified.

	\param len The available length of out_str.

	\result The util_enclosure_color_t of color string returned.
		\a *out_str.
*/

util_enclosure_color_t
util_get_enclosure_color_str(char * const out_str, uint8_t len, uint8_t *out_size);

OS_ASSUME_NONNULL_END

#endif /* SYSTEM_UTILITIES_H */
