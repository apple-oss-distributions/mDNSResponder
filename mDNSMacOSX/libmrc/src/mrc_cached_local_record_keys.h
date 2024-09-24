/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
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

#ifndef MRC_CACHED_LOCAL_RECORD_KEY_H
#define MRC_CACHED_LOCAL_RECORD_KEY_H

/*!
 *	@brief
 *		First label of the record name as a string with minimal backslash escape sequences.
 */
#define MRC_CACHED_LOCAL_RECORD_KEY_FIRST_LABEL	"first_label"

/*!
 *	@brief
 *		Record name as a string.
 */
#define MRC_CACHED_LOCAL_RECORD_KEY_NAME	"name"

/*!
 *	@brief
 *		Record RDATA's text representation as a string.
 */
#define MRC_CACHED_LOCAL_RECORD_KEY_RDATA	"rdata"

/*!
 *	@brief
 *		Record's source IPv4 or IPv6 address's text representation as a string.
 */
#define MRC_CACHED_LOCAL_RECORD_KEY_SOURCE_ADDRESS	"source_address"

#endif	// MRC_CACHED_LOCAL_RECORD_KEY_H
