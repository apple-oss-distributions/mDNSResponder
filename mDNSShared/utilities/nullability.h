/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
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

#ifndef NULLABILITY_H
#define NULLABILITY_H

//======================================================================================================================
// MARK: - Macros

#ifndef NULLABLE
	#ifdef __clang__
		#define NULLABLE _Nullable
		#define NONNULL _Nonnull
		#define UNUSED __unused
	#else
		#define NULLABLE
		#define NONNULL
		#define UNUSED __attribute__((unused))
	#endif
#endif

#endif // NULLABILITY_H
