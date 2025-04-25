/* threadsim.h
 *
 * Copyright (c) 2023-2024 Apple Inc. All rights reserved.
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
 *
 * Thread network data simulator entry points.
 */

typedef struct threadsim_network_state threadsim_network_state_t;
typedef struct threadsim_node_state threadsim_node_state_t;
threadsim_network_state_t *NULLABLE threadsim_network_state_create(void);
threadsim_node_state_t *NULLABLE threadsim_node_state_create(threadsim_network_state_t *NONNULL network,
															 srp_server_t *NONNULL server,
															 cti_network_state_t network_state,
															 cti_network_node_type_t role);

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
