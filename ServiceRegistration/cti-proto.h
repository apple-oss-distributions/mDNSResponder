/* cti-proto.h
 *
 * Copyright (c) 2020 Apple Computer, Inc. All rights reserved.
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
 *
 * CTI protocol definitions
 */

#ifndef __CTI_PROTO_H__
#define __CTI_PROTO_H__
#define CTI_SERVER_SOCKET_NAME "/var/run/cti-server-socket"

#include <stdbool.h>
#include "cti-common.h"

typedef struct cti_buffer cti_buffer_t;
struct cti_buffer {
	size_t expected;
	size_t current;
	size_t size;
	uint8_t *NULLABLE buffer;
};

#ifndef NO_IOLOOP
#ifndef __CTI_SERVICES_H__
typedef union {
	void (*NONNULL callback)(void);
	void (*NONNULL reply)(cti_connection_t NONNULL connection, void *NULLABLE result, int status);
} cti_callback_t;
#endif
typedef void (*cti_internal_callback_t)(cti_connection_t NONNULL conn_ref, void *NULLABLE object, cti_status_t status);
#endif

struct _cti_connection_t {
#ifdef NO_IOLOOP
	cti_connection_t NULLABLE next;
    uint16_t registered_event_flags;
#else
	void *NULLABLE io_context;
	void *NULLABLE context;
	int ref_count;
	cti_callback_t callback;
	cti_internal_callback_t NULLABLE internal_callback;
	uid_t uid;
	gid_t gid;
	pid_t pid;
#endif
	int fd;
	cti_buffer_t input, output;
	size_t message_length;
	uint16_t message_type;
	bool message_valid;
};

typedef void (*cti_datagram_callback_t)(cti_connection_t NONNULL connection);
void cti_connection_finalize(cti_connection_t NONNULL connection);
void cti_connection_close(cti_connection_t NONNULL connection);
#define cti_connection_release(connection) cti_connection_release_(connection, __FILE__, __LINE__)
void cti_connection_release_(cti_connection_t NONNULL connection, const char *NONNULL file, int line);
void dump_to_hex(uint8_t *NONNULL data, size_t length, char *NONNULL buffer, int len);
bool cti_make_space(cti_buffer_t *NONNULL buf, size_t space);
bool cti_connection_begin(cti_connection_t NONNULL connection, size_t space);
bool cti_connection_u64_put(cti_connection_t NONNULL connection, uint64_t val);
bool cti_connection_i32_put(cti_connection_t NONNULL connection, int32_t val);
bool cti_connection_u32_put(cti_connection_t NONNULL connection, uint32_t val);
bool cti_connection_u16_put(cti_connection_t NONNULL connection, uint16_t val);
bool cti_connection_u8_put(cti_connection_t NONNULL connection, uint8_t val);
bool cti_connection_bool_put(cti_connection_t NONNULL connection, bool val);
bool cti_connection_u64_parse(cti_connection_t NONNULL connection, uint64_t *NONNULL val);
bool cti_connection_i32_parse(cti_connection_t NONNULL connection, int32_t *NONNULL val);
bool cti_connection_u32_parse(cti_connection_t NONNULL connection, uint32_t *NONNULL val);
bool cti_connection_u16_parse(cti_connection_t NONNULL connection, uint16_t *NONNULL val);
bool cti_connection_u8_parse(cti_connection_t NONNULL connection, uint8_t *NONNULL val);
bool cti_connection_bool_parse(cti_connection_t NONNULL connection, bool *NONNULL val);
bool cti_connection_data_put(cti_connection_t NONNULL connection, const void *NONNULL data, uint16_t length);
bool cti_connection_string_put(cti_connection_t NONNULL connection, const char *NONNULL data);
bool cti_connection_data_parse(cti_connection_t NONNULL connection,
							   void *NONNULL *NULLABLE data, uint16_t *NONNULL length);
bool cti_connection_string_parse(cti_connection_t NONNULL connection, char *NONNULL *NULLABLE string);
void cti_connection_parse_start(cti_connection_t NONNULL connection);
bool cti_connection_parse_done(cti_connection_t NONNULL connection);
bool cti_connection_message_create(cti_connection_t NONNULL connection, int message_type, uint16_t space);
bool cti_connection_message_send(cti_connection_t NONNULL connection);
bool cti_send_response(cti_connection_t NONNULL connection, int status);
void cti_read(cti_connection_t NONNULL connection, cti_datagram_callback_t NONNULL datagram_callback);
cti_connection_t NULLABLE cti_connection_allocate(uint16_t expected_size);
int cti_make_unix_socket(const char *NONNULL sockname, size_t name_size, bool is_listener);
int cti_accept(int listen_fd, uid_t *NULLABLE p_uid, gid_t *NULLABLE p_gid, pid_t *NULLABLE p_pid);
#endif // __CTI_PROTO_H__
