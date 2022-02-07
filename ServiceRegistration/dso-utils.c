/* dso-utils.c
 *
 * Copyright (c) 2018-2021 Apple Inc. All rights reserved.
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

#include <netinet/in.h>
#include "dns-msg.h"
#include "ioloop.h"
#include "dso-utils.h"
#include "dso.h"

void
dso_simple_response(comm_t *comm, message_t *message, const dns_wire_t *wire, int rcode)
{
    struct iovec iov;
    dns_wire_t response;
    memset(&response, 0, DNS_HEADER_SIZE);

    // We take the ID and the opcode from the incoming message, because if the
    // header has been mangled, we (a) wouldn't have gotten here and (b) don't
    // have any better choice anyway.
    response.id = wire->id;
    dns_qr_set(&response, dns_qr_response);
    dns_opcode_set(&response, dns_opcode_get(wire));
    dns_rcode_set(&response, rcode);
    iov.iov_base = &response;
    iov.iov_len = DNS_HEADER_SIZE; // No RRs
    ioloop_send_message(comm, message, &iov, 1);
}

bool
dso_send_formerr(dso_state_t *dso, const dns_wire_t *header)
{
    comm_t *transport = dso->transport;
    (void)header;
    dso_simple_response(transport, NULL, header, dns_rcode_formerr);
    return true;
}

int32_t
dso_transport_idle(void * UNUSED context, int32_t UNUSED now, int32_t next_event)
{
    return next_event;
}

// Local Variables:
// mode: C
// tab-width: 4
// c-file-style: "bsd"
// c-basic-offset: 4
// fill-column: 108
// indent-tabs-mode: nil
// End:
