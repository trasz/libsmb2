/*-
 * Copyright (c) 2010 Edward Tomasz Napierala <trasz@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id$
 */

#include <assert.h>
#include <err.h>
#include <stdlib.h>
#include <string.h>

#include "smb2_connection.h"
#include "smb2_headers.h"
#include "smb2_status.h"
#include "smb2_packet.h"
#include "smb2_spnego.h"

struct smb2_packet_header_sync *
smb2_packet_add_header_sync(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;

	// temporary.
	assert(p->p_buf_len == 0);
	ph = (struct smb2_packet_header_sync *)(p->p_buf + p->p_buf_len);
	p->p_buf_len = sizeof(*ph);

	ph->ph_protocol_id = SMB2_PH_PROTOCOL_ID;
	ph->ph_structure_size = SMB2_PH_STRUCTURE_SIZE;
	ph->ph_status = SMB2_STATUS_SUCCESS;
	ph->ph_credit_request_response = 126;
	ph->ph_message_id = smb2_connection_next_message_id(p->p_conn);
	ph->ph_process_id = SMB2_PH_PROCESS_ID_NONE;

	return (ph);
}

struct smb2_packet_header_sync *
smb2_packet_parse_header(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE) {
		warnx("smb2_parse_packet_header: received packet too small (%d)", p->p_buf_len);
		return (NULL);
	}

	ph = (struct smb2_packet_header_sync *)p->p_buf;

	if (ph->ph_protocol_id != SMB2_PH_PROTOCOL_ID) {
		warnx("smb2_parse_packet_header: invalid protocol id (0x%X)", ph->ph_protocol_id);
		return (NULL);
	}
	if (ph->ph_structure_size != SMB2_PH_STRUCTURE_SIZE) {
		warnx("smb2_parse_packet_header: invalid structure size (%d)", ph->ph_structure_size);
		return (NULL);
	}

	smb2_connection_add_credits(p->p_conn, ph->ph_credit_request_response);
	//printf("credits granted: %d\n", ph->ph_credit_request_response);

	if (ph->ph_status != SMB2_STATUS_SUCCESS && ph->ph_status != SMB2_STATUS_MORE_PROCESSING_REQUIRED) {
		warnx("smb2_parse_packet_header: status not success (%s)", smb2_strstatus(ph->ph_status));
		return (NULL);
	}

	return (ph);
}

struct smb2_packet *
smb2_packet_new(struct smb2_connection *conn)
{
	struct smb2_packet *p;
	
	p = calloc(1, sizeof(*p));
	if (p == NULL)
		err(1, "malloc");

	p->p_conn = conn;

	return (p);
}

void
smb2_packet_delete(struct smb2_packet *p)
{

	free(p);
}

