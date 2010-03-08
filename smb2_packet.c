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

static void
smb2_packet_fill_header_sync(struct smb2_packet *p, int cmd)
{
	struct smb2_packet_header_sync *ph;

	// temporary.
	assert(p->p_buf_len == 0);
	ph = (struct smb2_packet_header_sync *)(p->p_buf + p->p_buf_len);
	p->p_buf_len = sizeof(*ph);

	ph->ph_protocol_id = SMB2_PH_PROTOCOL_ID;
	ph->ph_structure_size = SMB2_PH_STRUCTURE_SIZE;
	ph->ph_status = SMB2_STATUS_SUCCESS;
	ph->ph_command = cmd;
	ph->ph_credit_request_response = 126;
	ph->ph_message_id = smb2_connection_next_message_id(p->p_conn);
	ph->ph_process_id = SMB2_PH_PROCESS_ID_NONE;
}

static struct smb2_negotiate_request *
smb2_packet_add_nreq(struct smb2_packet *p)
{
	struct smb2_negotiate_request *nreq;

	smb2_packet_fill_header_sync(p, SMB2_NEGOTIATE);

	nreq = (struct smb2_negotiate_request *)(p->p_buf + p->p_buf_len);
	p->p_buf_len += sizeof(*nreq);
	
	nreq->nreq_structure_size = SMB2_NREQ_STRUCTURE_SIZE;
	nreq->nreq_dialect_count = 1;
	nreq->nreq_security_mode = SMB2_NREQ_NEGOTIATE_SIGNING_ENABLED;
	p->p_buf_len += sizeof(nreq->nreq_dialects[0]);
	nreq->nreq_dialects[0] = 0x0202;

	return (nreq);
}

static struct smb2_session_setup_request *
smb2_packet_add_ssreq(struct smb2_packet *p)
{
	struct smb2_session_setup_request *ssreq;
	void *buf;
	size_t len;

	smb2_packet_fill_header_sync(p, SMB2_SESSION_SETUP);

	ssreq = (struct smb2_session_setup_request *)(p->p_buf + p->p_buf_len);
	/* -1, because size includes one byte of the security buffer. */
	p->p_buf_len += sizeof(*ssreq) - 1;
	
	ssreq->ssreq_structure_size = SMB2_SSREQ_STRUCTURE_SIZE;
	ssreq->ssreq_security_mode = SMB2_SSREQ_NEGOTIATE_SIGNING_ENABLED;

	smb2_spnego_send(p->p_conn, &buf, &len);
	/* -1, because size includes one byte of the security buffer. */
	ssreq->ssreq_security_buffer_offset = SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE - 1;
	memcpy(p->p_buf + ssreq->ssreq_security_buffer_offset, buf, len);
	ssreq->ssreq_security_buffer_length = len;
	p->p_buf_len += len;

	return (ssreq);
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

void
smb2_packet_add_command(struct smb2_packet *p, int cmd)
{

	switch (cmd) {
	case SMB2_NEGOTIATE:
		smb2_packet_add_nreq(p);
		break;
	case SMB2_SESSION_SETUP:
		smb2_packet_add_ssreq(p);
		break;
	default:
		errx(1, "smb2_packet_add_command: unknown command %d", cmd);
	}
}
