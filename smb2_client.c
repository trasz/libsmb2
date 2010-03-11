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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <err.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smb2_client.h"
#include "smb2_connection.h"
#include "smb2_headers.h"
#include "smb2_spnego.h"
#include "smb2_tcp.h"

static struct smb2_negotiate_request *
smb2_packet_add_nreq(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;
	struct smb2_negotiate_request *nreq;

	ph = smb2_packet_add_header_sync(p);
	ph->ph_command = SMB2_NEGOTIATE;

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
	struct smb2_packet_header_sync *ph;
	struct smb2_session_setup_request *ssreq;
	void *buf;
	size_t len;

	ph = smb2_packet_add_header_sync(p);
	ph->ph_command = SMB2_SESSION_SETUP;

	ssreq = (struct smb2_session_setup_request *)(p->p_buf + p->p_buf_len);
	/* -1, because size includes one byte of the security buffer. */
	p->p_buf_len += sizeof(*ssreq) - 1;
	
	ssreq->ssreq_structure_size = SMB2_SSREQ_STRUCTURE_SIZE;
	ssreq->ssreq_security_mode = SMB2_SSREQ_NEGOTIATE_SIGNING_ENABLED;

	smb2_spnego_make_neg_token_init(p->p_conn, &buf, &len);
	/* -1, because size includes one byte of the security buffer. */
	ssreq->ssreq_security_buffer_offset = SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE - 1;
	memcpy(p->p_buf + ssreq->ssreq_security_buffer_offset, buf, len);
	ssreq->ssreq_security_buffer_length = len;
	p->p_buf_len += len;

	return (ssreq);
}

static void
smb2_client_add_command(struct smb2_packet *p, int cmd)
{

	switch (cmd) {
	case SMB2_NEGOTIATE:
		smb2_packet_add_nreq(p);
		break;
	case SMB2_SESSION_SETUP:
		smb2_packet_add_ssreq(p);
		break;
	default:
		errx(1, "smb2_client_add_command: unknown command %d", cmd);
	}
}

static void
smb2_parse_nres(struct smb2_packet *p)
{
	struct smb2_negotiate_response *nres;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE)
		errx(1, "smb2_parse_nres: received packet too small (%d)", p->p_buf_len);

	nres = (struct smb2_negotiate_response *)(p->p_buf + SMB2_PH_STRUCTURE_SIZE);

	/*
	 * -1, because SMB2_NRES_STRUCTURE_SIZE includes one byte of the buffer.
	 */
	if (nres->nres_security_buffer_offset != SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE - 1)
		errx(1, "smb2_parse_nres: weird security buffer offset, is %d, should be %d",
		    nres->nres_security_buffer_offset, SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE);

	if (nres->nres_security_buffer_offset + nres->nres_security_buffer_length > p->p_buf_len)
		errx(1, "smb2_parse_nres: security buffer (%d) longer than packet (%d)", nres->nres_security_buffer_length, p->p_buf_len);

	smb2_spnego_take_neg_token_init_2(p->p_conn, p->p_buf + nres->nres_security_buffer_offset, nres->nres_security_buffer_length);
}

static void
smb2_parse_ssres(struct smb2_packet *p)
{
	struct smb2_session_setup_response *ssres;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_SSRES_STRUCTURE_SIZE)
		errx(1, "smb2_parse_ssres: received packet too small (%d)", p->p_buf_len);

	ssres = (struct smb2_session_setup_response *)(p->p_buf + SMB2_PH_STRUCTURE_SIZE);

	/*
	 * -1, because SMB2_SSRES_STRUCTURE_SIZE includes one byte of the buffer.
	 */
	if (ssres->ssres_security_buffer_offset != SMB2_PH_STRUCTURE_SIZE + SMB2_SSRES_STRUCTURE_SIZE - 1)
		errx(1, "smb2_parse_ssres: weird security buffer offset, is %d, should be %d",
		    ssres->ssres_security_buffer_offset, SMB2_PH_STRUCTURE_SIZE + SMB2_SSRES_STRUCTURE_SIZE);

	if (ssres->ssres_security_buffer_offset + ssres->ssres_security_buffer_length > p->p_buf_len)
		errx(1, "smb2_parse_ssres: security buffer (%d) longer than packet (%d)", ssres->ssres_security_buffer_length, p->p_buf_len);

	smb2_spnego_take_neg_token_resp(p->p_conn, p->p_buf + ssres->ssres_security_buffer_offset, ssres->ssres_security_buffer_length);
}

static void
smb2_client_parse(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;

	ph = smb2_packet_parse_header(p);

	switch (ph->ph_command) {
		case SMB2_NEGOTIATE:
			smb2_parse_nres(p);
			break;
		case SMB2_SESSION_SETUP:
			smb2_parse_ssres(p);
			break;
		default:
			errx(1, "smb2_parse_packet_header: unknown command %d", ph->ph_command);
	}
}

static int
smb2_client_negotiate(struct smb2_connection *conn)
{
	struct smb2_packet *p;

	fprintf(stderr, "NEGOTIATE REQUEST...\n");
	p = smb2_packet_new(conn);
	smb2_client_add_command(p, SMB2_NEGOTIATE);
	smb2_tcp_send(p);
	smb2_packet_delete(p);

	fprintf(stderr, "NEGOTIATE RESPONSE...\n");
	p = smb2_packet_new(conn);
	smb2_tcp_receive(p);
	smb2_client_parse(p);
	smb2_packet_delete(p);

	fprintf(stderr, "SESSION SETUP REQUEST...\n");
	p = smb2_packet_new(conn);
	smb2_client_add_command(p, SMB2_SESSION_SETUP);
	smb2_tcp_send(p);
	smb2_packet_delete(p);

	fprintf(stderr, "SESSION SETUP RESPONSE...\n");
	p = smb2_packet_new(conn);
	smb2_tcp_receive(p);
	smb2_client_parse(p);
	smb2_packet_delete(p);

	return (0);
}

struct smb2_connection *
smb2_connect(const char *address)
{
	int error;
	struct sockaddr_in sin;
	struct hostent *he;
	struct smb2_connection *conn;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		err(1, "malloc");

	conn->c_credits_first = 0;
	conn->c_credits_after_last = 1;

	conn->c_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (conn->c_fd < 0)
		err(1, "socket");

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(SMB2_TCP_PORT);
	sin.sin_addr.s_addr = inet_addr(address);
	if (sin.sin_addr.s_addr == INADDR_NONE) {
		he = gethostbyname(address);
		if (he == NULL)
			errx(1, "gethostbyname: %s", hstrerror(h_errno));
		sin.sin_addr.s_addr = ((struct in_addr *)(void *)he->h_addr)->s_addr;
	}

	error = connect(conn->c_fd, (struct sockaddr *)&sin, sizeof(sin));
	if (error)
		err(1, "connect");

	error = smb2_client_negotiate(conn);
	if (error)
		errx(1, "smb2_negotiate");

	return (conn);
}

static void
usage(void)
{
	fprintf(stderr, "usage: smb2 hostname\n");
	exit(-1);
}

int
main(int argc, char **argv)
{
	struct smb2_connection *conn;

	if (argc != 2)
		usage();

	conn = smb2_connect(argv[1]);
	smb2_disconnect(conn);

	return (0);
}
