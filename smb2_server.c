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
#include <assert.h>
#include <err.h>
#include <limits.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smb2_client.h"
#include "smb2_connection.h"
#include "smb2_headers.h"
#include "smb2_spnego.h"
#include "smb2_status.h"
#include "smb2_tcp.h"

static struct smb2_negotiate_response *
smb2_packet_add_nres(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;
	struct smb2_negotiate_response *nres;
	void *buf;
	size_t len;

	ph = smb2_packet_add_header_sync(p);
	ph->ph_command = SMB2_NEGOTIATE;
	ph->ph_flags |= SMB2_FLAGS_SERVER_TO_REDIR;

	nres = (struct smb2_negotiate_response *)(p->p_buf + p->p_buf_len);
	/* -1, because size includes one byte of the security buffer. */
	p->p_buf_len += sizeof(*nres) - 1;
	
	nres->nres_structure_size = SMB2_NRES_STRUCTURE_SIZE;
	nres->nres_security_mode = SMB2_NRES_NEGOTIATE_SIGNING_ENABLED;
	nres->nres_dialect_revision = 0x0202;
	nres->nres_max_transact_size = 65535;
	nres->nres_max_read_size = 65535;
	nres->nres_max_write_size = 65535;

	smb2_spnego_make_neg_token_init_2(p->p_conn, &buf, &len);
	/* -1, because size includes one byte of the security buffer. */
	nres->nres_security_buffer_offset = SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE - 1;
	memcpy(p->p_buf + nres->nres_security_buffer_offset, buf, len);
	nres->nres_security_buffer_length = len;
	p->p_buf_len += len;
	smb2_spnego_done(p->p_conn);

	return (nres);
}

static struct smb2_session_setup_response *
smb2_packet_add_ssres(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;
	struct smb2_session_setup_response *ssres;
	void *buf;
	size_t len;

	ph = smb2_packet_add_header_sync(p);
	ph->ph_command = SMB2_SESSION_SETUP;
	if (p->p_conn->c_state != SMB2_STATE_SESSION_SETUP_DONE)
		ph->ph_status = SMB2_STATUS_MORE_PROCESSING_REQUIRED;
	else
		ph->ph_status = SMB2_STATUS_SUCCESS;
	ph->ph_flags |= SMB2_FLAGS_SERVER_TO_REDIR;

	ssres = (struct smb2_session_setup_response *)(p->p_buf + p->p_buf_len);
	p->p_buf_len += sizeof(*ssres);
	
	ssres->ssres_structure_size = SMB2_SSRES_STRUCTURE_SIZE;
	ssres->ssres_session_flags = 0;

	if (p->p_conn->c_state != SMB2_STATE_SESSION_SETUP_DONE) {
		/* --, because size includes one byte of the security buffer. */
		p->p_buf_len--;

		smb2_spnego_make_neg_token_resp(p->p_conn, &buf, &len);
		/* -1, because size includes one byte of the security buffer. */
		ssres->ssres_security_buffer_offset = SMB2_PH_STRUCTURE_SIZE + SMB2_SSRES_STRUCTURE_SIZE - 1;
		memcpy(p->p_buf + ssres->ssres_security_buffer_offset, buf, len);
		ssres->ssres_security_buffer_length = len;
		p->p_buf_len += len;
		smb2_spnego_done(p->p_conn);
	}

	return (ssres);
}

static void
smb2_server_add_command(struct smb2_packet *p, int cmd)
{

	switch (cmd) {
	case SMB2_NEGOTIATE:
		smb2_packet_add_nres(p);
		break;
	case SMB2_SESSION_SETUP:
		smb2_packet_add_ssres(p);
		break;
	default:
		errx(1, "smb2_packet_add_command: unknown command %d", cmd);
	}
}

static void
smb2_server_reply(const struct smb2_packet *request, int cmd)
{
	struct smb2_packet *p;

	fprintf(stderr, "SEND...\n");
	p = smb2_packet_new(request->p_conn);
	smb2_server_add_command(p, cmd);
	smb2_tcp_send(p);
	smb2_packet_delete(p);
	fprintf(stderr, "SENT.\n");
}

static void
smb2_server_new_state(struct smb2_packet *p, int state)
{

	assert(state >= p->p_conn->c_state);

	fprintf(stderr, "state %d -> %d\n", p->p_conn->c_state, state);
	p->p_conn->c_state = state;
}

static void
smb2_parse_nreq(struct smb2_packet *p)
{
	struct smb2_negotiate_request *nreq;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_NREQ_STRUCTURE_SIZE)
		errx(1, "smb2_parse_nreq: received packet too small (%d)", p->p_buf_len);

	nreq = (struct smb2_negotiate_request *)(p->p_buf + SMB2_PH_STRUCTURE_SIZE);

	smb2_server_reply(p, SMB2_NEGOTIATE);
	smb2_server_new_state(p, SMB2_STATE_NEGOTIATE_DONE);
}

static void
smb2_parse_ssreq(struct smb2_packet *p)
{
	struct smb2_session_setup_request *ssreq;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE)
		errx(1, "smb2_parse_ssreq: received packet too small (%d)", p->p_buf_len);

	ssreq = (struct smb2_session_setup_request *)(p->p_buf + SMB2_PH_STRUCTURE_SIZE);

	/*
	 * -1, because SMB2_SSREQ_STRUCTURE_SIZE includes one byte of the buffer.
	 */
	if (ssreq->ssreq_security_buffer_offset != SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE - 1)
		errx(1, "smb2_parse_ssreq: weird security buffer offset, is %d, should be %d",
		    ssreq->ssreq_security_buffer_offset, SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE);

	if (ssreq->ssreq_security_buffer_offset + ssreq->ssreq_security_buffer_length > p->p_buf_len)
		errx(1, "smb2_parse_ssreq: security buffer (%d) longer than packet (%d)", ssreq->ssreq_security_buffer_length, p->p_buf_len);

	smb2_spnego_take_neg_token_init(p->p_conn, p->p_buf + ssreq->ssreq_security_buffer_offset, ssreq->ssreq_security_buffer_length);

	smb2_server_reply(p, SMB2_SESSION_SETUP);
}

static void
smb2_parse_tcreq(struct smb2_packet *p)
{
	struct smb2_tree_connect_request *tcreq;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_TCREQ_STRUCTURE_SIZE)
		errx(1, "smb2_parse_tcreq: received packet too small (%d)", p->p_buf_len);

	tcreq = (struct smb2_tree_connect_request *)(p->p_buf + SMB2_PH_STRUCTURE_SIZE);
}

struct smb2_server_state {
	int	ss_state;
	int	ss_command;
	void	(*ss_parse)(struct smb2_packet *);
} states[] = {
	{ SMB2_STATE_NOTHING_DONE, SMB2_NEGOTIATE, smb2_parse_nreq },
	{ SMB2_STATE_NEGOTIATE_DONE, SMB2_SESSION_SETUP, smb2_parse_ssreq },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_TREE_CONNECT, smb2_parse_tcreq },
	{ -1, -1, NULL }};

static void
smb2_server_parse(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;
	bool got_smb1;
	struct smb2_server_state *s;

	ph = smb2_packet_parse_header(p, &got_smb1);
	/*
	 * XXX: This is evil.
	 */
	if (got_smb1)
		return;
	if (ph == NULL)
		return;

	for (s = states; s->ss_parse != NULL; s++) {
		if (s->ss_command != ph->ph_command)
			continue;
		if (s->ss_state != p->p_conn->c_state)
			errx(1, "smb2_server_parse: command %d received in state %d, should be %d", ph->ph_command, p->p_conn->c_state, s->ss_state);
		(s->ss_parse)(p);
		return;
	}

	errx(1, "smb2_server_parse: unknown command %d", ph->ph_command);
}

static int
smb2_serve(struct smb2_connection *conn)
{
	struct smb2_packet *p;

	for (;;) {
		fprintf(stderr, "RECEIVE...\n");
		p = smb2_packet_new(conn);
		smb2_tcp_receive(p);
		smb2_server_parse(p);
		smb2_packet_delete(p);
		fprintf(stderr, "RECEIVED.\n");
	}

	return (0);
}

int
smb2_listen(void)
{
	int error, fd;
	struct sockaddr_in sin;

	fd = socket(PF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		err(1, "socket");

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(SMB2_TCP_PORT);
	sin.sin_addr.s_addr = INADDR_ANY;

	error = bind(fd, (struct sockaddr *)&sin, sizeof(sin));
	if (error)
		err(1, "connect");

	error = listen(fd, 1);
	if (error)
		err(1, "listen");

	return (fd);
}

struct smb2_connection *
smb2_accept(int fd)
{
	struct smb2_connection *conn;
	pid_t child;

	printf("ACCEPT\n");

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		err(1, "malloc");

	conn->c_credits_first = 0;
	conn->c_credits_after_last = INT_MAX; /* XXX */

	conn->c_fd = accept(fd, NULL, 0);
	if (conn->c_fd < 0)
		err(1, "accept");

	child = fork();
	if (child < 0)
		err(1, "fork");
	if (child > 0) {
		signal(SIGCHLD, SIG_IGN);
		return (NULL);
	}

	return (conn);
}

static void
usage(void)
{
	fprintf(stderr, "usage: smb2d\n");
	exit(-1);
}

int
main(int argc, char **argv)
{
	struct smb2_connection *conn;
	int fd;

	if (argc != 1)
		usage();

	fd = smb2_listen();

	for (;;) {
		conn = smb2_accept(fd);
		if (conn == NULL)
			continue;

		smb2_serve(conn);
		smb2_disconnect(conn);
		exit(0);
	}

	return (0);
}
