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

static struct smb2_packet *
smb2_server_make_response(struct smb2_packet *req, int status)
{
	struct smb2_packet *res;
	struct smb2_packet_header_sync *resh, *reqh;

	reqh = (struct smb2_packet_header_sync *)req->p_buf;
	res = smb2_packet_new(req->p_conn);
	resh = smb2_packet_add_header_sync(res);
	resh->ph_status = status;
	resh->ph_command = reqh->ph_command;
	resh->ph_flags |= SMB2_FLAGS_SERVER_TO_REDIR;

	return (res);
}

static void
smb2_server_new_state(struct smb2_packet *p, int state)
{

	assert(state >= p->p_conn->c_state);

	fprintf(stderr, "state %d -> %d\n", p->p_conn->c_state, state);
	p->p_conn->c_state = state;
}

static void
smb2_serve_nreq(struct smb2_packet *req)
{
	struct smb2_packet *res;
	struct smb2_negotiate_request *nreq;
	struct smb2_negotiate_response *nres;
	void *buf;
	size_t len;

	if (req->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_NREQ_STRUCTURE_SIZE)
		errx(1, "smb2_serve_nreq: received packet too small (%d)", req->p_buf_len);

	nreq = (struct smb2_negotiate_request *)(req->p_buf + SMB2_PH_STRUCTURE_SIZE);

	smb2_server_new_state(req, SMB2_STATE_NEGOTIATE_DONE);

	res = smb2_server_make_response(req, SMB2_STATUS_SUCCESS);
	nres = (struct smb2_negotiate_response *)(res->p_buf + res->p_buf_len);

	/* -1, because size includes one byte of the security buffer. */
	res->p_buf_len += sizeof(*nres) - 1;

	nres->nres_structure_size = SMB2_NRES_STRUCTURE_SIZE;
	nres->nres_security_mode = SMB2_NRES_NEGOTIATE_SIGNING_ENABLED;
	nres->nres_dialect_revision = 0x0202;
	nres->nres_max_transact_size = 65535;
	nres->nres_max_read_size = 65535;
	nres->nres_max_write_size = 65535;

	smb2_spnego_server_make(res->p_conn, &buf, &len);
	/* -1, because size includes one byte of the security buffer. */
	nres->nres_security_buffer_offset = SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE - 1;
	memcpy(res->p_buf + nres->nres_security_buffer_offset, buf, len);
	nres->nres_security_buffer_length = len;
	res->p_buf_len += len;
	smb2_spnego_done(res->p_conn);

	smb2_tcp_send(res);
	smb2_packet_delete(res);
}

static void
smb2_serve_ssreq(struct smb2_packet *req)
{
	struct smb2_packet *res;
	struct smb2_session_setup_request *ssreq;
	struct smb2_session_setup_response *ssres;
	int status;
	void *buf;
	size_t len;

	if (req->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE)
		errx(1, "smb2_serve_ssreq: received packet too small (%d)", req->p_buf_len);

	ssreq = (struct smb2_session_setup_request *)(req->p_buf + SMB2_PH_STRUCTURE_SIZE);

	/*
	 * -1, because SMB2_SSREQ_STRUCTURE_SIZE includes one byte of the buffer.
	 */
	if (ssreq->ssreq_security_buffer_offset != SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE - 1)
		errx(1, "smb2_serve_ssreq: weird security buffer offset, is %d, should be %d",
		    ssreq->ssreq_security_buffer_offset, SMB2_PH_STRUCTURE_SIZE + SMB2_SSREQ_STRUCTURE_SIZE);

	if (ssreq->ssreq_security_buffer_offset + ssreq->ssreq_security_buffer_length > req->p_buf_len)
		errx(1, "smb2_serve_ssreq: security buffer (%d) longer than packet (%d)", ssreq->ssreq_security_buffer_length, req->p_buf_len);

	status = smb2_spnego_server_take(req->p_conn, req->p_buf + ssreq->ssreq_security_buffer_offset, ssreq->ssreq_security_buffer_length);
	if (status == SMB2_STATUS_SUCCESS)
		smb2_server_new_state(req, SMB2_STATE_SESSION_SETUP_DONE);

	if (req->p_conn->c_state != SMB2_STATE_SESSION_SETUP_DONE)
		res = smb2_server_make_response(req, SMB2_STATUS_MORE_PROCESSING_REQUIRED);
	else
		res = smb2_server_make_response(req, SMB2_STATUS_SUCCESS);
	ssres = (struct smb2_session_setup_response *)(res->p_buf + res->p_buf_len);
	/* -1, because size includes one byte of the security buffer. */
	res->p_buf_len += sizeof(*ssres) - 1;

	ssres->ssres_structure_size = SMB2_SSRES_STRUCTURE_SIZE;
	ssres->ssres_session_flags = 0;

	smb2_spnego_server_make(res->p_conn, &buf, &len);
	/* -1, because size includes one byte of the security buffer. */
	ssres->ssres_security_buffer_offset = SMB2_PH_STRUCTURE_SIZE + SMB2_SSRES_STRUCTURE_SIZE - 1;
	memcpy(res->p_buf + ssres->ssres_security_buffer_offset, buf, len);
	ssres->ssres_security_buffer_length = len;
	res->p_buf_len += len;
	smb2_spnego_done(res->p_conn);

	smb2_tcp_send(res);
	smb2_packet_delete(res);
}

static void
smb2_serve_careq(struct smb2_packet *req)
{
	struct smb2_cancel_request *careq;

	if (req->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_CAREQ_STRUCTURE_SIZE)
		errx(1, "smb2_serve_careq: received packet too small (%d)", req->p_buf_len);

	careq = (struct smb2_cancel_request *)(req->p_buf + SMB2_PH_STRUCTURE_SIZE);
	if (careq->careq_structure_size != SMB2_CAREQ_STRUCTURE_SIZE)
		errx(1, "smb2_serve_careq: wrong structure size; should be %zd, is %zd", careq->careq_structure_size, SMB2_CAREQ_STRUCTURE_SIZE);

	/*
	 * We don't really support CANCEL request.  Here, we're just ignoring it.
	 */
}

static void
smb2_serve_ereq(struct smb2_packet *req)
{
	struct smb2_packet *res;
	struct smb2_echo_request *ereq;
	struct smb2_echo_response *eres;

	if (req->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_EREQ_STRUCTURE_SIZE)
		errx(1, "smb2_serve_ereq: received packet too small (%d)", req->p_buf_len);

	ereq = (struct smb2_echo_request *)(req->p_buf + SMB2_PH_STRUCTURE_SIZE);
	if (ereq->ereq_structure_size != SMB2_EREQ_STRUCTURE_SIZE)
		errx(1, "smb2_serve_ereq: wrong structure size; should be %zd, is %zd", ereq->ereq_structure_size, SMB2_EREQ_STRUCTURE_SIZE);

	res = smb2_server_make_response(req, SMB2_STATUS_SUCCESS);
	eres = (struct smb2_echo_response *)(res->p_buf + res->p_buf_len);
	eres->eres_structure_size = SMB2_ERES_STRUCTURE_SIZE;
	res->p_buf_len += sizeof(*eres);

	smb2_tcp_send(res);
	smb2_packet_delete(res);
}

static void
smb2_serve_whatever(struct smb2_packet *req)
{
	struct smb2_packet *res;
	struct smb2_error_response *er;

	res = smb2_server_make_response(req, SMB2_STATUS_INVALID_PARAMETER);

	er = (struct smb2_error_response *)(res->p_buf + res->p_buf_len);
	er->er_structure_size = SMB2_ER_STRUCTURE_SIZE;
	res->p_buf_len += sizeof(*er);

	smb2_tcp_send(res);
	smb2_packet_delete(res);
}

struct smb2_server_command {
	int	sc_state;
	int	sc_command;
	void	(*sc_serve)(struct smb2_packet *);
} smb2_server_commands[] = {
	{ SMB2_STATE_NOTHING_DONE, SMB2_NEGOTIATE, smb2_serve_nreq },
	{ SMB2_STATE_NEGOTIATE_DONE, SMB2_SESSION_SETUP, smb2_serve_ssreq },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_LOGOFF, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_TREE_CONNECT, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_TREE_DISCONNECT, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_CREATE, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_CLOSE, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_FLUSH, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_READ, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_WRITE, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_LOCK, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_IOCTL, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_CANCEL, smb2_serve_careq },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_ECHO, smb2_serve_ereq },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_QUERY_DIRECTORY, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_CHANGE_NOTIFY, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_QUERY_INFO, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_SET_INFO, smb2_serve_whatever },
	{ SMB2_STATE_SESSION_SETUP_DONE, SMB2_OPLOCK_BREAK, smb2_serve_whatever },
	{ -1, -1, NULL }};

bool
smb2_server_smb1_negotiate_received(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE) {
		warnx("smb2_server_smb1_negotiate_received: received packet too small (%d)", p->p_buf_len);
		return (false);
	}

	ph = (struct smb2_packet_header_sync *)p->p_buf;
	if (ph->ph_protocol_id == SMB2_PH_SMB1_PROTOCOL_ID)
		return (true);

	return (false);
}

static void
smb2_server_serve(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;
	struct smb2_server_command *c;
	int command;

	ph = smb2_packet_parse_header(p);
	if (ph == NULL) {
		if (smb2_server_smb1_negotiate_received(p) == false)
			return;
		command = SMB2_NEGOTIATE;
	} else
		command = ph->ph_command;

	for (c = smb2_server_commands; c->sc_serve != NULL; c++) {
		if (c->sc_command != command)
			continue;
		if (c->sc_state != p->p_conn->c_state)
			errx(1, "smb2_server_serve: command %d received in state %d, should be %d", command, p->p_conn->c_state, c->sc_state);
		(c->sc_serve)(p);
		return;
	}

	errx(1, "smb2_server_serve: unknown command %d", command);
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
	struct smb2_packet *p;
	int fd;

	if (argc != 1)
		usage();

	fd = smb2_listen();

	for (;;) {
		conn = smb2_accept(fd);
		if (conn == NULL)
			continue;

		for (;;) {
			fprintf(stderr, "RECEIVE...\n");
			p = smb2_packet_new(conn);
			smb2_tcp_receive(p);
			smb2_server_serve(p);
			smb2_packet_delete(p);
			fprintf(stderr, "RECEIVED.\n");
		}

		smb2_disconnect(conn);
		exit(0);
	}

	return (0);
}
