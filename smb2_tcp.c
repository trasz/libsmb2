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

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "smb2_connection.h"
#include "smb2_headers.h"
#include "smb2_tcp.h"

void
smb2_tcp_send(struct smb2_packet *p)
{
	int written, to_write;

	p->p_tcp_encap = htonl(p->p_buf_len);
	to_write = sizeof(p->p_tcp_encap) + p->p_buf_len;
	written = write(p->p_conn->c_fd, &p->p_tcp_encap, to_write);
	if (written != to_write)
		errx(1, "smb2_tcp_send: write failed; wrote %d, should be %d", written, to_write);
}

void
smb2_tcp_receive(struct smb2_packet *p)
{
	int bytes_read;
	int32_t encapsulation;

	bytes_read = read(p->p_conn->c_fd, &encapsulation, sizeof(encapsulation));
	if (bytes_read != sizeof(encapsulation))
		errx(1, "smb2_tcp_receive: read failed (%d)", bytes_read);
	encapsulation = ntohl(encapsulation);
	if (encapsulation > sizeof(p->p_buf))
		errx(1, "smb2_tcp_receive: received overlength packet (%d)", encapsulation);
	bytes_read = read(p->p_conn->c_fd, p->p_buf, encapsulation);
	if (bytes_read != encapsulation)
		errx(1, "smb2_tcp_receive: read failed 2");
	p->p_buf_len = encapsulation;
}
