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

#ifndef SMB2_CONNECTION_H
#define	SMB2_CONNECTION_H

#include <stdint.h>

struct smb2_connection {
	int		c_fd;
	int64_t		c_credits_first;
	int64_t		c_credits_after_last;
	int		c_state;
	int		c_spnego_state;
	void		*c_spnego_buf;
	int		c_ntlmssp_negotiate_flags;
};

#define	SMB2_CONNECTION_STATE_INIT		0
#define	SMB2_CONNECTION_STATE_NEGOTIATED	0
#define	SMB2_CONNECTION_STATE_SESSION_SET_UP	0

void				smb2_connection_add_credits(struct smb2_connection *conn, int64_t credits);
int64_t				smb2_connection_next_message_id(struct smb2_connection *conn);
void				smb2_disconnect(struct smb2_connection *conn);

#endif /* !SMB2_CONNECTION_H */
