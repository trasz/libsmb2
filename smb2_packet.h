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
 * $Id: smb2_packet.h,v 1.2 2010/03/05 18:12:41 trasz Exp $
 */

#ifndef SMB2_PACKET_H
#define	SMB2_PACKET_H

#define	SMB2_P_BUF_SIZE		1024

struct smb2_connection;

struct smb2_packet {
	struct smb2_connection	*p_conn;
	int32_t			p_tcp_encap;	/* Used by TCP transport. */
	int8_t			p_buf[SMB2_P_BUF_SIZE];
	size_t			p_buf_len;
};

struct smb2_packet		*smb2_packet_new(struct smb2_connection *conn);
void				smb2_packet_delete(struct smb2_packet *p);
struct smb2_packet_header_sync	*smb2_packet_add_header_sync(struct smb2_packet *p);
struct smb2_packet_header_sync	*smb2_packet_parse_header(struct smb2_packet *p);

#endif /* !SMB2_PACKET_H */
