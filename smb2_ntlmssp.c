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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "smb2_connection.h"
#include "smb2_der.h"
#include "smb2_ntlmssp.h"

struct smb2_ntlmssp_negotiate {
	int64_t		nn_signature;
	int32_t		nn_message_type;
	int32_t		nn_negotiate_flags;
	int16_t		nn_domain_name_len;
	int16_t		nn_domain_name_max_len;
	int32_t		nn_domain_name_buffer_offset;
	int16_t		nn_workstation_len;
	int16_t		nn_workstation_max_len;
	int32_t		nn_workstation_buffer_offset;
	int64_t		nn_version;
};

struct smb2_ntlmssp_challenge {
	int64_t		nc_signature;
	int32_t		nc_message_type;
	int16_t		nc_target_name_len;
	int16_t		nc_target_name_max_len;
	int32_t		nc_target_name_buffer_offset;
	int32_t		nc_negotiate_flags;
	int64_t		nc_server_challenge;
	int64_t		nc_reserved;
	int16_t		nc_target_info_len;
	int16_t		nc_target_info_max_len;
	int32_t		nc_target_info_buffer_offset;
	int64_t		nc_version;
};

struct smb2_ntlmssp_authenticate {
	int64_t		na_signature;
	int32_t		na_message_type;
	int16_t		na_lm_challenge_response_len;
	int16_t		na_lm_challenge_response_max_len;
	int32_t		na_lm_challenge_response_buffer_offset;
	int16_t		na_nt_challenge_response_len;
	int16_t		na_nt_challenge_response_max_len;
	int32_t		na_nt_challenge_response_buffer_offset;
	int16_t		na_domain_name_len;
	int16_t		na_domain_name_max_len;
	int32_t		na_domain_name_buffer_offset;
	int16_t		na_user_name_len;
	int16_t		na_user_name_max_len;
	int32_t		na_user_name_buffer_offset;
	int16_t		na_workstation_len;
	int16_t		na_workstation_max_len;
	int32_t		na_workstation_buffer_offset;
	int16_t		na_encrypted_random_session_len;
	int16_t		na_encrypted_random_session_max_len;
	int32_t		na_encrypted_random_session_buffer_offset;
	int32_t		na_negotiate_flags;
	int64_t		na_version;
	int8_t		na_mic[16];
};

#define	SMB2_NTLMSSP_SIGNATURE		"NTLMSSP\0"
#define	SMB2_NTLMSSP_NEGOTIATE		1
#define	SMB2_NTLMSSP_CHALLENGE		2
#define	SMB2_NTLMSSP_AUTHENTICATE	3

void
smb2_ntlmssp_make_negotiate(struct smb2_connection *conn, void **buf, size_t *len)
{
	struct smb2_ntlmssp_negotiate *nn;

	nn = calloc(1, sizeof(*nn));
	if (nn == NULL)
		err(1, "malloc");

	memcpy(&nn->nn_signature, SMB2_NTLMSSP_SIGNATURE, sizeof(nn->nn_signature));
	nn->nn_message_type = SMB2_NTLMSSP_NEGOTIATE;
	/*
	 * Windows Server 2008 sends 0xe2088297 here.
	 */
	nn->nn_negotiate_flags = 0xA0000281;

	*buf = nn;
	*len = sizeof(*nn);
}

void
smb2_ntlmssp_take_challenge(struct smb2_connection *conn, void *buf, size_t len)
{
}

void
smb2_ntlmssp_make_authenticate(struct smb2_connection *conn, void **buf, size_t *len)
{
	struct smb2_ntlmssp_authenticate *na;

	na = calloc(1, sizeof(*na));
	if (na == NULL)
		err(1, "malloc");

	memcpy(&na->na_signature, SMB2_NTLMSSP_SIGNATURE, sizeof(na->na_signature));
	na->na_message_type = SMB2_NTLMSSP_CHALLENGE;
	na->na_negotiate_flags = 0xe2088297;

	*buf = na;
	*len = sizeof(*na);

}

void
smb2_ntlmssp_take_negotiate(struct smb2_connection *conn, void *buf, size_t len)
{
}

void
smb2_ntlmssp_make_challenge(struct smb2_connection *conn, void **buf, size_t *len)
{
	struct smb2_ntlmssp_challenge *nc;

	nc = calloc(1, sizeof(*nc));
	if (nc == NULL)
		err(1, "malloc");

	memcpy(&nc->nc_signature, SMB2_NTLMSSP_SIGNATURE, sizeof(nc->nc_signature));
	nc->nc_message_type = SMB2_NTLMSSP_CHALLENGE;
	nc->nc_negotiate_flags = 0xe2088297;

	*buf = nc;
	*len = sizeof(*nc);
}

void
smb2_ntlmssp_take_authenticate(struct smb2_connection *conn, void *buf, size_t len)
{
}

void
smb2_ntlmssp_done(struct smb2_connection *conn)
{
}
