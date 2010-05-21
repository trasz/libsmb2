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

/*
 * NTLMSSP support, mostly described in [MS-NLMP].  To minimize the risk
 * of interoperability problems, we're trying to behave exactly like Windows 7.
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

/*
 * Possible values for nn_message_type.
 */
#define	SMB2_NTLMSSP_NEGOTIATE		1
#define	SMB2_NTLMSSP_CHALLENGE		2
#define	SMB2_NTLMSSP_AUTHENTICATE	3

/*
 * Possible flags for nn_negotiate_flags.
 */
#define	SMB2_NTLMSSP_REQUEST_TARGET		(1 << 2)

#define	SMB2_NTLMSSP_MAX_PAYLOAD_LENGTH		1024

/*
 * This is what Windows 7 sends.
 */
#define	SMB2_NTLMSSP_VERSION		0x0F0000001DB00106L

/*
 * XXX: Obviously temporary.
 */
#define	SMB2_NTLMSSP_HOSTNAME		"WIN-B0L0MENRA7J"

/*
 * Values for AV_PAIR AvId, [MS-NLMP], 2.2.2.1.
 */
#define	SMB2_NTLMSSP_AV_EOL			0
#define	SMB2_NTLMSSP_AV_NB_COMPUTER_NAME	1
#define	SMB2_NTLMSSP_AV_NB_DOMAIN_NAME		2
#define	SMB2_NTLMSSP_AV_DNS_COMPUTER_NAME	3
#define	SMB2_NTLMSSP_AV_DNS_DOMAIN_NAME		4
#define	SMB2_NTLMSSP_AV_TIMESTAMP		7

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
	 * Windows 7 sends 0xe2088297 here.  Flags below are mandatory,
	 * as defined in [MS-NLMP], 3.1.5.1.1.
	 */
#if 0
	nn->nn_negotiate_flags = SMB2_NTLMSSP_REQUEST_TARGET |
	    SMB2_NTLMSSP_NEGOTIATE_NTLM | SMB2_NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
	    SMB2_NTLMSSP_NEGOTIATE_UNICODE;
	// SMB2_NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY?
#endif
	nn->nn_negotiate_flags = 0xe2088297;
	/*
	 * Windows 7 zeroes calling workstation domain and calling workstation name fields.
	 */
	nn->nn_version = SMB2_NTLMSSP_VERSION;

	*buf = nn;
	*len = sizeof(*nn);
}

void
smb2_ntlmssp_take_challenge(struct smb2_connection *conn, void *buf, size_t len)
{
	struct smb2_ntlmssp_challenge *nc;

	if (len < sizeof(*nc))
		errx(1, "smb2_ntlmssp_take_challenge: buffer too small - %d, should be %d", len, sizeof(*nc));

	nc = (struct smb2_ntlmssp_challenge *)buf;
	if (memcmp(&(nc->nc_signature), SMB2_NTLMSSP_SIGNATURE, sizeof(nc->nc_signature)) != 0)
		errx(1, "smb2_ntlmssp_take_challenge: signature doesn't match");
}

void
smb2_ntlmssp_make_authenticate(struct smb2_connection *conn, void **buf, size_t *len)
{
	struct smb2_ntlmssp_authenticate *na;

	na = calloc(1, sizeof(*na));
	if (na == NULL)
		err(1, "malloc");

	memcpy(&na->na_signature, SMB2_NTLMSSP_SIGNATURE, sizeof(na->na_signature));
	na->na_message_type = SMB2_NTLMSSP_AUTHENTICATE;
	na->na_negotiate_flags = 0xe2088297;

	*buf = na;
	*len = sizeof(*na);
}

void
smb2_ntlmssp_take_negotiate(struct smb2_connection *conn, void *buf, size_t len)
{
	struct smb2_ntlmssp_negotiate *nn;

	if (len < sizeof(*nn))
		errx(1, "smb2_ntlmssp_take_negotiate: buffer too small - %d, should be %d", len, sizeof(*nn));

	nn = (struct smb2_ntlmssp_negotiate *)buf;
	if (memcmp(&(nn->nn_signature), SMB2_NTLMSSP_SIGNATURE, sizeof(nn->nn_signature)) != 0)
		errx(1, "smb2_ntlmssp_take_negotiate: signature doesn't match");

	conn->c_ntlmssp_negotiate_flags = nn->nn_negotiate_flags;
}

void
append_av(char *buf, size_t *offp, int type, char *value)
{
	size_t i;
	
	/* Set AvId. */
	*buf = type;
	buf += 2;
	*offp += 2;

	/* Set AvLen. */
	if (type == SMB2_NTLMSSP_AV_EOL) {
		*buf = 0;
		*offp += 2;
		return;
	}

	/* XXX: Fake Unicode. */
	*buf = strlen(value) * 2;
	buf += 2;
	*offp += 2;

	/* Set Value. */
	for (i = 0; i < strlen(value); i++) {
		*(buf++) = *(value + i);
		*(buf++) = '\0';
		*offp += 2;
	}
}

void
smb2_ntlmssp_make_challenge(struct smb2_connection *conn, void **buf, size_t *len)
{
	struct smb2_ntlmssp_challenge *nc;
	size_t payload_off = sizeof(*nc), av_off, i;

	nc = calloc(1, sizeof(*nc) + SMB2_NTLMSSP_MAX_PAYLOAD_LENGTH);
	if (nc == NULL)
		err(1, "malloc");

	memcpy(&nc->nc_signature, SMB2_NTLMSSP_SIGNATURE, sizeof(nc->nc_signature));
	nc->nc_message_type = SMB2_NTLMSSP_CHALLENGE;

	/*
	 * XXX: This is obviously fake Unicode.  Replace with something sane.
	 */
	nc->nc_target_name_len = strlen(SMB2_NTLMSSP_HOSTNAME) * 2;
	nc->nc_target_name_max_len = nc->nc_target_name_len;
	nc->nc_target_name_buffer_offset = payload_off;

	for (i = 0; i < strlen(SMB2_NTLMSSP_HOSTNAME); i++) {
		*((char *)nc + payload_off++) = *(SMB2_NTLMSSP_HOSTNAME + i);
		*((char *)nc + payload_off++) = '\0';
	}

	nc->nc_negotiate_flags = 0xe28a8215;
#if 0
	nc->nc_negotiate_flags = SMB2_NTLMSSP_REQUEST_TARGET |
	    SMB2_NTLMSSP_NEGOTIATE_NTLM | SMB2_NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
	    SMB2_NTLMSSP_NEGOTIATE_UNICODE;
#endif
	memcpy(&nc->nc_server_challenge, "HereGoes", sizeof(nc->nc_server_challenge));

	/* Starting offset of the data pointed to by TargetInfo. */
	av_off = payload_off;

	append_av((char *)nc + payload_off, &payload_off, SMB2_NTLMSSP_AV_NB_DOMAIN_NAME, SMB2_NTLMSSP_HOSTNAME);
	append_av((char *)nc + payload_off, &payload_off, SMB2_NTLMSSP_AV_NB_COMPUTER_NAME, SMB2_NTLMSSP_HOSTNAME);
	append_av((char *)nc + payload_off, &payload_off, SMB2_NTLMSSP_AV_DNS_DOMAIN_NAME, SMB2_NTLMSSP_HOSTNAME);
	append_av((char *)nc + payload_off, &payload_off, SMB2_NTLMSSP_AV_DNS_COMPUTER_NAME, SMB2_NTLMSSP_HOSTNAME);
	append_av((char *)nc + payload_off, &payload_off, SMB2_NTLMSSP_AV_TIMESTAMP, "1234"); /* XXX: Send a real time. */
	append_av((char *)nc + payload_off, &payload_off, SMB2_NTLMSSP_AV_EOL, NULL);

	nc->nc_target_info_buffer_offset = av_off;
	nc->nc_target_info_len = payload_off - av_off;
	nc->nc_target_info_max_len = nc->nc_target_info_len;

	nc->nc_version = SMB2_NTLMSSP_VERSION;

	*buf = nc;
	*len = payload_off;
}

void
smb2_ntlmssp_take_authenticate(struct smb2_connection *conn, void *buf, size_t len)
{
	struct smb2_ntlmssp_authenticate *na;

	if (len < sizeof(*na))
		errx(1, "smb2_ntlmssp_take_authenticate: buffer too small - %d, should be %d", len, sizeof(*na));

	na = (struct smb2_ntlmssp_authenticate *)buf;
	if (memcmp(&(na->na_signature), SMB2_NTLMSSP_SIGNATURE, sizeof(na->na_signature)) != 0)
		errx(1, "smb2_ntlmssp_take_authenticate: signature doesn't match");
}

void
smb2_ntlmssp_done(struct smb2_connection *conn)
{
}
