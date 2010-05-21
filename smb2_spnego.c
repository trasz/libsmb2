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
 * What is being done here is mostly described in [MS-SPNG].  We're not using
 * mechanisms provided by the operating system (GSSAPI, as in <gssapi/gssapi.h>,
 * because:
 *
 * 1. MacOS X doesn't seem to support SPNEGO,
 * 2. GSSAPI implementations that do support SPNEGO don't neccessarily support NTLMSSP,
 * 3. GSSAPI is horrible and complicated to use, and
 * 4. There are bugs in the Microsoft implementation, making it not quite standard-compliant.
 *
 * This version supports only NTLM mechanism, which is what all Windows versions use
 * for simple login/password authentication.
 */

#include <err.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2_connection.h"
#include "smb2_der.h"
#include "smb2_ntlmssp.h"
#include "smb2_spnego.h"
#include "smb2_status.h"

#define	SMB2_SPNEGO_STATE_BEGIN			0
#define	SMB2_SPNEGO_STATE_GOT_CHALLENGE		1

#define	SMB2_SPNEGO_SERVER_STATE_NOTHING_DONE	0
#define	SMB2_SPNEGO_SERVER_STATE_NTI2_DONE	1
#define	SMB2_SPNEGO_SERVER_STATE_NTR_DONE	2

static struct smb2_der *
smb2_spnego_get_gss(struct smb2_der *d)
{
	struct smb2_der *c;
	unsigned char id;

	c = smb2_der_get_constructed(d, &id);
	/*
	 * See RFC 2743, section 3.1.
	 */
	if (id != 0x60)
		errx(1, "smb2_spnego_get_gss: not a GSS blob (id 0x%X)", id & 0xFF);

	return (c);
}

static struct smb2_der *
smb2_spnego_get_a0(struct smb2_der *d)
{
	struct smb2_der *c;
	unsigned char id;

	c = smb2_der_get_constructed(d, &id);
	/*
	 * XXX
	 */
	if (id != 0xA0)
		errx(1, "smb2_spnego_get_a0: not A0 (id 0x%X)", id & 0xFF);

	return (c);
}

static struct smb2_der *
smb2_spnego_unwrap_nti(struct smb2_der *blob)
{
	struct smb2_der *gss, *spnego, *tmp;
	char *spnego_oid;

	gss = smb2_spnego_get_gss(blob);
	spnego_oid = smb2_der_get_oid(gss);
	if (spnego_oid == NULL) {
		warnx("smb2_spnego_unwrap_nti: SPNEGO OID not found");
		smb2_der_delete(gss);
		return (NULL);
	}
	if (strcmp(spnego_oid, "1.3.6.1.5.5.2") != 0) {
		warnx("smb2_spnego_unwrap_nti: received non-SPNEGO token (OID %s)", spnego_oid);
		smb2_der_delete(gss);
		free(spnego_oid);
		return (NULL);
	}
	spnego = smb2_spnego_get_a0(gss);
	smb2_der_delete(gss);

	tmp = smb2_der_get_sequence(spnego);
	smb2_der_delete(spnego);

	return (tmp);
}

static struct smb2_der *
smb2_spnego_wrap_nti(struct smb2_der *spnego)
{
	struct smb2_der *blob, *gss, *tmp;

	tmp = smb2_der_new();
	smb2_der_add_sequence(tmp, spnego);

	gss = smb2_der_new();
	smb2_der_add_oid(gss, "1.3.6.1.5.5.2");
	smb2_der_add_constructed(gss, tmp, 0xa0);
	smb2_der_delete(tmp);

	blob = smb2_der_new();
	smb2_der_add_constructed(blob, gss, 0x60);
	smb2_der_delete(gss);

	return (blob);
}

void
smb2_spnego_take_neg_token_init_2(struct smb2_connection *conn, void *buf, size_t length)
{
	struct smb2_der *blob, *nti2, *mech_types, *tmp;
	char *mech_type_oid;
	bool ntlm_found = false;

	blob = smb2_der_new_from_buf(buf, length);
	nti2 = smb2_spnego_unwrap_nti(blob);
	if (nti2 == NULL)
		errx(1, "smb2_spnego_take_neg_token_init_2: didn't found SPNEGO data");

	mech_types = smb2_spnego_get_a0(nti2);
	tmp = smb2_der_get_sequence(mech_types);
	for (;;) {
		mech_type_oid = smb2_der_get_oid(tmp);
		if (mech_type_oid == NULL)
			break;

		if (strcmp(mech_type_oid, "1.3.6.1.4.1.311.2.2.10") == 0) {
			ntlm_found = true;
			break;
		}
		//warnx("smb2_spnego_take_neg_token_init_2: received non-NTLM token (OID %s)", mech_type_oid);
		free(mech_type_oid);
	}
	if (!ntlm_found)
		errx(1, "smb2_spnego_take_neg_token_init_2: NTLM OID not found");

	smb2_der_delete(mech_types);
	smb2_der_delete(tmp);
	smb2_der_delete(nti2);
	smb2_der_delete(blob);
}

static struct smb2_der *
smb2_spnego_wrap_ntlm(int spnego_id, int ntlm_id, void *buf, size_t len)
{
	struct smb2_der *blob, *spnego, *mech_types, *tmp, *negotiate;

	/*
         *                       SEQUENCE:
         *                               OID: 1.3.6.1.4.1.311.2.2.10
	 */
	tmp = smb2_der_new();
	smb2_der_add_oid(tmp, "1.3.6.1.4.1.311.2.2.10");

	mech_types = smb2_der_new();
	smb2_der_add_sequence(mech_types, tmp);
	smb2_der_delete(tmp);

	/*
         *                       CONSTRUCTED, id whatever:
         *                               OTHER, id 0x04:
	 */
	negotiate = smb2_der_new();
	smb2_der_add_whatever(negotiate, ntlm_id, buf, len);

	/*
	 * Now put it all together.
	 */
	spnego = smb2_der_new();
	smb2_der_add_constructed(spnego, mech_types, 0xA0);
	smb2_der_delete(mech_types);
	smb2_der_add_constructed(spnego, negotiate, spnego_id);
	smb2_der_delete(negotiate);

	blob = smb2_spnego_wrap_nti(spnego);
	smb2_der_delete(spnego);

	return (blob);
}

void
smb2_spnego_make_neg_token_init(struct smb2_connection *conn, void **buf, size_t *length)
{
	struct smb2_der *blob;
	void *ntlm_buf;
	size_t ntlm_len;

	if (conn->c_spnego_state == SMB2_SPNEGO_STATE_GOT_CHALLENGE) {
		printf("smb2_spnego_make_neg_token_init: sending AUTHENTICATE\n");
		smb2_ntlmssp_make_authenticate(conn, &ntlm_buf, &ntlm_len);
	} else {
		printf("smb2_spnego_make_neg_token_init: sending NEGOTIATE\n");
		smb2_ntlmssp_make_negotiate(conn, &ntlm_buf, &ntlm_len);
	}
	blob = smb2_spnego_wrap_ntlm(0xA2, 0x04, ntlm_buf, ntlm_len);

	conn->c_spnego_buf = blob;
	smb2_der_get_buffer(blob, buf, length);
}

void
smb2_spnego_take_neg_token_resp(struct smb2_connection *conn, void *buf, size_t length)
{
	struct smb2_der *blob;

	blob = smb2_der_new_from_buf(buf, length);
	smb2_der_print(blob);
	smb2_der_delete(blob);
	conn->c_spnego_state = SMB2_SPNEGO_STATE_GOT_CHALLENGE;
#if 0
	struct smb2_der *blob, *result, *mech, *token, *tmp, *tmp2;
	void *ntlm_buf;
	size_t ntlm_len;
	int res = 1;

	smb2_ntlmssp_make_challenge(conn, &ntlm_buf, &ntlm_len);

	result = smb2_der_new();
	smb2_der_add_whatever(result, 0x0A, &res, 1);

	mech = smb2_der_new();
	smb2_der_add_oid(mech, "1.3.6.1.4.1.311.2.2.10");

	token = smb2_der_new();
	smb2_der_add_whatever(token, 0x04, ntlm_buf, ntlm_len);

	tmp = smb2_der_new();
	smb2_der_add_constructed(tmp, result, 0xA0);
	smb2_der_delete(result);
	smb2_der_add_constructed(tmp, mech, 0xA1);
	smb2_der_delete(mech);
	smb2_der_add_constructed(tmp, token, 0xA2);
	smb2_der_delete(token);

	tmp2 = smb2_der_new();
	smb2_der_add_sequence(tmp2, tmp);
	smb2_der_delete(tmp);

	blob = smb2_der_new();
	smb2_der_add_constructed(blob, tmp2, 0xA1);
	smb2_der_delete(tmp2);
#endif
}

static void
smb2_spnego_make_neg_token_init_2(struct smb2_connection *conn, void **buf, size_t *length)
{
	struct smb2_der *blob, *tmp, *hint_name;
	void *ntlm_buf;
	size_t ntlm_len;

	/*
         *                               CONSTRUCTED, id 0xA0:
         *                                       "not_defined_in_RFC4178@please_ignore"
	 */
	hint_name = smb2_der_new();
	smb2_der_add_general_string(hint_name, "not_defined_in_RFC4178@please_ignore");

	tmp = smb2_der_new();
	smb2_der_add_constructed(tmp, hint_name, 0xA0);
	smb2_der_delete(hint_name);

	smb2_der_get_buffer(tmp, &ntlm_buf, &ntlm_len);
	blob = smb2_spnego_wrap_ntlm(0xA3, SMB2_DER_SEQUENCE, ntlm_buf, ntlm_len);

	conn->c_spnego_buf = blob;
	smb2_der_get_buffer(blob, buf, length);
}

static void
smb2_spnego_take_neg_token_init(struct smb2_connection *conn, void *buf, size_t length)
{
	struct smb2_der *blob, *nti, *mech_types, *tmp, *negotiate;
	char *mech_type_oid;
	void *ntlm_buf;
	size_t ntlm_len;

	blob = smb2_der_new_from_buf(buf, length);
	nti = smb2_spnego_unwrap_nti(blob);
	if (nti == NULL)
		errx(1, "smb2_spnego_take_neg_token_init: didn't found SPNEGO data");

	mech_types = smb2_spnego_get_a0(nti);
	tmp = smb2_der_get_sequence(mech_types);
	mech_type_oid = smb2_der_get_oid(tmp);
	if (mech_type_oid == NULL)
		errx(1, "smb2_spnego_take_neg_token_init: NTLM OID not found");
	if (strcmp(mech_type_oid, "1.3.6.1.4.1.311.2.2.10") != 0)
		errx(1, "smb2_spnego_take_neg_token_init: received non-NTLM token (OID %s)", mech_type_oid);

	negotiate = smb2_der_get_constructed(nti, NULL);
	smb2_der_get_whatever(negotiate, NULL, &ntlm_buf, &ntlm_len);
	smb2_ntlmssp_take_negotiate(conn, ntlm_buf, ntlm_len);

	free(mech_type_oid);
	smb2_der_delete(negotiate);
	smb2_der_delete(tmp);
	smb2_der_delete(mech_types);
	smb2_der_delete(nti);
	smb2_der_delete(blob);
}

int
smb2_spnego_server_take(struct smb2_connection *conn, void *buf, size_t length)
{
	/* XXX */
	if (conn->c_spnego_state == SMB2_SPNEGO_SERVER_STATE_NTR_DONE)
		return (SMB2_STATUS_SUCCESS);

	smb2_spnego_take_neg_token_init(conn, buf, length);
	return (SMB2_STATUS_MORE_PROCESSING_REQUIRED);
}

static void
smb2_spnego_make_neg_token_resp(struct smb2_connection *conn, void **buf, size_t *length)
{
	struct smb2_der *blob, *result, *mech, *token, *tmp, *tmp2;
	void *ntlm_buf;
	size_t ntlm_len;
	int res = 1;

	smb2_ntlmssp_make_challenge(conn, &ntlm_buf, &ntlm_len);

	result = smb2_der_new();
	smb2_der_add_whatever(result, 0x0A, &res, 1);

	mech = smb2_der_new();
	smb2_der_add_oid(mech, "1.3.6.1.4.1.311.2.2.10");

	token = smb2_der_new();
	smb2_der_add_whatever(token, 0x04, ntlm_buf, ntlm_len);

	tmp = smb2_der_new();
	smb2_der_add_constructed(tmp, result, 0xA0);
	smb2_der_delete(result);
	smb2_der_add_constructed(tmp, mech, 0xA1);
	smb2_der_delete(mech);
	smb2_der_add_constructed(tmp, token, 0xA2);
	smb2_der_delete(token);

	tmp2 = smb2_der_new();
	smb2_der_add_sequence(tmp2, tmp);
	smb2_der_delete(tmp);

	blob = smb2_der_new();
	smb2_der_add_constructed(blob, tmp2, 0xA1);
	smb2_der_delete(tmp2);

	conn->c_spnego_buf = blob;
	smb2_der_get_buffer(blob, buf, length);
}

void
smb2_spnego_server_make(struct smb2_connection *conn, void **buf, size_t *length)
{

	switch (conn->c_spnego_state) {
	case SMB2_SPNEGO_SERVER_STATE_NOTHING_DONE:
		smb2_spnego_make_neg_token_init_2(conn, buf, length);
		conn->c_spnego_state = SMB2_SPNEGO_SERVER_STATE_NTI2_DONE;
		break;
	case SMB2_SPNEGO_SERVER_STATE_NTI2_DONE:
		smb2_spnego_make_neg_token_resp(conn, buf, length);
		conn->c_spnego_state = SMB2_SPNEGO_SERVER_STATE_NTR_DONE;
		break;
	case SMB2_SPNEGO_SERVER_STATE_NTR_DONE:
		/* XXX: Make an OK reply; this is the response to NTLM AUTHENTICATE. */
		break;
	default:
		errx(1, "smb2_spnego_server_make: invalid spnego state %d", conn->c_spnego_state);
	}
}

void
smb2_spnego_done(struct smb2_connection *conn)
{
	struct smb2_der *blob;

	blob = (struct smb2_der *)conn->c_spnego_buf;
	smb2_der_delete(blob);
	conn->c_spnego_buf = NULL;
}
