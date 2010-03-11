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
 * 2. GSSAPI is horrible and complicated to use, and
 * 3. There are bugs in the Microsoft implementation, making it not quite standard-compliant.
 *
 * This version supports only NTLM mechanism.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2_connection.h"
#include "smb2_der.h"
#include "smb2_spnego.h"

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
smb2_spnego_unwrap(struct smb2_der *blob)
{
	struct smb2_der *gss, *spnego;
	char *spnego_oid;

	gss = smb2_spnego_get_gss(blob);
	spnego_oid = smb2_der_get_oid(gss);
	if (spnego_oid == NULL) {
		warnx("smb2_spnego_unwrap: SPNEGO OID not found");
		smb2_der_delete(gss);
		return (NULL);
	}
	if (strcmp(spnego_oid, "1.3.6.1.5.5.2") != 0) {
		warnx("smb2_spnego_unwrap: received non-SPNEGO token (OID %s)", spnego_oid);
		smb2_der_delete(gss);
		free(spnego_oid);
		return (NULL);
	}
	spnego = smb2_spnego_get_a0(gss);
	smb2_der_delete(gss);

	return (spnego);
}

static struct smb2_der *
smb2_spnego_wrap(struct smb2_der *spnego)
{
	struct smb2_der *blob, *gss;

	gss = smb2_der_new();
	smb2_der_add_oid(gss, "1.3.6.1.5.5.2");
	smb2_der_add_constructed(gss, spnego, 0xa0);

	blob = smb2_der_new();
	smb2_der_add_constructed(blob, gss, 0x60);
	smb2_der_delete(gss);

	return (blob);
}

void
smb2_spnego_take_neg_token_init_2(struct smb2_connection *conn, void *buf, size_t length)
{
	struct smb2_der *blob, *spnego, *nti2, *mech_types, *x, *y, *z, *w;
	char *mech_type_oid, *s;
	unsigned char id;

	blob = smb2_der_new_from_buf(buf, length);
	smb2_der_print(blob);
	spnego = smb2_spnego_unwrap(blob);
	if (spnego == NULL)
		errx(1, "smb2_spnego_take_neg_token_init_2: didn't found SPNEGO data");
	nti2 = smb2_der_get_sequence(spnego);

	mech_types = smb2_spnego_get_a0(nti2);
	y = smb2_der_get_sequence(mech_types);
	mech_type_oid = smb2_der_get_oid(y);
	if (mech_type_oid == NULL)
		errx(1, "smb2_spnego_take_neg_token_init_2: NTLM OID not found");
	if (strcmp(mech_type_oid, "1.3.6.1.4.1.311.2.2.10") != 0)
		errx(1, "smb2_spnego_take_neg_token_init_2: received non-NTLM token (OID %s)", mech_type_oid);

	x = smb2_der_get_constructed(nti2, &id);
	z = smb2_der_get_sequence(x);
	w = smb2_der_get_constructed(z, &id);
	s = smb2_der_get_general_string(w);

	free(s);
	free(mech_type_oid);
	smb2_der_delete(mech_types);
	smb2_der_delete(nti2);
	smb2_der_delete(spnego);
	smb2_der_delete(blob);
}

void
smb2_spnego_make_neg_token_init(struct smb2_connection *conn, void **buf, size_t *length)
{

	struct smb2_der *blob, *spnego;

	spnego = smb2_der_new();
	blob = smb2_spnego_wrap(spnego);
	smb2_der_delete(spnego);

	smb2_der_get_buffer(blob, buf, length);
}

void
smb2_spnego_take_neg_token_resp(struct smb2_connection *conn, void *buf, size_t length)
{
	struct smb2_der *blob;

	blob = smb2_der_new_from_buf(buf, length);
	smb2_der_print(blob);
	smb2_der_delete(blob);
}

void
smb2_spnego_make_neg_token_init_2(struct smb2_connection *conn, void **buf, size_t *length)
{
	struct smb2_der *blob, *spnego, *nti2, *mech_types, *tmp, *neg_hints, *hint_name;

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
         *                       SEQUENCE:
         *                               CONSTRUCTED, id 0xA0:
         *                                       "not_defined_in_RFC4178@please_ignore"
	 */
	hint_name = smb2_der_new();
	smb2_der_add_general_string(hint_name, "not_defined_in_RFC4178@please_ignore");

	tmp = smb2_der_new();
	smb2_der_add_constructed(tmp, hint_name, 0xA0);
	smb2_der_delete(hint_name);

	neg_hints = smb2_der_new();
	smb2_der_add_sequence(neg_hints, tmp);
	smb2_der_delete(tmp);

	/*
	 * Now put it all together to form NegTokenInit2.
	 */
	nti2 = smb2_der_new();
	smb2_der_add_constructed(nti2, mech_types, 0xA0);
	smb2_der_delete(mech_types);
	smb2_der_add_constructed(nti2, neg_hints, 0xA3);
	smb2_der_delete(neg_hints);

	spnego = smb2_der_new();
	smb2_der_add_sequence(spnego, nti2);
	smb2_der_delete(nti2);

	blob = smb2_spnego_wrap(spnego);
	smb2_der_delete(spnego);

	smb2_der_get_buffer(blob, buf, length);
}

void
smb2_spnego_take_neg_token_init(struct smb2_connection *conn, void *buf, size_t length)
{
	struct smb2_der *blob;

	blob = smb2_der_new_from_buf(buf, length);
	smb2_der_print(blob);
	smb2_der_delete(blob);
}

void
smb2_spnego_make_neg_token_resp(struct smb2_connection *conn, void **buf, size_t *length)
{
	struct smb2_der *blob, *spnego;

	spnego = smb2_der_new();
	blob = smb2_spnego_wrap(spnego);
	smb2_der_delete(spnego);

	smb2_der_get_buffer(blob, buf, length);
}
