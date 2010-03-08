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
 * ASN.1 Distinguished Encoding Rules.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2_der.h"

#define	SMB2_DER_OID_LEN	256

struct smb2_der {
	const char	*d_buf;
	size_t		d_len;
	size_t		d_next;
};

struct smb2_der *
smb2_der_new(const void *buf, size_t len)
{
	struct smb2_der *d;

	d = calloc(1, sizeof(*d));
	if (d == NULL)
		err(1, "malloc");

	d->d_buf = buf;
	d->d_len = len;
	d->d_next = 0;

	return (d);
}

void
smb2_der_delete(struct smb2_der *d)
{
	/* XXX: Left for debugging purposes. */
	d->d_buf = NULL;
	d->d_len = 0;
	d->d_next = 0;

	free(d);
}

static void
smb2_der_extract(struct smb2_der *d, char *id, size_t *len)
{
	char length_octet;

	if (d->d_next + 2 > d->d_len)
		errx(1, "smb2_der_extract: no more data");

	*id = d->d_buf[d->d_next];
	length_octet = d->d_buf[d->d_next + 1];
	d->d_next += 2;

	if (length_octet & 0x80)
		errx(1, "smb2_der_extract: long lengths not supported yet");
	*len = length_octet & 0xEF;

	if (d->d_next + *len > d->d_len)
		errx(1, "smb2_der_extract: object len %d, but only %d left", *len, d->d_len - d->d_next);
}

struct smb2_der *
smb2_der_get_constructed(struct smb2_der *d, char *identifier)
{
	struct smb2_der *c;
	size_t len;
	char id;

	smb2_der_extract(d, &id, &len);

	if (id != 0x60)
		errx(1, "smb2_der_get_constructed: not constructed");

	c = smb2_der_new(&(d->d_buf[d->d_next]), len);
	*identifier = id;

	d->d_next += len;
	
	return (c);
}

char *
smb2_der_get_oid(struct smb2_der *d)
{
	char *str;
	size_t len, stroff;
	char id;
	int subid;

	smb2_der_extract(d, &id, &len);

	if (id != 0x06)
		errx(1, "smb2_der_get_oid: not an oid (code 0x%x, not 0x06)", id);

	str = malloc(SMB2_DER_OID_LEN + 1);
	if (str == NULL)
		err(1, "malloc");

	/*
	 * For explanation of OID encoding, see "Information technology – ASN.1 encoding rules:
	 * Specification of Basic Encoding Rules (BER), Canonical Encoding Rules (CER)
	 * and Distinguished Encoding Rules (DER)", point 8.19.
	 */
	stroff = 0;
	subid = 0;
	for (;;) {
		// XXX: +1?
		if (d->d_next > len + 1)
			break;

		subid <<= 7;
		subid |= d->d_buf[d->d_next] & 0xEF;
		if ((d->d_buf[d->d_next] & 0x80) == 0) {
			/*
			 * First subidentifier is encoded differently; see 8.19.4 for details.
			 */
			if (stroff == 0)
				stroff += snprintf(str + stroff, SMB2_DER_OID_LEN - stroff, "%d.%d.", subid / 40, subid % 40);
			else
				stroff += snprintf(str + stroff, SMB2_DER_OID_LEN - stroff, "%d.", subid);
			subid = 0;
		}

		d->d_next++;
	}

	/* Strip trailing dot. */
	str[stroff - 1] = '\0';

	return (str);
}

void
smb2_der_get_whatever(struct smb2_der *d)
{
	size_t len;
	char id;

	smb2_der_extract(d, &id, &len);

	fprintf(stderr, "id is 0x%x, len is %zd, %zd left\n", id, len, d->d_len - d->d_next);

	d->d_next += len;
}

