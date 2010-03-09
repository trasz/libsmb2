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

	if (d == NULL)
		return;

	/* XXX: Left for debugging purposes. */
	d->d_buf = NULL;
	d->d_len = 0;
	d->d_next = 0;

	free(d);
}

void
smb2_der_rewind(struct smb2_der *d)
{

	d->d_next = 0;
}

static int
smb2_der_get_next_id(struct smb2_der *d, unsigned char *id)
{

	if (d->d_next == d->d_len) {
		//warnx("smb2_der_get_next_id: no more data");
		return (-1);
	}

	if (d->d_next + 2 > d->d_len) {
		warnx("smb2_der_get_next_id: truncated");
		return (-1);
	}

	*id = d->d_buf[d->d_next];

	return (0);
}

void
smb2_der_print(struct smb2_der *d, int indent)
{
	struct smb2_der *c;
	char *str;
	unsigned char id;
	size_t len;

	for (;;) {
		if (smb2_der_get_next_id(d, &id))
			break;
		if (id == 0x06) {
			str = smb2_der_get_oid(d);
			printf("%*sOID: %s\n", indent, "", str);
			free(str);
		} else if (id == 0x1B) {
			str = smb2_der_get_general_string(d);
			printf("%*s\"%s\"\n", indent, "", str);
			free(str);
		} else if (id == 0x30) {
			c = smb2_der_get_sequence(d);
			printf("%*sSEQUENCE:\n", indent, "");
			smb2_der_print(c, indent + 8);
			smb2_der_delete(c);
		} else if (id & 0x20) {
			c = smb2_der_get_constructed(d, &id);
			printf("%*sCONSTRUCTED, id 0x%X:\n", indent, "", id & 0xFF);
			smb2_der_print(c, indent + 8);
			smb2_der_delete(c);
		} else {
			smb2_der_get_whatever(d, &id, &len, NULL);
			fprintf(stderr, "%*sOTHER: id 0x%X, len %zd\n", indent, "", id & 0xFF, len);
		}
	}
}

static int
smb2_der_extract(struct smb2_der *d, unsigned char *id, size_t *len)
{
	char length_octet;

	if (d == NULL)
		return (-1);

	if (d->d_next == d->d_len) {
		warnx("smb2_der_extract: no more data");
		return (-1);
	}

	if (d->d_next + 2 > d->d_len) {
		warnx("smb2_der_extract: truncated");
		return (-1);
	}

	*id = d->d_buf[d->d_next];
	length_octet = d->d_buf[d->d_next + 1];
	d->d_next += 2;

	if (length_octet & 0x80) {
		warnx("smb2_der_extract: long lengths not supported yet");
		return (-1);
	}
	*len = length_octet & 0x7F;

	if (d->d_next + *len > d->d_len) {
		warnx("smb2_der_extract: object len %d, but only %d left", *len, d->d_len - d->d_next);
		return (-1);
	}

	return (0);
}

struct smb2_der *
smb2_der_get_constructed(struct smb2_der *d, unsigned char *identifier)
{
	struct smb2_der *c;
	size_t len;
	unsigned char id;

	if (smb2_der_extract(d, &id, &len))
		return (NULL);

	if ((id & 0x20) == 0) {
		warnx("smb2_der_get_constructed: not constructed");
		return (NULL);
	}

	c = smb2_der_new(&(d->d_buf[d->d_next]), len);
	*identifier = id;

	d->d_next += len;

	return (c);
}

struct smb2_der *
smb2_der_get_sequence(struct smb2_der *d)
{
	struct smb2_der *c;
	unsigned char id;

	c = smb2_der_get_constructed(d, &id);
	if (c == NULL)
		return (NULL);
	if (id != 0x30) {
		warnx("smb2_der_get_sequence: not a sequence (id 0x%X)", id & 0xFF);
		return (NULL);
	}

	return (c);
}

char *
smb2_der_get_oid(struct smb2_der *d)
{
	char *str;
	size_t len, stroff;
	unsigned char id;
	int subid;

	if (smb2_der_extract(d, &id, &len))
		return (NULL);

	if (id != 0x06) {
		warnx("smb2_der_get_oid: not an oid (code 0x%X, not 0x06)", id & 0xFF);
		return (NULL);
	}

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
	for (; len > 0; len--) {
		subid <<= 7;
		subid |= d->d_buf[d->d_next] & 0x7F;
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

char *
smb2_der_get_general_string(struct smb2_der *d)
{
	char *str;
	size_t len;
	unsigned char id;

	if (smb2_der_extract(d, &id, &len))
		return (NULL);

	if (id != 0x1B) {
		warnx("smb2_der_get_oid: not a general string (code 0x%X, not 0x1B)", id & 0xFF);
		return (NULL);
	}

	str = malloc(len + 1);
	if (str == NULL)
		err(1, "malloc");

	memcpy(str, &(d->d_buf[d->d_next]), len);
	str[len] = '\0';

	d->d_next += len;

	return (str);
}

int
smb2_der_get_whatever(struct smb2_der *d, unsigned char *id, size_t *len, void **buf)
{

	if (smb2_der_extract(d, id, len))
		return (-1);
	if (buf != NULL)
		*buf = (void *)&(d->d_buf[d->d_next]);
	d->d_next += *len;

	return (0);
}

