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
 * What is being done here is mostly described in [MS-SPNG].
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "smb2_connection.h"
#include "smb2_der.h"
#include "smb2_spnego.h"

void
smb2_spnego_take_neg_token_init_2(struct smb2_connection *conn, void *buf, size_t length)
{
	struct smb2_der *blob, *gss, *spnego;
	char *oid;
	char id;

	blob = smb2_der_new(buf, length);
	gss = smb2_der_get_constructed(blob, &id);
	oid = smb2_der_get_oid(gss);
	if (strcmp(oid, "1.3.6.1.5.5.2") != 0)
		errx(1, "smb2_spnego_take_neg_token_init_2: received non-SPNEGO token (OID %s)", oid);
	spnego = smb2_der_get_constructed(gss, &id);

	free(oid);
	smb2_der_delete(spnego);
	smb2_der_delete(gss);
	smb2_der_delete(blob);
}

void
smb2_spnego_make_neg_token_init(struct smb2_connection *conn, void **buf, size_t *length)
{
}

