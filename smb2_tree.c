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
 * Unicode handling routines.
 */

#include <err.h>
#include <iconv.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "smb2_unicode.h"

static iconv_t	smb2_unicode_cd_to_unicode = (iconv_t)-1;
static iconv_t	smb2_unicode_cd_to_utf8 = (iconv_t)-1;

void
smb2_unicode_init(void)
{

	smb2_unicode_cd_to_unicode = iconv_open("UCS-2LE", "UTF-8");
	if (smb2_unicode_cd_to_unicode == (iconv_t)-1)
		errx(1, "smb2_unicode_init failed");

	smb2_unicode_cd_to_utf8 = iconv_open("UTF-8", "UCS-2LE");
	if (smb2_unicode_cd_to_utf8 == (iconv_t)-1)
		errx(1, "smb2_unicode_init failed");
}

char *
smb2_unicode_to_utf8(void *buf, size_t len)
{
	size_t converted;
	size_t inbuflen = len, outbuflen;
	char *inbuf = buf, *outbuf, *outbufstart;

	outbuflen = len;
	/* +1 for trailing '\0'. */
	outbufstart = outbuf = malloc(outbuflen + 1);
	if (outbuf == NULL)
		err(1, "smb2_unicode_to_utf8");

	converted = iconv(smb2_unicode_cd_to_utf8, &inbuf, &inbuflen, &outbuf, &outbuflen);
	if (converted == (size_t)-1)
		err(1, "smb2_unicode_to_utf8: iconv");

	/* Reset conversion state. */
	converted = iconv(smb2_unicode_cd_to_utf8, NULL, NULL, NULL, NULL);
	if (converted == (size_t)-1)
		err(1, "smb2_unicode_to_utf8: iconv");

	return (outbufstart);
}
