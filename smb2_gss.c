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
#include <stdlib.h>
#include <string.h>
#include <gssapi/gssapi.h>

#include "smb2_connection.h"
#include "smb2_gss.h"

#if 0
static void
smb2_gss_err(const char *message, OM_uint32 maj_status_arg, OM_uint32 min_status_arg)
{
	OM_uint32 maj_status, min_status, more_msgs = 0;
	gss_buffer_desc msg;

	do {
		// XXX: What to do with min_status_arg?
		maj_status = gss_display_status(&min_status, maj_status_arg, GSS_C_GSS_CODE, GSS_C_NULL_OID, &more_msgs, &msg);
		if (maj_status != GSS_S_COMPLETE)
			errx(1, "smb2_gss_err: gss_display_status failed");

		warnx("%s: major status: %s", message, (char *)msg.value);
		gss_release_buffer(&min_status, &msg);
	} while (more_msgs != 0);
	do {
		// XXX: What to do with min_status_arg?
		maj_status = gss_display_status(&min_status, min_status_arg, GSS_C_MECH_CODE, GSS_C_NULL_OID, &more_msgs, &msg);
		if (maj_status != GSS_S_COMPLETE)
			errx(1, "smb2_gss_err: gss_display_status failed");

		warnx("%s: minor status: %s", message, (char *)msg.value);
		gss_release_buffer(&min_status, &msg);
	} while (more_msgs != 0);

	exit(1);
}

static void
smb2_gss_get_service_name(gss_name_t *service_name)
{
	OM_uint32 maj_status, min_status;
	gss_buffer_desc service_buf;

	service_buf.value = "whatever";
	service_buf.length = strlen(service_buf.value) + 1;

	maj_status = gss_import_name(&min_status, &service_buf, GSS_C_NT_HOSTBASED_SERVICE, service_name);
	if (maj_status != GSS_S_COMPLETE)
		smb2_gss_err("smb2_gss_get_service_name", maj_status, min_status);
}
#endif

void
smb2_gss_receive(struct smb2_connection *conn, void *buf, size_t length)
{
#if 0
	OM_uint32 maj_status, min_status;
	gss_buffer_desc inbuf;
	gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
	gss_name_t service_name;

	inbuf.value = buf;
	inbuf.length = length;

	smb2_gss_get_service_name(&service_name);
	maj_status = gss_init_sec_context(&min_status, GSS_C_NO_CREDENTIAL, &ctx, service_name,
	    GSS_C_NO_OID, GSS_C_MUTUAL_FLAG | GSS_C_DELEG_FLAG, GSS_C_INDEFINITE,
	    NULL, &inbuf, NULL, &conn->c_token, NULL, NULL);

	if (maj_status != GSS_S_COMPLETE && maj_status != GSS_S_CONTINUE_NEEDED)
		smb2_gss_err("smb2_gss_receive", maj_status, min_status);
#else
	conn->c_token.length = length;
	conn->c_token.value = malloc(length);
	memcpy(conn->c_token.value, buf, length);
#endif
}

void
smb2_gss_send(struct smb2_connection *conn, void **buf, size_t *length)
{

	*buf = conn->c_token.value;
	*length = conn->c_token.length;
}

