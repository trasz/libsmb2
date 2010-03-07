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
 * $Id: smb2_status.h,v 1.1 2010/03/05 14:59:21 trasz Exp $
 */

#include <stdio.h>
#include <string.h>

#include "smb2_status.h"

char *
smb2_strstatus(int32_t status)
{
	static char str[256] = { '\0' };

	switch (SMB2_STATUS_SEV(status)) {
	case SMB2_STATUS_SEVERITY_SUCCESS:
		strcat(str, "success");
		break;
	case SMB2_STATUS_SEVERITY_INFORMATIONAL:
		strcat(str, "informational");
		break;
	case SMB2_STATUS_SEVERITY_WARNING:
		strcat(str, "warning");
		break;
	case SMB2_STATUS_SEVERITY_ERROR:
		strcat(str, "error");
		break;
	default:
		strcat(str, "unknown status");
		break;
	}

	if (SMB2_STATUS_C(status))
		strcat(str, ", customer defined");

	if (SMB2_STATUS_N(status))
		strcat(str, ", N not zero");

	sprintf(str + strlen(str), ", facility 0x%x, code 0x%x", SMB2_STATUS_FACILITY(status), SMB2_STATUS_CODE(status));

	return (str);
}
