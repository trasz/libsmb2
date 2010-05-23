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

#ifndef SMB2_STATUS_H
#define	SMB2_STATUS_H

#include <stdint.h>

#define	SMB2_STATUS_SUCCESS				0x00000000
#define	SMB2_STATUS_INVALID_PARAMETER			0xC000000D
#define	SMB2_STATUS_MORE_PROCESSING_REQUIRED		0xC0000016
#define	SMB2_STATUS_BAD_NETWORK_NAME			0xC00000CC

#define	SMB2_STATUS_SEV(s)	((s & 0xC0000000) >> 30)
#define	SMB2_STATUS_C(s)	((s & 0x20000000) >> 29)
#define	SMB2_STATUS_N(s)	((s & 0x10000000) >> 28)
#define	SMB2_STATUS_FACILITY(s)	((s & 0x0FFF0000) >> 16)
#define	SMB2_STATUS_CODE(s)	(s & 0x0000FFFF)

#define	SMB2_STATUS_SEVERITY_SUCCESS		0
#define	SMB2_STATUS_SEVERITY_INFORMATIONAL	1
#define	SMB2_STATUS_SEVERITY_WARNING		2
#define	SMB2_STATUS_SEVERITY_ERROR		3

const char	*smb2_strstatus(int32_t status);

#endif /* !SMB2_STATUS_H */
