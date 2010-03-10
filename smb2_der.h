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

#ifndef SMB2_DER_H
#define	SMB2_DER_H

#include <stddef.h>

#define	SMB2_DER_OID		0x06
#define	SMB2_DER_GENERAL_STRING	0x1B
#define	SMB2_DER_SEQUENCE	0x30

struct smb2_der;

struct	smb2_der	*smb2_der_new_from_buf(void *buf, size_t len);
struct	smb2_der	*smb2_der_new(void);
void			smb2_der_delete(struct smb2_der *d);

size_t			smb2_der_get_off(const struct smb2_der *d);
void			smb2_der_set_off(struct smb2_der *d, size_t off);

void			smb2_der_get_buffer(const struct smb2_der *d, void **buf, size_t *len);
void			smb2_der_print(struct smb2_der *d);

struct smb2_der		*smb2_der_get_constructed(struct smb2_der *d, unsigned char *identifier);
struct smb2_der		*smb2_der_get_sequence(struct smb2_der *d);
char			*smb2_der_get_oid(struct smb2_der *d);
char			*smb2_der_get_general_string(struct smb2_der *d);
int			smb2_der_get_whatever(struct smb2_der *d, unsigned char *id, void **buf, size_t *len);

void			smb2_der_add_constructed(struct smb2_der *d, const struct smb2_der *c, unsigned char id);
void			smb2_der_add_sequence(struct smb2_der *d, const struct smb2_der *c);
void			smb2_der_add_oid(struct smb2_der *d, const char *oid);
void			smb2_der_add_general_string(struct smb2_der *d, const char *str);
void			smb2_der_add_whatever(struct smb2_der *d, unsigned char id, const void *buf, size_t len);

#endif /* !SMB2_DER_H */
