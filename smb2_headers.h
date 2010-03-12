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

#ifndef SMB2_HEADERS_H
#define	SMB2_HEADERS_H

#include <stdint.h>

#ifndef CTASSERT
#define CTASSERT(x)		_CTASSERT(x, __LINE__)
#define _CTASSERT(x, y)		__CTASSERT(x, y)
#define __CTASSERT(x, y)	typedef char __assert_ ## y [(x) ? 1 : -1]
#endif

#if defined(__GNUC__)
#define	ATTRIBUTE_PACKED  __attribute__((__packed__))
#else
#define	ATTRIBUTE_PACKED
#pragma pack(1)
#endif

struct smb2_packet_header_async {
	int32_t	ph_protocol_id;
	int16_t	ph_structure_size;
	int16_t	ph_credit_charge;
	int32_t	ph_status;
	int16_t	ph_command;
	int16_t	ph_credit_request_response;
	int32_t	ph_flags;
	int32_t	ph_next_command;
	int64_t	ph_message_id;
	int64_t	ph_async_id;
	int64_t	ph_session_id;
	int8_t	ph_signature[16];
} ATTRIBUTE_PACKED;

struct smb2_packet_header_sync {
	int32_t	ph_protocol_id;
	int16_t	ph_structure_size;
	int16_t	ph_credit_charge;
	int32_t	ph_status;
	int16_t	ph_command;
	int16_t	ph_credit_request_response;
	int32_t	ph_flags;
	int32_t	ph_next_command;
	int64_t	ph_message_id;
	int32_t	ph_process_id;
	int32_t	ph_tree_id;
	int64_t	ph_session_id;
	int8_t	ph_signature[16];
} ATTRIBUTE_PACKED;

#define	SMB2_PH_PROTOCOL_ID		0x424D53FE /* 0xFE 'S' 'M' 'B', reversed */
#define	SMB2_PH_SMB1_PROTOCOL_ID	0x424D53FF /* 0xFF 'S' 'M' 'B', reversed */
#define	SMB2_PH_STRUCTURE_SIZE		64
CTASSERT(sizeof(struct smb2_packet_header_async) == SMB2_PH_STRUCTURE_SIZE);
CTASSERT(sizeof(struct smb2_packet_header_sync) == SMB2_PH_STRUCTURE_SIZE);

#define	SMB2_NEGOTIATE		0x0000
#define	SMB2_SESSION_SETUP	0x0001
#define	SMB2_LOGOFF		0x0002
#define	SMB2_TREE_CONNECT	0x0003
#define	SMB2_TREE_DISCONNECT	0x0004
#define	SMB2_CREATE		0x0005
#define	SMB2_CLOSE		0x0006
#define	SMB2_FLUSH		0x0007
#define	SMB2_READ		0x0008
#define	SMB2_WRITE		0x0009
#define	SMB2_LOCK		0x000A
#define	SMB2_IOCTL		0x000B
#define	SMB2_CANCEL		0x000C
#define	SMB2_ECHO		0x000D
#define	SMB2_QUERY_DIRECTORY	0x000E
#define	SMB2_CHANGE_NOTIFY	0x000F
#define	SMB2_QUERY_INFO		0x0010
#define	SMB2_SET_INFO		0x0011
#define	SMB2_OPLOCK_BREAK	0x0012

#define SMB2_FLAGS_SERVER_TO_REDIR	0x00000001
#define SMB2_FLAGS_ASYNC_COMMAND	0x00000002
#define	SMB2_FLAGS_RELATED_OPERATIONS	0x00000004
#define	SMB2_FLAGS_SIGNED		0x00000008
#define	SMB2_FLAGS_DFS_OPERATIONS	0x10000000

#define	SMB2_PH_PROCESS_ID_NONE		0xFEFF

struct smb2_error_response {
	int16_t	er_structure_size;
	int16_t	er_reserved;
	int32_t	er_bytecount;
	int8_t	er_errordata[1];
} ATTRIBUTE_PACKED;

#define	SMB2_ER_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_error_response) == SMB2_ER_STRUCTURE_SIZE);

struct smb2_symbolic_link_error_response {
	int32_t	sler_sym_link_length;
	int32_t	sler_sym_link_error_tag;
	int32_t	sler_reparse_tag;
	int16_t	sler_reparse_data_length;
	int16_t	sler_unparsed_path_length;
	int16_t	sler_substitute_name_offset;
	int16_t	sler_substitute_name_length;
	int16_t	sler_print_name_offset;
	int16_t	sler_print_name_length;
	int32_t	sler_flags;
	int8_t	sler_path_buffer;
} ATTRIBUTE_PACKED;

#define	SMB2_SLER_SYM_LINK_ERROR_TAG	0x4C4D5953
#define	SMB2_SLER_REPARSE_TAG		0xA000000C
#define	SMB2_SLER_SYMLINK_FLAG_RELATIVE	0x00000001

struct smb2_negotiate_request {
	int16_t	nreq_structure_size;
	int16_t	nreq_dialect_count;
	int16_t	nreq_security_mode;
	int16_t	nreq_reserved;
	int32_t	nreq_capabilities;
	int8_t	nreq_client_guid[16];
	int64_t	nreq_client_start_time;
	int32_t	nreq_dialects[0];
} ATTRIBUTE_PACKED;

#define	SMB2_NREQ_STRUCTURE_SIZE		36
CTASSERT(sizeof(struct smb2_negotiate_request) == SMB2_NREQ_STRUCTURE_SIZE);
#define	SMB2_NREQ_NEGOTIATE_SIGNING_ENABLED	0x0001
#define	SMB2_NREQ_NEGOTIATE_SIGNING_REQUIRED	0x0002
#define	SMB2_NREQ_GLOBAL_CAP_DFS		0x00000001

struct smb2_negotiate_response {
	int16_t	nres_structure_size;
	int16_t	nres_security_mode;
	int16_t	nres_dialect_revision;
	int16_t	nres_reserved;
	int8_t	nres_server_guid[16];
	int32_t	nres_capabilities;
	int32_t	nres_max_transact_size;
	int32_t	nres_max_read_size;
	int32_t	nres_max_write_size;
	int64_t	nres_system_time;
	int64_t	nres_server_start_time;
	int16_t	nres_security_buffer_offset;
	int16_t	nres_security_buffer_length;
	int32_t	nres_reserved2;
	int8_t	nres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_NRES_STRUCTURE_SIZE		65
CTASSERT(sizeof(struct smb2_negotiate_response) == SMB2_NRES_STRUCTURE_SIZE);
#define	SMB2_NRES_NEGOTIATE_SIGNING_ENABLED	0x0001
#define	SMB2_NRES_NEGOTIATE_SIGNING_REQUIRED	0x0002
#define	SMB2_NRES_GLOBAL_CAP_DFS		0x00000001
#define	SMB2_NRES_GLOBAL_CAP_LEASING		0x00000002
#define	SMB2_NRES_GLOBAL_CAP_LARGE_MTU		0x00000004

struct smb2_session_setup_request {
	int16_t	ssreq_structure_size;
	int8_t	ssreq_vc_number;
	int8_t	ssreq_security_mode;
	int32_t	ssreq_capabilities;
	int32_t	ssreq_channel;
	int16_t	ssreq_security_buffer_offset;
	int16_t	ssreq_security_buffer_length;
	int64_t	ssreq_previous_session_id;
	int8_t	ssreq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_SSREQ_STRUCTURE_SIZE		25
CTASSERT(sizeof(struct smb2_session_setup_request) == SMB2_SSREQ_STRUCTURE_SIZE);
#define	SMB2_SSREQ_NEGOTIATE_SIGNING_ENABLED	0x0001
#define	SMB2_SSREQ_NEGOTIATE_SIGNING_REQUIRED	0x0002
#define	SMB2_SSREQ_GLOBAL_CAP_DFS		0x00000001
#define	SMB2_SSREQ_GLOBAL_CAP_UNUSED1		0x00000000
#define	SMB2_SSREQ_GLOBAL_CAP_UNUSED2		0x00000000
#define	SMB2_SSREQ_GLOBAL_CAP_UNUSED3		0x00000000

struct smb2_session_setup_response {
	int16_t	ssres_structure_size;
	int16_t	ssres_session_flags;
	int16_t	ssres_security_buffer_offset;
	int16_t	ssres_security_buffer_length;
	int8_t	ssres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_SSRES_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_session_setup_response) == SMB2_SSRES_STRUCTURE_SIZE);
#define	SMB2_SSRES_SESSION_FLAG_IS_GUEST	0x001
#define	SMB2_SSRES_SESSION_FLAG_IS_NULL		0x002

struct smb2_logoff_request {
	int16_t	lreq_structure_size;
	int16_t	lreq_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_LREQ_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_logoff_request) == SMB2_LREQ_STRUCTURE_SIZE);

struct smb2_logoff_response {
	int16_t	lres_structure_size;
	int16_t	lres_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_LRES_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_logoff_response) == SMB2_LRES_STRUCTURE_SIZE);

struct smb2_tree_connect_request {
	int16_t	tcreq_structure_size;
	int16_t	tcreq_reserved;
	int16_t	tcreq_path_offset;
	int16_t	tcreq_path_length;
	int8_t	tcreq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_TCREQ_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_tree_connect_request) == SMB2_TCREQ_STRUCTURE_SIZE);

struct smb2_tree_connect_response {
	int16_t	tcres_structure_size;
	int8_t	tcres_share_type;
	int8_t	tcres_reserved;
	int32_t	tcres_share_flags;
	int32_t	tcres_capabilities;
	int32_t	tcres_maximal_access;
} ATTRIBUTE_PACKED;

#define	SMB2_TCRES_STRUCTURE_SIZE			16
CTASSERT(sizeof(struct smb2_tree_connect_response) == SMB2_TCRES_STRUCTURE_SIZE);
#define	SMB2_TCRES_SHARE_TYPE_DISK			0x01
#define	SMB2_TCRES_SHARE_TYPE_PIPE			0x02
#define	SMB2_TCRES_SHARE_TYPE_PRINT			0x03
#define	SMB2_TCRES_SHAREFLAG_MANUAL_CACHING		0x00000000
#define	SMB2_TCRES_SHAREFLAG_AUTO_CACHING		0x00000010
#define	SMB2_TCRES_SHAREFLAG_VDO_CACHING		0x00000020
#define	SMB2_TCRES_FLAGS_DFS				0x00000001
#define	SMB2_TCRES_FLAGS_DFS_ROOT			0x00000002
#define	SMB2_TCRES_FLAGS_RESTRICT_EXCLUSIVE_OPENS	0x00000100
#define	SMB2_TCRES_FLAGS_FORCE_SHARED_DELETE		0x00000200
#define	SMB2_TCRES_FLAGS_ALLOW_NAMESPACE_CACHING	0x00000400
#define	SMB2_TCRES_FLAGS_BASED_DIRECTORY_ENUM		0x00000800
#define	SMB2_TCRES_FLAGS_FORCE_LEVELII_OPLOCK		0x00001000
#define	SMB2_TCRES_FLAGS_ENABLE_HASH			0x00002000
#define	SMB2_TCRES_SHARE_CAP_DFS			0x00000008

struct smb2_tree_disconnect_request {
	int16_t	tdreq_structure_size;
	int16_t	tdreq_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_TDREQ_STRUCTURE_SIZE			4
CTASSERT(sizeof(struct smb2_tree_disconnect_request) == SMB2_TDREQ_STRUCTURE_SIZE);

struct smb2_tree_disconnect_response {
	int16_t	tdres_structure_size;
	int16_t	tdres_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_TDRES_STRUCTURE_SIZE			4
CTASSERT(sizeof(struct smb2_tree_disconnect_response) == SMB2_TDRES_STRUCTURE_SIZE);

#if (!defined __GNUC__)
#pragma pack()
#endif

#endif /* !SMB2_HEADERS_H */
