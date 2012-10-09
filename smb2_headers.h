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
	uint32_t	ph_protocol_id;
	uint16_t	ph_structure_size;
	uint16_t	ph_credit_charge;
	uint32_t	ph_status;
	uint16_t	ph_command;
	uint16_t	ph_credit_request_response;
	uint32_t	ph_flags;
	uint32_t	ph_next_command;
	uint64_t	ph_message_id;
	uint64_t	ph_async_id;
	uint64_t	ph_session_id;
	uint8_t		ph_signature[16];
} ATTRIBUTE_PACKED;

struct smb2_packet_header_sync {
	uint32_t	ph_protocol_id;
	uint16_t	ph_structure_size;
	uint16_t	ph_credit_charge;
	uint32_t	ph_status;
	uint16_t	ph_command;
	uint16_t	ph_credit_request_response;
	uint32_t	ph_flags;
	uint32_t	ph_next_command;
	uint64_t	ph_message_id;
	uint32_t	ph_process_id;
	uint32_t	ph_tree_id;
	uint64_t	ph_session_id;
	uint8_t		ph_signature[16];
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
	uint16_t	er_structure_size;
	uint16_t	er_reserved;
	uint32_t	er_bytecount;
	uint8_t		er_errordata[1];
} ATTRIBUTE_PACKED;

#define	SMB2_ER_STRUCTURE_SIZE			9
CTASSERT(sizeof(struct smb2_error_response) == SMB2_ER_STRUCTURE_SIZE);

struct smb2_symbolic_link_error_response {
	uint32_t	sler_sym_link_length;
	uint32_t	sler_sym_link_error_tag;
	uint32_t	sler_reparse_tag;
	uint16_t	sler_reparse_data_length;
	uint16_t	sler_unparsed_path_length;
	uint16_t	sler_substitute_name_offset;
	uint16_t	sler_substitute_name_length;
	uint16_t	sler_print_name_offset;
	uint16_t	sler_print_name_length;
	uint32_t	sler_flags;
	uint8_t		sler_path_buffer;
} ATTRIBUTE_PACKED;

#define	SMB2_SLER_SYM_LINK_ERROR_TAG	0x4C4D5953
#define	SMB2_SLER_REPARSE_TAG		0xA000000C
#define	SMB2_SLER_SYMLINK_FLAG_RELATIVE	0x00000001

struct smb2_negotiate_request {
	uint16_t	nreq_structure_size;
	uint16_t	nreq_dialect_count;
	uint16_t	nreq_security_mode;
	uint16_t	nreq_reserved;
	uint32_t	nreq_capabilities;
	uint8_t		nreq_client_guid[16];
	uint64_t	nreq_client_start_time;
	uint32_t	nreq_dialects[0];
} ATTRIBUTE_PACKED;

#define	SMB2_NREQ_STRUCTURE_SIZE		36
CTASSERT(sizeof(struct smb2_negotiate_request) == SMB2_NREQ_STRUCTURE_SIZE);
#define	SMB2_NREQ_NEGOTIATE_SIGNING_ENABLED	0x0001
#define	SMB2_NREQ_NEGOTIATE_SIGNING_REQUIRED	0x0002
#define	SMB2_NREQ_GLOBAL_CAP_DFS		0x00000001

struct smb2_negotiate_response {
	uint16_t	nres_structure_size;
	uint16_t	nres_security_mode;
	uint16_t	nres_dialect_revision;
	uint16_t	nres_reserved;
	uint8_t		nres_server_guid[16];
	uint32_t	nres_capabilities;
	uint32_t	nres_max_transact_size;
	uint32_t	nres_max_read_size;
	uint32_t	nres_max_write_size;
	uint64_t	nres_system_time;
	uint64_t	nres_server_start_time;
	uint16_t	nres_security_buffer_offset;
	uint16_t	nres_security_buffer_length;
	uint32_t	nres_reserved2;
	uint8_t		nres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_NRES_STRUCTURE_SIZE		65
CTASSERT(sizeof(struct smb2_negotiate_response) == SMB2_NRES_STRUCTURE_SIZE);
#define	SMB2_NRES_NEGOTIATE_SIGNING_ENABLED	0x0001
#define	SMB2_NRES_NEGOTIATE_SIGNING_REQUIRED	0x0002
#define	SMB2_NRES_GLOBAL_CAP_DFS		0x00000001
#define	SMB2_NRES_GLOBAL_CAP_LEASING		0x00000002
#define	SMB2_NRES_GLOBAL_CAP_LARGE_MTU		0x00000004

struct smb2_session_setup_request {
	uint16_t	ssreq_structure_size;
	uint8_t		ssreq_vc_number;
	uint8_t		ssreq_security_mode;
	uint32_t	ssreq_capabilities;
	uint32_t	ssreq_channel;
	uint16_t	ssreq_security_buffer_offset;
	uint16_t	ssreq_security_buffer_length;
	uint64_t	ssreq_previous_session_id;
	uint8_t		ssreq_buffer[1];
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
	uint16_t	ssres_structure_size;
	uint16_t	ssres_session_flags;
	uint16_t	ssres_security_buffer_offset;
	uint16_t	ssres_security_buffer_length;
	uint8_t		ssres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_SSRES_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_session_setup_response) == SMB2_SSRES_STRUCTURE_SIZE);
#define	SMB2_SSRES_SESSION_FLAG_IS_GUEST	0x001
#define	SMB2_SSRES_SESSION_FLAG_IS_NULL		0x002

struct smb2_logoff_request {
	uint16_t	lreq_structure_size;
	uint16_t	lreq_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_LREQ_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_logoff_request) == SMB2_LREQ_STRUCTURE_SIZE);

struct smb2_logoff_response {
	uint16_t	lres_structure_size;
	uint16_t	lres_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_LRES_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_logoff_response) == SMB2_LRES_STRUCTURE_SIZE);

struct smb2_tree_connect_request {
	uint16_t	tcreq_structure_size;
	uint16_t	tcreq_reserved;
	uint16_t	tcreq_path_offset;
	uint16_t	tcreq_path_length;
	uint8_t		tcreq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_TCREQ_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_tree_connect_request) == SMB2_TCREQ_STRUCTURE_SIZE);

struct smb2_tree_connect_response {
	uint16_t	tcres_structure_size;
	uint8_t		tcres_share_type;
	uint8_t		tcres_reserved;
	uint32_t	tcres_share_flags;
	uint32_t	tcres_capabilities;
	uint32_t	tcres_maximal_access;
} ATTRIBUTE_PACKED;

#define	SMB2_TCRES_STRUCTURE_SIZE		16
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
	uint16_t	tdreq_structure_size;
	uint16_t	tdreq_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_TDREQ_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_tree_disconnect_request) == SMB2_TDREQ_STRUCTURE_SIZE);

struct smb2_tree_disconnect_response {
	uint16_t	tdres_structure_size;
	uint16_t	tdres_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_TDRES_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_tree_disconnect_response) == SMB2_TDRES_STRUCTURE_SIZE);

struct smb2_create_request {
	uint16_t	creq_structure_size;
	uint8_t		creq_security_flags;
	uint8_t		creq_requested_oplock_level;
	uint32_t	creq_impersonation_level;
	uint64_t	creq_smb_create_flags;
	uint64_t	creq_reserved;
	uint32_t	creq_desired_access;
	uint32_t	creq_file_attributes;
	uint32_t	creq_share_access;
	uint32_t	creq_create_disposition;
	uint32_t	creq_create_options;
	uint16_t	creq_name_offset;
	uint16_t	creq_name_length;
	uint32_t	creq_create_contexts_offset;
	uint32_t	creq_create_contexts_length;
	uint8_t	creq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_CREQ_STRUCTURE_SIZE		57
CTASSERT(sizeof(struct smb2_create_request) == SMB2_CREQ_STRUCTURE_SIZE);

struct smb2_create_response {
	uint16_t	cres_structure_size;
	uint8_t		cres_oplock_level;
	uint8_t		cres_reserved;
	uint32_t	cres_create_action;
	uint64_t	cres_creation_time;
	uint64_t	cres_last_access_time;
	uint64_t	cres_last_write_time;
	uint64_t	cres_change_time;
	uint64_t	cres_allocation_size;
	uint64_t	cres_end_of_file;
	uint32_t	cres_file_attributes;
	uint32_t	cres_reserved2;
	uint8_t		cres_file_id[16];
	uint32_t	cres_create_contexts_offset;
	uint32_t	cres_create_contexts_length;
	uint8_t		cres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_CRES_STRUCTURE_SIZE		89
CTASSERT(sizeof(struct smb2_create_response) == SMB2_CRES_STRUCTURE_SIZE);
#define	SMB2_OPLOCK_LEVEL_NONE			0x00
#define	SMB2_OPLOCK_LEVEL_II			0x01
#define	SMB2_OPLOCK_LEVEL_EXCLUSIVE		0x08
#define	SMB2_OPLOCK_LEVEL_BATCH			0x09
#define	SMB2_OPLOCK_LEVEL_LEASE			0xFF

#define	SMB2_CREATE_ACTION_FILE_SUPERSEDED	0x00000000
#define	SMB2_CREATE_ACTION_FILE_OPENED		0x00000001
#define	SMB2_CREATE_ACTION_FILE_CREATED		0x00000002
#define	SMB2_CREATE_ACTION_FILE_OVERWRITTEN	0x00000003

struct smb2_close_request {
	uint16_t	clreq_structure_size;
	uint16_t	clreq_flags;
	uint32_t	clreq_reserved;
	uint8_t		clreq_fileid[16];
} ATTRIBUTE_PACKED;

#define	SMB2_CLREQ_STRUCTURE_SIZE		24
CTASSERT(sizeof(struct smb2_close_request) == SMB2_CLREQ_STRUCTURE_SIZE);

struct smb2_close_response {
	uint16_t	clres_structure_size;
	uint16_t	clres_flags;
	uint32_t	clres_reserved;
	uint64_t	clres_creation_time;
	uint64_t	clres_last_access_time;
	uint64_t	clres_last_write_time;
	uint64_t	clres_change_time;
	uint64_t	clres_allocation_size;
	uint64_t	clres_end_of_file;
	uint32_t	clres_file_attributes;
} ATTRIBUTE_PACKED;

#define	SMB2_CLRES_STRUCTURE_SIZE		60
CTASSERT(sizeof(struct smb2_close_response) == SMB2_CLRES_STRUCTURE_SIZE);

struct smb2_flush_request {
	uint16_t	freq_structure_size;
	uint16_t	freq_reserved1;
	uint32_t	freq_reserved2;
	uint8_t		freq_file_id[16];
} ATTRIBUTE_PACKED;

#define	SMB2_FREQ_STRUCTURE_SIZE		24
CTASSERT(sizeof(struct smb2_flush_request) == SMB2_FREQ_STRUCTURE_SIZE);

struct smb2_flush_response {
	uint16_t	fres_structure_size;
	uint16_t	fres_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_FRES_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_flush_response) == SMB2_FRES_STRUCTURE_SIZE);

struct smb2_read_request {
	uint16_t	rreq_structure_size;
	uint8_t		rreq_padding;
	uint8_t		rreq_reserved;
	uint32_t	rreq_length;
	uint64_t	rreq_offset;
	uint8_t		rreq_file_id[16];
	uint32_t	rreq_minimum_count;
	uint32_t	rreq_channel;
	uint32_t	rreq_remaining_bytes;
	uint16_t	rreq_read_channel_info_offset;
	uint16_t	rreq_read_channel_info_length;
	uint8_t		rreq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_RREQ_STRUCTURE_SIZE		49
CTASSERT(sizeof(struct smb2_read_request) == SMB2_RREQ_STRUCTURE_SIZE);

struct smb2_read_response {
	uint16_t	rres_structure_size;
	uint8_t		rres_data_offset;
	uint8_t		rres_reserved;
	uint32_t	rres_data_length;
	uint32_t	rres_data_remaining;
	uint32_t	rres_reserved2;
	uint8_t		rres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_RRES_STRUCTURE_SIZE		17
CTASSERT(sizeof(struct smb2_read_response) == SMB2_RRES_STRUCTURE_SIZE);

struct smb2_write_request {
	uint16_t	wreq_structure_size;
	uint16_t	wreq_data_offset;
	uint32_t	wreq_length;
	uint64_t	wreq_offset;
	uint8_t		wreq_file_id[16];
	uint32_t	wreq_channel;
	uint32_t	wreq_remaining_bytes;
	uint16_t	wreq_write_channel_info_offset;
	uint16_t	wreq_write_channel_info_length;
	uint32_t	wreq_flags;
	uint8_t		wreq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_WREQ_STRUCTURE_SIZE		49
CTASSERT(sizeof(struct smb2_write_request) == SMB2_WREQ_STRUCTURE_SIZE);

struct smb2_write_response {
	uint16_t	wres_structure_size;
	uint16_t	wres_reserved;
	uint32_t	wres_count;
	uint32_t	wres_remaining;
	uint16_t	wres_write_channel_info_offset;
	uint16_t	wres_write_channel_info_length;
} ATTRIBUTE_PACKED;

/*
 * XXX: According to [MS-SMB2], this should be 17; bug in the specification?
 */
#define	SMB2_WRES_STRUCTURE_SIZE		16
CTASSERT(sizeof(struct smb2_write_response) == SMB2_WRES_STRUCTURE_SIZE);

struct smb2_oplock_break_notification {
	uint16_t	obn_structure_size;
	uint8_t		obn_oplock_level;
	uint8_t		obn_reserved;
	uint32_t	obn_reserved2;
	uint8_t		obn_file_id[16];
} ATTRIBUTE_PACKED;

#define	SMB2_OBN_STRUCTURE_SIZE			24
CTASSERT(sizeof(struct smb2_oplock_break_notification) == SMB2_OBN_STRUCTURE_SIZE);

struct smb2_oplock_break_acknowledgement {
	uint16_t	oba_structure_size;
	uint8_t		oba_oplock_level;
	uint8_t		oba_reserved;
	uint32_t	oba_reserved2;
	uint8_t		oba_file_id[16];
} ATTRIBUTE_PACKED;

#define	SMB2_OBA_STRUCTURE_SIZE			24
CTASSERT(sizeof(struct smb2_oplock_break_acknowledgement) == SMB2_OBA_STRUCTURE_SIZE);

struct smb2_oplock_break_response {
	uint16_t	obr_structure_size;
	uint8_t		obr_oplock_level;
	uint8_t		obr_reserved;
	uint32_t	obr_reserved2;
	uint8_t		obr_file_id[16];
} ATTRIBUTE_PACKED;

#define	SMB2_OBR_STRUCTURE_SIZE			24
CTASSERT(sizeof(struct smb2_oplock_break_response) == SMB2_OBR_STRUCTURE_SIZE);

struct smb2_lock_request {
	uint16_t	lkreq_structure_size;
	uint16_t	lkreq_lock_count;
	uint32_t	lkreq_lock_sequence;
	uint8_t		lkreq_file_id[16];
	uint8_t		lkreq_locks[24];
} ATTRIBUTE_PACKED;

#define	SMB2_LKREQ_STRUCTURE_SIZE		48
CTASSERT(sizeof(struct smb2_lock_request) == SMB2_LKREQ_STRUCTURE_SIZE);

struct smb2_lock_response {
	uint16_t	lkres_structure_size;
	uint16_t	lkres_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_LKRES_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_lock_response) == SMB2_LKRES_STRUCTURE_SIZE);

struct smb2_echo_request {
	uint16_t	ereq_structure_size;
	uint16_t	ereq_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_EREQ_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_echo_request) == SMB2_EREQ_STRUCTURE_SIZE);

struct smb2_echo_response {
	uint16_t	eres_structure_size;
	uint16_t	eres_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_ERES_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_echo_response) == SMB2_ERES_STRUCTURE_SIZE);

struct smb2_cancel_request {
	uint16_t	careq_structure_size;
	uint16_t	careq_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_CAREQ_STRUCTURE_SIZE		4
CTASSERT(sizeof(struct smb2_cancel_request) == SMB2_CAREQ_STRUCTURE_SIZE);

struct smb2_ioctl_request {
	uint16_t	ireq_structure_size;
	uint16_t	ireq_reserved;
	uint32_t	ireq_ctl_code;
	uint8_t		ireq_file_id[16];
	uint32_t	ireq_input_offset;
	uint32_t	ireq_input_count;
	uint32_t	ireq_max_input_response;
	uint32_t	ireq_output_offset;
	uint32_t	ireq_output_count;
	uint32_t	ireq_max_output_response;
	uint32_t	ireq_flags;
	uint32_t	ireq_reserved2;
	uint8_t		ireq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_IREQ_STRUCTURE_SIZE		57
CTASSERT(sizeof(struct smb2_ioctl_request) == SMB2_IREQ_STRUCTURE_SIZE);

struct smb2_ioctl_response {
	uint16_t	ires_structure_size;
	uint16_t	ires_reserved;
	uint32_t	ires_ctl_code;
	uint8_t		ires_file_id[16];
	uint32_t	ires_input_offset;
	uint32_t	ires_input_count;
	uint32_t	ires_output_offset;
	uint32_t	ires_output_count;
	uint32_t	ires_flags;
	uint32_t	ires_reserved2;
	uint8_t		ires_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_IRES_STRUCTURE_SIZE		49
CTASSERT(sizeof(struct smb2_ioctl_response) == SMB2_IRES_STRUCTURE_SIZE);

struct smb2_query_directory_request {
	uint16_t	qreq_structure_size;
	uint8_t		qreq_file_information_class;
	uint8_t		qreq_flags;
	uint32_t	qreq_file_index;
	uint8_t		qreq_file_id[16];
	uint16_t	qreq_file_name_offset;
	uint16_t	qreq_file_name_length;
	uint32_t	qreq_output_buffer_length;
	uint8_t		qreq_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_QREQ_STRUCTURE_SIZE		33
CTASSERT(sizeof(struct smb2_query_directory_request) == SMB2_QREQ_STRUCTURE_SIZE);

struct smb2_query_directory_response {
	uint16_t	qres_structure_size;
	uint16_t	qres_output_buffer_offset;
	uint32_t	qres_output_buffer_length;
	uint8_t		qres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_QRES_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_query_directory_response) == SMB2_QRES_STRUCTURE_SIZE);

struct smb2_change_notify_request {
	uint16_t	cnreq_structure_size;
	uint16_t	cnreq_flags;
	uint32_t	cnreq_output_buffer_length;
	uint8_t		cnreq_file_id[16];
	uint32_t	cnreq_completion_filter;
	uint32_t	cnreq_reserved;
} ATTRIBUTE_PACKED;

#define	SMB2_CNREQ_STRUCTURE_SIZE		32
CTASSERT(sizeof(struct smb2_change_notify_request) == SMB2_CNREQ_STRUCTURE_SIZE);

struct smb2_change_notify_response {
	uint16_t	cnres_structure_size;
	uint16_t	cnres_output_buffer_offset;
	uint32_t	cnres_output_buffer_length;
	uint8_t		cnres_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_CNRES_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_change_notify_response) == SMB2_CNRES_STRUCTURE_SIZE);

struct smb2_query_info_request {
	uint16_t	qireq_structure_size;
	uint8_t		qireq_info_type;
	uint8_t		qireq_file_info_class;
	uint32_t	qireq_output_buffer_length;
	uint16_t	qireq_input_buffer_offset;
	uint16_t	qireq_reserved;
	uint32_t	qireq_input_buffer_length;
	uint32_t	qireq_additional_information;
	uint32_t	qireq_flags;
	uint8_t		qireq_file_id[16];
	uint8_t		qires_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_QIREQ_STRUCTURE_SIZE		41
CTASSERT(sizeof(struct smb2_query_info_request) == SMB2_QIREQ_STRUCTURE_SIZE);

struct smb2_query_info_response {
	uint16_t	qires_structure_size;
	uint16_t	qires_output_buffer_offset;
	uint32_t	qires_output_buffer_length;
	uint8_t		qires_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_QIRES_STRUCTURE_SIZE		9
CTASSERT(sizeof(struct smb2_query_info_response) == SMB2_QIRES_STRUCTURE_SIZE);

struct smb2_set_info_request {
	uint16_t	sireq_structure_size;
	uint8_t		sireq_info_type;
	uint8_t		sireq_file_info_class;
	uint32_t	sireq_buffer_length;
	uint16_t	sireq_buffer_offset;
	uint16_t	sireq_reserved;
	uint32_t	sireq_additional_information;
	uint8_t		sireq_file_id[16];
	uint8_t		sires_buffer[1];
} ATTRIBUTE_PACKED;

#define	SMB2_SIREQ_STRUCTURE_SIZE		33
CTASSERT(sizeof(struct smb2_set_info_request) == SMB2_SIREQ_STRUCTURE_SIZE);

struct smb2_set_info_response {
	uint16_t	sires_structure_size;
} ATTRIBUTE_PACKED;

#define	SMB2_SIRES_STRUCTURE_SIZE		2
CTASSERT(sizeof(struct smb2_set_info_response) == SMB2_SIRES_STRUCTURE_SIZE);

#if (!defined __GNUC__)
#pragma pack()
#endif

#endif /* !SMB2_HEADERS_H */
