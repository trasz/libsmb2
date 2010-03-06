#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>

#include "smb2_connection.h"
#include "smb2_headers.h"
#include "smb2_status.h"
#include "smb2_packet.h"

static void
smb2_parse_nres(struct smb2_packet *p)
{
	struct smb2_negotiate_response *nres;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE)
		errx(1, "smb2_parse_nres: received packet too small (%d)", p->p_buf_len);

	nres = (struct smb2_negotiate_response *)(p->p_buf + SMB2_PH_STRUCTURE_SIZE);

	/*
	 * -1, because SMB2_NRES_STRUCTURE_SIZE includes one byte of the buffer.
	 */
	if (nres->nres_security_buffer_offset != SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE - 1)
		errx(1, "smb2_parse_nres: weird security buffer offset, is %d, should be %d",
		    nres->nres_security_buffer_offset, SMB2_PH_STRUCTURE_SIZE + SMB2_NRES_STRUCTURE_SIZE);

	if (nres->nres_security_buffer_offset + nres->nres_security_buffer_length > p->p_buf_len)
		errx(1, "smb2_parse_nres: security buffer (%d) longer than packet (%d)", nres->nres_security_buffer_length, p->p_buf_len);
}

static void
smb2_parse_ssres(struct smb2_packet *p)
{
	struct smb2_session_setup_response *ssres;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE + SMB2_SSRES_STRUCTURE_SIZE)
		errx(1, "smb2_parse_ssres: received packet too small (%d)", p->p_buf_len);

	ssres = (struct smb2_session_setup_response *)(p->p_buf + SMB2_PH_STRUCTURE_SIZE);
}

static void
smb2_parse_packet_header(struct smb2_packet *p)
{
	struct smb2_packet_header_sync *ph;

	if (p->p_buf_len < SMB2_PH_STRUCTURE_SIZE)
		errx(1, "smb2_parse_packet_header: received packet too small (%d)", p->p_buf_len);

	ph = (struct smb2_packet_header_sync *)p->p_buf;

	if (ph->ph_protocol_id != SMB2_PH_PROTOCOL_ID)
		errx(1, "smb2_parse_packet_header: invalid protocol id (0x%x)", ph->ph_protocol_id);
	if (ph->ph_structure_size != SMB2_PH_STRUCTURE_SIZE)
		errx(1, "smb2_parse_packet_header: invalid structure size (%d)", ph->ph_structure_size);

	smb2_connection_add_credits(p->p_conn, ph->ph_credit_request_response);
	printf("credits granted: %d\n", ph->ph_credit_request_response);

	if (ph->ph_status != SMB2_STATUS_SUCCESS)
		errx(1, "smb2_parse_packet_header: bad status (%d)", ph->ph_status);

	switch (ph->ph_command) {
	case SMB2_NEGOTIATE:
		smb2_parse_nres(p);
		break;
	case SMB2_SESSION_SETUP:
		smb2_parse_ssres(p);
		break;
	default:
		errx(1, "smb2_parse_packet_header: unknown command %d", ph->ph_command);
	}
}

void
smb2_parse(struct smb2_packet *p)
{
	smb2_parse_packet_header(p);
}

