#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "smb2_connection.h"
#include "smb2_headers.h"
#include "smb2_tcp.h"

void
smb2_tcp_send(struct smb2_packet *p)
{
	int written, to_write;

	p->p_tcp_encap = htonl(p->p_buf_len);
	to_write = sizeof(p->p_tcp_encap) + p->p_buf_len;
	written = write(p->p_conn->c_fd, &p->p_tcp_encap, to_write);
	if (written != to_write)
		errx(1, "smb2_tcp_send: write failed; wrote %d, should be %d", written, to_write);
}

void
smb2_tcp_receive(struct smb2_packet *p)
{
	int bytes_read;
	int32_t encapsulation;

	bytes_read = read(p->p_conn->c_fd, &encapsulation, sizeof(encapsulation));
	if (bytes_read != sizeof(encapsulation))
		errx(1, "smb2_tcp_receive: read failed (%d)", bytes_read);
	encapsulation = ntohl(encapsulation);
	if (encapsulation > sizeof(p->p_buf))
		errx(1, "smb2_tcp_receive: received overlength packet (%d)", encapsulation);
	bytes_read = read(p->p_conn->c_fd, p->p_buf, encapsulation);
	if (bytes_read != encapsulation)
		errx(1, "smb2_tcp_receive: read failed 2");
	p->p_buf_len = encapsulation;
}


