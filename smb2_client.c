#include <arpa/inet.h>
#include <sys/socket.h>
#include <err.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "smb2_client.h"
#include "smb2_connection.h"
#include "smb2_headers.h"
#include "smb2_tcp.h"

static int
smb2_tcp_negotiate(struct smb2_connection *conn)
{
	struct smb2_packet *p;

	fprintf(stderr, "NEGOTIATE REQUEST...\n");
	p = smb2_packet_new(conn);
	smb2_packet_add_command(p, SMB2_NEGOTIATE);
	smb2_tcp_send(p);
	smb2_packet_delete(p);

	fprintf(stderr, "NEGOTIATE RESPONSE...\n");
	p = smb2_packet_new(conn);
	smb2_tcp_receive(p);
	smb2_parse(p);
	smb2_packet_delete(p);

	fprintf(stderr, "SESSION SETUP REQUEST...\n");
	p = smb2_packet_new(conn);
	smb2_packet_add_command(p, SMB2_SESSION_SETUP);
	smb2_tcp_send(p);
	smb2_packet_delete(p);

	fprintf(stderr, "SESSION SETUP RESPONSE...\n");
	p = smb2_packet_new(conn);
	smb2_tcp_receive(p);
	smb2_parse(p);
	smb2_packet_delete(p);

	return (0);
}

struct smb2_connection *
smb2_connect(const char *address)
{
	int error;
	struct sockaddr_in sin;
	struct hostent *he;
	struct smb2_connection *conn;

	conn = calloc(1, sizeof(*conn));
	if (conn == NULL)
		err(1, "malloc");

	conn->c_credits_first = 0;
	conn->c_credits_after_last = 1;

	conn->c_fd = socket(PF_INET, SOCK_STREAM, 0);
	if (conn->c_fd < 0)
		err(1, "socket");

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(SMB2_TCP_PORT);
	sin.sin_addr.s_addr = inet_addr(address);
	if (sin.sin_addr.s_addr == INADDR_NONE) {
		he = gethostbyname(address);
		if (he == NULL)
			errx(1, "gethostbyname: %s", hstrerror(h_errno));
		sin.sin_addr.s_addr = ((struct in_addr *)(void *)he->h_addr)->s_addr;
	}

	error = connect(conn->c_fd, (struct sockaddr *)&sin, sizeof(sin));
	if (error)
		err(1, "connect");

	error = smb2_tcp_negotiate(conn);
	if (error)
		errx(1, "smb2_negotiate");

	return (conn);
}

void
smb2_disconnect(struct smb2_connection *conn)
{

	// XXX: Ignored return value.
	close(conn->c_fd);
	free(conn);
}

static void
usage(void)
{
	fprintf(stderr, "usage: smb2 hostname\n");
	exit(-1);
}

int
main(int argc, char **argv)
{
	struct smb2_connection *conn;

	if (argc != 2)
		usage();

	conn = smb2_connect(argv[1]);
	smb2_disconnect(conn);

	return (0);
}
