#include <err.h>

#include "smb2_connection.h"

void
smb2_connection_add_credits(struct smb2_connection *conn, int64_t credits)
{
	conn->c_credits_after_last += credits;
}

int64_t
smb2_connection_next_message_id(struct smb2_connection *conn)
{
	int64_t msgid;

	if (conn->c_credits_first == conn->c_credits_after_last)
		errx(1, "out of credits");

	msgid = conn->c_credits_first;
	conn->c_credits_first++;

	return (msgid);
}
