#include <stdint.h>

struct smb2_connection {
	int	c_fd;
	int64_t	c_credits_first;
	int64_t	c_credits_after_last;
};

void				smb2_connection_add_credits(struct smb2_connection *conn, int64_t credits);
int64_t				smb2_connection_next_message_id(struct smb2_connection *conn);
