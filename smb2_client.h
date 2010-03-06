struct smb2_connection;

struct smb2_connection		*smb2_connect(const char *address);
void				smb2_disconnect(struct smb2_connection *conn);

