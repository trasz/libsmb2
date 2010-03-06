#ifndef SMB2_TCP_H
#define	SMB2_TCP_H

#define	SMB2_TCP_PORT	445

#include "smb2_packet.h"

void	smb2_tcp_send(struct smb2_packet *p);
void	smb2_tcp_receive(struct smb2_packet *p);

#endif /* !SMB2_TCP_H */
