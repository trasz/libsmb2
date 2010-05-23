default: all

all: *.c *.h
	cc -Wall -ggdb -o smb2 smb2_client.c smb2_der.c smb2_spnego.c smb2_tcp.c smb2_connection.c smb2_packet.c smb2_status.c smb2_ntlmssp.c smb2_unicode.c -liconv
	cc -Wall -ggdb -o smb2d smb2_server.c smb2_der.c smb2_spnego.c smb2_tcp.c smb2_connection.c smb2_packet.c smb2_status.c smb2_ntlmssp.c smb2_unicode.c -liconv

clean:
	rm -rf smb2 smb2d smb2.dSYM smb2d.dSYM
