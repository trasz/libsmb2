default: all

all: *.c *.h
	cc -Wall -Werror -ggdb -o smb2 *.c spnego/spnego.c -lgssapi_krb5

clean:
	rm -rf smb2 smb2.dSYM
