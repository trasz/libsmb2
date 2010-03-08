default: all

all: *.c *.h
	cc -Wall -ggdb -o smb2 *.c -lgssapi_krb5

clean:
	rm -rf smb2 smb2.dSYM
