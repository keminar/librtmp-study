CC=gcc
INC=-I../ 
LIB_RTMP=-lrtmp -L../librtmp/
CFLAGS=-Wall -g -O0
PROGS=push_flv dump_flv handshake_server connect_server

all: $(PROGS)

debug: clean all

push_flv: 
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@

dump_flv:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@

handshake_server:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@
connect_server:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@
clean:
	rm -f $(PROGS)