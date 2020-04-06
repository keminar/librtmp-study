CC=gcc
INC=-I../ 
LIB_RTMP=-lrtmp -L../librtmp/
CFLAGS=-Wall -g -O0
PROGS=push_flv dump_flv handshake_server connect_server stream_server

all: $(PROGS)

debug: clean all

debug2: clean2 stream_server
clean2:
	rm -f stream_server

push_flv: 
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@

dump_flv:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@

handshake_server:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@
connect_server:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@
stream_server:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@
clean:
	rm -f $(PROGS)