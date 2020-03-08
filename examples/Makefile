CC=gcc
INC=-I../ 
LIB_RTMP=-lrtmp -L../librtmp/
CFLAGS=-Wall -g -O0
PROGS=push_flv dump_flv

all: $(PROGS)

push_flv: 
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@

dump_flv:
	$(CC) $@.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@

clean:
	rm -f $(PROGS)