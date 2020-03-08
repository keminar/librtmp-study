CC=gcc
INC=-I../ 
LIB_RTMP=-lrtmp -L../librtmp/
CFLAGS=-Wall -g -O0
PROGS=push_flv

all: $(PROGS)
push_flv: 
	$(CC) push_flv.c $(CFLAGS) $(INC) $(LIB_RTMP) -o $@

clean:
	rm -f $(PROGS)