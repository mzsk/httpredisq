# Makefile for httpsqs
CC=gcc
CFLAGS=-L/usr/local/libevent-2.0.10-stable/lib -I/usr/local/libevent-2.0.10-stable/include  -levent -lhiredis -I/usr/local/include/hiredis/ -lz -lbz2 -lrt -lpthread -lm -lc -O2

httpsqs: httpredisq.c
	$(CC) -o httpredisq httpredisq.c $(CFLAGS)

clean:
	rm -f httpredisq

install: httpredisq
	install $(INSTALL_FLAGS) -m 4755 -o root httpredisq $(DESTDIR)/usr/bin
