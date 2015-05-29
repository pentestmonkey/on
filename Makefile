SHELL	= /bin/sh
BIN	= .
PROGS	= $(BIN)/on
CFLAGS	= -O -I. $(XFLAGS)
RPCGEN	= rpcgen
#LIBS	= -lsocket -lnsl

all:	$(PROGS)

$(BIN)/on: rex.o rex_xdr.o
	$(CC) $(CFLAGS) -o on rex.o rex_xdr.o $(LIBS)

rex.h rex_xdr.c: rex.x
	$(RPCGEN) rex.x 2>/dev/null

rex.o rex_xdr.o: rex.h

clean:
	rm -f $(PROGS) *.o core rex_svc.c rex_clnt.c rex.h rex_xdr.c

install:
	install -o root -m 0755 on /usr/local/bin/
