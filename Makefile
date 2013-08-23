# udpxscan Makefile
# Customise the path of your kernel

VERSION = 2.0.0
TOPDIR = `basename ${PWD}`

CFLAGS += -Wall -fomit-frame-pointer
CFLAGS += -O3
#CFLAGS += -g
LDLIBS += -lrt
LDLIBS_UDPXYSCAN += -lcurl -lpthread

OBJ_UDPXYSCAN = udpxyscan.o

PREFIX ?= /usr/local
BIN = $(DESTDIR)/$(PREFIX)/bin
MAN = $(DESTDIR)/$(PREFIX)/share/man/man1

all: udpxyscan

$(OBJ_UDPXYSCAN): Makefile

udpxyscan: $(OBJ_UDPXYSCAN)
	$(CC) -o $@ $(OBJ_UDPXYSCAN) $(LDLIBS_UDPXYSCAN) $(LDLIBS)

clean:
	@rm -f udpxyscan $(OBJ_UDPXYSCAN)

install: all
	@install -d $(BIN)
	@install -d $(MAN)
	@install udpxyscan $(BIN)

uninstall:
	@rm $(BIN)/udpxyscan

dist:
	( cd ../ && \
	  tar -cj --exclude-vcs --exclude $(TOPDIR)/*.tar.bz2 $(TOPDIR)/ > $(TOPDIR)/udpxyscan-$(VERSION).tar.bz2 )

