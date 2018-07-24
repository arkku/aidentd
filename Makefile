PROGRAM=aidentd
OBJS=$(PROGRAM).o conntrack.o privileges.o netlink.o log.o forwarding.o
MAN=$(PROGRAM).8
DESTDIR ?= /usr/local
BINDIR=$(DESTDIR)/sbin
MANDIR=$(DESTDIR)/share/man/man8
VERSION = $(shell sed -ne '/VERSION_STRING[ ]*=/ {s/^.*VERSION_STRING[ ]*=[ ]*"\([^"]*\)".*/\1/; p; q}' $(PROGRAM).c)
ARCHIVE_PREFIX=$(PROGRAM)_$(VERSION)
ARCHIVE=../$(ARCHIVE_PREFIX).orig.tar.gz

CC = gcc
CFLAGS = -Wall -pedantic -std=gnu99 -Os
LDFLAGS = -lcap

all: $(PROGRAM)

$(PROGRAM): $(OBJS)
	$(CC) -o $@ $(CFLAGS) $+ $(LDFLAGS)

$(OBJS): $(PROGRAM).h log.h

priviliges.o: privileges.c privileges.h conntrack.h

conntrack.o: conntrack.c conntrack.h forwarding.h

netlink.o: netlink.c netlink.h

log.o: log.c

forwarding.o: forwarding.c forwarding.h

$(PROGRAM).o: $(PROGRAM).c conntrack.h privileges.h

$(BINDIR)/$(PROGRAM): $(PROGRAM) $(BINDIR)
	install $< "$@"

$(BINDIR):
	mkdir -p $<

$(MANDIR):
	mkdir -p $<

$(MANDIR)/$(MAN): $(MAN) $(MANDIR)
	install -m 0644 $< "$@"
	-mandb

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(PROGRAM)

install: $(BINDIR)/$(PROGRAM) $(MANDIR)/$(MAN)

$(ARCHIVE): $(wildcard *.c *.h) $(MAN) README.md Makefile
	git archive --format=tar.gz --prefix=$(ARCHIVE_PREFIX)/ --output=$@ HEAD

archive: $(ARCHIVE)
