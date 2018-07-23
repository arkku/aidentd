BIN=aidentd
OBJS=aidentd.o conntrack.o privileges.o netlink.o log.o forwarding.o
MAN=aidentd.8
PREFIX=/usr/local
INSTALL_DIR=$(PREFIX)/sbin
INSTALL_MAN=$(PREFIX)/share/man/man8

CC = gcc
CFLAGS = -Wall -pedantic -std=gnu99 -Os
LDFLAGS = -lcap

all: $(BIN)

aidentd: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $+ $(LDFLAGS)

$(OBJS): aidentd.h log.h

priviliges.o: privileges.c privileges.h conntrack.h

conntrack.o: conntrack.c conntrack.h forwarding.h

netlink.o: netlink.c netlink.h

log.o: log.c

forwarding.o: forwarding.c forwarding.h

aidentd.o: aidentd.c conntrack.h privileges.h

$(INSTALL_DIR)/$(BIN): $(BIN) $(INSTALL_DIR)
	install $< "$@"

$(INSTALL_DIR):
	mkdir -p $<

$(INSTALL_MAN):
	mkdir -p $<

$(INSTALL_MAN)/$(MAN): $(MAN) $(INSTALL_MAN)
	install -m 0644 $< "$@"
	-mandb

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(BIN)

install: $(INSTALL_DIR)/$(BIN) $(INSTALL_MAN)/$(MAN)
