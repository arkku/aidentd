BINS=aidentd
OBJS=aidentd.o conntrack.o privileges.o netlink.o log.o forwarding.o

CC = gcc
CFLAGS = -Wall -pedantic -std=gnu99 -Os
LDFLAGS = -lcap

all: $(BINS)

aidentd: $(OBJS)
	$(CC) -o $@ $(CFLAGS) $+ $(LDFLAGS)

$(OBJS): aidentd.h log.h

priviliges.o: privileges.c privileges.h conntrack.h

conntrack.o: conntrack.c conntrack.h forwarding.h

netlink.o: netlink.c netlink.h

log.o: log.c

forwarding.o: forwarding.c forwarding.h

aidentd.o: aidentd.c conntrack.h privileges.h

clean:
	rm -f $(OBJS)

distclean: clean
	rm -f $(BINS)
