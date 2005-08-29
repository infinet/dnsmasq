# Uncomment this on Solaris.
#LIBS = -lsocket -lnsl

CFLAGS ?= -O2
PKG_CONFIG ?= pkg-config

OBJS = cache.o rfc1035.o util.o option.o forward.o isc.o network.o \
       dnsmasq.o dhcp.o lease.o rfc2131.o netlink.o dbus.o

.c.o: dnsmasq.h config.h 
	$(CC) $(CFLAGS) `../bld/pkg-wrapper $(PKG_CONFIG) --cflags dbus-1` $(RPM_OPT_FLAGS) -Wall -W -c $*.c 

dnsmasq : $(OBJS) dnsmasq.h config.h
	$(CC) -o $@  $(OBJS) `../bld/pkg-wrapper $(PKG_CONFIG) --libs dbus-1` $(LIBS) 



