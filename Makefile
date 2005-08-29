PREFIX?=/usr/local
BINDIR = ${PREFIX}/sbin
MANDIR = ${PREFIX}/man

SRC = src

CFLAGS?= -O2

all : 
	$(MAKE) -f ../bld/Makefile -C $(SRC) dnsmasq 

clean :
	rm -f *~ bld/*~ contrib/*/*~ */*~ $(SRC)/*.o $(SRC)/dnsmasq core build

install : all
	install -d $(DESTDIR)$(BINDIR) -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 dnsmasq.8 $(DESTDIR)$(MANDIR)/man8 
	install -m 755 $(SRC)/dnsmasq $(DESTDIR)$(BINDIR)




