PREFIX?=/usr/local
BINDIR = ${PREFIX}/sbin
MANDIR = ${PREFIX}/man

SRC = src

CFLAGS?= -O2

all : 
	@cd $(SRC); $(MAKE) dnsmasq 

clean :
	rm -f *~ */*~ $(SRC)/*.o $(SRC)/dnsmasq core build

install : $(SRC)/dnsmasq
	install -d $(DESTDIR)$(BINDIR) -d $(DESTDIR)$(MANDIR)/man8
	install -m 644 dnsmasq.8 $(DESTDIR)$(MANDIR)/man8 
	install -m 755 $(SRC)/dnsmasq $(DESTDIR)$(BINDIR)




