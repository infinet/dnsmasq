# dnsmasq is Copyright (c) 2000-2012 Simon Kelley
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 2 dated June, 1991, or
#  (at your option) version 3 dated 29 June, 2007.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#    
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

PREFIX = /usr/local
BINDIR = ${PREFIX}/sbin
MANDIR = ${PREFIX}/share/man
LOCALEDIR = ${PREFIX}/share/locale

BUILD_DIR = $(SRC)

CFLAGS = -Wall -W -O2

PKG_CONFIG = pkg-config
INSTALL = install
MSGMERGE = msgmerge
MSGFMT = msgfmt
XGETTEXT = xgettext

#################################################################

SRC = src
PO = po
MAN = man

DBUS_CFLAGS=`echo $(COPTS) | ../bld/pkg-wrapper HAVE_DBUS $(PKG_CONFIG) --cflags dbus-1` 
DBUS_LIBS=  `echo $(COPTS) | ../bld/pkg-wrapper HAVE_DBUS $(PKG_CONFIG) --libs dbus-1` 
IDN_CFLAGS= `echo $(COPTS) | ../bld/pkg-wrapper HAVE_IDN $(PKG_CONFIG) --cflags libidn` 
IDN_LIBS=   `echo $(COPTS) | ../bld/pkg-wrapper HAVE_IDN $(PKG_CONFIG) --libs libidn` 
CT_CFLAGS=  `echo $(COPTS) | ../bld/pkg-wrapper HAVE_CONNTRACK $(PKG_CONFIG) --cflags libnetfilter_conntrack`
CT_LIBS=    `echo $(COPTS) | ../bld/pkg-wrapper HAVE_CONNTRACK $(PKG_CONFIG) --libs libnetfilter_conntrack`
LUA_CFLAGS= `echo $(COPTS) | ../bld/pkg-wrapper HAVE_LUASCRIPT $(PKG_CONFIG) --cflags lua5.1` 
LUA_LIBS=   `echo $(COPTS) | ../bld/pkg-wrapper HAVE_LUASCRIPT $(PKG_CONFIG) --libs lua5.1` 
SUNOS_LIBS= `if uname | grep SunOS 2>&1 >/dev/null; then echo -lsocket -lnsl -lposix4; fi`
VERSION=    -DVERSION='\"`../bld/get-version`\"'

OBJS = cache.o rfc1035.o util.o option.o forward.o network.o \
       dnsmasq.o dhcp.o lease.o rfc2131.o netlink.o dbus.o bpf.o \
       helper.o tftp.o log.o conntrack.o dhcp6.o rfc3315.o dhcp-common.o 

HDRS = dnsmasq.h config.h dhcp_protocol.h dhcp6_protocol.h dns_protocol.h


all : $(BUILD_DIR)
	@cd $(BUILD_DIR) && $(MAKE) \
 BUILD_CFLAGS="$(VERSION) $(DBUS_CFLAGS) $(IDN_CFLAGS) $(CT_CFLAGS) $(LUA_CFLAGS)" \
 BUILD_LIBS="$(DBUS_LIBS) $(IDN_LIBS) $(CT_LIBS) $(LUA_LIBS) $(SUNOS_LIBS)" \
 -f ../Makefile dnsmasq 

clean :
	rm -f *~ $(BUILD_DIR)/*.mo contrib/*/*~ */*~ $(BUILD_DIR)/*.pot 
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/dnsmasq.a $(BUILD_DIR)/dnsmasq core */core

install : all install-common

install-common :
	$(INSTALL) -d $(DESTDIR)$(BINDIR) -d $(DESTDIR)$(MANDIR)/man8
	$(INSTALL) -m 644 $(MAN)/dnsmasq.8 $(DESTDIR)$(MANDIR)/man8 
	$(INSTALL) -m 755 $(BUILD_DIR)/dnsmasq $(DESTDIR)$(BINDIR)

all-i18n : $(BUILD_DIR)
	@cd $(BUILD_DIR) && $(MAKE) \
 I18N=-DLOCALEDIR=\'\"$(LOCALEDIR)\"\' \
 BUILD_CFLAGS="$(VERSION) $(DBUS_CFLAGS) $(CT_CFLAGS) $(LUA_CFLAGS) `$(PKG_CONFIG) --cflags libidn`" \
 BUILD_LIBS="$(DBUS_LIBS) $(CT_LIBS) $(LUA_LIBS) $(SUNOS_LIBS) `$(PKG_CONFIG) --libs libidn`"  \
 -f ../Makefile dnsmasq
	@cd $(PO); for f in *.po; do \
		cd ../$(BUILD_DIR) && $(MAKE) \
 -f ../Makefile $${f%.po}.mo; \
	done

install-i18n : all-i18n install-common
	cd $(BUILD_DIR); ../bld/install-mo $(DESTDIR)$(LOCALEDIR) $(INSTALL)
	cd $(MAN); ../bld/install-man $(DESTDIR)$(MANDIR) $(INSTALL)

merge : $(BUILD_DIR)
	@cd $(BUILD_DIR) && $(MAKE) -f ../Makefile dnsmasq.pot
	@cd $(PO); for f in *.po; do \
		echo -n msgmerge $$f && $(MSGMERGE) --no-wrap -U $$f ../$(BUILD_DIR)/dnsmasq.pot; \
	done

$(BUILD_DIR):
	mkdir $(BUILD_DIR)


# rules below are targets in recusive makes with cwd=$(SRC)

$(OBJS:.o=.c) $(HDRS):
	ln -s ../$(SRC)/$@ .

%.o:	%.c $(HDRS)
	$(CC) $(CFLAGS) $(COPTS) $(I18N) $(BUILD_CFLAGS) $(RPM_OPT_FLAGS) -c $*.c	

dnsmasq : $(OBJS) 
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(BUILD_LIBS) $(LIBS) 

dnsmasq.pot : $(OBJS:.o=.c) $(HDRS)
	$(XGETTEXT) -d dnsmasq --foreign-user --omit-header --keyword=_ -o $@ -i $(OBJS:.o=.c)

%.mo : ../po/%.po dnsmasq.pot
	$(MSGMERGE) -o - ../po/$*.po dnsmasq.pot | $(MSGFMT) -o $*.mo -



.PHONY : all clean install install-common all-i18n install-i18n merge 
