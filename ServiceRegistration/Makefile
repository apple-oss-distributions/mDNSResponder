BUILDDIR = build
OBJDIR = objects
GENKEY=\"/usr/local/bin/mbedtls_gen_key\"
CERTWRITE=\"/usr/local/bin/mbedtls_cert_write\"

ifndef os
  SYSTEM := $(shell uname -s)
  ifeq ($(SYSTEM), Darwin)
    os=x
  else ifeq ($(SYSTEM), Linux)
    os_id := $(shell sed -n -e 's/^ID=//p' < /etc/os-release)
    ifeq ($(os_id), raspbian)
      os=raspbian
    else
      os=linux
    endif
  endif
endif

ifdef INSTBASE
  INSTALL_PREFIX=$(INSTBASE)
else
  INSTALL_PREFIX=$(DESTDIR)/usr
endif

CP?=/bin/cp

ifeq ($(os),x)
SRPCFLAGS = -O0 -g -Wall -Werror -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DUSE_KQUEUE -DHAVE_SOCKADDR_DL -DGENKEY_PROGRAM=$(GENKEY) -DCERTWRITE_PROGRAM=$(CERTWRITE) -DEXCLUDE_TLS -D__APPLE_USE_RFC_3542 -DIOLOOP_MACOS
SRPLDOPTS = -framework CoreServices -framework Security -framework CoreFoundation -framework Network
HMACOBJS     = $(OBJDIR)/hmac-macos.o
SIGNOBJS     = $(OBJDIR)/sign-macos.o 
VERIFYOBJS   = $(OBJDIR)/verify-macos.o
TLSOBJS      =
IOOBJS       = $(OBJDIR)/macos-ioloop.o $(OBJDIR)/posix.o
IOWOTLSOBJS  = $(OBJDIR)/macos-ioloop.o $(OBJDIR)/posix.o
else ifeq ($(os), linux)
SRPCFLAGS = -DMDNS_UDS_SERVERPATH=\"/var/run/mdnsd\" -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DNOT_HAVE_SA_LEN -DUSE_SELECT -DUSE_INOTIFY -DGENKEY_PROGRAM=$(GENKEY) -DCERTWRITE_PROGRAM=$(CERTWRITE) -DNO_KEYCHAIN
SRPLDOPTS = /usr/local/lib/libmbedtls.a /usr/local/lib/libmbedx509.a /usr/local/lib/libmbedcrypto.a 
#SRPLDOPTS = -lmbedcrypto -lmbedtls -lmbedx509
HMACOBJS     = $(OBJDIR)/hmac-mbedtls.o
SIGNOBJS     = $(OBJDIR)/sign-mbedtls.o 
VERIFYOBJS   = $(OBJDIR)/verify-mbedtls.o
TLSOBJS      = $(OBJDIR)/tls-mbedtls.o
IOOBJS       = $(OBJDIR)/ioloop.o $(TLSOBJS)
IOWOTLSOBJS  = $(OBJDIR)/ioloop-notls.o
else ifeq ($(os), linux-uclibc)
SRPCFLAGS = -DMDNS_UDS_SERVERPATH=\"/var/run/mdnsd\" -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DNOT_HAVE_SA_LEN -DUSE_SELECT -DLINUX_GETENTROPY -DGENKEY_PROGRAM=$(GENKEY) -DCERTWRITE_PROGRAM=$(CERTWRITE) -DNO_KEYCHAIN
SRPLDOPTS = -lmbedcrypto -lmbedtls -lmbedx509
HMACOBJS     = $(OBJDIR)/hmac-mbedtls.o
SIGNOBJS     = $(OBJDIR)/sign-mbedtls.o 
VERIFYOBJS   = $(OBJDIR)/verify-mbedtls.o
TLSOBJS      = $(OBJDIR)/tls-mbedtls.o
IOOBJS       = $(OBJDIR)/ioloop.o $(TLSOBJS)
IOWOTLSOBJS  = $(OBJDIR)/ioloop-notls.o
else ifeq ($(os), raspbian)
SRPCFLAGS = -DMDNS_UDS_SERVERPATH=\"/var/run/mdnsd\" -O0 -g -Wall -Werror -DSTANDALONE -I../mDNSCore -I/usr/local/include -I. -I../mDNSShared -I../DSO -MMD -MF .depfile-${notdir $<} -DNOT_HAVE_SA_LEN -DUSE_SELECT -DLINUX_GETENTROPY -DGENKEY_PROGRAM=$(GENKEY) -DCERTWRITE_PROGRAM=$(CERTWRITE) -DNO_KEYCHAIN
SRPLDOPTS = /usr/local/lib/libmbedtls.a /usr/local/lib/libmbedx509.a /usr/local/lib/libmbedcrypto.a 
HMACOBJS     = $(OBJDIR)/hmac-mbedtls.o
SIGNOBJS     = $(OBJDIR)/sign-mbedtls.o 
VERIFYOBJS   = $(OBJDIR)/verify-mbedtls.o
TLSOBJS      = $(OBJDIR)/tls-mbedtls.o
IOOBJS       = $(OBJDIR)/ioloop.o $(TLSOBJS)
IOWOTLSOBJS  = $(OBJDIR)/ioloop-notls.o
else
SRPCFLAGS=$(os) $(os_id)
endif

all:	setup $(BUILDDIR)/srp-client $(BUILDDIR)/srp-mdns-proxy $(BUILDDIR)/keydump $(BUILDDIR)/dnssd-proxy $(BUILDDIR)/srp-dns-proxy # $(BUILDDIR)/dnssd-relay

install: all
	$(CP) $(BUILDDIR)/srp-client $(INSTALL_PREFIX)/sbin
	$(CP) $(BUILDDIR)/srp-dns-proxy $(INSTALL_PREFIX)/sbin
	$(CP) $(BUILDDIR)/srp-mdns-proxy $(INSTALL_PREFIX)/sbin
	$(CP) $(BUILDDIR)/dnssd-proxy $(INSTALL_PREFIX)/sbin
	$(CP) $(BUILDDIR)/keydump $(INSTALL_PREFIX)/bin

# 'setup' sets up the build directory structure the way we want
setup:
	@if test ! -d $(OBJDIR)   ; then mkdir -p $(OBJDIR)   ; fi
	@if test ! -d $(BUILDDIR) ; then mkdir -p $(BUILDDIR) ; fi

# clean removes targets and objects
clean:
	@if test -d $(OBJDIR)   ; then rm -r $(OBJDIR)   ; fi
	@if test -d $(BUILDDIR) ; then rm -r $(BUILDDIR) ; fi

SIMPLEOBJS   = $(OBJDIR)/towire.o $(SIGNOBJS)
DSOOBJS      = $(OBJDIR)/dso.o
MDNSOBJS     = $(OBJDIR)/dnssd_clientstub.o $(OBJDIR)/dnssd_ipc.o
FROMWIREOBJS = $(OBJDIR)/fromwire.o $(VERIFYOBJS) $(OBJDIR)/wireutils.o
CFOBJS       = $(OBJDIR)/config-parse.o

$(BUILDDIR)/dnssd-relay:  $(OBJDIR)/dnssd-relay.o $(DSOOBJS) $(IOOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/dnssd-proxy:  $(OBJDIR)/dnssd-proxy.o $(SIMPLEOBJS) $(DSOOBJS) $(MDNSOBJS) $(FROMWIREOBJS) $(IOOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/srp-client:	$(OBJDIR)/srp-ioloop.o $(OBJDIR)/srp-client.o $(SIMPLEOBJS) $(IOWOTLSOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/srp-dns-proxy:	$(OBJDIR)/srp-dns-proxy.o $(OBJDIR)/srp-parse.o $(SIMPLEOBJS) $(FROMWIREOBJS) $(IOOBJS) $(HMACOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/srp-mdns-proxy:	$(OBJDIR)/srp-mdns-proxy.o $(OBJDIR)/srp-parse.o $(MDNSOBJS) $(SIMPLEOBJS) $(FROMWIREOBJS) $(IOOBJS) $(HMACOBJS) $(CFOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(BUILDDIR)/keydump:	$(OBJDIR)/keydump.o $(SIMPLEOBJS) $(FROMWIREOBJS) $(IOOBJS)
	$(CC) -o $@ $+ $(SRPLDOPTS)

$(OBJDIR)/dso.o:	../DSO/dso.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/dnssd_clientstub.o:  ../mDNSShared/dnssd_clientstub.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/dnssd_ipc.o:  ../mDNSShared/dnssd_ipc.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c -I. -I../mDNSShared $<

$(OBJDIR)/ioloop-notls.o: ioloop.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -DEXCLUDE_TLS -c  $<

$(OBJDIR)/%.o:	%.c
	$(CC) -o $@ $(SRPCFLAGS) $(CFLAGS) -c  $<

-include .depfile-config-parse.c
-include .depfile-dnssd-proxy.c
-include .depfile-dnssd_clientstub.c
-include .depfile-dnssd_ipc.c
-include .depfile-dso.c
-include .depfile-fromwire.c
-include .depfile-hmac-mbedtls.c
-include .depfile-hmac-macos.c
-include .depfile-ioloop.c
-include .depfile-keydump.c
-include .depfile-sign-mbedtls.c
-include .depfile-sign-macos.c
-include .depfile-srp-client.c
-include .depfile-srp-dns-proxy.c
-include .depfile-srp-ioloop.c
-include .depfile-srp-mdns-proxy.c
-include .depfile-srp-parse.c
-include .depfile-tls-mbedtls.c
-include .depfile-towire.c
-include .depfile-verify-mbedtls.c
-include .depfile-verify-macos.c
-include .depfile-wireutils.c
