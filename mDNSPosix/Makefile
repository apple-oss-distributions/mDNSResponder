# $Log: Makefile,v $
# Revision 1.13  2003/08/06 18:20:51  cheshire
# Makefile cleanup
#
# Revision 1.12  2003/08/01 02:20:02  cheshire
# Add mDNSIdentify tool, used to discover what version of mDNSResponder a particular host is running
#
# Revision 1.11  2003/07/14 18:11:54  cheshire
# Fix stricter compiler warnings
#
# Revision 1.10  2003/06/18 05:47:41  cheshire
# Enable stricter warnings on Jaguar and Panther builds
#
# Revision 1.9  2003/06/04 18:34:45  ksekar
# Bug #: <rdar://problem/3218120>: mDNSPosix does not build on Panther that has socklen_t
# Changed build targets "osx10.2" and "osx10.3" to "jaguar" and "panther".
#
# Revision 1.8  2003/06/04 00:23:12  ksekar
# Bug #: <rdar://problem/3218120>: mDNSPosix does not build on Panther that has socklen_t
# Created separate target OS's for 10.2 and 10.3.
#
# Revision 1.7  2003/04/16 02:11:37  cheshire
# Remove unnecessary $(CFLAGS) from linking rules
#
# Revision 1.6  2003/04/04 01:37:14  cheshire
# Added NetMonitor.c
#

# I assume that cc will be in your path. If not, you have to change the following to point to it.
CC = cc
CFLAGS_COMMON = -g -I../mDNSCore -I. -DMDNS_DEBUGMSGS=2

ifeq ($(os),solaris)
CFLAGS_OS =  -DNOT_HAVE_DAEMON -DNOT_HAVE_SA_LEN -D_XPG4_2 -D__EXTENSIONS__ -DHAVE_BROKEN_RECVIF_NAME -lsocket -lnsl
else
ifeq ($(os),linux)
CFLAGS_OS = -DNOT_HAVE_SA_LEN -W -Wall
else
ifeq ($(os),netbsd)
CFLAGS_OS =
else
ifeq ($(os),freebsd)
CFLAGS_OS =
else
ifeq ($(os),openbsd)
CFLAGS_OS = -DHAVE_BROKEN_RECVDSTADDR
else
ifeq ($(os),jaguar)
CFLAGS_OS = -DHAVE_IPV6 -W -Wall -no-cpp-precomp -DNOT_HAVE_SOCKLEN_T
else
ifeq ($(os),panther)
CFLAGS_OS = -DHAVE_IPV6 -W -Wall -no-cpp-precomp
else
cantbuild:
	@echo "Error: Must specify target OS on command-line, e.g. \"make os=panther\" or \"make os=jaguar\" or \"make os=linux\""
endif
endif
endif
endif
endif
endif
endif
CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_OS)

COMMONOBJ = objects/mDNSPosix.c.o objects/mDNSUNP.c.o objects/ExampleClientApp.c.o

HEADERS = Makefile mDNSUNP.h mDNSPosix.h   \
../mDNSCore/mDNSDebug.h                    \
../mDNSCore/mDNSClientAPI.h                \
../mDNSCore/mDNSPlatformFunctions.h

all: setup Client Responder ProxyResponder Identify NetMonitor

setup:
	if test ! -d objects ; then mkdir objects ; fi
	if test ! -d build   ; then mkdir build   ; fi

Client: setup build/mDNSClientPosix
	@echo "Client done"

Responder: setup build/mDNSResponderPosix
	@echo "Responder done"

ProxyResponder: setup build/mDNSProxyResponderPosix
	@echo "ProxyResponder done"

Identify: setup build/mDNSIdentify
	@echo "Identify done"

NetMonitor: setup build/mDNSNetMonitor
	@echo "NetMonitor done"

# $@ means "The file name of the target of the rule"
# $< means "The name of the first prerequisite"
# $+ means "The names of all the prerequisites, with spaces between them, exactly as given"
# For more magic automatic sariables, see
# <http://www.gnu.org/manual/make-3.80/html_chapter/make_10.html#SEC111>
build/mDNSClientPosix: $(COMMONOBJ) objects/mDNS.c.o objects/Client.c.o
	$(CC) $+ -o $@

build/mDNSResponderPosix: $(COMMONOBJ) objects/mDNS.c.o objects/Responder.c.o
	$(CC) $+ -o $@

build/mDNSProxyResponderPosix: $(COMMONOBJ) objects/mDNS.c.o objects/ProxyResponder.c.o
	$(CC) $+ -o $@

build/mDNSIdentify: $(COMMONOBJ) objects/Identify.c.o
	$(CC) $+ -o $@

build/mDNSNetMonitor: $(COMMONOBJ) objects/NetMonitor.c.o
	$(CC) $+ -o $@

objects/%.c.o: %.c ../mDNSCore/mDNS.c $(HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@

objects/mDNS.c.o: ../mDNSCore/mDNS.c $(HEADERS)
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	-rm -rf objects build .gdb_history
