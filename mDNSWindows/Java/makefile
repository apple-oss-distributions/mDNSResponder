# Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
#
# @APPLE_LICENSE_HEADER_START@
# 
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this
# file.
# 
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
# 
# @APPLE_LICENSE_HEADER_END@
#
# $Log: makefile,v $
# Revision 1.6  2005/02/10 22:35:36  cheshire
# <rdar://problem/3727944> Update name
#
# Revision 1.5  2005/02/08 23:47:51  shersche
# Build into proper directories for installer
#
# Revision 1.4  2004/12/16 22:38:00  shersche
# Compile DNSSDException.java first to avoid build errors, copy output to appropriate "buildroot" folder
#
# Revision 1.3  2004/11/23 08:13:07  shersche
# Link to the iphlpapi.lib for GetAdaptersInfo
#
# Revision 1.2  2004/06/26 20:07:06  rpantos
# Update to use WinVersRes.h
#
# Revision 1.1  2004/06/18 04:12:05  rpantos
# Move up one level. Integration changes for Scott.
#
# Revision 1.2  2004/05/01 00:31:41  rpantos
# Change line endings for CVS.
#
# Revision 1.1  2004/04/30 16:32:34  rpantos
# First checked in.
#
# This Makefile builds a .jar file and accompanying JNI support library
# containing the DNSSD implementation for Java and support classes.
#
# Prior to building Java support, you must build DNSSD.dll.
#
# nmake with no arguments builds all production targets.
# 'nmake DEBUG=1' to build debugging targets.
# 'nmake clean' or 'nmake clean DEBUG=1' to delete prod/debug objects & targets
#
# To run nmake, you may need to set up your PATH correctly, using a script 
# such as: "\Program Files\Microsoft Visual Studio .NET\Vc7\bin\vcvars32.bat"
# 
# The default location of the JDK is \javasdk. You can override this on the
# command line (e.g. 'nmake JDK=\j2dk1.4.2_03').

############################################################################

COREDIR = ..\..\mDNSCore
SHAREDDIR = ..\..\mDNSShared

JDK = \javasdk

CC = cl
RC = rc
LD = ld
CP = copy
RM = del /Q
RMDIR = rmdir /S /Q
JAVAC = $(JDK)\bin\javac
JAVAH = $(JDK)\bin\javah
JAR = $(JDK)\bin\jar
CFLAGS_COMMON = -LD -DAUTO_CALLBACKS=0 -I. -I..\.. \
	-I$(COREDIR) -I$(SHAREDDIR) -I$(JDK)\include -I$(JDK)\include\win32

# Set up diverging paths for debug vs. prod builds
DEBUG=0
!if $(DEBUG) == 1
CFLAGS_DEBUG = -Zi -DMDNS_DEBUGMSGS=2 
OBJDIR = objects\debug
BUILDDIR = build\debug
INSTALLDIR = root\"Program Files"\Bonjour
LIBDIR = ..\DLL\Debug
!else
CFLAGS_DEBUG = -Os -DMDNS_DEBUGMSGS=0 
OBJDIR = objects\prod
BUILDDIR = build\prod
INSTALLDIR = root\"Program Files"\Bonjour
LIBDIR = ..\DLL\Release
!endif

CFLAGS = $(CFLAGS_COMMON) $(CFLAGS_DEBUG)
JAVACFLAGS = $(CFLAGS) $(JAVACFLAGS_OS)

#############################################################################

all: setup Java postbuild

# 'setup' sets up the build directory structure the way we want
setup:
	@if not exist objects		mkdir objects
	@if not exist build			mkdir build
	@if not exist $(OBJDIR)		mkdir $(OBJDIR)
	@if not exist $(BUILDDIR)	mkdir $(BUILDDIR)

postbuild:
	@if not exist root						mkdir root
	@if not exist root\"Program Files"	mkdir root\"Program Files"
	@if not exist $(INSTALLDIR)			mkdir $(INSTALLDIR)
	copy $(BUILDDIR)\dns_sd.jar $(INSTALLDIR)
	copy $(BUILDDIR)\jdns_sd.dll $(INSTALLDIR)

# clean removes targets and objects
clean:
	@if exist $(OBJDIR)		$(RMDIR) $(OBJDIR)
	@if exist $(BUILDDIR)	$(RMDIR) $(BUILDDIR)

#############################################################################

# The following targets build Java wrappers for the dns-sd.h API.

Java: setup $(BUILDDIR)\dns_sd.jar $(BUILDDIR)\jdns_sd.dll postbuild
	@echo "Java wrappers done"

JAVASRC	= $(SHAREDDIR)\Java
JARCONTENTS =	$(OBJDIR)\com\apple\dnssd\DNSSDService.class \
				$(OBJDIR)\com\apple\dnssd\DNSSDException.class \
				$(OBJDIR)\com\apple\dnssd\DNSRecord.class \
				$(OBJDIR)\com\apple\dnssd\TXTRecord.class \
				$(OBJDIR)\com\apple\dnssd\DNSSDRegistration.class \
				$(OBJDIR)\com\apple\dnssd\BaseListener.class \
				$(OBJDIR)\com\apple\dnssd\BrowseListener.class \
				$(OBJDIR)\com\apple\dnssd\ResolveListener.class \
				$(OBJDIR)\com\apple\dnssd\RegisterListener.class \
				$(OBJDIR)\com\apple\dnssd\QueryListener.class \
				$(OBJDIR)\com\apple\dnssd\DomainListener.class \
				$(OBJDIR)\com\apple\dnssd\DNSSD.class

$(BUILDDIR)\dns_sd.jar: $(JARCONTENTS)
	$(JAR) -cf $@ -C $(OBJDIR) com

$(BUILDDIR)\jdns_sd.dll: $(JAVASRC)\JNISupport.c $(OBJDIR)\DNSSD.java.h $(OBJDIR)\jdns_sd.RES
	$(CC) -Fe$@ $(JAVASRC)\JNISupport.c $(CFLAGS) -I$(OBJDIR) \
	$(LIBDIR)\DNSSD.lib $(JDK)\lib\jvm.lib ws2_32.lib iphlpapi.lib $(OBJDIR)\jdns_sd.RES

.SUFFIXES : .java
{$(JAVASRC)}.java{$(OBJDIR)\com\apple\dnssd}.class:	
	$(JAVAC) -d $(OBJDIR) -classpath $(OBJDIR) $<

$(OBJDIR)\DNSSD.java.h: $(OBJDIR)\com\apple\dnssd\DNSSD.class
	$(JAVAH) -classpath $(OBJDIR) -o $@ \
		com.apple.dnssd.AppleBrowser \
		com.apple.dnssd.AppleResolver \
		com.apple.dnssd.AppleRegistration \
		com.apple.dnssd.AppleQuery \
		com.apple.dnssd.AppleService 

$(OBJDIR)\jdns_sd.RES: jdns_sd.rc
	$(RC) /fo $@ $?

