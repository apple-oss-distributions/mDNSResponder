#
# Top level makefile for Build & Integration.
# 
# This file is used to facilitate checking the mDNSResponder project
# directly out of CVS and submitting to B&I at Apple.
#
# The various platform directories contain makefiles or projects
# specific to that platform.
#
#    B&I builds must respect the following target:
#         install:
#         installsrc:
#         installhdrs:
#         clean:
#

include /Developer/Makefiles/pb_makefiles/platform.make

MVERS = "mDNSResponder-58.8"

install:
	cd "$(SRCROOT)/mDNSMacOSX"; pbxbuild install     OBJROOT=$(OBJROOT) SYMROOT=$(SYMROOT) DSTROOT=$(DSTROOT) MVERS=$(MVERS)

installsrc:
	ditto . ${SRCROOT}

installhdrs::
	cd "$(SRCROOT)/mDNSMacOSX"; pbxbuild installhdrs OBJROOT=$(OBJROOT) SYMROOT=$(SYMROOT) DSTROOT=$(DSTROOT) MVERS=$(MVERS)

clean::
	echo clean
