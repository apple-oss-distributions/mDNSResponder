ReadMe About mDNSPosix
----------------------

mDNSPosix is a port of Apple's core mDNS code to the Posix platform. 
The sample shows how you might implement an mDNS responder inside an
embedded device, such as a printer or a web camera.

mDNS is short for "multicast DNS", which is a technology that allows you
to register IP services and browse the network for those services.  For
more information about mDNS, see the mDNS web site.

  <http://www.multicastdns.org/>

mDNS is part of a family of technologies developed by the IETF zeroconf
working group.  For information about other zeroconf technologies, see
the zeroconf web site.

  <http://www.zeroconf.org/>

Apple uses the brand name "Rendezvous" to describe our implementation of
zeroconf technologies.  This sample is designed to show how easy it is
to make a device "Rendezvous compatible".

The code in this sample was compiled and tested on Mac OS X (10.1.x,
10.2), Solaris (SunOS 5.6), Linux (Redhat 2.4.9-21), and OpenBSD (2.9). 
YMMV.

IMPORTANT
This sample is not a full port of Apple's Rendezvous APIs to Posix. 
Specifically, the sample includes a responder daemon that registers
entities based on its command line arguments (or a text file).  This is
perfect for a embedded device, but is not suitable for a general purpose
computer.  A real implementation of the Rendezvous APIs would require a
mDNS daemon, client libraries that applications link with, and some form
of RPC between them.  Client libraries and client-to-daemon RPC are
beyond the scope of this sample, however, this would be a good place to
start if you were interested in implementing these facilities on your
platform.


Packing List
------------
The sample includes the following files and directories:

o ReadMe.txt -- This file.

o mDNSCore -- A directory containing the core mDNS code.  This code is
  written in pure ANSI C and has proved to be very portable.

o mDNSPosix.h -- The interface to the platform support code.

o mDNSPosix.c -- The platform support code for the Posix platform.
  This code glues the mDNS core to Posix.

o mDNSUNP.h -- Interface to the code in "mDNSUNP.c".

o mDNSUNP.c -- A few routines from the "Unix Network Programming" book
  that I borrowed to make the port easier.  The routines are slightly
  modified from the originals to meet my specific needs.  You can get the
  originals at the URL below.

  <http://www.kohala.com/start/unpv12e.html>

o Client.c -- The main program for the sample mDNS client.

o Responder.c -- The main program for the sample mDNS responder.

o Services.txt -- A sample configuration file for the mDNS responder. 
  You can test with this file using the option "-f Services.txt".

o ProxyResponder.c -- Another sample mDNS responder, this one intended
  for creating proxy registrations for other network devices that don't
  have their own mDNS responders.

o ExampleClientApp.h
o ExampleClientApp.c -- shared code prioviding the
  "ExampleClientEventLoop" used by Client.c and ProxyResponder.c.

o Makefile -- A makefile for building on Mac OS X and other platforms.


Building the Sample
-------------------
The sample does not use autoconf technology, primarily because I didn't
want to delay shipping while I learnt how to use it.  Thus the code
builds using a very simple make file.  To build the sample you should
type "make os=myos", e.g.

    make os=osx

For Linux you would change that to:

    make os=linux

There are definitions for each of the platforms I ported to.  If you're
porting to any other platform you'll have to add appropriate definitions
for it.


Using the Sample
----------------
Once you've built the sample you can test it by first running the
client, as shown below.

  quinn% build/mDNSClientPosix
  Hit ^C when you're bored waiting for responses.

By default the client starts a search for AppleShare servers and then
sits and waits, printing a message when services appear and disappear.

To continue with the test you should start the responder in another
shell window.

  quinn% build/mDNSResponderPosix -n Foo

This will start the responder and tell it to advertise a AppleShare
service "Foo".  In the client window you will see the client print out
the following as the service shows up on the network.

  quinn% build/mDNSClientPosix
  Hit ^C when you're bored waiting for responses.
  *** Found name = 'Foo', type = '_afpovertcp._tcp.', domain = 'local.'

Back in the responder window you can quit the responder cleanly using
SIGINT (typically ^C).

  quinn% build/mDNSResponderPosix -n Foo
  ^C
  quinn%

As the responder quits it will multicast that the "Foo" service is
disappearing and the client will see that notification and print a
message to that effect (shown below).  Finally, when you're done with
the client you can use SIGINT to quit it.

  quinn% build/mDNSClientPosix
  Hit ^C when you're bored waiting for responses.
  *** Found name = 'Foo', type = '_afpovertcp._tcp.', domain = 'local.'
  *** Lost  name = 'Foo', type = '_afpovertcp._tcp.', domain = 'local.'
  ^C
  quinn%

If things don't work, try starting each program in verbose mode (using
the "-v 1" option, or very verbose mode with "-v 2") to see if there's
an obvious cause.

That's it for the core functionality.  Each program supports a variety
of other options.  For example, you can advertise and browse for a
different service type using the "-t type" option.  Use the "-?" option
on each program for more user-level information.


How It Works
------------
A typical mDNS program is divided into three sections.

    +----------------+
    |   Application  |
    +----------------+
    |    mDNS Core   |
    +----------------+
    | Posix Platform |
    +----------------+

The mDNS core code comprises the files in the "mDNSCore" directory. 
It's standard ANSI C that's very portable.  It relies on the underlying
platform code for all external functionality.

In this example the external platform code glues the mDNS core to a
POSIX-ish platform.  This code is contained in the files:

o mDNSPosix.h
o mDNSPosix.c
o mDNSUNP.h
o mDNSUNP.c

The guts of the code is in "mDNSPosix.c".

I should be clear that true POSIX isn't powerful enough to accomplish
the job, so this code doesn't compile with _POSIX_SOURCE defined and
there's a bunch of conditional code that does different things on
different Unixen.  I've isolated the hairiest parts of this code in the
"mDNSUNP".

Above the mDNS core code is the code that actually does
application-specific tasks.  In this example I've supplied two
application programs: the responder (Responder.c) acts as a simple mDNS
responder, listening for mDNS service lookup requests and answering
them, and the client (Client.c), which is a simple mDNS browser, making
simple mDNS search queries.  Both programs use the same mDNS core and
Posix platform code.

A discussion of the mDNS protocol itself is beyond the scope of this
sample.  Quite frankly, my goal here was to demonstrate how it easy it
is to use Apple's mDNS core without actually understanding mDNS, and
because I achieved that goal I never had to learn a lot about how the
mDNS core code works.  It's just a black box that I call.  If you want
to learn more about mDNS, see the references at the top of this file.

The mDNS Posix platform code is actually pretty simple.  mDNS core
requires six key features in its platform support.

o the core calls the platformm at startup (mDNSPlatformInit)
  and shutdown (mDNSPlatformClose)

o the core calls the platform to send a UDP packet (mDNSPlatformSendUDP)

o the core calls the platform to set a timer (mDNSPlatformScheduleTask)

o the platform calls the core (mDNSCoreTask) when the timer expires

o the platform calls the core (mDNSCoreReceive) when a UDP datagram arrives

o the platform calls the core when network interfaces are
  added (mDNS_RegisterInterface) or removed (mDNS_DeregisterInterface)

All of these features are implemented in "mDNSPosix.c".

The runtime behaviour of the code is as follows.

1. The application calls mDNS_Init, which in turns calls the platform
   (mDNSPlatformInit).

2. mDNSPlatformInit gets a list of interfaces (get_ifi_info) and registers
   each one with the core (mDNS_RegisterInterface).  For each interface
   it also creates a multicast socket (SetupSocket).

3. The application then calls select() repeatedly to handle file descriptor
   events. Before calling select() each time, the application calls
   mDNSPosixGetFDSet() to give mDNSPosix.c a chance to add its own file
   descriptors to the set, and then after select() returns, it calls
   mDNSPosixProcessFDSet() to give mDNSPosix.c a chance to receive and
   process any packets that may have arrived.

4. When the core needs to send a UDP packet it calls
   mDNSPlatformSendUDP.  That routines finds the interface that
   corresponds to the source address requested by the core, and
   sends the datagram using the UDP socket created for the
   interface.  If the socket is flow send-side controlled it just
   drops the packet.

5. When SocketDataReady runs it uses a complex routine,
   "recvfrom_flags", to actually receive the packet.  This is required
   because the core needs information about the packet that is
   only available via the "recvmsg" call, and that call is complex
   to implement in a portable way.  I got my implementation of
   "recvfrom_flags" from Stevens' "UNIX Network Programming", but
   I had to modify it further to work with Linux.

One thing to note is that the Posix platform code is very deliberately
not multi-threaded.  I do everything from a main loop that calls
"select()".  This is good because it avoids all the problems that often
accompany multi-threaded code. If you decide to use threads in your
platform, you will have to implement the mDNSPlatformLock() and
mDNSPlatformUnlock() calls which are no-ops in mDNSPosix.c.


Caveats
-------
Currently the program uses a simple make file.

There are various problems with loopback-only self discovery.  The code
will attempt service discovery on the loopback interface only if no
other interfaces are available.  However, this exposes a number of
problems with the underlying network stack (at least on Mac OS X).

o On Mac OS X 10.1.x the code fails to start on the loopback interface
  because the IP_ADD_MEMBERSHIP option returns ENOBUFS.

o On Mac OS X 10.2 the loopback-only case fails because
  mDNSPlatformSendUDP's call to "sendto" fails with error EHOSTUNREACH
  [Radar ID 3016042].

I haven't been able to test the loopback-only case on other platforms
because I don't have access to the physical machine.


Licencing
---------
This code is distributed under the Apple Public Source License.
Information about the licence is included at the top of each source file.


Credits and Version History
---------------------------
If you find any problems with this sample, mail <dts@apple.com> and I
will try to fix them up.

1.0a1 (Jul 2002) was a prerelease version that was distributed
internally at Apple.

1.0a2 (Jul 2002) was a prerelease version that was distributed
internally at Apple.

1.0a3 (Aug 2002) was the first shipping version.  The core mDNS code is
the code from Mac OS 10.2 (Jaguar) GM.

Share and Enjoy

Apple Developer Technical Support
Networking, Communications, Hardware

6 Aug 2002


To Do List
----------
¥ port to a System V that's not Solaris
¥ use sig_atomic_t for signal to main thread flags
¥ test and debug the daemon function, including properly logging
