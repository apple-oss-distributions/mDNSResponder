This directory contains support files for running mDNS on Microsoft Windows 
and Windows CE/PocketPC.

mDNSWin32.c & mDNSWin32.h are the Platform Support files that go below
mDNS Core. These work on both Windows and Windows CE/PocketPC.

DNSServices is a higher-level API for using mDNS. It manages memory, tracks 
browers and registrations, etc.

DNSServiceDiscovery is an emulation layer that sits on top of DNSServices 
and provides the Mac OS X DNS Service Discovery API's on any platform.

Tool.c is an example client that uses the services of mDNS Core.

ToolWin32.mcp is a CodeWarrior project (CodeWarrior for Windows version 8). 
ToolWin32.vcproj is a Visual Studio .NET 7 project. These projects builds 
Tool.c to make rendezvous.exe, a small Windows command-line tool to do all 
the standard Rendezvous stuff on Windows. It has the following features:

- Browse for browsing and/or registration domains.
- Browse for services.
- Lookup Service Instances.
- Register domains for browsing and/or registration.
- Register services.

For example, if you have a Windows machine running a Web server,
then you can make it advertise that it is offering HTTP on port 80
with the following command:

rendezvous -rs "Windows Web Server" "_http._tcp." "local." 80 ""

To search for AFP servers, use this:

rendezvous -bs "_afpovertcp._tcp." "local."

You can also do multiple things at once (e.g. register a service and
browse for it so one instance of the app can be used for testing).
Multiple instances can also be run on the same machine to discover each
other. There is a -help command to show all the commands, their
parameters, and some examples of using it.

RendezvousBrowser contains the source code for a graphical browser application 
for Windows CE/PocketPC. The Windows CE/PocketPC version requires Microsoft 
eMbedded C++ 4.0 with SP2 installed and the PocketPC 2003 SDK.
