# OpenThread Stub Network Border Router
The OpenThread Stub Network Border Router (henceforth “BR”) consists of three parts: OpenThread itself, the Service Registration Protocol Advertising Proxy, and the OpenThread Stub Network Border Router management system, which is currently included as part of the Advertising Proxy.

Currently the BR is known to work on Raspbian Buster on the Raspberry Pi 4. It should also be possible to make it work on OpenWRT and other Linux installations. No BSD installations have been attempted yet. If you wish to set up a BR for your own use, your best way forward is to get a Raspberry Pi 4. Instructions for setting up a BR on a Raspberry Pi are included below.

The BR connects to one or more infrastructure networks using either or both of its Ethernet and Wi-Fi network interfaces. Additional infrastructure link connections can be established either using additional USB Ethernet adapters, additional USB Wi-Fi adapters, or VLANs. Most applications will only need a single infrastructure connection.

The BR requires one or more Thread devices to be connected in order to form a Thread mesh. If no Thread devices are present, no Thread mesh will form, and the BR will not advertise routes nor start the SRP Advertising Proxy.
## Setting up your own thread network
In order to create our own Thread Network you will need:
* A Border Router
* At least one thread device to connect to the border router
* A computer to test service discovery and the connection to the Thread accessory over the Border Router.
## Setting up The Border Router
* The Raspberry Pi is responsible for running `ot-daemon` (the Thread network daemon), and `srp-mdns-proxy`. The `srp-mdns-proxy` daemon advertises any service registrations from the Thread accessory on adjacent infrastructure network (e.g. your Wi-Fi network). It also advertises reachability to the Thread network, and if necessary provides an IPv6 prefix on the Infrastructure network.
* To connect to a Thread network a Thread RCP device must be provided. This is a device, typically a USB stick, that implements the Thread Radio Control protocol over USB. The Daemon will use the RCP to send / receive data over the Thread Network. This document describes how to build an RCP using a [Nordic PCA10059][1].

Please be aware that the BR software is in development, and is not free of bugs.  Your assistance in helping us to troubleshoot the software when you run into issues is extremely important. In support of this, we ask you to do the following before reporting bugs:

First, make sure you do a git pull and rebuild. Development is active, and so if you run into a bug that’s pretty easy to reach, there’s a good chance someone will already have reported it and it will be fixed with no effort on your part.

Second, always run `srp-mdns-proxy` under the debugger, so that when you get a crash, you can get a stack trace. If you have a very repeatable bug, just reporting it may be enough, but often that’s not the case. Sometimes bugs don’t happen very often, and so it’s important to get as much information as possible when they do happen. If you are running the proxy under the debugger, then when you hit a crash, you’ll be able to type “where” to get a backtrace, and then you can cut and paste the output into the bug report.

Third, when it crashes, look at the crash. Is it obvious why it crashed? If so, just include that information in the bug report. Of course you should include that information in the bug report regardless. But also, if it’s not obvious why it crashed, please consider enabling the address sanitizer in the build. To do this, type “make clean” and then “make ASAN=1". If you can, it’s best to just always do this, particularly during testing.

When you’ve enabled ASAN in the build, and you run `srp-mdns-proxy` under the debugger, type `set env LD_PRELOAD /usr/lib/gcc/arm-linux-gnueabihf/8/libasan.so` before running it. This is required to use ASAN on the Pi. If indeed the bug is some kind of memory smash, ASAN will catch the smash when it happens (usually) rather than later on when the smashed memory is accessed inappropriately. So usually it’ll be obvious what went wrong. Catching the bug under the address sanitizer can dramatically reduce the amount of time required to figure out what went wrong and fix it.

When you submit a bug report, please include the contents of `/var/log/syslog`. If the problem happened yesterday, but you only noticed it today, also include `/var/log/syslog.0`. srp-mdns-proxy logs a great deal of detail, which can be really helpful for isolating problems.
### Setting up the Raspberry Pi
To set up the Raspberry Pi you must perform the following steps:
* Install Raspbian
* Install RCP software on the Thread interface device
* Build and launch `ot-daemon`
* Build and launch `srp-mdns-proxy`
* Build and launch  `mdnsd`
### Installing Raspbian
Either purchase an SD card with Raspbian Buster already installed on it, or install Buster on an SD card as follows:
* Download [Raspbian Buster Lite][2]
* Install Raspbian on an SD Card with a tool such as Balena Etcher. See [Raspbian Documentation][3] for examples.
* Install SD card in Raspberry Pi and configure as normal (enable Wi-Fi, SSH, etc).
### Initial setup
These instructions are to be performed on the Raspberry Pi.
* Install tools and libraries
```sh
sudo apt install libmbedtls-dev libbsd-dev autoconf libtool
sudo apt install git
```
* Clone the appropriate repositories:
```
mkdir br
cd br
git clone https://github.com/Abhayakara/openthread.git
cd openthread/third_party/
git clone https://github.com/Abhayakara/mdnsresponder.git
cd ..
```
Note:  These repositories are branches off of the OpenThread project. Here we have developed a border router with srp-mdns-proxy integration built in.
### Install RCP software on Thread interface
A working RCP radio is required before the OpenThread daemon can work. This must be plugged into one of the USB ports on the Raspberry Pi. A USB 3.0 port is not required.
The following instructions explain how to build an RCP for a Nordic PCA10059 RCP. This section assumes that you have retrieved the openthread repo described earlier in **Initial Setup**.
* build the RCP Image. From the openthread root directory on the Raspberry Pi:
```sh
./script/bootstrap
./bootstrap
make -f examples/Makefile-nrf52840 USB=1 BOOTLOADER=USB
```
* convert the output to a .hex
```sh
 arm-none-eabi-objcopy -O ihex output/nrf52840/bin/ot-rcp ot-rcp.hex
```
* You must now follow the [instructions for flashing the Nordic USB stick with ot-rcp.hex file](https://infocenter.nordicsemi.com/index.jsp?topic=%2Fug_nc_programmer%2FUG%2Fnrf_connect_programmer%2Fncp_programming_dongle.html). Unfortunately the nRFConnect program is not available for Raspberry Pi; it is available for Mac, Linux (X86_64) and Windows. So you will need to copy the ot-rcp.hex file to a machine that supports nRFConnect in order to flash it to the USB stick.
*The RCP stick is now ready to be attached to the Border Router*
### Build and Launch OpenThread Daemon
* Build the daemon
Again, from the openthread root directory on the Raspberry Pi:
```
./bootstrap
HOST= make -f src/posix/Makefile-posix DAEMON=1 DEBUG=1
```
* Launch the daemon
```sh
sudo output/posix/armv7l-unknown-linux-gnueabihf/bin/ot-daemon 'spinel+hdlc+uart:///dev/ttyACM0?uart-baudrate=115200' &

OT_CTL_SCRIPT="
  panid 0xabcd
  channel 11
  masterkey 00112233445566778899aabbccddeeff
  dataset commit active
  ifconfig up
  thread start
  networkname"

sudo output/posix/armv7l-unknown-linux-gnueabihf/bin/ot-ctl "$OT_CTL_SCRIPT"

```
Note:  the `OT_CTL_SCRIPT` above sets the Thread Network Credentials. These may be altered as you see fit.
At this point you may use `ot-ctl` to manage your Thread Network. [OT-cli reference][5]
### Build and launch mdnsd
From the OpenThread directory:
```sh
cd third_party/mdnsresponder/mDNSPosix
sudo make os=linux DEBUG=1
sudo make install DEBUG=1
```
Building _and installing_ with DEBUG=1 ensures that lots of useful debugging information gets logged in `/var/log/syslog`.
### Build and Launch srp-mdns-proxy
This section presumes that the **Build and Launch OpenThread Daemon** steps have been performed. The step that clones mdnsresponder into the third\_party folder is particularly important.
* build srp-mdns-proxy
```sh
cd third_party/mdnsresponder/ServiceRegistration
make
```
* launch srp-mdns-proxy
```sh
sudo ./build/srp-mdns-proxy --log-stderr
```
At this point srp-mdns-proxy should begin running. You should see debug output as the service runs.
### Commissioning a Thread Device to the Thread Network
The Border router has now initiated a Thread Network. To connect a Thread Device to the Thread Network you must provide the device with Thread Network Credentials. This may be done by:
* **Static Commissioning**. The accessory may be built with pre-determined Thread Network Credentials.
* **Joiner Mode**. The accessory may be built such that it boots into 'Joiner Mode'. An accessory in Joiner Mode must be manually commissioned by a node on the Thread Network (In this case the Border Router). See [OpenThread][6] for details.
#### Commissioning a Thread Accessory Statically
The accessory may be built to launch "just knowing" its Thread Network Credentials. This option must be used only for the convenience of testing the device over Thread without having to commission using Thread joiner mode.

The details for how to do static commissioning will be specific to your thread accessory’s development environment. You will have to set thread commissioning parameters, likely in a header file, something like this (assuming the example network parameters we used above in `OT_CTL_SCRIPT`):
```
#ifndef THREAD_PANID
#define THREAD_PANID 43981
#endif
#ifndef THREAD_EXTPANID
#define THREAD_EXTPANID 0xDEAD00BEEF00CAFEull
#endif
#ifndef THREAD_CHANNEL
#define THREAD_CHANNEL 11
#endif
#ifndef THREAD_MASTERKEY_UPPER64
#define THREAD_MASTERKEY_UPPER64 0x0011223344556677ull
#endif
#ifndef THREAD_MASTERKEY_LOWER64
#define THREAD_MASTERKEY_LOWER64 0x8899AABBCCDDEEFFull
#endif
```
Note: PANID is decimal, not hex. 43981 corresponds to 0xabcd
* Compile the accessory for static commissioning (your Thread accessory development platform may have build parameters that must be set for static commissioning).
* Load the compiled accessory code onto the development board
#### Commissioning a Thread Device using Joiner Mode
When the Thread accessory is built without static commissioning, it will automatically boot into [Joiner Mode][7]. Joiner Mode is when a Thread accessory is actively searching for a Thread mesh to join. The Thread mesh must be told to accept a Joiner.
* When the accessory is in Joiner Mode, it will periodically report its **EUI** and **Joiner Passphrase**. Make a note of these. For accessories built with a CLI, it may be necessary to query the CLI for the EUI and Joiner passphrase.
* Launch `ot-ctl` at the border router. From the OpenThread root directory:
```sh
sudo output/posix/armv7l-unknown-linux-gnueabihf/bin/ot-ctl
```
* Initialize the commissioner
```
> commissioner start
Commissioner: petitioning
Done
> Commissioner: active
```
* Tell the commissioner to accept the joiner with EUI and Passphrase
```
> commissioner joiner add <EUI> <PASSPHRASE>
Done
```
   for example:
```
> commissioner joiner add F4CE366B04F7D4DF 6D8E3F0A99C2D399A334619304800804
Done
```
   Note:  you may replace the EUI with `*` to accept all joiners with the appropriate passphrase.
* After a few minutes the accessory will be allowed into the Thread Network by the Border Router, receive its commissioning credentials, and, if it implements an SRP client, will register with srp-mdns-proxy.
### Testing
#### Using SRP and the advertising proxy to find the device
If your Thread accessory is registering itself using Service Registration Protocol, you can discover it simply by looking it up. If you know the hostname that it is using, you can type that instead of an IP address when attempting to ping it. In the example below, we assume the hostname is `My-Thread-Accessory.local`.

Generally speaking, if your device is advertising a service, you can get a list of all devices advertising that service using the `dns-sd` command. For example, to get a list of all Apple HomeKit accessories, you could issue the following query:
```
dns-sd -B _hap._udp
```
This will list all the HomeKit devices on the Thread network, and possibly some HomeKit devices on the infrastructure network as well. You should be able to find your Thread accessory in this list, if it implements HomeKit. If you are using a different application layer, it will have a different service type, which you can also specify in the dns-sd command. The output should look something like this:
```
DATE: ---Wed 11 Nov 2020---
15:07:24.671  ...STARTING...
Timestamp     A/R    Flags  if Domain               Service Type         Instance Name
15:07:24.671  Add        2  12 local.               _hap._udp.           My Thread Accessory
```
The next step after you've browsed and chosen a device is to resolve it (look it up):
```
dns-sd -L "My Thread Accessory" _hap._udp
```
The reason for the quotes is that the name has spaces in it. The output should look something like this:
```
Lookup My Thread Accessory._hap._udp.local
DATE: ---Wed 11 Nov 2020---
17:19:38.128  ...STARTING...
17:19:38.333  My\032Thread\032Accessory._hap._udp.local. can be reached at My-Thread-Accessory.local.:631 (interface 12)
 txtvers=1 qtotal=1 rp=hap/udp mopria-certified=1.3
```
Now you know that the hostname for your accessory is My-Thread-Accessory.local, so you can use that as the hostname when you try to ping it.
#### Finding the device by IP address
If the device is not using SRP, then you will have to figure out its IP address. How to do this will again be dependent on the development environment. Typically you will run the accessory with console output, and the required information can be obtained either from the console output or by requesting it from the CLI, if present.

If the device is not using SRP, then in the example below you will need to enter its IP address rather than its hostname. Be aware that most of the time the Thread device will have two IPv6 addresses on the Thread mesh-local prefix, and one IP address on the off-mesh-reachable prefix. You will not be able to ping the device using either address on the Thread mesh-local prefix.
#### Pinging the device
Make sure the accessory is actually connected to the thread network—the node type should not be “detached” or “disabled.”
Verify the Raspberry Pi that is acting as a border router can communicate with the thread device. Ping the thread device from the border router
```sh
ping6 My-Thread-Accessory.local
```
Verify that other hosts on the network can ping the thread device.
```sh
ping6 My-Thread-Accessory.local
```
Routing with the BR is automatic. If the ping fails, make sure you are not pinging a mesh-local address. Note that if you are using a Mac as the test host, it must be running Big Sur or later for Stub Network routing to work correctly. You will not be able to ping the accessory if you are running Catalina or earlier.

[1]:	https://www.nordicsemi.com/Software-and-tools/Development-Kits/nRF52840-Dongle
[2]:	https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2020-08-24/2020-08-20-raspios-buster-armhf-lite.zip
[3]:	https://www.raspberrypi.org/documentation/installation/installing-images/
[4]:	#flashing-nordic-devices
[5]:	https://github.com/openthread/openthread/blob/master/src/cli/README.md
[6]:	https://openthread.io/guides/build/commissioning
[7]:	https://openthread.io/guides/build/commissioning
