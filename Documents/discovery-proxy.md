# DNSSD Discovery Proxy

This Discovery Proxy will work, using DNS polling, with any version of Mac OS X 10.4 (released in 2004) or later. Support for wide area unicast service discovery has also been included in every version of iOS since the first iPhone in 2007. However, to get the benefit of fast asynchronous change notifications using DNS Push Notifications, which keeps the user interface up to date without polling, we highly recommend testing using the current shipping versions, macOS Catalina and iOS 13.

## Example Scenario

A very common configuration in many company networks today is that the network printers (which all support AirPrint) are connected to wired Ethernet, and the iPhones and iPads (AirPrint clients) are connected via Wi-Fi, which is a different link, and a different IPv4 subnet and/or IPv6 prefix.  The iPhones and iPads are fully capable of connecting to the AirPrint printers on the wired Ethernet link.  The problem is that the iPhones and iPads on Wi-Fi can’t discover the AirPrint printers on Ethernet, because Ethernet is a separate IP link, and link-local [Multicast DNS](https://tools.ietf.org/html/rfc6762) does not cross between different IP links.

In principle the Wi-Fi Access Point could be configured to bridge between Ethernet and Wi-Fi, making them one logical link, but there are a number of reasons that this a bad idea.  Multicast on Wi-Fi is unreliable, slow, and very wasteful of precious wireless spectrum.  Because of this, it is becoming increasingly common to limit or disable multicast on Wi-Fi, thereby breaking discovery even in cases where you might have expected it to work.

Installing a DNS-SD Discovery Proxy, either on the Wi-Fi Access Point itself, or on any other device connected to the wired Ethernet, solves this problem.  With the appropriate network configuration in place, clients on Wi-Fi automatically know to talk to that proxy to perform [Multicast DNS](https://tools.ietf.org/html/rfc6762) queries on their behalf.

In this way, clients on Wi-Fi are able to perform service discovery exclusively using unicast, even in configurations where multicast is entirely disabled on the Wi-Fi network.  Your clients on Wi-Fi will now be able to discover and use those AirPrint printers on wired Ethernet.

## Target Audience

This sample code is made available for anyone wanting to experiment with the DNS-SD Discovery Proxy.

However, the intended goal is not that end users and network administrators build and install their own DNS-SD Discovery Proxies.  The intended goal is that vendors making Wi-Fi Access Points, routers, and home gateways add this capability to their products.  If you work for one of these vendors, and want to add DNS-SD Discovery Proxy capability to your products, please contact us for help about how to do that.

This is pre-release code, and most likely still has some bugs.  If you find bugs please help us improve the code by reporting any bugs you find, or by suggesting code changes in the form of Git pull requests.

## Building and Operating a DNS-SD Discovery Proxy on your Network

There are four steps to building and operating a DNS-SD Discovery Proxy on your network:

1. Installing a prebuilt package, or building the Discovery Proxy code for yourself.

2. Picking a DNS subdomain name for your advertised services.

3. Configuring and running the Discovery Proxy.

4. Configuring clients with your chosen DNS subdomain name for wide-area discovery (either manually on the client device itself, or automatically via appropriate network configuration).

## Option (i) Building the Discovery Proxy Code Yourself

Because this code is targeted at small embedded devices, it uses mbedtls.  If you don’t already have mbedtls installed, you can get it using the following commands:
```
	git clone --recursive https://github.com/ARMmbed/mbedtls
	cd mbedtls
	make no_test
	sudo make install
```
Once you have mbedtls installed, change directory to the location where you want your copy of the mDNSResponder code, clone this Git repository, and build the code:
```
	git clone --branch release https://github.com/IETF-Hackathon/mDNSResponder.git
	cd mDNSResponder/mDNSResponder/ServiceRegistration
	make
```
In the “build” subdirectory this will create the dnssd-proxy executable.  Now you have built the code, continue below with [Picking a DNS Subdomain Name for your Advertised Services](#picking-a-dns-subdomain-name-for-your-advertised-services).

## Option (ii) Installing the Prebuilt Package for OpenWrt

If you’re using OpenWrt and don’t want to build the code yourself, we have a prebuilt package for the router we are using for development, the [GL.iNet AR750S](https://www.gl-inet.com/products/gl-ar750s/).  This package may also work on routers with similar hardware.

Connect the upstream WAN port of the AR750S to your existing home network, and connect your computer to a downstream LAN port on the AR750S, or its Wi-Fi network.  Ensure that your AR750S is up to date with the latest firmware from GL.iNet.  At time of writing, this is version 3.025.  When you update the firmware, turn off the “Keep Settings” option.  This will restore your device to factory defaults, which ensures that you’re following the setup steps described here starting with the same factory default configuration that we did.

Your AR750S should be in the default configuration, where it is obtaining an IP address for itself using DHCP on its upstream WAN port (your existing home network), and sharing that IP address with its LAN (and Wi-Fi) clients by operating its own DHCP server and NAT gateway.

At this point, take a moment to observe that your computer connected to the AR750S’s downstream LAN port or Wi-Fi cannot discover anything on the upstream WAN port side.  If you press Cmd-Shift-K (“New Remote Connection”) in Terminal, you’ll not see any services on the upstream WAN port side.  If you go to System Preferences and try to add a printer, you’ll not discover any printers on the upstream WAN port side.  If you run “Image Capture”, you’ll not discover any scanners on the upstream WAN port side.

To install the Discovery Proxy on your AR750S, bring up a Terminal window on your Mac and type: ``` ssh root@192.168.8.1 ``` Enter the admin password that you configured when you set up the router.  To save having to enter the password every time, for convenience you can also install your ssh public key on the router using [the router’s web user interface](http://192.168.8.1/cgi-bin/luci/admin/system/admin). We are assuming that the AR750S' IP address is 192.168.8.1; if it is some other address, use that where we have used 192.168.8.1.

When you are at a command prompt on the router, add a line to the end of /etc/opkg/customfeeds.conf to add our OpenWrt package, as shown below:
```
    echo 'src/gz dnssd https://raw.githubusercontent.com/IETF-Hackathon/mDNSResponder/release/OpenWrt/packages/mips_24kc/base' >> /etc/opkg/customfeeds.conf
```
Remove the dnsmasq package, since we’re installing a new DNS server,
and install the new components we need:
```
    opkg update
    opkg remove dnsmasq-full
    opkg install isc-dhcp-server-ipv4 mbedtls-util mbedtls-write dnssd-proxy
```
Generate the TLS certificate for your Discovery Proxy.  Generating the key may take as much as 3 minutes.  Do not interrupt the key generation process.  It’s just sitting there collecting random data, so it will eventually complete.
```
    cd /etc/dnssd-proxy
    gen_key type=rsa rsa_keysize=4096 filename=server.key
    cert_write selfsign=1 issuer_key=server.key issuer_name=CN=discoveryproxy.home.arpa not_before=20190226000000 not_after=20211231235959 is_ca=1 max_pathlen=0 output_file=server.crt
```
Create firewall rules to allow [Multicast DNS](https://tools.ietf.org/html/rfc6762) service discovery on the AR750S’s upstream WAN port:
```
    uci add glfw opening
    uci set glfw.@opening[-1].name='mDNS'
    uci set glfw.@opening[-1].port='5353'
    uci set glfw.@opening[-1].proto='UDP'
    uci set glfw.@opening[-1].status='Enabled'
    uci commit
```
Configure the DHCP domain which is communicated to clients:
```
    uci set dhcp.isc_dhcpd.domain="service.home.arpa"
    uci commit
    /etc/init.d/dhcpd restart
    reboot
```
At this point your AR750S Discovery Proxy is configured and ready for use.  In this default configuration your AR750S Discovery Proxy is configured to offer unicast Discovery Proxy service on its downstream LAN ports and Wi-Fi, using [Multicast DNS](https://tools.ietf.org/html/rfc6762) on its upstream WAN port (your existing home network) to discover existing services on that network.

This makes services on the AR750S’s upstream WAN port visible to clients on the AR750S’s downstream LAN ports and Wi-Fi, even though those clients are not on the same link or IPv4 subnet as the services they are discovering, and no multicast packets are being forwarded between the client link (AR750S LAN port or Wi-Fi) and the services link (AR750S WAN port).  This is possible because existing clients are already able to perform service discovery using unicast DNS queries, in addition to the old way using multicast DNS queries.

Once the AR750S completes its reboot, the Discovery Proxy is available and running.  If you’re connecting via Wi-Fi, confirm that your computer is still associated with the AR750S (it may have reverted to your previous Wi-Fi network while the AR750S was rebooting).

**IMPORTANT:** We are aware of a boot-time race condition.  At the instant the Discovery Proxy and the mDNSResponder process start, early in the boot process, there is not yet any configured upstream DNS recursive resolver.  Mere milliseconds later the DHCP client obtains the DHCP lease and updates the network configuration information.  The mDNSResponder process should notice this change and update its configuration information, but due to a bug it currently does not.  We have a fix planned, but until the code is updated, after powering on the device, you need to use the commands shown below to log in to the AR750S and manually restart the mDNSResponder daemon:
```
    ssh root@192.168.8.1
    /etc/init.d/mDNSResponder restart
```
Now try again to see what your computer can discover.

If you have machines with ssh enabled that are usually visible in “New Remote Connection” in Terminal, they should now be visible when you’re connected to an AR750S downstream LAN port or Wi-Fi.

If you have network printers on your existing home network, they should now appear in when you click the “+” button to add a printer in the “Printers & Scanners” section of System Preferences.

If you have a scanner on your existing home network, it should now appear when you run the “Image Capture” app.

Note: We received one report of problems connecting.  If you use VPN, and your company has configured its internal networks using the same [IPv4 private address](https://tools.ietf.org/html/rfc1918) range that your home network uses, there can be IPv4 address conflicts, where there is more than one device with the same IPv4 address, and your client device’s networking code doesn’t know which one you are trying to reach.  If you find you can discover services but not connect to them, turn off VPN and try again to see if that makes a difference.  (Yet another reason to be using IPv6 instead of IPv4!)

Likewise, if your existing home network is using the same 192.168.8/24 IPv4 subnet that the AR750S uses for its own Wi-Fi/LAN network, you’ll have to reconfigure the AR750S to use a non-conflicting IPv4 subnet address range for its Wi-Fi/LAN network.

For more advanced configuration options, or if you want to understand more about how this works, see [Picking a DNS Subdomain Name for your Advertised Services](#picking-a-dns-subdomain-name-for-your-advertised-services).

## Picking a DNS Subdomain Name for your Advertised Services

DNS-Based Service Discovery, is based, naturally enough, on DNS domain names.

Two DNS domain names are involved here, the DNS name for the advertised link, and the DNS hostname for the Discovery Proxy performing the discovery on that advertised link.  These two names are different.

For each physical (or virtual) link on your network for which you wish to enable remote discovery of services you need to chose a DNS domain name, much like how you choose and assign domain names to individual hosts.  In this context the term “link” means an IP multicast domain — a group of devices that can all communicate with each other using IP multicast, which is used by [Multicast DNS](https://tools.ietf.org/html/rfc6762).

On each of the links on your network for which you wish to enable remote discovery of services you install a Discovery Proxy, to perform discovery operations on behalf of remote clients.  The Discovery Proxy should be assigned a static IP address, so that clients can reliably connect to it.

For an initial trial you’ll probably want to start with a single Discovery Proxy on a single link, to evaluate how well it works for your situation.

In an operational network, for each link you will need a properly delegated subdomain, delegated (using DNS “NS” records) to the Discovery Proxy on that link, which acts as the authoritative DNS server for that DNS subdomain name.  To delegate the link name subdomain to the appropriate Discovery Proxy, the Discovery Proxy device needs a DNS hostname, to go in the delegating DNS “NS” record.  You can run a Discovery Proxy without a DNS hostname, but in this case you will not be able to use DNS delegation, and clients will have to be configured with the IP address of the Discovery Proxy, as explained below in the section [Manually adding a DNS resolver address](#manually-adding-a-dns-resolver-address-on-the-client-for-testing).  If you don’t have a DNS hostname for your Discovery Proxy device, then where these instructions talk about the hostname, you can use the name “discoveryproxy.home.arpa” instead.

For evaluation you can use a temporary name for the link, without it being formally delegated.

If you (or your organization) has a DNS domain name already, then you can use a subdomain of that name for the link.  If your DNS domain name is “example.org” then you could use “my-building.example.org” as the name for the link on which the Discovery Proxy resides.  For testing, it is okay if this link subdomain name is not formally delegated to your Discovery Proxy.  If you don’t have a suitable domain name you can use, then you can use “service.home.arpa” as the name for the link on which the Discovery Proxy resides.  The “home.arpa” domain is reserved for this kind of local use.

To recap: two DNS domain names are involved here, the DNS name for the advertised link, and the DNS hostname for the Discovery Proxy responsible for performing discovery on that advertised link.  These two names are different.  One names the advertised link; the other names the device making that advertised link visible to clients.  By default the names for testing are:
```
	Link name: service.home.arpa
	Discovery Proxy hostname: discoveryproxy.home.arpa
```
## Configuring and Running the Discovery Proxy

Because the Discovery Proxy uses TLS, a key and certificate are required.  Currently self-signed certificates are allowed.

To generate the key and self-signed certificate, use the commands below.  Replace the hostname discoveryproxy.home.arpa with the actual hostname of the Discovery Proxy device, if you have one.

On a linux or MacOS install, you will run the gen_key and cert_write commands:
```
    $HOME/mbedtls/programs/pkey/gen_key type=rsa rsa_keysize=4096 filename=server.key
    $HOME/mbedtls/programs/x509/cert_write selfsign=1 issuer_key=server.key issuer_name=CN=discoveryproxy.home.arpa not_before=20190226000000 not_after=20211231235959 is_ca=1 max_pathlen=0 output_file=server.crt
    sudo mkdir /etc/dnssd-proxy
    sudo mv server.key server.crt /etc/dnssd-proxy
```
The dnssd-proxy operation is controlled by the file
```
	/etc/dnssd-proxy.cf
```
If running on Linux or Mac, create this file with text as illustrated below:
```
	interface en0 service.home.arpa.
	my-name discoveryproxy.home.arpa.
	my-ipv4-addr 203.0.113.123
	udp-port 53
	tcp-port 53
	tls-port 853
```
Replace “en0” with the name of the interface on which you want the Discovery Proxy to discover services.  To see the list of available interfaces, use the “ifconfig” command.  On a modern Mac there are many.  As a general rule, look for one of the “en” interfaces, where the flags say “UP,BROADCAST,…”

If you have a subdomain name for the link, replace “service.home.arpa” with that subdomain name.

If your Discovery Proxy device has a DNS hostname, replace “discoveryproxy.home.arpa” with that DNS hostname.

Replace “203.0.113.123” with the actual IP address of your Discovery Proxy device.

Once you have the key, the certificate, and the configuration file in place, on Linux or Mac run the dnssd-proxy executable in a Terminal window.  You should see some lines beginning “hardwired_add”, followed by “waiting” when the dnssd-proxy is ready to start processing requests.

## Configuring Clients with Your Chosen DNS Subdomain Name for Wide-Area Discovery

This Discovery Proxy, built using [DNS Stateful Operations](https://tools.ietf.org/html/rfc8490) and [DNS Push Notifications](https://tools.ietf.org/html/draft-ietf-dnssd-push), can be used with iOS 13 and macOS Catalina.  Older versions of iOS and macOS will work with the Discovery Proxy, but since they do not include support for DNS Stateful Operations and DNS Push Notifications, they will not get immediate updates when data changes (like services coming and going on the network).

The client needs to be told in which DNS domains to look for services, in addition to “local” ([Multicast DNS](https://tools.ietf.org/html/rfc6762) on the local link).

In an operational network, this configuration is performed automatically, by adding special DNS records.  If your network’s DHCP server configures your client devices with a “domain” parameter of “example.org”, then the following DNS record will automatically inform those client devices to look for services in “my-building.example.org”.  No manual client configuration is required.
```
	lb._dns-sd._udp.example.org. PTR my-building.example.org.
```
In our example setup given above for the GL.iNet AR750S, the DHCP server is set to configure client devices with a “domain” parameter of “service.home.arpa”, and when client devices perform the “lb” query to verify whether unicast DNS Service Discovery should be used, they receive a positive answer:
```
	lb._dns-sd._udp.service.home.arpa. PTR service.home.arpa.
```
There are other ways that automatic configuration can be performed, described in [Section 11 of RFC 6763](https://tools.ietf.org/html/rfc6763#section-11).

In an operational network, no client configuration is required.  It is all completely automatic.  However, for testing, until you have the necessary DNS records created, as described here, you can simulate this via some manual client configuration.

### Manually adding a DNS search domain on the client, for testing

If you don’t have the ability at this time to add a PTR record to your organization’s existing DNS server, then for evaluation you can manually add “my-building.example.org” (or “service.home.arpa”, or whatever name you chose) as a DNS search domain on your client devices.

To manually add a DNS search domain on macOS, go to System Preferences, Network.  Select the currently active network interface and click “Advanced…”  Select “DNS” and click “+” under “Search Domains” to add a new search domain.

To manually add a DNS search domain on iOS, go to Settings, Wi-Fi.  Tap on the “i” button, Configure DNS, Manual, and then tap “Add Search Domain”.

### Manually adding a DNS resolver address on the client, for testing

If “my-building.example.org” is properly delegated to your Discovery Proxy using the appropriate “NS” record, then this is all that is required for client devices to remotely discover services on the “my-building.example.org” link.

If “my-building.example.org” is not yet delegated to your Discovery Proxy, or you’re using a temporary name like “service.home.arpa”, then instead you’ll need to manually configure your client devices to use the IP address of your Discovery Proxy as their DNS resolver.  This will cause them to send all of their DNS requests to your Discovery Proxy.  The Discovery Proxy will answer all the DNS requests it is responsible for (e.g., service discovery requests for “my-building.example.org”, “service.home.arpa”, or similar) and forward all others to its own default DNS resolver.

To manually add a DNS resolver on macOS, go to System Preferences, Network.  Select the currently active network interface and click “Advanced…”  Select “DNS”, click “+” under “DNS Servers” and enter the IP address of your Discovery Proxy.

To manually add a DNS resolver on iOS, go to Settings, Wi-Fi.  Tap on the “i” button, Configure DNS, Manual.  Under “DNS SERVERS” delete the servers listed there, and manually add the IP address of your Discovery Proxy.

## Testing

At this point your clients should be able to discover services on the remote link, even when they’re not directly connected to that link.

If you have AirPrint printers on the Discovery Proxy link, then remote clients should be able to discover those and (firewall policy permitting) print on them.

If you have Macs on the Discovery Proxy link with Remote Login enabled, then on other Macs, when you press Cmd-Shift-K in Terminal, you should discover those advertised ssh services, even when not directly connected to that link.

Note: This works for all service types *except* AirPlay.  For policy reasons Apple requires AirPlay clients and servers to be within the same broadcast domain, and prohibits the use of unicast for discovering AirPlay services.

## Support

For help with getting this working, please post questions on the [Apple Developer Forum networking page](https://forums.developer.apple.com/community/core-os/networking).

For discussion of the protocol design, and to get involved with its ongoing development, please join the IETF [DNSSD](https://datatracker.ietf.org/wg/dnssd/about/) Working Group’s [email list](https://www.ietf.org/mailman/listinfo/dnssd).

Even if you have no problems setting up a Discovery Proxy, if you find the Discovery Proxy useful and would like to see it appear in commercial Wi-Fi Access Points, routers, and home gateways, please send a quick email to the DNSSD email list saying that.  These implementation and deployment reports are very valuable for us to assess the interest in this work and to guide its future development.
