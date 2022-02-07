# Automatic Discovery of DNS Push Zones

## 1. Motivation

Currently mDNSResponder mostly uses multicast DNS(mDNS) to do the service discovery for the clients. This works very well in a network where only a few services are being advertised. However, as the number of devices being advertised on the network increases, the performance of mDNS will decrease, particularly on Wi-Fi networks. This is because multicast traffic is sent on Wi-Fi networks at a much lower data rate than the native data rate of the network, so multicast traffic consumes proportionally more bandwidth than unicast traffic. This is discussed in detail in [Section 3.1 of _Multicast Considerations over IEEE 802 Wireless media_](https://tools.ietf.org/id/draft-ietf-mboned-ieee802-mcast-problems-01.html#rfc.section.3.1). When the number of services advertised is low, these problems are not very serious. However, when the number of stations becomes large, the amount of multicast traffic triggered by a single mDNS query can be quite substantial, and at this point the multiplicative factor of the lower data rate becomes particularly pronounced.

An additional problem with multicast traffic is that it is not acknowledged. The likelihood of missed advertisements, even for small amounts of traffic, is much greater for multicast traffic than unicast traffic. Devices such as Apple Watch, which turn off their radio to save power, are particularly vulnerable, but we also see this problem on home networks with poor signal quality or serious congestion.

In such situations, we will sometimes not be able to find the service. This will mean that we cannot use the smart home device (for example, a light, camera, speaker or printer). This results in a bad user experience: the reliability the user expects us to deliver is not being delivered. Unicast DNS is more reliable both because it doesn't have the problems of multicast, and also because the cost of retransmission is lower. Consequently, we would prefer to use unicast DNS for queries whenever possible. We still rely on multicast DNS to bootstrap the unicast DNS service. But once we start to use unicast DNS, the scalability and performance of service discovery should be much better.

In addition, Thread accessories operating through Thread Border Routers such as the HomePod Mini use Service Registration Protocol (SRP) to register services with an SRP server, `srp-mdns-proxy`. The SRP server then acts as an [advertising proxy](https://www.ietf.org/archive/id/draft-sctl-advertising-proxy-01.html), advertising services for these accessories using mDNS. So even though SRP is a unicast protocol, in order to find the Thread services, we still need mDNS to browse and resolve them. By providing a unicast DNS service that can be used instead to do service discovery, we can get rid of mDNS completely for discovering Thread services.

## 2. Goal

Our goal is to have a proxy that advertises the services in the network. The client (the device discovering the service) then uses unicast DNS to communicate with this proxy.  The proxy gathers information about the services to be advertised from multiple sources including mDNS, or SRP. When the user wants to find a service in the network, the discovery process happens automatically. For example, if a user says: I want to use the service `_hap._udp.` (HomeKit Accessory Protocol), mDNSResponder fulfills the user's request without asking for the additional information.

## 3. Notes

The Unicast DNS service combines four functions.
1. A [Discovery Proxy](https://tools.ietf.org/html/rfc8766), which satisfies unicast DNS Service Discovery requests by proxy, using multicast DNS. This acts as a DNS authoritative name server for one or more DNS zones, each corresponding to a network interface on which the Discovery Proxy can act as a proxy.
2. An [SRP server](https://tools.ietf.org/html/draft-ietf-dnssd-srp-09), which allows clients advertising services to register those services using a two-packet unicast exchange over UDP. This acts as an authoritative name server for a single zone, which is maintained using SRP.
3. An advertising proxy, which advertises DNS Service Discovery services that have been registered with SRP using multicast DNS.
4. A DNS full-service resolver. In addition to the usual service of a full-service resolver&mdash;resolving and answering DNS queries&mdash;the full-service resolver knows to go to the SRP server for queries in the SRP domain, and to the Discovery Proxy for queries in the domain(s) served by the discovery proxy. Although the full service resolver will not be useful on the infrastructure network (e.g. home Wi-Fi), it is needed on the Thread network so that Thread accessories can do DNS lookups.

Right now, all of these functions are integrated into a single daemon, which is called `srp-mdns-proxy`.

## 4. Move from mDNS to uDNS

Consider the following scenario: a user wants to use HomeKit-enabled device, for example, a light bulb.

### 4.1 mDNS Service Discovery

With our current mDNS Service Discovery, the process would be:

#### 4.1.1. Determine the domain to browse.

Since the user does not specify the domain in which to look for the `_hap` service, we first need to determine the appropriate domain, which is called the "browsing domain". mDNSResponder maintains a list of browsing domains, one of which is always '.local.'.  Other browsing domains can be discovered using the mechanism described in [Section 11 of DNS-Based Service Discovery](https://tools.ietf.org/html/rfc6763#page-28). Since the device is being advertised using multicast DNS on the local network, even if other default browsing domains are configured on that network, the domain in which it can be discovered will be `.local.`.

#### 4.1.2. Determine where the query should be sent.

Like the browsing domain, the user does not know (and probably doesn't care) where the query should go. mDNSResponder will attempt to find the service in all of the default browsing domains. Since one of these is '.local', which is resolved using multicast DNS, we will send a query for the service to the multicast address (`224.0.0.251` or `ff02::fb`).

#### 4.1.3. Find the service instances that are providing the `_hap._udp.` service.

To do that, mDNSResponder sends out a query with the domain and destination we get above with mDNS:
```
_hap._udp.local. PTR ?
```

Each device on the local network that is advertising an instance of the service will respond with an answer for its service:
```
_hap._udp.local. PTR my-homekit-device-1._hap._udp.local.
_hap._udp.local. PTR my-homekit-device-2._hap._udp.local.
```
Now the user knows that there are two service instances in the network: `my-homekit-device-1._hap._udp.local.` and `my-homekit-device-2._hap._udp.local.` Suppose the user chooses `my-homekit-device-1._hap._udp.local.`

#### 4.1.4. Resolve the service instance.

mDNSResponder will then send out a query using mDNS, for the service instance name chosen by user:
```
my-homekit-device-1._hap._udp.local. SRV ?
```

The response will be the host name of the device, and the port number on which the service is available on that device:
```
my-homekit-device-1._hap._udp.local. SRV my-homekit-device-1.local 12345
```

#### 4.1.5. Resolve the local host name and connect to it.

To find the address of the device, mDNSResponder sends out A and AAAA queries:
```
my-homekit-device-1.local A/AAAA ?
```

The response from the device will include zero or more A and zero or more AAAA records, for example:
```
my-homekit-device-1.local A 192.0.2.17
my-homekit-device-1.local A 169.254.123.234
my-homekit-device-1.local AAAA fe80::fedc:1234:6cd1:0c2a
```

With these IP addresses and the port number, the client now knows how to connect to the desired device and use the service.
Service discovery is now complete.

### 4.2. uDNS Service Discovery

For unicast DNS to work we need to have a DNSSD Discovery Proxy to answer the uDNS query from the client.

As we have described above, the major three steps that trigger DNS Service Discovery traffic are:
1. Browse for the service type.
2. Resolve the service instance.
3. Resolve the device name(it is local host name if using multicast DNS).
Therefore, we need to use uDNS for these three queries.  The process is as follows:

#### 4.2.1. Determine the domain to browse.

Since we want to use uDNS, the default browsing domain `.local.` will not work, since queries in `.local.` are always satisfied using multicast DNS. We need a way to find the browsing domain that the user needs, even if they do not specify it.
This is done by querying for `lb._dns-sd._udp.local.` in domain enumeration (see [Section 11 of RFC6763, Discovery of Browsing and Registration Domains](https://tools.ietf.org/html/rfc6763#section-11) for details). Therefore, mDNSResponder sends out a query:
```
lb._dns-sd._udp.local. PTR ?
```

Any instance of `srp-mdns-proxy` that is able to answer DNSSD queries for local services using unicast DNS will be a list of one or more domains for which it can answer such queries:
```
lb._dns-sd._udp.local. PTR <SRP domain>
```

Note that the process above is accomplished using multicast DNS, because the query ends in `local.`. This is necessary for the initial setup since we need to fetch some information from the network without any pre-configured setting.
Now mDNSResponder knows one of the browsing domain for the client is `<SRP domain>`.

#### 4.2.2. Determine where the query should be sent.

Now mDNSResponder knows what domain to append when the user wants to browse some service without specifying the domain in advance. The next question is: where should it send the unicast query for this domain? To find that, mDNSResponder sends out an `NS` query.
```
<SRP domain> NS ?
```

Since `srp-mdns-proxy` is the server that serves this domain, the name server of this domain should also be `srp-mdns-proxy`. Thus, `srp-mdns-proxy` advertises the `NS` record:
```
<SRP domain> NS <SRP proxy>.local.
```

The name `<SRP proxy>.local.` can now be resolved to one or more IP addresses, as described earlier.
mDNSResponder now knows that for any query for a name in the domain `<SRP domain>`, the unicast query should be sent to the IP address of `<SRP proxy>.local.`, in other words, `<SRP proxy>.local.` is the DNS resolver for `<SRP domain>`.


After getting the domain and resolver information with mDNS, client is now ready to do service discovery with unicast DNS. The process is the same as described in steps 4.1.3, 4.1.4, and 4.1.5. However, because we are no longer looking in '.local.', the three queries are now:
```
# Find available service instances.
<service type>.<SRP domain> PTR ?

# Given the service instance, look up its hostname and port
<service instance name>.<service type>.<SRP domain>. SRV ?

# Resolve the hostname of the service instance.
<device name>.<SRP domain>. A/AAAA ?
```

And all queries will be sent to the resolver we set above, the SRP proxy.

#### 4.3 Use DNS push to query for records.

Unfortunately, unicast queries are not well suited to service discovery, as described in [Section 2 of DNS Push Notifications](https://tools.ietf.org/html/rfc8765#section-2). To address this problem, we need to use DNS push for ongoing service discovery queries. Therefore, after step 4.2.2, mDNSResponder needs to first check if this domain is served by a DNS push enabled DNS resolver, and then set up a DNS push connection to it.

#### 4.3.1 Discover whether the resolver supports `_dns-push-tls._tcp`.

Given the domain mDNSResponder found in 4.2.1., we need to know if there is resolver that supports DNS push for this domain, so mDNSResponder send a unicast DNS query to the authoritative name server (the SRP proxy):

```
# Get a list of DNS Push servers for the domain
_dns-push-tls.<SRP domain> PTR ?

# Resolve service instance of the DNS push server.
<service instance name>._dns-push-tls.<SRP domain>. SRV ?

# Get the IP address of the SRP server that provides DNS push service.
<SRP server hostname>.<SRP domain>. A/AAAA ?
```

The SRP server should also be configured with the corresponding DNS record:
```
_dns-push-tls.<SRP domain> PTR <service instance name>._dns-push-tls.<SRP domain>.

<service instance name>._dns-push-tls.<SRP domain>. SRV <SRP server name>.<SRP domain>. <port number 853>

<SRP server host name>.<SRP server>. A/AAAA <IP addresses of SRP server>
```

#### 4.3.2 Set up TLS connection for DNS push connection.

The next step is to set up a TLS connection between the client (mDNSResponder) and SRP server (`srp-mdns-proxy`). DNS push uses the DNS Stateful Operations protocol (DSO, see [DNS Stateful Operations](https://tools.ietf.org/html/rfc8490)). DSO uses TLS as a transport for [Opportunistic Security](https://tools.ietf.org/html/rfc7435). We have additional security considerations:
1. Privacy: mDNS offers no privacy; since we are replacing mDNS, we could decide not to fix this problem. But since DNS Push uses TLS, we get some privacy by using it: only the SRP server knows what questions we are asking.
2. Trustworthiness of the SRP server (`srp-mdns-proxy`): we do not want an SRP server that we don't trust to give us wrong answers, so we'd like to be able to establish some kind of trust for the SRP server using its TLS certificate. Remember that we are replacing multicast DNS, which provides no trust other than by happenstance: any device on the network can in principle advertise any service. Any greater trust establishment needs to be done at the application layer when connecting to the service that has been discovered.

Our trust model therefore requires that we be able to somehow validate TLS certificate and to know that given that particular TLS certificate, we can trust the endpoint that is able to provide it.  So the questions are, how can we validate the certificate, and how can we trust it?

##### One possible solution would be:

Note: can we publish this part? We probably need to vague it up a bit prior to release.

One use case is the situation where `srp-mdns-proxy` is running on HomePod Mini and the client is also an Apple device, and they are all under the same iCloud account. In this case we can compare the certificate we get from the TLS handshake with the certificate we can also see in our iCloud keychain. If they are equal and policy check also passes, then it means that the `srp-mdns-proxy` we are talking to is an Apple device signed in to the same iCloud account, and so we have a really good reason to trust it.

Note that we do not require the server to verify the trustworthiness of the client here, which means any client that is in the same network with `srp-mdns-proxy` is able to do unicast DNS service discovery. This is fine for now, since the same information is also available using mDNS, and there is no way to control access to information advertised using mDNS. It is not a goal of this project to add such access control.

Therefore, on the server side, which is the `srp-mdns-proxy`:
We need to create a self-signed TLS certificate on `srp-mdns-proxy`, synchronize it to iCloud Keychain, and use it to set up the TLS listener for DNS push.

On the client side:
When it is time to evaluate the TLS certificate, the client fetches the corresponding certificate from the iCloud Keychain, evaluates the policy and compares the two certificates.

## 5. When mDNS is not used at all

Although the process we described above uses uDNS for the service discovery queries, it still requires some mDNS queries to do the initial setup. If we have a network that can configure the SRP proxy as a unicast DNS resolver, for example DHCP, we can get rid of mDNS completely.

Note: given that the below information is repeating what is stated in RFC6763, is there a reason to restate it here?

#### 5.1. Determine the domain to browse.

Since we cannot use mDNS, query for `lb._dns-sd._udp.local.` will not work any more. Instead, mDNSResponder can send another query:
```
<Reversed device IPv4 address ORed with network mask>.in-addr.arpa. PTR ?
<Reversed device IPv6 address ORed with network mask>.ip6.arpa. PTR ?
```

And `srp-mdns-proxy` should advertise the corresponding record:
```
<Reversed device IPv4 address ORed with network mask>.in-addr.arpa. PTR <the domain to be served by srp-dnssd-proxy>
<Reversed device IPv6 address ORed with network mask>.ip6.arpa. PTR <the domain to be served by srp-dnssd-proxy>
```

Since the `srp-mdns-proxy` is configured to be the DNS resolver for the network, the device will send queries to it with unicast DNS.

#### 5.2. Determine where the query should be sent.

No need to determine, because the `srp-dnssd-proxy` has been set as the resolver for the device.

The remaining process is the same with the 4.2. described above.

## 6. The domains get served by srp-dnssd-proxy

Currently the SRP server serves the following domains by default:
```
<Thread network ID>.thread.home.arpa.
<SRP proxy hostname>-<interface name>.home.arpa.
```

As its name indicates, the served domain `<Thread network ID>.thread.home.arpa.` is for Thread network, so any record that registered by a Thread accessory on the Thread network using SRP is published by the SRP server in this DNS zone, and will be available for unicast DNS and DNS push queries to this zone.

For each viable multicast-capable interface on the host on which the SRP server is running, the discovery proxy function of the SRP server will create a DNS zone for that interface. Queries to the DNS zone for that interface will be proxied using multicast DNS to that interface. The domain name will be of the form: `<SRP server hostname>-<interface name>.home.arpa.`.
