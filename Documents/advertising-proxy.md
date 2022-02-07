# DNSSD Advertising Proxy

The DNSSD Advertising proxy advertises services registered using SRP on one or more links using mDNS. The primary purpose of this proxy is to enable discovery of devices on [stub networks](https://tools.ietf.org/html/draft-lemon-stub-networks-ps-00).

The advertising proxy works by providing [DNSSD Service Registration Protocol](https://datatracker.ietf.org/doc/draft-ietf-dnssd-srp/) service on some link, typically a stub network link. Hosts on the stub network can offer services that should be discoverable both on the stub network and on the adjacent infrastructure link. To do this, they register their service using the DNSSD Service Registration Protocol.

Once a service has been registered with the advertising proxy, the advertising proxy stores that information in its internal database and then advertises it on the adjacent infrastructure link (typically a home Wi-Fi network) using multicast DNS. Registrations must be periodically renewed; if they are not, then the registration is eventually removed from the database and is no longer advertised using mDNS.
