# DNSSD Service Registration Protocol Client

The DNSSD SRP client is a sample implementation implemented using a generic API that should work on a variety of platforms. Two APIs are currently offered, one for [POSIX platforms](../ServiceRegistration/srp-ioloop.c) and another for [Thread](../ServiceRegistration/srp-thread.c). The API is documented in [a header file](../ServiceRegistration/srp-api.h).

API implementations provide functions that are used to discover network configuration information, send and receive packets, set timers, and so on. These functions must be provided for a new platform. In addition, the platform is responsible for actually invoking the SRP client, and several entry points are provided to facilitate this.
