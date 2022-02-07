# DNSSD Service Registration Protocol Update Proxy

The SRP Update proxy is an SRP server that uses a regular DNS authoritative server as its backing store (database). SRP updates are received, validated, and then transformed into one or more DNS updates, authenticated using TSIG. When an SRP update is processed, if it is successful, the client will be informed. If it fails, the client will receive an error response based on the error response received from the server. Using DNS update predicates, the SRP Update Proxy ensures that first-come, first-serve naming semantics are followed.
