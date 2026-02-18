# External References

Relevant documentation and specifications referenced during development.

## CrowdSec

- **CrowdSec Documentation** - https://docs.crowdsec.net
- **go-cs-bouncer (Go bouncer library)** - https://github.com/crowdsecurity/go-cs-bouncer
- **Custom bouncer development guide** - https://docs.crowdsec.net/docs/bouncers/custom
- **LAPI Decision Stream API** - https://crowdsecurity.github.io/cs-api-doc/#operation/getDecisionsStream
- **cscli bouncers reference** - https://docs.crowdsec.net/docs/cscli/cscli_bouncers

## AbuseIPDB

- **AbuseIPDB API Documentation (v2)** - https://docs.abuseipdb.com
- **Report Endpoint** - https://docs.abuseipdb.com/#report-an-ip-address
- **Check Endpoint** - https://docs.abuseipdb.com/#check-an-ip-address
- **Category Definitions** - https://www.abuseipdb.com/categories
- **Rate Limits** - https://docs.abuseipdb.com/#introduction

## Go Standard Library

- **net/netip** - https://pkg.go.dev/net/netip (private IP range checking)
- **net/http** - https://pkg.go.dev/net/http
- **crypto/tls** - https://pkg.go.dev/crypto/tls

## Go Dependencies

- **zerolog (structured logging)** - https://github.com/rs/zerolog
- **cobra (CLI framework)** - https://github.com/spf13/cobra
- **testify (test assertions)** - https://github.com/stretchr/testify

## Container Security

- **Distroless base images** - https://github.com/GoogleContainerTools/distroless
- **gcr.io/distroless/static-debian12** - https://github.com/GoogleContainerTools/distroless/blob/main/base/README.md

## IP Address Range RFCs

- **RFC 1918** - Address Allocation for Private Internets (10.x, 172.16-31.x, 192.168.x) - https://datatracker.ietf.org/doc/html/rfc1918
- **RFC 1122** - Requirements for Internet Hosts -- Communication Layers (loopback 127.0.0.0/8) - https://datatracker.ietf.org/doc/html/rfc1122
- **RFC 3927** - Dynamic Configuration of IPv4 Link-Local Addresses (169.254.0.0/16) - https://datatracker.ietf.org/doc/html/rfc3927
- **RFC 4193** - Unique Local IPv6 Unicast Addresses (fc00::/7) - https://datatracker.ietf.org/doc/html/rfc4193
- **RFC 4291** - IP Version 6 Addressing Architecture (::1, fe80::/10) - https://datatracker.ietf.org/doc/html/rfc4291
- **RFC 6598** - IANA-Reserved IPv4 Prefix for Shared Address Space / CGNAT (100.64.0.0/10) - https://datatracker.ietf.org/doc/html/rfc6598

## HTTP Specifications

- **RFC 6585** - Additional HTTP Status Codes (defines 429 Too Many Requests) - https://datatracker.ietf.org/doc/html/rfc6585
- **RFC 9110** - HTTP Semantics (supersedes RFC 7231) - https://datatracker.ietf.org/doc/html/rfc9110
