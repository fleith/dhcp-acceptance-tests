# Next RFC Expansion Plan

This roadmap extends server-focused DHCPv6 coverage without counting an RFC
until the suite validates its protocol-specific response semantics. Capability
gaps should remain visible through scoped tags rather than broad allowed-failure
jobs.

## Recommended order

1. RFC 3646 DNS configuration options
2. RFC 6939 DHCPv6 Client Link-Layer Address option
3. RFC 5908 DHCPv6 NTP Server option
4. RFC 6603 Prefix Exclude option

The source specifications are [RFC 3646](https://www.rfc-editor.org/rfc/rfc3646.html),
[RFC 6939](https://www.rfc-editor.org/rfc/rfc6939.html),
[RFC 5908](https://www.rfc-editor.org/rfc/rfc5908.html), and
[RFC 6603](https://www.rfc-editor.org/rfc/rfc6603.html).

## Parallel workstreams

### Agent A: RFC 3646 DNS options

Promote the existing DNS smoke test into explicit RFC 3646 coverage for both
stateful and stateless DHCPv6. Validate recursive-server and domain-search
encoding, multiple values, ORO selection, duplicate ORO codes, and omission
when neither option is requested. Negative tests should send malformed ORO
payloads and prove that a later valid INFORMATION-REQUEST still succeeds.

Exit criteria: both baseline backends pass the positive, omission, duplicate,
and recovery scenarios; version profiles disclose any narrower behavior.

### Agent B: RFC 6939 relay identity

Build on the RFC 9915 relay helpers by adding option 79 to RELAY-FORWARD. Start
with capability probes for ISC DHCP and Kea, then test a valid Ethernet address,
the option at the relay closest to the client, unknown hardware types, truncated
addresses, illegal placement outside RELAY-FORWARD, and valid traffic after each
malformed packet.

Exit criteria: a backend is credited only if the fixture can configure and
observe server use of the relayed address. Simple packet acceptance is recorded
as companion coverage, not RFC compliance.

### Agent C: RFC 5908 NTP delivery

Add option 56 configuration and Scapy decoding for unicast address and FQDN
suboptions. Exercise stateful and stateless requests, multiple suboptions,
duplicate ORO codes, unrequested omission, invalid suboption lengths, and
recovery after malformed requests.

Exit criteria: response bytes are decoded and compared with configured values
on each supported backend; unsupported suboption forms are tagged per backend.

### Agent D: RFC 6603 Prefix Exclude discovery

Run a short support spike before feature implementation because this option is
an extension to prefix delegation and may not be configurable in every server
profile. If supported, extend IA_PD validation with the excluded prefix,
prefix-length math, renew/rebind persistence, release behavior, a changed
excluded-prefix NoBinding case, malformed lengths, and out-of-parent prefixes.

Exit criteria: implement full scenarios only for backends that can advertise
and enforce OPTION_PD_EXCLUDE. Otherwise publish a capability result and do not
increase the server-focused RFC count.

## Integration sequence

Agent A and Agent C can proceed independently because both extend configuration
option delivery. Agent B should reuse the merged RFC 9915 relay helpers. Agent D
depends on the existing IA_PD helpers but can perform its capability spike in
parallel. Merge shared helper changes before feature-specific branches, then run
the full ISC and Kea v6 matrices plus all pinned compatibility profiles.

Each pull request must include positive behavior, at least one malformed or
unauthorized input, a recovery exchange, JUnit-visible scenario names, README
coverage wording, and no broader expected-failure pattern than the exact known
scenario.
