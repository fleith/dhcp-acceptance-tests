import ipaddress

from behave import then, when

from dhcpv6_support import (
    INTERFACE,
    Ether,
    IPv6,
    UDP,
    cls as _cls,
    client_duid as _client_duid,
    context_storage_v6,
    dhcpv6_packets as _dhcpv6_packets,
    duids_equal as _duids_equal,
    get_server_duid as _get_server_duid,
    new_trid as _new_trid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


def _normalized_domain(domain):
    if isinstance(domain, bytes):
        domain = domain.decode("ascii")
    return str(domain).rstrip(".").lower()


@when("a client sends a DHCPv6 INFORMATION-REQUEST for DNS configuration")
def step_when_send_information_request(context):
    _require_scapy_v6()
    trid = _new_trid()

    request = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_InfoRequest")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _cls("DHCP6OptOptReq")(reqopts=[23, 24, 32, 83])
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(request, iface=INTERFACE, verbose=False)

    context_storage_v6["information_request_trid"] = trid
    context_storage_v6["information_request_sniffer"] = sniffer


@then('the matching DHCPv6 REPLY contains DNS server "{dns_server}" and domain "{domain}"')
def step_then_reply_contains_dns_configuration(context, dns_server, domain):
    trid = context_storage_v6["information_request_trid"]
    sniffer = context_storage_v6["information_request_sniffer"]
    replies = _dhcpv6_packets(sniffer, "DHCP6_Reply", trid)
    assert replies, "No matching DHCPv6 REPLY for INFORMATION-REQUEST received"

    reply = replies[0]
    context_storage_v6["information_reply"] = reply
    assert _get_server_duid(reply), (
        "DHCPv6 INFORMATION-REQUEST REPLY missing Server Identifier"
    )
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    actual_client_duid = getattr(client_id, "duid", None)
    expected_client_duid = _client_duid()
    assert _duids_equal(actual_client_duid, expected_client_duid), (
        "DHCPv6 INFORMATION-REQUEST REPLY has an unexpected Client Identifier: "
        f"expected {expected_client_duid!r}, got {actual_client_duid!r}"
    )
    assert reply.getlayer(_cls("DHCP6OptIA_NA")) is None, (
        "DHCPv6 INFORMATION-REQUEST REPLY unexpectedly assigned a non-temporary address"
    )
    assert reply.getlayer(_cls("DHCP6OptIAAddress")) is None, (
        "DHCPv6 INFORMATION-REQUEST REPLY unexpectedly included an address lease"
    )

    dns_option = reply.getlayer(_cls("DHCP6OptDNSServers"))
    assert dns_option, "DHCPv6 REPLY missing DNS Recursive Name Server option"
    dns_servers = {ipaddress.ip_address(address) for address in dns_option.dnsservers}
    expected_dns_server = ipaddress.ip_address(dns_server)
    assert expected_dns_server in dns_servers, (
        f"DHCPv6 REPLY DNS servers {sorted(map(str, dns_servers))} do not include "
        f"{expected_dns_server}"
    )

    domain_option = reply.getlayer(_cls("DHCP6OptDNSDomains"))
    assert domain_option, "DHCPv6 REPLY missing Domain Search List option"
    domains = {_normalized_domain(domain) for domain in domain_option.dnsdomains}
    expected_domain = _normalized_domain(domain)
    assert expected_domain in domains, (
        f"DHCPv6 REPLY domain search list {sorted(domains)} does not include "
        f"{expected_domain}"
    )


@then("the INFORMATION-REQUEST REPLY uses the learned server DUID")
def step_then_information_reply_uses_learned_server_duid(context):
    reply = context_storage_v6.get("information_reply")
    assert reply is not None, "No validated INFORMATION-REQUEST REPLY is available"
    expected = context_storage_v6.get("server_duid")
    assert expected is not None, "No server DUID was learned from ADVERTISE"
    actual = _get_server_duid(reply)
    assert _duids_equal(actual, expected), (
        "INFORMATION-REQUEST REPLY changed the server DUID: "
        f"expected {expected!r}, got {actual!r}"
    )
