"""DHCPv6 DECLINE coverage for RFC 8415."""

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
    ia_na as _ia_na,
    new_trid as _new_trid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


def _nested_options(packet, option_class):
    """Return matching Scapy options from payloads and encapsulated option lists."""
    matches = []
    visited = set()

    def walk(value):
        if value is None:
            return
        if isinstance(value, (list, tuple)):
            for item in value:
                walk(item)
            return
        if not hasattr(value, "fields_desc") or id(value) in visited:
            return

        visited.add(id(value))
        if isinstance(value, option_class):
            matches.append(value)

        for field in value.fields_desc:
            nested = value.getfieldval(field.name)
            if isinstance(nested, (list, tuple)) or hasattr(nested, "fields_desc"):
                walk(nested)
        walk(getattr(value, "payload", None))

    walk(packet)
    return matches


@when("the client sends a DHCPv6 DECLINE for its active lease")
def step_when_send_decline(context):
    _require_scapy_v6()
    declined_ip = context_storage_v6["leased_ipv6"]
    context.declined_ipv6 = declined_ip

    trid = _new_trid()
    decline = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Decline")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["server_duid"])
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na(declined_ip)
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(decline, iface=INTERFACE, verbose=False)

    context_storage_v6["decline_trid"] = trid
    context_storage_v6["decline_sniffer"] = sniffer


@then("the server replies that the DHCPv6 DECLINE succeeded")
def step_then_decline_succeeds(context):
    trid = context_storage_v6["decline_trid"]
    replies = _dhcpv6_packets(
        context_storage_v6["decline_sniffer"], "DHCP6_Reply", trid
    )
    assert replies, "No matching DHCPv6 REPLY for DECLINE received"

    reply = replies[0]
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    server_id = reply.getlayer(_cls("DHCP6OptServerId"))
    actual_client_duid = getattr(client_id, "duid", None)
    expected_client_duid = _client_duid()
    assert _duids_equal(actual_client_duid, expected_client_duid), (
        "DHCPv6 DECLINE REPLY has an unexpected Client Identifier: "
        f"expected {expected_client_duid!r}, got {actual_client_duid!r}"
    )
    actual_server_duid = getattr(server_id, "duid", None)
    expected_server_duid = context_storage_v6["server_duid"]
    assert _duids_equal(actual_server_duid, expected_server_duid), (
        "DHCPv6 DECLINE REPLY has an unexpected Server Identifier: "
        f"expected {expected_server_duid!r}, got {actual_server_duid!r}"
    )

    statuses = _nested_options(reply, _cls("DHCP6OptStatusCode"))
    failures = [
        getattr(status, "statuscode", None)
        for status in statuses
        if getattr(status, "statuscode", None) != 0
    ]
    assert not failures, f"DHCPv6 DECLINE failed with status code(s): {failures}"


@when("the client sends another DHCPv6 SOLICIT after declining the lease")
def step_when_client_solicits_after_decline(context):
    context.execute_steps("When a client sends a DHCPv6 SOLICIT message")


@then("the client is advertised an address other than the declined address")
def step_then_different_address_advertised(context):
    context.execute_steps("Then the client receives a DHCPv6 ADVERTISE from the server")
    advertised_ip = context_storage_v6.get("offered_ipv6")
    assert advertised_ip, "DHCPv6 ADVERTISE missing IA Address"
    assert advertised_ip != context.declined_ipv6, (
        f"Server re-advertised declined IPv6 address {context.declined_ipv6}"
    )
