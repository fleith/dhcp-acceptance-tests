"""DHCPv6 RELEASE coverage from RFC 8415."""

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
    get_server_duid as _get_server_duid,
    ia_na as _ia_na,
    new_trid as _new_trid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


def _status_codes(packet):
    """Return Status Code options from the reply or a nested IA_NA."""
    status_type = _cls("DHCP6OptStatusCode")
    statuses = []
    visited = set()

    def collect(layer):
        if layer is None or id(layer) in visited:
            return
        visited.add(id(layer))

        if isinstance(layer, status_type):
            statuses.append(layer)

        for option in getattr(layer, "ianaopts", None) or []:
            collect(option)

        payload = getattr(layer, "payload", None)
        if payload is not None and payload.__class__.__name__ != "NoPayload":
            collect(payload)

    collect(packet)
    return statuses


@when("the client sends a DHCPv6 RELEASE for its active lease")
def step_when_client_releases_lease(context):
    _require_scapy_v6()
    lease_ip = context_storage_v6["leased_ipv6"]
    trid = _new_trid()

    release = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Release")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["server_duid"])
        / _ia_na(
            lease_ip,
            context_storage_v6.get("leased_preferred_lifetime", 0),
            context_storage_v6.get("leased_valid_lifetime", 0),
        )
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(release, iface=INTERFACE, verbose=False)

    context_storage_v6["release_trid"] = trid
    context_storage_v6["release_sniffer"] = sniffer


@then("the server returns a successful DHCPv6 RELEASE reply")
def step_then_server_acknowledges_release(context):
    trid = context_storage_v6["release_trid"]
    sniffer = context_storage_v6["release_sniffer"]
    replies = _dhcpv6_packets(sniffer, "DHCP6_Reply", trid)
    assert replies, "No transaction-matched DHCPv6 REPLY for RELEASE received"

    reply = replies[0]
    assert _get_server_duid(reply) == context_storage_v6["server_duid"], (
        "DHCPv6 RELEASE REPLY Server Identifier does not match the lease server"
    )

    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    assert client_id and getattr(client_id, "duid", None) == _client_duid(), (
        "DHCPv6 RELEASE REPLY Client Identifier does not match the releasing client"
    )

    statuses = _status_codes(reply)
    assert statuses, "DHCPv6 RELEASE REPLY missing Status Code"
    failures = [
        (status.statuscode, getattr(status, "statusmsg", b""))
        for status in statuses
        if status.statuscode != 0
    ]
    assert not failures, f"DHCPv6 RELEASE was not successful: {failures}"
