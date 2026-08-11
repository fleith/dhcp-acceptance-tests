"""DHCPv6 REBIND acceptance steps for RFC 9915."""

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
    ensure_interface_ipv6 as _ensure_interface_ipv6,
    get_server_duid as _get_server_duid,
    ia_na as _ia_na,
    iaid as _iaid,
    new_trid as _new_trid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


@when("the client sends a DHCPv6 REBIND message")
def step_when_send_rebind(context):
    _require_scapy_v6()
    lease_ip = context_storage_v6["leased_ipv6"]
    context_storage_v6["lease_ipv6_added"] = _ensure_interface_ipv6(lease_ip)

    trid = _new_trid()
    rebind = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=lease_ip, dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Rebind")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na(
            lease_ip,
            context_storage_v6["leased_preferred_lifetime"],
            context_storage_v6["leased_valid_lifetime"],
        )
    )

    assert not rebind.haslayer(_cls("DHCP6OptServerId")), (
        "DHCPv6 REBIND must not include a Server Identifier"
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(rebind, iface=INTERFACE, verbose=False)

    context_storage_v6["rebind_trid"] = trid
    context_storage_v6["rebind_sniffer"] = sniffer


@then("a matching DHCPv6 REPLY extends the same lease")
def step_then_reply_extends_rebound_lease(context):
    trid = context_storage_v6["rebind_trid"]
    sniffer = context_storage_v6["rebind_sniffer"]
    replies = _dhcpv6_packets(sniffer, "DHCP6_Reply", trid)
    assert replies, f"No DHCPv6 REPLY received for REBIND transaction {trid:#08x}"

    expected_client_duid = _client_duid()
    expected_iaid = _iaid()
    expected_ip = context_storage_v6["leased_ipv6"]

    matching_replies = []
    observed_replies = []
    for reply in replies:
        client_id = reply.getlayer(_cls("DHCP6OptClientId"))
        ia_na = reply.getlayer(_cls("DHCP6OptIA_NA"))
        ia_addr = reply.getlayer(_cls("DHCP6OptIAAddress"))
        observed = (
            getattr(client_id, "duid", None),
            _get_server_duid(reply),
            getattr(ia_na, "iaid", None),
            getattr(ia_addr, "addr", None),
        )
        observed_replies.append(observed)
        if (
            _duids_equal(observed[0], expected_client_duid)
            and observed[1] is not None
            and observed[2] == expected_iaid
            and observed[3] == expected_ip
        ):
            matching_replies.append((reply, ia_addr))

    assert matching_replies, (
        "DHCPv6 REBIND REPLY did not match expected "
        f"client/IAID/address {(expected_client_duid, expected_iaid, expected_ip)!r}; "
        f"observed {observed_replies!r}"
    )

    reply, rebound_iaaddr = matching_replies[0]
    context_storage_v6["server_duid"] = _get_server_duid(reply)
    assert rebound_iaaddr.preflft > 0, (
        "DHCPv6 REBIND REPLY did not refresh the preferred lifetime"
    )
    assert rebound_iaaddr.validlft >= rebound_iaaddr.preflft, (
        "DHCPv6 REBIND REPLY returned an invalid preferred/valid lifetime pair"
    )
