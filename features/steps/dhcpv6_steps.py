import ipaddress

from behave import given, when, then

from dhcpv6_support import (
    INTERFACE,
    SUBNET_V6,
    Ether,
    IPv6,
    UDP,
    cls as _cls,
    client_duid as _client_duid,
    context_storage_v6,
    dhcpv6_packets as _dhcpv6_packets,
    ensure_interface_ipv6 as _ensure_interface_ipv6,
    get_iaaddr as _get_iaaddr,
    get_server_duid as _get_server_duid,
    ia_na as _ia_na,
    iaid as _iaid,
    initialize_client_state as _initialize_client_state,
    new_trid as _new_trid,
    remove_interface_ipv6 as _remove_interface_ipv6,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


@given("the DHCPv6 server is running")
def step_given_dhcpv6_server_running(context):
    _require_scapy_v6()
    _initialize_client_state()


@given("a client holds a DHCPv6 lease from the server")
def step_given_client_holds_dhcpv6_lease(context):
    context.execute_steps(
        """
        Given the DHCPv6 server is running
        When a client sends a DHCPv6 SOLICIT message
        Then the client receives a DHCPv6 ADVERTISE from the server
        When the client sends a DHCPv6 REQUEST message
        Then the server responds with a DHCPv6 REPLY that finalizes the lease
        """
    )


@when("a client sends a DHCPv6 SOLICIT message")
def step_when_send_solicit(context):
    _require_scapy_v6()
    trid = _new_trid()

    solicit = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Solicit")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na()
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(solicit, iface=INTERFACE, verbose=False)

    context_storage_v6["solicit_trid"] = trid
    context_storage_v6["solicit_sniffer"] = sniffer


@then("the client receives a DHCPv6 ADVERTISE from the server")
def step_then_receive_advertise(context):
    trid = context_storage_v6["solicit_trid"]
    sniffer = context_storage_v6["solicit_sniffer"]
    advertise_pkts = _dhcpv6_packets(sniffer, "DHCP6_Advertise", trid)

    if not advertise_pkts:
        all_pkts = sniffer.results or []
        print(f"\n[DEBUG DHCPv6] Expected ADVERTISE trid={hex(trid)}, captured={len(all_pkts)}")
        for i, p in enumerate(all_pkts):
            if p.haslayer(UDP):
                print(f"[DEBUG DHCPv6 pkt{i}] {p.summary()}")

    assert advertise_pkts, "No DHCPv6 ADVERTISE received"

    adv = advertise_pkts[0]
    server_duid = _get_server_duid(adv)
    assert server_duid, "DHCPv6 ADVERTISE missing Server Identifier"

    offered_iaaddr = adv.getlayer(_cls("DHCP6OptIAAddress"))
    offered_ip = getattr(offered_iaaddr, "addr", None) if offered_iaaddr else None
    if offered_ip:
        assert ipaddress.ip_address(offered_ip) in ipaddress.ip_network(SUBNET_V6), (
            f"Offered IPv6 {offered_ip} not in subnet {SUBNET_V6}"
        )
        context_storage_v6["offered_ipv6"] = offered_ip
        context_storage_v6["offered_preferred_lifetime"] = offered_iaaddr.preflft
        context_storage_v6["offered_valid_lifetime"] = offered_iaaddr.validlft

    context_storage_v6["server_duid"] = server_duid


@when("the client sends a DHCPv6 REQUEST message")
def step_when_send_request(context):
    _require_scapy_v6()
    trid = _new_trid()

    request = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Request")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["server_duid"])
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na(
            context_storage_v6.get("offered_ipv6"),
            context_storage_v6.get("offered_preferred_lifetime", 0),
            context_storage_v6.get("offered_valid_lifetime", 0),
        )
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(request, iface=INTERFACE, verbose=False)

    context_storage_v6["request_trid"] = trid
    context_storage_v6["request_sniffer"] = sniffer


@then("the server responds with a DHCPv6 REPLY that finalizes the lease")
def step_then_reply_finalizes_lease(context):
    trid = context_storage_v6["request_trid"]
    sniffer = context_storage_v6["request_sniffer"]
    replies = _dhcpv6_packets(sniffer, "DHCP6_Reply", trid)
    assert replies, "No DHCPv6 REPLY received"

    reply = replies[0]
    leased_iaaddr = reply.getlayer(_cls("DHCP6OptIAAddress"))
    leased_ip = getattr(leased_iaaddr, "addr", None) if leased_iaaddr else None
    if not leased_ip:
        print("\n[DEBUG DHCPv6] REPLY did not contain an IA Address")
        print(reply.show(dump=True))
    assert leased_ip, "DHCPv6 REPLY missing IA Address"
    assert ipaddress.ip_address(leased_ip) in ipaddress.ip_network(SUBNET_V6), (
        f"Leased IPv6 {leased_ip} not in subnet {SUBNET_V6}"
    )

    server_duid = _get_server_duid(reply)
    if server_duid:
        context_storage_v6["server_duid"] = server_duid
    context_storage_v6["leased_ipv6"] = leased_ip
    context_storage_v6["leased_preferred_lifetime"] = leased_iaaddr.preflft
    context_storage_v6["leased_valid_lifetime"] = leased_iaaddr.validlft


@when("the client sends a DHCPv6 RENEW message")
def step_when_send_renew(context):
    _require_scapy_v6()
    lease_ip = context_storage_v6["leased_ipv6"]
    added = _ensure_interface_ipv6(lease_ip)
    context_storage_v6["lease_ipv6_added"] = added

    trid = _new_trid()
    renew = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=lease_ip, dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Renew")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["server_duid"])
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na(
            lease_ip,
            context_storage_v6.get("leased_preferred_lifetime", 0),
            context_storage_v6.get("leased_valid_lifetime", 0),
        )
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(renew, iface=INTERFACE, verbose=False)

    context_storage_v6["renew_trid"] = trid
    context_storage_v6["renew_sniffer"] = sniffer


@then("the server responds with a DHCPv6 REPLY extending the lease")
def step_then_reply_extends_lease(context):
    trid = context_storage_v6["renew_trid"]
    sniffer = context_storage_v6["renew_sniffer"]
    replies = _dhcpv6_packets(sniffer, "DHCP6_Reply", trid)
    assert replies, "No DHCPv6 REPLY for RENEW received"

    reply = replies[0]
    renewed_ip = _get_iaaddr(reply)
    assert renewed_ip, "DHCPv6 RENEW REPLY missing IA Address"
    assert ipaddress.ip_address(renewed_ip) in ipaddress.ip_network(SUBNET_V6), (
        f"Renewed IPv6 {renewed_ip} not in subnet {SUBNET_V6}"
    )
