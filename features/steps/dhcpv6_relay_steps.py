"""DHCPv6 relay-forward and relay-reply steps for RFC 9915."""

import ipaddress
import os

from behave import then, when

from dhcpv6_support import (
    INTERFACE,
    SUBNET_V6,
    Ether,
    IPv6,
    UDP,
    cls as _cls,
    client_duid as _client_duid,
    context_storage_v6,
    duids_equal as _duids_equal,
    get_server_duid as _get_server_duid,
    ia_na as _ia_na,
    new_trid as _new_trid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


RELAY_LINK_ADDRESS = os.getenv("TEST_DHCPV6_RELAY_LINK_ADDRESS", "fd00:29::1")


def _relay_packet(inner_message=None):
    packet = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2", hlim=32)
        / UDP(sport=547, dport=547)
        / _cls("DHCP6_RelayForward")(
            hopcount=0,
            linkaddr=RELAY_LINK_ADDRESS,
            peeraddr=context_storage_v6["client_ll"],
        )
    )
    if inner_message is not None:
        packet /= _cls("DHCP6OptRelayMsg")(message=inner_message)
    return packet


def _send_relay(inner_message=None, timeout=8):
    relay = _relay_packet(inner_message)
    sniffer = _start_v6_sniffer(
        timeout=timeout,
        stop_filter=lambda packet: packet.haslayer(_cls("DHCP6_RelayReply")),
    )
    sendp(relay, iface=INTERFACE, verbose=False)
    context_storage_v6["relay_sniffer"] = sniffer


def _relay_replies():
    sniffer = context_storage_v6["relay_sniffer"]
    sniffer.join()
    return [
        packet
        for packet in (sniffer.results or [])
        if packet.haslayer(_cls("DHCP6_RelayReply"))
    ]


def _inner_message(relay_reply):
    option = relay_reply.getlayer(_cls("DHCP6OptRelayMsg"))
    return getattr(option, "message", None) if option else None


def _matching_relay_reply(message_name, trid):
    message_class = _cls(message_name)
    matches = []
    for reply in _relay_replies():
        inner = _inner_message(reply)
        if (
            inner is not None
            and inner.haslayer(message_class)
            and getattr(inner[message_class], "trid", None) == trid
        ):
            matches.append((reply, inner))
    return matches


def _assert_relay_path(reply):
    relay = reply[_cls("DHCP6_RelayReply")]
    assert int(relay.hopcount) == 0, f"RELAY-REPLY changed hop-count to {relay.hopcount}"
    assert relay.linkaddr == RELAY_LINK_ADDRESS, (
        f"RELAY-REPLY changed link-address to {relay.linkaddr}"
    )
    assert relay.peeraddr == context_storage_v6["client_ll"], (
        f"RELAY-REPLY changed peer-address to {relay.peeraddr}"
    )


@when("a relay forwards a client DHCPv6 SOLICIT")
def step_when_relay_forwards_solicit(context):
    _require_scapy_v6()
    trid = _new_trid()
    inner = (
        _cls("DHCP6_Solicit")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na()
    )
    _send_relay(inner)
    context_storage_v6["relay_solicit_trid"] = trid


@then("the server returns a matching DHCPv6 RELAY-REPLY with an ADVERTISE")
def step_then_relay_reply_contains_advertise(context):
    matches = _matching_relay_reply(
        "DHCP6_Advertise", context_storage_v6["relay_solicit_trid"]
    )
    assert matches, "No transaction-matched RELAY-REPLY carrying an ADVERTISE"
    reply, advertise = matches[0]
    _assert_relay_path(reply)

    client_id = advertise.getlayer(_cls("DHCP6OptClientId"))
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid()), (
        "Relayed ADVERTISE Client Identifier does not match the inner SOLICIT"
    )
    server_duid = _get_server_duid(advertise)
    ia_addr = advertise.getlayer(_cls("DHCP6OptIAAddress"))
    assert server_duid is not None, "Relayed ADVERTISE missing Server Identifier"
    assert ia_addr is not None, "Relayed ADVERTISE missing IA Address"
    assert ipaddress.ip_address(ia_addr.addr) in ipaddress.ip_network(SUBNET_V6), (
        f"Relayed ADVERTISE address {ia_addr.addr} is outside {SUBNET_V6}"
    )
    context_storage_v6["relay_server_duid"] = server_duid
    context_storage_v6["relay_offered_ipv6"] = ia_addr.addr
    context_storage_v6["relay_offered_preferred"] = ia_addr.preflft
    context_storage_v6["relay_offered_valid"] = ia_addr.validlft


@when("the relay forwards the client DHCPv6 REQUEST")
def step_when_relay_forwards_request(context):
    trid = _new_trid()
    inner = (
        _cls("DHCP6_Request")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["relay_server_duid"])
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na(
            context_storage_v6["relay_offered_ipv6"],
            context_storage_v6["relay_offered_preferred"],
            context_storage_v6["relay_offered_valid"],
        )
    )
    _send_relay(inner)
    context_storage_v6["relay_request_trid"] = trid


@then("the server returns a matching DHCPv6 RELAY-REPLY with a leased address")
def step_then_relay_reply_contains_lease(context):
    matches = _matching_relay_reply(
        "DHCP6_Reply", context_storage_v6["relay_request_trid"]
    )
    assert matches, "No transaction-matched RELAY-REPLY carrying a REPLY"
    reply, inner_reply = matches[0]
    _assert_relay_path(reply)
    ia_addr = inner_reply.getlayer(_cls("DHCP6OptIAAddress"))
    assert ia_addr is not None, "Relayed DHCPv6 REPLY missing IA Address"
    assert ia_addr.addr == context_storage_v6["relay_offered_ipv6"], (
        f"Relayed REPLY leased {ia_addr.addr} instead of offered address "
        f"{context_storage_v6['relay_offered_ipv6']}"
    )


@when("a relay sends a RELAY-FORWARD without a Relay Message option")
def step_when_relay_omits_message_option(context):
    _require_scapy_v6()
    _send_relay(inner_message=None, timeout=2)


@then("the server does not answer the malformed RELAY-FORWARD")
def step_then_malformed_relay_is_ignored(context):
    assert not _relay_replies(), "Server answered RELAY-FORWARD without Relay Message"
