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
SECOND_RELAY_ADDRESS = os.getenv("TEST_DHCPV6_SECOND_RELAY_ADDRESS", "fd00:29::fe")
INNER_INTERFACE_ID = b"access-port-7"
OUTER_INTERFACE_ID = b"uplink-2"


def _client_solicit():
    trid = _new_trid()
    message = (
        _cls("DHCP6_Solicit")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na()
    )
    return trid, message


def _relay_forward(
    inner_message=None,
    *,
    hopcount=0,
    linkaddr=RELAY_LINK_ADDRESS,
    peeraddr=None,
    interface_id=None,
):
    relay = _cls("DHCP6_RelayForward")(
        hopcount=hopcount,
        linkaddr=linkaddr,
        peeraddr=peeraddr or context_storage_v6["client_ll"],
    )
    if interface_id is not None:
        relay /= _cls("DHCP6OptIfaceId")(ifaceid=interface_id)
    if inner_message is not None:
        relay /= _cls("DHCP6OptRelayMsg")(message=inner_message)
    return relay


def _relay_packet(relay_message):
    return (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2", hlim=32)
        / UDP(sport=547, dport=547)
        / relay_message
    )


def _send_relay_message(relay_message, timeout=8):
    packet = _relay_packet(relay_message)
    sniffer = _start_v6_sniffer(
        timeout=timeout,
        stop_filter=lambda packet: packet.haslayer(_cls("DHCP6_RelayReply")),
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    context_storage_v6["relay_sniffer"] = sniffer


def _send_relay(inner_message=None, timeout=8, **relay_fields):
    relay = _relay_forward(inner_message, **relay_fields)
    _send_relay_message(relay, timeout=timeout)


def _relay_replies():
    sniffer = context_storage_v6["relay_sniffer"]
    sniffer.join()
    return [
        packet
        for packet in (sniffer.results or [])
        if packet.haslayer(_cls("DHCP6_RelayReply"))
    ]


def _direct_relay_option(relay, option_name):
    """Return an option from this relay layer without descending into nesting."""
    option_class = _cls(option_name)
    layer = relay.payload
    while layer and layer.__class__.__name__ != "NoPayload":
        if isinstance(layer, option_class):
            return layer
        layer = layer.payload
    return None


def _relay_reply_path(relay_reply):
    """Return the outer-to-inner RELAY-REPLY headers and client message."""
    relay_class = _cls("DHCP6_RelayReply")
    current = relay_reply.getlayer(relay_class)
    layers = []
    while isinstance(current, relay_class):
        layers.append(current)
        relay_message = _direct_relay_option(current, "DHCP6OptRelayMsg")
        current = getattr(relay_message, "message", None) if relay_message else None
    return layers, current


def _matching_relay_reply(message_name, trid):
    message_class = _cls(message_name)
    matches = []
    for reply in _relay_replies():
        relay_layers, inner = _relay_reply_path(reply)
        if (
            inner is not None
            and inner.haslayer(message_class)
            and getattr(inner[message_class], "trid", None) == trid
        ):
            matches.append((reply, relay_layers, inner))
    return matches


def _assert_relay_path(relay_layers, expected=None):
    expected = expected or [
        {
            "hopcount": 0,
            "linkaddr": RELAY_LINK_ADDRESS,
            "peeraddr": context_storage_v6["client_ll"],
        }
    ]
    assert len(relay_layers) == len(expected), (
        f"RELAY-REPLY has {len(relay_layers)} relay layers; expected {len(expected)}"
    )
    for index, (relay, wanted) in enumerate(zip(relay_layers, expected), start=1):
        assert int(relay.hopcount) == wanted["hopcount"], (
            f"RELAY-REPLY layer {index} changed hop-count to {relay.hopcount}; "
            f"expected {wanted['hopcount']}"
        )
        assert relay.linkaddr == wanted["linkaddr"], (
            f"RELAY-REPLY layer {index} changed link-address to {relay.linkaddr}; "
            f"expected {wanted['linkaddr']}"
        )
        assert relay.peeraddr == wanted["peeraddr"], (
            f"RELAY-REPLY layer {index} changed peer-address to {relay.peeraddr}; "
            f"expected {wanted['peeraddr']}"
        )


@when("a relay forwards a client DHCPv6 SOLICIT")
def step_when_relay_forwards_solicit(context):
    _require_scapy_v6()
    trid, inner = _client_solicit()
    _send_relay(inner)
    context_storage_v6["relay_solicit_trid"] = trid
    context_storage_v6["expected_relay_path"] = None


@then("the server returns a matching DHCPv6 RELAY-REPLY with an ADVERTISE")
def step_then_relay_reply_contains_advertise(context):
    matches = _matching_relay_reply(
        "DHCP6_Advertise", context_storage_v6["relay_solicit_trid"]
    )
    assert matches, "No transaction-matched RELAY-REPLY carrying an ADVERTISE"
    _, relay_layers, advertise = matches[0]
    _assert_relay_path(relay_layers, context_storage_v6.get("expected_relay_path"))

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
    _, relay_layers, inner_reply = matches[0]
    _assert_relay_path(relay_layers, context_storage_v6.get("expected_relay_path"))
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
    assert not _relay_replies(), "Server answered a malformed RELAY-FORWARD"


@when("a relay forwards a client DHCPv6 SOLICIT with hop-count {hop_count:d}")
def step_when_relay_forwards_solicit_with_hop_count(context, hop_count):
    _require_scapy_v6()
    trid, inner = _client_solicit()
    _send_relay(inner, hopcount=hop_count)
    context_storage_v6["relay_solicit_trid"] = trid
    context_storage_v6["expected_relay_path"] = [
        {
            "hopcount": hop_count,
            "linkaddr": RELAY_LINK_ADDRESS,
            "peeraddr": context_storage_v6["client_ll"],
        }
    ]


@then("the server returns a matching DHCPv6 RELAY-REPLY with hop-count {hop_count:d}")
def step_then_relay_reply_preserves_hop_count(context, hop_count):
    matches = _matching_relay_reply(
        "DHCP6_Advertise", context_storage_v6["relay_solicit_trid"]
    )
    assert matches, (
        f"No transaction-matched RELAY-REPLY at valid hop-count {hop_count}"
    )
    _, relay_layers, _ = matches[0]
    _assert_relay_path(relay_layers, context_storage_v6["expected_relay_path"])


@when("two relays with distinct Interface-IDs forward a client DHCPv6 SOLICIT")
def step_when_nested_relays_forward_solicit(context):
    _require_scapy_v6()
    trid, solicit = _client_solicit()
    inner_relay = _relay_forward(
        solicit,
        hopcount=0,
        linkaddr=RELAY_LINK_ADDRESS,
        peeraddr=context_storage_v6["client_ll"],
        interface_id=INNER_INTERFACE_ID,
    )
    outer_relay = _relay_forward(
        inner_relay,
        hopcount=1,
        linkaddr="::",
        peeraddr=SECOND_RELAY_ADDRESS,
        interface_id=OUTER_INTERFACE_ID,
    )
    _send_relay_message(outer_relay)
    context_storage_v6["relay_solicit_trid"] = trid
    context_storage_v6["expected_relay_path"] = [
        {
            "hopcount": 1,
            "linkaddr": "::",
            "peeraddr": SECOND_RELAY_ADDRESS,
            "interface_id": OUTER_INTERFACE_ID,
        },
        {
            "hopcount": 0,
            "linkaddr": RELAY_LINK_ADDRESS,
            "peeraddr": context_storage_v6["client_ll"],
            "interface_id": INNER_INTERFACE_ID,
        },
    ]


@then("the server returns an ADVERTISE through both original relay layers")
def step_then_nested_reply_preserves_path(context):
    matches = _matching_relay_reply(
        "DHCP6_Advertise", context_storage_v6["relay_solicit_trid"]
    )
    assert matches, "No nested RELAY-REPLY carrying the transaction-matched ADVERTISE"
    _, relay_layers, advertise = matches[0]
    _assert_relay_path(relay_layers, context_storage_v6["expected_relay_path"])
    assert advertise.haslayer(_cls("DHCP6OptIAAddress")), (
        "Nested relayed ADVERTISE missing IA Address"
    )
    context_storage_v6["nested_reply_layers"] = relay_layers


@then("each RELAY-REPLY layer preserves its Interface-ID")
def step_then_nested_reply_preserves_interface_ids(context):
    relay_layers = context_storage_v6["nested_reply_layers"]
    expected = context_storage_v6["expected_relay_path"]
    for index, (relay, wanted) in enumerate(zip(relay_layers, expected), start=1):
        option = _direct_relay_option(relay, "DHCP6OptIfaceId")
        actual = getattr(option, "ifaceid", None) if option else None
        assert actual == wanted["interface_id"], (
            f"RELAY-REPLY layer {index} Interface-ID {actual!r} does not match "
            f"{wanted['interface_id']!r}"
        )


@when("a relay sends a RELAY-FORWARD with a truncated Interface-ID option")
def step_when_relay_sends_truncated_interface_id(context):
    _require_scapy_v6()
    trid, solicit = _client_solicit()
    malformed_option = _cls("DHCP6OptUnknown")(
        optcode=18,
        optlen=16,
        data=b"short",
    )
    # Keep the mandatory Relay Message intact and place the truncated metadata
    # after it. This isolates Interface-ID length handling instead of allowing
    # the declared length to consume the following Relay Message header.
    relay = _relay_forward(solicit)
    relay /= malformed_option
    _send_relay_message(relay, timeout=2)
    context_storage_v6["malformed_relay_trid"] = trid


@then(
    "the server safely ignores the malformed metadata or answers its inner transaction"
)
def step_then_truncated_interface_id_is_safely_handled(context):
    replies = _relay_replies()
    if not replies:
        return

    matches = _matching_relay_reply(
        "DHCP6_Advertise", context_storage_v6["malformed_relay_trid"]
    )
    assert len(matches) == len(replies), (
        "Malformed Interface-ID produced a RELAY-REPLY that did not contain "
        "the original inner SOLICIT transaction"
    )
    for _, relay_layers, advertise in matches:
        _assert_relay_path(relay_layers)
        client_id = advertise.getlayer(_cls("DHCP6OptClientId"))
        assert _duids_equal(getattr(client_id, "duid", None), _client_duid()), (
            "Response to malformed Interface-ID changed the inner client identity"
        )
