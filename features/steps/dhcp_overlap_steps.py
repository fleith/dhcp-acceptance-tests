"""Runtime lease-selection checks for accepted overlapping DHCPv4 subnets."""

import ipaddress
import os

from behave import given, then, when

from dhcpv4_support import (
    BOOTP,
    DHCP,
    build_client_packet,
    dhcp_option,
    dhcp_options,
    mac_bytes,
    option_bytes,
    raw_dhcp_option,
    require_scapy_v4,
    start_dhcp_sniffer,
)

try:
    from scapy.all import sendp
except ImportError:
    sendp = None


INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
EXPECTED_POOL_START = os.getenv("TEST_DHCPV4_OVERLAP_EXPECTED_POOL_START", "")
EXPECTED_POOL_END = os.getenv("TEST_DHCPV4_OVERLAP_EXPECTED_POOL_END", "")
LOSING_HINT = os.getenv("TEST_DHCPV4_OVERLAP_LOSING_HINT", "")
EXPECTED_DOMAIN = os.getenv("TEST_DHCPV4_OVERLAP_EXPECTED_DOMAIN", "")
EXPECTED_SCOPE = os.getenv("TEST_DHCPV4_OVERLAP_EXPECTED_SCOPE", "")
PARAMETER_REQUEST_LIST = [1, 3, 6, 15, 51, 58, 59]


def _state(context):
    if not hasattr(context, "overlap_lease"):
        context.overlap_lease = {}
    return context.overlap_lease


def _new_mac():
    value = bytearray(os.urandom(6))
    value[0] = (value[0] | 0x02) & 0xFE
    return ":".join(f"{octet:02x}" for octet in value)


def _new_xid():
    return int.from_bytes(os.urandom(4), "big") or 1


def _message_type(packet):
    return dhcp_options(packet).get("message-type")


def _matches(packet, xid, mac, message_types):
    return (
        packet.haslayer(DHCP)
        and packet.haslayer(BOOTP)
        and packet[BOOTP].xid == xid
        and _message_type(packet) in message_types
        and bytes(packet[BOOTP].chaddr)[:6] == mac_bytes(mac)
    )


def _exchange(packet, xid, mac, message_types):
    sniffer = start_dhcp_sniffer(
        INTERFACE,
        timeout=4,
        stop_filter=lambda candidate: _matches(
            candidate, xid, mac, message_types
        ),
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    sniffer.join()
    return [
        candidate
        for candidate in (sniffer.results or [])
        if _matches(candidate, xid, mac, message_types)
    ]


def _complete_dora(context, requested_hint=None):
    mac = _new_mac()
    xid = _new_xid()
    discover_options = [("message-type", "discover")]
    if requested_hint:
        discover_options.append(("requested_addr", requested_hint))
    discover_options.extend(
        [("param_req_list", PARAMETER_REQUEST_LIST), "end"]
    )
    discover = build_client_packet(mac, xid, discover_options)
    discover_responses = _exchange(discover, xid, mac, {2, 5, 6})
    offers = [packet for packet in discover_responses if _message_type(packet) == 2]
    assert not [
        packet for packet in discover_responses if _message_type(packet) in {5, 6}
    ], f"Server returned ACK/NAK directly to overlap DISCOVER 0x{xid:08x}"
    assert offers, f"No DHCPOFFER for overlap transaction 0x{xid:08x}"
    offered_addresses = {packet[BOOTP].yiaddr for packet in offers}
    assert len(offered_addresses) == 1, (
        f"Overlap transaction received conflicting offers: {offered_addresses}"
    )
    offered_ip = offered_addresses.pop()
    server_id = dhcp_option(offers[0], "server_id")
    request_options = [("message-type", "request")]
    if server_id is not None:
        request_options.append(("server_id", server_id))
    request_options.extend(
        [
            ("requested_addr", offered_ip),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ]
    )
    request = build_client_packet(mac, xid, request_options)
    request_responses = _exchange(request, xid, mac, {5, 6})
    naks = [packet for packet in request_responses if _message_type(packet) == 6]
    assert not naks, f"Server rejected its overlap offer {offered_ip}"
    acknowledgements = [
        packet for packet in request_responses if _message_type(packet) == 5
    ]
    assert acknowledgements, f"No DHCPACK for overlap offer {offered_ip}"
    acknowledged_addresses = {
        packet[BOOTP].yiaddr for packet in acknowledgements
    }
    assert acknowledged_addresses == {offered_ip}, (
        f"DHCPACK changed overlap offer {offered_ip}: {acknowledged_addresses}"
    )
    _state(context).update(
        {
            "offer": offers[0],
            "ack": acknowledgements[0],
            "offered_ip": offered_ip,
            "requested_hint": requested_hint,
        }
    )


@given("distinguishable overlapping DHCPv4 lease scopes are configured")
def step_overlap_fixture(context):
    require_scapy_v4()
    assert sendp is not None, "Scapy send support is required for overlap tests"
    required = {
        "TEST_DHCPV4_OVERLAP_EXPECTED_POOL_START": EXPECTED_POOL_START,
        "TEST_DHCPV4_OVERLAP_EXPECTED_POOL_END": EXPECTED_POOL_END,
        "TEST_DHCPV4_OVERLAP_LOSING_HINT": LOSING_HINT,
        "TEST_DHCPV4_OVERLAP_EXPECTED_DOMAIN": EXPECTED_DOMAIN,
        "TEST_DHCPV4_OVERLAP_EXPECTED_SCOPE": EXPECTED_SCOPE,
    }
    missing = [name for name, value in required.items() if not value]
    assert not missing, "Overlap fixture is missing: " + ", ".join(missing)
    start = ipaddress.ip_address(EXPECTED_POOL_START)
    end = ipaddress.ip_address(EXPECTED_POOL_END)
    losing = ipaddress.ip_address(LOSING_HINT)
    assert start <= end, "Expected overlap pool range is reversed"
    assert not start <= losing <= end, (
        f"Losing hint {losing} is inside expected {EXPECTED_SCOPE} pool {start}-{end}"
    )


@when("a direct DHCPv4 client completes DORA in the overlapping topology")
def step_overlap_dora(context):
    _complete_dora(context)


@when(
    "a direct DHCPv4 client requests an address from the non-selected overlapping pool"
)
def step_overlap_hint_dora(context):
    _complete_dora(context, requested_hint=LOSING_HINT)


@then("the overlap DHCPOFFER and DHCPACK use the expected lease pool")
def step_overlap_pool(context):
    state = _state(context)
    start = ipaddress.ip_address(EXPECTED_POOL_START)
    end = ipaddress.ip_address(EXPECTED_POOL_END)
    for label, packet in (("DHCPOFFER", state["offer"]), ("DHCPACK", state["ack"])):
        address = ipaddress.ip_address(packet[BOOTP].yiaddr)
        assert start <= address <= end, (
            f"{label} address {address} is outside expected {EXPECTED_SCOPE} "
            f"pool {start}-{end}"
        )


@then("both overlap responses carry the expected scope policy")
def step_overlap_policy(context):
    state = _state(context)
    for label, packet in (("DHCPOFFER", state["offer"]), ("DHCPACK", state["ack"])):
        raw = raw_dhcp_option(packet, 15, ("domain", "domain_name"))
        actual = option_bytes(raw)
        assert actual is not None, f"{label} omitted the overlap scope domain marker"
        decoded = actual.rstrip(b"\x00").decode("ascii", "replace")
        assert decoded == EXPECTED_DOMAIN, (
            f"{label} carried scope marker {decoded!r}; expected "
            f"{EXPECTED_DOMAIN!r} for {EXPECTED_SCOPE}"
        )


@then("the non-selected overlapping address is not allocated")
def step_overlap_hint_not_allocated(context):
    state = _state(context)
    assert state["requested_hint"] == LOSING_HINT
    assert state["offered_ip"] != LOSING_HINT, (
        f"Server allocated non-selected overlap hint {LOSING_HINT}"
    )
