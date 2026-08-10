"""Negative capability checks for unsupported RFC 4039 Rapid Commit."""

import os

from behave import then, when

from dhcpv4_support import (
    BOOTP,
    DHCP,
    build_client_packet,
    dhcp_option,
    dhcp_options,
    mac_bytes,
    raw_dhcp_option,
    require_scapy_v4,
    start_dhcp_sniffer,
)

try:
    from scapy.all import sendp
except ImportError:
    sendp = None


DHCP_SERVER_IP = os.getenv("TEST_SERVER_IP", "192.168.56.1")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
PARAMETER_REQUEST_LIST = [1, 3, 6, 51, 58, 59]
RAPID_COMMIT_OPTION = 80
_OPTION_ABSENT = object()


def _state(context):
    if not hasattr(context, "rfc4039_fallback"):
        context.rfc4039_fallback = {"macs": set(), "xids": set()}
    return context.rfc4039_fallback


def _new_mac(context):
    state = _state(context)
    while True:
        address = bytearray(os.urandom(6))
        address[0] = (address[0] | 0x02) & 0xFE
        mac = ":".join(f"{octet:02x}" for octet in address)
        if mac not in state["macs"]:
            state["macs"].add(mac)
            return mac


def _new_xid(context):
    state = _state(context)
    while True:
        xid = int.from_bytes(os.urandom(4), "big")
        if xid and xid not in state["xids"]:
            state["xids"].add(xid)
            return xid


def _send_and_capture(packet):
    require_scapy_v4()
    if sendp is None:
        raise RuntimeError(
            "Scapy is required to send DHCP packets; please install scapy."
        )
    sniffer = start_dhcp_sniffer(INTERFACE)
    sendp(packet, iface=INTERFACE, verbose=False)
    sniffer.join()
    return list(sniffer.results or [])


def _matching_responses(packets, message_type, xid, mac, server_id):
    """Match one server and one client, not unrelated broadcast DHCP traffic."""
    expected_chaddr = mac_bytes(mac)
    return [
        packet
        for packet in packets
        if packet.haslayer(DHCP)
        and packet.haslayer(BOOTP)
        and dhcp_options(packet).get("message-type") == message_type
        and packet[BOOTP].xid == xid
        and bytes(packet[BOOTP].chaddr)[: len(expected_chaddr)] == expected_chaddr
        and dhcp_option(packet, "server_id") == server_id
    ]


def _client_options(message_type, rapid_commit=_OPTION_ABSENT, **extra):
    options = [("message-type", message_type)]
    if "server_id" in extra:
        options.append(("server_id", extra["server_id"]))
    if "requested_addr" in extra:
        options.append(("requested_addr", extra["requested_addr"]))
    if rapid_commit is not _OPTION_ABSENT:
        # Numeric encoding is stable across Scapy 2.5 and 2.7.
        options.append((RAPID_COMMIT_OPTION, rapid_commit))
    options.extend([("param_req_list", PARAMETER_REQUEST_LIST), "end"])
    return options


def _rapid_commit_option(packet):
    return raw_dhcp_option(packet, RAPID_COMMIT_OPTION, names=("rapid_commit",))


def _discover(context, mac, rapid_commit=_OPTION_ABSENT):
    xid = _new_xid(context)
    packet = build_client_packet(
        mac,
        xid,
        _client_options("discover", rapid_commit),
    )
    packets = _send_and_capture(packet)
    offers = _matching_responses(packets, 2, xid, mac, DHCP_SERVER_IP)
    acknowledgements = _matching_responses(packets, 5, xid, mac, DHCP_SERVER_IP)
    return {
        "acks": acknowledgements,
        "mac": mac,
        "offers": offers,
        "packets": packets,
        "server_id": DHCP_SERVER_IP,
        "xid": xid,
    }


def _require_normal_offer(discovery):
    assert not discovery["acks"], (
        "Server incorrectly sent a rapid DHCPACK for unsupported RFC 4039 "
        f"transaction 0x{discovery['xid']:08x}"
    )
    assert discovery["offers"], (
        f"No fallback DHCPOFFER from {discovery['server_id']} for transaction "
        f"0x{discovery['xid']:08x}"
    )
    assert all(
        _rapid_commit_option(offer) is None for offer in discovery["offers"]
    ), (
        "Normal fallback DHCPOFFER incorrectly included Rapid Commit Option 80 "
        f"for transaction 0x{discovery['xid']:08x}"
    )
    offered_addresses = {offer[BOOTP].yiaddr for offer in discovery["offers"]}
    assert len(offered_addresses) == 1, (
        f"Conflicting fallback offers for transaction 0x{discovery['xid']:08x}: "
        f"{sorted(offered_addresses)}"
    )
    discovery["offered_ip"] = offered_addresses.pop()
    return discovery


def _request(discovery, rapid_commit=_OPTION_ABSENT):
    packet = build_client_packet(
        discovery["mac"],
        discovery["xid"],
        _client_options(
            "request",
            rapid_commit,
            server_id=discovery["server_id"],
            requested_addr=discovery["offered_ip"],
        ),
    )
    packets = _send_and_capture(packet)
    acknowledgements = _matching_responses(
        packets,
        5,
        discovery["xid"],
        discovery["mac"],
        discovery["server_id"],
    )
    rejections = _matching_responses(
        packets,
        6,
        discovery["xid"],
        discovery["mac"],
        discovery["server_id"],
    )
    unexpected_offers = _matching_responses(
        packets,
        2,
        discovery["xid"],
        discovery["mac"],
        discovery["server_id"],
    )
    assert not rejections, (
        f"Server rejected fallback binding {discovery['offered_ip']} for "
        f"transaction 0x{discovery['xid']:08x}"
    )
    assert not unexpected_offers, (
        "Server replied to DHCPREQUEST with an unexpected DHCPOFFER for "
        f"transaction 0x{discovery['xid']:08x}"
    )
    assert acknowledgements, (
        f"No DHCPACK from {discovery['server_id']} for fallback transaction "
        f"0x{discovery['xid']:08x}"
    )
    assert all(_rapid_commit_option(ack) is None for ack in acknowledgements), (
        "Normal fallback DHCPACK incorrectly included Rapid Commit Option 80 "
        f"for transaction 0x{discovery['xid']:08x}"
    )
    acknowledged_addresses = {ack[BOOTP].yiaddr for ack in acknowledgements}
    assert acknowledged_addresses == {discovery["offered_ip"]}, (
        f"DHCPACK changed fallback binding {discovery['offered_ip']}: "
        f"{sorted(acknowledged_addresses)}"
    )
    result = dict(discovery)
    result["acks"] = acknowledgements
    result["acknowledged_ip"] = discovery["offered_ip"]
    return result


@when("a client requests unsupported DHCPv4 Rapid Commit during discovery")
def step_when_client_requests_unsupported_rapid_commit(context):
    mac = _new_mac(context)
    _state(context)["rapid_discovery"] = _discover(context, mac, b"")


@then("the server sends a normal DHCPOFFER without Option 80 or a rapid DHCPACK")
def step_then_server_offers_normal_fallback(context):
    discovery = _state(context)["rapid_discovery"]
    _require_normal_offer(discovery)


@then(
    "the client completes the fallback with a normal DHCPREQUEST and DHCPACK "
    "without Option 80"
)
def step_then_client_completes_normal_fallback(context):
    state = _state(context)
    state["rapid_fallback"] = _request(state["rapid_discovery"])


@when("a client sends malformed nonzero-length DHCPv4 Rapid Commit")
def step_when_client_sends_malformed_rapid_commit(context):
    state = _state(context)
    mac = _new_mac(context)
    state["malformed_mac"] = mac
    xid = _new_xid(context)
    packet = build_client_packet(
        mac,
        xid,
        _client_options("discover", b"\x00"),
    )
    _send_and_capture(packet)


@when("the same client completes a subsequent valid DORA")
def step_when_same_client_completes_valid_dora(context):
    state = _state(context)
    recovery = _require_normal_offer(_discover(context, state["malformed_mac"]))
    state["recovery"] = _request(recovery)


@then("the valid exchange succeeds after the malformed option")
def step_then_valid_exchange_succeeds_after_malformed_option(context):
    state = _state(context)
    recovery = state["recovery"]
    assert recovery["acknowledged_ip"] == recovery["offered_ip"]
