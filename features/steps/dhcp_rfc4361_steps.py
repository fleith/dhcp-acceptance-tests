"""RFC 4361 node-specific client identifier acceptance steps."""

import os

from behave import then, when

from dhcpv4_support import (
    BOOTP,
    build_client_packet,
    dhcp_option,
    dhcp_packets,
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
_OPTION_ABSENT = object()


def _state(context):
    if not hasattr(context, "rfc4361"):
        context.rfc4361 = {"macs": set(), "xids": set(), "duids": set()}
    return context.rfc4361


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


def _new_duid(context):
    """Build a DUID-LL using a unique, locally administered link address."""
    state = _state(context)
    while True:
        link_address = bytearray(os.urandom(6))
        link_address[0] = (link_address[0] | 0x02) & 0xFE
        duid = b"\x00\x03\x00\x01" + bytes(link_address)
        if duid not in state["duids"]:
            state["duids"].add(duid)
            return duid


def _client_identifier(iaid, duid):
    assert 0 <= iaid <= 0xFFFFFFFF, f"IAID is outside its 32-bit range: {iaid}"
    assert duid, "RFC 4361 client identifier requires a DUID"
    return b"\xff" + iaid.to_bytes(4, "big") + duid


def _client_options(message_type, client_id=_OPTION_ABSENT, **extra_options):
    options = [("message-type", message_type)]
    if "server_id" in extra_options:
        options.append(("server_id", extra_options["server_id"]))
    if client_id is not _OPTION_ABSENT:
        options.append(("client_id", client_id))
    if "requested_addr" in extra_options:
        options.append(("requested_addr", extra_options["requested_addr"]))
    options.extend(
        [
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ]
    )
    return options


def _send(packet):
    require_scapy_v4()
    if sendp is None:
        raise RuntimeError(
            "Scapy is required to send DHCP packets; please install scapy."
        )
    sendp(packet, iface=INTERFACE, verbose=False)


def _packets_for_mac(packets, mac):
    expected = bytes.fromhex(mac.replace(":", ""))
    return [
        packet
        for packet in packets
        if packet.haslayer(BOOTP)
        and bytes(packet[BOOTP].chaddr[:6]) == expected
    ]


def _discover(context, mac, client_id=_OPTION_ABSENT):
    xid = _new_xid(context)
    packet = build_client_packet(
        mac,
        xid,
        _client_options("discover", client_id),
    )
    sniffer = start_dhcp_sniffer(INTERFACE)
    _send(packet)
    offers = _packets_for_mac(
        dhcp_packets(sniffer, 2, xid, DHCP_SERVER_IP),
        mac,
    )
    assert offers, (
        f"No DHCPOFFER from {DHCP_SERVER_IP} for transaction 0x{xid:08x}"
    )

    offered_addresses = {offer[BOOTP].yiaddr for offer in offers}
    assert len(offered_addresses) == 1, (
        f"Server returned conflicting offers for transaction 0x{xid:08x}: "
        f"{sorted(offered_addresses)}"
    )
    offer = offers[0]
    server_id = dhcp_option(offer, "server_id")
    assert server_id == DHCP_SERVER_IP, (
        f"DHCPOFFER server identifier was {server_id!r}, expected {DHCP_SERVER_IP!r}"
    )
    return {
        "client_id": client_id,
        "mac": mac,
        "offer": offer,
        "offered_ip": offer[BOOTP].yiaddr,
        "server_id": server_id,
        "xid": xid,
    }


def _request(offer_state, client_id=_OPTION_ABSENT):
    packet = build_client_packet(
        offer_state["mac"],
        offer_state["xid"],
        _client_options(
            "request",
            client_id,
            server_id=offer_state["server_id"],
            requested_addr=offer_state["offered_ip"],
        ),
    )
    sniffer = start_dhcp_sniffer(INTERFACE)
    _send(packet)
    acknowledgements = _packets_for_mac(
        dhcp_packets(
            sniffer,
            5,
            offer_state["xid"],
            offer_state["server_id"],
        ),
        offer_state["mac"],
    )
    assert acknowledgements, (
        f"No DHCPACK from {offer_state['server_id']} for transaction "
        f"0x{offer_state['xid']:08x}"
    )

    acknowledged_addresses = {ack[BOOTP].yiaddr for ack in acknowledgements}
    assert acknowledged_addresses == {offer_state["offered_ip"]}, (
        f"DHCPACK did not preserve offered address {offer_state['offered_ip']}: "
        f"{sorted(acknowledged_addresses)}"
    )
    result = dict(offer_state)
    result["ack"] = acknowledgements[0]
    result["acknowledged_ip"] = acknowledgements[0][BOOTP].yiaddr
    return result


def _dora(context, client_id=_OPTION_ABSENT, mac=None):
    mac = mac or _new_mac(context)
    offer_state = _discover(context, mac, client_id)
    return _request(offer_state, client_id)


@when("an RFC 4361 client completes DORA with a Type 255 IAID and DUID")
def step_when_type_255_client_completes_dora(context):
    iaid = 0x01020304
    duid = _new_duid(context)
    client_id = _client_identifier(iaid, duid)
    context.rfc4361["type_255"] = _dora(context, client_id)
    context.rfc4361["type_255_iaid"] = iaid
    context.rfc4361["type_255_duid"] = duid


@then("the server acknowledges the RFC 4361 binding")
def step_then_type_255_binding_is_acknowledged(context):
    exchange = _state(context)["type_255"]
    expected = _client_identifier(
        context.rfc4361["type_255_iaid"],
        context.rfc4361["type_255_duid"],
    )
    assert exchange["client_id"] == expected
    assert exchange["client_id"][0] == 255
    assert exchange["acknowledged_ip"] == exchange["offered_ip"]


@when("one RFC 4361 identifier completes DORA from two hardware addresses")
def step_when_stable_identifier_uses_two_hardware_addresses(context):
    client_id = _client_identifier(0x11111111, _new_duid(context))
    first = _dora(context, client_id)
    second = _dora(context, client_id)
    assert first["mac"] != second["mac"], "RFC 4361 probes reused a hardware address"
    context.rfc4361["stable_identifier"] = (first, second)


@then("both hardware addresses receive the same RFC 4361 binding")
def step_then_stable_identifier_retains_binding(context):
    first, second = _state(context)["stable_identifier"]
    assert first["acknowledged_ip"] == second["acknowledged_ip"], (
        "Server keyed the RFC 4361 binding by chaddr instead of Option 61: "
        f"{first['acknowledged_ip']} then {second['acknowledged_ip']}"
    )


@when("two RFC 4361 clients use the same DUID with different IAIDs")
def step_when_same_duid_uses_different_iaids(context):
    duid = _new_duid(context)
    first = _dora(context, _client_identifier(0x22222221, duid))
    second = _dora(context, _client_identifier(0x22222222, duid))
    context.rfc4361["different_iaids"] = (first, second)


@then("the different RFC 4361 IAIDs receive distinct bindings")
def step_then_different_iaids_are_distinct(context):
    first, second = _state(context)["different_iaids"]
    assert first["client_id"] != second["client_id"]
    assert first["client_id"][5:] == second["client_id"][5:]
    assert first["acknowledged_ip"] != second["acknowledged_ip"], (
        "Server collapsed distinct RFC 4361 IAIDs into one binding: "
        f"{first['acknowledged_ip']}"
    )


@when("two RFC 4361 clients use the same IAID with different DUIDs")
def step_when_same_iaid_uses_different_duids(context):
    iaid = 0x33333333
    first = _dora(context, _client_identifier(iaid, _new_duid(context)))
    second = _dora(context, _client_identifier(iaid, _new_duid(context)))
    context.rfc4361["different_duids"] = (first, second)


@then("the different RFC 4361 DUIDs receive distinct bindings")
def step_then_different_duids_are_distinct(context):
    first, second = _state(context)["different_duids"]
    assert first["client_id"][1:5] == second["client_id"][1:5]
    assert first["client_id"][5:] != second["client_id"][5:]
    assert first["acknowledged_ip"] != second["acknowledged_ip"], (
        "Server collapsed distinct RFC 4361 DUIDs into one binding: "
        f"{first['acknowledged_ip']}"
    )


@when("legacy DHCPv4 clients complete DORA without Option 61")
def step_when_legacy_clients_complete_dora(context):
    first_mac = _new_mac(context)
    first = _dora(context, mac=first_mac)
    repeated = _dora(context, mac=first_mac)
    other = _dora(context)
    context.rfc4361["legacy_chaddr"] = (first, repeated, other)


@then("chaddr determines each legacy client binding")
def step_then_chaddr_determines_legacy_binding(context):
    first, repeated, other = _state(context)["legacy_chaddr"]
    assert first["client_id"] is _OPTION_ABSENT
    assert repeated["client_id"] is _OPTION_ABSENT
    assert other["client_id"] is _OPTION_ABSENT
    assert first["acknowledged_ip"] == repeated["acknowledged_ip"], (
        "A legacy client did not retain its chaddr-based binding"
    )
    assert first["acknowledged_ip"] != other["acknowledged_ip"], (
        "Different legacy chaddr values were treated as one client identity"
    )


@when("a truncated RFC 4361 identifier is followed by a valid DORA exchange")
def step_when_truncated_identifier_precedes_valid_dora(context):
    mac = _new_mac(context)
    iaid = 0x44444444
    truncated_id = b"\xff" + iaid.to_bytes(4, "big")
    xid = _new_xid(context)
    malformed_discover = build_client_packet(
        mac,
        xid,
        _client_options("discover", truncated_id),
    )
    sniffer = start_dhcp_sniffer(INTERFACE)
    _send(malformed_discover)
    malformed_offers = dhcp_packets(sniffer, 2, xid, DHCP_SERVER_IP)

    valid_id = _client_identifier(iaid, _new_duid(context))
    context.rfc4361["truncated_outcome"] = (
        "offered" if malformed_offers else "ignored"
    )
    context.rfc4361["after_truncated"] = _dora(context, valid_id, mac=mac)


@then("the later valid RFC 4361 binding is acknowledged")
def step_then_valid_binding_survives_truncated_identifier(context):
    exchange = _state(context)["after_truncated"]
    assert len(exchange["client_id"]) > 5
    assert exchange["acknowledged_ip"] == exchange["offered_ip"]


@when("an RFC 4361 client changes its identifier between DISCOVER and REQUEST")
def step_when_client_id_changes_during_dora(context):
    mac = _new_mac(context)
    duid = _new_duid(context)
    discover_id = _client_identifier(0x55555551, duid)
    request_id = _client_identifier(0x55555552, duid)
    offer_state = _discover(context, mac, discover_id)

    request = build_client_packet(
        mac,
        offer_state["xid"],
        _client_options(
            "request",
            request_id,
            server_id=offer_state["server_id"],
            requested_addr=offer_state["offered_ip"],
        ),
    )
    sniffer = start_dhcp_sniffer(INTERFACE)
    _send(request)
    acknowledgements = _packets_for_mac(
        dhcp_packets(
            sniffer,
            5,
            offer_state["xid"],
            offer_state["server_id"],
        ),
        mac,
    )
    rejections = _packets_for_mac(
        dhcp_packets(
            sniffer,
            6,
            offer_state["xid"],
            offer_state["server_id"],
        ),
        mac,
    )
    context.rfc4361["changed_identifier"] = {
        "acks": acknowledgements,
        "discover_id": discover_id,
        "offer": offer_state,
        "outcome": (
            "ack" if acknowledgements else "nak" if rejections else "ignored"
        ),
        "rejections": rejections,
        "request_id": request_id,
    }


@then("later valid exchanges keep the two RFC 4361 identifiers isolated")
def step_then_changed_identifier_recovers_without_collapsing(context):
    result = _state(context)["changed_identifier"]
    assert result["discover_id"] != result["request_id"]
    assert not (result["acks"] and result["rejections"]), (
        "Server returned both DHCPACK and DHCPNAK after Option 61 changed "
        "between DISCOVER and REQUEST"
    )

    discover_binding = _dora(
        context,
        result["discover_id"],
        mac=result["offer"]["mac"],
    )
    request_binding = _dora(context, result["request_id"])
    assert discover_binding["acknowledged_ip"] == discover_binding["offered_ip"]
    assert request_binding["acknowledged_ip"] == request_binding["offered_ip"]
    assert discover_binding["acknowledged_ip"] != request_binding["acknowledged_ip"], (
        "Changing Option 61 during DORA caused two valid RFC 4361 identifiers "
        f"to collapse onto {discover_binding['acknowledged_ip']}"
    )
    if result["acks"]:
        changed_request_ip = result["acks"][0][BOOTP].yiaddr
        assert request_binding["acknowledged_ip"] == changed_request_ip, (
            "Server ACKed the changed REQUEST but did not preserve that lease "
            "for the REQUEST client identifier"
        )
