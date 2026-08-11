"""Acceptance steps for RFC 3442 Classless Static Route option 121."""

import ipaddress
import os

from behave import then, when
from dhcpv4_support import (
    build_client_packet,
    client_mac,
    dhcp_option,
    dhcp_packets,
    start_dhcp_sniffer,
)

try:
    from scapy.all import BOOTP, DHCP, sendp
except ImportError:
    BOOTP = DHCP = sendp = None


DHCP_SERVER_IP = os.getenv("TEST_SERVER_IP", "192.168.56.1")
CLIENT_MAC = os.getenv("TEST_CLIENT_MAC", "02:00:00:00:00:01")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SUBNET = os.getenv("TEST_SUBNET", "192.168.56.0/24")
ROUTE_GATEWAY = os.getenv("TEST_RFC3442_GATEWAY", DHCP_SERVER_IP)
DEFAULT_ROUTE = os.getenv(
    "TEST_RFC3442_DEFAULT_ROUTE", f"0.0.0.0/0={ROUTE_GATEWAY}"
)
NON_OCTET_ROUTE = os.getenv(
    "TEST_RFC3442_NON_OCTET_ROUTE", f"198.51.100.128/25={ROUTE_GATEWAY}"
)
ADDITIONAL_ROUTES = os.getenv(
    "TEST_RFC3442_ADDITIONAL_ROUTES", f"203.0.113.0/24={ROUTE_GATEWAY}"
)
UNKNOWN_PRL_CODE = int(os.getenv("TEST_RFC3442_UNKNOWN_PRL_CODE", "224"))

_STANDARD_PRL = [121, 3, 33, 1, 6, 51, 58, 59]


def _require_packet_support():
    if BOOTP is None or DHCP is None or sendp is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")


def _state(context):
    if not hasattr(context, "rfc3442"):
        context.rfc3442 = {}
    return context.rfc3442


def _new_client_mac():
    random_bytes = os.urandom(3)
    return f"02:00:00:{random_bytes[0]:02x}:{random_bytes[1]:02x}:{random_bytes[2]:02x}"


def _client_mac(context):
    state = _state(context)
    if "client_mac" not in state:
        state["client_mac"] = _new_client_mac()
    return client_mac(state, CLIENT_MAC)


def _parse_route(route_spec):
    try:
        destination_text, router_text = (
            part.strip() for part in route_spec.rsplit("=", 1)
        )
        destination = ipaddress.ip_network(destination_text, strict=True)
        router = ipaddress.ip_address(router_text)
    except ValueError as exc:
        raise AssertionError(
            f"Invalid RFC 3442 route {route_spec!r}; expected IPv4-CIDR=IPv4-router"
        ) from exc
    assert destination.version == 4 and router.version == 4, (
        f"RFC 3442 route must contain IPv4 values: {route_spec!r}"
    )
    return str(destination), str(router)


def _expected_routes():
    additional = [
        route.strip() for route in ADDITIONAL_ROUTES.split(",") if route.strip()
    ]
    routes = [_parse_route(DEFAULT_ROUTE), _parse_route(NON_OCTET_ROUTE)]
    routes.extend(_parse_route(route) for route in additional)
    assert len(routes) >= 3, (
        "RFC 3442 coverage requires a default route, a non-octet-prefix route, "
        "and at least one additional route"
    )
    assert any(ipaddress.ip_network(route[0]).prefixlen == 0 for route in routes), (
        f"Configured RFC 3442 routes do not include a default route: {routes!r}"
    )
    assert any(
        ipaddress.ip_network(route[0]).prefixlen % 8
        for route in routes
    ), f"Configured RFC 3442 routes do not include a non-octet prefix: {routes!r}"
    return routes


def _dhcp_tlv_payloads(packet, option_code):
    """Read an option directly from the DHCP wire TLVs, joining RFC 3396 fragments."""
    assert packet is not None and packet.haslayer(DHCP), "Response has no DHCP layer"
    encoded = bytes(packet[DHCP])
    cookie = b"\x63\x82\x53\x63"

    payloads = []
    # Scapy normally keeps the cookie in BOOTP.options, but some constructed
    # DHCP layers include it here. Accept either representation of the same wire data.
    offset = len(cookie) if encoded.startswith(cookie) else 0
    while offset < len(encoded):
        code = encoded[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        assert offset < len(encoded), f"DHCP option {code} is missing its length byte"
        length = encoded[offset]
        offset += 1
        end = offset + length
        assert end <= len(encoded), f"DHCP option {code} is truncated on the wire"
        if code == option_code:
            payloads.append(encoded[offset:end])
        offset = end
    return payloads


def _decode_classless_routes(packet):
    payloads = _dhcp_tlv_payloads(packet, 121)
    assert payloads, "DHCP response is missing Classless Static Route option 121"
    payload = b"".join(payloads)
    routes = []
    offset = 0
    while offset < len(payload):
        prefix_length = payload[offset]
        offset += 1
        assert prefix_length <= 32, (
            f"Option 121 contains invalid prefix length {prefix_length}"
        )
        destination_length = (prefix_length + 7) // 8
        route_end = offset + destination_length + 4
        assert route_end <= len(payload), "Option 121 contains a truncated route entry"

        significant = payload[offset:offset + destination_length]
        offset += destination_length
        if prefix_length % 8 and significant:
            host_mask = (1 << (8 - (prefix_length % 8))) - 1
            assert significant[-1] & host_mask == 0, (
                "Option 121 non-octet destination has non-zero host bits"
            )
        destination_bytes = significant + b"\x00" * (4 - destination_length)
        destination = ipaddress.ip_network(
            (ipaddress.IPv4Address(destination_bytes), prefix_length), strict=True
        )
        router = ipaddress.IPv4Address(payload[offset:route_end])
        offset = route_end
        routes.append((str(destination), str(router)))
    return routes


def _response_for(context, state_key, message_type, label):
    state = _state(context)
    packets = dhcp_packets(
        state[state_key],
        message_type,
        state["xid"],
        server_id=DHCP_SERVER_IP,
    )
    mac = bytes.fromhex(state["client_mac"].replace(":", ""))
    packets = [packet for packet in packets if bytes(packet[BOOTP].chaddr[:6]) == mac]
    assert packets, (
        f"No {label} from {DHCP_SERVER_IP} for transaction {state['xid']:#010x} "
        f"and client {state['client_mac']}"
    )
    return packets[0]


def _send_discover(context, parameter_request_list):
    _require_packet_support()
    state = _state(context)
    state.clear()
    state["client_mac"] = _new_client_mac()
    state["xid"] = int.from_bytes(os.urandom(4), "big")
    state["prl"] = parameter_request_list
    discover = build_client_packet(
        _client_mac(context),
        state["xid"],
        [
            ("message-type", "discover"),
            ("param_req_list", parameter_request_list),
            ("end"),
        ],
    )
    state["offer_sniffer"] = start_dhcp_sniffer(INTERFACE)
    sendp(discover, iface=INTERFACE, verbose=False)


def _capture_offer(context):
    state = _state(context)
    offer = _response_for(context, "offer_sniffer", 2, "DHCPOFFER")
    offered_ip = offer[BOOTP].yiaddr
    assert ipaddress.ip_address(offered_ip) in ipaddress.ip_network(SUBNET), (
        f"DHCPOFFER address {offered_ip} is outside configured subnet {SUBNET}"
    )
    assert dhcp_option(offer, "server_id") == DHCP_SERVER_IP, (
        f"DHCPOFFER server identifier is not {DHCP_SERVER_IP}"
    )
    state["offer"] = offer
    state["offered_ip"] = offered_ip
    return offer


def _send_request(context):
    _require_packet_support()
    state = _state(context)
    assert state.get("offered_ip"), "No transaction-specific offer is available"
    request = build_client_packet(
        _client_mac(context),
        state["xid"],
        [
            ("message-type", "request"),
            ("server_id", DHCP_SERVER_IP),
            ("requested_addr", state["offered_ip"]),
            ("param_req_list", state["prl"]),
            ("end"),
        ],
    )
    state["ack_sniffer"] = start_dhcp_sniffer(INTERFACE)
    sendp(request, iface=INTERFACE, verbose=False)


def _capture_ack(context):
    state = _state(context)
    ack = _response_for(context, "ack_sniffer", 5, "DHCPACK")
    assert ack[BOOTP].yiaddr == state["offered_ip"], (
        f"DHCPACK address {ack[BOOTP].yiaddr} does not match offered address "
        f"{state['offered_ip']}"
    )
    state["ack"] = ack
    return ack


@when("a client completes DORA requesting the Classless Static Route option")
def step_complete_dora_with_classless_routes(context):
    _send_discover(context, _STANDARD_PRL)
    _capture_offer(context)
    _send_request(context)
    _capture_ack(context)


@then("the transaction-specific DHCPOFFER contains the configured classless routes")
def step_offer_contains_classless_routes(context):
    actual = _decode_classless_routes(_state(context).get("offer"))
    expected = _expected_routes()
    assert actual == expected, f"DHCPOFFER routes {actual!r} do not equal {expected!r}"


@then("the transaction-specific DHCPACK contains the configured classless routes")
def step_ack_contains_classless_routes(context):
    actual = _decode_classless_routes(_state(context).get("ack"))
    expected = _expected_routes()
    assert actual == expected, f"DHCPACK routes {actual!r} do not equal {expected!r}"


@then(
    "both RFC 3442 responses contain a default route, a non-octet-prefix route, "
    "and multiple routes"
)
def step_responses_cover_route_shapes(context):
    for label, packet in (
        ("DHCPOFFER", _state(context).get("offer")),
        ("DHCPACK", _state(context).get("ack")),
    ):
        routes = _decode_classless_routes(packet)
        prefixes = [
            ipaddress.ip_network(destination).prefixlen
            for destination, _ in routes
        ]
        assert len(routes) >= 3, f"{label} returned fewer than three routes: {routes!r}"
        assert 0 in prefixes, f"{label} has no default route: {routes!r}"
        assert any(prefix % 8 for prefix in prefixes), (
            f"{label} has no non-octet-prefix route: {routes!r}"
        )


@then("the configured classless default route is distinct from any legacy Router option")
def step_classless_default_is_distinct(context):
    expected_default = _parse_route(DEFAULT_ROUTE)
    for label, packet in (
        ("DHCPOFFER", _state(context).get("offer")),
        ("DHCPACK", _state(context).get("ack")),
    ):
        routes = _decode_classless_routes(packet)
        defaults = [route for route in routes if route[0] == "0.0.0.0/0"]
        assert defaults == [expected_default], (
            f"{label} did not return the configured RFC 3442 default route: "
            f"{defaults!r}"
        )

        legacy_router_data = b"".join(_dhcp_tlv_payloads(packet, 3))
        if legacy_router_data:
            assert len(legacy_router_data) % 4 == 0, (
                f"{label} contains a malformed legacy Router option"
            )
            legacy_routers = [
                str(ipaddress.IPv4Address(legacy_router_data[offset:offset + 4]))
                for offset in range(0, len(legacy_router_data), 4)
            ]
            assert expected_default[1] not in legacy_routers, (
                "RFC 3442 fixture requires a classless default distinct "
                f"from legacy routers, got {legacy_routers!r}"
            )


@when("a client sends DHCPDISCOVER with duplicated and unknown RFC 3442 PRL codes")
def step_discover_with_unusual_prl(context):
    assert 1 <= UNKNOWN_PRL_CODE <= 254, (
        f"TEST_RFC3442_UNKNOWN_PRL_CODE must be between 1 and 254, got {UNKNOWN_PRL_CODE}"
    )
    assert UNKNOWN_PRL_CODE not in _STANDARD_PRL, (
        f"TEST_RFC3442_UNKNOWN_PRL_CODE {UNKNOWN_PRL_CODE} is already a known test code"
    )
    unusual_prl = [121, UNKNOWN_PRL_CODE, 121, 3, 33, UNKNOWN_PRL_CODE]
    _send_discover(context, unusual_prl)


@then("the server returns a transaction-specific DHCPOFFER for the unusual PRL")
def step_offer_for_unusual_prl(context):
    _capture_offer(context)


@when("the client requests that offer with the same unusual PRL")
def step_request_with_unusual_prl(context):
    _send_request(context)


@then("the server returns a transaction-specific DHCPACK for the offered address")
def step_ack_for_unusual_prl(context):
    _capture_ack(context)
