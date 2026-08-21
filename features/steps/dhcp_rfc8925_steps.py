"""Acceptance steps for the testable RFC 8925 option-delivery subset."""

import ipaddress
import os
import subprocess
import time

from behave import given, then, when
from dhcpv4_support import (
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    assert_raw_option_absent,
    build_client_packet,
    dhcp_option,
    dhcp_options,
    dhcp_packets,
    mac_bytes,
    raw_dhcp_option,
    require_scapy_v4,
    start_dhcp_sniffer,
)

try:
    from scapy.all import ARP, AsyncSniffer, ICMP, sendp
except ImportError:
    ARP = AsyncSniffer = ICMP = sendp = None


DHCP_SERVER_IP = os.getenv("TEST_SERVER_IP", "192.168.56.1")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SUBNET = os.getenv("TEST_SUBNET", "192.168.56.0/24")
RFC8925_WAIT = int(os.getenv("TEST_RFC8925_WAIT", "1800"))
RFC8925_NON_V6ONLY_SUBNET = os.getenv(
    "TEST_DHCPV4_RELAY_SUBNET", "172.29.2.0/24"
)
MIN_V6ONLY_WAIT = 300
MAX_V6ONLY_WAIT = 0xFFFFFFFF
OPTION_IPV6_ONLY_PREFERRED = 108
OPTION_RAPID_COMMIT = 80
OPTION_108_NAMES = ("ipv6-only-preferred", "v6-only-preferred")
STANDARD_PRL = [1, 3, 6, 51, 58, 59]
POOL_START_OFFSET = int(os.getenv("DHCPV4_POOL_START_OFFSET", "100"))
POOL_END_OFFSET = int(os.getenv("DHCPV4_POOL_END_OFFSET", "200"))


def _state(context):
    if not hasattr(context, "rfc8925"):
        context.rfc8925 = {}
    return context.rfc8925


def _new_client_mac():
    octets = bytearray(os.urandom(6))
    octets[0] = (octets[0] | 0x02) & 0xFE
    return ":".join(f"{octet:02x}" for octet in octets)


def _new_xid():
    while True:
        xid = int.from_bytes(os.urandom(4), "big")
        if xid:
            return xid


def _require_packet_support():
    require_scapy_v4()
    if sendp is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")


def _configured_pool_addresses():
    network = ipaddress.ip_network(SUBNET, strict=False)
    assert 0 < POOL_START_OFFSET <= POOL_END_OFFSET < network.num_addresses - 1, (
        f"Invalid pool offsets {POOL_START_OFFSET}-{POOL_END_OFFSET} for {network}"
    )
    return {
        str(network.network_address + offset)
        for offset in range(POOL_START_OFFSET, POOL_END_OFFSET + 1)
    }


def _client_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def _message_options(message_type, prl, *, offer=None):
    options = [("message-type", message_type)]
    if offer is not None:
        options.extend(
            [
                ("server_id", offer["server_id"]),
                ("requested_addr", offer["offered_ip"]),
            ]
        )
    options.extend([("param_req_list", prl), ("end")])
    return options


def _relay_address(subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    return str(next(network.hosts()))


def _remove_relay_address(address, prefix):
    subprocess.run(
        ["ip", "addr", "del", f"{address}/{prefix}", "dev", INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _enable_relay_address(context, subnet):
    network = ipaddress.ip_network(subnet, strict=False)
    address = _relay_address(subnet)
    subprocess.run(
        ["ip", "addr", "add", f"{address}/{network.prefixlen}", "dev", INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    context.add_cleanup(_remove_relay_address, address, network.prefixlen)
    return address


def _build_relayed_packet(mac, xid, options, relay_address):
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=relay_address, dst=DHCP_SERVER_IP)
        / UDP(sport=67, dport=67)
        / BOOTP(
            op=1,
            hops=1,
            xid=xid,
            giaddr=relay_address,
            chaddr=mac_bytes(mac),
            flags=0x8000,
        )
        / DHCP(options=options)
    )


def _matching_packets(sniffer, message_type, xid, mac, server_id=None):
    packets = dhcp_packets(sniffer, message_type, xid, server_id=server_id)
    expected_client = _client_bytes(mac)
    return [
        packet
        for packet in packets
        if bytes(packet[BOOTP].chaddr[:6]) == expected_client
    ]


def _matching_captured_packets(packets, message_type, xid, mac, server_id=None):
    expected_client = _client_bytes(mac)
    matches = [
        packet
        for packet in packets
        if packet.haslayer(DHCP)
        and packet.haslayer(BOOTP)
        and dhcp_options(packet).get("message-type") == message_type
        and packet[BOOTP].xid == xid
        and bytes(packet[BOOTP].chaddr[:6]) == expected_client
    ]
    if server_id is not None:
        matches = [
            packet
            for packet in matches
            if dhcp_option(packet, "server_id") == server_id
        ]
    return matches


def _capture_offer(
    sniffer, xid, mac, expected_subnet, expected_server=None, allow_addressless=False
):
    packets = _matching_packets(sniffer, 2, xid, mac, expected_server)
    network = ipaddress.ip_network(expected_subnet, strict=False)
    packets = [
        packet
        for packet in packets
        if ipaddress.ip_address(packet[BOOTP].yiaddr) in network
        or (allow_addressless and packet[BOOTP].yiaddr == "0.0.0.0")
    ]
    assert packets, (
        f"No DHCPOFFER for xid 0x{xid:08x}, client {mac}, subnet {network}, "
        f"and server {expected_server or 'selected by response'}"
    )
    offer = packets[0]
    server_id = dhcp_option(offer, "server_id")
    assert server_id, "Matching DHCPOFFER has no server identifier"
    if expected_server is not None:
        assert server_id == expected_server, (
            f"DHCPOFFER server {server_id} does not match {expected_server}"
        )
    return {
        "offered_ip": offer[BOOTP].yiaddr,
        "packet": offer,
        "server_id": server_id,
    }


def _capture_ack(sniffer, xid, mac, offer):
    packets = _matching_packets(sniffer, 5, xid, mac, offer["server_id"])
    packets = [
        packet for packet in packets if packet[BOOTP].yiaddr == offer["offered_ip"]
    ]
    assert packets, (
        f"No DHCPACK for xid 0x{xid:08x}, client {mac}, server "
        f"{offer['server_id']}, and offered address {offer['offered_ip']}"
    )
    return packets[0]


def _complete_dora(
    context, prl, *, relayed_subnet=None, allow_addressless=False
):
    _require_packet_support()
    state = _state(context)
    state.clear()
    state["client_mac"] = _new_client_mac()
    state["xid"] = _new_xid()
    state["prl"] = list(prl)
    state["selected_subnet"] = relayed_subnet

    relay_address = None
    if relayed_subnet is not None:
        relay_address = _enable_relay_address(context, relayed_subnet)

    discover_options = _message_options("discover", state["prl"])
    if relay_address is None:
        discover = build_client_packet(
            state["client_mac"], state["xid"], discover_options
        )
    else:
        discover = _build_relayed_packet(
            state["client_mac"], state["xid"], discover_options, relay_address
        )
    offer_sniffer = start_dhcp_sniffer(INTERFACE)
    sendp(discover, iface=INTERFACE, verbose=False)

    expected_subnet = relayed_subnet or SUBNET
    # A relayed exchange may use an interface-specific server identifier.
    # Match that identifier from OFFER through ACK rather than imposing the
    # directly connected fixture address on the relay path.
    expected_server = None if relayed_subnet else DHCP_SERVER_IP
    offer = _capture_offer(
        offer_sniffer,
        state["xid"],
        state["client_mac"],
        expected_subnet,
        expected_server,
        allow_addressless,
    )

    state["offer"] = offer["packet"]
    state["offered_ip"] = offer["offered_ip"]
    state["server_id"] = offer["server_id"]
    if offer["offered_ip"] == "0.0.0.0":
        assert allow_addressless, "Unexpected addressless DHCPOFFER"
        state["ack"] = None
        state["addressless"] = True
        return

    request_options = _message_options("request", state["prl"], offer=offer)
    if relay_address is None:
        request = build_client_packet(
            state["client_mac"], state["xid"], request_options
        )
    else:
        request = _build_relayed_packet(
            state["client_mac"], state["xid"], request_options, relay_address
        )
    ack_sniffer = start_dhcp_sniffer(INTERFACE)
    sendp(request, iface=INTERFACE, verbose=False)
    ack = _capture_ack(
        ack_sniffer,
        state["xid"],
        state["client_mac"],
        offer,
    )

    state["ack"] = ack
    state["addressless"] = False


def _wire_option_payloads(packet, option_code):
    """Extract option payloads from a real response without Scapy type assumptions."""
    assert packet is not None and packet.haslayer(DHCP), "DHCP response has no options"
    encoded = bytes(packet[DHCP])
    cookie = b"\x63\x82\x53\x63"
    offset = len(cookie) if encoded.startswith(cookie) else 0
    payloads = []

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


def _decode_wait_value(packet, label):
    value = raw_dhcp_option(packet, OPTION_IPV6_ONLY_PREFERRED, OPTION_108_NAMES)
    assert value is not None, f"{label} is missing DHCP option 108"
    payloads = _wire_option_payloads(packet, OPTION_IPV6_ONLY_PREFERRED)
    assert len(payloads) == 1, (
        f"{label} must contain exactly one option 108, found {len(payloads)}"
    )
    payload = payloads[0]
    assert len(payload) == 4, (
        f"{label} option 108 has malformed length {len(payload)}; expected 4"
    )
    return int.from_bytes(payload, "big")


def _decode_wait(packet, label):
    wait = _decode_wait_value(packet, label)
    assert MIN_V6ONLY_WAIT <= wait <= MAX_V6ONLY_WAIT, (
        f"{label} option 108 wait {wait} is outside the RFC 8925 range "
        f"{MIN_V6ONLY_WAIT}..{MAX_V6ONLY_WAIT}"
    )
    return wait


def _assert_option_absent(packet, label):
    assert_raw_option_absent(
        packet,
        OPTION_IPV6_ONLY_PREFERRED,
        OPTION_108_NAMES,
        message_type=label,
    )
    assert not _wire_option_payloads(packet, OPTION_IPV6_ONLY_PREFERRED), (
        f"{label} unexpectedly contains DHCP option 108 on the wire"
    )


def _responses(context):
    state = _state(context)
    assert state.get("offer") is not None, "RFC 8925 DHCPOFFER state is missing"
    assert state.get("ack") is not None, "RFC 8925 DHCPACK state is missing"
    return (("DHCPOFFER", state["offer"]), ("DHCPACK", state["ack"]))


def _option_108_responses(context):
    state = _state(context)
    assert state.get("offer") is not None, "RFC 8925 DHCPOFFER state is missing"
    responses = [("DHCPOFFER", state["offer"])]
    if state.get("ack") is not None:
        responses.append(("DHCPACK", state["ack"]))
    return responses


@when(
    "an RFC 8925 client requests option 108 and follows any addressful fallback"
)
def step_request_option_108(context):
    _complete_dora(
        context,
        STANDARD_PRL + [OPTION_IPV6_ONLY_PREFERRED],
        allow_addressless=True,
    )


@then("its matching DHCPOFFER contains the configured IPv6-Only Preferred wait")
def step_offer_contains_wait(context):
    actual = _decode_wait(_state(context)["offer"], "DHCPOFFER")
    assert actual == RFC8925_WAIT, (
        f"DHCPOFFER option 108 wait {actual} does not match {RFC8925_WAIT}"
    )


@then("any fallback DHCPACK contains the configured IPv6-Only Preferred wait")
def step_ack_contains_wait(context):
    if _state(context).get("ack") is None:
        assert _state(context)["offered_ip"] == "0.0.0.0"
        return
    actual = _decode_wait(_state(context)["ack"], "DHCPACK")
    assert actual == RFC8925_WAIT, (
        f"DHCPACK option 108 wait {actual} does not match {RFC8925_WAIT}"
    )


@then("all IPv6-Only Preferred responses use one RFC-compliant four-byte timer")
def step_responses_use_rfc_compliant_timer(context):
    assert MIN_V6ONLY_WAIT <= RFC8925_WAIT <= MAX_V6ONLY_WAIT, (
        f"TEST_RFC8925_WAIT must be in the RFC 8925 range "
        f"{MIN_V6ONLY_WAIT}..{MAX_V6ONLY_WAIT}, got {RFC8925_WAIT}"
    )
    waits = [
        _decode_wait(packet, label)
        for label, packet in _option_108_responses(context)
    ]
    assert waits and all(wait == RFC8925_WAIT for wait in waits)


@when(
    "an RFC 8925 client requests duplicate option 108 PRL entries"
)
def step_request_duplicate_option_108(context):
    prl = STANDARD_PRL + [OPTION_IPV6_ONLY_PREFERRED, OPTION_IPV6_ONLY_PREFERRED]
    _complete_dora(context, prl, allow_addressless=True)


@then("all matching responses contain the same configured IPv6-Only Preferred wait")
def step_duplicate_request_is_stable(context):
    waits = [
        _decode_wait(packet, label)
        for label, packet in _option_108_responses(context)
    ]
    assert waits and all(wait == RFC8925_WAIT for wait in waits), (
        f"Duplicate PRL request returned unstable option 108 waits: {waits}"
    )


@then("all matching responses contain a four-octet zero wait")
def step_zero_default_wait(context):
    assert RFC8925_WAIT == 0, (
        "The @rfc8925_zero_default profile requires TEST_RFC8925_WAIT=0, got "
        f"{RFC8925_WAIT}"
    )
    waits = [
        _decode_wait_value(packet, label)
        for label, packet in _option_108_responses(context)
    ]
    assert waits and all(wait == 0 for wait in waits), (
        f"Zero-default profile returned waits {waits}"
    )


@when("an ordinary RFC 8925 client completes DORA without requesting option 108")
def step_ordinary_client_dora(context):
    _complete_dora(context, STANDARD_PRL)


@then("both matching responses omit the IPv6-Only Preferred option")
def step_responses_omit_option_108(context):
    for label, packet in _responses(context):
        _assert_option_absent(packet, label)


@then("the ordinary RFC 8925 exchange completes with one leased address")
def step_ordinary_exchange_completes(context):
    state = _state(context)
    assert state["offer"][BOOTP].yiaddr == state["offered_ip"]
    assert state["ack"][BOOTP].yiaddr == state["offered_ip"]
    assert ipaddress.ip_address(state["offered_ip"]) in ipaddress.ip_network(
        SUBNET, strict=False
    )


@when("an RFC 8925 client requests option 108 on the relayed non-IPv6-mostly subnet")
def step_request_option_108_on_relayed_subnet(context):
    _complete_dora(
        context,
        STANDARD_PRL + [OPTION_IPV6_ONLY_PREFERRED],
        relayed_subnet=RFC8925_NON_V6ONLY_SUBNET,
    )


@then(
    "both matching relayed-subnet responses omit the IPv6-Only Preferred option"
)
def step_relayed_responses_omit_option_108(context):
    selected_subnet = ipaddress.ip_network(
        _state(context)["selected_subnet"], strict=False
    )
    for label, packet in _responses(context):
        assert ipaddress.ip_address(packet[BOOTP].yiaddr) in selected_subnet, (
            f"{label} address {packet[BOOTP].yiaddr} is outside {selected_subnet}"
        )
        _assert_option_absent(packet, label)


@when("an RFC 8925 client requests Rapid Commit together with option 108")
def step_request_rapid_commit_with_option_108(context):
    _require_packet_support()
    state = _state(context)
    state.clear()
    mac = _new_client_mac()
    xid = _new_xid()
    options = [
        ("message-type", "discover"),
        (OPTION_RAPID_COMMIT, b""),
        (
            "param_req_list",
            STANDARD_PRL + [OPTION_IPV6_ONLY_PREFERRED],
        ),
        "end",
    ]
    packet = build_client_packet(mac, xid, options)
    sniffer = start_dhcp_sniffer(INTERFACE)
    sendp(packet, iface=INTERFACE, verbose=False)
    sniffer.join()
    packets = list(sniffer.results or [])
    state["rapid_commit_acks"] = _matching_captured_packets(
        packets, 5, xid, mac, DHCP_SERVER_IP
    )
    state["rapid_commit_offers"] = _matching_captured_packets(
        packets, 2, xid, mac, DHCP_SERVER_IP
    )


@then("the server does not send a rapid DHCPACK")
def step_no_rapid_commit_ack(context):
    assert not _state(context)["rapid_commit_acks"], (
        "Server honored DHCPv4 Rapid Commit even though the response included "
        "IPv6-Only Preferred"
    )


@then("the fallback DHCPOFFER contains IPv6-Only Preferred without Rapid Commit")
def step_option_108_offer_omits_rapid_commit(context):
    offers = _state(context)["rapid_commit_offers"]
    assert offers, "Server sent neither a normal DHCPOFFER nor an addressless DHCPOFFER"
    for offer in offers:
        assert _decode_wait(offer, "DHCPOFFER") == RFC8925_WAIT
        assert not _wire_option_payloads(offer, OPTION_RAPID_COMMIT), (
            "Fallback DHCPOFFER incorrectly contained Rapid Commit option 80"
        )


@given("the RFC 8925 observability fixture has a bounded IPv4 pool")
def step_bounded_observability_pool(context):
    candidates = _configured_pool_addresses()
    assert 2 <= len(candidates) <= 8, (
        "RFC 8925 observability requires a pool of 2-8 addresses; "
        f"configured pool has {len(candidates)}"
    )
    _state(context)["pool_candidates"] = candidates


@when("an RFC 8925 client requests an addressless option 108 response")
def step_request_addressless_option_108(context):
    _require_packet_support()
    assert AsyncSniffer is not None and ICMP is not None and ARP is not None, (
        "Scapy ICMP/ARP capture support is required for RFC 8925 observability"
    )
    state = _state(context)
    pool_candidates = state.get("pool_candidates") or _configured_pool_addresses()
    state.clear()
    state["pool_candidates"] = pool_candidates
    mac = _new_client_mac()
    xid = _new_xid()
    discover = build_client_packet(
        mac,
        xid,
        [
            ("message-type", "discover"),
            (
                "param_req_list",
                STANDARD_PRL + [OPTION_IPV6_ONLY_PREFERRED],
            ),
            "end",
        ],
    )
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        lfilter=lambda packet: (
            packet.haslayer(DHCP)
            or packet.haslayer(ICMP)
            or packet.haslayer(ARP)
        ),
        timeout=5,
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)
    sendp(discover, iface=INTERFACE, verbose=False)
    sniffer.join()
    packets = list(sniffer.results or [])
    state["addressless_offers"] = _matching_captured_packets(
        packets, 2, xid, mac, DHCP_SERVER_IP
    )
    state["addressless_acks"] = _matching_captured_packets(
        packets, 5, xid, mac, DHCP_SERVER_IP
    )
    state["addressless_probes"] = [
        packet
        for packet in packets
        if (
            packet.haslayer(IP)
            and packet.haslayer(ICMP)
            and packet[IP].src == DHCP_SERVER_IP
            and packet[IP].dst in pool_candidates
            and packet[ICMP].type == 8
        )
        or (
            packet.haslayer(ARP)
            and packet[ARP].op == 1
            and packet[ARP].pdst in pool_candidates
        )
    ]


@then("the server sends an addressless DHCPOFFER without probing the pool")
def step_addressless_offer_has_no_probe(context):
    state = _state(context)
    assert not state["addressless_acks"], (
        "Addressless RFC 8925 discovery unexpectedly produced DHCPACK"
    )
    assert state["addressless_offers"], "No RFC 8925 DHCPOFFER was captured"
    assert {offer[BOOTP].yiaddr for offer in state["addressless_offers"]} == {
        "0.0.0.0"
    }, "The addressless observability profile returned an IPv4 address"
    for offer in state["addressless_offers"]:
        assert _decode_wait(offer, "DHCPOFFER") == RFC8925_WAIT
    assert not state["addressless_probes"], (
        "Server sent an ICMP or ARP probe for a configured pool candidate "
        "before an addressless response"
    )


@when("ordinary clients immediately acquire every configured pool address")
def step_ordinary_clients_fill_pool(context):
    candidates = _state(context)["pool_candidates"]
    committed = []
    for _candidate in candidates:
        _complete_dora(context, STANDARD_PRL)
        state = _state(context)
        assert state.get("ack") is not None, "Ordinary client did not receive DHCPACK"
        committed.append(state["ack"][BOOTP].yiaddr)
    state["pool_candidates"] = candidates
    state["committed_pool_addresses"] = committed


@then("the bounded pool reaches full committed capacity")
def step_bounded_pool_reaches_capacity(context):
    state = _state(context)
    committed = state["committed_pool_addresses"]
    assert len(committed) == len(set(committed)), (
        f"Ordinary clients did not receive unique leases: {committed}"
    )
    assert set(committed) == state["pool_candidates"], (
        f"Committed {sorted(committed)}, expected every configured candidate "
        f"{sorted(state['pool_candidates'])}"
    )
