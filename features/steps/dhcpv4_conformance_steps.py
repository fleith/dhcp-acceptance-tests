"""Focused DHCPv4 conformance, resilience, relay, and persistence steps."""

import ipaddress
import json
import os
import shlex
import subprocess
import time
from pathlib import Path

from behave import given, then, when

from dhcpv4_support import (
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    build_client_packet,
    dhcp_option,
    dhcp_options,
    mac_bytes,
    option_bytes,
    raw_dhcp_option,
    raw_dhcp_option_fragments,
    require_scapy_v4,
    start_dhcp_sniffer,
)

try:
    from scapy.all import AsyncSniffer, Raw, sendp
except ImportError:
    AsyncSniffer = Raw = sendp = None

try:
    import dns.resolver
except ImportError:
    dns = None


SERVER_IP = os.getenv("TEST_SERVER_IP", "192.168.56.1")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SUBNET = os.getenv("TEST_SUBNET", "192.168.56.0/24")
RELAY_SUBNET = os.getenv("TEST_DHCPV4_RELAY_SUBNET", "192.168.58.0/24")
RESERVED_MAC = os.getenv("TEST_DHCPV4_RESERVED_MAC", "02:00:00:ff:00:01")
RESERVED_OFFSET = int(os.getenv("TEST_DHCPV4_RESERVED_OFFSET", "50"))
CLASS_NAME = os.getenv("TEST_DHCPV4_CLASS_NAME", "acceptance-class")
CLASS_DOMAIN = os.getenv("TEST_DHCPV4_CLASS_DOMAIN", "class.acceptance.test")
CONCURRENT_CLIENTS = int(os.getenv("TEST_DHCPV4_CONCURRENT_CLIENTS", "8"))
BATCH_DEADLINE = float(os.getenv("TEST_DHCPV4_BATCH_DEADLINE", "15"))
CHURN_CYCLES = int(os.getenv("TEST_DHCPV4_CHURN_CYCLES", "12"))
FUZZ_CASES = int(os.getenv("TEST_DHCPV4_FUZZ_CASES", "24"))
STATE_DIR = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))
STATE_FILE = STATE_DIR / "dhcpv4-persistent-binding.json"
PERSISTENT_MAC = "02:00:00:fe:00:01"
PERSISTENT_CLIENT_ID = b"\xffacceptance-persistent-client"
PARAMETER_REQUEST_LIST = [1, 3, 6, 15, 51, 58, 59]
RELAY_OPTION = b"\x01\x08circuit1\x02\x08remote01"
RFC3396_LONG_OPTION_CODE = 224
RFC3396_LONG_OPTION = b"0123456789abcdef" * 20
RELOADED_CLASS_DOMAIN = os.getenv(
    "TEST_RELOADED_CLASS_DOMAIN", "reloaded.acceptance.test"
)
DDNS_FQDN = os.getenv(
    "TEST_DDNS_FQDN", "acceptance-client.dhcp-acceptance.test."
)


def _state(context):
    if not hasattr(context, "dhcpv4_conformance"):
        context.dhcpv4_conformance = {"active": []}
    return context.dhcpv4_conformance


def _new_mac():
    value = bytearray(os.urandom(6))
    value[0] = (value[0] | 0x02) & 0xFE
    return ":".join(f"{octet:02x}" for octet in value)


def _new_xid():
    while True:
        xid = int.from_bytes(os.urandom(4), "big")
        if xid:
            return xid


def _message_type(packet):
    return dhcp_options(packet).get("message-type")


def _matches(packet, xid, message_types=None, mac=None):
    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return False
    if packet[BOOTP].xid != xid:
        return False
    if message_types is not None and _message_type(packet) not in message_types:
        return False
    if mac is not None:
        expected = mac_bytes(mac)
        if bytes(packet[BOOTP].chaddr)[: len(expected)] != expected:
            return False
    return True


def _capture_packets(packets, xid, message_types, mac=None, timeout=3, stop_first=True):
    require_scapy_v4()
    if sendp is None:
        raise RuntimeError("Scapy is required for DHCPv4 conformance scenarios")
    stop_filter = None
    if stop_first:
        stop_filter = lambda candidate: _matches(
            candidate, xid, message_types=message_types, mac=mac
        )
    sniffer = start_dhcp_sniffer(INTERFACE, timeout=timeout, stop_filter=stop_filter)
    for packet in packets:
        sendp(packet, iface=INTERFACE, verbose=False)
        if len(packets) > 1:
            time.sleep(0.12)
    sniffer.join()
    return [
        packet
        for packet in (sniffer.results or [])
        if _matches(packet, xid, message_types=message_types, mac=mac)
    ]


def _client_options(message_type, *, client_id=None, extra=None, requested=None):
    options = [("message-type", message_type)]
    if client_id is not None:
        options.append(("client_id", client_id))
    if requested is not None:
        options.append(("requested_addr", requested))
    if extra:
        options.extend(extra)
    options.extend([("param_req_list", PARAMETER_REQUEST_LIST), "end"])
    return options


def _discover(mac, *, client_id=None, requested=None, extra=None, xid=None):
    xid = xid or _new_xid()
    packet = build_client_packet(
        mac,
        xid,
        _client_options(
            "discover", client_id=client_id, extra=extra, requested=requested
        ),
    )
    responses = _capture_packets([packet], xid, {2, 5, 6}, mac=mac)
    offers = [packet for packet in responses if _message_type(packet) == 2]
    assert not [packet for packet in responses if _message_type(packet) in {5, 6}], (
        f"Server sent ACK/NAK directly to DISCOVER transaction 0x{xid:08x}"
    )
    return {"mac": mac, "xid": xid, "packet": packet, "offers": offers}


def _request(discovery, *, client_id=None, extra=None, repeats=1):
    assert discovery["offers"], f"No DHCPOFFER for 0x{discovery['xid']:08x}"
    offered = {packet[BOOTP].yiaddr for packet in discovery["offers"]}
    assert len(offered) == 1, f"Transaction received conflicting offers: {offered}"
    offered_ip = offered.pop()
    options = [("message-type", "request")]
    server_id = dhcp_option(discovery["offers"][0], "server_id")
    if server_id is not None:
        options.append(("server_id", server_id))
    if client_id is not None:
        options.append(("client_id", client_id))
    options.append(("requested_addr", offered_ip))
    if extra:
        options.extend(extra)
    options.extend([("param_req_list", PARAMETER_REQUEST_LIST), "end"])
    request = build_client_packet(discovery["mac"], discovery["xid"], options)
    responses = _capture_packets(
        [request] * repeats,
        discovery["xid"],
        {5, 6},
        mac=discovery["mac"],
        timeout=3,
        stop_first=repeats == 1,
    )
    assert not [packet for packet in responses if _message_type(packet) == 6], (
        f"Server rejected offered address {offered_ip}"
    )
    acknowledgements = [packet for packet in responses if _message_type(packet) == 5]
    assert acknowledgements, f"No DHCPACK for offered address {offered_ip}"
    ack_addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
    assert ack_addresses == {offered_ip}, (
        f"DHCPACK changed offered address {offered_ip}: {ack_addresses}"
    )
    return {
        "mac": discovery["mac"],
        "xid": discovery["xid"],
        "ip": offered_ip,
        "offer": discovery["offers"][0],
        "acks": acknowledgements,
        "request": request,
        "client_id": client_id,
    }


def _dora(context, mac=None, *, client_id=None, requested=None, extra=None):
    lease = _request(
        _discover(
            mac or _new_mac(),
            client_id=client_id,
            requested=requested,
            extra=extra,
        ),
        client_id=client_id,
        extra=extra,
    )
    _state(context)["active"].append(lease)
    return lease


def _release(lease):
    options = [("message-type", "release")]
    server_id = dhcp_option(lease.get("offer"), "server_id") or SERVER_IP
    options.append(("server_id", server_id))
    if lease.get("client_id") is not None:
        options.append(("client_id", lease["client_id"]))
    options.append("end")
    packet = build_client_packet(
        lease["mac"],
        lease["xid"],
        options,
        ciaddr=lease["ip"],
        source_ip=lease["ip"],
        destination_ip=server_id,
        flags=0,
    )
    sendp(packet, iface=INTERFACE, verbose=False)


def _cleanup(context):
    for lease in list(_state(context).get("active", [])):
        try:
            _release(lease)
        except Exception as exc:
            print(f"\n[WARN] Could not release focused DHCPv4 lease: {exc}")
    _state(context)["active"] = []


def _ensure_cleanup(context):
    state = _state(context)
    if not state.get("cleanup_registered"):
        context.add_cleanup(_cleanup, context)
        state["cleanup_registered"] = True


def _run_adapter(variable):
    command = os.getenv(variable, "").strip()
    assert command, f"{variable} is required when this capability is enabled"
    result = subprocess.run(
        shlex.split(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"{variable} failed with exit {result.returncode}: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def _rebind(lease):
    options = [("message-type", "request")]
    if lease.get("client_id") is not None:
        options.append(("client_id", lease["client_id"]))
    options.extend([("param_req_list", PARAMETER_REQUEST_LIST), "end"])
    xid = _new_xid()
    packet = build_client_packet(
        lease["mac"],
        xid,
        options,
        ciaddr=lease["ip"],
        source_ip=lease["ip"],
        flags=0x8000,
    )
    responses = _capture_packets([packet], xid, {5, 6}, mac=lease["mac"], timeout=5)
    assert not [packet for packet in responses if _message_type(packet) == 6]
    acks = [packet for packet in responses if _message_type(packet) == 5]
    assert acks, f"Active binding {lease['ip']} was not renewed/rebound"
    assert {packet[BOOTP].yiaddr for packet in acks} <= {lease["ip"], "0.0.0.0"}
    return acks[0]


@when("one DHCPv4 client retransmits the same DISCOVER")
def step_retransmit_discover(context):
    _ensure_cleanup(context)
    mac = _new_mac()
    xid = _new_xid()
    packet = build_client_packet(mac, xid, _client_options("discover"))
    responses = _capture_packets(
        [packet, packet], xid, {2, 5, 6}, mac=mac, timeout=3, stop_first=False
    )
    assert not [packet for packet in responses if _message_type(packet) in {5, 6}], (
        "A retransmitted DISCOVER received ACK/NAK instead of DHCPOFFER"
    )
    offers = [packet for packet in responses if _message_type(packet) == 2]
    assert offers, "Retransmitted DHCPDISCOVER received no DHCPOFFER"
    _state(context)["retransmit_discovery"] = {
        "mac": mac,
        "xid": xid,
        "packet": packet,
        "offers": offers,
    }


@then("every matching offer is an uncommitted pool candidate")
def step_retransmit_offer_identity(context):
    offers = _state(context)["retransmit_discovery"]["offers"]
    addresses = {packet[BOOTP].yiaddr for packet in offers}
    network = ipaddress.ip_network(SUBNET, strict=False)
    assert addresses, "Retransmitted DISCOVER produced no candidate addresses"
    assert all(ipaddress.ip_address(address) in network for address in addresses), (
        f"Retransmission produced out-of-subnet candidates: {addresses}"
    )


@when("that client retransmits the matching REQUEST")
def step_retransmit_request(context):
    discovery = dict(_state(context)["retransmit_discovery"])
    # A server may rotate uncommitted OFFER candidates. The client selects one
    # offer; idempotency is required once REQUEST identifies that candidate.
    discovery["offers"] = [discovery["offers"][-1]]
    lease = _request(discovery, repeats=2)
    _state(context)["retransmit_lease"] = lease
    _state(context)["active"].append(lease)


@then("every matching acknowledgement preserves one binding")
def step_retransmit_ack_identity(context):
    lease = _state(context)["retransmit_lease"]
    addresses = {packet[BOOTP].yiaddr for packet in lease["acks"]}
    assert addresses == {lease["ip"]}, f"Retransmitted REQUEST changed binding: {addresses}"


@then("another DHCPv4 client receives a distinct active lease")
def step_second_client_distinct(context):
    second = _dora(context)
    first = _state(context)["retransmit_lease"]
    assert second["ip"] != first["ip"], (
        f"Two active clients were assigned {first['ip']}"
    )


@when("multiple DHCPv4 clients acquire leases concurrently")
def step_concurrent_clients(context):
    _ensure_cleanup(context)
    started = time.monotonic()
    assert 2 <= CONCURRENT_CLIENTS <= 32, (
        "TEST_DHCPV4_CONCURRENT_CLIENTS must stay in the bounded range 2..32"
    )
    clients = [
        {"mac": _new_mac(), "xid": _new_xid()}
        for _ in range(CONCURRENT_CLIENTS)
    ]
    discovers = [
        build_client_packet(client["mac"], client["xid"], _client_options("discover"))
        for client in clients
    ]
    sniffer = start_dhcp_sniffer(INTERFACE, timeout=5)
    for packet in discovers:
        sendp(packet, iface=INTERFACE, verbose=False)
    sniffer.join()
    captured = list(sniffer.results or [])
    for client in clients:
        offers = [
            packet for packet in captured
            if _matches(packet, client["xid"], {2}, client["mac"])
        ]
        assert offers, f"No offer for concurrent client 0x{client['xid']:08x}"
        client["discovery"] = {
            "mac": client["mac"], "xid": client["xid"], "offers": offers
        }

    requests = []
    for client in clients:
        discovery = client["discovery"]
        offered_ip = discovery["offers"][0][BOOTP].yiaddr
        server_id = dhcp_option(discovery["offers"][0], "server_id")
        options = [("message-type", "request")]
        if server_id is not None:
            options.append(("server_id", server_id))
        options.extend([
            ("requested_addr", offered_ip),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ])
        requests.append(build_client_packet(client["mac"], client["xid"], options))
        client["offered_ip"] = offered_ip

    ack_sniffer = start_dhcp_sniffer(INTERFACE, timeout=5)
    for packet in requests:
        sendp(packet, iface=INTERFACE, verbose=False)
    ack_sniffer.join()
    captured_acks = list(ack_sniffer.results or [])
    leases = []
    for client in clients:
        acks = [
            packet for packet in captured_acks
            if _matches(packet, client["xid"], {5}, client["mac"])
        ]
        assert acks, f"No ACK for concurrent client 0x{client['xid']:08x}"
        assert {packet[BOOTP].yiaddr for packet in acks} == {client["offered_ip"]}
        lease = {
            "mac": client["mac"],
            "xid": client["xid"],
            "ip": client["offered_ip"],
            "offer": client["discovery"]["offers"][0],
            "acks": acks,
            "client_id": None,
        }
        leases.append(lease)
        _state(context)["active"].append(lease)
    _state(context)["concurrent_leases"] = leases
    _state(context)["concurrent_elapsed"] = time.monotonic() - started


@then("every concurrent client has one unique active binding")
def step_concurrent_unique(context):
    leases = _state(context)["concurrent_leases"]
    addresses = [lease["ip"] for lease in leases]
    assert len(addresses) == CONCURRENT_CLIENTS
    assert len(set(addresses)) == len(addresses), (
        f"Concurrent clients received duplicate addresses: {addresses}"
    )


@then("the concurrent DHCPv4 batch completes within the configured deadline")
def step_concurrent_deadline(context):
    elapsed = _state(context)["concurrent_elapsed"]
    assert 1 <= BATCH_DEADLINE <= 120
    assert elapsed <= BATCH_DEADLINE, (
        f"Concurrent DHCPv4 batch took {elapsed:.3f}s; deadline is {BATCH_DEADLINE:.3f}s"
    )


@when("the configured reserved DHCPv4 client acquires a lease")
def step_reserved_client(context):
    _ensure_cleanup(context)
    _state(context)["reserved_lease"] = _dora(context, RESERVED_MAC)


@then("the reserved client receives its configured address")
def step_reserved_address(context):
    network = ipaddress.ip_network(SUBNET, strict=False)
    expected = str(ipaddress.ip_address(int(network.network_address) + RESERVED_OFFSET))
    actual = _state(context)["reserved_lease"]["ip"]
    assert actual == expected, f"Reserved client received {actual}, expected {expected}"


@when("a DHCPv4 client in the configured vendor class acquires a lease")
def step_class_client(context):
    _ensure_cleanup(context)
    extra = [("vendor_class_id", CLASS_NAME)]
    _state(context)["class_lease"] = _dora(context, extra=extra)


@then("the class-specific domain option is present in OFFER and ACK")
def step_class_option(context):
    lease = _state(context)["class_lease"]
    expected = CLASS_DOMAIN.rstrip(".").encode()
    for label, packet in (("DHCPOFFER", lease["offer"]), ("DHCPACK", lease["acks"][0])):
        value = raw_dhcp_option(packet, 15, ("domain", "domain_name"))
        assert value is not None, f"{label} omitted class-specific domain option"
        actual = option_bytes(value).rstrip(b"\x00.")
        assert actual == expected, f"{label} domain {actual!r} != {expected!r}"


def _malformed_payload(mac, xid, case, offered_ip, server_id):
    bootp = bytes(BOOTP(chaddr=mac_bytes(mac), flags=0x8000, xid=xid))
    cookie = b"\x63\x82\x53\x63"
    if cookie in bootp:
        bootp = bootp[: bootp.index(cookie)]
    request_tail = (
        b"\x36\x04" + ipaddress.ip_address(server_id).packed
        + b"\x32\x04" + ipaddress.ip_address(offered_ip).packed
        + b"\xff"
    )
    if case % 6 == 0:
        options = cookie + b"\x35\x00" + request_tail
    elif case % 6 == 1:
        options = cookie + b"\x35\xff\x03" + request_tail
    elif case % 6 == 2:
        options = b"\x00\x00\x00\x00\x35\x01\x03" + request_tail
    elif case % 6 == 3:
        options = cookie + request_tail
    elif case % 6 == 4:
        options = cookie + b"\x35\x01\x00" + request_tail
    else:
        declared = 8 + (case % 200)
        options = cookie + bytes([53, declared, 3]) + request_tail[:3]
    return bootp + options


@when("a deterministic corpus of malformed DHCPv4 messages is sent")
def step_malformed_corpus(context):
    require_scapy_v4()
    assert 5 <= FUZZ_CASES <= 128, "TEST_DHCPV4_FUZZ_CASES must be in 5..128"
    cases = []
    for index in range(FUZZ_CASES):
        mac = _new_mac()
        discovery = _discover(mac)
        assert discovery["offers"], f"No setup offer for malformed case {index}"
        offer = discovery["offers"][0]
        xid = discovery["xid"]
        offered_ip = offer[BOOTP].yiaddr
        server_id = dhcp_option(offer, "server_id") or SERVER_IP
        malformed = _malformed_payload(mac, xid, index, offered_ip, server_id)
        if index % 6 == 3:
            malformed = bytearray(malformed)
            malformed[0] = 2
            malformed = bytes(malformed)
        packet = (
            Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / Raw(load=malformed)
        )
        cases.append({"xid": xid, "packet": packet})
    sniffer = start_dhcp_sniffer(INTERFACE, timeout=3)
    for case in cases:
        sendp(case["packet"], iface=INTERFACE, verbose=False)
    sniffer.join()
    xids = {case["xid"] for case in cases}
    responses = [
        packet for packet in (sniffer.results or [])
        if packet.haslayer(BOOTP)
        and packet.haslayer(DHCP)
        and packet[BOOTP].xid in xids
        and _message_type(packet) == 5
    ]
    _state(context)["malformed_responses"] = responses


@then("no malformed DHCPv4 transaction receives a DHCPACK")
def step_malformed_no_lease(context):
    responses = _state(context)["malformed_responses"]
    assert not responses, (
        "Malformed REQUEST transactions received DHCPACK: "
        f"{[(packet[BOOTP].xid, _message_type(packet)) for packet in responses]}"
    )


@then("a valid DHCPv4 client still completes DORA")
def step_valid_after_malformed(context):
    _ensure_cleanup(context)
    _state(context)["post_malformed_lease"] = _dora(context)


@when("bounded DHCPv4 clients repeatedly acquire and release leases")
def step_bounded_churn(context):
    require_scapy_v4()
    assert 2 <= CHURN_CYCLES <= 64, "TEST_DHCPV4_CHURN_CYCLES must be in 2..64"
    completed = []
    active = set()
    for _ in range(CHURN_CYCLES):
        lease = _request(_discover(_new_mac()))
        assert lease["ip"] not in active, f"Duplicate active churn address {lease['ip']}"
        active.add(lease["ip"])
        completed.append(lease["ip"])
        _release(lease)
        active.remove(lease["ip"])
    _state(context)["churn_completed"] = completed
    _state(context)["churn_duplicate_free"] = not active


@then("every churn transaction completed without duplicate active addresses")
def step_churn_safe(context):
    completed = _state(context)["churn_completed"]
    assert len(completed) == CHURN_CYCLES
    assert _state(context)["churn_duplicate_free"]


def _relay_ip():
    network = ipaddress.ip_network(RELAY_SUBNET, strict=False)
    return str(ipaddress.ip_address(int(network.network_address) + 1))


def _remove_relay_ip(address):
    prefix = ipaddress.ip_network(RELAY_SUBNET, strict=False).prefixlen
    subprocess.run(
        ["ip", "addr", "del", f"{address}/{prefix}", "dev", INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@given("a DHCPv4 relay address exists on the alternate served subnet")
def step_relay_address(context):
    address = _relay_ip()
    prefix = ipaddress.ip_network(RELAY_SUBNET, strict=False).prefixlen
    subprocess.run(
        ["ip", "addr", "add", f"{address}/{prefix}", "dev", INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    context.add_cleanup(_remove_relay_ip, address)
    _state(context)["relay_ip"] = address


def _relayed_packet(
    mac, xid, message_type, *, requested=None, server_id=None, force_overload=False
):
    options = [("message-type", message_type)]
    if server_id is not None:
        options.append(("server_id", server_id))
    if requested is not None:
        options.append(("requested_addr", requested))
    parameter_request_list = list(PARAMETER_REQUEST_LIST)
    if force_overload:
        parameter_request_list.append(RFC3396_LONG_OPTION_CODE)
        options.append(("max_dhcp_size", 576))
    options.extend([
        ("param_req_list", parameter_request_list),
        (82, RELAY_OPTION),
        "end",
    ])
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=_relay_ip(), dst=SERVER_IP)
        / UDP(sport=67, dport=67)
        / BOOTP(
            op=1,
            hops=1,
            xid=xid,
            giaddr=_relay_ip(),
            chaddr=mac_bytes(mac),
            flags=0x8000,
        )
        / DHCP(options=options)
    )


@when("the relay forwards a DHCPDISCOVER with circuit and remote identifiers")
def step_relay_discover(context):
    mac = _new_mac()
    xid = _new_xid()
    discover = _relayed_packet(mac, xid, "discover")
    responses = _capture_packets([discover], xid, {2, 5, 6}, mac=mac)
    offers = [packet for packet in responses if _message_type(packet) == 2]
    assert offers, "Relayed DHCPDISCOVER received no DHCPOFFER"
    state = _state(context)
    state["relay_mac"] = mac
    state["relay_xid"] = xid
    state["relay_offer"] = offers[0]


@then("the server returns an offer to the relay from the selected subnet")
def step_relay_offer_subnet(context):
    offer = _state(context)["relay_offer"]
    assert ipaddress.ip_address(offer[BOOTP].yiaddr) in ipaddress.ip_network(
        RELAY_SUBNET, strict=False
    ), f"Relayed offer {offer[BOOTP].yiaddr} is outside {RELAY_SUBNET}"
    assert offer.haslayer(IP) and offer[IP].dst == _relay_ip(), (
        f"DHCPOFFER destination {offer[IP].dst if offer.haslayer(IP) else None} "
        f"is not relay {_relay_ip()}"
    )
    assert offer.haslayer(UDP) and offer[UDP].dport == 67


def _assert_relay_metadata(packet, label):
    assert packet[BOOTP].giaddr == _relay_ip(), (
        f"{label} giaddr {packet[BOOTP].giaddr} != {_relay_ip()}"
    )
    value = raw_dhcp_option(
        packet,
        82,
        ("relay_agent_information", "relay_agent_Information", "relay_agent_information_option"),
    )
    assert value is not None, f"{label} omitted Relay Agent Information"
    assert option_bytes(value) == RELAY_OPTION, (
        f"{label} changed Relay Agent Information: {option_bytes(value)!r}"
    )


@then("the offer preserves giaddr and echoes Relay Agent Information verbatim")
def step_relay_offer_metadata(context):
    _assert_relay_metadata(_state(context)["relay_offer"], "DHCPOFFER")


@when("the relay forwards the matching DHCPREQUEST")
def step_relay_request(context):
    state = _state(context)
    offer = state["relay_offer"]
    request = _relayed_packet(
        state["relay_mac"],
        state["relay_xid"],
        "request",
        requested=offer[BOOTP].yiaddr,
        server_id=dhcp_option(offer, "server_id"),
    )
    responses = _capture_packets(
        [request], state["relay_xid"], {5, 6}, mac=state["relay_mac"]
    )
    assert not [packet for packet in responses if _message_type(packet) == 6]
    acks = [packet for packet in responses if _message_type(packet) == 5]
    assert acks, "Relayed DHCPREQUEST received no DHCPACK"
    state["relay_ack"] = acks[0]
    state["active"].append({
        "mac": state["relay_mac"],
        "xid": state["relay_xid"],
        "ip": offer[BOOTP].yiaddr,
        "offer": offer,
        "acks": acks,
        "client_id": None,
    })
    _ensure_cleanup(context)


@then("the server returns an acknowledgement to the relay for the offered address")
def step_relay_ack_address(context):
    state = _state(context)
    assert state["relay_ack"][BOOTP].yiaddr == state["relay_offer"][BOOTP].yiaddr
    assert state["relay_ack"][IP].dst == _relay_ip()
    assert state["relay_ack"][UDP].dport == 67


@then("the acknowledgement preserves giaddr and echoes Relay Agent Information verbatim")
def step_relay_ack_metadata(context):
    _assert_relay_metadata(_state(context)["relay_ack"], "DHCPACK")


@when("an ordinary DHCPv4 client completes DORA without Relay Agent Information")
def step_ordinary_without_relay_info(context):
    _ensure_cleanup(context)
    _state(context)["ordinary_lease"] = _dora(context)


@then("neither server response contains Relay Agent Information")
def step_no_invented_relay_info(context):
    lease = _state(context)["ordinary_lease"]
    for label, packet in (("DHCPOFFER", lease["offer"]), ("DHCPACK", lease["acks"][0])):
        value = raw_dhcp_option(
            packet, 82, ("relay_agent_information", "relay_agent_Information")
        )
        assert value is None, f"{label} invented Relay Agent Information"


@when("the relay completes DORA with an oversized requested option")
def step_relay_overload_dora(context):
    mac = _new_mac()
    xid = _new_xid()
    discover = _relayed_packet(mac, xid, "discover", force_overload=True)
    responses = _capture_packets([discover], xid, {2, 5, 6}, mac=mac)
    offers = [packet for packet in responses if _message_type(packet) == 2]
    assert offers, "Overload relay DHCPDISCOVER received no DHCPOFFER"
    offer = offers[0]

    request = _relayed_packet(
        mac,
        xid,
        "request",
        requested=offer[BOOTP].yiaddr,
        server_id=dhcp_option(offer, "server_id"),
        force_overload=True,
    )
    responses = _capture_packets([request], xid, {5, 6}, mac=mac)
    assert not [packet for packet in responses if _message_type(packet) == 6]
    acks = [packet for packet in responses if _message_type(packet) == 5]
    assert acks, "Overload relay DHCPREQUEST received no DHCPACK"
    state = _state(context)
    state["relay_overload_responses"] = [offer, acks[0]]
    state["active"].append({
        "mac": mac,
        "xid": xid,
        "ip": offer[BOOTP].yiaddr,
        "offer": offer,
        "acks": acks,
        "client_id": None,
    })
    _ensure_cleanup(context)


@then("both relayed responses preserve the oversized option fragments")
def step_relay_long_option_is_preserved(context):
    responses = _state(context).get("relay_overload_responses", [])
    assert len(responses) == 2, "Missing overloaded relay OFFER/ACK responses"
    for label, packet in zip(("DHCPOFFER", "DHCPACK"), responses):
        fragments = raw_dhcp_option_fragments(packet, RFC3396_LONG_OPTION_CODE)
        actual = b"".join(value for _, value in fragments)
        assert actual == RFC3396_LONG_OPTION, (
            f"{label} did not reconstruct the configured oversized option: "
            f"{[(area, len(value)) for area, value in fragments]}"
        )


@then("both relayed responses keep Relay Agent Information in the main option area")
def step_relay_info_not_overloaded(context):
    for label, packet in zip(
        ("DHCPOFFER", "DHCPACK"),
        _state(context).get("relay_overload_responses", []),
    ):
        fragments = raw_dhcp_option_fragments(packet, 82)
        assert fragments, f"{label} omitted Relay Agent Information"
        assert b"".join(value for _, value in fragments) == RELAY_OPTION
        assert all(area == "options" for area, _ in fragments), (
            f"{label} placed Relay Agent Information in overloaded areas: "
            f"{[area for area, _ in fragments]}"
        )


def _write_persistent_state(lease):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps({
            "ip": lease["ip"],
            "mac": lease["mac"],
            "xid": lease["xid"],
            "client_id": PERSISTENT_CLIENT_ID.hex(),
            "server_id": dhcp_option(lease["offer"], "server_id") or SERVER_IP,
        }, indent=2),
        encoding="utf-8",
    )


def _read_persistent_state():
    assert STATE_FILE.exists(), f"Persistent state file does not exist: {STATE_FILE}"
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    state["client_id"] = bytes.fromhex(state["client_id"])
    return state


@when("the persistent DHCPv4 client acquires and records a lease")
def step_persistent_prepare(context):
    lease = _request(_discover(PERSISTENT_MAC, client_id=PERSISTENT_CLIENT_ID),
                     client_id=PERSISTENT_CLIENT_ID)
    _write_persistent_state(lease)
    _state(context)["persistent_prepared"] = lease


@then("the persistent lease state file identifies an active binding")
def step_persistent_file(context):
    state = _read_persistent_state()
    lease = _state(context)["persistent_prepared"]
    assert state["ip"] == lease["ip"]
    assert state["mac"] == PERSISTENT_MAC


@given("a recorded persistent DHCPv4 binding")
def step_recorded_binding(context):
    _state(context)["recorded"] = _read_persistent_state()


@when("a different client requests the recorded address")
def step_competing_client(context):
    recorded = _state(context)["recorded"]
    discovery = _discover(_new_mac(), requested=recorded["ip"])
    _state(context)["competing_offers"] = discovery["offers"]


@then("the different client is not offered the active recorded address")
def step_competing_not_recorded(context):
    recorded = _state(context)["recorded"]
    offered = {packet[BOOTP].yiaddr for packet in _state(context)["competing_offers"]}
    assert recorded["ip"] not in offered, (
        f"Server reallocated active persistent binding {recorded['ip']} after restart"
    )


@when("the persistent client enters INIT-REBOOT for the recorded address")
def step_persistent_init_reboot(context):
    recorded = _state(context)["recorded"]
    xid = _new_xid()
    packet = build_client_packet(
        recorded["mac"],
        xid,
        _client_options(
            "request", client_id=recorded["client_id"], requested=recorded["ip"]
        ),
    )
    responses = _capture_packets([packet], xid, {5, 6}, mac=recorded["mac"])
    _state(context)["persistent_reboot_responses"] = responses


@then("the server acknowledges the recorded persistent binding")
def step_persistent_ack(context):
    recorded = _state(context)["recorded"]
    responses = _state(context)["persistent_reboot_responses"]
    assert not [packet for packet in responses if _message_type(packet) == 6]
    acks = [packet for packet in responses if _message_type(packet) == 5]
    assert acks, "Server did not ACK the persistent binding after restart"
    assert {packet[BOOTP].yiaddr for packet in acks} == {recorded["ip"]}


@when("the persistent client releases the recorded binding")
def step_persistent_release(context):
    recorded = _state(context)["recorded"]
    lease = {
        "mac": recorded["mac"],
        "xid": recorded["xid"],
        "ip": recorded["ip"],
        "offer": None,
        "client_id": recorded["client_id"],
    }
    _release(lease)
    STATE_FILE.unlink(missing_ok=True)


@then("the persistent lease state file is removed")
def step_persistent_removed(context):
    assert not STATE_FILE.exists()


# ---------------------------------------------------------------------------
# Explicitly enabled service capabilities
# ---------------------------------------------------------------------------


@given("a classed DHCPv4 binding exists before configuration reload")
def step_reload_existing_binding(context):
    _ensure_cleanup(context)
    lease = _dora(context, extra=[("vendor_class_id", CLASS_NAME)])
    _state(context)["reload_existing_lease"] = lease


@when("the service reload adapter applies updated class policy")
def step_run_reload_adapter(context):
    _run_adapter("TEST_RELOAD_COMMAND")


@then("the pre-reload binding can still be renewed")
def step_reload_preserves_binding(context):
    _state(context)["reload_ack"] = _rebind(_state(context)["reload_existing_lease"])


@then("a new classed client receives the reloaded policy")
def step_reload_new_policy(context):
    lease = _dora(context, extra=[("vendor_class_id", CLASS_NAME)])
    for label, packet in (("DHCPOFFER", lease["offer"]), ("DHCPACK", lease["acks"][0])):
        value = raw_dhcp_option(packet, 15, ("domain", "domain_name"))
        assert value is not None, f"{label} omitted reloaded class policy"
        actual = option_bytes(value).rstrip(b"\x00.").decode("ascii")
        assert actual == RELOADED_CLASS_DOMAIN.rstrip("."), (
            f"{label} still uses class domain {actual!r}; "
            f"expected {RELOADED_CLASS_DOMAIN!r}"
        )


@given("an active DHCPv4 binding exists before HA failover")
def step_ha_existing_binding(context):
    _ensure_cleanup(context)
    _state(context)["ha_lease"] = _dora(
        context, client_id=b"\xffacceptance-ha-client"
    )


def _recover_ha():
    command = os.getenv("TEST_HA_RECOVER_COMMAND", "").strip()
    if command:
        subprocess.run(shlex.split(command), check=False, timeout=30)


@when("the HA adapter isolates the active primary")
def step_ha_failover(context):
    _run_adapter("TEST_HA_FAILOVER_COMMAND")
    context.add_cleanup(_recover_ha)


@then("the binding can be rebound through the remaining HA peer")
def step_ha_rebind(context):
    _state(context)["ha_rebind_ack"] = _rebind(_state(context)["ha_lease"])


@then("the remaining HA peer never allocates that active address to another client")
def step_ha_no_duplicate(context):
    active = _state(context)["ha_lease"]
    other = _dora(context, requested=active["ip"])
    assert other["ip"] != active["ip"], (
        f"HA peer reallocated active binding {active['ip']}"
    )


@given("the DHCP service has a reachable authoritative DNS update target")
def step_ddns_target(context):
    server = os.getenv("TEST_DNS_SERVER", "").strip()
    assert server, "TEST_DNS_SERVER is required when DDNS capability is enabled"
    assert dns is not None, "dnspython is required for DDNS capability tests"
    _state(context)["dns_server"] = server


def _fqdn_wire(name):
    labels = name.rstrip(".").split(".")
    wire = b"".join(bytes([len(label.encode())]) + label.encode() for label in labels)
    return wire + b"\x00"


def _ddns_option(name):
    # RFC 4702: E+S flags, zero RCODE fields, canonical DNS wire name.
    return b"\x05\x00\x00" + _fqdn_wire(name)


def _unique_ddns_fqdn():
    labels = DDNS_FQDN.rstrip(".").split(".")
    suffix = ".".join(labels[1:]) if len(labels) > 1 else labels[0]
    return f"timing-{os.urandom(4).hex()}.{suffix}."


def _dns_addresses(context, fqdn):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = [_state(context)["dns_server"]]
    resolver.lifetime = 2
    try:
        return {answer.address for answer in resolver.resolve(fqdn, "A")}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return set()


@when("a DHCPv4 client commits a lease with its configured FQDN")
def step_ddns_lease(context):
    _ensure_cleanup(context)
    fqdn_option = _ddns_option(DDNS_FQDN)
    _state(context)["ddns_fqdn"] = DDNS_FQDN
    _state(context)["ddns_lease"] = _dora(context, extra=[(81, fqdn_option)])


@when("a DHCPv4 client requests an FQDN lease but stops after DHCPOFFER")
def step_ddns_stops_after_offer(context):
    _ensure_cleanup(context)
    fqdn = _unique_ddns_fqdn()
    extra = [(81, _ddns_option(fqdn))]
    discovery = _discover(_new_mac(), extra=extra)
    assert discovery["offers"], f"No DHCPOFFER for DDNS timing name {fqdn}"
    _state(context)["ddns_fqdn"] = fqdn
    _state(context)["ddns_extra"] = extra
    _state(context)["ddns_discovery"] = discovery


@then("the authoritative DNS service has no record before lease commitment")
def step_ddns_absent_before_commit(context):
    fqdn = _state(context)["ddns_fqdn"]
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        addresses = _dns_addresses(context, fqdn)
        assert not addresses, (
            f"DDNS name {fqdn} was published before DHCPREQUEST/DHCPACK: "
            f"{sorted(addresses)}"
        )
        time.sleep(0.5)


@when("the client commits the offered FQDN lease")
def step_ddns_commit_offered_lease(context):
    state = _state(context)
    lease = _request(state["ddns_discovery"], extra=state["ddns_extra"])
    state["active"].append(lease)
    state["ddns_lease"] = lease


@then("the authoritative DNS service resolves the FQDN to the committed address")
def step_ddns_resolves(context):
    fqdn = _state(context).get("ddns_fqdn", DDNS_FQDN)
    expected = _state(context)["ddns_lease"]["ip"]
    deadline = time.monotonic() + 15
    last_error = None
    while time.monotonic() < deadline:
        try:
            answers = _dns_addresses(context, fqdn)
            if expected in answers:
                return
            last_error = f"answers={sorted(answers)}"
        except Exception as exc:
            last_error = str(exc)
        time.sleep(0.5)
    raise AssertionError(
        f"DDNS name {fqdn} did not resolve to {expected}: {last_error}"
    )


@given("the test client has a configured second DHCPv4 interface")
def step_second_interface(context):
    interface = os.getenv("TEST_SECOND_INTERFACE", "").strip()
    subnet = os.getenv("TEST_SECOND_SUBNET", "").strip()
    server = os.getenv("TEST_SECOND_SERVER_IP", "").strip()
    assert interface and subnet and server, (
        "TEST_SECOND_INTERFACE, TEST_SECOND_SUBNET, and TEST_SECOND_SERVER_IP "
        "are required when multi_interface capability is enabled"
    )
    subprocess.run(["ip", "link", "show", "dev", interface], check=True)
    _state(context)["second_interface"] = {
        "name": interface,
        "subnet": subnet,
        "server": server,
    }


def _packets_on_interface(interface, outbound, xid, message_types, mac):
    sniffer = AsyncSniffer(
        iface=interface,
        lfilter=lambda packet: packet.haslayer(DHCP),
        stop_filter=lambda packet: _matches(packet, xid, message_types, mac),
        timeout=5,
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)
    sendp(outbound, iface=interface, verbose=False)
    sniffer.join()
    return [
        packet for packet in (sniffer.results or [])
        if _matches(packet, xid, message_types, mac)
    ]


@when("a DHCPv4 client acquires a lease through the second interface")
def step_second_interface_dora(context):
    config = _state(context)["second_interface"]
    mac = _new_mac()
    xid = _new_xid()
    discover = build_client_packet(mac, xid, _client_options("discover"))
    offers = _packets_on_interface(config["name"], discover, xid, {2}, mac)
    assert offers, "Second interface received no DHCPOFFER"
    offered = offers[0][BOOTP].yiaddr
    options = [
        ("message-type", "request"),
        ("server_id", dhcp_option(offers[0], "server_id") or config["server"]),
        ("requested_addr", offered),
        ("param_req_list", PARAMETER_REQUEST_LIST),
        "end",
    ]
    request = build_client_packet(mac, xid, options)
    acks = _packets_on_interface(config["name"], request, xid, {5, 6}, mac)
    assert not [packet for packet in acks if _message_type(packet) == 6]
    acks = [packet for packet in acks if _message_type(packet) == 5]
    assert acks, "Second interface received no DHCPACK"
    _state(context)["second_interface_lease"] = acks[0][BOOTP].yiaddr


@then("the second-interface lease belongs to its configured subnet")
def step_second_interface_subnet(context):
    state = _state(context)
    assert ipaddress.ip_address(state["second_interface_lease"]) in ipaddress.ip_network(
        state["second_interface"]["subnet"], strict=False
    )


@given("an active DHCPv4 binding exists before a runtime storage failure")
def step_storage_fault_existing_binding(context):
    _ensure_cleanup(context)
    _state(context)["storage_fault_lease"] = _dora(
        context, client_id=b"\xffacceptance-storage-fault"
    )


def _recover_storage_fault():
    command = os.getenv("TEST_STORAGE_RECOVER_COMMAND", "").strip()
    if command:
        subprocess.run(shlex.split(command), check=False, timeout=30)


@when("the storage-fault adapter makes lease persistence unavailable")
def step_storage_fault_enable(context):
    _run_adapter("TEST_STORAGE_FAIL_COMMAND")
    context.add_cleanup(_recover_storage_fault)


@then("a new DHCPv4 client cannot commit an unrecorded lease")
def step_storage_fault_no_commit(context):
    mac = _new_mac()
    discovery = _discover(mac)
    if not discovery["offers"]:
        return
    offered_ip = discovery["offers"][0][BOOTP].yiaddr
    server_id = dhcp_option(discovery["offers"][0], "server_id") or SERVER_IP
    request = build_client_packet(
        mac,
        discovery["xid"],
        [
            ("message-type", "request"),
            ("server_id", server_id),
            ("requested_addr", offered_ip),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ],
    )
    responses = _capture_packets(
        [request], discovery["xid"], {5, 6}, mac=mac, timeout=4
    )
    assert not [packet for packet in responses if _message_type(packet) == 5], (
        f"Server DHCPACKed {offered_ip} while lease persistence was unavailable"
    )


@when("the storage-fault adapter restores lease persistence")
def step_storage_fault_recover(context):
    _run_adapter("TEST_STORAGE_RECOVER_COMMAND")


@then("the pre-fault binding can still be renewed")
def step_storage_fault_binding_recovers(context):
    _rebind(_state(context)["storage_fault_lease"])
