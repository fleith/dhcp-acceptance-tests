"""Bounded DHCPv4 address-pool exhaustion and recovery steps."""

import ipaddress
import os
import time

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
    require_scapy_v4,
    start_dhcp_sniffer,
)

try:
    from scapy.all import sendp
except ImportError:
    sendp = None


DHCP_SERVER_IP = os.getenv("TEST_SERVER_IP", "192.168.56.1")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SUBNET = os.getenv("TEST_SUBNET", "192.168.56.0/24")
POOL_START_OFFSET = int(os.getenv("DHCPV4_POOL_START_OFFSET", "100"))
POOL_END_OFFSET = int(os.getenv("DHCPV4_POOL_END_OFFSET", "200"))
MAX_EXHAUSTION_CAPACITY = int(os.getenv("TEST_DHCPV4_EXHAUSTION_LIMIT", "16"))
PARAMETER_REQUEST_LIST = [1, 3, 6, 51, 58, 59]


def _state(context):
    if not hasattr(context, "dhcpv4_pool_exhaustion"):
        context.dhcpv4_pool_exhaustion = {
            "active_leases": {},
            "macs": set(),
            "xids": set(),
        }
    return context.dhcpv4_pool_exhaustion


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


def _pool_addresses():
    network = ipaddress.ip_network(SUBNET, strict=False)
    assert network.version == 4, f"DHCPv4 pool requires an IPv4 subnet, got {SUBNET}"
    assert network.prefixlen == 24, (
        "Offset-based DHCPv4 exhaustion fixture requires a /24 test subnet; "
        f"got {SUBNET}"
    )
    assert 1 <= POOL_START_OFFSET <= POOL_END_OFFSET <= 254, (
        "DHCPV4_POOL_START_OFFSET and DHCPV4_POOL_END_OFFSET must describe "
        "usable /24 host addresses"
    )
    capacity = POOL_END_OFFSET - POOL_START_OFFSET + 1
    assert 2 <= capacity <= MAX_EXHAUSTION_CAPACITY, (
        f"Configured DHCPv4 exhaustion pool capacity {capacity} is outside the "
        f"safe range 2..{MAX_EXHAUSTION_CAPACITY}; run this scenario with a "
        "dedicated bounded pool"
    )
    return [
        str(ipaddress.ip_address(int(network.network_address) + offset))
        for offset in range(POOL_START_OFFSET, POOL_END_OFFSET + 1)
    ]


def _matching_server_packet(packet, message_types, xid, mac):
    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return False
    if packet[BOOTP].xid != xid:
        return False
    expected_mac = mac_bytes(mac)
    if bytes(packet[BOOTP].chaddr)[: len(expected_mac)] != expected_mac:
        return False
    if dhcp_option(packet, "server_id") != DHCP_SERVER_IP:
        return False
    return dhcp_options(packet).get("message-type") in message_types


def _send_and_capture(packet, xid, mac, message_types, timeout=3):
    require_scapy_v4()
    if sendp is None:
        raise RuntimeError("Scapy is required to run DHCPv4 pool exhaustion")
    sniffer = start_dhcp_sniffer(
        INTERFACE,
        timeout=timeout,
        stop_filter=lambda candidate: _matching_server_packet(
            candidate, message_types, xid, mac
        ),
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    sniffer.join()
    return [
        candidate
        for candidate in (sniffer.results or [])
        if _matching_server_packet(candidate, message_types, xid, mac)
    ]


def _discover(context, mac, requested_address=None, timeout=3):
    xid = _new_xid(context)
    options = [("message-type", "discover")]
    if requested_address is not None:
        options.append(("requested_addr", requested_address))
    options.extend([("param_req_list", PARAMETER_REQUEST_LIST), "end"])
    packet = build_client_packet(mac, xid, options)
    responses = _send_and_capture(packet, xid, mac, {2, 5, 6}, timeout=timeout)
    acknowledgements = [
        response
        for response in responses
        if dhcp_options(response).get("message-type") == 5
    ]
    assert not acknowledgements, (
        f"Server sent DHCPACK directly to ordinary DISCOVER transaction 0x{xid:08x}"
    )
    rejections = [
        response
        for response in responses
        if dhcp_options(response).get("message-type") == 6
    ]
    assert not rejections, (
        f"Server sent DHCPNAK to ordinary DISCOVER transaction 0x{xid:08x}"
    )
    offers = [
        response
        for response in responses
        if dhcp_options(response).get("message-type") == 2
    ]
    return {"mac": mac, "offers": offers, "xid": xid}


def _request(context, discovery):
    assert discovery["offers"], (
        f"No DHCPOFFER for transaction 0x{discovery['xid']:08x}"
    )
    offered_addresses = {offer[BOOTP].yiaddr for offer in discovery["offers"]}
    assert len(offered_addresses) == 1, (
        f"Conflicting DHCPOFFER addresses: {sorted(offered_addresses)}"
    )
    offered_ip = offered_addresses.pop()
    request = build_client_packet(
        discovery["mac"],
        discovery["xid"],
        [
            ("message-type", "request"),
            ("server_id", DHCP_SERVER_IP),
            ("requested_addr", offered_ip),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ],
    )
    responses = _send_and_capture(
        request,
        discovery["xid"],
        discovery["mac"],
        {5, 6},
    )
    acknowledgements = [
        response
        for response in responses
        if dhcp_options(response).get("message-type") == 5
    ]
    rejections = [
        response
        for response in responses
        if dhcp_options(response).get("message-type") == 6
    ]
    assert not rejections, f"Server rejected offered address {offered_ip}"
    assert acknowledgements, f"No DHCPACK for offered address {offered_ip}"
    acknowledged_addresses = {ack[BOOTP].yiaddr for ack in acknowledgements}
    assert acknowledged_addresses == {offered_ip}, (
        f"DHCPACK changed offered address {offered_ip}: {acknowledged_addresses}"
    )
    lease = {
        "ip": offered_ip,
        "mac": discovery["mac"],
        "xid": discovery["xid"],
    }
    _state(context)["active_leases"][offered_ip] = lease
    return lease


def _acquire(context, mac, requested_address=None):
    return _request(context, _discover(context, mac, requested_address))


def _release(context, lease):
    release = (
        Ether(src=lease["mac"], dst="ff:ff:ff:ff:ff:ff")
        / IP(src=lease["ip"], dst=DHCP_SERVER_IP)
        / UDP(sport=68, dport=67)
        / BOOTP(
            ciaddr=lease["ip"],
            chaddr=mac_bytes(lease["mac"]),
            xid=lease["xid"],
        )
        / DHCP(
            options=[
                ("message-type", "release"),
                ("server_id", DHCP_SERVER_IP),
                "end",
            ]
        )
    )
    sendp(release, iface=INTERFACE, verbose=False)
    _state(context)["active_leases"].pop(lease["ip"], None)


def _cleanup_leases(context):
    for lease in list(_state(context)["active_leases"].values()):
        try:
            _release(context, lease)
        except Exception as exc:
            print(f"\n[WARN] Could not release DHCPv4 exhaustion lease: {exc}")


@given("every configured DHCPv4 pool address is leased")
def step_given_every_pool_address_is_leased(context):
    require_scapy_v4()
    context.dhcpv4_pool_exhaustion = {
        "active_leases": {},
        "macs": set(),
        "xids": set(),
    }
    expected_addresses = set(_pool_addresses())
    context.add_cleanup(_cleanup_leases, context)
    leases = [
        _acquire(context, _new_mac(context))
        for _ in range(len(expected_addresses))
    ]
    leased_addresses = {lease["ip"] for lease in leases}
    assert leased_addresses == expected_addresses, (
        f"Pool fill leased {sorted(leased_addresses)} instead of configured "
        f"pool {sorted(expected_addresses)}"
    )
    state = _state(context)
    state["fill_leases"] = leases


@when("an additional DHCPv4 client requests a lease")
def step_when_additional_client_requests_lease(context):
    state = _state(context)
    waiting_mac = _new_mac(context)
    state["waiting_mac"] = waiting_mac
    state["exhausted_discovery"] = _discover(
        context,
        waiting_mac,
        timeout=2,
    )


@then("the exhausted DHCPv4 pool offers no address")
def step_then_exhausted_pool_offers_no_address(context):
    discovery = _state(context)["exhausted_discovery"]
    assert not discovery["offers"], (
        "Server offered an address after every configured DHCPv4 pool address "
        "had an active lease: "
        f"{[offer[BOOTP].yiaddr for offer in discovery['offers']]}"
    )


@when("one DHCPv4 pool lease is released")
def step_when_one_pool_lease_is_released(context):
    state = _state(context)
    released = state["fill_leases"].pop()
    _release(context, released)
    state["released_ip"] = released["ip"]
    time.sleep(0.5)


@then("the waiting DHCPv4 client acquires the released address")
def step_then_waiting_client_acquires_released_address(context):
    state = _state(context)
    lease = _acquire(
        context,
        state["waiting_mac"],
        requested_address=state["released_ip"],
    )
    assert lease["ip"] == state["released_ip"], (
        f"Waiting client acquired {lease['ip']} instead of released pool "
        f"address {state['released_ip']}"
    )
