"""Reusable batched DHCPv4 acquire/release primitives for load-oriented tests."""

import math
import os
import time

from dhcpv4_support import (
    BOOTP,
    DHCP,
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


INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SERVER_IP = os.getenv("TEST_SERVER_IP", "172.29.0.2")
CAPTURE_TIMEOUT = float(os.getenv("TEST_DHCPV4_SOAK_CAPTURE_TIMEOUT", "10"))
PARAMETER_REQUEST_LIST = [1, 3, 6, 15, 51, 58, 59]


def _new_mac():
    value = bytearray(os.urandom(6))
    value[0] = (value[0] | 0x02) & 0xFE
    return ":".join(f"{octet:02x}" for octet in value)


def _unique_xid(used):
    while True:
        xid = int.from_bytes(os.urandom(4), "big") or 1
        if xid not in used:
            used.add(xid)
            return xid


def _message_type(packet):
    return dhcp_options(packet).get("message-type")


def _matches(packet, clients, message_types):
    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return False
    client = clients.get(packet[BOOTP].xid)
    if client is None or _message_type(packet) not in message_types:
        return False
    expected_mac = mac_bytes(client["mac"])
    return bytes(packet[BOOTP].chaddr)[: len(expected_mac)] == expected_mac


def _capture_exchange(entries, message_types):
    require_scapy_v4()
    assert sendp is not None, "Scapy send support is required for soak tests"
    clients = {entry["xid"]: entry for entry in entries}
    seen = set()

    def stop_filter(packet):
        if _matches(packet, clients, message_types):
            seen.add(packet[BOOTP].xid)
        return len(seen) == len(clients)

    sniffer = start_dhcp_sniffer(
        INTERFACE,
        timeout=CAPTURE_TIMEOUT,
        stop_filter=stop_filter,
    )
    for entry in entries:
        entry["sent_at"] = time.time()
        sendp(entry["packet"], iface=INTERFACE, verbose=False)
    sniffer.join()
    responses = [
        packet
        for packet in (sniffer.results or [])
        if _matches(packet, clients, message_types)
    ]
    by_xid = {}
    for packet in responses:
        by_xid.setdefault(packet[BOOTP].xid, []).append(packet)
    latencies = []
    for xid, packets in by_xid.items():
        first = min(float(packet.time) for packet in packets)
        latencies.append(max(0.0, (first - clients[xid]["sent_at"]) * 1000.0))
    return by_xid, latencies


def _discover_batch(count):
    used_xids = set()
    clients = [
        {"mac": _new_mac(), "xid": _unique_xid(used_xids)}
        for _ in range(count)
    ]
    for client in clients:
        client["packet"] = build_client_packet(
            client["mac"],
            client["xid"],
            [
                ("message-type", "discover"),
                ("param_req_list", PARAMETER_REQUEST_LIST),
                "end",
            ],
        )
    responses, latencies = _capture_exchange(clients, {2, 5, 6})
    for client in clients:
        packets = responses.get(client["xid"], [])
        assert not [packet for packet in packets if _message_type(packet) in {5, 6}]
        offers = [packet for packet in packets if _message_type(packet) == 2]
        assert offers, f"No offer for soak client 0x{client['xid']:08x}"
        addresses = {packet[BOOTP].yiaddr for packet in offers}
        assert len(addresses) == 1, (
            f"Soak client 0x{client['xid']:08x} received conflicting offers: "
            f"{addresses}"
        )
        client["ip"] = addresses.pop()
        client["server_id"] = dhcp_option(offers[0], "server_id") or SERVER_IP
    return clients, latencies


def _selection_request(client):
    return build_client_packet(
        client["mac"],
        client["xid"],
        [
            ("message-type", "request"),
            ("server_id", client["server_id"]),
            ("requested_addr", client["ip"]),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ],
    )


def commit_batch(count):
    started = time.monotonic()
    clients, offer_latencies = _discover_batch(count)
    entries = [
        {**client, "packet": _selection_request(client)} for client in clients
    ]
    responses, ack_latencies = _capture_exchange(entries, {5, 6})
    leases = []
    for client in clients:
        packets = responses.get(client["xid"], [])
        assert not [packet for packet in packets if _message_type(packet) == 6], (
            f"Server rejected soak offer {client['ip']}"
        )
        acknowledgements = [
            packet for packet in packets if _message_type(packet) == 5
        ]
        assert acknowledgements, f"No ACK for soak offer {client['ip']}"
        addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
        assert addresses == {client["ip"]}, (
            f"Soak ACK changed {client['ip']} to {addresses}"
        )
        leases.append(
            {
                "mac": client["mac"],
                "xid": client["xid"],
                "ip": client["ip"],
                "server_id": client["server_id"],
            }
        )
    return leases, {
        "offer_ms": offer_latencies,
        "commit_ms": ack_latencies,
        "elapsed_seconds": time.monotonic() - started,
    }


def _release_packet(lease):
    return build_client_packet(
        lease["mac"],
        lease["xid"],
        [
            ("message-type", "release"),
            ("server_id", lease.get("server_id") or SERVER_IP),
            "end",
        ],
        ciaddr=lease["ip"],
        source_ip=lease["ip"],
        destination_ip=lease.get("server_id") or SERVER_IP,
        flags=0,
    )


def release_batch(leases):
    assert sendp is not None, "Scapy send support is required for soak tests"
    for lease in leases:
        sendp(_release_packet(lease), iface=INTERFACE, verbose=False)


def assert_unique(leases, label):
    addresses = [lease["ip"] for lease in leases]
    assert len(addresses) == len(set(addresses)), (
        f"{label} contains duplicate active addresses: {addresses}"
    )


def percentile(values, requested_percentile):
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    index = max(
        0,
        math.ceil((requested_percentile / 100.0) * len(ordered)) - 1,
    )
    return ordered[index]
