"""Client-side companion coverage for RFC 5227 Address Conflict Detection."""

import os
import random
import time

from behave import then, when

from dhcpv4_support import (
    BOOTP,
    DHCP,
    build_client_packet,
    dhcp_option,
    dhcp_packets,
    mac_bytes,
    require_scapy_v4,
    start_dhcp_sniffer,
)

try:
    from scapy.all import ARP, AsyncSniffer, Ether, sendp
except ImportError:
    ARP = AsyncSniffer = Ether = sendp = None


DHCP_SERVER_IP = os.getenv("TEST_SERVER_IP", "192.168.56.1")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
PARAMETER_REQUEST_LIST = [1, 3, 6, 51, 58, 59]
DHCP_CAPTURE_TIMEOUT = 2.0
ARP_CAPTURE_SETTLE = 0.15
PROBE_WAIT = 1.0
PROBE_NUM = 3
PROBE_MIN = 1.0
PROBE_MAX = 2.0
ANNOUNCE_WAIT = 2.0
ANNOUNCE_NUM = 2
ANNOUNCE_INTERVAL = 2.0
TIMING_TOLERANCE = 0.25


def _state(context):
    if not hasattr(context, "rfc5227"):
        context.rfc5227 = {
            "decline_sent": False,
            "macs": set(),
            "xids": set(),
        }
    return context.rfc5227


def _require_packet_support():
    require_scapy_v4()
    if any(layer is None for layer in (ARP, AsyncSniffer, Ether, sendp)):
        raise RuntimeError(
            "Scapy ARP capture support is required for RFC 5227 companion tests"
        )


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


def _send(packet):
    _require_packet_support()
    sendp(packet, iface=INTERFACE, verbose=False)


def _client_options(message_type, **values):
    options = [("message-type", message_type)]
    if "server_id" in values:
        options.append(("server_id", values["server_id"]))
    if "requested_addr" in values:
        options.append(("requested_addr", values["requested_addr"]))
    if message_type in ("discover", "request"):
        options.append(("param_req_list", PARAMETER_REQUEST_LIST))
    options.append("end")
    return options


def _discover(context, mac):
    xid = _new_xid(context)
    discover = build_client_packet(
        mac,
        xid,
        _client_options("discover"),
    )
    sniffer = start_dhcp_sniffer(INTERFACE, timeout=DHCP_CAPTURE_TIMEOUT)
    _send(discover)
    offers = dhcp_packets(sniffer, 2, xid, DHCP_SERVER_IP)
    assert offers, (
        f"No DHCPOFFER from {DHCP_SERVER_IP} for transaction 0x{xid:08x}"
    )

    offered_addresses = {offer[BOOTP].yiaddr for offer in offers}
    assert len(offered_addresses) == 1, (
        f"Conflicting offers for transaction 0x{xid:08x}: "
        f"{sorted(offered_addresses)}"
    )
    offer = offers[0]
    server_id = dhcp_option(offer, "server_id")
    assert server_id == DHCP_SERVER_IP, (
        f"DHCPOFFER server identifier was {server_id!r}, "
        f"expected {DHCP_SERVER_IP!r}"
    )
    return {
        "mac": mac,
        "offer": offer,
        "offered_ip": offer[BOOTP].yiaddr,
        "server_id": server_id,
        "xid": xid,
    }


def _arp_probe(mac, target_ip):
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc=mac,
            hwdst="00:00:00:00:00:00",
            psrc="0.0.0.0",
            pdst=target_ip,
        )
    )


def _peer_claim(peer_mac, target_ip):
    return (
        Ether(src=peer_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc=peer_mac,
            hwdst="00:00:00:00:00:00",
            psrc=target_ip,
            pdst=target_ip,
        )
    )


def _unrelated_arp(peer_mac):
    return (
        Ether(src=peer_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op=1,
            hwsrc=peer_mac,
            hwdst="00:00:00:00:00:00",
            psrc="192.0.2.10",
            pdst="192.0.2.20",
        )
    )


def _same_arp(left, right):
    return (
        int(left.op) == int(right.op)
        and left.hwsrc.lower() == right.hwsrc.lower()
        and left.psrc == right.psrc
        and left.pdst == right.pdst
    )


def _is_conflict(packet, lease):
    if not packet.haslayer(ARP):
        return False
    arp = packet[ARP]
    if arp.hwsrc.lower() == lease["mac"].lower():
        return False
    return arp.psrc == lease["acknowledged_ip"] or (
        arp.psrc == "0.0.0.0" and arp.pdst == lease["acknowledged_ip"]
    )


def _client_dhcp_message_types(packets, lease):
    client_chaddr = mac_bytes(lease["mac"])
    return [
        dhcp_option(packet, "message-type")
        for packet in packets
        if packet.haslayer(DHCP)
        and packet.haslayer(BOOTP)
        and packet[BOOTP].xid == lease["xid"]
        and bytes(packet[BOOTP].chaddr)[:6] == client_chaddr
    ]


def _probe_with_traffic(context, traffic_kind):
    state = _state(context)
    lease = state.get("lease")
    assert lease, "No transaction-specific DHCPACK is available"
    target_ip = lease["acknowledged_ip"]

    if traffic_kind == "claim":
        traffic = _peer_claim(_new_mac(context), target_ip)
    elif traffic_kind == "simultaneous-probe":
        traffic = _arp_probe(_new_mac(context), target_ip)
    elif traffic_kind == "unrelated":
        traffic = _unrelated_arp(_new_mac(context))
    elif traffic_kind == "self-claim":
        traffic = _peer_claim(lease["mac"], target_ip)
    else:
        raise AssertionError(f"Unknown RFC 5227 traffic kind: {traffic_kind}")

    sniffer = AsyncSniffer(
        iface=INTERFACE,
        lfilter=lambda packet: packet.haslayer(ARP) or packet.haslayer(DHCP),
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)

    initial_wait = random.uniform(0, PROBE_WAIT)
    time.sleep(initial_wait)
    probes = []
    probe_times = []
    stopped_on_conflict = False
    monitoring_started = None

    for probe_index in range(PROBE_NUM):
        probe = _arp_probe(lease["mac"], target_ip)
        probe_times.append(time.monotonic())
        probes.append(probe)
        _send(probe)

        traffic_started = None
        if probe_index == 0:
            traffic_started = time.monotonic()
            _send(traffic)
            time.sleep(ARP_CAPTURE_SETTLE)
            stopped_on_conflict = _is_conflict(traffic, lease)
            if stopped_on_conflict:
                break

        if probe_index < PROBE_NUM - 1:
            inter_probe_wait = random.uniform(PROBE_MIN, PROBE_MAX)
            elapsed = (
                time.monotonic() - traffic_started
                if traffic_started is not None
                else 0
            )
            time.sleep(max(0, inter_probe_wait - elapsed))

    if not stopped_on_conflict:
        monitoring_started = time.monotonic()
        time.sleep(ANNOUNCE_WAIT)

    captured = list(sniffer.stop() or [])

    captured_arp = [packet[ARP] for packet in captured if packet.haslayer(ARP)]
    for probe in probes:
        assert any(_same_arp(arp, probe[ARP]) for arp in captured_arp), (
            f"An RFC 5227 ARP Probe for {target_ip} was not captured"
        )
    assert any(_same_arp(arp, traffic[ARP]) for arp in captured_arp), (
        f"The injected {traffic_kind} ARP packet was not captured"
    )

    predecision_messages = _client_dhcp_message_types(captured, lease)
    state["conflicts"] = [
        packet for packet in captured if _is_conflict(packet, lease)
    ]
    state["conflict_check_complete"] = True
    state["predecision_declines"] = predecision_messages.count(4)
    state["initial_probe_wait"] = initial_wait
    state["monitoring_duration"] = (
        time.monotonic() - monitoring_started
        if monitoring_started is not None
        else 0
    )
    state["probe_intervals"] = [
        later - earlier for earlier, later in zip(probe_times, probe_times[1:])
    ]
    state["probes_sent"] = len(probes)
    state["stopped_on_conflict"] = stopped_on_conflict
    state["traffic_kind"] = traffic_kind


def _announce_address(context):
    state = _state(context)
    lease = state["lease"]
    target_ip = lease["acknowledged_ip"]
    announcement = _peer_claim(lease["mac"], target_ip)
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        lfilter=lambda packet: packet.haslayer(ARP),
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)

    sent_at = []
    for announcement_index in range(ANNOUNCE_NUM):
        sent_at.append(time.monotonic())
        _send(announcement)
        if announcement_index < ANNOUNCE_NUM - 1:
            time.sleep(ANNOUNCE_INTERVAL)

    time.sleep(ARP_CAPTURE_SETTLE)
    captured = list(sniffer.stop() or [])
    captured_announcements = [
        packet[ARP]
        for packet in captured
        if packet.haslayer(ARP) and _same_arp(packet[ARP], announcement[ARP])
    ]
    assert len(captured_announcements) >= ANNOUNCE_NUM, (
        f"Captured {len(captured_announcements)} RFC 5227 announcements for "
        f"{target_ip}, expected at least {ANNOUNCE_NUM}"
    )
    state["announcements_sent"] = len(sent_at)
    state["announcement_intervals"] = [
        later - earlier for earlier, later in zip(sent_at, sent_at[1:])
    ]


def _request_offer(offer):
    request = build_client_packet(
        offer["mac"],
        offer["xid"],
        _client_options(
            "request",
            server_id=offer["server_id"],
            requested_addr=offer["offered_ip"],
        ),
    )
    sniffer = start_dhcp_sniffer(INTERFACE, timeout=DHCP_CAPTURE_TIMEOUT)
    _send(request)
    acknowledgements = dhcp_packets(
        sniffer,
        5,
        offer["xid"],
        offer["server_id"],
    )
    assert acknowledgements, (
        f"No DHCPACK for transaction 0x{offer['xid']:08x} from "
        f"{offer['server_id']}"
    )
    acknowledged_addresses = {ack[BOOTP].yiaddr for ack in acknowledgements}
    assert acknowledged_addresses == {offer["offered_ip"]}, (
        f"DHCPACK did not preserve offered address {offer['offered_ip']}: "
        f"{sorted(acknowledged_addresses)}"
    )
    return acknowledgements[0]


@when(
    "an RFC 5227 companion client completes DORA with a transaction-specific "
    "DHCPACK"
)
def step_when_companion_completes_dora(context):
    state = _state(context)
    offer = _discover(context, _new_mac(context))
    ack = _request_offer(offer)
    state["offer"] = offer
    state["ack"] = ack
    state["lease"] = {
        **offer,
        "acknowledged_ip": ack[BOOTP].yiaddr,
    }


@when("the companion probes while a distinct peer claims the acknowledged address")
def step_when_distinct_peer_claims_address(context):
    _probe_with_traffic(context, "claim")


@when("the companion probes while a distinct peer probes the acknowledged address")
def step_when_distinct_peer_probes_address(context):
    _probe_with_traffic(context, "simultaneous-probe")


@when("the companion probes while unrelated ARP traffic occurs")
def step_when_unrelated_arp_occurs(context):
    _probe_with_traffic(context, "unrelated")


@when("the companion probes while its own address claim is observed")
def step_when_self_claim_is_observed(context):
    _probe_with_traffic(context, "self-claim")


@then("the companion detects an address conflict")
def step_then_conflict_is_detected(context):
    state = _state(context)
    assert state.get("conflict_check_complete"), "Conflict checking did not complete"
    assert state.get("conflicts"), (
        f"The injected {state.get('traffic_kind')} was not classified as a conflict"
    )


@then("the companion does not detect an address conflict")
def step_then_no_conflict_is_detected(context):
    state = _state(context)
    assert state.get("conflict_check_complete"), "Conflict checking did not complete"
    assert not state.get("conflicts"), (
        f"The injected {state.get('traffic_kind')} was incorrectly classified "
        "as a conflict"
    )


@then("the companion stops probing after the conflict decision")
def step_then_companion_stops_probing(context):
    state = _state(context)
    assert state.get("conflict_check_complete"), "Conflict checking did not complete"
    assert state.get("stopped_on_conflict"), (
        "The companion continued probing after classifying an address conflict"
    )
    assert state.get("probes_sent") == 1, (
        f"Expected probing to stop after one conflicting probe, sent "
        f"{state.get('probes_sent')}"
    )


@then("the companion completes the RFC 5227 probe and monitoring sequence")
def step_then_companion_completes_probe_sequence(context):
    state = _state(context)
    assert state.get("conflict_check_complete"), "Conflict checking did not complete"
    assert not state.get("conflicts"), "A conflict-free sequence recorded a conflict"
    assert state.get("probes_sent") == PROBE_NUM, (
        f"Sent {state.get('probes_sent')} probes, expected {PROBE_NUM}"
    )
    assert 0 <= state.get("initial_probe_wait", -1) <= PROBE_WAIT + TIMING_TOLERANCE
    for interval in state.get("probe_intervals", []):
        assert PROBE_MIN <= interval <= PROBE_MAX + TIMING_TOLERANCE, (
            f"RFC 5227 inter-probe interval {interval:.3f}s is outside "
            f"{PROBE_MIN}..{PROBE_MAX}s"
        )
    assert state.get("monitoring_duration", 0) >= ANNOUNCE_WAIT, (
        "The companion did not monitor for conflicts through ANNOUNCE_WAIT"
    )


@then("the companion did not send DHCPDECLINE")
def step_then_no_decline_was_sent(context):
    state = _state(context)
    assert state.get("predecision_declines") == 0, (
        "A DHCPDECLINE was captured during conflict-free probing"
    )
    assert not state.get("decline_sent"), (
        "The companion recorded a DHCPDECLINE without detecting a conflict"
    )


@when("the companion sends DHCPDECLINE for the conflicted acknowledged address")
def step_when_companion_sends_decline(context):
    state = _state(context)
    offer = state.get("offer")
    lease = state.get("lease")
    assert state.get("conflict_check_complete"), "Conflict checking did not complete"
    assert state.get("conflicts"), "DHCPDECLINE requires an observed address conflict"
    decline = build_client_packet(
        offer["mac"],
        offer["xid"],
        _client_options(
            "decline",
            server_id=offer["server_id"],
            requested_addr=lease["acknowledged_ip"],
        ),
    )
    _send(decline)
    state["decline_sent"] = True
    time.sleep(0.25)


@then("the same client receives a different transaction-specific DHCPOFFER")
def step_then_same_client_receives_different_offer(context):
    state = _state(context)
    original = state["offer"]
    assert state.get("decline_sent"), "No DHCPDECLINE was sent"
    replacement = _discover(context, original["mac"])
    assert replacement["xid"] != original["xid"]
    assert replacement["offered_ip"] != original["offered_ip"], (
        f"Server re-offered declined address {original['offered_ip']} to the same client"
    )
    state["replacement_offer"] = replacement


@then("the companion accepts and announces the acknowledged address")
def step_then_companion_accepts_and_announces(context):
    state = _state(context)
    offer = state["offer"]
    ack = state.get("ack")
    assert ack is not None, "No transaction-specific DHCPACK was captured"
    assert ack[BOOTP].xid == offer["xid"]
    assert ack[BOOTP].yiaddr == offer["offered_ip"]
    assert dhcp_option(ack, "server_id") == offer["server_id"]
    assert state.get("probes_sent") == PROBE_NUM
    assert not state.get("conflicts")
    assert not state.get("decline_sent")

    _announce_address(context)
    assert state.get("announcements_sent") == ANNOUNCE_NUM
    for interval in state.get("announcement_intervals", []):
        assert interval >= ANNOUNCE_INTERVAL, (
            f"RFC 5227 announcement interval {interval:.3f}s is shorter than "
            f"{ANNOUNCE_INTERVAL}s"
        )
