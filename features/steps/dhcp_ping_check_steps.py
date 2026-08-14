"""RFC 2131 server-side candidate-address ping-check acceptance steps."""

import ipaddress
import os
import subprocess
import time

from behave import given, then, when

from dhcpv4_support import (
    BOOTP,
    DHCP,
    IP,
    build_client_packet,
    dhcp_options,
    require_scapy_v4,
)

try:
    from scapy.all import AsyncSniffer, ICMP, sendp
except ImportError:
    AsyncSniffer = ICMP = sendp = None


INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SERVER_IP = os.getenv("TEST_SERVER_IP", "172.29.0.2")
CANDIDATE = os.getenv("TEST_DHCPV4_PING_CHECK_ADDRESS", "")
POOL_START = int(os.getenv("DHCPV4_POOL_START_OFFSET", "100"))
POOL_END = int(os.getenv("DHCPV4_POOL_END_OFFSET", "200"))


def _state(context):
    if not hasattr(context, "server_ping_check"):
        context.server_ping_check = {}
    return context.server_ping_check


def _remove_candidate_address():
    if CANDIDATE:
        subprocess.run(
            ["ip", "address", "del", f"{CANDIDATE}/32", "dev", INTERFACE],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def _message_type(packet):
    if not packet.haslayer(DHCP):
        return None
    return dhcp_options(packet).get("message-type")


def _is_probe(packet):
    return (
        packet.haslayer(IP)
        and packet.haslayer(ICMP)
        and packet[IP].src == SERVER_IP
        and packet[IP].dst == CANDIDATE
        and packet[ICMP].type == 8
    )


def _is_probe_reply(packet):
    return (
        packet.haslayer(IP)
        and packet.haslayer(ICMP)
        and packet[IP].src == CANDIDATE
        and packet[IP].dst == SERVER_IP
        and packet[ICMP].type == 0
    )


@given("the ping-check fixture contains exactly one candidate address")
def step_one_candidate(context):
    require_scapy_v4()
    assert AsyncSniffer is not None and ICMP is not None and sendp is not None, (
        "Scapy ICMP capture support is required for server ping-check tests"
    )
    assert CANDIDATE, "TEST_DHCPV4_PING_CHECK_ADDRESS must identify the candidate"
    assert POOL_START == POOL_END, (
        "Server ping-check scenarios require a one-address DHCPv4 pool"
    )
    subnet = ipaddress.ip_network(os.getenv("TEST_SUBNET", "172.29.0.0/24"))
    assert ipaddress.ip_address(CANDIDATE) in subnet
    assert int(CANDIDATE.rsplit(".", 1)[1]) == POOL_START, (
        f"Candidate {CANDIDATE} does not match pool offset {POOL_START}"
    )


@given("no host owns the ping-check candidate address")
def step_candidate_silent(context):
    _remove_candidate_address()


@given("the test peer owns and answers for the ping-check candidate address")
def step_candidate_occupied(context):
    _remove_candidate_address()
    subprocess.run(
        ["ip", "address", "add", f"{CANDIDATE}/32", "dev", INTERFACE],
        check=True,
    )
    context.add_cleanup(_remove_candidate_address)


@when("a DHCPv4 client discovers a lease in the ping-check fixture")
def step_discover(context):
    xid = int.from_bytes(os.urandom(4), "big") or 1
    mac_tail = os.urandom(3)
    mac = f"02:00:00:{mac_tail[0]:02x}:{mac_tail[1]:02x}:{mac_tail[2]:02x}"
    discover = build_client_packet(
        mac,
        xid,
        [("message-type", "discover"), ("param_req_list", [1, 3, 6, 51]), "end"],
    )
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        lfilter=lambda packet: packet.haslayer(DHCP) or packet.haslayer(ICMP),
        timeout=5,
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)
    sendp(discover, iface=INTERFACE, verbose=False)
    sniffer.join()
    packets = list(sniffer.results or [])
    state = _state(context)
    state["xid"] = xid
    state["packets"] = packets
    state["probes"] = [packet for packet in packets if _is_probe(packet)]
    state["probe_replies"] = [packet for packet in packets if _is_probe_reply(packet)]
    state["offers"] = [
        packet
        for packet in packets
        if packet.haslayer(BOOTP)
        and packet[BOOTP].xid == xid
        and _message_type(packet) == 2
    ]


@then("the server sends an ICMP Echo Request for the candidate address")
def step_probe_observed(context):
    state = _state(context)
    icmp_packets = [
        (
            packet[IP].src,
            packet[IP].dst,
            int(packet[ICMP].type),
        )
        for packet in state["packets"]
        if packet.haslayer(IP) and packet.haslayer(ICMP)
    ]
    offered = [packet[BOOTP].yiaddr for packet in state["offers"]]
    assert state["probes"], (
        f"No ICMP Echo Request from {SERVER_IP} to candidate {CANDIDATE} was captured; "
        f"captured_icmp={icmp_packets}, offered={offered}"
    )


@then("the silent candidate address is offered after the probe")
def step_silent_candidate_offered(context):
    state = _state(context)
    assert not state["probe_replies"], (
        f"Silent candidate {CANDIDATE} unexpectedly answered the server probe"
    )
    assert state["offers"], "Server did not offer the silent candidate address"
    assert {packet[BOOTP].yiaddr for packet in state["offers"]} == {CANDIDATE}
    assert min(float(packet.time) for packet in state["offers"]) > min(
        float(packet.time) for packet in state["probes"]
    ), "DHCPOFFER was sent before the candidate-address probe"


@then("the test peer returns an ICMP Echo Reply for the candidate address")
def step_probe_reply_observed(context):
    assert _state(context)["probe_replies"], (
        f"Test peer did not answer the probe for {CANDIDATE}"
    )


@then("the responding candidate address is not offered")
def step_occupied_candidate_withheld(context):
    offers = _state(context)["offers"]
    assert not offers, (
        f"Server offered responding candidate {CANDIDATE}: "
        f"{[packet[BOOTP].yiaddr for packet in offers]}"
    )
