import ipaddress
import os
import re
import subprocess
import time
from behave import given, when, then

try:
    from scapy.all import Ether, IPv6, UDP, AsyncSniffer, sendp
    from scapy.layers import dhcp6 as sc_dhcp6
except ImportError:
    Ether = IPv6 = UDP = AsyncSniffer = sendp = None
    sc_dhcp6 = None


DHCPV6_SERVER_IP = os.getenv("TEST_SERVER_IPV6", "fd00:29::2")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SUBNET_V6 = os.getenv("TEST_SUBNET_V6", "fd00:29::/64")
LEASE_TIME = int(os.getenv("TEST_LEASE_TIME", "120"))

context_storage_v6 = {}


def _require_scapy_v6():
    if Ether is None or sc_dhcp6 is None:
        raise RuntimeError("Scapy with DHCPv6 support is required; please install scapy>=2.5.")


def _cls(name):
    c = getattr(sc_dhcp6, name, None)
    if c is None:
        raise RuntimeError(f"Scapy DHCPv6 class '{name}' is not available in this version.")
    return c


def _random_duid():
    # DUID-UUID (type=4)
    return b"\x00\x04" + os.urandom(16)


def _new_trid():
    return int.from_bytes(os.urandom(3), "big")


def _interface_mac():
    out = subprocess.check_output(["ip", "link", "show", "dev", INTERFACE]).decode()
    match = re.search(r"link/ether\s+([0-9a-f:]{17})", out)
    if not match:
        raise RuntimeError(f"No MAC address found for interface {INTERFACE}")
    return match.group(1)


def _interface_link_local_ipv6():
    out = subprocess.check_output(
        ["ip", "-6", "-o", "addr", "show", "dev", INTERFACE, "scope", "link"]
    ).decode()
    for line in out.splitlines():
        match = re.search(r"inet6\s+([0-9a-fA-F:]+)/(\d+)", line)
        if match:
            return match.group(1)
    raise RuntimeError(f"No link-local IPv6 address found on interface {INTERFACE}")


def _client_duid():
    return context_storage_v6["client_duid"]


def _iaid():
    return context_storage_v6["iaid"]


def _start_v6_sniffer(timeout=10):
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        lfilter=lambda p: p.haslayer(UDP) and (p[UDP].sport == 547 or p[UDP].dport == 547),
        timeout=timeout,
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)
    return sniffer


def _dhcpv6_packets(sniffer, msg_name, trid):
    msg_cls = _cls(msg_name)
    sniffer.join()
    return [
        p
        for p in (sniffer.results or [])
        if p.haslayer(msg_cls) and getattr(p[msg_cls], "trid", None) == trid
    ]


def _get_server_duid(pkt):
    opt = pkt.getlayer(_cls("DHCP6OptServerId"))
    return getattr(opt, "duid", None) if opt else None


def _get_iaaddr(pkt):
    opt = pkt.getlayer(_cls("DHCP6OptIAAddress"))
    return getattr(opt, "addr", None) if opt else None


def _ensure_interface_ipv6(ipv6_addr):
    prefix = ipaddress.ip_network(SUBNET_V6, strict=False).prefixlen
    current = subprocess.check_output(["ip", "-6", "addr", "show", "dev", INTERFACE]).decode()
    if ipv6_addr in current:
        return False
    subprocess.run(["ip", "-6", "addr", "add", f"{ipv6_addr}/{prefix}", "dev", INTERFACE], check=True)
    return True


def _remove_interface_ipv6(ipv6_addr):
    prefix = ipaddress.ip_network(SUBNET_V6, strict=False).prefixlen
    subprocess.run(
        ["ip", "-6", "addr", "del", f"{ipv6_addr}/{prefix}", "dev", INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@given("the DHCPv6 server is running")
def step_given_dhcpv6_server_running(context):
    _require_scapy_v6()
    context_storage_v6.clear()
    context_storage_v6["client_duid"] = _random_duid()
    context_storage_v6["iaid"] = int.from_bytes(os.urandom(4), "big")
    context_storage_v6["client_mac"] = _interface_mac()
    context_storage_v6["client_ll"] = _interface_link_local_ipv6()


@given("a client holds a DHCPv6 lease from the server")
def step_given_client_holds_dhcpv6_lease(context):
    context.execute_steps(
        """
        Given the DHCPv6 server is running
        When a client sends a DHCPv6 SOLICIT message
        Then the client receives a DHCPv6 ADVERTISE from the server
        When the client sends a DHCPv6 REQUEST message
        Then the server responds with a DHCPv6 REPLY that finalizes the lease
        """
    )


@when("a client sends a DHCPv6 SOLICIT message")
def step_when_send_solicit(context):
    _require_scapy_v6()
    trid = _new_trid()

    solicit = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Solicit")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _cls("DHCP6OptIA_NA")(iaid=_iaid())
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(solicit, iface=INTERFACE, verbose=False)

    context_storage_v6["solicit_trid"] = trid
    context_storage_v6["solicit_sniffer"] = sniffer


@then("the client receives a DHCPv6 ADVERTISE from the server")
def step_then_receive_advertise(context):
    trid = context_storage_v6["solicit_trid"]
    sniffer = context_storage_v6["solicit_sniffer"]
    advertise_pkts = _dhcpv6_packets(sniffer, "DHCP6_Advertise", trid)

    if not advertise_pkts:
        all_pkts = sniffer.results or []
        print(f"\n[DEBUG DHCPv6] Expected ADVERTISE trid={hex(trid)}, captured={len(all_pkts)}")
        for i, p in enumerate(all_pkts):
            if p.haslayer(UDP):
                print(f"[DEBUG DHCPv6 pkt{i}] {p.summary()}")

    assert advertise_pkts, "No DHCPv6 ADVERTISE received"

    adv = advertise_pkts[0]
    server_duid = _get_server_duid(adv)
    assert server_duid, "DHCPv6 ADVERTISE missing Server Identifier"

    offered_ip = _get_iaaddr(adv)
    if offered_ip:
        assert ipaddress.ip_address(offered_ip) in ipaddress.ip_network(SUBNET_V6), (
            f"Offered IPv6 {offered_ip} not in subnet {SUBNET_V6}"
        )
        context_storage_v6["offered_ipv6"] = offered_ip

    context_storage_v6["server_duid"] = server_duid


@when("the client sends a DHCPv6 REQUEST message")
def step_when_send_request(context):
    _require_scapy_v6()
    trid = _new_trid()

    request = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Request")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["server_duid"])
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _cls("DHCP6OptIA_NA")(iaid=_iaid())
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(request, iface=INTERFACE, verbose=False)

    context_storage_v6["request_trid"] = trid
    context_storage_v6["request_sniffer"] = sniffer


@then("the server responds with a DHCPv6 REPLY that finalizes the lease")
def step_then_reply_finalizes_lease(context):
    trid = context_storage_v6["request_trid"]
    sniffer = context_storage_v6["request_sniffer"]
    replies = _dhcpv6_packets(sniffer, "DHCP6_Reply", trid)
    assert replies, "No DHCPv6 REPLY received"

    reply = replies[0]
    leased_ip = _get_iaaddr(reply)
    assert leased_ip, "DHCPv6 REPLY missing IA Address"
    assert ipaddress.ip_address(leased_ip) in ipaddress.ip_network(SUBNET_V6), (
        f"Leased IPv6 {leased_ip} not in subnet {SUBNET_V6}"
    )

    server_duid = _get_server_duid(reply)
    if server_duid:
        context_storage_v6["server_duid"] = server_duid
    context_storage_v6["leased_ipv6"] = leased_ip


@when("the client sends a DHCPv6 RENEW message")
def step_when_send_renew(context):
    _require_scapy_v6()
    lease_ip = context_storage_v6["leased_ipv6"]
    added = _ensure_interface_ipv6(lease_ip)
    context_storage_v6["lease_ipv6_added"] = added

    trid = _new_trid()
    renew = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=lease_ip, dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Renew")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(duid=context_storage_v6["server_duid"])
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _cls("DHCP6OptIA_NA")(iaid=_iaid())
    )

    sniffer = _start_v6_sniffer(timeout=12)
    sendp(renew, iface=INTERFACE, verbose=False)

    context_storage_v6["renew_trid"] = trid
    context_storage_v6["renew_sniffer"] = sniffer


@then("the server responds with a DHCPv6 REPLY extending the lease")
def step_then_reply_extends_lease(context):
    trid = context_storage_v6["renew_trid"]
    sniffer = context_storage_v6["renew_sniffer"]
    replies = _dhcpv6_packets(sniffer, "DHCP6_Reply", trid)
    assert replies, "No DHCPv6 REPLY for RENEW received"

    reply = replies[0]
    renewed_ip = _get_iaaddr(reply)
    assert renewed_ip, "DHCPv6 RENEW REPLY missing IA Address"
    assert ipaddress.ip_address(renewed_ip) in ipaddress.ip_network(SUBNET_V6), (
        f"Renewed IPv6 {renewed_ip} not in subnet {SUBNET_V6}"
    )