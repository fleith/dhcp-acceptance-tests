"""Shared DHCPv6 packet and client-state helpers for Behave steps."""

import ipaddress
import os
import re
import subprocess
import time

try:
    from scapy.all import AsyncSniffer, Ether, IPv6, UDP, sendp
    from scapy.layers import dhcp6 as sc_dhcp6
except ImportError:
    AsyncSniffer = Ether = IPv6 = UDP = sendp = None
    sc_dhcp6 = None


DHCPV6_SERVER_IP = os.getenv("TEST_SERVER_IPV6", "fd00:29::2")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SUBNET_V6 = os.getenv("TEST_SUBNET_V6", "fd00:29::/64")
LEASE_TIME = int(os.getenv("TEST_LEASE_TIME", "120"))

context_storage_v6 = {}


def require_scapy_v6():
    if Ether is None or sc_dhcp6 is None:
        raise RuntimeError("Scapy with DHCPv6 support is required; please install scapy>=2.5.")


def cls(name):
    packet_class = getattr(sc_dhcp6, name, None)
    if packet_class is None:
        raise RuntimeError(f"Scapy DHCPv6 class '{name}' is not available in this version.")
    return packet_class


def random_duid():
    # DUID-UUID (type=4)
    return b"\x00\x04" + os.urandom(16)


def new_trid():
    return int.from_bytes(os.urandom(3), "big")


def interface_mac():
    out = subprocess.check_output(["ip", "link", "show", "dev", INTERFACE]).decode()
    match = re.search(r"link/ether\s+([0-9a-f:]{17})", out)
    if not match:
        raise RuntimeError(f"No MAC address found for interface {INTERFACE}")
    return match.group(1)


def interface_link_local_ipv6():
    out = subprocess.check_output(
        ["ip", "-6", "-o", "addr", "show", "dev", INTERFACE, "scope", "link"]
    ).decode()
    for line in out.splitlines():
        match = re.search(r"inet6\s+([0-9a-fA-F:]+)/(\d+)", line)
        if match:
            return match.group(1)
    raise RuntimeError(f"No link-local IPv6 address found on interface {INTERFACE}")


def initialize_client_state():
    context_storage_v6.clear()
    context_storage_v6["client_duid"] = random_duid()
    context_storage_v6["iaid"] = int.from_bytes(os.urandom(4), "big")
    context_storage_v6["client_mac"] = interface_mac()
    context_storage_v6["client_ll"] = interface_link_local_ipv6()


def client_duid():
    return context_storage_v6["client_duid"]


def duids_equal(first, second):
    """Compare raw and Scapy-decoded DUID values by their wire representation."""
    if first is None or second is None:
        return first is second
    return bytes(first) == bytes(second)


def iaid():
    return context_storage_v6["iaid"]


def start_v6_sniffer(timeout=10):
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        lfilter=lambda packet: packet.haslayer(UDP)
        and (packet[UDP].sport == 547 or packet[UDP].dport == 547),
        timeout=timeout,
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)
    return sniffer


def dhcpv6_packets(sniffer, message_name, trid):
    message_class = cls(message_name)
    sniffer.join()
    return [
        packet
        for packet in (sniffer.results or [])
        if packet.haslayer(message_class)
        and getattr(packet[message_class], "trid", None) == trid
    ]


def get_server_duid(packet):
    option = packet.getlayer(cls("DHCP6OptServerId"))
    return getattr(option, "duid", None) if option else None


def get_iaaddr(packet):
    option = packet.getlayer(cls("DHCP6OptIAAddress"))
    return getattr(option, "addr", None) if option else None


def ia_na(address=None, preferred_lifetime=0, valid_lifetime=0):
    options = []
    if address:
        options.append(
            cls("DHCP6OptIAAddress")(
                addr=address,
                preflft=preferred_lifetime,
                validlft=valid_lifetime,
            )
        )
    return cls("DHCP6OptIA_NA")(iaid=iaid(), ianaopts=options)


def ensure_interface_ipv6(ipv6_addr):
    prefix = ipaddress.ip_network(SUBNET_V6, strict=False).prefixlen
    current = subprocess.check_output(["ip", "-6", "addr", "show", "dev", INTERFACE]).decode()
    if ipv6_addr in current:
        return False
    subprocess.run(
        ["ip", "-6", "addr", "add", f"{ipv6_addr}/{prefix}", "dev", INTERFACE],
        check=True,
    )
    return True


def remove_interface_ipv6(ipv6_addr):
    prefix = ipaddress.ip_network(SUBNET_V6, strict=False).prefixlen
    subprocess.run(
        ["ip", "-6", "addr", "del", f"{ipv6_addr}/{prefix}", "dev", INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
