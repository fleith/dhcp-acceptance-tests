"""Shared packet helpers for DHCPv4 acceptance scenarios."""

import time

try:
    from scapy.all import AsyncSniffer, BOOTP, DHCP, Ether, IP, UDP
except ImportError:
    AsyncSniffer = BOOTP = DHCP = Ether = IP = UDP = None


def require_scapy_v4():
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")


def mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def client_mac(state, default_mac):
    return state.get("client_mac", default_mac)


def start_dhcp_sniffer(interface, timeout=5):
    """Capture DHCP packets, including frames for synthetic client MACs."""
    require_scapy_v4()
    sniffer = AsyncSniffer(
        iface=interface,
        lfilter=lambda packet: packet.haslayer(DHCP),
        timeout=timeout,
        promisc=True,
    )
    sniffer.start()
    time.sleep(0.1)
    return sniffer


def dhcp_options(packet):
    """Return named DHCP options while ignoring sentinels and raw options."""
    if not packet or not packet.haslayer(DHCP):
        return {}
    return {
        option[0]: option[1]
        for option in packet[DHCP].options
        if isinstance(option, (tuple, list))
        and len(option) >= 2
        and isinstance(option[0], str)
        and option[0] not in ("end", "pad")
    }


def dhcp_option(packet, option_name):
    return dhcp_options(packet).get(option_name)


def raw_dhcp_option(packet, code, names=()):
    """Find an option by numeric code or any known Scapy field name."""
    if not packet or not packet.haslayer(DHCP):
        return None
    for option in packet[DHCP].options:
        if not isinstance(option, (tuple, list)) or len(option) < 2:
            continue
        key = option[0]
        if key == code or (isinstance(key, str) and key in names):
            return option[1]
    return None


def option_bytes(value):
    """Normalize Scapy's bytes-like and Latin-1 option representations."""
    if value is None:
        return None
    if isinstance(value, str):
        return value.encode("latin-1", "ignore")
    if isinstance(value, int):
        width = max(1, (value.bit_length() + 7) // 8)
        return value.to_bytes(width, "big")
    return bytes(value)


def assert_dhcp_option(packet, option_name, message_type="DHCPACK"):
    options = dhcp_options(packet)
    assert option_name in options, (
        f"{message_type} missing option '{option_name}'; present: {list(options.keys())}"
    )


def assert_raw_option_absent(packet, code, names=(), message_type="DHCP response"):
    value = raw_dhcp_option(packet, code, names)
    assert value is None, f"{message_type} unexpectedly included DHCP option {code}"


def dhcp_packets(sniffer, message_type, xid, server_id=None):
    """Return responses matching message type, transaction, and optional server."""
    sniffer.join()
    packets = [
        packet
        for packet in (sniffer.results or [])
        if packet.haslayer(DHCP)
        and packet.haslayer(BOOTP)
        and dhcp_options(packet).get("message-type") == message_type
        and packet[BOOTP].xid == xid
    ]
    if server_id is not None:
        packets = [
            packet for packet in packets if dhcp_option(packet, "server_id") == server_id
        ]
    return packets


def build_client_packet(
    mac,
    xid,
    options,
    *,
    ciaddr="0.0.0.0",
    source_ip="0.0.0.0",
    destination_ip="255.255.255.255",
    destination_mac="ff:ff:ff:ff:ff:ff",
    flags=0x8000,
):
    """Build a client-to-server DHCPv4 frame for raw-socket scenarios."""
    require_scapy_v4()
    return (
        Ether(src=mac, dst=destination_mac)
        / IP(src=source_ip, dst=destination_ip)
        / UDP(sport=68, dport=67)
        / BOOTP(chaddr=mac_bytes(mac), ciaddr=ciaddr, flags=flags, xid=xid)
        / DHCP(options=options)
    )
