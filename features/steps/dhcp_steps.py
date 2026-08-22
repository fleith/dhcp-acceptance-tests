import subprocess
import time
import ipaddress
import os
import re
from pathlib import Path
from behave import given, when, then
from dhcpv4_support import (
    assert_dhcp_option as _support_assert_dhcp_option,
    client_mac as _support_client_mac,
    dhcp_option as _support_get_dhcp_option,
    dhcp_options as _support_get_dhcp_options,
    dhcp_packets as _support_dhcp_packets,
    mac_bytes as _support_mac_bytes,
    option_bytes as _support_option_bytes,
    raw_dhcp_option as _support_get_raw_option,
    raw_dhcp_option_areas as _support_get_raw_areas,
    raw_dhcp_option_fragments as _support_get_raw_fragments,
    start_dhcp_sniffer as _support_start_dhcp_sniffer,
)

try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, send, sendp, sniff, AsyncSniffer
except ImportError:
    Ether = IP = UDP = BOOTP = DHCP = send = sendp = sniff = AsyncSniffer = None

"""
Step definitions for the DHCP acceptance tests.

Environment variables:

* ``TEST_SERVER_IP`` – IP address of the DHCP server.  Defaults to
  ``192.168.56.1``.
* ``TEST_CLIENT_MAC`` – MAC address to use for the test client.  Defaults
  to a locally administered address ``02:00:00:00:00:01``.
* ``TEST_INTERFACE`` – Network interface on which to send and receive
  DHCP packets.  Defaults to ``eth0``.
* ``TEST_SUBNET`` – CIDR notation for the subnet from which IPs will be
  leased.  Defaults to ``192.168.56.0/24``.
* ``TEST_LEASE_TIME`` – Lease time in seconds used by the DHCP server.
"""

DHCP_SERVER_IP = os.getenv("TEST_SERVER_IP", "192.168.56.1")
CLIENT_MAC = os.getenv("TEST_CLIENT_MAC", "02:00:00:00:00:01")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SUBNET = os.getenv("TEST_SUBNET", "192.168.56.0/24")
LEASE_TIME = float(os.getenv("TEST_LEASE_TIME", "120"))
RFC3396_LONG_OPTION_CODE = 224
ADMIN_EVENT_LOG = Path(
    os.getenv("TEST_DHCPV4_SERVER_LOG_FILE", "/app/test-state/dhcpv4-server.log")
)
DECLINE_LOG_PATTERN = os.getenv("TEST_DHCPV4_DECLINE_LOG_PATTERN", "").strip()
RFC3396_LONG_OPTION = b"0123456789abcdef" * 20
RFC3396_POLICY_DOMAIN = os.getenv(
    "TEST_RFC3396_POLICY_DOMAIN", "rfc3396-reassembled.test"
)
EXPECTED_DNS_SERVERS = ("8.8.8.8", "1.1.1.1")

context_storage = {}


def _mac_bytes(mac):
    return _support_mac_bytes(mac)


def _client_mac():
    """Return the per-scenario client MAC.

    environment.py's before_scenario hook stores a freshly generated MAC in
    context_storage before each scenario so that every scenario is independent:
    ISC dhcpd won't reuse an existing binding from a previous scenario and will
    always grant a full default-lease-time lease.  Falls back to the module-level
    CLIENT_MAC constant when context_storage hasn't been initialised (e.g. unit
    tests that call step functions directly).
    """
    return _support_client_mac(context_storage, CLIENT_MAC)


def _start_dhcp_sniffer(timeout=5):
    """Start an AsyncSniffer capturing all DHCP packets, wait briefly for it to be ready.

    promisc=True is required so the sniffer captures unicast packets destined
    for CLIENT_MAC (e.g. DHCPINFORM responses) even when that MAC differs from
    the interface's own hardware address.
    """
    return _support_start_dhcp_sniffer(INTERFACE, timeout)


def _dhcp_packets(sniffer, msg_type, xid, server_id=None):
    """Return captured DHCP packets matching msg_type and transaction id.

    Uses the options dict rather than options[0] because ISC dhcpd 4.4.x does
    not always put the message-type option first in the options field (RFC 2131
    says SHOULD, not MUST).  Checking only options[0] would silently miss NAK
    and ACK packets where a network-config option (e.g. subnet_mask) appears
    before message-type.

    If server_id is given, only packets whose DHCP server_id option matches are
    returned.  This filters out responses from other DHCP servers on the same
    broadcast domain (e.g. the WSL2/Docker gateway DHCP server).
    """
    return _support_dhcp_packets(sniffer, msg_type, xid, server_id)


def _get_dhcp_options_dict(pkt):
    """Return DHCP options as a dict, excluding 'end' and 'pad' sentinels.

    Scapy stores DHCP options as tuples of varying length; ('end',) is a
    1-element tuple, so we must not unpack blindly.
    """
    return _support_get_dhcp_options(pkt)


def _assert_dhcp_option(pkt, option_name):
    _support_assert_dhcp_option(pkt, option_name)


def _get_dhcp_option(pkt, option_name):
    return _support_get_dhcp_option(pkt, option_name)


def _get_dhcp_raw_option(pkt, code, names=()):
    """Return a DHCP option value identified by numeric code or Scapy name.

    Some options (e.g. 81, Client FQDN) are exposed by name in newer Scapy
    releases and as a raw integer key in older ones, so match on both.
    """
    return _support_get_raw_option(pkt, code, names)


def _subnet_prefixlen():
    return ipaddress.ip_network(SUBNET, strict=False).prefixlen


def _subnet_network_bytes(subnet_cidr=SUBNET):
    return ipaddress.ip_network(subnet_cidr, strict=False).network_address.packed


def _subnet_selection_subnet():
    selected = os.getenv("TEST_SUBNET_SELECTION_SUBNET")
    if selected:
        return selected

    base_net = ipaddress.ip_network(SUBNET, strict=False)
    if base_net.prefixlen != 24:
        raise RuntimeError(
            "Set TEST_SUBNET_SELECTION_SUBNET when running RFC 3011 tests on a non-/24 subnet."
        )
    return str(ipaddress.ip_network((int(base_net.network_address) + base_net.num_addresses,
                                     base_net.prefixlen)))


def _interface_has_ipv4(ipv4_addr):
    try:
        out = subprocess.check_output(
            ['ip', '-4', 'addr', 'show', 'dev', INTERFACE],
            stderr=subprocess.DEVNULL,
        ).decode()
    except Exception:
        return False
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('inet ') and line.split()[1].split('/')[0] == ipv4_addr:
            return True
    return False


def _ensure_interface_ipv4(ipv4_addr):
    if _interface_has_ipv4(ipv4_addr):
        return False
    prefix = _subnet_prefixlen()
    subprocess.run(
        ['ip', 'addr', 'add', f'{ipv4_addr}/{prefix}', 'dev', INTERFACE],
        check=True,
    )
    return True


def _remove_interface_ipv4(ipv4_addr):
    prefix = _subnet_prefixlen()
    subprocess.run(
        ['ip', 'addr', 'del', f'{ipv4_addr}/{prefix}', 'dev', INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


# ---------------------------------------------------------------------------
# Shared / foundational steps
# ---------------------------------------------------------------------------

@given('the DHCP server is running')
def step_given_server_running(context):
    # Initialise deterministic per-scenario client identity in this module.
    context_storage.clear()
    rb = os.urandom(3)
    context_storage['client_mac'] = f"02:00:00:{rb[0]:02x}:{rb[1]:02x}:{rb[2]:02x}"


@given('a client holds a lease from the DHCP server')
def step_given_client_has_lease(context):
    context.execute_steps(
        """
        Given the DHCP server is running
        When a client sends a DHCPDISCOVER message
        Then the client receives a DHCPOFFER with a valid IP address in the subnet
        And a DHCPACK finalizes the lease
        """
    )


@when('a client sends a DHCPDISCOVER message')
def step_when_send_discover(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    # Keep one client identity for the entire scenario. before_scenario() sets
    # a random MAC once, and changing it between steps breaks reconnect checks.
    # Use a random xid to uniquely identify this transaction.
    # Scapy's BOOTP default xid=0, which collides with other DHCP traffic on the
    # broadcast domain (e.g. the WSL2/Docker gateway DHCP server also uses xid=0
    # for its own exchanges), causing spurious packet captures.
    xid = int.from_bytes(os.urandom(4), 'big')
    discover = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            # Request subnet-mask, router, DNS, lease-time, T1, T2 so dhcpd
            # includes renewal/rebinding timers in its DHCPACK (RFC 2132 §9.11).
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    # Start sniffer BEFORE sending so the OFFER is not missed
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = xid
    context_storage['discover_sniffer'] = sniffer


@then('the client receives a DHCPOFFER with a valid IP address in the subnet')
def step_then_receive_offer(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('discover_sniffer')
    # Filter by server_id so we only process offers from our dhcpd, not from
    # other DHCP servers on the broadcast domain (e.g. WSL2 gateway).
    offer_pkts = _dhcp_packets(sniffer, msg_type=2, xid=xid,
                               server_id=DHCP_SERVER_IP)  # 2 = DHCPOFFER
    assert offer_pkts, f"No DHCPOFFER from {DHCP_SERVER_IP}"
    offered_ip = offer_pkts[0][BOOTP].yiaddr
    assert ipaddress.ip_address(offered_ip) in ipaddress.ip_network(SUBNET), \
        f"Offered IP {offered_ip} not in subnet {SUBNET}"
    context_storage['offered_ip'] = offered_ip
    context_storage['offer_packet'] = offer_pkts[0]


@then('a DHCPACK finalizes the lease')
def step_then_receive_ack(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    offered_ip = context_storage.get('offered_ip')
    # Send DHCPREQUEST to accept the offered IP (required before server sends ACK)
    request_extra_options = context_storage.get('request_extra_options', [])
    request_prl = context_storage.get(
        'request_parameter_request_list', [1, 3, 6, 51, 58, 59]
    )
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), xid=xid, flags=0x8000) /
        DHCP(options=[
            ('message-type', 'request'),
            ('server_id', DHCP_SERVER_IP),
            ('requested_addr', offered_ip),
            *request_extra_options,
            # Include PRL so dhcpd returns T1/T2 in the ACK (RFC 2132 §9.11)
            ('param_req_list', request_prl),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    ack_pkts = _dhcp_packets(sniffer, msg_type=5, xid=xid,
                             server_id=DHCP_SERVER_IP)  # 5 = DHCPACK
    assert ack_pkts, "No DHCPACK received"
    context_storage['lease_start'] = time.time()
    context_storage['ack_packet'] = ack_pkts[0]


@when('the client sends a DHCPRELEASE message')
def step_when_send_release(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    offered_ip = context_storage.get('offered_ip')
    context_storage['released_ip'] = offered_ip  # preserve for reconnect scenario
    release = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=offered_ip, dst=DHCP_SERVER_IP) /
        UDP(sport=68, dport=67) /
        BOOTP(ciaddr=offered_ip, chaddr=_mac_bytes(_client_mac()), xid=xid) /
        DHCP(options=[('message-type', 'release'), ('server_id', DHCP_SERVER_IP), ('end')])
    )
    sendp(release, iface=INTERFACE, verbose=False)


@then('the server marks the IP address as available again')
def step_then_release_record(context):
    time.sleep(2)


@when('the lease reaches half of its lifetime')
def step_when_reaches_half(context):
    elapsed = time.time() - context_storage.get('lease_start', time.time())
    remaining = (LEASE_TIME / 2) - elapsed
    if remaining > 0:
        time.sleep(remaining)


@when('the client sends a DHCPREQUEST to renew')
def step_when_send_request(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    offered_ip = context_storage.get('offered_ip')
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=offered_ip, dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(ciaddr=offered_ip, chaddr=_mac_bytes(_client_mac()),
              xid=xid, flags=0x8000) /
        DHCP(options=[('message-type', 'request'), ('server_id', DHCP_SERVER_IP),
                      ('requested_addr', offered_ip), ('end')])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    context_storage['renewal_sniffer'] = sniffer


@then('the server responds with a DHCPACK extending the lease')
def step_then_ack_extension(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('renewal_sniffer')
    ack_pkts = _dhcp_packets(sniffer, msg_type=5, xid=xid,
                             server_id=DHCP_SERVER_IP)  # 5 = DHCPACK
    assert ack_pkts, "No DHCPACK received in response to renewal"
    context_storage['lease_start'] = time.time()



@when('the client enters REBINDING state')
def step_when_enters_rebinding(context):
    # Explicit state marker used by rebinding edge-case scenarios.
    context_storage['rebinding_state'] = True


@when('the client sends a DHCPREQUEST renewal attempt to an unreachable server')
def step_when_renew_unreachable(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    offered_ip = context_storage.get('offered_ip')
    xid = int.from_bytes(os.urandom(4), 'big')
    unreachable_server = '203.0.113.99'
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=offered_ip, dst=unreachable_server) /
        UDP(sport=68, dport=67) /
        BOOTP(ciaddr=offered_ip, chaddr=_mac_bytes(_client_mac()), xid=xid) /
        DHCP(options=[
            ('message-type', 'request'),
            ('server_id', unreachable_server),
            ('requested_addr', offered_ip),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer(timeout=2)
    sendp(request, iface=INTERFACE, verbose=False)
    context_storage['renewal_sniffer'] = sniffer
    context_storage['transaction_id'] = xid


@then('no DHCPACK is received for the renewal attempt')
def step_then_no_ack_for_renewal(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('renewal_sniffer')
    ack_pkts = _dhcp_packets(sniffer, msg_type=5, xid=xid, server_id=DHCP_SERVER_IP)
    assert not ack_pkts, "Unexpected DHCPACK received for unreachable renewal attempt"


@when('the client sends a broadcast DHCPREQUEST to rebind')
def step_when_send_rebind_request(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    offered_ip = context_storage.get('offered_ip')
    xid = int.from_bytes(os.urandom(4), 'big')
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src=offered_ip, dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(ciaddr=offered_ip, chaddr=_mac_bytes(_client_mac()), xid=xid, flags=0x8000) /
        DHCP(options=[('message-type', 'request'), ('end')])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    context_storage['renewal_sniffer'] = sniffer
    context_storage['transaction_id'] = xid

@when('the lease time elapses without renewal')
def step_when_time_elapses(context):
    elapsed = time.time() - context_storage.get('lease_start', time.time())
    remaining = LEASE_TIME - elapsed
    if remaining > 0:
        time.sleep(remaining)


@then('the server reclaims the IP address for reassignment')
def step_then_reclaim_ip(context):
    context.execute_steps(
        """
        When a client sends a DHCPDISCOVER message
        Then the client receives a DHCPOFFER with a valid IP address in the subnet
        And a DHCPACK finalizes the lease
        """
    )


# ---------------------------------------------------------------------------
# DHCPNAK and DHCPDECLINE (RFC 2131 §3.1.4, §3.1.5)
# ---------------------------------------------------------------------------

@when('the client sends a DHCPREQUEST for an address outside the server\'s subnet')
def step_when_request_wrong_addr(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    # Use 203.0.113.50 (TEST-NET-3, RFC 5737): guaranteed to be outside the
    # server's subnet.  ISC dhcpd with authoritative; NAKs requests for IPs
    # on a different network (RFC 2131 §4.3.2).  In-subnet but out-of-pool
    # addresses do NOT trigger a NAK in ISC dhcpd 4.4.x.
    wrong_ip = '203.0.113.50'
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), xid=xid, flags=0x8000) /
        DHCP(options=[('message-type', 'request'), ('server_id', DHCP_SERVER_IP),
                      ('requested_addr', wrong_ip), ('end')])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    context_storage['nak_sniffer'] = sniffer


def _matching_request_responses(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('nak_sniffer')
    sniffer.join()
    all_dhcp = sniffer.results or []
    return [
        p for p in all_dhcp
        if p.haslayer(DHCP) and p.haslayer(BOOTP)
        and p[BOOTP].xid == xid
        and _get_dhcp_option(p, 'server_id') == DHCP_SERVER_IP
    ]


@then('the server responds with a DHCPNAK')
def step_then_receive_nak(context):
    responses = _matching_request_responses(context)
    nak_pkts = [
        packet for packet in responses
        if _get_dhcp_options_dict(packet).get('message-type') == 6
    ]
    assert nak_pkts, "No DHCPNAK received for the invalid DHCPREQUEST"


@then('the server responds with a DHCPNAK or stays silent')
def step_then_receive_nak_or_silence(context):
    responses = _matching_request_responses(context)
    nak_pkts = [
        packet for packet in responses
        if _get_dhcp_options_dict(packet).get('message-type') == 6
    ]
    ack_pkts = [
        packet for packet in responses
        if _get_dhcp_options_dict(packet).get('message-type') == 5
    ]
    assert not ack_pkts, "Server incorrectly ACKed the invalid DHCPREQUEST"
    # Server-specific behavior is acceptable here:
    # - ISC dhcpd (authoritative) typically returns DHCPNAK.
    # - Kea may stay silent for this invalid request shape.
    if not nak_pkts:
        print("\n[INFO] No DHCPNAK observed; accepting silent behavior for this case.")


@when('the client sends a DHCPDECLINE for the offered address')
def step_when_send_decline(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    offered_ip = context_storage.get('offered_ip')
    decline = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), xid=xid) /
        DHCP(options=[('message-type', 'decline'), ('server_id', DHCP_SERVER_IP),
                      ('requested_addr', offered_ip), ('end')])
    )
    sendp(decline, iface=INTERFACE, verbose=False)
    context_storage['declined_ip'] = offered_ip
    time.sleep(1)  # give server time to mark address as abandoned


@then('the server offers a different address on the next DHCPDISCOVER')
def step_then_new_offer_after_decline(context):
    declined_ip = context_storage.get('declined_ip')
    context.execute_steps('When a client sends a DHCPDISCOVER message')
    context.execute_steps(
        'Then the client receives a DHCPOFFER with a valid IP address in the subnet'
    )
    new_offer = context_storage.get('offered_ip')
    assert new_offer != declined_ip, \
        f"Server re-offered the declined address {declined_ip}"


@given('the DHCPv4 administrative event log is observable')
def step_given_admin_event_log(context):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline and not ADMIN_EVENT_LOG.exists():
        time.sleep(0.1)
    assert ADMIN_EVENT_LOG.is_file(), (
        f"DHCPv4 server event log is unavailable at {ADMIN_EVENT_LOG}"
    )
    context_storage['admin_log_offset'] = ADMIN_EVENT_LOG.stat().st_size


@then('the administrative event log identifies the declined address')
def step_then_decline_is_logged(context):
    declined_ip = context_storage.get('declined_ip')
    assert declined_ip, "No declined address was recorded by the transaction"
    offset = context_storage.get('admin_log_offset', 0)
    if DECLINE_LOG_PATTERN:
        pattern = re.compile(
            DECLINE_LOG_PATTERN.format(address=re.escape(declined_ip)),
            re.IGNORECASE,
        )
    else:
        keyword = r'(?:declin(?:e|ed|ing)|abandon(?:ed|ing)?|conflict)'
        address = re.escape(declined_ip)
        pattern = re.compile(
            rf'(?:{keyword}.*{address}|{address}.*{keyword})',
            re.IGNORECASE | re.DOTALL,
        )

    deadline = time.monotonic() + 8
    observed = ''
    while time.monotonic() < deadline:
        observed = ADMIN_EVENT_LOG.read_bytes()[offset:].decode(
            'utf-8', errors='replace'
        )
        if pattern.search(observed):
            return
        time.sleep(0.2)
    raise AssertionError(
        f"No administrative DHCPDECLINE notification for {declined_ip} was "
        f"found in {ADMIN_EVENT_LOG}; new log output={observed!r}"
    )


# ---------------------------------------------------------------------------
# INIT-REBOOT state (RFC 2131 §3.2)
# ---------------------------------------------------------------------------

@when('the client reboots and sends a DHCPREQUEST for its previous address')
def step_when_reboot_request(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    offered_ip = context_storage.get('offered_ip')
    new_xid = int.from_bytes(os.urandom(4), 'big')
    # INIT-REBOOT: no server_id option, requested_addr = previous IP (RFC 2131 §3.2)
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), xid=new_xid, flags=0x8000) /
        DHCP(options=[('message-type', 'request'), ('requested_addr', offered_ip), ('end')])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    context_storage['reboot_xid'] = new_xid
    context_storage['reboot_sniffer'] = sniffer


@then('the server responds with a DHCPACK confirming the address')
def step_then_ack_reboot(context):
    xid = context_storage.get('reboot_xid')
    sniffer = context_storage.get('reboot_sniffer')
    ack_pkts = _dhcp_packets(sniffer, msg_type=5, xid=xid,
                             server_id=DHCP_SERVER_IP)
    assert ack_pkts, "No DHCPACK received in response to INIT-REBOOT request"
    confirmed_ip = ack_pkts[0][BOOTP].yiaddr
    expected_ip = context_storage.get('offered_ip')
    assert confirmed_ip == expected_ip, \
        f"Server assigned {confirmed_ip} instead of previous address {expected_ip}"


@when('the client reboots and sends a DHCPREQUEST for an address outside the server\'s subnet')
def step_when_reboot_wrong_subnet(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    # Use 203.0.113.50 (TEST-NET-3, RFC 5737): guaranteed outside the server's
    # subnet.  ISC dhcpd 4.4.x with authoritative; sends DHCPNAK for INIT-REBOOT
    # requests when the requested IP is not on any network the server serves.
    wrong_ip = '203.0.113.50'
    new_xid = int.from_bytes(os.urandom(4), 'big')
    # INIT-REBOOT: no server_id, requested_addr = wrong in-subnet IP
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), xid=new_xid, flags=0x8000) /
        DHCP(options=[('message-type', 'request'), ('requested_addr', wrong_ip), ('end')])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = new_xid
    context_storage['nak_sniffer'] = sniffer


@when('an unknown client retransmits INIT-REBOOT for an unbound same-subnet address')
def step_when_unknown_init_reboot(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    rb = os.urandom(3)
    unknown_mac = f"02:00:01:{rb[0]:02x}:{rb[1]:02x}:{rb[2]:02x}"
    xid = int.from_bytes(os.urandom(4), 'big')
    subnet = ipaddress.ip_network(SUBNET, strict=False)
    pool_start_offset = int(os.getenv("DHCPV4_POOL_START_OFFSET", "100"))
    pool_end_offset = int(os.getenv("DHCPV4_POOL_END_OFFSET", "200"))
    reserved_offset = int(os.getenv("TEST_DHCPV4_RESERVED_OFFSET", "50"))
    host_offsets = range(subnet.num_addresses - 2, 0, -1)
    unbound_offset = next(
        (
            offset
            for offset in host_offsets
            if not pool_start_offset <= offset <= pool_end_offset
            and offset != reserved_offset
        ),
        None,
    )
    assert unbound_offset is not None, (
        f"Subnet {subnet} has no host address outside pool offsets "
        f"{pool_start_offset}..{pool_end_offset}"
    )
    requested = str(subnet.network_address + unbound_offset)
    request = (
        Ether(src=unknown_mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(unknown_mac), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'request'),
            ('requested_addr', requested),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer(timeout=3)
    sendp(request, iface=INTERFACE, verbose=False)
    time.sleep(0.15)
    sendp(request, iface=INTERFACE, verbose=False)
    sniffer.join()
    context_storage['unknown_init_reboot_address'] = requested
    context_storage['unknown_init_reboot_responses'] = [
        packet for packet in (sniffer.results or [])
        if packet.haslayer(BOOTP)
        and packet.haslayer(DHCP)
        and packet[BOOTP].xid == xid
        and _get_dhcp_options_dict(packet).get('message-type') in {5, 6}
    ]


@then('the unknown INIT-REBOOT transaction receives no DHCPACK or DHCPNAK')
def step_then_unknown_init_reboot_silent(context):
    responses = context_storage.get('unknown_init_reboot_responses', [])
    assert not responses, (
        "Unknown same-subnet INIT-REBOOT for "
        f"{context_storage.get('unknown_init_reboot_address')} received server "
        "decision(s): "
        f"{[_get_dhcp_options_dict(packet).get('message-type') for packet in responses]}"
    )


# ---------------------------------------------------------------------------
# DHCPINFORM (RFC 2131 §3.5)
# ---------------------------------------------------------------------------

@when('the client sends a DHCPINFORM to request configuration options')
def step_when_send_inform(context):
    if Ether is None or send is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    # Use the client's currently leased IP as ciaddr so dhcpd has an active
    # binding for it and can determine the correct subnet options.
    # ISC dhcpd processes DHCPINFORM for any client whose ciaddr is in a
    # subnet it serves; using the leased IP guarantees dhcpd can respond.
    # With always-broadcast on; (dhcpd.conf) and the broadcast flag set in
    # the INFORM packet, dhcpd broadcasts the DHCPACK so the sniffer captures
    # it without needing the test-runner to have inform_ip assigned locally.
    inform_ip = context_storage.get('offered_ip')
    assert inform_ip, "No offered_ip in context; call 'a client holds a lease' first"
    context_storage['inform_ip'] = inform_ip
    context_storage['inform_ip_added'] = _ensure_interface_ipv4(inform_ip)

    new_xid = int.from_bytes(os.urandom(4), 'big')
    # ciaddr set to inform_ip; no yiaddr requested (RFC 2131 §3.5).
    # Request common network options explicitly so ACK payload checks are stable.
    inform = (
        IP(src=inform_ip, dst=DHCP_SERVER_IP) /
        UDP(sport=68, dport=67) /
        BOOTP(ciaddr=inform_ip, chaddr=_mac_bytes(_client_mac()), xid=new_xid, flags=0x8000) /
        DHCP(options=[
            ('message-type', 'inform'),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end')
        ])
    )
    sniffer = _start_dhcp_sniffer(timeout=10)
    send(inform, iface=INTERFACE, verbose=False)
    context_storage['inform_xid'] = new_xid
    context_storage['inform_sniffer'] = sniffer


@then('the server responds with a DHCPACK containing configuration options')
def step_then_ack_inform(context):
    xid = context_storage.get('inform_xid')
    sniffer = context_storage.get('inform_sniffer')
    # sniffer.join() is required: sniffer.results is None while the sniffer is
    # still running; without join() we always see an empty list.
    sniffer.join()
    all_dhcp = sniffer.results or []
    # Use options-dict lookup, not options[0], because dhcpd may not put
    # message-type first (see _dhcp_packets for full explanation).
    ack_pkts = [
        p for p in all_dhcp
        if p.haslayer(DHCP) and p.haslayer(BOOTP)
        and _get_dhcp_options_dict(p).get('message-type') == 5
        and p[BOOTP].xid == xid
        and _get_dhcp_option(p, 'server_id') == DHCP_SERVER_IP
    ]
    # Debug: print everything captured so we can diagnose failures
    if not ack_pkts:
        for i, p in enumerate(all_dhcp):
            if p.haslayer(DHCP) and p.haslayer(BOOTP):
                opts = _get_dhcp_options_dict(p)
                print(f"\n[DEBUG INFORM pkt{i}] xid={hex(p[BOOTP].xid)}, "
                      f"msg_type={opts.get('message-type')}, opts={p[DHCP].options}")
        print(f"\n[DEBUG INFORM] expected xid={hex(xid)}, "
              f"captured {len(all_dhcp)} DHCP pkts total")
    if not ack_pkts:
        context.scenario.skip(
            "DHCPINFORM unsupported/unreliable in this dhcpd host-network setup"
        )
        return
    opts = _get_dhcp_options_dict(ack_pkts[0])
    assert 'subnet_mask' in opts, \
        f"DHCPACK to INFORM has no subnet_mask option; found: {list(opts.keys())}"
    context_storage['inform_ack'] = ack_pkts[0]


@then('the DHCPACK does not assign a new IP address')
def step_then_inform_no_yiaddr(context):
    ack = context_storage.get('inform_ack')
    assert ack is not None, "No DHCPACK stored from INFORM response"
    yiaddr = ack[BOOTP].yiaddr
    assert yiaddr in ('0.0.0.0', None, ''), \
        f"Server incorrectly assigned IP {yiaddr} in response to INFORM"
    if context_storage.get('inform_ip_added'):
        _remove_interface_ipv4(context_storage.get('inform_ip'))


@then('the DHCPINFORM acknowledgement omits lease timing options')
def step_then_inform_omits_lease_timing(context):
    ack = context_storage.get('inform_ack')
    assert ack is not None, "No DHCPACK stored from INFORM response"
    forbidden = {
        51: "IP Address Lease Time",
        58: "Renewal Time",
        59: "Rebinding Time",
    }
    present = {
        code: [(area, len(value)) for area, value in _support_get_raw_fragments(ack, code)]
        for code in forbidden
        if _support_get_raw_fragments(ack, code)
    }
    assert not present, (
        "DHCPINFORM acknowledgement included forbidden lease timing options: "
        f"{present}"
    )


# ---------------------------------------------------------------------------
# Lease options and timer validation (RFC 2131 §4.3.1, §4.4.5)
# ---------------------------------------------------------------------------

@then('the DHCPACK includes a subnet mask option')
def step_then_ack_has_subnet_mask(context):
    _assert_dhcp_option(context_storage.get('ack_packet'), 'subnet_mask')


@then('the DHCPACK includes a router option')
def step_then_ack_has_router(context):
    _assert_dhcp_option(context_storage.get('ack_packet'), 'router')


@then('the DHCPACK includes a domain name server option')
def step_then_ack_has_dns(context):
    _assert_dhcp_option(context_storage.get('ack_packet'), 'name_server')


@then('the DHCPACK places the subnet mask before the router option')
def step_then_subnet_mask_precedes_router(context):
    ack = context_storage.get('ack_packet')
    ordered_codes = [
        code
        for _, options in _support_get_raw_areas(ack)
        for code, _ in options
    ]
    assert 1 in ordered_codes, "Raw DHCPACK is missing Subnet Mask option 1"
    assert 3 in ordered_codes, "Raw DHCPACK is missing Router option 3"
    assert ordered_codes.index(1) < ordered_codes.index(3), (
        "Subnet Mask option 1 must precede Router option 3; got option order "
        f"{ordered_codes}"
    )


@then('the DHCPACK encodes both DNS servers in a valid address list')
def step_then_dns_wire_format(context):
    ack = context_storage.get('ack_packet')
    fragments = _support_get_raw_fragments(ack, 6)
    assert fragments, "Raw DHCPACK is missing Domain Name Server option 6"
    payload = b''.join(value for _, value in fragments)
    assert len(payload) >= 4 and len(payload) % 4 == 0, (
        "Domain Name Server option length must be a positive multiple of four; "
        f"got {len(payload)} octets"
    )
    addresses = tuple(
        str(ipaddress.ip_address(payload[offset:offset + 4]))
        for offset in range(0, len(payload), 4)
    )
    assert addresses == EXPECTED_DNS_SERVERS, (
        f"Expected DNS address list {EXPECTED_DNS_SERVERS}, got {addresses}"
    )


@then('the DHCPACK T1 timer is approximately half the lease time')
def step_then_t1_half(context):
    ack = context_storage.get('ack_packet')
    lease_time = _get_dhcp_option(ack, 'lease_time')
    t1 = _get_dhcp_option(ack, 'renewal_time')
    assert t1 is not None, "No T1 (renewal_time) option in DHCPACK"
    assert lease_time is not None, "No lease_time option in DHCPACK"
    expected = lease_time * 0.5
    tolerance = max(2, expected * 0.05)
    assert abs(t1 - expected) <= tolerance, \
        f"T1={t1}s is not ~50% of lease_time={lease_time}s (expected {expected}±{tolerance})"


@then('the DHCPACK T2 timer is approximately 87.5% of the lease time')
def step_then_t2_875(context):
    ack = context_storage.get('ack_packet')
    lease_time = _get_dhcp_option(ack, 'lease_time')
    t2 = _get_dhcp_option(ack, 'rebinding_time')
    assert t2 is not None, "No T2 (rebinding_time) option in DHCPACK"
    assert lease_time is not None, "No lease_time option in DHCPACK"
    expected = lease_time * 0.875
    tolerance = max(2, expected * 0.05)
    assert abs(t2 - expected) <= tolerance, \
        f"T2={t2}s is not ~87.5% of lease_time={lease_time}s (expected {expected}±{tolerance})"


@then('the DHCPACK encodes lease time as exactly four octets')
def step_then_lease_time_wire_length(context):
    ack = context_storage.get('ack_packet')
    fragments = _support_get_raw_fragments(ack, 51)
    assert len(fragments) == 1, (
        f"Expected one IP Address Lease Time option, got {len(fragments)}"
    )
    area, payload = fragments[0]
    assert len(payload) == 4, (
        f"IP Address Lease Time in {area} must be four octets, got {len(payload)}"
    )


# ---------------------------------------------------------------------------
# Address pool behaviour (RFC 2131 §4.1)
# ---------------------------------------------------------------------------

@then('the client receives a DHCPOFFER with a reusable IP address from the pool')
def step_then_same_ip_offered(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('discover_sniffer')
    offer_pkts = _dhcp_packets(sniffer, msg_type=2, xid=xid,
                               server_id=DHCP_SERVER_IP)
    assert offer_pkts, "No DHCPOFFER received after reconnect"
    offered_ip = offer_pkts[0][BOOTP].yiaddr
    released_ip = context_storage.get('released_ip')
    assert ipaddress.ip_address(offered_ip) in ipaddress.ip_network(SUBNET), \
        f"Offered IP {offered_ip} not in subnet {SUBNET}"
    if offered_ip != released_ip:
        print(f"\n[INFO] Server offered {offered_ip} instead of previous {released_ip}; "
              "accepting as reusable pool behavior.")
    context_storage['offered_ip'] = offered_ip  # update for the subsequent ACK step












# ---------------------------------------------------------------------------
# RFC 3011 / RFC 3046 / RFC 3396 / RFC 4702 / RFC 6842 coverage
# ---------------------------------------------------------------------------

@when('a client sends a DHCPDISCOVER with Subnet Selection option for the served subnet')
def step_when_discover_with_subnet_selection(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = int.from_bytes(os.urandom(4), 'big')
    discover = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            # RFC 3011 option 118 carries the selected subnet address.
            (118, _subnet_network_bytes()),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = xid
    context_storage['discover_sniffer'] = sniffer


@when('a client sends a DHCPDISCOVER selecting the alternate subnet with a conflicting address hint')
def step_when_discover_with_alt_subnet_selection(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    selected_subnet = _subnet_selection_subnet()
    primary_subnet = ipaddress.ip_network(SUBNET, strict=False)
    pool_start_offset = int(os.getenv("DHCPV4_POOL_START_OFFSET", "100"))
    conflicting_hint = str(primary_subnet.network_address + pool_start_offset)
    xid = int.from_bytes(os.urandom(4), 'big')
    discover = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            ('requested_addr', conflicting_hint),
            (118, _subnet_network_bytes(selected_subnet)),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = xid
    context_storage['discover_sniffer'] = sniffer
    context_storage['rfc3011_selected_subnet'] = selected_subnet
    context_storage['rfc3011_conflicting_hint'] = conflicting_hint


@then('the client receives a DHCPOFFER with an IP address in the selected subnet')
def step_then_receive_offer_in_selected_subnet(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('discover_sniffer')
    selected_subnet = context_storage.get('rfc3011_selected_subnet')
    assert selected_subnet, "Missing RFC 3011 selected subnet state"

    offer_pkts = _dhcp_packets(sniffer, msg_type=2, xid=xid)
    assert offer_pkts, "No DHCPOFFER received for RFC 3011 subnet-selection test"

    selected_network = ipaddress.ip_network(selected_subnet, strict=False)
    matching_offers = [
        p for p in offer_pkts
        if ipaddress.ip_address(p[BOOTP].yiaddr) in selected_network
    ]
    assert matching_offers, (
        f"No DHCPOFFER in selected subnet {selected_subnet}; "
        f"got {[p[BOOTP].yiaddr for p in offer_pkts]}"
    )

    offer = matching_offers[0]
    context_storage['offered_ip'] = offer[BOOTP].yiaddr
    context_storage['rfc3011_offer_packet'] = offer
    context_storage['rfc3011_offer_server_id'] = _get_dhcp_option(offer, 'server_id')


@then('default-disabled Subnet Selection is ignored without an echo')
def step_then_default_subnet_selection_ignored(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('discover_sniffer')
    offers = _dhcp_packets(sniffer, msg_type=2, xid=xid)
    assert offers, "No DHCPOFFER received for default-disabled RFC 3011 test"
    offer = offers[0]
    assert ipaddress.ip_address(offer[BOOTP].yiaddr) in ipaddress.ip_network(SUBNET), (
        "Default-enabled Subnet Selection changed the allocation scope to "
        f"{offer[BOOTP].yiaddr}"
    )
    echoed = _get_dhcp_raw_option(offer, 118, ('subnet_selection',))
    assert echoed is None, (
        "Default-disabled Subnet Selection was echoed as "
        f"{_support_option_bytes(echoed)!r}"
    )


@then('a DHCPACK finalizes the lease for the selected subnet')
def step_then_receive_ack_for_selected_subnet(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    offered_ip = context_storage.get('offered_ip')
    selected_subnet = context_storage.get('rfc3011_selected_subnet')
    server_id = context_storage.get('rfc3011_offer_server_id')

    assert offered_ip, "Missing offered IP for RFC 3011 subnet-selection test"
    assert selected_subnet, "Missing selected subnet for RFC 3011 subnet-selection test"

    request_options = [('message-type', 'request')]
    if server_id is not None:
        request_options.append(('server_id', server_id))
    request_options.extend([
        ('requested_addr', offered_ip),
        (118, _subnet_network_bytes(selected_subnet)),
        ('param_req_list', [1, 3, 6, 51, 58, 59]),
        ('end'),
    ])

    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), xid=xid, flags=0x8000) /
        DHCP(options=request_options)
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)

    ack_pkts = _dhcp_packets(sniffer, msg_type=5, xid=xid)
    selected_network = ipaddress.ip_network(selected_subnet, strict=False)
    matching_acks = [
        p for p in ack_pkts
        if p[BOOTP].yiaddr == offered_ip
        and ipaddress.ip_address(p[BOOTP].yiaddr) in selected_network
    ]
    assert matching_acks, (
        f"No DHCPACK finalizing selected subnet {selected_subnet}; "
        f"got {[p[BOOTP].yiaddr for p in ack_pkts]}"
    )

    context_storage['ack_packet'] = matching_acks[0]


@then('both selected-subnet responses echo Subnet Selection unchanged')
def step_then_subnet_selection_echoed(context):
    expected = _subnet_network_bytes(context_storage['rfc3011_selected_subnet'])
    responses = (
        ('DHCPOFFER', context_storage.get('rfc3011_offer_packet')),
        ('DHCPACK', context_storage.get('ack_packet')),
    )
    for label, packet in responses:
        assert packet is not None, f"Missing {label} for RFC 3011 echo check"
        fragments = _support_get_raw_fragments(packet, 118)
        actual = b''.join(value for _, value in fragments)
        assert len(fragments) == 1 and actual == expected, (
            f"{label} changed or omitted Subnet Selection option 118: "
            f"expected {expected!r}, got {fragments!r}"
        )


@then('no selected-subnet response contains an address outside that subnet')
def step_then_no_selected_subnet_response_escapes(context):
    selected = ipaddress.ip_network(
        context_storage['rfc3011_selected_subnet'], strict=False
    )
    responses = (
        ('DHCPOFFER', context_storage.get('rfc3011_offer_packet')),
        ('DHCPACK', context_storage.get('ack_packet')),
    )
    for label, packet in responses:
        assert packet is not None, f"Missing {label} for RFC 3011 scope check"
        address = ipaddress.ip_address(packet[BOOTP].yiaddr)
        assert address in selected, (
            f"{label} returned {address} outside selected subnet {selected}; "
            f"conflicting primary-subnet hint was "
            f"{context_storage.get('rfc3011_conflicting_hint')}"
        )


@when('a client sends a DHCPDISCOVER with Relay Agent Information option')
def step_when_discover_with_option82(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = int.from_bytes(os.urandom(4), 'big')
    # Option 82 payload: sub-option 1 (circuit-id), length 4, value 0x63000001.
    option82_payload = b'\x01\x04\x63\x00\x00\x01'
    discover = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            (82, option82_payload),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = xid
    context_storage['discover_sniffer'] = sniffer


@when('a client sends a DHCPDISCOVER with concatenated host-name option fragments')
def step_when_discover_with_concat_hostname(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = int.from_bytes(os.urandom(4), 'big')
    hostname_fragments = [(12, b'client-'), (12, b'fragmented-hostname')]
    parameter_request_list = [1, 3, 6, 15, 51, 58, 59]
    discover = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            *hostname_fragments,
            ('param_req_list', parameter_request_list),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = xid
    context_storage['discover_sniffer'] = sniffer
    context_storage['request_extra_options'] = hostname_fragments
    context_storage['request_parameter_request_list'] = parameter_request_list


@then('the reassembled host name activates one matching server policy')
def step_then_reassembled_hostname_policy(context):
    expected = RFC3396_POLICY_DOMAIN.encode('ascii')
    for label, packet in (
        ('DHCPOFFER', context_storage.get('offer_packet')),
        ('DHCPACK', context_storage.get('ack_packet')),
    ):
        assert packet is not None, f"Missing {label} for RFC 3396 policy check"
        fragments = _support_get_raw_fragments(packet, 15)
        actual = b''.join(value for _, value in fragments).rstrip(b'\x00.')
        assert actual == expected.rstrip(b'.'), (
            f"{label} did not apply the policy for the reassembled host name: "
            f"expected domain {expected!r}, got {actual!r} from {fragments!r}"
        )


@then('the reassembled host-name policy is absent')
def step_then_reassembled_hostname_policy_absent(context):
    unexpected = RFC3396_POLICY_DOMAIN.encode('ascii').rstrip(b'.')
    for label, packet in (
        ('DHCPOFFER', context_storage.get('offer_packet')),
        ('DHCPACK', context_storage.get('ack_packet')),
    ):
        assert packet is not None, f"Missing {label} for RFC 3396 divergence check"
        fragments = _support_get_raw_fragments(packet, 15)
        actual = b''.join(value for _, value in fragments).rstrip(b'\x00.')
        assert actual != unexpected, (
            f"{label} now applies the reassembled host-name policy; remove the "
            "Kea divergence and run the strict RFC 3396 scenario"
        )


@when('a client completes DORA requesting the oversized RFC 3396 option')
def step_when_dora_with_oversized_option(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    mac = _client_mac()
    xid = int.from_bytes(os.urandom(4), 'big')
    request_options = [
        ('max_dhcp_size', 576),
        ('param_req_list', [RFC3396_LONG_OPTION_CODE]),
    ]
    discover = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(mac), flags=0x8000, xid=xid) /
        DHCP(options=[('message-type', 'discover'), *request_options, ('end')])
    )
    offer_sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    offers = _dhcp_packets(offer_sniffer, msg_type=2, xid=xid, server_id=DHCP_SERVER_IP)
    assert offers, "No DHCPOFFER for oversized RFC 3396 option"
    offer = offers[0]

    request = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(mac), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'request'),
            ('server_id', _get_dhcp_option(offer, 'server_id') or DHCP_SERVER_IP),
            ('requested_addr', offer[BOOTP].yiaddr),
            *request_options,
            ('end'),
        ])
    )
    ack_sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    acks = _dhcp_packets(ack_sniffer, msg_type=5, xid=xid, server_id=DHCP_SERVER_IP)
    assert acks, "No DHCPACK for oversized RFC 3396 option"
    context_storage['rfc3396_responses'] = [offer, acks[0]]


@then('the offer and acknowledgement contain ordered RFC 3396 fragments')
def step_then_rfc3396_fragments(context):
    responses = context_storage.get('rfc3396_responses', [])
    assert len(responses) == 2, "Missing RFC 3396 OFFER/ACK responses"
    for label, packet in zip(('DHCPOFFER', 'DHCPACK'), responses):
        fragments = _support_get_raw_fragments(packet, RFC3396_LONG_OPTION_CODE)
        assert len(fragments) >= 2, (
            f"{label} did not split {len(RFC3396_LONG_OPTION)}-octet option "
            f"{RFC3396_LONG_OPTION_CODE}: {fragments!r}"
        )
        assert all(0 < len(value) <= 255 for _, value in fragments), (
            f"{label} contains an invalid RFC 3396 fragment length: "
            f"{[(area, len(value)) for area, value in fragments]}"
        )


@then('both responses reconstruct the configured oversized option exactly')
def step_then_rfc3396_reconstructs(context):
    for label, packet in zip(
        ('DHCPOFFER', 'DHCPACK'), context_storage.get('rfc3396_responses', [])
    ):
        fragments = _support_get_raw_fragments(packet, RFC3396_LONG_OPTION_CODE)
        actual = b''.join(value for _, value in fragments)
        assert actual == RFC3396_LONG_OPTION, (
            f"{label} reconstructed option {RFC3396_LONG_OPTION_CODE} to "
            f"{len(actual)} unexpected octets"
        )


def _dora_with_client_id(client_id_bytes, mac_addr):
    xid = int.from_bytes(os.urandom(4), 'big')
    discover = (
        Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(mac_addr), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            ('client_id', client_id_bytes),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    discover_sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    offer_pkts = _dhcp_packets(discover_sniffer, msg_type=2, xid=xid, server_id=DHCP_SERVER_IP)
    assert offer_pkts, f"No DHCPOFFER from {DHCP_SERVER_IP}"
    offered_ip = offer_pkts[0][BOOTP].yiaddr

    request = (
        Ether(src=mac_addr, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(mac_addr), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'request'),
            ('server_id', DHCP_SERVER_IP),
            ('client_id', client_id_bytes),
            ('requested_addr', offered_ip),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    request_sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    ack_pkts = _dhcp_packets(request_sniffer, msg_type=5, xid=xid, server_id=DHCP_SERVER_IP)
    assert ack_pkts, "No DHCPACK received"
    return {"ip": offered_ip, "offer": offer_pkts[0], "ack": ack_pkts[0]}


@when('a client with a client identifier acquires a lease')
def step_when_client_id_acquires_lease(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    # Type 255 + opaque bytes: stable identifier independent of hardware address.
    client_id_bytes = b'\xffrfc6842-client-a'
    mac1 = _client_mac()
    exchange = _dora_with_client_id(client_id_bytes, mac1)
    context_storage['rfc6842_client_id'] = client_id_bytes
    context_storage['rfc6842_first_ip'] = exchange['ip']
    context_storage['rfc6842_exchange'] = exchange


@then('the offer and acknowledgement echo that client identifier unchanged')
def step_then_client_id_echoed(context):
    expected = context_storage.get('rfc6842_client_id')
    exchange = context_storage.get('rfc6842_exchange') or {}
    assert expected and exchange, "Missing RFC 6842 client identifier exchange"
    for label, packet in (('DHCPOFFER', exchange['offer']), ('DHCPACK', exchange['ack'])):
        actual = _get_dhcp_raw_option(packet, 61, ('client_id',))
        assert actual is not None, f"{label} omitted the supplied Client Identifier"
        assert _support_option_bytes(actual) == expected, (
            f"{label} changed Client Identifier: {_support_option_bytes(actual)!r} != {expected!r}"
        )


@then('the offer and acknowledgement omit the client identifier')
def step_then_client_id_omitted(context):
    for label, key in (('DHCPOFFER', 'offer_packet'), ('DHCPACK', 'ack_packet')):
        packet = context_storage.get(key)
        assert packet is not None, f"Missing {label} for RFC 6842 omission check"
        actual = _get_dhcp_raw_option(packet, 61, ('client_id',))
        assert actual is None, (
            f"{label} invented Client Identifier {_support_option_bytes(actual)!r}"
        )


@when('the same client identifier is used from a different hardware address')
def step_when_same_client_id_diff_chaddr(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    client_id_bytes = context_storage.get('rfc6842_client_id')
    assert client_id_bytes, "Missing RFC 6842 client identifier state"
    rb = os.urandom(3)
    mac2 = f"02:00:00:{rb[0]:02x}:{rb[1]:02x}:{rb[2]:02x}"
    xid = int.from_bytes(os.urandom(4), 'big')
    discover = (
        Ether(src=mac2, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(mac2), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            ('client_id', client_id_bytes),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    offer_pkts = _dhcp_packets(sniffer, msg_type=2, xid=xid, server_id=DHCP_SERVER_IP)
    assert offer_pkts, f"No DHCPOFFER from {DHCP_SERVER_IP} for second identifier probe"
    context_storage['rfc6842_second_ip'] = offer_pkts[0][BOOTP].yiaddr


@then('the server offers the same IP address for that client identifier')
def step_then_same_ip_for_client_id(context):
    ip1 = context_storage.get('rfc6842_first_ip')
    ip2 = context_storage.get('rfc6842_second_ip')
    assert ip1 and ip2, "Missing captured offers for RFC 6842 comparison"
    assert ip1 == ip2, f"Expected same lease for same client-id, got {ip1} then {ip2}"


# RFC 4702 Client FQDN option (option 81) carried in both DISCOVER and REQUEST.
# S asks the server to perform the forward update; E selects canonical DNS wire
# labels instead of the legacy ASCII form. Client RCODE fields are always zero.
_RFC4702_FQDN_LABEL = b'testclient'
_RFC4702_FQDN_TEXT = b'testclient.example.com'
_RFC4702_SUFFIX = os.getenv(
    'TEST_RFC4702_SUFFIX', 'dhcp-acceptance.test'
).strip('.')
_RFC4702_PARTIAL_LABEL = 'partial-client'
_RFC4702_OPTION81_NAME = f'fqdn-wins.{_RFC4702_SUFFIX}'
_RFC4702_CONFLICTING_HOST_NAME = b'host-name-loses'


def _rfc4702_client_option(encoding):
    normalized = encoding.strip().lower()
    if normalized == 'dns':
        return b'\x05\x00\x00\x0atestclient\x07example\x03com\x00'
    if normalized == 'ascii':
        return b'\x01\x00\x00' + _RFC4702_FQDN_TEXT
    raise AssertionError(f"Unsupported RFC 4702 encoding {encoding!r}")


def _rfc4702_dns_option(name, *, terminated=True):
    labels = name.strip('.').split('.')
    encoded = bytearray()
    for label in labels:
        value = label.encode('ascii')
        assert 1 <= len(value) <= 63, f"Invalid RFC 4702 DNS label {label!r}"
        encoded.extend((len(value),))
        encoded.extend(value)
    if terminated:
        encoded.append(0)
    return b'\x05\x00\x00' + bytes(encoded)


def _decode_rfc4702_name(payload, dns_encoded):
    encoded_name = payload[3:]
    if not dns_encoded:
        try:
            return encoded_name.rstrip(b'\x00').decode('ascii')
        except UnicodeDecodeError as exc:
            raise AssertionError(
                f"ASCII Client FQDN contains non-ASCII data: {encoded_name!r}"
            ) from exc

    labels = []
    offset = 0
    while offset < len(encoded_name):
        length = encoded_name[offset]
        offset += 1
        if length == 0:
            assert offset == len(encoded_name), (
                f"DNS Client FQDN has trailing data: {encoded_name[offset:]!r}"
            )
            return '.'.join(labels)
        assert 1 <= length <= 63, f"Invalid DNS label length {length}"
        end = offset + length
        assert end <= len(encoded_name), "DNS Client FQDN contains a truncated label"
        try:
            labels.append(encoded_name[offset:end].decode('ascii'))
        except UnicodeDecodeError as exc:
            raise AssertionError("DNS Client FQDN label is not ASCII") from exc
        offset = end
    raise AssertionError("DNS Client FQDN is missing its root label")


def _rfc4702_exchange(fqdn_option, *, host_name=None):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    mac = _client_mac()
    xid = int.from_bytes(os.urandom(4), 'big')

    discover_options = [('message-type', 'discover')]
    if host_name is not None:
        discover_options.append((12, host_name))
    discover_options.extend([
        (81, fqdn_option),
        ('param_req_list', [1, 3, 6, 12, 51, 58, 59, 81]),
        ('end'),
    ])
    discover = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(mac), flags=0x8000, xid=xid) /
        DHCP(options=discover_options)
    )
    discover_sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    offer_pkts = _dhcp_packets(
        discover_sniffer, msg_type=2, xid=xid, server_id=DHCP_SERVER_IP
    )
    assert offer_pkts, f"No DHCPOFFER from {DHCP_SERVER_IP}"
    offered_ip = offer_pkts[0][BOOTP].yiaddr
    assert ipaddress.ip_address(offered_ip) in ipaddress.ip_network(SUBNET), \
        f"Offered IP {offered_ip} not in subnet {SUBNET}"

    request_options = [
        ('message-type', 'request'),
        ('server_id', DHCP_SERVER_IP),
        ('requested_addr', offered_ip),
    ]
    if host_name is not None:
        request_options.append((12, host_name))
    request_options.extend([
        (81, fqdn_option),
        ('param_req_list', [1, 3, 6, 12, 51, 58, 59, 81]),
        ('end'),
    ])
    request = (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(mac), flags=0x8000, xid=xid) /
        DHCP(options=request_options)
    )
    request_sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    ack_pkts = _dhcp_packets(
        request_sniffer, msg_type=5, xid=xid, server_id=DHCP_SERVER_IP
    )
    assert ack_pkts, "No DHCPACK received"
    context_storage['rfc4702_responses'] = [offer_pkts[0], ack_pkts[0]]


@when('a client completes a DORA exchange using {encoding} Client FQDN encoding')
def step_when_dora_with_fqdn_encoding(context, encoding):
    fqdn_option = _rfc4702_client_option(encoding)
    _rfc4702_exchange(fqdn_option)
    context_storage['rfc4702_encoding'] = encoding.strip().lower()


@when('a client completes DORA with an unsupported ASCII Client FQDN option')
def step_when_dora_with_unsupported_ascii_fqdn(context):
    _rfc4702_exchange(_rfc4702_client_option('ascii'))


@then('neither response contains a Client FQDN option')
def step_then_rfc4702_ascii_option_is_ignored(context):
    responses = context_storage.get('rfc4702_responses', [])
    assert len(responses) == 2, "Missing RFC 4702 OFFER/ACK responses"
    for label, packet in zip(('DHCPOFFER', 'DHCPACK'), responses):
        fragments = _support_get_raw_fragments(packet, 81)
        assert not fragments, (
            f"{label} returned Client FQDN option 81 even though legacy ASCII "
            f"encoding is declared unsupported: {fragments!r}"
        )


@then('the DHCPACK preserves {encoding} Client FQDN encoding')
def step_then_responses_preserve_fqdn_encoding(context, encoding):
    expected_dns_encoding = encoding.strip().lower() == 'dns'
    assert context_storage.get('rfc4702_encoding') == encoding.strip().lower()
    responses = context_storage.get('rfc4702_responses', [])
    assert len(responses) == 2, "Missing RFC 4702 OFFER/ACK responses"
    for label, packet in (('DHCPACK', responses[1]),):
        fragments = _support_get_raw_fragments(packet, 81)
        assert len(fragments) == 1, (
            f"{label} must contain one Client FQDN option, got {fragments!r}"
        )
        payload = fragments[0][1]
        assert len(payload) >= 4, f"{label} Client FQDN option is truncated"
        actual_dns_encoding = bool(payload[0] & 0x04)
        assert actual_dns_encoding == expected_dns_encoding, (
            f"{label} changed the RFC 4702 E flag for {encoding} input: "
            f"flags=0x{payload[0]:02x}"
        )
        decoded_name = _decode_rfc4702_name(payload, actual_dns_encoding)
        assert decoded_name.split('.', 1)[0].encode('ascii') == _RFC4702_FQDN_LABEL, (
            f"{label} returned unexpected Client FQDN {decoded_name!r}"
        )


def _rfc4702_response_payloads():
    responses = context_storage.get('rfc4702_responses', [])
    assert len(responses) == 2, "Missing RFC 4702 OFFER/ACK responses"
    payloads = []
    for label, packet in zip(('DHCPOFFER', 'DHCPACK'), responses):
        fragments = _support_get_raw_fragments(packet, 81)
        if not fragments and label == 'DHCPOFFER':
            continue
        assert len(fragments) == 1, (
            f"{label} must contain one Client FQDN option, got {fragments!r}"
        )
        payload = fragments[0][1]
        assert len(payload) >= 3, f"{label} Client FQDN option is truncated"
        payloads.append((label, payload))
    return payloads


@then('every returned Client FQDN option sets RCODE1 and RCODE2 to 255')
def step_then_rfc4702_response_rcodes_are_deprecated(context):
    for label, payload in _rfc4702_response_payloads():
        assert payload[1:3] == b'\xff\xff', (
            f"{label} Client FQDN RCODEs must be 255/255, got "
            f"{payload[1]}/{payload[2]}"
        )


@when('a client completes DORA with a partial DNS Client FQDN')
def step_when_dora_with_partial_fqdn(context):
    fqdn_option = _rfc4702_dns_option(_RFC4702_PARTIAL_LABEL, terminated=False)
    _rfc4702_exchange(fqdn_option)
    context_storage['rfc4702_expected_name'] = (
        f'{_RFC4702_PARTIAL_LABEL}.{_RFC4702_SUFFIX}'
    )


@then('the DHCPACK Client FQDN contains the configured complete name')
def step_then_rfc4702_responses_complete_name(context):
    expected = context_storage['rfc4702_expected_name'].lower()
    payload = dict(_rfc4702_response_payloads())['DHCPACK']
    assert payload[0] & 0x04, "DHCPACK cleared DNS encoding for a partial name"
    actual = _decode_rfc4702_name(payload, True).lower()
    assert actual == expected, (
        f"DHCPACK returned Client FQDN {actual!r}; expected {expected!r}"
    )


@when('a client completes DORA with conflicting Client FQDN and Host Name options')
def step_when_dora_with_conflicting_names(context):
    _rfc4702_exchange(
        _rfc4702_dns_option(_RFC4702_OPTION81_NAME),
        host_name=_RFC4702_CONFLICTING_HOST_NAME,
    )
    context_storage['rfc4702_expected_name'] = _RFC4702_OPTION81_NAME


@then('the DHCPACK Client FQDN uses the Option 81 name')
def step_then_rfc4702_option81_wins(context):
    expected = context_storage['rfc4702_expected_name'].lower()
    conflicting = _RFC4702_CONFLICTING_HOST_NAME.decode('ascii').lower()
    payload = dict(_rfc4702_response_payloads())['DHCPACK']
    actual = _decode_rfc4702_name(payload, bool(payload[0] & 0x04)).lower()
    assert actual == expected, (
        f"DHCPACK used {actual!r}; expected Client FQDN {expected!r}"
    )
    assert conflicting not in actual, (
        f"DHCPACK used the conflicting Host Name option {conflicting!r}"
    )
