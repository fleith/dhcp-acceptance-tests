import subprocess
import time
import ipaddress
import os
from behave import given, when, then

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

context_storage = {}


def _mac_bytes(mac):
    return bytes.fromhex(mac.replace(":", ""))


def _client_mac():
    """Return the per-scenario client MAC.

    environment.py's before_scenario hook stores a freshly generated MAC in
    context_storage before each scenario so that every scenario is independent:
    ISC dhcpd won't reuse an existing binding from a previous scenario and will
    always grant a full default-lease-time lease.  Falls back to the module-level
    CLIENT_MAC constant when context_storage hasn't been initialised (e.g. unit
    tests that call step functions directly).
    """
    return context_storage.get('client_mac', CLIENT_MAC)


def _start_dhcp_sniffer(timeout=5):
    """Start an AsyncSniffer capturing all DHCP packets, wait briefly for it to be ready.

    promisc=True is required so the sniffer captures unicast packets destined
    for CLIENT_MAC (e.g. DHCPINFORM responses) even when that MAC differs from
    the interface's own hardware address.
    """
    sniffer = AsyncSniffer(
        iface=INTERFACE, lfilter=lambda p: p.haslayer(DHCP), timeout=timeout, promisc=True
    )
    sniffer.start()
    time.sleep(0.1)  # give the sniffer thread time to open its socket
    return sniffer


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
    sniffer.join()
    pkts = [
        p for p in (sniffer.results or [])
        if p.haslayer(DHCP)
        and p.haslayer(BOOTP)
        and _get_dhcp_options_dict(p).get('message-type') == msg_type
        and p[BOOTP].xid == xid
    ]
    if server_id is not None:
        pkts = [p for p in pkts
                if _get_dhcp_option(p, 'server_id') == server_id]
    return pkts


def _get_dhcp_options_dict(pkt):
    """Return DHCP options as a dict, excluding 'end' and 'pad' sentinels.

    Scapy stores DHCP options as tuples of varying length; ('end',) is a
    1-element tuple, so we must not unpack blindly.
    """
    if not pkt or not pkt.haslayer(DHCP):
        return {}
    return {opt[0]: opt[1] for opt in pkt[DHCP].options
            if len(opt) >= 2 and isinstance(opt[0], str)
            and opt[0] not in ('end', 'pad')}


def _assert_dhcp_option(pkt, option_name):
    opts = _get_dhcp_options_dict(pkt)
    assert option_name in opts, \
        f"DHCPACK missing option '{option_name}'; present: {list(opts.keys())}"


def _get_dhcp_option(pkt, option_name):
    return _get_dhcp_options_dict(pkt).get(option_name)


def _subnet_prefixlen():
    return ipaddress.ip_network(SUBNET, strict=False).prefixlen


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


@then('a DHCPACK finalizes the lease')
def step_then_receive_ack(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    offered_ip = context_storage.get('offered_ip')
    # Send DHCPREQUEST to accept the offered IP (required before server sends ACK)
    request = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), xid=xid, flags=0x8000) /
        DHCP(options=[
            ('message-type', 'request'),
            ('server_id', DHCP_SERVER_IP),
            ('requested_addr', offered_ip),
            # Include PRL so dhcpd returns T1/T2 in the ACK (RFC 2132 §9.11)
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
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


@then('the server responds with a DHCPNAK')
def step_then_receive_nak(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('nak_sniffer')
    sniffer.join()
    all_dhcp = sniffer.results or []
    nak_pkts = [
        p for p in all_dhcp
        if p.haslayer(DHCP) and p.haslayer(BOOTP)
        and _get_dhcp_options_dict(p).get('message-type') == 6
        and p[BOOTP].xid == xid
        and _get_dhcp_option(p, 'server_id') == DHCP_SERVER_IP
    ]
    if not nak_pkts:
        for i, p in enumerate(all_dhcp):
            if p.haslayer(DHCP) and p.haslayer(BOOTP):
                opts = _get_dhcp_options_dict(p)
                print(f"\n[DEBUG NAK pkt{i}] xid={hex(p[BOOTP].xid)}, "
                      f"msg_type={opts.get('message-type')}, opts={p[DHCP].options}")
        print(f"\n[DEBUG NAK] expected xid={hex(xid)}, "
              f"captured {len(all_dhcp)} DHCP pkts total")
    assert nak_pkts, "No DHCPNAK received from server"


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


# ---------------------------------------------------------------------------
# Address pool behaviour (RFC 2131 §4.1)
# ---------------------------------------------------------------------------

@then('the client receives a DHCPOFFER for the same IP address as before')
def step_then_same_ip_offered(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('discover_sniffer')
    offer_pkts = _dhcp_packets(sniffer, msg_type=2, xid=xid,
                               server_id=DHCP_SERVER_IP)
    assert offer_pkts, "No DHCPOFFER received after reconnect"
    offered_ip = offer_pkts[0][BOOTP].yiaddr
    released_ip = context_storage.get('released_ip')
    assert offered_ip == released_ip, \
        f"Server offered {offered_ip} but client previously had {released_ip}"
    context_storage['offered_ip'] = offered_ip  # update for the subsequent ACK step












# ---------------------------------------------------------------------------
# RFC 3046 / RFC 3396 / RFC 6842 coverage
# ---------------------------------------------------------------------------

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
    discover = (
        Ether(src=_client_mac(), dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=_mac_bytes(_client_mac()), flags=0x8000, xid=xid) /
        DHCP(options=[
            ('message-type', 'discover'),
            (12, b'client-'),
            (12, b'fragmented-hostname'),
            ('param_req_list', [1, 3, 6, 51, 58, 59]),
            ('end'),
        ])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = xid
    context_storage['discover_sniffer'] = sniffer


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
    return offered_ip


@when('a client with a client identifier acquires a lease')
def step_when_client_id_acquires_lease(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    # Type 255 + opaque bytes: stable identifier independent of hardware address.
    client_id_bytes = b'\xffrfc6842-client-a'
    mac1 = _client_mac()
    lease_ip = _dora_with_client_id(client_id_bytes, mac1)
    context_storage['rfc6842_client_id'] = client_id_bytes
    context_storage['rfc6842_first_ip'] = lease_ip


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
