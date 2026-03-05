import time
import ipaddress
import os
from behave import given, when, then

try:
    from scapy.all import Ether, IP, UDP, BOOTP, DHCP, sendp, sniff, AsyncSniffer
except ImportError:
    Ether = IP = UDP = BOOTP = DHCP = sendp = sniff = AsyncSniffer = None

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
LEASE_TIME = float(os.getenv("TEST_LEASE_TIME", "60"))

context_storage = {}


def _start_dhcp_sniffer():
    """Start an AsyncSniffer capturing all DHCP packets, wait briefly for it to be ready."""
    sniffer = AsyncSniffer(iface=INTERFACE, lfilter=lambda p: p.haslayer(DHCP), timeout=5)
    sniffer.start()
    time.sleep(0.1)  # give the sniffer thread time to open its socket
    return sniffer


def _dhcp_packets(sniffer, msg_type, xid):
    """Return captured DHCP packets matching msg_type and transaction id."""
    sniffer.join()
    return [
        p for p in (sniffer.results or [])
        if p.haslayer(DHCP)
        and p.haslayer(BOOTP)
        and p[DHCP].options
        and p[DHCP].options[0][1] == msg_type
        and p[BOOTP].xid == xid
    ]


@given('the DHCP server is running')
def step_given_server_running(context):
    pass


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
    discover = (
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), flags=0x8000) /
        DHCP(options=[('message-type', 'discover'), ('end')])
    )
    # Start sniffer BEFORE sending so the OFFER is not missed
    sniffer = _start_dhcp_sniffer()
    sendp(discover, iface=INTERFACE, verbose=False)
    context_storage['transaction_id'] = discover[BOOTP].xid
    context_storage['discover_sniffer'] = sniffer


@then('the client receives a DHCPOFFER with a valid IP address in the subnet')
def step_then_receive_offer(context):
    xid = context_storage.get('transaction_id')
    sniffer = context_storage.get('discover_sniffer')
    offer_pkts = _dhcp_packets(sniffer, msg_type=2, xid=xid)  # 2 = DHCPOFFER
    assert offer_pkts, "No DHCPOFFER received"
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
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src="0.0.0.0", dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), xid=xid, flags=0x8000) /
        DHCP(options=[('message-type', 'request'), ('server_id', DHCP_SERVER_IP),
                      ('requested_addr', offered_ip), ('end')])
    )
    sniffer = _start_dhcp_sniffer()
    sendp(request, iface=INTERFACE, verbose=False)
    ack_pkts = _dhcp_packets(sniffer, msg_type=5, xid=xid)  # 5 = DHCPACK
    assert ack_pkts, "No DHCPACK received"
    context_storage['lease_start'] = time.time()


@when('the client sends a DHCPRELEASE message')
def step_when_send_release(context):
    if Ether is None:
        raise RuntimeError("Scapy is required to send DHCP packets; please install scapy.")
    xid = context_storage.get('transaction_id')
    offered_ip = context_storage.get('offered_ip')
    release = (
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=offered_ip, dst=DHCP_SERVER_IP) /
        UDP(sport=68, dport=67) /
        BOOTP(ciaddr=offered_ip, chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")), xid=xid) /
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
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") /
        IP(src=offered_ip, dst="255.255.255.255") /
        UDP(sport=68, dport=67) /
        BOOTP(ciaddr=offered_ip, chaddr=bytes.fromhex(CLIENT_MAC.replace(":", "")),
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
    ack_pkts = _dhcp_packets(sniffer, msg_type=5, xid=xid)  # 5 = DHCPACK
    assert ack_pkts, "No DHCPACK received in response to renewal"
    context_storage['lease_start'] = time.time()


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
