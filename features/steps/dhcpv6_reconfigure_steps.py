"""DHCPv6 Reconfigure capability, discard, and recovery steps."""

from behave import then, when

from dhcpv6_support import (
    INTERFACE,
    Ether,
    IPv6,
    UDP,
    cls as _cls,
    client_duid as _client_duid,
    context_storage_v6,
    dhcpv6_packets as _dhcpv6_packets,
    new_trid as _new_trid,
    random_duid as _random_duid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


def _send_invalid_reconfigure(include_reconfigure_message):
    _require_scapy_v6()
    reconfigure = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Reconf")(trid=0)
        / _cls("DHCP6OptServerId")(duid=_random_duid())
        / _cls("DHCP6OptClientId")(duid=_client_duid())
    )
    if include_reconfigure_message:
        reconfigure /= _cls("DHCP6OptReconfMsg")(msgtype=5)

    sniffer = _start_v6_sniffer(timeout=2)
    sendp(reconfigure, iface=INTERFACE, verbose=False)
    context_storage_v6["invalid_reconfigure_sniffer"] = sniffer


@when("a client requests a lease while accepting DHCPv6 Reconfigure")
def step_when_client_accepts_reconfigure(context):
    context_storage_v6["include_reconfigure_accept"] = True
    context.execute_steps("When a client sends a DHCPv6 SOLICIT message")


@when("a client sends a forged unauthenticated DHCPv6 RECONFIGURE to the server")
def step_when_client_forges_reconfigure(context):
    _send_invalid_reconfigure(include_reconfigure_message=True)


@when("a client sends DHCPv6 RECONFIGURE without a Reconfigure Message option")
def step_when_client_sends_malformed_reconfigure(context):
    _send_invalid_reconfigure(include_reconfigure_message=False)


@then("the server does not answer the invalid DHCPv6 RECONFIGURE")
def step_then_server_ignores_invalid_reconfigure(context):
    replies = _dhcpv6_packets(
        context_storage_v6["invalid_reconfigure_sniffer"],
        "DHCP6_Reply",
        0,
    )
    assert not replies, "Server answered a client-originated DHCPv6 RECONFIGURE"


@then("the DHCPv6 server remains responsive to valid configuration requests")
def step_then_server_recovers_after_reconfigure(context):
    context.execute_steps(
        """
        When a client sends a DHCPv6 INFORMATION-REQUEST for DNS configuration
        Then the matching DHCPv6 REPLY contains DNS server "2001:4860:4860::8888" and domain "example.test"
        """
    )
