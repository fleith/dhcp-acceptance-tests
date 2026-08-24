"""DHCPv6 CONFIRM acceptance and validation steps for RFC 9915."""

import os

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
    duids_equal as _duids_equal,
    get_server_duid as _get_server_duid,
    ia_na as _ia_na,
    new_trid as _new_trid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


STATUS_SUCCESS = 0
STATUS_NOT_ON_LINK = 4
OFF_LINK_ADDRESS = os.getenv("TEST_DHCPV6_OFF_LINK_ADDRESS", "fd00:99::123")


def _status_codes(packet):
    status_class = _cls("DHCP6OptStatusCode")
    statuses = []
    visited = set()

    def collect(layer):
        if layer is None or id(layer) in visited:
            return
        visited.add(id(layer))
        if isinstance(layer, status_class):
            statuses.append(int(layer.statuscode))
        for option in getattr(layer, "ianaopts", None) or []:
            collect(option)
        payload = getattr(layer, "payload", None)
        if payload is not None and payload.__class__.__name__ != "NoPayload":
            collect(payload)

    collect(packet)
    return statuses


def _send_confirm(address, include_client_id=True, include_server_id=False, timeout=5):
    _require_scapy_v6()
    trid = _new_trid()
    confirm = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Confirm")(trid=trid)
    )
    if include_client_id:
        confirm /= _cls("DHCP6OptClientId")(duid=_client_duid())
    if include_server_id:
        confirm /= _cls("DHCP6OptServerId")(duid=context_storage_v6["server_duid"])
    confirm /= _cls("DHCP6OptElapsedTime")(elapsedtime=0)
    confirm /= _ia_na(address, preferred_lifetime=0, valid_lifetime=0)

    sniffer = _start_v6_sniffer(
        timeout=timeout,
        stop_filter=lambda packet: packet.haslayer(_cls("DHCP6_Reply"))
        and getattr(packet[_cls("DHCP6_Reply")], "trid", None) == trid,
    )
    sendp(confirm, iface=INTERFACE, verbose=False)
    context_storage_v6["confirm_trid"] = trid
    context_storage_v6["confirm_sniffer"] = sniffer


def _confirm_replies():
    replies = _dhcpv6_packets(
        context_storage_v6["confirm_sniffer"],
        "DHCP6_Reply",
        context_storage_v6["confirm_trid"],
    )
    if replies:
        context_storage_v6["confirm_reply"] = replies[0]
    return replies


@when("the client sends a DHCPv6 CONFIRM for its active address")
def step_when_confirm_active_address(context):
    _send_confirm(context_storage_v6["leased_ipv6"])


@when("the client sends a DHCPv6 CONFIRM for an off-link address")
def step_when_confirm_off_link_address(context):
    _send_confirm(OFF_LINK_ADDRESS)


@when("the client sends a DHCPv6 CONFIRM without a Client Identifier")
def step_when_confirm_without_client_id(context):
    _send_confirm(
        context_storage_v6["leased_ipv6"],
        include_client_id=False,
        timeout=2,
    )


@when("the client sends a DHCPv6 CONFIRM containing a Server Identifier")
def step_when_confirm_with_server_id(context):
    _send_confirm(
        context_storage_v6["leased_ipv6"],
        include_server_id=True,
        timeout=2,
    )


@when("the client sends a DHCPv6 CONFIRM with an empty IA_NA")
def step_when_confirm_with_empty_ia_na(context):
    _send_confirm(None, timeout=2)


@then("the matching DHCPv6 CONFIRM reply reports Success")
def step_then_confirm_success(context):
    replies = _confirm_replies()
    assert replies, "No DHCPv6 REPLY received for on-link CONFIRM"
    statuses = _status_codes(replies[0])
    assert STATUS_SUCCESS in statuses, (
        f"CONFIRM REPLY missing Success status; observed {statuses}"
    )
    assert replies[0].getlayer(_cls("DHCP6OptIAAddress")) is None, (
        "CONFIRM REPLY unexpectedly renewed or assigned an address"
    )


@then("the matching DHCPv6 CONFIRM reply reports NotOnLink")
def step_then_confirm_not_on_link(context):
    replies = _confirm_replies()
    assert replies, "No DHCPv6 REPLY received for off-link CONFIRM"
    statuses = _status_codes(replies[0])
    assert STATUS_NOT_ON_LINK in statuses, (
        f"CONFIRM REPLY missing NotOnLink status; observed {statuses}"
    )


@then("the matching DHCPv6 CONFIRM reply echoes both identifiers")
def step_then_confirm_reply_echoes_identifiers(context):
    reply = context_storage_v6.get("confirm_reply")
    assert reply is not None, "No validated DHCPv6 CONFIRM REPLY is available"
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid()), (
        "DHCPv6 CONFIRM REPLY Client Identifier does not match the request"
    )
    assert _duids_equal(
        _get_server_duid(reply), context_storage_v6["server_duid"]
    ), "DHCPv6 CONFIRM REPLY Server Identifier does not match the lease server"


@then("the server does not answer the malformed DHCPv6 CONFIRM")
def step_then_malformed_confirm_is_ignored(context):
    assert not _confirm_replies(), "Server answered a malformed DHCPv6 CONFIRM"
