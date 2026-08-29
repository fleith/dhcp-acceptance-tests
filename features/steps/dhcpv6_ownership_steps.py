"""Negative IA_NA ownership checks for DHCPv6 REQUEST and REBIND."""

import os

from behave import then, when

from dhcpv6_support import (
    INTERFACE,
    Ether,
    IPv6,
    UDP,
    cls as _cls,
    context_storage_v6,
    dhcpv6_packets as _dhcpv6_packets,
    new_trid as _new_trid,
    random_duid as _random_duid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


FORGED_RESPONSE_TIMEOUT = float(
    os.getenv("TEST_DHCPV6_FORGED_OWNERSHIP_TIMEOUT", "4")
)


def _nested_options(packet, option_class):
    matches = []
    visited = set()

    def walk(value):
        if value is None or id(value) in visited:
            return
        if isinstance(value, (list, tuple)):
            for item in value:
                walk(item)
            return
        if not hasattr(value, "fields_desc"):
            return
        visited.add(id(value))
        if isinstance(value, option_class):
            matches.append(value)
        for field in value.fields_desc:
            walk(value.getfieldval(field.name))
        walk(getattr(value, "payload", None))

    walk(packet)
    return matches


def _send_forged_ownership_message(message_name):
    _require_scapy_v6()
    victim_address = context_storage_v6["leased_ipv6"]
    attacker_duid = _random_duid()
    attacker_iaid = int.from_bytes(os.urandom(4), "big")
    trid = _new_trid()
    packet = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls(message_name)(trid=trid)
        / _cls("DHCP6OptClientId")(duid=attacker_duid)
    )
    if message_name == "DHCP6_Request":
        packet /= _cls("DHCP6OptServerId")(
            duid=context_storage_v6["server_duid"]
        )
    packet /= _cls("DHCP6OptElapsedTime")(elapsedtime=0)
    packet /= _cls("DHCP6OptIA_NA")(
        iaid=attacker_iaid,
        ianaopts=[
            _cls("DHCP6OptIAAddress")(
                addr=victim_address,
                preflft=context_storage_v6["leased_preferred_lifetime"],
                validlft=context_storage_v6["leased_valid_lifetime"],
            )
        ],
    )
    sniffer = _start_v6_sniffer(timeout=FORGED_RESPONSE_TIMEOUT)
    sendp(packet, iface=INTERFACE, verbose=False)
    context_storage_v6["forged_ownership_trid"] = trid
    context_storage_v6["forged_ownership_sniffer"] = sniffer
    context_storage_v6["forged_ownership_victim"] = victim_address


@when("a different DUID sends a DHCPv6 REQUEST for the active IA_NA")
def step_when_forged_request_for_active_ia_na(context):
    _send_forged_ownership_message("DHCP6_Request")


@when("a different DUID sends a DHCPv6 REBIND for the active IA_NA")
def step_when_forged_rebind_for_active_ia_na(context):
    _send_forged_ownership_message("DHCP6_Rebind")


@then("the forged IA_NA response does not assign the victim address")
def step_then_forged_response_excludes_victim_address(context):
    replies = _dhcpv6_packets(
        context_storage_v6["forged_ownership_sniffer"],
        "DHCP6_Reply",
        context_storage_v6["forged_ownership_trid"],
    )
    victim = context_storage_v6["forged_ownership_victim"]
    returned = {
        option.addr
        for reply in replies
        for option in _nested_options(reply, _cls("DHCP6OptIAAddress"))
        if int(getattr(option, "validlft", 0)) > 0
    }
    assert victim not in returned, (
        f"Server assigned active victim address {victim} to a different DUID"
    )
