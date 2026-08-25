"""Focused coverage for the remaining server requirements in RFC 9915."""

import ipaddress
import os

from behave import given, then, when

from dhcpv6_support import (
    INTERFACE,
    SUBNET_V6,
    Ether,
    IPv6,
    UDP,
    cls as _cls,
    client_duid as _client_duid,
    context_storage_v6,
    duids_equal as _duids_equal,
    get_server_duid as _get_server_duid,
    iaid as _iaid,
    new_trid as _new_trid,
    random_duid as _random_duid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


BATCH_SIZE = int(os.getenv("TEST_DHCPV6_ADDRESS_SAMPLE_SIZE", "8"))
UNKNOWN_REBIND_HINT = os.getenv("TEST_DHCPV6_UNKNOWN_REBIND_HINT", "fd00:29::1fe")
RESERVED_HINTS = (
    "fd00:29::",
    "fd00:29:0:0:200:5eff:fe00:1",
    "fd00:29:0:0:200:5eff:fe00:5213",
    "fd00:29:0:0:fdff:ffff:ffff:ff80",
)
RESERVED_POOL_ALLOWED = {
    ipaddress.ip_address(value.strip())
    for value in os.getenv("TEST_DHCPV6_RESERVED_POOL_ALLOWED", "").split(",")
    if value.strip()
}
RESERVED_POOL_FORBIDDEN = {
    ipaddress.ip_address(value.strip())
    for value in os.getenv("TEST_DHCPV6_RESERVED_POOL_FORBIDDEN", "").split(",")
    if value.strip()
}


def _ia_na_for(iaid, address=None):
    options = []
    if address is not None:
        options.append(
            _cls("DHCP6OptIAAddress")(addr=address, preflft=0, validlft=0)
        )
    return _cls("DHCP6OptIA_NA")(iaid=iaid, ianaopts=options)


def _solicit(duid, iaid, trid, address=None, rapid_commit=False):
    packet = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Solicit")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=duid)
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na_for(iaid, address)
    )
    if rapid_commit:
        packet /= _cls("DHCP6OptRapidCommit")()
    return packet


def _matching_responses(sniffer, transactions):
    sniffer.join()
    response_classes = (_cls("DHCP6_Advertise"), _cls("DHCP6_Reply"))
    packets = []
    for packet in sniffer.results or []:
        for response_class in response_classes:
            if packet.haslayer(response_class):
                trid = getattr(packet[response_class], "trid", None)
                if trid in transactions:
                    packets.append(packet)
                break
    return packets


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


@given("the client requests the DHCPv6 Preference option")
def step_given_client_requests_preference(context):
    context_storage_v6["request_preference"] = True


@when("representative reserved IPv6 interface identifiers are requested by distinct clients")
def step_when_reserved_iids_are_requested(context):
    _require_scapy_v6()
    transactions = {}
    packets = []
    for hint in RESERVED_HINTS:
        trid = _new_trid()
        transactions[trid] = hint
        packets.append(
            _solicit(
                _random_duid(),
                int.from_bytes(os.urandom(4), "big"),
                trid,
                hint,
            )
        )
    sniffer = _start_v6_sniffer(timeout=12)
    sendp(packets, iface=INTERFACE, verbose=False)
    context_storage_v6["reserved_transactions"] = transactions
    context_storage_v6["reserved_responses"] = _matching_responses(sniffer, transactions)


@then("no DHCPv6 response offers a reserved IPv6 interface identifier")
def step_then_no_reserved_iid_is_offered(context):
    transactions = context_storage_v6["reserved_transactions"]
    responses = context_storage_v6["reserved_responses"]
    assert responses, "No responses were observed for the reserved-address hint sample"
    reserved = {ipaddress.ip_address(value) for value in transactions.values()}
    observed = []
    for response in responses:
        ia_address = response.getlayer(_cls("DHCP6OptIAAddress"))
        address = getattr(ia_address, "addr", None) if ia_address else None
        if address is not None:
            observed.append(ipaddress.ip_address(address))
    forbidden = reserved.intersection(observed)
    assert not forbidden, f"Server offered reserved IPv6 address(es): {sorted(forbidden)}"


@when("distinct clients exhaust the reserved-IID boundary pools")
def step_when_exhaust_reserved_iid_boundary_pools(context):
    _require_scapy_v6()
    assert RESERVED_POOL_ALLOWED and RESERVED_POOL_FORBIDDEN, (
        "Reserved-IID pool topology requires TEST_DHCPV6_RESERVED_POOL_ALLOWED "
        "and TEST_DHCPV6_RESERVED_POOL_FORBIDDEN"
    )
    assert RESERVED_POOL_ALLOWED.isdisjoint(RESERVED_POOL_FORBIDDEN)
    observed = []
    for _ in range(len(RESERVED_POOL_ALLOWED) + 1):
        trid = _new_trid()
        sniffer = _start_v6_sniffer(timeout=5)
        sendp(
            _solicit(
                _random_duid(),
                int.from_bytes(os.urandom(4), "big"),
                trid,
                rapid_commit=True,
            ),
            iface=INTERFACE,
            verbose=False,
        )
        responses = _matching_responses(sniffer, {trid: True})
        addresses = {
            ipaddress.ip_address(option.addr)
            for response in responses
            for option in _nested_options(response, _cls("DHCP6OptIAAddress"))
            if int(getattr(option, "validlft", 0)) > 0
        }
        assert len(addresses) <= 1, (
            f"One boundary-pool transaction returned multiple addresses: {addresses}"
        )
        observed.extend(addresses)
    context_storage_v6["reserved_pool_observed"] = observed


@then("every allocatable boundary address is committed exactly once")
def step_then_allowed_boundary_addresses_are_committed(context):
    observed = context_storage_v6["reserved_pool_observed"]
    assert len(observed) == len(set(observed)), (
        f"Reserved-IID pool allocated duplicate active addresses: {observed}"
    )
    assert set(observed) == RESERVED_POOL_ALLOWED, (
        "Allocator did not use exactly the non-reserved boundary candidates: "
        f"expected={sorted(RESERVED_POOL_ALLOWED)}, observed={sorted(observed)}"
    )


@then("no reserved boundary IID is assigned")
def step_then_reserved_boundary_addresses_are_not_assigned(context):
    forbidden = RESERVED_POOL_FORBIDDEN.intersection(
        context_storage_v6["reserved_pool_observed"]
    )
    assert not forbidden, (
        f"Allocator committed reserved IPv6 boundary address(es): {sorted(forbidden)}"
    )


@then("the reference allocator assigns a reserved boundary IID")
def step_then_reference_assigns_reserved_boundary_address(context):
    forbidden = RESERVED_POOL_FORBIDDEN.intersection(
        context_storage_v6["reserved_pool_observed"]
    )
    assert forbidden, (
        "Reference allocator no longer assigns any reserved IID from the "
        "explicit boundary pools"
    )


@when("several distinct clients request DHCPv6 addresses")
def step_when_distinct_clients_request_addresses(context):
    _require_scapy_v6()
    assert BATCH_SIZE >= 4, "TEST_DHCPV6_ADDRESS_SAMPLE_SIZE must be at least 4"
    transactions = {}
    packets = []
    for _ in range(BATCH_SIZE):
        trid = _new_trid()
        transactions[trid] = True
        packets.append(
            _solicit(
                _random_duid(),
                int.from_bytes(os.urandom(4), "big"),
                trid,
                rapid_commit=True,
            )
        )
    sniffer = _start_v6_sniffer(timeout=12)
    sendp(packets, iface=INTERFACE, verbose=False)
    responses = _matching_responses(sniffer, transactions)
    addresses = []
    for response in responses:
        ia_address = response.getlayer(_cls("DHCP6OptIAAddress"))
        address = getattr(ia_address, "addr", None) if ia_address else None
        if address is not None:
            addresses.append(ipaddress.ip_address(address))
    unique_addresses = sorted(set(addresses))
    assert len(unique_addresses) == BATCH_SIZE, (
        f"Expected {BATCH_SIZE} unique address responses, observed {unique_addresses!r}"
    )
    context_storage_v6["sample_iids"] = [
        int(address) & ((1 << 64) - 1) for address in unique_addresses
    ]


def _is_contiguous(values):
    ordered = sorted(values)
    return all(current == previous + 1 for previous, current in zip(ordered, ordered[1:]))


@then("their generated IPv6 interface identifiers are not a contiguous sequence")
def step_then_iids_are_not_contiguous(context):
    values = context_storage_v6["sample_iids"]
    assert not _is_contiguous(values), f"Observed predictable contiguous IID sample: {values!r}"


@then("their generated IPv6 interface identifiers form a contiguous sequence")
def step_then_iids_are_contiguous(context):
    values = context_storage_v6["sample_iids"]
    assert _is_contiguous(values), f"Kea allocation strategy changed: {values!r}"


@when("an unknown client sends a DHCPv6 REBIND with an on-link address hint")
def step_when_unknown_client_rebinds(context):
    _require_scapy_v6()
    trid = _new_trid()
    rebind = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Rebind")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na_for(_iaid(), UNKNOWN_REBIND_HINT)
    )
    sniffer = _start_v6_sniffer(timeout=12)
    sendp(rebind, iface=INTERFACE, verbose=False)
    context_storage_v6["unknown_rebind_trid"] = trid
    context_storage_v6["unknown_rebind_responses"] = _matching_responses(sniffer, {trid: True})


@then("a matching DHCPv6 REPLY creates a renewable binding")
def step_then_unknown_rebind_creates_binding(context):
    replies = [
        packet for packet in context_storage_v6["unknown_rebind_responses"]
        if packet.haslayer(_cls("DHCP6_Reply"))
    ]
    assert replies, "Configured server did not create a binding for unknown REBIND"
    reply = replies[0]
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    ia_na = reply.getlayer(_cls("DHCP6OptIA_NA"))
    ia_address = reply.getlayer(_cls("DHCP6OptIAAddress"))
    leased_ip = getattr(ia_address, "addr", None) if ia_address else None
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid())
    assert getattr(ia_na, "iaid", None) == _iaid()
    assert leased_ip and ipaddress.ip_address(leased_ip) in ipaddress.ip_network(SUBNET_V6)
    assert ia_address.preflft > 0 and ia_address.validlft >= ia_address.preflft
    context_storage_v6.update(
        server_duid=_get_server_duid(reply),
        leased_ipv6=leased_ip,
        leased_preferred_lifetime=ia_address.preflft,
        leased_valid_lifetime=ia_address.validlft,
    )


@then("the unknown REBIND reply reports NoBinding without assigning an address")
def step_then_unknown_rebind_reports_no_binding(context):
    replies = [
        packet for packet in context_storage_v6["unknown_rebind_responses"]
        if packet.haslayer(_cls("DHCP6_Reply"))
    ]
    assert replies, "Unknown-binding REBIND received no DHCPv6 REPLY"
    reply = replies[0]
    statuses = [
        int(option.statuscode)
        for option in _nested_options(reply, _cls("DHCP6OptStatusCode"))
    ]
    addresses = _nested_options(reply, _cls("DHCP6OptIAAddress"))
    assert not addresses, (
        "NoBinding REBIND REPLY unexpectedly assigned an IA_NA address"
    )
    assert 3 in statuses, f"Unknown-binding REBIND missing NoBinding; observed {statuses}"
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid()), (
        "NoBinding REBIND REPLY changed the Client Identifier"
    )


@then("the reference unknown REBIND reply omits the required NoBinding status")
def step_then_reference_rebind_omits_no_binding(context):
    replies = [
        packet for packet in context_storage_v6["unknown_rebind_responses"]
        if packet.haslayer(_cls("DHCP6_Reply"))
    ]
    assert replies, "Reference server no longer replies to unknown REBIND"
    statuses = [
        int(option.statuscode)
        for option in _nested_options(replies[0], _cls("DHCP6OptStatusCode"))
    ]
    assert 3 not in statuses, (
        f"Reference divergence changed; NoBinding is now present in {statuses}"
    )


@then("the ADVERTISE has the configured effective server preference")
def step_then_advertise_has_effective_preference(context):
    expected = int(os.getenv("TEST_DHCPV6_EXPECTED_PREFERENCE", "0"))
    option = context_storage_v6["advertise_packet"].getlayer(_cls("DHCP6OptPref"))
    actual = int(getattr(option, "prefval", 0)) if option else 0
    assert actual == expected, f"Expected effective Preference {expected}, observed {actual}"
    if expected != 0:
        assert option is not None, "Configured nonzero Preference option was omitted"


@then("the direct ADVERTISE and REPLY contain no Interface-ID")
def step_then_direct_messages_have_no_interface_id(context):
    interface_id = _cls("DHCP6OptIfaceId")
    assert not context_storage_v6["advertise_packet"].haslayer(interface_id)
    assert not context_storage_v6["request_reply"].haslayer(interface_id)


@when("a direct client sends a SOLICIT containing an illegal Interface-ID")
def step_when_direct_client_sends_interface_id(context):
    trid = _new_trid()
    solicit = _solicit(_client_duid(), _iaid(), trid)
    solicit /= _cls("DHCP6OptIfaceId")(ifaceid=b"illegal-direct-interface-id")
    sniffer = _start_v6_sniffer(timeout=3)
    sendp(solicit, iface=INTERFACE, verbose=False)
    context_storage_v6["illegal_interface_responses"] = _matching_responses(sniffer, {trid: True})


@then("no direct server response contains Interface-ID")
def step_then_no_response_contains_interface_id(context):
    interface_id = _cls("DHCP6OptIfaceId")
    offenders = [
        packet for packet in context_storage_v6["illegal_interface_responses"]
        if packet.haslayer(interface_id)
    ]
    assert not offenders, "Server copied illegal direct-client Interface-ID into its response"


@then("every captured direct lifecycle response contains no Interface-ID")
def step_then_lifecycle_responses_exclude_interface_id(context):
    interface_id = _cls("DHCP6OptIfaceId")
    response_keys = (
        "advertise_packet",
        "request_reply",
        "renew_reply",
        "rebind_reply",
        "confirm_reply",
        "information_reply",
        "release_reply",
    )
    missing = [key for key in response_keys if key not in context_storage_v6]
    assert not missing, f"Direct lifecycle response capture(s) missing: {missing}"
    offenders = [
        key for key in response_keys
        if context_storage_v6[key].haslayer(interface_id)
    ]
    assert not offenders, (
        "Interface-ID appeared in direct lifecycle response(s): "
        + ", ".join(offenders)
    )


@then("the direct DECLINE reply contains no Interface-ID")
def step_then_decline_reply_excludes_interface_id(context):
    reply = context_storage_v6.get("decline_reply")
    assert reply is not None, "No validated direct DECLINE REPLY is available"
    assert not reply.haslayer(_cls("DHCP6OptIfaceId")), (
        "Interface-ID appeared in a direct DECLINE REPLY"
    )
