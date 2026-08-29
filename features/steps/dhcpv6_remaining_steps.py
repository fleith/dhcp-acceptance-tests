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
UNKNOWN_REBIND_PREFIX = ipaddress.ip_network(
    os.getenv("TEST_DHCPV6_UNKNOWN_REBIND_PREFIX", "fd00:30:0:e::/64"),
    strict=False,
)
PD_POOL = ipaddress.ip_network(
    os.getenv("TEST_DHCPV6_PD_POOL", "fd00:30::/60"), strict=False
)
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


def _ia_na_for(iaid, address=None, preferred=0, valid=0):
    options = []
    if address is not None:
        options.append(
            _cls("DHCP6OptIAAddress")(
                addr=address, preflft=preferred, validlft=valid
            )
        )
    return _cls("DHCP6OptIA_NA")(iaid=iaid, ianaopts=options)


def _ia_prefix_for(network, preferred=0, valid=0):
    network = ipaddress.ip_network(network, strict=False)
    return _cls("DHCP6OptIAPrefix")(
        preflft=preferred,
        validlft=valid,
        plen=network.prefixlen,
        prefix=str(network.network_address),
        iaprefopts=[],
    )


def _ia_pd_for(iaid, network=None, preferred=0, valid=0):
    prefixes = []
    if network is not None:
        prefixes.append(_ia_prefix_for(network, preferred, valid))
    return _cls("DHCP6OptIA_PD")(iaid=iaid, T1=0, T2=0, iapdopt=prefixes)


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


def _has_transaction_response(packet, trid):
    return any(
        packet.haslayer(response_class)
        and getattr(packet[response_class], "trid", None) == trid
        for response_class in (_cls("DHCP6_Advertise"), _cls("DHCP6_Reply"))
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
    # Send enough independent transactions to walk every configured
    # single-address pool. A non-compliant allocator cannot hide a late
    # reserved value behind the valid candidates at the front of the list.
    for _ in range(len(RESERVED_POOL_ALLOWED) + len(RESERVED_POOL_FORBIDDEN) + 1):
        trid = _new_trid()
        sniffer = _start_v6_sniffer(
            timeout=5,
            stop_filter=lambda packet, expected=trid: _has_transaction_response(
                packet, expected
            ),
        )
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
    addresses_by_transaction = {}
    for response in responses:
        message = next(
            (
                response.getlayer(response_class)
                for response_class in (_cls("DHCP6_Advertise"), _cls("DHCP6_Reply"))
                if response.haslayer(response_class)
            ),
            None,
        )
        ia_address = response.getlayer(_cls("DHCP6OptIAAddress"))
        address = getattr(ia_address, "addr", None) if ia_address else None
        trid = getattr(message, "trid", None)
        if address is not None and trid in transactions:
            addresses_by_transaction.setdefault(trid, ipaddress.ip_address(address))
    missing = [trid for trid in transactions if trid not in addresses_by_transaction]
    assert not missing, f"Address-generation sample missed transactions: {missing!r}"
    ordered_addresses = [addresses_by_transaction[trid] for trid in transactions]
    assert len(set(ordered_addresses)) == BATCH_SIZE, (
        f"Expected {BATCH_SIZE} unique address responses, observed {ordered_addresses!r}"
    )
    context_storage_v6["sample_iids"] = [
        int(address) & ((1 << 64) - 1) for address in ordered_addresses
    ]


def _is_contiguous(values):
    ordered = sorted(values)
    return all(current == previous + 1 for previous, current in zip(ordered, ordered[1:]))


def _has_constant_stride(values):
    deltas = [
        (current - previous) % (1 << 64)
        for previous, current in zip(values, values[1:])
    ]
    return bool(deltas) and len(set(deltas)) == 1


def _is_strictly_monotonic(values):
    return all(a < b for a, b in zip(values, values[1:])) or all(
        a > b for a, b in zip(values, values[1:])
    )


@then("their generated IPv6 interface identifiers resist simple sequence predictors")
def step_then_iids_resist_simple_predictors(context):
    values = context_storage_v6["sample_iids"]
    assert not _is_contiguous(values), f"Observed predictable contiguous IID sample: {values!r}"
    assert not _has_constant_stride(values), (
        f"Observed predictable constant-stride IID sample: {values!r}"
    )
    assert not _is_strictly_monotonic(values), (
        f"Observed predictable monotonic IID sample: {values!r}"
    )


@then("their generated IPv6 interface identifiers form a contiguous sequence")
def step_then_iids_are_contiguous(context):
    values = context_storage_v6["sample_iids"]
    assert _is_contiguous(values), f"Kea allocation strategy changed: {values!r}"


def _unknown_rebind_kinds(resources):
    normalized = " ".join(resources.strip().upper().split())
    mapping = {
        "IA_NA": ("IA_NA",),
        "IA_PD": ("IA_PD",),
        "IA_NA AND IA_PD": ("IA_NA", "IA_PD"),
    }
    assert normalized in mapping, f"Unsupported unknown REBIND shape {resources!r}"
    return mapping[normalized]


def _ia_children(ia, field, option_class):
    return [
        option
        for option in (getattr(ia, field, None) or [])
        if isinstance(option, option_class)
    ]


def _ia_for(reply, kind, iaid):
    option_class = _cls("DHCP6OptIA_NA" if kind == "IA_NA" else "DHCP6OptIA_PD")
    matches = [
        option
        for option in _nested_options(reply, option_class)
        if int(getattr(option, "iaid", -1)) == iaid
    ]
    assert len(matches) == 1, (
        f"Expected one {kind} for IAID {iaid:#010x}, found {len(matches)}"
    )
    return matches[0]


@when("an unknown client sends a DHCPv6 REBIND containing {resources}")
def step_when_unknown_client_rebinds(context, resources):
    _require_scapy_v6()
    trid = _new_trid()
    kinds = _unknown_rebind_kinds(resources)
    address_iaid = _iaid()
    prefix_iaid = address_iaid ^ 0x80000000
    rebind = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Rebind")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
    )
    iaids = {}
    if "IA_NA" in kinds:
        iaids["IA_NA"] = address_iaid
        rebind /= _ia_na_for(address_iaid, UNKNOWN_REBIND_HINT)
    if "IA_PD" in kinds:
        iaids["IA_PD"] = prefix_iaid
        rebind /= _ia_pd_for(prefix_iaid, UNKNOWN_REBIND_PREFIX)
    sniffer = _start_v6_sniffer(
        timeout=12,
        stop_filter=lambda packet: _has_transaction_response(packet, trid),
    )
    sendp(rebind, iface=INTERFACE, verbose=False)
    context_storage_v6["unknown_rebind_trid"] = trid
    context_storage_v6["unknown_rebind_responses"] = _matching_responses(sniffer, {trid: True})
    context_storage_v6["unknown_rebind_kinds"] = kinds
    context_storage_v6["unknown_rebind_iaids"] = iaids


@then("a matching DHCPv6 REPLY creates every requested binding")
def step_then_unknown_rebind_creates_bindings(context):
    replies = [
        packet for packet in context_storage_v6["unknown_rebind_responses"]
        if packet.haslayer(_cls("DHCP6_Reply"))
    ]
    assert replies, "Configured server did not create a binding for unknown REBIND"
    reply = replies[0]
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid())
    server_duid = _get_server_duid(reply)
    assert server_duid is not None, "Unknown REBIND REPLY omitted Server Identifier"
    bindings = {}
    iaids = context_storage_v6["unknown_rebind_iaids"]
    for kind in context_storage_v6["unknown_rebind_kinds"]:
        ia = _ia_for(reply, kind, iaids[kind])
        if kind == "IA_NA":
            resources = [
                option
                for option in _ia_children(ia, "ianaopts", _cls("DHCP6OptIAAddress"))
                if int(getattr(option, "validlft", 0)) > 0
            ]
            assert len(resources) == 1, (
                f"Unknown REBIND IA_NA returned {len(resources)} active addresses"
            )
            option = resources[0]
            address = ipaddress.ip_address(option.addr)
            assert address in ipaddress.ip_network(SUBNET_V6)
            bindings[kind] = {
                "address": str(address),
                "preferred": int(option.preflft),
                "valid": int(option.validlft),
            }
        else:
            resources = [
                option
                for option in _ia_children(ia, "iapdopt", _cls("DHCP6OptIAPrefix"))
                if int(getattr(option, "validlft", 0)) > 0
            ]
            assert len(resources) == 1, (
                f"Unknown REBIND IA_PD returned {len(resources)} active prefixes"
            )
            option = resources[0]
            network = ipaddress.ip_network(
                f"{option.prefix}/{int(option.plen)}", strict=False
            )
            assert network.subnet_of(PD_POOL)
            bindings[kind] = {
                "network": network,
                "preferred": int(option.preflft),
                "valid": int(option.validlft),
            }
        assert bindings[kind]["preferred"] > 0
        assert bindings[kind]["valid"] >= bindings[kind]["preferred"]
    context_storage_v6["unknown_rebind_reply"] = reply
    context_storage_v6["unknown_rebind_server_duid"] = server_duid
    context_storage_v6["unknown_rebind_bindings"] = bindings


@then("every created unknown REBIND resource renews successfully")
def step_then_unknown_rebind_resources_renew(context):
    trid = _new_trid()
    renew = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls("DHCP6_Renew")(trid=trid)
        / _cls("DHCP6OptClientId")(duid=_client_duid())
        / _cls("DHCP6OptServerId")(
            duid=context_storage_v6["unknown_rebind_server_duid"]
        )
        / _cls("DHCP6OptElapsedTime")(elapsedtime=0)
    )
    iaids = context_storage_v6["unknown_rebind_iaids"]
    bindings = context_storage_v6["unknown_rebind_bindings"]
    if "IA_NA" in bindings:
        binding = bindings["IA_NA"]
        renew /= _ia_na_for(
            iaids["IA_NA"], binding["address"], binding["preferred"], binding["valid"]
        )
    if "IA_PD" in bindings:
        binding = bindings["IA_PD"]
        renew /= _ia_pd_for(
            iaids["IA_PD"], binding["network"], binding["preferred"], binding["valid"]
        )
    sniffer = _start_v6_sniffer(
        timeout=12,
        stop_filter=lambda packet: _has_transaction_response(packet, trid),
    )
    sendp(renew, iface=INTERFACE, verbose=False)
    replies = [
        packet
        for packet in _matching_responses(sniffer, {trid: True})
        if packet.haslayer(_cls("DHCP6_Reply"))
    ]
    assert replies, "Created unknown REBIND resources could not be renewed"
    reply = replies[0]
    assert _duids_equal(_get_server_duid(reply), context_storage_v6["unknown_rebind_server_duid"])
    for kind, binding in bindings.items():
        ia = _ia_for(reply, kind, iaids[kind])
        if kind == "IA_NA":
            renewed = [
                option for option in _ia_children(ia, "ianaopts", _cls("DHCP6OptIAAddress"))
                if int(getattr(option, "validlft", 0)) > 0
                and ipaddress.ip_address(option.addr) == ipaddress.ip_address(binding["address"])
            ]
        else:
            renewed = [
                option for option in _ia_children(ia, "iapdopt", _cls("DHCP6OptIAPrefix"))
                if int(getattr(option, "validlft", 0)) > 0
                and ipaddress.ip_network(f"{option.prefix}/{int(option.plen)}", strict=False)
                == binding["network"]
            ]
        assert len(renewed) == 1, f"RENEW did not preserve unknown {kind} binding"


@then("every unknown IA reports NoBinding without assigning a resource")
def step_then_unknown_rebind_reports_per_ia_no_binding(context):
    replies = [
        packet for packet in context_storage_v6["unknown_rebind_responses"]
        if packet.haslayer(_cls("DHCP6_Reply"))
    ]
    assert replies, "Unknown-binding REBIND received no DHCPv6 REPLY"
    reply = replies[0]
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid()), (
        "NoBinding REBIND REPLY changed the Client Identifier"
    )
    iaids = context_storage_v6["unknown_rebind_iaids"]
    for kind in context_storage_v6["unknown_rebind_kinds"]:
        ia = _ia_for(reply, kind, iaids[kind])
        field = "ianaopts" if kind == "IA_NA" else "iapdopt"
        resource_class = (
            _cls("DHCP6OptIAAddress")
            if kind == "IA_NA"
            else _cls("DHCP6OptIAPrefix")
        )
        resources = [
            option
            for option in _ia_children(ia, field, resource_class)
            if int(getattr(option, "validlft", 0)) > 0
        ]
        statuses = [
            int(option.statuscode)
            for option in _ia_children(ia, field, _cls("DHCP6OptStatusCode"))
        ]
        assert not resources, f"NoBinding {kind} unexpectedly assigned {resources!r}"
        assert 3 in statuses, f"Unknown {kind} missing per-IA NoBinding; got {statuses}"


@then("the reference unknown REBIND reply omits a required per-IA NoBinding status")
def step_then_reference_rebind_omits_per_ia_no_binding(context):
    replies = [
        packet for packet in context_storage_v6["unknown_rebind_responses"]
        if packet.haslayer(_cls("DHCP6_Reply"))
    ]
    assert replies, "Reference server no longer replies to unknown REBIND"
    reply = replies[0]
    failures = []
    iaids = context_storage_v6["unknown_rebind_iaids"]
    for kind in context_storage_v6["unknown_rebind_kinds"]:
        option_class = _cls("DHCP6OptIA_NA" if kind == "IA_NA" else "DHCP6OptIA_PD")
        matches = [
            option for option in _nested_options(reply, option_class)
            if int(getattr(option, "iaid", -1)) == iaids[kind]
        ]
        field = "ianaopts" if kind == "IA_NA" else "iapdopt"
        statuses = [
            int(option.statuscode)
            for ia in matches
            for option in _ia_children(ia, field, _cls("DHCP6OptStatusCode"))
        ]
        if len(matches) != 1 or 3 not in statuses:
            failures.append((kind, len(matches), statuses))
    assert failures, "Reference server now returns per-IA NoBinding for every unknown IA"


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
