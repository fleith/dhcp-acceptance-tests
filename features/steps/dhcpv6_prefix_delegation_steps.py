"""DHCPv6 Prefix Delegation acceptance steps for RFC 9915."""

import ipaddress
import os

from behave import given, then, when

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
    iaid as _iaid,
    initialize_client_state as _initialize_client_state,
    new_trid as _new_trid,
    random_duid as _random_duid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


PD_POOL = ipaddress.ip_network(
    os.getenv("TEST_DHCPV6_PD_POOL", "fd00:29:100::/60"), strict=False
)
PD_PREFIX_LEN = int(os.getenv("TEST_DHCPV6_PD_PREFIX_LEN", "64"))
PD_HINT_PREFIX_LEN = int(
    os.getenv("TEST_DHCPV6_PD_HINT_PREFIX_LEN", str(PD_PREFIX_LEN))
)
PD_PREFERRED_LIFETIME = int(
    os.getenv("TEST_DHCPV6_PD_PREFERRED_LIFETIME", "120")
)
PD_VALID_LIFETIME = int(os.getenv("TEST_DHCPV6_PD_VALID_LIFETIME", "120"))
PD_T1 = int(os.getenv("TEST_DHCPV6_PD_T1", "60"))
PD_T2 = int(os.getenv("TEST_DHCPV6_PD_T2", "105"))
PD_CLIENT_T1 = int(os.getenv("TEST_DHCPV6_PD_CLIENT_T1", "4000"))
PD_CLIENT_T2 = int(os.getenv("TEST_DHCPV6_PD_CLIENT_T2", "3000"))
PD_RESPONSE_TIMEOUT = float(os.getenv("TEST_DHCPV6_PD_RESPONSE_TIMEOUT", "12"))
PD_CLEANUP_TIMEOUT = float(os.getenv("TEST_DHCPV6_PD_CLEANUP_TIMEOUT", "2"))
PD_CLEANUP_RETRIES = int(os.getenv("TEST_DHCPV6_PD_CLEANUP_RETRIES", "2"))
PD_OUT_OF_POOL_HINT = ipaddress.ip_network(
    os.getenv("TEST_DHCPV6_PD_OUT_OF_POOL_PREFIX", "fd00:29:ffff::/64"),
    strict=False,
)

_DERIVED_POOL_CAPACITY = (
    1 << (PD_PREFIX_LEN - PD_POOL.prefixlen)
    if PD_PREFIX_LEN >= PD_POOL.prefixlen
    else 0
)
PD_POOL_CAPACITY = int(
    os.getenv("TEST_DHCPV6_PD_POOL_CAPACITY", str(_DERIVED_POOL_CAPACITY))
)
PD_EXHAUSTION_LIMIT = int(os.getenv("TEST_DHCPV6_PD_EXHAUSTION_LIMIT", "32"))

STATUS_SUCCESS = 0
STATUS_NO_BINDING = 3
STATUS_NO_PREFIX_AVAIL = 6


def _fresh_iaid():
    return int.from_bytes(os.urandom(4), "big")


def _primary_client():
    return context_storage_v6["pd_client"]


def _fresh_client(iaid=None):
    return {
        "duid": _random_duid(),
        "iaid": _fresh_iaid() if iaid is None else iaid,
        "mac": context_storage_v6["client_mac"],
        "link_local": context_storage_v6["client_ll"],
    }


def _track_binding(binding):
    context_storage_v6.setdefault("pd_cleanup_bindings", []).append(binding)
    return binding


def _release_tracked_bindings():
    bindings = context_storage_v6.get("pd_cleanup_bindings", [])
    failures = []
    for binding in bindings:
        delegation = binding["delegation"]
        release_pd = _ia_pd(
            delegation["iaid"],
            prefixes=[
                _ia_prefix(
                    delegation["network"], delegation["network"].prefixlen
                )
            ],
        )
        released = False
        for _ in range(PD_CLEANUP_RETRIES):
            _, reply = _send_message(
                "DHCP6_Release",
                "DHCP6_Reply",
                binding["client"],
                [release_pd],
                server_duid=binding["server_duid"],
                response_required=False,
                timeout=PD_CLEANUP_TIMEOUT,
            )
            if reply is None:
                continue
            unexpected = [
                code
                for code in _all_status_codes(reply)
                if code not in (STATUS_SUCCESS, STATUS_NO_BINDING)
            ]
            if not unexpected:
                released = True
                break

        if not released:
            failures.append(str(delegation["network"]))

    assert not failures, (
        "Could not confirm cleanup RELEASE for delegated prefix(es): "
        f"{', '.join(failures)}"
    )


def _nested_options(value, option_class):
    """Return matching Scapy options from packet fields and payload chains."""
    matches = []
    visited = set()

    def walk(candidate):
        if candidate is None:
            return
        if isinstance(candidate, (list, tuple)):
            for item in candidate:
                walk(item)
            return
        if not hasattr(candidate, "fields_desc") or id(candidate) in visited:
            return

        visited.add(id(candidate))
        if isinstance(candidate, option_class):
            matches.append(candidate)

        for field in candidate.fields_desc:
            nested = candidate.getfieldval(field.name)
            if isinstance(nested, (list, tuple)) or hasattr(nested, "fields_desc"):
                walk(nested)
        walk(getattr(candidate, "payload", None))

    walk(value)
    return matches


def _encapsulated_options(ia_pd, option_class):
    return [
        option
        for option in (getattr(ia_pd, "iapdopt", None) or [])
        if isinstance(option, option_class)
    ]


def _ia_prefix(
    prefix="::", prefix_len=0, preferred_lifetime=0, valid_lifetime=0
):
    if isinstance(prefix, (ipaddress.IPv6Network, ipaddress.IPv4Network)):
        prefix = str(prefix.network_address)
    return _cls("DHCP6OptIAPrefix")(
        preflft=preferred_lifetime,
        validlft=valid_lifetime,
        plen=prefix_len,
        prefix=str(prefix),
        iaprefopts=[],
    )


def _ia_pd(iaid, prefixes=None, t1=0, t2=0):
    return _cls("DHCP6OptIA_PD")(
        iaid=iaid,
        T1=t1,
        T2=t2,
        iapdopt=list(prefixes or []),
    )


def _pd_for_iaid(packet, expected_iaid):
    matches = [
        option
        for option in _nested_options(packet, _cls("DHCP6OptIA_PD"))
        if getattr(option, "iaid", None) == expected_iaid
    ]
    assert len(matches) == 1, (
        f"Expected exactly one IA_PD for IAID {expected_iaid:#010x}, "
        f"found {len(matches)}"
    )
    return matches[0]


def _pd_status_codes(ia_pd):
    return [
        getattr(option, "statuscode", None)
        for option in _encapsulated_options(ia_pd, _cls("DHCP6OptStatusCode"))
    ]


def _all_status_codes(packet):
    return [
        getattr(option, "statuscode", None)
        for option in _nested_options(packet, _cls("DHCP6OptStatusCode"))
    ]


def _assert_pd_success(ia_pd):
    failures = [code for code in _pd_status_codes(ia_pd) if code != STATUS_SUCCESS]
    assert not failures, f"IA_PD failed with status code(s): {failures}"


def _delegation(ia_pd):
    prefixes = _encapsulated_options(ia_pd, _cls("DHCP6OptIAPrefix"))
    assert prefixes, f"IA_PD {getattr(ia_pd, 'iaid', None)!r} contains no IA Prefix"
    assert len(prefixes) == 1, (
        f"Expected one delegated prefix in IA_PD, found {len(prefixes)}"
    )

    option = prefixes[0]
    prefix_len = int(option.plen)
    address = ipaddress.ip_address(option.prefix)
    network = ipaddress.ip_network(f"{address}/{prefix_len}", strict=False)
    assert address == network.network_address, (
        f"IA Prefix {address}/{prefix_len} has nonzero host bits"
    )

    preferred = int(option.preflft)
    valid = int(option.validlft)
    assert preferred <= valid, (
        f"Delegated prefix {network} has preferred lifetime {preferred}s greater "
        f"than valid lifetime {valid}s"
    )
    return {
        "iaid": int(ia_pd.iaid),
        "network": network,
        "preferred": preferred,
        "valid": valid,
        "t1": int(ia_pd.T1),
        "t2": int(ia_pd.T2),
    }


def _assert_approximately(actual, expected, label):
    tolerance = max(2, expected * 0.05)
    assert abs(actual - expected) <= tolerance, (
        f"{label}={actual}s is not approximately {expected}s "
        f"(tolerance +/-{tolerance}s)"
    )


def _assert_timer_pair(delegation, label="IA_PD"):
    t1 = delegation["t1"]
    t2 = delegation["t2"]
    valid = delegation["valid"]
    if t1 > 0 and t2 > 0:
        assert t1 <= t2, f"{label} T1={t1}s exceeds T2={t2}s"
    if t1 > 0:
        assert t1 <= valid, f"{label} T1={t1}s exceeds valid lifetime {valid}s"
    if t2 > 0:
        assert t2 <= valid, f"{label} T2={t2}s exceeds valid lifetime {valid}s"


def _assert_configured_delegation(delegation, expected_prefix_len=None):
    expected_prefix_len = (
        PD_PREFIX_LEN if expected_prefix_len is None else expected_prefix_len
    )
    network = delegation["network"]
    assert network.subnet_of(PD_POOL), (
        f"Delegated prefix {network} is outside configured pool {PD_POOL}"
    )
    assert network.prefixlen == expected_prefix_len, (
        f"Delegated prefix length /{network.prefixlen} does not match configured "
        f"/{expected_prefix_len}"
    )
    assert delegation["preferred"] > 0, "Preferred lifetime must be nonzero"
    assert delegation["valid"] > 0, "Valid lifetime must be nonzero"
    _assert_approximately(
        delegation["preferred"], PD_PREFERRED_LIFETIME, "preferred lifetime"
    )
    _assert_approximately(delegation["valid"], PD_VALID_LIFETIME, "valid lifetime")
    _assert_approximately(delegation["t1"], PD_T1, "IA_PD T1")
    _assert_approximately(delegation["t2"], PD_T2, "IA_PD T2")
    _assert_timer_pair(delegation)


def _assert_active_delegation(delegation, expected_prefix_len=None):
    expected_prefix_len = (
        PD_PREFIX_LEN if expected_prefix_len is None else expected_prefix_len
    )
    network = delegation["network"]
    assert network.subnet_of(PD_POOL), (
        f"Delegated prefix {network} is outside configured pool {PD_POOL}"
    )
    assert network.prefixlen == expected_prefix_len, (
        f"Delegated prefix length /{network.prefixlen} does not match configured "
        f"/{expected_prefix_len}"
    )
    assert delegation["preferred"] > 0, "Preferred lifetime must be nonzero"
    assert delegation["valid"] > 0, "Valid lifetime must be nonzero"
    assert delegation["preferred"] <= PD_PREFERRED_LIFETIME, (
        "Preferred lifetime exceeds the configured delegation lifetime"
    )
    assert delegation["valid"] <= PD_VALID_LIFETIME, (
        "Valid lifetime exceeds the configured delegation lifetime"
    )
    _assert_timer_pair(delegation)


def _message_packet(message_name, trid, client, options, server_duid=None):
    packet = (
        Ether(src=client["mac"], dst="33:33:00:01:00:02")
        / IPv6(src=client["link_local"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls(message_name)(trid=trid)
        / _cls("DHCP6OptClientId")(duid=client["duid"])
    )
    if server_duid is not None:
        packet /= _cls("DHCP6OptServerId")(duid=server_duid)
    packet /= _cls("DHCP6OptElapsedTime")(elapsedtime=0)
    for option in options:
        packet /= option
    return packet


def _send_message(
    message_name,
    response_name,
    client,
    options,
    server_duid=None,
    response_required=True,
    timeout=PD_RESPONSE_TIMEOUT,
):
    trid = _new_trid()
    packet = _message_packet(message_name, trid, client, options, server_duid)
    response_class = _cls(response_name)

    def matching_response(packet):
        if not packet.haslayer(response_class):
            return False
        response = packet[response_class]
        if getattr(response, "trid", None) != trid:
            return False
        client_id = packet.getlayer(_cls("DHCP6OptClientId"))
        return _duids_equal(getattr(client_id, "duid", None), client["duid"])

    sniffer = _start_v6_sniffer(
        timeout=timeout,
        stop_filter=matching_response,
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    responses = _dhcpv6_packets(sniffer, response_name, trid)
    matching = []
    for response in responses:
        client_id = response.getlayer(_cls("DHCP6OptClientId"))
        if _duids_equal(getattr(client_id, "duid", None), client["duid"]):
            matching.append(response)

    if response_required:
        assert matching, (
            f"No transaction- and client-matched DHCPv6 {response_name} "
            f"for {message_name} transaction {trid:#08x}"
        )
    return packet, matching[0] if matching else None


def _solicit(client, ia_pds, extra_options=None):
    packet, advertise = _send_message(
        "DHCP6_Solicit",
        "DHCP6_Advertise",
        client,
        list(ia_pds) + list(extra_options or []),
    )
    server_duid = _get_server_duid(advertise)
    assert server_duid is not None, "DHCPv6 ADVERTISE missing Server Identifier"
    return packet, advertise, server_duid


def _request_advertised(client, server_duid, delegations, ia_na_option=None):
    options = []
    if ia_na_option is not None:
        options.append(ia_na_option)
    for delegation in delegations:
        options.append(
            _ia_pd(
                delegation["iaid"],
                prefixes=[
                    _ia_prefix(
                        delegation["network"],
                        delegation["network"].prefixlen,
                        delegation["preferred"],
                        delegation["valid"],
                    )
                ],
            )
        )

    _, reply = _send_message(
        "DHCP6_Request",
        "DHCP6_Reply",
        client,
        options,
        server_duid=server_duid,
    )
    actual_server_duid = _get_server_duid(reply)
    assert _duids_equal(actual_server_duid, server_duid), (
        "DHCPv6 REQUEST REPLY came from a different server"
    )
    return reply


def _binding_from_reply(
    reply,
    iaid,
    expected_network=None,
    require_fresh_lifetimes=True,
):
    ia_pd = _pd_for_iaid(reply, iaid)
    _assert_pd_success(ia_pd)
    delegation = _delegation(ia_pd)
    if require_fresh_lifetimes:
        _assert_configured_delegation(delegation)
    else:
        _assert_active_delegation(delegation)
    if expected_network is not None:
        assert delegation["network"] == expected_network, (
            f"Server returned {delegation['network']} instead of {expected_network}"
        )
    return delegation


def _complete_delegation(client, prefix_hint=None, hint_len=None, t1=0, t2=0):
    prefixes = []
    if prefix_hint is not None or hint_len is not None:
        hint_network = prefix_hint or ipaddress.ip_network(
            f"::/{hint_len}", strict=False
        )
        prefixes.append(
            _ia_prefix(
                hint_network,
                hint_network.prefixlen if hint_len is None else hint_len,
            )
        )

    _, advertise, server_duid = _solicit(
        client, [_ia_pd(client["iaid"], prefixes=prefixes, t1=t1, t2=t2)]
    )
    advertised_pd = _pd_for_iaid(advertise, client["iaid"])
    _assert_pd_success(advertised_pd)
    advertised = _delegation(advertised_pd)
    _assert_configured_delegation(advertised)

    reply = _request_advertised(client, server_duid, [advertised])
    delegated = _binding_from_reply(reply, client["iaid"], advertised["network"])
    return _track_binding({
        "client": client,
        "server_duid": server_duid,
        "delegation": delegated,
    })


def _renew_binding(binding, message_name="DHCP6_Renew"):
    delegation = binding["delegation"]
    options = [
        _ia_pd(
            delegation["iaid"],
            prefixes=[
                _ia_prefix(
                    delegation["network"],
                    delegation["network"].prefixlen,
                    delegation["preferred"],
                    delegation["valid"],
                )
            ],
        )
    ]
    server_duid = (
        binding["server_duid"] if message_name == "DHCP6_Renew" else None
    )
    _, reply = _send_message(
        message_name,
        "DHCP6_Reply",
        binding["client"],
        options,
        server_duid=server_duid,
    )
    return _binding_from_reply(
        reply,
        delegation["iaid"],
        delegation["network"],
        require_fresh_lifetimes=True,
    ), reply


def _offer_for_new_client(client, hint=None):
    prefixes = []
    if hint is not None:
        prefixes.append(_ia_prefix(hint, hint.prefixlen))
    _, advertise, server_duid = _solicit(
        client, [_ia_pd(client["iaid"], prefixes=prefixes)]
    )
    ia_pd = _pd_for_iaid(advertise, client["iaid"])
    return advertise, server_duid, ia_pd


def _bind_advertised_client(client, server_duid, ia_pd):
    _assert_pd_success(ia_pd)
    advertised = _delegation(ia_pd)
    _assert_configured_delegation(advertised)
    reply = _request_advertised(client, server_duid, [advertised])
    delegated = _binding_from_reply(reply, client["iaid"], advertised["network"])
    return _track_binding({
        "client": client,
        "server_duid": server_duid,
        "delegation": delegated,
    })


def _fill_pool_until_exhausted(excluded_network=None):
    assert PD_POOL_CAPACITY > 0, (
        "TEST_DHCPV6_PD_POOL_CAPACITY must describe a nonempty prefix pool"
    )
    assert PD_POOL_CAPACITY <= PD_EXHAUSTION_LIMIT, (
        f"Configured capacity {PD_POOL_CAPACITY} exceeds safe exhaustion limit "
        f"{PD_EXHAUSTION_LIMIT}; use a smaller acceptance-test pool or raise "
        "TEST_DHCPV6_PD_EXHAUSTION_LIMIT explicitly"
    )

    configured_prefixes = (
        [PD_POOL]
        if PD_POOL.prefixlen == PD_PREFIX_LEN
        else list(PD_POOL.subnets(new_prefix=PD_PREFIX_LEN))
    )
    assert len(configured_prefixes) == PD_POOL_CAPACITY, (
        f"Configured pool contains {len(configured_prefixes)} delegated prefixes, "
        f"but TEST_DHCPV6_PD_POOL_CAPACITY is {PD_POOL_CAPACITY}"
    )

    bindings = []
    seen = {excluded_network} if excluded_network is not None else set()
    prefixes_to_bind = [
        network for network in configured_prefixes if network != excluded_network
    ]
    for requested_network in prefixes_to_bind:
        client = _fresh_client()
        advertise, server_duid, ia_pd = _offer_for_new_client(
            client, hint=requested_network
        )
        statuses = _pd_status_codes(ia_pd)
        prefixes = _encapsulated_options(ia_pd, _cls("DHCP6OptIAPrefix"))
        if STATUS_NO_PREFIX_AVAIL in statuses:
            assert not prefixes, "NoPrefixAvail IA_PD unexpectedly contains a prefix"
            raise AssertionError(
                f"Prefix pool exhausted after {len(bindings)} setup bindings; "
                f"expected {len(prefixes_to_bind)}"
            )

        advertised = _delegation(ia_pd)
        assert advertised["network"] == requested_network, (
            f"Server advertised {advertised['network']} instead of available "
            f"setup hint {requested_network}"
        )
        binding = _bind_advertised_client(client, server_duid, ia_pd)
        network = binding["delegation"]["network"]
        assert network not in seen, f"Server delegated duplicate prefix {network}"
        seen.add(network)
        bindings.append(binding)

    context_storage_v6["pd_pool_fill_bindings"] = bindings


@given("the DHCPv6 server is ready for prefix delegation")
def step_given_server_ready_for_prefix_delegation(context):
    _require_scapy_v6()
    assert PD_POOL.version == 6, "Configured prefix-delegation pool must be IPv6"
    assert PD_PREFIX_LEN >= PD_POOL.prefixlen, (
        f"Delegated /{PD_PREFIX_LEN} cannot be drawn from pool {PD_POOL}"
    )
    assert PD_PREFERRED_LIFETIME <= PD_VALID_LIFETIME, (
        "Configured preferred lifetime cannot exceed configured valid lifetime"
    )
    assert not PD_OUT_OF_POOL_HINT.overlaps(PD_POOL), (
        f"Out-of-pool hint {PD_OUT_OF_POOL_HINT} overlaps configured pool {PD_POOL}"
    )
    context.add_cleanup(_release_tracked_bindings)
    _initialize_client_state()
    context_storage_v6["pd_client"] = {
        "duid": _client_duid(),
        "iaid": _iaid(),
        "mac": context_storage_v6["client_mac"],
        "link_local": context_storage_v6["client_ll"],
    }


@when("the client solicits a delegated prefix without a hint")
def step_when_solicit_prefix_without_hint(context):
    client = _primary_client()
    packet, advertise, server_duid = _solicit(
        client, [_ia_pd(client["iaid"])]
    )
    sent_pd = _pd_for_iaid(packet, client["iaid"])
    assert not _encapsulated_options(sent_pd, _cls("DHCP6OptIAPrefix")), (
        "No-hint SOLICIT unexpectedly contained an IA Prefix"
    )
    context_storage_v6["pd_advertise"] = advertise
    context_storage_v6["pd_server_duid"] = server_duid


@then("the server advertises a delegated prefix")
def step_then_server_advertises_prefix(context):
    client = _primary_client()
    ia_pd = _pd_for_iaid(context_storage_v6["pd_advertise"], client["iaid"])
    _assert_pd_success(ia_pd)
    context_storage_v6["pd_advertised"] = _delegation(ia_pd)


@then("the advertised prefix matches the configured delegation policy")
def step_then_advertised_prefix_matches_policy(context):
    _assert_configured_delegation(context_storage_v6["pd_advertised"])


@when("the client requests the advertised delegated prefix")
def step_when_request_advertised_prefix(context):
    client = _primary_client()
    reply = _request_advertised(
        client,
        context_storage_v6["pd_server_duid"],
        [context_storage_v6["pd_advertised"]],
    )
    context_storage_v6["pd_request_reply"] = reply


@then("the server replies with the delegated prefix binding")
def step_then_server_finalizes_prefix_binding(context):
    advertised = context_storage_v6["pd_advertised"]
    delegated = _binding_from_reply(
        context_storage_v6["pd_request_reply"],
        advertised["iaid"],
        advertised["network"],
    )
    context_storage_v6["pd_binding"] = _track_binding({
        "client": _primary_client(),
        "server_duid": context_storage_v6["pd_server_duid"],
        "delegation": delegated,
    })


@when("the client solicits a delegated prefix with the configured length hint")
def step_when_solicit_prefix_length_hint(context):
    client = _primary_client()
    hint = _ia_prefix("::", PD_HINT_PREFIX_LEN)
    _, advertise, server_duid = _solicit(
        client, [_ia_pd(client["iaid"], prefixes=[hint])]
    )
    ia_pd = _pd_for_iaid(advertise, client["iaid"])
    _assert_pd_success(ia_pd)
    context_storage_v6["pd_advertised"] = _delegation(ia_pd)
    context_storage_v6["pd_server_duid"] = server_duid
    context_storage_v6["pd_requested_hint_len"] = PD_HINT_PREFIX_LEN


@then("the server advertises the configured prefix length for the matching hint")
def step_then_server_accepts_matching_prefix_length_hint(context):
    delegation = context_storage_v6["pd_advertised"]
    requested = context_storage_v6["pd_requested_hint_len"]
    _assert_configured_delegation(delegation, expected_prefix_len=requested)


@given("the client holds an active delegated prefix")
def step_given_active_delegated_prefix(context):
    context_storage_v6["pd_binding"] = _complete_delegation(_primary_client())


@when("the client renews the delegated prefix")
def step_when_renew_delegated_prefix(context):
    renewed, reply = _renew_binding(context_storage_v6["pd_binding"])
    context_storage_v6["pd_renewed"] = renewed
    context_storage_v6["pd_renew_reply"] = reply


@then("the server renews the same delegated prefix")
def step_then_server_renews_same_prefix(context):
    binding = context_storage_v6["pd_binding"]["delegation"]
    renewed = context_storage_v6["pd_renewed"]
    assert renewed["network"] == binding["network"]
    _assert_configured_delegation(renewed)


@when("the client rebinds the delegated prefix")
def step_when_rebind_delegated_prefix(context):
    rebound, reply = _renew_binding(
        context_storage_v6["pd_binding"], message_name="DHCP6_Rebind"
    )
    context_storage_v6["pd_rebound"] = rebound
    context_storage_v6["pd_rebind_reply"] = reply


@then("an available server rebinds the same delegated prefix")
def step_then_server_rebinds_same_prefix(context):
    original = context_storage_v6["pd_binding"]["delegation"]
    rebound = context_storage_v6["pd_rebound"]
    assert rebound["network"] == original["network"]
    _assert_configured_delegation(rebound)
    assert _get_server_duid(context_storage_v6["pd_rebind_reply"]) is not None, (
        "REBIND REPLY missing Server Identifier"
    )


@when("the client requests an IA_NA and an IA_PD together")
def step_when_request_address_and_prefix(context):
    client = _primary_client()
    _, advertise, server_duid = _solicit(
        client, [_ia_na(), _ia_pd(client["iaid"])]
    )

    advertised_pd = _pd_for_iaid(advertise, client["iaid"])
    _assert_pd_success(advertised_pd)
    pd_offer = _delegation(advertised_pd)
    _assert_configured_delegation(pd_offer)

    ia_na = advertise.getlayer(_cls("DHCP6OptIA_NA"))
    ia_addr = advertise.getlayer(_cls("DHCP6OptIAAddress"))
    assert ia_na is not None, "Combined ADVERTISE missing IA_NA"
    assert ia_addr is not None, "Combined ADVERTISE missing IA Address"
    requested_ia_na = _ia_na(ia_addr.addr, ia_addr.preflft, ia_addr.validlft)

    reply = _request_advertised(
        client, server_duid, [pd_offer], ia_na_option=requested_ia_na
    )
    context_storage_v6["pd_combined_reply"] = reply
    context_storage_v6["pd_combined_iaid"] = client["iaid"]
    context_storage_v6["pd_combined_server_duid"] = server_duid


@then("the server returns both address and prefix bindings")
def step_then_server_returns_address_and_prefix(context):
    reply = context_storage_v6["pd_combined_reply"]
    ia_na = reply.getlayer(_cls("DHCP6OptIA_NA"))
    ia_addr = reply.getlayer(_cls("DHCP6OptIAAddress"))
    assert ia_na is not None, "Combined REPLY missing IA_NA"
    assert ia_addr is not None, "Combined REPLY missing IA Address"
    assert int(ia_addr.preflft) <= int(ia_addr.validlft), (
        "IA Address preferred lifetime exceeds valid lifetime"
    )

    pd = _pd_for_iaid(reply, context_storage_v6["pd_combined_iaid"])
    _assert_pd_success(pd)
    delegation = _delegation(pd)
    _assert_configured_delegation(delegation)
    _track_binding({
        "client": _primary_client(),
        "server_duid": context_storage_v6["pd_combined_server_duid"],
        "delegation": delegation,
    })
    context_storage_v6["pd_combined_address_ia"] = ia_na
    context_storage_v6["pd_combined_delegation"] = delegation


@then("their applicable T1 and T2 timers are consistent")
def step_then_combined_timers_are_consistent(context):
    ia_na = context_storage_v6["pd_combined_address_ia"]
    delegation = context_storage_v6["pd_combined_delegation"]
    address_t1 = int(ia_na.T1)
    address_t2 = int(ia_na.T2)
    if address_t1 > 0 and address_t2 > 0:
        assert address_t1 <= address_t2, (
            f"IA_NA T1={address_t1}s exceeds T2={address_t2}s"
        )
    _assert_timer_pair(delegation)

    positive_t1 = [value for value in (address_t1, delegation["t1"]) if value > 0]
    positive_t2 = [value for value in (address_t2, delegation["t2"]) if value > 0]
    if positive_t1 and positive_t2:
        assert min(positive_t1) <= min(positive_t2), (
            "Earliest combined renewal timer occurs after earliest rebind timer"
        )


@when("the client requests two delegated prefixes with unique IAIDs")
def step_when_request_two_prefixes(context):
    client = _primary_client()
    second_iaid = client["iaid"] ^ 0x80000000
    iaids = [client["iaid"], second_iaid]
    assert len(set(iaids)) == 2, "Generated IA_PD IAIDs are not unique"

    _, advertise, server_duid = _solicit(
        client, [_ia_pd(value) for value in iaids]
    )
    advertised = []
    for value in iaids:
        ia_pd = _pd_for_iaid(advertise, value)
        _assert_pd_success(ia_pd)
        delegation = _delegation(ia_pd)
        _assert_configured_delegation(delegation)
        advertised.append(delegation)

    reply = _request_advertised(client, server_duid, advertised)
    context_storage_v6["pd_multiple_reply"] = reply
    context_storage_v6["pd_multiple_iaids"] = iaids
    context_storage_v6["pd_multiple_server_duid"] = server_duid


@then("the server returns two unique delegated prefixes for those IAIDs")
def step_then_server_returns_two_unique_prefixes(context):
    reply = context_storage_v6["pd_multiple_reply"]
    delegations = []
    for value in context_storage_v6["pd_multiple_iaids"]:
        ia_pd = _pd_for_iaid(reply, value)
        _assert_pd_success(ia_pd)
        delegation = _delegation(ia_pd)
        _assert_configured_delegation(delegation)
        delegations.append(delegation)
        _track_binding({
            "client": _primary_client(),
            "server_duid": context_storage_v6["pd_multiple_server_duid"],
            "delegation": delegation,
        })
    assert len({item["network"] for item in delegations}) == 2, (
        "Multiple IA_PD IAIDs received duplicate delegated prefixes"
    )


@when("the client solicits a delegated prefix with nonzero T1 and T2")
def step_when_solicit_with_nonzero_timers(context):
    assert PD_CLIENT_T1 > 0 and PD_CLIENT_T2 > 0
    client = _primary_client()
    _, advertise, _ = _solicit(
        client,
        [
            _ia_pd(
                client["iaid"],
                t1=PD_CLIENT_T1,
                t2=PD_CLIENT_T2,
            )
        ],
    )
    context_storage_v6["pd_nonzero_timer_advertise"] = advertise


@then("the server replaces the client-supplied IA_PD timers")
def step_then_server_ignores_client_timers(context):
    client = _primary_client()
    ia_pd = _pd_for_iaid(
        context_storage_v6["pd_nonzero_timer_advertise"], client["iaid"]
    )
    _assert_pd_success(ia_pd)
    delegation = _delegation(ia_pd)
    _assert_configured_delegation(delegation)
    assert (delegation["t1"], delegation["t2"]) != (
        PD_CLIENT_T1,
        PD_CLIENT_T2,
    ), "Server echoed client-supplied IA_PD T1/T2 values"


@when("the client solicits the configured out-of-pool prefix hint")
def step_when_solicit_out_of_pool_hint(context):
    client = _primary_client()
    _, advertise, _ = _solicit(
        client,
        [
            _ia_pd(
                client["iaid"],
                prefixes=[
                    _ia_prefix(
                        PD_OUT_OF_POOL_HINT,
                        PD_OUT_OF_POOL_HINT.prefixlen,
                    )
                ],
            )
        ],
    )
    context_storage_v6["pd_out_of_pool_advertise"] = advertise


@then("the server does not grant the out-of-pool prefix")
def step_then_server_rejects_out_of_pool_hint(context):
    client = _primary_client()
    ia_pd = _pd_for_iaid(
        context_storage_v6["pd_out_of_pool_advertise"], client["iaid"]
    )
    statuses = _pd_status_codes(ia_pd)
    prefixes = _encapsulated_options(ia_pd, _cls("DHCP6OptIAPrefix"))
    if STATUS_NO_PREFIX_AVAIL in statuses:
        assert not prefixes, "NoPrefixAvail IA_PD unexpectedly contains a prefix"
        return

    _assert_pd_success(ia_pd)
    delegation = _delegation(ia_pd)
    _assert_configured_delegation(delegation)
    assert delegation["network"] != PD_OUT_OF_POOL_HINT, (
        f"Server granted out-of-pool hinted prefix {PD_OUT_OF_POOL_HINT}"
    )


@when("a different DUID sends a RELEASE for the delegated prefix")
def step_when_forged_release(context):
    binding = context_storage_v6["pd_binding"]
    delegation = binding["delegation"]
    attacker = _fresh_client(iaid=delegation["iaid"])
    assert not _duids_equal(attacker["duid"], binding["client"]["duid"])
    release_pd = _ia_pd(
        delegation["iaid"],
        prefixes=[
            _ia_prefix(
                delegation["network"], delegation["network"].prefixlen
            )
        ],
    )
    _, reply = _send_message(
        "DHCP6_Release",
        "DHCP6_Reply",
        attacker,
        [release_pd],
        server_duid=binding["server_duid"],
        response_required=False,
    )
    context_storage_v6["pd_forged_release_reply"] = reply


@then("the server reports no binding or preserves the original binding")
def step_then_forged_release_preserves_binding(context):
    reply = context_storage_v6["pd_forged_release_reply"]
    if reply is not None:
        unexpected = [
            code
            for code in _all_status_codes(reply)
            if code not in (STATUS_SUCCESS, STATUS_NO_BINDING)
        ]
        assert not unexpected, (
            f"Forged RELEASE returned unexpected status code(s): {unexpected}"
        )

    renewed, _ = _renew_binding(context_storage_v6["pd_binding"])
    original = context_storage_v6["pd_binding"]["delegation"]
    assert renewed["network"] == original["network"], (
        "Forged RELEASE removed or changed the original client's binding"
    )


@given("every other configured delegated prefix is bound")
def step_given_every_other_prefix_bound(context):
    original = context_storage_v6["pd_binding"]["delegation"]["network"]
    _fill_pool_until_exhausted(excluded_network=original)


@when("the client releases the delegated prefix")
def step_when_release_delegated_prefix(context):
    binding = context_storage_v6["pd_binding"]
    delegation = binding["delegation"]
    release_pd = _ia_pd(
        delegation["iaid"],
        prefixes=[
            _ia_prefix(
                delegation["network"], delegation["network"].prefixlen
            )
        ],
    )
    _, reply = _send_message(
        "DHCP6_Release",
        "DHCP6_Reply",
        binding["client"],
        [release_pd],
        server_duid=binding["server_duid"],
    )
    context_storage_v6["pd_release_reply"] = reply
    context_storage_v6["pd_released_network"] = delegation["network"]


@then("the server accepts the delegated prefix release")
def step_then_server_accepts_prefix_release(context):
    failures = [
        code
        for code in _all_status_codes(context_storage_v6["pd_release_reply"])
        if code != STATUS_SUCCESS
    ]
    assert not failures, f"Delegated prefix RELEASE failed: {failures}"


@when("a different DUID requests the released delegated prefix")
def step_when_different_duid_requests_released_prefix(context):
    released = context_storage_v6["pd_released_network"]
    client = _fresh_client()
    advertise, server_duid, ia_pd = _offer_for_new_client(client, hint=released)
    _assert_pd_success(ia_pd)
    advertised = _delegation(ia_pd)
    _assert_configured_delegation(advertised)
    reply = _request_advertised(client, server_duid, [advertised])
    delegated = _binding_from_reply(reply, client["iaid"], advertised["network"])
    _track_binding({
        "client": client,
        "server_duid": server_duid,
        "delegation": delegated,
    })
    context_storage_v6["pd_reuse_advertise"] = advertise
    context_storage_v6["pd_reused_delegation"] = delegated


@then("the server delegates exactly the released prefix")
def step_then_server_reuses_exact_prefix(context):
    assert context_storage_v6["pd_reused_delegation"]["network"] == (
        context_storage_v6["pd_released_network"]
    ), (
        f"Server did not reuse released prefix "
        f"{context_storage_v6['pd_released_network']}"
    )


@given("every configured delegated prefix is bound")
def step_given_prefix_pool_exhausted(context):
    _fill_pool_until_exhausted()


@when("an additional client solicits a delegated prefix")
def step_when_additional_client_solicits_prefix(context):
    client = _fresh_client()
    advertise, _, _ = _offer_for_new_client(client)
    context_storage_v6["pd_exhaustion_advertise"] = advertise
    context_storage_v6["pd_exhaustion_iaid"] = client["iaid"]


@then("the advertised IA_PD contains NoPrefixAvail and no prefix")
def step_then_no_prefix_available(context):
    ia_pd = _pd_for_iaid(
        context_storage_v6["pd_exhaustion_advertise"],
        context_storage_v6["pd_exhaustion_iaid"],
    )
    statuses = _pd_status_codes(ia_pd)
    assert STATUS_NO_PREFIX_AVAIL in statuses, (
        f"Exhausted IA_PD missing NoPrefixAvail status; observed {statuses}"
    )
    prefixes = _encapsulated_options(ia_pd, _cls("DHCP6OptIAPrefix"))
    assert not prefixes, "NoPrefixAvail IA_PD must not contain delegated prefixes"
