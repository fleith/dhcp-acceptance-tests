"""RFC 9915 DHCPv6 validation, Rapid Commit, and retransmission steps."""

import os
import shlex
import subprocess
import time

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
    get_iaaddr as _get_iaaddr,
    get_server_duid as _get_server_duid,
    ia_na as _ia_na,
    initialize_client_state as _initialize_client_state,
    new_trid as _new_trid,
    random_duid as _random_duid,
    require_scapy_v6 as _require_scapy_v6,
    sendp,
    start_v6_sniffer as _start_v6_sniffer,
)


def _request_counter():
    command = os.getenv("TEST_DHCPV6_REQUEST_COUNTER_COMMAND", "").strip()
    assert command, (
        "TEST_DHCPV6_REQUEST_COUNTER_COMMAND is required when the "
        "dhcpv6_request_observability capability is enabled"
    )
    request = context_storage_v6.get("request_packet")
    assert request is not None, "No completed DHCPv6 REQUEST is available"
    env = os.environ.copy()
    env.update(
        {
            "TEST_DHCPV6_REQUEST_TRID": str(context_storage_v6["request_trid"]),
            "TEST_DHCPV6_REQUEST_DUID_HEX": bytes(_client_duid()).hex(),
            "TEST_DHCPV6_REQUEST_PACKET_HEX": bytes(
                request.getlayer(_cls("DHCP6_Request"))
            ).hex(),
        }
    )
    result = subprocess.run(
        shlex.split(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, (
        "DHCPv6 REQUEST counter adapter failed with exit "
        f"{result.returncode}: stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    output = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    assert output, "DHCPv6 REQUEST counter adapter returned no count"
    try:
        value = int(output[-1], 10)
    except ValueError as error:
        raise AssertionError(
            "DHCPv6 REQUEST counter adapter must print a decimal integer as its "
            f"last nonempty line; received {output[-1]!r}"
        ) from error
    assert value >= 0, f"DHCPv6 REQUEST counter cannot be negative: {value}"
    return value


def _client_message(message_name, trid, options):
    packet = (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / _cls(message_name)(trid=trid)
    )
    for option in options:
        packet /= option
    return packet


def _different_server_duid():
    expected = context_storage_v6.get("server_duid")
    while True:
        candidate = _random_duid()
        if not _duids_equal(candidate, expected):
            return candidate


def _send_malformed_transactions(cases, timeout=3):
    sniffer = _start_v6_sniffer(timeout=timeout)
    transactions = []
    for label, packet, trid in cases:
        sendp(packet, iface=INTERFACE, verbose=False)
        transactions.append((label, trid))
        time.sleep(0.1)
    context_storage_v6["malformed_transaction_sniffer"] = sniffer
    context_storage_v6["malformed_transactions"] = transactions


def _lease_ia():
    return _ia_na(
        context_storage_v6["leased_ipv6"],
        context_storage_v6.get("leased_preferred_lifetime", 0),
        context_storage_v6.get("leased_valid_lifetime", 0),
    )


def _offered_ia():
    return _ia_na(
        context_storage_v6["offered_ipv6"],
        context_storage_v6.get("offered_preferred_lifetime", 0),
        context_storage_v6.get("offered_valid_lifetime", 0),
    )


@when("the client sends every invalid DHCPv6 SOLICIT identifier combination")
def step_send_invalid_solicits(context):
    _require_scapy_v6()
    missing_client_trid = _new_trid()
    unexpected_server_trid = _new_trid()
    cases = [
        (
            "SOLICIT missing Client Identifier",
            _client_message(
                "DHCP6_Solicit",
                missing_client_trid,
                [_cls("DHCP6OptElapsedTime")(elapsedtime=0), _ia_na()],
            ),
            missing_client_trid,
        ),
        (
            "SOLICIT containing Server Identifier",
            _client_message(
                "DHCP6_Solicit",
                unexpected_server_trid,
                [
                    _cls("DHCP6OptClientId")(duid=_client_duid()),
                    _cls("DHCP6OptServerId")(duid=_different_server_duid()),
                    _cls("DHCP6OptElapsedTime")(elapsedtime=0),
                    _ia_na(),
                ],
            ),
            unexpected_server_trid,
        ),
    ]
    _send_malformed_transactions(cases)


@when("the client sends every invalid DHCPv6 REQUEST identifier combination")
def step_send_invalid_requests(context):
    _require_scapy_v6()
    cases = []
    for label, include_client, server_duid in (
        ("REQUEST missing Client Identifier", False, context_storage_v6["server_duid"]),
        ("REQUEST missing Server Identifier", True, None),
        ("REQUEST with mismatched Server Identifier", True, _different_server_duid()),
    ):
        trid = _new_trid()
        options = []
        if include_client:
            options.append(_cls("DHCP6OptClientId")(duid=_client_duid()))
        if server_duid is not None:
            options.append(_cls("DHCP6OptServerId")(duid=server_duid))
        options.extend([_cls("DHCP6OptElapsedTime")(elapsedtime=0), _offered_ia()])
        cases.append((label, _client_message("DHCP6_Request", trid, options), trid))
    _send_malformed_transactions(cases)


@when("the client sends every invalid DHCPv6 RELEASE identifier combination")
def step_send_invalid_releases(context):
    _require_scapy_v6()
    cases = []
    for label, include_client, server_duid in (
        ("RELEASE missing Client Identifier", False, context_storage_v6["server_duid"]),
        ("RELEASE missing Server Identifier", True, None),
        ("RELEASE with mismatched Server Identifier", True, _different_server_duid()),
    ):
        trid = _new_trid()
        options = []
        if include_client:
            options.append(_cls("DHCP6OptClientId")(duid=_client_duid()))
        if server_duid is not None:
            options.append(_cls("DHCP6OptServerId")(duid=server_duid))
        options.extend([_cls("DHCP6OptElapsedTime")(elapsedtime=0), _lease_ia()])
        cases.append((label, _client_message("DHCP6_Release", trid, options), trid))
    _send_malformed_transactions(cases)


@then("the server discards every malformed DHCPv6 transaction")
def step_assert_malformed_transactions_discarded(context):
    sniffer = context_storage_v6["malformed_transaction_sniffer"]
    sniffer.join()
    captured = sniffer.results or []
    failures = []
    for label, trid in context_storage_v6["malformed_transactions"]:
        response_names = [
            name
            for name in ("DHCP6_Advertise", "DHCP6_Reply")
            if any(
                packet.haslayer(_cls(name))
                and getattr(packet[_cls(name)], "trid", None) == trid
                for packet in captured
            )
        ]
        if response_names:
            failures.append(f"{label}: {', '.join(response_names)}")
    assert not failures, "Server answered malformed DHCPv6 transaction(s): " + "; ".join(failures)


@when("a client requests a DHCPv6 lease using Rapid Commit")
def step_send_rapid_commit_solicit(context):
    _require_scapy_v6()
    trid = _new_trid()
    solicit = _client_message(
        "DHCP6_Solicit",
        trid,
        [
            _cls("DHCP6OptClientId")(duid=_client_duid()),
            _cls("DHCP6OptElapsedTime")(elapsedtime=0),
            _cls("DHCP6OptRapidCommit")(),
            _ia_na(),
        ],
    )
    sniffer = _start_v6_sniffer(timeout=12)
    sendp(solicit, iface=INTERFACE, verbose=False)
    context_storage_v6["rapid_commit_trid"] = trid
    context_storage_v6["rapid_commit_sniffer"] = sniffer


@then("the server returns a Rapid Commit REPLY with a committed lease")
def step_assert_rapid_commit_reply(context):
    trid = context_storage_v6["rapid_commit_trid"]
    replies = _dhcpv6_packets(
        context_storage_v6["rapid_commit_sniffer"], "DHCP6_Reply", trid
    )
    assert replies, "No DHCPv6 REPLY received for Rapid Commit SOLICIT"
    reply = replies[0]
    assert reply.getlayer(_cls("DHCP6OptRapidCommit")) is not None, (
        "Rapid Commit REPLY omitted the Rapid Commit option"
    )
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid()), (
        "Rapid Commit REPLY Client Identifier does not match the SOLICIT"
    )
    server_duid = _get_server_duid(reply)
    assert server_duid is not None, "Rapid Commit REPLY missing Server Identifier"
    ia_address = reply.getlayer(_cls("DHCP6OptIAAddress"))
    leased_ip = getattr(ia_address, "addr", None) if ia_address else None
    assert leased_ip, "Rapid Commit REPLY missing a committed IA Address"
    context_storage_v6["server_duid"] = server_duid
    context_storage_v6["leased_ipv6"] = leased_ip
    context_storage_v6["leased_preferred_lifetime"] = ia_address.preflft
    context_storage_v6["leased_valid_lifetime"] = ia_address.validlft


@when("the client retransmits the identical DHCPv6 REQUEST")
def step_retransmit_identical_request(context):
    request = context_storage_v6.get("request_packet")
    assert request is not None, "No completed DHCPv6 REQUEST is available to retransmit"
    sniffer = _start_v6_sniffer(timeout=12)
    sendp(request.copy(), iface=INTERFACE, verbose=False)
    context_storage_v6["retransmit_request_sniffer"] = sniffer


@given("the service REQUEST-processing counter is recorded")
def step_record_request_processing_counter(context):
    context_storage_v6["request_counter_before"] = _request_counter()


@then("the retransmitted REQUEST returns the same binding and identifiers")
def step_assert_retransmitted_request(context):
    trid = context_storage_v6["request_trid"]
    replies = _dhcpv6_packets(
        context_storage_v6["retransmit_request_sniffer"], "DHCP6_Reply", trid
    )
    assert replies, "Retransmitted DHCPv6 REQUEST received no newly captured REPLY"
    reply = replies[0]
    retransmitted_ip = _get_iaaddr(reply)
    assert retransmitted_ip == context_storage_v6["leased_ipv6"], (
        "Retransmitted REQUEST changed the active binding: "
        f"{retransmitted_ip} != {context_storage_v6['leased_ipv6']}"
    )
    client_id = reply.getlayer(_cls("DHCP6OptClientId"))
    assert _duids_equal(getattr(client_id, "duid", None), _client_duid()), (
        "Retransmitted REQUEST REPLY changed the Client Identifier"
    )
    assert _duids_equal(_get_server_duid(reply), context_storage_v6["server_duid"]), (
        "Retransmitted REQUEST REPLY changed the Server Identifier"
    )


@then("the service REQUEST-processing counter advances by one")
def step_assert_request_processing_counter(context):
    before = context_storage_v6["request_counter_before"]
    after = _request_counter()
    assert after == before + 1, (
        "Identical DHCPv6 REQUEST was not regenerated exactly once: "
        f"counter changed from {before} to {after}"
    )


@when("a different client solicits the retransmitted active address")
def step_different_client_solicits_retransmitted_address(context):
    active_address = context_storage_v6["leased_ipv6"]
    previous_duid = _client_duid()
    context.retransmitted_active_ipv6 = active_address
    _initialize_client_state()
    assert not _duids_equal(_client_duid(), previous_duid), "DHCPv6 client DUID did not change"
    context_storage_v6["solicit_ipv6_hint"] = active_address
    context.execute_steps("When a client sends a DHCPv6 SOLICIT message")


@then("the server does not advertise the retransmitted active address")
def step_assert_retransmitted_address_not_reallocated(context):
    context.execute_steps("Then the client receives a DHCPv6 ADVERTISE from the server")
    advertised = context_storage_v6["offered_ipv6"]
    assert advertised != context.retransmitted_active_ipv6, (
        "Server reallocated an active binding after a retransmitted REQUEST: "
        f"{advertised}"
    )
