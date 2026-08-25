"""Capability-gated authenticated DHCPv6 Reconfigure acceptance steps."""

import ipaddress
import os
import shlex
import subprocess
from pathlib import Path

from behave import given, then, when

from dhcpv6_rkap import (
    OPTION_AUTH,
    OPTION_CLIENT_ID,
    OPTION_RECONFIGURE_MESSAGE,
    OPTION_SERVER_ID,
    RkapValidationError,
    extract_rkap_key,
    parse_dhcpv6_message,
    validate_rkap_reconfigure,
)
from dhcpv6_support import (
    IPv6,
    UDP,
    cls,
    client_duid,
    context_storage_v6,
    require_scapy_v6,
    start_v6_sniffer,
)


STATE_DIR = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))
RECONFIGURE_TIMEOUT = float(os.getenv("TEST_RECONFIGURE_TIMEOUT", "5"))
REQUIRED_RECONFIGURE_OPTIONS = {
    OPTION_CLIENT_ID,
    OPTION_SERVER_ID,
    OPTION_AUTH,
    OPTION_RECONFIGURE_MESSAGE,
}


def _run_command(variable, extra_env=None, required=True):
    command = os.getenv(variable, "").strip()
    if not command and not required:
        return None
    assert command, f"{variable} is required when authenticated_reconfigure is enabled"
    env = os.environ.copy()
    if extra_env:
        env.update(extra_env)
    result = subprocess.run(
        shlex.split(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
        env=env,
    )
    assert result.returncode == 0, (
        f"{variable} failed with exit {result.returncode}: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    return result


def _dhcp_message_bytes(packet, message_name):
    layer = packet.getlayer(cls(message_name))
    assert layer is not None, f"Captured packet lacks {message_name}"
    return bytes(layer)


def _trigger_environment(accepted):
    return {
        "TEST_RECONFIGURE_CLIENT_ACCEPTED": "1" if accepted else "0",
        "TEST_RECONFIGURE_CLIENT_DUID_HEX": bytes(client_duid()).hex(),
        "TEST_RECONFIGURE_CLIENT_IPV6": context_storage_v6["leased_ipv6"],
        "TEST_RECONFIGURE_CLIENT_LINK_LOCAL": context_storage_v6["client_ll"],
        "TEST_RECONFIGURE_SERVER_DUID_HEX": bytes(
            context_storage_v6["server_duid"]
        ).hex(),
        "TEST_RECONFIGURE_REQUESTED_MESSAGE": "5",
    }


def _capture_triggered_reconfigure(accepted):
    require_scapy_v6()
    reconfigure_class = cls("DHCP6_Reconf")
    sniffer = start_v6_sniffer(
        timeout=RECONFIGURE_TIMEOUT,
        stop_filter=lambda packet: packet.haslayer(reconfigure_class),
    )
    _run_command(
        "TEST_RECONFIGURE_TRIGGER_COMMAND",
        _trigger_environment(accepted),
    )
    sniffer.join()
    return [
        packet
        for packet in (sniffer.results or [])
        if packet.haslayer(reconfigure_class)
    ]


def _learn_rkap_key_from_reply():
    reply = context_storage_v6["request_reply"]
    learned = extract_rkap_key(_dhcp_message_bytes(reply, "DHCP6_Reply"))
    context_storage_v6["reconfigure_rkap_key"] = learned.value
    context_storage_v6["reconfigure_previous_replay"] = learned.replay


def _validate_packet(packet, previous_replay=None, update_state=True):
    ipv6 = packet.getlayer(IPv6)
    udp = packet.getlayer(UDP)
    assert ipv6 is not None and not ipaddress.ip_address(ipv6.dst).is_multicast, (
        "DHCPv6 Reconfigure was not unicast to the client"
    )
    assert ipv6.dst in {
        context_storage_v6["leased_ipv6"],
        context_storage_v6["client_ll"],
    }, f"DHCPv6 Reconfigure targeted unexpected IPv6 address {ipv6.dst}"
    assert udp is not None and udp.sport == 547 and udp.dport == 546, (
        "DHCPv6 Reconfigure did not use server-to-client UDP ports 547->546"
    )

    if previous_replay is None:
        previous_replay = context_storage_v6["reconfigure_previous_replay"]
    message = _dhcp_message_bytes(packet, "DHCP6_Reconf")
    validated = validate_rkap_reconfigure(
        message,
        context_storage_v6["reconfigure_rkap_key"],
        client_duid(),
        context_storage_v6["server_duid"],
        previous_replay=previous_replay,
    )
    assert validated.requested_message == 5, (
        "Authenticated Reconfigure did not request DHCPv6 RENEW"
    )

    if update_state:
        context_storage_v6["reconfigure_previous_replay"] = validated.replay
        context_storage_v6["validated_reconfigure"] = validated

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    packet_file = STATE_DIR / "authenticated-reconfigure.hex"
    packet_file.write_text(bytes(packet).hex(), encoding="ascii")
    _run_command(
        "TEST_RECONFIGURE_AUTH_VALIDATOR_COMMAND",
        {"TEST_RECONFIGURE_PACKET_HEX_FILE": str(packet_file)},
        required=False,
    )
    return validated


@given("a DHCPv6 client holds a Reconfigure-capable lease with an RKAP key")
def step_reconfigure_capable_lease(context):
    context_storage_v6["include_reconfigure_accept"] = True
    context.execute_steps(
        """
        Given the DHCPv6 server is running
        When a client sends a DHCPv6 SOLICIT message
        Then the client receives a DHCPv6 ADVERTISE from the server
        When the client sends a DHCPv6 REQUEST message
        Then the server responds with a DHCPv6 REPLY that finalizes the lease
        """
    )
    _learn_rkap_key_from_reply()


@given("a DHCPv6 client holds a lease without accepting Reconfigure")
def step_non_accepting_lease(context):
    context_storage_v6.pop("include_reconfigure_accept", None)
    context.execute_steps(
        """
        Given the DHCPv6 server is running
        When a client sends a DHCPv6 SOLICIT message
        Then the client receives a DHCPv6 ADVERTISE from the server
        When the client sends a DHCPv6 REQUEST message
        Then the server responds with a DHCPv6 REPLY that finalizes the lease
        """
    )
    try:
        extract_rkap_key(
            _dhcp_message_bytes(context_storage_v6["request_reply"], "DHCP6_Reply")
        )
    except RkapValidationError:
        return
    raise AssertionError("Non-accepting client received an RKAP reconfigure key")


@when("the service adapter triggers DHCPv6 Reconfigure for that client")
def step_trigger_reconfigure(context):
    packets = _capture_triggered_reconfigure(accepted=True)
    assert packets, "No server-initiated DHCPv6 Reconfigure was captured"
    context_storage_v6["capability_reconfigure"] = packets[0]


@when("the service adapter attempts Reconfigure for the non-accepting client")
def step_trigger_non_accepting_reconfigure(context):
    context_storage_v6["non_accepting_reconfigure_packets"] = (
        _capture_triggered_reconfigure(accepted=False)
    )


@then("the client receives a valid unicast RKAP Reconfigure requesting RENEW")
def step_validate_authenticated_reconfigure(context):
    _validate_packet(context_storage_v6["capability_reconfigure"])


@then("the client successfully renews the lease after Reconfigure")
def step_renew_after_reconfigure(context):
    context.execute_steps(
        """
        When the client sends a DHCPv6 RENEW message
        Then the server responds with a DHCPv6 REPLY extending the lease
        """
    )


@then("no DHCPv6 Reconfigure targets the non-accepting client")
def step_no_reconfigure_for_non_accepting_client(context):
    packets = context_storage_v6["non_accepting_reconfigure_packets"]
    assert not packets, (
        f"Server sent {len(packets)} Reconfigure message(s) to a client that did not "
        "include Reconfigure Accept"
    )


@then("the non-accepting client's lease remains renewable")
def step_non_accepting_lease_remains_renewable(context):
    step_renew_after_reconfigure(context)


@then("protected-field and digest tampering invalidate RKAP validation")
def step_tampering_invalidates_rkap(context):
    packet = context_storage_v6["capability_reconfigure"]
    message = _dhcp_message_bytes(packet, "DHCP6_Reconf")
    validated = _validate_packet(packet)
    _, _, options = parse_dhcpv6_message(message)
    client_id = next(option for option in options if option.code == OPTION_CLIENT_ID)
    message_option = next(
        option for option in options if option.code == OPTION_RECONFIGURE_MESSAGE
    )
    auth = next(option for option in options if option.code == OPTION_AUTH)

    variants = {}
    changed = bytearray(message)
    changed[client_id.offset + 4] ^= 0x01
    variants["client-id"] = bytes(changed)
    changed = bytearray(message)
    changed[message_option.offset + 4] = 6
    variants["reconfigure-message"] = bytes(changed)
    changed = bytearray(message)
    changed[auth.offset + 4 + 12] ^= 0x01
    variants["digest"] = bytes(changed)

    failures = []
    for name, variant in variants.items():
        try:
            validate_rkap_reconfigure(
                variant,
                context_storage_v6["reconfigure_rkap_key"],
                client_duid(),
                context_storage_v6["server_duid"],
                previous_replay=None,
            )
        except RkapValidationError:
            failures.append(name)
    assert set(failures) == set(variants), (
        "RKAP validation accepted tampered variants: "
        + ", ".join(sorted(set(variants) - set(failures)))
    )
    context_storage_v6["rejected_reconfigure_variants"] = failures
    context_storage_v6["reconfigure_previous_replay"] = validated.replay


@then("no renewal is initiated for a rejected Reconfigure variant")
def step_no_renew_for_rejected_variant(context):
    assert context_storage_v6.get("rejected_reconfigure_variants"), (
        "No rejected Reconfigure variants were recorded"
    )
    assert "renew_trid" not in context_storage_v6, (
        "A DHCPv6 RENEW was initiated for a rejected Reconfigure variant"
    )


@when("the service sends two completed authenticated Reconfigure transactions")
def step_two_completed_reconfigure_transactions(context):
    first_packets = _capture_triggered_reconfigure(accepted=True)
    assert first_packets, "No first authenticated DHCPv6 Reconfigure was captured"
    first_packet = first_packets[0]
    first = _validate_packet(first_packet)
    step_renew_after_reconfigure(context)

    second_packets = _capture_triggered_reconfigure(accepted=True)
    assert second_packets, "No second authenticated DHCPv6 Reconfigure was captured"
    second_packet = second_packets[0]
    second = _validate_packet(second_packet)
    context_storage_v6["reconfigure_sequence"] = (
        first_packet,
        first,
        second_packet,
        second,
    )


@then("the second Reconfigure has a greater replay-detection value")
def step_replay_value_increases(context):
    _, first, _, second = context_storage_v6["reconfigure_sequence"]
    assert second.replay > first.replay, (
        f"Second RKAP replay value {second.replay} did not exceed {first.replay}"
    )


@then("the previously accepted Reconfigure is rejected as a replay")
def step_stale_reconfigure_is_rejected(context):
    first_packet, _, _, second = context_storage_v6["reconfigure_sequence"]
    try:
        validate_rkap_reconfigure(
            _dhcp_message_bytes(first_packet, "DHCP6_Reconf"),
            context_storage_v6["reconfigure_rkap_key"],
            client_duid(),
            context_storage_v6["server_duid"],
            previous_replay=second.replay,
        )
    except RkapValidationError as error:
        assert "not greater" in str(error), (
            f"Stale Reconfigure failed for an unexpected reason: {error}"
        )
        return
    raise AssertionError("Previously accepted DHCPv6 Reconfigure passed replay detection")


@then("the direct Reconfigure contains only its required RFC 9915 options")
def step_reconfigure_has_only_permitted_metadata(context):
    validated = _validate_packet(context_storage_v6["capability_reconfigure"])
    assert len(validated.option_codes) == len(REQUIRED_RECONFIGURE_OPTIONS), (
        f"Direct Reconfigure options were not unique: {validated.option_codes}"
    )
    assert set(validated.option_codes) == REQUIRED_RECONFIGURE_OPTIONS, (
        f"Direct Reconfigure contained unexpected options: {validated.option_codes}"
    )


@then("the client lease remains renewable after Reconfigure metadata validation")
def step_lease_renewable_after_metadata_validation(context):
    step_renew_after_reconfigure(context)
