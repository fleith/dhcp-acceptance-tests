"""Capability-gated authenticated DHCPv6 Reconfigure acceptance steps."""

import os
import shlex
import subprocess
from pathlib import Path

from behave import given, then, when

from dhcpv6_support import (
    cls,
    client_duid,
    context_storage_v6,
    duids_equal,
    require_scapy_v6,
    start_v6_sniffer,
)


STATE_DIR = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))


def _run_command(variable, extra_env=None):
    command = os.getenv(variable, "").strip()
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


@given("a DHCPv6 client holds a Reconfigure-capable lease")
def step_reconfigure_capable_lease(context):
    context.execute_steps(
        """
        Given the DHCPv6 server is running
        When a client requests a lease while accepting DHCPv6 Reconfigure
        Then the client receives a DHCPv6 ADVERTISE from the server
        When the client sends a DHCPv6 REQUEST message
        Then the server responds with a DHCPv6 REPLY that finalizes the lease
        """
    )


@when("the service adapter triggers DHCPv6 Reconfigure for that client")
def step_trigger_reconfigure(context):
    require_scapy_v6()
    reconfigure_class = cls("DHCP6_Reconf")
    sniffer = start_v6_sniffer(
        timeout=10,
        stop_filter=lambda packet: packet.haslayer(reconfigure_class),
    )
    _run_command("TEST_RECONFIGURE_TRIGGER_COMMAND")
    sniffer.join()
    packets = [
        packet for packet in (sniffer.results or [])
        if packet.haslayer(reconfigure_class)
    ]
    assert packets, "No server-initiated DHCPv6 Reconfigure was captured"
    context_storage_v6["capability_reconfigure"] = packets[0]


@then("the client receives a server-authenticated Reconfigure requesting RENEW")
def step_validate_authenticated_reconfigure(context):
    packet = context_storage_v6["capability_reconfigure"]
    client_option = packet.getlayer(cls("DHCP6OptClientId"))
    server_option = packet.getlayer(cls("DHCP6OptServerId"))
    message_option = packet.getlayer(cls("DHCP6OptReconfMsg"))
    auth_option = packet.getlayer(cls("DHCP6OptAuth"))
    assert client_option is not None and duids_equal(
        getattr(client_option, "duid", None), client_duid()
    ), "Reconfigure targets a different DHCPv6 client"
    assert server_option is not None and duids_equal(
        getattr(server_option, "duid", None), context_storage_v6.get("server_duid")
    ), "Reconfigure uses an unexpected Server Identifier"
    assert message_option is not None and getattr(message_option, "msgtype", None) == 5, (
        "Reconfigure does not request DHCPv6 RENEW"
    )
    assert auth_option is not None and len(bytes(auth_option)) > 15, (
        "Reconfigure is missing a populated Authentication option"
    )

    STATE_DIR.mkdir(parents=True, exist_ok=True)
    packet_file = STATE_DIR / "authenticated-reconfigure.hex"
    packet_file.write_text(bytes(packet).hex(), encoding="ascii")
    _run_command(
        "TEST_RECONFIGURE_AUTH_VALIDATOR_COMMAND",
        {"TEST_RECONFIGURE_PACKET_HEX_FILE": str(packet_file)},
    )


@then("the client successfully renews the lease after Reconfigure")
def step_renew_after_reconfigure(context):
    context.execute_steps(
        """
        When the client sends a DHCPv6 RENEW message
        Then the server responds with a DHCPv6 REPLY extending the lease
        """
    )
