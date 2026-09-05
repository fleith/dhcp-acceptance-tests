"""Option 82 scoped overlapping-address checks for a target DHCPv4 service."""

import ipaddress
import os
import subprocess
import json
import shlex

from behave import given, then, when

from dhcpv4_support import (
    BOOTP,
    DHCP,
    Ether,
    IP,
    UDP,
    dhcp_option,
    dhcp_options,
    mac_bytes,
    option_bytes,
    raw_dhcp_option,
    require_scapy_v4,
    start_dhcp_sniffer,
    build_client_packet,
)

try:
    from scapy.all import sendp
except ImportError:
    sendp = None


SERVER_IP = os.getenv("TEST_SERVER_IP", "172.29.0.2")
INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
CLIENT_SUBNET = os.getenv("TEST_DHCPV4_FACTORY_CLIENT_SUBNET", "10.40.0.0/24")
EXPECTED_ADDRESS = os.getenv(
    "TEST_DHCPV4_FACTORY_EXPECTED_ADDRESS", "10.40.0.100"
)
RELAY_PREFIX = int(os.getenv("TEST_DHCPV4_FACTORY_RELAY_PREFIX", "24"))
RESPONSE_TIMEOUT = float(
    os.getenv("TEST_DHCPV4_FACTORY_RESPONSE_TIMEOUT", "5")
)
PARAMETER_REQUEST_LIST = [1, 3, 6, 15, 51, 58, 59]


def _opaque_environment(name, default):
    """Read an opaque identifier; a hex: prefix permits arbitrary bytes."""
    value = os.getenv(name, default)
    if value.startswith("hex:"):
        return bytes.fromhex(value.removeprefix("hex:"))
    return value.encode("utf-8")


def _factory_scopes():
    return [
        {
            "name": "factory-a",
            "giaddr": os.getenv(
                "TEST_DHCPV4_FACTORY_A_GIADDR", "172.31.0.11"
            ),
            "circuit_id": _opaque_environment(
                "TEST_DHCPV4_FACTORY_A_CIRCUIT_ID", "factory-a"
            ),
            "remote_id": _opaque_environment(
                "TEST_DHCPV4_FACTORY_A_REMOTE_ID", "switch-a"
            ),
        },
        {
            "name": "factory-b",
            "giaddr": os.getenv(
                "TEST_DHCPV4_FACTORY_B_GIADDR", "172.31.0.12"
            ),
            "circuit_id": _opaque_environment(
                "TEST_DHCPV4_FACTORY_B_CIRCUIT_ID", "factory-b"
            ),
            "remote_id": _opaque_environment(
                "TEST_DHCPV4_FACTORY_B_REMOTE_ID", "switch-b"
            ),
        },
        {
            "name": "factory-c",
            "giaddr": os.getenv(
                "TEST_DHCPV4_FACTORY_C_GIADDR", "172.31.0.13"
            ),
            "circuit_id": _opaque_environment(
                "TEST_DHCPV4_FACTORY_C_CIRCUIT_ID", "factory-c"
            ),
            "remote_id": _opaque_environment(
                "TEST_DHCPV4_FACTORY_C_REMOTE_ID", "switch-c"
            ),
        },
    ]


def _state(context):
    if not hasattr(context, "dhcpv4_factory_namespaces"):
        context.dhcpv4_factory_namespaces = {"leases": []}
    return context.dhcpv4_factory_namespaces


def _new_mac():
    value = bytearray(os.urandom(6))
    value[0] = (value[0] | 0x02) & 0xFE
    return ":".join(f"{octet:02x}" for octet in value)


def _new_xid():
    return int.from_bytes(os.urandom(4), "big") or 1


def _message_type(packet):
    return dhcp_options(packet).get("message-type")


def _matches(packet, xid, mac, message_types):
    return (
        packet.haslayer(DHCP)
        and packet.haslayer(BOOTP)
        and packet[BOOTP].xid == xid
        and bytes(packet[BOOTP].chaddr)[:6] == mac_bytes(mac)
        and _message_type(packet) in message_types
    )


def _exchange(packet, xid, mac, message_types, *, stop_first=True):
    sniffer = start_dhcp_sniffer(
        INTERFACE,
        timeout=RESPONSE_TIMEOUT,
        stop_filter=(
            (lambda candidate: _matches(candidate, xid, mac, message_types))
            if stop_first
            else None
        ),
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    sniffer.join()
    return [
        candidate
        for candidate in (sniffer.results or [])
        if _matches(candidate, xid, mac, message_types)
    ]


def _relay_option(scope):
    circuit_id = scope["circuit_id"]
    remote_id = scope["remote_id"]
    assert len(circuit_id) <= 255, f"{scope['name']} Circuit ID is too long"
    assert len(remote_id) <= 255, f"{scope['name']} Remote ID is too long"
    return (
        bytes((1, len(circuit_id)))
        + circuit_id
        + bytes((2, len(remote_id)))
        + remote_id
    )


def _relayed_packet(
    scope,
    mac,
    xid,
    message_type,
    *,
    client_id,
    requested=None,
    server_id=None,
    ciaddr="0.0.0.0",
):
    options = [("message-type", message_type)]
    if server_id is not None:
        options.append(("server_id", server_id))
    if requested is not None:
        options.append(("requested_addr", requested))
    options.extend(
        [
            ("client_id", client_id),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            (82, _relay_option(scope)),
            "end",
        ]
    )
    return (
        Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=scope["giaddr"], dst=SERVER_IP)
        / UDP(sport=67, dport=67)
        / BOOTP(
            op=1,
            hops=1,
            xid=xid,
            ciaddr=ciaddr,
            giaddr=scope["giaddr"],
            chaddr=mac_bytes(mac),
            flags=0x8000 if ciaddr == "0.0.0.0" else 0,
        )
        / DHCP(options=options)
    )


def _interface_addresses():
    result = subprocess.run(
        ["ip", "-o", "-4", "addr", "show", "dev", INTERFACE],
        check=True,
        capture_output=True,
        text=True,
    )
    return {
        field.split("/", 1)[0]
        for line in result.stdout.splitlines()
        for field in line.split()
        if "/" in field
        and field.split("/", 1)[0].count(".") == 3
    }


def _remove_relay_address(address):
    subprocess.run(
        ["ip", "addr", "del", f"{address}/{RELAY_PREFIX}", "dev", INTERFACE],
        check=False,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _install_relay_addresses(context, scopes):
    existing = _interface_addresses()
    for scope in scopes:
        address = scope["giaddr"]
        if address in existing:
            continue
        subprocess.run(
            [
                "ip",
                "addr",
                "add",
                f"{address}/{RELAY_PREFIX}",
                "dev",
                INTERFACE,
            ],
            check=True,
        )
        context.add_cleanup(_remove_relay_address, address)
        existing.add(address)


def _complete_dora(scope, mac=None, client_id=None):
    mac = mac or _new_mac()
    xid = _new_xid()
    client_id = client_id or b"\x00factory-" + os.urandom(12)
    discover = _relayed_packet(
        scope,
        mac,
        xid,
        "discover",
        client_id=client_id,
        requested=EXPECTED_ADDRESS,
    )
    responses = _exchange(discover, xid, mac, {2, 5, 6})
    assert not [packet for packet in responses if _message_type(packet) in {5, 6}], (
        f"{scope['name']} DISCOVER received ACK/NAK instead of DHCPOFFER"
    )
    offers = [packet for packet in responses if _message_type(packet) == 2]
    assert offers, f"{scope['name']} received no DHCPOFFER"
    offered_addresses = {packet[BOOTP].yiaddr for packet in offers}
    assert len(offered_addresses) == 1, (
        f"{scope['name']} received conflicting offers: {offered_addresses}"
    )
    offered_address = offered_addresses.pop()
    server_id = dhcp_option(offers[0], "server_id")
    assert server_id, f"{scope['name']} DHCPOFFER omitted Server Identifier"
    request = _relayed_packet(
        scope,
        mac,
        xid,
        "request",
        client_id=client_id,
        requested=offered_address,
        server_id=server_id,
    )
    responses = _exchange(request, xid, mac, {5, 6})
    assert not [packet for packet in responses if _message_type(packet) == 6], (
        f"{scope['name']} server rejected its offered address {offered_address}"
    )
    acknowledgements = [
        packet for packet in responses if _message_type(packet) == 5
    ]
    assert acknowledgements, f"{scope['name']} received no DHCPACK"
    assert {packet[BOOTP].yiaddr for packet in acknowledgements} == {
        offered_address
    }, f"{scope['name']} DHCPACK changed offered address {offered_address}"
    return {
        "scope": scope,
        "mac": mac,
        "xid": xid,
        "client_id": client_id,
        "address": offered_address,
        "offer": offers[0],
        "ack": acknowledgements[0],
    }


def _release(lease):
    scope = lease["scope"]
    packet = _relayed_packet(
        scope,
        lease["mac"],
        _new_xid(),
        "release",
        client_id=lease["client_id"],
        server_id=dhcp_option(lease["ack"], "server_id")
        or dhcp_option(lease["offer"], "server_id")
        or SERVER_IP,
        ciaddr=lease["address"],
    )
    sendp(packet, iface=INTERFACE, verbose=False)


def _cleanup_leases(context):
    for lease in _state(context).get("leases", []):
        try:
            _release(lease)
        except Exception as exc:
            print(f"\n[WARN] Could not release {lease['scope']['name']} lease: {exc}")
    _state(context)["leases"] = []


def _assert_relay_response(packet, scope, label):
    expected_option = _relay_option(scope)
    assert packet[BOOTP].giaddr == scope["giaddr"], (
        f"{scope['name']} {label} changed giaddr to {packet[BOOTP].giaddr}"
    )
    assert packet.haslayer(IP) and packet[IP].dst == scope["giaddr"], (
        f"{scope['name']} {label} destination is not relay {scope['giaddr']}"
    )
    assert packet.haslayer(UDP) and packet[UDP].dport == 67, (
        f"{scope['name']} {label} was not returned to relay UDP port 67"
    )
    actual = raw_dhcp_option(
        packet,
        82,
        (
            "relay_agent_information",
            "relay_agent_Information",
            "relay_agent_information_option",
        ),
    )
    assert actual is not None, f"{scope['name']} {label} omitted Option 82"
    assert option_bytes(actual) == expected_option, (
        f"{scope['name']} {label} changed Option 82: "
        f"{option_bytes(actual)!r} != {expected_option!r}"
    )


@given("three trusted factory relay scopes share one DHCPv4 client subnet")
def step_factory_scopes(context):
    require_scapy_v4()
    assert sendp is not None, "Scapy send support is required for factory tests"
    subnet = ipaddress.ip_network(CLIENT_SUBNET, strict=False)
    expected = ipaddress.ip_address(EXPECTED_ADDRESS)
    assert expected in subnet, (
        f"Expected duplicate address {expected} is outside {subnet}"
    )
    scopes = _factory_scopes()
    assert len({scope["giaddr"] for scope in scopes}) == len(scopes), (
        "Factory relay giaddr values must be unique"
    )
    assert len(
        {
            (scope["giaddr"], scope["circuit_id"], scope["remote_id"])
            for scope in scopes
        }
    ) == len(scopes), "Factory relay tuples must be unique"
    for scope in scopes:
        ipaddress.ip_address(scope["giaddr"])
        assert scope["circuit_id"], f"{scope['name']} Circuit ID is empty"
        assert scope["remote_id"], f"{scope['name']} Remote ID is empty"
    _install_relay_addresses(context, scopes)
    state = _state(context)
    state["scopes"] = scopes
    if not state.get("cleanup_registered"):
        context.add_cleanup(_cleanup_leases, context)
        state["cleanup_registered"] = True


@when("one client in each factory completes DORA through its trusted relay")
def step_factory_dora(context):
    state = _state(context)
    for scope in state["scopes"]:
        state["leases"].append(_complete_dora(scope))


@then("every factory commits the configured shared IPv4 address")
def step_factory_shared_address(context):
    leases = _state(context)["leases"]
    assert len(leases) == 3
    actual = {lease["scope"]["name"]: lease["address"] for lease in leases}
    assert set(actual.values()) == {EXPECTED_ADDRESS}, (
        f"Factories did not independently commit {EXPECTED_ADDRESS}: {actual}"
    )
    client_ids = {lease["client_id"] for lease in leases}
    assert len(client_ids) == len(leases), "Factory clients must be independent"


@then("every factory response preserves its own giaddr and Option 82 bytes")
def step_factory_metadata(context):
    for lease in _state(context)["leases"]:
        _assert_relay_response(lease["offer"], lease["scope"], "DHCPOFFER")
        _assert_relay_response(lease["ack"], lease["scope"], "DHCPACK")


@then("every factory binding rebinds through its original relay scope")
def step_factory_rebinds(context):
    for lease in _state(context)["leases"]:
        xid = _new_xid()
        rebind = _relayed_packet(
            lease["scope"],
            lease["mac"],
            xid,
            "request",
            client_id=lease["client_id"],
            ciaddr=lease["address"],
        )
        responses = _exchange(rebind, xid, lease["mac"], {5, 6})
        assert not [packet for packet in responses if _message_type(packet) == 6], (
            f"{lease['scope']['name']} active binding was rejected"
        )
        acknowledgements = [
            packet for packet in responses if _message_type(packet) == 5
        ]
        assert acknowledgements, (
            f"{lease['scope']['name']} active binding was not renewed"
        )
        assert acknowledgements[0][BOOTP].yiaddr in {
            lease["address"],
            "0.0.0.0",
        }
        _assert_relay_response(
            acknowledgements[0], lease["scope"], "rebind DHCPACK"
        )


@when("a client presents one factory Circuit ID through another factory relay")
def step_mismatched_factory_scope(context):
    scopes = _state(context)["scopes"]
    forged_scope = dict(scopes[0])
    forged_scope["circuit_id"] = scopes[1]["circuit_id"]
    mac = _new_mac()
    xid = _new_xid()
    client_id = b"\xffoption82-mismatched-scope"
    discover = _relayed_packet(
        forged_scope,
        mac,
        xid,
        "discover",
        client_id=client_id,
        requested=EXPECTED_ADDRESS,
    )
    _state(context)["mismatched_responses"] = _exchange(
        discover, xid, mac, {2, 5, 6}, stop_first=False
    )


@then("the mismatched relay scope receives no address offer")
def step_mismatched_factory_rejected(context):
    responses = _state(context)["mismatched_responses"]
    allocations = [
        packet for packet in responses if _message_type(packet) in {2, 5}
    ]
    assert not allocations, (
        "Server allocated an address for a Circuit ID replayed through the "
        "wrong trusted relay"
    )


def _lifecycle_adapter(action):
    command = os.environ.get("TEST_FACTORY_LIFECYCLE_COMMAND", "")
    assert command, "TEST_FACTORY_LIFECYCLE_COMMAND is required"
    result = subprocess.run(
        shlex.split(command) + [action], capture_output=True, text=True,
        check=True, timeout=30,
    )
    return json.loads(result.stdout) if action == "snapshot" else None


def _snapshot(context):
    rows = _lifecycle_adapter("snapshot")
    assert isinstance(rows, list), "Snapshot must be a JSON array"
    result = {}
    for row in rows:
        assert set(row) == {"factory", "address", "state", "client_id", "mac", "expires_at"}
        key = (row["factory"], row["address"])
        assert key not in result, f"Duplicate lease key {key}"
        assert row["state"] in {"active", "declined"}
        result[key] = row
    return result


@given("the disposable factory lifecycle fixture is reset")
def step_factory_reset(context):
    _lifecycle_adapter("reset")
    assert not _snapshot(context), "Reset must clear the disposable fixture"


@when("identical client identities commit the shared address in all factories")
def step_factory_identical(context):
    mac, identity = _new_mac(), b"\x00factory-clone-" + os.urandom(8)
    for scope in _state(context)["scopes"]:
        _state(context)["leases"].append(_complete_dora(scope, mac, identity))
    step_factory_metadata(context)


@then("all factory owners exist in authoritative lease state")
def step_factory_owners(context):
    rows = _snapshot(context)
    leases = _state(context)["leases"]
    assert len(rows) == len(leases) == 3
    for lease in leases:
        assert lease["address"] == EXPECTED_ADDRESS
        row = rows[(lease["scope"]["name"], EXPECTED_ADDRESS)]
        assert row["state"] == "active"
        assert row["client_id"] == lease["client_id"].hex()
        assert row["mac"].lower() == lease["mac"].lower()
    _state(context)["baseline"] = rows


@when("Factory A releases its shared address")
def step_factory_release(context):
    lease = _state(context)["leases"][0]
    _release(lease)
    _state(context)["leases"].remove(lease)
    _lifecycle_adapter("settle")


@then("Factory A alone has no active owner")
def step_factory_release_state(context):
    rows = _snapshot(context)
    baseline = _state(context)["baseline"]
    expected = {key: row for key, row in baseline.items() if key[0] != "factory-a"}
    assert rows == expected, "Release modified another factory or retained A"


@when("a replacement client commits the shared address in Factory A")
def step_factory_replacement(context):
    state = _state(context)
    state["leases"].append(_complete_dora(state["scopes"][0]))


@when("Factory A declines its shared address")
def step_factory_decline(context):
    state = _state(context)
    lease = state["leases"][0]
    packet = _relayed_packet(
        lease["scope"], lease["mac"], _new_xid(), "decline",
        client_id=lease["client_id"], requested=lease["address"],
        server_id=dhcp_option(lease["ack"], "server_id"),
    )
    sendp(packet, iface=INTERFACE, verbose=False)
    state["leases"].remove(lease)
    _lifecycle_adapter("settle")


@then("Factory A alone is quarantined")
def step_factory_quarantine(context):
    rows = _snapshot(context)
    baseline = _state(context)["baseline"]
    assert set(rows) == set(baseline)
    for key, row in rows.items():
        if key[0] == "factory-a":
            assert row["state"] == "declined"
        else:
            original = baseline[key]
            assert row["state"] == "active"
            assert row["client_id"] == original["client_id"]
            assert row["mac"] == original["mac"]


@then("a contender cannot obtain Factory A's quarantined address")
def step_factory_quarantine_contender(context):
    scope = _state(context)["scopes"][0]
    mac, xid = _new_mac(), _new_xid()
    packet = _relayed_packet(scope, mac, xid, "discover", client_id=b"\x00contender")
    replies = _exchange(packet, xid, mac, {2, 5, 6}, stop_first=False)
    assert not [reply for reply in replies if _message_type(reply) in {2, 5}]


@when("an identical owner renews by unicast without factory metadata")
def step_factory_ambiguous(context):
    lease = _state(context)["leases"][0]
    xid = _new_xid()
    from scapy.all import getmacbyip
    server_mac = getmacbyip(SERVER_IP)
    assert server_mac, "Unicast server MAC could not be resolved"
    packet = build_client_packet(
        lease["mac"], xid,
        [("message-type", "request"), ("client_id", lease["client_id"]), "end"],
        ciaddr=lease["address"], source_ip=lease["address"],
        destination_ip=SERVER_IP, destination_mac=server_mac, flags=0,
    )
    _state(context)["ambiguous"] = _exchange(
        packet, xid, lease["mac"], {2, 5, 6}, stop_first=False,
    )


@then("the ambiguous renewal receives no acknowledgement")
def step_factory_no_ambiguous_ack(context):
    assert not [p for p in _state(context)["ambiguous"] if _message_type(p) in {2, 5}]


@then("authoritative factory leases remain unchanged")
def step_factory_unchanged(context):
    assert _snapshot(context) == _state(context)["baseline"]


@when("the factory adapter restarts the service preserving storage")
def step_factory_restart(context):
    _lifecycle_adapter("restart")
