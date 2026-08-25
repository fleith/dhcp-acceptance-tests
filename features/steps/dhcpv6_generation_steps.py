"""Bounded DHCPv6 generation, restart, collision, and reuse coverage."""

import ipaddress
import os
import shlex
import subprocess

from behave import given, then, when

from dhcpv6_support import (
    INTERFACE,
    Ether,
    IPv6,
    UDP,
    cls,
    context_storage_v6,
    duids_equal,
    initialize_client_state,
    new_trid,
    random_duid,
    require_scapy_v6,
    sendp,
    start_v6_sniffer,
)


DIRECT_SUBNET = ipaddress.ip_network(
    os.getenv("TEST_DHCPV6_GENERATION_DIRECT_SUBNET", "fd00:29::/64"),
    strict=False,
)
RELAY_SUBNET_TEXT = os.getenv("TEST_DHCPV6_GENERATION_RELAY_SUBNET", "").strip()
RELAY_LINK_ADDRESS = os.getenv(
    "TEST_DHCPV6_GENERATION_RELAY_LINK_ADDRESS", ""
).strip()
SAMPLE_PER_SUBNET = int(
    os.getenv("TEST_DHCPV6_GENERATION_SAMPLE_PER_SUBNET", "12")
)
POOL_CAPACITY = int(
    os.getenv("TEST_DHCPV6_GENERATION_POOL_CAPACITY_PER_SUBNET", "0")
)
RESPONSE_TIMEOUT = float(
    os.getenv("TEST_DHCPV6_GENERATION_RESPONSE_TIMEOUT", "8")
)


def _relay_message(relay):
    option_class = cls("DHCP6OptRelayMsg")
    layer = relay.payload
    while layer and layer.__class__.__name__ != "NoPayload":
        if isinstance(layer, option_class):
            return getattr(layer, "message", None)
        layer = layer.payload
    return None


def _response_message(packet, trid, relayed):
    if relayed:
        relay = packet.getlayer(cls("DHCP6_RelayReply"))
        if relay is None:
            return None
        message = _relay_message(relay)
    else:
        message = packet.getlayer(cls("DHCP6_Reply"))
    if message is None or not message.haslayer(cls("DHCP6_Reply")):
        return None
    reply = message.getlayer(cls("DHCP6_Reply"))
    return reply if getattr(reply, "trid", None) == trid else None


def _wrap(message, relayed):
    if relayed:
        relay = cls("DHCP6_RelayForward")(
            hopcount=0,
            linkaddr=RELAY_LINK_ADDRESS,
            peeraddr=context_storage_v6["client_ll"],
        ) / cls("DHCP6OptRelayMsg")(message=message)
        return (
            Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
            / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2", hlim=32)
            / UDP(sport=547, dport=547)
            / relay
        )
    return (
        Ether(src=context_storage_v6["client_mac"], dst="33:33:00:01:00:02")
        / IPv6(src=context_storage_v6["client_ll"], dst="ff02::1:2")
        / UDP(sport=546, dport=547)
        / message
    )


def _exchange(message, relayed):
    trid = message.trid
    sniffer = start_v6_sniffer(
        timeout=RESPONSE_TIMEOUT,
        stop_filter=lambda packet: _response_message(packet, trid, relayed)
        is not None,
    )
    sendp(_wrap(message, relayed), iface=INTERFACE, verbose=False)
    sniffer.join()
    replies = [
        reply
        for packet in (sniffer.results or [])
        for reply in [_response_message(packet, trid, relayed)]
        if reply is not None
    ]
    assert replies, (
        f"No DHCPv6 REPLY for transaction {trid:#08x} "
        f"({'relayed' if relayed else 'direct'})"
    )
    return replies[0]


def _ia_na(iaid, address=None, preferred=0, valid=0):
    options = []
    if address is not None:
        options.append(
            cls("DHCP6OptIAAddress")(
                addr=address,
                preflft=preferred,
                validlft=valid,
            )
        )
    return cls("DHCP6OptIA_NA")(iaid=iaid, ianaopts=options)


def _client():
    return {"duid": random_duid(), "iaid": int.from_bytes(os.urandom(4), "big")}


def _reply_binding(reply, client, relayed):
    client_id = reply.getlayer(cls("DHCP6OptClientId"))
    server_id = reply.getlayer(cls("DHCP6OptServerId"))
    ia_na = reply.getlayer(cls("DHCP6OptIA_NA"))
    address = reply.getlayer(cls("DHCP6OptIAAddress"))
    assert duids_equal(getattr(client_id, "duid", None), client["duid"])
    assert server_id is not None, "DHCPv6 generation REPLY omitted Server Identifier"
    assert getattr(ia_na, "iaid", None) == client["iaid"]
    assert address is not None and int(address.validlft) > 0
    return {
        "duid": client["duid"],
        "iaid": client["iaid"],
        "server_duid": bytes(server_id.duid),
        "address": address.addr,
        "preferred": int(address.preflft),
        "valid": int(address.validlft),
        "relayed": relayed,
    }


def _allocate(relayed, hint=None):
    client = _client()
    message = (
        cls("DHCP6_Solicit")(trid=new_trid())
        / cls("DHCP6OptClientId")(duid=client["duid"])
        / cls("DHCP6OptElapsedTime")(elapsedtime=0)
        / _ia_na(client["iaid"], hint)
        / cls("DHCP6OptRapidCommit")()
    )
    return _reply_binding(_exchange(message, relayed), client, relayed)


def _binding_message(name, binding, include_server=False):
    message = (
        cls(name)(trid=new_trid())
        / cls("DHCP6OptClientId")(duid=binding["duid"])
    )
    if include_server:
        message /= cls("DHCP6OptServerId")(duid=binding["server_duid"])
    message /= cls("DHCP6OptElapsedTime")(elapsedtime=0)
    message /= _ia_na(
        binding["iaid"],
        binding["address"],
        binding["preferred"],
        binding["valid"],
    )
    return message


def _rebind(binding):
    reply = _exchange(_binding_message("DHCP6_Rebind", binding), binding["relayed"])
    rebound = _reply_binding(
        reply,
        {"duid": binding["duid"], "iaid": binding["iaid"]},
        binding["relayed"],
    )
    assert rebound["address"] == binding["address"], (
        f"REBIND changed {binding['address']} to {rebound['address']}"
    )
    binding.update(rebound)


def _release(binding):
    _exchange(
        _binding_message("DHCP6_Release", binding, include_server=True),
        binding["relayed"],
    )


def _restart(phase):
    command = os.getenv("TEST_DHCPV6_GENERATION_RESTART_COMMAND", "").strip()
    assert command, "TEST_DHCPV6_GENERATION_RESTART_COMMAND is required"
    env = os.environ.copy()
    env["TEST_DHCPV6_GENERATION_RESTART_PHASE"] = str(phase)
    result = subprocess.run(
        shlex.split(command),
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
        env=env,
    )
    assert result.returncode == 0, (
        f"DHCPv6 restart adapter phase {phase} failed: "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def _scope_bindings(bindings, relayed):
    return [binding for binding in bindings if binding["relayed"] is relayed]


@given("the DHCPv6 generation lifecycle topology is configured")
def step_generation_topology(context):
    require_scapy_v6()
    initialize_client_state()
    assert RELAY_SUBNET_TEXT and RELAY_LINK_ADDRESS, (
        "TEST_DHCPV6_GENERATION_RELAY_SUBNET and "
        "TEST_DHCPV6_GENERATION_RELAY_LINK_ADDRESS are required"
    )
    relay_subnet = ipaddress.ip_network(RELAY_SUBNET_TEXT, strict=False)
    assert ipaddress.ip_address(RELAY_LINK_ADDRESS) in relay_subnet
    assert DIRECT_SUBNET.version == relay_subnet.version == 6
    assert not DIRECT_SUBNET.overlaps(relay_subnet)
    assert 4 <= SAMPLE_PER_SUBNET <= 32
    assert POOL_CAPACITY == SAMPLE_PER_SUBNET * 2, (
        "TEST_DHCPV6_GENERATION_POOL_CAPACITY_PER_SUBNET must equal twice "
        "TEST_DHCPV6_GENERATION_SAMPLE_PER_SUBNET for deterministic reuse"
    )
    context_storage_v6["generation_relay_subnet"] = relay_subnet


@when("a large client sample commits addresses in both configured subnets")
def step_allocate_generation_sample(context):
    bindings = []
    for relayed in (False, True):
        for _ in range(SAMPLE_PER_SUBNET):
            bindings.append(_allocate(relayed))
    context_storage_v6["generation_original"] = bindings
    context_storage_v6["generation_active"] = list(bindings)


@then("every generated address is unique and belongs to its selected subnet")
def step_generation_sample_unique(context):
    bindings = context_storage_v6["generation_original"]
    addresses = [ipaddress.ip_address(item["address"]) for item in bindings]
    assert len(addresses) == len(set(addresses)), (
        f"Generated sample contains active collisions: {addresses}"
    )
    relay_subnet = context_storage_v6["generation_relay_subnet"]
    for binding, address in zip(bindings, addresses):
        expected = relay_subnet if binding["relayed"] else DIRECT_SUBNET
        assert address in expected, f"Generated address {address} is outside {expected}"


@when("the service adapter performs two persistent DHCPv6 restarts")
def step_two_persistent_restarts(context):
    history = []
    for phase in (1, 2):
        _restart(phase)
        for binding in context_storage_v6["generation_active"]:
            _rebind(binding)
        history.append([item["address"] for item in context_storage_v6["generation_active"]])
    context_storage_v6["generation_restart_history"] = history


@then("every recorded owner rebinds its exact address after each restart")
def step_restart_owners_preserved(context):
    expected = [item["address"] for item in context_storage_v6["generation_original"]]
    for observed in context_storage_v6["generation_restart_history"]:
        assert observed == expected


@when("fresh clients fill the remaining capacity in both subnets")
def step_fill_generation_capacity(context):
    fresh = []
    for relayed in (False, True):
        for _ in range(SAMPLE_PER_SUBNET):
            fresh.append(_allocate(relayed))
    context_storage_v6["generation_fresh"] = fresh
    context_storage_v6["generation_active"].extend(fresh)


@then("no fresh allocation collides with a recorded active address")
def step_no_restart_collision(context):
    original = {item["address"] for item in context_storage_v6["generation_original"]}
    fresh = [item["address"] for item in context_storage_v6["generation_fresh"]]
    assert original.isdisjoint(fresh), (
        f"Fresh post-restart allocation collided with active binding(s): "
        f"{sorted(original.intersection(fresh))}"
    )
    assert len(fresh) == len(set(fresh))


@when("half of the original bindings are released in each subnet")
def step_release_half_original(context):
    released = []
    active = context_storage_v6["generation_active"]
    for relayed in (False, True):
        selected = _scope_bindings(
            context_storage_v6["generation_original"], relayed
        )[: SAMPLE_PER_SUBNET // 2]
        for binding in selected:
            _release(binding)
            active.remove(binding)
            released.append(binding)
    context_storage_v6["generation_released"] = released


@then("replacement clients reuse only released addresses without duplicates")
def step_reuse_released_generation_addresses(context):
    released = context_storage_v6["generation_released"]
    replacements = []
    for relayed in (False, True):
        candidates = _scope_bindings(released, relayed)
        for candidate in candidates:
            replacements.append(_allocate(relayed, hint=candidate["address"]))
    released_addresses = {item["address"] for item in released}
    replacement_addresses = [item["address"] for item in replacements]
    active_addresses = {
        item["address"] for item in context_storage_v6["generation_active"]
    }
    assert set(replacement_addresses) == released_addresses, (
        "Capacity-constrained replacements did not reuse exactly the released set: "
        f"released={sorted(released_addresses)}, "
        f"replacement={sorted(replacement_addresses)}"
    )
    assert len(replacement_addresses) == len(set(replacement_addresses))
    assert active_addresses.isdisjoint(replacement_addresses)
