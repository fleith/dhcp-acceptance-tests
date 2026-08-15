"""Stateful DHCPv4 load and crash-consistency acceptance steps."""

import ipaddress
import json
import math
import os
import time
from pathlib import Path

from behave import given, then, when

from dhcpv4_support import (
    BOOTP,
    DHCP,
    build_client_packet,
    dhcp_option,
    dhcp_options,
    mac_bytes,
    require_scapy_v4,
    start_dhcp_sniffer,
)

try:
    from scapy.all import sendp
except ImportError:
    sendp = None


INTERFACE = os.getenv("TEST_INTERFACE", "eth0")
SERVER_IP = os.getenv("TEST_SERVER_IP", "172.29.0.2")
STATE_DIR = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))
STATE_FILE = STATE_DIR / "dhcpv4-stress-state.json"
READY_MARKER = STATE_DIR / "dhcpv4-stress-inflight-ready"
CRASH_MARKER = STATE_DIR / "dhcpv4-stress-server-crashed"
RESULTS_DIR = Path(os.getenv("TEST_RESULTS_DIR", "/app/test-results/default"))

PREPARE_CLIENTS = int(os.getenv("TEST_DHCPV4_STRESS_PREPARE_CLIENTS", "32"))
INFLIGHT_CLIENTS = int(os.getenv("TEST_DHCPV4_STRESS_INFLIGHT_CLIENTS", "24"))
POST_CLIENTS = int(os.getenv("TEST_DHCPV4_STRESS_POST_CLIENTS", "8"))
CHURN_ROUNDS = int(os.getenv("TEST_DHCPV4_STRESS_CHURN_ROUNDS", "2"))
CHURN_BATCH = int(os.getenv("TEST_DHCPV4_STRESS_CHURN_BATCH", "8"))
CRASH_LOAD_SECONDS = float(
    os.getenv("TEST_DHCPV4_STRESS_CRASH_LOAD_SECONDS", "3")
)
CAPTURE_TIMEOUT = float(os.getenv("TEST_DHCPV4_STRESS_CAPTURE_TIMEOUT", "10"))
BATCH_DEADLINE = float(os.getenv("TEST_DHCPV4_STRESS_BATCH_DEADLINE", "20"))
P95_LIMIT_MS = float(os.getenv("TEST_DHCPV4_STRESS_P95_LIMIT_MS", "3000"))
POOL_CAPACITY = int(os.getenv("TEST_DHCPV4_STRESS_POOL_CAPACITY", "101"))
PARAMETER_REQUEST_LIST = [1, 3, 6, 15, 51, 58, 59]


def _state(context):
    if not hasattr(context, "dhcpv4_stress"):
        context.dhcpv4_stress = {}
    return context.dhcpv4_stress


def _new_mac():
    value = bytearray(os.urandom(6))
    value[0] = (value[0] | 0x02) & 0xFE
    return ":".join(f"{octet:02x}" for octet in value)


def _new_xid():
    return int.from_bytes(os.urandom(4), "big") or 1


def _unique_xid(used):
    while True:
        xid = _new_xid()
        if xid not in used:
            used.add(xid)
            return xid


def _message_type(packet):
    return dhcp_options(packet).get("message-type")


def _matches(packet, clients, message_types):
    if not packet.haslayer(DHCP) or not packet.haslayer(BOOTP):
        return False
    client = clients.get(packet[BOOTP].xid)
    if client is None or _message_type(packet) not in message_types:
        return False
    expected_mac = mac_bytes(client["mac"])
    return bytes(packet[BOOTP].chaddr)[: len(expected_mac)] == expected_mac


def _capture_exchange(entries, message_types, timeout=CAPTURE_TIMEOUT):
    """Send a batch and stop after each transaction has one matching response."""
    require_scapy_v4()
    assert sendp is not None, "Scapy send support is required for stress tests"
    clients = {entry["xid"]: entry for entry in entries}
    seen = set()

    def stop_filter(packet):
        if _matches(packet, clients, message_types):
            seen.add(packet[BOOTP].xid)
        return len(seen) == len(clients)

    sniffer = start_dhcp_sniffer(
        INTERFACE,
        timeout=timeout,
        stop_filter=stop_filter,
    )
    for entry in entries:
        entry["sent_at"] = time.time()
        sendp(entry["packet"], iface=INTERFACE, verbose=False)
    sniffer.join()
    responses = [
        packet
        for packet in (sniffer.results or [])
        if _matches(packet, clients, message_types)
    ]
    by_xid = {}
    for packet in responses:
        by_xid.setdefault(packet[BOOTP].xid, []).append(packet)
    latencies = []
    for xid, packets in by_xid.items():
        first = min(float(packet.time) for packet in packets)
        latencies.append(max(0.0, (first - clients[xid]["sent_at"]) * 1000.0))
    return by_xid, latencies


def _discover_batch(count):
    used_xids = set()
    clients = [
        {"mac": _new_mac(), "xid": _unique_xid(used_xids)}
        for _ in range(count)
    ]
    for client in clients:
        client["packet"] = build_client_packet(
            client["mac"],
            client["xid"],
            [
                ("message-type", "discover"),
                ("param_req_list", PARAMETER_REQUEST_LIST),
                "end",
            ],
        )
    responses, latencies = _capture_exchange(clients, {2, 5, 6})
    for client in clients:
        packets = responses.get(client["xid"], [])
        unexpected = [packet for packet in packets if _message_type(packet) in {5, 6}]
        assert not unexpected, (
            f"Stress DISCOVER 0x{client['xid']:08x} received ACK/NAK"
        )
        offers = [packet for packet in packets if _message_type(packet) == 2]
        assert offers, f"No offer for stress client 0x{client['xid']:08x}"
        addresses = {packet[BOOTP].yiaddr for packet in offers}
        assert len(addresses) == 1, (
            f"Stress client 0x{client['xid']:08x} received conflicting offers: "
            f"{addresses}"
        )
        client["ip"] = addresses.pop()
        client["server_id"] = dhcp_option(offers[0], "server_id") or SERVER_IP
    return clients, latencies


def _selection_request(client):
    return build_client_packet(
        client["mac"],
        client["xid"],
        [
            ("message-type", "request"),
            ("server_id", client["server_id"]),
            ("requested_addr", client["ip"]),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ],
    )


def _commit_batch(count):
    started = time.monotonic()
    clients, offer_latencies = _discover_batch(count)
    entries = []
    for client in clients:
        entries.append({**client, "packet": _selection_request(client)})
    responses, ack_latencies = _capture_exchange(entries, {5, 6})
    leases = []
    for client in clients:
        packets = responses.get(client["xid"], [])
        assert not [packet for packet in packets if _message_type(packet) == 6], (
            f"Server rejected stress offer {client['ip']}"
        )
        acknowledgements = [
            packet for packet in packets if _message_type(packet) == 5
        ]
        assert acknowledgements, f"No ACK for stress offer {client['ip']}"
        addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
        assert addresses == {client["ip"]}, (
            f"Stress ACK changed {client['ip']} to {addresses}"
        )
        leases.append(
            {
                "mac": client["mac"],
                "xid": client["xid"],
                "ip": client["ip"],
                "server_id": client["server_id"],
            }
        )
    return leases, {
        "offer_ms": offer_latencies,
        "commit_ms": ack_latencies,
        "elapsed_seconds": time.monotonic() - started,
    }


def _release_packet(lease):
    return build_client_packet(
        lease["mac"],
        lease["xid"],
        [
            ("message-type", "release"),
            ("server_id", lease.get("server_id") or SERVER_IP),
            "end",
        ],
        ciaddr=lease["ip"],
        source_ip=lease["ip"],
        destination_ip=lease.get("server_id") or SERVER_IP,
        flags=0,
    )


def _release_batch(leases):
    for lease in leases:
        sendp(_release_packet(lease), iface=INTERFACE, verbose=False)


def _load_state():
    assert STATE_FILE.exists(), f"Stress state file does not exist: {STATE_FILE}"
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def _save_state(data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _append_batch_metrics(data, phase, metrics):
    data["metrics"].setdefault("batches", []).append(
        {
            "phase": phase,
            "transactions": len(metrics["commit_ms"]),
            "elapsed_seconds": metrics["elapsed_seconds"],
        }
    )
    data["metrics"].setdefault("latencies_ms", {}).setdefault(
        "offer", []
    ).extend(metrics["offer_ms"])
    data["metrics"]["latencies_ms"].setdefault("commit", []).extend(
        metrics["commit_ms"]
    )


def _assert_unique(leases, label):
    addresses = [lease["ip"] for lease in leases]
    assert len(addresses) == len(set(addresses)), (
        f"{label} contains duplicate active addresses: {addresses}"
    )


def _percentile(values, percentile):
    if not values:
        return 0.0
    ordered = sorted(float(value) for value in values)
    index = max(0, math.ceil((percentile / 100.0) * len(ordered)) - 1)
    return ordered[index]


def _summary(data):
    latency_summary = {}
    all_values = []
    for name, values in sorted(data["metrics"].get("latencies_ms", {}).items()):
        all_values.extend(values)
        latency_summary[name] = {
            "count": len(values),
            "p50": round(_percentile(values, 50), 3),
            "p95": round(_percentile(values, 95), 3),
            "p99": round(_percentile(values, 99), 3),
            "max": round(max(values, default=0.0), 3),
        }
    return {
        "profile": data["profile"],
        "counts": data["metrics"]["counts"],
        "active_bindings_verified": len(data["leases"]),
        "batch_max_seconds": round(
            max(
                (
                    batch["elapsed_seconds"]
                    for batch in data["metrics"].get("batches", [])
                ),
                default=0.0,
            ),
            3,
        ),
        "latencies_ms": latency_summary,
        "combined_p95_ms": round(_percentile(all_values, 95), 3),
    }


@given("the isolated DHCPv4 stress fixture is safely bounded")
def step_stress_fixture(context):
    require_scapy_v4()
    assert sendp is not None, "Scapy send support is required for stress tests"
    assert 2 <= PREPARE_CLIENTS <= 96
    assert 1 <= INFLIGHT_CLIENTS <= 96
    assert 1 <= POST_CLIENTS <= 32
    assert 0 <= CHURN_ROUNDS <= 50
    assert 1 <= CHURN_BATCH <= 96
    assert 1 <= CRASH_LOAD_SECONDS <= 60
    assert 2 <= CAPTURE_TIMEOUT <= 60
    assert 2 <= BATCH_DEADLINE <= 120
    assert 100 <= P95_LIMIT_MS <= 30000
    maximum_active = PREPARE_CLIENTS + INFLIGHT_CLIENTS + POST_CLIENTS
    assert maximum_active <= POOL_CAPACITY, (
        f"Stress profile can hold {maximum_active} active leases but pool capacity "
        f"is {POOL_CAPACITY}"
    )
    for path in (STATE_FILE, READY_MARKER, CRASH_MARKER):
        path.unlink(missing_ok=True)


@when("sustained DHCPv4 churn runs before a committed stress batch")
def step_prepare_stress(context):
    data = {
        "schema_version": 1,
        "profile": {
            "prepare_clients": PREPARE_CLIENTS,
            "inflight_clients": INFLIGHT_CLIENTS,
            "post_clients": POST_CLIENTS,
            "churn_rounds": CHURN_ROUNDS,
            "churn_batch": CHURN_BATCH,
        },
        "leases": [],
        "metrics": {
            "counts": {
                "churn_committed": 0,
                "pre_crash_committed": 0,
                "inflight_acknowledged": 0,
                "post_crash_committed": 0,
                "recovered": 0,
            },
            "batches": [],
            "latencies_ms": {},
        },
    }
    for round_number in range(1, CHURN_ROUNDS + 1):
        leases, metrics = _commit_batch(CHURN_BATCH)
        _assert_unique(leases, f"churn round {round_number}")
        _append_batch_metrics(data, f"churn-{round_number}", metrics)
        data["metrics"]["counts"]["churn_committed"] += len(leases)
        _release_batch(leases)
        time.sleep(0.2)

    leases, metrics = _commit_batch(PREPARE_CLIENTS)
    _assert_unique(leases, "pre-crash batch")
    data["leases"] = leases
    data["metrics"]["counts"]["pre_crash_committed"] = len(leases)
    _append_batch_metrics(data, "pre-crash", metrics)
    _save_state(data)
    _state(context)["data"] = data


@then("every pre-crash stress binding is unique and recorded")
def step_pre_crash_unique(context):
    data = _state(context)["data"]
    assert len(data["leases"]) == PREPARE_CLIENTS
    _assert_unique(data["leases"], "recorded pre-crash bindings")
    assert STATE_FILE.exists()


@then("each completed stress batch meets its latency deadline")
def step_prepare_deadline(context):
    data = _state(context)["data"]
    slow = [
        batch
        for batch in data["metrics"]["batches"]
        if batch["elapsed_seconds"] > BATCH_DEADLINE
    ]
    assert not slow, f"Stress batches exceeded {BATCH_DEADLINE}s: {slow}"


@given("recorded pre-crash DHCPv4 stress bindings")
def step_recorded_pre_crash(context):
    data = _load_state()
    assert len(data["leases"]) == PREPARE_CLIENTS
    _assert_unique(data["leases"], "pre-crash state")
    _state(context)["data"] = data


def _renewal_entry(lease, xid):
    return {
        "mac": lease["mac"],
        "xid": xid,
        "ip": lease["ip"],
        "packet": build_client_packet(
            lease["mac"],
            xid,
            [
                ("message-type", "request"),
                ("param_req_list", PARAMETER_REQUEST_LIST),
                "end",
            ],
            ciaddr=lease["ip"],
            source_ip=lease["ip"],
            flags=0x8000,
        ),
    }


@when(
    "mixed allocation renewal and retransmission traffic runs until the server crashes"
)
def step_inflight_load(context):
    data = _state(context)["data"]
    clients, offer_latencies = _discover_batch(INFLIGHT_CLIENTS)
    selecting = [
        {**client, "packet": _selection_request(client)} for client in clients
    ]
    used_xids = {client["xid"] for client in selecting}
    renewing = [
        _renewal_entry(lease, _unique_xid(used_xids))
        for lease in data["leases"]
    ]
    all_entries = selecting + renewing
    lookup = {entry["xid"]: entry for entry in all_entries}

    sniffer = start_dhcp_sniffer(
        INTERFACE,
        timeout=CRASH_LOAD_SECONDS + 1,
    )
    first_sent = {}
    deadline = time.monotonic() + CRASH_LOAD_SECONDS
    cycles = 0
    while time.monotonic() < deadline:
        cycles += 1
        for entry in all_entries:
            first_sent.setdefault(entry["xid"], time.time())
            sendp(entry["packet"], iface=INTERFACE, verbose=False)
        if cycles == 1:
            READY_MARKER.write_text(
                "allocation, renewal, and retransmission traffic sent\n",
                encoding="utf-8",
            )
        time.sleep(0.1)
    sniffer.join()
    packets = [
        packet
        for packet in (sniffer.results or [])
        if _matches(packet, lookup, {5, 6})
    ]
    assert CRASH_MARKER.exists(), (
        "Stress runner did not record the orchestrated server crash"
    )
    assert not [packet for packet in packets if _message_type(packet) == 6], (
        "Server returned DHCPNAK during mixed crash load"
    )

    by_xid = {}
    for packet in packets:
        by_xid.setdefault(packet[BOOTP].xid, []).append(packet)
    acknowledged = []
    inflight_latencies = []
    selecting_xids = {client["xid"] for client in selecting}
    for xid in selecting_xids:
        acks = [packet for packet in by_xid.get(xid, []) if _message_type(packet) == 5]
        if not acks:
            continue
        client = lookup[xid]
        addresses = {packet[BOOTP].yiaddr for packet in acks}
        assert addresses == {client["ip"]}, (
            f"In-flight ACK changed {client['ip']} to {addresses}"
        )
        acknowledged.append(
            {
                "mac": client["mac"],
                "xid": client["xid"],
                "ip": client["ip"],
                "server_id": client["server_id"],
            }
        )
        inflight_latencies.append(
            max(0.0, (min(float(packet.time) for packet in acks) - first_sent[xid]) * 1000.0)
        )

    combined = data["leases"] + acknowledged
    _assert_unique(combined, "pre-crash and acknowledged in-flight bindings")
    data["leases"] = combined
    data["metrics"]["counts"]["inflight_acknowledged"] = len(acknowledged)
    data["metrics"]["counts"]["crash_load_cycles"] = cycles
    data["metrics"]["latencies_ms"].setdefault("offer", []).extend(
        offer_latencies
    )
    data["metrics"]["latencies_ms"]["inflight_commit"] = inflight_latencies
    _save_state(data)
    _state(context)["data"] = data


@then("every acknowledged in-flight binding is recorded without duplication")
def step_inflight_unique(context):
    data = _state(context)["data"]
    _assert_unique(data["leases"], "acknowledged crash-load state")
    assert len(data["leases"]) == (
        PREPARE_CLIENTS + data["metrics"]["counts"]["inflight_acknowledged"]
    )


@then("the orchestrated DHCPv4 server crash was observed")
def step_crash_observed(context):
    assert CRASH_MARKER.exists()
    assert _state(context)["data"]["metrics"]["counts"]["crash_load_cycles"] >= 1


@given("recorded acknowledged DHCPv4 stress bindings")
def step_recorded_acknowledged(context):
    data = _load_state()
    assert data["leases"], "No acknowledged stress bindings were recorded"
    _assert_unique(data["leases"], "recorded acknowledged bindings")
    _state(context)["data"] = data


@when("all recorded stress clients reassert their bindings after restart")
def step_reassert_bindings(context):
    data = _state(context)["data"]
    entries = []
    original_by_xid = {}
    used_xids = set()
    for lease in data["leases"]:
        xid = _unique_xid(used_xids)
        original_by_xid[xid] = lease
        entries.append(
            {
                "mac": lease["mac"],
                "xid": xid,
                "packet": build_client_packet(
                    lease["mac"],
                    xid,
                    [
                        ("message-type", "request"),
                        ("requested_addr", lease["ip"]),
                        ("param_req_list", PARAMETER_REQUEST_LIST),
                        "end",
                    ],
                ),
            }
        )
    responses, latencies = _capture_exchange(entries, {5, 6})
    recovered = []
    for xid, lease in original_by_xid.items():
        packets = responses.get(xid, [])
        assert not [packet for packet in packets if _message_type(packet) == 6], (
            f"Restarted server rejected acknowledged binding {lease['ip']}"
        )
        acks = [packet for packet in packets if _message_type(packet) == 5]
        assert acks, f"Restarted server did not ACK binding {lease['ip']}"
        addresses = {packet[BOOTP].yiaddr for packet in acks}
        assert addresses == {lease["ip"]}, (
            f"Restart recovery changed {lease['ip']} to {addresses}"
        )
        recovered.append(lease["ip"])
    data["metrics"]["counts"]["recovered"] = len(recovered)
    data["metrics"]["latencies_ms"]["recovery"] = latencies
    _save_state(data)
    _state(context)["recovered"] = recovered


@then("every recorded stress binding is acknowledged for its original client")
def step_recovery_exact(context):
    data = _state(context)["data"]
    assert set(_state(context)["recovered"]) == {
        lease["ip"] for lease in data["leases"]
    }


@when("a fresh DHCPv4 batch acquires leases after crash recovery")
def step_post_crash_batch(context):
    data = _state(context)["data"]
    leases, metrics = _commit_batch(POST_CLIENTS)
    _assert_unique(leases, "post-crash batch")
    _append_batch_metrics(data, "post-crash", metrics)
    data["metrics"]["counts"]["post_crash_committed"] = len(leases)
    _state(context)["post_crash"] = leases
    data["leases"].extend(leases)
    _save_state(data)


@then("no post-crash lease duplicates an active recorded binding")
def step_post_crash_unique(context):
    data = _state(context)["data"]
    _assert_unique(data["leases"], "all active post-recovery bindings")
    post_addresses = {lease["ip"] for lease in _state(context)["post_crash"]}
    recorded_addresses = {
        lease["ip"]
        for lease in data["leases"][: -len(_state(context)["post_crash"])]
    }
    assert not post_addresses & recorded_addresses


@then("the DHCPv4 stress metrics satisfy the configured limits")
def step_metrics(context):
    data = _state(context)["data"]
    summary = _summary(data)
    assert summary["batch_max_seconds"] <= BATCH_DEADLINE, (
        f"Stress batch took {summary['batch_max_seconds']}s; limit is "
        f"{BATCH_DEADLINE}s"
    )
    assert summary["combined_p95_ms"] <= P95_LIMIT_MS, (
        f"Stress p95 was {summary['combined_p95_ms']}ms; limit is "
        f"{P95_LIMIT_MS}ms"
    )
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    metrics_path = RESULTS_DIR / "dhcpv4-stress-metrics.json"
    metrics_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("\n[stress-metrics] " + json.dumps(summary, sort_keys=True))


@when("all DHCPv4 stress bindings are released")
def step_release_stress(context):
    data = _state(context)["data"]
    _release_batch(data["leases"])
    time.sleep(0.2)
    for path in (STATE_FILE, READY_MARKER, CRASH_MARKER):
        path.unlink(missing_ok=True)


@then("the DHCPv4 stress coordination state is removed")
def step_stress_state_removed(context):
    assert not STATE_FILE.exists()
    assert not READY_MARKER.exists()
    assert not CRASH_MARKER.exists()
