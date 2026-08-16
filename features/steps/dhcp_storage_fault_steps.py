"""Orchestrated DHCPv4 runtime lease-storage failure acceptance steps."""

import json
import os
import time
from pathlib import Path

from behave import given, then, when

from dhcpv4_load_support import (
    BOOTP,
    PARAMETER_REQUEST_LIST,
    SERVER_IP,
    assert_unique,
    build_client_packet,
    capture_exchange,
    commit_batch,
    dhcp_option,
    message_type,
    new_mac,
    release_batch,
    selection_request,
    unique_xid,
)
from dhcpv4_support import require_scapy_v4


STATE_DIR = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))
STATE_FILE = STATE_DIR / "dhcpv4-storage-fault-state.json"
FAULT_MARKER = STATE_DIR / "dhcpv4-storage-fault-active"
RESULTS_DIR = Path(os.getenv("TEST_RESULTS_DIR", "/app/test-results/default"))

BASELINE_CLIENTS = int(
    os.getenv("TEST_DHCPV4_STORAGE_BASELINE_CLIENTS", "10")
)
POOL_CAPACITY = int(os.getenv("TEST_DHCPV4_STORAGE_POOL_CAPACITY", "11"))
FAULT_TIMEOUT = float(os.getenv("TEST_DHCPV4_STORAGE_FAULT_TIMEOUT", "4"))
RECOVERY_TIMEOUT = float(
    os.getenv("TEST_DHCPV4_STORAGE_RECOVERY_TIMEOUT", "10")
)


def _state(context):
    if not hasattr(context, "dhcpv4_storage_fault"):
        context.dhcpv4_storage_fault = {}
    return context.dhcpv4_storage_fault


def _save_state(data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_state():
    assert STATE_FILE.exists(), (
        f"Storage-fault state file does not exist: {STATE_FILE}"
    )
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def _discover_for_mac(mac, timeout):
    used_xids = set()
    xid = unique_xid(used_xids)
    entry = {
        "mac": mac,
        "xid": xid,
        "packet": build_client_packet(
            mac,
            xid,
            [
                ("message-type", "discover"),
                ("param_req_list", PARAMETER_REQUEST_LIST),
                "end",
            ],
        ),
    }
    responses, latencies = capture_exchange(
        [entry], {2, 5, 6}, timeout=timeout
    )
    packets = responses.get(xid, [])
    assert not [packet for packet in packets if message_type(packet) in {5, 6}], (
        "DHCPDISCOVER unexpectedly received DHCPACK or DHCPNAK"
    )
    offers = [packet for packet in packets if message_type(packet) == 2]
    if not offers:
        return None, latencies
    addresses = {packet[BOOTP].yiaddr for packet in offers}
    assert len(addresses) == 1, (
        f"Storage-fault client received conflicting offers: {addresses}"
    )
    entry["ip"] = addresses.pop()
    entry["server_id"] = dhcp_option(offers[0], "server_id") or SERVER_IP
    return entry, latencies


def _commit_known_client(mac, timeout):
    client, offer_latencies = _discover_for_mac(mac, timeout)
    assert client is not None, "Recovered server did not offer a lease"
    request = {**client, "packet": selection_request(client)}
    responses, commit_latencies = capture_exchange(
        [request], {5, 6}, timeout=timeout
    )
    packets = responses.get(client["xid"], [])
    assert not [packet for packet in packets if message_type(packet) == 6], (
        f"Recovered server rejected offered address {client['ip']}"
    )
    acknowledgements = [
        packet for packet in packets if message_type(packet) == 5
    ]
    assert acknowledgements, (
        f"Recovered server did not acknowledge offered address {client['ip']}"
    )
    addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
    assert addresses == {client["ip"]}
    return {
        "mac": client["mac"],
        "xid": client["xid"],
        "ip": client["ip"],
        "server_id": client["server_id"],
    }, offer_latencies + commit_latencies


@given("the isolated DHCPv4 storage-fault fixture is safely bounded")
def step_storage_fixture(context):
    require_scapy_v4()
    assert 2 <= BASELINE_CLIENTS <= 16
    assert BASELINE_CLIENTS + 1 <= POOL_CAPACITY
    assert 2 <= FAULT_TIMEOUT <= 30
    assert 2 <= RECOVERY_TIMEOUT <= 60
    for path in (STATE_FILE, FAULT_MARKER):
        path.unlink(missing_ok=True)


@when("a durable DHCPv4 baseline batch is committed")
def step_storage_baseline(context):
    leases, metrics = commit_batch(BASELINE_CLIENTS)
    assert_unique(leases, "durable pre-fault batch")
    data = {
        "schema_version": 1,
        "baseline": leases,
        "contender": None,
        "fault_outcome": None,
        "metrics": {
            "baseline_clients": len(leases),
            "baseline_elapsed_seconds": metrics["elapsed_seconds"],
        },
    }
    _save_state(data)
    _state(context)["data"] = data


@then("every pre-fault binding is unique and recorded")
def step_storage_baseline_recorded(context):
    data = _state(context)["data"]
    assert len(data["baseline"]) == BASELINE_CLIENTS
    assert_unique(data["baseline"], "recorded durable pre-fault bindings")
    assert STATE_FILE.exists()


@given("recorded durable DHCPv4 bindings and an active storage fault")
def step_storage_fault_active(context):
    data = _load_state()
    assert len(data["baseline"]) == BASELINE_CLIENTS
    assert_unique(data["baseline"], "durable bindings before fault")
    assert FAULT_MARKER.exists(), (
        "The host runner did not verify and mark the active storage fault"
    )
    _state(context)["data"] = data


@when("a new DHCPv4 client attempts to commit during the storage fault")
def step_storage_fault_attempt(context):
    data = _state(context)["data"]
    mac = new_mac()
    client, offer_latencies = _discover_for_mac(mac, FAULT_TIMEOUT)
    contender = {
        "mac": mac,
        "offered_ip": None,
        "acknowledged_ip": None,
        "server_id": None,
    }
    if client is None:
        data["fault_outcome"] = "no-offer"
        data["contender"] = contender
        data["metrics"]["fault_offer_latency_ms"] = offer_latencies
        _save_state(data)
        return

    contender["offered_ip"] = client["ip"]
    contender["server_id"] = client["server_id"]
    request = {**client, "packet": selection_request(client)}
    responses, commit_latencies = capture_exchange(
        [request], {5, 6}, timeout=FAULT_TIMEOUT
    )
    packets = responses.get(client["xid"], [])
    acknowledgements = [
        packet for packet in packets if message_type(packet) == 5
    ]
    negative_acknowledgements = [
        packet for packet in packets if message_type(packet) == 6
    ]
    assert not (acknowledgements and negative_acknowledgements), (
        "Storage-fault transaction received both DHCPACK and DHCPNAK"
    )
    if acknowledgements:
        addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
        assert addresses == {client["ip"]}
        contender["acknowledged_ip"] = client["ip"]
        data["fault_outcome"] = "ack"
    else:
        data["fault_outcome"] = (
            "nak" if negative_acknowledgements else "no-ack"
        )
    data["contender"] = contender
    data["metrics"]["fault_offer_latency_ms"] = offer_latencies
    data["metrics"]["fault_commit_latency_ms"] = commit_latencies
    _save_state(data)


@then("the storage-fault transaction outcome is recorded for recovery verification")
def step_storage_outcome_recorded(context):
    data = _state(context)["data"]
    assert data["fault_outcome"] in {"ack", "no-offer", "no-ack", "nak"}
    assert data["contender"]["mac"]
    if data["fault_outcome"] == "ack":
        assert data["contender"]["acknowledged_ip"]
    assert STATE_FILE.exists()


@given("recorded DHCPv4 storage-fault transaction state")
def step_storage_recovery_state(context):
    data = _load_state()
    assert data["fault_outcome"] in {"ack", "no-offer", "no-ack", "nak"}
    assert data["contender"]["mac"]
    assert not FAULT_MARKER.exists(), (
        "Storage-fault marker still exists after host recovery"
    )
    _state(context)["data"] = data


@when("every pre-fault client reasserts its recorded binding")
def step_storage_reassert(context):
    data = _state(context)["data"]
    used_xids = set()
    entries = []
    original_by_xid = {}
    for lease in data["baseline"]:
        xid = unique_xid(used_xids)
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
    responses, latencies = capture_exchange(
        entries, {5, 6}, timeout=RECOVERY_TIMEOUT
    )
    recovered = []
    for xid, lease in original_by_xid.items():
        packets = responses.get(xid, [])
        assert not [packet for packet in packets if message_type(packet) == 6], (
            f"Recovered server rejected durable binding {lease['ip']}"
        )
        acknowledgements = [
            packet for packet in packets if message_type(packet) == 5
        ]
        assert acknowledgements, (
            f"Recovered server did not acknowledge durable binding {lease['ip']}"
        )
        addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
        assert addresses == {lease["ip"]}
        recovered.append(lease["ip"])
    data["metrics"]["recovered_baseline_clients"] = len(recovered)
    data["metrics"]["recovery_latency_ms"] = latencies
    _state(context)["recovered"] = recovered
    _save_state(data)


@then("every durable binding remains owned by its original client")
def step_storage_ownership(context):
    data = _state(context)["data"]
    assert set(_state(context)["recovered"]) == {
        lease["ip"] for lease in data["baseline"]
    }


@when("the storage-fault client is reconciled after recovery")
def step_storage_reconcile(context):
    data = _state(context)["data"]
    contender = data["contender"]
    if data["fault_outcome"] == "ack":
        xid = unique_xid(set())
        entry = {
            "mac": contender["mac"],
            "xid": xid,
            "packet": build_client_packet(
                contender["mac"],
                xid,
                [
                    ("message-type", "request"),
                    ("requested_addr", contender["acknowledged_ip"]),
                    ("param_req_list", PARAMETER_REQUEST_LIST),
                    "end",
                ],
            ),
        }
        responses, latencies = capture_exchange(
            [entry], {5, 6}, timeout=RECOVERY_TIMEOUT
        )
        packets = responses.get(xid, [])
        assert not [packet for packet in packets if message_type(packet) == 6], (
            "Recovered server rejected the binding acknowledged during the fault"
        )
        acknowledgements = [
            packet for packet in packets if message_type(packet) == 5
        ]
        assert acknowledgements, (
            "Server lost the binding it acknowledged during the storage fault"
        )
        addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
        assert addresses == {contender["acknowledged_ip"]}
        lease = {
            "mac": contender["mac"],
            "xid": xid,
            "ip": contender["acknowledged_ip"],
            "server_id": contender["server_id"],
        }
    else:
        lease, latencies = _commit_known_client(
            contender["mac"], RECOVERY_TIMEOUT
        )
    data["recovered_contender"] = lease
    data["metrics"]["contender_recovery_latency_ms"] = latencies
    _save_state(data)


@then("its recovered state is consistent with the fault-time outcome")
def step_storage_reconcile_consistent(context):
    data = _state(context)["data"]
    active = data["baseline"] + [data["recovered_contender"]]
    assert_unique(active, "post-storage-recovery bindings")
    if data["fault_outcome"] == "ack":
        assert (
            data["recovered_contender"]["ip"]
            == data["contender"]["acknowledged_ip"]
        )


@then("all storage-fault bindings are released and metrics are written")
def step_storage_cleanup(context):
    data = _state(context)["data"]
    release_batch(data["baseline"] + [data["recovered_contender"]])
    time.sleep(0.2)
    report = {
        "fault_outcome": data["fault_outcome"],
        "baseline_addresses": [lease["ip"] for lease in data["baseline"]],
        "fault_offered_address": data["contender"]["offered_ip"],
        "recovered_contender_address": data["recovered_contender"]["ip"],
        "metrics": data["metrics"],
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / "dhcpv4-storage-fault-metrics.json"
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("\n[storage-fault-metrics] " + json.dumps(report, sort_keys=True))
    for state_path in (STATE_FILE, FAULT_MARKER):
        state_path.unlink(missing_ok=True)
