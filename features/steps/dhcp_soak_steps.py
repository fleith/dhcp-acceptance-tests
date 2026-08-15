"""Bounded DHCPv4 soak, pool-reuse, latency, and resource-regression steps."""

import json
import os
import statistics
import time
from collections import Counter
from pathlib import Path

from behave import given, then, when

from dhcpv4_load_support import (
    assert_unique,
    commit_batch,
    percentile,
    release_batch,
)
from dhcpv4_support import require_scapy_v4


STATE_DIR = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))
STATE_FILE = STATE_DIR / "dhcpv4-soak-state.json"
READY_MARKER = STATE_DIR / "dhcpv4-soak-ready"
RESOURCE_FILE = STATE_DIR / "dhcpv4-soak-resources.ndjson"
RESULTS_DIR = Path(os.getenv("TEST_RESULTS_DIR", "/app/test-results/default"))

ROUNDS = int(os.getenv("TEST_DHCPV4_SOAK_ROUNDS", "8"))
BATCH_SIZE = int(os.getenv("TEST_DHCPV4_SOAK_BATCH_SIZE", "16"))
POST_BATCH_SIZE = int(os.getenv("TEST_DHCPV4_SOAK_POST_BATCH_SIZE", "8"))
POOL_CAPACITY = int(os.getenv("TEST_DHCPV4_SOAK_POOL_CAPACITY", "101"))
RELEASE_SETTLE_SECONDS = float(
    os.getenv("TEST_DHCPV4_SOAK_RELEASE_SETTLE_SECONDS", "0.2")
)
BATCH_DEADLINE = float(os.getenv("TEST_DHCPV4_SOAK_BATCH_DEADLINE", "20"))
P95_LIMIT_MS = float(os.getenv("TEST_DHCPV4_SOAK_P95_LIMIT_MS", "3000"))
LATENCY_GROWTH_LIMIT_MS = float(
    os.getenv("TEST_DHCPV4_SOAK_LATENCY_GROWTH_LIMIT_MS", "500")
)
MEMORY_GROWTH_LIMIT_MIB = float(
    os.getenv("TEST_DHCPV4_SOAK_MEMORY_GROWTH_LIMIT_MIB", "64")
)
PIDS_GROWTH_LIMIT = int(
    os.getenv("TEST_DHCPV4_SOAK_PIDS_GROWTH_LIMIT", "8")
)


def _state(context):
    if not hasattr(context, "dhcpv4_soak"):
        context.dhcpv4_soak = {}
    return context.dhcpv4_soak


def _save_state(data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_state():
    assert STATE_FILE.exists(), f"Soak state file does not exist: {STATE_FILE}"
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def _latency_summary(values):
    return {
        "count": len(values),
        "p50": round(percentile(values, 50), 3),
        "p95": round(percentile(values, 95), 3),
        "p99": round(percentile(values, 99), 3),
        "max": round(max(values, default=0.0), 3),
    }


def _parse_size_mib(value):
    text = value.strip()
    units = {
        "b": 1.0 / (1024 * 1024),
        "kb": 1000.0 / (1024 * 1024),
        "kib": 1.0 / 1024,
        "mb": 1_000_000.0 / (1024 * 1024),
        "mib": 1.0,
        "gb": 1_000_000_000.0 / (1024 * 1024),
        "gib": 1024.0,
    }
    lowered = text.lower()
    for unit in sorted(units, key=len, reverse=True):
        if lowered.endswith(unit):
            return float(text[: -len(unit)].strip()) * units[unit]
    raise AssertionError(f"Unsupported Docker memory value: {value!r}")


def _parse_resource_samples():
    assert RESOURCE_FILE.exists(), (
        f"Server resource sample file does not exist: {RESOURCE_FILE}"
    )
    samples = []
    for line_number, line in enumerate(
        RESOURCE_FILE.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            used_memory = raw["MemUsage"].split("/", 1)[0].strip()
            samples.append(
                {
                    "captured_at": raw.get("captured_at"),
                    "memory_mib": _parse_size_mib(used_memory),
                    "cpu_percent": float(raw["CPUPerc"].rstrip("%")),
                    "pids": int(raw["PIDs"]),
                }
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise AssertionError(
                f"Invalid Docker resource sample on line {line_number}: {error}"
            ) from error
    assert len(samples) >= 2, (
        f"Expected at least two server resource samples, found {len(samples)}"
    )
    return samples


def _resource_summary(samples):
    memory = [sample["memory_mib"] for sample in samples]
    cpu = [sample["cpu_percent"] for sample in samples]
    pids = [sample["pids"] for sample in samples]
    return {
        "samples": len(samples),
        "memory_mib": {
            "baseline": round(memory[0], 3),
            "final": round(memory[-1], 3),
            "peak": round(max(memory), 3),
            "growth": round(memory[-1] - memory[0], 3),
        },
        "cpu_percent": {
            "mean": round(statistics.fmean(cpu), 3),
            "p95": round(percentile(cpu, 95), 3),
            "max": round(max(cpu), 3),
        },
        "pids": {
            "baseline": pids[0],
            "final": pids[-1],
            "peak": max(pids),
            "growth": pids[-1] - pids[0],
        },
    }


@given("the isolated DHCPv4 soak profile is safely bounded")
def step_soak_bounded(context):
    require_scapy_v4()
    assert 2 <= ROUNDS <= 1000
    assert 2 <= BATCH_SIZE <= 96
    assert 1 <= POST_BATCH_SIZE <= 32
    assert BATCH_SIZE + POST_BATCH_SIZE <= POOL_CAPACITY
    assert ROUNDS * BATCH_SIZE > POOL_CAPACITY, (
        "Soak profile must request more leases than the pool can supply without "
        "reusing released addresses"
    )
    assert 0 <= RELEASE_SETTLE_SECONDS <= 5
    assert 2 <= BATCH_DEADLINE <= 120
    assert 100 <= P95_LIMIT_MS <= 30000
    assert 0 <= LATENCY_GROWTH_LIMIT_MS <= 10000
    assert 0 <= MEMORY_GROWTH_LIMIT_MIB <= 4096
    assert 0 <= PIDS_GROWTH_LIMIT <= 256
    for path in (STATE_FILE, READY_MARKER, RESOURCE_FILE):
        path.unlink(missing_ok=True)


@when("repeated DHCPv4 soak batches acquire and release leases")
def step_soak_churn(context):
    started = time.monotonic()
    address_counts = Counter()
    round_metrics = []
    total_committed = 0
    total_released = 0

    for round_number in range(1, ROUNDS + 1):
        leases, metrics = commit_batch(BATCH_SIZE)
        assert_unique(leases, f"soak round {round_number}")
        assert len(leases) == BATCH_SIZE
        assert metrics["elapsed_seconds"] <= BATCH_DEADLINE, (
            f"Soak round {round_number} took {metrics['elapsed_seconds']:.3f}s; "
            f"limit is {BATCH_DEADLINE}s"
        )
        addresses = [lease["ip"] for lease in leases]
        address_counts.update(addresses)
        total_committed += len(leases)
        round_metrics.append(
            {
                "round": round_number,
                "elapsed_seconds": metrics["elapsed_seconds"],
                "offer_ms": metrics["offer_ms"],
                "commit_ms": metrics["commit_ms"],
                "addresses": addresses,
            }
        )
        if round_number == 1:
            READY_MARKER.write_text(
                "first DHCPv4 soak batch committed\n", encoding="utf-8"
            )
        release_batch(leases)
        total_released += len(leases)
        time.sleep(RELEASE_SETTLE_SECONDS)

    data = {
        "schema_version": 1,
        "profile": {
            "rounds": ROUNDS,
            "batch_size": BATCH_SIZE,
            "post_batch_size": POST_BATCH_SIZE,
            "pool_capacity": POOL_CAPACITY,
        },
        "counts": {
            "rounds_completed": len(round_metrics),
            "lease_commits": total_committed,
            "lease_releases": total_released,
            "unique_addresses": len(address_counts),
            "reused_allocations": sum(
                count - 1 for count in address_counts.values() if count > 1
            ),
            "post_soak_commits": 0,
        },
        "elapsed_seconds": time.monotonic() - started,
        "rounds": round_metrics,
    }
    _save_state(data)
    _state(context)["data"] = data


@then("every DHCPv4 soak transaction completes without active duplication")
def step_soak_transactions(context):
    data = _state(context)["data"]
    expected = ROUNDS * BATCH_SIZE
    assert data["counts"]["rounds_completed"] == ROUNDS
    assert data["counts"]["lease_commits"] == expected
    assert data["counts"]["lease_releases"] == expected
    assert all(len(set(item["addresses"])) == BATCH_SIZE for item in data["rounds"])


@then("released DHCPv4 pool addresses are reused without conflicts")
def step_pool_reuse(context):
    data = _state(context)["data"]
    assert data["counts"]["unique_addresses"] <= POOL_CAPACITY
    assert data["counts"]["reused_allocations"] > 0, (
        "No released address was reused during the bounded soak"
    )


@then("DHCPv4 response latency remains stable through the soak")
def step_latency_stable(context):
    data = _state(context)["data"]
    window = max(1, min(5, ROUNDS // 4))
    early = data["rounds"][:window]
    late = data["rounds"][-window:]
    all_values = [
        value
        for item in data["rounds"]
        for key in ("offer_ms", "commit_ms")
        for value in item[key]
    ]
    early_values = [
        value
        for item in early
        for key in ("offer_ms", "commit_ms")
        for value in item[key]
    ]
    late_values = [
        value
        for item in late
        for key in ("offer_ms", "commit_ms")
        for value in item[key]
    ]
    overall_p95 = percentile(all_values, 95)
    early_p95 = percentile(early_values, 95)
    late_p95 = percentile(late_values, 95)
    drift = late_p95 - early_p95
    assert overall_p95 <= P95_LIMIT_MS, (
        f"Soak response p95 was {overall_p95:.3f}ms; limit is {P95_LIMIT_MS}ms"
    )
    assert drift <= LATENCY_GROWTH_LIMIT_MS, (
        f"Late-window p95 grew by {drift:.3f}ms; limit is "
        f"{LATENCY_GROWTH_LIMIT_MS}ms"
    )
    data["latency_ms"] = {
        "overall": _latency_summary(all_values),
        "early_window": _latency_summary(early_values),
        "late_window": _latency_summary(late_values),
        "p95_growth": round(drift, 3),
        "window_rounds": window,
    }
    _save_state(data)


@given("completed DHCPv4 soak state and server resource samples")
def step_completed_soak(context):
    data = _load_state()
    assert data["counts"]["rounds_completed"] == ROUNDS
    samples = _parse_resource_samples()
    data["resources"] = _resource_summary(samples)
    _state(context)["data"] = data


@then("DHCPv4 server memory and process growth remain within configured limits")
def step_resource_limits(context):
    resources = _state(context)["data"]["resources"]
    memory_growth = resources["memory_mib"]["growth"]
    pids_growth = resources["pids"]["growth"]
    assert memory_growth <= MEMORY_GROWTH_LIMIT_MIB, (
        f"Server memory grew by {memory_growth:.3f} MiB; limit is "
        f"{MEMORY_GROWTH_LIMIT_MIB} MiB"
    )
    assert pids_growth <= PIDS_GROWTH_LIMIT, (
        f"Server PID count grew by {pids_growth}; limit is {PIDS_GROWTH_LIMIT}"
    )


@then("a fresh DHCPv4 batch succeeds after the soak")
def step_post_soak_available(context):
    data = _state(context)["data"]
    leases, metrics = commit_batch(POST_BATCH_SIZE)
    assert_unique(leases, "post-soak availability batch")
    assert len(leases) == POST_BATCH_SIZE
    assert metrics["elapsed_seconds"] <= BATCH_DEADLINE
    data["counts"]["post_soak_commits"] = len(leases)
    data["post_soak_latency_ms"] = _latency_summary(
        metrics["offer_ms"] + metrics["commit_ms"]
    )
    release_batch(leases)
    time.sleep(RELEASE_SETTLE_SECONDS)
    _save_state(data)


@then("the DHCPv4 soak metrics report is written")
def step_write_soak_metrics(context):
    data = _state(context)["data"]
    report = {
        key: data[key]
        for key in (
            "profile",
            "counts",
            "elapsed_seconds",
            "latency_ms",
            "post_soak_latency_ms",
            "resources",
        )
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / "dhcpv4-soak-metrics.json"
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("\n[soak-metrics] " + json.dumps(report, sort_keys=True))
    for state_path in (STATE_FILE, READY_MARKER, RESOURCE_FILE):
        state_path.unlink(missing_ok=True)
