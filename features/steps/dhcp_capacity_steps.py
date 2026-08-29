"""Large-pool DHCPv4 capacity, endurance, and resource-scaling steps."""

import ipaddress
import json
import os
import statistics
import time
from collections import Counter
from pathlib import Path

from behave import given, then, when

from dhcpv4_load_support import (
    assert_unique,
    capture_exchange,
    commit_batch,
    message_type,
    new_mac,
    percentile,
    release_batch,
    unique_xid,
)
from dhcpv4_support import BOOTP, build_client_packet, require_scapy_v4


STATE_DIR = Path(os.getenv("TEST_STATE_DIR", "/app/test-state"))
STATE_FILE = STATE_DIR / "dhcpv4-capacity-state.json"
RESOURCE_FILE = STATE_DIR / "dhcpv4-capacity-resources.ndjson"
RESULTS_DIR = Path(os.getenv("TEST_RESULTS_DIR", "/app/test-results/default"))

POOL_START = os.getenv("TEST_DHCPV4_CAPACITY_POOL_START", "")
POOL_END = os.getenv("TEST_DHCPV4_CAPACITY_POOL_END", "")
POOL_SIZE = int(os.getenv("TEST_DHCPV4_CAPACITY_POOL_SIZE", "0"))
BATCH_SIZE = int(os.getenv("TEST_DHCPV4_CAPACITY_BATCH_SIZE", "64"))
REPLACEMENTS = int(os.getenv("TEST_DHCPV4_CAPACITY_REPLACEMENTS", "64"))
POST_BATCH_SIZE = int(os.getenv("TEST_DHCPV4_CAPACITY_POST_BATCH_SIZE", "16"))
CAPTURE_TIMEOUT = float(
    os.getenv("TEST_DHCPV4_CAPACITY_CAPTURE_TIMEOUT", "15")
)
BATCH_DEADLINE = float(
    os.getenv("TEST_DHCPV4_CAPACITY_BATCH_DEADLINE", "30")
)
P95_LIMIT_MS = float(
    os.getenv("TEST_DHCPV4_CAPACITY_P95_LIMIT_MS", "5000")
)
MIN_COMMITS_PER_SECOND = float(
    os.getenv("TEST_DHCPV4_CAPACITY_MIN_COMMITS_PER_SECOND", "1")
)
RELEASE_SETTLE_SECONDS = float(
    os.getenv("TEST_DHCPV4_CAPACITY_RELEASE_SETTLE_SECONDS", "0.5")
)
DURATION_SECONDS = float(
    os.getenv("TEST_DHCPV4_CAPACITY_DURATION_SECONDS", "3600")
)
MIN_ENDURANCE_COMMITS = int(
    os.getenv("TEST_DHCPV4_CAPACITY_MIN_ENDURANCE_COMMITS", "1024")
)
MEMORY_GROWTH_LIMIT_MIB = float(
    os.getenv("TEST_DHCPV4_CAPACITY_MEMORY_GROWTH_LIMIT_MIB", "256")
)
MEMORY_PER_LEASE_LIMIT_KIB = float(
    os.getenv("TEST_DHCPV4_CAPACITY_MEMORY_PER_LEASE_LIMIT_KIB", "512")
)
PIDS_GROWTH_LIMIT = int(
    os.getenv("TEST_DHCPV4_CAPACITY_PIDS_GROWTH_LIMIT", "8")
)
PARAMETER_REQUEST_LIST = [1, 3, 6, 15, 51, 58, 59]


def _state(context):
    if not hasattr(context, "dhcpv4_capacity"):
        context.dhcpv4_capacity = {}
    return context.dhcpv4_capacity


def _save_state(data):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_state():
    assert STATE_FILE.exists(), f"Capacity state file does not exist: {STATE_FILE}"
    return json.loads(STATE_FILE.read_text(encoding="utf-8"))


def _pool_bounds():
    assert POOL_START and POOL_END, (
        "Capacity tests require TEST_DHCPV4_CAPACITY_POOL_START and "
        "TEST_DHCPV4_CAPACITY_POOL_END"
    )
    start = ipaddress.IPv4Address(POOL_START)
    end = ipaddress.IPv4Address(POOL_END)
    assert start <= end, f"Capacity pool starts after it ends: {start} > {end}"
    calculated = int(end) - int(start) + 1
    assert calculated == POOL_SIZE, (
        f"Configured capacity pool size {POOL_SIZE} does not match "
        f"{start}-{end} ({calculated} addresses)"
    )
    return start, end


def _latency_summary(values):
    return {
        "count": len(values),
        "p50": round(percentile(values, 50), 3),
        "p95": round(percentile(values, 95), 3),
        "p99": round(percentile(values, 99), 3),
        "max": round(max(values, default=0.0), 3),
    }


def _commit_waves(total, label):
    leases = []
    waves = []
    remaining = total
    wave_number = 0
    started = time.monotonic()
    while remaining:
        wave_number += 1
        count = min(BATCH_SIZE, remaining)
        wave_leases, metrics = commit_batch(count)
        assert metrics["elapsed_seconds"] <= BATCH_DEADLINE, (
            f"{label} wave {wave_number} took {metrics['elapsed_seconds']:.3f}s; "
            f"limit is {BATCH_DEADLINE}s"
        )
        assert_unique(wave_leases, f"{label} wave {wave_number}")
        combined = leases + wave_leases
        assert_unique(combined, f"{label} cumulative active bindings")
        leases = combined
        waves.append(
            {
                "wave": wave_number,
                "commits": count,
                "elapsed_seconds": metrics["elapsed_seconds"],
                "offer_ms": metrics["offer_ms"],
                "commit_ms": metrics["commit_ms"],
            }
        )
        remaining -= count
    return leases, waves, time.monotonic() - started


def _all_latencies(data):
    values = []
    for wave in data["waves"]:
        values.extend(wave["offer_ms"])
        values.extend(wave["commit_ms"])
    values.extend(data.get("renew_ms", []))
    return values


def _renew_entry(lease, xid):
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


def _resource_summary():
    assert RESOURCE_FILE.exists(), (
        f"Capacity resource sample file does not exist: {RESOURCE_FILE}"
    )
    samples = []
    for line_number, line in enumerate(
        RESOURCE_FILE.read_text(encoding="utf-8").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            samples.append(
                {
                    "memory_mib": _parse_size_mib(
                        raw["MemUsage"].split("/", 1)[0].strip()
                    ),
                    "cpu_percent": float(raw["CPUPerc"].rstrip("%")),
                    "pids": int(raw["PIDs"]),
                }
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise AssertionError(
                f"Invalid capacity resource sample on line {line_number}: {error}"
            ) from error
    assert len(samples) >= 2, (
        f"Expected at least two capacity resource samples, found {len(samples)}"
    )
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


@given("the isolated DHCPv4 capacity profile is safely bounded")
def step_capacity_profile_bounded(context):
    require_scapy_v4()
    _pool_bounds()
    assert 128 <= POOL_SIZE <= 4096
    assert 8 <= BATCH_SIZE <= 128
    assert 1 <= REPLACEMENTS <= min(POOL_SIZE, 512)
    assert 1 <= POST_BATCH_SIZE <= 64
    assert 2 <= CAPTURE_TIMEOUT <= 120
    assert 2 <= BATCH_DEADLINE <= 180
    assert 100 <= P95_LIMIT_MS <= 30000
    assert 0.1 <= MIN_COMMITS_PER_SECOND <= 100000
    assert 0 <= RELEASE_SETTLE_SECONDS <= 10
    assert 1 <= DURATION_SECONDS <= 604800
    assert BATCH_SIZE <= MIN_ENDURANCE_COMMITS <= 10_000_000
    assert 0 <= MEMORY_GROWTH_LIMIT_MIB <= 8192
    assert 0 <= MEMORY_PER_LEASE_LIMIT_KIB <= 65536
    assert 0 <= PIDS_GROWTH_LIMIT <= 1024
    STATE_FILE.unlink(missing_ok=True)


@when("concurrent waves fill the configured DHCPv4 capacity pool")
def step_fill_capacity_pool(context):
    leases, waves, elapsed = _commit_waves(POOL_SIZE, "capacity fill")
    data = {
        "schema_version": 1,
        "mode": "scale",
        "profile": {
            "pool_start": POOL_START,
            "pool_end": POOL_END,
            "pool_size": POOL_SIZE,
            "batch_size": BATCH_SIZE,
            "replacements": REPLACEMENTS,
            "duration_seconds": 0,
        },
        "counts": {
            "lease_commits": len(leases),
            "renewals": 0,
            "replacements": 0,
            "post_capacity_commits": 0,
            "peak_active": len(leases),
            "unique_addresses": len({lease["ip"] for lease in leases}),
            "reused_allocations": 0,
        },
        "elapsed_seconds": elapsed,
        "waves": waves,
        "active_leases": leases,
        "renew_ms": [],
    }
    _save_state(data)
    _state(context)["data"] = data


@then("every large-pool binding is unique and within the configured pool")
def step_capacity_bindings_unique(context):
    data = _state(context)["data"]
    leases = data["active_leases"]
    start, end = _pool_bounds()
    assert len(leases) == POOL_SIZE
    assert_unique(leases, "full capacity pool")
    outside = [
        lease["ip"]
        for lease in leases
        if not start <= ipaddress.IPv4Address(lease["ip"]) <= end
    ]
    assert not outside, f"Capacity server allocated addresses outside its pool: {outside}"


@then("large-pool response latency and throughput meet configured limits")
def step_capacity_performance(context):
    data = _state(context)["data"]
    latencies = _all_latencies(data)
    latency = _latency_summary(latencies)
    rate = data["counts"]["lease_commits"] / data["elapsed_seconds"]
    assert latency["p95"] <= P95_LIMIT_MS, (
        f"Capacity response p95 was {latency['p95']}ms; limit is {P95_LIMIT_MS}ms"
    )
    assert rate >= MIN_COMMITS_PER_SECOND, (
        f"Capacity commit rate was {rate:.3f}/s; minimum is "
        f"{MIN_COMMITS_PER_SECOND}/s"
    )
    data["latency_ms"] = latency
    data["commits_per_second"] = round(rate, 3)
    _save_state(data)


@when("every large-pool binding is renewed by its original client")
def step_renew_capacity_bindings(context):
    data = _state(context)["data"]
    leases = data["active_leases"]
    renewed = []
    latencies = []
    used_xids = set()
    for offset in range(0, len(leases), BATCH_SIZE):
        batch = leases[offset : offset + BATCH_SIZE]
        entries = [
            _renew_entry(lease, unique_xid(used_xids)) for lease in batch
        ]
        responses, batch_latencies = capture_exchange(
            entries,
            {5, 6},
            timeout=CAPTURE_TIMEOUT,
        )
        for entry in entries:
            packets = responses.get(entry["xid"], [])
            assert not [packet for packet in packets if message_type(packet) == 6], (
                f"Server rejected capacity renewal for {entry['ip']}"
            )
            acknowledgements = [
                packet for packet in packets if message_type(packet) == 5
            ]
            assert acknowledgements, f"No renewal ACK for capacity lease {entry['ip']}"
            addresses = {packet[BOOTP].yiaddr for packet in acknowledgements}
            assert addresses <= {entry["ip"], "0.0.0.0"}, (
                f"Capacity renewal changed {entry['ip']} to {addresses}"
            )
            renewed.append(entry["ip"])
        latencies.extend(batch_latencies)
    data["renewed_addresses"] = renewed
    data["renew_ms"] = latencies
    data["counts"]["renewals"] = len(renewed)
    _save_state(data)


@then("every large-pool renewal preserves its binding")
def step_capacity_renewals_preserve_bindings(context):
    data = _state(context)["data"]
    expected = {lease["ip"] for lease in data["active_leases"]}
    assert len(data["renewed_addresses"]) == POOL_SIZE
    assert set(data["renewed_addresses"]) == expected


@when("one additional client discovers against the full capacity pool")
def step_discover_against_full_pool(context):
    used_xids = set()
    client = {
        "mac": new_mac(),
        "xid": unique_xid(used_xids),
    }
    client["packet"] = build_client_packet(
        client["mac"],
        client["xid"],
        [
            ("message-type", "discover"),
            ("param_req_list", PARAMETER_REQUEST_LIST),
            "end",
        ],
    )
    responses, _ = capture_exchange(
        [client],
        {2, 5, 6},
        timeout=min(CAPTURE_TIMEOUT, 5),
    )
    _state(context)["full_pool_responses"] = responses.get(client["xid"], [])


@then("the full capacity pool returns no offer")
def step_full_pool_returns_no_offer(context):
    offers = [
        packet
        for packet in _state(context)["full_pool_responses"]
        if message_type(packet) == 2
    ]
    assert not offers, "An additional client received an OFFER from the full pool"


@when("a configured capacity subset is released and replaced concurrently")
def step_release_and_replace_capacity_subset(context):
    data = _state(context)["data"]
    released = data["active_leases"][:REPLACEMENTS]
    survivors = data["active_leases"][REPLACEMENTS:]
    released_addresses = {lease["ip"] for lease in released}
    release_batch(released)
    time.sleep(RELEASE_SETTLE_SECONDS)
    replacements, waves, elapsed = _commit_waves(REPLACEMENTS, "capacity replacement")
    replacement_addresses = {lease["ip"] for lease in replacements}
    survivor_addresses = {lease["ip"] for lease in survivors}
    assert replacement_addresses == released_addresses, (
        "Capacity replacement did not reuse exactly the released address set: "
        f"released={sorted(released_addresses)} replacement={sorted(replacement_addresses)}"
    )
    assert not replacement_addresses & survivor_addresses
    active = survivors + replacements
    assert_unique(active, "capacity bindings after replacement")
    data["active_leases"] = active
    data["replacement_addresses"] = sorted(replacement_addresses)
    data["released_addresses"] = sorted(released_addresses)
    data["counts"]["lease_commits"] += len(replacements)
    data["counts"]["replacements"] = len(replacements)
    data["counts"]["reused_allocations"] += len(replacements)
    data["waves"].extend(waves)
    data["elapsed_seconds"] += elapsed
    _save_state(data)


@then("only released capacity addresses are reassigned without conflicts")
def step_capacity_replacements_are_safe(context):
    data = _state(context)["data"]
    assert data["replacement_addresses"] == data["released_addresses"]
    assert len(data["active_leases"]) == POOL_SIZE
    assert_unique(data["active_leases"], "full pool after replacement")


@when("DHCPv4 capacity batches churn for the configured duration")
def step_duration_based_capacity_churn(context):
    started = time.monotonic()
    waves = []
    address_counts = Counter()
    commits = 0
    while (
        time.monotonic() - started < DURATION_SECONDS
        or commits < MIN_ENDURANCE_COMMITS
    ):
        leases, metrics = commit_batch(BATCH_SIZE)
        assert_unique(leases, f"capacity endurance wave {len(waves) + 1}")
        assert metrics["elapsed_seconds"] <= BATCH_DEADLINE
        addresses = [lease["ip"] for lease in leases]
        address_counts.update(addresses)
        commits += len(leases)
        waves.append(
            {
                "wave": len(waves) + 1,
                "commits": len(leases),
                "elapsed_seconds": metrics["elapsed_seconds"],
                "offer_ms": metrics["offer_ms"],
                "commit_ms": metrics["commit_ms"],
            }
        )
        release_batch(leases)
        time.sleep(RELEASE_SETTLE_SECONDS)
    elapsed = time.monotonic() - started
    data = {
        "schema_version": 1,
        "mode": "endurance",
        "profile": {
            "pool_start": POOL_START,
            "pool_end": POOL_END,
            "pool_size": POOL_SIZE,
            "batch_size": BATCH_SIZE,
            "replacements": 0,
            "duration_seconds": DURATION_SECONDS,
        },
        "counts": {
            "lease_commits": commits,
            "renewals": 0,
            "replacements": 0,
            "post_capacity_commits": 0,
            "peak_active": BATCH_SIZE,
            "unique_addresses": len(address_counts),
            "reused_allocations": sum(
                count - 1 for count in address_counts.values() if count > 1
            ),
        },
        "elapsed_seconds": elapsed,
        "waves": waves,
        "active_leases": [],
        "renew_ms": [],
    }
    _save_state(data)
    _state(context)["data"] = data


@then("every endurance transaction is unique and the minimum volume completes")
def step_endurance_volume_and_uniqueness(context):
    data = _state(context)["data"]
    assert data["counts"]["lease_commits"] >= MIN_ENDURANCE_COMMITS
    assert data["elapsed_seconds"] >= DURATION_SECONDS
    assert all(wave["commits"] == BATCH_SIZE for wave in data["waves"])


@then("released capacity addresses are reused during endurance")
def step_endurance_reuses_addresses(context):
    data = _state(context)["data"]
    assert data["counts"]["lease_commits"] > POOL_SIZE
    assert data["counts"]["reused_allocations"] > 0


@then("the DHCPv4 capacity state is recorded")
def step_capacity_state_recorded(context):
    data = _load_state()
    assert data["counts"]["lease_commits"] > 0


@given("recorded DHCPv4 capacity state and server resource samples")
def step_recorded_capacity_state(context):
    data = _load_state()
    data["resources"] = _resource_summary()
    _state(context)["data"] = data


@then("DHCPv4 capacity memory and process scaling meet configured limits")
def step_capacity_resource_scaling(context):
    data = _state(context)["data"]
    resources = data["resources"]
    memory_growth = max(0.0, resources["memory_mib"]["growth"])
    peak_active = data["counts"]["peak_active"]
    memory_per_lease_kib = memory_growth * 1024 / peak_active
    pids_growth = resources["pids"]["growth"]
    assert memory_growth <= MEMORY_GROWTH_LIMIT_MIB, (
        f"Capacity memory grew by {memory_growth:.3f} MiB; limit is "
        f"{MEMORY_GROWTH_LIMIT_MIB} MiB"
    )
    assert memory_per_lease_kib <= MEMORY_PER_LEASE_LIMIT_KIB, (
        f"Capacity memory growth was {memory_per_lease_kib:.3f} KiB/peak lease; "
        f"limit is {MEMORY_PER_LEASE_LIMIT_KIB} KiB"
    )
    assert pids_growth <= PIDS_GROWTH_LIMIT, (
        f"Capacity PID count grew by {pids_growth}; limit is {PIDS_GROWTH_LIMIT}"
    )
    resources["memory_kib_per_peak_lease"] = round(memory_per_lease_kib, 3)
    _save_state(data)


@when("all recorded DHCPv4 capacity bindings are released")
def step_release_all_capacity_bindings(context):
    data = _state(context)["data"]
    release_batch(data["active_leases"])
    data["active_leases"] = []
    time.sleep(RELEASE_SETTLE_SECONDS)
    _save_state(data)


@then("a fresh DHCPv4 batch succeeds after the capacity run")
def step_post_capacity_availability(context):
    data = _state(context)["data"]
    leases, metrics = commit_batch(POST_BATCH_SIZE)
    assert_unique(leases, "post-capacity availability batch")
    assert len(leases) == POST_BATCH_SIZE
    assert metrics["elapsed_seconds"] <= BATCH_DEADLINE
    data["counts"]["post_capacity_commits"] = len(leases)
    data["post_capacity_latency_ms"] = _latency_summary(
        metrics["offer_ms"] + metrics["commit_ms"]
    )
    release_batch(leases)
    time.sleep(RELEASE_SETTLE_SECONDS)
    _save_state(data)


@then("the DHCPv4 capacity metrics report is written")
def step_write_capacity_metrics(context):
    data = _state(context)["data"]
    report = {
        key: data[key]
        for key in (
            "mode",
            "profile",
            "counts",
            "elapsed_seconds",
            "commits_per_second",
            "latency_ms",
            "post_capacity_latency_ms",
            "resources",
        )
    }
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    path = RESULTS_DIR / "dhcpv4-capacity-metrics.json"
    path.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print("\n[capacity-metrics] " + json.dumps(report, sort_keys=True))
    for state_path in (STATE_FILE, RESOURCE_FILE):
        state_path.unlink(missing_ok=True)
