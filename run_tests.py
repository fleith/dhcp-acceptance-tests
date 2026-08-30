#!/usr/bin/env python3
"""Detect network configuration from the test interface and run behave."""
import ipaddress
import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from summarize_junit import read_reports


def get_interface_info(iface, family):
    if family == 4:
        out = subprocess.check_output(['ip', '-4', 'addr', 'show', iface]).decode()
        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('inet '):
                ip_prefix = line.split()[1]
                ip = ip_prefix.split('/')[0]
                net = ipaddress.ip_network(ip_prefix, strict=False)
                return ip, str(net)
        raise RuntimeError(f"No IPv4 address found on interface {iface}")

    if family == 6:
        out = subprocess.check_output(
            ['ip', '-6', '-o', 'addr', 'show', 'dev', iface, 'scope', 'global']
        ).decode()
        for line in out.splitlines():
            match = re.search(r'inet6\s+([0-9a-fA-F:]+/\d+)', line)
            if not match:
                continue
            ip_prefix = match.group(1)
            ip = ip_prefix.split('/')[0]
            net = ipaddress.ip_network(ip_prefix, strict=False)
            return ip, str(net)
        raise RuntimeError(f"No global IPv6 address found on interface {iface}")

    raise ValueError(f"Unsupported IP family: {family}")


def get_interface_for_address(address, family=4):
    if not address:
        raise RuntimeError("Automatic interface selection requires an address")
    family_flag = '-4' if family == 4 else '-6'
    out = subprocess.check_output(['ip', family_flag, '-o', 'addr', 'show']).decode()
    for line in out.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[3].split('/')[0] == address:
            return fields[1]
    raise RuntimeError(f"No interface owns configured address {address}")


def explicitly_requests_known_divergence(args):
    return any('@known_divergence' in arg for arg in args)


def explicitly_requests_pool_exhaustion(args):
    return any('@pool_exhaustion' in arg for arg in args)


def explicitly_requests_orchestrated(args):
    return any(
        '@orchestrated' in arg or '@persistence_' in arg
        for arg in args
    )


def explicitly_requests_focused_robustness(args):
    return any('@focused_robustness' in arg for arg in args)


def explicitly_requests_capabilities(args):
    return any('@capability' in arg or '@requires_' in arg for arg in args)


iface = os.getenv('TEST_INTERFACE', 'eth0').strip()
ip_version = os.getenv('TEST_IP_VERSION', 'v4').strip().lower()

if iface == 'auto':
    family = 6 if ip_version == 'v6' else 4
    iface = get_interface_for_address(
        os.getenv('TEST_INTERFACE_ADDRESS', '').strip(), family
    )

if ip_version == 'v4':
    iface_ip, subnet = get_interface_info(iface, 4)
    server_ip = os.getenv('TEST_SERVER_IP', '172.29.0.2')
elif ip_version == 'v6':
    iface_ip, subnet = get_interface_info(iface, 6)
    server_ip = os.getenv('TEST_SERVER_IPV6', 'fd00:29::2')
elif ip_version == 'dual':
    # Dual mode runs both families from run_dhcp_tests.sh using separate invocations.
    iface_ip, subnet = get_interface_info(iface, 4)
    server_ip = os.getenv('TEST_SERVER_IP', '172.29.0.2')
else:
    raise RuntimeError(f"Unsupported TEST_IP_VERSION='{ip_version}'. Use v4, v6, or dual.")

env = os.environ.copy()
env['TEST_INTERFACE'] = iface

if env.get('TEST_SECOND_INTERFACE', '').strip() == 'auto':
    env['TEST_SECOND_INTERFACE'] = get_interface_for_address(
        env.get('TEST_SECOND_INTERFACE_ADDRESS', '').strip(), 4
    )

if ip_version == 'v4':
    env.setdefault('TEST_SERVER_IP', server_ip)
    env.setdefault('TEST_SUBNET', subnet)
elif ip_version == 'v6':
    env.setdefault('TEST_SERVER_IPV6', server_ip)
    env.setdefault('TEST_SUBNET_V6', subnet)

behave_args = shlex.split(os.getenv('TEST_BEHAVE_ARGS', '')) + sys.argv[1:]
if ip_version == 'v4':
    behave_args = ['--tags=~@ipv6'] + behave_args
elif ip_version == 'v6':
    behave_args = ['--tags=@ipv6'] + behave_args

if not explicitly_requests_known_divergence(behave_args):
    behave_args = ['--tags=~@known_divergence'] + behave_args

if not explicitly_requests_pool_exhaustion(behave_args):
    behave_args = ['--tags=~@pool_exhaustion'] + behave_args

if not explicitly_requests_orchestrated(behave_args):
    behave_args = ['--tags=~@orchestrated'] + behave_args

if not explicitly_requests_focused_robustness(behave_args):
    behave_args = ['--tags=~@focused_robustness'] + behave_args

if not explicitly_requests_capabilities(behave_args):
    behave_args = ['--tags=~@capability'] + behave_args

results_dir = os.getenv('TEST_RESULTS_DIR', '/app/test-results/default')
shutil.rmtree(results_dir, ignore_errors=True)
os.makedirs(results_dir, exist_ok=True)
if '--junit' not in behave_args:
    behave_args = [
        '--junit',
        f'--junit-directory={results_dir}',
    ] + behave_args

print(
    f"[test-runner] ip_version={ip_version} iface={iface} iface_ip={iface_ip} "
    f"server_ip={server_ip} subnet={subnet} results={results_dir}",
    flush=True,
)

result = subprocess.run([sys.executable, '-m', 'behave'] + behave_args, env=env)
if result.returncode == 0 and env.get('TEST_REQUIRE_EXECUTED_SCENARIOS') == '1':
    _, totals, _ = read_reports(Path(results_dir))
    executed = max(
        totals['tests'] - totals['failures'] - totals['errors'] - totals['skipped'],
        0,
    )
    if executed == 0:
        print(
            '[test-runner] ERROR: focused invocation executed zero scenarios',
            flush=True,
        )
        sys.exit(3)
sys.exit(result.returncode)
