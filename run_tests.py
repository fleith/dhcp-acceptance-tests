#!/usr/bin/env python3
"""Detect network configuration from the test interface and run behave."""
import ipaddress
import os
import re
import subprocess
import sys


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


def has_explicit_tags(args):
    return any(arg == '--tags' or arg.startswith('--tags=') for arg in args)


iface = os.getenv('TEST_INTERFACE', 'eth0')
ip_version = os.getenv('TEST_IP_VERSION', 'v4').strip().lower()

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
env.setdefault('TEST_INTERFACE', iface)

if ip_version == 'v4':
    env.setdefault('TEST_SERVER_IP', server_ip)
    env.setdefault('TEST_SUBNET', subnet)
elif ip_version == 'v6':
    env.setdefault('TEST_SERVER_IPV6', server_ip)
    env.setdefault('TEST_SUBNET_V6', subnet)

behave_args = sys.argv[1:]
if not has_explicit_tags(behave_args):
    if ip_version == 'v4':
        behave_args = ['--tags=~@ipv6'] + behave_args
    elif ip_version == 'v6':
        behave_args = ['--tags=@ipv6'] + behave_args

print(
    f"[test-runner] ip_version={ip_version} iface={iface} iface_ip={iface_ip} "
    f"server_ip={server_ip} subnet={subnet}",
    flush=True,
)

result = subprocess.run([sys.executable, '-m', 'behave'] + behave_args, env=env)
sys.exit(result.returncode)