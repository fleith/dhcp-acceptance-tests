#!/usr/bin/env python3
"""Detect network configuration from the test interface and run behave."""
import ipaddress
import os
import subprocess
import sys


def get_interface_info(iface):
    out = subprocess.check_output(['ip', '-4', 'addr', 'show', iface]).decode()
    for line in out.split('\n'):
        line = line.strip()
        if line.startswith('inet '):
            ip_prefix = line.split()[1]
            ip = ip_prefix.split('/')[0]
            net = ipaddress.ip_network(ip_prefix, strict=False)
            return ip, str(net)
    raise RuntimeError(f"No IPv4 address found on interface {iface}")


iface = os.getenv('TEST_INTERFACE', 'eth0')
iface_ip, subnet = get_interface_info(iface)
server_ip = os.getenv('TEST_SERVER_IP', iface_ip)

env = os.environ.copy()
env.setdefault('TEST_SERVER_IP', server_ip)
env.setdefault('TEST_SUBNET', subnet)
env.setdefault('TEST_INTERFACE', iface)

print(
    f"[test-runner] iface={iface} iface_ip={iface_ip} server_ip={server_ip} subnet={subnet}",
    flush=True,
)

result = subprocess.run([sys.executable, '-m', 'behave'] + sys.argv[1:], env=env)
sys.exit(result.returncode)
