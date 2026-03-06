"""Behave environment hooks for the DHCP acceptance tests."""
import os
import sys


def _random_mac():
    """Generate a random locally-administered unicast MAC address."""
    rb = os.urandom(3)
    return f"02:00:00:{rb[0]:02x}:{rb[1]:02x}:{rb[2]:02x}"


def _steps_module():
    """Import dhcp_steps, adding its directory to sys.path if needed."""
    steps_dir = os.path.join(os.path.dirname(__file__), 'steps')
    if steps_dir not in sys.path:
        sys.path.insert(0, steps_dir)
    import dhcp_steps
    return dhcp_steps


def before_scenario(context, scenario):
    """Reset shared state and assign a fresh client MAC before each scenario.

    Using a unique MAC per scenario prevents ISC dhcpd from reusing an existing
    binding from a previous scenario.  Without this, dhcpd gives the remaining
    lease time of the old binding (e.g. 110 s instead of the configured 120 s),
    which would make the T1/T2 percentage checks unreliable.
    """
    steps = _steps_module()
    steps.context_storage.clear()
    steps.context_storage['client_mac'] = _random_mac()


def after_scenario(context, scenario):
    """Clean up temporary per-scenario network state."""
    steps = _steps_module()
    inform_ip = steps.context_storage.get('inform_ip')
    if steps.context_storage.get('inform_ip_added') and inform_ip:
        steps._remove_interface_ipv4(inform_ip)
