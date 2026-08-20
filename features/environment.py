"""Behave environment hooks for the DHCP acceptance tests."""
import os
import sys


def _random_mac():
    """Generate a random locally-administered unicast MAC address."""
    rb = os.urandom(3)
    return f"02:00:00:{rb[0]:02x}:{rb[1]:02x}:{rb[2]:02x}"


def _import_steps_module(module_name):
    """Import a steps module, adding features/steps to sys.path if needed."""
    steps_dir = os.path.join(os.path.dirname(__file__), 'steps')
    if steps_dir not in sys.path:
        sys.path.insert(0, steps_dir)
    return __import__(module_name)


def _steps_modules():
    modules = []
    modules.append(_import_steps_module('dhcp_steps'))
    try:
        modules.append(_import_steps_module('dhcpv6_steps'))
    except Exception:
        # DHCPv6 steps may not exist on older branches.
        pass
    return modules


def _server_impl():
    return os.getenv('TEST_SERVER_IMPL', 'isc-dhcpd').strip().lower()


def _capabilities():
    return {
        value.strip().lower()
        for value in os.getenv('TEST_CAPABILITIES', '').split(',')
        if value.strip()
    }


def before_scenario(context, scenario):
    """Reset shared state and assign a fresh client MAC before each scenario.

    Using a unique MAC per scenario prevents server-side lease reuse from
    affecting lease-time assertions.
    """
    server_impl = _server_impl()
    if 'kea' in scenario.tags and server_impl != 'kea':
        scenario.skip(f"Scenario requires Kea backend; current backend is {server_impl}.")
        return
    if 'isc' in scenario.tags and server_impl not in ('isc', 'isc-dhcpd'):
        scenario.skip(f"Scenario requires ISC DHCP backend; current backend is {server_impl}.")
        return

    reference_divergences = {
        'reference_init_reboot_divergence': {'isc', 'isc-dhcpd', 'kea'},
        'isc_rfc6842_divergence': {'isc', 'isc-dhcpd'},
        'kea_rfc3011_default_divergence': {'kea'},
        'kea_rfc3396_request_reassembly_divergence': {'kea'},
    }
    for tag, implementations in reference_divergences.items():
        if tag in scenario.tags and server_impl in implementations:
            scenario.skip(
                f"Known {server_impl} reference-backend divergence tracked by @{tag}."
            )
            return

    capabilities = _capabilities()
    scenario_tags = getattr(scenario, 'effective_tags', scenario.tags)
    required_capabilities = {
        tag.removeprefix('requires_').lower()
        for tag in scenario_tags
        if tag.startswith('requires_')
    }
    missing = required_capabilities - capabilities
    if missing:
        scenario.skip(
            "Scenario requires explicitly enabled service capabilities: "
            + ", ".join(sorted(missing))
        )
        return

    for steps in _steps_modules():
        if hasattr(steps, 'context_storage'):
            steps.context_storage.clear()
            steps.context_storage['client_mac'] = _random_mac()
        if hasattr(steps, 'context_storage_v6'):
            steps.context_storage_v6.clear()
            steps.context_storage_v6['client_mac'] = _random_mac()


def after_scenario(context, scenario):
    """Clean up temporary per-scenario network state."""
    modules = _steps_modules()

    for steps in modules:
        inform_ip = getattr(steps, 'context_storage', {}).get('inform_ip') if hasattr(steps, 'context_storage') else None
        if hasattr(steps, 'context_storage') and steps.context_storage.get('inform_ip_added') and inform_ip:
            steps._remove_interface_ipv4(inform_ip)

        lease_v6 = getattr(steps, 'context_storage_v6', {}).get('leased_ipv6') if hasattr(steps, 'context_storage_v6') else None
        if hasattr(steps, 'context_storage_v6') and steps.context_storage_v6.get('lease_ipv6_added') and lease_v6:
            steps._remove_interface_ipv6(lease_v6)
