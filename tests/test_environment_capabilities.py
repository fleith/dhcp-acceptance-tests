import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from features import environment


class EnvironmentCapabilityTests(unittest.TestCase):
    def test_inherited_required_capability_skips_without_advertisement(self):
        skipped = []
        scenario = SimpleNamespace(
            tags=[],
            effective_tags={"ipv6", "capability", "requires_authenticated_reconfigure"},
            skip=skipped.append,
        )

        with patch.dict(os.environ, {"TEST_CAPABILITIES": ""}, clear=False):
            environment.before_scenario(SimpleNamespace(), scenario)

        self.assertEqual(len(skipped), 1)
        self.assertIn("authenticated_reconfigure", skipped[0])

    def test_baseline_reference_divergence_is_skipped(self):
        skipped = []
        scenario = SimpleNamespace(
            tags={"reference_init_reboot_divergence"},
            effective_tags={"reference_init_reboot_divergence"},
            skip=skipped.append,
        )

        with patch.dict(
            os.environ,
            {"TEST_SERVER_IMPL": "kea", "TEST_SERVER_VERSION": "baseline"},
            clear=False,
        ):
            environment.before_scenario(SimpleNamespace(), scenario)

        self.assertEqual(len(skipped), 1)
        self.assertIn("kea/baseline", skipped[0])

    def test_modern_reference_profile_runs_strict_scenario(self):
        skipped = []
        scenario = SimpleNamespace(
            tags={"reference_init_reboot_divergence"},
            effective_tags={"reference_init_reboot_divergence"},
            skip=skipped.append,
        )

        with (
            patch.dict(
                os.environ,
                {
                    "TEST_SERVER_IMPL": "isc-dhcpd",
                    "TEST_SERVER_VERSION": "isc-final",
                },
                clear=False,
            ),
            patch.object(environment, "_steps_modules", return_value=[]),
        ):
            environment.before_scenario(SimpleNamespace(), scenario)

        self.assertEqual(skipped, [])


if __name__ == "__main__":
    unittest.main()
