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


if __name__ == "__main__":
    unittest.main()
