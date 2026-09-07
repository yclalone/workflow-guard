from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ActionMetadataTests(unittest.TestCase):
    def test_composite_action_is_self_contained(self) -> None:
        metadata = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("using: composite", metadata)
        self.assertIn("actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065", metadata)
        self.assertIn('pip install --disable-pip-version-check "$GITHUB_ACTION_PATH"', metadata)
        self.assertIn('workflow-guard "${args[@]}"', metadata)

    def test_action_exposes_safe_defaults(self) -> None:
        metadata = (ROOT / "action.yml").read_text(encoding="utf-8")
        self.assertIn("default: high", metadata)
        self.assertIn("default: text", metadata)
        self.assertIn("WORKFLOW_GUARD_PATH: ${{ inputs.path }}", metadata)


if __name__ == "__main__":
    unittest.main()
