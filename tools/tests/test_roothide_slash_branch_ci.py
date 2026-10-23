"""The RootHide integration branch contains a slash and needs native push CI."""
from pathlib import Path
import unittest


WORKFLOW = (Path(__file__).resolve().parents[2] / '.github/workflows/main.yml').read_text(encoding='utf-8')


class SlashBranchCI(unittest.TestCase):
    def test_push_and_pr_cover_nested_branch_names(self):
        on = WORKFLOW.split('\non:\n', 1)[1].split('\nconcurrency:', 1)[0]
        self.assertIn("  push:\n    branches:\n", on)
        self.assertIn("  pull_request:\n    branches:\n      - '**'", on)
        push = on.split('  push:\n', 1)[1].split('  pull_request:\n', 1)[0]
        self.assertIn("      - '**'", push)
        self.assertNotIn("      - '*'", push)

    def test_hardware_release_still_requires_explicit_dispatch(self):
        release = WORKFLOW.split('- name: Publish directly downloadable experimental IPA', 1)[1]
        self.assertIn("github.event_name == 'workflow_dispatch'", release.split('\n      - name:', 1)[0])
        self.assertIn("env.ROOTHIDE_HARDWARE_TEST == 'YES'", release.split('\n      - name:', 1)[0])


if __name__ == '__main__':
    unittest.main()
