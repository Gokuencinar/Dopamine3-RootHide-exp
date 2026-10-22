"""CI releases a unique, verified IPA without replacing hardware gates."""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAIN = (ROOT / '.github/workflows/main.yml').read_text(encoding='utf-8')


def step(name: str) -> str:
    return MAIN.split(f'- name: {name}\n', 1)[1].split('\n      - name:', 1)[0]


class UniqueIPARelease(unittest.TestCase):
    def test_artifact_labels_are_distinct_for_every_run_and_attempt(self):
        self.assertIn('run-name:', MAIN)
        for marker in (
            'RootHide3-Device-Test-APP-ONLY-',
            'RootHide3-COMPILE-ONLY-NOT-FOR-INSTALL-',
            'RootHide3-FULL-EXPERIMENTAL-JAILBREAK-DISABLED-',
            'RootHide3-HARDWARE-BETA-JAILBREAK-ENABLED-',
        ):
            self.assertIn(marker + 'r${{ github.run_number }}-a${{ github.run_attempt }}', MAIN)

    def test_native_ipa_filename_is_unique_and_verified_first(self):
        package = step('Verify jailbreak-enabled RootHide hardware beta')
        self.assertIn('id: hardware_beta_package', package)
        self.assertIn('--hardware-beta --ipa Application/RootHide3-Hardware-Beta.ipa', package)
        self.assertLess(package.index('python3 tools/verify_roothide_full_experimental.py'),
                        package.index('suffix="r${GITHUB_RUN_NUMBER}'))
        self.assertIn('RootHide3-Hardware-Beta-${suffix}.ipa', package)
        self.assertIn('roothide3-hw-${suffix}', package)
        self.assertIn('shasum -a 256 "$asset"', package)
        upload = step('Upload jailbreak-enabled RootHide hardware beta')
        self.assertIn('steps.hardware_beta_package.outputs.asset', upload)

    def test_direct_release_after_verification_before_strict_guard(self):
        release = step('Publish directly downloadable experimental IPA')
        self.assertIn('gh release create "$TAG"', release)
        self.assertIn('"Application/$ASSET"', release)
        self.assertIn('--prerelease --latest=false', release)
        self.assertIn('shasum -a 256 -c "$ASSET.sha256"', release)
        self.assertIn("github.event_name == 'workflow_dispatch'", release)
        self.assertIn("github.ref == 'refs/heads/roothide-dopamine3-integration'", release)
        self.assertIn("github.ref == 'refs/heads/fix/roothide3-ssh-preboot-installer-rc'", release)
        self.assertIn("env.ROOTHIDE_HARDWARE_TEST == 'YES'", release)
        self.assertLess(MAIN.index('- name: Verify jailbreak-enabled RootHide hardware beta'),
                        MAIN.index('- name: Publish directly downloadable experimental IPA'))
        self.assertLess(MAIN.index('- name: Publish directly downloadable experimental IPA'),
                        MAIN.index('- name: Check RootHide port prerequisites before upload'))
        self.assertIn('contents: write', MAIN)
        self.assertNotIn('gh release create', MAIN.split('  device-test:', 1)[1].split('  build:', 1)[0])


if __name__ == '__main__':
    unittest.main()
