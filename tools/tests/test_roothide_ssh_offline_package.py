"""The 1900 OpenSSH inputs are offline, pinned and never auto-load the job.

Static/package checks are not proof of a live SSH banner on an iPhone.
"""

import hashlib
import io
from pathlib import Path
import unittest
import zipfile

try:
    from tools.verify_roothide_full_experimental import check_offline_ssh_payload
except ImportError:
    from verify_roothide_full_experimental import check_offline_ssh_payload


ROOT = Path(__file__).resolve().parents[2]
RES = ROOT / "Application/Dopamine/Resources"
EXPECTED = {
    "roothide_ssh_client_1900.deb": "f178c962e65862f5c42bd7317cd234b0f61c5e374901a8811a5e89141d4b7f08",
    "roothide_ssh_sftp_1900.deb": "07670c829ba94722ab69a8457363c0eb737c2e9951cb558668d0ce724a529431",
    "roothide_ssh_server_safe_1900.deb": "ccd27b95690071f181dfb3869d59b721efa1e27e0ab6f0c8c5937f29e9bd7bfd",
}


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


class OfflineRootHideSSH(unittest.TestCase):
    def test_full_hardware_ipa_verifier_requires_exact_pinned_ssh_packages(self):
        memory = io.BytesIO()
        with zipfile.ZipFile(memory, "w") as archive:
            for name in EXPECTED:
                archive.writestr("Payload/Dopamine.app/" + name, (RES / name).read_bytes())
        with zipfile.ZipFile(io.BytesIO(memory.getvalue())) as archive:
            errors, verified = check_offline_ssh_payload(archive)
            self.assertEqual(errors, [])
            self.assertEqual(set(verified), set(EXPECTED))
        corrupt = io.BytesIO()
        with zipfile.ZipFile(corrupt, "w") as archive:
            archive.writestr("Payload/Dopamine.app/roothide_ssh_server_safe_1900.deb", b"bad")
        with zipfile.ZipFile(io.BytesIO(corrupt.getvalue())) as archive:
            errors, verified = check_offline_ssh_payload(archive)
            self.assertEqual(verified, {})
            self.assertEqual(len(errors), 3)  # two missing, one checksum mismatch

    def test_debs_are_pinned_and_archived(self):
        project = source("Application/Dopamine.xcodeproj/project.pbxproj")
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        for name, expected in EXPECTED.items():
            with self.subTest(name=name):
                data = (RES / name).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), expected)
                self.assertEqual(data[:8], b"!<arch>\n")
                self.assertEqual(project.count(f"/* {name} in Resources */"), 2)
                self.assertIn(f'@"name":@"{name}"', env)
                self.assertIn(f'@"sha":@"{expected}"', env)

    def test_verifiable_derivative_preserves_upstream_sha_and_disables_unsafe_script(self):
        build = source("tools/build_roothide_ssh_server_payload.py")
        self.assertIn('7030f44fdbb1851cb6e702c02a60842dff54ac7fcabb80745bf34069757d9c6a', build)
        self.assertIn('SAFE_SHELL_SCRIPT', build)
        self.assertIn('("extrainst_", "prerm")', build)
        self.assertIn('cannot update original config md5sums entry', build)
        self.assertIn('PermitRootLogin prohibit-password', build)
        self.assertIn('PasswordAuthentication no', build)
        self.assertIn('KbdInteractiveAuthentication no', build)
        self.assertIn('PermitEmptyPasswords no', build)

    def test_inspect_receipts_no_reinstall_on_existing_or_partial_roots(self):
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        section = env.split('- (int)rh3InstallPinnedOpenSSHBeforeImport', 1)[1].split(
            '- (int)rh3GenerateMissingOpenSSHHostKeyBeforeImport', 1)[0]
        self.assertIn('RH3SSHRootForPhase(YES)', section)
        self.assertIn('Library/dpkg/status', section)
        self.assertIn('Status: install ok installed', section)
        self.assertIn('if (installed == packages.count)', section)
        self.assertIn('if (installed != 0)', section)
        self.assertIn('return EEXIST;', section)
        self.assertIn('CommonCrypto/CommonDigest', env)
        self.assertNotIn('curl', section)
        self.assertNotIn('apt-get', section)
        self.assertNotIn('launchctl', section)

    def test_no_live_key_replacement_and_import_occurs_after_configuration(self):
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        prep = env.split('- (int)prepareRootHideOpenSSHBeforeUserspaceReboot', 1)[1].split(
            '// Read the effective launchd disabled override', 1)[0]
        self.assertLess(prep.index('rh3InstallPinnedOpenSSHBeforeImport'),
                        prep.index('rh3GenerateMissingOpenSSHHostKeyBeforeImport'))
        self.assertLess(prep.index('rh3GenerateMissingOpenSSHHostKeyBeforeImport'),
                        prep.index('rh3RepairRootHideSSHAllowKeyGeneration:NO installerPhase:YES'))
        self.assertIn('if (fstatat(fd, "ssh_host_ed25519_key"', env)
        self.assertIn('if (err != ENOENT || pubExists)', env)


if __name__ == "__main__":
    unittest.main()
