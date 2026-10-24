"""Guard the r211/r212 OpenSSH partial-dpkg recovery contract.

Source inspection is not a native iOS / launchd / sshd test. Package archive
checks inspect the actual bundled 1900 input, never an invented sample plist.
"""

import hashlib
from pathlib import Path
import plistlib
import shutil
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(
    encoding="utf-8"
)
INSTALL = SOURCE.split("- (int)rh3InstallPinnedOpenSSHBeforeImport\n{", 1)[1].split(
    "- (int)rh3GenerateMissingOpenSSHHostKeyBeforeImport", 1
)[0]
PREBOOT = SOURCE.split("- (int)prepareRootHideOpenSSHBeforeUserspaceReboot", 1)[1].split(
    "// Read the effective launchd disabled override", 1
)[0]
DIAG = SOURCE.split("- (int)diagnoseRootHideOpenSSHSocket", 1)[1].split(
    "// Never treat presence of TweakLoader", 1
)[0]
RESOURCE = ROOT / "Application/Dopamine/Resources/roothide_ssh_server_safe_1900.deb"
BOOTSTRAP = ROOT / "Application/Dopamine/Resources/roothide_bootstrap_1900.tar.zst"


def deb_members(binary):
    """Read ar headers without requiring native dpkg or writing to disk."""
    if not binary.startswith(b"!<arch>\n"):
        raise ValueError("not an ar archive")
    offset = 8
    parts = {}
    while offset < len(binary):
        header = binary[offset : offset + 60]
        if len(header) != 60 or header[58:] != bytes((96, 10)):
            raise ValueError("bad ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58])
        parts[name] = binary[offset + 60 : offset + 60 + size]
        offset += 60 + size + size % 2
    return parts


@unittest.skipUnless(RESOURCE.exists(), "bundled SSH package unavailable")
class RootHideSSHPartialRecovery(unittest.TestCase):
    def test_only_audited_1900_receipts_recover(self):
        for state in (
            "install ok installed",
            "install ok unpacked",
            "install ok half-configured",
        ):
            self.assertIn(f"Status: {state}", INSTALL)
        for boundary in (
            "Version: 9.2p1",
            "Architecture: iphoneos-arm64e",
            "if (++matches != 1)",
            "state = RH3SSHAbsent",
            "inventoryError = EEXIST",
        ):
            self.assertIn(boundary, INSTALL)
        self.assertNotIn("Status: install ok half-installed", INSTALL)
        self.assertNotIn("Status: deinstall ok config-files", INSTALL)

    def test_package_owner_and_disk_paths_are_verified_before_mutation(self):
        self.assertIn("O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC", INSTALL)
        self.assertIn('@"Library/dpkg/info"', INSTALL)
        self.assertIn('stringByAppendingString:@".list"', INSTALL)
        self.assertIn("openat(infoDirectory, listName.fileSystemRepresentation", INSTALL)
        self.assertIn("st_uid != 0", INSTALL)
        self.assertIn("st_nlink != 1", INSTALL)
        self.assertIn("file.st_uid != 0", INSTALL)
        self.assertIn("file.st_size < 32", INSTALL)
        self.assertIn("![list containsString:listed]", INSTALL)
        self.assertLess(INSTALL.index("if (inventoryError) {"), INSTALL.index("verifiedPaths"))

    def test_dpkg_only_installs_absent_and_configures_unpacked(self):
        self.assertIn("if (installed == packages.count)", INSTALL)
        self.assertIn("if (state == RH3SSHInstalled) continue;", INSTALL)
        self.assertIn('state == RH3SSHAbsent ?\n            exec_cmd_trusted(', INSTALL)
        self.assertIn('"-i",\n                             verifiedPaths[i].fileSystemRepresentation, NULL)', INSTALL)
        self.assertIn('"--configure", name, NULL)', INSTALL)
        self.assertIn("if (result) return result", INSTALL)
        self.assertIn("RH3SSHReadInstalledReceiptMask(root, &finalMask)", INSTALL)
        self.assertIn("finalMask != 7", INSTALL)
        self.assertLess(INSTALL.index("if (inventoryError) {"), INSTALL.index('exec_cmd_trusted('))
        self.assertNotIn('"--configure", "-a"', INSTALL)
        self.assertNotIn('"--force"', INSTALL)

    def test_existing_host_keys_and_config_are_never_replaced_during_recovery(self):
        self.assertNotIn("ssh_host_ed25519_key", INSTALL)
        self.assertNotIn('"ed25519", "-N"', INSTALL)
        self.assertIn("etc/ssh/sshd_config", INSTALL)
        self.assertIn("if (state == RH3SSHInstalled) continue;", INSTALL)
        self.assertLess(PREBOOT.index("rh3InstallPinnedOpenSSHBeforeImport"),
                        PREBOOT.index("rh3GenerateMissingOpenSSHHostKeyBeforeImport"))
        self.assertLess(PREBOOT.index("rh3GenerateMissingOpenSSHHostKeyBeforeImport"),
                        PREBOOT.index("rh3RepairRootHideSSHAllowKeyGeneration:NO installerPhase:YES"))

    def test_diagnostic_uses_current_root_after_rotation(self):
        self.assertIn("NSString *serverRoot = RH3SSHCurrentServerRoot()", DIAG)
        self.assertIn("RH3CanonicalAppPath(serverRoot)", DIAG)

    def test_inventory_reason_is_bounded_and_package_specific(self):
        # Every rejection of a receipt, info .list, or footprint must name
        # its guard before returning the same fail-closed error as before.
        reasons = (
            "duplicate_receipt", "version_mismatch", "architecture_mismatch",
            "unsupported_receipt_state", "absent_receipt_has_list",
            "absent_receipt_list_probe", "installed_receipt_list_missing",
            "installed_receipt_list_open", "installed_receipt_list_metadata",
            "installed_receipt_list_read", "installed_receipt_list_encoding",
            "absent_receipt_file_exists", "absent_receipt_file_probe",
            "installed_receipt_file_missing", "installed_receipt_file_type",
            "installed_receipt_file_owner",
            "installed_receipt_file_permissions",
            "installed_receipt_file_not_executable",
            "installed_receipt_file_size",
            "installed_receipt_manifest_missing_entry",
        )
        for reason in reasons:
            with self.subTest(reason=reason):
                self.assertIn('"' + reason + '"', INSTALL)
        self.assertIn('packageTags[] = { "client", "sftp", "server" }', INSTALL)
        self.assertIn(
            "SSH inventory: package=%s state=%s item=%lu reason=%s error=%d",
            INSTALL,
        )
        self.assertIn("SSH inventory: package=%s state=untrusted item=0 reason=%s error=%d", INSTALL)
        self.assertIn('if (inventoryError) inventoryItem = fileIndex + 1;', INSTALL)
        # Missing or unreadable .list should NOT be reclassified as encoding
        # failure, and it should still be logged with item=0.
        self.assertIn('if (!inventoryError && state != RH3SSHAbsent && !list)', INSTALL)
        self.assertIn('if (!inventoryError) [states addObject:@(state)];', INSTALL)
        self.assertLess(INSTALL.index('SSH inventory: package=%s state=%s'),
                        INSTALL.index('if (inventoryError) {', INSTALL.index('SSH inventory: package=%s state=%s')))
        # Neither user-specific paths nor the raw dpkg status/manifest text
        # may enter a diagnostic message.
        for forbidden in (
            'rh3RecordDiagnosticStage:status',
            'rh3RecordDiagnosticStage:list',
            'rh3RecordDiagnosticStage:path',
            'rh3RecordDiagnosticStage:root',
            '[NSString stringWithFormat:@"SSH inventory: %@", root]',
        ):
            self.assertNotIn(forbidden, INSTALL)

    def test_bundled_1900_footprints_match_the_strict_file_guards(self):
        footprints = (
            ("roothide_ssh_client_1900.deb", (
                ("./etc/ssh/ssh_config", False),
                ("./usr/bin/ssh-keygen", True),
            )),
            ("roothide_ssh_sftp_1900.deb", (
                ("./usr/libexec/sftp-server", True),
            )),
            ("roothide_ssh_server_safe_1900.deb", (
                ("./usr/sbin/sshd", True),
                ("./etc/ssh/sshd_config", False),
                ("./Library/LaunchDaemons/com.openssh.sshd.plist", False),
            )),
        )
        if not shutil.which("tar"):
            self.skipTest("tar not installed")
        for package, entries in footprints:
            with self.subTest(package=package):
                deb = deb_members((RESOURCE.parent / package).read_bytes())
                result = subprocess.run(
                    ["tar", "-tvf", "-"], input=deb["data.tar.zst"],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
                )
                if result.returncode:
                    self.skipTest("tar cannot read bundled zstd input")
                lines = result.stdout.decode(errors="replace").splitlines()
                for path, executable in entries:
                    matches = [line for line in lines if line.endswith(" " + path)]
                    self.assertEqual(len(matches), 1, path)
                    mode = matches[0].split()[0]
                    self.assertEqual(mode[0], "-")  # no symlinks or directories
                    self.assertEqual(mode[1:4], "rwx" if executable else "rw-")
                    self.assertEqual(mode[4:10], "r-xr-x" if executable else "r--r--")
                    self.assertIn(" root ", matches[0])

    def test_bootstrap_dpkg_list_format_supports_exact_manifest_matching(self):
        if not BOOTSTRAP.exists() or not shutil.which("tar"):
            self.skipTest("bundled dpkg manifest unavailable")
        receipt = subprocess.run(
            ["tar", "-xOf", str(BOOTSTRAP), "./Library/dpkg/info/libssl3.list"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        if receipt.returncode:
            self.skipTest("cannot read bundled dpkg list")
        list_text = receipt.stdout.decode("utf-8") + "\n"
        self.assertIn("\n/usr/lib/libssl.3.dylib\n", list_text)
        self.assertIn('@"\\n/%@\\n"', INSTALL)

    def test_pinned_server_payload_avoids_automatic_launch_and_has_expected_listener(self):
        binary = RESOURCE.read_bytes()
        self.assertEqual(hashlib.sha256(binary).hexdigest(),
                         "ccd27b95690071f181dfb3869d59b721efa1e27e0ab6f0c8c5937f29e9bd7bfd")
        parts = deb_members(binary)
        self.assertEqual(set(parts), {"debian-binary", "control.tar.zst", "data.tar.zst"})
        if not shutil.which("tar"):
            self.skipTest("tar unavailable to read bundled zstd archives")
        def unpack(member, path):
            process = subprocess.run(
                ["tar", "-xOf", "-", path], input=parts[member],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            if process.returncode != 0:
                self.skipTest("tar installation cannot decompress zstd from stdin")
            return process.stdout
        script = unpack("control.tar.zst", "./extrainst_")
        self.assertIn(b"exit 0\n", script)
        self.assertNotIn(b"launchctl", script)
        script = unpack("control.tar.zst", "./prerm")
        self.assertIn(b"exit 0\n", script)
        job = plistlib.loads(unpack("data.tar.zst", "./Library/LaunchDaemons/com.openssh.sshd.plist"))
        self.assertEqual(job["Label"], "com.openssh.sshd")
        self.assertFalse(job["inetdCompatibility"]["Wait"])
        self.assertEqual(job["Sockets"]["SSHListener"]["SockServiceName"], "ssh")
        self.assertEqual(job["Sockets"]["SSHListener2"]["SockServiceName"], "2222")


if __name__ == "__main__":
    unittest.main()
