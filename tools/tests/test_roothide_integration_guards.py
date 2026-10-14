"""Static regressions for the staged Dopamine 3 / RootHide integration.

These assertions verify source-level safety gates, not actual jailbreak
functionality. Device testing remains necessary before any release.
"""

import hashlib
import io
import tarfile
import unittest

from tools import roothide_port_audit as audit


class RootHideGuardTests(unittest.TestCase):
    def source(self, name: str) -> str:
        content = audit.read(name)
        self.assertTrue(content, f"Missing source: {name}")
        return content

    def test_bootstrap_opt_in_defaults_off(self) -> None:
        bootstrap = self.source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn("#define ROOTHIDE3_BOOTSTRAP_READY 0", bootstrap)

    def test_hidden_root_requires_brand_and_exact_location(self) -> None:
        source = self.source("BaseBin/libjailbreak/src/roothider/common.m")
        self.assertIn("bool roothide_is_active(void)", source)
        self.assertIn("jbrand == 0", source)
        self.assertIn("/.jbroot-%016llX", source)
        self.assertIn("strcmp(rootPath, root)", source)

    def test_dispatcher_checks_domain_and_action_indices(self) -> None:
        source = self.source("BaseBin/libjailbreak/src/jbserver.c")
        self.assertIn("domainIdx > server->maxDomain", source)
        self.assertIn("actionIdx > jbserver_last_action_for_domain(domainIdx)", source)

    def test_roothide_ipc_rejects_invalid_client_inputs(self) -> None:
        source = self.source("BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c")
        self.assertIn("if (!roothide_is_active()) return false", source)
        self.assertIn("preferredArchCount > 16", source)
        self.assertIn("xpc_get_type(checkvalue) != XPC_TYPE_UINT64", source)
        self.assertIn("proc_pidpath_audittoken(callerToken", source)

    def test_blacklisted_spawn_tracks_child_pid(self) -> None:
        source = self.source("BaseBin/launchdhook/src/spawn_hook.c")
        self.assertIn("roothide_is_active() && isBlacklistedPath(path)", source)
        self.assertIn("allocBlacklistProcessId()", source)
        self.assertIn("commitBlacklistProcessId(trackedPid)", source)

    def test_root_hide_never_exposes_var_jb_via_settings(self) -> None:
        manager = self.source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        settings = self.source("Application/Dopamine/UI/Settings/DOSettingsController.m")
        self.assertIn("if ([DOBootstrapper rootHidePortEnabled]) return YES;", manager)
        self.assertIn("if ([DOBootstrapper rootHidePortEnabled]) return;", manager)
        self.assertIn("![DOBootstrapper rootHidePortEnabled] &&", settings)

    def test_failed_removal_preserves_recovery_state_without_reboot(self) -> None:
        source = self.source("Application/Dopamine/UI/Settings/DOSettingsController.m")
        start = source.index("- (void)removeJailbreakPressed")
        end = source.index("- (void)resetSettingsPressed", start)
        removal = source[start:end]
        self.assertIn("NSError *deleteError = [[DOEnvironmentManager sharedManager] deleteBootstrap]", removal)
        self.assertIn("if (deleteError) {", removal)
        self.assertLess(removal.index("if (deleteError) {"), removal.index("return;"))
        self.assertLess(removal.index("return;"), removal.index("reboot];"))

    def test_hidden_bootstrap_disables_stock_procursus_repositories(self) -> None:
        bootstrap = self.source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn('@"etc/apt/sources.list.d/procursus.sources"', bootstrap)
        self.assertIn('@"etc/apt/sources.list.d/procursus.list"', bootstrap)
        self.assertIn('@"etc/apt/sources.list"', bootstrap)
        self.assertIn("https://roothide.github.io/procursus", bootstrap)

    def test_arm64_only_devices_are_refused_before_root_creation(self) -> None:
        bootstrap = self.source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn("if (![[DOEnvironmentManager sharedManager] isArm64e])", bootstrap)
        self.assertIn("arm64 is unsupported", bootstrap)

    def test_krw_can_resolve_libjailbreak_inside_hidden_root(self) -> None:
        makefile = self.source("Packages/libkrw-provider/Makefile")
        self.assertIn("-rpath /var/jb/usr/lib", makefile)
        self.assertIn("-rpath @loader_path/..", makefile)

    def test_core_symbolication_lookup_fails_closed_without_framework(self) -> None:
        source = self.source("BaseBin/libjailbreak/src/roothider/dyld_patch.m")
        self.assertIn("if (!csHandle || !path || !name)", source)
        self.assertIn("if (!__CSSymbolicatorCreateWithPathAndArchitecture ||", source)
        self.assertIn("if (!symbolicator.csCppData && !symbolicator.csCppObj)", source)
        self.assertIn("if (!symbol.csCppData && !symbol.csCppObj)", source)

    def test_roothide_blacklist_imports_declared_logger(self) -> None:
        source = self.source("BaseBin/libjailbreak/src/roothider/blacklist.m")
        self.assertIn('#include "log.h"', source)
        self.assertIn("JBLogDebug(", source)

    def test_dopamine3_owns_crashreporter_without_incompatible_roothide_abi(self) -> None:
        makefile = self.source("BaseBin/libjailbreak/Makefile")
        header = self.source("BaseBin/libjailbreak/src/roothider.h")
        launchd_header = self.source("BaseBin/launchdhook/src/crashreporter.h")
        self.assertIn("$(filter-out src/roothider/crashreporter.m,", makefile)
        self.assertNotIn('#include "roothider/crashreporter.h"', header)
        self.assertIn("void crashreporter_pause(void);", launchd_header)
        self.assertIn("void crashreporter_resume(void);", launchd_header)

    def test_stock_bootstraps_have_pinned_content_hashes(self) -> None:
        script = self.source("Application/Dopamine/Resources/download_bootstraps.sh")
        self.assertIn("a99b39bb0344ee3b42bb961325038dceae7daaec500976f3b822cf36cccf020a", script)
        self.assertIn("8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb", script)
        self.assertIn("shasum -a 256 -c -", script)

    def test_roothide_donor_packages_have_arm64e_metadata(self) -> None:
        names = {
            "roothideapp.deb": "com.roothide.manager",
            "roothide_sileo.deb": "org.coolstar.sileo",
            "roothide_zebra.deb": "xyz.willy.zebra",
        }
        for filename, package_id in names.items():
            with self.subTest(package=filename):
                raw = (audit.ROOT / "Application/Dopamine/Resources" / filename).read_bytes()
                self.assertTrue(raw.startswith(b"!<arch>\n"))
                cursor, control = 8, None
                while cursor + 60 <= len(raw):
                    header = raw[cursor:cursor + 60]
                    member_name = header[:16].strip().rstrip(b"/").decode("ascii")
                    size = int(header[48:58])
                    payload = raw[cursor + 60:cursor + 60 + size]
                    cursor += 60 + size + (size % 2)
                    if member_name.startswith("control.tar."):
                        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:*") as archive:
                            member = next(item for item in archive.getmembers()
                                          if item.name in ("./control", "control"))
                            control = archive.extractfile(member).read().decode("utf-8")
                        break
                self.assertIsNotNone(control)
                self.assertIn(f"Package: {package_id}", control)
                self.assertIn("Architecture: iphoneos-arm64e", control)

    def test_ci_disallows_unverified_release_upload(self) -> None:
        workflow = self.source(".github/workflows/main.yml")
        self.assertIn("RootHide3-COMPILE-ONLY-NOT-FOR-INSTALL", workflow)
        self.assertIn("python3 tools/roothide_port_audit.py --strict", workflow)
        self.assertIn("if: steps.roothide_port.outputs.is_port == 'false'", workflow)
        self.assertIn("if: steps.roothide_port.outputs.is_port == 'true'", workflow)

    def test_ci_quarantines_port_from_pull_request_merge_refs(self) -> None:
        workflow = self.source(".github/workflows/main.yml")
        self.assertIn('${GITHUB_HEAD_REF:-$GITHUB_REF_NAME}', workflow)
        self.assertIn('[[ -f BaseBin/libjailbreak/src/roothider.h ]]', workflow)
        self.assertIn("id: roothide_port", workflow)
        self.assertIn("ROOTHIDE_EXPERIMENTAL_BUILD: ${{ steps.roothide_port.outputs.is_port == 'true' && '1' || '0' }}", workflow)
        self.assertNotIn("!startsWith(github.ref_name", workflow)

    def test_root_hide_skips_stock_fakelib_and_protection(self) -> None:
        source = self.source("Application/Dopamine/Jailbreak/DOJailbreaker.m")
        self.assertIn("Initializing RootHide dyld support", source)
        self.assertIn("ensure_dyld_trustcache(", source)
        self.assertIn("exec_set_patch(true)", source)
        self.assertIn('setenv("DYLD_IN_CACHE", "0"', source)
        self.assertIn("Preserve Dopamine 3's conventional protection", source)

    def test_donor_bootstrap_self_deletion_does_not_block_install_marker(self) -> None:
        source = self.source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        self.assertIn("BOOL ranInitialSetup = NO", source)
        self.assertIn("ranInitialSetup = YES", source)
        self.assertIn("if (!ranInitialSetup && ![fm fileExistsAtPath:marker])", source)
        self.assertIn("if (ranInitialSetup) {", source)

    def test_new_root_records_ownership_before_extracting_archive(self) -> None:
        source = self.source("Application/Dopamine/Jailbreak/DOBootstrapper.m")
        start = source.index("- (NSError *)rh3CreateRoot:")
        end = source.index("- (NSError *)rh3RerandomizeRoot:", start)
        creation = source[start:end]
        self.assertLess(creation.index('RH3WritePendingState(root, @"creating")'),
                        creation.index("decompressZstd:archive"))
        self.assertIn('@[@"creating", @"layout", @"prepared", @"running-script", @"script-complete"]', source)

    def test_macos_ci_unpacks_xz_sdk_with_correct_decoder(self) -> None:
        workflow = self.source(".github/workflows/main.yml")
        self.assertIn('tar -xJf "$THEOS/sdks/iPhoneOS16.5.sdk.tar.xz"', workflow)
        self.assertNotIn("gunzip $THEOS/sdks/iPhoneOS16.5.sdk.tar.xz", workflow)

    def test_xcode_momentarius_titan_frameworks_do_not_pin_host_sdk_version(self) -> None:
        project = self.source("Application/Dopamine.xcodeproj/project.pbxproj")
        for identifier in ("2F11A328301C006D00C1C9F0", "2F11A32A301C007500C1C9F0",
                           "3165D0063020A584002737DA"):
            with self.subTest(identifier=identifier):
                reference = next(line for line in project.splitlines()
                                 if line.strip().startswith(identifier + " /*"))
                self.assertNotRegex(reference, r"MacOSX[0-9]+(?:\.[0-9]+)?\.sdk")
                self.assertIn("System/Library/Frameworks/", reference)

    def test_roothide_assets_have_expected_hashes_and_are_in_app_target(self) -> None:
        hashes = {
            "roothide_bootstrap_1800.tar.zst": "3350ed91d77163e0cd73f0f90185b5c9b87d9d294133e25ced3a29329e90370e",
            "roothide_bootstrap_1900.tar.zst": "420f72d1a62c9f884733cdefc596728469482a48858ec7ceca4d3ab2d3cba56c",
            "roothideapp.deb": "b8f075e1844709845962900b22fe71136a66369a2c35bb1201087f2fd9476b7d",
            "roothide_sileo.deb": "e85ab12f8d98da9a5350293647266b898282b0d766df2397526ab253d84eede3",
            "roothide_zebra.deb": "ca82c18256e19ff78af3e53308d53f047a2d429cb7e025c892377abe4d2e7825",
        }
        project = self.source("Application/Dopamine.xcodeproj/project.pbxproj")
        for filename, expected_sha256 in hashes.items():
            with self.subTest(filename=filename):
                path = audit.ROOT / "Application/Dopamine/Resources" / filename
                self.assertTrue(path.is_file(), f"Missing bundled asset: {filename}")
                hasher = hashlib.sha256()
                with path.open("rb") as file:
                    for block in iter(lambda: file.read(1024 * 1024), b""):
                        hasher.update(block)
                self.assertEqual(hasher.hexdigest(), expected_sha256)
                self.assertIn(f"/* {filename} in Resources */", project)


if __name__ == "__main__":
    unittest.main()
