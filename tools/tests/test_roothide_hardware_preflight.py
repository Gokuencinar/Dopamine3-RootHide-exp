"""The hardware beta must reject unsupported/previously jailbroken devices."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RootHideHardwarePreflightTests(unittest.TestCase):
    def test_preflight_before_kernel_exploit(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m").read_text(encoding="utf-8")
        entry = source[source.index("- (void)runWithError:"):
                       source.index("[self gatherSystemInformation]")]
        self.assertIn("if (![DOBootstrapper rootHidePortEnabled])", entry)
        self.assertIn("NSError *preflightError = [self rootHidePreflightError]", entry)
        preflight = source.split("- (NSError *)rootHidePreflightError", 1)[1].split("- (void)runWithError:", 1)[0]
        self.assertIn("NSProcessInfo.processInfo.operatingSystemVersion", preflight)
        self.assertIn("!rh3_bootstrap_version_for_os((int)os.majorVersion)", preflight)
        self.assertIn("isArm64e", preflight)
        self.assertIn("isSupported", preflight)
        self.assertIn("isJailbrokenWithOtherJailbreak", preflight)
        self.assertIn("[[DOBootstrapper new] rootHidePreflightError]", preflight)

    def test_ui_preflight_precedes_even_the_memory_workaround(self):
        source = (ROOT / "Application/Dopamine/UI/DOMainViewController.m").read_text(encoding="utf-8")
        start = source.split("- (void)startJailbreak", 1)[1]
        self.assertLess(start.index("[jailbreaker rootHidePreflightError]"),
                        start.index("[jailbreaker contiguousMappingWorkaroundNeeded]"))
        rejection = start.split("if (preflightError)", 1)[1].split("#endif", 1)[0]
        self.assertIn("return;", rejection)
        self.assertNotIn("reboot", rejection.lower())

    def test_preflight_checks_assets_and_existing_state_without_mutation(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")
        preflight = source.split("- (NSError *)rootHidePreflightError", 1)[1].split("- (NSError *)rh3BuildPackageSourcesInRoot:", 1)[0]
        self.assertIn('lstat("/var/jb", &visibleRoot)', preflight)
        self.assertIn("errno != ENOENT", preflight)
        self.assertIn("rootHideExistingRootWithError:&error", preflight)
        self.assertIn("RH3CheckInterruptedOperations(root)", preflight)
        self.assertIn('stage isEqualToString:@"running-script"', preflight)
        self.assertIn("rh3VerifyAssetsForVersion:version", preflight)
        for mutation in ("removeItemAtPath:", "moveItemAtPath:", "writeToFile:", "exec_cmd"):
            self.assertNotIn(mutation, preflight)

    def test_hardware_ci_requires_explicit_manual_input(self):
        workflow = (ROOT / ".github/workflows/main.yml").read_text(encoding="utf-8")
        self.assertIn("github.event_name == 'workflow_dispatch' && inputs.hardware_beta == true", workflow)
        self.assertIn("default: false", workflow)
        self.assertIn("--hardware-beta --ipa Application/RootHide3-Hardware-Beta.ipa", workflow)
        self.assertIn("RootHide3-HARDWARE-BETA-JAILBREAK-ENABLED", workflow)
        self.assertIn("python3 tools/roothide_port_audit.py --strict", workflow)

    def test_sideloaded_app_defers_privileged_filesystem_checks_but_rechecks_before_creation(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")
        preflight = source.split("- (NSError *)rootHidePreflightError", 1)[1].split("- (NSError *)rh3BuildPackageSourcesInRoot:", 1)[0]
        self.assertLess(preflight.index("rh3VerifyAssetsForVersion:version"), preflight.index("isInstalledThroughTrollStore"))
        self.assertLess(preflight.index("isInstalledThroughTrollStore"), preflight.index('lstat("/var/jb"'))
        self.assertIn("geteuid() != 0", preflight)
        prepare = source.split("- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion\n{", 1)[1].split("- (NSError *)finalizeRootHideBootstrap", 1)[0]
        self.assertLess(prepare.index('fileOrSymlinkExistsAtPath:@"/var/jb"'), prepare.index("rh3CreateRoot:root"))
        self.assertLess(prepare.index("rootHideExistingRootWithError:&error"), prepare.index("rh3CreateRoot:root"))

    def test_trollstore_platform_entitlement_not_equated_with_jailbreak(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text(encoding="utf-8")
        method = source[source.index("- (BOOL)isJailbrokenWithOtherJailbreak"):
                        source.index("- (NSString *)jailbrokenVersion")]
        self.assertIn("if ([DOBootstrapper rootHidePortEnabled])", method)
        self.assertIn("return otherJailbreakActived(false);", method)
        self.assertLess(method.index("return otherJailbreakActived(false)"),
                        method.index("if (csFlags & CS_PLATFORM_BINARY)"))

    def test_only_hardware_beta_root_helper_can_remove_owned_bootstrap(self):
        source = (ROOT / "Application/Dopamine/main.m").read_text(encoding="utf-8")
        helper = source.split("#if RH3_FULL_APP_EXPERIMENTAL && ROOTHIDE3_BOOTSTRAP_READY", 1)[1].split("#endif", 1)[0]
        self.assertIn('argc != 3 || strcmp(argv[2], "delete-bootstrap") || geteuid() != 0', helper)
        self.assertLess(helper.index("geteuid() != 0"), helper.index("deleteBootstrap]"))
        self.assertIn("return 77", helper)
        self.assertIn("if (error)", helper)
        self.assertIn("return 1", helper)
        self.assertNotIn("setJailbreakHidden", helper)


if __name__ == "__main__":
    unittest.main()
