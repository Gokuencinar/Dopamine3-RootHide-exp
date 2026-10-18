"""Windows-safe source contracts for conservative RootHide3 bootstrap recovery.

These checks guard the order and scope of critical Objective-C operations;
they do not simulate iOS filesystem, kernel, dpkg, or launchd behavior.
"""

from pathlib import Path
import re
import subprocess
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE_PATH = ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m"
SOURCE = SOURCE_PATH.read_text(encoding="utf-8")


def section(start: str, end: str) -> str:
    begin = SOURCE.index(start)
    return SOURCE[begin:SOURCE.index(end, begin + len(start))]


class RootHideBootstrapRecoveryContracts(unittest.TestCase):
    def test_activation_remains_disabled_and_stock_methods_keep_dispatch(self):
        self.assertIn("#define ROOTHIDE3_BOOTSTRAP_READY 0", SOURCE)
        for name, dispatch in (
            ("prepareBootstrapWithCompletion:", "prepareRootHideBootstrapWithCompletion:completion"),
            ("finalizeBootstrap", "finalizeRootHideBootstrap"),
            ("deleteBootstrap", "deleteRootHideBootstrap"),
        ):
            self.assertIn(dispatch, SOURCE)
        original = subprocess.run(
            ["git", "show", "HEAD:Application/Dopamine/Jailbreak/DOBootstrapper.m"],
            cwd=ROOT, capture_output=True, text=True, check=True, encoding="utf-8",
        ).stdout
        # Only the RootHide category and its helpers may change. The upstream
        # implementation after the original @implementation is unchanged.
        boundary = "@implementation DOBootstrapper\n"
        self.assertEqual(SOURCE.split(boundary, 1)[1], original.split(boundary, 1)[1])

    def test_unknown_or_damaged_ownership_is_never_adopted(self):
        lookup = section("+ (NSString *)rootHideExistingRootWithError:",
                         "- (NSError *)rh3VerifyBundledFile:")
        self.assertIn("RH3KnownPendingState(pending)", lookup)
        self.assertIn("Unknown or damaged RootHide 3 installation state", lookup)
        self.assertIn("Damaged RootHide 3 installed marker", lookup)
        self.assertIn("Conflicting RootHide 3 installed and pending stages", lookup)
        self.assertIn("Unowned or unknown .jbroot", lookup)
        self.assertIn("Orphaned RootHide AppGroup", lookup)
        self.assertIn("Interrupted RootHide 3 AppGroup removal", lookup)
        self.assertNotIn("removeItemAtPath:", lookup)

    def test_non_idempotent_script_is_marked_before_execution(self):
        finalize = section("- (NSError *)finalizeRootHideBootstrap\n{", "- (NSError *)deleteRootHideBootstrap\n{")
        intent = finalize.index('RH3WritePendingState(root, @"running-script")')
        execute = finalize.index('exec_cmd_env_nowait(&scriptPid, scriptEnvironment')
        completed = finalize.index('RH3WritePendingState(root, @"script-complete")')
        self.assertLess(intent, execute)
        self.assertLess(execute, completed)
        self.assertIn('if ([pending isEqualToString:@"running-script"])', finalize)
        self.assertIn('RootHide setup script still exists after completion', finalize)
        self.assertIn("manual recovery required", finalize)
        self.assertIn('exec_cmd_env_nowait(&scriptPid, scriptEnvironment, shell.fileSystemRepresentation,', finalize)
        self.assertIn('"-e", script.fileSystemRepresentation, NULL)', finalize)
        self.assertLess(finalize.index("RootHide setup returned without removing its script"), completed)
        self.assertNotIn('RH3WritePendingState(root, @"prepared")', finalize)

    def test_interrupted_stages_block_repreparation_before_mutation(self):
        prepare = section("- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion\n{",
                          "- (NSError *)finalizeRootHideBootstrap\n{")
        interrupted = prepare.index('stage isEqualToString:@"running-script"')
        reinstall = prepare.index("[self rh3InstallBasebinAtRoot:root]")
        self.assertLess(interrupted, reinstall)
        self.assertIn('stage isEqualToString:@"creating"', prepare)
        self.assertLess(prepare.index("RH3CheckInterruptedOperations(root)"),
                        prepare.index("[self rh3RerandomizeRoot:&root]"))
        self.assertIn('RH3CheckInterruptedOperations(root)',
                      section("- (NSError *)finalizeRootHideBootstrap\n{", "- (NSError *)deleteRootHideBootstrap\n{"))

    def test_orphaned_dependency_backups_remain_for_manual_recovery(self):
        check = section("static NSError *RH3CheckInterruptedOperations", "// Rewrite only absolute links")
        self.assertIn('@".roothide3-deps-"', check)
        self.assertIn('@"basebin.roothide3-backup"', check)
        self.assertNotIn("removeItemAtPath:", check)
        dependencies = section("- (NSError *)rh3InstallDependenciesAtRoot:",
                               "- (void)prepareRootHideBootstrapWithCompletion:")
        self.assertIn("if (rollbackError)", dependencies)
        self.assertIn("Dependency rollback incomplete", dependencies)
        self.assertIn("if (![fm removeItemAtPath:stage error:&cleanupError])", dependencies)

    def test_safe_mode_survives_basebin_replacement_or_rolls_back(self):
        basebin = section("- (NSError *)rh3InstallBasebinAtRoot:",
                          "// Dopamine's bundled dependency debs")
        inspect = basebin.index("BOOL preserveSafeMode =")
        backup = basebin.index("[fm moveItemAtPath:oldBasebin toPath:backup")
        restore = basebin.index("writeToFile:newSafeMode atomically:YES")
        error_rollback = basebin.index("if (error) {")
        remove_backup = basebin.index("[fm removeItemAtPath:backup error:&error]")
        self.assertLess(inspect, backup)
        self.assertLess(backup, restore)
        self.assertLess(restore, error_rollback)
        self.assertLess(error_rollback, remove_backup)
        self.assertIn("!S_ISREG(safeModeInfo.st_mode)", basebin)
        self.assertIn("BaseBin rollback failed; backup retained", basebin)

    def test_failed_creation_is_quarantined_without_recursive_auto_cleanup(self):
        create = section("- (NSError *)rh3CreateRoot:", "- (NSError *)rh3RerandomizeRoot:")
        self.assertIn('RH3WritePendingState(root, @"creating")', create)
        self.assertIn("cleanup_both:", create)
        self.assertIn("cleanup_root:", create)
        cleanup = create.split("cleanup_both:", 1)[1]
        self.assertNotRegex(cleanup, r"removeItemAtPath:\s*(?:root|secondary)\b")
        self.assertIn("manual recovery required", cleanup)


if __name__ == "__main__":
    unittest.main()
