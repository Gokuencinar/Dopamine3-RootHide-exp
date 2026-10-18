"""Regression contracts for iOS 16 RootHide donor tmp collision / recovery.

Static checks don't substitute for a filesystem test on an iPhone. They
protect against repeating the Cocoa 516 bug or automatically deleting an
unrecognized .jbroot / AppGroup after a failed extraction.
"""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
SRC = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text(encoding="utf-8")


def section(start, end):
    i = SRC.index(start)
    return SRC[i:SRC.index(end, i + len(start))]


class RootHideTmpCollisionTests(unittest.TestCase):
    def test_donor_var_tmp_is_checked_with_lstat_not_file_exists(self):
        helper = section("static BOOL RH3IsExpectedDonorTmpLink(", "// Allow read-only recognition")
        self.assertIn("lstat(path.fileSystemRepresentation, &st)", helper)
        self.assertIn("S_ISLNK(st.st_mode)", helper)
        self.assertIn('isEqualToString:@"../tmp"', helper)

        create = section("- (NSError *)rh3CreateRoot:", "- (NSError *)rh3RecoverTmpCollisionAtRoot:")
        self.assertIn("RH3IsExpectedDonorTmpLink(secondaryTmp)", create)
        self.assertIn("RH3IsRealDirectory(rootTmp)", create)
        self.assertIn("unlink(secondaryTmp.fileSystemRepresentation)", create)
        self.assertNotIn("removeItemAtPath:secondaryTmp", create)
        self.assertLess(create.index("RH3IsExpectedDonorTmpLink(secondaryTmp)"),
                        create.index("unlink(secondaryTmp.fileSystemRepresentation)"))
        self.assertLess(create.index("unlink(secondaryTmp.fileSystemRepresentation)"),
                        create.index("[fm moveItemAtPath:rootTmp toPath:secondaryTmp"))

    def test_recovery_is_specific_to_owned_iOS16_incomplete_layout(self):
        detector = section("static BOOL RH3IsKnownTmpCollision(", "// Staged dependency files")
        for item in ("rootHideBrandForPath:root", "root.lastPathComponent",
                     'RH3PendingState(root) isEqualToString:@"creating"',
                     "rootStat.st_uid != 0", "secondaryStat.st_uid != 0",
                     "RH3IsExpectedDonorTmpLink(", 'isEqualToString:@"private/var"',
                     "RH3InstalledMarker", "RH3IsRealDirectory(secondaryVar)"):
            self.assertIn(item, detector)
        recover = section("- (NSError *)rh3RecoverTmpCollisionAtRoot:", "- (NSError *)rh3RerandomizeRoot:")
        self.assertIn("version != 1900", recover)  # iOS 16 profile = 1900, NOT 1800
        self.assertIn("operatingSystemVersion.majorVersion != 16", recover)
        self.assertIn("!RH3IsKnownTmpCollision(root, secondary)", recover)
        self.assertLess(recover.index("!RH3IsKnownTmpCollision(root, secondary)"),
                        recover.index("unlink(secondaryTmp.fileSystemRepresentation)"))
        self.assertIn('RH3WritePendingState(root, @"layout")', recover)
        self.assertNotIn("removeItemAtPath:root", recover)
        self.assertNotIn("removeItemAtPath:secondary", recover)
        self.assertNotIn("prep_bootstrap.sh", recover)
        preflight = section("- (NSError *)rootHidePreflightError", "- (NSError *)rh3BuildPackageSourcesInRoot:")
        self.assertIn("version == 1900", preflight)
        self.assertIn("RH3IsKnownTmpCollision(root,", preflight)
        prepare = section("- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion\n{",
                          "- (NSError *)finalizeRootHideBootstrap\n{")
        self.assertIn("[self rh3RecoverTmpCollisionAtRoot:root version:version]", prepare)
        self.assertLess(prepare.index("[self rh3RecoverTmpCollisionAtRoot:root version:version]"),
                        prepare.index("[self rh3InstallBasebinAtRoot:root]"))
        self.assertIn('stage isEqualToString:@"running-script"', prepare)


if __name__ == "__main__":
    unittest.main()
