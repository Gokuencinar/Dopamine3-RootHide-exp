"""Source-level safeguards for experimental launchd bootstrap and recovery.

These checks do not simulate a live launchd process or prove iPhone boot safety.
"""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RootHideLaunchdHandshakeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = (
            ROOT / "Application/Dopamine/Jailbreak/DOJailbreaker.m"
        ).read_text(encoding="utf-8")
        cls.safe = cls.source.split("- (NSError *)injectRootHideLaunchdHookSafely", 1)[1].split(
            "- (NSError *)injectLaunchdHook", 1
        )[0]

    def test_stock_injection_kept_separate(self):
        stock = self.source.split("- (NSError *)injectLaunchdHook", 1)[1].split(
            "- (NSError *)applyProtection", 1
        )[0]
        self.assertIn("if ([DOBootstrapper rootHidePortEnabled]) return [self injectRootHideLaunchdHookSafely];", stock)
        self.assertIn("dispatch_semaphore_wait(info.boomerangDone, DISPATCH_TIME_FOREVER);", stock)

    def test_root_is_validated_before_launchd_injection(self):
        self.assertIn("rootHideExistingRootWithError:&rootError", self.safe)
        self.assertIn("rootHideBrandForPath:root", self.safe)
        self.assertIn("lstat(path.fileSystemRepresentation, &info)", self.safe)
        self.assertIn("S_ISREG(info.st_mode)", self.safe)
        self.assertLess(self.safe.index("rootHideExistingRootWithError:&rootError"),
                        self.safe.index("mach_port_allocate("))
        self.assertLess(self.safe.index("S_ISREG(info.st_mode)"),
                        self.safe.index("mach_port_allocate("))

    def test_no_tweaks_before_hook_and_bounded_recovery(self):
        self.assertIn('@"basebin/.safe_mode"', self.safe)
        self.assertLess(self.safe.index('@"basebin/.safe_mode"'), self.safe.index("mach_port_allocate("))
        self.assertIn("!S_ISREG(safeModeInfo.st_mode)", self.safe)
        self.assertIn("errno != ENOENT", self.safe)
        self.assertIn("WNOHANG", self.safe)
        self.assertIn("CFAbsoluteTimeGetCurrent() + 15.0", self.safe)
        self.assertIn("dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC)", self.safe)
        self.assertIn("mach_port_destroy(mach_task_self(), serverPort)", self.safe)

    def test_async_context_outlives_calling_stack(self):
        self.assertIn("@interface RH3BoomerangContext : NSObject", self.source)
        self.assertLess(self.source.index("@implementation RH3BoomerangContext"),
                        self.source.index("@implementation DOJailbreaker"))
        self.assertIn("(__bridge_retained void *)context", self.safe)
        self.assertIn("(__bridge_transfer RH3BoomerangContext *)opaque", self.source)
        self.assertIn("if (xpc_pipe_receive(context.serverPort, &message) != 0) break;", self.source)
        self.assertNotIn("boomerang_server, &info", self.safe)

    def test_bootstrap_failure_cleans_up_before_injection(self):
        start = self.source.index("*errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];")
        end = self.source.index('setenv("TERM"', start)
        on_failure = self.source[start:end]
        self.assertIn("if ([DOBootstrapper rootHidePortEnabled]) [self cleanUpPostExploitation];", on_failure)
        self.assertLess(on_failure.index("cleanUpPostExploitation"),
                        self.source.index('setenv("TERM"') - start)


if __name__ == "__main__":
    unittest.main()
