"""RootHide launchd injection must not hang before the handshake timeout."""
from pathlib import Path
import unittest

SRC = (Path(__file__).resolve().parents[2] /
       "Application/Dopamine/Jailbreak/DOJailbreaker.m")


class RootHideOpainjectTimeoutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SRC.read_text(encoding="utf-8")

    def test_only_roothide_path_invokes_bounded_injector(self):
        source = self.source
        root = source[source.index("- (NSError *)injectRootHideLaunchdHookSafely"):
                      source.index("- (NSError *)injectLaunchdHook")]
        self.assertIn("[self rh3InjectLaunchdWithTimeout]", root)
        self.assertNotIn('exec_cmd(JBROOT_PATH("/basebin/opainject")', root)
        self.assertLess(root.index("[self rh3InjectLaunchdWithTimeout]"),
                        root.index("dispatch_semaphore_wait(context.completed"))
        stock = source[source.index("- (NSError *)injectLaunchdHook"):
                       source.index("- (NSError *)applyProtection")]
        self.assertIn('exec_cmd(JBROOT_PATH("/basebin/opainject")', stock)

    def test_child_supervised_with_deadline_and_explicit_cleanup(self):
        source = self.source
        section = source[source.index("- (NSError *)rh3InjectLaunchdWithTimeout"):
                         source.index("- (NSError *)injectRootHideLaunchdHookSafely")]
        self.assertIn('exec_cmd_nowait(&child, JBROOT_PATH("/basebin/opainject")', section)
        self.assertIn("child <= 1", section)
        self.assertIn("CFAbsoluteTimeGetCurrent() + 45.0", section)
        self.assertIn("waitpid(child, &status, WNOHANG)", section)
        self.assertIn("WIFEXITED(status) && WEXITSTATUS(status) == 0", section)
        self.assertIn("kill(child, SIGTERM)", section)
        self.assertIn("kill(child, SIGKILL)", section)
        self.assertNotIn("waitpid(child, &status, 0)", section)
        self.assertIn("launchd state requires manual device recovery", section)


if __name__ == "__main__":
    unittest.main()
