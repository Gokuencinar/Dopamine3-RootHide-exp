"""Imported SSH dictionaries need an accurate, once-per-process checkpoint."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class OpenSSHLaunchdCheckpoint(unittest.TestCase):
    def test_checkpoint_is_not_a_false_claim_of_socket_readiness(self):
        src = (ROOT / "BaseBin/launchdhook/src/daemon_hook.m").read_text(encoding="utf-8")
        self.assertIn('strcmp(label, "com.openssh.sshd")', src)
        self.assertIn("__sync_bool_compare_and_swap(&rh3SSHLaunchdDictionarySeen, 0, 1)", src)
        self.assertIn("OpenSSH plist added to launchd dictionary; live job/socket not proved", src)
        self.assertLess(src.index("xpc_dictionary_set_value(xdict, path, daemonXdict);"),
                        src.index("OpenSSH plist added to launchd dictionary"))
        self.assertNotIn("launchctl bootstrap", src)


if __name__ == "__main__":
    unittest.main()
