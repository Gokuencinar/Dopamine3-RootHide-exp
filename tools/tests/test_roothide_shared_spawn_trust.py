"""Shared spawn trust callback must not report success after a refused RootHide binary."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'BaseBin/systemhook/src/common/common.c').read_text(encoding='utf-8')


class SharedSpawnTrust(unittest.TestCase):
    def test_trust_failure_propagates_for_active_root_macho_only(self):
        body = SOURCE.split('static int spawn_exec_hook_common(', 1)[1].split(
            'int posix_spawn_hook_shared(', 1)[0]
        trust = body.split('if (spawnConfig & kSpawnConfigTrust)', 1)[1].split(
            'const char *existingLibraryInserts', 1)[0]
        self.assertIn('trust_binary(path)', trust)
        self.assertIn('rh3_trust_is_active_root_child(path, root)', trust)
        self.assertIn('rh3_trust_looks_like_macho(path)', trust)
        self.assertIn('rh3_trust_spawn_status(', trust)
        self.assertIn('getpid() != 1', trust)
        self.assertIn('return isExec ? -1 : trustStatus;', trust)
        self.assertIn('errno = trustStatus;', trust)

    def test_no_pid1_server_xpc_or_unbounded_child_mutation(self):
        body = SOURCE.split('static int spawn_exec_hook_common(', 1)[1].split(
            'int posix_spawn_hook_shared(', 1)[0]
        trust = body.split('if (spawnConfig & kSpawnConfigTrust)', 1)[1].split(
            'const char *existingLibraryInserts', 1)[0]
        self.assertNotIn('jbclient_roothide_jailbroken()', trust)
        self.assertNotIn('jbclient_roothide_patch_child(', trust)
        self.assertNotIn('jbdSpawnPatchChild(', trust)


if __name__ == '__main__':
    unittest.main()
