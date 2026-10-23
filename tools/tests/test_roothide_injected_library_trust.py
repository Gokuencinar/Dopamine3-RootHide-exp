"""Never mask a failed active-root injected dylib trust operation as spawn success."""
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
HOOK = ROOT / 'BaseBin/systemhook/src/roothider_port.c'
MAIN = ROOT / 'BaseBin/systemhook/src/main.c'


class RootHideInjectedLibraryTrust(unittest.TestCase):
    def test_library_trust_failure_reaches_spawn_caller(self):
        hook = HOOK.read_text(encoding='utf-8')
        main = MAIN.read_text(encoding='utf-8')
        self.assertIn('int roothide_trust_injected_libraries(char *const envp[])', hook)
        self.assertIn('int roothide_trust_injected_libraries(char *const envp[])', main)
        source = hook.split('int roothide_trust_injected_libraries(', 1)[1]
        self.assertIn('rh3_trust_is_active_root_child(', source)
        self.assertIn('jbclient_trust_library_recurse(entry, NULL)', source)
        self.assertIn('rh3_trust_looks_like_macho(entry)', source)
        self.assertIn('return EACCES;', source)
        trust = main.split('static int rh3_trust_before_spawn(', 1)[1].split(
            'int __posix_spawn_hook(', 1)[0]
        self.assertIn('return roothide_trust_injected_libraries(envp);', trust)

    def test_checked_in_root_and_caller_guards_stay_scoped(self):
        hook = HOOK.read_text(encoding='utf-8')
        source = hook.split('int roothide_trust_injected_libraries(', 1)[1]
        self.assertIn('systemhook_is_roothide_root_path(root)', source)
        self.assertIn('realpath(root, resolvedRoot)', source)
        self.assertIn('realpath(entry, resolved)', source)
        self.assertIn('strcmp(entry, HOOK_DYLIB_PATH)', source)
        self.assertNotIn('jbclient_roothide_patch_child', source)
        self.assertNotIn('host_set_special_port', source)


if __name__ == '__main__':
    unittest.main()
