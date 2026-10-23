"""RootHide fork regression: per-process initialization must not be root-only.

Source and pinned bootstrap checks; not evidence of execution on an iPhone.
"""
import subprocess
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]
PORT = ROOT / 'BaseBin/systemhook/src/roothider_port.c'


class GlobalRoothideInitialization(unittest.TestCase):
    def test_pinned_bootstrap_actually_carries_the_initializer(self):
        asset = ROOT / 'Application/Dopamine/Resources/roothide_bootstrap_1900.tar.zst'
        result = subprocess.run(['tar', '-tf', str(asset)], text=True, capture_output=True, timeout=30)
        if result.returncode:
            self.skipTest('system tar cannot inspect the pinned zstd archive')
        self.assertIn('./usr/lib/roothideinit.dylib', result.stdout)

    def test_init_is_not_restricted_to_executables_inside_jbroot(self):
        src = PORT.read_text()
        routine = src.split('void roothide_prepare_checked_in_process(', 1)[1].split('void roothide_prepare_process(', 1)[0]
        # The constructor has already authenticated the process check-in
        # before calling this routine. Re-querying launchd here can fail
        # while services are coming up, silently suppressing roothideinit.
        self.assertNotIn('jbclient_roothide_jailbroken()', routine)
        self.assertIn('systemhook_is_roothide_root_path(root)', routine)
        self.assertIn('rh3_load_rooted_init(root)', routine)
        self.assertNotIn('root_contains_executable(', routine)
        executable = src.split('void roothide_prepare_process(', 1)[1].split('void roothide_trust_injected_libraries(', 1)[0]
        self.assertIn('root_contains_executable(root, executable)', executable)
        self.assertIn('roothide_redirect_home(root)', executable)
        self.assertNotIn('rh3_load_rooted_init(root)', executable)

    def test_load_is_limited_to_verified_signed_root_owned_file(self):
        src = PORT.read_text()
        routine = src.split('static void rh3_load_rooted_init(', 1)[1].split('void roothide_prepare_checked_in_process(', 1)[0]
        self.assertIn('lstat(', routine)
        self.assertIn('S_ISREG(', routine)
        self.assertIn('st.st_uid != 0', routine)
        self.assertIn('st.st_mode & 0022', routine)
        self.assertIn('realpath(', routine)
        self.assertIn('rh3_trust_is_active_root_child(', routine)
        self.assertIn('dlopen(', routine)
        self.assertIn('RTLD_NOW', routine)

    def test_systemhook_initialization_calls_per_process_init_after_checkin(self):
        src = (ROOT / 'BaseBin/systemhook/src/main.c').read_text()
        ctor = src.split('__attribute__((constructor)) static void initializer', 1)[1]
        self.assertLess(ctor.index('parse_dyldhook_jbinfo'), ctor.index('roothide_prepare_checked_in_process('))
        self.assertLess(ctor.index('jbclient_process_checkin('), ctor.index('roothide_prepare_checked_in_process('))
        self.assertIn('else {', ctor.split('jbclient_process_checkin(', 1)[1].split('roothide_prepare_checked_in_process(', 1)[0])
        # The donor loads roothideinit before resolving an executable path.
        # xpcproxy and shortly-lived services may not resolve a realpath.
        self.assertLess(ctor.index('roothide_prepare_checked_in_process('), ctor.index('if (load_executable_path() == 0)'))
        self.assertLess(ctor.index('roothide_prepare_checked_in_process('), ctor.index('roothide_prepare_process('))
        self.assertLess(ctor.index('roothide_prepare_process('), ctor.index('should_enable_tweaks()'))


if __name__ == '__main__':
    unittest.main()
