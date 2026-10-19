"""Guard the optional dyld fcntl redirect without replacing the hook backend."""
from pathlib import Path
import sys
import unittest
import test_roothide_boot_transition as boot

ROOT = Path(__file__).resolve().parents[2]


def redirect():
    source = (ROOT/'BaseBin/systemhook/src/main.c').read_text(encoding='utf-8')
    return source.split('// Hook the dyld_shared_cache __fcntl', 1)[1].split(
        '// Initialize stuff neccessary for sandbox_apply hook', 1)[0].split('\n', 1)[1]


class FcntlRedirect(unittest.TestCase):
    def test_missing_dyld_or_symbol_cannot_install_a_null_target(self):
        code = redirect()
        self.assertIn('fcntlDyldHeader ? litehook_find_symbol', code)
        self.assertIn('if (dyld___fcntl)', code)
        self.assertLess(code.index('if (dyld___fcntl)'), code.index('litehook_hook_function'))

    @unittest.skipUnless(sys.platform == 'darwin', 'native fcntl redirect installation test')
    def test_null_resolution_preserves_fcntl_and_found_target_is_still_installed(self):
        # Compile the actual initializer block. The resolver and patch backend
        # are fixtures, so this checks installation decisions, not iOS patching.
        boot.BootTransition().run_native(r'''
#include <stddef.h>
#include <string.h>
struct mach_header_64 { int fixture; };
static struct mach_header_64 image;
static const struct mach_header_64 *header;
static void *resolved, *installedSource, *installedTarget;
static int resolutions, installs, originals;
int __fcntl(int fd, int command, ...) { originals++; return fd+command; }
static int replacement(int fd, int command, ...) { return fd-command; }
static const struct mach_header_64 *get_dyld_mach_header(void) { return header; }
static void *litehook_find_symbol(const struct mach_header_64 *h, const char *name) {
 resolutions++;
 if(h!=&image || strcmp(name,"___fcntl"))return NULL;
 return resolved;
}
static int litehook_hook_function(void *source, void *target) {
 installs++; installedSource=source; installedTarget=target; return 0;
}
static void initialize(void) {
''' + redirect() + r'''
}
int main(void) {
 initialize();
 if(resolutions || installs || __fcntl(3,50)!=53 || originals!=1)return 1;
 header=&image;
 initialize();
 if(resolutions!=1 || installs || __fcntl(3,50)!=53 || originals!=2)return 2;
 resolved=replacement;
 initialize();
 if(resolutions!=2 || installs!=1 || installedSource!=(void *)__fcntl || installedTarget!=resolved)return 3;
 return 0;
}
''', 'BaseBin/systemhook/src', False)


if __name__ == '__main__':
    unittest.main()
