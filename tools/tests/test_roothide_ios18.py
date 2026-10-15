"""Host regressions for the experimental iOS 18 path, not device evidence."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class IOS18CandidateTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == "darwin", "requires Apple's Clang blocks/availability runtime")
    def test_native_ios18_task_pair_updates_do_not_clear_adjacent_kernel_fields(self):
        production = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        function = production.split("#define DYLD_INFO_MAX_SEARCH_INDEX 200", 1)[1].split("void analyzeSegmentsLayout", 1)[0]
        harness = r'''
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define DYLD_INFO_MAX_SEARCH_INDEX 200
#define JBLogDebug(...) ((void)0)
#define JBLogError(...) ((void)0)
#define TASK_DYLD_INFO 17
#define TASK_DYLD_INFO_COUNT 6
#define KERN_SUCCESS 0
typedef int kern_return_t;
typedef int *task_info_t;
typedef struct { uint64_t all_image_info_addr, all_image_info_size; } task_dyld_info_data_t;
typedef int dispatch_once_t;
static unsigned char selfmem[2048], targetmem[2048];
static int mode, writes;
static void dispatch_once(dispatch_once_t *token, void (^block)(void)) { if (!*token) { *token=1; block(); } }
static int mach_task_self(void) { return 1; }
static int task_info(int a, int b, task_info_t out, uint32_t *count) {
    task_dyld_info_data_t value = {0x12340000, 0x100};
    memcpy(out, &value, sizeof(value)); return 0;
}
static uint64_t task_self(void) { return 0x1000; }
static uint64_t proc_find(int pid) { return 1; }
static uint64_t proc_task(uint64_t proc) { return 0x1000; }
static int kreadbuf(uint64_t addr, void *out, size_t len) {
    if (mode==4) return -1;
    unsigned char *base = addr >= 0x2000 ? targetmem : selfmem;
    uint64_t offset = addr - (addr >= 0x2000 ? 0x2000 : 0x1000);
    if (offset > 2048 || len > 2048-offset) return -1;
    memcpy(out, base+offset, len); return 0;
}
static int kwritebuf(uint64_t addr, const void *in, size_t len) {
    writes++;
    if (mode==5 || addr != 0x2000+160 || len != 16) return -1;
    memcpy(targetmem+160, in, len); return 0;
}
'''
        main = r'''
int main(int argc, char **argv) {
    mode = atoi(argv[1]);
    uint64_t pair[2] = {0x12340000, 0x100};
    memcpy(selfmem+160, pair, 16);
    if (mode==1) memcpy(selfmem+320, pair, 16); // ambiguous offset
    if (mode==2) memset(selfmem+160, 0, 16);   // missing offset
    uint64_t target[2] = {0x99990000, 0x100};
    memcpy(targetmem+160, target, 16);
    uint64_t legacy[6] = {1,0,0,0,1,0};
    memcpy(targetmem+240, legacy, sizeof(legacy));
    unsigned char before[2048]; memcpy(before, targetmem, sizeof(before));
    int result = task_set_dyld_info(0x2000, 0x88880000, 0x200,
                                   mode==3 ? 0x33330000 : target[0], target[1]);
    if (mode==0) {
        uint64_t expected[2] = {0x88880000, 0x200};
        memcpy(before+160, expected, 16);
        if (result || writes!=1 || memcmp(before,targetmem,2048)) return 1;
    } else if (result!=-1 || memcmp(before,targetmem,2048) || writes!=(mode==5)) return 2;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "task-pair.c"
            executable = Path(directory) / "task-pair"
            source.write_text(harness + function + main, encoding="utf-8")
            subprocess.run(["clang", "-fblocks", str(source), "-o", str(executable)], check=True, capture_output=True)
            for case in range(6):
                with self.subTest(case=case):
                    subprocess.run([str(executable), str(case)], check=True, capture_output=True)

    def test_compiled_bootstrap_policy_does_not_extend_to_future_os(self):
        compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
        if not compiler:
            self.skipTest("native C compiler unavailable")
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "profile.c"
            executable = Path(directory) / "profile-test.exe"
            header = ROOT / "Application/Dopamine/Jailbreak/RootHideBootstrapProfile.h"
            source.write_text('#include "' + header.as_posix() + '"\n'
                'int main(void) {\n'
                'for (int i = -1; i <= 100; i++) {\n'
                ' int expected = i == 15 ? 1800 : (i == 16 || i == 18) ? 1900 : 0;\n'
                ' if (rh3_bootstrap_version_for_os(i) != expected) return 1;\n'
                '} return 0; }\n', encoding="utf-8")
            subprocess.run([compiler, "-std=c11", "-Wall", "-Werror", str(source), "-o", str(executable)], check=True, capture_output=True)
            subprocess.run([str(executable)], check=True, capture_output=True)

    def test_all_installer_entrypoints_share_profile_and_exploit_checks(self):
        bootstrap = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        self.assertEqual(bootstrap.count("rh3_bootstrap_version_for_os("), 2)
        prepare = bootstrap.split("- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion\n{", 1)[1]
        self.assertLess(prepare.index("!version || ![[DOEnvironmentManager sharedManager] isSupported]"),
                        prepare.index("rh3CreateRoot:root"))
        self.assertNotIn("RootHide bootstrap for iOS 17+", prepare)

    def test_existing_bootstrap_cannot_silently_cross_os_or_archive_abi(self):
        source = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m").read_text()
        self.assertIn('@"OSMajor": @(NSProcessInfo.processInfo.operatingSystemVersion.majorVersion)', source)
        self.assertIn('@"ArchiveABI": @(version)', source)
        self.assertIn("st.st_uid != 0", source)
        self.assertIn("majorVersion < 18) return nil", source)
        prepare = source.split("- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion\n{", 1)[1]
        self.assertLess(prepare.index("RH3CheckBootstrapProfile(root, version)"), prepare.index("rh3RerandomizeRoot:&root"))
        create = source.split("- (NSError *)rh3CreateRoot:", 1)[1].split("- (NSError *)rh3RerandomizeRoot:", 1)[0]
        self.assertLess(create.index('Could not persist RootHide bootstrap OS/ABI profile'), create.index('RH3WritePendingState(root, @"layout")'))

    def test_old_kernel_namecache_implementations_are_excluded(self):
        makefile = (ROOT / "BaseBin/libjailbreak/Makefile").read_text()
        self.assertIn("$(filter-out src/roothider/unsandbox.m src/roothider/unsandbox1.m src/roothider/unsandbox2.m,", makefile)
        # A new caller would need a deliberate kernel port, not donor structs.
        for file in (ROOT / "BaseBin").rglob("*"):
            if file.suffix not in (".c", ".m", ".cpp") or "unsandbox" in file.stem:
                continue
            self.assertNotRegex(file.read_text(encoding="utf-8", errors="replace"), r"\bunsandbox[12]?\s*\(")

    def test_ios18_loader_hook_has_matching_c_and_assembly(self):
        hook = (ROOT / "BaseBin/dyldhook/src/roothider.c").read_text()
        assembly = (ROOT / "BaseBin/dyldhook/src/roothider.S").read_text()
        self.assertIn("#if IOS <= 18", hook)
        self.assertIn("#if IOS <= 18", assembly)
        symbol = "_ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc"
        self.assertIn("HOOK(" + symbol + ")", hook)
        self.assertIn("_MACHOMERGER_ORIG_" + symbol, assembly)

    def test_spinlock_symbols_only_required_for_ios15_arm64e(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/dyld_patch.m").read_text()
        loader = source.split("struct DYLDINFO* loadDyldInfo(", 1)[1].split("int hook_dyld_entry", 1)[0]
        lookup = loader.split("#ifdef __arm64e__", 1)[1].split("#endif", 1)[0]
        self.assertIn("if (!__builtin_available(iOS 16.0, *))", lookup)
        self.assertEqual(loader.count("get_symbol("), lookup.count("get_symbol("))
        self.assertIn("if (!result) return NULL", loader)
        patch = source.split("int proc_patch_dyld_internal(", 1)[1]
        self.assertNotIn("assert((stockDyldInfo", patch)
        self.assertLess(patch.index("Missing iOS 15 spinlock symbol or trampoline"), patch.index("task_for_pid("))


if __name__ == "__main__":
    unittest.main()
