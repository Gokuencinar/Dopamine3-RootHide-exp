"""Host regression for RootHide dyld4 interface selection and vtable writes.

This compiles the production vtable routine with fake vm_protect and ptrauth;
it does not assert successful dyld hooking on an iPhone.
"""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/systemhook/src/main.c"
PORT = ROOT / "BaseBin/systemhook/src/roothider_port.c"


class DyldVtableReferenceTests(unittest.TestCase):
    def test_inherited_insert_trust_is_limited_to_real_active_root(self):
        source = PORT.read_text(encoding="utf-8")
        routine = source.split("int roothide_trust_injected_libraries(", 1)[1]
        self.assertIn("systemhook_is_roothide_root_path(root)", routine)
        self.assertIn("rh3_trust_is_active_root_child(entry, root)", routine)
        self.assertIn("realpath(entry, resolved)", routine)
        self.assertIn("rh3_trust_is_active_root_child(resolved, resolvedRoot)", routine)
        self.assertIn("return EACCES;", routine)

    def test_libsandbox_resolution_failure_cannot_replace_dlsym(self):
        source = SOURCE.read_text(encoding="utf-8")
        hook = source.split("void *dyld_dlsym_hook(", 1)[1].split("\n}", 1)[0]
        initializer = source.split('gLibSandboxHandle = dlopen(', 1)[1].split("// Apply dyld hooks", 1)[0]
        self.assertIn("gLibSandboxHandle && sandbox_apply_orig && name", hook)
        self.assertIn("if (gLibSandboxHandle)", initializer)

    def test_gapis_arm64_hooks_cover_all_four_library_loading_routes(self):
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index('void ***gAPIsPtr = litehook_find_dsc_symbol(')
        end = source.index('\n\t}', start)  # enclosing gDyld else
        branch = source[start:end]
        for slot, hook in (
            (13, "dyld_dlopen_hook"),
            (17, "dyld_dlopen_preflight_hook"),
            (92, "dyld_dlopen_from_hook"),
            (93, "dyld_dlopen_audited_hook"),
        ):
            self.assertIn(f'dyld_hook_routine(*gAPIsPtr, {slot}, (void *)&{hook}', branch)
        self.assertIn("__arm64e__", branch)
        self.assertIn("!__builtin_available(iOS 18.0, *)", branch)

    def test_actual_vtable_routine_uses_private_copy_and_rolls_back_on_error(self):
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("No C compiler on host")
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("int dyld_hook_routine(")
        end = source.index("// The dyld4 vtable layout", start)
        production = source[start:end]
        harness = r'''
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#define VM_PROT_READ 1
#define VM_PROT_WRITE 2
#define VM_PROT_COPY 4
#define mach_task_self_ 1
#define ptrauth_key_process_independent_data 1
#define ptrauth_key_process_independent_code 2
#define ptrauth_key_function_pointer 3
#define ptrauth_auth_data(p,k,d) (p)
#define ptrauth_auth_and_resign(p,k,d,k2,d2) (p)
typedef uintptr_t mach_vm_address_t;
static int protection_calls, copy_writes, fail_readonly;
static int vm_protect(int task, mach_vm_address_t address, size_t length,
                      int set_maximum, int protection) {
    (void)task; (void)address; (void)length; (void)set_maximum;
    protection_calls++;
    if (protection & VM_PROT_WRITE) {
        if (!(protection & VM_PROT_COPY)) return 1;
        copy_writes++;
    }
    if (protection == VM_PROT_READ && fail_readonly) return 2;
    return 0;
}
'''
        cases = r'''
#define CHECK(x) do {if (!(x)) {fprintf(stderr,"line %d: %s\n",__LINE__,#x);return 1;}} while (0)
int main(void) {
    void *slots[120]={0};
    slots[13]=(void*)0x1234;
    void **slot_table=slots;
    void *original=NULL;
    CHECK(dyld_hook_routine(&slot_table,13,(void*)0x5678,&original,0xBF31)==0);
    CHECK(original==(void*)0x1234 && slots[13]==(void*)0x5678);
    CHECK(copy_writes==1 && protection_calls==2);
    slots[13]=(void*)0x1234;
    original=NULL; protection_calls=copy_writes=0; fail_readonly=1;
    CHECK(dyld_hook_routine(&slot_table,13,(void*)0x5678,&original,0xBF31)!=0);
    CHECK(slots[13]==(void*)0x1234);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            f = Path(directory) / "dyld_vtable.c"
            exe = Path(directory) / "dyld_vtable.exe"
            f.write_text(harness + production + cases, encoding="utf-8")
            build = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", str(f),
                                    "-o", str(exe)], capture_output=True, text=True, timeout=30)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=8)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
