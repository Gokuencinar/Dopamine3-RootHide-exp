"""Execute the actual systemhook LC_UUID predicate on raw 16-byte UUIDs."""

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "BaseBin/systemhook/src/main.c"


class DyldUUIDBinaryTests(unittest.TestCase):
    def test_real_uuid_predicate_accepts_binary_magic_without_string_terminator(self):
        cc = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not cc:
            self.skipTest("C compiler unavailable")
        source = SOURCE.read_text(encoding="utf-8")
        start = source.index("static bool rh3_is_dopamine_dyld_uuid(")
        end = source.index("int parse_dyldhook_jbinfo(", start)
        helper = source[start:end]
        self.assertIn("rh3_is_dopamine_dyld_uuid(dyldUUID)", source[end:])
        self.assertNotIn('string_has_prefix((char *)dyldUUID', source)
        harness = r'''
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
typedef unsigned char uuid_t[16];
''' + helper + r'''
int main(void) {
    uuid_t good = {'D','O','P','A', 0xff,0xff,0xff,0xff,
                   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    uuid_t bad = {'X','O','P','A', 0xff,0xff,0xff,0xff,
                  0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    uuid_t short_magic = {'D','O','P',0, 0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    if (!rh3_is_dopamine_dyld_uuid(good)) return 1;
    if (rh3_is_dopamine_dyld_uuid(bad)) return 2;
    if (rh3_is_dopamine_dyld_uuid(short_magic)) return 3;
    good[15] = 0;
    if (!rh3_is_dopamine_dyld_uuid(good)) return 4;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            c_file = Path(folder) / "uuid.c"
            executable = Path(folder) / "uuid.exe"
            c_file.write_text(harness, encoding="utf-8")
            compiled = subprocess.run(
                [cc, "-std=c11", "-Wall", "-Wextra", "-Werror", str(c_file), "-o", str(executable)],
                capture_output=True, text=True, timeout=15)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(executable)], capture_output=True, text=True, timeout=7)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
