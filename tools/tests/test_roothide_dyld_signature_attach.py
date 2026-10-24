"""iOS dyld fcntl signature attach contracts for RootHide's private dyld.

Must not fake a successful F_ADDFILESIGS_INFO/RETURN or silently ignore the
trusted result when mapping package libraries, including APT libgnutls.
"""

from pathlib import Path
import unittest


SOURCE = (Path(__file__).resolve().parents[2] /
          "BaseBin/dyldhook/src/lv_bypass.c")


class DyldSignatureAttach(unittest.TestCase):
    def test_self_contained_private_dyld_uses_cerror_trampoline(self):
        source = SOURCE.read_text(encoding="utf-8")
        trampoline = (SOURCE.parent / "main.S").read_text(encoding="utf-8")
        helper = source.split("static int fcntl_trust_error(", 1)[1].split(
            "int HOOK(__fcntl)", 1)[0]
        self.assertIn("MAKE_TRAMPOLINE(cerror)", trampoline)
        self.assertIn("return cerror(error);", helper)
        self.assertNotIn("errno =", helper,
                         "Darwin errno requires __error() and breaks self-contained dyldhook")

    def test_all_dyld_signature_attach_ops_are_handled(self):
        source = SOURCE.read_text(encoding="utf-8")
        for cmd in ("case F_ADDSIGS:", "case F_ADDFILESIGS:",
                    "case F_ADDFILESIGS_INFO:", "case F_ADDFILESIGS_RETURN:"):
            self.assertIn(cmd, source)

    def test_kernel_first_and_no_forged_success_for_return_info(self):
        source = SOURCE.read_text(encoding="utf-8")
        hook = source[source.index("int HOOK(__fcntl)("):]
        self.assertIn("if (result == 0 || !jbinfo_is_checked_in()) return result;", hook)
        self.assertIn("return fcntl_trust_error(r);", hook)
        self.assertIn("cmd == F_ADDFILESIGS_RETURN", hook)
        self.assertIn("|| cmd == F_ADDFILESIGS_INFO", hook)
        self.assertNotIn("((fsignatures_t *)arg1)->fs_file_start =", hook)
        self.assertIn("return (int)msyscall_errno(0x5C, fd, cmd,", hook)


if __name__ == "__main__":
    unittest.main()
