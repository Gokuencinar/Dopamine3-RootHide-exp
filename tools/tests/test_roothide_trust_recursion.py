"""Trust recursion must reject allocation failures without crashing launchd."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RootHideTrustRecursionTests(unittest.TestCase):
    def test_allocation_is_checked_before_overwriting_output(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("*cdhashesOut = realloc", source)
        self.assertIn("cdhash_t *resized = realloc(", source)
        self.assertIn("if (!resized) {", source)
        self.assertLess(source.index("if (!resized) {"), source.index("*cdhashesOut = resized;"))
        self.assertIn("*cdhashCountOut = newCount;", source)

    def test_recursive_failure_returns_error_and_skips_trustcache_upload(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m").read_text(
            encoding="utf-8"
        )
        caller = (
            ROOT / "BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c"
        ).read_text(encoding="utf-8")
        self.assertIn("RH3_MAX_TRUST_DEPENDENCIES 4096", source)
        self.assertIn("RH3_MAX_TRUST_DEPTH 64", source)
        self.assertIn("return failed ? -1 : 0;", source)
        self.assertIn("if (recurse_collect_untrusted_cdhashes(", caller)
        self.assertLess(caller.index("return -1;", caller.index("if (recurse_collect_untrusted_cdhashes(")), caller.index("jb_trustcache_add_cdhashes(cdhashes, cdhashesCount)"))

    def test_missing_required_dependencies_propagate_but_weak_can_be_absent(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m").read_text(encoding="utf-8")
        self.assertIn("unsigned depth, bool required, bool *failed)", source)
        self.assertIn("if (required) *failed = true;", source)
        self.assertIn("cmd != LC_LOAD_WEAK_DYLIB && cmd != LC_LAZY_LOAD_DYLIB", source)
        self.assertIn("depth + 1, dependencyRequired, failed)", source)
        self.assertIn("0, true, &failed)", source)
        self.assertIn('JBLogError("Failed to decode code signature', source)
        self.assertIn('JBLogError("Failed to calculate ad-hoc CDHash', source)
        self.assertIn("*failed = true;", source[source.index("ensure_randomized_cdhash_for_slice("):])

    def test_unreadable_macho_signature_is_not_treated_as_non_adhoc(self):
        source = (ROOT / "BaseBin/libjailbreak/src/roothider/signatures.m").read_text(encoding="utf-8")
        start = source.index("CS_SuperBlob *superblob = macho_read_code_signature(macho);")
        stop = source.index("if (cdhashWasKnown ||", start)
        block = source[start:stop]
        self.assertIn("if (superblob) {", block)
        self.assertIn('JBLogError("Missing or unreadable code signature', block)
        self.assertIn("*failed = true;", block[block.index("} else {", block.index("free(superblob);")):])
        self.assertIn("if (csd_superblob_is_adhoc_signed(decodedSuperblob))", block)


if __name__ == "__main__":
    unittest.main()
