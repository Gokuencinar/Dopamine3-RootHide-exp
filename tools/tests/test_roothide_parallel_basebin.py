"""Makefile dependency guards for the parallel RootHide3 BaseBin build.

The macOS runner verifies the real build with GNU Make, Swift, Xcode and
trustcache. These portable checks prevent unsafe dependency removal.
"""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
MAKEFILE = (ROOT / "BaseBin/Makefile").read_text(encoding="utf-8")

SUBPROJECTS = (
    "ChOma", "XPF", "MachOMerger", "opainject", "tweakprobe", "libjailbreak",
    "systemhook", "forkfix", "launchdhook", "hookd", "boomerang",
    "jbctl", "idownloadd", "watchdoghook", "rootlesshooks",
    "roothidehooks", "jailbreakd", "bootstrapper", "dopamine",
)


def prerequisites(name: str) -> set[str]:
    match = re.search(r"^" + re.escape(name) + r":([^\n]*)$", MAKEFILE, re.M)
    if match is None:
        raise AssertionError(f"Missing Make rule: {name}")
    return set(match.group(1).split())


def depends_on(name: str, dependency: str, seen=None) -> bool:
    if name == dependency:
        return True
    if seen is None:
        seen = set()
    if name in seen:
        return False
    seen.add(name)
    return any(
        depends_on(child, dependency, seen.copy())
        for child in prerequisites(name)
        if re.search(r"^" + re.escape(child) + r":", MAKEFILE, re.M)
    )


class ParallelBaseBinBuild(unittest.TestCase):
    def test_no_global_serial_barrier(self):
        self.assertNotRegex(MAKEFILE, r"(?m)^\s*\.NOTPARALLEL\s*:")

    def test_staging_completes_before_any_subproject(self):
        self.assertEqual(prerequisites("staging"), {".build", ".include"})
        self.assertIn("staging", prerequisites(".PHONY"))
        for name in SUBPROJECTS:
            with self.subTest(name=name):
                self.assertIn("staging", prerequisites(name))
                self.assertTrue(depends_on(name, ".build"))
                self.assertTrue(depends_on(name, ".include"))
        self.assertRegex(MAKEFILE, r"(?ms)^\.build:\n\s+rm -rf \.build\n")
        self.assertRegex(MAKEFILE, r"(?ms)^\.include:\n\s+rm -rf \.include\n")

    def test_generated_headers_and_libraries_are_serialized(self):
        self.assertTrue(depends_on("XPF", "ChOma"))
        self.assertTrue(depends_on("libjailbreak", "ChOma"))
        self.assertTrue(depends_on("dopamine", "XPF"))
        self.assertTrue(depends_on("dopamine", "libjailbreak"))
        for name in (
            "systemhook", "forkfix", "launchdhook", "hookd", "boomerang",
            "jbctl", "idownloadd", "watchdoghook", "rootlesshooks",
            "roothidehooks", "jailbreakd", "bootstrapper",
        ):
            with self.subTest(name=name):
                self.assertTrue(depends_on(name, "libjailbreak"))
        self.assertTrue(depends_on("forkfix", "systemhook"))

    def test_trustcache_and_tar_are_serialized_after_every_component(self):
        self.assertEqual(prerequisites("subprojects"), set(SUBPROJECTS))
        self.assertIn("subprojects", prerequisites("basebin.tc"))
        for name in SUBPROJECTS:
            with self.subTest(name=name):
                self.assertTrue(depends_on("basebin.tc", name))
        self.assertIn("basebin.tc", prerequisites("dyldhook"))
        self.assertIn("dyldhook", prerequisites("basebin.tar"))
        self.assertIn("basebin.tc", prerequisites("basebin.tar"))
        self.assertTrue(depends_on("basebin.tar", "subprojects"))

    def test_only_distinct_staged_artifacts_are_written(self):
        names = re.findall(r"\bcp\s+[^\n]*?\s+\.build/(\S+)", MAKEFILE)
        self.assertEqual(len(names), len(set(names)), names)
        self.assertNotIn("rm -rf .build\n", MAKEFILE.split("basebin.tc: subprojects")[1].split("clean:")[0])


if __name__ == "__main__":
    unittest.main()
