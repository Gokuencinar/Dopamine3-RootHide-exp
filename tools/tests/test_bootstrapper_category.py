"""Keep Objective-C RootHide bootstrap category API and implementation aligned."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class BootstrapperCategoryTests(unittest.TestCase):
    def test_roothide_methods_are_declared_in_implemented_category(self):
        header = (ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.h").read_text(
            encoding="utf-8"
        )
        implementation = (
            ROOT / "Application/Dopamine/Jailbreak/DOBootstrapper.m"
        ).read_text(encoding="utf-8")
        self.assertIn("@interface DOBootstrapper (RootHidePort)", header)
        self.assertIn("@implementation DOBootstrapper (RootHidePort)", implementation)
        category = header.split("@interface DOBootstrapper (RootHidePort)", 1)[1]
        for selector in (
            "rootHidePortEnabled",
            "rootHideExistingRootWithError:",
            "rootHideBrandForPath:",
        ):
            with self.subTest(selector=selector):
                self.assertIn(selector, category)
                self.assertNotIn(selector, header.split("@end", 1)[0])


if __name__ == "__main__":
    unittest.main()
