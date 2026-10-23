"""Contract: runtime diagnosis must agree with systemhook's fail-closed policy.

The primary .safe_mode marker is not the whole state: a watchdog marker in
the associated AppGroup/var can independently disable tweak injection.
"""
from pathlib import Path
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"


class EffectiveSafeModeDiagnosisTests(unittest.TestCase):
    def test_runtime_diagnosis_reports_primary_watchdog_and_unknown_separately(self):
        source = SOURCE.read_text(encoding="utf-8")
        diagnose = source.split("- (int)diagnoseRootHideRuntime", 1)[1].split(
            "- (int)repairRootHideSSH", 1)[0]
        self.assertIn("rh3_tweak_watchdog_latched(", diagnose)
        self.assertIn("tweak_primary_safe_mode=", diagnose)
        self.assertIn("tweak_watchdog_latched=", diagnose)
        self.assertIn("tweak_status_unknown=", diagnose)
        self.assertIn("tweak_safe_mode=", diagnose)
        self.assertIn("primaryReadError != ENOENT", diagnose)
        self.assertIn("primaryUnknown || watchdogUnknown", diagnose)
        self.assertNotIn("BOOL marker = lstat(", diagnose)


if __name__ == "__main__":
    unittest.main()
