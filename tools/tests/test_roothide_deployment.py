"""Regression for a strongly linked framework accidentally targeting iOS 26.1."""
import io
from pathlib import Path
import plistlib
import struct
import unittest
import zipfile
from tools.tests.test_verify_roothide_build import thin_macho
from tools.verify_roothide_full_experimental import check_embedded_deployment


def fixture(minimum, *, legacy=False, platform=2, declared='15.0'):
    command = (struct.pack('<IIII', 0x25, 16, minimum, 0) if legacy else
               struct.pack('<IIIIII', 0x32, 24, platform, minimum, 0, 0))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, 'w') as z:
        z.writestr('Payload/Dopamine.app/Info.plist', plistlib.dumps({'MinimumOSVersion':declared}))
        z.writestr('Payload/Dopamine.app/Frameworks/Titan.framework/Titan', thin_macho(extra_commands=command))
    stream.seek(0)
    return stream


class EmbeddedDeploymentTests(unittest.TestCase):
    def test_newer_embedded_target_is_rejected(self):
        with zipfile.ZipFile(fixture(0x1a0100)) as z:
            errors, checked = check_embedded_deployment(z)
            self.assertEqual(checked, 1)
            self.assertTrue(any('Titan.framework/Titan' in e and 'newer iOS' in e for e in errors))

    def test_supported_legacy_and_modern_targets(self):
        for legacy in (False, True):
            for minimum in (0x0e0000, 0x0f0000):
                with self.subTest(legacy=legacy, minimum=minimum), zipfile.ZipFile(fixture(minimum, legacy=legacy)) as z:
                    self.assertEqual(check_embedded_deployment(z), ([], 1))

    def test_wrong_platform_and_absent_declared_version_fail(self):
        for opts in ({'platform':1}, {'declared':''}):
            with self.subTest(opts=opts), zipfile.ZipFile(fixture(0x0f0000, **opts)) as z:
                self.assertTrue(check_embedded_deployment(z)[0])

    def test_titan_debug_and_release_can_load_with_the_ios15_app(self):
        project = (Path(__file__).resolve().parents[2]/'Application/Dopamine.xcodeproj/project.pbxproj').read_text()
        for config in ('3165CFD73020A516002737DA', '3165CFD83020A516002737DA'):
            settings = project.split(config + ' /*', 1)[1].split('name = ', 1)[0]
            self.assertIn('IPHONEOS_DEPLOYMENT_TARGET = 15.0;', settings)
