"""Regression checks for untrusted GitHub Actions download caches."""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/main.yml'
BOOTSTRAPS = ROOT / 'Application/Dopamine/Resources/download_bootstraps.sh'


class RootHideCICache(unittest.TestCase):
    def test_restores_downloads_only_and_saves_before_strict_failure(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        self.assertEqual(workflow.count('uses: actions/cache/restore@v4'), 2)
        self.assertEqual(workflow.count('uses: actions/cache/save@v4'), 2)
        self.assertLess(workflow.index('Restore pinned Theos SDK download'),
                        workflow.index('- name: Install THEOS'))
        self.assertLess(workflow.index('Save verified Theos SDK download'),
                        workflow.index('- name: Build and Install trustcache'))
        self.assertLess(workflow.index('Restore verified Procursus bootstrap downloads'),
                        workflow.index('- name: Download Bootstraps'))
        self.assertLess(workflow.index('Save verified Procursus bootstrap downloads'),
                        workflow.index('- name: Build\n'))
        self.assertLess(workflow.index('Save verified Procursus bootstrap downloads'),
                        workflow.index('- name: Check RootHide port prerequisites before upload'))
        for label in ('Save verified Theos SDK download',
                      'Save verified Procursus bootstrap downloads'):
            block = workflow.split(f'- name: {label}\n', 1)[1].split('\n      - name:', 1)[0]
            self.assertIn("github.event_name != 'pull_request'", block)
            self.assertIn("github.ref == 'refs/heads/roothide-dopamine3-integration'", block)
            self.assertIn("cache-hit != 'true'", block)
        keys = re.findall(r'^\s+key: (rh3-macos15-[^\s]+)', workflow, flags=re.M)
        self.assertEqual(len(keys), 4)
        self.assertEqual(keys[0], keys[1])
        self.assertEqual(keys[2], keys[3])
        for unsafe in ('Application/build/', 'BaseBin/.build/', 'basebin.tar',
                       'basebin.tc', 'Dopamine.ipa', 'DerivedData', 'trustcache'):
            for section in re.findall(r'uses: actions/cache/(?:restore|save)@v4\n\s+with:\n(.*?)(?=\n\s+- name:|\Z)',
                                      workflow, flags=re.S):
                self.assertNotIn(unsafe, section)

    def test_checksum_pins_are_unchanged_and_checked_on_hits(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        script = BOOTSTRAPS.read_text(encoding='utf-8')
        for fragment in ('5e0fd3f01266cce4ce012d4a99b38eb56578fca40d09edc81cd83dee958202fb',
                         'SDK_ARCHIVE', 'shasum -a 256 -c -', 'if [[ -f "$SDK_ARCHIVE" && ! -L "$SDK_ARCHIVE" ]]'):
            self.assertIn(fragment, workflow)
        for fragment in ('a99b39bb0344ee3b42bb961325038dceae7daaec500976f3b822cf36cccf020a',
                         '8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb',
                         'Using verified cached Procursus', 'shasum -a 256 -c -',
                         '[[ -f "$file" && ! -L "$file" ]]',
                         'bytes.fromhex("28b52ffd")'):
            self.assertIn(fragment, script)
        self.assertNotIn('restore-keys:', workflow)  # No broad or cross-version match.

    @unittest.skipUnless(sys.platform == 'darwin', 'offline bash/cache verification on macOS CI')
    def test_corrupt_or_symlinked_bootstrap_is_redownloaded_offline(self):
        original = BOOTSTRAPS.read_text(encoding='utf-8')
        first = bytes.fromhex('28b52ffd') + b'A' * 2048
        second = bytes.fromhex('28b52ffd') + b'B' * 2048
        for before, payload in (
            ('a99b39bb0344ee3b42bb961325038dceae7daaec500976f3b822cf36cccf020a', first),
            ('8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb', second),
        ):
            original = original.replace(before, hashlib.sha256(payload).hexdigest())
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            bin_dir = directory / 'bin'
            bin_dir.mkdir()
            (directory / 'fixture1800').write_bytes(first)
            (directory / 'fixture1900').write_bytes(second)
            (directory / 'bootstrap_1800.tar.zst').write_bytes(first)
            (directory / 'bootstrap_1900.tar.zst').write_bytes(second)
            script = directory / 'download.sh'
            script.write_text(original, encoding='utf-8')
            curl = bin_dir / 'curl'
            curl.write_text('''#!/bin/bash
set -euo pipefail
out=
for ((i=1;i<=$#;i++)); do
  if [[ "${!i}" == --output ]]; then
    j=$((i+1)); out="${!j}"; break
  fi
done
[[ -n "$out" ]]
if [[ "$out" == *1800* ]]; then cp "$TEST_DIR/fixture1800" "$out"; else cp "$TEST_DIR/fixture1900" "$out"; fi
echo download >> "$TEST_DIR/downloads"
''', encoding='utf-8')
            curl.chmod(0o755)
            env = dict(os.environ, PATH=f'{bin_dir}:{os.environ["PATH"]}', TEST_DIR=str(directory))

            def run():
                subprocess.run(['/bin/bash', str(script)], cwd=directory, env=env, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            run()
            self.assertFalse((directory / 'downloads').exists())  # Valid hit: no downloads.
            (directory / 'bootstrap_1800.tar.zst').write_bytes(b'cache-poison')
            run()
            self.assertEqual((directory / 'bootstrap_1800.tar.zst').read_bytes(), first)
            self.assertEqual((directory / 'downloads').read_text().count('download'), 1)
            outside = directory / 'outside'
            outside.write_bytes(b'must survive')
            (directory / 'bootstrap_1900.tar.zst').unlink()
            (directory / 'bootstrap_1900.tar.zst').symlink_to(outside)
            run()
            self.assertEqual(outside.read_bytes(), b'must survive')
            self.assertEqual((directory / 'bootstrap_1900.tar.zst').read_bytes(), second)
            self.assertEqual((directory / 'downloads').read_text().count('download'), 2)


if __name__ == '__main__':
    unittest.main()
