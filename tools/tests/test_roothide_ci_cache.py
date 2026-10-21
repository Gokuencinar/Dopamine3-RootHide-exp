"""Regression checks for GitHub Actions download, source, and object caches."""
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
    def test_restores_pinned_dependencies_and_saves_before_strict_failure(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        self.assertEqual(workflow.count('uses: actions/cache/restore@v4'), 4)
        self.assertEqual(workflow.count('uses: actions/cache/save@v4'), 4)
        self.assertLess(workflow.index('Restore pinned Theos SDK download'),
                        workflow.index('- name: Install THEOS'))
        self.assertLess(workflow.index('Save verified Theos SDK download'),
                        workflow.index('- name: Build and Install trustcache'))
        self.assertLess(workflow.index('Restore pinned RootHide Theos source checkout'),
                        workflow.index('- name: Install THEOS'))
        self.assertLess(workflow.index('Save pinned RootHide Theos source checkout'),
                        workflow.index('- name: Build and Install trustcache'))
        self.assertLess(workflow.index('Restore verified Procursus bootstrap downloads'),
                        workflow.index('- name: Download Bootstraps'))
        self.assertLess(workflow.index('Save verified Procursus bootstrap downloads'),
                        workflow.index('- name: Build\n'))
        self.assertLess(workflow.index('Save verified Procursus bootstrap downloads'),
                        workflow.index('- name: Check RootHide port prerequisites before upload'))
        self.assertLess(workflow.index('Save RootHide object cache'),
                        workflow.index('- name: Check RootHide port prerequisites before upload'))
        for label in ('Save verified Theos SDK download',
                      'Save verified Procursus bootstrap downloads',
                      'Save pinned RootHide Theos source checkout'):
            block = workflow.split(f'- name: {label}\n', 1)[1].split('\n      - name:', 1)[0]
            self.assertIn("github.event_name != 'pull_request'", block)
            self.assertIn("startsWith(github.ref, 'refs/heads/roothide-')", block)
            self.assertIn("cache-hit != 'true'", block)
        keys = re.findall(r'^\s+key: (rh3-macos15-[^\s]+)', workflow, flags=re.M)
        self.assertEqual(len(keys), 6)
        self.assertEqual(keys[0], keys[3])
        self.assertEqual(keys[1], keys[2])
        self.assertEqual(keys[4], keys[5])
        for unsafe in ('Application/build/', 'BaseBin/.build/', 'basebin.tar',
                       'basebin.tc', 'Dopamine.ipa', 'DerivedData', 'trustcache'):
            for section in re.findall(r'uses: actions/cache/(?:restore|save)@v4\n\s+with:\n(.*?)(?=\n\s+- name:|\Z)',
                                      workflow, flags=re.S):
                self.assertNotIn(unsafe, section)

    def test_roothide_theos_source_cache_is_cleaned_and_pinned(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        cache = workflow.split('- name: Restore pinned RootHide Theos source checkout\n', 1)[1].split('\n      - name:', 1)[0]
        self.assertIn("github.event_name != 'pull_request'", cache)
        self.assertIn("startsWith(github.ref, 'refs/heads/roothide-')", cache)
        self.assertIn('!theos/sdks', cache)
        self.assertIn('cfba89a53a05b4a1b822121158acc3669c20602f', cache)
        install = workflow.split('- name: Install THEOS\n', 1)[1].split('\n      - name:', 1)[0]
        for guard in ('cached_origin', 'cached_sha', 'checkout --detach "$THEOS_REV"',
                      'reset --hard "$THEOS_REV"', 'clean -ffdx',
                      'submodule update --init --recursive --force',
                      "grep -Eq '^[-+U]'"):
            self.assertIn(guard, install)

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
        # Download caches must have an exact SHA-pinned key. Only compiled
        # objects may use a restricted restore prefix (same Xcode and mode).
        for label in ('Restore pinned Theos SDK download',
                      'Restore verified Procursus bootstrap downloads'):
            block = workflow.split(f'- name: {label}\n', 1)[1].split('\n      - name:', 1)[0]
            self.assertNotIn('restore-keys:', block)

    def test_incremental_cache_is_object_only_and_refuses_untrusted_writes(self):
        workflow = WORKFLOW.read_text(encoding='utf-8')
        makefile = (ROOT/'Application/Makefile').read_text(encoding='utf-8')
        restore = workflow.split('- name: Restore RootHide object cache\n', 1)[1].split(
            '\n      - name:', 1)[0]
        save = workflow.split('- name: Save RootHide object cache\n', 1)[1].split(
            '\n      - name:', 1)[0]
        configure = workflow.split('- name: Configure incremental C and Objective-C cache\n', 1)[1].split(
            '\n      - name:', 1)[0]
        self.assertIn('uses: actions/cache/restore@v4', restore)
        self.assertIn('uses: actions/cache/save@v4', save)
        for block in (restore, save):
            self.assertIn('github.event_name != \'pull_request\'', block)
            self.assertIn("startsWith(github.ref, 'refs/heads/roothide-')", block)
            self.assertIn('path: ~/.cache/ccache-roothide3', block)
            self.assertNotIn('BaseBin/.build', block)
            self.assertNotIn('DerivedData', block)
            self.assertNotIn('.ipa', block)
        self.assertIn('restore-keys:', restore)
        self.assertEqual(re.search(r'key: (rh3-objects-[^\n]+)', restore).group(1),
                         re.search(r'key: (rh3-objects-[^\n]+)', save).group(1))
        self.assertIn('steps.ccache_identity.outputs.xcode_id', restore)
        self.assertIn('env.ROOTHIDE_HARDWARE_TEST', restore)
        self.assertIn('steps.ccache_identity.outputs.cache_day', save)
        self.assertIn("steps.rh3_object_cache.outputs.cache-hit != 'true'", save)
        self.assertIn('continue-on-error: true', save)
        self.assertIn('CCACHE_MAXSIZE=512M', configure)
        self.assertIn('CMAKE_C_COMPILER_LAUNCHER=', configure)
        self.assertIn('CMAKE_CXX_COMPILER_LAUNCHER=', configure)
        self.assertIn('brew install ccache', configure)
        self.assertNotIn('CCACHE_SLOPPINESS', configure)
        self.assertIn('RH3_CCACHE=1', workflow)
        self.assertIn('ccache --show-stats', workflow)
        self.assertIn('C_COMPILER_LAUNCHER=', makefile)
        self.assertIn('CXX_COMPILER_LAUNCHER=', makefile)
        self.assertIn('ifeq ($(RH3_CCACHE),1)', makefile)

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
