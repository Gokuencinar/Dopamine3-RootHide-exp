"""Read-only recovery evidence, not permission to replay bootstrap scripts."""
from pathlib import Path
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = (ROOT / 'Application/Dopamine/Jailbreak/DOBootstrapper.m').read_text(encoding='utf-8')
PARSER = SOURCE[SOURCE.index('static NSDictionary *RH3RecoveryPackageSummary('):
                SOURCE.index('static void RH3LogRecoveryPackageState(')]
READER = SOURCE[SOURCE.index('static void RH3LogRecoveryPackageState('):
                SOURCE.index('static NSString *RH3RecoveryPathKind(')]


class RecoveryPackageEvidence(unittest.TestCase):
    def test_reader_is_bounded_read_only_and_does_not_follow_database_links(self):
        self.assertIn('const char *components[] = {"Library", "dpkg"}', READER)
        self.assertIn('openat(directory, "status", O_RDONLY | O_NOFOLLOW | O_CLOEXEC)', READER)
        self.assertIn('O_DIRECTORY | O_NOFOLLOW', READER)
        self.assertIn('before.st_size > 1024 * 1024', READER)
        self.assertIn('before.st_nlink != 1', READER)
        self.assertIn('before.st_uid != 0', READER)
        self.assertIn('before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec', READER)
        self.assertIn('before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec', READER)
        for forbidden in ('O_WRONLY', 'O_RDWR', 'O_CREAT', 'O_TRUNC', 'unlink(',
                          'exec_cmd(', 'posix_spawn(', 'master.passwd', 'spwd.db',
                          'RH3WritePendingState(', 'dataWithContentsOfFile:'):
            self.assertNotIn(forbidden, READER)

    def test_hashes_match_canonical_status_in_both_pinned_archives(self):
        try:
            import zstandard
        except ImportError:
            zstandard = None
        if zstandard is None and not shutil.which('zstd'):
            self.skipTest('zstandard module or zstd required')
        for version in (1800, 1900):
            archive = ROOT / f'Application/Dopamine/Resources/roothide_bootstrap_{version}.tar.zst'
            if zstandard:
                with archive.open('rb') as source:
                    with zstandard.ZstdDecompressor().stream_reader(source) as stream:
                        with tarfile.open(fileobj=stream, mode='r|') as tar:
                            files = self._files(tar)
            else:
                raw = subprocess.check_output(['zstd', '-dc', str(archive)])
                with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
                    files = self._files(tar)
            self.assertIn(hashlib.sha256(files['Library/dpkg/status']).hexdigest(), READER, version)
            self.assertIn(hashlib.sha256(files['prep_bootstrap.sh']).hexdigest(), SOURCE, version)

    @staticmethod
    def _files(tar):
        files = {}
        for member in tar:
            name = member.name.lstrip('./')
            if name in ('Library/dpkg/status', 'prep_bootstrap.sh'):
                if not member.isfile():
                    raise AssertionError('pinned recovery inputs must be regular files')
                files[name] = tar.extractfile(member).read()
                if len(files) == 2:
                    return files
        raise AssertionError('missing pinned recovery inputs')

    @unittest.skipUnless(sys.platform == 'darwin', 'Foundation runtime requires macOS')
    def test_actual_objective_c_parser_handles_package_state_and_rejects_ambiguity(self):
        harness = r'''
#import <Foundation/Foundation.h>
PARSER
static NSDictionary *parse(NSString *s) {
    return RH3RecoveryPackageSummary([s dataUsingEncoding:NSUTF8StringEncoding]);
}
int main(void) { @autoreleasepool {
    NSDictionary *state = parse(@"Package: firmware\r\nVersion: 16.7.15\r\nStatus: install ok installed\r\nSecret: hidden\r\n\r\nPackage: unrelated\r\nVersion: 1\r\nStatus: install ok installed\r\n");
    if (state.count != 1 || ![state[@"firmware"] isEqualToString:@"version=16.7.15; status=install ok installed"]) return 1;
    if (parse(@"Package: apt\nVersion: 1\nVersion: 2\n") != nil) return 2;
    if (parse(@"Package: apt\n\nPackage: apt\n") != nil) return 3;
    const unsigned char invalid[] = {0xff, 0xfe};
    if (RH3RecoveryPackageSummary([NSData dataWithBytes:invalid length:2]) != nil) return 4;
    if (parse(@"Package: apt\nStatus: bad\tstate\n") != nil) return 5;
    NSString *longValue = [@"x" stringByPaddingToLength:129 withString:@"x" startingAtIndex:0];
    if (parse([@"Package: apt\nVersion: " stringByAppendingString:longValue]) != nil) return 6;
    if (![parse(@"Package: dpkg\n")[@"dpkg"] isEqualToString:@"version=missing; status=missing"]) return 7;
    if (parse(@"Package: unrelated\nDescription: private\n").count != 0) return 8;
    return 0;
} }
'''.replace('PARSER', PARSER)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / 'parser.m'
            binary = Path(directory) / 'parser'
            source.write_text(harness, encoding='utf-8')
            subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-framework', 'Foundation',
                            str(source), '-o', str(binary)], check=True, capture_output=True)
            subprocess.run([str(binary)], check=True, capture_output=True)


if __name__ == '__main__':
    unittest.main()
