from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / 'Application/Dopamine/Jailbreak/RootHideForensics.h'


class ForensicsContract(unittest.TestCase):
    def test_collection_is_connected_to_interrupted_snapshot(self):
        source = (HEADER.parent / 'DOBootstrapper.m').read_text(encoding='utf-8')
        self.assertIn('RH3CollectForensics(root, ^(NSString *line)', source)
        header = HEADER.read_text(encoding='utf-8')
        for token in ('posix_spawn(', 'exec_cmd(', 'unlink(', 'rename(', 'O_WRONLY', 'O_CREAT',
                      'master.passwd', 'pwd.db', 'spwd.db'):
            self.assertNotIn(token, header)

    @unittest.skipUnless(sys.platform == 'darwin', 'Foundation runtime requires macOS')
    def test_real_report_filtering_and_filesystem_boundaries(self):
        source = r'''
#import "RootHideForensics.h"
int main(void) { @autoreleasepool {
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *directory = [[NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString] stringByResolvingSymlinksInPath];
    [fm createDirectoryAtPath:directory withIntermediateDirectories:YES attributes:nil error:nil];
    NSString *report = @"{\"timestamp\":\"2026-10-19 08:34:28.000 +0200\"}\n{\"procName\":\"dash\",\"pid\":416,\"termination\":{\"namespace\":\"CODESIGNING\",\"code\":2},\"crashReporterKey\":\"SECRET\"}";
    NSString *path = [directory stringByAppendingPathComponent:@"dash-test.ips"];
    [report writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
    NSMutableArray *lines = [NSMutableArray array];
    NSDate *anchor = RH3ForensicDate(@"2026-10-19 08:34:28 +0200");
    if (!anchor) return 1;
    RH3ForensicReports(directory, anchor, ^(NSString *line) { [lines addObject:line]; });
    NSString *output = [lines componentsJoinedByString:@"\n"];
    if (![output containsString:@"namespace=CODESIGNING"] || [output containsString:@"SECRET"]) {
        struct stat st = {0}; lstat(path.fileSystemRepresentation, &st);
        fprintf(stderr, "uid=%u owner=%u directory=%s anchor=%s\n%s\n", getuid(), st.st_uid,
            directory.UTF8String, anchor.description.UTF8String, output.UTF8String);
        return 2;
    }
    [lines removeAllObjects];
    RH3ForensicReports(directory, [anchor dateByAddingTimeInterval:3600], ^(NSString *line) { [lines addObject:line]; });
    if ([[lines componentsJoinedByString:@"\n"] containsString:@"namespace=CODESIGNING"]) return 3;
    NSString *link = [directory stringByAppendingPathComponent:@"dash-link.ips"];
    symlink(path.fileSystemRepresentation, link.fileSystemRepresentation);
    int fd = RH3ForensicOpen(link, NO);
    if (fd >= 0) { close(fd); return 4; }
    fd = RH3ForensicOpen(path, NO);
    if (RH3ForensicRead(fd, 10)) { close(fd); return 5; }
    close(fd);
    if (![[NSString stringWithContentsOfFile:path encoding:NSUTF8StringEncoding error:nil] isEqualToString:report]) return 6;
    if (RH3ForensicFilename(@"unrelated-test.ips") || RH3ForensicFilename(@"dashmalware-test.ips")) return 7;
    [fm removeItemAtPath:directory error:nil];
    return 0;
} }
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'forensics.m'
            binary = Path(directory) / 'forensics'
            path.write_text(source, encoding='utf-8')
            result = subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-fblocks', '-framework',
                                     'Foundation', '-I', str(HEADER.parent), str(path), '-o', str(binary)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
