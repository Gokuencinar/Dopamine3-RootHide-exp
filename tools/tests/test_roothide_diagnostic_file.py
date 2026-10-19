"""Native filesystem checks for the same logger compiled into the app."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(sys.platform == 'darwin', 'Foundation filesystem runtime requires macOS')
class DiagnosticFile(unittest.TestCase):
    def test_fd_survives_path_change_and_latest_selection_survives_reopen(self):
        source = r'''
#import <Foundation/Foundation.h>
#include "RH3DiagnosticFile.h"
int main(void) { @autoreleasepool {
    char template[] = "/tmp/rh3-log-XXXXXX";
    char *base = mkdtemp(template); if (!base) return 1;
    NSString *top = @(base), *directory = [top stringByAppendingPathComponent:@"Documents"];
    NSFileManager *fm = NSFileManager.defaultManager;
    [fm createDirectoryAtPath:directory withIntermediateDirectories:NO attributes:nil error:nil];
    NSString *legacy = [directory stringByAppendingPathComponent:@"RootHide3-last-attempt.log"];
    [@"old attempt" writeToFile:legacy atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (![RH3LatestDiagnosticURL(directory).path isEqual:legacy]) return 2;
    NSString *first = nil, *second = nil;
    int a = RH3StartDiagnostic(directory, [@"first\n" dataUsingEncoding:NSUTF8StringEncoding], &first);
    int b = RH3StartDiagnostic(directory, [@"second\n" dataUsingEncoding:NSUTF8StringEncoding], &second);
    if (a < 0 || b < 0 || [first isEqual:second]) return 3;
    if (![RH3LatestDiagnosticURL(directory).path isEqual:second]) return 4;
    if (RH3AppendDiagnostic(a, [@"late old write\n" dataUsingEncoding:NSUTF8StringEncoding])) return 5;
    if (![RH3LatestDiagnosticURL(directory).path isEqual:second]) return 6;
    NSString *moved = [top stringByAppendingPathComponent:@"MovedDocuments"];
    [fm moveItemAtPath:directory toPath:moved error:nil];
    [fm createDirectoryAtPath:directory withIntermediateDirectories:NO attributes:nil error:nil];
    if (RH3AppendDiagnostic(b, [@"checkpoint after path change\n" dataUsingEncoding:NSUTF8StringEncoding])) return 7;
    close(a); close(b);
    NSURL *latest = RH3LatestDiagnosticURL(moved);
    NSString *text = [NSString stringWithContentsOfURL:latest encoding:NSUTF8StringEncoding error:nil];
    if (![text isEqual:@"second\ncheckpoint after path change\n"]) return 8;
    if (![[NSString stringWithContentsOfFile:[moved stringByAppendingPathComponent:legacy.lastPathComponent] encoding:NSUTF8StringEncoding error:nil] isEqual:@"old attempt"]) return 9;
    int reopened = RH3OpenLatestDiagnostic(moved);
    if (reopened < 0 || RH3AppendDiagnostic(reopened, [@"action after relaunch\n" dataUsingEncoding:NSUTF8StringEncoding])) return 17;
    close(reopened);
    if (![[NSString stringWithContentsOfURL:latest encoding:NSUTF8StringEncoding error:nil] hasSuffix:@"action after relaunch\n"]) return 18;
    chmod(latest.path.fileSystemRepresentation,0644);
    if (RH3OpenLatestDiagnostic(moved) >= 0) return 19;
    chmod(latest.path.fileSystemRepresentation,0600);
    NSString *linked = [moved stringByAppendingPathComponent:@"linked"];
    link(latest.path.fileSystemRepresentation,linked.fileSystemRepresentation);
    if (RH3OpenLatestDiagnostic(moved) >= 0) return 20;
    unlink(linked.fileSystemRepresentation);
    // A missing current file must not select the old legacy log.
    [fm removeItemAtURL:latest error:nil];
    if (RH3LatestDiagnosticURL(moved)) return 10;
    // A pointer naming another directory is rejected.
    [@"../RootHide3-attempt-escape.log" writeToFile:[moved stringByAppendingPathComponent:RH3LatestDiagnosticName] atomically:YES encoding:NSUTF8StringEncoding error:nil];
    if (RH3LatestDiagnosticURL(moved)) return 11;
    // A symlinked pointer may neither be exported nor overwritten by start.
    [fm removeItemAtPath:[moved stringByAppendingPathComponent:RH3LatestDiagnosticName] error:nil];
    symlink("missing", [moved stringByAppendingPathComponent:RH3LatestDiagnosticName].fileSystemRepresentation);
    if (RH3LatestDiagnosticURL(moved)) return 12;
    int bad = RH3StartDiagnostic(moved, [@"blocked" dataUsingEncoding:NSUTF8StringEncoding], NULL);
    if (bad >= 0) { close(bad); return 13; }
    // Bounded writes fail before changing the file; invalid descriptors fail.
    NSString *cap = [directory stringByAppendingPathComponent:@"cap"];
    int fd = open(cap.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL,0600);
    if (fd < 0 || ftruncate(fd,RH3DiagnosticLimit)) return 14;
    if (RH3AppendDiagnostic(fd, [@"x" dataUsingEncoding:NSUTF8StringEncoding]) != EFBIG) return 15;
    struct stat st; fstat(fd,&st); close(fd);
    if (st.st_size != RH3DiagnosticLimit || RH3AppendDiagnostic(-1,[NSData data]) != EBADF) return 16;
    [fm removeItemAtPath:top error:nil];
    return 0;
} }
'''
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'log.m'
            binary = Path(directory) / 'log'
            path.write_text(source, encoding='utf-8')
            result = subprocess.run(['xcrun', 'clang', '-fobjc-arc', '-framework', 'Foundation', '-I',
                str(ROOT / 'Application/Dopamine/UI'), str(path), '-o', str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
