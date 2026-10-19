#import <Foundation/Foundation.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>

static NSString *const RH3LatestDiagnosticName = @".RootHide3-latest-attempt";
static const size_t RH3DiagnosticLimit = 128 * 1024;

static int RH3AppendDiagnostic(int fd, NSData *data)
{
    struct stat st;
    if (fstat(fd, &st)) return errno;
    if (!S_ISREG(st.st_mode) || st.st_nlink != 1) return EINVAL;
    if (st.st_size < 0 || (uint64_t)st.st_size + data.length > RH3DiagnosticLimit) return EFBIG;
    size_t used = 0;
    while (used < data.length) {
        ssize_t count = write(fd, (const char *)data.bytes + used, data.length - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return count < 0 ? errno : EIO;
        used += (size_t)count;
    }
    return fsync(fd) == 0 ? 0 : errno;
}

// Open while still in the original sandbox. Every later checkpoint uses fd,
// not a path that privilege changes or path-redirection hooks can reinterpret.
static int RH3StartDiagnostic(NSString *directory, NSData *header, NSString **pathOut)
{
    int parent = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return -1;
    struct stat owner;
    if (fstat(parent, &owner)) { int e = errno; close(parent); errno = e; return -1; }
    NSString *name = [NSString stringWithFormat:@"RootHide3-attempt-%@.log", NSUUID.UUID.UUIDString];
    int fd = openat(parent, name.UTF8String, O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    int failure = fd < 0 ? errno : 0;
    // TrollStore may start as root. Make the export readable by the original
    // container owner after a later unprivileged launch as well.
    if (!failure && geteuid() == 0 && fchown(fd, owner.st_uid, owner.st_gid)) failure = errno;
    if (!failure && fchmod(fd, 0600)) failure = errno;
    if (!failure) failure = RH3AppendDiagnostic(fd, header);
    NSString *temporary = [@".RootHide3-pointer-" stringByAppendingString:NSUUID.UUID.UUIDString];
    int pointer = -1;
    if (!failure) {
        struct stat previous;
        int result = fstatat(parent, RH3LatestDiagnosticName.UTF8String, &previous, AT_SYMLINK_NOFOLLOW);
        if (result == 0 && (!S_ISREG(previous.st_mode) || previous.st_nlink != 1 || previous.st_uid != owner.st_uid)) failure = EINVAL;
        else if (result != 0 && errno != ENOENT) failure = errno;
    }
    if (!failure) {
        pointer = openat(parent, temporary.UTF8String, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (pointer < 0) failure = errno;
    }
    if (!failure && geteuid() == 0 && fchown(pointer, owner.st_uid, owner.st_gid)) failure = errno;
    if (!failure && fchmod(pointer, 0600)) failure = errno;
    if (!failure) failure = RH3AppendDiagnostic(pointer, [name dataUsingEncoding:NSUTF8StringEncoding]);
    if (pointer >= 0) close(pointer);
    if (!failure && renameat(parent, temporary.UTF8String, parent, RH3LatestDiagnosticName.UTF8String)) failure = errno;
    if (!failure && fsync(parent)) failure = errno;
    close(parent);
    if (failure) {
        if (fd >= 0) close(fd);
        errno = failure;
        return -1; // No exploit may begin after an unsuccessful log start.
    }
    if (pathOut) *pathOut = [directory stringByAppendingPathComponent:name];
    return fd;
}

// A missing/damaged current target must never silently fall back to an older
// attempt. The legacy name is considered only before this version's first log.
static NSURL *RH3LatestDiagnosticURL(NSString *directory)
{
    int parent = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return nil;
    NSString *name = nil;
    int pointer = openat(parent, RH3LatestDiagnosticName.UTF8String, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int pointerError = errno;
    if (pointer >= 0) {
        struct stat st;
        char bytes[256];
        if (!fstat(pointer, &st) && S_ISREG(st.st_mode) && st.st_nlink == 1 && st.st_size > 0 && st.st_size < sizeof(bytes)) {
            ssize_t length = read(pointer, bytes, sizeof(bytes));
            if (length == st.st_size) name = [[NSString alloc] initWithBytes:bytes length:(NSUInteger)length encoding:NSUTF8StringEncoding];
        }
        close(pointer);
        if (![name hasPrefix:@"RootHide3-attempt-"] || ![name hasSuffix:@".log"] || ![name.lastPathComponent isEqual:name]) name = nil;
    } else if (pointerError == ENOENT) {
        name = @"RootHide3-last-attempt.log";
    }
    int fd = name ? openat(parent, name.UTF8String, O_RDONLY | O_NOFOLLOW | O_CLOEXEC) : -1;
    struct stat st;
    BOOL readable = fd >= 0 && !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_nlink == 1 && st.st_size > 0;
    if (fd >= 0) close(fd);
    close(parent);
    return readable ? [NSURL fileURLWithPath:[directory stringByAppendingPathComponent:name]] : nil;
}

// Reattach before privilege changes on the next app launch. Action diagnostics
// then append to the same attempt that contains the userspace boot checkpoints.
static int RH3OpenLatestDiagnostic(NSString *directory)
{
    NSURL *latest = RH3LatestDiagnosticURL(directory);
    if (!latest) return -1;
    int parent = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) return -1;
    struct stat owner, file;
    int fd = openat(parent, latest.lastPathComponent.fileSystemRepresentation, O_WRONLY | O_APPEND | O_NOFOLLOW | O_CLOEXEC);
    BOOL valid = fd >= 0 && !fstat(parent, &owner) && !fstat(fd, &file) &&
        S_ISREG(file.st_mode) && file.st_nlink == 1 && file.st_uid == owner.st_uid &&
        (file.st_mode & 0777) == 0600 && file.st_size > 0 && file.st_size < RH3DiagnosticLimit;
    close(parent);
    if (!valid && fd >= 0) close(fd);
    return valid ? fd : -1;
}
