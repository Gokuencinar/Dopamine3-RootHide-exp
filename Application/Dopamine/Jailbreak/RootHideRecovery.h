// Preserve a failed legacy bootstrap before creating a different, fresh root.
// The journal is immutable. A crash between renames can only resume preservation.
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static NSString *const RH3RecoveryJournalName = @".roothide3-recovery.plist";

static NSError *RH3RecoveryFailure(NSString *message)
{
    return [NSError errorWithDomain:@"RootHideRecovery" code:1
                          userInfo:@{NSLocalizedDescriptionKey:message}];
}

static NSData *RH3RecoveryReadFile(NSString *path, NSUInteger limit, uid_t owner)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat a = {0}, b = {0};
    if (fd < 0) return nil;
    if (fstat(fd, &a) || !S_ISREG(a.st_mode) || a.st_uid != owner || a.st_nlink != 1 ||
        a.st_size <= 0 || (uint64_t)a.st_size > limit) { close(fd); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)a.st_size];
    size_t used = 0;
    while (used < data.length) {
        ssize_t n = read(fd, (char *)data.mutableBytes + used, data.length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        used += (size_t)n;
    }
    BOOL stable = !fstat(fd, &b) && used == data.length && a.st_size == b.st_size &&
        a.st_ino == b.st_ino && a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec &&
        a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
        a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
    close(fd);
    return stable ? data : nil;
}

static BOOL RH3RecoveryValidName(NSString *name)
{
    if (![name isKindOfClass:NSString.class] || name.length != 24 || ![name hasPrefix:@".jbroot-"]) return NO;
    const char *hex = name.UTF8String + 8;
    for (int i = 0; i < 16; i++) if (!strchr("0123456789ABCDEF", hex[i])) return NO;
    uint64_t value = strtoull(hex, NULL, 16);
    uint8_t check = (uint8_t)(value >> 8 ^ value >> 16 ^ value >> 24 ^ value >> 32 ^ value >> 40 ^ value >> 48 ^ value >> 56);
    return value && check == (uint8_t)value;
}

static NSString *RH3RecoveryBackupName(NSString *name)
{
    return [@".roothide3-backup-" stringByAppendingString:[name substringFromIndex:8]];
}

// Returns nil without an error when no recovery has ever been started.
// Paths are derived from a checked brand; paths from a plist are never used.
static NSDictionary *RH3RecoveryInspect(NSString *primary, NSString *secondary, uid_t owner, NSError **error)
{
    NSString *journalPath = [primary stringByAppendingPathComponent:RH3RecoveryJournalName];
    struct stat journalStat;
    if (lstat(journalPath.fileSystemRepresentation, &journalStat)) {
        if (errno != ENOENT && error) *error = RH3RecoveryFailure(@"Cannot inspect RootHide recovery journal");
        return nil;
    }
    NSData *bytes = RH3RecoveryReadFile(journalPath, 4096, owner);
    NSDictionary *record = bytes ? [NSPropertyListSerialization propertyListWithData:bytes options:NSPropertyListImmutable format:NULL error:nil] : nil;
    if (![record isKindOfClass:NSDictionary.class] || ![record[@"Schema"] isEqual:@1] ||
        !RH3RecoveryValidName(record[@"Name"]) || (journalStat.st_mode & 0777) != 0600) {
        if (error) *error = RH3RecoveryFailure(@"Damaged RootHide recovery journal; all containers were preserved");
        return nil;
    }
    NSString *name = record[@"Name"], *backup = RH3RecoveryBackupName(name);
    NSMutableArray *locations = [NSMutableArray array];
    BOOL complete = YES;
    NSArray *bases = @[primary, secondary];
    for (NSUInteger i = 0; i < bases.count; i++) {
        int parent = open([bases[i] fileSystemRepresentation], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct stat original = {0}, saved = {0};
        int os = parent < 0 ? -1 : fstatat(parent, name.UTF8String, &original, AT_SYMLINK_NOFOLLOW);
        int oe = errno;
        int ss = parent < 0 ? -1 : fstatat(parent, backup.UTF8String, &saved, AT_SYMLINK_NOFOLLOW);
        int se = errno;
        if (parent >= 0) close(parent);
        NSArray *identity = record[i == 0 ? @"PrimaryIdentity" : @"SecondaryIdentity"];
        struct stat st = os == 0 ? original : saved;
        if (parent < 0 || ![identity isKindOfClass:NSArray.class] || identity.count != 2 ||
            ![identity[0] isKindOfClass:NSNumber.class] || ![identity[1] isKindOfClass:NSNumber.class] ||
            (os == 0) == (ss == 0) || (os != 0 && oe != ENOENT) || (ss != 0 && se != ENOENT) ||
            !S_ISDIR(st.st_mode) || st.st_uid != owner ||
            (uint64_t)st.st_dev != [identity[0] unsignedLongLongValue] ||
            (uint64_t)st.st_ino != [identity[1] unsignedLongLongValue]) {
            if (error) *error = RH3RecoveryFailure(@"RootHide recovery paths or identities changed; refusing to move data");
            return nil;
        }
        if (os == 0) complete = NO;
        [locations addObject:[bases[i] stringByAppendingPathComponent:os == 0 ? name : backup]];
    }
    return @{@"Name":name, @"Locations":locations, @"Complete":@(complete)};
}

#ifndef RH3_RECOVERY_RENAME
#define RH3_RECOVERY_RENAME(a,b,c,d) renameatx_np(a,b,c,d,RENAME_EXCL)
#endif

static BOOL RH3RecoveryPreserve(NSString *primary, NSString *secondary, NSString *name,
                                uid_t owner, NSError **error)
{
    if (!RH3RecoveryValidName(name)) {
        if (error) *error = RH3RecoveryFailure(@"Invalid RootHide recovery brand");
        return NO;
    }
    NSError *inspectError = nil;
    NSDictionary *existing = RH3RecoveryInspect(primary, secondary, owner, &inspectError);
    if (inspectError) { if (error) *error = inspectError; return NO; }
    if (existing && ![existing[@"Name"] isEqual:name]) {
        if (error) *error = RH3RecoveryFailure(@"One legacy bootstrap has already been preserved; another automatic recovery is disabled");
        return NO;
    }
    NSArray *bases = @[primary, secondary];
    if (!existing) {
        NSMutableDictionary *record = [@{@"Schema":@1, @"Name":name} mutableCopy];
        for (NSUInteger i = 0; i < bases.count; i++) {
            struct stat st;
            NSString *path = [bases[i] stringByAppendingPathComponent:name];
            if (lstat(path.fileSystemRepresentation, &st) || !S_ISDIR(st.st_mode) || st.st_uid != owner) {
                if (error) *error = RH3RecoveryFailure(@"Cannot verify owned RootHide containers before preservation");
                return NO;
            }
            record[i == 0 ? @"PrimaryIdentity" : @"SecondaryIdentity"] = @[@((uint64_t)st.st_dev), @((uint64_t)st.st_ino)];
        }
        NSData *bytes = [NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
        NSString *journalPath = [primary stringByAppendingPathComponent:RH3RecoveryJournalName];
        int fd = bytes ? open(journalPath.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
        if (fd < 0) { if (error) *error = RH3RecoveryFailure(@"Cannot create exclusive RootHide recovery journal"); return NO; }
        size_t used = 0;
        while (used < bytes.length) {
            ssize_t n = write(fd, (const char *)bytes.bytes + used, bytes.length - used);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            used += (size_t)n;
        }
        BOOL saved = used == bytes.length && fsync(fd) == 0;
        close(fd);
        if (!saved) { if (error) *error = RH3RecoveryFailure(@"Recovery journal write failed; no container was moved"); return NO; }
    }
    // Revalidate both recorded inodes before every rename, including after a crash.
    for (NSUInteger i = 0; i < bases.count; i++) {
        NSDictionary *state = RH3RecoveryInspect(primary, secondary, owner, error);
        if (!state) return NO;
        NSString *location = state[@"Locations"][i];
        if (![location.lastPathComponent isEqual:name]) continue;
        int parent = open([bases[i] fileSystemRepresentation], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        NSString *backup = RH3RecoveryBackupName(name);
        // Persist the journal directory entry before either rename.
        int journalParent = open(primary.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        BOOL durable = journalParent >= 0 && fsync(journalParent) == 0;
        if (journalParent >= 0) close(journalParent);
        int result = parent >= 0 && durable ? RH3_RECOVERY_RENAME(parent, name.UTF8String, parent, backup.UTF8String) : -1;
        BOOL synced = result == 0 && fsync(parent) == 0;
        if (parent >= 0) close(parent);
        if (!synced) { if (error) *error = RH3RecoveryFailure(@"RootHide preservation interrupted; journal and containers retained for resumption"); return NO; }
    }
    NSDictionary *state = RH3RecoveryInspect(primary, secondary, owner, error);
    return state && [state[@"Complete"] boolValue];
}
