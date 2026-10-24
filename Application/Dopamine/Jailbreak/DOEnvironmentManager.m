//
//  EnvironmentManager.m
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import "DOEnvironmentManager.h"
#import "UIImage+JPEG2000.h"

#import <sys/sysctl.h>
#import <sys/mount.h>
#import <sys/utsname.h>
#import <sys/stat.h>
#import <sys/xattr.h>
#import <sys/acl.h>
#import <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <time.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach-o/fat.h>
#import <libgrabkernel2/libgrabkernel2.h>
#import <libjailbreak/info.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/util.h>
#import <libjailbreak/display.h>
#import <libjailbreak/machine_info.h>
#import <libjailbreak/carboncopy.h>
#import <libjailbreak/roothider/common.h>
#import <libjailbreak/jbserver_domains.h>

#import <IOKit/IOKitLib.h>
#import "DOUIManager.h"
#import "DOExploitManager.h"
#import "DOPreferenceManager.h"
#import "RootHideAppRegistration.h"
#import "RootHideScriptWait.h"
#import "RH3TweakToggle.h"
#import "RH3ProbeSpawnEnv.h"
#import <CoreServices/LSApplicationProxy.h>
#import <libjailbreak/roothider.h>
#import "NSData+Hex.h"
#import <CommonCrypto/CommonDigest.h>
#import <LocalAuthentication/LocalAuthentication.h>

#ifndef ROOTHIDE3_SSH_DEFAULT_PREPARE
#define ROOTHIDE3_SSH_DEFAULT_PREPARE 0
#endif

int reboot3(uint64_t flags, ...);
CFPropertyListRef MGCopyAnswer(CFStringRef);
extern char **environ;

static BOOL DOUsesLegacyJbctl(NSString *version)
{
    return version && [version compare:@"3.0.5" options:NSNumericSearch] == NSOrderedAscending;
}

static void RH3LogCommandSpawnStage(const char *stage, pid_t pid, int result, void *context)
{
    // Only log the static stage and the PID/error. No package arguments,
    // environment variables, subscription IDs or private app paths.
    NSString *name = (__bridge NSString *)context;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"RootHide command %@: %s pid=%d result=%d",
         name, stage, pid, result]];
}

// launchctl print is a diagnostic format, not a stable API. Extract only
// tightly bounded scalar values from a single service; NEVER log raw output,
// paths, environment, sockets, usernames or configuration contents.
static NSString *RH3SSHPrintScalar(NSString *text, NSString *field, BOOL numeric)
{
    NSString *prefix = [field stringByAppendingString:@" = "];
    for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (![trimmed hasPrefix:prefix]) continue;
        NSString *value = [[trimmed substringFromIndex:prefix.length]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (!value.length || value.length > 32) return @"unknown";
        if (numeric) {
            NSString *digits = [value hasPrefix:@"-"] ? [value substringFromIndex:1] : value;
            if (digits.length && [digits rangeOfCharacterFromSet:
                  [NSCharacterSet.decimalDigitCharacterSet invertedSet]].location == NSNotFound)
                return value;
            return @"unknown";
        }
        NSString *lower = value.lowercaseString;
        for (NSString *allowed in @[@"waiting", @"running", @"stopped", @"inactive",
                                     @"active", @"spawn scheduled", @"not running"]) {
            if ([lower isEqualToString:allowed]) return [allowed stringByReplacingOccurrencesOfString:@" " withString:@"_"];
        }
        return @"other";
    }
    return @"unknown";
}

// Classify a *single* launchctl path without ever writing its contents to a
// diagnostic log. /private/var and /var aliases are normalized in the same
// way as the already-verified hidden root used for preflight.
static NSString *RH3SSHPrintPathClass(NSString *text, NSString *field,
                                    NSString *root, NSString *expectedSuffix)
{
    NSString *prefix = [field stringByAppendingString:@" = "];
    for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (![trimmed hasPrefix:prefix]) continue;
        NSString *value = [[trimmed substringFromIndex:prefix.length]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (!value.length || value.length > 4096) return @"invalid";
        if (![value hasPrefix:@"/"]) return @"non_absolute";
        NSString *actual = RH3CanonicalAppPath(value);
        NSString *active = RH3CanonicalAppPath(root);
        NSString *expected = RH3CanonicalAppPath([root stringByAppendingPathComponent:expectedSuffix]);
        if ([actual isEqualToString:expected]) return @"expected";
        if ([actual hasPrefix:[active stringByAppendingString:@"/"]]) return @"active_other";
        if ([actual isEqualToString:@"/usr/sbin/sshd"] ||
            [actual isEqualToString:@"/usr/libexec/sshd-keygen-wrapper"])
            return @"stock_ssh";
        if ([actual hasPrefix:@"/var/jb/"]) return @"var_jb_alias";
        return @"other_absolute";
    }
    return @"missing";
}

// Return a path only to the caller, never to the diagnostic log. Use this to
// compare launchd's live Program with the root-owned OpenSSH plist, without
// exporting either path. A missing/malformed path stays indeterminate.
static NSString *RH3SSHPrintPrivatePath(NSString *text, NSString *field)
{
    NSString *prefix = [field stringByAppendingString:@" = "];
    NSString *found = nil;
    for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (![trimmed hasPrefix:prefix]) continue;
        if (found) return nil; // Refuse ambiguous nested/multiple program fields.
        NSString *value = [[trimmed substringFromIndex:prefix.length]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        if (!value.length || value.length > 4096 || ![value hasPrefix:@"/"]) return nil;
        found = value;
    }
    return found;
}

// launchctl's persistent disabled overrides are independent of the Disabled
// key in a launchd plist. Match just one exact service label, never log the
// complete domain (which contains names of unrelated installed services).
static NSString *RH3SSHParseDisabledOverride(NSString *text)
{
    NSString *found = nil;
    for (NSString *line in [text componentsSeparatedByCharactersInSet:NSCharacterSet.newlineCharacterSet]) {
        NSString *trimmed = [line stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet];
        NSString *prefix = @"\"com.openssh.sshd\" => ";
        if (![trimmed hasPrefix:prefix]) continue;
        if (found) return @"unknown"; // Ambiguous duplicate.
        NSString *value = [[trimmed substringFromIndex:prefix.length]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceCharacterSet].lowercaseString;
        if ([value isEqualToString:@"disabled"] || [value isEqualToString:@"true"])
            found = @"disabled";
        else if ([value isEqualToString:@"enabled"] || [value isEqualToString:@"false"])
            found = @"enabled";
        else return @"unknown";
    }
    return found ?: @"no_override";
}

// Deliberately operate on one verified, root-owned Procursus job. Changing a
// persistent plist is opt-in; the existing RootHide PID 1 hooks are untouched.
// The private backup never has a .plist suffix, so it cannot be imported as a
// second launchd job. No private path or file contents are written to logs.
static int RH3SSHWriteAll(int fd, NSData *data)
{
    const uint8_t *bytes = data.bytes;
    NSUInteger offset = 0;
    while (offset < data.length) {
        ssize_t written = write(fd, bytes + offset, data.length - offset);
        if (written > 0) offset += (NSUInteger)written;
        else if (written < 0 && errno == EINTR) continue;
        else return written == 0 ? EIO : errno;
    }
    return fsync(fd) ? errno : 0;
}

static NSData *RH3SSHReadBounded(int fd, off_t length)
{
    if (length < 32 || length > 65536) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)length];
    uint8_t *bytes = data.mutableBytes;
    NSUInteger offset = 0;
    while (offset < (NSUInteger)length) {
        ssize_t amount = pread(fd, bytes + offset, (NSUInteger)length - offset, (off_t)offset);
        if (amount > 0) offset += (NSUInteger)amount;
        else if (amount < 0 && errno == EINTR) continue;
        else return nil;
    }
    return data;
}

// Read-only dpkg receipt probe. A binary or a launchd plist existing on disk
// does not establish that dpkg completed all three SSH packages. Do not try
// to repair a partial transaction here, and never log receipt contents.
// Bits: client=1, sftp=2, server=4. Every package must be fully installed.
static int RH3SSHReadInstalledReceiptMask(NSString *root, NSUInteger *mask)
{
    if (!root || !mask) return EINVAL;
    *mask = 0;
    NSString *status = [root stringByAppendingPathComponent:@"Library/dpkg/status"];
    int fd = open(status.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    struct stat st = {0};
    int error = fstat(fd, &st) ? errno : 0;
    if (!error && (!S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_nlink != 1 ||
                   (st.st_mode & 022) || st.st_size < 128 || st.st_size > 512 * 1024))
        error = EPERM;
    NSMutableData *bytes = error ? nil : [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    if (!error && !bytes) error = ENOMEM;
    NSUInteger offset = 0;
    while (!error && offset < bytes.length) {
        ssize_t amount = pread(fd, (uint8_t *)bytes.mutableBytes + offset,
                               bytes.length - offset, (off_t)offset);
        if (amount > 0) offset += (NSUInteger)amount;
        else if (amount < 0 && errno == EINTR) continue;
        else error = amount == 0 ? EIO : errno;
    }
    close(fd);
    if (error) return error;
    NSString *text = [[NSString alloc] initWithData:bytes encoding:NSUTF8StringEncoding];
    if (!text) return EILSEQ;
    NSArray<NSString *> *packages = @[@"openssh-client", @"openssh-sftp-server", @"openssh-server"];
    for (NSString *record in [text componentsSeparatedByString:@"\n\n"]) {
        for (NSUInteger i = 0; i < packages.count; i++) {
            if ([record hasPrefix:[NSString stringWithFormat:@"Package: %@\n", packages[i]]] &&
                [record containsString:@"\nStatus: install ok installed"])
                *mask |= (NSUInteger)1 << i;
        }
    }
    return 0;
}

// jbclient_get_jbroot() uses dispatch_once and can retain the OLD brand if
// called before a RootHide re-randomization. Ask the existing read-only
// systemwide server action afresh for this specific SSH write transaction.
// No new XPC capability or process privilege is introduced.
static NSString *RH3SSHCurrentServerRoot(void)
{
    xpc_object_t reply = jbserver_xpc_send(JBS_DOMAIN_SYSTEMWIDE,
                                           JBS_SYSTEMWIDE_GET_JBROOT, NULL);
    if (!reply) return nil;
    if (xpc_get_type(reply) != XPC_TYPE_DICTIONARY) {
        // In this Objective-C ARC translation unit xpc_object_t is an
        // Objective-C OS object: the compiler manages its lifetime.
        return nil;
    }
    const char *path = xpc_dictionary_get_string(reply, "root-path");
    NSString *root = path ? [NSString stringWithUTF8String:path] : nil;
    return root;
}

// In the initial exploit phase gSystemInfo has already been updated AFTER
// re-randomization (DOBootstrapper.m), and the parent is platform+installer.
// Avoid waiting on PID 1's synchronous XPC server during an optional boot
// preparation. After the jailbreak, query the server fresh instead of using
// jbclient_get_jbroot()'s stale dispatch_once cache.
static NSString *RH3SSHRootForPhase(BOOL installerPhase)
{
    if (!installerPhase) return RH3SSHCurrentServerRoot();
    const char *root = gSystemInfo.jailbreakInfo.rootPath;
    return root ? [NSString stringWithUTF8String:root] : nil;
}

static void RH3SSHCountSocketPorts(id entry, NSUInteger *port22, NSUInteger *port2222);
static BOOL RH3SSHValidateSingleSocket(id entry, NSUInteger *port22, NSUInteger *port2222);

static int RH3SSHRebaseInstalledPlist(NSString *plistPath, NSString *sshd,
                                     NSString *config, NSString *key, BOOL *changed,
                                     const char **stageOut)
{
    if (changed) *changed = NO;
    if (stageOut) *stageOut = "name";
    if (![plistPath.lastPathComponent isEqualToString:@"com.openssh.sshd.plist"])
        return ENOTSUP;
    NSString *launchDirectory = plistPath.stringByDeletingLastPathComponent;
    NSString *libraryDirectory = launchDirectory.stringByDeletingLastPathComponent;
    if (![launchDirectory.lastPathComponent isEqualToString:@"LaunchDaemons"] ||
        ![libraryDirectory.lastPathComponent isEqualToString:@"Library"])
        return ENOTSUP;
    const char *jobName = "com.openssh.sshd.plist";
    const char *backupName = ".com.openssh.sshd.rh3-original";
    // An unexpected interruption must not permanently poison the next run
    // via a fixed O_EXCL temporary name. Use a unique, non-.plist path for
    // this transaction; never reclaim another attempt's unknown temp inode.
    char nextName[80] = {0};
    int nextLen = snprintf(nextName, sizeof(nextName),
                           ".com.openssh.sshd.rh3-next-%08x%08x",
                           arc4random(), arc4random());
    if (nextLen <= 0 || (size_t)nextLen >= sizeof(nextName)) return EOVERFLOW;
    char backupTempName[88] = {0};
    int backupLen = snprintf(backupTempName, sizeof(backupTempName),
                             ".com.openssh.sshd.rh3-original-next-%08x%08x",
                             arc4random(), arc4random());
    if (backupLen <= 0 || (size_t)backupLen >= sizeof(backupTempName)) return EOVERFLOW;
    const char *rollbackName = ".com.openssh.sshd.rh3-rollback";
    // O_NOFOLLOW on LaunchDaemons alone does not protect its Library parent.
    // Pin both directories so that an intermediate symlink cannot redirect an
    // opt-in write to another (even root-owned) service directory.
    if (stageOut) *stageOut = "open_library";
    int libraryFD = open(libraryDirectory.fileSystemRepresentation,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (libraryFD < 0) return errno;
    if (stageOut) *stageOut = "library_stat";
    struct stat libraryInfo = {0};
    int libraryError = fstat(libraryFD, &libraryInfo) ? errno : 0;
    BOOL trustedLibrary = libraryInfo.st_gid == 0 &&
        (libraryInfo.st_mode & 0777) == 0775;
    if (!libraryError && (!S_ISDIR(libraryInfo.st_mode) || libraryInfo.st_uid != 0 ||
        (libraryInfo.st_mode & S_IWOTH) ||
        ((libraryInfo.st_mode & S_IWGRP) && !trustedLibrary)))
        libraryError = EPERM;
    if (libraryError) {
        close(libraryFD);
        return libraryError;
    }
    if (stageOut) *stageOut = "open_directory";
    int dir = openat(libraryFD, "LaunchDaemons",
                     O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int directoryError = dir < 0 ? errno : 0;
    close(libraryFD);
    if (directoryError) return directoryError;
    int result = 0;
    const char *stage = "directory_stat";
    int original = -1, backup = -1, next = -1, replacementRead = -1;
    BOOL madeBackupTemp = NO, madeNext = NO, madeRollback = NO, renamedJob = NO;
    struct stat directory = {0}, before = {0}, current = {0}, replacement = {0};
    NSData *originalData = nil, *nextData = nil;
    do {
        if (fstat(dir, &directory)) { result = errno; break; }
        stage = "directory_type";
        if (!S_ISDIR(directory.st_mode)) { result = EPERM; break; }
        stage = "directory_owner";
        if (directory.st_uid != 0) { result = EPERM; break; }
        stage = "directory_permissions";
        if (directory.st_mode & 022) { result = EPERM; break; }
        stage = "open_original";
        original = openat(dir, jobName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (original < 0) { result = errno; break; }
        stage = "original_stat";
        if (fstat(original, &before)) { result = errno; break; }
        stage = "original_type";
        if (!S_ISREG(before.st_mode)) { result = EPERM; break; }
        stage = "original_owner";
        if (before.st_uid != 0) { result = EPERM; break; }
        stage = "original_group";
        if (before.st_gid != 0) { result = EPERM; break; }
        stage = "original_permissions";
        if ((before.st_mode & 022) || (before.st_mode & 07000)) {
            result = EPERM; break;
        }
        // An interrupted prior run may have left our exact-inode rollback
        // link. Recover ONLY two provable states: same inode before rename,
        // or an already-verified replacement whose other plist keys equal
        // the old hardlink. Otherwise keep the journal untouched for manual
        // recovery, never overwrite a possible dpkg update.
        stage = "pending_rollback_check";
        struct stat pendingInfo = {0};
        if (!fstatat(dir, rollbackName, &pendingInfo, AT_SYMLINK_NOFOLLOW)) {
            int pending = openat(dir, rollbackName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (pending < 0) { result = errno; break; }
            struct stat pendingOpened = {0};
            BOOL pendingSafe = !fstat(pending, &pendingOpened) &&
                S_ISREG(pendingOpened.st_mode) && pendingOpened.st_uid == 0 &&
                pendingOpened.st_gid == 0 && !(pendingOpened.st_mode & 022) &&
                pendingOpened.st_flags == 0 &&
                pendingOpened.st_dev == pendingInfo.st_dev &&
                pendingOpened.st_ino == pendingInfo.st_ino;
            BOOL sameInode = pendingSafe && before.st_dev == pendingOpened.st_dev &&
                before.st_ino == pendingOpened.st_ino && before.st_nlink == 2 &&
                pendingOpened.st_nlink == 2;
            BOOL committed = NO;
            if (pendingSafe && !sameInode && before.st_nlink == 1 &&
                pendingOpened.st_nlink == 1) {
                NSData *liveBytes = RH3SSHReadBounded(original, before.st_size);
                NSData *pendingBytes = RH3SSHReadBounded(pending, pendingOpened.st_size);
                id live = liveBytes ? [NSPropertyListSerialization propertyListWithData:liveBytes
                               options:NSPropertyListImmutable format:NULL error:NULL] : nil;
                id previous = pendingBytes ? [NSPropertyListSerialization propertyListWithData:pendingBytes
                                   options:NSPropertyListImmutable format:NULL error:NULL] : nil;
                NSString *liveProgram = [live isKindOfClass:NSDictionary.class] &&
                    [live[@"Program"] isKindOfClass:NSString.class] ? live[@"Program"] : nil;
                // A committed change can refer to LAST boot's brand. The
                // new boot rotates before recovery. Recognize only an exact
                // branded RootHide sshd with matching arguments.
                NSString *oldRoot = [[[liveProgram stringByDeletingLastPathComponent]
                    stringByDeletingLastPathComponent] stringByDeletingLastPathComponent];
                BOOL brandedSSH = oldRoot.length &&
                    [DOBootstrapper rootHideBrandForPath:oldRoot] &&
                    [liveProgram isEqual:[oldRoot stringByAppendingPathComponent:@"usr/sbin/sshd"]] &&
                    [live[@"ProgramArguments"] isEqual:@[liveProgram, @"-i", @"-f",
                        [oldRoot stringByAppendingPathComponent:@"etc/ssh/sshd_config"], @"-h",
                        [oldRoot stringByAppendingPathComponent:@"etc/ssh/ssh_host_ed25519_key"]]];
                if ([live isKindOfClass:NSDictionary.class] &&
                    [previous isKindOfClass:NSDictionary.class] &&
                    [live[@"Label"] isEqual:@"com.openssh.sshd"] &&
                    [previous[@"Label"] isEqual:@"com.openssh.sshd"] &&
                    brandedSSH) {
                    NSMutableDictionary *liveOther = [live mutableCopy];
                    NSMutableDictionary *oldOther = [previous mutableCopy];
                    [liveOther removeObjectsForKeys:@[@"Program", @"ProgramArguments"]];
                    [oldOther removeObjectsForKeys:@[@"Program", @"ProgramArguments"]];
                    committed = [liveOther isEqual:oldOther];
                }
            }
            close(pending);
            if (!sameInode && !committed) { result = EBUSY; break; }
            stage = "pending_rollback_cleanup";
            if (unlinkat(dir, rollbackName, 0) || fsync(dir) ||
                fstat(original, &before)) { result = errno; break; }
        } else if (errno != ENOENT) { result = errno; break; }
        stage = "original_links";
        if (before.st_nlink != 1) { result = EPERM; break; }
        // The replacement is a fresh inode. Do not silently discard ACLs,
        // extended attributes or BSD flags on a package-managed original.
        // Refuse these uncommon layouts until metadata-preserving replacement
        // is explicitly supported and native-tested.
        stage = "original_flags";
        if (before.st_flags != 0) { result = ENOTSUP; break; }
        stage = "original_xattrs";
        ssize_t xattrBytes = flistxattr(original, NULL, 0, 0);
        if (xattrBytes != 0) { result = xattrBytes < 0 ? errno : ENOTSUP; break; }
        stage = "original_acl";
        errno = 0;
        // Darwin/APFS uses EXTENDED ACLs. acl_get_fd() queries the legacy
        // POSIX access ACL and can return EINVAL on a healthy iOS file.
        acl_t originalACL = acl_get_fd_np(original, ACL_TYPE_EXTENDED);
        if (originalACL) {
            acl_free(originalACL);
            result = ENOTSUP; break;
        }
        if (errno != ENOENT) { result = errno ? errno : ENOTSUP; break; }
        stage = "read_original";
        originalData = RH3SSHReadBounded(original, before.st_size);
        if (!originalData) { result = EIO; break; }
        stage = "parse_original";
        id parsed = [NSPropertyListSerialization propertyListWithData:originalData
                    options:NSPropertyListMutableContainers format:NULL error:NULL];
        if (![parsed isKindOfClass:NSDictionary.class]) { result = EINVAL; break; }
        NSMutableDictionary *job = [parsed mutableCopy];
        NSDictionary *sockets = [job[@"Sockets"] isKindOfClass:NSDictionary.class] ? job[@"Sockets"] : nil;
        NSDictionary *inetd = [job[@"inetdCompatibility"] isKindOfClass:NSDictionary.class] ?
                              job[@"inetdCompatibility"] : nil;
        stage = "socket_contract";
        NSUInteger port22 = 0, port2222 = 0;
        // Sockets itself is keyed by SSHListener/SSHListener2; the service
        // names live inside each value, not at the dictionary top level.
        // Each listener must have exactly ONE recognized port; an array
        // smuggling both ports under one listener must not let an unrelated
        // second socket pass the aggregate counter.
        BOOL socketEntriesTrusted = sockets.count == 2;
        for (id socketEntry in sockets.allValues) {
            NSUInteger entry22 = 0, entry2222 = 0;
            if (!RH3SSHValidateSingleSocket(socketEntry, &entry22, &entry2222))
                socketEntriesTrusted = NO;
            port22 += entry22;
            port2222 += entry2222;
        }
        if (![job[@"Label"] isEqual:@"com.openssh.sshd"] || !socketEntriesTrusted ||
            port22 != 1 || port2222 != 1 ||
            ![inetd[@"Wait"] isKindOfClass:NSNumber.class] || [inetd[@"Wait"] boolValue]) {
            result = ENOTSUP; break;
        }
        NSArray *args = @[sshd, @"-i", @"-f", config, @"-h", key];
        if ([job[@"Program"] isEqual:sshd] && [job[@"ProgramArguments"] isEqual:args])
            break; // Idempotent: verified paths already persisted.
        job[@"Program"] = sshd;
        job[@"ProgramArguments"] = args;
        stage = "serialize_rebased";
        nextData = [NSPropertyListSerialization dataWithPropertyList:job
                    format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        if (!nextData || nextData.length > 65536 || nextData.length < 32) {
            result = EOVERFLOW; break;
        }

        stage = "backup_lookup_existing";
        struct stat backupExisting = {0};
        BOOL backupWasPresent = fstatat(dir, backupName, &backupExisting,
                                        AT_SYMLINK_NOFOLLOW) == 0;
        if (!backupWasPresent && errno != ENOENT) { result = errno; break; }
        stage = "create_backup";
        // Construct and verify the backup under a private unique name. Darwin
        // renameatx_np(RENAME_EXCL) atomically publishes the completed file
        // with NO overwrite and no nlink==2 crash window. If unsupported,
        // refuse the optional repair rather than weaken exclusive semantics.
        // A crash during write leaves an ignorable staging file, not a
        // poisoned well-known backup that prevents future safe attempts.
        if (!backupWasPresent) {
            backup = openat(dir, backupTempName,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
            if (backup < 0) { result = errno; break; }
            madeBackupTemp = YES;
            stage = "backup_owner";
            if (fchown(backup, 0, 0)) { result = errno; break; }
            stage = "backup_permissions";
            if (fchmod(backup, 0600)) { result = errno; break; }
            stage = "backup_write_sync";
            result = RH3SSHWriteAll(backup, originalData);
            if (result) break;
            close(backup); backup = -1;
            stage = "backup_readback";
            backup = openat(dir, backupTempName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            struct stat created = {0};
            if (backup < 0) { result = errno; break; }
            if (fstat(backup, &created) || !S_ISREG(created.st_mode) ||
                created.st_uid != 0 || created.st_gid != 0 ||
                (created.st_mode & 0777) != 0600 || created.st_nlink != 1 ||
                created.st_flags != 0 ||
                ![RH3SSHReadBounded(backup, created.st_size) isEqual:originalData]) {
                result = EIO; break;
            }
            stage = "backup_created_xattrs";
            ssize_t createdXattrs = flistxattr(backup, NULL, 0, 0);
            if (createdXattrs != 0) {
                result = createdXattrs < 0 ? errno : ENOTSUP; break;
            }
            stage = "backup_created_acl";
            errno = 0;
            acl_t createdACL = acl_get_fd_np(backup, ACL_TYPE_EXTENDED);
            if (createdACL) { acl_free(createdACL); result = ENOTSUP; break; }
            if (errno != ENOENT) { result = errno ? errno : ENOTSUP; break; }
            close(backup); backup = -1;
            stage = "backup_publish_exclusive";
            if (renameatx_np(dir, backupTempName, dir, backupName, RENAME_EXCL)) {
                result = errno; break;
            }
            madeBackupTemp = NO;
            stage = "backup_publish_sync";
            if (fsync(dir)) { result = errno; break; }
            stage = "backup_published_readback";
            backup = openat(dir, backupName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            if (backup < 0) { result = errno; break; }
            struct stat published = {0};
            if (fstat(backup, &published) || !S_ISREG(published.st_mode) ||
                published.st_uid != 0 || published.st_gid != 0 ||
                (published.st_mode & 0777) != 0600 || published.st_nlink != 1 ||
                ![RH3SSHReadBounded(backup, published.st_size) isEqual:originalData]) {
                result = EIO; break;
            }
            close(backup); backup = -1;
        } else {
            // Preserve the very first package original across repeated repairs.
            // Refuse a symlink, foreign owner, malformed or writable backup.
            stage = "backup_open_existing";
            backup = openat(dir, backupName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            struct stat bs = {0};
            if (backup < 0) { result = errno; break; }
            stage = "backup_stat";
            if (fstat(backup, &bs)) { result = errno; break; }
            stage = "backup_metadata";
            if (!S_ISREG(bs.st_mode) || bs.st_uid != 0 || bs.st_gid != 0 ||
                (bs.st_mode & 0777) != 0600 || bs.st_nlink != 1 ||
                bs.st_flags != 0) {
                result = EPERM; break;
            }
            stage = "backup_xattrs";
            ssize_t backupXattrs = flistxattr(backup, NULL, 0, 0);
            if (backupXattrs != 0) {
                result = backupXattrs < 0 ? errno : ENOTSUP; break;
            }
            stage = "backup_acl";
            errno = 0;
            acl_t backupACL = acl_get_fd_np(backup, ACL_TYPE_EXTENDED);
            if (backupACL) { acl_free(backupACL); result = ENOTSUP; break; }
            if (errno != ENOENT) { result = errno ? errno : ENOTSUP; break; }
            stage = "backup_read";
            NSData *saved = RH3SSHReadBounded(backup, bs.st_size);
            id savedJob = saved ? [NSPropertyListSerialization propertyListWithData:saved
                              options:NSPropertyListImmutable format:NULL error:NULL] : nil;
            stage = "backup_contract";
            if (![savedJob isKindOfClass:NSDictionary.class] ||
                ![savedJob[@"Label"] isEqual:@"com.openssh.sshd"] ||
                ![savedJob[@"Sockets"] isKindOfClass:NSDictionary.class]) {
                result = EPERM; break;
            }
            close(backup); backup = -1;
        }

        stage = "create_replacement";
        next = openat(dir, nextName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (next < 0) { result = errno; break; }
        madeNext = YES;
        stage = "replacement_owner";
        if (fchown(next, before.st_uid, before.st_gid)) { result = errno; break; }
        stage = "replacement_permissions";
        if (fchmod(next, before.st_mode & 0777)) { result = errno; break; }
        stage = "replacement_write_sync";
        result = RH3SSHWriteAll(next, nextData);
        if (result) break;
        close(next); next = -1;
        // Check attributes of the actual new inode after construction. A
        // default/inherited ACL can appear on freshly created files even
        // when the package original had none.
        stage = "replacement_open_readback";
        replacementRead = openat(dir, nextName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (replacementRead < 0) { result = errno; break; }
        stage = "replacement_stat";
        if (fstat(replacementRead, &replacement)) { result = errno; break; }
        if (!S_ISREG(replacement.st_mode) || replacement.st_uid != before.st_uid ||
            replacement.st_gid != before.st_gid ||
            (replacement.st_mode & 0777) != (before.st_mode & 0777) ||
            replacement.st_flags != 0 || replacement.st_nlink != 1 ||
            ![RH3SSHReadBounded(replacementRead, replacement.st_size) isEqual:nextData]) {
            result = EIO; break;
        }
        stage = "replacement_xattrs";
        ssize_t replacementXattrs = flistxattr(replacementRead, NULL, 0, 0);
        if (replacementXattrs != 0) {
            result = replacementXattrs < 0 ? errno : ENOTSUP; break;
        }
        stage = "replacement_acl";
        errno = 0;
        acl_t replacementACL = acl_get_fd_np(replacementRead, ACL_TYPE_EXTENDED);
        if (replacementACL) { acl_free(replacementACL); result = ENOTSUP; break; }
        if (errno != ENOENT) { result = errno ? errno : ENOTSUP; break; }
        close(replacementRead); replacementRead = -1;
        stage = "original_revalidate";
        if (fstatat(dir, jobName, &current, AT_SYMLINK_NOFOLLOW) ||
            current.st_dev != before.st_dev || current.st_ino != before.st_ino ||
            current.st_size != before.st_size ||
            current.st_mtimespec.tv_sec != before.st_mtimespec.tv_sec ||
            current.st_mtimespec.tv_nsec != before.st_mtimespec.tv_nsec ||
            current.st_ctimespec.tv_sec != before.st_ctimespec.tv_sec ||
            current.st_ctimespec.tv_nsec != before.st_ctimespec.tv_nsec ||
            current.st_uid != before.st_uid || current.st_gid != before.st_gid ||
            current.st_mode != before.st_mode || current.st_flags != before.st_flags ||
            current.st_nlink != before.st_nlink ||
            ![RH3SSHReadBounded(original, before.st_size) isEqual:originalData]) {
            result = EBUSY; break; // A package manager or other process changed it.
        }
        // An atomic hard link retains the exact previous inode, including
        // its metadata. Keep it durably present through rename and readback:
        // any post-rename failure can restore without reserializing a plist.
        // EEXIST (e.g. interrupted previous attempt) is fail-closed.
        stage = "create_rollback_link";
        if (linkat(dir, jobName, dir, rollbackName, 0)) { result = errno; break; }
        madeRollback = YES;
        stage = "rollback_link_sync";
        if (fsync(dir)) { result = errno; break; }
        stage = "original_revalidate_after_link";
        struct stat linked = {0};
        if (fstatat(dir, jobName, &current, AT_SYMLINK_NOFOLLOW) ||
            fstatat(dir, rollbackName, &linked, AT_SYMLINK_NOFOLLOW) ||
            current.st_dev != before.st_dev || current.st_ino != before.st_ino ||
            linked.st_dev != before.st_dev || linked.st_ino != before.st_ino ||
            !S_ISREG(linked.st_mode) ||
            current.st_nlink != before.st_nlink + 1 ||
            linked.st_nlink != before.st_nlink + 1 ||
            ![RH3SSHReadBounded(original, before.st_size) isEqual:originalData]) {
            result = EBUSY; break;
        }
        stage = "replace_atomic";
        if (renameat(dir, nextName, dir, jobName)) { result = errno; break; }
        renamedJob = YES;
        if (changed) *changed = YES; // Even if readback/fsync later fails.
        madeNext = NO;
        stage = "replacement_directory_sync";
        if (fsync(dir)) { result = errno; break; }
        // Check the persisted result before reporting success to the user.
        stage = "verify_open";
        int checked = openat(dir, jobName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat checkedInfo = {0};
        if (checked < 0) { result = errno; break; }
        stage = "verify_stat";
        if (fstat(checked, &checkedInfo)) result = errno;
        stage = "verify_read";
        NSData *verifiedData = result ? nil : RH3SSHReadBounded(checked, checkedInfo.st_size);
        close(checked);
        id verified = verifiedData ? [NSPropertyListSerialization propertyListWithData:verifiedData
                                options:NSPropertyListImmutable format:NULL error:NULL] : nil;
        NSMutableDictionary *originalOtherKeys = [parsed mutableCopy];
        NSMutableDictionary *verifiedOtherKeys = [verified isKindOfClass:NSDictionary.class] ?
                                                  [verified mutableCopy] : nil;
        [originalOtherKeys removeObjectsForKeys:@[@"Program", @"ProgramArguments"]];
        [verifiedOtherKeys removeObjectsForKeys:@[@"Program", @"ProgramArguments"]];
        stage = "verify_contract";
        if (![verified isKindOfClass:NSDictionary.class] ||
            ![verified[@"Program"] isEqual:sshd] ||
            ![verified[@"ProgramArguments"] isEqual:args] ||
            ![verified[@"Sockets"] isEqual:sockets] ||
            ![verified[@"inetdCompatibility"] isEqual:inetd] ||
            ![verifiedOtherKeys isEqual:originalOtherKeys]) {
            result = EIO; break; // Original is still recoverable from the backup.
        }
    } while (0);
    if (renamedJob && result && madeRollback) {
        // Do not clobber a concurrent package manager update. Only replace
        // our own candidate inode and bytes with the exact original hard link.
        // This narrows, but cannot eliminate, races with an independent dpkg
        // writer because Darwin has no renameat compare-and-swap contract.
        struct stat live = {0};
        int liveFD = openat(dir, jobName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        BOOL unchangedReplacement = liveFD >= 0 && !fstat(liveFD, &live) &&
            S_ISREG(live.st_mode) &&
            live.st_dev == replacement.st_dev && live.st_ino == replacement.st_ino &&
            live.st_uid == replacement.st_uid && live.st_gid == replacement.st_gid &&
            live.st_mode == replacement.st_mode && live.st_flags == replacement.st_flags &&
            [RH3SSHReadBounded(liveFD, live.st_size) isEqual:nextData];
        if (liveFD >= 0) close(liveFD);
        struct stat nameAgain = {0};
        if (unchangedReplacement &&
            !fstatat(dir, jobName, &nameAgain, AT_SYMLINK_NOFOLLOW) &&
            nameAgain.st_dev == live.st_dev && nameAgain.st_ino == live.st_ino &&
            !renameat(dir, rollbackName, dir, jobName)) {
            madeRollback = NO;
            if (!fsync(dir)) {
                if (changed) *changed = NO;
                stage = "post_replace_rolled_back";
            } else stage = "rollback_sync_failed";
        } else stage = "rollback_failed_preserved";
    }
    if (backup >= 0) close(backup);
    if (madeBackupTemp) (void)unlinkat(dir, backupTempName, 0);
    if (next >= 0) close(next);
    if (replacementRead >= 0) close(replacementRead);
    if (original >= 0) close(original);
    if (madeNext) (void)unlinkat(dir, nextName, 0);
    if (madeRollback && !renamedJob) {
        (void)unlinkat(dir, rollbackName, 0);
        (void)fsync(dir);
    } else if (madeRollback && !result) {
        if (unlinkat(dir, rollbackName, 0) || fsync(dir)) {
            result = errno;
            stage = "rollback_link_cleanup";
        }
    }
    // Never discard a completely published first backup on a later error.
    // It may be the only durable recovery copy if an interrupted operation
    // crossed the commit boundary, and future attempts validate it read-only.
    if (stageOut) *stageOut = result ? stage : (changed && *changed ? "replaced_verified" : "already_current");
    close(dir);
    return result;
}

// Procursus names the entries SSHListener and SSHListener2 rather than the
// Apple example's Listeners. Count their actual service names, not key names.
static void RH3SSHCountSocketPorts(id entry, NSUInteger *port22, NSUInteger *port2222)
{
    if ([entry isKindOfClass:NSArray.class]) {
        for (id member in (NSArray *)entry) RH3SSHCountSocketPorts(member, port22, port2222);
        return;
    }
    if (![entry isKindOfClass:NSDictionary.class]) return;
    id service = ((NSDictionary *)entry)[@"SockServiceName"];
    NSString *name = [service isKindOfClass:NSString.class] ? service :
        ([service isKindOfClass:NSNumber.class] ? [service stringValue] : nil);
    if ([name isEqualToString:@"ssh"] || [name isEqualToString:@"22"]) ++*port22;
    if ([name isEqualToString:@"2222"]) ++*port2222;
}

// Unlike the read-only diagnostic counter, the write path must reject every
// extra/unknown array member. Counting only recognized ports would otherwise
// accept [{SockServiceName=ssh}, {SockServiceName=9999}] as ONE valid listener.
static BOOL RH3SSHValidateSingleSocket(id entry, NSUInteger *port22, NSUInteger *port2222)
{
    if ([entry isKindOfClass:NSArray.class]) {
        NSArray *members = entry;
        return members.count == 1 &&
               RH3SSHValidateSingleSocket(members[0], port22, port2222);
    }
    if (![entry isKindOfClass:NSDictionary.class]) return NO;
    // A service name alone does not prove that launchd created a passive
    // TCP stream listener. A malformed UDP/active socket must not be
    // rewritten by the optional SSH repair. Omitted launchd keys retain
    // their native defaults; do not reject standard Procursus jobs.
    NSDictionary *socket = (NSDictionary *)entry;
    id sockType = socket[@"SockType"];
    if (sockType && (![sockType isKindOfClass:NSString.class] ||
                     ![[sockType lowercaseString] isEqualToString:@"stream"])) return NO;
    id sockProtocol = socket[@"SockProtocol"];
    if (sockProtocol && (![sockProtocol isKindOfClass:NSString.class] ||
                         ![[sockProtocol lowercaseString] isEqualToString:@"tcp"])) return NO;
    // launch.h specifies SockPassive (not SocketPassive). Reject an
    // explicitly active listener before opting in to rewrite its SSH job.
    id passive = socket[@"SockPassive"];
    if (passive && (![passive isKindOfClass:NSNumber.class] || ![passive boolValue])) return NO;
    id service = ((NSDictionary *)entry)[@"SockServiceName"];
    NSString *name = [service isKindOfClass:NSString.class] ? service :
        ([service isKindOfClass:NSNumber.class] ? [service stringValue] : nil);
    if ([name isEqualToString:@"ssh"] || [name isEqualToString:@"22"]) {
        ++*port22;
        return YES;
    }
    if ([name isEqualToString:@"2222"]) {
        ++*port2222;
        return YES;
    }
    return NO;
}

@implementation DOEnvironmentManager

+ (instancetype)sharedManager
{
    static DOEnvironmentManager *shared;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        shared = [[DOEnvironmentManager alloc] init];
    });
    return shared;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _bootstrapNeedsMigration = NO;
        _bootstrapper = [[DOBootstrapper alloc] init];
        if ([self isJailbroken]) {
            const char *serverRoot = jbclient_get_jbroot();
            if ([DOBootstrapper rootHidePortEnabled]) {
                NSString *root = serverRoot ? RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot]) : nil;
                uint64_t brand = root ? [DOBootstrapper rootHideBrandForPath:root] : 0;
                if (brand) {
                    gSystemInfo.jailbreakInfo.rootPath = strdup(root.fileSystemRepresentation);
                    gSystemInfo.jailbreakInfo.jbrand = brand;
                }
            } else {
                gSystemInfo.jailbreakInfo.rootPath = strdup(serverRoot ?: "");
            }
        }
        else if ([self isInstalledThroughTrollStore]) {
            [self locateJailbreakRoot];
        }
    }
    return self;
}

- (NSString *)nightlyHash
{
#ifdef NIGHTLY
    return [NSString stringWithUTF8String:COMMIT_HASH];
#else
    return nil;
#endif
}

- (NSString *)appVersion
{
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

- (NSString *)appVersionDisplayString
{
    NSString *nightlyHash = [self nightlyHash];
    if (nightlyHash) {
        return [NSString stringWithFormat:@"%@~%@", self.appVersion, [nightlyHash substringToIndex:6]];
    }
    else {
        return [self appVersion];
    }
}

- (NSString *)privatePrebootPath
{
    return @"/private/preboot";
}

- (NSString *)activePrebootPath
{
    NSString *bootManifestString = [NSString stringWithUTF8String:boot_manifest_hash()];
    return [[self privatePrebootPath] stringByAppendingPathComponent:bootManifestString];
}

- (void)locateJailbreakRoot
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        if (!gSystemInfo.jailbreakInfo.rootPath) {
            NSError *error = nil;
            NSString *root = [DOBootstrapper rootHideExistingRootWithError:&error];
            if (root && !error) {
                gSystemInfo.jailbreakInfo.rootPath = strdup(root.fileSystemRepresentation);
                gSystemInfo.jailbreakInfo.jbrand = [DOBootstrapper rootHideBrandForPath:root];
            }
        }
        return;
    }
    if (!gSystemInfo.jailbreakInfo.rootPath) {
        NSString *activePrebootPath = [self activePrebootPath];
        
        NSString *randomizedJailbreakPath;
        
        // First attempt at finding jailbreak root, look for Dopamine 2.x path
        for (NSString *subItem in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:activePrebootPath error:nil]) {
            if (subItem.length == 15 && [subItem hasPrefix:@"dopamine-"]) {
                randomizedJailbreakPath = [activePrebootPath stringByAppendingPathComponent:subItem];
                break;
            }
        }
        
        if (!randomizedJailbreakPath) {
            // Second attempt at finding jailbreak root, look for Dopamine 1.x path, but as other jailbreaks use it too, make sure it is Dopamine
            // Some other jailbreaks also commit the sin of creating .installed_dopamine, for these we try to filter them out by checking for their installed_ file
            // If we find this and are sure it's from Dopamine 1.x, rename it so all Dopamine 2.x users will have the same path
            for (NSString *subItem in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:activePrebootPath error:nil]) {
                if (subItem.length == 9 && [subItem hasPrefix:@"jb-"]) {
                    NSString *candidateLegacyPath = [activePrebootPath stringByAppendingPathComponent:subItem];
                    
                    BOOL installedDopamine = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.installed_dopamine"]];
                    
                    if (installedDopamine) {
                        // Hopefully all other jailbreaks that use jb-<UUID>?
                        // These checks exist because of dumb users (and jailbreak developers) creating .installed_dopamine on jailbreaks that are NOT dopamine...
                        BOOL installedNekoJB = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.installed_nekojb"]];
                        BOOL installedDefinitelyNotAGoodName = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.xia0o0o0o_jb_installed"]];
                        BOOL installedPalera1n = [[NSFileManager defaultManager] fileExistsAtPath:[candidateLegacyPath stringByAppendingPathComponent:@"procursus/.palecursus_strapped"]];
                        if (installedNekoJB || installedPalera1n || installedDefinitelyNotAGoodName) {
                            continue;
                        }
                        
                        randomizedJailbreakPath = candidateLegacyPath;
                        _bootstrapNeedsMigration = YES;
                        break;
                    }
                }
            }
        }
        
        if (randomizedJailbreakPath) {
            NSString *jailbreakRootPath = [randomizedJailbreakPath stringByAppendingPathComponent:@"procursus"];
            if ([[NSFileManager defaultManager] fileExistsAtPath:jailbreakRootPath]) {
                // This attribute serves as the primary source of what the root path is
                // Anything else in the jailbreak will get it from here
                gSystemInfo.jailbreakInfo.rootPath = strdup(jailbreakRootPath.fileSystemRepresentation);
            }
        }
    }
}

- (NSError *)ensureJailbreakRootExists
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        NSError *error = nil;
        NSString *root = [DOBootstrapper rootHideExistingRootWithError:&error];
        if (error) return error;
        if (root) {
            gSystemInfo.jailbreakInfo.rootPath = strdup(root.fileSystemRepresentation);
            gSystemInfo.jailbreakInfo.jbrand = [DOBootstrapper rootHideBrandForPath:root];
        }
        // A new hidden root is created by prepareBootstrap, after privilege escalation.
        return nil;
    }
    NSError *error = nil;

    [self locateJailbreakRoot];

    // DOPACLEAN logic to move a corrupted dopamine directory to a different path to at least make jailbreaking work again
    // if (gSystemInfo.jailbreakInfo.rootPath) {
    //     NSString *randomizedJailbreakPath = [NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath].stringByDeletingLastPathComponent;
    //     NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    //     NSUInteger stringLen = 6;
    //     NSMutableString *randomString = [NSMutableString stringWithCapacity:stringLen];
    //     for (NSUInteger i = 0; i < stringLen; i++) {
    //         NSUInteger randomIndex = arc4random_uniform((uint32_t)[characterSet length]);
    //         unichar randomCharacter = [characterSet characterAtIndex:randomIndex];
    //         [randomString appendFormat:@"%C", randomCharacter];
    //     }
        
    //     NSString *activePrebootPath = [self activePrebootPath];
    //     NSString *orphanedName = [NSString stringWithFormat:@"orphaned-%@", randomString];
    //     NSString *orphanedPath = [activePrebootPath stringByAppendingPathComponent:orphanedName];
    //     [[NSFileManager defaultManager] moveItemAtPath:randomizedJailbreakPath toPath:orphanedPath error:nil];
    // }

    // return [NSError errorWithDomain:@"Cleaned" code:1 userInfo:nil];

    if (!gSystemInfo.jailbreakInfo.rootPath || _bootstrapNeedsMigration) {
        [_bootstrapper ensurePrivatePrebootIsWritable];

        NSString *activePrebootPath = [self activePrebootPath];

        NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        NSUInteger stringLen = 6;
        NSMutableString *randomString = [NSMutableString stringWithCapacity:stringLen];
        for (NSUInteger i = 0; i < stringLen; i++) {
            NSUInteger randomIndex = arc4random_uniform((uint32_t)[characterSet length]);
            unichar randomCharacter = [characterSet characterAtIndex:randomIndex];
            [randomString appendFormat:@"%C", randomCharacter];
        }
        
        NSString *randomJailbreakFolderName = [NSString stringWithFormat:@"dopamine-%@", randomString];
        NSString *randomizedJailbreakPath = [activePrebootPath stringByAppendingPathComponent:randomJailbreakFolderName];
        NSString *jailbreakRootPath = [randomizedJailbreakPath stringByAppendingPathComponent:@"procursus"];
        
        if (_bootstrapNeedsMigration) {
            NSString *oldRandomizedJailbreakPath = [[NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath] stringByDeletingLastPathComponent];
            [[NSFileManager defaultManager] moveItemAtPath:oldRandomizedJailbreakPath toPath:randomizedJailbreakPath error:&error];
        }
        else {
            if (![[NSFileManager defaultManager] fileExistsAtPath:jailbreakRootPath]) {
                [[NSFileManager defaultManager] createDirectoryAtPath:jailbreakRootPath withIntermediateDirectories:YES attributes:nil error:&error];
            }
        }
        
        if (!error) {
            gSystemInfo.jailbreakInfo.rootPath = strdup(jailbreakRootPath.UTF8String);
        }
    }
    
    return error;
}

- (BOOL)isArm64e
{
    cpu_subtype_t cpusubtype = 0;
    size_t len = sizeof(cpusubtype);
    if (sysctlbyname("hw.cpusubtype", &cpusubtype, &len, NULL, 0) == -1) return NO;
    return (cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E;
}

- (BOOL)isSPTM
{
    if (@available(iOS 17.0, *)) {
        io_registry_entry_t memory_map = IORegistryEntryFromPath(kIOMainPortDefault, "IODeviceTree:/chosen/memory-map");
        if (memory_map == IO_OBJECT_NULL)   return NO;

        CFArrayRef keys = (CFArrayRef)IORegistryEntryCreateCFProperty(memory_map, CFSTR(kIORegistryEntryPropertyKeysKey), kCFAllocatorDefault, 0);
        IOObjectRelease(memory_map);
        if (!keys)  return NO;

        CFRange range = CFRangeMake(0, CFArrayGetCount(keys));

        bool isSPTM = CFArrayContainsValue(keys, range, CFSTR("SPTM")) && CFArrayContainsValue(keys, range, CFSTR("TXM"));
        CFRelease(keys);

        return isSPTM;
    }
    return false;
}

- (NSString *)versionSupportString
{
    cpu_subtype_t cpuFamily = 0;
    size_t cpuFamilySize = sizeof(cpuFamily);
    sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
    
    if ([self isArm64e]) {
        if (cpuFamily == CPUFAMILY_ARM_VORTEX_TEMPEST || cpuFamily == CPUFAMILY_ARM_LIGHTNING_THUNDER) {
            return @"iOS 15.0 - 18.7.1, 26.0 - 26.0.1 (A12/A13, PPL)";
        }
        else if (![self isSPTM]) {
            return @"iOS 15.0 - 17.3.1 (PPL)";
        }
        else {
            return @"iOS 17.0 - 17.3.1 (SPTM)";
        }
    }
    else {
        return @"iOS 15.0 - 18.7.1 (arm64)";
    }
}

- (BOOL)isInstalledThroughTrollStore
{
    static BOOL trollstoreInstallation = NO;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString* trollStoreMarkerPath = [[[NSBundle mainBundle].bundlePath stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"_TrollStore"];
        trollstoreInstallation = [[NSFileManager defaultManager] fileExistsAtPath:trollStoreMarkerPath];
    });
    return trollstoreInstallation;
}

- (void)updateJailbreakState
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        char *jbVersionC = NULL;
        _isJailbroken = jbclient_dopamine_is_jailbroken(&jbVersionC);
        if (jbVersionC) {
            _jailbrokenVersion = [NSString stringWithUTF8String:jbVersionC];
            free(jbVersionC);
        }
    });
}

- (BOOL)isJailbroken
{
    [self updateJailbreakState];
    return _isJailbroken;
}

- (void)setJailbroken:(BOOL)jailbroken withVersion:(NSString *)version
{
    _isJailbroken = jailbroken;
    if (_isJailbroken) _jailbrokenVersion = version;
}

- (BOOL)isJailbrokenWithOtherJailbreak
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        // Do not classify TrollStore's platform-signed host app itself as
        // a jailbreak. Inspect active jailbreak state instead.
        return otherJailbreakActived(false);
    }
    if (![self isJailbroken]) {
        uint32_t csFlags = 0;
        csops(getpid(), CS_OPS_STATUS, &csFlags, sizeof(csFlags));
        
        // Palera1n
        if (csFlags & CS_PLATFORM_BINARY) return YES;
        
        // Older Dopamine build
        if (!access("/usr/lib/systemhook.dylib", F_OK)) return YES;
    }
    return NO;
}

- (NSString *)jailbrokenVersion
{
    [self updateJailbreakState];
    if (!_isJailbroken) return nil;
    return _jailbrokenVersion;
}

- (NSString *)systemVersion
{
    return (__bridge NSString *)MGCopyAnswer((__bridge CFStringRef)@"ProductVersion");
}

- (BOOL)isBootstrapped
{
    return (BOOL)jbinfo(rootPath);
}

- (void)runUnsandboxed:(void (^)(void))unsandboxBlock
{
    if ([self isInstalledThroughTrollStore]) {
        unsandboxBlock();
    }
    else if ([self isJailbroken]) {
        uint64_t labelBackup = 0;
        jbclient_root_set_mac_label(1, -1, &labelBackup);
        unsandboxBlock();
        jbclient_root_set_mac_label(1, labelBackup, NULL);
    }
    else {
        // Hope that we are already unsandboxed
        unsandboxBlock();
    }
}

- (void)runAsRoot:(void (^)(void))rootBlock
{
    uint32_t orgUser = geteuid();
    uint32_t orgGroup = getegid();
    
    if (orgUser == 0 && orgGroup == 0) {
        rootBlock();
        return;
    }

    if (self.isJailbroken) {
        if (jbclient_dopamine_get_root() == 0) {
            rootBlock();
            jbclient_dopamine_drop_root();
        }
    }
}

- (int)rh3ActionStage:(NSString *)stage result:(int)result
{
    NSString *line = [NSString stringWithFormat:@"RootHide action %@: result=%d euid=%u egid=%u", stage, result, geteuid(), getegid()];
    [[DOUIManager sharedInstance] sendLog:line debug:NO];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:line];
    return result;
}

- (int)rh3PerformPrivilegedAction:(int (^)(void))action
{
    @synchronized (self) {
    // Anchor the diagnostic descriptor in the original app container first.
    [DOUIManager sharedInstance];
    BOOL jailbroken = self.isJailbroken;
    BOOL active = roothide_is_active();
    if (!jailbroken || !active) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"RootHide action preflight: jailbroken=%d active_root=%d; refused", jailbroken, active]];
        return [self rh3ActionStage:@"environment unavailable" result:ENXIO];
    }
    BOOL elevated = geteuid() != 0 || getegid() != 0;
    if (elevated) {
        int result = jbclient_dopamine_get_root();
        if (result != 0) return [self rh3ActionStage:@"get-root" result:result];
    }
    int result = 0;
    BOOL labelChanged = NO;
    uint64_t labelBackup = 0;
    @try {
        if (geteuid() != 0 || getegid() != 0) result = [self rh3ActionStage:@"verify-root" result:EPERM];
        else if (![self isInstalledThroughTrollStore]) {
            result = jbclient_dopamine_roothide_set_sandbox_label(UINT64_MAX, &labelBackup);
            labelChanged = result == 0;
            [self rh3ActionStage:@"unsandbox" result:result];
        }
        if (!result) result = action();
    } @finally {
        if (labelChanged) {
            int restore = jbclient_dopamine_roothide_set_sandbox_label(labelBackup, NULL);
            if (restore) { [self rh3ActionStage:@"restore-sandbox" result:restore]; if (!result) result = restore; }
        }
        if (elevated) {
            int restore = jbclient_dopamine_drop_root();
            if (restore) { [self rh3ActionStage:@"drop-root" result:restore]; if (!result) result = restore; }
        }
    }
    return result;
    }
}

- (int)spawnJbctlAsRootWithArgs:(NSArray *)args
{
    bool needsLegacySolution = DOUsesLegacyJbctl(self.jailbrokenVersion);
    if ([DOBootstrapper rootHidePortEnabled]) {
        NSString *operation = args.count ? args[0] : @"unknown";
        if ([operation isEqualToString:@"internal"] && args.count > 1)
            operation = [NSString stringWithFormat:@"internal/%@", args[1]];
        // Only the verb is recorded: package paths and command arguments may
        // contain private data. This checkpoint also covers an early pipe error.
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"RootHide jbctl request %@: jailbroken=%d active_root=%d legacy=%d",
             operation, self.isJailbroken, roothide_is_active(), needsLegacySolution]];
    }

    char **argBuf = malloc((args.count + 4) * sizeof(char *));
    argBuf[0] = strdup(JBROOT_PATH("/basebin/jbctl"));
    int i = 1;
    for (NSString *arg in args) {
        argBuf[i++] = strdup(arg.UTF8String);
    }

    if (!needsLegacySolution) {
        argBuf[i++] = strdup("--waitfor");
        argBuf[i++] = strdup("3");
    }
    argBuf[i++] = NULL;
    
    posix_spawn_file_actions_t act = NULL;
	posix_spawn_file_actions_init(&act);
    posix_spawnattr_t attr = NULL;
    posix_spawnattr_init(&attr);
     
    int waitPipe[2] = {-1, -1};
    int pipeError = 0;
    
    if (!needsLegacySolution) {
        if (pipe(waitPipe) != 0) pipeError = errno;
        else {
            pipeError = posix_spawn_file_actions_adddup2(&act, waitPipe[0], 3);
            if (!pipeError && waitPipe[1] != 3) pipeError = posix_spawn_file_actions_addclose(&act, waitPipe[1]);
            if (!pipeError && waitPipe[0] != 3) pipeError = posix_spawn_file_actions_addclose(&act, waitPipe[0]);
        }
    }
    else {
        posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
    }

    __block int pid = 0;
    __block int r = EPERM;

    if (pipeError) r = pipeError;
    else if ([DOBootstrapper rootHidePortEnabled]) {
        r = [self rh3PerformPrivilegedAction:^int{
            int status = posix_spawn(&pid, argBuf[0], &act, &attr, (char *const *)argBuf, (char *const *)environ);
            if (needsLegacySolution && status == 0 && pid > 0 && kill(pid, SIGCONT) != 0) status = errno;
            return [self rh3ActionStage:@"jbctl spawn" result:status];
        }];
    } else [self runAsRoot:^{
        [self runUnsandboxed:^{
            r = posix_spawn(&pid, argBuf[0], &act, &attr, (char *const *)argBuf, (char *const *)environ);
            if (needsLegacySolution && r == 0 && pid > 0) {
                // Legacy solution is a gamble, which is why it was removed and superseeded by --waitfor
                // But if jailbroken with <3.0.5, jbctl doesn't support --waitfor yet
                kill(pid, SIGCONT);
            }
        }];
        // We *NEED* to leave this block on iOS 17+ to avoid a panic, --waitfor ensures this always happens
    }];

    posix_spawnattr_destroy(&attr);
    posix_spawn_file_actions_destroy(&act);
    for (int y = 0; y < i; y++) {
        free(argBuf[y]);
    }
    free(argBuf);

    if (!needsLegacySolution) {
        if (r == 0) {
            // We left the root/unsandbox block, now resume jbctl by writing to pipe
            char w = 'w';
            ssize_t count;
            do { count = write(waitPipe[1], &w, sizeof(w)); } while (count < 0 && errno == EINTR);
            if (count != sizeof(w)) r = count < 0 ? errno : EIO;
        }

        if (waitPipe[0] >= 0) close(waitPipe[0]);
        if (waitPipe[1] >= 0) close(waitPipe[1]);
    }

    if (r != 0 || pid <= 0) {
        int failure = r != 0 ? r : ECHILD;
        if ([DOBootstrapper rootHidePortEnabled])
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"RootHide jbctl failed before wait: result=%d pid=%d pipe_error=%d", failure, pid, pipeError]];
        return failure;
    }
    if ([DOBootstrapper rootHidePortEnabled]) {
        int raw = -1;
        BOOL installing = args.count > 1 && [args[0] isEqualToString:@"internal"] && [args[1] isEqualToString:@"install_pkg"];
        int result = RH3WaitForBootstrapChildStatus(pid, installing ? 120 : 30, &raw);
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"RootHide jbctl: pid=%d raw_wait=%d result=%d", pid, raw, result]];
        return result < 0 ? -result : result;
    }
    return cmd_wait_for_exit(pid);
}

- (int)runTrollStoreAction:(NSString *)action
{
    if (![self isInstalledThroughTrollStore]) return -1;
    
    uint32_t selfPathSize = PATH_MAX;
    char selfPath[selfPathSize];
    _NSGetExecutablePath(selfPath, &selfPathSize);
    return exec_cmd_root(selfPath, "trollstore", action.UTF8String, NULL);
}

- (int)respring
{
    int result = [self spawnJbctlAsRootWithArgs:@[@"respring"]];
    if ([DOBootstrapper rootHidePortEnabled]) [self rh3ActionStage:@"respring" result:result];
    return result;
}

- (int)rebootUserspace
{
    int result = [self spawnJbctlAsRootWithArgs:@[@"reboot_userspace"]];
    if ([DOBootstrapper rootHidePortEnabled]) [self rh3ActionStage:@"reboot userspace" result:result];
    return result;
}

- (void)rebuildIconCache
{
    [self spawnJbctlAsRootWithArgs:@[@"rebuild_icon_cache"]];
}

- (int)rh3RunCommand:(NSString *)binary arguments:(NSArray<NSString *> *)arguments input:(NSData *)input timeout:(unsigned)timeout
{
    if (input.length > 2048) return E2BIG;
    char **argv = calloc(arguments.count + 2, sizeof(char *));
    if (!argv) return ENOMEM;
    argv[0] = strdup(binary.fileSystemRepresentation);
    for (NSUInteger i = 0; i < arguments.count; i++) argv[i + 1] = strdup(arguments[i].UTF8String);
    BOOL allocated = YES;
    for (NSUInteger i = 0; i <= arguments.count; i++) if (!argv[i]) allocated = NO;
    if (!allocated) {
        for (NSUInteger i = 0; i <= arguments.count; i++) free(argv[i]);
        free(argv);
        return ENOMEM;
    }
    int channel[2] = {-1, -1};
    posix_spawn_file_actions_t actions;
    int result = posix_spawn_file_actions_init(&actions);
    BOOL initialized = result == 0;
    if (!result && input) {
        if (pipe(channel)) result = errno;
        else {
            result = posix_spawn_file_actions_adddup2(&actions, channel[0], STDIN_FILENO);
            if (!result && channel[0] != STDIN_FILENO) result = posix_spawn_file_actions_addclose(&actions, channel[0]);
            if (!result) result = posix_spawn_file_actions_addclose(&actions, channel[1]);
        }
    } else if (!result) result = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    __block pid_t pid = -1;
    __block char **probeEnvironment = NULL;
    __block NSString *probeHookPath = nil;
    NSString *commandName = binary.lastPathComponent;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"RootHide command %@: privilege and trust starting", commandName]];
    if (!result) result = [self rh3PerformPrivilegedAction:^int{
        if ([commandName isEqualToString:@"rh3tweakprobe"] && [DOBootstrapper rootHidePortEnabled]) {
            NSError *rootError = nil;
            NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
            const char *activeRoot = jbclient_get_jbroot();
            if (rootError || !root || !activeRoot ||
                ![RH3CanonicalAppPath(root) isEqualToString:
                  RH3CanonicalAppPath([NSString stringWithUTF8String:activeRoot])] ||
                ![RH3CanonicalAppPath(binary) isEqualToString:
                  RH3CanonicalAppPath([root stringByAppendingPathComponent:@"basebin/rh3tweakprobe"])])
                return EPERM;
            NSString *hook = [root stringByAppendingPathComponent:@"basebin/systemhook.dylib"];
            struct stat hookInfo = {0};
            if (lstat(hook.fileSystemRepresentation, &hookInfo) ||
                !S_ISREG(hookInfo.st_mode) || hookInfo.st_uid != 0 ||
                hookInfo.st_nlink != 1 || (hookInfo.st_mode & 0022)) return EPERM;
            // A successful JBD_MSG_SPAWN_PATCH_CHILD alone cannot prove that
            // systemhook was passed to dyld. Only this disposable probe gets
            // a private dyld environment. Do not modify the app's environ.
            int envStatus = rh3_probe_env_build(environ, hook.fileSystemRepresentation,
                                               &probeEnvironment);
            if (envStatus) return envStatus;
            probeHookPath = hook;
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                @"RootHide tweak probe: verified private systemhook environment prepared"];
        }
        int trust = jbclient_trust_executable_recurse(binary.fileSystemRepresentation, NULL);
        if (trust) return [self rh3ActionStage:@"command trust" result:trust];
        if (probeEnvironment && probeHookPath) {
            // The probe executable being trusted does NOT establish that
            // dyld can map its inserted dylib. Verify/trust only this already
            // authenticated active-root hook; do not widen global trust.
            int hookTrust = jbclient_trust_library_recurse(probeHookPath.fileSystemRepresentation, NULL);
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"RootHide tweak probe: private systemhook trust result=%d", hookTrust]];
            if (hookTrust) return [self rh3ActionStage:@"probe dylib trust" result:hookTrust];
        }
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"RootHide command %@: trust complete; spawn starting", commandName]];
        return exec_cmd_roothide_spawn_traced(&pid, argv[0], &actions, NULL, argv,
                                             probeEnvironment ? probeEnvironment : environ,
                                             RH3LogCommandSpawnStage, (__bridge void *)commandName);
    }];
    rh3_probe_env_free(probeEnvironment);
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"RootHide command %@: spawn returned=%d pid=%d", binary.lastPathComponent, result, pid]];
    if (initialized) posix_spawn_file_actions_destroy(&actions);
    for (NSUInteger i = 0; i <= arguments.count; i++) free(argv[i]);
    free(argv);
    // Retain our read end until the small write completes: even if the child
    // exits early, the write cannot raise SIGPIPE in the app. Never log input.
    if (!result && input) {
        ssize_t count;
        do { count = write(channel[1], input.bytes, input.length); } while (count < 0 && errno == EINTR);
        if (count != (ssize_t)input.length) result = count < 0 ? errno : EIO;
    }
    if (channel[0] >= 0) close(channel[0]);
    if (channel[1] >= 0) close(channel[1]);
    if (result || pid <= 1) return result ?: ECHILD;
    int raw = -1;
    int status = RH3WaitForBootstrapChildStatus(pid, timeout, &raw);
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"RootHide child %@: pid=%d raw_wait=%d result=%d", binary.lastPathComponent, pid, raw, status]];
    return status < 0 ? -status : status;
}

- (int)refreshJailbreakApps
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"apps: refresh starting; acquiring privileges"];
        __block NSArray *apps = nil;
        NSMutableDictionary<NSString *, NSString *> *identifiers = [NSMutableDictionary dictionary];
        int result = [self rh3PerformPrivilegedAction:^int{
            NSError *error = [self->_bootstrapper repairRootHideAppLinks];
            if (error) return [self rh3ActionStage:@"app links" result:(int)error.code];
            apps = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/Applications") error:&error];
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"apps: owned Applications directory read; entries=%lu error=%ld", (unsigned long)apps.count, (long)error.code]];
            if (!apps) return EIO;
            // The app loses root/sandbox privileges when this block returns.
            // Resolve only bounded, regular Info.plists while the active root
            // is still readable. Later LaunchServices queries stay unprivileged.
            for (NSString *name in apps) {
                if (![name.pathExtension isEqualToString:@"app"] ||
                    ![name.lastPathComponent isEqualToString:name]) continue;
                NSString *bundle = [JBROOT_PATH(@"/Applications") stringByAppendingPathComponent:name];
                NSString *plist = [bundle stringByAppendingPathComponent:@"Info.plist"];
                struct stat appSt = {0}, plistSt = {0};
                if (lstat(bundle.fileSystemRepresentation, &appSt) || !S_ISDIR(appSt.st_mode) ||
                    lstat(plist.fileSystemRepresentation, &plistSt) || !S_ISREG(plistSt.st_mode) ||
                    plistSt.st_size <= 0 || plistSt.st_size > 65536 || plistSt.st_nlink != 1) continue;
                // Vendor-owned UID 501 bundles are valid for read-only parsing;
                // this does not grant them root trust or modify their ownership.
                NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:plist];
                NSString *identifier = [info[@"CFBundleIdentifier"] isKindOfClass:NSString.class]
                    ? info[@"CFBundleIdentifier"] : nil;
                if (identifier.length && identifier.length <= 256 &&
                    [identifier rangeOfCharacterFromSet:
                        [[NSCharacterSet characterSetWithCharactersInString:
                            @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"] invertedSet]].location == NSNotFound)
                    identifiers[name] = identifier;
            }
            return 0;
        }];
        // Refresh only the jailbreak's own bundles, not every system app.
        NSUInteger alreadyRegistered = 0, refreshed = 0;
        for (NSString *app in apps) {
            if (result) break;
            if (![app.pathExtension isEqualToString:@"app"] || ![app.lastPathComponent isEqualToString:app]) continue;
            NSString *path = [JBROOT_PATH(@"/Applications") stringByAppendingPathComponent:app];
            NSString *bundleID = identifiers[app];
            if (bundleID.length) {
                LSApplicationProxy *registered = [LSApplicationProxy applicationProxyForIdentifier:bundleID];
                if (registered.installed &&
                    [RH3CanonicalAppPath(registered.bundleURL.path) isEqualToString:RH3CanonicalAppPath(path)]) {
                    alreadyRegistered++;
                    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                        [NSString stringWithFormat:@"apps: %@ registration already points to active root; skipping uicache", app]];
                    continue;
                }
            }
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"apps: registration starting for %@", app]];
            result = [self rh3RunCommand:JBROOT_PATH(@"/usr/bin/uicache") arguments:@[@"-p", path] input:nil timeout:30];
            if (!result) refreshed++;
        }
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"apps: registration summary already_present=%lu refreshed=%lu result=%d",
             (unsigned long)alreadyRegistered, (unsigned long)refreshed, result]];
        return [self rh3ActionStage:@"refresh apps" result:result];
    }
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
        }];
    }];
    return 0;
}

// Return a coarse category, never the path or contents of a package-managed
// file. Unknown (negative) is distinct from absent. No symlink traversal.
static int RH3DiagnosticNodeKind(NSString *path)
{
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (S_ISREG(st.st_mode)) return 1;
    if (S_ISDIR(st.st_mode)) return 2;
    if (S_ISLNK(st.st_mode)) return 3;
    return 4;
}

// For the app bundle's direct .jbroot backlink (depth two), inspect the
// symlink itself without dereferencing it into another container.
// -1=unreadable, 0=missing, 1=exact ../.., 2=wrong target/type.
static int RH3DiagnosticAppBacklink(NSString *bundle)
{
    NSString *path = [bundle stringByAppendingPathComponent:@".jbroot"];
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0)
        return errno == ENOENT ? 0 : -1;
    if (!S_ISLNK(st.st_mode)) return 2;
    char target[PATH_MAX] = {0};
    ssize_t n = readlink(path.fileSystemRepresentation, target, sizeof(target) - 1);
    if (n < 0) return -1;
    target[n] = '\0';
    return strcmp(target, "../..") == 0 ? 1 : 2;
}

// 1=Mach-O/FAT header; 0=other; -1=unavailable/unsafe to read. Metadata
// only: this deliberately does not assert CodeDirectory or trustcache validity.
static int RH3DiagnosticMachMagic(NSString *path)
{
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st = {0};
    uint32_t magic = 0;
    int valid = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size >= sizeof(magic) &&
                pread(fd, &magic, sizeof(magic), 0) == sizeof(magic);
    close(fd);
    if (!valid) return -1;
    return magic == MH_MAGIC || magic == MH_CIGAM ||
           magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
           magic == FAT_MAGIC || magic == FAT_CIGAM ||
           magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64;
}

// Read-only diagnosis for hardware where NewTerm and SSH are inaccessible.
// Never start sshd, write launchd state, rebuild databases, or log file paths.
- (int)diagnoseRootHideRuntime
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    int result = [self rh3PerformPrivilegedAction:^int {
        NSError *rootError = nil;
        NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
        const char *serverRoot = jbclient_get_jbroot();
        if (rootError || !root || !serverRoot ||
            ![RH3CanonicalAppPath(root) isEqual:RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot])])
            return EPERM;
        struct stat statInfo = {0};
        int primaryResult = lstat([root stringByAppendingPathComponent:@"basebin/.safe_mode"].fileSystemRepresentation,
                                  &statInfo);
        int primaryReadError = primaryResult == 0 ? 0 : errno;
        BOOL primarySafeMode = primaryResult == 0;
        BOOL primaryUnknown = primaryResult == 0
            ? (!S_ISREG(statInfo.st_mode) || statInfo.st_uid != 0)
            : primaryReadError != ENOENT;
        NSString *secondary = [@"/private/var/mobile/Containers/Shared/AppGroup"
                               stringByAppendingPathComponent:root.lastPathComponent];
        bool watchdogLatched = true; // Fail closed on an unreadable latch.
        int latchResult = rh3_tweak_watchdog_latched(root.fileSystemRepresentation,
                                                    secondary.fileSystemRepresentation, &watchdogLatched);
        BOOL watchdogUnknown = latchResult != 0;
        BOOL effectiveUnknown = primaryUnknown || (!primarySafeMode && watchdogUnknown);
        BOOL marker = primarySafeMode || watchdogLatched || primaryUnknown || watchdogUnknown;
        BOOL loader = lstat([root stringByAppendingPathComponent:@"usr/lib/TweakLoader.dylib"].fileSystemRepresentation,
                            &statInfo) == 0 && (S_ISREG(statInfo.st_mode) || S_ISLNK(statInfo.st_mode));
        BOOL newTerm = NO;
        for (NSString *name in @[@"NewTerm.app", @"NewTerm2.app", @"NewTerm3.app"]) {
            NSString *bundle = [[root stringByAppendingPathComponent:@"Applications"] stringByAppendingPathComponent:name];
            if (lstat(bundle.fileSystemRepresentation, &statInfo) == 0 && S_ISDIR(statInfo.st_mode)) {
                newTerm = YES;
                break;
            }
        }
        BOOL sshd = lstat([root stringByAppendingPathComponent:@"usr/sbin/sshd"].fileSystemRepresentation,
                          &statInfo) == 0 && S_ISREG(statInfo.st_mode);
        BOOL sshdExecutable = sshd &&
            access([root stringByAppendingPathComponent:@"usr/sbin/sshd"].fileSystemRepresentation, X_OK) == 0;
        BOOL sshConfig = lstat([root stringByAppendingPathComponent:@"etc/ssh/sshd_config"].fileSystemRepresentation,
                               &statInfo) == 0 && S_ISREG(statInfo.st_mode);
        NSUInteger hostKeys = 0;
        for (NSString *key in @[@"ssh_host_ed25519_key", @"ssh_host_ecdsa_key", @"ssh_host_rsa_key"]) {
            NSString *path = [[root stringByAppendingPathComponent:@"etc/ssh"] stringByAppendingPathComponent:key];
            if (lstat(path.fileSystemRepresentation, &statInfo) == 0 &&
                S_ISREG(statInfo.st_mode) && statInfo.st_size > 0) hostKeys++;
        }
        NSError *listingError = nil;
        NSArray<NSString *> *daemons = [NSFileManager.defaultManager contentsOfDirectoryAtPath:
            [root stringByAppendingPathComponent:@"Library/LaunchDaemons"] error:&listingError];
        NSUInteger sshPlists = 0;
        NSUInteger sshPlistProgramRooted = 0, sshPlistProgramAccessible = 0;
        for (NSString *name in daemons) {
            NSString *lower = name.lowercaseString;
            // The donor contains us.diatr.shshd.plist (SHSH blobs daemon),
            // which is NOT OpenSSH and must not count as an SSH server.
            if ([[lower pathExtension] isEqualToString:@"plist"] &&
                [lower containsString:@"ssh"] && ![lower containsString:@"shsh"]) {
                sshPlists++;
                NSString *plistPath = [[root stringByAppendingPathComponent:@"Library/LaunchDaemons"]
                                       stringByAppendingPathComponent:name];
                NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:plistPath];
                NSString *program = [plist[@"Program"] isKindOfClass:[NSString class]] ? plist[@"Program"] : nil;
                if (!program) {
                    NSArray *arguments = [plist[@"ProgramArguments"] isKindOfClass:[NSArray class]] ? plist[@"ProgramArguments"] : nil;
                    if (arguments.count && [arguments[0] isKindOfClass:[NSString class]]) program = arguments[0];
                }
                if (program.length && [program hasPrefix:[root stringByAppendingString:@"/"]])
                    sshPlistProgramRooted++;
                if (program.length && access(program.fileSystemRepresentation, X_OK) == 0)
                    sshPlistProgramAccessible++;
            }
        }
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"runtime: tweak_safe_mode=%d tweak_primary_safe_mode=%d tweak_watchdog_latched=%d tweak_status_unknown=%d primary_errno=%d latch_error=%d tweak_loader_present=%d newterm_bundle_present=%d sshd_binary_present=%d ssh_plists=%lu daemon_listing_ok=%d; presence is not running state",
             marker, primarySafeMode, watchdogUnknown ? -1 : (int)watchdogLatched, effectiveUnknown,
             primaryReadError, latchResult, loader, newTerm, sshd,
             (unsigned long)sshPlists, daemons != nil && listingError == nil]];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"runtime: sshd_executable=%d ssh_config_present=%d ssh_host_key_files=%lu ssh_launch_program_rooted=%lu ssh_launch_program_accessible=%lu; no server started",
             sshdExecutable, sshConfig, (unsigned long)hostKeys,
             (unsigned long)sshPlistProgramRooted, (unsigned long)sshPlistProgramAccessible]];
        return 0;
    }];
    return [self rh3ActionStage:@"read-only tweak/terminal/SSH diagnosis" result:result];
}

// One action and a persistent report. NEVER trustcache, patch, create a
// test process or modify security state for diagnosis. The interactive
// tweak injection test is a separate opt-in operation and is not invoked.
// Keep going if any section returns unavailable, including a failed jailbreak.
- (int)diagnoseRootHideComprehensive
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    DOUIManager *log = [DOUIManager sharedInstance];
    [log rh3RecordDiagnosticStage:@"=== RH3 FULL DIAG BEGIN: existing installation; no repair/reboot ==="];
    [log rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"full diag: app_jailbroken=%d rootHidePort=1; status is not proof of functional jailbreak",
         (int)self.isJailbroken]];

    NSArray<NSArray<NSString *> *> *apps = @[
        @[@"RootHide", @"RootHide.app"],
        @[@"Sileo", @"Sileo.app"],
        @[@"Zebra", @"Zebra.app"],
        @[@"NewTerm", @"NewTerm.app"],
        @[@"NewTerm2", @"NewTerm2.app"],
        @[@"NewTerm3", @"NewTerm3.app"]
    ];
    NSMutableArray<NSDictionary *> *appSnapshots = [NSMutableArray array];
    int inventory = [self rh3PerformPrivilegedAction:^int {
        NSError *error = nil;
        NSString *root = [DOBootstrapper rootHideExistingRootWithError:&error];
        const char *serverRoot = jbclient_get_jbroot();
        if (error || !root || !serverRoot ||
            ![RH3CanonicalAppPath(root) isEqualToString:
              RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot])]) {
            [log rh3RecordDiagnosticStage:@"full diag: active hidden root identity=unverified; inventory skipped"];
            return EPERM;
        }
        [log rh3RecordDiagnosticStage:@"full diag: hidden root identity=verified; inventory read-only; no private paths logged"];
        // Names here are fixed component labels, never filesystem-derived.
        // Classification: -1 unknown, 0 absent, 1 regular, 2 directory,
        // 3 symlink (not followed), 4 other; macho: -1 unavailable, 0 no, 1 yes.
        NSArray<NSArray<NSString *> *> *components = @[
            @[@"launchdhook", @"basebin/launchdhook.dylib"],
            // dyldhook is linked into the generated private dyld image;
            // a separate dyldhook.dylib is not required or expected here.
            @[@"private_dyld", @"basebin/.fakelib/dyld"],
            @[@"systemhook", @"basebin/systemhook.dylib"],
            @[@"jailbreakd", @"basebin/jailbreakd"],
            @[@"tweakprobe", @"basebin/rh3tweakprobe"],
            @[@"TweakLoader", @"usr/lib/TweakLoader.dylib"],
            @[@"sshd", @"usr/sbin/sshd"],
            @[@"login_usr", @"usr/bin/login"],
            @[@"login_bin", @"bin/login"],
            @[@"launchctl", @"usr/bin/launchctl"],
            @[@"dpkg_database", @"var/lib/dpkg/status"],
            @[@"RootHide_manager", @"Applications/RootHide.app"],
            @[@"Sileo_bundle", @"Applications/Sileo.app"],
            @[@"Zebra_bundle", @"Applications/Zebra.app"],
            @[@"NewTerm_bundle", @"Applications/NewTerm.app"],
            @[@"NewTerm2_bundle", @"Applications/NewTerm2.app"],
            @[@"NewTerm3_bundle", @"Applications/NewTerm3.app"],
            @[@"LaunchDaemons_directory", @"Library/LaunchDaemons"],
            @[@"safe_mode_marker", @"basebin/.safe_mode"],
            @[@"AppGroup_directory", @"var/mobile/Containers/Shared/AppGroup"]
        ];
        for (NSArray<NSString *> *component in components) {
            NSString *path = [root stringByAppendingPathComponent:component[1]];
            int kind = RH3DiagnosticNodeKind(path);
            int macho = kind == 1 ? RH3DiagnosticMachMagic(path) : -1;
            struct stat st = {0};
            int metaErr = lstat(path.fileSystemRepresentation, &st) == 0 ? 0 : errno;
            [log rh3RecordDiagnosticStage:[NSString stringWithFormat:
                @"full diag: component=%@ kind=%d errno=%d uid0=%d gid0=%d mode_octal=%03o nlink_single=%d macho_magic=%d (metadata only; no trust proof)",
                component[0], kind, metaErr, metaErr ? -1 : st.st_uid == 0,
                metaErr ? -1 : st.st_gid == 0, metaErr ? 0 : (unsigned)(st.st_mode & 0777),
                metaErr ? -1 : st.st_nlink == 1, macho]];
        }
        // Capture app filesystem evidence BEFORE drop_root/restore-sandbox.
        // Keep LaunchServices IPC outside this privileged callback. An app's
        // vendor UID (often mobile=501) is not a reason to claim a missing
        // bundle, nor permission to trust it for privileged execution.
        for (NSArray<NSString *> *entry in apps) {
            NSString *bundle = [[root stringByAppendingPathComponent:@"Applications"]
                                stringByAppendingPathComponent:entry[1]];
            NSString *plist = [bundle stringByAppendingPathComponent:@"Info.plist"];
            struct stat bundleSt = {0}, plistSt = {0};
            int bundleError = lstat(bundle.fileSystemRepresentation, &bundleSt) == 0 ? 0 : errno;
            BOOL bundleVerified = bundleError == 0 && S_ISDIR(bundleSt.st_mode);
            int plistError = bundleVerified
                ? (lstat(plist.fileSystemRepresentation, &plistSt) == 0 ? 0 : errno) : -1;
            BOOL plistRegular = plistError == 0 && S_ISREG(plistSt.st_mode) &&
                plistSt.st_size > 0 && plistSt.st_size <= 65536 && plistSt.st_nlink == 1;
            NSDictionary *info = plistRegular ? [NSDictionary dictionaryWithContentsOfFile:plist] : nil;
            BOOL plistVerified = info != nil;
            NSString *identifier = [info[@"CFBundleIdentifier"] isKindOfClass:NSString.class]
                ? info[@"CFBundleIdentifier"] : nil;
            NSString *executable = [info[@"CFBundleExecutable"] isKindOfClass:NSString.class]
                ? info[@"CFBundleExecutable"] : nil;
            BOOL validID = identifier.length > 0 && identifier.length <= 256 &&
                [identifier rangeOfCharacterFromSet:
                    [[NSCharacterSet characterSetWithCharactersInString:
                        @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-_"] invertedSet]].location == NSNotFound;
            BOOL validExecutable = executable.length > 0 && executable.length <= 128 &&
                [executable.lastPathComponent isEqualToString:executable];
            int binaryMagic = validExecutable
                ? RH3DiagnosticMachMagic([bundle stringByAppendingPathComponent:executable]) : -1;
            int backlink = bundleVerified ? RH3DiagnosticAppBacklink(bundle) : -1;
            [appSnapshots addObject:@{
                @"name": entry[0], @"bundle": bundle, @"identifier": validID ? identifier : @"",
                @"bundle_verified": @(bundleVerified), @"plist_verified": @(plistVerified),
                @"bundle_errno": @(bundleError), @"plist_errno": @(plistError),
                @"bundle_uid0": @(bundleVerified ? (int)(bundleSt.st_uid == 0) : -1),
                @"plist_uid0": @(plistError == 0 ? (int)(plistSt.st_uid == 0) : -1),
                @"id_valid": @(validID), @"macho": @(binaryMagic), @"backlink": @(backlink)
            }];
        }
        return 0;
    }];
    [log rh3RecordDiagnosticStage:[NSString stringWithFormat:@"full diag: inventory result=%d", inventory]];

    // Launch Services can be queried without re-registering icons or bundles.
    // Failure to observe a proxy is not proof that the app is absent.
    for (NSDictionary *facts in appSnapshots) {
        NSString *identifier = facts[@"identifier"];
        NSString *bundle = facts[@"bundle"];
        BOOL validID = [facts[@"id_valid"] boolValue];
        LSApplicationProxy *proxy = validID ? [LSApplicationProxy applicationProxyForIdentifier:identifier] : nil;
        int registrationMatches = inventory || !validID ? -1 :
            (proxy && [RH3CanonicalAppPath(proxy.bundleURL.path) isEqualToString:RH3CanonicalAppPath(bundle)]) ? 1 : 0;
        [log rh3RecordDiagnosticStage:[NSString stringWithFormat:
            @"full diag: app=%@ bundle_verified=%d plist_verified=%d bundle_errno=%d plist_errno=%d bundle_uid0=%d plist_uid0=%d id_valid=%d executable_macho=%d backlink=%d registered_active_root=%d (not visibility=absence; no identifiers/paths exported)",
            facts[@"name"], [facts[@"bundle_verified"] intValue], [facts[@"plist_verified"] intValue],
            [facts[@"bundle_errno"] intValue], [facts[@"plist_errno"] intValue],
            [facts[@"bundle_uid0"] intValue], [facts[@"plist_uid0"] intValue],
            validID, [facts[@"macho"] intValue], [facts[@"backlink"] intValue], registrationMatches]];
    }
    if (appSnapshots.count == 0)
        [log rh3RecordDiagnosticStage:@"full diag: app inventory=unavailable; active root or privilege validation failed (not absence)"];

    int runtime = [self diagnoseRootHideRuntime];
    [log rh3RecordDiagnosticStage:[NSString stringWithFormat:@"full diag: safe-mode/SSH/NewTerm runtime result=%d", runtime]];
    int ssh = [self diagnoseRootHideOpenSSHSocket];
    [log rh3RecordDiagnosticStage:[NSString stringWithFormat:@"full diag: launchd SSH live job result=%d; no connection sent", ssh]];
    [log rh3RecordDiagnosticStage:
        @"full diag: tweak_load_proof=not_measured probe=skipped_non_mutating "
        @"(historical probe exit codes, if any, appear in boot history; "
        @"no trustcache edits or child patching on this action)"];
    [log rh3RecordDiagnosticStage:
        @"full diag: signature_cdhash_trustcache=not_measured "
        @"dyld_mapping=not_measured xpcproxy_exec=not_measured "
        @"ssh_banner=not_measured login_exec=not_measured "
        @"manager_ui=not_measured; do not infer success from file presence"];
    [log rh3RecordDiagnosticStage:[NSString stringWithFormat:
        @"=== RH3 FULL DIAG END: inventory=%d runtime=%d ssh=%d tweak=skipped_readonly; no repair/trustcache/child_patch ===",
        inventory, runtime, ssh]];
    // Never mark the device validated, even if all local probes succeed.
    return inventory ? inventory : runtime ? runtime : ssh;
}

// Explicit, opt-in repair for the OpenSSH socket job installed later by the
// package manager. The donor's us.diatr.shshd job is unrelated (SHSH blobs).
// Never write to /etc or /usr on the stock OS, load a service, or change
// passwords. The original XPC hook did not affect the live launchd job on
// r165; opt-in recovery persists ONLY Program/ProgramArguments with a backup.
- (int)repairRootHideSSH
{
    // The interactive, separately confirmed repair retains its original
    // capability to provision a missing ED25519 host key.
    return [self rh3RepairRootHideSSHAllowKeyGeneration:YES installerPhase:NO];
}

// The RootHide 1900 donor archive has no OpenSSH daemon, sshd_config, SSH
// socket plist or ssh-keygen. The historical pre-import repair therefore
// returned ENOENT before it could do anything useful. Install only the three
// pinned, offline packages inside an already selected *active* hidden root.
// The server is a reproducible derivative whose extrainst_/prerm do nothing;
// its default config rejects password logins until credentials are explicitly
// provisioned. There is NO package-network access, shell invocation, global
// code-signing bypass, stock /etc write or premature service activation here.
- (int)rh3InstallPinnedOpenSSHBeforeImport
{
    if (NSProcessInfo.processInfo.operatingSystemVersion.majorVersion != 16)
        return ENOTSUP; // Only the pinned bootstrap 1900 packages have been audited.
    NSError *rootError = nil;
    NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
    NSString *active = RH3SSHRootForPhase(YES);
    if (rootError || !root || !active ||
        ![RH3CanonicalAppPath(root) isEqualToString:RH3CanonicalAppPath(active)])
        return EPERM;

    NSArray<NSDictionary<NSString *, NSString *> *> *packages = @[
        @{ @"name":@"roothide_ssh_client_1900.deb", @"package":@"openssh-client",
           @"sha":@"f178c962e65862f5c42bd7317cd234b0f61c5e374901a8811a5e89141d4b7f08" },
        @{ @"name":@"roothide_ssh_sftp_1900.deb", @"package":@"openssh-sftp-server",
           @"sha":@"07670c829ba94722ab69a8457363c0eb737c2e9951cb558668d0ce724a529431" },
        @{ @"name":@"roothide_ssh_server_safe_1900.deb", @"package":@"openssh-server",
           @"sha":@"ccd27b95690071f181dfb3869d59b721efa1e27e0ab6f0c8c5937f29e9bd7bfd" },
    ];
    // The r211 attempt can leave client installed and the next package
    // unpacked/absent. Dpkg owns the recovery state; reinstalling all three
    // packages could overwrite an existing sshd_config or user-owned files.
    // Permit only exact pinned receipts and validate the package's OWN files
    // and dpkg .list before deciding how to complete each package.
    enum { RH3SSHAbsent = 0, RH3SSHInstalled = 1,
           RH3SSHUnpacked = 2, RH3SSHHalfConfigured = 3 };
    NSArray<NSArray<NSString *> *> *footprints = @[
        @[@"etc/ssh/ssh_config", @"usr/bin/ssh-keygen"],
        @[@"usr/libexec/sftp-server"],
        @[@"usr/sbin/sshd", @"etc/ssh/sshd_config",
          @"Library/LaunchDaemons/com.openssh.sshd.plist"]
    ];
    // Existing host keys are NEVER package payloads. They remain authoritative
    // and are checked separately before any absent key is generated.
    NSString *infoDirectoryPath = [root stringByAppendingPathComponent:@"Library/dpkg/info"];
    for (NSString *suffix in @[@"Library", @"Library/dpkg", @"Library/dpkg/info",
                               @"etc", @"usr", @"usr/bin", @"usr/libexec", @"usr/sbin",
                               @"Library/LaunchDaemons", @"etc/ssh"]) {
        int dir = open([root stringByAppendingPathComponent:suffix].fileSystemRepresentation,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dir < 0) {
            // etc/ssh is absent on a pristine 1900 bootstrap.
            if (errno == ENOENT && [suffix isEqualToString:@"etc/ssh"]) continue;
            return errno;
        }
        struct stat st = {0};
        int err = fstat(dir, &st) ? errno : 0;
        close(dir);
        BOOL trustedLibrary = [suffix isEqualToString:@"Library"] &&
                              st.st_gid == 0 && (st.st_mode & 0777) == 0775;
        if (err) return err;
        if (!S_ISDIR(st.st_mode) || st.st_uid != 0 || (st.st_mode & S_IWOTH) ||
            ((st.st_mode & S_IWGRP) && !trustedLibrary)) return EPERM;
    }
    int infoDirectory = open(infoDirectoryPath.fileSystemRepresentation,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (infoDirectory < 0) return errno;
    // All reads use O_NOFOLLOW and bounded, root-owned inputs. Fail closed on
    // any duplicate stanza, another package version, or an ambiguous dpkg
    // state such as half-installed, triggers-pending or config-files.
    NSMutableArray<NSNumber *> *states = [NSMutableArray new];
    NSString *statusPath = [root stringByAppendingPathComponent:@"Library/dpkg/status"];
    int statusFD = open(statusPath.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (statusFD < 0) { int err = errno; close(infoDirectory); return err; }
    struct stat statusInfo = {0};
    int statusError = fstat(statusFD, &statusInfo) ? errno : 0;
    if (!statusError && (!S_ISREG(statusInfo.st_mode) || statusInfo.st_uid != 0 ||
        statusInfo.st_nlink != 1 || (statusInfo.st_mode & 022) ||
        statusInfo.st_size < 128 || statusInfo.st_size > 512 * 1024)) statusError = EPERM;
    NSMutableData *statusBytes = statusError ? nil : [NSMutableData dataWithLength:(NSUInteger)statusInfo.st_size];
    if (!statusError && !statusBytes) statusError = ENOMEM;
    NSUInteger offset = 0;
    while (!statusError && offset < statusBytes.length) {
        ssize_t amount = pread(statusFD, (uint8_t *)statusBytes.mutableBytes + offset,
                               statusBytes.length - offset, (off_t)offset);
        if (amount > 0) offset += (NSUInteger)amount;
        else if (amount < 0 && errno == EINTR) continue;
        else statusError = amount == 0 ? EIO : errno;
    }
    close(statusFD);
    if (statusError) { close(infoDirectory); return statusError; }
    NSString *status = [[NSString alloc] initWithData:statusBytes encoding:NSUTF8StringEncoding];
    if (!status) { close(infoDirectory); return EILSEQ; }
    NSArray<NSString *> *records = [status componentsSeparatedByString:@"\n\n"];
    NSUInteger installed = 0;
    int inventoryError = 0;
    // Fixed, bounded diagnostics: never log a status record, manifest text,
    // root path, contents, or user configuration. The first unsafe condition
    // remains fatal, but identifies exactly which package and guard rejected
    // it (receipt_mask=3 by itself cannot identify that guard).
    const char *const packageTags[] = { "client", "sftp", "server" };
    for (NSUInteger i = 0; i < packages.count && !inventoryError; i++) {
        NSDictionary *package = packages[i];
        NSString *prefix = [@"Package: " stringByAppendingFormat:@"%@\n", package[@"package"]];
        NSUInteger matches = 0;
        NSInteger state = RH3SSHAbsent;
        const char *inventoryReason = "verified";
        NSUInteger inventoryItem = 0;
        for (NSString *record in records) {
            if (![record hasPrefix:prefix]) continue;
            if (++matches != 1) {
                inventoryError = EEXIST;
                inventoryReason = "duplicate_receipt";
                break;
            }
            NSString *fields = [record stringByAppendingString:@"\n"];
            if (![fields containsString:@"\nVersion: 9.2p1\n"]) {
                inventoryError = EEXIST;
                inventoryReason = "version_mismatch";
                break;
            }
            if (![fields containsString:@"\nArchitecture: iphoneos-arm64e\n"]) {
                inventoryError = EEXIST;
                inventoryReason = "architecture_mismatch";
                break;
            }
            if ([fields containsString:@"\nStatus: install ok installed\n"])
                state = RH3SSHInstalled;
            else if ([fields containsString:@"\nStatus: install ok unpacked\n"])
                state = RH3SSHUnpacked;
            else if ([fields containsString:@"\nStatus: install ok half-configured\n"])
                state = RH3SSHHalfConfigured;
            else {
                inventoryError = EEXIST;
                inventoryReason = "unsupported_receipt_state";
                break;
            }
        }
        if (inventoryError) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"SSH inventory: package=%s state=untrusted item=0 reason=%s error=%d",
                 packageTags[i], inventoryReason, inventoryError]];
            break;
        }
        if (state == RH3SSHInstalled) installed++;
        NSString *listName = [package[@"package"] stringByAppendingString:@".list"];
        int listFD = openat(infoDirectory, listName.fileSystemRepresentation,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        NSData *listBytes = nil;
        if (state == RH3SSHAbsent) {
            if (listFD >= 0) {
                inventoryError = EEXIST;
                inventoryReason = "absent_receipt_has_list";
            } else if (errno != ENOENT) {
                inventoryError = errno;
                inventoryReason = "absent_receipt_list_probe";
            }
        } else {
            struct stat listInfo = {0};
            if (listFD < 0) {
                inventoryError = EEXIST;
                inventoryReason = errno == ENOENT ? "installed_receipt_list_missing" : "installed_receipt_list_open";
            }
            else if (fstat(listFD, &listInfo) || !S_ISREG(listInfo.st_mode) ||
                     listInfo.st_uid != 0 || listInfo.st_nlink != 1 ||
                     (listInfo.st_mode & 022) || listInfo.st_size < 32 ||
                     listInfo.st_size > 65536) {
                inventoryError = EEXIST;
                inventoryReason = "installed_receipt_list_metadata";
            }
            else listBytes = RH3SSHReadBounded(listFD, listInfo.st_size);
            if (!inventoryError && !listBytes) {
                inventoryError = EIO;
                inventoryReason = "installed_receipt_list_read";
            }
        }
        if (listFD >= 0) close(listFD);
        NSString *list = listBytes ?
            [[[NSString alloc] initWithData:listBytes encoding:NSUTF8StringEncoding]
                stringByAppendingString:@"\n"] : nil;
        if (!inventoryError && state != RH3SSHAbsent && !list) {
            inventoryError = EILSEQ;
            inventoryReason = "installed_receipt_list_encoding";
        }
        for (NSUInteger fileIndex = 0; fileIndex < footprints[i].count; fileIndex++) {
            if (inventoryError) break;
            NSString *suffix = footprints[i][fileIndex];
            NSString *path = [root stringByAppendingPathComponent:suffix];
            struct stat file = {0};
            int found = lstat(path.fileSystemRepresentation, &file);
            if (state == RH3SSHAbsent) {
                if (found == 0) {
                    inventoryError = EEXIST;
                    inventoryReason = "absent_receipt_file_exists";
                } else if (errno != ENOENT) {
                    inventoryError = errno;
                    inventoryReason = "absent_receipt_file_probe";
                }
            } else {
                // Require a complete manifest line; a substring inside some
                // other filename is not evidence that dpkg owns this inode.
                NSString *listed = [NSString stringWithFormat:@"\n/%@\n", suffix];
                BOOL executable = [suffix hasSuffix:@"/sshd"] ||
                    [suffix hasSuffix:@"/ssh-keygen"] || [suffix hasSuffix:@"/sftp-server"];
                const char *fileReason = NULL;
                if (found != 0) fileReason = "installed_receipt_file_missing";
                else if (!S_ISREG(file.st_mode)) fileReason = "installed_receipt_file_type";
                else if (file.st_uid != 0) fileReason = "installed_receipt_file_owner";
                else if (file.st_mode & 022) fileReason = "installed_receipt_file_permissions";
                else if (executable && !(file.st_mode & S_IXUSR))
                    fileReason = "installed_receipt_file_not_executable";
                else if (file.st_size < 32) fileReason = "installed_receipt_file_size";
                else if (![list containsString:listed]) fileReason = "installed_receipt_manifest_missing_entry";
                if (fileReason) {
                    inventoryReason = fileReason;
                    inventoryError = EEXIST;
                }
            }
            if (inventoryError) inventoryItem = fileIndex + 1;
        }
        // item=0 means receipt/.list; a nonzero item is the fixed ordinal in
        // the pinned package footprint. Never interpolate file or root paths.
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH inventory: package=%s state=%s item=%lu reason=%s error=%d",
             packageTags[i],
             state == RH3SSHAbsent ? "absent" :
             state == RH3SSHInstalled ? "installed" :
             state == RH3SSHUnpacked ? "unpacked" : "half_configured",
             (unsigned long)inventoryItem, inventoryReason, inventoryError]];
        if (!inventoryError) [states addObject:@(state)];
    }
    close(infoDirectory);
    if (inventoryError) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH packages: partial-state inventory conflict (%d); existing files preserved",
             inventoryError]];
        return inventoryError;
    }
    if (installed == packages.count) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH packages: already installed; existing configuration preserved"];
        return 0;
    }
    if (installed != 0) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH packages: recoverable partial receipts installed=%lu; preserving installed packages",
             (unsigned long)installed]];
    }
    NSMutableArray<NSString *> *verifiedPaths = [NSMutableArray new];
    for (NSDictionary *package in packages) {
        NSString *path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:package[@"name"]];
        struct stat info = {0};
        if (lstat(path.fileSystemRepresentation, &info) || !S_ISREG(info.st_mode) ||
            info.st_size < 1024 || info.st_size > 4 * 1024 * 1024) return ENOENT;
        NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:nil];
        if (!data || data.length != (NSUInteger)info.st_size) return EIO;
        unsigned char digest[CC_SHA256_DIGEST_LENGTH] = {0};
        CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
        NSMutableString *hash = [NSMutableString new];
        for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hash appendFormat:@"%02x", digest[i]];
        if (![hash isEqualToString:package[@"sha"]]) return EBADMSG;
        [verifiedPaths addObject:path];
    }
    // Install only genuinely absent packages; configure unpacked ones in
    // dependency order. Never use --force, --configure -a or -i on an installed
    // package (in particular never overwrite an existing sshd_config).
    for (NSUInteger i = 0; i < packages.count; i++) {
        NSInteger state = states[i].integerValue;
        if (state == RH3SSHInstalled) continue;
        const char *name = [packages[i][@"package"] UTF8String];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH packages: verified offline %lu/3; step=%s",
             (unsigned long)(i + 1), state == RH3SSHAbsent ? "install_absent" : "configure_unpacked"]];
        int result = state == RH3SSHAbsent ?
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-i",
                             verifiedPaths[i].fileSystemRepresentation, NULL) :
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "--configure", name, NULL);
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH packages: dpkg step=%lu result=%d; no service started",
             (unsigned long)(i + 1), result]];
        if (result) return result; // Preserve the precise dpkg state for another attempt.
    }
    NSUInteger finalMask = 0;
    int checkResult = RH3SSHReadInstalledReceiptMask(root, &finalMask);
    if (checkResult || finalMask != 7) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH packages: transaction incomplete read=%d receipt_mask=%lu; preserving state",
             checkResult, (unsigned long)finalMask]];
        return checkResult ?: EIO;
    }
    for (NSArray<NSString *> *files in footprints) {
        for (NSString *suffix in files) {
            struct stat file = {0};
            NSString *path = [root stringByAppendingPathComponent:suffix];
            BOOL executable = [suffix hasSuffix:@"/sshd"] ||
                [suffix hasSuffix:@"/ssh-keygen"] || [suffix hasSuffix:@"/sftp-server"];
            if (lstat(path.fileSystemRepresentation, &file) != 0 ||
                !S_ISREG(file.st_mode) || file.st_uid != 0 || (file.st_mode & 022) ||
                (executable && !(file.st_mode & S_IXUSR)) || file.st_size < 32)
                return EIO;
        }
    }
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        @"SSH packages: all three pinned receipts and payload paths verified; existing keys/config untouched"];
    return 0;
}

- (int)rh3GenerateMissingOpenSSHHostKeyBeforeImport
{
    NSString *root = RH3SSHRootForPhase(YES);
    if (!root) return EPERM;
    NSString *directory = [root stringByAppendingPathComponent:@"etc/ssh"];
    int fd = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    struct stat info = {0};
    int err = fstat(fd, &info) ? errno : 0;
    if (!err && (!S_ISDIR(info.st_mode) || info.st_uid != 0 || (info.st_mode & 022))) err = EPERM;
    if (err) { close(fd); return err; }
    struct stat keyInfo = {0};
    if (fstatat(fd, "ssh_host_ed25519_key", &keyInfo, AT_SYMLINK_NOFOLLOW) == 0) {
        close(fd);
        return S_ISREG(keyInfo.st_mode) && keyInfo.st_uid == 0 &&
            !(keyInfo.st_mode & 077) && keyInfo.st_size >= 32 ? 0 : EPERM;
    }
    err = errno;
    struct stat publicInfo = {0};
    BOOL pubExists = fstatat(fd, "ssh_host_ed25519_key.pub", &publicInfo, AT_SYMLINK_NOFOLLOW) == 0;
    close(fd);
    if (err != ENOENT || pubExists) return err == ENOENT ? EEXIST : err;
    NSString *keygen = [root stringByAppendingPathComponent:@"usr/bin/ssh-keygen"];
    NSString *key = [directory stringByAppendingPathComponent:@"ssh_host_ed25519_key"];
    struct stat executable = {0};
    if (lstat(keygen.fileSystemRepresentation, &executable) != 0 ||
        !S_ISREG(executable.st_mode) || executable.st_uid != 0 ||
        !(executable.st_mode & S_IXUSR) || (executable.st_mode & 022)) return ENOENT;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH host key: generating absent ED25519 key in verified hidden root"];
    int result = exec_cmd_trusted(keygen.fileSystemRepresentation, "-q", "-t", "ed25519",
                                  "-N", "", "-f", key.fileSystemRepresentation, NULL);
    if (result) return result;
    fd = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return errno;
    err = fstatat(fd, "ssh_host_ed25519_key", &keyInfo, AT_SYMLINK_NOFOLLOW) ? errno : 0;
    if (!err && (!S_ISREG(keyInfo.st_mode) || keyInfo.st_uid != 0 ||
                 (keyInfo.st_mode & 077) || keyInfo.st_size < 32)) err = EPERM;
    if (!err && fsync(fd)) err = errno;
    close(fd);
    return err;
}

- (int)rh3RepairRootHideSSHAllowKeyGeneration:(BOOL)allowKeyGeneration
                                  installerPhase:(BOOL)installerPhase
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    // Never attempt writes under protected Bundle/Application merely because
    // GET_ROOT and Seatbelt removal succeeded. r167 proved create_backup
    // fails EPERM in precisely this state after a normal app relaunch.
    uint32_t installerFlags = 0;
    int installerStatus = csops(getpid(), CS_OPS_STATUS, &installerFlags, sizeof(installerFlags));
    if (installerStatus != 0 || !(installerFlags & CS_INSTALLER)) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            @"SSH repair: installer right unavailable; no plist write attempted. Use opt-in pre-import preparation."];
        return EPERM;
    }
    // During jailbreak startup the app is ALREADY uid 0 / unsandboxed by
    // elevatePrivileges. Do not issue more sandbox-label or get-root RPCs.
    // Outside that phase, keep the existing explicit privileged-action path.
    if (installerPhase && (geteuid() != 0 || getegid() != 0 ||
        !(installerFlags & CS_PLATFORM_BINARY) || !roothide_is_active()))
        return EPERM;
    __block NSString *root = nil, *plistPath = nil, *configPath = nil;
    __block NSString *keyPath = nil, *publicKeyPath = nil, *sshdPath = nil, *keygenPath = nil;
    __block BOOL needsKey = NO;
    int (^sshPreflight)(void) = ^int {
        NSError *error = nil;
        root = [DOBootstrapper rootHideExistingRootWithError:&error];
        NSString *activeRoot = RH3SSHRootForPhase(installerPhase);
        if (error || !root || !activeRoot ||
            ![RH3CanonicalAppPath(root) isEqualToString:
              RH3CanonicalAppPath(activeRoot)]) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: active hidden root identity not verified"];
            return EPERM;
        }
        // Reject symlinks or writable directories along paths where an
        // attacker could redirect ssh-keygen or the root-owned host key.
        // Checking only lstat(usr/sbin/sshd) would follow a symlink in an
        // intermediate usr or usr/sbin component. Pin their directory types
        // and root ownership before accepting an executable for launchd.
        for (NSString *suffix in @[@"etc", @"etc/ssh", @"usr", @"usr/sbin",
                                   @"Library", @"Library/LaunchDaemons"]) {
            NSString *directory = [root stringByAppendingPathComponent:suffix];
            int fd = open(directory.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (fd < 0) {
                int saved = errno;
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    [NSString stringWithFormat:@"SSH preflight: directory %@ cannot be opened safely (errno=%d)", suffix, saved]];
                return saved;
            }
            struct stat st = {0};
            // Both pinned RootHide donors ship Library/ as 0775 root:wheel.
            // The wheel group is privileged; rejecting this exact layout
            // prevents SSH setup before key generation. Keep every other
            // ancestor non-group-writable and all ancestors non-world-writable.
            int statError = fstat(fd, &st) ? errno : 0;
            BOOL trustedLibrary = [suffix isEqualToString:@"Library"] &&
                st.st_gid == 0 && (st.st_mode & 0777) == 0775;
            BOOL unsafeMode = (st.st_mode & S_IWOTH) ||
                ((st.st_mode & S_IWGRP) && !trustedLibrary);
            int check = statError ? statError :
                (!S_ISDIR(st.st_mode) || st.st_uid != 0 || unsafeMode ? EPERM : 0);
            close(fd);
            if (check) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    [NSString stringWithFormat:@"SSH preflight: directory %@ is not safely owned or writable (result=%d)", suffix, check]];
                return check;
            }
        }
        NSString *daemonsDir = [root stringByAppendingPathComponent:@"Library/LaunchDaemons"];
        NSArray<NSString *> *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:daemonsDir error:&error];
        if (!names || error) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: LaunchDaemons directory listing failed"];
            return EIO;
        }
        for (NSString *name in names) {
            if (![name.pathExtension.lowercaseString isEqualToString:@"plist"] ||
                [name.lowercaseString containsString:@"shsh"]) continue;
            NSString *candidate = [daemonsDir stringByAppendingPathComponent:name];
            struct stat st = {0};
            if (lstat(candidate.fileSystemRepresentation, &st) != 0 ||
                !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_size < 32 || st.st_size > 65536)
                continue;
            NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:candidate];
            if (![dict[@"Label"] isEqual:@"com.openssh.sshd"]) continue;
            if (plistPath) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: duplicate OpenSSH socket job"];
                return EEXIST; // Ambiguous OpenSSH service: don't guess.
            }
            if (![dict[@"Sockets"] isKindOfClass:[NSDictionary class]]) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: OpenSSH socket job invalid"];
                return ENOTSUP;
            }
            plistPath = candidate;
        }
        if (!plistPath) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: verified OpenSSH socket job not found"];
            return ENOENT;
        }
        sshdPath = [root stringByAppendingPathComponent:@"usr/sbin/sshd"];
        keygenPath = [root stringByAppendingPathComponent:@"usr/bin/ssh-keygen"];
        configPath = [root stringByAppendingPathComponent:@"etc/ssh/sshd_config"];
        keyPath = [root stringByAppendingPathComponent:@"etc/ssh/ssh_host_ed25519_key"];
        publicKeyPath = [keyPath stringByAppendingString:@".pub"];
        // A previously provisioned host key is authoritative. In particular,
        // the installer-phase rebase must never require ssh-keygen: it does
        // not generate keys and the package may supply only the server.
        for (NSString *binary in @[sshdPath]) {
            struct stat st = {0};
            if (lstat(binary.fileSystemRepresentation, &st) != 0 ||
                !S_ISREG(st.st_mode) || st.st_uid != 0 || !(st.st_mode & S_IXUSR) ||
                (st.st_mode & (S_IWGRP | S_IWOTH))) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    [NSString stringWithFormat:@"SSH preflight: %@ missing, non-executable, or not root-owned", binary.lastPathComponent]];
                return ENOENT;
            }
        }
        struct stat cfg = {0};
        if (lstat(configPath.fileSystemRepresentation, &cfg) != 0 ||
            !S_ISREG(cfg.st_mode) || cfg.st_uid != 0 ||
            (cfg.st_mode & (S_IWGRP | S_IWOTH))) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: sshd_config missing or untrusted"];
            return ENOENT;
        }
        struct stat keyInfo = {0};
        if (lstat(keyPath.fileSystemRepresentation, &keyInfo) == 0) {
            if (!S_ISREG(keyInfo.st_mode) || keyInfo.st_uid != 0 ||
                (keyInfo.st_mode & 077) != 0 || keyInfo.st_size < 32) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: existing ED25519 host key rejected; unchanged"];
                return EPERM;
            }
        } else if (errno == ENOENT) {
            // ssh-keygen creates both files. Refuse any pre-existing public
            // key path (including symlinks) rather than risk overwriting it.
            struct stat publicInfo = {0};
            if (lstat(publicKeyPath.fileSystemRepresentation, &publicInfo) == 0) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: public host key exists but private key missing; unchanged"];
                return EEXIST;
            }
            if (errno != ENOENT) return errno;
            needsKey = YES;
        }
        else return errno;
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH preflight: verified; key_generation_needed=%d", needsKey]];
        return 0;
    };
    int result = installerPhase ? sshPreflight() : [self rh3PerformPrivilegedAction:sshPreflight];
    if (result) return [self rh3ActionStage:@"SSH repair preflight" result:result];
    if (needsKey && !allowKeyGeneration) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            @"SSH pre-import: host key missing; automatic preparation will not create keys"];
        return ENOENT;
    }
    if (needsKey) {
            // Only the separately confirmed interactive key-generation action
            // needs this executable. Never make its presence a prerequisite
            // for an existing host key or for an installer-phase plist rebase.
            int keygenDirectory = open([root stringByAppendingPathComponent:@"usr/bin"].fileSystemRepresentation,
                                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (keygenDirectory < 0) return errno;
            struct stat keygenDirInfo = {0};
            int keygenDirError = fstat(keygenDirectory, &keygenDirInfo) ? errno : 0;
            close(keygenDirectory);
            if (keygenDirError) return keygenDirError;
            if (!S_ISDIR(keygenDirInfo.st_mode) || keygenDirInfo.st_uid != 0 ||
                (keygenDirInfo.st_mode & (S_IWGRP | S_IWOTH))) return EPERM;
            struct stat keygenInfo = {0};
            if (lstat(keygenPath.fileSystemRepresentation, &keygenInfo) != 0 ||
                !S_ISREG(keygenInfo.st_mode) || keygenInfo.st_uid != 0 ||
                !(keygenInfo.st_mode & S_IXUSR) ||
                (keygenInfo.st_mode & (S_IWGRP | S_IWOTH))) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    @"SSH preflight: key generation requested but trusted ssh-keygen unavailable"];
                return ENOENT;
            }
        // Never use ssh-keygen -A: it writes the stock /etc/ssh directory.
        // -f pins output to the verified, root-owned hidden bootstrap.
        result = [self rh3RunCommand:keygenPath arguments:
            @[@"-q", @"-t", @"ed25519", @"-N", @"", @"-f", keyPath] input:nil timeout:30];
        if (result) return [self rh3ActionStage:@"SSH host key generation" result:result];
    }
    if (!installerPhase) {
        result = [self rh3RunCommand:sshdPath arguments:
            @[@"-t", @"-f", configPath, @"-h", keyPath] input:nil timeout:20];
        if (result) return [self rh3ActionStage:@"SSH configuration validation" result:result];
    } else {
        // The spawn + patch-child XPC are synchronous and have NO true
        // deadline. Do not risk hanging the entire jailbreak for optional
        // SSH. The prior physical r166/r167 sshd -t passed, while this phase
        // rechecks ownership/modes without executing any child process.
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            @"SSH pre-import: static config/key ownership checked; executable sshd -t deferred to avoid a bootstrap-stage stall"];
    }

    int (^sshCommit)(void) = ^int {
        NSError *error = nil;
        NSString *active = [DOBootstrapper rootHideExistingRootWithError:&error];
        NSString *serverRoot = RH3SSHRootForPhase(installerPhase);
        if (error || !active || !serverRoot ||
            ![RH3CanonicalAppPath(active) isEqualToString:RH3CanonicalAppPath(root)] ||
            ![RH3CanonicalAppPath(active) isEqualToString:
              RH3CanonicalAppPath(serverRoot)])
            return EPERM;
        // The binary and configuration ancestors must still be real,
        // root-owned directories when the transaction is committed; lstat
        // on each final file cannot detect a swapped intermediate symlink.
        for (NSString *suffix in @[@"usr", @"usr/sbin", @"etc", @"etc/ssh"]) {
            int ancestor = open([root stringByAppendingPathComponent:suffix].fileSystemRepresentation,
                                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (ancestor < 0) return errno;
            struct stat info = {0};
            int ancestorError = fstat(ancestor, &info) ? errno : 0;
            close(ancestor);
            if (ancestorError) return ancestorError;
            if (!S_ISDIR(info.st_mode) || info.st_uid != 0 ||
                (info.st_mode & (S_IWGRP | S_IWOTH))) return EPERM;
        }
        struct stat keyInfo = {0};
        if (lstat(keyPath.fileSystemRepresentation, &keyInfo) != 0 ||
            !S_ISREG(keyInfo.st_mode) || keyInfo.st_uid != 0 ||
            (keyInfo.st_mode & 077) || keyInfo.st_size < 32) return EPERM;
        struct stat configInfo = {0}, binaryInfo = {0};
        if (lstat(configPath.fileSystemRepresentation, &configInfo) ||
            !S_ISREG(configInfo.st_mode) || configInfo.st_uid != 0 ||
            (configInfo.st_mode & (S_IWGRP | S_IWOTH)) ||
            lstat(sshdPath.fileSystemRepresentation, &binaryInfo) ||
            !S_ISREG(binaryInfo.st_mode) || binaryInfo.st_uid != 0 ||
            !(binaryInfo.st_mode & S_IXUSR) ||
            (binaryInfo.st_mode & (S_IWGRP | S_IWOTH))) return EPERM;
        if (needsKey) {
            struct stat publicInfo = {0};
            if (lstat(publicKeyPath.fileSystemRepresentation, &publicInfo) != 0 ||
                !S_ISREG(publicInfo.st_mode) || publicInfo.st_uid != 0 ||
                (publicInfo.st_mode & (S_IWGRP | S_IWOTH)) ||
                publicInfo.st_size < 32) return EPERM;
            int directory = open([root stringByAppendingPathComponent:@"etc/ssh"].fileSystemRepresentation,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (directory < 0) return errno;
            int syncResult = fsync(directory) == 0 ? 0 : errno;
            close(directory);
            if (syncResult) return syncResult;
        }
        BOOL changed = NO;
        const char *failedAt = "unknown";
        int writeResult;
        // The interactive repair and the installer-phase preparation can
        // share this manager. Serialize all of the journal/rename protocol,
        // including recovery, within this process. Dpkg is independent and
        // still requires its own native concurrency validation.
        @synchronized (self) {
            writeResult = RH3SSHRebaseInstalledPlist(plistPath, sshdPath, configPath,
                                                     keyPath, &changed, &failedAt);
        }
        NSString *validation = installerPhase
            ? @"SSH pre-import: static config/key ownership checked"
            : @"SSH repair: config/key validated";
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"%@; socket job atomic rebase result=%d changed=%d stage=%s; no service started",
             validation, writeResult, changed, failedAt]];
        return writeResult;
    };
    result = installerPhase ? sshCommit() : [self rh3PerformPrivilegedAction:sshCommit];
    return [self rh3ActionStage:@"SSH socket plist repair (no server started)" result:result];
}

// Candidate privilege window for the protected primary jbroot: after root
// re-randomization and package finalization, before the userspace reboot.
// Launchd's effective import order remains hardware-unverified.
// RootHide's exploit phase has already installed CS_INSTALLER on this process.
// Never turn installer privileges on here; avoid inventing a new XPC bypass.
// An OpenSSH failure is non-fatal to the jailbreak, which preserves recovery.
- (int)prepareRootHideOpenSSHBeforeUserspaceReboot
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    // Only the manually dispatched, jailbreak-and-tweaks-on beta defaults to
    // preparing its key-only SSH service. An explicitly saved NO always wins.
    // Standard builds and the isolated diagnostic remain opt-in by default.
    id savedPolicy = [[DOPreferenceManager sharedManager]
                      preferenceValueForKey:@"rh3SSHInstallerRepairOptIn"];
    BOOL enabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:
                    @"rh3SSHInstallerRepairOptIn" fallback:ROOTHIDE3_SSH_DEFAULT_PREPARE];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH pre-import policy: default=%d explicitly_saved=%d enabled=%d",
         ROOTHIDE3_SSH_DEFAULT_PREPARE, savedPolicy != nil, enabled]];
    if (!enabled) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            @"SSH pre-import: not requested; no job changed"];
        return ECANCELED;
    }
    uint32_t flags = 0;
    int status = csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags));
    if (status != 0 || geteuid() != 0 || getegid() != 0 ||
        !(flags & CS_INSTALLER) || !(flags & CS_PLATFORM_BINARY)) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH pre-import: installer privilege unavailable csops_ok=%d uid0=%d installer=%d platform=%d; job unchanged",
             status == 0, geteuid() == 0 && getegid() == 0,
             status == 0 && !!(flags & CS_INSTALLER),
             status == 0 && !!(flags & CS_PLATFORM_BINARY)]];
        return EPERM;
    }
    // Guard against applying a stale absolute program after a root rotation:
    // the SSH repair queries the server and the verified active root afresh,
    // validates sshd -t/key ownership and persists only the single SSH job.
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        @"SSH pre-import: verified installer phase, repairing selected service"];
    int installResult = [self rh3InstallPinnedOpenSSHBeforeImport];
    if (installResult) return [self rh3ActionStage:@"SSH pre-import pinned package installation" result:installResult];
    int keyResult = [self rh3GenerateMissingOpenSSHHostKeyBeforeImport];
    if (keyResult) return [self rh3ActionStage:@"SSH pre-import host key preparation" result:keyResult];
    // Explicit pre-import consent now permits installing the pinned packages
    // and creating ONLY a missing ED25519 host key. Existing keys are neither
    // rotated nor replaced; the rebase below still has its own safety checks.
    int result = [self rh3RepairRootHideSSHAllowKeyGeneration:NO installerPhase:YES];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH pre-import: result=%d; optional service only, no boot interruption", result]];
    // The opt-in persists: every subsequent jailbreak re-randomizes the root
    // and must refresh Program/-f/-h to that new root before launchd import.
    // The user can disable this independently in Settings at any time.
    return result;
}

// Read the effective launchd disabled override without changing the service.
// A failure, timeout, partial output or unsupported subcommand is unknown.
- (NSString *)rh3OpenSSHDisabledOverrideUsingLaunchctl:(NSString *)binary
{
    int fds[2] = {-1, -1};
    if (pipe(fds) != 0) return @"unknown";
    posix_spawn_file_actions_t actions;
    int result = posix_spawn_file_actions_init(&actions);
    BOOL actionsReady = (result == 0);
    if (!result) result = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, fds[1], STDERR_FILENO);
    if (!result) result = posix_spawn_file_actions_addclose(&actions, fds[0]);
    if (!result) result = posix_spawn_file_actions_addclose(&actions, fds[1]);
    __block pid_t pid = -1;
    if (!result) result = [self rh3PerformPrivilegedAction:^int {
        // Only the already-verified hidden launchctl, never PATH or a shell.
        char *const argv[] = {(char *)binary.fileSystemRepresentation,
                              "print-disabled", "system", NULL};
        char *const cleanEnv[] = {NULL};
        return posix_spawn(&pid, argv[0], &actions, NULL, argv, cleanEnv);
    }];
    if (actionsReady) posix_spawn_file_actions_destroy(&actions);
    close(fds[1]);
    if (result || pid <= 1) { close(fds[0]); return @"unknown"; }

    int flags = fcntl(fds[0], F_GETFL);
    if (flags < 0 || fcntl(fds[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        kill(pid, SIGKILL); // Own diagnostic child only.
        (void)RH3WaitForBootstrapChildStatus(pid, 2, NULL);
        close(fds[0]);
        return @"unknown";
    }
    NSMutableData *capture = [NSMutableData dataWithCapacity:8192];
    const NSUInteger maximum = 128 * 1024;
    BOOL eof = NO, reaped = NO, overflow = NO, timedOut = NO;
    int status = -1;
    struct timespec start = {0}, now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) timedOut = YES;
    while (!timedOut && !overflow && !(eof && reaped)) {
        char buffer[2048];
        for (;;) {
            ssize_t n = read(fds[0], buffer, sizeof(buffer));
            if (n > 0) {
                if ((NSUInteger)n > maximum - capture.length) {
                    overflow = YES;
                    break;
                }
                [capture appendBytes:buffer length:(NSUInteger)n];
            } else if (n == 0) { eof = YES; break; }
            else if (errno == EINTR) continue;
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            else { overflow = YES; break; }
        }
        if (!reaped) {
            pid_t waited = waitpid(pid, &status, WNOHANG);
            if (waited == pid) reaped = YES;
            else if (waited < 0 && errno != EINTR) overflow = YES;
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            now.tv_sec - start.tv_sec >= 10) timedOut = YES;
        if (!eof || !reaped) usleep(40000);
    }
    if (!reaped) {
        kill(pid, SIGKILL); // Never signal the service or launchd.
        (void)RH3WaitForBootstrapChildStatus(pid, 2, &status);
    }
    close(fds[0]);
    if (overflow || timedOut || !eof || !reaped ||
        !WIFEXITED(status) || WEXITSTATUS(status) != 0) return @"unknown";
    NSString *output = [[NSString alloc] initWithData:capture encoding:NSUTF8StringEncoding];
    return output ? RH3SSHParseDisabledOverride(output) : @"unknown";
}

// User-triggered, read-only diagnosis of the *live* launchd socket job.
// Only use the already-installed Procursus launchctl from the active hidden
// root. No shell, service-control operations or TCP connection.
// The child may generate a verbose report: drain continuously, bound capture,
// discard untrusted text and log only whitelisted scalar fields.
- (int)diagnoseRootHideOpenSSHSocket
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH socket diagnosis: read-only launchctl print requested"];
    id savedSSHPreference = [[DOPreferenceManager sharedManager]
                             preferenceValueForKey:@"rh3SSHInstallerRepairOptIn"];
    BOOL sshPreparationEnabled = [[DOPreferenceManager sharedManager]
        boolPreferenceValueForKey:@"rh3SSHInstallerRepairOptIn" fallback:ROOTHIDE3_SSH_DEFAULT_PREPARE];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH socket policy: beta_default=%d saved=%d enabled=%d (read-only)",
         ROOTHIDE3_SSH_DEFAULT_PREPARE, savedSSHPreference != nil, sshPreparationEnabled]];
    __block NSString *root = nil;
    __block int packageStatus = -1;
    __block NSUInteger packageMask = 0;
    __block int executablePresent = -1, configurationPresent = -1, hostKeyPresent = -1;
    __block int onDiskWait = -1;
    __block int onDiskDisabled = -1;
    __block NSUInteger socketCount = 0;
    __block NSUInteger port22Count = 0, port2222Count = 0;
    __block NSString *diskProgram = nil;
    // -1=unknown; 0=false; 1=true. Backup: 0=absent, 1=metadata trusted,
    // 2=present but unexpected metadata, -1=unreadable. No paths are logged.
    __block int directoryTrusted = -1, originalGroupTrusted = -1;
    __block int originalModeTrusted = -1, originalLinksTrusted = -1, backupState = -1;
    // CS_INSTALLER may be present during the initial exploit but absent from
    // the app after its next launch. UID 0 and an unsandboxed label do not
    // establish installer rights in the protected AppBundle container.
    // All probes below are read-only; -1 means no trustworthy observation.
    __block int installerPresent = -1, platformPresent = -1, csopsResult = -1;
    __block int directoryOwnerWritable = -1, directoryImmutable = -1, mountWritable = -1;
    int preflight = [self rh3PerformPrivilegedAction:^int {
        NSError *error = nil;
        root = [DOBootstrapper rootHideExistingRootWithError:&error];
        // The cached jbclient_get_jbroot() may still refer to the previous
        // randomized brand, giving a false EPERM before launchd is inspected.
        NSString *serverRoot = RH3SSHCurrentServerRoot();
        if (error || !root || !serverRoot ||
            ![RH3CanonicalAppPath(root) isEqualToString:
              RH3CanonicalAppPath(serverRoot)]) return EPERM;
        packageStatus = RH3SSHReadInstalledReceiptMask(root, &packageMask);
        struct stat entry = {0};
        NSString *sshd = [root stringByAppendingPathComponent:@"usr/sbin/sshd"];
        executablePresent = lstat(sshd.fileSystemRepresentation, &entry) == 0 &&
                            S_ISREG(entry.st_mode) && entry.st_uid == 0 &&
                            (entry.st_mode & S_IXUSR) ? 1 : 0;
        NSString *config = [root stringByAppendingPathComponent:@"etc/ssh/sshd_config"];
        configurationPresent = lstat(config.fileSystemRepresentation, &entry) == 0 &&
                               S_ISREG(entry.st_mode) && entry.st_uid == 0 ? 1 : 0;
        NSString *key = [root stringByAppendingPathComponent:@"etc/ssh/ssh_host_ed25519_key"];
        hostKeyPresent = lstat(key.fileSystemRepresentation, &entry) == 0 &&
                         S_ISREG(entry.st_mode) && entry.st_uid == 0 &&
                         !(entry.st_mode & 077) && entry.st_size >= 32 ? 1 : 0;
        uint32_t processFlags = 0;
        csopsResult = csops(getpid(), CS_OPS_STATUS, &processFlags, sizeof(processFlags));
        if (csopsResult == 0) {
            installerPresent = !!(processFlags & CS_INSTALLER);
            platformPresent = !!(processFlags & CS_PLATFORM_BINARY);
        }
        NSString *directory = [root stringByAppendingPathComponent:@"Library/LaunchDaemons"];
        NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:&error];
        if (!names || error) return EIO;
        struct stat folder = {0}, backupInfo = {0};
        if (lstat(directory.fileSystemRepresentation, &folder) == 0) {
            directoryTrusted = S_ISDIR(folder.st_mode) && folder.st_uid == 0 &&
                               (folder.st_mode & 022) == 0;
            directoryOwnerWritable = !!(folder.st_mode & S_IWUSR);
            directoryImmutable = !!(folder.st_flags &
                (UF_IMMUTABLE | SF_IMMUTABLE | UF_APPEND | SF_APPEND));
        }
        struct statfs filesystem = {0};
        if (statfs(directory.fileSystemRepresentation, &filesystem) == 0)
            mountWritable = !(filesystem.f_flags & MNT_RDONLY);
        NSString *backupPath = [directory stringByAppendingPathComponent:@".com.openssh.sshd.rh3-original"];
        if (lstat(backupPath.fileSystemRepresentation, &backupInfo) == 0)
            backupState = S_ISREG(backupInfo.st_mode) && backupInfo.st_uid == 0 &&
                          backupInfo.st_gid == 0 && (backupInfo.st_mode & 0777) == 0600 &&
                          backupInfo.st_nlink == 1 ? 1 : 2;
        else if (errno == ENOENT) backupState = 0;
        NSUInteger matches = 0;
        for (NSString *name in names) {
            if (![name.pathExtension.lowercaseString isEqualToString:@"plist"] ||
                [name.lowercaseString containsString:@"shsh"]) continue;
            NSString *candidate = [directory stringByAppendingPathComponent:name];
            struct stat file = {0};
            if (lstat(candidate.fileSystemRepresentation, &file) ||
                !S_ISREG(file.st_mode) || file.st_uid != 0 ||
                file.st_size < 32 || file.st_size > 65536) continue;
            NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:candidate];
            if (![plist[@"Label"] isEqual:@"com.openssh.sshd"]) continue;
            matches++;
            if (matches > 1) return EEXIST;
            originalGroupTrusted = file.st_gid == 0;
            originalModeTrusted = (file.st_mode & 022) == 0;
            originalLinksTrusted = file.st_nlink == 1;
            NSString *program = [plist[@"Program"] isKindOfClass:NSString.class] ? plist[@"Program"] : nil;
            if (program.length && program.length <= 4096) diskProgram = program;
            NSDictionary *sockets = [plist[@"Sockets"] isKindOfClass:NSDictionary.class] ? plist[@"Sockets"] : nil;
            socketCount = sockets.count;
            for (id entry in sockets.allValues)
                RH3SSHCountSocketPorts(entry, &port22Count, &port2222Count);
            NSDictionary *inetd = [plist[@"inetdCompatibility"] isKindOfClass:NSDictionary.class] ? plist[@"inetdCompatibility"] : nil;
            if ([inetd[@"Wait"] isKindOfClass:NSNumber.class]) onDiskWait = [inetd[@"Wait"] boolValue] ? 1 : 0;
            if ([plist[@"Disabled"] isKindOfClass:NSNumber.class])
                onDiskDisabled = [plist[@"Disabled"] boolValue] ? 1 : 0;
        }
        if (matches != 1) return ENOENT;
        return 0;
    }];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH socket receipt: read_result=%d fully_installed_mask=%lu (7=all; 0=none); sshd_trusted=%d config_trusted=%d ed25519_key_trusted=%d (read-only)",
         packageStatus, (unsigned long)packageMask,
         executablePresent, configurationPresent, hostKeyPresent]];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH socket plist: result=%d sockets=%lu port22=%lu port2222=%lu disabled=%d inetd_wait=%d (minus one=unknown)",
         preflight, (unsigned long)socketCount, (unsigned long)port22Count,
         (unsigned long)port2222Count, onDiskDisabled, onDiskWait]];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH socket plist metadata: directory_trusted=%d original_group_trusted=%d original_mode_trusted=%d original_links_trusted=%d backup_state=%d (read-only)",
         directoryTrusted, originalGroupTrusted, originalModeTrusted, originalLinksTrusted, backupState]];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH socket creation policy: csops_ok=%d app_installer=%d app_platform=%d directory_owner_write=%d directory_immutable=%d mount_writable=%d (read-only)",
         csopsResult == 0, installerPresent, platformPresent,
         directoryOwnerWritable, directoryImmutable, mountWritable]];
    if (preflight) return [self rh3ActionStage:@"SSH socket plist diagnosis" result:preflight];

    NSString *binary = [root stringByAppendingPathComponent:@"usr/bin/launchctl"];
    int channel[2] = {-1, -1};
    if (pipe(channel) != 0) return [self rh3ActionStage:@"SSH socket diagnostic pipe" result:errno];
    posix_spawn_file_actions_t actions;
    int result = posix_spawn_file_actions_init(&actions);
    BOOL actionsReady = result == 0;
    if (!result) result = posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, channel[1], STDOUT_FILENO);
    if (!result) result = posix_spawn_file_actions_adddup2(&actions, channel[1], STDERR_FILENO);
    if (!result) result = posix_spawn_file_actions_addclose(&actions, channel[0]);
    if (!result) result = posix_spawn_file_actions_addclose(&actions, channel[1]);

    __block pid_t pid = -1;
    if (!result) result = [self rh3PerformPrivilegedAction:^int {
        // Do not fall back to a PATH lookup or a stock-rootfs executable.
        struct stat executable = {0};
        if (lstat(binary.fileSystemRepresentation, &executable) ||
            !S_ISREG(executable.st_mode) || executable.st_uid != 0 ||
            !(executable.st_mode & S_IXUSR)) return ENOENT;
        // Never trustcache or patch a process for a passive diagnostic.
        // If the installed launchctl cannot execute directly, report its
        // spawn failure instead of changing jailbreak process state.
        char *const argv[] = {(char *)binary.fileSystemRepresentation,
                              "print", "system/com.openssh.sshd", NULL};
        char *const cleanEnv[] = {NULL}; // No injected libraries or private environment.
        return posix_spawn(&pid, argv[0], &actions, NULL, argv, cleanEnv);
    }];
    if (actionsReady) posix_spawn_file_actions_destroy(&actions);
    close(channel[1]);
    if (result || pid <= 1) {
        close(channel[0]);
        return [self rh3ActionStage:@"SSH socket launchctl spawn" result:result ?: ECHILD];
    }

    int flags = fcntl(channel[0], F_GETFL);
    if (flags < 0 || fcntl(channel[0], F_SETFL, flags | O_NONBLOCK) < 0) {
        int saved = errno;
        // Only terminate our own diagnostic child, never a launchd service.
        kill(pid, SIGKILL);
        (void)RH3WaitForBootstrapChildStatus(pid, 2, NULL);
        close(channel[0]);
        return [self rh3ActionStage:@"SSH socket nonblocking capture" result:saved];
    }
    NSMutableData *capture = [NSMutableData dataWithCapacity:4096];
    const NSUInteger maximum = 16384;
    BOOL capped = NO, eof = NO, reaped = NO, timedOut = NO, outputLimit = NO;
    NSUInteger drainedBytes = 0;
    int childStatus = -1, readError = 0;
    struct timespec start = {0}, now = {0};
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        readError = errno;
        timedOut = YES;
    }
    while (!timedOut && !outputLimit && !(eof && reaped)) {
        char buffer[2048];
        for (;;) {
            ssize_t amount = read(channel[0], buffer, sizeof(buffer));
            if (amount > 0) {
                drainedBytes += (NSUInteger)amount;
                if (drainedBytes > 128 * 1024) { outputLimit = YES; capped = YES; break; }
                NSUInteger available = maximum - capture.length;
                NSUInteger keep = MIN((NSUInteger)amount, available);
                if (keep) [capture appendBytes:buffer length:keep];
                if (keep < (NSUInteger)amount) capped = YES;
            } else if (amount == 0) {
                eof = YES;
                break;
            } else if (errno == EINTR) continue;
            else if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            else { readError = errno; eof = YES; break; }
        }
        if (!reaped) {
            pid_t waited = waitpid(pid, &childStatus, WNOHANG);
            if (waited == pid) reaped = YES;
            else if (waited < 0 && errno != EINTR) { readError = errno; reaped = YES; }
        }
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 ||
            now.tv_sec - start.tv_sec >= 10) timedOut = YES;
        if (!eof || !reaped) usleep(40000);
    }
    if (!reaped) {
        // Time-bounded diagnostic only; never signal launchd or sshd.
        kill(pid, SIGKILL);
        (void)RH3WaitForBootstrapChildStatus(pid, 2, &childStatus);
    }
    close(channel[0]);
    int exitCode = reaped && WIFEXITED(childStatus) ? WEXITSTATUS(childStatus) : -1;
    NSString *output = [[NSString alloc] initWithData:capture encoding:NSUTF8StringEncoding] ?: @"";
    NSString *state = RH3SSHPrintScalar(output, @"state", NO);
    NSString *runs = RH3SSHPrintScalar(output, @"runs", YES);
    NSString *lastExit = RH3SSHPrintScalar(output, @"last exit code", YES);
    NSString *lastSignal = RH3SSHPrintScalar(output, @"last terminating signal", YES);
    NSString *servicePID = RH3SSHPrintScalar(output, @"pid", YES);
    NSString *programClass = RH3SSHPrintPathClass(output, @"program", root, @"usr/sbin/sshd");
    NSString *originClass = RH3SSHPrintPathClass(output, @"path", root, @"Library/LaunchDaemons/com.openssh.sshd.plist");
    NSString *liveProgram = RH3SSHPrintPrivatePath(output, @"program");
    NSString *canonicalDisk = RH3CanonicalAppPath(diskProgram);
    NSString *canonicalLive = RH3CanonicalAppPath(liveProgram);
    int programMatchesPlist = canonicalDisk && canonicalLive ? [canonicalDisk isEqualToString:canonicalLive] : -1;
    NSString *diskProgramClass = diskProgram ?
        RH3SSHPrintPathClass([@"program = " stringByAppendingString:diskProgram],
                            @"program", root, @"usr/sbin/sshd") : @"missing";
    NSString *disabledOverride = [self rh3OpenSSHDisabledOverrideUsingLaunchctl:binary];
    // These booleans reflect the human launchctl output only, not whether
    // dyld successfully executed sshd. Neither expected path is logged.
    BOOL configArgSeen = [output containsString:[root stringByAppendingPathComponent:@"etc/ssh/sshd_config"]];
    BOOL keyArgSeen = [output containsString:[root stringByAppendingPathComponent:@"etc/ssh/ssh_host_ed25519_key"]];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"SSH socket launchctl: spawn=0 exit=%d timed_out=%d read_errno=%d bytes=%lu truncated=%d output_limit=%d state=%@ runs=%@ last_exit=%@ last_signal=%@ pid_present=%d program_class=%@ origin_class=%@ disk_program_class=%@ program_matches_plist=%d disabled_override=%@ config_arg_seen=%d key_arg_seen=%d sockets_mentioned=%d (read-only)",
         exitCode, timedOut, readError, (unsigned long)capture.length, capped,
         outputLimit, state, runs, lastExit, lastSignal,
         ![servicePID isEqualToString:@"unknown"], programClass, originClass,
         diskProgramClass, programMatchesPlist, disabledOverride,
         configArgSeen, keyArgSeen,
         [output containsString:@"sockets ="] || [output containsString:@"Sockets ="]]];
    // Preserve command failure separately from the *service's* last exit.
    int code = timedOut ? ETIMEDOUT : outputLimit ? EOVERFLOW : readError ? readError : exitCode < 0 ? ECHILD : exitCode;
    return [self rh3ActionStage:@"SSH socket live launchctl print" result:code];
}

// Never treat presence of TweakLoader as proof of injection. A throwaway
// signed helper checks that systemhook ran AND its dlopen returned non-NULL.
// This does not claim that every third-party tweak works in every process.
- (int)verifyRootHideTweakInjection
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    if (![self isTweakInjectionEnabled])
        return [self rh3ActionStage:@"tweak injection probe refused (safe mode)" result:EBUSY];
    __block NSString *helper = nil;
    int result = [self rh3PerformPrivilegedAction:^int {
        NSError *rootError = nil;
        NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
        const char *serverRoot = jbclient_get_jbroot();
        if (rootError || !root || !serverRoot ||
            ![RH3CanonicalAppPath(root) isEqualToString:
              RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot])]) return EPERM;
        helper = [root stringByAppendingPathComponent:@"basebin/rh3tweakprobe"];
        struct stat st = {0};
        if (lstat(helper.fileSystemRepresentation, &st) != 0 ||
            !S_ISREG(st.st_mode) || st.st_uid != 0 || !(st.st_mode & S_IXUSR)) return ENOENT;
        return 0;
    }];
    if (result) return [self rh3ActionStage:@"tweak injection probe preflight" result:result];
    result = [self rh3RunCommand:helper arguments:@[] input:nil timeout:15];
    return [self rh3ActionStage:@"tweak injection executable probe" result:result];
}

- (void)unregisterJailbreakApps
{
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            NSArray *jailbreakApps = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/Applications") error:nil];
            if (jailbreakApps.count) {
                for (NSString *jailbreakApp in jailbreakApps) {
                    NSString *jailbreakAppPath = [JBROOT_PATH(@"/Applications") stringByAppendingPathComponent:jailbreakApp];
                    exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-u", jailbreakAppPath.fileSystemRepresentation, NULL);
                }
            }
        }];
    }];
}

- (void)reboot
{
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            reboot3(0x8000000000000000, 0);
        }];
    }];
}


- (NSString *)rh3MobilePasswordHash
{
    // Read only the hidden bootstrap's account file; never print the hash.
    int etc = open(JBROOT_PATH("/etc"), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (etc < 0) return nil;
    int fd = openat(etc, "master.passwd", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    close(etc);
    if (fd < 0) return nil;
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != 0 || st.st_size <= 0 || st.st_size > 65536) { close(fd); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size];
    ssize_t count = pread(fd, data.mutableBytes, data.length, 0);
    close(fd);
    if (count != (ssize_t)data.length) return nil;
    NSString *contents = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    for (NSString *line in [contents componentsSeparatedByString:@"\n"]) {
        NSArray *fields = [line componentsSeparatedByString:@":"];
        if (fields.count >= 4 && [fields[0] isEqualToString:@"mobile"] && [fields[2] isEqualToString:@"501"]) return fields[1];
    }
    return nil;
}

- (int)changeMobilePassword:(NSString *)newPassword
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        if (!newPassword.length || [newPassword containsString:@"\n"] || [newPassword containsString:@"\r"] ||
            [newPassword rangeOfString:[NSString stringWithFormat:@"%C", (unichar)0]].location != NSNotFound) return EINVAL;
        // Procursus pw defaults to /etc (the real system directory). The
        // RootHide archive stores its own mobile account in hidden/etc and
        // pw has returned EX_NOUSER=67 when called without an explicit
        // database location. Never mutate the host user database or guess
        // which file a process hook may redirect.
        NSString *hiddenEtc = JBROOT_PATH(@"/etc");
        __block NSString *before = nil;
        int result = [self rh3PerformPrivilegedAction:^int{
            NSError *rootError = nil;
            NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
            NSString *expected = [root stringByAppendingPathComponent:@"etc"];
            if (rootError || !root || ![RH3CanonicalAppPath(expected) isEqualToString:RH3CanonicalAppPath(hiddenEtc)])
                return EPERM;
            int directory = open(hiddenEtc.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (directory < 0) return errno;
            struct stat info = {0};
            int check = fstat(directory, &info) ? errno : ((!S_ISDIR(info.st_mode) || info.st_uid != 0) ? EPERM : 0);
            close(directory);
            if (check) return check;
            before = [self rh3MobilePasswordHash];
            // Source of the on-device error is still unknown: pw returned
            // exit code 1 AFTER spawn/patch. Record only boolean file state,
            // never password hashes, password input or raw account records.
            struct stat fileInfo = {0};
            BOOL masterSafe = lstat([hiddenEtc stringByAppendingPathComponent:@"master.passwd"].fileSystemRepresentation,
                                    &fileInfo) == 0 && S_ISREG(fileInfo.st_mode) && fileInfo.st_uid == 0;
            BOOL passwdPresent = lstat([hiddenEtc stringByAppendingPathComponent:@"passwd"].fileSystemRepresentation,
                                      &fileInfo) == 0 && S_ISREG(fileInfo.st_mode);
            BOOL pwdDbPresent = lstat([hiddenEtc stringByAppendingPathComponent:@"pwd.db"].fileSystemRepresentation,
                                     &fileInfo) == 0 && S_ISREG(fileInfo.st_mode);
            BOOL spwdDbPresent = lstat([hiddenEtc stringByAppendingPathComponent:@"spwd.db"].fileSystemRepresentation,
                                      &fileInfo) == 0 && S_ISREG(fileInfo.st_mode);
            BOOL mkdbExecutable = access(JBROOT_PATH("/usr/sbin/pwd_mkdb"), X_OK) == 0;
            // UID 0 plus an unsandboxed label can still lack CS_INSTALLER
            // after the Dopamine app is relaunched. That right is required to
            // update files in the protected hidden AppBundle. Record only
            // booleans; the password, account record and hashes stay private.
            uint32_t currentFlags = 0;
            int csStatus = csops(getpid(), CS_OPS_STATUS, &currentFlags, sizeof(currentFlags));
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"mobile password write capability: csops_ok=%d installer=%d platform=%d uid0=%d; no privilege change attempted",
                 csStatus == 0, csStatus == 0 && !!(currentFlags & CS_INSTALLER),
                 csStatus == 0 && !!(currentFlags & CS_PLATFORM_BINARY),
                 geteuid() == 0]];
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"mobile password preflight: master_safe=%d passwd_present=%d pwd_db_present=%d spwd_db_present=%d pwd_mkdb_executable=%d mobile_record_present=%d",
                 masterSafe, passwdPresent, pwdDbPresent, spwdDbPresent, mkdbExecutable, before != nil]];
            return before ? 0 : EIO;
        }];
        if (!result) result = [self rh3RunCommand:JBROOT_PATH(@"/usr/sbin/pw") arguments:@[@"-V", hiddenEtc, @"usermod", @"mobile", @"-h", @"0"]
                                          input:[[newPassword stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding] timeout:20];
        if (result) {
            // A command reporting failure could still have modified its DB.
            // Do not assume the old password remained valid or retry blindly.
            (void)[self rh3PerformPrivilegedAction:^int{
                NSString *after = [self rh3MobilePasswordHash];
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    [NSString stringWithFormat:@"mobile password failed-command verification: record_readable=%d hash_changed=%d; no automatic retry",
                     after != nil, before != nil && after != nil && ![after isEqualToString:before]]];
                return 0;
            }];
        }
        if (!result) result = [self rh3PerformPrivilegedAction:^int{
            NSString *after = [self rh3MobilePasswordHash];
            return after.length > 1 && ![after hasPrefix:@"!"] && ![after hasPrefix:@"*"] && ![after isEqualToString:before] ? 0 : EIO;
        }];
        return [self rh3ActionStage:@"mobile password database update" result:result];
    }
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            NSString *dashCommand = [NSString stringWithFormat:@"printf \"%%s\\n\" \"%@\" | %@ usermod 501 -h 0", newPassword, JBROOT_PATH(@"/usr/sbin/pw")];
            exec_cmd(JBROOT_PATH("/usr/bin/dash"), "-c", dashCommand.UTF8String, NULL);
        }];
    }];
    return 0;
}

- (NSError*)updateEnvironment
{
    NSString *newBasebinTarPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"];
    int result = jbclient_platform_stage_jailbreak_update(newBasebinTarPath.fileSystemRepresentation);
    if (result == 0) {
        result = [self rebootUserspace];
        if (result == 0) return nil;
    }
    return [NSError errorWithDomain:@"Dopamine" code:result userInfo:nil];
}

- (void)updateJailbreakFromTIPA:(NSString *)tipaPath
{
    [self spawnJbctlAsRootWithArgs:@[@"update", @"tipa", tipaPath]];
}

- (BOOL)isTweakInjectionEnabled
{
    if ([DOBootstrapper rootHidePortEnabled] && self.isJailbroken) {
        // A sandboxed fileExistsAtPath can report NO even while the hidden
        // RootHide marker exists. That made Settings appear ON while
        // systemhook correctly stayed in safe mode. Read the verified root
        // using the same temporary credentials as the runtime diagnosis.
        __block BOOL markerPresent = YES; // Fail closed on an unreadable root.
        int result = [self rh3PerformPrivilegedAction:^int {
            NSError *rootError = nil;
            NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
            const char *serverRoot = jbclient_get_jbroot();
            if (rootError || !root || !serverRoot ||
                ![RH3CanonicalAppPath(root) isEqualToString:
                  RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot])])
                return EPERM;
            NSString *marker = [root stringByAppendingPathComponent:@"basebin/.safe_mode"];
            struct stat info = {0};
            if (lstat(marker.fileSystemRepresentation, &info) == 0) {
                if (!S_ISREG(info.st_mode) || info.st_uid != 0) return EPERM;
                markerPresent = YES;
                return 0;
            }
            if (errno != ENOENT) return errno;
            markerPresent = NO;
            NSString *secondary = [@"/private/var/mobile/Containers/Shared/AppGroup"
                                   stringByAppendingPathComponent:root.lastPathComponent];
            bool watchdogLatched = true;
            int latchResult = rh3_tweak_watchdog_latched(root.fileSystemRepresentation,
                                                        secondary.fileSystemRepresentation,
                                                        &watchdogLatched);
            if (latchResult) return latchResult;
            if (watchdogLatched) markerPresent = YES;
            return 0;
        }];
        if (result) {
            [self rh3ActionStage:@"read tweak injection state" result:result];
            return NO;
        }
        return !markerPresent;
    }
    return ![[NSFileManager defaultManager] fileExistsAtPath:JBROOT_PATH(@"/basebin/.safe_mode")];
}

- (int)setTweakInjectionEnabled:(BOOL)enabled
{
    NSString *safeModePath = JBROOT_PATH(@"/basebin/.safe_mode");
    if ([DOBootstrapper rootHidePortEnabled]) {
        // Never modify the protected marker from a running Settings action,
        // even if the app unexpectedly retains CS_INSTALLER. A watchdog panic
        // can race with a direct unlink/clear. Only the next controlled
        // installer phase (before PID 1 injection) may apply this request.
        __block BOOL stagedPending = NO;
        __block BOOL unchanged = NO;
        int status = [self rh3PerformPrivilegedAction:^int {
            NSError *rootError = nil;
            NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
            const char *activeRoot = jbclient_get_jbroot();
            if (rootError || !root || !activeRoot ||
                ![RH3CanonicalAppPath(root) isEqualToString:
                  RH3CanonicalAppPath([NSString stringWithUTF8String:activeRoot])] ||
                ![RH3CanonicalAppPath(safeModePath) isEqualToString:
                  RH3CanonicalAppPath([root stringByAppendingPathComponent:@"basebin/.safe_mode"])])
                return EPERM;
            NSString *secondary = [@"/private/var/mobile/Containers/Shared/AppGroup"
                                   stringByAppendingPathComponent:root.lastPathComponent];
            struct stat info = {0};
            int exists = lstat(safeModePath.fileSystemRepresentation, &info) == 0;
            if (!exists && errno != ENOENT) {
                int markerErrno = errno;
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    [NSString stringWithFormat:@"tweaks: marker unreadable, result=%d; refused", markerErrno]];
                return markerErrno;
            }
            if (exists && (!S_ISREG(info.st_mode) || info.st_uid != 0))
                return EPERM;
            bool watchdogLatched = true;
            int latchResult = rh3_tweak_watchdog_latched(root.fileSystemRepresentation,
                                                        secondary.fileSystemRepresentation,
                                                        &watchdogLatched);
            if (latchResult) return latchResult;
            // No protected file operation. Request is confined to this
            // jbrand's pinned, root-owned AppGroup/var directory.
            BOOL needsChange = enabled ? (exists || watchdogLatched) : !exists;
            int pendingResult = needsChange
                ? rh3_tweak_request_stage(root.fileSystemRepresentation,
                                          secondary.fileSystemRepresentation, enabled)
                : rh3_tweak_request_cancel(root.fileSystemRepresentation,
                                           secondary.fileSystemRepresentation);
            if (pendingResult) return pendingResult;
            if (needsChange) {
                stagedPending = YES;
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    @"tweaks: request persisted in AppGroup; protected safe-mode marker unchanged"];
            } else {
                unchanged = YES;
            }
            return 0;
        }];
        if (status == 0 && stagedPending) status = EINPROGRESS;
        if (status == 0 && unchanged) status = EALREADY;
        return [self rh3ActionStage:enabled ? @"enable tweak injection" : @"disable tweak injection"
                                  result:status];
    }
    if ([self isJailbroken]) {
        [self runAsRoot:^{
            [self runUnsandboxed:^{
                if (enabled) {
                    [[NSFileManager defaultManager] removeItemAtPath:safeModePath error:nil];
                }
                else {
                    [[NSData data] writeToFile:safeModePath atomically:YES];
                }
            }];
        }];
    }
    return 0;
}

- (int)cancelRootHideTweakInjectionRequest
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    int status = [self rh3PerformPrivilegedAction:^int {
        NSError *rootError = nil;
        NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
        const char *serverRoot = jbclient_get_jbroot();
        if (rootError || !root || !serverRoot ||
            ![RH3CanonicalAppPath(root) isEqualToString:
              RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot])])
            return EPERM;
        NSString *secondary = [@"/private/var/mobile/Containers/Shared/AppGroup"
                               stringByAppendingPathComponent:root.lastPathComponent];
        // Explicit cancel of the single pending leaf, never the effective
        // .safe_mode marker or watchdog latch. The helper pins both roots.
        return rh3_tweak_request_cancel(root.fileSystemRepresentation,
                                        secondary.fileSystemRepresentation);
    }];
    return [self rh3ActionStage:@"cancel pending tweak request" result:status];
}

- (BOOL)isIDownloadEnabled
{
    __block BOOL isEnabled = NO;
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            NSDictionary *disabledDict = [NSDictionary dictionaryWithContentsOfFile:@"/var/db/com.apple.xpc.launchd/disabled.plist"];
            NSNumber *idownloaddDisabledNum = disabledDict[@"com.opa334.Dopamine.idownloadd"];
            if (idownloaddDisabledNum) {
                isEnabled = ![idownloaddDisabledNum boolValue];
            }
            else {
                isEnabled = NO;
            }
        }];
    }];
    return isEnabled;
}

- (void)setIDownloadEnabled:(BOOL)enabled needsUnsandbox:(BOOL)needsUnsandbox
{
    void (^updateBlock)(void) = ^{
        if (enabled) {
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "enable", "system/com.opa334.Dopamine.idownloadd", NULL);
        }
        else {
            exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "disable", "system/com.opa334.Dopamine.idownloadd", NULL);
        }
    };

    if (needsUnsandbox) {
        [self runAsRoot:^{
            [self runUnsandboxed:updateBlock];
        }];
    }
    else {
        updateBlock();
    }
}

- (void)setIDownloadLoaded:(BOOL)loaded needsUnsandbox:(BOOL)needsUnsandbox
{
    if (loaded) {
        [self setIDownloadEnabled:loaded needsUnsandbox:needsUnsandbox];
    }
    
    void (^updateBlock)(void) = ^{
        if (loaded) {
            exec_cmd(JBROOT_PATH("/usr/bin/launchctl"), "load", JBROOT_PATH("/basebin/LaunchDaemons/com.opa334.Dopamine.idownloadd.plist"), NULL);
        }
        else {
            exec_cmd(JBROOT_PATH("/usr/bin/launchctl"), "unload", JBROOT_PATH("/basebin/LaunchDaemons/com.opa334.Dopamine.idownloadd.plist"), NULL);
        }
    };
    
    if (needsUnsandbox) {
        [self runAsRoot:^{
            [self runUnsandboxed:updateBlock];
        }];
    }
    else {
        updateBlock();
    }
    
    if (!loaded) {
        [self setIDownloadEnabled:loaded needsUnsandbox:needsUnsandbox];
    }
}

- (BOOL)isFakelibMounted
{
    struct statfs fsb;
    if (statfs("/usr/lib", &fsb) != 0) return NO;
    return strcmp(fsb.f_mntonname, "/usr/lib") == 0;
}

- (int)setFakelibMounted:(BOOL)mounted
{
    int r = 0;
    if (mounted != [self isFakelibMounted]) {
        NSString *arg = mounted ? @"mount" : @"unmount";
        r = [self spawnJbctlAsRootWithArgs:@[@"internal", @"fakelib", arg]];
    }
    return r;
}

- (int)setPrivatePrebootProtected:(BOOL)protected
{
    NSString *arg = protected ? @"activate" : @"deactivate";
    return [self spawnJbctlAsRootWithArgs:@[@"internal", @"protection", arg]];
}

- (BOOL)isJailbreakHidden
{
    // RootHide's root is intentionally never advertised through /var/jb.
    // The ordinary Dopamine switch does not control RootHide's hiding.
    if ([DOBootstrapper rootHidePortEnabled]) return YES;
    return ![[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"];
}

- (void)setJailbreakHidden:(BOOL)hidden
{
    // In RootHide mode creating /var/jb exposes the secret .jbroot location,
    // and the normal fake-library/protection toggle can damage this bootstrap.
    if ([DOBootstrapper rootHidePortEnabled]) return;
    if (hidden && ![self isJailbroken] && geteuid() != 0) {
        [self runTrollStoreAction:@"hide-jailbreak"];
        return;
    }
    
    void (^actionBlock)(void) = ^{
        BOOL alreadyHidden = [self isJailbreakHidden];
        if (hidden != alreadyHidden) {
            if (hidden) {
                if ([self isJailbroken]) {
                    [self unregisterJailbreakApps];
                    [self setPrivatePrebootProtected:NO];
                    [self setFakelibMounted:NO];
                    jbclient_platform_set_systemwide_domain_enabled(false);
                }
                [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:nil];
            }
            else {
                [[NSFileManager defaultManager] createSymbolicLinkAtPath:@"/var/jb" withDestinationPath:JBROOT_PATH(@"/") error:nil];
                if ([self isJailbroken]) {
                    jbclient_platform_set_systemwide_domain_enabled(true);
                    [self setFakelibMounted:YES];
                    [self setPrivatePrebootProtected:YES];
                    [self refreshJailbreakApps];
                }
            }
        }
    };
    
    if ([self isJailbroken]) {
        [self runAsRoot:^{
            [self runUnsandboxed:actionBlock];
        }];
    }
    else {
        actionBlock();
    }
}

- (NSString *)accessibleKernelPath
{
    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *kernelcachePath = [[self activePrebootPath] stringByAppendingPathComponent:@"System/Library/Caches/com.apple.kernelcaches/kernelcache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) {
            return kernelcachePath;
        }
        return @"/System/Library/Caches/com.apple.kernelcaches/kernelcache";
    }
    else {
        NSString *kernelInApp = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"kernelcache"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:kernelInApp]) {
            return kernelInApp;
        }
        
        [[DOUIManager sharedInstance] sendLog:@"Downloading Kernel" debug:NO];
        NSString *kernelcachePath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kernelcache"];
        if (![[NSFileManager defaultManager] fileExistsAtPath:kernelcachePath]) {
            if (grab_images([NSHomeDirectory() stringByAppendingPathComponent:@"Documents"]) == false) return nil;
        }
        return kernelcachePath;
    }
}

- (NSString *)accessibleSPTMPath
{
    NSString *sptmInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"sptm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmInAppPath]) {
        return sptmInAppPath;
    }
    
    NSString *sptmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sptm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmInDocsPath]) {
        return sptmInDocsPath;
    }
    
    sptmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/sptm.im4p"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:sptmInDocsPath]) {
        return sptmInDocsPath;
    }

    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *sptmPath = [[self activePrebootPath] stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,SecurePageTableMonitor.img4"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:sptmPath]) {
            return sptmPath;
        }
    }

    return nil;
}

- (NSString *)accessibleTXMPath
{
    NSString *txmInAppPath = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"txm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmInAppPath]) {
        return txmInAppPath;
    }
    
    NSString *txmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/txm.img4"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmInDocsPath]) {
        return txmInDocsPath;
    }
    
    txmInDocsPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/txm.im4p"];
    if ([[NSFileManager defaultManager] fileExistsAtPath:txmInDocsPath]) {
        return txmInDocsPath;
    }

    if ([self isInstalledThroughTrollStore] || getuid() == 0) {
        NSString *txmPath = [[self activePrebootPath] stringByAppendingPathComponent:@"/usr/standalone/firmware/FUD/Ap,TrustedExecutionMonitor.img4"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:txmPath]) {
            return txmPath;
        }
    }

    return nil;
}


- (BOOL)isPACBypassRequired
{
    if (![self isArm64e]) return NO;
    
    if (@available(iOS 15.2, *)) {
        return NO;
    }
    return YES;
}

- (BOOL)isPPLBypassRequired
{
    return [self isArm64e];
}

- (BOOL)isSupported
{
    //cpu_subtype_t cpuFamily = 0;
    //size_t cpuFamilySize = sizeof(cpuFamily);
    //sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
    //if (cpuFamily == CPUFAMILY_ARM_TYPHOON) return false; // A8X is unsupported for now (due to 4k page size)
    
    DOExploitManager *exploitManager = [DOExploitManager sharedManager];
    if ([exploitManager availableExploitsForType:EXPLOIT_TYPE_KERNEL].count) {
        if (![self isPACBypassRequired] || [exploitManager availableExploitsForType:EXPLOIT_TYPE_PAC].count) {
            if (![self isPPLBypassRequired] || [exploitManager availableExploitsForType:EXPLOIT_TYPE_PPL].count) {
                return true;
            }
        }
    }
    
    return false;
}

- (BOOL)deviceSupportsFaceID
{
    if (![LAContext class]) return NO;

    LAContext *myContext = [[LAContext alloc] init];
    NSError *authError = nil;
    if (![myContext canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&authError]) {
        NSLog(@"%@", [authError localizedDescription]);
        return NO;
    }

    return myContext.biometryType == LABiometryTypeFaceID;
}

- (BOOL)deviceSupportsLandscapeBootLogo
{
    struct utsname u;
    uname(&u);
    const char *ipadString = "iPad";

    bool isPad = strncmp(u.machine, ipadString, strlen(ipadString)) == 0;
    return isPad && [self deviceSupportsFaceID];
}

- (NSError *)prepareBootstrap
{
    __block NSError *errOut;
    dispatch_semaphore_t sema = dispatch_semaphore_create(0);
    [_bootstrapper prepareBootstrapWithCompletion:^(NSError *error) {
        errOut = error;
        dispatch_semaphore_signal(sema);
    }];
    dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
    return errOut;
}

- (NSError *)finalizeBootstrap
{
    return [_bootstrapper finalizeBootstrap];
}

- (NSError *)deleteBootstrap
{
    if (![self isJailbroken] && getuid() != 0) {
        int r = [self runTrollStoreAction:@"delete-bootstrap"];
        if ([DOBootstrapper rootHidePortEnabled]) {
            // The legacy TrollStore action returns success even if its child
            // encountered an NSError. Do not falsely report a hidden-root
            // deletion unless the owned root is actually gone.
            if (r != 0) {
                return [NSError errorWithDomain:bootstrapErrorDomain
                                           code:BootstrapErrorCodeFailedReplacing
                                       userInfo:@{NSLocalizedDescriptionKey:
                                           [NSString stringWithFormat:@"RootHide removal helper failed (%d)", r]}];
            }
            NSError *verificationError = nil;
            NSString *remaining = [DOBootstrapper rootHideExistingRootWithError:&verificationError];
            if (verificationError) return verificationError;
            if (remaining) {
                return [NSError errorWithDomain:bootstrapErrorDomain
                                           code:BootstrapErrorCodeFailedReplacing
                                       userInfo:@{NSLocalizedDescriptionKey:
                                           @"RootHide root remains after the removal helper returned"}];
            }
            return nil;
        }
        if (r != 0) {
            // TODO: maybe handle error
        }
        return nil;
    }
    else if ([self isJailbroken]) {
        __block NSError *error;
        [self runAsRoot:^{
            [self runUnsandboxed:^{
                error = [self->_bootstrapper deleteBootstrap];
            }];
        }];
        return error;
    }
    else {
        // Let's hope for the best
        return [_bootstrapper deleteBootstrap];
    }
}

- (NSError *)reinstallPackageManagers
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        __block NSError *error = nil;
        NSArray<NSString *> *packages = [self->_bootstrapper rootHideSelectedManagerPackagesWithError:&error];
        if (!packages) return error;
        NSString *rootHideManager = [self->_bootstrapper rootHideManagerPackageWithError:&error];
        if (!rootHideManager) return error;
        int result = 0;
        // The picker controls Sileo/Zebra. RootHide Manager has its own
        // package and must also be restorable on an existing installation.
        for (NSString *path in [packages arrayByAddingObject:rootHideManager]) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"apps: explicit reinstall starting %@", path.lastPathComponent]];
            // jbctl establishes real uid 0 after the app restores its own
            // credentials. dpkg must not inherit the app's real uid 501.
            result = [self spawnJbctlAsRootWithArgs:@[@"internal", @"install_pkg", path]];
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"apps: explicit reinstall %@ result=%d", path.lastPathComponent, result]];
            if (result) break;
        }
        if (!result) result = [self rh3PerformPrivilegedAction:^int{
            error = [self->_bootstrapper repairRootHideAppLinks];
            return error ? (int)error.code : 0;
        }];
        // dpkg exits successfully without guaranteeing SpringBoard has an LS
        // record. Re-register only bundles in our verified hidden root.
        if (!result) result = [self refreshJailbreakApps];
        [self rh3ActionStage:@"reinstall package managers" result:result];
        return error ?: (result ? [NSError errorWithDomain:@"RootHide" code:result userInfo:@{NSLocalizedDescriptionKey:@"La instalación o el registro de los gestores no terminó; comparte el diagnóstico. Si hubo un timeout, no repitas la acción."}] : nil);
    }
    __block NSError *error;
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            error = [self->_bootstrapper installPackageManagers];
        }];
    }];
    return error;
}

- (NSError *)repairRootHideLibkrwProvider
{
    if (![DOBootstrapper rootHidePortEnabled] || !self.isJailbroken)
        return [NSError errorWithDomain:@"RootHide" code:ENXIO
                               userInfo:@{NSLocalizedDescriptionKey:@"RootHide must be active to repair the libkrw provider"}];
    NSError *fileError = nil;
    NSString *provider = [self->_bootstrapper rootHideLibkrwProviderPackageWithError:&fileError];
    if (!provider) return fileError ?: [NSError errorWithDomain:@"RootHide" code:ENOENT userInfo:nil];
    // Only an explicit user action may add the virtual dpkg provider to an
    // existing root. Verify that the real compiled plugin is already present:
    // the metadata-only donor must never conceal a missing binary.
    int preflight = [self rh3PerformPrivilegedAction:^int{
        NSError *rootError = nil;
        NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
        const char *active = jbclient_get_jbroot();
        if (rootError || !root || !active ||
            ![RH3CanonicalAppPath(root) isEqual:RH3CanonicalAppPath([NSString stringWithUTF8String:active])])
            return EPERM;
        NSString *library = [root stringByAppendingPathComponent:@"usr/lib/libkrw/libkrw-dopamine.dylib"];
        struct stat info = {0};
        if (lstat(library.fileSystemRepresentation, &info) != 0 || !S_ISREG(info.st_mode) ||
            info.st_uid != 0 || info.st_size <= 0) return ENOENT;
        return 0;
    }];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"packages: libkrw metadata-only repair preflight result=%d", preflight]];
    if (preflight)
        return [NSError errorWithDomain:@"RootHide" code:preflight
                               userInfo:@{NSLocalizedDescriptionKey:@"RootHide provider binary or verified root not found; no changes made"}];
    int result = [self spawnJbctlAsRootWithArgs:@[@"internal", @"install_pkg", provider]];
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"packages: explicit libkrw virtual provider install result=%d", result]];
    return result ? [NSError errorWithDomain:@"RootHide" code:result userInfo:@{
        NSLocalizedDescriptionKey: @"libkrw metadata registration did not complete. Export the diagnostic; if timed out do not retry."
    }] : nil;
}

- (NSError *)updateBootLogo
{
    const char *bootLogoPath = JBROOT_PATH("/basebin/bootlogo.jp2");
    if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"bootlogoEnabled" fallback:YES]) {
        UIImage *bootLogoImage;

        if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"customBootlogoEnabled" fallback:NO]) {
            bootLogoImage = [NSClassFromString(@"UIImage") imageWithContentsOfFile:[DOUIManager sharedInstance].bootlogoPath];
        }

        if (!bootLogoImage) {
            bootLogoImage = [[DOUIManager sharedInstance] renderBootLogo];
        }

        [self runAsRoot:^{
            [self runUnsandboxed:^{
                unlink(bootLogoPath);
                [[bootLogoImage jp2DataWithCompressionQuality:0.9] writeToFile:[NSString stringWithUTF8String:bootLogoPath] atomically:NO];
            }];
        }];

        return nil;
    }
    else {
        [self runAsRoot:^{
            [self runUnsandboxed:^{
                unlink(bootLogoPath);
            }];
        }];
        return nil;
    }
}

@end
