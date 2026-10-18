//
//  Bootstrapper.m
//  Dopamine
//
//  Created by Lars Fröder on 09.01.24.
//

#import "DOBootstrapper.h"
#import "RootHideBootstrapProfile.h"
#import "DOBootstrapper+zstd.h"
#import "DOEnvironmentManager.h"
#import "DOUIManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/roothider/jailbreakd.h>
#import <sys/mount.h>
#import <dlfcn.h>
#import <sys/stat.h>
#import "NSString+Version.h"
#import <errno.h>
#import <string.h>
#import <stdlib.h>
#import <fcntl.h>
#import <unistd.h>
#import <dispatch/dispatch.h>
#import <CommonCrypto/CommonDigest.h>
#import <sys/sysctl.h>
#import "RootHideRecovery.h"
#import "RootHideScriptWait.h"
extern char **environ;

// Enable only after the RootHide 3 launchd/dyld/systemhook stack and packages
// are integrated and validated. Stock Dopamine keeps its original code path.
#ifndef ROOTHIDE3_BOOTSTRAP_READY
#define ROOTHIDE3_BOOTSTRAP_READY 0
#endif

static NSString *const RH3RootDirectory = @"/var/containers/Bundle/Application";
static NSString *const RH3AppGroupDirectory = @"/var/mobile/Containers/Shared/AppGroup";
static NSString *const RH3InstalledMarker = @".installed_roothide3";
static NSString *const RH3PendingMarker = @".installing_roothide3";
static NSError *RH3Error(BootstrapErrorCode code, NSString *message);

// Only run side-effect-free readiness checks in this bounded asynchronous
// preflight. A dead IPC service can otherwise block the main installation
// thread forever. A timed-out call may remain in-flight until the app exits:
// never run an installation script after a timeout or pretend it was cancelled.
static BOOL RH3AwaitReadinessCheck(int (^operation)(void), int *valueOut)
{
    if (!operation || !valueOut) return NO;
    __block int value = -1;
    dispatch_group_t group = dispatch_group_create();
    dispatch_group_async(group, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        @autoreleasepool {
            value = operation();
        }
    });
    if (dispatch_group_wait(group, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC)) != 0)
        return NO;
    *valueOut = value;
    return YES;
}

static void RH3FreeShellEnvironment(char **environment)
{
    if (!environment) return;
    for (char **entry = environment; *entry; entry++) free(*entry);
    free(environment);
}

static NSDictionary *RH3BootstrapProfile(NSInteger version)
{
    return @{@"Schema": @1, @"OSMajor": @(NSProcessInfo.processInfo.operatingSystemVersion.majorVersion),
             @"ArchiveABI": @(version)};
}

static NSError *RH3CheckBootstrapProfile(NSString *root, NSInteger version)
{
    NSString *path = [root stringByAppendingPathComponent:@".roothide3-bootstrap-profile.plist"];
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0) {
        // Preserve recovery for old iOS 15/16 test roots. A newer OS attempt
        // may never infer that an unrecorded old root has the right userspace.
        if (errno == ENOENT && NSProcessInfo.processInfo.operatingSystemVersion.majorVersion < 17) return nil;
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Existing RootHide bootstrap has no readable OS/ABI profile; remove it using its original version before installing this candidate");
    }
    if (!S_ISREG(st.st_mode) || st.st_uid != 0 ||
        ![[NSDictionary dictionaryWithContentsOfFile:path] isEqualToDictionary:RH3BootstrapProfile(version)])
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Existing RootHide bootstrap OS/ABI profile differs; automatic cross-version migration is not supported");
    return nil;
}

// Every unfinished root is explicitly owned by this port. In particular, a
// RootHide 2 .jbroot (or a crashed older build without our marker) is NEVER
// interpreted as a recoverable RootHide 3 installation.
static NSString *RH3PendingState(NSString *root)
{
    NSString *path = [root stringByAppendingPathComponent:RH3PendingMarker];
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode)) return nil;
    return [NSString stringWithContentsOfFile:path
                                        encoding:NSUTF8StringEncoding error:nil];
}

static BOOL RH3KnownPendingState(NSString *stage)
{
    return [@[@"creating", @"layout", @"prepared", @"running-script", @"script-complete"]
            containsObject:stage];
}

static NSError *RH3WritePendingState(NSString *root, NSString *stage)
{
    NSString *path = [root stringByAppendingPathComponent:RH3PendingMarker];
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) == 0 && !S_ISREG(st.st_mode))
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Refusing to overwrite a non-file RootHide install marker");
    NSError *error = nil;
    if (![stage writeToFile:path
                atomically:YES encoding:NSUTF8StringEncoding error:&error]) return error;
    return nil;
}

static BOOL RH3IsRealDirectory(NSString *path)
{
    struct stat st;
    return lstat(path.fileSystemRepresentation, &st) == 0 && S_ISDIR(st.st_mode);
}

// An interrupted donor bootstrap cannot be replayed safely. Collect only
// filesystem metadata and selected package state, without opening password databases, following links,
// running any child process, or changing a transaction marker. The owner
// checks in rootHideExistingRootWithError: must succeed before this is called.
static NSDictionary *RH3RecoveryPackageSummary(NSData *data)
{
    NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!text) return nil;
    text = [text stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
    NSSet *allowed = [NSSet setWithArray:@[@"firmware", @"apt", @"dpkg", @"debianutils",
                                          @"dash", @"bash", @"zsh", @"vi"]];
    NSMutableDictionary *result = [NSMutableDictionary dictionary];
    for (NSString *paragraph in [text componentsSeparatedByString:@"\n\n"]) {
        NSMutableDictionary *fields = [NSMutableDictionary dictionary];
        for (NSString *line in [paragraph componentsSeparatedByString:@"\n"]) {
            for (NSString *key in @[@"Package", @"Version", @"Status"]) {
                NSString *prefix = [key stringByAppendingString:@": "];
                if ([line hasPrefix:prefix]) {
                    NSString *value = [line substringFromIndex:prefix.length];
                    if (value.length > 128 || [value rangeOfCharacterFromSet:
                        NSCharacterSet.controlCharacterSet].location != NSNotFound)
                        return nil;
                    // Duplicate fields/stanzas cannot establish package state.
                    if (fields[key]) return nil;
                    fields[key] = value;
                }
            }
        }
        NSString *package = fields[@"Package"];
        if (!package || ![allowed containsObject:package]) continue;
        if (result[package]) return nil;
        result[package] = [NSString stringWithFormat:@"version=%@; status=%@",
                           fields[@"Version"] ?: @"missing", fields[@"Status"] ?: @"missing"];
    }
    return result;
}

static void RH3LogRecoveryPackageState(NSString *root, DOUIManager *ui)
{
    // Read just the canonical package database, never account/password files.
    // Walk each directory without following symlinks. No bootstrap commands run.
    int directory = open(root.fileSystemRepresentation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        [ui rh3RecordDiagnosticStage:@"RECOVERY package audit: root unavailable"];
        return;
    }
    const char *components[] = {"Library", "dpkg"};
    for (size_t i = 0; i < sizeof(components) / sizeof(components[0]); i++) {
        const char *component = components[i];
        int next = openat(directory, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(directory);
        directory = next;
        struct stat st = {0};
        if (directory < 0 || fstat(directory, &st) != 0 || st.st_uid != 0) {
            if (directory >= 0) close(directory);
            [ui rh3RecordDiagnosticStage:@"RECOVERY package audit: canonical database directory unavailable"];
            return;
        }
    }
    int fd = openat(directory, "status", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    close(directory);
    struct stat before = {0}, after = {0};
    if (fd < 0 || fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != 0 || before.st_nlink != 1 || before.st_size <= 0 || before.st_size > 1024 * 1024) {
        if (fd >= 0) close(fd);
        [ui rh3RecordDiagnosticStage:@"RECOVERY package audit: status is unavailable or outside read limits"];
        return;
    }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
    size_t used = 0;
    while (used < data.length) {
        ssize_t count = read(fd, (uint8_t *)data.mutableBytes + used, data.length - used);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) break;
        used += (size_t)count;
    }
    BOOL stable = fstat(fd, &after) == 0 && used == data.length &&
        before.st_size == after.st_size && before.st_ino == after.st_ino &&
        before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec &&
        before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec &&
        before.st_ctimespec.tv_sec == after.st_ctimespec.tv_sec &&
        before.st_ctimespec.tv_nsec == after.st_ctimespec.tv_nsec;
    close(fd);
    if (!stable) {
        [ui rh3RecordDiagnosticStage:@"RECOVERY package audit: read incomplete or database changed; indeterminate"];
        return;
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hash = [NSMutableString string];
    for (unsigned i = 0; i < sizeof(digest); i++) [hash appendFormat:@"%02x", digest[i]];
    NSInteger version = rh3_bootstrap_version_for_os((int)NSProcessInfo.processInfo.operatingSystemVersion.majorVersion);
    NSString *baseline = version == 1800 ? @"c24b53f710b989977f4cd81d5da26baad74b3e77459687acb16e85c3432379c7" :
                         version == 1900 ? @"558c08def3e1c8481f0c7a3a0fa9dd1299af5c91f510067f098787d693bdf13c" : nil;
    [ui rh3RecordDiagnosticStage:[NSString stringWithFormat:
        @"RECOVERY Library/dpkg/status: bytes=%lu; sha256=%@; pinned-baseline=%@",
        (unsigned long)data.length, hash, baseline ? ([hash isEqualToString:baseline] ? @"same" : @"different") : @"unknown"]];
    NSDictionary *packages = RH3RecoveryPackageSummary(data);
    if (!packages) {
        [ui rh3RecordDiagnosticStage:@"RECOVERY package audit: malformed or ambiguous fields; indeterminate"];
        return;
    }
    for (NSString *name in @[@"firmware", @"apt", @"dpkg", @"debianutils", @"dash", @"bash", @"zsh", @"vi"])
        [ui rh3RecordDiagnosticStage:[NSString stringWithFormat:@"RECOVERY package %@: %@",
                                     name, packages[name] ?: @"absent"]];
}

static NSString *RH3RecoveryPathKind(NSString *path)
{
    struct stat st = {0};
    if (lstat(path.fileSystemRepresentation, &st) != 0)
        return errno == ENOENT ? @"absent" : [NSString stringWithFormat:@"inaccessible (%d)", errno];
    if (S_ISREG(st.st_mode)) return [NSString stringWithFormat:
        @"regular file (size=%lld; mtime=%lld; uid=%u; mode=%04o)",
        (long long)st.st_size, (long long)st.st_mtime, (unsigned)st.st_uid, (unsigned)(st.st_mode & 07777)];
    if (S_ISDIR(st.st_mode)) return @"directory";
    if (S_ISLNK(st.st_mode)) return @"symlink (not followed)";
    return @"other file type";
}

static void RH3LogInterruptedBootstrapSnapshot(NSString *root)
{
    if (![DOBootstrapper rootHideBrandForPath:root]) return;
    DOUIManager *ui = [DOUIManager sharedInstance];
    [ui rh3RecordDiagnosticStage:@"RECOVERY read-only snapshot: running-script; no script replay or mutation attempted"];
    // Presence of the final script is NOT proof that no commands ran: its
    // removal is the donor script's last command. Do not inspect passwd
    // contents, expose identities, or infer transaction success from files.
    for (NSString *relative in @[@".installing_roothide3", @".installed_roothide3",
                                @"prep_bootstrap.sh", @".roothide3-bootstrap-profile.plist",
                                @"basebin.roothide3-backup", @"private/var",
                                @"etc/master.passwd", @"etc/pwd.db", @"etc/spwd.db",
                                @"var/lib/dpkg/status", @"usr/libexec/firmware",
                                @"Library/dpkg/info/apt.postinst", @"usr/bin/uialert"]) {
        NSString *kind = RH3RecoveryPathKind([root stringByAppendingPathComponent:relative]);
        [ui rh3RecordDiagnosticStage:[NSString stringWithFormat:@"RECOVERY %@: %@", relative, kind]];
    }
    NSError *listError = nil;
    NSArray<NSString *> *entries = [NSFileManager.defaultManager contentsOfDirectoryAtPath:root error:&listError];
    if (!entries) {
        [ui rh3RecordDiagnosticStage:@"RECOVERY could not list root backup entries"];
    } else {
        BOOL foundBackup = NO;
        for (NSString *entry in entries) {
            if ([entry hasPrefix:@".roothide3-deps-"]) {
                foundBackup = YES;
                [ui rh3RecordDiagnosticStage:@"RECOVERY interrupted dependency backup exists (preserved)"];
                break;
            }
        }
        if (!foundBackup) [ui rh3RecordDiagnosticStage:@"RECOVERY no staged dependency backup name observed"];
    }
    RH3LogRecoveryPackageState(root, ui);
    [ui rh3RecordDiagnosticStage:@"RECOVERY result: indeterminate; manual forensic inspection required before any retry"];
}

// The pinned RootHide donor archive contains var/tmp -> ../tmp. After var/
// moves to the separate AppGroup, this is briefly a DANGLING symlink.
// fileExistsAtPath: follows that link, incorrectly reports NO and leaves the
// destination occupied for the subsequent tmp/ move (Cocoa 516 / EEXIST).
static BOOL RH3IsExpectedDonorTmpLink(NSString *path)
{
    struct stat st;
    if (lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISLNK(st.st_mode))
        return NO;
    return [[NSFileManager.defaultManager destinationOfSymbolicLinkAtPath:path error:nil]
            isEqualToString:@"../tmp"];
}

// Allow read-only recognition of ONE precisely identified interrupted
// layout. It can only be repaired later, with root privileges, and only
// before the bootstrap script or package installation has started.
static BOOL RH3IsKnownTmpCollision(NSString *root, NSString *secondary)
{
    if (![DOBootstrapper rootHideBrandForPath:root] ||
        ![root.lastPathComponent isEqualToString:secondary.lastPathComponent] ||
        ![RH3PendingState(root) isEqualToString:@"creating"])
        return NO;
    struct stat rootStat, secondaryStat, st;
    if (lstat(root.fileSystemRepresentation, &rootStat) != 0 ||
        lstat(secondary.fileSystemRepresentation, &secondaryStat) != 0 ||
        !S_ISDIR(rootStat.st_mode) || !S_ISDIR(secondaryStat.st_mode) ||
        rootStat.st_uid != 0 || secondaryStat.st_uid != 0)
        return NO;
    NSString *marker = [root stringByAppendingPathComponent:RH3InstalledMarker];
    NSString *profile = [root stringByAppendingPathComponent:@".roothide3-bootstrap-profile.plist"];
    NSString *backlink = [secondary stringByAppendingPathComponent:@".jbroot"];
    for (NSString *path in @[marker, profile, backlink]) {
        if (lstat(path.fileSystemRepresentation, &st) == 0 || errno != ENOENT)
            return NO;
    }
    NSString *rootVar = [root stringByAppendingPathComponent:@"var"];
    NSString *privateVar = [root stringByAppendingPathComponent:@"private/var"];
    NSString *secondaryVar = [secondary stringByAppendingPathComponent:@"var"];
    return RH3IsRealDirectory([root stringByAppendingPathComponent:@"tmp"]) &&
           RH3IsRealDirectory(secondaryVar) &&
           [[[NSFileManager defaultManager] destinationOfSymbolicLinkAtPath:rootVar error:nil]
              isEqualToString:@"private/var"] &&
           [[[NSFileManager defaultManager] destinationOfSymbolicLinkAtPath:privateVar error:nil]
              isEqualToString:secondaryVar] &&
           RH3IsExpectedDonorTmpLink([secondaryVar stringByAppendingPathComponent:@"tmp"]);
}

// Staged dependency files can contain the only copies of overwritten binaries.
// A crash loses the in-memory rollback journal, so leave every backup intact
// and require manual inspection instead of repeating a partial transaction.
static NSError *RH3CheckInterruptedOperations(NSString *root)
{
    NSError *readError = nil;
    NSArray<NSString *> *entries = [NSFileManager.defaultManager
                                    contentsOfDirectoryAtPath:root error:&readError];
    if (!entries) return readError ?: RH3Error(BootstrapErrorCodeFailedReplacing,
                                              @"Unable to inspect RootHide recovery state");
    for (NSString *entry in entries) {
        if ([entry hasPrefix:@".roothide3-deps-"] ||
            [entry isEqualToString:@"basebin.roothide3-backup"]) {
            return RH3Error(BootstrapErrorCodeFailedReplacing,
                            [NSString stringWithFormat:@"Interrupted RootHide transaction at %@; preserve backups for manual recovery", entry]);
        }
    }
    return nil;
}

// Rewrite only absolute links into our old, owned directories. Keep links to
// iOS system files and relative symlinks intact while re-randomizing jbrand.
static NSString *RH3RetargetLink(NSString *link, NSString *oldRoot,
                                 NSString *oldSecondary, NSString *newRoot,
                                 NSString *newSecondary)
{
    NSArray<NSString *> *from = @[oldRoot, [@"/private" stringByAppendingString:oldRoot],
                                   oldSecondary, [@"/private" stringByAppendingString:oldSecondary]];
    NSArray<NSString *> *to = @[newRoot, [@"/private" stringByAppendingString:newRoot],
                                 newSecondary, [@"/private" stringByAppendingString:newSecondary]];
    for (NSUInteger i = 0; i < from.count; i++) {
        NSString *prefix = from[i];
        if ([link isEqualToString:prefix] ||
            [link hasPrefix:[prefix stringByAppendingString:@"/"]]) {
            return [to[i] stringByAppendingString:[link substringFromIndex:prefix.length]];
        }
    }
    return link;
}

static uint64_t RH3NewBrand(void)
{
    uint64_t value = ((uint64_t)arc4random() << 32) | arc4random();
    uint8_t check = (uint8_t)(value >> 8 ^ value >> 16 ^ value >> 24 ^
                              value >> 32 ^ value >> 40 ^ value >> 48 ^ value >> 56);
    return (value & ~UINT64_C(0xff)) | check;
}

static uint64_t RH3BrandFromName(NSString *name)
{
    if (![name hasPrefix:@".jbroot-"] || name.length != 24) return 0;
    const char *hex = name.UTF8String + 8;
    for (size_t i = 0; i < 16; i++) {
        if (!strchr("0123456789ABCDEF", hex[i])) return 0;
    }
    char *end = NULL;
    unsigned long long brand = strtoull(hex, &end, 16);
    if (!brand || !end || *end != '\0') return 0;
    uint8_t check = (uint8_t)(brand >> 8 ^ brand >> 16 ^ brand >> 24 ^
                              brand >> 32 ^ brand >> 40 ^ brand >> 48 ^ brand >> 56);
    return check == (uint8_t)brand ? (uint64_t)brand : 0;
}

static NSError *RH3Error(BootstrapErrorCode code, NSString *message)
{
    return [NSError errorWithDomain:bootstrapErrorDomain code:code
                          userInfo:@{NSLocalizedDescriptionKey: message}];
}

static NSString *RH3RecoverySHA256(NSData *data)
{
    if (!data) return nil;
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hash = [NSMutableString string];
    for (unsigned i = 0; i < sizeof(digest); i++) [hash appendFormat:@"%02x", digest[i]];
    return hash;
}

// This permits preserving a legacy root, NEVER replaying its script. The old
// account files and marker remain in the backup, untouched and unread.
static NSError *RH3LegacyRecoveryEligibility(NSString *root)
{
    if (geteuid() != 0 || NSProcessInfo.processInfo.operatingSystemVersion.majorVersion != 16)
        return RH3RecoveryFailure(@"Legacy bootstrap recovery is restricted to privileged iOS 16 attempts");
    NSError *interrupted = RH3CheckInterruptedOperations(root);
    if (interrupted) return interrupted;
    NSError *profile = RH3CheckBootstrapProfile(root, 1900);
    if (profile) return profile;
    struct stat profileStat;
    if (lstat([root stringByAppendingPathComponent:@".roothide3-bootstrap-profile.plist"].fileSystemRepresentation, &profileStat) ||
        !S_ISREG(profileStat.st_mode) || profileStat.st_uid != 0)
        return RH3RecoveryFailure(@"Legacy recovery requires an explicit matching bootstrap profile");
    if (![RH3PendingState(root) isEqual:@"running-script"])
        return RH3RecoveryFailure(@"Only a legacy running-script installation can be preserved");
    struct stat marker;
    NSString *markerPath = [root stringByAppendingPathComponent:RH3PendingMarker];
    struct timeval boot = {0};
    size_t size = sizeof(boot);
    int mib[] = {CTL_KERN, KERN_BOOTTIME};
    if (lstat(markerPath.fileSystemRepresentation, &marker) || marker.st_uid != 0 ||
        sysctl(mib, 2, &boot, &size, NULL, 0) || size != sizeof(boot) || boot.tv_sec <= marker.st_mtime ||
        boot.tv_sec <= marker.st_ctime)
        return RH3RecoveryFailure(@"A full reboot after the interrupted attempt is required before preserving its bootstrap");
    for (NSString *relative in @[@".installed_roothide3", @"etc/pwd.db", @"etc/spwd.db",
                                 @"basebin.roothide3-backup"]) {
        struct stat st;
        if (lstat([root stringByAppendingPathComponent:relative].fileSystemRepresentation, &st) == 0 || errno != ENOENT)
            return RH3RecoveryFailure(@"Bootstrap has additional installation state; automatic preservation refused");
    }
    // Refuse symlinked parents before reading only these two non-secret files.
    for (NSString *relative in @[@"Library", @"Library/dpkg", @"etc"]) {
        struct stat st;
        if (lstat([root stringByAppendingPathComponent:relative].fileSystemRepresentation, &st) ||
            !S_ISDIR(st.st_mode) || st.st_uid != 0)
            return RH3RecoveryFailure(@"Bootstrap database directories are not verified owned directories");
    }
    NSString *status = RH3RecoverySHA256(RH3RecoveryReadFile([root stringByAppendingPathComponent:@"Library/dpkg/status"], 1024 * 1024, 0));
    NSString *script = RH3RecoverySHA256(RH3RecoveryReadFile([root stringByAppendingPathComponent:@"prep_bootstrap.sh"], 4096, 0));
    if (![status isEqual:@"558c08def3e1c8481f0c7a3a0fa9dd1299af5c91f510067f098787d693bdf13c"] ||
        ![script isEqual:@"c48a3d0c49d5d71f06d0d041330aa53b144591f72bda2208a305be09ca730489"])
        return RH3RecoveryFailure(@"Legacy bootstrap differs from the pinned donor; no automatic recovery attempted");
    return nil;
}

@interface DOBootstrapper ()
- (NSError *)extractTar:(NSString *)tarPath toPath:(NSString *)destinationPath;
- (void)patchBasebinDaemonPlists;
- (BOOL)fileOrSymlinkExistsAtPath:(NSString *)path;
- (int)installPackage:(NSString *)packagePath;
- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion;
- (NSError *)finalizeRootHideBootstrap;
- (NSError *)deleteRootHideBootstrap;
@end

// The hidden bootstrap intentionally does not share the stock Dopamine preboot
// container or /var/jb symlink. It is selected only by an explicit build flag.
@implementation DOBootstrapper (RootHidePort)

+ (NSError *)preserveInterruptedRootHideBootstrap
{
    if (![self rootHidePortEnabled] || geteuid() != 0)
        return RH3RecoveryFailure(@"RootHide preservation requires its enabled privileged installer");
    NSError *error = nil;
    NSDictionary *journal = RH3RecoveryInspect(RH3RootDirectory, RH3AppGroupDirectory, 0, &error);
    if (error) return error;
    if ([journal[@"Complete"] boolValue]) return nil;
    NSString *root = journal ? journal[@"Locations"][0] : [self rootHideExistingRootWithError:&error];
    if (error) return error;
    if (!root || ![RH3PendingState(root) isEqual:@"running-script"]) return nil;
    RH3LogInterruptedBootstrapSnapshot(root);
    error = RH3LegacyRecoveryEligibility(root);
    if (error) return error;
    NSString *name = journal ? journal[@"Name"] : root.lastPathComponent;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"RECOVERY preserving legacy containers; their script and markers will NOT be replayed or deleted"];
    if (!RH3RecoveryPreserve(RH3RootDirectory, RH3AppGroupDirectory, name, 0, &error)) return error;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"RECOVERY legacy containers preserved; a different fresh bootstrap may now be prepared"];
    // ensureJailbreakRootExists must discover a new path after preservation.
    gSystemInfo.jailbreakInfo.rootPath = NULL;
    gSystemInfo.jailbreakInfo.jbrand = 0;
    return nil;
}

+ (BOOL)rootHidePortEnabled
{
#if ROOTHIDE3_BOOTSTRAP_READY
    return YES;
#else
    return NO;
#endif
}

+ (uint64_t)rootHideBrandForPath:(NSString *)path
{
    if (![[path stringByDeletingLastPathComponent] isEqualToString:RH3RootDirectory]) return 0;
    return RH3BrandFromName(path.lastPathComponent);
}

+ (NSString *)rootHideExistingRootWithError:(NSError **)error
{
    NSError *recoveryError = nil;
    NSDictionary *recovery = RH3RecoveryInspect(RH3RootDirectory, RH3AppGroupDirectory, 0, &recoveryError);
    if (recoveryError || (recovery && ![recovery[@"Complete"] boolValue])) {
        if (error) *error = recoveryError ?: RH3RecoveryFailure(@"RootHide preservation is incomplete; the privileged installer must finish it before selecting a root");
        return nil;
    }
    NSFileManager *fm = NSFileManager.defaultManager;
    NSError *directoryError = nil;
    NSArray<NSString *> *entries = [fm contentsOfDirectoryAtPath:RH3RootDirectory error:&directoryError];
    if (!entries) {
        if (error) *error = directoryError;
        return nil;
    }

    NSString *foundRoot = nil;
    for (NSString *entry in entries) {
        if ([entry hasPrefix:@".jbroot-"] && [entry containsString:@".removing-roothide3-"]) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"An interrupted RootHide 3 uninstall needs manual recovery");
            return nil;
        }
        uint64_t brand = RH3BrandFromName(entry);
        if (!brand) continue;
        NSString *root = [RH3RootDirectory stringByAppendingPathComponent:entry];
        if (!RH3IsRealDirectory(root)) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"RootHide-named path is not a real directory");
            return nil;
        }
        NSString *ownMarker = [root stringByAppendingPathComponent:RH3InstalledMarker];
        NSString *pendingPath = [root stringByAppendingPathComponent:RH3PendingMarker];
        NSString *pending = RH3PendingState(root);
        struct stat pendingInfo;
        int pendingStatus = lstat(pendingPath.fileSystemRepresentation, &pendingInfo);
        if ((pendingStatus == 0 && (!S_ISREG(pendingInfo.st_mode) || !RH3KnownPendingState(pending))) ||
            (pendingStatus != 0 && errno != ENOENT)) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"Unknown or damaged RootHide 3 installation state; manual recovery required");
            return nil;
        }
        struct stat installedInfo;
        int installedStatus = lstat(ownMarker.fileSystemRepresentation, &installedInfo);
        BOOL installed = installedStatus == 0 && S_ISREG(installedInfo.st_mode) &&
                         [[NSString stringWithContentsOfFile:ownMarker
                                                    encoding:NSUTF8StringEncoding error:nil] isEqualToString:@"3"];
        if ((installedStatus == 0 && !installed) || (installedStatus != 0 && errno != ENOENT)) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"Damaged RootHide 3 installed marker; manual recovery required");
            return nil;
        }
        if (installed && pending && ![pending isEqualToString:@"script-complete"]) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"Conflicting RootHide 3 installed and pending stages; manual recovery required");
            return nil;
        }
        if (!installed && !RH3KnownPendingState(pending)) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                [NSString stringWithFormat:@"Unowned or unknown .jbroot at %@; refusing to adopt or delete it", root]);
            return nil;
        }
        NSString *secondary = [RH3AppGroupDirectory stringByAppendingPathComponent:entry];
        if (!RH3IsRealDirectory(secondary)) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"RootHide AppGroup is not a real directory");
            return nil;
        }
        NSString *backlink = [secondary stringByAppendingPathComponent:@".jbroot"];
        BOOL recoverableTmpCollision = RH3IsKnownTmpCollision(root, secondary);
        NSDictionary *attributes = [fm attributesOfItemAtPath:backlink error:nil];
        NSString *destination = [fm destinationOfSymbolicLinkAtPath:backlink error:nil];
        if ((! [attributes[NSFileType] isEqual:NSFileTypeSymbolicLink] ||
             ![destination isEqualToString:root]) && !recoverableTmpCollision) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                [NSString stringWithFormat:@"RootHide AppGroup link is missing or invalid for %@", root]);
            return nil;
        }
        NSString *privateVar = [root stringByAppendingPathComponent:@"private/var"];
        if (![[fm destinationOfSymbolicLinkAtPath:privateVar error:nil]
              isEqualToString:[secondary stringByAppendingPathComponent:@"var"]]) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"RootHide private/var link does not match the owned AppGroup");
            return nil;
        }
        if (foundRoot) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"Multiple RootHide 3 containers found. No automatic deletion will be attempted.");
            return nil;
        }
        foundRoot = root;
    }
    // A rename or removal can crash after changing the primary container but
    // before its AppGroup partner. Never create another root over orphaned
    // RootHide/RootHide2 data, and never try to repair unknown ownership.
    NSArray<NSString *> *secondaries = [fm contentsOfDirectoryAtPath:RH3AppGroupDirectory
                                                               error:&directoryError];
    if (!secondaries) {
        if (error) *error = directoryError;
        return nil;
    }
    for (NSString *entry in secondaries) {
        if ([entry hasPrefix:@".jbroot-"] && [entry containsString:@".removing-roothide3-"]) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                        @"Interrupted RootHide 3 AppGroup removal needs manual recovery");
            return nil;
        }
        if (!RH3BrandFromName(entry)) continue;
        NSString *partner = [RH3RootDirectory stringByAppendingPathComponent:entry];
        if (!RH3IsRealDirectory(partner)) {
            if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                [NSString stringWithFormat:@"Orphaned RootHide AppGroup %@; refusing to create or remove a bootstrap", entry]);
            return nil;
        }
    }
    return foundRoot;
}

- (NSError *)rh3VerifyBundledFile:(NSString *)filename sha256:(NSString *)expectedSHA256
{
    NSString *path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:filename];
    NSError *readError = nil;
    NSData *data = [NSData dataWithContentsOfFile:path options:NSDataReadingMappedIfSafe error:&readError];
    if (!data || data.length == 0 || data.length > UINT32_MAX) {
        return RH3Error(BootstrapErrorCodeFailedExtracting,
                        [NSString stringWithFormat:@"Missing or unreadable RootHide asset %@: %@", filename, readError ?: @"empty file"]);
    }
    unsigned char digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
    NSMutableString *hash = [NSMutableString stringWithCapacity:CC_SHA256_DIGEST_LENGTH * 2];
    for (size_t i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) [hash appendFormat:@"%02x", digest[i]];
    if (![hash isEqualToString:expectedSHA256]) {
        return RH3Error(BootstrapErrorCodeFailedExtracting,
                        [NSString stringWithFormat:@"RootHide asset %@ differs from the pinned donor package", filename]);
    }
    return nil;
}

- (NSError *)rh3VerifyAssetsForVersion:(NSInteger)version
{
    NSString *archive = [NSString stringWithFormat:@"roothide_bootstrap_%ld.tar.zst", (long)version];
    NSString *archiveSHA = version == 1800
        ? @"3350ed91d77163e0cd73f0f90185b5c9b87d9d294133e25ced3a29329e90370e"
        : @"420f72d1a62c9f884733cdefc596728469482a48858ec7ceca4d3ab2d3cba56c";
    NSDictionary<NSString *, NSString *> *assets = @{
        archive: archiveSHA,
        @"roothideapp.deb": @"b8f075e1844709845962900b22fe71136a66369a2c35bb1201087f2fd9476b7d",
        @"roothide_sileo.deb": @"e85ab12f8d98da9a5350293647266b898282b0d766df2397526ab253d84eede3",
        @"roothide_zebra.deb": @"ca82c18256e19ff78af3e53308d53f047a2d429cb7e025c892377abe4d2e7825",
    };
    for (NSString *name in assets) {
        NSError *error = [self rh3VerifyBundledFile:name sha256:assets[name]];
        if (error) return error;
    }
    if (![NSFileManager.defaultManager fileExistsAtPath:
         [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"basebin.tar"]]) {
        return RH3Error(BootstrapErrorCodeFailedExtracting, @"Dopamine 3 basebin.tar is missing");
    }
    // These three are generated by the Packages Makefiles and copied by Xcode.
    // Refuse a new root before extraction rather than leaving an unfinished
    // bootstrap because the app build omitted a required dependency.
    for (NSString *name in @[@"libroot.deb", @"libkrw-dopamine.deb", @"basebin-link.deb"]) {
        NSString *path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:name];
        struct stat st;
        if (lstat(path.fileSystemRepresentation, &st) != 0 || !S_ISREG(st.st_mode))
            return RH3Error(BootstrapErrorCodeFailedExtracting,
                            [NSString stringWithFormat:@"Missing RootHide dependency payload %@", name]);
    }
    return nil;
}

- (NSError *)rootHidePreflightError
{
    // Bundled resources are readable before exploitation even when sideloaded.
    // Foreign-container checks need privileges: ordinary AltStore installations
    // must defer those until ensureJailbreakRootExists/prepareBootstrap below.
    NSInteger version = rh3_bootstrap_version_for_os((int)NSProcessInfo.processInfo.operatingSystemVersion.majorVersion);
    if (!version)
        return RH3Error(BootstrapErrorCodeFailedExtracting, @"No RootHide bootstrap profile for this iOS version");
    NSError *assetError = [self rh3VerifyAssetsForVersion:version];
    if (assetError) return assetError;
    if (![[DOEnvironmentManager sharedManager] isInstalledThroughTrollStore] && geteuid() != 0)
        return nil;
    // Privileged hosts can reject conflicts earlier. No mutations here.
    struct stat visibleRoot;
    if (lstat("/var/jb", &visibleRoot) == 0)
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"An existing /var/jb bootstrap must be removed using its own jailbreak before testing RootHide 3.");
    if (errno != ENOENT)
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Unable to inspect /var/jb before RootHide activation.");
    NSError *error = nil;
    NSDictionary *recovery = RH3RecoveryInspect(RH3RootDirectory, RH3AppGroupDirectory, 0, &error);
    if (error) return error;
    if (recovery && ![recovery[@"Complete"] boolValue])
        return RH3LegacyRecoveryEligibility(recovery[@"Locations"][0]);
    NSString *root = [DOBootstrapper rootHideExistingRootWithError:&error];
    if (error) return error;
    if (root) {
        error = RH3CheckInterruptedOperations(root);
        if (error) return error;
        NSString *stage = RH3PendingState(root);
        BOOL recoverableTmpCollision = [stage isEqualToString:@"creating"] &&
            RH3IsKnownTmpCollision(root, [RH3AppGroupDirectory stringByAppendingPathComponent:root.lastPathComponent]) &&
            NSProcessInfo.processInfo.operatingSystemVersion.majorVersion == 16 && version == 1900;
        if (([stage isEqualToString:@"creating"] && !recoverableTmpCollision) ||
            [stage isEqualToString:@"running-script"]) {
            if ([stage isEqualToString:@"running-script"]) {
                RH3LogInterruptedBootstrapSnapshot(root);
                if (!recovery) return RH3LegacyRecoveryEligibility(root);
            }
            return RH3Error(BootstrapErrorCodeFailedReplacing,
                            @"Interrupted RootHide extraction or setup script needs manual recovery before another activation.");
        }
        error = RH3CheckBootstrapProfile(root, version);
        if (error) return error;
    }
    return nil;
}

- (NSError *)rh3BuildPackageSourcesInRoot:(NSString *)root version:(NSInteger)version
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *aptDir = [root stringByAppendingPathComponent:@"etc/apt/sources.list.d"];
    NSError *error = nil;
    if (![fm createDirectoryAtPath:aptDir withIntermediateDirectories:YES attributes:nil error:&error]) return error;

    // The donor archive can contain Procursus's *stock* repository in
    // procursus.sources. Leaving it enabled alongside the RootHide arm64e
    // repository risks installing packages built for the wrong bootstrap.
    // This method only runs on a freshly created, verified hidden root.
    for (NSString *relative in @[@"etc/apt/sources.list.d/procursus.sources",
                                  @"etc/apt/sources.list.d/procursus.list",
                                  @"etc/apt/sources.list"]) {
        NSString *sourcePath = [root stringByAppendingPathComponent:relative];
        if ([fm attributesOfItemAtPath:sourcePath error:nil] &&
            ![fm removeItemAtPath:sourcePath error:&error]) {
            return error ?: RH3Error(BootstrapErrorCodeFailedExtracting,
                                    @"Unable to remove an incompatible stock Procursus source");
        }
    }

    NSString *sources = [NSString stringWithFormat:
        @"Types: deb\nURIs: https://repo.chariz.com/\nSuites: ./\nComponents:\n\n"
        @"Types: deb\nURIs: https://havoc.app/\nSuites: ./\nComponents:\n\n"
        @"Types: deb\nURIs: https://roothide.github.io/\nSuites: ./\nComponents:\n\n"
        @"Types: deb\nURIs: https://roothide.github.io/procursus\nSuites: iphoneos-arm64e/%ld\nComponents: main\n\n"
        @"Types: deb\nURIs: https://github.com/roothide/roothide.github.io/releases/download/%ld/\nSuites: ./\nComponents:\n",
        (long)version, (long)version];
    if (![sources writeToFile:[aptDir stringByAppendingPathComponent:@"default.sources"]
                   atomically:YES encoding:NSUTF8StringEncoding error:&error]) return error;

    NSString *zebraDir = [root stringByAppendingPathComponent:
                          @"var/mobile/Library/Application Support/xyz.willy.Zebra"];
    if (![fm createDirectoryAtPath:zebraDir withIntermediateDirectories:YES
                       attributes:@{NSFilePosixPermissions:@0755} error:&error]) return error;
    chown(zebraDir.fileSystemRepresentation, 501, 501);
    NSString *zebraSources = [NSString stringWithFormat:
        @"deb https://repo.chariz.com/ ./\n"
        @"deb https://havoc.app/ ./\n"
        @"deb https://roothide.github.io/ ./\n"
        @"deb https://roothide.github.io/procursus iphoneos-arm64e/%ld main\n"
        @"deb https://github.com/roothide/roothide.github.io/releases/download/%ld/ ./\n",
        (long)version, (long)version];
    if (![zebraSources writeToFile:[zebraDir stringByAppendingPathComponent:@"sources.list"]
                         atomically:YES encoding:NSUTF8StringEncoding error:&error]) return error;
    return nil;
}

- (BOOL)rh3ReplaceSymlinkAtPath:(NSString *)path withDestination:(NSString *)destination error:(NSError **)error
{
    NSFileManager *fm = NSFileManager.defaultManager;
    struct stat st;
    int statResult = lstat(path.fileSystemRepresentation, &st);
    if (statResult == 0 && !S_ISLNK(st.st_mode)) {
        if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                   [NSString stringWithFormat:@"Refusing to replace non-symlink %@", path]);
        return NO;
    }
    if (statResult != 0 && errno != ENOENT) {
        if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                   [NSString stringWithFormat:@"Cannot inspect symlink %@", path]);
        return NO;
    }
    // Create before replacing: unlink/create leaves a damaged installation if
    // creation fails. POSIX rename atomically exchanges the existing symlink.
    NSString *temporary = [path stringByAppendingFormat:@".roothide3-%@", NSUUID.UUID.UUIDString];
    if (![fm createSymbolicLinkAtPath:temporary withDestinationPath:destination error:error]) return NO;
    if (rename(temporary.fileSystemRepresentation, path.fileSystemRepresentation) == 0) return YES;
    int savedErrno = errno;
    [fm removeItemAtPath:temporary error:nil];
    if (error) *error = RH3Error(BootstrapErrorCodeFailedReplacing,
                                [NSString stringWithFormat:@"Atomic symlink replacement failed at %@ (%s)",
                                 path, strerror(savedErrno)]);
    return NO;
}

// Only rewrite absolute links into our old *owned* container. Other absolute
// symlinks (including iOS system paths) and all relative symlinks are retained.
- (NSError *)rh3RepairLinksAtRoot:(NSString *)root secondary:(NSString *)secondary
                        oldRoot:(NSString *)oldRoot oldSecondary:(NSString *)oldSecondary
                        changes:(NSMutableArray<NSDictionary<NSString *, NSString *> *> *)changes
{
    NSFileManager *fm = NSFileManager.defaultManager;
    for (NSString *base in @[root, secondary]) {
        __block NSError *walkError = nil;
        NSDirectoryEnumerator<NSURL *> *entries = [fm enumeratorAtURL:[NSURL fileURLWithPath:base]
                                     includingPropertiesForKeys:nil options:0
                                     errorHandler:^BOOL(NSURL *url, NSError *enumerationError) {
            walkError = enumerationError;
            return NO;
        }];
        if (!entries) return RH3Error(BootstrapErrorCodeFailedReplacing, @"Cannot inspect renamed RootHide tree");
        for (NSURL *entry in entries) {
            NSString *path = entry.path;
            struct stat st;
            if (lstat(path.fileSystemRepresentation, &st) != 0)
                return RH3Error(BootstrapErrorCodeFailedReplacing,
                                [NSString stringWithFormat:@"Cannot inspect renamed entry %@", path]);
            if (!S_ISLNK(st.st_mode)) continue;
            NSString *oldTarget = [fm destinationOfSymbolicLinkAtPath:path error:nil];
            if (!oldTarget) return RH3Error(BootstrapErrorCodeFailedReplacing, @"Unreadable RootHide link");
            NSString *newTarget = RH3RetargetLink(oldTarget, oldRoot, oldSecondary, root, secondary);
            if ([newTarget isEqualToString:oldTarget]) continue;
            if (![self rh3ReplaceSymlinkAtPath:path withDestination:newTarget error:nil])
                return RH3Error(BootstrapErrorCodeFailedReplacing,
                                [NSString stringWithFormat:@"Could not repair RootHide symlink %@", path]);
            [changes addObject:@{@"path":path, @"old":oldTarget}];
        }
        if (walkError) return walkError;
    }
    // These are layout invariants, not optional symlinks. Check exact targets.
    NSString *privateVar = [root stringByAppendingPathComponent:@"private/var"];
    NSString *backlink = [secondary stringByAppendingPathComponent:@".jbroot"];
    for (NSDictionary *link in @[@{@"path":privateVar, @"target":[secondary stringByAppendingPathComponent:@"var"]},
                                 @{@"path":backlink, @"target":root}]) {
        NSString *path = link[@"path"];
        NSString *target = [fm destinationOfSymbolicLinkAtPath:path error:nil];
        if (!target) return RH3Error(BootstrapErrorCodeFailedReplacing, @"Required RootHide layout symlink missing");
        if (![target isEqualToString:link[@"target"]]) {
            if (![self rh3ReplaceSymlinkAtPath:path withDestination:link[@"target"] error:nil])
                return RH3Error(BootstrapErrorCodeFailedReplacing, @"Failed repairing required RootHide layout link");
            [changes addObject:@{@"path":path, @"old":target}];
        }
    }
    return nil;
}

- (NSError *)rh3CreateRoot:(NSString *)root version:(NSInteger)version
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSError *error = nil;
    NSString *name = root.lastPathComponent;
    NSString *secondary = [RH3AppGroupDirectory stringByAppendingPathComponent:name];
    NSString *archive = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"roothide_bootstrap_%ld.tar.zst", (long)version]];
    NSString *tmpTar = [NSTemporaryDirectory() stringByAppendingPathComponent:
                        [NSString stringWithFormat:@"roothide-%@.tar", NSUUID.UUID.UUIDString]];
    NSString *rootVar = [root stringByAppendingPathComponent:@"var"];
    NSString *secondaryVar = [secondary stringByAppendingPathComponent:@"var"];
    NSString *rootTmp = [root stringByAppendingPathComponent:@"tmp"];
    NSString *secondaryTmp = [secondaryVar stringByAppendingPathComponent:@"tmp"];
    NSString *privateVar = [root stringByAppendingPathComponent:@"private/var"];

    if (![fm createDirectoryAtPath:root withIntermediateDirectories:NO
                       attributes:@{NSFilePosixPermissions:@0755} error:&error]) return error;
    // Mark ownership before extraction: an interrupted install must not be
    // indistinguishable from an unowned RootHide 2 container. Only a fully
    // linked 'creating' root is resumed by rootHideExistingRootWithError:;
    // incomplete layouts stay untouched for explicit manual recovery.
    error = RH3WritePendingState(root, @"creating");
    if (error) goto cleanup_root;
    if (chown(root.fileSystemRepresentation, 0, 0) != 0) {
        error = RH3Error(BootstrapErrorCodeFailedExtracting,
                         [NSString stringWithFormat:@"chown hidden root failed: %s", strerror(errno)]);
        goto cleanup_root;
    }

    error = [self decompressZstd:archive toTar:tmpTar];
    if (!error) error = [self extractTar:tmpTar toPath:root];
    [fm removeItemAtPath:tmpTar error:nil];
    if (error) goto cleanup_root;

    if (![fm createDirectoryAtPath:secondary withIntermediateDirectories:NO
                       attributes:@{NSFilePosixPermissions:@0755} error:&error]) goto cleanup_root;
    if (chown(secondary.fileSystemRepresentation, 0, 0) != 0) {
        error = RH3Error(BootstrapErrorCodeFailedExtracting,
                         [NSString stringWithFormat:@"chown hidden AppGroup failed: %s", strerror(errno)]);
        goto cleanup_both;
    }
    if (![fm fileExistsAtPath:rootVar] || ![fm fileExistsAtPath:rootTmp]) {
        error = RH3Error(BootstrapErrorCodeFailedExtracting,
                         @"RootHide bootstrap archive is missing var/ or tmp/");
        goto cleanup_both;
    }
    if (![fm moveItemAtPath:rootVar toPath:secondaryVar error:&error] ||
        ![fm createSymbolicLinkAtPath:rootVar withDestinationPath:@"private/var" error:&error]) goto cleanup_both;
    // The extracted archive owns this path; avoid changing any system path.
    if ([fm fileExistsAtPath:privateVar] ||
        [fm attributesOfItemAtPath:privateVar error:nil]) {
        if (![fm removeItemAtPath:privateVar error:&error]) goto cleanup_both;
    }
    if (![fm createSymbolicLinkAtPath:privateVar withDestinationPath:secondaryVar error:&error]) goto cleanup_both;
    // The RootHide archive explicitly provides var/tmp -> ../tmp.
    // Never replace an arbitrary existing directory, file or foreign link.
    if (!RH3IsRealDirectory(rootTmp) || !RH3IsExpectedDonorTmpLink(secondaryTmp)) {
        error = RH3Error(BootstrapErrorCodeFailedExtracting,
                         @"Unexpected RootHide tmp layout; preserving both containers for recovery");
        goto cleanup_both;
    }
    if (unlink(secondaryTmp.fileSystemRepresentation) != 0) {
        error = RH3Error(BootstrapErrorCodeFailedExtracting,
                         [NSString stringWithFormat:@"Cannot unlink donor var/tmp symlink: %s", strerror(errno)]);
        goto cleanup_both;
    }
    if (![fm moveItemAtPath:rootTmp toPath:secondaryTmp error:&error] ||
        ![fm createSymbolicLinkAtPath:rootTmp withDestinationPath:@"var/tmp" error:&error] ||
        ![fm createSymbolicLinkAtPath:[secondary stringByAppendingPathComponent:@".jbroot"]
                    withDestinationPath:root error:&error]) goto cleanup_both;

    if (![RH3BootstrapProfile(version) writeToFile:
          [root stringByAppendingPathComponent:@".roothide3-bootstrap-profile.plist"] atomically:YES]) {
        error = RH3Error(BootstrapErrorCodeFailedExtracting, @"Could not persist RootHide bootstrap OS/ABI profile");
        goto cleanup_both;
    }
    error = [self rh3BuildPackageSourcesInRoot:root version:version];
    if (!error) error = RH3WritePendingState(root, @"layout");
    if (!error) return nil;

cleanup_both:
cleanup_root:
    // A failed extraction can leave the only available recovery state in these
    // containers. Never recursively delete even a newly allocated .jbroot;
    // the explicit 'creating' marker prevents accidental reuse by this port.
    return error ?: RH3Error(BootstrapErrorCodeFailedExtracting,
                            @"RootHide bootstrap layout incomplete; manual recovery required");
}

// Recover only the verified interrupted layout from the iOS 16 donor
// var/tmp -> ../tmp collision. Do not traverse other .jbroot containers,
// delete directories, or repeat package/setup scripts.
- (NSError *)rh3RecoverTmpCollisionAtRoot:(NSString *)root version:(NSInteger)version
{
    if (version != 1900 || NSProcessInfo.processInfo.operatingSystemVersion.majorVersion != 16)
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"The interrupted RootHide tmp layout has an incompatible bootstrap profile");
    NSString *secondary = [RH3AppGroupDirectory stringByAppendingPathComponent:root.lastPathComponent];
    if (!RH3IsKnownTmpCollision(root, secondary))
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Unknown interrupted RootHide layout; manual recovery required");
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *rootTmp = [root stringByAppendingPathComponent:@"tmp"];
    NSString *secondaryTmp = [secondary stringByAppendingPathComponent:@"var/tmp"];
    NSError *error = nil;
    // Only the donor symlink is removed, after lstat and exact target check.
    if (unlink(secondaryTmp.fileSystemRepresentation) != 0)
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        [NSString stringWithFormat:@"Cannot unlink verified RootHide var/tmp (%s)", strerror(errno)]);
    if (![fm moveItemAtPath:rootTmp toPath:secondaryTmp error:&error] ||
        ![fm createSymbolicLinkAtPath:rootTmp withDestinationPath:@"var/tmp" error:&error] ||
        ![fm createSymbolicLinkAtPath:[secondary stringByAppendingPathComponent:@".jbroot"]
                 withDestinationPath:root error:&error])
        return error ?: RH3Error(BootstrapErrorCodeFailedReplacing,
                                 @"RootHide tmp recovery was interrupted; manual recovery required");
    if (![RH3BootstrapProfile(version) writeToFile:
          [root stringByAppendingPathComponent:@".roothide3-bootstrap-profile.plist"]
                                      atomically:YES])
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Cannot persist recovered RootHide bootstrap profile");
    error = [self rh3BuildPackageSourcesInRoot:root version:version];
    if (error) return error;
    return RH3WritePendingState(root, @"layout");
}

- (NSError *)rh3RerandomizeRoot:(NSString **)rootPtr
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *oldRoot = *rootPtr;
    NSString *oldName = oldRoot.lastPathComponent;
    NSString *oldSecondary = [RH3AppGroupDirectory stringByAppendingPathComponent:oldName];
    NSError *error = nil;

    if (![DOBootstrapper rootHideBrandForPath:oldRoot] ||
        !RH3IsRealDirectory(oldRoot) || !RH3IsRealDirectory(oldSecondary))
        return RH3Error(BootstrapErrorCodeFailedReplacing, @"Invalid RootHide root for re-randomization");

    for (int attempt = 0; attempt < 16; attempt++) {
        uint64_t brand = RH3NewBrand();
        if (!brand) continue;
        NSString *name = [NSString stringWithFormat:@".jbroot-%016llX", brand];
        NSString *newRoot = [RH3RootDirectory stringByAppendingPathComponent:name];
        NSString *newSecondary = [RH3AppGroupDirectory stringByAppendingPathComponent:name];
        if ([fm attributesOfItemAtPath:newRoot error:nil] ||
            [fm attributesOfItemAtPath:newSecondary error:nil]) continue;

        if (![fm moveItemAtPath:oldRoot toPath:newRoot error:&error]) return error;
        if (![fm moveItemAtPath:oldSecondary toPath:newSecondary error:&error]) {
            NSError *rollbackError = nil;
            if (![fm moveItemAtPath:newRoot toPath:oldRoot error:&rollbackError]) return rollbackError;
            return error;
        }
        NSMutableArray<NSDictionary<NSString *,NSString *> *> *changes = [NSMutableArray new];
        error = [self rh3RepairLinksAtRoot:newRoot secondary:newSecondary
                                 oldRoot:oldRoot oldSecondary:oldSecondary changes:changes];
        if (error) {
            // Undo every changed link before renaming directories back. Failure
            // is reported and not hidden: the user must not run another update
            // against a potentially half-migrated root.
            NSError *rollbackError = nil;
            for (NSDictionary *entry in changes.reverseObjectEnumerator) {
                if (![self rh3ReplaceSymlinkAtPath:entry[@"path"]
                                   withDestination:entry[@"old"] error:&rollbackError]) break;
            }
            if (!rollbackError && ![fm moveItemAtPath:newSecondary toPath:oldSecondary error:&rollbackError]) {
                // Keep both new directories together if rollback is incomplete.
            }
            if (!rollbackError && ![fm moveItemAtPath:newRoot toPath:oldRoot error:&rollbackError]) {
                // The caller will see a hard failure rather than using stale paths.
            }
            return rollbackError ?: error;
        }
        *rootPtr = newRoot;
        return nil;
    }
    return RH3Error(BootstrapErrorCodeFailedReplacing,
                    @"Could not allocate an unused RootHide jbrand after 16 attempts");
}

- (NSError *)rh3InstallBasebinAtRoot:(NSString *)root
{
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *oldBasebin = [root stringByAppendingPathComponent:@"basebin"];
    NSString *backup = [root stringByAppendingPathComponent:@"basebin.roothide3-backup"];
    NSError *error = nil;
    struct stat backupInfo;
    if (lstat(backup.fileSystemRepresentation, &backupInfo) == 0) {
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"A previous RootHide basebin backup exists; refusing to overwrite it");
    }
    if (errno != ENOENT)
        return RH3Error(BootstrapErrorCodeFailedReplacing, @"Unable to inspect RootHide BaseBin backup");
    struct stat basebinInfo;
    BOOL hadBasebin = lstat(oldBasebin.fileSystemRepresentation, &basebinInfo) == 0;
    if (hadBasebin && !S_ISDIR(basebinInfo.st_mode))
        return RH3Error(BootstrapErrorCodeFailedReplacing, @"RootHide BaseBin is not a real directory");
    if (!hadBasebin && errno != ENOENT)
        return RH3Error(BootstrapErrorCodeFailedReplacing, @"Unable to inspect existing RootHide BaseBin");
    // A disabled-tweaks setting is stored inside the old BaseBin. Preserve it
    // before replacing the directory, including on a bootstrap retry.
    NSString *safeModePath = [oldBasebin stringByAppendingPathComponent:@".safe_mode"];
    struct stat safeModeInfo;
    BOOL preserveSafeMode = hadBasebin && lstat(safeModePath.fileSystemRepresentation, &safeModeInfo) == 0;
    if (preserveSafeMode && !S_ISREG(safeModeInfo.st_mode))
        return RH3Error(BootstrapErrorCodeFailedReplacing, @"Unsafe RootHide safe-mode marker type");
    if (hadBasebin && !preserveSafeMode && errno != ENOENT)
        return RH3Error(BootstrapErrorCodeFailedReplacing, @"Unable to inspect RootHide safe-mode marker");
    if (hadBasebin && ![fm moveItemAtPath:oldBasebin toPath:backup error:&error]) return error;
    NSString *archive = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"basebin.tar"];
    error = [self extractTar:archive toPath:root];
    if (!error && preserveSafeMode) {
        NSString *newSafeMode = [oldBasebin stringByAppendingPathComponent:@".safe_mode"];
        struct stat newInfo;
        if (lstat(newSafeMode.fileSystemRepresentation, &newInfo) == 0) {
            if (!S_ISREG(newInfo.st_mode))
                error = RH3Error(BootstrapErrorCodeFailedReplacing, @"Unsafe extracted safe-mode marker type");
        } else if (errno != ENOENT) {
            error = RH3Error(BootstrapErrorCodeFailedReplacing, @"Unable to inspect new safe-mode marker");
        }
        if (!error && ![[NSData data] writeToFile:newSafeMode atomically:YES])
            error = RH3Error(BootstrapErrorCodeFailedReplacing, @"Unable to preserve RootHide safe mode");
    }
    // RootHide 3 currently uploads the BaseBin trustcache included in
    // basebin.tar. The 2.x donor instead regenerated a randomized cache,
    // but that path has not been integrated into our Dopamine 3 loader.
    // Reject an invalid archive here, while the previous BaseBin is still
    // available for rollback. The loader validates the cache contents.
    NSString *trustcache = [oldBasebin stringByAppendingPathComponent:@"basebin.tc"];
    struct stat trustcacheInfo;
    if (!error && (lstat(trustcache.fileSystemRepresentation, &trustcacheInfo) != 0 ||
                   !S_ISREG(trustcacheInfo.st_mode) || trustcacheInfo.st_size <= 0)) {
        error = RH3Error(BootstrapErrorCodeFailedReplacing,
                         @"RootHide BaseBin archive has no regular packaged trustcache");
    }
    if (error) {
        NSError *rollbackError = nil;
        if ([fm attributesOfItemAtPath:oldBasebin error:nil] &&
            ![fm removeItemAtPath:oldBasebin error:&rollbackError])
            return RH3Error(BootstrapErrorCodeFailedReplacing,
                            [NSString stringWithFormat:@"BaseBin removal failed; backup retained at %@: %@",
                             backup, rollbackError.localizedDescription]);
        if (hadBasebin && ![fm moveItemAtPath:backup toPath:oldBasebin error:&rollbackError])
            return RH3Error(BootstrapErrorCodeFailedReplacing,
                            [NSString stringWithFormat:@"BaseBin rollback failed; backup retained at %@: %@",
                             backup, rollbackError.localizedDescription]);
        return error;
    }
    if (hadBasebin && ![fm removeItemAtPath:backup error:&error]) return error;
    NSString *bundleIdentifier = NSBundle.mainBundle.bundleIdentifier;
    if (bundleIdentifier) {
        [bundleIdentifier writeToFile:[oldBasebin stringByAppendingPathComponent:@".AppIdentifier"]
                           atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    [self patchBasebinDaemonPlists];
    return nil;
}

// Dopamine's bundled dependency debs install into /var/jb. Running dpkg -i on
// them would create a visible rootless bootstrap on a RootHide installation.
// Instead unpack into a private staging directory and install only their
// precisely enumerated files inside the verified hidden root.
- (NSError *)rh3InstallDependenciesAtRoot:(NSString *)root
{
    if (![DOBootstrapper rootHideBrandForPath:root] || !RH3IsRealDirectory(root))
        return RH3Error(BootstrapErrorCodeFailedFinalising, @"Invalid RootHide dependency destination");
    if (geteuid() != 0)
        return RH3Error(BootstrapErrorCodeFailedFinalising, @"RootHide dependencies require root privileges");

    NSArray<NSDictionary<NSString *, NSString *> *> *files = @[
        @{@"package":@"libroot.deb", @"from":@"var/jb/usr/lib/libroot.dylib", @"to":@"usr/lib/libroot.dylib"},
        @{@"package":@"libkrw-dopamine.deb", @"from":@"var/jb/usr/lib/libkrw/libkrw-dopamine.dylib", @"to":@"usr/lib/libkrw/libkrw-dopamine.dylib"},
        @{@"package":@"basebin-link.deb", @"from":@"var/jb/usr/bin/jbctl", @"to":@"usr/bin/jbctl", @"target":@"../../basebin/jbctl"},
        @{@"package":@"basebin-link.deb", @"from":@"var/jb/usr/bin/opainject", @"to":@"usr/bin/opainject", @"target":@"../../basebin/opainject"},
        @{@"package":@"basebin-link.deb", @"from":@"var/jb/usr/lib/libjailbreak.dylib", @"to":@"usr/lib/libjailbreak.dylib", @"target":@"../../basebin/libjailbreak.dylib"},
    ];
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *stage = [root stringByAppendingPathComponent:
                       [@".roothide3-deps-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    NSError *error = nil;
    if (![fm createDirectoryAtPath:stage withIntermediateDirectories:NO
                       attributes:@{NSFilePosixPermissions:@0700} error:&error]) return error;

    NSMutableDictionary<NSString *,NSString *> *unpacked = [NSMutableDictionary new];
    NSMutableArray<NSDictionary<NSString *,NSString *> *> *applied = [NSMutableArray new];
    for (NSUInteger index = 0; index < files.count; index++) {
        NSDictionary<NSString *,NSString *> *file = files[index];
        NSString *packageName = file[@"package"];
        NSString *directory = unpacked[packageName];
        if (!directory) {
            NSString *package = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:packageName];
            struct stat packageInfo;
            if (lstat(package.fileSystemRepresentation, &packageInfo) != 0 || !S_ISREG(packageInfo.st_mode)) {
                error = RH3Error(BootstrapErrorCodeFailedFinalising,
                                 [NSString stringWithFormat:@"Missing bundled RootHide dependency %@", packageName]);
                break;
            }
            directory = [stage stringByAppendingPathComponent:
                         [NSString stringWithFormat:@"package-%lu", (unsigned long)unpacked.count]];
            if (exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg-deb"), "-x",
                                 package.fileSystemRepresentation, directory.fileSystemRepresentation, NULL) != 0) {
                error = RH3Error(BootstrapErrorCodeFailedFinalising,
                                 [NSString stringWithFormat:@"Cannot unpack RootHide dependency %@", packageName]);
                break;
            }
            unpacked[packageName] = directory;
        }
        NSString *source = [directory stringByAppendingPathComponent:file[@"from"]];
        NSString *target = [root stringByAppendingPathComponent:file[@"to"]];
        NSString *parent = target.stringByDeletingLastPathComponent;
        struct stat sourceInfo;
        BOOL shouldBeLink = [packageName isEqualToString:@"basebin-link.deb"];
        if (lstat(source.fileSystemRepresentation, &sourceInfo) != 0 ||
            !(shouldBeLink ? S_ISLNK(sourceInfo.st_mode) : S_ISREG(sourceInfo.st_mode)) ||
            !RH3IsRealDirectory(parent)) {
            error = RH3Error(BootstrapErrorCodeFailedFinalising,
                             [NSString stringWithFormat:@"Unexpected RootHide dependency layout %@", file[@"to"]]);
            break;
        }
        if (shouldBeLink &&
            ![[fm destinationOfSymbolicLinkAtPath:source error:nil] isEqualToString:file[@"target"]]) {
            error = RH3Error(BootstrapErrorCodeFailedFinalising,
                             [NSString stringWithFormat:@"Untrusted dependency symlink target in %@", file[@"from"]]);
            break;
        }
        NSString *prepared = [stage stringByAppendingPathComponent:
                              [NSString stringWithFormat:@"prepared-%lu", (unsigned long)index]];
        NSString *backup = [stage stringByAppendingPathComponent:
                            [NSString stringWithFormat:@"backup-%lu", (unsigned long)index]];
        // Do not rely on Foundation's copyItem semantics for symbolic links:
        // explicitly recreate only the checked relative target from our
        // basebin-link payload. This cannot resolve through /var/jb.
        if (shouldBeLink) {
            if (![fm createSymbolicLinkAtPath:prepared withDestinationPath:file[@"target"]
                                    error:&error]) break;
        } else if (![fm copyItemAtPath:source toPath:prepared error:&error]) {
            break;
        }
        struct stat previousInfo;
        BOOL hadPrevious = lstat(target.fileSystemRepresentation, &previousInfo) == 0;
        if (hadPrevious && S_ISDIR(previousInfo.st_mode)) {
            error = RH3Error(BootstrapErrorCodeFailedReplacing,
                             [NSString stringWithFormat:@"Refusing to replace directory %@", target]);
            break;
        }
        if (hadPrevious && ![fm moveItemAtPath:target toPath:backup error:&error]) break;
        // Record before installation: rollback also covers a failed move.
        [applied addObject:@{@"target":target, @"backup":backup,
                             @"previous":hadPrevious ? @"1" : @"0"}];
        if (![fm moveItemAtPath:prepared toPath:target error:&error]) break;
    }
    if (error) {
        NSError *rollbackError = nil;
        for (NSDictionary *entry in applied.reverseObjectEnumerator) {
            NSString *target = entry[@"target"];
            if (lstat(target.fileSystemRepresentation, &(struct stat){0}) == 0 &&
                ![fm removeItemAtPath:target error:&rollbackError]) break;
            if ([entry[@"previous"] isEqualToString:@"1"] &&
                ![fm moveItemAtPath:entry[@"backup"] toPath:target error:&rollbackError]) break;
        }
        if (rollbackError) {
            // Never erase staged backups when an attempted rollback failed.
            return RH3Error(BootstrapErrorCodeFailedReplacing,
                            [NSString stringWithFormat:@"Dependency rollback incomplete at %@: %@",
                             stage, rollbackError.localizedDescription]);
        }
    }
    NSError *cleanupError = nil;
    if (![fm removeItemAtPath:stage error:&cleanupError])
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        [NSString stringWithFormat:@"RootHide dependency staging could not be removed at %@: %@; manual recovery required",
                         stage, cleanupError.localizedDescription]);
    return error;
}

- (void)prepareRootHideBootstrapWithCompletion:(void (^)(NSError *))completion
{
    // The RootHide package ABI name is not a CPU restriction: every bundled
    // bootstrap executable and manager includes ARM64. Keep Dopamine's
    // device/build exploit checks, plus the explicit experimental OS profiles.
    NSInteger version = rh3_bootstrap_version_for_os((int)NSProcessInfo.processInfo.operatingSystemVersion.majorVersion);
    if (!version || ![[DOEnvironmentManager sharedManager] isSupported]) {
        completion(RH3Error(BootstrapErrorCodeFailedExtracting,
                           @"No RootHide bootstrap profile or Dopamine exploit combination for this device/iOS"));
        return;
    }
    NSError *error = [self rh3VerifyAssetsForVersion:version];
    if (error) { completion(error); return; }

    NSFileManager *fm = NSFileManager.defaultManager;
    if ([self fileOrSymlinkExistsAtPath:@"/var/jb"]) {
        completion(RH3Error(BootstrapErrorCodeFailedReplacing,
                            @"A conventional /var/jb bootstrap already exists. RootHide 3 will not replace it."));
        return;
    }
    NSString *existingPath = gSystemInfo.jailbreakInfo.rootPath
        ? [NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath] : nil;
    if (existingPath.length && ![DOBootstrapper rootHideBrandForPath:existingPath]) {
        completion(RH3Error(BootstrapErrorCodeFailedReplacing,
                            @"The active jailbreak root is not a RootHide .jbroot container"));
        return;
    }
    NSString *root = [DOBootstrapper rootHideExistingRootWithError:&error];
    if (error) { completion(error); return; }
    if (existingPath.length && root && ![existingPath isEqualToString:root]) {
        completion(RH3Error(BootstrapErrorCodeFailedReplacing,
                            @"Active RootHide path does not match the verified container"));
        return;
    }
    if (root) {
        error = RH3CheckInterruptedOperations(root);
        if (error) { completion(error); return; }
        NSString *stage = RH3PendingState(root);
        if ([stage isEqualToString:@"creating"] &&
            RH3IsKnownTmpCollision(root, [RH3AppGroupDirectory stringByAppendingPathComponent:root.lastPathComponent])) {
            [[DOUIManager sharedInstance] sendLog:@"Repairing verified RootHide donor tmp symlink collision" debug:NO];
            error = [self rh3RecoverTmpCollisionAtRoot:root version:version];
            if (error) { completion(error); return; }
            stage = RH3PendingState(root);
        }
        if ([stage isEqualToString:@"creating"] || [stage isEqualToString:@"running-script"]) {
            if ([stage isEqualToString:@"running-script"])
                RH3LogInterruptedBootstrapSnapshot(root);
            completion(RH3Error(BootstrapErrorCodeFailedReplacing,
                @"Interrupted RootHide extraction or setup script needs manual recovery. Export the RootHide diagnostic log; the existing bootstrap and marker were preserved."));
            return;
        }
        // Re-randomizing a half-installed root would make an interrupted
        // transaction harder to recover. Keep its jbrand until setup finishes.
        error = RH3CheckBootstrapProfile(root, version);
        if (error) { completion(error); return; }
        if (!stage) {
            [[DOUIManager sharedInstance] sendLog:@"Re-randomizing RootHide bootstrap" debug:NO];
            error = [self rh3RerandomizeRoot:&root];
            if (error) { completion(error); return; }
        } else {
            [[DOUIManager sharedInstance] sendLog:@"Resuming RootHide 3 installation" debug:NO];
        }
    } else {
        for (int attempt = 0; attempt < 16; attempt++) {
            uint64_t brand = RH3NewBrand();
            if (!brand) continue;
            NSString *name = [NSString stringWithFormat:@".jbroot-%016llX", brand];
            NSDictionary *preserved = RH3RecoveryInspect(RH3RootDirectory, RH3AppGroupDirectory, 0, &error);
            if (error) { completion(error); return; }
            if ([name isEqual:preserved[@"Name"]]) continue;
            NSString *candidate = [RH3RootDirectory stringByAppendingPathComponent:name];
            NSString *secondary = [RH3AppGroupDirectory stringByAppendingPathComponent:name];
            if ([fm fileExistsAtPath:candidate] || [fm fileExistsAtPath:secondary]) continue;
            root = candidate;
            break;
        }
        if (!root) {
            completion(RH3Error(BootstrapErrorCodeFailedExtracting,
                                @"Could not allocate a new RootHide container"));
            return;
        }
        [[DOUIManager sharedInstance] sendLog:@"Extracting isolated RootHide bootstrap" debug:NO];
        error = [self rh3CreateRoot:root version:version];
        if (error) { completion(error); return; }
    }

    gSystemInfo.jailbreakInfo.rootPath = strdup(root.fileSystemRepresentation);
    gSystemInfo.jailbreakInfo.jbrand = [DOBootstrapper rootHideBrandForPath:root];
    if (!gSystemInfo.jailbreakInfo.jbrand) {
        completion(RH3Error(BootstrapErrorCodeFailedExtracting, @"Invalid RootHide jbrand"));
        return;
    }

    error = [self rh3InstallBasebinAtRoot:root];
    if (!error) error = [self rh3BuildPackageSourcesInRoot:root version:version];
    // Once prep_bootstrap.sh has succeeded it removes itself; never downgrade
    // script-complete to prepared after a later BaseBin refresh.
    if (!error && ![RH3PendingState(root) isEqualToString:@"script-complete"] &&
        RH3PendingState(root)) error = RH3WritePendingState(root, @"prepared");
    if (!error) JBFixMobilePermissions();
    completion(error);
}

- (NSError *)finalizeRootHideBootstrap
{
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: validation starting"];
    NSString *root = gSystemInfo.jailbreakInfo.rootPath
        ? [NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath] : nil;
    if (![DOBootstrapper rootHideBrandForPath:root]) {
        return RH3Error(BootstrapErrorCodeFailedFinalising, @"RootHide container is not initialized");
    }
    NSError *rootError = nil;
    NSString *ownedRoot = [DOBootstrapper rootHideExistingRootWithError:&rootError];
    if (rootError) return rootError;
    if (![root isEqualToString:ownedRoot])
        return RH3Error(BootstrapErrorCodeFailedFinalising,
                        @"Active RootHide root differs from its verified owned container");
    rootError = RH3CheckInterruptedOperations(root);
    if (rootError) return rootError;
    NSFileManager *fm = NSFileManager.defaultManager;
    NSString *marker = [root stringByAppendingPathComponent:RH3InstalledMarker];
    NSString *script = [root stringByAppendingPathComponent:@"prep_bootstrap.sh"];
    NSString *pending = RH3PendingState(root);
    BOOL ranInitialSetup = NO;
    BOOL installed = [[NSString stringWithContentsOfFile:marker
                                               encoding:NSUTF8StringEncoding error:nil] isEqualToString:@"3"];
    if ([pending isEqualToString:@"script-complete"] &&
        [self fileOrSymlinkExistsAtPath:script])
        return RH3Error(BootstrapErrorCodeFailedFinalising,
                        @"RootHide setup script still exists after completion; manual recovery required");
    if ([pending isEqualToString:@"running-script"]) {
        RH3LogInterruptedBootstrapSnapshot(root);
        return RH3Error(BootstrapErrorCodeFailedFinalising,
                        @"RootHide setup script execution was interrupted; manual recovery required");
    }
    if (!installed && ![@[@"prepared", @"script-complete"] containsObject:pending])
        return RH3Error(BootstrapErrorCodeFailedFinalising, @"RootHide bootstrap is not fully prepared");
    if (!installed && [pending isEqualToString:@"prepared"] &&
        ![fm fileExistsAtPath:script])
        return RH3Error(BootstrapErrorCodeFailedFinalising,
                        @"RootHide setup was interrupted while executing its script; manual recovery is required");
    if ([pending isEqualToString:@"prepared"] && [fm fileExistsAtPath:script]) {
        // Verify the daemon with a real, bounded request (not the optimistic
        // launchd port-allocated flag) BEFORE mutating the transaction state.
        // Never replay the donor script if an earlier attempt was interrupted.
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: probing jailbreakd before script (8s limit)"];
        int daemonReply = -1;
        BOOL daemonResponded = RH3AwaitReadinessCheck(^int(void) {
            return jbdTestCall(23);
        }, &daemonReply);
        NSString *daemonDiagnostic = daemonResponded
            ? [NSString stringWithFormat:@"bootstrap: jailbreakd probe returned %d", daemonReply]
            : @"bootstrap: jailbreakd probe timed out (script NOT started)";
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:daemonDiagnostic];
        [[DOUIManager sharedInstance] sendLog:daemonDiagnostic debug:NO];
        if (!daemonResponded || daemonReply != 46)
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                @"RootHide jailbreakd has not confirmed readiness; script not started and prepared state retained. Restart the app after collecting logs; do not manually re-run the script.");

        // Previously exec_cmd_trusted hid this trust RPC inside a macro and
        // ignored its result. Split the steps so a trust failure cannot be
        // mistaken for a script hang or begin a non-idempotent transaction.
        NSString *shell = JBROOT_PATH(@"/bin/sh");
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: trusting shell before script (8s limit)"];
        int shellTrustResult = -1;
        BOOL trustResponded = RH3AwaitReadinessCheck(^int(void) {
            return jbclient_trust_file_by_path(shell.fileSystemRepresentation);
        }, &shellTrustResult);
        NSString *trustDiagnostic = trustResponded
            ? [NSString stringWithFormat:@"bootstrap: shell trust returned %d", shellTrustResult]
            : @"bootstrap: shell trust timed out (script NOT started)";
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:trustDiagnostic];
        [[DOUIManager sharedInstance] sendLog:trustDiagnostic debug:NO];
        if (!trustResponded || shellTrustResult != 0)
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                @"RootHide shell trust failed or timed out; script not started and prepared state retained.");

        // Donor prep_bootstrap.sh loops prompting for a password when this
        // variable is absent. Stock Dopamine's CLI already sets it to 1.
        // Prepare a private environment snapshot before entering the
        // non-idempotent state, without modifying the application's environ.
        size_t environmentCount = 0;
        for (char **entry = environ; entry && *entry; entry++) environmentCount++;
        char **scriptEnvironment = calloc(environmentCount + 2, sizeof(char *));
        if (!scriptEnvironment)
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                @"Cannot allocate RootHide shell environment; script not started and prepared state retained");
        size_t kept = 0;
        for (char **entry = environ; entry && *entry; entry++) {
            if (strncmp(*entry, "NO_PASSWORD_PROMPT=", sizeof("NO_PASSWORD_PROMPT=") - 1) == 0) continue;
            if (kept >= environmentCount || !(scriptEnvironment[kept] = strdup(*entry))) {
                RH3FreeShellEnvironment(scriptEnvironment);
                return RH3Error(BootstrapErrorCodeFailedFinalising,
                    @"Unable to copy RootHide shell environment; script not started and prepared state retained");
            }
            kept++;
        }
        scriptEnvironment[kept++] = strdup("NO_PASSWORD_PROMPT=1");
        if (!scriptEnvironment[kept - 1]) {
            RH3FreeShellEnvironment(scriptEnvironment);
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                @"Unable to prepare RootHide password-prompt bypass; script not started and prepared state retained");
        }
        scriptEnvironment[kept] = NULL;

        // Write this marker ONLY after both preflights succeed. Once the
        // shell spawn begins it may have side effects even if no reply comes
        // back, so never reset or automatically replay this state.
        NSError *stateError = RH3WritePendingState(root, @"running-script");
        if (stateError) {
            RH3FreeShellEnvironment(scriptEnvironment);
            return stateError;
        }
        [[DOUIManager sharedInstance] sendLog:@"Finalizing isolated RootHide bootstrap" debug:NO];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: running-script marker saved; spawning prep_bootstrap.sh"];
        // The pinned donor script has no set -e: without this option a failed
        // firmware/dpkg/password command can be hidden by its final rm exit 0.
        // Scope the prompt bypass to this one shell; the donor is unchanged.
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: launching shell with NO_PASSWORD_PROMPT=1 (scoped child env)"];
        __block pid_t scriptPid = 0;
        __block int result = -1;
        dispatch_group_t launch = dispatch_group_create();
        // The spawn includes child-patching IPC and may itself stall. Ownership
        // of the private environment stays with the worker even after timeout.
        dispatch_group_async(launch, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            result = exec_cmd_env_nowait(&scriptPid, scriptEnvironment, shell.fileSystemRepresentation,
                                         "-e", script.fileSystemRepresentation, NULL);
            RH3FreeShellEnvironment(scriptEnvironment);
        });
        if (dispatch_group_wait(launch, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC)) != 0) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: shell spawn/child-patch timed out; outcome unknown; running-script preserved"];
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                @"RootHide shell launch or child patch did not return within 20 seconds. Export the log and fully reboot; do not replay this bootstrap script.");
        }
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:
            @"bootstrap: shell spawn returned %d (pid %d)", result, scriptPid]];
        if (result == 0 && scriptPid > 1) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: waiting for setup script process exit"];
            result = RH3WaitForBootstrapChild(scriptPid, 180);
            if (result == -ETIMEDOUT)
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: setup script exceeded 180 seconds; child not killed; running-script preserved"];
        } else if (result == 0) {
            result = -1; // Invalid PID: never declare bootstrap success.
        }
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"bootstrap: prep_bootstrap.sh returned %d", result]];
        if (result) {
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                            [NSString stringWithFormat:@"RootHide prep_bootstrap.sh failed (%d); manual recovery required", result]);
        }
        if ([self fileOrSymlinkExistsAtPath:script])
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                            @"RootHide setup returned without removing its script; manual recovery required");
        stateError = RH3WritePendingState(root, @"script-complete");
        if (stateError) return stateError;
        pending = @"script-complete";
        ranInitialSetup = YES;
    }
    if (!ranInitialSetup && ![fm fileExistsAtPath:marker]) {
        // The script removes itself on success, so this state is recoverable
        // only if we durably recorded its successful completion beforehand.
        if (![pending isEqualToString:@"script-complete"])
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                            @"Cannot resume RootHide without completed bootstrap script");
    }
    if (ranInitialSetup) {
        [[DOUIManager sharedInstance] sendLog:@"RootHide bootstrap script completed; installing dependencies" debug:NO];
    }
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: installing RootHide dependencies"];
    // The package payloads generated by Dopamine are rooted at /var/jb;
    // do NOT use dpkg -i for them on RootHide. Install selected contents into
    // this verified hidden root, with backups and rollback.
    NSError *dependenciesError = [self rh3InstallDependenciesAtRoot:root];
    if (dependenciesError) return dependenciesError;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: RootHide dependencies installed"];
    if (!installed) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: installing package managers"];
        NSError *error = [self installPackageManagers];
        if (error) return error;
        NSString *manager = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"roothideapp.deb"];
        if (geteuid() != 0)
            return RH3Error(BootstrapErrorCodeFailedFinalising, @"RootHide Manager installation requires root");
        int managerResult = exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"),
                                             "-i", manager.fileSystemRepresentation, NULL);
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"bootstrap: RootHide Manager dpkg exited %d", managerResult]];
        if (managerResult) {
            return RH3Error(BootstrapErrorCodeFailedFinalising,
                            [NSString stringWithFormat:@"RootHide Manager install failed (%d)", managerResult]);
        }
    }
    if ([self fileOrSymlinkExistsAtPath:@"/var/jb"])
        return RH3Error(BootstrapErrorCodeFailedFinalising,
                        @"A package exposed /var/jb during RootHide setup; refusing to mark it installed");
    if (!installed) {
        NSError *writeError = nil;
        if (![@"3" writeToFile:marker atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) return writeError;
    }
    if (pending && ![fm removeItemAtPath:[root stringByAppendingPathComponent:RH3PendingMarker]
                                   error:nil])
        return RH3Error(BootstrapErrorCodeFailedFinalising, @"Unable to clear RootHide install state");
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"bootstrap: RootHide finalization committed"];
    return nil;
}

- (NSError *)deleteRootHideBootstrap
{
    NSError *error = nil;
    NSString *root = [DOBootstrapper rootHideExistingRootWithError:&error];
    if (error) return error;
    if (!root || ![DOBootstrapper rootHideBrandForPath:root]) {
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Refusing to remove a bootstrap without a verified RootHide 3 root and jbrand");
    }
    NSString *secondary = [RH3AppGroupDirectory stringByAppendingPathComponent:root.lastPathComponent];
    NSFileManager *fm = NSFileManager.defaultManager;
    if (!RH3IsRealDirectory(root) || !RH3IsRealDirectory(secondary) ||
        ![[fm destinationOfSymbolicLinkAtPath:[secondary stringByAppendingPathComponent:@".jbroot"]
                                       error:nil] isEqualToString:root])
        return RH3Error(BootstrapErrorCodeFailedReplacing,
                        @"Refusing to delete unverified RootHide 3 containers");
    // Rename BOTH owned directories to quarantine first. If the second rename
    // fails, restore the first. RootHide2 directories are never selected.
    NSString *suffix = [@".removing-roothide3-" stringByAppendingString:NSUUID.UUID.UUIDString];
    NSString *quarantinedRoot = [root stringByAppendingString:suffix];
    NSString *quarantinedSecondary = [secondary stringByAppendingString:suffix];
    if (![fm moveItemAtPath:root toPath:quarantinedRoot error:&error]) return error;
    if (![fm moveItemAtPath:secondary toPath:quarantinedSecondary error:&error]) {
        NSError *rollback = nil;
        if (![fm moveItemAtPath:quarantinedRoot toPath:root error:&rollback]) return rollback;
        return error;
    }
    // Do not recurse outside these two quarantined, owned directories. An
    // interrupted deletion leaves distinguishable quarantine paths for manual
    // recovery rather than making any other .jbroot eligible for deletion.
    if (![fm removeItemAtPath:quarantinedRoot error:&error]) return error;
    if (![fm removeItemAtPath:quarantinedSecondary error:&error]) return error;
    return nil;
}

@end

#define LIBKRW_DOPAMINE_BUNDLED_VERSION @"2.0.3"
#define LIBROOT_DOPAMINE_BUNDLED_VERSION @"1.0.1"
#define BASEBIN_LINK_BUNDLED_VERSION @"1.0.0"
#define LAUNCHCTL_BUNDLED_VERSION @"1:1.2.0"

static NSDictionary *gBundledPackages = @{
    @"libkrw0-dopamine" : LIBKRW_DOPAMINE_BUNDLED_VERSION,
    @"libroot-dopamine" : LIBROOT_DOPAMINE_BUNDLED_VERSION,
    @"dopamine-basebin-link" : BASEBIN_LINK_BUNDLED_VERSION,
    @"launchctl" : LAUNCHCTL_BUNDLED_VERSION,
};

struct hfs_mount_args {
    char    *fspec;
    uid_t    hfs_uid;        /* uid that owns hfs files (standard HFS only) */
    gid_t    hfs_gid;        /* gid that owns hfs files (standard HFS only) */
    mode_t    hfs_mask;        /* mask to be applied for hfs perms  (standard HFS only) */
    uint32_t hfs_encoding;        /* encoding for this volume (standard HFS only) */
    struct    timezone hfs_timezone;    /* user time zone info (standard HFS only) */
    int        flags;            /* mounting flags, see below */
    int     journal_tbuffer_size;   /* size in bytes of the journal transaction buffer */
    int        journal_flags;          /* flags to pass to journal_open/create */
    int        journal_disable;        /* don't use journaling (potentially dangerous) */
};

NSString *const bootstrapErrorDomain = @"BootstrapErrorDomain";

@implementation DOBootstrapper

- (instancetype)init
{
    self = [super init];
    if (self) {
        /*NSURLSessionConfiguration *config = [NSURLSessionConfiguration backgroundSessionConfigurationWithIdentifier:@"com.opa334.bootstrapper.background-session"];
        _urlSession = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:nil];*/
    }
    return self;
}

- (NSError *)extractTar:(NSString *)tarPath toPath:(NSString *)destinationPath
{
    int r = libarchive_unarchive(tarPath.fileSystemRepresentation, destinationPath.fileSystemRepresentation);
    if (r != 0) {
        return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"libarchive returned %d", r]}];
    }
    return nil;
}

- (BOOL)deleteSymlinkAtPath:(NSString *)path error:(NSError **)error
{
    NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:error];
    if (!attributes) return YES;
    if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
        return [[NSFileManager defaultManager] removeItemAtPath:path error:error];
    }
    return NO;
}

- (BOOL)fileOrSymlinkExistsAtPath:(NSString *)path
{
    if ([[NSFileManager defaultManager] fileExistsAtPath:path]) return YES;
    
    NSDictionary<NSFileAttributeKey, id> *attributes = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
    if (attributes) {
        if (attributes[NSFileType] == NSFileTypeSymbolicLink) {
            return YES;
        }
    }
    
    return NO;
}

- (NSError *)createSymlinkAtPath:(NSString *)path toPath:(NSString *)destinationPath createIntermediateDirectories:(BOOL)createIntermediate
{
    NSError *error;
    NSString *parentPath = [path stringByDeletingLastPathComponent];
    if (![[NSFileManager defaultManager] fileExistsAtPath:parentPath]) {
        if (!createIntermediate) return [NSError errorWithDomain:bootstrapErrorDomain code:-1 userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed create %@->%@ symlink: Parent dir does not exists", path, destinationPath]}];
        if (![[NSFileManager defaultManager] createDirectoryAtPath:parentPath withIntermediateDirectories:YES attributes:nil error:&error]) return error;
    }
    
    [[NSFileManager defaultManager] createSymbolicLinkAtPath:path withDestinationPath:destinationPath error:&error];
    return error;
}

- (BOOL)isPrivatePrebootMountedWritable
{
    struct statfs ppStfs;
    statfs([[DOEnvironmentManager sharedManager] privatePrebootPath].fileSystemRepresentation, &ppStfs);
    return !(ppStfs.f_flags & MNT_RDONLY);
}

- (int)remountPrivatePrebootWritable:(BOOL)writable
{
    const char *ppPath = [[DOEnvironmentManager sharedManager] privatePrebootPath].fileSystemRepresentation;

    struct statfs ppStfs;
    int r = statfs(ppPath, &ppStfs);
    if (r != 0) return r;
    
    uint32_t flags = MNT_UPDATE;
    if (!writable) {
        flags |= MNT_RDONLY;
    }
    struct hfs_mount_args mntargs =
    {
        .fspec = ppStfs.f_mntfromname,
        .hfs_mask = 0,
    };
    return mount("apfs", ppPath, flags, &mntargs);
}

- (NSError *)ensurePrivatePrebootIsWritable
{
    if (![self isPrivatePrebootMountedWritable]) {
        int r = [self remountPrivatePrebootWritable:YES];
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedRemount userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Remounting /private/preboot as writable failed with error: %s", strerror(errno)]}];
        }
    }
    return nil;
}

- (void)fixupPathPermissions
{
    // Ensure the following paths are owned by root:wheel and have permissions of 755:
    // /private
    // /private/preboot
    // /private/preboot/UUID
    // /private/preboot/UUID/dopamine-<UUID>
    // /private/preboot/UUID/dopamine-<UUID>/procursus

    NSString *tmpPath = JBROOT_PATH(@"/");
    while (![tmpPath isEqualToString:@"/"]) {
        struct stat s;
        stat(tmpPath.fileSystemRepresentation, &s);
        if (s.st_uid != 0 || s.st_gid != 0) {
            chown(tmpPath.fileSystemRepresentation, 0, 0);
        }
        if ((s.st_mode & S_IRWXU) != 0755) {
            chmod(tmpPath.fileSystemRepresentation, 0755);
        }
        tmpPath = [tmpPath stringByDeletingLastPathComponent];
    }
}

- (void)patchBasebinDaemonPlist:(NSString *)plistPath
{
    NSMutableDictionary *plistDict = [NSMutableDictionary dictionaryWithContentsOfFile:plistPath];
    if (plistDict) {
        bool madeChanges = NO;
        NSMutableArray *programArguments = ((NSArray *)plistDict[@"ProgramArguments"]).mutableCopy;
        for (NSString *argument in [programArguments reverseObjectEnumerator]) {
            if ([argument containsString:@"@JBROOT@"]) {
                programArguments[[programArguments indexOfObject:argument]] = [argument stringByReplacingOccurrencesOfString:@"@JBROOT@" withString:JBROOT_PATH(@"/")];
                madeChanges = YES;
            }
        }
        if (madeChanges) {
            plistDict[@"ProgramArguments"] = programArguments.copy;
            [plistDict writeToFile:plistPath atomically:NO];
        }
    }
}

- (void)patchBasebinDaemonPlists
{
    NSURL *basebinDaemonsURL = [NSURL fileURLWithPath:JBROOT_PATH(@"/basebin/LaunchDaemons")];
    for (NSURL *basebinDaemonURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:basebinDaemonsURL includingPropertiesForKeys:nil options:0 error:nil]) {
        [self patchBasebinDaemonPlist:basebinDaemonURL.path];
    }
}

- (NSString *)bootstrapVersion
{
    uint64_t cfver = (((uint64_t)kCFCoreFoundationVersionNumber / 100) * 100);
    if (cfver >= 2000) {
        return @"1900";
    }
    return [NSString stringWithFormat:@"%llu", cfver];
}

- (NSURL *)bootstrapURL
{
    return [NSURL URLWithString:[NSString stringWithFormat:@"https://apt.procurs.us/bootstraps/%@/bootstrap-ssh-iphoneos-arm64.tar.zst", [self bootstrapVersion]]];
}

/*- (void)downloadBootstrapWithCompletion:(void (^)(NSString *path, NSError *error))completion
{
    NSURL *bootstrapURL = [self bootstrapURL];
    if (!bootstrapURL) {
        completion(nil, [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedToGetURL userInfo:@{NSLocalizedDescriptionKey : @"Failed to obtain bootstrap URL"}]);
        return;
    }
    
    _downloadCompletionBlock = ^(NSURL * _Nullable location, NSError * _Nullable error) {
        NSError *ourError;
        if (error) {
            ourError = [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedToDownload userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to download bootstrap: %@", error.localizedDescription]}];
        }
        completion(location.path, ourError);
    };
    
    _bootstrapDownloadTask = [_urlSession downloadTaskWithURL:bootstrapURL];
    [_bootstrapDownloadTask resume];
}*/

- (void)extractBootstrap:(NSString *)path withCompletion:(void (^)(NSError *))completion
{
    NSString *bootstrapTar = [@"/var/tmp" stringByAppendingPathComponent:@"bootstrap.tar"];
    NSError *decompressionError = [self decompressZstd:path toTar:bootstrapTar];
    if (decompressionError) {
        completion(decompressionError);
        return;
    }
    
    decompressionError = [self extractTar:bootstrapTar toPath:@"/"];
    if (decompressionError) {
        completion(decompressionError);
        return;
    }
    
    [[NSData data] writeToFile:JBROOT_PATH(@"/.installed_dopamine") atomically:YES];
    completion(nil);
}

- (NSError *)updateVarJbSymlink
{
    // Remove /var/jb as it might be wrong
    NSError *error;
    if (![self deleteSymlinkAtPath:@"/var/jb" error:&error]) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:@"/var/jb"]) {
            if (![[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:&error]) {
                return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb directory failed with error: %@", error]}];
            }
        }
        else {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedReplacing userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Removing /var/jb symlink failed with error: %@", error]}];
        }
    }

    return [self createSymlinkAtPath:@"/var/jb" toPath:JBROOT_PATH(@"/") createIntermediateDirectories:YES];;
}

- (void)prepareBootstrapWithCompletion:(void (^)(NSError *))completion
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        [self prepareRootHideBootstrapWithCompletion:completion];
        return;
    }
    [[DOUIManager sharedInstance] sendLog:@"Updating BaseBin" debug:NO];

    // Ensure /private/preboot is mounted writable (Not writable by default on iOS <=15)
    NSError *error = [self ensurePrivatePrebootIsWritable];
    if (error) {
        completion(error);
        return;
    }
    
    [self fixupPathPermissions];
    
    // Clean up xinaA15 v1 leftovers if desired
    if (![[NSFileManager defaultManager] fileExistsAtPath:@"/var/.keep_symlinks"]) {
        NSArray *xinaLeftoverSymlinks = @[
            @"/var/alternatives",
            @"/var/ap",
            @"/var/apt",
            @"/var/bin",
            @"/var/bzip2",
            @"/var/cache",
            @"/var/dpkg",
            @"/var/etc",
            @"/var/gzip",
            @"/var/lib",
            @"/var/Lib",
            @"/var/libexec",
            @"/var/Library",
            @"/var/LIY",
            @"/var/Liy",
            @"/var/local",
            @"/var/newuser",
            @"/var/profile",
            @"/var/sbin",
            @"/var/suid_profile",
            @"/var/sh",
            @"/var/sy",
            @"/var/share",
            @"/var/ssh",
            @"/var/sudo_logsrvd.conf",
            @"/var/suid_profile",
            @"/var/sy",
            @"/var/usr",
            @"/var/zlogin",
            @"/var/zlogout",
            @"/var/zprofile",
            @"/var/zshenv",
            @"/var/zshrc",
            @"/var/log/dpkg",
            @"/var/log/apt",
        ];
        NSArray *xinaLeftoverFiles = @[
            @"/var/lib",
            @"/var/master.passwd"
        ];
        
        for (NSString *xinaLeftoverSymlink in xinaLeftoverSymlinks) {
            [self deleteSymlinkAtPath:xinaLeftoverSymlink error:nil];
        }
        
        for (NSString *xinaLeftoverFile in xinaLeftoverFiles) {
            if ([[NSFileManager defaultManager] fileExistsAtPath:xinaLeftoverFile]) {
                [[NSFileManager defaultManager] removeItemAtPath:xinaLeftoverFile error:nil];
            }
        }
    }
    
    NSString *basebinPath = JBROOT_PATH(@"/basebin");
    NSString *installedPath = JBROOT_PATH(@"/.installed_dopamine");
    error = [self updateVarJbSymlink];
    if (error) {
        completion(error);
        return;
    }
    
    if ([[NSFileManager defaultManager] fileExistsAtPath:basebinPath]) {
        if (![[NSFileManager defaultManager] removeItemAtPath:basebinPath error:&error]) {
            BOOL recovered = NO;

            NSString *corruptedFilePath = JBROOT_PATH(@"/basebin/gen/dyld.old");
            if ([[NSFileManager defaultManager] fileExistsAtPath:corruptedFilePath]) {
                if (![[NSFileManager defaultManager] removeItemAtPath:corruptedFilePath error:nil]) {
                    // Try to recover from file system corruption
                    // In Dopamine 3.0 - 3.0.6 there was an OOB kwritebuf in jbupdate that could cause a panic
                    // This would sometimes leave /var/jb/basebin/gen/dyld.old behind in a corrupted state
                    // We cannot delete this file unfortunately, but we can move it

                    NSString *activePrebootPath = [[DOEnvironmentManager sharedManager] activePrebootPath];

                    NSString *characterSet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                    NSUInteger stringLen = 6;
                    NSMutableString *randomString = [NSMutableString stringWithCapacity:stringLen];
                    for (NSUInteger i = 0; i < stringLen; i++) {
                        NSUInteger randomIndex = arc4random_uniform((uint32_t)[characterSet length]);
                        unichar randomCharacter = [characterSet characterAtIndex:randomIndex];
                        [randomString appendFormat:@"%C", randomCharacter];
                    }

                    NSString *orphanedName = [NSString stringWithFormat:@"orphaned-%@", randomString];
                    NSString *orphanedPath = [activePrebootPath stringByAppendingPathComponent:orphanedName];
                    [[NSFileManager defaultManager] moveItemAtPath:corruptedFilePath toPath:orphanedPath error:nil];

                    if ([[NSFileManager defaultManager] removeItemAtPath:basebinPath error:&error]) {
                        // If now that the file is moved, we can remove the basebin dir, consider the issue solved
                        recovered = YES;
                        error = nil;
                    }
                }
            }

            if (!recovered) {
                completion([NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedExtracting userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed deleting existing basebin file with error: %@", error.localizedDescription]}]);
                return;
            }
        }
    }
    error = [self extractTar:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin.tar"] toPath:JBROOT_PATH(@"/")];
    if (error) {
        completion(error);
        return;
    }
    [self patchBasebinDaemonPlists];
    
    void (^bootstrapFinishedCompletion)(NSError *) = ^(NSError *error){
        if (error) {
            completion(error);
            return;
        }
        
        NSString *defaultSources = @"Types: deb\n"
            @"URIs: https://repo.chariz.com/\n"
            @"Suites: ./\n"
            @"Components:\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: https://havoc.app/\n"
            @"Suites: ./\n"
            @"Components:\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: http://apt.thebigboss.org/repofiles/cydia/\n"
            @"Suites: stable\n"
            @"Components: main\n"
            @"\n"
            @"Types: deb\n"
            @"URIs: https://ellekit.space/\n"
            @"Suites: ./\n"
            @"Components:\n";
        [defaultSources writeToFile:JBROOT_PATH(@"/etc/apt/sources.list.d/default.sources") atomically:NO encoding:NSUTF8StringEncoding error:nil];
        
        NSString *mobilePreferencesPath = JBROOT_PATH(@"/var/mobile/Library/Preferences");
        if (![[NSFileManager defaultManager] fileExistsAtPath:mobilePreferencesPath]) {
            NSDictionary<NSFileAttributeKey, id> *attributes = @{
                NSFilePosixPermissions : @0755,
                NSFileOwnerAccountID : @501,
                NSFileGroupOwnerAccountID : @501,
            };
            [[NSFileManager defaultManager] createDirectoryAtPath:mobilePreferencesPath withIntermediateDirectories:YES attributes:attributes error:nil];
        }
        
        JBFixMobilePermissions();

        completion(nil);
    };
    
    
    BOOL needsBootstrap = ![[NSFileManager defaultManager] fileExistsAtPath:installedPath];
    if (needsBootstrap) {
        // First, wipe any existing content that's not basebin
        for (NSURL *subItemURL in [[NSFileManager defaultManager] contentsOfDirectoryAtURL:[NSURL fileURLWithPath:JBROOT_PATH(@"/")] includingPropertiesForKeys:nil options:0 error:nil]) {
            if (![subItemURL.lastPathComponent isEqualToString:@"basebin"]) {
                [[NSFileManager defaultManager] removeItemAtURL:subItemURL error:nil];
            }
        }
        
        /*void (^bootstrapDownloadCompletion)(NSString *, NSError *) = ^(NSString *path, NSError *error) {
            if (error) {
                completion(error);
                return;
            }
            [self extractBootstrap:path withCompletion:bootstrapFinishedCompletion];
        };*/
        
        [[DOUIManager sharedInstance] sendLog:@"Extracting Bootstrap" debug:NO];

        NSString *bootstrapZstdPath = [NSString stringWithFormat:@"%@/bootstrap_%@.tar.zst", [NSBundle mainBundle].bundlePath, [self bootstrapVersion]];
        [self extractBootstrap:bootstrapZstdPath withCompletion:bootstrapFinishedCompletion];

        /*NSString *documentsCandidate = @"/var/mobile/Documents/bootstrap.tar.zstd";
        NSString *bundleCandidate = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"bootstrap.tar.zstd"];
        // Check if the user provided a bootstrap
        if ([[NSFileManager defaultManager] fileExistsAtPath:documentsCandidate]) {
            bootstrapDownloadCompletion(documentsCandidate, nil);
        }
        else if ([[NSFileManager defaultManager] fileExistsAtPath:bundleCandidate]) {
            bootstrapDownloadCompletion(bundleCandidate, nil);
        }
        else {
            [[DOUIManager sharedInstance] sendLog:@"Downloading Bootstrap" debug:NO];
            [self downloadBootstrapWithCompletion:bootstrapDownloadCompletion];
        }*/
    }
    else {
        bootstrapFinishedCompletion(nil);
    }
}

- (int)installPackage:(NSString *)packagePath
{
    if (getuid() == 0) {
        return exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-i", packagePath.fileSystemRepresentation, NULL);
    }
    else {
        // idk why but waitpid sometimes fails and this returns -1, so we just ignore the return value
        exec_cmd(JBROOT_PATH("/basebin/jbctl"), "internal", "install_pkg", packagePath.fileSystemRepresentation, NULL);
        return 0;
    }
}

- (int)uninstallPackageWithIdentifier:(NSString *)identifier
{
    return exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"), "-r", identifier.UTF8String, NULL);
}

- (NSString *)installedVersionForPackageWithIdentifier:(NSString *)identifier
{
    NSString *dpkgStatus = [NSString stringWithContentsOfFile:JBROOT_PATH(@"/var/lib/dpkg/status") encoding:NSUTF8StringEncoding error:nil];
    NSString *packageStartLine = [NSString stringWithFormat:@"Package: %@", identifier];
    
    NSArray *packageInfos = [dpkgStatus componentsSeparatedByString:@"\n\n"];
    for (NSString *packageInfo in packageInfos) {
        if ([packageInfo hasPrefix:packageStartLine]) {
            __block NSString *version = nil;
            [packageInfo enumerateLinesUsingBlock:^(NSString * _Nonnull line, BOOL * _Nonnull stop) {
                if ([line hasPrefix:@"Version: "]) {
                    version = [line substringFromIndex:9];
                }
            }];
            return version;
        }
    }
    return nil;
}

- (NSError *)installPackageManagers
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        // RootHide's arm64e managers are intentionally bundled under distinct
        // names so stock Dopamine's package selection never sees them.
        for (NSDictionary *manager in [[DOUIManager sharedInstance] enabledPackageManagers]) {
            NSString *stockPackage = manager[@"Package"];
            NSString *package = nil;
            if ([stockPackage isEqualToString:@"sileo.deb"]) package = @"roothide_sileo.deb";
            else if ([stockPackage isEqualToString:@"zebra.deb"]) package = @"roothide_zebra.deb";
            if (!package) {
                return RH3Error(BootstrapErrorCodeFailedFinalising,
                                [NSString stringWithFormat:@"Unsupported RootHide package manager: %@", stockPackage]);
            }
            NSString *path = [NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:package];
            if (geteuid() != 0)
                return RH3Error(BootstrapErrorCodeFailedFinalising,
                                @"RootHide package installation requires root privileges");
            int status = exec_cmd_trusted(JBROOT_PATH("/usr/bin/dpkg"),
                                          "-i", path.fileSystemRepresentation, NULL);
            if (status != 0) {
                return RH3Error(BootstrapErrorCodeFailedFinalising,
                                [NSString stringWithFormat:@"Installing %@ failed (%d)", package, status]);
            }
        }
        return nil;
    }
    NSArray *enabledPackageManagers = [[DOUIManager sharedInstance] enabledPackageManagers];
    for (NSDictionary *packageManagerDict in enabledPackageManagers) {
        NSString *path = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:packageManagerDict[@"Package"]];
        NSString *name = packageManagerDict[@"Display Name"];
        int r = [self installPackage:path];
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install %@: %d\n", name, r]}];
        }
    }
    return nil;
}

- (BOOL)shouldInstallPackage:(NSString *)identifier
{
    NSString *bundledVersion = gBundledPackages[identifier];
    if (!bundledVersion) return NO;
    
    NSString *installedVersion = [self installedVersionForPackageWithIdentifier:identifier];
    if (!installedVersion) return YES;
    
    return [installedVersion numericalVersionRepresentation] < [bundledVersion numericalVersionRepresentation];
}

- (NSError *)finalizeBootstrap
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        return [self finalizeRootHideBootstrap];
    }
    // Initial setup on first jailbreak
    if ([[NSFileManager defaultManager] fileExistsAtPath:JBROOT_PATH(@"/prep_bootstrap.sh")]) {
        [[DOUIManager sharedInstance] sendLog:@"Finalizing Bootstrap" debug:NO];
        int r = exec_cmd_trusted(JBROOT_PATH("/bin/sh"), JBROOT_PATH("/prep_bootstrap.sh"), NULL);
        if (r != 0) {
            return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"prep_bootstrap.sh returned %d\n", r]}];
        }
        
        NSError *error = [self installPackageManagers];
        if (error) return error;
    }
    
    BOOL shouldInstallLibroot = [self shouldInstallPackage:@"libroot-dopamine"];
    BOOL shouldInstallLibkrw = [self shouldInstallPackage:@"libkrw0-dopamine"];
    BOOL shouldInstallBasebinLink = [self shouldInstallPackage:@"dopamine-basebin-link"];
    BOOL shouldInstallLaunchctl = NO;
    if (__builtin_available(iOS 19.0, *)) {
        shouldInstallLaunchctl = [self shouldInstallPackage:@"launchctl"];
    }
    
    if (shouldInstallLibroot || shouldInstallLibkrw || shouldInstallBasebinLink || shouldInstallLaunchctl) {
        [[DOUIManager sharedInstance] sendLog:@"Updating Bundled Packages" debug:NO];

        if (shouldInstallLaunchctl) {
            NSString *launchctlPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"launchctl_1_1.2.0_iphoneos-arm64.deb"];
            int r = [self installPackage:launchctlPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install launchctl: %d\n", r]}];
        }

        if (shouldInstallLibroot) {
            NSString *librootPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libroot.deb"];
            int r = [self installPackage:librootPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install libroot: %d\n", r]}];
        }
        
        if (shouldInstallLibkrw) {
            NSString *libkrwPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"libkrw-dopamine.deb"];
            int r = [self installPackage:libkrwPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install the libkrw plugin: %d\n", r]}];
        }
        
        if (shouldInstallBasebinLink) {
            // Clean symlinks from earlier Dopamine versions
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/opainject")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/opainject") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/jbctl")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/jbctl") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/lib/libjailbreak.dylib")]) {
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/lib/libjailbreak.dylib") error:nil];
            }
            if ([self fileOrSymlinkExistsAtPath:JBROOT_PATH(@"/usr/bin/libjailbreak.dylib")]) {
                // Yes this exists >.< was a typo
                [[NSFileManager defaultManager] removeItemAtPath:JBROOT_PATH(@"/usr/bin/libjailbreak.dylib") error:nil];
            }
            
            NSString *basebinLinkPath = [[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"basebin-link.deb"];
            int r = [self installPackage:basebinLinkPath];
            if (r != 0) return [NSError errorWithDomain:bootstrapErrorDomain code:BootstrapErrorCodeFailedFinalising userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to install basebin link: %d\n", r]}];
        }
    }

    return nil;
}

- (NSError *)deleteBootstrap
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        return [self deleteRootHideBootstrap];
    }
    NSError *error = [self ensurePrivatePrebootIsWritable];
    if (error) return error;
    NSString *path = [[NSString stringWithUTF8String:gSystemInfo.jailbreakInfo.rootPath] stringByDeletingLastPathComponent];
    [[NSFileManager defaultManager] removeItemAtPath:path error:&error];
    if (error) return error;
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/jb" error:nil];
    return error;
}

- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)downloadTask didWriteData:(int64_t)bytesWritten totalBytesWritten:(int64_t)totalBytesWritten totalBytesExpectedToWrite:(int64_t)totalBytesExpectedToWrite
{
    if (downloadTask == _bootstrapDownloadTask) {
        NSString *sizeString = [NSByteCountFormatter stringFromByteCount:totalBytesWritten countStyle:NSByteCountFormatterCountStyleFile];
        NSString *writtenBytesString = [NSByteCountFormatter stringFromByteCount:totalBytesExpectedToWrite countStyle:NSByteCountFormatterCountStyleFile];
        
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Downloading Bootstrap (%@/%@)", sizeString, writtenBytesString] debug:NO update:YES];
    }
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
    _downloadCompletionBlock(nil, error);
}

- (void)URLSession:(nonnull NSURLSession *)session downloadTask:(nonnull NSURLSessionDownloadTask *)downloadTask didFinishDownloadingToURL:(nonnull NSURL *)location
{
    _downloadCompletionBlock(location, nil);
}

@end
