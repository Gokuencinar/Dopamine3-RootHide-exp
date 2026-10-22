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
#import <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#import <mach-o/dyld.h>
#import <libgrabkernel2/libgrabkernel2.h>
#import <libjailbreak/info.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/util.h>
#import <libjailbreak/display.h>
#import <libjailbreak/machine_info.h>
#import <libjailbreak/carboncopy.h>
#import <libjailbreak/roothider/common.h>

#import <IOKit/IOKitLib.h>
#import "DOUIManager.h"
#import "DOExploitManager.h"
#import "DOPreferenceManager.h"
#import "RootHideAppRegistration.h"
#import "RootHideScriptWait.h"
#import <CoreServices/LSApplicationProxy.h>
#import <libjailbreak/roothider.h>
#import "NSData+Hex.h"
#import <LocalAuthentication/LocalAuthentication.h>

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

static int RH3SSHRebaseInstalledPlist(NSString *plistPath, NSString *sshd,
                                     NSString *config, NSString *key, BOOL *changed)
{
    if (changed) *changed = NO;
    if (![plistPath.lastPathComponent isEqualToString:@"com.openssh.sshd.plist"])
        return ENOTSUP;
    const char *jobName = "com.openssh.sshd.plist";
    const char *backupName = ".com.openssh.sshd.rh3-original";
    const char *nextName = ".com.openssh.sshd.rh3-next";
    int dir = open(plistPath.stringByDeletingLastPathComponent.fileSystemRepresentation,
                   O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return errno;
    int result = 0;
    int original = -1, backup = -1, next = -1;
    BOOL madeBackup = NO, madeNext = NO, renamedJob = NO;
    struct stat directory = {0}, before = {0}, current = {0};
    NSData *originalData = nil, *nextData = nil;
    do {
        if (fstat(dir, &directory) || !S_ISDIR(directory.st_mode) ||
            directory.st_uid != 0 || (directory.st_mode & 022)) {
            result = EPERM; break;
        }
        original = openat(dir, jobName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (original < 0) { result = errno; break; }
        if (fstat(original, &before) || !S_ISREG(before.st_mode) ||
            before.st_uid != 0 || before.st_gid != 0 ||
            (before.st_mode & 022) || before.st_nlink != 1) {
            result = EPERM; break;
        }
        originalData = RH3SSHReadBounded(original, before.st_size);
        if (!originalData) { result = EIO; break; }
        id parsed = [NSPropertyListSerialization propertyListWithData:originalData
                    options:NSPropertyListMutableContainers format:NULL error:NULL];
        if (![parsed isKindOfClass:NSDictionary.class]) { result = EINVAL; break; }
        NSMutableDictionary *job = [parsed mutableCopy];
        NSDictionary *sockets = [job[@"Sockets"] isKindOfClass:NSDictionary.class] ? job[@"Sockets"] : nil;
        NSDictionary *inetd = [job[@"inetdCompatibility"] isKindOfClass:NSDictionary.class] ?
                              job[@"inetdCompatibility"] : nil;
        if (![job[@"Label"] isEqual:@"com.openssh.sshd"] || sockets.count != 2 ||
            ![inetd[@"Wait"] isKindOfClass:NSNumber.class] || [inetd[@"Wait"] boolValue]) {
            result = ENOTSUP; break;
        }
        NSArray *args = @[sshd, @"-i", @"-f", config, @"-h", key];
        if ([job[@"Program"] isEqual:sshd] && [job[@"ProgramArguments"] isEqual:args])
            break; // Idempotent: verified paths already persisted.
        job[@"Program"] = sshd;
        job[@"ProgramArguments"] = args;
        nextData = [NSPropertyListSerialization dataWithPropertyList:job
                    format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        if (!nextData || nextData.length > 65536 || nextData.length < 32) {
            result = EOVERFLOW; break;
        }

        backup = openat(dir, backupName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (backup >= 0) {
            madeBackup = YES;
            if (fchown(backup, 0, 0) || fchmod(backup, 0600) ||
                (result = RH3SSHWriteAll(backup, originalData)) != 0) {
                if (!result) result = errno;
                break;
            }
            close(backup); backup = -1;
            if (fsync(dir)) { result = errno; break; }
        } else if (errno == EEXIST) {
            // Preserve the very first package original across repeated repairs.
            // Refuse a symlink, foreign owner, malformed or writable backup.
            backup = openat(dir, backupName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            struct stat bs = {0};
            if (backup < 0 || fstat(backup, &bs) || !S_ISREG(bs.st_mode) ||
                bs.st_uid != 0 || bs.st_gid != 0 || (bs.st_mode & 0777) != 0600 ||
                bs.st_nlink != 1) { result = EPERM; break; }
            NSData *saved = RH3SSHReadBounded(backup, bs.st_size);
            id savedJob = saved ? [NSPropertyListSerialization propertyListWithData:saved
                              options:NSPropertyListImmutable format:NULL error:NULL] : nil;
            if (![savedJob isKindOfClass:NSDictionary.class] ||
                ![savedJob[@"Label"] isEqual:@"com.openssh.sshd"] ||
                ![savedJob[@"Sockets"] isKindOfClass:NSDictionary.class]) {
                result = EPERM; break;
            }
            close(backup); backup = -1;
        } else { result = errno; break; }

        next = openat(dir, nextName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (next < 0) { result = errno; break; }
        madeNext = YES;
        if (fchown(next, before.st_uid, before.st_gid) ||
            fchmod(next, before.st_mode & 0777)) { result = errno; break; }
        result = RH3SSHWriteAll(next, nextData);
        if (result) break;
        close(next); next = -1;
        if (fstatat(dir, jobName, &current, AT_SYMLINK_NOFOLLOW) ||
            current.st_dev != before.st_dev || current.st_ino != before.st_ino ||
            current.st_size != before.st_size || current.st_mtime != before.st_mtime) {
            result = EBUSY; break; // A package manager or other process changed it.
        }
        if (renameat(dir, nextName, dir, jobName)) { result = errno; break; }
        renamedJob = YES;
        if (changed) *changed = YES; // Even if readback/fsync later fails.
        madeNext = NO;
        if (fsync(dir)) { result = errno; break; }
        // Check the persisted result before reporting success to the user.
        int checked = openat(dir, jobName, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        struct stat checkedInfo = {0};
        if (checked < 0) { result = errno; break; }
        if (fstat(checked, &checkedInfo)) result = errno;
        NSData *verifiedData = result ? nil : RH3SSHReadBounded(checked, checkedInfo.st_size);
        close(checked);
        id verified = verifiedData ? [NSPropertyListSerialization propertyListWithData:verifiedData
                                options:NSPropertyListImmutable format:NULL error:NULL] : nil;
        NSMutableDictionary *originalOtherKeys = [parsed mutableCopy];
        NSMutableDictionary *verifiedOtherKeys = [verified isKindOfClass:NSDictionary.class] ?
                                                  [verified mutableCopy] : nil;
        [originalOtherKeys removeObjectsForKeys:@[@"Program", @"ProgramArguments"]];
        [verifiedOtherKeys removeObjectsForKeys:@[@"Program", @"ProgramArguments"]];
        if (![verified isKindOfClass:NSDictionary.class] ||
            ![verified[@"Program"] isEqual:sshd] ||
            ![verified[@"ProgramArguments"] isEqual:args] ||
            ![verified[@"Sockets"] isEqual:sockets] ||
            ![verified[@"inetdCompatibility"] isEqual:inetd] ||
            ![verifiedOtherKeys isEqual:originalOtherKeys]) {
            result = EIO; break; // Original is still recoverable from the backup.
        }
    } while (0);
    if (backup >= 0) close(backup);
    if (next >= 0) close(next);
    if (original >= 0) close(original);
    if (madeNext) (void)unlinkat(dir, nextName, 0);
    if (madeBackup && result && !renamedJob)
        (void)unlinkat(dir, backupName, 0); // Original job was not replaced.
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
    NSString *commandName = binary.lastPathComponent;
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"RootHide command %@: privilege and trust starting", commandName]];
    if (!result) result = [self rh3PerformPrivilegedAction:^int{
        int trust = jbclient_trust_executable_recurse(binary.fileSystemRepresentation, NULL);
        if (trust) return [self rh3ActionStage:@"command trust" result:trust];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"RootHide command %@: trust complete; spawn starting", commandName]];
        return exec_cmd_roothide_spawn_traced(&pid, argv[0], &actions, NULL, argv, environ,
                                             RH3LogCommandSpawnStage, (__bridge void *)commandName);
    }];
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
        int result = [self rh3PerformPrivilegedAction:^int{
            NSError *error = [self->_bootstrapper repairRootHideAppLinks];
            if (error) return [self rh3ActionStage:@"app links" result:(int)error.code];
            apps = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/Applications") error:&error];
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"apps: owned Applications directory read; entries=%lu error=%ld", (unsigned long)apps.count, (long)error.code]];
            return apps ? 0 : EIO;
        }];
        // Refresh only the jailbreak's own bundles, not every system app.
        NSUInteger alreadyRegistered = 0, refreshed = 0;
        for (NSString *app in apps) {
            if (result) break;
            if (![app.pathExtension isEqualToString:@"app"] || ![app.lastPathComponent isEqualToString:app]) continue;
            NSString *path = [JBROOT_PATH(@"/Applications") stringByAppendingPathComponent:app];
            NSDictionary *bundleInfo = [NSDictionary dictionaryWithContentsOfFile:
                [path stringByAppendingPathComponent:@"Info.plist"]];
            NSString *bundleID = [bundleInfo[@"CFBundleIdentifier"] isKindOfClass:NSString.class]
                ? bundleInfo[@"CFBundleIdentifier"] : nil;
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
        BOOL marker = lstat([root stringByAppendingPathComponent:@"basebin/.safe_mode"].fileSystemRepresentation,
                            &statInfo) == 0 && S_ISREG(statInfo.st_mode);
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
            [NSString stringWithFormat:@"runtime: tweak_safe_mode=%d tweak_loader_present=%d newterm_bundle_present=%d sshd_binary_present=%d ssh_plists=%lu daemon_listing_ok=%d; presence is not running state",
             marker, loader, newTerm, sshd, (unsigned long)sshPlists, daemons != nil && listingError == nil]];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"runtime: sshd_executable=%d ssh_config_present=%d ssh_host_key_files=%lu ssh_launch_program_rooted=%lu ssh_launch_program_accessible=%lu; no server started",
             sshdExecutable, sshConfig, (unsigned long)hostKeys,
             (unsigned long)sshPlistProgramRooted, (unsigned long)sshPlistProgramAccessible]];
        return 0;
    }];
    return [self rh3ActionStage:@"read-only tweak/terminal/SSH diagnosis" result:result];
}

// Explicit, opt-in repair for the OpenSSH socket job installed later by the
// package manager. The donor's us.diatr.shshd job is unrelated (SHSH blobs).
// Never write to /etc or /usr on the stock OS, load a service, or change
// passwords. The original XPC hook did not affect the live launchd job on
// r165; opt-in recovery persists ONLY Program/ProgramArguments with a backup.
- (int)repairRootHideSSH
{
    if (![DOBootstrapper rootHidePortEnabled]) return ENOTSUP;
    __block NSString *root = nil, *plistPath = nil, *configPath = nil;
    __block NSString *keyPath = nil, *publicKeyPath = nil, *sshdPath = nil, *keygenPath = nil;
    __block BOOL needsKey = NO;
    int result = [self rh3PerformPrivilegedAction:^int {
        NSError *error = nil;
        root = [DOBootstrapper rootHideExistingRootWithError:&error];
        const char *activeRoot = jbclient_get_jbroot();
        if (error || !root || !activeRoot ||
            ![RH3CanonicalAppPath(root) isEqualToString:
              RH3CanonicalAppPath([NSString stringWithUTF8String:activeRoot])]) {
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"SSH preflight: active hidden root identity not verified"];
            return EPERM;
        }
        // Reject symlinks or writable directories along paths where an
        // attacker could redirect ssh-keygen or the root-owned host key.
        for (NSString *suffix in @[@"etc", @"etc/ssh", @"Library", @"Library/LaunchDaemons"]) {
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
        for (NSString *binary in @[sshdPath, keygenPath]) {
            struct stat st = {0};
            if (lstat(binary.fileSystemRepresentation, &st) != 0 ||
                !S_ISREG(st.st_mode) || st.st_uid != 0 || !(st.st_mode & S_IXUSR)) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    [NSString stringWithFormat:@"SSH preflight: %@ missing, non-executable, or not root-owned", binary.lastPathComponent]];
                return ENOENT;
            }
        }
        struct stat cfg = {0};
        if (lstat(configPath.fileSystemRepresentation, &cfg) != 0 ||
            !S_ISREG(cfg.st_mode) || cfg.st_uid != 0) {
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
    }];
    if (result) return [self rh3ActionStage:@"SSH repair preflight" result:result];
    if (needsKey) {
        // Never use ssh-keygen -A: it writes the stock /etc/ssh directory.
        // -f pins output to the verified, root-owned hidden bootstrap.
        result = [self rh3RunCommand:keygenPath arguments:
            @[@"-q", @"-t", @"ed25519", @"-N", @"", @"-f", keyPath] input:nil timeout:30];
        if (result) return [self rh3ActionStage:@"SSH host key generation" result:result];
    }
    result = [self rh3RunCommand:sshdPath arguments:
        @[@"-t", @"-f", configPath, @"-h", keyPath] input:nil timeout:20];
    if (result) return [self rh3ActionStage:@"SSH configuration validation" result:result];

    result = [self rh3PerformPrivilegedAction:^int {
        NSError *error = nil;
        NSString *active = [DOBootstrapper rootHideExistingRootWithError:&error];
        const char *serverRoot = jbclient_get_jbroot();
        if (error || !active || !serverRoot ||
            ![RH3CanonicalAppPath(active) isEqualToString:RH3CanonicalAppPath(root)] ||
            ![RH3CanonicalAppPath(active) isEqualToString:
              RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot])])
            return EPERM;
        struct stat keyInfo = {0};
        if (lstat(keyPath.fileSystemRepresentation, &keyInfo) != 0 ||
            !S_ISREG(keyInfo.st_mode) || keyInfo.st_uid != 0 ||
            (keyInfo.st_mode & 077) || keyInfo.st_size < 32) return EPERM;
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
        int writeResult = RH3SSHRebaseInstalledPlist(plistPath, sshdPath, configPath, keyPath, &changed);
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"SSH repair: config/key validated; socket job atomic rebase result=%d changed=%d; no service started",
             writeResult, changed]];
        return writeResult;
    }];
    return [self rh3ActionStage:@"SSH socket plist repair (no server started)" result:result];
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
    __block NSString *root = nil;
    __block int onDiskWait = -1;
    __block int onDiskDisabled = -1;
    __block NSUInteger socketCount = 0;
    __block NSUInteger port22Count = 0, port2222Count = 0;
    __block NSString *diskProgram = nil;
    int preflight = [self rh3PerformPrivilegedAction:^int {
        NSError *error = nil;
        root = [DOBootstrapper rootHideExistingRootWithError:&error];
        const char *serverRoot = jbclient_get_jbroot();
        if (error || !root || !serverRoot ||
            ![RH3CanonicalAppPath(root) isEqualToString:
              RH3CanonicalAppPath([NSString stringWithUTF8String:serverRoot])]) return EPERM;
        NSString *directory = [root stringByAppendingPathComponent:@"Library/LaunchDaemons"];
        NSArray *names = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:directory error:&error];
        if (!names || error) return EIO;
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
        [NSString stringWithFormat:@"SSH socket plist: result=%d sockets=%lu port22=%lu port2222=%lu disabled=%d inetd_wait=%d (minus one=unknown)",
         preflight, (unsigned long)socketCount, (unsigned long)port22Count,
         (unsigned long)port2222Count, onDiskDisabled, onDiskWait]];
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
        // A toggle is not a successful change unless the verified file was
        // actually removed/created. No silent failures or unbounded shell.
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
            struct stat info = {0};
            int exists = lstat(safeModePath.fileSystemRepresentation, &info) == 0;
            if (!exists && errno != ENOENT) return errno;
            if (exists && (!S_ISREG(info.st_mode) || info.st_uid != 0))
                return EPERM;
            if (enabled) {
                if (exists && unlink(safeModePath.fileSystemRepresentation) != 0)
                    return errno;
            } else if (!exists) {
                int fd = open(safeModePath.fileSystemRepresentation,
                              O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
                if (fd < 0) return errno;
                if (close(fd)) return errno;
            }
            struct stat after = {0};
            int remaining = lstat(safeModePath.fileSystemRepresentation, &after);
            int verified = enabled ? (remaining == -1 && errno == ENOENT ? 0 : EIO) :
                (remaining == 0 && S_ISREG(after.st_mode) && after.st_uid == 0 ? 0 : EIO);
            if (verified) return verified;
            int dir = open([root stringByAppendingPathComponent:@"basebin"].fileSystemRepresentation,
                           O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (dir < 0) return errno;
            int synced = fsync(dir) == 0 ? 0 : errno;
            close(dir);
            return synced;
        }];
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
