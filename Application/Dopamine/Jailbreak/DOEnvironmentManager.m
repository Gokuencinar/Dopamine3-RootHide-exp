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
    if (!self.isJailbroken || !roothide_is_active()) return [self rh3ActionStage:@"environment unavailable" result:ENXIO];
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

    if (r != 0 || pid <= 0) return r != 0 ? r : ECHILD;
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
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
        [NSString stringWithFormat:@"RootHide command %@: privilege and trust starting", binary.lastPathComponent]];
    if (!result) result = [self rh3PerformPrivilegedAction:^int{
        int trust = jbclient_trust_executable_recurse(binary.fileSystemRepresentation, NULL);
        if (trust) return [self rh3ActionStage:@"command trust" result:trust];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"RootHide command %@: trust complete; spawn starting", binary.lastPathComponent]];
        return exec_cmd_roothide_spawn(&pid, argv[0], &actions, NULL, argv, environ);
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
        for (NSString *app in apps) {
            if (result) break;
            if (![app.pathExtension isEqualToString:@"app"] || ![app.lastPathComponent isEqualToString:app]) continue;
            NSString *path = [JBROOT_PATH(@"/Applications") stringByAppendingPathComponent:app];
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"apps: registration starting for %@", app]];
            result = [self rh3RunCommand:JBROOT_PATH(@"/usr/bin/uicache") arguments:@[@"-p", path] input:nil timeout:30];
        }
        return [self rh3ActionStage:@"refresh apps" result:result];
    }
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
        }];
    }];
    return 0;
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
        __block NSString *before = nil;
        int result = [self rh3PerformPrivilegedAction:^int{ before = [self rh3MobilePasswordHash]; return before ? 0 : EIO; }];
        if (!result) result = [self rh3RunCommand:JBROOT_PATH(@"/usr/sbin/pw") arguments:@[@"usermod", @"501", @"-h", @"0"]
                                          input:[[newPassword stringByAppendingString:@"\n"] dataUsingEncoding:NSUTF8StringEncoding] timeout:20];
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
    return ![[NSFileManager defaultManager] fileExistsAtPath:JBROOT_PATH(@"/basebin/.safe_mode")];
}

- (void)setTweakInjectionEnabled:(BOOL)enabled
{
    NSString *safeModePath = JBROOT_PATH(@"/basebin/.safe_mode");
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
        int result = 0;
        for (NSString *path in packages) {
            // jbctl establishes real uid 0 after the app restores its own
            // credentials. dpkg must not inherit the app's real uid 501.
            result = [self spawnJbctlAsRootWithArgs:@[@"internal", @"install_pkg", path]];
            if (result) break;
        }
        if (!result) result = [self rh3PerformPrivilegedAction:^int{
            error = [self->_bootstrapper repairRootHideAppLinks];
            return error ? (int)error.code : 0;
        }];
        [self rh3ActionStage:@"reinstall package managers" result:result];
        return error ?: (result ? [NSError errorWithDomain:@"RootHide" code:result userInfo:@{NSLocalizedDescriptionKey:@"No se pudieron reinstalar los gestores; consulta el diagnóstico."}] : nil);
    }
    __block NSError *error;
    [self runAsRoot:^{
        [self runUnsandboxed:^{
            error = [self->_bootstrapper installPackageManagers];
        }];
    }];
    return error;
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
