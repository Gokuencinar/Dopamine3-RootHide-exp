//
//  Jailbreaker.m
//  Dopamine
//
//  Created by Lars Fröder on 10.01.24.
//

#import "DOJailbreaker.h"
#import "RootHideBootstrapProfile.h"
#import "RootHideAppRegistration.h"
#import "RootHideAppOwnerPolicy.h"
#import "RootHideScriptWait.h"
#import "RH3TweakToggle.h"
#import "DOEnvironmentManager.h"
#import "DOExploitManager.h"
#import "DOUIManager.h"
#import "DOPreferenceManager.h"
#import <sys/stat.h>
#import <sys/wait.h>
#import <errno.h>
#import <signal.h>
#import <compression.h>
#import <xpf/xpf.h>
#import <dlfcn.h>
#import <libjailbreak/codesign.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/primitives_IOSurface.h>
#import <libjailbreak/physrw_pte.h>
#import <libjailbreak/physrw.h>
#import <libjailbreak/translation.h>
#import <libjailbreak/kernel.h>
#import <libjailbreak/info.h>
#import <libjailbreak/util.h>
#import <libjailbreak/trustcache.h>
#import <libjailbreak/trustcache_fs.h>
#import <libjailbreak/jbserver_boomerang.h>
#import <libjailbreak/signatures.h>
#import <libjailbreak/jbclient_xpc.h>
#import <libjailbreak/jbclient_mach.h>
#import <libjailbreak/kcall_arm64.h>
#import <libjailbreak/basebin_gen.h>
#import <libjailbreak/roothider/common.h>
#import <CoreServices/LSApplicationProxy.h>
#import <sys/utsname.h>
#import "spawn.h"
#import "clock_alarm.h"
#import <IOSurface/IOSurfaceRef.h>
#ifndef ROOTHIDE3_TWEAKS_DEFAULT_ON
#define ROOTHIDE3_TWEAKS_DEFAULT_ON 0
#endif
#if ROOTHIDE3_TWEAKS_DEFAULT_ON && !ROOTHIDE3_BOOTSTRAP_READY
#error RootHide tweak-default-on requires an explicitly enabled jailbreak build
#endif
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

#define kCFPreferencesNoContainer CFSTR("kCFPreferencesNoContainer")
void _CFPreferencesSetValueWithContainer(CFStringRef key, CFPropertyListRef value, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
Boolean _CFPreferencesSynchronizeWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFArrayRef _CFPreferencesCopyKeyListWithContainer(CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);
CFDictionaryRef _CFPreferencesCopyMultipleWithContainer(CFArrayRef keysToFetch, CFStringRef applicationID, CFStringRef userName, CFStringRef hostName, CFStringRef containerPath);

//char *_dirhelper(int a, char *dst, size_t size);

NSString *const JBErrorDomain = @"JBErrorDomain";
typedef NS_ENUM(NSInteger, JBErrorCode) {
    JBErrorCodeFailedToFindKernel            = -1,
    JBErrorCodeFailedKernelPatchfinding      = -2,
    JBErrorCodeFailedLoadingExploit          = -3,
    JBErrorCodeFailedExploitation            = -4,
    JBErrorCodeFailedBuildingPhysRW          = -5,
    JBErrorCodeFailedCleanup                 = -6,
    JBErrorCodeFailedGetRoot                 = -7,
    JBErrorCodeFailedUnsandbox               = -8,
    JBErrorCodeFailedPlatformize             = -9,
    JBErrorCodeFailedBasebinTrustcache       = -10,
    JBErrorCodeFailedLaunchdInjection        = -11,
    JBErrorCodeFailedInitProtection          = -12,
    JBErrorCodeFailedInitFakeLib             = -13,
    JBErrorCodeFailedDuplicateApps           = -14,
    JBErrorCodeFailedDiagnosticRecording     = -15,
};

// Hold the boomerang response context independently of the calling stack;
// timed-out RootHide launchd injection cannot leave a detached thread using
// expired stack memory.
@interface RH3BoomerangContext : NSObject
@property (nonatomic, assign) mach_port_t serverPort;
@property (nonatomic, strong) dispatch_semaphore_t completed;
@end

@implementation RH3BoomerangContext
@end

// A running sandboxed app cannot safely unlink .safe_mode in the protected
// Bundle/Application bootstrap (r172: EPERM). Only apply an *explicit* staged
// choice while the jailbreak installer identity is already active. Do not
// elevate CS flags or silently reinterpret the old tweak preference here.
static int RH3ApplyStagedTweakChoice(NSString *root)
{
    if (!root || ![DOBootstrapper rootHideBrandForPath:root] ||
        !gSystemInfo.jailbreakInfo.rootPath ||
        ![root isEqualToString:@(gSystemInfo.jailbreakInfo.rootPath)]) return EPERM;
    NSString *installed = [root stringByAppendingPathComponent:@".installed_roothide3"];
    struct stat installedInfo = {0};
    if (lstat(installed.fileSystemRepresentation, &installedInfo) != 0) {
        // The first installation always forces safe mode; no implicit opt-in.
        return errno == ENOENT ? 0 : errno;
    }
    if (!S_ISREG(installedInfo.st_mode) || installedInfo.st_uid != 0 ||
        ![[NSString stringWithContentsOfFile:installed encoding:NSUTF8StringEncoding
                                           error:nil] isEqualToString:@"3"]) return EPERM;

    NSString *secondary = [@"/var/mobile/Containers/Shared/AppGroup"
                           stringByAppendingPathComponent:root.lastPathComponent];
    bool enable = false;
    int status = rh3_tweak_request_read(root.fileSystemRepresentation,
                                       secondary.fileSystemRepresentation, &enable);
    if (status == ENOENT) return 0;
    BOOL invalidRequest = status == EINVAL || status == EPERM;
    if (status && !invalidRequest) return status;
    if (invalidRequest) {
        // A malformed request must never enable tweaks or permanently strand
        // an otherwise verified jailbreak. First revalidate the writable
        // parent independently: a damaged root/AppGroup backlink still aborts.
        int verifiedDir = -1;
        int parentStatus = rh3_tweak_open_request_dir(root.fileSystemRepresentation,
                                                     secondary.fileSystemRepresentation,
                                                     &verifiedDir);
        if (parentStatus) return parentStatus;
        close(verifiedDir);
        enable = false; // Restore protected safe mode, leave bad request untouched.
    }
    uint32_t flags = 0;
    if (geteuid() != 0 || getegid() != 0 ||
        csops(getpid(), CS_OPS_STATUS, &flags, sizeof(flags)) != 0 ||
        !(flags & CS_INSTALLER) || !(flags & CS_PLATFORM_BINARY)) return EPERM;

    NSString *basebinPath = [root stringByAppendingPathComponent:@"basebin"];
    int basebin = open(basebinPath.fileSystemRepresentation,
                       O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (basebin < 0) return errno;
    struct stat parent = {0};
    status = fstat(basebin, &parent) ? errno : 0;
    if (!status && (!S_ISDIR(parent.st_mode) || parent.st_uid != 0 ||
                    (parent.st_mode & 0022))) status = EPERM;
    struct stat marker = {0};
    bool exists = false;
    if (!status) {
        if (fstatat(basebin, ".safe_mode", &marker, AT_SYMLINK_NOFOLLOW) == 0) {
            exists = true;
            if (!S_ISREG(marker.st_mode) || marker.st_uid != 0 || marker.st_nlink != 1)
                status = EPERM;
        } else if (errno != ENOENT) status = errno;
    }
    if (!status && enable && exists && unlinkat(basebin, ".safe_mode", 0)) status = errno;
    if (!status && !enable && !exists) {
        int fd = openat(basebin, ".safe_mode",
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (fd < 0) status = errno;
        else {
            if (fchmod(fd, 0644) != 0) status = errno;
            if (!status && fsync(fd)) status = errno;
            if (close(fd) && !status) status = errno;
        }
    }
    if (!status && fsync(basebin)) status = errno;
    if (close(basebin) && !status) status = errno;
    if (status) return status;

    // Watchdog's post-boot safe-mode latch is under writable AppGroup/var.
    // Only explicit enable in this verified installer phase may remove it.
    if (enable) {
        status = rh3_tweak_watchdog_clear(root.fileSystemRepresentation,
                                         secondary.fileSystemRepresentation);
        if (status) return status;
    }
    if (invalidRequest) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            @"tweaks: invalid pending request; safe-mode marker enforced, request retained for explicit replacement"];
        return 0;
    }
    return rh3_tweak_request_cancel(root.fileSystemRepresentation,
                                   secondary.fileSystemRepresentation);
}

@implementation DOJailbreaker

- (NSError *)gatherSystemInformation
{
    NSString *kernelPath = [[DOEnvironmentManager sharedManager] accessibleKernelPath];
    if (!kernelPath) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedToFindKernel userInfo:@{NSLocalizedDescriptionKey:@"Failed to find kernelcache. Ensure your device is properly connected to the internet. If it still does not work, try installing Dopamine via TrollStore instead."}];
    NSLog(@"Kernel at %@", kernelPath);

    NSString *sptmPath = [[DOEnvironmentManager sharedManager] accessibleSPTMPath];
    if (sptmPath) {
        NSLog(@"SPTM at %@", sptmPath);
    }
    NSString *txmPath = [[DOEnvironmentManager sharedManager] accessibleTXMPath];
    if (txmPath) {
        NSLog(@"TXM at %@", txmPath);
    }
    
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Patchfinding") debug:NO];
    
    int r = xpf_start_with_kernel_path(kernelPath.fileSystemRepresentation, sptmPath ? sptmPath.fileSystemRepresentation : NULL, txmPath ? txmPath.fileSystemRepresentation : NULL);
    if (r == 0) {
        char *sets[] = {
            "translation",
            "trustcache",
            "sandbox",
            "physmap",
            "struct",
            "physrw",
            "IOSurface",
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
        };

        uint32_t idx = 0;
        while(sets[++idx]);

        if (xpf_set_is_supported("devmode")) {
            sets[idx++] = "devmode"; 
        }
        if (xpf_set_is_supported("badRecovery")) {
            sets[idx++] = "badRecovery"; 
        }
        if (xpf_set_is_supported("arm64kcall")) {
            sets[idx++] = "arm64kcall"; 
        }
        if (xpf_set_is_supported("perfkrw")) {
            sets[idx++] = "perfkrw";
        }

        _systemInfoXdict = xpf_construct_offset_dictionary((const char **)sets);
        if (_systemInfoXdict) {
            xpc_dictionary_set_uint64(_systemInfoXdict, "kernelConstant.staticBase", gXPF.kernelBase);
            if (gXPF.sptm) {
                xpc_dictionary_set_uint64(_systemInfoXdict, "kernelConstant.staticSptmBase", gXPF.sptmBase);
            }
            if (gXPF.txm) {
                xpc_dictionary_set_uint64(_systemInfoXdict, "kernelConstant.staticTxmBase", gXPF.txmBase);
            }
            printf("System Info:\n");
            xpc_dictionary_apply(_systemInfoXdict, ^bool(const char *key, xpc_object_t value) {
                if (xpc_get_type(value) == XPC_TYPE_UINT64) {
                    printf("0x%016llx <- %s\n", xpc_uint64_get_value(value), key);
                }
                return true;
            });
        }
        if (!_systemInfoXdict) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF failed with error: (%s)", xpf_get_error()]}];
        }
        xpf_stop();
    }
    else {
        NSError *error = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedKernelPatchfinding userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"XPF start failed with error: (%s)", xpf_get_error()]}];
        xpf_stop();
        return error;
    }
    
    jbinfo_initialize_dynamic_offsets(_systemInfoXdict);
    jbinfo_initialize_hardcoded_offsets();

    // Stash app identifier into jailbreakInfo
    // This will later allow launchdhook to figure out which process is the dopamine app
    if ([NSBundle mainBundle].bundleIdentifier) {
        gSystemInfo.jailbreakInfo.appIdentifier = strdup([NSBundle mainBundle].bundleIdentifier.UTF8String);
    }

    _systemInfoXdict = jbinfo_get_serialized();
    
    if (_systemInfoXdict) {
        printf("System Info libjailbreak:\n");
        xpc_dictionary_apply(_systemInfoXdict, ^bool(const char *key, xpc_object_t value) {
            if (xpc_get_type(value) == XPC_TYPE_UINT64) {
                if (xpc_uint64_get_value(value)) {
                    printf("0x%016llx <- %s\n", xpc_uint64_get_value(value), key);
                }
            }
            return true;
        });
    }
    
    return nil;
}

- (NSError *)doExploitation
{
    DOExploit *kernelExploit = [DOExploitManager sharedManager].selectedKernelExploit;
    DOExploit *pacBypass     = [DOExploitManager sharedManager].selectedPACBypass;
    DOExploit *pplBypass     = [DOExploitManager sharedManager].selectedPPLBypass;

    if (!kernelExploit) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Kernel exploit is required but we did not find any"}];
    }
    if (!pacBypass && [DOEnvironmentManager sharedManager].isPACBypassRequired) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"PAC bypass is required but we did not find any"}];
    }
    if (!pplBypass && [DOEnvironmentManager sharedManager].isPPLBypassRequired) {
        if ([DOEnvironmentManager sharedManager].isSPTM) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"SPTM bypass is required but we did not find any"}];
        }
        else {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"PPL bypass is required but we did not find any"}];
        }
    }
    
    [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Exploiting Kernel (%@)"), kernelExploit.name] debug:NO];
    if ([kernelExploit load] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load kernel exploit: %s", dlerror()]}];
    if ([kernelExploit run] != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to exploit kernel"}];
    
    jbinfo_initialize_boot_constants();
    libjailbreak_translation_init();
    libjailbreak_IOSurface_primitives_init();
    
    if (pacBypass) {
        [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PAC (%@)"), pacBypass.name] debug:NO];
        if ([pacBypass load] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load PAC bypass: %s", dlerror()]}];};
        if ([pacBypass run] != 0) {[kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to bypass PAC"}];}
        // At this point we presume the PAC bypass has given us stable kcall primitives
        gSystemInfo.jailbreakInfo.usesPACBypass = true;
    }

    if ([[DOEnvironmentManager sharedManager] isPPLBypassRequired]) {
        if ([DOEnvironmentManager sharedManager].isSPTM) {
            [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing SPTM (%@)"), pplBypass.name] debug:NO];
        }
        else {
            [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:DOLocalizedString(@"Bypassing PPL (%@)"), pplBypass.name] debug:NO];
        }

        if ([pplBypass load] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLoadingExploit userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to load PPL bypass: %s", dlerror()]}];};
        if ([pplBypass run] != 0) {[pacBypass cleanup]; [kernelExploit cleanup]; return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Failed to bypass PPL"}];}
        // At this point we presume the PPL bypass gave us unrestricted phys write primitives
    }
    
    if (![DOEnvironmentManager sharedManager].isArm64e) {
        arm64_kcall_init();
    }

    return nil;
}

- (NSError *)buildPhysRWPrimitive
{
    int r = -1;
    if (device_supports_physrw_pte()) {
        r = libjailbreak_physrw_pte_init(false, 0);
    }
    else {
        r = libjailbreak_physrw_init(false);
    }
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBuildingPhysRW userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to build phys r/w primitive: %d", r]}];
    }
    return nil;
}

- (NSError *)cleanUpExploits
{
    int r = [[DOExploitManager sharedManager] cleanUpExploits];
    if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedCleanup userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to cleanup exploits: %d", r]}];
    IOSurface_map_cleanup();
    return nil;
}

- (NSError *)elevatePrivileges
{
    uint64_t proc = proc_self();
    uint64_t ucred = proc_ucred(proc);
    
    // Get uid 0
    kwrite32(proc + koffsetof(proc, svuid), 0);
    kwrite32(ucred + koffsetof(ucred, svuid), 0);
    kwrite32(ucred + koffsetof(ucred, ruid), 0);
    kwrite32(ucred + koffsetof(ucred, uid), 0);
    
    // Get gid 0
    kwrite32(proc + koffsetof(proc, svgid), 0);
    kwrite32(ucred + koffsetof(ucred, rgid), 0);
    kwrite32(ucred + koffsetof(ucred, svgid), 0);
    kwrite32(ucred + koffsetof(ucred, groups), 0);
    
    // Add P_SUGID
    uint32_t flag = kread32(proc + koffsetof(proc, flag));
    if ((flag & P_SUGID) != 0) {
        flag &= P_SUGID;
        kwrite32(proc + koffsetof(proc, flag), flag);
    }
    
    if (getuid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, uid still %d", getuid()]}];
    if (getgid() != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedGetRoot userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to get root, gid still %d", getgid()]}];
    
    // Unsandbox
    uint64_t label = kread_ptr(ucred + koffsetof(ucred, label));
    mac_label_set(label, 1, -1);
    NSError *error = nil;
    [[NSFileManager defaultManager] contentsOfDirectoryAtPath:@"/var" error:&error];
    if (error) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedUnsandbox userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"Failed to unsandbox, /var does not seem accessible (%s)", error.description.UTF8String]}];
    setenv("HOME", "/var/root", true);
    setenv("CFFIXED_USER_HOME", "/var/root", true);
    setenv("TMPDIR", "/var/tmp", true);
    
    // FUCKING dirhelper caches the temporary path
    // So we have to do userland patchfinding to find the fucking string and overwrite it
    /*char **pain = NULL;
    uint32_t *dirhelperData = (uint32_t *)_dirhelper;
    for (int i = 0; i < 100; i++) {
        arm64_register destinationReg;
        uint64_t imm = 0;
        if (arm64_dec_ldr_imm(dirhelperData[i], &destinationReg, NULL, &imm, NULL, NULL) == 0) {
            if (ARM64_REG_GET_NUM(destinationReg) == 1) {
                uint32_t *adrpAddr = &dirhelperData[i - 1];
                uint64_t adrpTarget = 0;
                uint32_t adrpInst = *adrpAddr;
                if (arm64_dec_adr_p(adrpInst, (uint64_t)adrpAddr, &adrpTarget, NULL, NULL) == 0) {
                    pain = (char **)(uint64_t)(adrpTarget + imm);
                    break;
                }
            }
        }
    }
    *pain = strdup("/var/tmp");*/
    
    // Get CS_PLATFORM_BINARY
    proc_csflags_set(proc, CS_PLATFORM_BINARY);
    uint32_t csflags;
    csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
    if (!(csflags & CS_PLATFORM_BINARY)) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedPlatformize userInfo:@{NSLocalizedDescriptionKey:@"Failed to get CS_PLATFORM_BINARY"}];

    if ([DOBootstrapper rootHidePortEnabled]) {
        // RootHide2's elevatePrivileges also sets CS_INSTALLER. UID 0 and
        // removing the Seatbelt label do not grant installer access to the
        // protected app-container directory when using a sideloaded app.
        // Use Dopamine's existing csflags primitive, with its dynamic offsets.
        proc_csflags_set(proc, CS_INSTALLER);
        csflags = 0;
        int status = csops(getpid(), CS_OPS_STATUS, &csflags, sizeof(csflags));
        if (status != 0 || !(csflags & CS_INSTALLER)) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedPlatformize
                                  userInfo:@{NSLocalizedDescriptionKey:
                [NSString stringWithFormat:@"RootHide installer access could not be enabled (csops=%d, flags=0x%08x)", status, csflags]}];
        }
        [[DOUIManager sharedInstance] sendLog:
            [NSString stringWithFormat:@"RootHide installer access enabled (uid=%u, euid=%u, flags=0x%08x)",
             (unsigned)getuid(), (unsigned)geteuid(), csflags] debug:YES];
    }
    
    return nil;
}

- (NSError *)showNonDefaultSystemApps
{
    _CFPreferencesSetValueWithContainer(CFSTR("SBShowNonDefaultSystemApps"), kCFBooleanTrue, CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);
    _CFPreferencesSynchronizeWithContainer(CFSTR("com.apple.springboard"), CFSTR("mobile"), kCFPreferencesAnyHost, kCFPreferencesNoContainer);
    return nil;
}

- (NSError *)ensureDevModeEnabled
{
    if (@available(iOS 16.0, *)) {
        uint64_t developer_mode_storage = 0;
        if (ksymbol(developer_mode_enabled)) {
            developer_mode_storage = kread64(ksymbol(developer_mode_enabled));
        }
        else if (ksymbol_txm(txm_developer_mode_storage)) {
            developer_mode_storage = ksymbol_txm(txm_developer_mode_storage);
        }

        if (developer_mode_storage) {
            kwrite8(developer_mode_storage, 1);
        }
    }
    return nil;
}

- (NSError *)loadBasebinTrustcache
{
    trustcache_file_v1 *basebinTcFile = NULL;
    if (trustcache_file_build_from_path(JBROOT_PATH("/basebin/basebin.tc"), &basebinTcFile) == 0) {
        int r = trustcache_file_upload_with_uuid(basebinTcFile, BASEBIN_TRUSTCACHE_UUID);
        free(basebinTcFile);
        if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBasebinTrustcache userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload BaseBin trustcache: %d", r]}];
        return nil;
    }
    return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedBasebinTrustcache userInfo:@{NSLocalizedDescriptionKey : @"Failed to load BaseBin trustcache"}];
}

struct boomerang_info {
    mach_port_t serverPort;
    dispatch_semaphore_t boomerangDone;
};

void *boomerang_server(struct boomerang_info *info)
{
    while (true) {
        xpc_object_t xdict = nil;
        if (!xpc_pipe_receive(info->serverPort, &xdict)) {
            if (jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict) == JBS_BOOMERANG_DONE) {
                dispatch_semaphore_signal(info->boomerangDone);
                break;
            }
        }
    }
    return NULL;
}

static void *rh3_boomerang_server(void *opaque)
{
    @autoreleasepool {
        RH3BoomerangContext *context = (__bridge_transfer RH3BoomerangContext *)opaque;
        while (true) {
            xpc_object_t message = nil;
            // Destroying the receive right on timeout makes receive fail;
            // the thread then releases its retained context and exits.
            if (xpc_pipe_receive(context.serverPort, &message) != 0) break;
            if (message && jbserver_received_boomerang_xpc_message(&gBoomerangServer, message) == JBS_BOOMERANG_DONE) {
                dispatch_semaphore_signal(context.completed);
                break;
            }
        }
    }
    return NULL;
}

- (NSError *)rh3LaunchdInjectionError:(NSString *)reason
{
    return [NSError errorWithDomain:JBErrorDomain
                               code:JBErrorCodeFailedLaunchdInjection
                           userInfo:@{NSLocalizedDescriptionKey: reason}];
}

// exec_cmd() waits without a deadline. A hung opainject would block the
// jailbreak before its boomerang timeout even starts. Only the RootHide
// launchd path uses this bounded helper; stock Dopamine is unchanged.
- (NSError *)rh3InjectLaunchdWithTimeout
{
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: opainject spawn about to start"];
    pid_t child = 0;
    int started = exec_cmd_nowait(&child, JBROOT_PATH("/basebin/opainject"),
                                 "1", JBROOT_PATH("/basebin/launchdhook.dylib"), NULL);
    if (started != 0 || child <= 1) {
        return [self rh3LaunchdInjectionError:
            [NSString stringWithFormat:@"RootHide opainject failed to start (%d)", started]];
    }

    // Waiting on an observable child is preferable to blocking in exec_cmd.
    // A timeout does NOT assert the launchd side effects were rolled back.
    const CFAbsoluteTime deadline = CFAbsoluteTimeGetCurrent() + 45.0;
    int status = 0;
    while (CFAbsoluteTimeGetCurrent() < deadline) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) {
            if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: opainject exited 0"];
                return nil;
            }
            return [self rh3LaunchdInjectionError:
                [NSString stringWithFormat:@"RootHide opainject exited unsuccessfully (status %d)", status]];
        }
        if (waited == -1 && errno != EINTR) {
            return [self rh3LaunchdInjectionError:
                [NSString stringWithFormat:@"Cannot wait for RootHide opainject (errno %d)", errno]];
        }
        usleep(100000);
    }

    // Never leave a known suspended/injecting child running indefinitely.
    // Reap only our child; never signal launchd (the injection TARGET).
    (void)kill(child, SIGTERM);
    CFAbsoluteTime grace = CFAbsoluteTimeGetCurrent() + 1.0;
    while (CFAbsoluteTimeGetCurrent() < grace) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited == -1 && errno == ECHILD)) {
            return [self rh3LaunchdInjectionError:
                @"RootHide opainject exceeded 45 seconds; launchd state is unknown and reboot is disabled"];
        }
        if (waited == -1 && errno != EINTR) break;
        usleep(100000);
    }
    (void)kill(child, SIGKILL);
    // WNOHANG only: signal delivery/reaping can fail. A further activation
    // must be refused rather than assuming an injected launchd is healthy.
    for (int i = 0; i < 20; i++) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child || (waited == -1 && errno == ECHILD)) break;
        if (waited == -1 && errno != EINTR) break;
        usleep(100000);
    }
    return [self rh3LaunchdInjectionError:
        @"RootHide opainject timed out and was terminated if possible; launchd state requires manual device recovery"];
}

- (NSError *)injectRootHideLaunchdHookSafely
{
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: verifying hidden root and safe mode"];
    NSError *rootError = nil;
    NSString *root = [DOBootstrapper rootHideExistingRootWithError:&rootError];
    const char *activeRoot = gSystemInfo.jailbreakInfo.rootPath;
    if (rootError) return rootError;
    if (!root || !activeRoot || ![root isEqualToString:@(activeRoot)] ||
        ![DOBootstrapper rootHideBrandForPath:root]) {
        return [self rh3LaunchdInjectionError:@"RootHide launchd injection requires a verified, active hidden root"];
    }

    // Reject partially installed hooks and unexpected symlinks before
    // modifying launchd. This is intentionally stricter than stock Dopamine.
    for (NSString *name in @[@"jbctl", @"opainject", @"launchdhook.dylib", @"systemhook.dylib"]) {
        NSString *path = [[root stringByAppendingPathComponent:@"basebin"] stringByAppendingPathComponent:name];
        struct stat info = {0};
        if (lstat(path.fileSystemRepresentation, &info) != 0 || !S_ISREG(info.st_mode) || info.st_size < 32) {
            return [self rh3LaunchdInjectionError:
                [NSString stringWithFormat:@"RootHide launchd prerequisite is missing or unsafe: %@", name]];
        }
    }

    // Only the FIRST RootHide activation must force no-tweak mode. For an
    // already committed bootstrap, respect the user's saved .safe_mode state.
    // Recreating that marker on EVERY jailbreak was disabling tweaks again
    // even after a successful, explicit enable + userspace reboot.
    NSString *installedMarker = [root stringByAppendingPathComponent:@".installed_roothide3"];
    struct stat installedInfo = {0};
    BOOL hasInstalledMarker = lstat(installedMarker.fileSystemRepresentation, &installedInfo) == 0;
    if (hasInstalledMarker && (!S_ISREG(installedInfo.st_mode) || installedInfo.st_uid != 0 ||
                               installedInfo.st_size < 1 || installedInfo.st_size > 16)) {
        return [self rh3LaunchdInjectionError:@"RootHide installed marker is not a verified root-owned regular file"];
    }
    if (!hasInstalledMarker && errno != ENOENT) {
        return [self rh3LaunchdInjectionError:@"Could not inspect RootHide installed marker"];
    }
    BOOL installed = hasInstalledMarker &&
        [[NSString stringWithContentsOfFile:installedMarker encoding:NSUTF8StringEncoding error:nil]
         isEqualToString:@"3"];
    NSString *safeMode = [root stringByAppendingPathComponent:@"basebin/.safe_mode"];
    struct stat safeModeInfo = {0};
    BOOL safeModeAlreadyExists = lstat(safeMode.fileSystemRepresentation, &safeModeInfo) == 0;
    if (safeModeAlreadyExists) {
        if (!S_ISREG(safeModeInfo.st_mode))
            return [self rh3LaunchdInjectionError:@"RootHide safe-mode marker is not a regular file"];
    } else if (errno != ENOENT) {
        return [self rh3LaunchdInjectionError:@"Could not inspect RootHide safe-mode marker"];
    }
    if (!installed) {
#if ROOTHIDE3_TWEAKS_DEFAULT_ON
        // Explicit all-enabled beta ONLY: for a fresh, clean bootstrap do not
        // create the first-activation safe-mode marker. Preserve an existing
        // marker after a failed attempt, and NEVER clear the watchdog latch.
        // systemhook still independently enforces _SafeMode, DISABLE_TWEAKS,
        // the watchdog latch and per-process injection exclusions.
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"launchd: explicit all-enabled beta; existing safe mode preserved=%d; watchdog still authoritative",
             safeModeAlreadyExists]];
#else
        if (![[NSData data] writeToFile:safeMode atomically:YES]) {
            return [self rh3LaunchdInjectionError:@"Could not prepare RootHide safe mode before launchd injection"];
        }
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: first activation; no-tweak mode enforced"];
#endif
    } else {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"launchd: existing bootstrap; saved no-tweak marker present=%d",
             lstat(safeMode.fileSystemRepresentation, &safeModeInfo) == 0]];
    }

    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: allocating boomerang port"];
    mach_port_t serverPort = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    if (kr != KERN_SUCCESS) return [self rh3LaunchdInjectionError:@"Could not allocate RootHide boomerang port"];
    kr = mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), serverPort);
        return [self rh3LaunchdInjectionError:@"Could not prepare RootHide boomerang port"];
    }

    RH3BoomerangContext *context = [RH3BoomerangContext new];
    context.serverPort = serverPort;
    context.completed = dispatch_semaphore_create(0);
    void *retained = (__bridge_retained void *)context;
    pthread_t thread;
    int threadError = pthread_create(&thread, NULL, rh3_boomerang_server, retained);
    if (threadError) {
        (void)CFBridgingRelease(retained);
        mach_port_destroy(mach_task_self(), serverPort);
        return [self rh3LaunchdInjectionError:
            [NSString stringWithFormat:@"Could not start RootHide boomerang server (%d)", threadError]];
    }
    pthread_detach(thread);

    posix_spawnattr_t attr;
    int attributeError = posix_spawnattr_init(&attr);
    BOOL attrInitialized = (attributeError == 0);
    if (attrInitialized) {
        attributeError = posix_spawnattr_set_registered_ports_np(&attr,
            (mach_port_t[]){MACH_PORT_NULL, MACH_PORT_NULL, serverPort}, 3);
    }
    pid_t child = 0;
    int spawnError = attributeError;
    if (!spawnError) {
        const char *jbctl = JBROOT_PATH("/basebin/jbctl");
        spawnError = posix_spawn(&child, jbctl, NULL, &attr,
            (char *const *)(const char *[]){jbctl, "internal", "launchd_stash_port", NULL}, NULL);
    }
    if (attrInitialized) posix_spawnattr_destroy(&attr);
    if (spawnError) {
        mach_port_destroy(mach_task_self(), serverPort);
        return [self rh3LaunchdInjectionError:
            [NSString stringWithFormat:@"RootHide jbctl launch failed (%d)", spawnError]];
    }

    int status = 0;
    BOOL childFinished = NO;
    CFAbsoluteTime until = CFAbsoluteTimeGetCurrent() + 15.0;
    while (CFAbsoluteTimeGetCurrent() < until) {
        pid_t waited = waitpid(child, &status, WNOHANG);
        if (waited == child) { childFinished = YES; break; }
        if (waited < 0 && errno != EINTR) break;
        usleep(100000);
    }
    if (!childFinished) {
        kill(child, SIGTERM);
        (void)waitpid(child, &status, WNOHANG);
        mach_port_destroy(mach_task_self(), serverPort);
        return [self rh3LaunchdInjectionError:@"RootHide jbctl timed out; activation aborted (helper termination unconfirmed)"];
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        mach_port_destroy(mach_task_self(), serverPort);
        return [self rh3LaunchdInjectionError:
            [NSString stringWithFormat:@"RootHide jbctl returned an unsuccessful status (%d)", status]];
    }

    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: jbctl stash-port succeeded"];
    NSError *injectionError = [self rh3InjectLaunchdWithTimeout];
    if (injectionError) {
        mach_port_destroy(mach_task_self(), serverPort);
        return injectionError;
    }
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: waiting for boomerang handshake"];
    if (dispatch_semaphore_wait(context.completed, dispatch_time(DISPATCH_TIME_NOW, 60 * NSEC_PER_SEC)) != 0) {
        mach_port_destroy(mach_task_self(), serverPort);
        return [self rh3LaunchdInjectionError:@"RootHide launchd handshake timed out; no userspace reboot will be requested"];
    }
    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"launchd: boomerang handshake completed"];
    mach_port_destroy(mach_task_self(), serverPort);
    return nil;
}

- (NSError *)injectLaunchdHook
{
    if ([DOBootstrapper rootHidePortEnabled]) return [self injectRootHideLaunchdHookSafely];
    // Host a boomerang server that will be used by launchdhook to get the jailbreak primitives from this app
    mach_port_t serverPort = MACH_PORT_NULL;
    mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
    mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
    
    struct boomerang_info info;
    info.serverPort = serverPort;
    info.boomerangDone = dispatch_semaphore_create(0);
    
    pthread_t boomerangThread;
    pthread_create(&boomerangThread, NULL, (void *(*)(void *))boomerang_server, &info);
    pthread_detach(boomerangThread);

    // Stash port to server in launchd's initPorts[2]
    // Since we don't have the neccessary entitlements, we need to do it over jbctl
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){MACH_PORT_NULL, MACH_PORT_NULL, serverPort}, 3);
    pid_t spawnedPid = 0;
    const char *jbctlPath = JBROOT_PATH("/basebin/jbctl");
    int spawnError = posix_spawn(&spawnedPid, jbctlPath, NULL, &attr, (char *const *)(const char *[]){ jbctlPath, "internal", "launchd_stash_port", NULL }, NULL);
    if (spawnError != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Spawning jbctl failed with error code %d", spawnError]}];
    }
    posix_spawnattr_destroy(&attr);
    int status = 0;
    do {
        if (waitpid(spawnedPid, &status, 0) == -1) {
            return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : @"Waiting for jbctl failed"}];
        }
    } while (!WIFEXITED(status) && !WIFSIGNALED(status));

    // Inject launchdhook.dylib into launchd via opainject
    int r = exec_cmd(JBROOT_PATH("/basebin/opainject"), "1", JBROOT_PATH("/basebin/launchdhook.dylib"), NULL);
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"opainject failed with error code %d", r]}];
    }

    // Wait for everything to finish
    dispatch_semaphore_wait(info.boomerangDone, DISPATCH_TIME_FOREVER);
    mach_port_deallocate(mach_task_self(), serverPort);

    return nil;
}

- (NSError *)applyProtection
{
    int r = [[DOEnvironmentManager sharedManager] setPrivatePrebootProtected:YES];
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitProtection userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed initializing protection with error: %d", r]}];
    }
    return nil;
}

- (NSError *)createFakeLib
{
    int r = basebin_generate(false);
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Creating fakelib failed with error: %d", r]}];
    }

    cdhash_t *cdhashes = NULL;
    uint32_t cdhashesCount = 0;
    file_collect_untrusted_cdhashes_by_path(JBROOT_PATH("/basebin/.fakelib/dyld"), &cdhashes, &cdhashesCount);
    if (cdhashesCount != 1) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Got unexpected number of cdhashes for dyld???: %d", cdhashesCount]}];
    
    trustcache_file_v1 *dyldTCFile = NULL;
    r = trustcache_file_build_from_cdhashes(cdhashes, cdhashesCount, &dyldTCFile);
    free(cdhashes);
    if (r == 0) {
        int r = trustcache_file_upload_with_uuid(dyldTCFile, DYLD_TRUSTCACHE_UUID);
        if (r != 0) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Failed to upload dyld trustcache: %d", r]}];
        free(dyldTCFile);
    }
    else {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : @"Failed to build dyld trustcache"}];
    }
    
    r = [[DOEnvironmentManager sharedManager] setFakelibMounted:YES];
    if (r != 0) {
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedInitFakeLib userInfo:@{NSLocalizedDescriptionKey : [NSString stringWithFormat:@"Mounting fakelib failed with error: %d", r]}];
    }
    
    // Now that fakelib is up, we want to make systemhook inject into any binary we spawn
    setenv("DYLD_INSERT_LIBRARIES", "/usr/lib/systemhook.dylib", 1);
    return nil;
}

- (NSError *)ensureNoDuplicateApps
{
    NSMutableSet *dopamineInstalledAppIds = [NSMutableSet new];
    NSMutableDictionary *rootHideAppPaths = [NSMutableDictionary dictionary];
    NSMutableSet *userInstalledAppIds = [NSMutableSet new];
    
    NSString *dopamineAppsPath = JBROOT_PATH(@"/Applications");
    NSString *userAppsPath = @"/var/containers/Bundle/Application";
    
    for (NSString *dopamineAppName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:dopamineAppsPath error:nil]) {
        NSString *infoPlistPath = [[dopamineAppsPath stringByAppendingPathComponent:dopamineAppName] stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
        NSString *appId = infoDictionary[@"CFBundleIdentifier"];
        if (appId) {
            if (![dopamineInstalledAppIds containsObject:appId]) {
                [dopamineInstalledAppIds addObject:appId];
                rootHideAppPaths[appId] = [dopamineAppsPath stringByAppendingPathComponent:dopamineAppName];
            }
            else {
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_Dopamine_App"), appId, dopamineAppsPath]}];
            }
        }
    }
    
    for (NSString *appUUID in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:userAppsPath error:nil]) {
        NSString *UUIDPath = [userAppsPath stringByAppendingPathComponent:appUUID];
        for (NSString *appCandidate in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:UUIDPath error:nil]) {
            if ([appCandidate.pathExtension isEqualToString:@"app"]) {
                NSString *appPath = [UUIDPath stringByAppendingPathComponent:appCandidate];
                NSString *infoPlistPath = [appPath stringByAppendingPathComponent:@"Info.plist"];
                NSDictionary *infoDictionary = [NSDictionary dictionaryWithContentsOfFile:infoPlistPath];
                NSString *appId = infoDictionary[@"CFBundleIdentifier"];
                if (appId) {
                    [userInstalledAppIds addObject:appId];
                }
            }
        }
    }
    
    NSMutableSet *duplicateApps = dopamineInstalledAppIds.mutableCopy;
    [duplicateApps intersectSet:userInstalledAppIds];
    if (duplicateApps.count) {
        NSMutableString *duplicateAppsString = [NSMutableString new];
        [duplicateAppsString appendString:@"["];
        BOOL isFirst = YES;
        for (NSString *duplicateApp in duplicateApps) {
            if (isFirst) isFirst = NO;
            else [duplicateAppsString appendString:@", "];
            [duplicateAppsString appendString:duplicateApp];
        }
        [duplicateAppsString appendString:@"]"];
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_User_App"), duplicateAppsString, dopamineAppsPath]}];
    }
    
    for (NSString *dopamineAppId in dopamineInstalledAppIds) {
        LSApplicationProxy *appProxy = [LSApplicationProxy applicationProxyForIdentifier:dopamineAppId];
        if (appProxy.installed) {
            NSString *appProxyPath = [[appProxy.bundleURL.path stringByResolvingSymlinksInPath] stringByStandardizingPath];
            if ([DOBootstrapper rootHidePortEnabled]) {
                NSString *expected = rootHideAppPaths[dopamineAppId];
                NSString *canonicalExpected = RH3CanonicalAppPath(expected);
                if ([RH3CanonicalAppPath(appProxy.bundleURL.path) isEqual:canonicalExpected]) continue;
                NSString *oldRoot = RH3StaleRegisteredRoot(appProxy.bundleURL.path, expected);
                NSError *ownershipError = nil;
                NSString *owned = [DOBootstrapper rootHideExistingRootWithError:&ownershipError];
                struct stat oldInfo = {0}, appInfo = {0}, plistInfo = {0}, appsInfo = {0};
                int oldStatus = oldRoot ? lstat(oldRoot.fileSystemRepresentation, &oldInfo) : 0;
                int oldError = errno;
                NSString *plist = [expected stringByAppendingPathComponent:@"Info.plist"];
                BOOL valid = oldRoot && [DOBootstrapper rootHideBrandForPath:oldRoot] && oldStatus != 0 && oldError == ENOENT &&
                    !ownershipError && [RH3CanonicalAppPath(owned) isEqual:RH3CanonicalAppPath(dopamineAppsPath.stringByDeletingLastPathComponent)] &&
                    lstat(dopamineAppsPath.fileSystemRepresentation, &appsInfo) == 0 && S_ISDIR(appsInfo.st_mode) &&
                    rh3_apps_directory_owner_allowed(appsInfo.st_uid, 0, appsInfo.st_mode) &&
                    lstat(expected.fileSystemRepresentation, &appInfo) == 0 && S_ISDIR(appInfo.st_mode) &&
                    !(appInfo.st_mode & 0022) &&
                    rh3_bundle_owner_allowed(expected.lastPathComponent.UTF8String, appInfo.st_uid, 0) &&
                    lstat(plist.fileSystemRepresentation, &plistInfo) == 0 && S_ISREG(plistInfo.st_mode) &&
                    rh3_bundle_owner_allowed(expected.lastPathComponent.UTF8String, plistInfo.st_uid, 0) &&
                    [[NSDictionary dictionaryWithContentsOfFile:plist][@"CFBundleIdentifier"] isEqual:dopamineAppId];
                if (valid) {
                    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"apps: refreshing stale registration for %@", dopamineAppId]];
                    NSString *uicache = JBROOT_PATH(@"/usr/bin/uicache");
                    __block int refresh = -1;
                    dispatch_group_t work = dispatch_group_create();
                    dispatch_group_async(work, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                        int trust = jbclient_trust_file_by_path(uicache.fileSystemRepresentation);
                        pid_t child = 0;
                        refresh = trust ? trust : exec_cmd_nowait(&child, uicache.fileSystemRepresentation, "-p", expected.fileSystemRepresentation, NULL);
                        if (!refresh) refresh = RH3WaitForBootstrapChild(child, 30);
                    });
                    BOOL finished = dispatch_group_wait(work, dispatch_time(DISPATCH_TIME_NOW, 40 * NSEC_PER_SEC)) == 0;
                    [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"apps: refresh %@ completed=%d result=%d", dopamineAppId, finished, finished ? refresh : -1]];
                    if (!finished || refresh) return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{NSLocalizedDescriptionKey:@"RootHide app registration refresh failed or timed out; bootstrap preserved"}];
                    appProxy = [LSApplicationProxy applicationProxyForIdentifier:dopamineAppId];
                    if (appProxy.installed && [RH3CanonicalAppPath(appProxy.bundleURL.path) isEqual:canonicalExpected]) continue;
                }
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{NSLocalizedDescriptionKey:[NSString stringWithFormat:@"RootHide registration for %@ does not match the verified current bundle; no foreign app was removed", dopamineAppId]}];
            }
            if (![appProxyPath hasPrefix:dopamineAppsPath]) {
                return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDuplicateApps userInfo:@{ NSLocalizedDescriptionKey : [NSString stringWithFormat:DOLocalizedString(@"Duplicate_Apps_Error_Icon_Cache"), dopamineAppId, dopamineAppsPath, appProxy.bundleURL.path]}];
            }
        }
    }
    
    return nil;
}

- (NSError *)removeJailbreak
{
    if (@available(iOS 18.0, *)) {
        // On iOS 18+, jailbreak apps persist on the home screen even after a reboot into unjailbroken state
        // So we need to remove them from icon cache before deleting the bootstrap
        [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Rebuilding Icon Cache") debug:NO];
        [[DOEnvironmentManager sharedManager] rebuildIconCache];
    }

    NSError *err;
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Removing Jailbreak") debug:NO];
    err = [[DOEnvironmentManager sharedManager] deleteBootstrap];
    if (err) return err;

    return nil;
}

- (NSError *)finalizeBootstrapIfNeeded
{
    return [[DOEnvironmentManager sharedManager] finalizeBootstrap];
}

- (NSError *)cleanUpPostExploitation
{
    if (@available(iOS 17.0, *)) {
        uint64_t proc = proc_self();
        uint64_t ucred = proc_ucred(proc);

        // Get uid 0
        kwrite32(ucred + koffsetof(ucred, svuid), 501);
        kwrite32(ucred + koffsetof(ucred, ruid), 501);
        kwrite32(ucred + koffsetof(ucred, uid), 501);
        
        // Get gid 0
        kwrite32(ucred + koffsetof(ucred, rgid), 501);
        kwrite32(ucred + koffsetof(ucred, svgid), 501);
        kwrite32(ucred + koffsetof(ucred, groups), 501);
    }

    return nil;
}

- (NSError *)rootHidePreflightError
{
    if (![DOBootstrapper rootHidePortEnabled]) return nil;
    BOOL recovery = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"rootHideRecoveryRequested" fallback:NO];
    [DOBootstrapper setRootHideRecoveryRequested:recovery];
    if (recovery && [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO])
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation userInfo:@{NSLocalizedDescriptionKey:@"Disable Remove Jailbreak before requesting recovery"}];
    NSString *reason = nil;
    NSOperatingSystemVersion os = NSProcessInfo.processInfo.operatingSystemVersion;
    DOEnvironmentManager *environment = [DOEnvironmentManager sharedManager];
    if (!rh3_bootstrap_version_for_os((int)os.majorVersion))
        reason = @"No experimental RootHide bootstrap profile is available for this iOS version.";
    else if (![environment isSupported])
        reason = @"No compatible Dopamine exploit combination is available for this device and iOS build.";
    else if ([environment isJailbrokenWithOtherJailbreak])
        reason = @"Existing jailbreak detected: reboot to an unjailbroken state before testing RootHide 3.";
    if (reason)
        return [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedExploitation
                              userInfo:@{NSLocalizedDescriptionKey: reason}];
    return [[DOBootstrapper new] rootHidePreflightError];
}

- (void)runWithError:(NSError **)errOut didRemoveJailbreak:(BOOL*)didRemove showLogs:(BOOL *)showLogs
{
#if RH3_INSTALLABLE_DIAGNOSTIC
    // A second, non-UI guard: no diagnostic build may reach exploitation or
    // removal even if another caller invokes the jailbreaker directly.
    if (didRemove) *didRemove = NO;
    if (showLogs) *showLogs = NO;
    if (errOut) *errOut = [NSError errorWithDomain:JBErrorDomain
                                            code:JBErrorCodeFailedBasebinTrustcache
                                        userInfo:@{NSLocalizedDescriptionKey:
                                        @"RootHide 3 diagnostic mode: jailbreak and removal are disabled."}];
    return;
#else
#if RH3_FULL_APP_EXPERIMENTAL
    // The full experimental build carries all Dopamine/RootHide components,
    // but must NEVER fall through to stock /var/jb installation while the
    // RootHide bootstrap runtime remains unverified.
    if (![DOBootstrapper rootHidePortEnabled]) {
        if (didRemove) *didRemove = NO;
        if (showLogs) *showLogs = NO;
        if (errOut) *errOut = [NSError errorWithDomain:JBErrorDomain
                                                code:JBErrorCodeFailedBasebinTrustcache
                                            userInfo:@{NSLocalizedDescriptionKey:
                                            @"RootHide 3 runtime is not validated. Jailbreak and removal are disabled in this experimental build."}];
        return;
    }
    // Recheck for non-UI callers and changes since the UI preflight.
    NSError *preflightError = [self rootHidePreflightError];
    if (preflightError) {
        if (didRemove) *didRemove = NO;
        if (showLogs) *showLogs = YES;
        if (errOut) *errOut = preflightError;
        return;
    }
#endif
    // Consume the preference before elevation; the captured request lasts for this attempt.
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOPreferenceManager sharedManager] setPreferenceValue:@NO forKey:@"rootHideRecoveryRequested"];
    BOOL removeJailbreakEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO];
    // opainject/jbctl and dyld generation run before the RootHide patch daemon
    // is available. Enable child patching only after launchd and dyld are ready.
    if ([DOBootstrapper rootHidePortEnabled]) exec_set_patch(false);
    BOOL tweaksEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"tweakInjectionEnabled" fallback:YES];
    BOOL idownloadEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"idownloadEnabled" fallback:NO];
    BOOL appJITEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"appJITEnabled" fallback:YES];
    NSNumber *jetsamMultiplierOption = [[DOPreferenceManager sharedManager] preferenceValueForKey:@"jetsamMultiplier"];
    
    struct utsname systemInfo;
    uname(&systemInfo);
    NSString *startLog = [NSString stringWithFormat:@"Starting Jailbreak (Model: %s, %@, Configuration: {removeJailbreak=%d, tweakInjection=%d, idownload=%d, appJIT=%d})", systemInfo.machine, NSProcessInfo.processInfo.operatingSystemVersionString, removeJailbreakEnabled, tweaksEnabled, idownloadEnabled, appJITEnabled];
    if ([DOBootstrapper rootHidePortEnabled]) {
        if (![[DOUIManager sharedInstance] rh3BeginDiagnosticAttempt]) {
            *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedDiagnosticRecording
                userInfo:@{NSLocalizedDescriptionKey:@"Cannot create a durable RootHide diagnostic log. No exploit was started."}];
            return;
        }
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: exploit starting"];
    }
    [[DOUIManager sharedInstance] sendLog:startLog debug:YES];
    
    *errOut = [self gatherSystemInformation];
    if (*errOut) return;
    *errOut = [self doExploitation];
    if (*errOut) {
        // We don't care about the return value of cleanup at this point, we just need to prevent a panic on exit
        [self cleanUpExploits];
        return;
    }
    
    gSystemInfo.jailbreakSettings.markAppsAsDebugged = appJITEnabled;
    gSystemInfo.jailbreakSettings.jetsamMultiplier = jetsamMultiplierOption ? (jetsamMultiplierOption.doubleValue / 2) : 0;
    
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Building Phys R/W Primitive") debug:NO];
    *errOut = [self buildPhysRWPrimitive];
    if (*errOut) {
        [self cleanUpExploits];
        return;
    }
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Cleaning Up Exploits") debug:NO];
    *errOut = [self cleanUpExploits];
    if (*errOut) return;
    
    // We will not be able to reset this after elevating privileges, so do it now
    if (removeJailbreakEnabled) [[DOPreferenceManager sharedManager] setPreferenceValue:@NO forKey:@"removeJailbreakEnabled"];

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Elevating Privileges") debug:NO];
    *errOut = [self elevatePrivileges];

    if (*errOut) return;
    *errOut = [self showNonDefaultSystemApps];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }
    *errOut = [self ensureDevModeEnabled];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }

    // Preserve a legacy interruption only during installation, after privilege
    // escalation and before selecting a root or injecting launchd. Removal must
    // never replace the requested target with a fresh bootstrap.
    if ([DOBootstrapper rootHidePortEnabled] && !removeJailbreakEnabled) {
        *errOut = [DOBootstrapper preserveInterruptedRootHideBootstrap];
        if (*errOut) {
            [self cleanUpPostExploitation];
            return;
        }
    }
    // Now that we are unsandboxed, populate the jailbreak root path
    *errOut = [[DOEnvironmentManager sharedManager] ensureJailbreakRootExists];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }
    
    *errOut = [[DOEnvironmentManager sharedManager] prepareBootstrap];
    if (*errOut) {
        // A RootHide bootstrap transaction may be incomplete here. Do not
        // proceed into launchd injection with live post-exploitation state.
        // Keep Dopamine's original error path unchanged.
        if ([DOBootstrapper rootHidePortEnabled]) [self cleanUpPostExploitation];
        return;
    }
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: hidden bootstrap prepared"];
    if ([DOBootstrapper rootHidePortEnabled] && !removeJailbreakEnabled) {
        NSString *activeRoot = gSystemInfo.jailbreakInfo.rootPath ?
            @(gSystemInfo.jailbreakInfo.rootPath) : nil;
        int requestedTweakState = RH3ApplyStagedTweakChoice(activeRoot);
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"tweaks: staged installer-phase transition result=%d",
             requestedTweakState]];
        if (requestedTweakState) {
            *errOut = [NSError errorWithDomain:JBErrorDomain
                                         code:JBErrorCodeFailedLaunchdInjection
                                     userInfo:@{NSLocalizedDescriptionKey:
                                         [NSString stringWithFormat:@"Unsafe or incomplete RootHide tweak-mode change (%d); no launchd injection attempted", requestedTweakState]}];
            [self cleanUpPostExploitation];
            return;
        }
    }
    if ([DOBootstrapper rootHidePortEnabled]) {
        setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/rootfs/sbin:/rootfs/bin:/rootfs/usr/sbin:/rootfs/usr/bin", 1);
    }
    else {
        setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/var/jb/sbin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/usr/bin", 1);
    }
    setenv("TERM", "xterm-256color", 1);

    *errOut = [[DOEnvironmentManager sharedManager] updateBootLogo];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }
    
    // RootHide's verified bootstrap marker is authoritative after the first
    // install. The UI preference can be stale: silently applying it again
    // would recreate .safe_mode after the user removed it successfully.
    // First-time RootHide safety is enforced by injectRootHideLaunchdHookSafely.
    if (!tweaksEnabled && ![DOBootstrapper rootHidePortEnabled]) {
        printf("Creating safe mode marker file since tweaks were disabled in settings\n");
        [[NSData data] writeToFile:JBROOT_PATH(@"/basebin/.safe_mode") atomically:YES];
    }
    if ([DOBootstrapper rootHidePortEnabled]) {
        struct stat rh3SafeInfo = {0};
        int rh3SafeExists = lstat(JBROOT_PATH("/basebin/.safe_mode"), &rh3SafeInfo) == 0;
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"tweaks: existing RootHide marker authoritative; old_preference=%d safe_mode=%d",
             tweaksEnabled, rh3SafeExists]];
    }
    
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Loading BaseBin TrustCache") debug:NO];
    *errOut = [self loadBasebinTrustcache];
    if (*errOut) {
        [self cleanUpPostExploitation];
        return;
    }
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: BaseBin trustcache loaded"];

    if (removeJailbreakEnabled) {
        *errOut = [self removeJailbreak];
        [self cleanUpPostExploitation];
        if (!*errOut) *didRemove = YES;
        return;
    }

    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Initializing Environment") debug:NO];
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: about to inject hook into PID 1 (crash-sensitive)"];
    *errOut = [self injectLaunchdHook];
    if (*errOut) {
        if ([DOBootstrapper rootHidePortEnabled])
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"phase: launchd injection FAILED: %@", (*errOut).localizedDescription]];
        [self cleanUpPostExploitation];
        return;
    }
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: launchd injection completed"];
    
    if ([DOBootstrapper rootHidePortEnabled]) {
        int logFD = [[DOUIManager sharedInstance] rh3CopyDiagnosticFD];
        int descriptorError = logFD < 0 ? errno : 0;
        __block int status = -1;
        dispatch_group_t registration = dispatch_group_create();
        dispatch_group_async(registration, dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            if (logFD >= 0) { status = jbclient_dopamine_roothide_bootlog(logFD); close(logFD); }
        });
        BOOL finished = dispatch_group_wait(registration, dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC)) == 0;
        NSString *registrationDetails = [NSString stringWithFormat:@"boot diagnostic registration: completed=%d result=%d fd_errno=%d", finished, finished ? status : -1, descriptorError];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:registrationDetails];
        [[DOUIManager sharedInstance] sendLog:registrationDetails debug:NO];
        if (!finished || status != 0) {
            NSString *message = [NSString stringWithFormat:@"Cannot register persistent boot diagnostics; activation stopped before userspace reboot (%@)", registrationDetails];
            *errOut = [NSError errorWithDomain:JBErrorDomain code:JBErrorCodeFailedLaunchdInjection userInfo:@{NSLocalizedDescriptionKey:message}];
            [self cleanUpPostExploitation]; return;
        }
    }

    // After the launchd hook is initialized, we need to make the app believe the device is jailbroken
    [[DOEnvironmentManager sharedManager] setJailbroken:YES withVersion:[NSString stringWithContentsOfFile:JBROOT_PATH(@"/basebin/.version") encoding:NSUTF8StringEncoding error:nil]];
    
    if ([DOBootstrapper rootHidePortEnabled]) {
        // RootHide does not use stock Dopamine's /usr/lib fakelib mount or
        // /private/preboot protection. Keep that path intact for Dopamine.
        [[DOUIManager sharedInstance] sendLog:@"Initializing RootHide dyld support" debug:NO];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: dyld generation starting"];
        int result = basebin_generate(false);
        if (result == 0) {
            result = ensure_dyld_trustcache(JBROOT_PATH("/basebin/.fakelib/dyld"));
        }
        if (result != 0) {
            *errOut = [NSError errorWithDomain:JBErrorDomain
                                         code:JBErrorCodeFailedInitFakeLib
                                     userInfo:@{NSLocalizedDescriptionKey :
                                         [NSString stringWithFormat:@"RootHide dyld initialization failed (%d)", result]}];
            [self cleanUpPostExploitation];
            return;
        }
        exec_set_patch(true);
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: dyld generation complete"];
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: configuring RootHide helper environment"];
        setenv("DYLD_IN_CACHE", "0", 1);
        setenv("DISABLE_TWEAKS", "1", 1);
        setenv("DYLD_INSERT_LIBRARIES", JBROOT_PATH("/basebin/systemhook.dylib"), 1);
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: RootHide helper environment configured"];
    }
    else {
        // Preserve Dopamine 3's conventional protection and fakelib behavior.
        [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Initializing Protection") debug:NO];
        *errOut = [self applyProtection];
        if (*errOut) {
            [self cleanUpPostExploitation];
            return;
        }

        [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Applying Bind Mount") debug:NO];
        *errOut = [self createFakeLib];
        if (*errOut) {
            [self cleanUpPostExploitation];
            return;
        }
    }
    
    // Stock Dopamine refreshes iconservicesagent here. In the experimental
    // RootHide first activation this is the FIRST spawned child after
    // enabling dyld/systemhook patching. A stalled patch-daemon/child
    // handshake causes exec_cmd_trusted to wait forever for a nonessential
    // icon refresh, preventing bootstrap finalization altogether. Defer
    // that refresh in RootHide; retain stock Dopamine's exact behavior.
    if ([DOBootstrapper rootHidePortEnabled]) {
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: deferring optional iconservicesagent refresh"];
    }
    else {
        exec_cmd_trusted(JBROOT_PATH("/usr/bin/killall"), "-9", "iconservicesagent", NULL);
    }
    
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: starting RootHide bootstrap finalization / packages"];
    *errOut = [self finalizeBootstrapIfNeeded];
    if (*errOut) {
        if ([DOBootstrapper rootHidePortEnabled])
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"phase: bootstrap FAILED: %@", (*errOut).localizedDescription]];
        [self cleanUpPostExploitation];
        return;
    }
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: bootstrap finalization completed"];

    // Run only when expressly requested in Settings. The re-randomized
    // primary RootHide bootstrap has the initial exploit's CS_INSTALLER
    // identity here. Actual import timing by launchd remains unverified;
    // persist only the selected OpenSSH plist before userspace reboot.
    // The service is NOT required for the jailbreak; an SSH error must never
    // turn a successful bootstrap into another interrupted jailbreak.
    if ([DOBootstrapper rootHidePortEnabled]) {
        int sshResult = [[DOEnvironmentManager sharedManager]
                         prepareRootHideOpenSSHBeforeUserspaceReboot];
        if (sshResult != 0 && sshResult != ECANCELED)
            [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                [NSString stringWithFormat:@"SSH pre-import: optional service preparation failed (%d); preserving jailbreak", sshResult]];
    }
    
    [[DOEnvironmentManager sharedManager] setIDownloadEnabled:idownloadEnabled needsUnsandbox:NO];
    
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Checking For Duplicate Apps") debug:NO];
    *errOut = [self ensureNoDuplicateApps];
    if (*errOut) {
        [self cleanUpPostExploitation];
        *showLogs = NO;
        return;
    }
    *errOut = [self cleanUpPostExploitation];
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:*errOut ? @"phase: cleanup failed" : @"phase: app-side jailbreak initialization completed; userspace reboot not yet verified"];


    //printf("Starting launch daemons...\n");
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "bootstrap", "system", JBROOT_PATH("/Library/LaunchDaemons"), NULL);
    //exec_cmd_trusted(JBROOT_PATH("/usr/bin/launchctl"), "bootstrap", "system", JBROOT_PATH("/basebin/LaunchDaemons"), NULL);
    // Note: This causes the app to freeze in some instances due to launchd only having physrw_pte, we might want to only do it when neccessary
    // It's only neccessary when we don't immediately userspace reboot
    
    printf("Done!\n");
#endif // RH3_INSTALLABLE_DIAGNOSTIC
}

- (int)finalize
{
#if RH3_INSTALLABLE_DIAGNOSTIC
    // No device lifecycle operations in the install/open smoke-test app.
    return 0;
#else
    [[DOUIManager sharedInstance] sendLog:DOLocalizedString(@"Rebooting Userspace") debug:NO];
    if ([DOBootstrapper rootHidePortEnabled])
        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"phase: requesting intentional userspace reboot"];
    return [[DOEnvironmentManager sharedManager] rebootUserspace];
#endif
}

- (IOSurfaceRef)allocatePurpleGfxMemWithSize:(size_t)size
{
    NSDictionary *surfaceProperties = @{
        @"IOSurfaceMemoryRegion" : @"PurpleGfxMem",
        @"IOSurfaceAllocSize" : @(size),
    };
    return IOSurfaceCreate((__bridge CFDictionaryRef)surfaceProperties);
}

- (BOOL)surfaceIsContiguous:(IOSurfaceRef)surface
{
    vm_address_t mem_addr = (vm_address_t)IOSurfaceGetBaseAddress(surface);
    vm_size_t mem_size = (vm_size_t)IOSurfaceGetAllocSize(surface);
    vm_region_submap_short_info_data_64_t info = {0};
    uint32_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
    natural_t depth = 9999999;
    
    kern_return_t kr = vm_region_recurse_64(mach_task_self(), &mem_addr, &mem_size, &depth, (vm_region_recurse_info_t)&info, &count);
    return (kr == 0 && info.share_mode == SM_EMPTY && info.object_id != 0);
}

- (BOOL)contiguousMappingWorks
{
    IOSurfaceRef surface = [self allocatePurpleGfxMemWithSize:0x8000];
    if (surface == NULL) return false;
    
    BOOL contiguous = [self surfaceIsContiguous:surface];
    CFRelease(surface);
    return contiguous;
}

- (BOOL)contiguousMappingWorkaroundNeeded
{
    DOExploit *kernelExploit = [DOExploitManager sharedManager].selectedKernelExploit;
    if ([kernelExploit hasRequirement:@"contiguousMapping"]) {
        return ![self contiguousMappingWorks];
    }
    return NO;
}

- (int)crashBackboardd
{
#pragma pack(push, 4)
    typedef struct {
        mach_msg_header_t header;
        mach_msg_body_t body;
        mach_msg_ool_descriptor_t archive;
        NDR_record_t ndr;
        mach_msg_type_number_t archiveLength;
    } Request;
#pragma pack(pop)
    
    kern_return_t bootstrap_look_up(mach_port_t, const char *, mach_port_t *);
    
    NSData *archive =
        [NSKeyedArchiver archivedDataWithRootObject:@[ @[] ]
                              requiringSecureCoding:YES
                                              error:nil];
    mach_port_t bootstrap = MACH_PORT_NULL;
    mach_port_t service = MACH_PORT_NULL;

    if (!archive ||
        task_get_bootstrap_port(mach_task_self(), &bootstrap) != KERN_SUCCESS ||
        bootstrap_look_up(bootstrap, "com.apple.backboard.hid.services", &service) != KERN_SUCCESS) {
        return -1;
    }

    Request request = {0};
    request.header.msgh_bits =
        MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0) | MACH_MSGH_BITS_COMPLEX;
    request.header.msgh_size = sizeof(request);
    request.header.msgh_remote_port = service;
    request.header.msgh_id = 6000032;   // kPostTouchAnnotationsMessageID
    request.body.msgh_descriptor_count = 1;
    request.archive.address = (void *)archive.bytes;
    request.archive.size = (mach_msg_size_t)archive.length;
    request.archive.copy = MACH_MSG_VIRTUAL_COPY;
    request.archive.type = MACH_MSG_OOL_DESCRIPTOR;
    request.ndr = NDR_record;
    request.archiveLength = (mach_msg_type_number_t)archive.length;

    (void)mach_msg(&request.header,
                   MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                   request.header.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   1000,
                   MACH_PORT_NULL);
    
    mach_port_deallocate(mach_task_self(), service);
    return 0;
}

- (int)crashBackboardd_15
{
    // CVE-2024-27801
    xpc_connection_t (*haxx_xpc_connection_create_mach_service)(const char *, dispatch_queue_t, uint64_t) = dlsym(RTLD_DEFAULT, "xpc_connection_create_mach_service");
    if (!haxx_xpc_connection_create_mach_service) {
        return -1;
    }
    xpc_connection_t client = haxx_xpc_connection_create_mach_service("com.apple.backboard.TouchDeliveryPolicyServer", NULL, 0);
    xpc_connection_set_event_handler(client, ^(xpc_object_t event) {});
    xpc_connection_resume(client);
    xpc_object_t message = xpc_dictionary_create(NULL, NULL, 0);
    uint8_t root[1024] = { 0 };
    memcpy(root, "bplist17", strlen("bplist17"));
    xpc_dictionary_set_data(message, "root",root, 1024);
    xpc_dictionary_set_uint64(message, "proxynum", 1);
    xpc_dictionary_set_uint64(message, "inv", 1);
    uint8_t uaf_xpc[1024];
    memset(uaf_xpc, 0x41, 1024);
    xpc_dictionary_set_value(message, "ool", xpc_data_create(uaf_xpc, 1024));
    xpc_connection_send_message_with_reply_sync(client, message);
    return 0;
}

- (void)applyContiguousMappingWorkaround
{
    if (@available(iOS 16.0, *)) {
        [self crashBackboardd];
    }
    else {
        [self crashBackboardd_15];
    }
    // After backboardd has crashed, we have about 200ms until the new backboardd kills our app
    // In this timeframe we need to steal it's contiguous PurpleGfxMem allocation
    IOSurfaceRef surface = NULL;
    do {
        if (surface) {
            CFRelease(surface);
            surface = NULL;
            usleep(50);
        }
        surface = [self allocatePurpleGfxMemWithSize:0x8000];
    }
    while (![self surfaceIsContiguous:surface]);
    
    printf("Got contiguous mapping surface %p\n", surface);
    
    // We keep the surface alive for another 20 seconds
    // This persists our process being killed
    // Once it is freed, the next Dopamine can regain the contiguous mapping
    mach_port_t surfacePort = IOSurfaceCreateMachPort(surface);
    kern_return_t kr = clock_alarm_preserve_port(surfacePort, 20);
    mach_port_mod_refs(mach_task_self(), surfacePort, MACH_PORT_RIGHT_SEND, -1);
    CFRelease(surface);
    
    printf("preserved port? %d\n", kr);
}

@end
