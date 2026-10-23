#include <libjailbreak/roothide_bootlog.h>
#include <spawn.h>
#include "../systemhook/src/common/common.h"
#include "boomerang.h"
#include "crashreporter.h"
#include "update.h"
#include <libjailbreak/util.h>
#include <substrate.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <litehook.h>
#include "jbserver/jbserver_local.h"
#include "hookd_provider.h"
#include <libjailbreak/roothider.h>
#include <libjailbreak/jbroot.h>
#include <errno.h>
#include <dlfcn.h>
#include "roothide_manager_spawn.h"
extern char **environ;

void abort_with_reason(uint32_t reason_namespace, uint64_t reason_code, const char *reason_string, uint64_t reason_flags);

extern int systemwide_trust_file_by_path(const char *path);
extern int platform_set_process_debugged(uint64_t pid, bool fullyDebugged);
extern void systemwide_domain_set_enabled(bool enabled);

int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
                              struct _posix_spawn_args_desc *desc,
                              char *const argv[restrict],
                              char *const envp[restrict]);

// A blacklisted process must not inherit the jailbreak's injected libraries.
// Keep the original spawn flags and preserve unrelated environment entries.
static int roothide_spawn_uninjected(pid_t *pid, const char *path,
                                    struct _posix_spawn_args_desc *desc,
                                    char *const argv[restrict],
                                    char *const envp[restrict])
{
	if (!envp) return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
	size_t count = 0;
	while (envp[count]) {
		if (++count > 4096) return E2BIG;
	}
	char **filtered = calloc(count + 1, sizeof(char *));
	if (!filtered) return ENOMEM;
	size_t len = 0;
	for (size_t i = 0; i < count; i++) {
		if (strncmp(envp[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) continue;
		filtered[len++] = envp[i];
	}
	int result = __posix_spawn_orig_wrapper(pid, path, desc, argv, filtered);
	free(filtered);
	return result;
}

#define LOG_PROCESS_LAUNCHES 0

extern bool gInEarlyBoot;
extern bool gFreeBootLogoBeforeBackboardd;
void free_boot_logo(void);

void early_boot_done(void)
{
	gInEarlyBoot = false;
}

static const char *rh3_pid1_var_alias_n(const char *path, size_t *length);

bool roothide_launchdhook_origin_verified(void)
{
	// During userspace reboot the brand may not be restored yet. The root
	// string alone is not proof of RootHide: require that the *loaded*
	// launchdhook image resides in that exact validated bootstrap directory.
	const char *root = get_jbroot();
	if (!systemhook_is_roothide_root_path(root)) return false;
	Dl_info image = {0};
	if (!dladdr((const void *)&roothide_launchdhook_origin_verified, &image) || !image.dli_fname) return false;
	static const char suffix[] = "/basebin/launchdhook.dylib";
	size_t rootLength = strlen(root);
	size_t imageLength = strlen(image.dli_fname);
	// The active hidden root may be named /private/var while dyld reports
	// its loaded image under /var (or vice versa). This is a lexical alias
	// only, never realpath or an unrestricted symlink traversal in PID 1.
	root = rh3_pid1_var_alias_n(root, &rootLength);
	const char *imageName = rh3_pid1_var_alias_n(image.dli_fname, &imageLength);
	if (rootLength >= PATH_MAX || imageLength != rootLength + sizeof(suffix) - 1) return false;
	return !memcmp(imageName, root, rootLength) &&
	       !strcmp(imageName + rootLength, suffix);
}

void ensure_fakelib_mounted(void)
{
	// RootHide reinjects from its private .jbroot. Mounting fakelib over
	// /usr/lib would expose it and is only needed by stock Dopamine.
	if (roothide_is_active() || roothide_launchdhook_origin_verified()) return;
	struct statfs fsb;
	if (statfs("/usr/lib", &fsb) != 0) return;
	if (strcmp(fsb.f_mntonname, "/usr/lib") != 0) {
		systemwide_domain_set_enabled(true);

		// The jailbreak server is not reachable at this point in the launchd lifecycle
		// So we need to host our own, just so that jbctl can talk to it
		mach_port_t serverPort = jbserver_local_start();
		jbctl_earlyboot(serverPort, "internal", "fakelib", "mount", NULL);
		jbserver_local_stop();

		// Note down that the jailbreak was hidden
		// So that after the userspace reboot, we can unmount fakelib again
		setenv("DOPAMINE_IS_HIDDEN", "1", true);
	}
}

// RootHide 2 used private dyld mappings for *all injected* launchd children.
// The shared Dopamine 3 spawn helper omits DYLD_IN_CACHE=0 in PID 1. A fixed
// whitelist of manager/SSH binaries misses lsd, cfprefsd and SpringBoard,
// even when launchd has already selected RootHide's exact systemhook insert.
// Restore that dyld contract for any child with the verified active-root hook
// in its existing environment; never introduce an insert or touch a child
// without it. Do not suspend children or send jailbreakd/XPC requests in PID 1.
// Normalize only the two names for iOS's same /var mount. Never resolve an
// untrusted symlink or consult the filesystem/XPC inside PID 1.
static const char *rh3_pid1_var_alias_n(const char *path, size_t *length)
{
    if (path && length && *length >= 13 && !memcmp(path, "/private/var/", 13)) {
        *length -= 8;
        return path + 8;
    }
    return path;
}

static bool rh3_pid1_private_dyld_target(const char *path)
{
	// PID 1 can spawn services through xpcproxy or by their absolute system
	// paths; neither name is proof that a RootHide injection was requested.
	// Require the exact active-root systemhook AND verified loaded launchdhook
	// in the separate checks below. Never resolve paths or query XPC here.
	return getpid() == 1 && path && !gInEarlyBoot && !launchdhookFirstLoad &&
	       roothide_is_active();
}

// Search a colon-delimited dyld insert list by exact path, never substring:
// an unrelated library or an old randomized RootHide root is not sufficient.
static bool rh3_pid1_has_private_systemhook(char *const envp[])
{
	const char *hook = JBROOT_PATH("/basebin/systemhook.dylib");
	if (!hook) return false;
	size_t hookLen = strlen(hook);
    hook = rh3_pid1_var_alias_n(hook, &hookLen);
	static const char prefix[] = "DYLD_INSERT_LIBRARIES=";
	const char *firstInsert = NULL;
	bool found = false;
	for (size_t i = 0; envp && envp[i] && i < 4096; i++) {
		if (strncmp(envp[i], prefix, sizeof(prefix) - 1)) continue;
		const char *entry = envp[i] + sizeof(prefix) - 1;
		// envbuf_getenv and dyld need not agree on which duplicate wins.
		// Never treat a later conflicting value as proof of injection.
		if (firstInsert) {
			if (strcmp(firstInsert, entry)) return false;
			continue;
		}
		firstInsert = entry;
		while (*entry) {
			const char *end = strchr(entry, ':');
			size_t length = end ? (size_t)(end - entry) : strlen(entry);
                const char *equivalent = rh3_pid1_var_alias_n(entry, &length);
			if (length == hookLen && !memcmp(equivalent, hook, hookLen)) found = true;
			if (!end) break;
			entry = end + 1;
		}
	}
	return found;
}

// Caller owns *ownedEnv when non-NULL. Preserve every unrelated entry and
// replace any DYLD_IN_CACHE assignments with one unambiguous value.
static int rh3_pid1_prepare_private_dyld_env(const char *path, char *const argv[],
					      struct _posix_spawn_args_desc *desc,
					      char *const envp[], char ***ownedEnv)
{
	*ownedEnv = NULL;
	(void)argv;
	if (!rh3_pid1_private_dyld_target(path) || !envp)
		return 0;
	// A NULL descriptor or attrp is a valid posix_spawn request with default
	// attributes, not a reason to skip an otherwise verified RootHide child.
	// Only inspect SETEXEC/driver properties when explicit attributes exist.
	if (desc && desc->attrp) {
		posix_spawnattr_t attributes = desc->attrp;
		short flags = 0;
		if (posix_spawnattr_getflags(&attributes, &flags) != 0 ||
		    (flags & POSIX_SPAWN_SETEXEC)) return 0;
		int type = 0;
		if (posix_spawnattr_getprocesstype_np(&attributes, &type) == 0 &&
		    type == POSIX_SPAWN_PROC_TYPE_DRIVER) return 0;
	}
	if (!rh3_pid1_has_private_systemhook(envp)) return 0;
	// dladdr on every unrelated launchd spawn is unnecessary: only prove
	// origin when the selected environment already contains our own hook.
	if (!roothide_launchdhook_origin_verified()) return 0;

	static const char cacheKey[] = "DYLD_IN_CACHE=";
	static char cacheValue[] = "DYLD_IN_CACHE=0";
	size_t count = 0, cacheCount = 0, insertCount = 0;
	bool alreadyZero = false;
	while (envp[count]) {
		if (++count > 4096) return E2BIG;
		if (!strncmp(envp[count - 1], cacheKey, sizeof(cacheKey) - 1)) {
			cacheCount++;
			alreadyZero = !strcmp(envp[count - 1], cacheValue);
		}
		if (!strncmp(envp[count - 1], "DYLD_INSERT_LIBRARIES=", sizeof("DYLD_INSERT_LIBRARIES=") - 1))
			insertCount++;
	}
	if (cacheCount == 1 && alreadyZero && insertCount <= 1) return 0;
	char **result = calloc(count + 2, sizeof(*result));
	if (!result) return ENOMEM;
	size_t used = 0;
	bool keptInsert = false;
	for (size_t i = 0; i < count; i++) {
		if (!strncmp(envp[i], cacheKey, sizeof(cacheKey) - 1)) continue;
		// Only identical duplicate inserts reach this point; keep exactly
		// one without removing any of the caller's unrelated libraries.
		if (!strncmp(envp[i], "DYLD_INSERT_LIBRARIES=", sizeof("DYLD_INSERT_LIBRARIES=") - 1)) {
			if (keptInsert) continue;
			keptInsert = true;
		}
		result[used++] = envp[i];
	}
	result[used++] = cacheValue;
	result[used] = NULL;
	*ownedEnv = result;
	return 0;
}

int __posix_spawn_orig_wrapper(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	// Match RootHide 2's PID/uniqueid bookkeeping. XPC reply hiding uses
	// this cache to tie a launchd job to the process that actually owns it.
	// Do not dereference the API's optional pid output when it is NULL.
	pid_t localPid = 0;
	pid_t *recordedPid = pid ? pid : &localPid;
	const char *manager = roothide_is_active() ? rh3_manager_spawn_name(path, argv) : NULL;
	if (manager) {
		// The previous substring test counted unrelated /evil/systemhook.dylib
		// as a successful RootHide injection. Log only the exact active-root hook.
		bool hook = rh3_pid1_has_private_systemhook(envp);
		char stage[160];
		snprintf(stage, sizeof(stage), "manager launch %s: systemhook_insert=%d proxy=%d", manager, hook,
		         !strcmp(path, "/usr/libexec/xpcproxy"));
		rh3_bootlog(stage);
	}
	char **privateDyldEnv = NULL;
	int envResult = rh3_pid1_prepare_private_dyld_env(path, argv, desc, envp, &privateDyldEnv);
	if (envResult) return envResult;
	// we need to disable the crash reporter during the orig call
	// otherwise the child process inherits the exception ports
	// and this would trip jailbreak detections
	crashreporter_pause();	
	int r = __posix_spawn_inline(recordedPid, path, desc, argv,
	                             privateDyldEnv ? privateDyldEnv : envp);
	crashreporter_resume();
	if (privateDyldEnv) {
		free(privateDyldEnv);
		char stage[96];
		snprintf(stage, sizeof(stage), "PID1 private dyld: spawn_result=%d pid=%d", r,
		         r == 0 ? *recordedPid : 0);
		rh3_bootlog(stage);
	}
	if (manager) {
		char stage[160];
		snprintf(stage, sizeof(stage), "manager launch %s: spawn_result=%d pid=%d", manager,
		         r, r == 0 ? *recordedPid : 0);
		rh3_bootlog(stage);
	}
	if (r == 0 && *recordedPid > 0 && roothide_is_active()) {
		register_job(*recordedPid);
	}

	return r;
}

// launchd commonly spawns UIKit apps through xpcproxy: path alone is then
// /usr/libexec/xpcproxy, not the app executable. Recognize *only* the
// UIKitApplication:<bundle id>[...] label in argv[1]. No substring matching,
// which could accidentally classify unrelated launchd services as apps.
static bool roothide_blacklisted_uikit_proxy(const char *path,
                                            char *const argv[restrict])
{
	if (!path || strcmp(path, "/usr/libexec/xpcproxy") != 0 ||
	    !argv || !argv[0] || !argv[1]) return false;
	static const char prefix[] = "UIKitApplication:";
	const char *label = argv[1];
	if (strncmp(label, prefix, sizeof(prefix) - 1) != 0) return false;
	const char *identifier = label + sizeof(prefix) - 1;
	const char *suffix = strchr(identifier, '[');
	if (!suffix || suffix == identifier) return false;
	const size_t length = (size_t)(suffix - identifier);
	if (length >= 256) return false;
	char bundleId[256];
	memcpy(bundleId, identifier, length);
	bundleId[length] = '\0';
	return isBlacklistedApp(bundleId);
}

int __posix_spawn_hook(pid_t *restrict pid, const char *restrict path,
					   struct _posix_spawn_args_desc *desc,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	if (path) {
		char executablePath[1024];
		uint32_t bufsize = sizeof(executablePath);
		_NSGetExecutablePath(&executablePath[0], &bufsize);
		if (!strcmp(path, executablePath)) {
			bool rootHideHandoff = roothide_is_active();
			short originalFlags = 0;
			if (rootHideHandoff) {
				if (!desc || !desc->attrp) return EINVAL;
				int result = posix_spawnattr_getflags(&desc->attrp, &originalFlags);
				if (result != 0) return result;
				if (!(originalFlags & POSIX_SPAWN_SETEXEC)) return EINVAL;
				result = posix_spawnattr_setflags(&desc->attrp, originalFlags | POSIX_SPAWN_START_SUSPENDED);
				if (result != 0) return result;
				rh3_bootlog("userspace re-exec: suspended launchd handoff enabled");
			}
			// This spawn will perform a userspace reboot...
			// Instead of the ordinary hook, we want to reinsert this dylib
			// This has already been done in envp so we only need to call the original posix_spawn

			// We are back in "early boot" for the remainder of this launchd instance
			// Mainly so we don't lock up while spawning boomerang
			gInEarlyBoot = true;

			hookd_provider_teardown();

			// If the jailbreak is currently hidden, fakelib is not mounted
			// It needs to be mounted to regain launchd code execution after the userspace reboot
			ensure_fakelib_mounted();

#if LOG_PROCESS_LAUNCHES
			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
			fprintf(f, "==== USERSPACE REBOOT ====\n");
			fclose(f);
#endif

			// Before the userspace reboot, we want to stash the primitives into boomerang
			rh3_bootlog("userspace re-exec: stashing primitives");
			boomerang_stashPrimitives();
			rh3_bootlog("userspace re-exec: primitives stashed");

			// Fix Xcode debugging being broken after the userspace reboot
			if (__builtin_available(iOS 17.0, *)) {
				unmount("/System/Developer", MNT_FORCE);
			}
			else {
				unmount("/Developer", MNT_FORCE);
			}

			// If there is a pending jailbreak update, apply it now
			const char *stagedJailbreakUpdate = getenv("STAGED_JAILBREAK_UPDATE");
			if (stagedJailbreakUpdate) {
				int r = jbupdate_basebin(stagedJailbreakUpdate);
				if (r != 0) {
					char msg[1000];
					snprintf(msg, 1000, "Failed updating basebin (error %d).", r);
					abort_with_reason(7, 1, msg, 0);
				}
				unsetenv("STAGED_JAILBREAK_UPDATE");
			}

			// Always use environ instead of envp, as boomerang_stashPrimitives calls setenv
			// setenv / unsetenv can sometimes cause environ to get reallocated
			// In that case envp may point to garbage or be empty
			// Say goodbye to this process
			rh3_bootlog("userspace re-exec: entering kernel spawn");
			int result = __posix_spawn_orig_wrapper(pid, path, desc, argv, environ);
			int spawnError = errno;
			if (rootHideHandoff) {
				char stage[128];
				snprintf(stage, sizeof(stage), "userspace re-exec: kernel spawn RETURNED result=%d errno=%d", result, spawnError);
				rh3_bootlog(stage);
				(void)posix_spawnattr_setflags(&desc->attrp, originalFlags);
			}
			errno = spawnError;
			return result;
		}
	}

#if LOG_PROCESS_LAUNCHES
	if (path) {
		FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		fprintf(f, "%s", path);
		int ai = 0;
		while (argv) {
			if (argv[ai]) {
				if (ai >= 1) {
					fprintf(f, " %s", argv[ai]);
				}
				ai++;
			}
			else {
				break;
			}
		}
		fprintf(f, "\n");
		fclose(f);

		// if (!strcmp(path, "/usr/libexec/xpcproxy")) {
		// 	const char *tmpBlacklist[] = {
		// 		"com.apple.logd"
		// 	};
		// 	size_t blacklistCount = sizeof(tmpBlacklist) / sizeof(tmpBlacklist[0]);
		// 	for (size_t i = 0; i < blacklistCount; i++)
		// 	{
		// 		if (!strcmp(tmpBlacklist[i], firstArg)) {
		// 			FILE *f = fopen("/var/mobile/launch_log.txt", "a");
		// 			fprintf(f, "blocked injection %s\n", firstArg);
		// 			fclose(f);
		// 			return __posix_spawn_orig_wrapper(pid, path, file_actions, desc, envp);
		// 		}
		// 	}
		// }
	}
#endif

	// We can't support injection into processes that get spawned before the launchd XPC server is up
	// (Technically we could but there is little reason to, since it requires additional work)
	if (gInEarlyBoot) {
		if (path && !strcmp(path, "/usr/libexec/xpcproxy")) {
			// The spawned process being xpcproxy indicates that the launchd XPC server is up
			// All processes spawned including this one should be injected into
			early_boot_done();
		}
		else {
			return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
		}
	}

	// If we're drawing a boot logo, free up it's resources before backboardd starts
	if (gFreeBootLogoBeforeBackboardd) {
		if (path && !strcmp(path, "/usr/libexec/xpcproxy")) {
			if (argv && argv[0]) {
				if (argv[1]) {
					if (!strcmp(argv[1], "com.apple.backboardd")) {
						free_boot_logo();
						gFreeBootLogoBeforeBackboardd = false;
					}
				}
			}
		}
	}

	// RootHide 2 did not turn on global process injection while its
	// initial bootstrap was being finalized in an already-running launchd.
	// Otherwise a failed setup can leave half-initialized hooks across
	// system processes. On the first userspace reboot this flag is false.
	// Do not change normal Dopamine 3's launchd behavior.
	if (roothide_is_active() && launchdhookFirstLoad) {
		// Avoid relaunching the experimental jailbreak app during an
		// interrupted first activation, matching RootHide 2's safeguard.
		if (path && strstr(path, ".app/") && string_has_suffix(path, "/Dopamine"))
			return EPERM;
		return __posix_spawn_orig_wrapper(pid, path, desc, argv, envp);
	}

	// Blacklisted apps are launched without tweak injection. Their identifiers
	// are read from the RootHide configuration under the active jailbreak root.
		if (path && roothide_is_active() &&
		    (isBlacklistedPath(path) || roothide_blacklisted_uikit_proxy(path, argv))) {
		// Record the child PID before its first userspace instructions execute;
		// the server uses this record to deny RootHide IPC to the child.
		pid_t *trackedPid = allocBlacklistProcessId();
		if (!trackedPid) return ENOMEM;
		int result = roothide_spawn_uninjected(trackedPid, path, desc, argv, envp);
		if (pid && result == 0) *pid = *trackedPid;
		commitBlacklistProcessId(trackedPid);
		return result;
	}
	return posix_spawn_hook_shared(pid, path, desc, argv, envp, __posix_spawn_orig_wrapper, systemwide_trust_file_by_path, platform_set_process_debugged, jbsetting(jetsamMultiplier));
}

void initSpawnHooks(void)
{
	litehook_hook_function(__posix_spawn, __posix_spawn_hook);
}
