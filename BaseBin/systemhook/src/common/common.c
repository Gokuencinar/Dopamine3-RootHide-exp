#include "common.h"
#include "roothide_spawn.h"
#include "roothide_trust_policy.h"
#include <xpc/xpc.h>
#include <xpc_private.h>
#include <mach-o/dyld.h>
#include <sys/param.h>
#include <sys/mount.h>
#include <sandbox.h>
#include <paths.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include "envbuf.h"
#include "private.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbserver_domains.h>
#include <libjailbreak/util.h>
#include <libjailbreak/jbroot.h>
#include <libjailbreak/hookd.h>
#include <libkern/OSCacheControl.h>
#include <stdint.h>
#include <errno.h>

// RootHide's jbrand stores a checksum in its low byte. Do not trust a
// .jbroot-looking path merely because its directory name has 16 hex digits.
static bool is_roothide_root_path_n(const char *root, size_t length)
{
	static const char prefix[] = "/var/containers/Bundle/Application/.jbroot-";
	static const char privatePrefix[] = "/private/var/containers/Bundle/Application/.jbroot-";
	const char *brand = NULL;
	if (!root) return false;
	if (length == sizeof(prefix) - 1 + 16 && !memcmp(root, prefix, sizeof(prefix) - 1)) {
		brand = root + sizeof(prefix) - 1;
	}
	else if (length == sizeof(privatePrefix) - 1 + 16 && !memcmp(root, privatePrefix, sizeof(privatePrefix) - 1)) {
		brand = root + sizeof(privatePrefix) - 1;
	}
	if (!brand) return false;
	uint64_t value = 0;
	for (size_t i = 0; i < 16; i++) {
		unsigned digit;
		if (brand[i] >= '0' && brand[i] <= '9') digit = brand[i] - '0';
		else if (brand[i] >= 'A' && brand[i] <= 'F') digit = brand[i] - 'A' + 10;
		else return false;
		value = (value << 4) | digit;
	}
	if (!value) return false;
	uint8_t check = (uint8_t)(value >> 8 ^ value >> 16 ^ value >> 24 ^
	                          value >> 32 ^ value >> 40 ^ value >> 48 ^ value >> 56);
	return check == (uint8_t)value;
}

bool systemhook_is_roothide_root_path(const char *root)
{
	return root && is_roothide_root_path_n(root, strlen(root));
}

static bool is_systemhook_insertion(const char *entry, size_t length)
{
	static const char suffix[] = "/basebin/systemhook.dylib";
	const size_t suffixLength = sizeof(suffix) - 1;
	if (length == sizeof(STOCK_HOOK_DYLIB_PATH) - 1 &&
	    !memcmp(entry, STOCK_HOOK_DYLIB_PATH, length)) return true;
	return length > suffixLength &&
	       !memcmp(entry + length - suffixLength, suffix, suffixLength) &&
	       is_roothide_root_path_n(entry, length - suffixLength);
}

// Normalize both jailbreak hook paths, including old randomized RootHide
// roots, without touching any other dylibs in the caller's environment.
// Every byte written is bounded by existingLength + selectedLength + 2.
static char *normalized_systemhook_inserts(const char *existing, const char *selected)
{
	const size_t existingLength = existing ? strlen(existing) : 0;
	const size_t selectedLength = selected ? strlen(selected) : 0;
	if (selectedLength > SIZE_MAX - 2 || existingLength > SIZE_MAX - selectedLength - 2) return NULL;
	char *result = malloc(existingLength + selectedLength + 2);
	if (!result) return NULL;
	size_t used = 0;
	if (selectedLength) {
		memcpy(result, selected, selectedLength);
		used = selectedLength;
	}
	for (const char *it = existing; it && *it;) {
		const char *end = strchr(it, ':');
		size_t partLength = end ? (size_t)(end - it) : strlen(it);
		if (partLength && !is_systemhook_insertion(it, partLength)) {
			if (used) result[used++] = ':';
			memcpy(result + used, it, partLength);
			used += partLength;
		}
		if (!end) break;
		it = end + 1;
	}
	result[used] = '\0';
	return result;
}

const char *systemhook_dylib_path(void)
{
	if (!systemhook_is_roothide_root_path(get_jbroot())) return STOCK_HOOK_DYLIB_PATH;
	// JBROOT_PATH uses stack storage. Copy it into per-thread storage before
	// returning the selected path to callers in launchd and systemhook.
	const char *hiddenPath = JBROOT_PATH("/basebin/systemhook.dylib");
	static _Thread_local char resolvedPath[PATH_MAX];
	if (!hiddenPath || strlen(hiddenPath) >= sizeof(resolvedPath)) return STOCK_HOOK_DYLIB_PATH;
	strlcpy(resolvedPath, hiddenPath, sizeof(resolvedPath));
	return resolvedPath;
}

bool string_has_prefix(const char *str, const char* prefix)
{
	if (!str || !prefix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t prefix_len = strlen(prefix);

	if (str_len < prefix_len) {
		return false;
	}

	return !strncmp(str, prefix, prefix_len);
}

bool string_has_suffix(const char* str, const char* suffix)
{
	if (!str || !suffix) {
		return false;
	}

	size_t str_len = strlen(str);
	size_t suffix_len = strlen(suffix);

	if (str_len < suffix_len) {
		return false;
	}

	return !strcmp(str + str_len - suffix_len, suffix);
}

void string_enumerate_components(const char *string, const char *separator, void (^enumBlock)(const char *pathString, bool *stop))
{
	char *stringCopy = strdup(string);
	char *curString = strtok(stringCopy, separator);
	while (curString != NULL) {
		bool stop = false;
		enumBlock(curString, &stop);
		if (stop) break;
		curString = strtok(NULL, separator);
	}
	free(stringCopy);
}

int timespec_compare(struct timespec *t1, struct timespec *t2)
{
	if (t1->tv_sec == t2->tv_sec && t1->tv_nsec == t2->tv_nsec) return 0;

	if (t1->tv_sec == t2->tv_sec) {
		return t1->tv_nsec > t2->tv_nsec ? 1 : -1;
	}
	else {
		return t1->tv_sec > t2->tv_sec ? 1 : -1;
	}
}

xpc_object_t xpc_object_from_plist(const char *path)
{
	xpc_object_t xObj = NULL;
	// O_NONBLOCK keeps an unexpected FIFO from stalling process startup
	// before fstat can reject it; regular files ignore this flag.
	int ldFd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (ldFd >= 0) {
		struct stat s = {};
		if(fstat(ldFd, &s) != 0) {
			close(ldFd);
			return NULL;
		}
		// Reject non-regular or implausibly large config before mapping it.
		// This parser runs in long-lived processes including launchd.
		if (!S_ISREG(s.st_mode) || s.st_size <= 0 || s.st_size > 4 * 1024 * 1024) {
			close(ldFd);
			return NULL;
		}
		size_t len = s.st_size;
		void *addr = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, ldFd, 0);
		close(ldFd);
		if (addr != MAP_FAILED) {
			xObj = xpc_create_from_plist(addr, len);
			munmap(addr, len);
		}
	}
	return xObj;
}

xpc_object_t jbuserconfig_get_value(const char *key)
{
	const char *configPath = JBROOT_PATH("/basebin/config.plist");
	if (!access(configPath, R_OK)) {
		static xpc_object_t configDict = NULL;
		static struct timespec lastConfigWrite = { .tv_sec=0, .tv_nsec = 0 };

		struct stat configStat;
		if (stat(configPath, &configStat) == 0) {
			if (timespec_compare(&configStat.st_mtimespec, &lastConfigWrite) > 0) {
				lastConfigWrite = configStat.st_mtimespec;
				if (configDict) xpc_release(configDict);
				configDict = xpc_object_from_plist(configPath);
			}
		}

		// A zero-length or malformed config must not be passed as a dictionary
		// to XPC when a long-lived hook examines a new process.
		if (!configDict || xpc_get_type(configDict) != XPC_TYPE_DICTIONARY) return NULL;
		return xpc_dictionary_get_value(configDict, key);
	}

	return NULL;
}

static kSpawnConfig spawn_config_for_executable(const char* path, char *const argv[restrict])
{
	// Blacklist to ensure general system stability
	// I don't like this but for some processes it seems neccessary
	const char *processBlacklist[] = {
		"/System/Library/Frameworks/GSS.framework/Helpers/GSSCred",
		"/System/Library/PrivateFrameworks/DataAccess.framework/Support/dataaccessd",
		"/System/Library/PrivateFrameworks/IDSBlastDoorSupport.framework/XPCServices/IDSBlastDoorService.xpc/IDSBlastDoorService",
		"/System/Library/PrivateFrameworks/MessagesBlastDoorSupport.framework/XPCServices/MessagesBlastDoorService.xpc/MessagesBlastDoorService",
	};
	size_t blacklistCount = sizeof(processBlacklist) / sizeof(processBlacklist[0]);
	for (size_t i = 0; i < blacklistCount; i++)
	{
		if (!strcmp(processBlacklist[i], path)) return 0;
	}

	xpc_object_t userBlacklist = jbuserconfig_get_value("ProcessBlacklist");
	if (userBlacklist && xpc_get_type(userBlacklist) == XPC_TYPE_ARRAY) {
		size_t userBlacklistCount = xpc_array_get_count(userBlacklist);
		for (size_t i = 0; i < userBlacklistCount; i++) {
				// A malformed preferences array must not crash launchd (PID 1).
				// XPC returns NULL for non-string entries; skip them instead
				// of feeding NULL to strcmp in the shared spawn path.
				const char *excluded = xpc_array_get_string(userBlacklist, i);
				if (excluded && !strcmp(excluded, path)) return kSpawnConfigTrust;
		}
	}

	return (kSpawnConfigInject | kSpawnConfigTrust);
}

// 1. Ensure the binary about to be spawned and all of it's dependencies are trust cached
// 2. Insert the active bootstrap's systemhook.dylib into all binaries spawned
// 3. Increase Jetsam limit to more sane value (Multipler defined as JETSAM_MULTIPLIER)
// 4. Fix spawning as root via persona entitlement on iOS 17.6+

static int spawn_exec_hook_common(bool isExec,
						   const char *path,
						   char *const argv[restrict],
						   char *const envp[restrict],
		struct _posix_spawn_args_desc *desc,
								 int (*trust_binary)(const char *path),
								double jetsamMultiplier,
								 int (^orig)(pid_t *pid, char *const envp[restrict]))
{
	if (!path) {
		return orig(NULL, envp);
	}

	bool personaFixNeedsResume = true;
	int personaFixUid = -1;
	int personaFixGid = -1;
	posix_spawnattr_t attr = NULL;
	if (desc) attr = desc->attrp;

	kSpawnConfig spawnConfig = spawn_config_for_executable(path, argv);
	const char *hookDylibPath = HOOK_DYLIB_PATH;

	if (spawnConfig & kSpawnConfigTrust) {
		// A failed trust-cache operation must not be reported as a successful
		// spawn/exec of a Mach-O in the authenticated hidden root. Otherwise
		// NewTerm/login and RootHide binaries fail later with EBADEXEC without
		// the caller learning that preparation failed. Keep PID1's server-local
		// behavior unchanged: it cannot synchronously repair via its own XPC.
		int trustResult = trust_binary(path);
		if (trustResult != 0 && getpid() != 1) {
			const char *root = get_jbroot();
			bool activeRootChild = systemhook_is_roothide_root_path(root) &&
			                       rh3_trust_is_active_root_child(path, root);
			bool isMachO = activeRootChild && rh3_trust_looks_like_macho(path);
			int trustStatus = rh3_trust_spawn_status(trustResult, activeRootChild, isMachO);
			if (trustStatus) {
				errno = trustStatus;
				return isExec ? -1 : trustStatus;
			}
		}
	}

	const char *existingLibraryInserts = envbuf_getenv((const char **)envp, "DYLD_INSERT_LIBRARIES");

	// Check if we can find at least one reason to not insert jailbreak related environment variables
	// In this case we also need to remove pre existing environment variables if they are already set
	bool shouldInsertJBEnv = true;
	bool hasSafeModeVariable = false;
	do {
		if (!(spawnConfig & kSpawnConfigInject)) {
			shouldInsertJBEnv = false;
			break;
		}

		// Check if we can find a _SafeMode or _MSSafeMode variable
		// In this case we do not want to inject anything
		const char *safeModeValue = envbuf_getenv((const char **)envp, "_SafeMode");
		const char *msSafeModeValue = envbuf_getenv((const char **)envp, "_MSSafeMode");
		if (safeModeValue) {
			if (!strcmp(safeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}
		if (msSafeModeValue) {
			if (!strcmp(msSafeModeValue, "1")) {
				shouldInsertJBEnv = false;
				hasSafeModeVariable = true;
				break;
			}
		}

		int proctype = 0;
		if (posix_spawnattr_getprocesstype_np(&attr, &proctype) == 0) {
			if (proctype == POSIX_SPAWN_PROC_TYPE_DRIVER) {
				// Do not inject hook into DriverKit drivers
				shouldInsertJBEnv = false;
				break;
			}
		}

		if (access(hookDylibPath, F_OK) != 0) {
			// If the hook dylib doesn't exist, don't try to inject it (would crash the process)
			shouldInsertJBEnv = false;
			break;
		}
	} while (0);

	uint8_t *attrStruct = (uint8_t *)attr;
	if (attrStruct) {
		// If systemhook is being injected and jetsam limits are set, increase them by a factor of jetsamMultiplier
		if (shouldInsertJBEnv) {
			if (jetsamMultiplier == 0 || isnan(jetsamMultiplier)) jetsamMultiplier = 3; // default value (3x)
			if (jetsamMultiplier > 1) {
				int memlimit_active = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE);
				if (memlimit_active != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_ACTIVE) = memlimit_active * jetsamMultiplier;
				}
				int memlimit_inactive = *(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE);
				if (memlimit_inactive != -1) {
					*(int*)(attrStruct + POSIX_SPAWNATTR_OFF_MEMLIMIT_INACTIVE) = memlimit_inactive * jetsamMultiplier;
				}
			}
		}

		// On iOS 17.6 and up Apple neutered persona overwrites to block going from (non root) -> (root)
		// Since jailbreak infra relies on this, we need to reenable it via our patches
		// To do this we will spawn the process as suspended, modify the ucred to the desired uid/gid and resume it
		// POSIX_SPAWN_SETEXEC is not a concern since using it together with POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE is not supported anyways
		if (__builtin_available(iOS 17.6, *)) {
			bool hasExecFlag = false;
			short flags = 0;
			if (posix_spawnattr_getflags(&attr, &flags) == 0) {
				if (flags & POSIX_SPAWN_SETEXEC) {
					hasExecFlag = true;
				}
			}
			if (!hasExecFlag && !isExec && getuid() != 0) {
				struct _posix_spawn_persona_info *personaInfo = *(struct _posix_spawn_persona_info **)(attrStruct + POSIX_SPAWNATTR_OFF_PERSONA);
				if (personaInfo) {
					if (personaInfo->pspi_id == 99 && (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_FLAGS_OVERRIDE)) {
						if (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_UID) {
							personaFixUid = personaInfo->pspi_uid;
						}
						if (personaInfo->pspi_flags & POSIX_SPAWN_PERSONA_GID) {
							personaFixGid = personaInfo->pspi_gid;
						}
					}
				}

				if (personaFixUid == 0 || personaFixGid == 0) {
					// Revert any request to become root back to mobile
					// Otherwise posix_spawn will straight up fail
					if (personaFixUid == 0) personaInfo->pspi_uid = 501;
					if (personaFixGid == 0) personaInfo->pspi_gid = 501;

					if (flags & POSIX_SPAWN_START_SUSPENDED) {
						personaFixNeedsResume = false;
					}
					else {
						posix_spawnattr_setflags(&attr, flags | POSIX_SPAWN_START_SUSPENDED);
					}
				}
			}
		}
	}

	int r = -1;

	pid_t childPid = -1;

	char *normalizedInserts = normalized_systemhook_inserts(existingLibraryInserts,
	                                                      shouldInsertJBEnv ? hookDylibPath : NULL);
	if (!normalizedInserts) {
		errno = ENOMEM;
		return isExec ? -1 : ENOMEM;
	}
	bool envNeedsUpdate = existingLibraryInserts ?
	                      strcmp(existingLibraryInserts, normalizedInserts) != 0 :
	                      normalizedInserts[0] != '\0';
	// Match RootHide's original spawn path: an injected child must use its
	// private dyld mappings, even if the parent already had the correct inserts.
	const char *dyldInCache = envbuf_getenv((const char **)envp, "DYLD_IN_CACHE");
	bool forcePrivateDyld = getpid() != 1 && normalizedInserts[0] && systemhook_is_roothide_root_path(get_jbroot());
	if (forcePrivateDyld && (!dyldInCache || strcmp(dyldInCache, "0"))) envNeedsUpdate = true;
	if (!envNeedsUpdate && !hasSafeModeVariable) {
		// Environment already contains the desired hook and third-party libraries.
		r = orig(&childPid, envp);
	}
	else {
		// Normalize stale/duplicate jailbreak hooks while preserving unrelated dylibs.
		char **envc = envbuf_mutcopy((const char **)envp);
		if (envp && !envc) {
			free(normalizedInserts);
			errno = ENOMEM;
			return isExec ? -1 : ENOMEM;
		}
		if (normalizedInserts[0]) {
			envbuf_setenv(&envc, "DYLD_INSERT_LIBRARIES", normalizedInserts);
		}
		else {
			envbuf_unsetenv(&envc, "DYLD_INSERT_LIBRARIES");
		}
		if (forcePrivateDyld) envbuf_setenv(&envc, "DYLD_IN_CACHE", "0");
		if (!shouldInsertJBEnv) {
			envbuf_unsetenv(&envc, "_SafeMode");
			envbuf_unsetenv(&envc, "_MSSafeMode");
		}
		r = orig(&childPid, envc);
		envbuf_free(envc);
	}
	free(normalizedInserts);

		// Only fix a child actually created by this spawn. The previous
		// operator precedence evaluated UID==0 even when spawn failed, and
		// could send a persona request (and SIGCONT) to the invalid PID -1.
		if (r == 0 && childPid > 0 && (personaFixUid == 0 || personaFixGid == 0)) {
		jbclient_persona_fix(childPid, personaFixUid, personaFixGid);
		if (personaFixNeedsResume) {
			kill(childPid, SIGCONT);
		}
	}

	return r;
}

int posix_spawn_hook_shared(pid_t *restrict pid, 
					   const char *restrict path,
			 struct _posix_spawn_args_desc *desc,
						  	    char *const argv[restrict],
					   			char *const envp[restrict],
					   				  void *orig,
					   				  int (*trust_binary)(const char *path),
					   				  int (*set_process_debugged)(uint64_t pid, bool fullyDebugged),
					   				 double jetsamMultiplier)
{
	int (*posix_spawn_orig)(pid_t *restrict, const char *restrict, struct _posix_spawn_args_desc *, char *const[restrict], char *const[restrict]) = orig;
	// common.c is also linked into launchdhook. PID 1 must keep its local
	// server path; asking it for its own XPC state here would deadlock.
	bool rootHide = getpid() != 1 && path && systemhook_is_roothide_root_path(get_jbroot()) && jbclient_roothide_jailbroken();
	if (rootHide && (!desc || !desc->attrp)) {
		// The public entry builds the correctly sized private descriptor. It
		// reenters once, with an initialized attrp; keep file actions intact.
		posix_spawnattr_t attributes = NULL;
		int error = posix_spawnattr_init(&attributes);
		if (error) return error;
		error = posix_spawn(pid, path, desc && desc->file_actions ?
			(posix_spawn_file_actions_t *)&desc->file_actions : NULL, &attributes, argv, envp);
		posix_spawnattr_destroy(&attributes);
		return error;
	}

	int r = spawn_exec_hook_common(false, path, argv, envp, desc, trust_binary, jetsamMultiplier, ^int(pid_t *pidOut, char *const envp_patched[restrict]) {
		int rr;
		if (rootHide) {
			int type = 0;
			posix_spawnattr_t attributes = desc->attrp;
			bool driver = posix_spawnattr_getprocesstype_np(&attributes, &type) == 0 && type == POSIX_SPAWN_PROC_TYPE_DRIVER;
			rr = rh3_spawn_patched(pid ?: pidOut, &attributes, driver,
				^int(pid_t *child) { return posix_spawn_orig(child, path, desc, argv, envp_patched); },
				jbclient_roothide_patch_child,
				^int(bool resume) { return jbclient_roothide_exec_start(path, resume); },
				^int(void) { return jbclient_roothide_exec_cancel(path); });
		}
		else rr = posix_spawn_orig(pid ?: pidOut, path, desc, argv, envp_patched);
		if (rr == 0 && pid && pidOut) {
			*pidOut = *pid;
		}
		return rr;
	});

	if (r == 0 && pid && desc && !rootHide) {
		posix_spawnattr_t attr = desc->attrp;
		short flags = 0;
		if (posix_spawnattr_getflags(&attr, &flags) == 0) {
			if (flags & POSIX_SPAWN_START_SUSPENDED) {
				// If something spawns a process as suspended, ensure mapping invalid pages in it is possible
				// Normally it would only be possible after systemhook.dylib enables it
				// Fixes Frida issues
				set_process_debugged(*pid, false);
			}
		}
	}

	return r;
}

kern_return_t vm_allocate_nearby(vm_map_t target_task, vm_address_t from_area, vm_size_t from_area_size, vm_address_t *address, vm_size_t size, uint64_t limit)
{
	if (from_area != 0 && from_area_size > 0 && address) {
		// Make sure allocation is within limit for every single page in the area
		uint64_t realLimit = limit - (from_area_size / 2);

		for (uint64_t off = 0; off < realLimit; off += vm_page_size) {
			vm_address_t tmp = (from_area + from_area_size) + off;
			kern_return_t kr = vm_allocate(target_task, &tmp, size, VM_FLAGS_FIXED);
			if (kr == KERN_SUCCESS) {
				*address = tmp;
				return kr;
			}

			tmp = (from_area - size) - off;
			kr = vm_allocate(target_task, &tmp, size, VM_FLAGS_FIXED);
			if (kr == KERN_SUCCESS) {
				*address = tmp;
				return kr;
			}
		}
	}

	return KERN_NO_SPACE;
}

int execve_hook_shared(const char *path,
					   char *const argv[],
					   char *const envp[],
			 				 void *orig,
			 				 int (*trust_binary)(const char *path))
{
	int (*execve_orig)(const char *, char *const[], char *const[]) = orig;

	int r = spawn_exec_hook_common(true, path, argv, envp, NULL, trust_binary, 0, ^int(pid_t *pidOut, char *const envp_patched[restrict]){
		return execve_orig(path, argv, envp_patched);
	});

	return r;
}

__attribute__((noinline, naked)) volatile void *get_tpidrr0_el0(void)
{
	asm("MRS X0, TPIDRRO_EL0");
	asm("RET");
}

kern_return_t litehook_hook_memory_hookd(void *target, void *source, size_t sourceSize)
{
	kern_return_t kr = hookd_hook(mach_task_self_, (uint64_t)target, source, sourceSize);
	if (kr == KERN_SUCCESS) {
		sys_icache_invalidate(target, sourceSize);
	}
	return kr;
}

kern_return_t mach_vm_protect_fixed(mach_port_name_t task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection)
{
	kern_return_t rv;

	bool skipped = false;
	if (!skipped) {
		if ((new_protection & VM_PROT_EXECUTE) || (new_protection & VM_PROT_COPY)) {
			rv = hookd_vm_protect(task, address, size, set_maximum, new_protection);
		}
		else {
			rv = _kernelrpc_mach_vm_protect_trap(task, address, size, set_maximum, new_protection);
			if (rv == MACH_SEND_INVALID_DEST) {
				rv = _kernelrpc_mach_vm_protect(task, address, size, set_maximum, new_protection);
			}
		}
	}

	return rv;
}
