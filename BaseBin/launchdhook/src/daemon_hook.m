#import <xpc/xpc.h>
#import <xpc_private.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <substrate.h>
#import <mach-o/dyld.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/roothide_bootlog.h>
#import <Foundation/Foundation.h>
#import <litehook.h>

void xpc_dictionary_add_launch_daemon_plist_at_path(xpc_object_t xdict, const char *path)
{
	// Import must not block PID 1 when a malformed package has installed a
	// FIFO or other special file in place of a launch daemon plist.
	int ldFd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (ldFd >= 0) {
		struct stat s = {};
		if(fstat(ldFd, &s) != 0) {
			close(ldFd);
			return;
		}
		// Import runs inside launchd. A malformed package entry must never
		// cause an unbounded mapping or a read from a special device here.
		// Four MiB is a defensive ceiling, far above ordinary launchd plists.
		if (!S_ISREG(s.st_mode) || s.st_size <= 0 || s.st_size > 4 * 1024 * 1024) {
			close(ldFd);
			return;
		}
		size_t len = s.st_size;
		void *addr = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, ldFd, 0);
		if (addr != MAP_FAILED) {
			xpc_object_t daemonXdict = xpc_create_from_plist(addr, len);
			if (daemonXdict) {
				// Import package-managed launchd dictionaries verbatim. The
				// former SSH-only in-memory rebase ran without consent, and r165
				// showed it did not govern the live job. A separately opted-in
				// installer-phase repair can update the verified on-disk plist
				// for a later import; its effective timing is unverified.
				// Ignore malformed/non-job plists instead of giving launchd a
				// foreign XPC type. The required Label is not rewritten.
				if (xpc_get_type(daemonXdict) == XPC_TYPE_DICTIONARY &&
				    xpc_dictionary_get_string(daemonXdict, "Label") != NULL)
					xpc_dictionary_set_value(xdict, path, daemonXdict);
				// Under -fobjc-arc, xpc_object_t is an Objective-C OS object:
				// ARC releases this local at scope exit. xpc_dictionary_set_value
				// keeps its own reference. An explicit xpc_release is forbidden
				// by ARC and must not be added here.
			}
			munmap(addr, len);
		}
		close(ldFd);
	}
}

xpc_object_t (*xpc_dictionary_get_value_orig)(xpc_object_t xdict, const char *key);
// launchd may read Paths repeatedly while importing a daemon. Avoid appending
// the same private directories on every read, which grows the shared array.
static bool rh3_xpc_paths_contains(xpc_object_t paths, const char *path)
{
    if (!paths || !path || xpc_get_type(paths) != XPC_TYPE_ARRAY) return false;
    size_t count = xpc_array_get_count(paths);
    for (size_t i = 0; i < count; i++) {
        const char *current = xpc_array_get_string(paths, i);
        if (current && !strcmp(current, path)) return true;
    }
    return false;
}

xpc_object_t xpc_dictionary_get_value_hook(xpc_object_t xdict, const char *key)
{
	xpc_object_t origXvalue = xpc_dictionary_get_value_orig(xdict, key);
	if (!strcmp(key, "LaunchDaemons")) {
		if (origXvalue && xpc_get_type(origXvalue) == XPC_TYPE_DICTIONARY) {
			for (NSString *daemonPlistName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/basebin/LaunchDaemons") error:nil]) {
				if ([daemonPlistName.pathExtension isEqualToString:@"plist"]) {
					xpc_dictionary_add_launch_daemon_plist_at_path(origXvalue, [JBROOT_PATH(@"/basebin/LaunchDaemons") stringByAppendingPathComponent:daemonPlistName].fileSystemRepresentation);
				}
			}
			for (NSString *daemonPlistName in [[NSFileManager defaultManager] contentsOfDirectoryAtPath:JBROOT_PATH(@"/Library/LaunchDaemons") error:nil]) {
				if ([daemonPlistName.pathExtension isEqualToString:@"plist"]) {
					xpc_dictionary_add_launch_daemon_plist_at_path(origXvalue, [JBROOT_PATH(@"/Library/LaunchDaemons") stringByAppendingPathComponent:daemonPlistName].fileSystemRepresentation);
				}
			}
		}
	}
	else if (!strcmp(key, "Paths")) {
		if (origXvalue && xpc_get_type(origXvalue) == XPC_TYPE_ARRAY) {
			const char *basebin = JBROOT_PATH("/basebin/LaunchDaemons");
			const char *packages = JBROOT_PATH("/Library/LaunchDaemons");
			if (!rh3_xpc_paths_contains(origXvalue, basebin))
				xpc_array_set_string(origXvalue, XPC_ARRAY_APPEND, basebin);
			if (!rh3_xpc_paths_contains(origXvalue, packages))
				xpc_array_set_string(origXvalue, XPC_ARRAY_APPEND, packages);
		}
	}
	else if (!strcmp(key, "com.apple.private.xpc.launchd.userspace-reboot")) {
		if (!origXvalue || xpc_get_type(origXvalue) == XPC_TYPE_BOOL) {
			bool origValue = false;
			if (origXvalue) {
				origValue = xpc_bool_get_value(origXvalue);
			}
			if (!origValue) {
				// Allow watchdogd to do userspace reboots
				return xpc_dictionary_get_value_orig(xdict, "com.apple.private.iowatchdog.user-access");
			}
		}
	}
	return origXvalue;
}

void initDaemonHooks(void)
{
	xpc_dictionary_get_value_orig = xpc_dictionary_get_value;
	litehook_rebind_symbol(LITEHOOK_REBIND_GLOBAL, xpc_dictionary_get_value, (void *)xpc_dictionary_get_value_hook, NULL);
}
