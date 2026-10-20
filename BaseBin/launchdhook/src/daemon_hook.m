#import <xpc/xpc.h>
#import <xpc_private.h>
#import <sys/types.h>
#import <sys/stat.h>
#import <fcntl.h>
#import <unistd.h>
#import <substrate.h>
#import <mach-o/dyld.h>
#import <libjailbreak/libjailbreak.h>
#import <Foundation/Foundation.h>
#import <litehook.h>

// Do not alter third-party plists on disk: RootHide re-randomizes its hidden
// root, so absolute paths persisted by a package become stale. Rebase ONLY
// the installed OpenSSH socket job in the launchd XPC dictionary, each boot.
static void rh3_prepare_openssh_socket_job(xpc_object_t job)
{
    if (!job || xpc_get_type(job) != XPC_TYPE_DICTIONARY) return;
    const char *label = xpc_dictionary_get_string(job, "Label");
    if (!label || strcmp(label, "com.openssh.sshd")) return;
    xpc_object_t sockets = xpc_dictionary_get_value(job, "Sockets");
    if (!sockets || xpc_get_type(sockets) != XPC_TYPE_DICTIONARY) return;
    NSString *program = JBROOT_PATH(@"/usr/sbin/sshd");
    NSString *config = JBROOT_PATH(@"/etc/ssh/sshd_config");
    NSString *key = JBROOT_PATH(@"/etc/ssh/ssh_host_ed25519_key");
    struct stat st = {0};
    if (lstat(program.fileSystemRepresentation, &st) ||
        !S_ISREG(st.st_mode) || st.st_uid != 0 || !(st.st_mode & S_IXUSR)) return;
    if (lstat(config.fileSystemRepresentation, &st) ||
        !S_ISREG(st.st_mode) || st.st_uid != 0) return;
    if (lstat(key.fileSystemRepresentation, &st) ||
        !S_ISREG(st.st_mode) || st.st_uid != 0 || (st.st_mode & 077) ||
        st.st_size < 32) return;
    xpc_object_t args = xpc_array_create(NULL, 0);
    if (!args) return;
    for (NSString *part in @[program, @"-i", @"-f", config, @"-h", key])
        xpc_array_set_string(args, XPC_ARRAY_APPEND, part.fileSystemRepresentation);
    xpc_dictionary_set_string(job, "Program", program.fileSystemRepresentation);
    xpc_dictionary_set_value(job, "ProgramArguments", args);
    // XPC objects bridge to Objective-C here and are ARC-managed.
}

void xpc_dictionary_add_launch_daemon_plist_at_path(xpc_object_t xdict, const char *path)
{
	int ldFd = open(path, O_RDONLY);
	if (ldFd >= 0) {
		struct stat s = {};
		if(fstat(ldFd, &s) != 0) {
			close(ldFd);
			return;
		}
		size_t len = s.st_size;
		void *addr = mmap(NULL, len, PROT_READ, MAP_FILE | MAP_PRIVATE, ldFd, 0);
		if (addr != MAP_FAILED) {
			xpc_object_t daemonXdict = xpc_create_from_plist(addr, len);
			if (daemonXdict) {
				rh3_prepare_openssh_socket_job(daemonXdict);
				xpc_dictionary_set_value(xdict, path, daemonXdict);
			}
			munmap(addr, len);
		}
		close(ldFd);
	}
}

xpc_object_t (*xpc_dictionary_get_value_orig)(xpc_object_t xdict, const char *key);
xpc_object_t xpc_dictionary_get_value_hook(xpc_object_t xdict, const char *key)
{
	xpc_object_t origXvalue = xpc_dictionary_get_value_orig(xdict, key);
	if (!strcmp(key, "LaunchDaemons")) {
		if (xpc_get_type(origXvalue) == XPC_TYPE_DICTIONARY) {
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
		if (xpc_get_type(origXvalue) == XPC_TYPE_ARRAY) {
			xpc_array_set_string(origXvalue, XPC_ARRAY_APPEND, JBROOT_PATH("/basebin/LaunchDaemons"));
			xpc_array_set_string(origXvalue, XPC_ARRAY_APPEND, JBROOT_PATH("/Library/LaunchDaemons"));
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
