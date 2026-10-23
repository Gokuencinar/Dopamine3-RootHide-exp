#import "internal.h"
#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <sys/mount.h>
#import <libjailbreak/stock_fixes.h>
#include <libjailbreak/roothider/common.h>
#include <sys/wait.h>
#include <errno.h>
#include <limits.h>

SInt32 CFUserNotificationDisplayAlert(CFTimeInterval timeout, CFOptionFlags flags, CFURLRef iconURL, CFURLRef soundURL, CFURLRef localizationURL, CFStringRef alertHeader, CFStringRef alertMessage, CFStringRef defaultButtonTitle, CFStringRef alternateButtonTitle, CFStringRef otherButtonTitle, CFOptionFlags *responseFlags) API_AVAILABLE(ios(3.0));

void execute_unsandboxed(void (^block)(void))
{
	uint64_t credBackup = 0;
	jbclient_root_steal_ucred(0, &credBackup);
	block();
	jbclient_root_steal_ucred(credBackup, NULL);
}

int mount_unsandboxed(const char *type, const char *dir, int flags, void *data)
{
	__block int r = 0;
	execute_unsandboxed(^{
		r = mount(type, dir, flags, data);
	});
	return r;
}

int unmount_unsandboxed(const char *dir, int flags)
{
	__block int r = 0;
	execute_unsandboxed(^{
		r = unmount(dir, flags);
	});
	return r;
}

bool is_protected(const char *path)
{
	struct statfs sb;
	if (statfs(path, &sb) != 0) return false;
	return strcmp(path, sb.f_mntonname) == 0;
}

int ensure_protected(const char *path)
{
	if (!is_protected(path)) {
		return mount_unsandboxed("bindfs", path, 0, (void *)path);
	}
	return 0;
}

int ensure_unprotected(const char *path)
{
	if (is_protected(path)) {
		return unmount_unsandboxed(path, MNT_FORCE);
	}
	return 0;
}

// jbctl is a new process: main.m receives the canonical rootPath from the
// server, but does NOT reconstruct jbinfo(jbrand). Consequently the common
// roothide_is_active() predicate can be false here even for a real RootHide
// startup. A checked-in RootHide root shape is sufficient to *refuse* global
// stock mounts; this check never grants credentials or permits any write.
static bool rh3_jbctl_hidden_root_from_checked_in_state(void)
{
	const char *root = jbinfo(rootPath);
	if (!root) return false;
	size_t rootLength = strnlen(root, PATH_MAX);
	if (rootLength >= PATH_MAX) return false;
	static const char *const prefixes[] = {
		"/var/containers/Bundle/Application/.jbroot-",
		"/private/var/containers/Bundle/Application/.jbroot-"
	};
	for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		size_t n = strlen(prefixes[i]);
		if (rootLength != n + 16 || strncmp(root, prefixes[i], n)) continue;
		const char *hex = root + n;
		for (size_t j = 0; j < 16; j++) {
			if (!((hex[j] >= '0' && hex[j] <= '9') ||
			      (hex[j] >= 'A' && hex[j] <= 'F') ||
			      (hex[j] >= 'a' && hex[j] <= 'f'))) return false;
		}
		return hex[16] == '\0';
	}
	return false;
}

int protection_set_active(bool active)
{
	// The stock Dopamine bootstrap protects /private/preboot with bindfs.
	// RootHide uses a randomly branded app-container root instead, and the
	// official RootHide 2 startup deliberately skipped these stock mounts.
	// Never create *or unmount* global preboot mounts in RootHide mode.
	if (roothide_is_active() || rh3_jbctl_hidden_root_from_checked_in_state()) return 0;
	int r = 0;
	if (active) {
		// Protect /private/preboot/UUID/<System, usr> from being modified by bind mounting them on top of themselves
		// This protects dumb users from accidentally deleting these, which would induce a recovery loop after rebooting
		r |= ensure_protected(prebootUUIDPath("/System"));
		r |= ensure_protected(prebootUUIDPath("/usr"));
	}
	else {
		r |= ensure_unprotected(prebootUUIDPath("/System"));
		r |= ensure_unprotected(prebootUUIDPath("/usr"));
	}
	return r;
}

bool fakelib_is_mounted(void)
{
	struct statfs fsb;
    if (statfs("/usr/lib", &fsb) != 0) return NO;
    return strcmp(fsb.f_mntonname, "/usr/lib") == 0;
}

int fakelib_set_mounted(bool mounted)
{
	// RootHide reinjects from its private bootstrap, not a bindfs overlay on
	// the global /usr/lib. Refuse either direction to avoid modifying an
	// unrelated mount, even if a stale/foreign fakelib mount is present.
	if (roothide_is_active() || rh3_jbctl_hidden_root_from_checked_in_state()) return ENOTSUP;
	int r = 0;
	if (mounted != fakelib_is_mounted()) {
		if (mounted) {
			r = mount_unsandboxed("bindfs", "/usr/lib", MNT_RDONLY, (void *)JBROOT_PATH("/basebin/.fakelib"));
		}
		else {
			r = unmount_unsandboxed("/usr/lib", MNT_FORCE);
		}
	}
	return r;
}

int jbctl_handle_internal(const char *command, int argc, char* argv[])
{
	if (!strcmp(command, "launchd_stash_port")) {
		mach_port_t *selfInitPorts = NULL;
		mach_msg_type_number_t selfInitPortsCount = 0;
		if (mach_ports_lookup(mach_task_self(), &selfInitPorts, &selfInitPortsCount) != 0) {
			printf("ERROR: Failed port lookup on self\n");
			return -1;
		}
		if (selfInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on self\n");
			return -1;
		}
		if (selfInitPorts[2] == MACH_PORT_NULL) {
			printf("ERROR: Port to stash not set\n");
			return -1;
		}

		printf("Port to stash: %u\n", selfInitPorts[2]);

		mach_port_t launchdTaskPort;
		if (task_for_pid(mach_task_self(), 1, &launchdTaskPort) != 0) {
			printf("task_for_pid on launchd failed\n");
			return -1;
		}
		mach_port_t *launchdInitPorts = NULL;
		mach_msg_type_number_t launchdInitPortsCount = 0;
		if (mach_ports_lookup(launchdTaskPort, &launchdInitPorts, &launchdInitPortsCount) != 0) {
			printf("mach_ports_lookup on launchd failed\n");
			return -1;
		}
		if (launchdInitPortsCount < 3) {
			printf("ERROR: Unexpected initports count on launchd\n");
			return -1;
		}
		launchdInitPorts[2] = selfInitPorts[2]; // Transfer port to launchd
		if (mach_ports_register(launchdTaskPort, launchdInitPorts, launchdInitPortsCount) != 0) {
			printf("ERROR: Failed stashing port into launchd\n");
			return -1;
		}
		mach_port_deallocate(mach_task_self(), launchdTaskPort);
		return 0;
	}
	else if (!strcmp(command, "protection")) {
		bool toSet = false;
		if (argc > 1) {
			if (!strcmp(argv[1], "activate")) {
				toSet = true;
			}
			else if (!strcmp(argv[1], "deactivate")) {
				toSet = false;
			}
			else {
				return -1;
			}

			return protection_set_active(toSet);
		}
		return -1;
	}
	else if (!strcmp(command, "fakelib")) {
		bool toMount = false;
		if (argc > 1) {
			if (!strcmp(argv[1], "mount")) {
				toMount = true;
			}
			else if (!strcmp(argv[1], "unmount")) {
				toMount = false;
			}
			else {
				return -1;
			}

			return fakelib_set_mounted(toMount);
		}
		return -1;
	}
	else if (!strcmp(command, "startup")) {
		protection_set_active(true);
		char *panicMessage = NULL;
		if (jbclient_watchdog_get_last_userspace_panic(&panicMessage) == 0) {
			NSString *printMessage = [NSString stringWithFormat:@"Dopamine has protected you from a userspace panic by temporarily disabling tweak injection and triggering a userspace reboot instead. A log is available under Analytics in the Preferences app. You can reenable tweak injection in the Dopamine app.\n\nPanic message: \n%s", panicMessage];
			CFUserNotificationDisplayAlert(0, 2/*kCFUserNotificationCautionAlertLevel*/, NULL, NULL, NULL, CFSTR("Watchdog Timeout"), (__bridge CFStringRef)printMessage, NULL, NULL, NULL, NULL);
			free(panicMessage);
		}
		exec_cmd(JBROOT_PATH("/usr/bin/uicache"), "-a", NULL);
	}
	else if (!strcmp(command, "install_pkg")) {
		if (argc > 1) {
			extern char **environ;
			const char *dpkg = JBROOT_PATH("/usr/bin/dpkg");
			if (jbclient_roothide_jailbroken()) {
				int result = jbclient_trust_executable_recurse(dpkg, NULL);
				pid_t child = 0;
				char *args[] = {(char *)dpkg, "-i", argv[1], NULL};
				if (!result) result = exec_cmd_roothide_spawn(&child, dpkg, NULL, NULL, args, environ);
				if (result || child <= 1) return result ?: ECHILD;
				int raw = cmd_wait_for_exit(child);
				if (raw < 0) return ECHILD;
				if (WIFEXITED(raw)) return WEXITSTATUS(raw);
				if (WIFSIGNALED(raw)) return 128 + WTERMSIG(raw);
				return EIO;
			}
			int r = execve(dpkg, (char *const *)(const char *[]){dpkg, "-i", argv[1], NULL}, environ);
			return r;
		}
		return -1;
	}
	return -1;
}
