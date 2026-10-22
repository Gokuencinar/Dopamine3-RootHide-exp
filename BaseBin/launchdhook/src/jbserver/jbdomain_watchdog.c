#include "jbserver_global.h"

#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <libjailbreak/util.h>
#include <libjailbreak/roothider.h>
#include "../crashreporter.h"

static bool watchdog_domain_allowed(audit_token_t clientToken)
{
	xpc_object_t entitlementValue = xpc_copy_entitlement_for_token("com.apple.private.iowatchdog.user-access", &clientToken);
	if (entitlementValue && xpc_get_type(entitlementValue) == XPC_TYPE_BOOL) {
		return xpc_bool_get_value(entitlementValue);
	}
	return false;
}

static int watchdog_intercept_userspace_panic(const char *panicMessage)
{
	FILE *outFile = crashreporter_open_outfile("userspace-panic", NULL);
	if (outFile) {
		fprintf(outFile, "\n%s", panicMessage);
		fprintf(outFile, "\n\nThis panic was prevented by Dopamine and a userspace reboot was done instead.");
		crashreporter_save_outfile(outFile);
	}

	setenv("WATCHDOG_PANIC_MESSAGE", panicMessage, 1);
    // The RootHide primary bootstrap is an iOS app Bundle/Application
    // directory: after the installer phase it can reject marker creation
    // with EPERM. Persist a separate, root-owned watchdog latch under the
    // existing writable AppGroup/var mapping instead. systemhook reads it
    // in addition to the legacy basebin marker; neither is cleared except
    // by an explicit, verified installer-phase user request.
    bool hiddenRoot = roothide_is_active();
    int parent = -1;
    if (hiddenRoot) {
        parent = open(JBROOT_PATH("/var"), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (parent < 0) return errno;
        struct stat directory = {0};
        int problem = fstat(parent, &directory) ? errno :
            (!S_ISDIR(directory.st_mode) || directory.st_uid != 0 ||
             (directory.st_mode & 0022) ? EPERM : 0);
        if (problem) { close(parent); return problem; }
    }
    // Preserve the stock Dopamine path. On RootHide openat pins a verified
    // writable directory and never follows a symlink for the marker itself.
    int markerFD = hiddenRoot ?
        openat(parent, ".roothide3-watchdog-safe-mode",
               O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600) :
        open(JBROOT_PATH("/basebin/.safe_mode"),
             O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
    if (markerFD < 0) { int failure = errno; if (parent >= 0) close(parent); return failure; }
	struct stat markerInfo = {0};
	int markerError = fstat(markerFD, &markerInfo) ? errno :
        (!S_ISREG(markerInfo.st_mode) || markerInfo.st_uid != 0 ||
         markerInfo.st_nlink != 1 ||
         (hiddenRoot && ((markerInfo.st_mode & 0077) || markerInfo.st_size != 0))
          ? EPERM : 0);
	if (!markerError && fsync(markerFD)) markerError = errno;
	if (close(markerFD) && !markerError) markerError = errno;
    if (!markerError && parent >= 0 && fsync(parent)) markerError = errno;
    if (parent >= 0 && close(parent) && !markerError) markerError = errno;
	if (markerError) return markerError;

	return 0;
}

static int watchdog_get_last_userspace_panic(char **panicMessage)
{
	char *messageInEnv = getenv("WATCHDOG_PANIC_MESSAGE");
	if (messageInEnv) {
		*panicMessage = strdup(messageInEnv);
		unsetenv("WATCHDOG_PANIC_MESSAGE");
		return 0;
	}
	else {
		*panicMessage = NULL;
		return 1;
	}
}

struct jbserver_domain gWatchdogDomain = {
	.permissionHandler = watchdog_domain_allowed,
	.actions = {
		// JBS_WATCHDOG_INTERCEPT_USERSPACE_PANIC
		{
			.handler = watchdog_intercept_userspace_panic,
			.args = (jbserver_arg[]){
				{ .name = "panic-message", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		// JBS_WATCHDOG_GET_LAST_USERSPACE_PANIC
		{
			.handler = watchdog_get_last_userspace_panic,
			.args = (jbserver_arg[]){
				{ .name = "panic-message", .type = JBS_TYPE_STRING, .out = true },
				{ 0 },
			},
		},
		{ 0 },
	},
};
