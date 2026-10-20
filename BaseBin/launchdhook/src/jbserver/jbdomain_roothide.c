#include <signal.h>
#include <libjailbreak/roothide_bootlog.h>
#include "jbserver_global.h"

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/codesign.h>
#include <libproc.h>
#include <string.h>

int roothide_unsupport_request()
{
	JBLogError("**************************** Unsupported request ****************************");
	return -1;
}

bool roothide_domain_allowed(audit_token_t clientToken)
{
	if (!roothide_is_active()) return false;
	//its fast enough
	if(isBlacklistedToken(&clientToken)) {
		JBLogDebug("ignore xpc message from blacklisted process (%d),%s", audit_token_to_pid(clientToken), proc_get_path(audit_token_to_pid(clientToken),NULL));
		return false;
	}

	return true;
}

typedef struct {
	uint32_t Count;
	uint32_t* Types;
	uint32_t* Subtypes;
} preferredArchInfo;
int recurse_collect_untrusted_cdhashes(const char *path, const char *callerImagePath, const char *callerExecutablePath, const char *workingDir, preferredArchInfo* preferredArch, cdhash_t **cdhashesOut, uint32_t *cdhashCountOut);

static int trust_macho_recurse(const char *machoPath, const char *dlopenCallerImagePath, const char *dlopenCallerExecutablePath, const char *workingDir, xpc_object_t preferredArchsArray)
{
	if(!machoPath || !*machoPath || !dlopenCallerExecutablePath || !*dlopenCallerExecutablePath) return -1;

	size_t preferredArchCount = 0;
	if (preferredArchsArray) preferredArchCount = xpc_array_get_count(preferredArchsArray);
	// This IPC method accepts data from app processes. Keep stack storage bounded.
	if (preferredArchCount > 16) return -1;
	uint32_t preferredArchTypes[16] = { 0 };
	uint32_t preferredArchSubtypes[16] = { 0 };
	for (size_t i = 0; i < preferredArchCount; i++) {
		preferredArchTypes[i] = 0;
		preferredArchSubtypes[i] = UINT32_MAX;
		xpc_object_t arch = xpc_array_get_value(preferredArchsArray, i);
		if (xpc_get_type(arch) == XPC_TYPE_DICTIONARY) {
			preferredArchTypes[i] = xpc_dictionary_get_uint64(arch, "type");
			preferredArchSubtypes[i] = xpc_dictionary_get_uint64(arch, "subtype");
		}
	}

	preferredArchInfo preferredArch = {preferredArchCount, preferredArchTypes, preferredArchSubtypes};

	cdhash_t *cdhashes = NULL;
	uint32_t cdhashesCount = 0;
	if (recurse_collect_untrusted_cdhashes(machoPath, dlopenCallerImagePath, dlopenCallerExecutablePath, workingDir, &preferredArch, &cdhashes, &cdhashesCount) != 0) {
		free(cdhashes);
		return -1;
	}
	int result = 0;
	if (cdhashes && cdhashesCount > 0)
		result = jb_trustcache_add_cdhashes(cdhashes, cdhashesCount);
	free(cdhashes);
	return result;
}

int roothide_trust_executable_recurse(const char *executablePath, const char *processWorkingDir, xpc_object_t preferredArchsArray)
{
	return trust_macho_recurse(executablePath, NULL, executablePath, processWorkingDir, preferredArchsArray);
}

static int roothide_trust_library_recurse(const char *libraryPath, const char *callerLibraryPath, const char *callerExecutablePath, const char *currentWorkingDir)
{
	// When trusting a library that's dlopened at runtime, we need to pass the caller path
	// This is to support dlopen("@executable_path/whatever", RTLD_NOW) and stuff like that
	// (Yes that is a thing >.<)
	// Also we need to pass the path of the image that called dlopen due to @loader_path, sigh...
	return trust_macho_recurse(libraryPath, callerLibraryPath, callerExecutablePath, currentWorkingDir, NULL);
}

static int roothide_jailbroken_check(audit_token_t *callerToken, bool* jailbroken)
{
	// RootHide must be explicitly initialized by the hidden bootstrap.
	// Merely loading the Dopamine 3 IPC server does not imply RootHide is active.
	*jailbroken = roothide_is_active();
	return 0;
}

static int roothide_palehide_present(audit_token_t *callerToken, bool* palehide)
{
	static bool result = false;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		if(jbinfo(palera1n)=='hide') {
			result = true;
		} else {
			// hang forver on iphone7p ios15.8.2
			// mach_port_t tfp0 = MACH_PORT_NULL;
			// kern_return_t kr = task_for_pid(mach_task_self(), 0, &tfp0);
			// if(kr == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
			// 	mach_port_deallocate(mach_task_self(), tfp0);
			// 	result = true;
			// }
		}
	});

	*palehide = result;
	return 0;
}

static int roothide_blacklist_check(audit_token_t *callerToken, const char* checktype, xpc_object_t checkvalue, bool* blacklisted)
{
	if (!checktype || !checkvalue || !blacklisted) return -1;
	*blacklisted = false;
	if(strcmp(checktype, "pid")==0) {
		if (xpc_get_type(checkvalue) != XPC_TYPE_UINT64) return -1;
		pid_t pid = (pid_t)xpc_uint64_get_value(checkvalue);
		if(pid > 1) {
			*blacklisted = isBlacklistedPid(pid);
			return 0;
		}
	} else if(strcmp(checktype, "path")==0) {
		if (xpc_get_type(checkvalue) != XPC_TYPE_STRING) return -1;
		const char* path = xpc_string_get_string_ptr(checkvalue);
		if(path) {
			*blacklisted = isBlacklistedPath(path);
			return 0;
		}
	} else if(strcmp(checktype, "bundle")==0) {
		if (xpc_get_type(checkvalue) != XPC_TYPE_STRING) return -1;
		const char* bundle = xpc_string_get_string_ptr(checkvalue);
		if(bundle) {
			*blacklisted = isBlacklistedApp(bundle);
			return 0;
		}
	} else {
		JBLogError("Invalid checktype: %s", checktype);
		return -1;
	}
	JBLogError("Failed to check blacklist for %s : %s", checktype, xpc_type_get_name(xpc_get_type(checkvalue)));
	return -1;
}

static int roothide_jailbreakd_lookup(audit_token_t *callerToken, xpc_object_t *portOut)
{
	if (!portOut || !jailbreakd_has_checked_in()) {
		// A missing daemon can trigger many requests from system processes;
		// record the first refusal without repeatedly writing to PID 1's log.
		static int loggedUnavailable = 0;
		if (__sync_bool_compare_and_swap(&loggedUnavailable, 0, 1))
			rh3_bootlog("RootHide jailbreakd lookup refused: checkin not confirmed");
		return -1;
	}
	mach_port_t port = jailbreakdClientPort();
	if (!MACH_PORT_VALID(port)) return -1;
	*portOut = xpc_mach_send_create(port);
	if (!*portOut) mach_port_deallocate(mach_task_self(), port);
	return *portOut ? 0 : -1;
}

static int roothide_jailbreakd_checkin(audit_token_t *callerToken, xpc_object_t *portOut)
{
	pid_t pid = audit_token_to_pid(*callerToken);
	uid_t uid = audit_token_to_euid(*callerToken);

	if(uid != 0 || !portOut || !jailbreakd_is_ready()) {
		rh3_bootlog("RootHide jailbreakd checkin refused: identity or bootstrap unavailable");
		return -1;
	}
	char executablePath[PATH_MAX] = {0};
	const char *expectedPath = JBROOT_PATH("/basebin/jailbreakd");
	char expectedRealPath[PATH_MAX] = {0};
	char executableRealPath[PATH_MAX] = {0};
	if (!expectedPath || proc_pidpath_audittoken(callerToken, executablePath, sizeof(executablePath)) <= 0 ||
	    !realpath(expectedPath, expectedRealPath) ||
	    !realpath(executablePath, executableRealPath) ||
	    strcmp(executableRealPath, expectedRealPath) != 0) {
		rh3_bootlog("RootHide jailbreakd checkin refused: executable identity mismatch");
		return -1;
	}

	mach_port_t port = jailbreakdServerPort();
	if (!MACH_PORT_VALID(port)) return -1;
	*portOut = xpc_mach_recv_create(port);
	if (!*portOut) return -1;
	setJailbreakdProcess(pid);
	jailbreakd_mark_checked_in(pid);
	rh3_bootlog("RootHide jailbreakd authenticated checkin completed");
	return 0;
}

static int roothide_dyld_patch_enabled(audit_token_t *callerToken, bool* enabled)
{
	*enabled = jbinfo(dyld_patch_enabled);
	return 0;
}

static int roothide_set_dyld_patch(audit_token_t *callerToken, bool enabled)
{
	pid_t pid = audit_token_to_pid(*callerToken);
	uid_t uid = audit_token_to_euid(*callerToken);

    uint32_t csFlags = 0;
	if (csops(pid, CS_OPS_STATUS, &csFlags, sizeof(csFlags)) != 0) return -1;

	if(uid != 0 && (csFlags & CS_PLATFORM_BINARY)==0) {
		JBLogError("roothide_set_dyld_patch: denying request from %d,%d", pid, uid);
		return -1;
	}

#ifdef __arm64e__
	if (!__builtin_available(iOS 16.0, *))
	{
		if(roothide_config_set_spinlock_fix(enabled) != 0) {
			JBLogError("roothide_config_set_spinlock_fix failed");
			return -1;
		}
	}
#endif

	jbinfo(dyld_patch_enabled) = enabled;

	return 0;
}

struct jbserver_domain gRootHideDomain = {
	.permissionHandler = roothide_domain_allowed,
	.actions = {
		//JBS_ROOTHIDE_JAILBROKEN_CHECK
        {
            .handler = roothide_jailbroken_check,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "jailbroken", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_PALEHIDE_PRESENT
        {
            .handler = roothide_palehide_present,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "palehide", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_BLACKLIST_CHECK
        {
            .handler = roothide_blacklist_check,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
					{ .name = "checktype", .type = JBS_TYPE_STRING, .out = false },
					{ .name = "checkvalue", .type = JBS_TYPE_XPC_GENERIC, .out = false },
                    { .name = "blacklisted", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_JAILBREAKD_LOOKUP
        {
            .handler = roothide_jailbreakd_lookup,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "port", .type = JBS_TYPE_XPC_GENERIC, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_JAILBREAKD_CHECKIN
        {
            .handler = roothide_jailbreakd_checkin,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "port", .type = JBS_TYPE_XPC_GENERIC, .out = true },
                    { 0 },
            },
        },
		// JBS_ROOTHIDE_TRUST_LIBRARY_RECURSE
		{
			.handler = roothide_trust_library_recurse,
			.args = (jbserver_arg[]){
				{ .name = "library-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "caller-library-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "caller-executable-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "current-working-dir", .type = JBS_TYPE_STRING, .out = false },
				{ 0 },
			},
		},
		// JBS_ROOTHIDE_TRUST_EXECUTABLE_RECURSE
		{
			.handler = roothide_trust_executable_recurse,
			.args = (jbserver_arg[]){
				{ .name = "executable-path", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "process-working-dir", .type = JBS_TYPE_STRING, .out = false },
				{ .name = "preferred-archs", .type = JBS_TYPE_ARRAY, .out = false },
				{ 0 },
			},
		},
		//JBS_ROOTHIDE_DYLD_PATCH_ENABLED_GET
        {
            .handler = roothide_dyld_patch_enabled,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "enabled", .type = JBS_TYPE_BOOL, .out = true },
                    { 0 },
            },
        },
		//JBS_ROOTHIDE_DYLD_PATCH_ENABLED_SET
        {
            .handler = roothide_set_dyld_patch,
            .args = (jbserver_arg[]) {
                    { .name = "caller-token", .type = JBS_TYPE_CALLER_TOKEN, .out = false },
                    { .name = "enabled", .type = JBS_TYPE_BOOL, .out = false },
                    { 0 },
            },
        },
		{ 0 },
	},
};
