#include <dlfcn.h>
#include <mach-o/dyld.h>
#include "jbclient_xpc.h"
#include "jbserver.h"
#include "roothider/jailbreakd.h"

#include "roothider/log.h"
#include "roothider/xpc_private.h"

// Use the existing private daemon and its audit-token/parent checks. Never
// translate these requests into a privileged launchd action or cache a port
// across fork. This C client is linked into the standalone systemhook too.
static int roothide_lifecycle_request(uint64_t action, pid_t pid, const char *path, bool resume)
{
	mach_port_t port = jbclient_jailbreakd_lookup();
	if (!MACH_PORT_VALID(port)) return -1;
	xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
	if (!pipe) { mach_port_deallocate(mach_task_self(), port); return -1; }
	xpc_object_t request = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(request, "id", action);
	if (pid > 0) xpc_dictionary_set_int64(request, "pid", pid);
	if (path) xpc_dictionary_set_string(request, "execfile", path);
	xpc_dictionary_set_bool(request, "resume", resume);
	xpc_object_t reply = NULL;
	int error = xpc_pipe_routine(pipe, request, &reply);
	xpc_release(request);
	xpc_release(pipe);
	mach_port_deallocate(mach_task_self(), port);
	int result = -1;
	if (!error && reply && xpc_get_type(reply) == XPC_TYPE_DICTIONARY) {
		xpc_object_t value = xpc_dictionary_get_value(reply, "result");
		if (value && xpc_get_type(value) == XPC_TYPE_INT64)
			result = (int)xpc_int64_get_value(value);
	}
	if (reply) xpc_release(reply);
	return result;
}

int jbclient_roothide_patch_child(pid_t pid, bool resume)
{
	if (pid <= 0) return -1;
	return roothide_lifecycle_request(JBD_MSG_SPAWN_PATCH_CHILD, pid, NULL, resume);
}

int jbclient_roothide_exec_start(const char *path, bool resume)
{
	if (!path) return -1;
	return roothide_lifecycle_request(JBD_MSG_SPAWN_EXEC_START, 0, path, resume);
}

int jbclient_roothide_exec_cancel(const char *path)
{
	if (!path) return -1;
	return roothide_lifecycle_request(JBD_MSG_SPAWN_EXEC_CANCEL, 0, path, false);
}

#ifdef ENABLE_LOGS
void (*XPCLogDebugFunction)(const char *format, ...);
void (*XPCLogErrorFunction)(const char *format, ...);

#define JBLogDebug(...) do { if(XPCLogDebugFunction)XPCLogDebugFunction(__VA_ARGS__); } while(0)
#define JBLogError(...) do { if(XPCLogErrorFunction)XPCLogErrorFunction(__VA_ARGS__); } while(0)

void enableXPCLog(void* debugLog, void* errorLog)
{
	XPCLogDebugFunction = debugLog;
	XPCLogErrorFunction = errorLog;
}
#endif

mach_port_t jbclient_jailbreakd_lookup()
{
	mach_port_t port = MACH_PORT_NULL;
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_JAILBREAKD_LOOKUP, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			xpc_object_t portobj = xpc_dictionary_get_value(xreply, "port");
			if (portobj) {
				port = xpc_mach_send_copy_right(portobj);
			}
		}
		xpc_release(xreply);
	}
	return port;
}

mach_port_t jbclient_jailbreakd_checkin()
{
	mach_port_t port = MACH_PORT_NULL;
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_JAILBREAKD_CHECKIN, NULL);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			xpc_object_t portobj = xpc_dictionary_get_value(xreply, "port");
			if (portobj) {
				port = xpc_mach_recv_extract_right(portobj);
			}
		}
		xpc_release(xreply);
	}
	return port;
}

bool jbclient_roothide_jailbroken()
{
	bool jailbroken = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_JAILBROKEN_CHECK, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			jailbroken = xpc_dictionary_get_bool(xreply, "jailbroken");
		}
		xpc_release(xreply);
	}

	return jailbroken;
}

bool jbclient_palehide_present()
{
	bool palehide = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_PALEHIDE_PRESENT, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			palehide = xpc_dictionary_get_bool(xreply, "palehide");
		}
		xpc_release(xreply);
	}

	return palehide;
}

bool jbclient_blacklist_check_pid(pid_t pid)
{
	bool blacklisted = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(xargs, "checktype", "pid");
    xpc_dictionary_set_uint64(xargs, "checkvalue", pid);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_BLACKLIST_CHECK, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			blacklisted = xpc_dictionary_get_bool(xreply, "blacklisted");
		}
		xpc_release(xreply);
	}

	return blacklisted;
}

bool jbclient_blacklist_check_path(const char* path)
{
	if (!path) return false;
	bool blacklisted = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(xargs, "checktype", "path");
    xpc_dictionary_set_string(xargs, "checkvalue", path);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_BLACKLIST_CHECK, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			blacklisted = xpc_dictionary_get_bool(xreply, "blacklisted");
		}
		xpc_release(xreply);
	}

	return blacklisted;
}

bool jbclient_blacklist_check_bundle(const char* bundle)
{
	if (!bundle) return false;
	bool blacklisted = false;

    xpc_object_t xargs = xpc_dictionary_create_empty();
    xpc_dictionary_set_string(xargs, "checktype", "bundle");
    xpc_dictionary_set_string(xargs, "checkvalue", bundle);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_BLACKLIST_CHECK, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		if(result == 0) {
			blacklisted = xpc_dictionary_get_bool(xreply, "blacklisted");
		}
		xpc_release(xreply);
	}

	return blacklisted;
}

int jbclient_trust_executable_recurse(const char *executablePath, xpc_object_t preferredArchsArray)
{
	if (!executablePath) return -1;

	if(access(executablePath, F_OK) != 0) {
		return -2;
	}

	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(xargs, "executable-path", executablePath);

	char* cwd = getcwd(NULL, 0);
	if(cwd) {
		xpc_dictionary_set_string(xargs, "process-working-dir", cwd);
		free((void*)cwd);
	}

	if (preferredArchsArray) {
		xpc_dictionary_set_value(xargs, "preferred-archs", preferredArchsArray);
	}

	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_TRUST_EXECUTABLE_RECURSE, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

// Resolve the caller's image in this client library instead of depending on
// a symbol supplied by whichever injected hook happened to load us.
const char* dyld_image_path_containing_address(const void* addr)
{
	if (!addr) return NULL;
	Dl_info imageInfo = { 0 };
	return dladdr(addr, &imageInfo) ? imageInfo.dli_fname : NULL;
}

int jbclient_trust_library_recurse(const char *libraryPath, void *addressInCaller)
{
	if (!libraryPath) return -1;

	if (_dyld_shared_cache_contains_path(libraryPath)) {
		return -1;
	}

	if(libraryPath[0] == '/') {
		if(access(libraryPath, F_OK) != 0) {
			return -3;
		}
	}

	/* the executable file may be removed from disk at runtime,
					so we need to use the cached path from dyld */
	char executablePath[PATH_MAX] = {0};
	uint32_t bufsize = sizeof(executablePath);
	//According to dyld this returns real-path on ios (but not on macos)
	if(_NSGetExecutablePath(executablePath, &bufsize) != 0) {
		return -2;
	}

	xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_string(xargs, "library-path", libraryPath);
	xpc_dictionary_set_string(xargs, "caller-executable-path", executablePath);

	if(addressInCaller) {
		const char* callerPath = dyld_image_path_containing_address(addressInCaller);
		if (callerPath) {
			xpc_dictionary_set_string(xargs, "caller-library-path", callerPath);
		}
	}

	char* cwd = getcwd(NULL, 0);
	if(cwd) {
		xpc_dictionary_set_string(xargs, "current-working-dir", cwd);
		free((void*)cwd);
	}


	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_TRUST_LIBRARY_RECURSE, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}

bool jbclient_dyld_patch_enabled()
{
	static bool enabled = false;

	static dispatch_once_t onceToken;
	dispatch_once(&onceToken, ^{
		xpc_object_t xargs = xpc_dictionary_create_empty();
		xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_DYLD_PATCH_ENABLED_GET, xargs);
		xpc_release(xargs);
		if (xreply) {
			int64_t result = xpc_dictionary_get_int64(xreply, "result");
			if(result == 0) {
				enabled = xpc_dictionary_get_bool(xreply, "enabled");
			}
			xpc_release(xreply);
		}
	});

	return enabled;
}

int jbclient_set_dyld_patch(bool enabled)
{
    xpc_object_t xargs = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(xargs, "enabled", enabled);
	xpc_object_t xreply = jbserver_xpc_send(JBS_DOMAIN_ROOTHIDE, JBS_ROOTHIDE_DYLD_PATCH_ENABLED_SET, xargs);
	xpc_release(xargs);
	if (xreply) {
		int64_t result = xpc_dictionary_get_int64(xreply, "result");
		xpc_release(xreply);
		return result;
	}
	return -1;
}
