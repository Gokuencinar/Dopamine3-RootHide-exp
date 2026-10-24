#include <spawn.h>
#include <unistd.h>
#include <assert.h>
#include <pthread.h>
#include <stdatomic.h>
#include <xpc/xpc.h>
#include <mach/mach.h>
#include <bsm/libbsm.h>
#include <sys/param.h>

#include "../libjailbreak.h"
#include "jailbreakd.h"
#include "jailbreakd_bootstrap.h"
#include "../roothide_bootlog.h"
#include "common.h"
#include "log.h"

#ifdef ENABLE_LOGS
static void (*JBDLogDebugFunction)(const char *format, ...);
static void (*JBDLogErrorFunction)(const char *format, ...);

#define JBLogDebug(...) do { if(JBDLogDebugFunction)JBDLogDebugFunction(__VA_ARGS__); } while(0)
#define JBLogError(...) do { if(JBDLogErrorFunction)JBDLogErrorFunction(__VA_ARGS__); } while(0)

void enableJBDLog(void* debugLog, void* errorLog)
{
	JBDLogDebugFunction = debugLog;
	JBDLogErrorFunction = errorLog;
}
#endif

int posix_spawnattr_setspecialport_np(posix_spawnattr_t *attr, mach_port_t new_port, int which);
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

static bool __firstLoad = false;
static bool __jailbreakd_initialized = false;
static _Atomic(pid_t) __jailbreakd_checked_in_pid = 0;
static struct jbserver_impl *gJailbreakdBootstrapServer = NULL;
mach_port_t gJailbreakdPort = MACH_PORT_NULL;

bool jailbreakd_is_ready(void)
{
	return getpid() == 1 && __jailbreakd_initialized && MACH_PORT_VALID(gJailbreakdPort);
}

bool jailbreakd_has_checked_in(void)
{
	return jailbreakd_is_ready() && __jailbreakd_checked_in_pid > 1;
}

void jailbreakd_mark_checked_in(pid_t pid)
{
	if (getpid() == 1 && __jailbreakd_initialized && pid > 1)
		__jailbreakd_checked_in_pid = pid;
}

int registerServerPort()
{
	assert(getpid() == 1);
	// The new receive right cannot be used until the new daemon actually
	// checks in. Old checkins belong to a different generation.
	__jailbreakd_checked_in_pid = 0;

	// Remove both the send and receive rights when replacing the old port.
	if(MACH_PORT_VALID(gJailbreakdPort)) {
		mach_port_destroy(mach_task_self(), gJailbreakdPort);
		gJailbreakdPort = MACH_PORT_NULL;
	}

	if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &gJailbreakdPort) != KERN_SUCCESS)
		return -1;
	if (mach_port_insert_right(mach_task_self(), gJailbreakdPort, gJailbreakdPort, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
		mach_port_destroy(mach_task_self(), gJailbreakdPort);
		gJailbreakdPort = MACH_PORT_NULL;
		return -1;
	}

	JBLogDebug("jailbreakd server port: %x", gJailbreakdPort);

	// Do not expose a send right through HOST_LAUNCHCTL_PORT yet. The
	// receive right still lives in PID 1 until the daemon authenticates and
	// extracts it. A valid fast-port right is not proof of a live receiver;
	// clients must use the guarded launchd domain lookup instead.
	return 0;
}

void setJailbreakdProcess(pid_t pid)
{
	// Never block launchd's XPC reply path waiting for an older daemon.
	// It might still be alive after a userspace re-exec. In that case leave
	// the process alone; the new daemon owns the new receive right.
	const char *pidenv = getenv("JAILBREAKD_PID");
	if (pidenv)
	{
		pid_t oldpid = atoi(pidenv);
		if(oldpid > 1 && oldpid != pid)
		{
			(void)waitpid(oldpid, NULL, WNOHANG);
		}
	}

	char buf[32];
	snprintf(buf, sizeof(buf), "%d", pid);
	setenv("JAILBREAKD_PID", buf, 1);
}

int spawnJailbreakd()
{
	assert(getpid() == 1);

	static mach_port_t bootstraport = MACH_PORT_NULL;

    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &bootstraport);
		mach_port_insert_right(mach_task_self(), bootstraport, bootstraport, MACH_MSG_TYPE_MAKE_SEND);
		JBLogDebug("jailbreakd bootstrap port: %x", bootstraport);

		static dispatch_source_t source; //retain the dispatch source
		source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)bootstraport, 0, dispatch_get_global_queue(0,0));
		dispatch_source_set_event_handler(source, ^{
			JBLogDebug("received message from jailbreakd");
			xpc_object_t xdict = NULL;
			int err = xpc_pipe_receive(bootstraport, &xdict);
			if(err == 0) {
				// This private port is consumed by xpc_pipe_receive, whereas the
				// launchd hook intercepts xpc_receive_mach_msg. Dispatch requests
				// here just as jbserver_local_loop does, including authentication.
				int status = RH3DispatchBootstrapMessage(gJailbreakdBootstrapServer, xdict);
				if (status != 0) JBLogError("jailbreakd bootstrap request rejected: %d", status);
				xpc_release(xdict);
			}
		});
		dispatch_resume(source);
	});

	pid_t pid;
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	// posix_spawnattr_setspecialport_np(&attr, bootstraport, TASK_BOOTSTRAP_PORT);
	// posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ bootstraport, MACH_PORT_NULL }, 3);
	posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, bootstraport }, 3);
	// The regular RootHide boot log belongs to the app and has a verified
	// inode/device pair. Pass only those three diagnostics to the dedicated
	// daemon, never launchd's entire environment or unrelated credentials.
	const char *path=getenv("RH3_BOOT_LOG_PATH");
	const char *dev=getenv("RH3_BOOT_LOG_DEV");
	const char *ino=getenv("RH3_BOOT_LOG_INO");
	char logPath[PATH_MAX+24], logDev[96], logIno[96];
	char *daemonEnv[5] = {NULL,NULL,NULL,NULL,NULL};
	size_t index = 0;
	if (!__firstLoad) daemonEnv[index++] = "RESPAWN_REQUIRED=1";
	if (path && dev && ino &&
	    snprintf(logPath,sizeof(logPath),"RH3_BOOT_LOG_PATH=%s",path) < (int)sizeof(logPath) &&
	    snprintf(logDev,sizeof(logDev),"RH3_BOOT_LOG_DEV=%s",dev) < (int)sizeof(logDev) &&
	    snprintf(logIno,sizeof(logIno),"RH3_BOOT_LOG_INO=%s",ino) < (int)sizeof(logIno)) {
		daemonEnv[index++] = logPath;
		daemonEnv[index++] = logDev;
		daemonEnv[index++] = logIno;
	}
	rh3_bootlog(__firstLoad ? "RootHide daemon spawn: first load" : "RootHide daemon spawn: userspace reboot respawn required");
	int ret = posix_spawn(&pid, JBROOT_PATH("/basebin/jailbreakd"), NULL, &attr,
	    (char*[]){"jailbreakd",NULL}, index ? daemonEnv : NULL);
	posix_spawnattr_destroy(&attr);

	if (ret != 0) {
		rh3_bootlog("RootHide daemon spawn failed");
		JBLogError("posix_spawn jailbreakd failed: %d\n", ret);
		return ret;
	}
	rh3_bootlog("RootHide daemon spawn returned successfully");

	JBLogDebug("jailbreakd spawned, pid=%d\n", pid);

	/* here we can't wait for jailbreakd to initialize since opainject will suspend all other threads */

	setJailbreakdProcess(pid);

	return 0;
}

int initJailbreakd(bool firstLoad, struct jbserver_impl *bootstrapServer)
{
	assert(getpid() == 1);

	assert(__jailbreakd_initialized == false);
	if (!bootstrapServer) return -1;
	gJailbreakdBootstrapServer = bootstrapServer;

	__firstLoad = firstLoad;

	if(registerServerPort() != 0) {
		JBLogError("registerServerPort failed");
		return -1;
	}

	// A missing optional daemon must not leave RootHide IPC advertising a
	// working port: client lookup would otherwise crash launchd on retry.
	__jailbreakd_initialized = true;
	int result = spawnJailbreakd();
	if (result != 0) __jailbreakd_initialized = false;
	return result;
}

mach_port_t reactiveJailbreakdPort()
{
/* restarting jailbreakd may cause it to lose its previous internal state,
	so we only use it during development. */
#ifndef ENABLE_LOGS
	// A dead jailbreakd port is recoverable by reporting an unavailable
	// service. Aborting here kills launchd and triggers an initproc panic.
	JBLogError("jailbreakd port lost; returning unavailable instead of aborting launchd");
	return MACH_PORT_NULL;
#endif

	assert(getpid() == 1);

	//prevent jailbreakdClientPort from calling before initJailbreakd
	assert(__jailbreakd_initialized);

	mach_port_t port = MACH_PORT_NULL;

	static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	pthread_mutex_lock(&mutex);

	// lock and check if another thread has reactivated the port

	kern_return_t kr = mach_port_mod_refs(mach_task_self(), gJailbreakdPort, MACH_PORT_RIGHT_SEND, 1);
	if(kr == KERN_SUCCESS) {
		port = gJailbreakdPort;
	}
	else
	{
		//make jailbreakd crashes perceptible
		sleep(5);

		//register server port before spawn jailbreakd
		if(registerServerPort() == 0)
		{
			//acquire the send right first
			kr = mach_port_mod_refs(mach_task_self(), gJailbreakdPort, MACH_PORT_RIGHT_SEND, 1);
			if(kr == KERN_SUCCESS)
			{
				port = gJailbreakdPort;

				// Try to restart jailbreakd
				if(spawnJailbreakd() != 0) {
					JBLogError("loadJailbreakd failed");
				}
			}
			else
			{
				JBLogError("jailbreakdClientPort failed");
			}
		}
		else
		{
			JBLogError("registerServerPort failed");
		}
	}

	pthread_mutex_unlock(&mutex);

	return port;
}

mach_port_t jailbreakdServerPort()
{
	assert(getpid() == 1);
	return jailbreakd_is_ready() ? gJailbreakdPort : MACH_PORT_NULL;
}

mach_port_t jailbreakdClientPort()
{
	mach_port_t port = MACH_PORT_NULL;

	if(getpid() == 1)
	{
		// A created receive port is not enough: return only after the daemon's
		// authenticated check-in. Never initiate a self-referential XPC lookup.
		if (!jailbreakd_has_checked_in()) return MACH_PORT_NULL;
		kern_return_t kr = mach_port_mod_refs(mach_task_self(), gJailbreakdPort, MACH_PORT_RIGHT_SEND, 1);
		if(kr == KERN_SUCCESS) {
			port = gJailbreakdPort;
		} else {
			JBLogError("jailbreakd port dead: %x,%s port=%x", kr, mach_error_string(kr), gJailbreakdPort);
			port = reactiveJailbreakdPort();
		}
	}
	else
	{
		// The RootHide launchd domain refuses lookup until jailbreakd has
		// checked in. Do not bypass its authentication/liveness gate with the
		// kernel host special-port cache.
		port = jbclient_jailbreakd_lookup();
	}

	return port;
}

// xpc_object_t jailbreakdRequestViaLaunchd(xpc_object_t xdict)
// {
// 	// to do
// }

xpc_object_t jailbreakdXpcRequest(xpc_object_t xdict)
{
	mach_port_t port = jailbreakdClientPort();
	if (!MACH_PORT_VALID(port)) {
		JBLogError("invalid jailbreakdClientPort: %x", port);
		return NULL;
	}

	xpc_object_t xreply = NULL;
	xpc_object_t pipe = xpc_pipe_create_from_port(port, 0);
	if (pipe) {
		int err = xpc_pipe_routine(pipe, xdict, &xreply);
		if (err != 0) {
			char *desc = NULL;
			JBLogError("xpc_pipe_routine error on sending message to jailbreakd: %d / %s\n%s", err, xpc_strerror(err), (desc=xpc_copy_description(xdict)));
			if(desc) free(desc);
			if(xreply) xpc_release(xreply);
			xreply = NULL;
		};
	} else {
		JBLogError("xpc_pipe_create_from_port failed");
	}

	mach_port_deallocate(mach_task_self(), port);

	if (pipe) xpc_release(pipe);
	return xreply;
}

int jbdTestCall(int value)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_TEST_CALL);
	xpc_dictionary_set_int64(message, "value", value);

	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}

int jbdSystemwideLog(const char* fmt, ...)
{
	char* log = NULL;

	va_list args;
	va_start(args, fmt);
	vasprintf(&log, fmt, args);
	va_end(args);

	__uint64_t tid = 0;
	pthread_threadid_np(pthread_self(), &tid);

	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SYSTEMWIDE_LOG);
	xpc_dictionary_set_uint64(message, "tid", tid);
	xpc_dictionary_set_string(message, "log", log);

	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	free(log);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}

int jbdSpawnPatchChild(int pid, bool resume)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPAWN_PATCH_CHILD);
	xpc_dictionary_set_int64(message, "pid", pid);
	xpc_dictionary_set_bool(message, "resume", resume);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

int jbdSpawnPatchChildIdentified(int pid, uint64_t uniqueid, bool resume)
{
	if (getpid() != 1 || pid <= 1 || !uniqueid || !jailbreakd_has_checked_in()) return -1;
	xpc_object_t message = xpc_dictionary_create_empty();
	if (!message) return -1;
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPAWN_PATCH_CHILD);
	xpc_dictionary_set_int64(message, "pid", pid);
	xpc_dictionary_set_uint64(message, "uniqueid", uniqueid);
	xpc_dictionary_set_bool(message, "resume", resume);
	// Uses the *direct* daemon port. This function can block, so it must
	// exclusively run on a background launchd worker, never in its spawn hook.
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	if (!reply) return -1;
	xpc_object_t value = xpc_dictionary_get_value(reply, "result");
	int result = value && xpc_get_type(value) == XPC_TYPE_INT64
		? (int)xpc_int64_get_value(value) : -1;
	xpc_release(reply);
	return result;
}

int jbdSpinlockFixOnly(int pid, bool resume)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPINLOCK_FIX_ONLY);
	xpc_dictionary_set_int64(message, "pid", pid);
	xpc_dictionary_set_bool(message, "resume", resume);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

int jbdSpawnExecStart(const char* execfile, bool resume)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPAWN_EXEC_START);
	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_dictionary_set_bool(message, "resume", resume);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

int jbdSpawnExecCancel(const char* execfile)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_SPAWN_EXEC_CANCEL);
	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);
	int64_t result = -1;
	if (reply) {
		result  = xpc_dictionary_get_int64(reply, "result");
		xpc_release(reply);
	}
	return result;
}

int jbdExecTraceStart(const char* execfile, bool* traced)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_EXEC_TRACE_START);

	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_dictionary_set_uint64(message, "traced", (uint64_t)(void*)traced);

	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}

int jbdExecTraceCancel(const char* execfile, bool* detached)
{
	xpc_object_t message = xpc_dictionary_create_empty();
	xpc_dictionary_set_uint64(message, "id", JBD_MSG_EXEC_TRACE_CANCEL);

	xpc_dictionary_set_string(message, "execfile", execfile);
	xpc_dictionary_set_uint64(message, "detached", (uint64_t)(void*)detached);
	xpc_object_t reply = jailbreakdXpcRequest(message);
	xpc_release(message);

	if (!reply) return -100;

	int result = xpc_dictionary_get_int64(reply, "result");
	xpc_release(reply);
	return result;
}
