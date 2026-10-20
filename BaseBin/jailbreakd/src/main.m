#include <Foundation/Foundation.h>
#include <kern_memorystatus.h>
#include <mach-o/dyld.h>
#include <libproc.h>
#include <spawn.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/roothide_bootlog.h>

extern char **environ;

void jailbreakd_received_message(mach_port_t port);

int posix_spawnattr_setspecialport_np(posix_spawnattr_t *attr, mach_port_t new_port, int which);
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t * __restrict attr, mach_port_t portarray[], uint32_t count);

void setJetsamLimit(uint32_t sizeInMB, bool is_fatal_limit)
{
	uint32_t cmd = is_fatal_limit ? MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT : MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK;
	int rc = memorystatus_control(cmd, getpid(), sizeInMB, NULL, 0);
	if (rc < 0) { perror ("memorystatus_control"); exit(rc);}
}

void enableXPCLog(void* debugLog, void* errorLog);

int main(int argc, char* argv[])
{
	rh3_bootlog("jailbreakd: process entered main");
	// The RootHide 2 crash reporter is not linked into Dopamine 3 libjailbreak:
	// its pause/resume ABI conflicts with launchdhook's crash reporter. Keep
	// this process on the platform crash-report path until a separate daemon
	// reporter can be validated without the old panic/reboot behavior.

		setJetsamLimit(50, false);
	rh3_bootlog("jailbreakd: jetsam configured");

#ifdef ENABLE_LOGS
	enableXPCLog(JBLogDebugFunction, JBLogErrorFunction);
	enableJBDLog(JBLogDebugFunction, JBLogErrorFunction);
#endif

	JBLogDebug("Hello from jailbrakd! uid=%d pid=%d ppid=%d", getuid(), getpid(), getppid());

	@autoreleasepool {

		mach_port_t *registeredPorts=NULL;
		mach_msg_type_number_t registeredPortsCount = 0;
		rh3_bootlog("jailbreakd: retrieving bootstrap registered ports");
		kern_return_t kr = mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount);
		if(kr != KERN_SUCCESS || registeredPortsCount < 3) {
			rh3_bootlog("jailbreakd: registered bootstrap port lookup failed");
			JBLogError("mach_ports_lookup error: %d, %x, %s", registeredPortsCount, kr, mach_error_string(kr));
			return 1;
		}
		for(int i=0; i<registeredPortsCount; i++) {
			JBLogDebug("registeredPorts[%d]: %x", i, registeredPorts[i]);
		}

		mach_port_t bootstraport = registeredPorts[2];
		if(!MACH_PORT_VALID(bootstraport)) {
			rh3_bootlog("jailbreakd: registered bootstrap port invalid");
			JBLogError("invalid bootstraport");
			return 2;
		}
		JBLogDebug("bootstraport: %x", bootstraport);

		registeredPorts[2] = MACH_PORT_NULL;
		mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);

		JBLogDebug("start initializing jb primitives");
		jbclient_xpc_set_custom_port(bootstraport);
		rh3_bootlog("jailbreakd: initializing primitives");
		int ret = jbclient_initialize_primitives();
		rh3_bootlog(ret ? "jailbreakd: primitive initialization failed" : "jailbreakd: primitive initialization completed");
		JBLogDebug("jbclient_initialize_primitives ret: %d", ret);
		if(ret != 0) {
			JBLogError("Failed to initialize jailbreak primitives: %d", ret);
			return 3;
		}

		if(getenv("RESPAWN_REQUIRED"))
		{
			rh3_bootlog("jailbreakd: userspace reboot respawn branch entered");
			unsetenv("RESPAWN_REQUIRED");

			// RootHide's legacy dyld-injection path needs a suspended,
			// patched replacement. With dyld patch disabled, the existing
			// process already has working primitives and can check in itself.
			// Previously we patched (and then killed) a throwaway child
			// unconditionally, causing the entire daemon to exit when that
			// unnecessary patch failed after userspace reboot.
			if (!dyld_patch_enabled()) {
				rh3_bootlog("jailbreakd: dyld patch inactive; skip unnecessary replacement and check in");
			} else {
			char selfPath[PATH_MAX]={0};
			uint32_t selfPathSize = sizeof(selfPath);
			_NSGetExecutablePath(selfPath, &selfPathSize);

			pid_t pid = 0;
			posix_spawnattr_t attr = NULL;
			posix_spawnattr_init(&attr);
			posix_spawnattr_setflags(&attr, POSIX_SPAWN_START_SUSPENDED);
			// posix_spawnattr_setspecialport_np(&attr, bootstraport, TASK_BOOTSTRAP_PORT);
			// posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ bootstraport, MACH_PORT_NULL }, 3);
			posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, bootstraport }, 3);
			rh3_bootlog("jailbreakd: creating suspended replacement");
			int ret = posix_spawn(&pid, selfPath, NULL, &attr, argv, environ);
			rh3_bootlog(ret ? "jailbreakd: replacement spawn failed" : "jailbreakd: suspended replacement spawned");
			posix_spawnattr_destroy(&attr);

			if(ret != 0) {
				JBLogError("posix_spawn jailbreakd failed: %d, %s", ret, strerror(ret));
				return 4;
			}

			JBLogDebug("jailbreakd respawned: %d", pid);

			rh3_bootlog("jailbreakd: waiting for suspension and patching replacement");
			int patchResult = unrestrict(pid, proc_patch_dyld, false);
			char stage[112];
			snprintf(stage, sizeof(stage), "jailbreakd: replacement patch result=%d", patchResult);
			rh3_bootlog(stage);
			rh3_bootlog(patchResult ? "jailbreakd: replacement patch failed" : "jailbreakd: replacement patch completed");
			if(patchResult != 0) {
				// Only the direct child created above. A failed patch must
				// never leave a permanently suspended runnable daemon.
				(void)kill(pid, SIGKILL);
				(void)waitpid(pid, NULL, WNOHANG);
				JBLogError("Failed to unrestrict process %d", pid);
				return 5;
			}

			rh3_bootlog("jailbreakd: resuming patched replacement");
			if (kill(pid, SIGCONT) != 0) {
				rh3_bootlog("jailbreakd: replacement resume failed");
				(void)kill(pid, SIGKILL);
				(void)waitpid(pid, NULL, WNOHANG);
				return 5;
			}
			rh3_bootlog("jailbreakd: replacement resume signaled");
			return 0;
			}
		}

		rh3_bootlog("jailbreakd: authenticated checkin starting");
		JBLogDebug("check in jailbreakd port...");
		mach_port_t serverPort = jbclient_jailbreakd_checkin();
		if (!MACH_PORT_VALID(serverPort)) {
			rh3_bootlog("jailbreakd: authenticated checkin failed");
			JBLogError("Failed to check in server port");
			return 6;
		}

		JBLogDebug("starting jailbreakd server, port=%x", serverPort);
		rh3_bootlog("jailbreakd: authenticated checkin returned valid server port");

		dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, dispatch_get_main_queue());
		dispatch_source_set_event_handler(source, ^{
			jailbreakd_received_message(serverPort);
		});
		dispatch_resume(source);
		rh3_bootlog("jailbreakd: XPC receive source active");

		dispatch_main();
	}

	JBLogDebug("jailbreakd exit...");
	return 0;
}
