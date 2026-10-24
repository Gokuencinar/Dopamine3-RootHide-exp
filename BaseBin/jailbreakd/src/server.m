#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <errno.h>
#include <libproc.h>

#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/roothider.h>
#include <libjailbreak/roothide_bootlog.h>

void jailbreakd_reply_message(JBD_MESSAGE_ID msgId, xpc_object_t reply)
{
	char* desc = NULL;
	JBLogDebug("reply message %d with %s", msgId, (desc=xpc_copy_description(reply)));
	if(desc) free(desc);
	int err = xpc_pipe_routine_reply(reply);
	if (err != 0) {
		JBLogError("Error %d sending response", err);
	}
}

void jailbreakd_received_message(mach_port_t port)
{
	@autoreleasepool {
			xpc_object_t message = nil;
			int err = xpc_pipe_receive(port, &message);
			if (err != 0) {
				JBLogError("xpc_pipe_receive error %d", err);
				return;
			}

			if (!message || xpc_get_type(message) != XPC_TYPE_DICTIONARY) {
				// xpc_object_t is ARC-managed in this Objective-C target.
				return;
			}

			xpc_object_t reply = xpc_dictionary_create_reply(message);
			if (!reply) {
				return;
			}

		JBD_MESSAGE_ID msgId = xpc_dictionary_get_uint64(message, "id");

		if (xpc_get_type(message) == XPC_TYPE_DICTIONARY) {
			audit_token_t auditToken = {0};
			xpc_dictionary_get_audit_token(message, &auditToken);
			uid_t clientUid = audit_token_to_euid(auditToken);
			pid_t clientPid = audit_token_to_pid(auditToken);

			char* desc = NULL;
			JBLogDebug("received message %d from %d(%s) with dictionary: %s", msgId, clientPid, proc_get_path(clientPid,NULL), (desc=xpc_copy_description(message)));
			if(desc) free(desc);

			switch (msgId) {
				case JBD_MSG_SPINLOCK_FIX_ONLY: {
					int64_t result = 0;
					pid_t pid = xpc_dictionary_get_int64(message, "pid");
					bool resume = xpc_dictionary_get_bool(message, "resume");
					pid_t ppid = proc_get_ppid(pid);
					JBLogDebug("spinlock fix: client pid=%d, child pid=%d, child's parent pid=%d, child proc=%s", clientPid, pid, ppid, proc_get_path(pid,NULL));
					if(ppid == clientPid) {
						if(ppid==1 && resume==false) {
							//`frida -f` sucks with proc_fix_spinlock on ios15
							result = proc_patch_csflags(pid);
						}
						else if(proc_fix_spinlock(pid) == 0) {
								if(resume) kill(pid, SIGCONT);
						} else {
							JBLogError("spinlock fix failed: %d", pid);
							result = -1;
						}
					} else {
						JBLogError("spinlock fix denied: %d", pid);
						result = -1;
					}
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_PATCH_CHILD: {
					int64_t result = 0;
					pid_t pid = xpc_dictionary_get_int64(message, "pid");
					bool resume = xpc_dictionary_get_bool(message, "resume");
					pid_t ppid = proc_get_ppid(pid);
					const char *childPath = proc_get_path(pid, NULL);
						// Identified PID1 jobs are patched but never resumed by this
						// daemon. A timeout can win while XPC is blocked; only the
						// PID1 worker knows whether its deadline is still valid.
						bool deferredResume = xpc_dictionary_get_bool(message, "deferred_resume");
						// A queued launchd request may arrive after a timeout or the
						// child has exited. PID alone can then belong to another child.
						// Require the original kernel uniqueid for every PID1 request.
						uint64_t expectedUniqueid = xpc_dictionary_get_uint64(message, "uniqueid");
						bool sameChild = clientPid != 1 ||
							(expectedUniqueid && proc_get_uniqueid(pid) == expectedUniqueid);
					bool probeChild = childPath &&
						string_has_suffix(childPath, "/basebin/rh3tweakprobe");
					JBLogDebug("spawn patch: client pid=%d, child pid=%d, child's parent pid=%d, child proc=%s", clientPid, pid, ppid, proc_get_path(pid,NULL));
						if(ppid == clientPid && sameChild && (!deferredResume || (clientPid == 1 && expectedUniqueid && !resume))) {
						if(ppid==1 && resume==false && !deferredResume) {
							//`frida -f` sucks with proc_patch_dyld on ios15
							result = proc_patch_csflags(pid);
						}
							else if(roothide_patch_proc(pid) == 0) {
									// Recheck immediately before signal, in case the child
									// terminated during patching. Never resume a recycled PID.
									if(clientPid == 1 && proc_get_uniqueid(pid) != expectedUniqueid) {
										result = -1;
										} else if(resume && !deferredResume && kill(pid, SIGCONT) != 0) {
									// The parent will kill/reap its OWN suspended child
									// when it receives this nonzero patch result.
									JBLogError("spawn patch: failed to resume child %d", pid);
									result = -1;
								}
						} else {
							JBLogError("spawn patch failed: %d", pid);
							result = -1;
						}
					} else {
						JBLogError("spawn patch denied: %d", pid);
						result = -1;
					}
					xpc_dictionary_set_int64(reply, "result", result);
					// A successful child patch may set only CS_GET_TASK_ALLOW;
					// it does not certify private dyld or constructor execution.
					// Record this distinction only for the disposable probe.
					if (probeChild) {
						char stage[176];
						snprintf(stage, sizeof(stage),
							"jailbreakd: tweakprobe patch result=%lld dyld_patch_flag=%d parent_is_pid1=%d resume=%d; not_constructor_proof",
							(long long)result, (int)dyld_patch_enabled(), (int)(ppid == 1), (int)resume);
						rh3_bootlog(stage);
					}
					break;
				}

				case JBD_MSG_SPAWN_EXEC_START: {
					bool resume = xpc_dictionary_get_bool(message, "resume");
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("spawn exec start: %d %s", clientPid, execfile);
					int64_t result = spawnExecPatchAdd(clientPid, resume);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SPAWN_EXEC_CANCEL: {
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("spawn exec cancel: %d %s", clientPid, execfile);
					int64_t result = spawnExecPatchDel(clientPid);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

					case JBD_MSG_EXEC_TRACE_START: {
						//dead lock: jbd->ptrace->kernel->amfi port->launchd->spawn amfid->jdb
							// ARC and dispatch block capture keep these XPC objects alive
							// until the asynchronous response has been sent.
							xpc_object_t asyncMessage = message;
							xpc_object_t asyncReply = reply;
							dispatch_async(dispatch_get_global_queue(0, 0), ^{
							int64_t result = -1;
							uint64_t traced = xpc_dictionary_get_uint64(asyncMessage, "traced");
							const char* execfile = xpc_dictionary_get_string(asyncMessage, "execfile");
							JBLogDebug("exec trace start: %d %s", clientPid, execfile);
							result = execTraceProcess(clientPid, traced);
								xpc_dictionary_set_int64(asyncReply, "result", result);
								jailbreakd_reply_message(msgId, asyncReply);
							});
							reply = nil; //reply later
					break;
				}

				case JBD_MSG_EXEC_TRACE_CANCEL: {
					int64_t result = -1;
					uint64_t detached = xpc_dictionary_get_uint64(message, "detached");
					const char* execfile = xpc_dictionary_get_string(message, "execfile");
					JBLogDebug("exec trace cancel: %d %s", clientPid, execfile);
					result = execTraceCancel(clientPid, detached);
					xpc_dictionary_set_int64(reply, "result", result);
					break;
				}

				case JBD_MSG_SYSTEMWIDE_LOG: {
#ifdef ENABLE_LOGS
					static char logFilePath[PATH_MAX] = {0};
					static dispatch_once_t onceToken;
					dispatch_once(&onceToken, ^{
						JBLogGetLogFilePath("systemwide", NULL, logFilePath);
					});

					const char* progname = NULL;
					const char* procpath = proc_get_path(clientPid,NULL);
					if(procpath) {
						progname = strrchr(procpath, '/');
						if(progname) progname++; else progname = procpath;
					}
					uint64_t tid = xpc_dictionary_get_uint64(message, "tid");
					const char* log = xpc_dictionary_get_string(message, "log");
					JBLogFunction(logFilePath, clientPid, tid, progname ? progname : "(null)", "%s", log);
					xpc_dictionary_set_int64(reply, "result", 0);
#else
						// Unsupported logging requests must not terminate jailbreakd.
						xpc_dictionary_set_int64(reply, "result", -ENOTSUP);
#endif
					break;
				}

				case JBD_MSG_TEST_CALL: {
					int value = xpc_dictionary_get_int64(message, "value");
					JBLogDebug("jailbreakd test call(%llu) from %d,%s", value, clientPid, proc_get_path(clientPid,NULL));
					xpc_dictionary_set_int64(reply, "result", value * 2);

						// Do not intentionally crash the production daemon in a test call.

					break;
				}
			}
		}
			if (reply) {
				jailbreakd_reply_message(msgId, reply);
			}
		}
}
