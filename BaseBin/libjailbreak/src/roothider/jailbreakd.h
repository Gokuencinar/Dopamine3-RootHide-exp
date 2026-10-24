#ifndef JAILBREAKD_H
#define JAILBREAKD_H

#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <mach/mach.h>

typedef enum {
	JBD_MSG_TEST_CALL = 101,
	JBD_MSG_SYSTEMWIDE_LOG = 102,
	JBD_MSG_SPAWN_PATCH_CHILD = 1001,
	JBD_MSG_SPAWN_EXEC_START = 1002,
	JBD_MSG_SPAWN_EXEC_CANCEL = 1003,
	JBD_MSG_EXEC_TRACE_START = 1004,
	JBD_MSG_EXEC_TRACE_CANCEL = 1005,
	JBD_MSG_SPINLOCK_FIX_ONLY = 1006,
} JBD_MESSAGE_ID;

void enableJBDLog(void* debugLog, void* errorLog);

struct jbserver_impl;
int initJailbreakd(bool firstLoad, struct jbserver_impl *bootstrapServer);
bool jailbreakd_is_ready(void);
// "Spawned" is not the same as "checked in and able to receive XPC".
// Only expose the patch-child port to clients after authenticated checkin.
bool jailbreakd_has_checked_in(void);
void jailbreakd_mark_checked_in(pid_t pid);

void setJailbreakdProcess(pid_t pid);

mach_port_t jailbreakdClientPort();
mach_port_t jailbreakdServerPort();

int jbdTestCall(int value);
int jbdSystemwideLog(const char* fmt, ...);

int jbdSpawnPatchChild(int pid, bool resume);
// PID1 asynchronous patching: bind the request to the actual suspended
// process, not just its recyclable numeric PID. Never use the unbound API
// from PID1 for an asynchronous child.
int jbdSpawnPatchChildIdentified(int pid, uint64_t uniqueid, bool resume);
int jbdSpawnExecStart(const char* execfile, bool resume);
int jbdSpawnExecCancel(const char* execfile);
int jbdExecTraceStart(const char* execfile, bool* traced);
int jbdExecTraceCancel(const char* execfile, bool* detached);
int jbdSpinlockFixOnly(int pid, bool resume);

#endif // JAILBREAKD_H
