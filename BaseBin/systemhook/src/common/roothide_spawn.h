#ifndef RH3_SPAWN_LIFECYCLE_H
#define RH3_SPAWN_LIFECYCLE_H
#include <spawn.h>
#include <stdbool.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>

// RootHide needs the child patched before its first userspace instruction.
// Keep this policy independent of Mach/XPC so failure ordering can be tested.
static int rh3_spawn_patched(pid_t *pidOut, posix_spawnattr_t *attributes, bool driver,
                            int (^spawn)(pid_t *), int (*patch)(pid_t, bool),
                            int (^execStart)(bool), int (^execCancel)(void))
{
    if (driver) return spawn(pidOut);
    short flags = 0;
    int error = posix_spawnattr_getflags(attributes, &flags);
    if (error) return error;
    bool setexec = (flags & POSIX_SPAWN_SETEXEC) != 0;
    bool resume = (flags & POSIX_SPAWN_START_SUSPENDED) == 0;
    error = posix_spawnattr_setflags(attributes, flags | POSIX_SPAWN_START_SUSPENDED);
    if (error) return error;
    if (setexec && execStart(resume) != 0) {
        posix_spawnattr_setflags(attributes, flags);
        return EIO;
    }
    // Keep the caller's PID pointer all the way to the kernel, as fixed in
    // RootHide upstream 4c781be. A private temporary is only for NULL callers.
    pid_t temporary = 0;
    pid_t *slot = pidOut ? pidOut : &temporary;
    int result = spawn(slot);
    pid_t child = result == 0 ? *slot : 0;
    int restored = posix_spawnattr_setflags(attributes, flags);
    // Successful SETEXEC never returns. Cancel the watcher on failed exec.
    if (setexec) {
        int cancelled = execCancel();
        return restored || cancelled ? EIO : (result ? result : EIO);
    }
    if (result) return result;
    if (child <= 0) return EIO;
    if (restored || patch(child, resume) != 0) {
        // Only this newly created, still suspended child is ours to terminate.
        kill(child, SIGKILL);
        while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {}
        if (pidOut) *pidOut = 0;
        return EIO;
    }
    if (pidOut) *pidOut = child;
    return 0;
}
#endif
