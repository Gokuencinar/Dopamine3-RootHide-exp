#ifndef RH3_LAUNCHD_HANDOFF_H
#define RH3_LAUNCHD_HANDOFF_H
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>

int proc_paused(pid_t pid, bool *paused);

// RootHide's self-exec starts PID 1 suspended. Never patch the old, running
// image or resume a new image whose dyld preparation failed.
static int rh3_prepare_reexecuted_launchd(void)
{
    rh3_bootlog("boomerang: waiting for suspended launchd");
    for (unsigned attempt = 0; attempt < 1000; attempt++) {
        bool paused = false;
        if (proc_paused(1, &paused) != 0) return ESRCH;
        if (!paused) { usleep(10000); continue; }
        // Match the donor's delay for task IPC and code-signing initialization.
        usleep(100000);
        rh3_bootlog("boomerang: preparing suspended launchd");
        int result = roothide_patch_proc(1);
        if (result != 0) return result;
        rh3_bootlog("boomerang: launchd prepared; resuming");
        if (kill(1, SIGCONT) != 0) return errno;
        rh3_bootlog("boomerang: launchd resumed");
        return 0;
    }
    return ETIMEDOUT;
}
#endif
