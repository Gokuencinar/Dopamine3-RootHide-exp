//
// Created by Ylarod on 2024/3/15.
//

#ifndef EXEC_PATCH_H
#define EXEC_PATCH_H

#import <stdbool.h>
#include <stdlib.h>
#include <errno.h>

// A one-shot NOTE_EXEC/NOTE_EXIT event may consume its kernel registration
// before the caller cancels a failed SETEXEC. ENOENT then means there is no
// remaining watch to delete; callers must still clear their userland record.
// Do not hide other kevent failures (e.g. EBADF or EINVAL).
static inline bool rh3_exec_patch_watch_cancelled(int result, int error)
{
    return result == 0 || (result == -1 && error == ENOENT);
}

int spawnExecPatchAdd(int pid, bool resume);
int spawnExecPatchDel(int pid);

int execTraceProcess(pid_t pid, uint64_t traced);
int execTraceCancel(pid_t pid, uint64_t detached);

#endif //EXEC_PATCH_H
