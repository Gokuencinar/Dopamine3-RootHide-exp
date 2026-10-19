#include <libproc.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>

// RootHide uses the exact daemon target of the stock fallback without
// replacing jbctl with sbreload. Report failed or missing targets explicitly.
static int rh3_respring_backboardd(void)
{
    int count = proc_listallpids(NULL, 0);
    if (count <= 0) return ESRCH;
    if (count > 32768) return E2BIG;
    int capacity = count + 32;
    pid_t *pids = calloc(capacity, sizeof(pid_t));
    if (!pids) return ENOMEM;
    count = proc_listallpids(pids, capacity * sizeof(pid_t));
    if (count < 0 || count > capacity) { free(pids); return EIO; }
    int result = ESRCH;
    for (int i = 0; i < count; i++) {
        char path[PATH_MAX] = {0};
        if (pids[i] <= 1 || proc_pidpath(pids[i], path, sizeof(path)) <= 0 ||
            strcmp(path, "/usr/libexec/backboardd")) continue;
        result = kill(pids[i], SIGTERM) == 0 ? 0 : errno;
        break;
    }
    free(pids);
    return result;
}
