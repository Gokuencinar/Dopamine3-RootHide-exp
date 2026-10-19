#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>

// A timeout leaves the non-idempotent child alone and the running marker intact.
static int RH3WaitForBootstrapChildStatus(pid_t pid, unsigned timeoutSeconds, int *rawStatus)
{
    if (rawStatus) *rawStatus = -1;
    if (pid <= 1) return -EINVAL;
    struct timespec start, now;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return -errno;
    for (;;) {
        int status = 0;
        pid_t result = waitpid(pid, &status, WNOHANG);
        if (result == pid) {
            if (rawStatus) *rawStatus = status;
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
        }
        if (result < 0 && errno != EINTR) return -errno;
        if (clock_gettime(CLOCK_MONOTONIC, &now)) return -errno;
        if (now.tv_sec - start.tv_sec > timeoutSeconds ||
            (now.tv_sec - start.tv_sec == timeoutSeconds && now.tv_nsec >= start.tv_nsec))
            return -ETIMEDOUT;
        struct timespec interval = {0, 100000000};
        nanosleep(&interval, NULL);
    }
}

static int RH3WaitForBootstrapChild(pid_t pid, unsigned timeoutSeconds)
{
    return RH3WaitForBootstrapChildStatus(pid, timeoutSeconds, NULL);
}
