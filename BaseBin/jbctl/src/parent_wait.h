#ifndef JBCTL_PARENT_WAIT_H
#define JBCTL_PARENT_WAIT_H
#include <errno.h>
#include <unistd.h>
// EOF or a failed parent cleanup must never release a privileged command.
static int jbctl_wait_for_parent(int fd)
{
    char token = 0;
    ssize_t count;
    do { count = read(fd, &token, 1); } while (count < 0 && errno == EINTR);
    int result = count == 1 && token == 'w' ? 0 : (count < 0 ? errno : EIO);
    close(fd);
    return result;
}
#endif
