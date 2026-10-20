#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

// Work from the verified secondary container, never through its var symlink
// in the primary root or through mobile/Containers (which points to iOS).
static int RH3MobileDirectory(int parent, const char *name, uid_t owner, uid_t mobile, gid_t group)
{
    if (mkdirat(parent, name, 0755) && errno != EEXIST) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || (st.st_uid != owner && st.st_uid != mobile)) {
        close(fd); errno = EPERM; return -1;
    }
    if ((st.st_uid != mobile || st.st_gid != group) && fchown(fd, mobile, group)) {
        int error = errno; close(fd); errno = error; return -1;
    }
    // Give the owner directory access without widening existing group/world
    // permissions. Never recurse into files, databases or unrelated folders.
    mode_t mode = (st.st_mode & 0777) | 0700;
    if (fchmod(fd, mode)) { int error = errno; close(fd); errno = error; return -1; }
    return fd;
}

static int RH3PrepareMobileHome(int secondary, uid_t owner, uid_t mobile, gid_t group)
{
    struct stat st;
    if (fstat(secondary, &st) || !S_ISDIR(st.st_mode) || st.st_uid != owner) return EPERM;
    int var = openat(secondary, "var", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (var < 0) return errno;
    if (fstat(var, &st) || st.st_uid != owner) { close(var); return EPERM; }
    int home = RH3MobileDirectory(var, "mobile", owner, mobile, group);
    int error = home < 0 ? errno : 0;
    close(var);
    if (error) return error;
    int library = RH3MobileDirectory(home, "Library", owner, mobile, group);
    error = library < 0 ? errno : 0;
    close(home);
    if (error) return error;
    const char *names[] = {"Caches", "Preferences", "Application Support"};
    for (unsigned i = 0; i < sizeof(names)/sizeof(names[0]); i++) {
        int fd = RH3MobileDirectory(library, names[i], owner, mobile, group);
        if (fd < 0) { error = errno; break; }
        close(fd);
    }
    close(library);
    return error;
}
