#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "RootHideAppOwnerPolicy.h"

// The caller validates the active RootHide container before opening it. Walk
// only real directories inside Applications; never follow links into another
// container. Relative backlinks survive the normal jbrand rename.
static int RH3AppBacklink(int directory, unsigned depth, uid_t owner)
{
    char target[80] = "";
    for (unsigned i = 0; i < depth; i++) strlcat(target, i ? "/.." : "..", sizeof(target));
    struct stat st;
    if (fstatat(directory, ".jbroot", &st, AT_SYMLINK_NOFOLLOW) == 0) {
        if (!S_ISLNK(st.st_mode) || st.st_uid != owner) return EPERM;
        char existing[PATH_MAX];
        ssize_t n = readlinkat(directory, ".jbroot", existing, sizeof(existing) - 1);
        if (n < 0) return errno;
        existing[n] = 0;
        if (!strcmp(existing, target)) return 0;
    } else if (errno != ENOENT) return errno;
    for (unsigned attempt = 0; attempt < 64; attempt++) {
        char temporary[80];
        snprintf(temporary, sizeof(temporary), ".jbroot.rh3-%ld-%u", (long)getpid(), attempt);
        if (symlinkat(target, directory, temporary) != 0) {
            if (errno == EEXIST) continue;
            return errno;
        }
        int result = renameat(directory, temporary, directory, ".jbroot") == 0 ? 0 : errno;
        if (result) unlinkat(directory, temporary, 0);
        return result;
    }
    return EEXIST;
}

static int RH3AppLinksWalk(int fd, unsigned depth, uid_t owner, unsigned *visited,
                           bool mobileBundle)
{
    if (depth > 16) return ELOOP;
    DIR *dir = fdopendir(dup(fd));
    if (!dir) return errno;
    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(dir))) {
        if (entry->d_name[0] == '.') continue;
        if (++*visited > 10000) { result = E2BIG; break; }
        struct stat st;
        if (fstatat(fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW)) { result = errno; break; }
        if (S_ISLNK(st.st_mode)) continue;
        if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode)) continue;
        bool childMobileBundle = mobileBundle ||
            (depth == 1 && rh3_bundle_mobile_owner_allowed(entry->d_name));
        bool accepted = depth == 1 && S_ISDIR(st.st_mode)
            ? rh3_bundle_owner_allowed(entry->d_name, st.st_uid, owner)
            : rh3_app_descendant_owner_allowed(mobileBundle, st.st_uid, owner);
        if (!accepted || (S_ISDIR(st.st_mode) && (st.st_mode & 0022))) {
            result = EPERM;
            break;
        }
        int child = openat(fd, entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC |
                           (S_ISDIR(st.st_mode) ? O_DIRECTORY : 0));
        if (child < 0) { result = errno; break; }
        struct stat opened;
        if (fstat(child, &opened) || opened.st_ino != st.st_ino || opened.st_dev != st.st_dev ||
            opened.st_uid != st.st_uid || (S_ISDIR(st.st_mode) && (opened.st_mode & 0022))) result = ESTALE;
        else if (S_ISDIR(st.st_mode)) result = RH3AppLinksWalk(child, depth + 1, owner, visited, childMobileBundle);
        else {
            uint32_t magic = 0;
            if (pread(child, &magic, sizeof(magic), 0) == sizeof(magic) &&
                (magic == 0xfeedfacf || magic == 0xcffaedfe || magic == 0xcafebabe || magic == 0xbebafeca ||
                 magic == 0xcafebabf || magic == 0xbfbafeca)) result = RH3AppBacklink(fd, depth, owner);
        }
        close(child);
        if (result) break;
    }
    closedir(dir);
    return result;
}

static int RH3RepairAppLinks(int rootFD, uid_t owner)
{
    struct stat st;
    if (fstat(rootFD, &st)) return errno;
    if (!S_ISDIR(st.st_mode) || st.st_uid != owner) return EPERM;
    int apps = openat(rootFD, "Applications", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (apps < 0) return errno;
    if (fstat(apps, &st) || !S_ISDIR(st.st_mode) ||
        !rh3_apps_directory_owner_allowed(st.st_uid, owner, st.st_mode)) { close(apps); return EPERM; }
    unsigned visited = 0;
    int result = RH3AppLinksWalk(apps, 1, owner, &visited, false);
    close(apps);
    return result;
}
