#ifndef RH3_TRUST_SPAWN_POLICY_H
#define RH3_TRUST_SPAWN_POLICY_H

#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif
#ifndef O_NONBLOCK
#define O_NONBLOCK 0
#endif

// Recognize exactly the *active* hidden root, not another randomized root or
// a lookalike prefix. /var and /private/var are aliases on supported iOS.
// The caller separately validates that activeRoot is a genuine branded root.
static inline const char *rh3_trust_skip_private_alias(const char *path)
{
    return path && !strncmp(path, "/private/var/", 13) ? path + 8 : path;
}

static inline bool rh3_trust_is_active_root_child(const char *path, const char *activeRoot)
{
    if (!path || !activeRoot) return false;
    path = rh3_trust_skip_private_alias(path);
    activeRoot = rh3_trust_skip_private_alias(activeRoot);
    size_t length = strlen(activeRoot);
    // Do not dereference path[length] until the string is proven long enough.
    return length && strlen(path) > length &&
           !memcmp(path, activeRoot, length) && path[length] == '/';
}

// For active-root binaries an absent or failed trust decision must be visible
// to posix_spawn/exec rather than silently attempting to run an untrusted
// executable. Leave stock and unrelated paths on their previous code path.
// Shell scripts are also spawnable from the hidden root, but the recursive
// Mach-O trust client cannot parse their shebangs. Only fail closed on a real
// Mach-O or FAT magic after trust returned an error; leave scripts and other
// formats to the kernel's own exec validation.
static inline bool rh3_trust_looks_like_macho(const char *path)
{
    if (!path) return false;
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat info = {0};
    uint32_t magic = 0;
    bool valid = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
                 read(fd, &magic, sizeof(magic)) == sizeof(magic);
    close(fd);
    if (!valid) return false;
    return magic == 0xfeedface || magic == 0xcefaedfe ||
           magic == 0xfeedfacf || magic == 0xcffaedfe ||
           magic == 0xcafebabe || magic == 0xbebafeca ||
           magic == 0xcafebabf || magic == 0xbfbafeca;
}

static inline int rh3_trust_spawn_status(int trustResult, bool activeRootChild, bool isMachO)
{
    if (!activeRootChild || trustResult == 0 || !isMachO) return 0;
    // The client returns -2 for *any* failed access(F_OK), including
    // EACCES/ELOOP. Do not claim ENOENT without a preserved errno contract.
    return EACCES;
}

#endif
