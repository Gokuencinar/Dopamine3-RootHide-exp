#ifndef RH3_TWEAK_TOGGLE_H
#define RH3_TWEAK_TOGGLE_H

// RootHide's primary bootstrap lives in Bundle/Application and needs
// CS_INSTALLER for writes. Its secondary AppGroup/var directory is writable
// without granting installer privileges to the relaunched application.
// This helper stores only an explicit, unapplied user request. No reader of
// this file may equate it with an effective tweak state or auto-clear safe mode.

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define RH3_TWEAK_REQUEST_NAME ".roothide3-tweak-toggle.pending"
#define RH3_TWEAK_WATCHDOG_LATCH_NAME ".roothide3-watchdog-safe-mode"
#define RH3_TWEAK_REQUEST_ENABLE "RH3_TWEAK_V1:E\n"
#define RH3_TWEAK_REQUEST_DISABLE "RH3_TWEAK_V1:D\n"

// The caller first verifies rootHideExistingRootWithError and jbclient's
// active root. Pin the secondary directory to that exact root via .jbroot,
// and refuse writable-by-others directories and redirected symlinks.
static inline int rh3_tweak_open_request_dir(const char *root, const char *secondary, int *dirOut)
{
    if (!root || !secondary || !dirOut) return EINVAL;
    *dirOut = -1;
    int primary = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (primary < 0) return errno;
    struct stat primaryInfo = {0};
    int error = fstat(primary, &primaryInfo) ? errno :
        (!S_ISDIR(primaryInfo.st_mode) || primaryInfo.st_uid != 0 ? EPERM : 0);
    if (error) { close(primary); return error; }

    int parent = open(secondary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (parent < 0) { error = errno; close(primary); return error; }
    struct stat parentInfo = {0}, linkInfo = {0}, targetInfo = {0};
    if (fstat(parent, &parentInfo)) error = errno;
    else if (!S_ISDIR(parentInfo.st_mode) || parentInfo.st_uid != 0 ||
             (parentInfo.st_mode & 0022)) error = EPERM;
    else if (fstatat(parent, ".jbroot", &linkInfo, AT_SYMLINK_NOFOLLOW)) error = errno;
    else if (!S_ISLNK(linkInfo.st_mode)) error = EPERM;
    else if (fstatat(parent, ".jbroot", &targetInfo, 0)) error = errno;
    else if (targetInfo.st_dev != primaryInfo.st_dev || targetInfo.st_ino != primaryInfo.st_ino)
        error = EPERM;
    close(primary);
    if (error) { close(parent); return error; }

    int directory = openat(parent, "var", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    error = directory < 0 ? errno : 0;
    close(parent);
    if (error) return error;
    struct stat varInfo = {0};
    if (fstat(directory, &varInfo)) error = errno;
    else if (!S_ISDIR(varInfo.st_mode) || varInfo.st_uid != 0 ||
             (varInfo.st_mode & 0022)) error = EPERM;
    if (error) { close(directory); return error; }
    *dirOut = directory;
    return 0;
}

static inline int rh3_tweak_request_verify(int directory, bool *exists)
{
    if (!exists) return EINVAL;
    struct stat info = {0};
    if (fstatat(directory, RH3_TWEAK_REQUEST_NAME, &info, AT_SYMLINK_NOFOLLOW)) {
        if (errno == ENOENT) { *exists = false; return 0; }
        return errno;
    }
    if (!S_ISREG(info.st_mode) || info.st_uid != 0 || info.st_nlink != 1 ||
        (info.st_mode & 0077) || info.st_size < 0 || info.st_size > 64) return EPERM;
    *exists = true;
    return 0;
}

// The watchdog can set this latch in AppGroup when the protected BaseBin
// denies its late attempt to create .safe_mode. A missing marker is only an
// enabled state when this independent latch is also absent. Unknown or
// unsafe latch state MUST be treated as disabled by every runtime consumer.
static inline int rh3_tweak_watchdog_latched(const char *root, const char *secondary, bool *latchedOut)
{
    if (!latchedOut) return EINVAL;
    *latchedOut = true;
    int directory = -1;
    int error = rh3_tweak_open_request_dir(root, secondary, &directory);
    if (error) return error;
    struct stat info = {0};
    if (fstatat(directory, RH3_TWEAK_WATCHDOG_LATCH_NAME, &info, AT_SYMLINK_NOFOLLOW)) {
        if (errno == ENOENT) { *latchedOut = false; error = 0; }
        else error = errno;
    }
    else if (!S_ISREG(info.st_mode) || info.st_uid != 0 || info.st_nlink != 1 ||
             (info.st_mode & 0077) || info.st_size != 0) error = EPERM;
    close(directory);
    return error;
}

// Only an explicitly approved installer-phase transition may remove a
// watchdog latch. Never call from pending replay or a failed preflight.
static inline int rh3_tweak_watchdog_clear(const char *root, const char *secondary)
{
    int directory = -1;
    int error = rh3_tweak_open_request_dir(root, secondary, &directory);
    if (error) return error;
    struct stat info = {0};
    if (fstatat(directory, RH3_TWEAK_WATCHDOG_LATCH_NAME, &info, AT_SYMLINK_NOFOLLOW)) {
        if (errno != ENOENT) error = errno;
    }
    else if (!S_ISREG(info.st_mode) || info.st_uid != 0 || info.st_nlink != 1 ||
             (info.st_mode & 0077) || info.st_size != 0) error = EPERM;
    else if (unlinkat(directory, RH3_TWEAK_WATCHDOG_LATCH_NAME, 0)) error = errno;
    else if (fsync(directory)) error = errno;
    close(directory);
    return error;
}

// Returns ENOENT when there is no request, EINVAL on corrupt content.
static inline int rh3_tweak_request_read(const char *root, const char *secondary, bool *enableOut)
{
    if (!enableOut) return EINVAL;
    int directory = -1;
    int error = rh3_tweak_open_request_dir(root, secondary, &directory);
    if (error) return error;
    bool exists = false;
    error = rh3_tweak_request_verify(directory, &exists);
    if (!error && !exists) error = ENOENT;
    if (!error) {
        int fd = openat(directory, RH3_TWEAK_REQUEST_NAME, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) error = errno;
        else {
            struct stat info = {0};
            char data[sizeof(RH3_TWEAK_REQUEST_DISABLE)] = {0};
            ssize_t length = read(fd, data, sizeof(data));
            if (fstat(fd, &info)) error = errno;
            else if (!S_ISREG(info.st_mode) || info.st_uid != 0 || info.st_nlink != 1 ||
                     (info.st_mode & 0077) || info.st_size != length) error = EPERM;
            else if (length == (ssize_t)strlen(RH3_TWEAK_REQUEST_ENABLE) &&
                     !memcmp(data, RH3_TWEAK_REQUEST_ENABLE, (size_t)length)) *enableOut = true;
            else if (length == (ssize_t)strlen(RH3_TWEAK_REQUEST_DISABLE) &&
                     !memcmp(data, RH3_TWEAK_REQUEST_DISABLE, (size_t)length)) *enableOut = false;
            else error = EINVAL;
            if (close(fd) && !error) error = errno;
        }
    }
    close(directory);
    return error;
}

static inline int rh3_tweak_request_cancel(const char *root, const char *secondary)
{
    int directory = -1;
    int error = rh3_tweak_open_request_dir(root, secondary, &directory);
    if (error) return error;
    // This is an explicit cancel from Settings or a successful installer
    // replay. unlinkat never follows a symlink at the *exact* pending name;
    // allow recovery of an invalid old request without touching its target.
    if (unlinkat(directory, RH3_TWEAK_REQUEST_NAME, 0)) {
        if (errno != ENOENT) error = errno;
    }
    else if (fsync(directory)) error = errno;
    close(directory);
    return error;
}

// Atomic, bounded and reversible; never modifies Bundle/Application. A
// successful stage is NOT successful activation and must return EINPROGRESS
// to the settings UI until an explicitly approved installer phase applies it.
static inline int rh3_tweak_request_stage(const char *root, const char *secondary, bool enable)
{
    int directory = -1;
    int error = rh3_tweak_open_request_dir(root, secondary, &directory);
    if (error) return error;
    // The directory is pinned to the verified root. An explicit new choice
    // may replace even a malformed previous *request* atomically: renameat
    // replaces the named leaf (including a symlink) without following it.
    // Readers still strictly reject malformed content and metadata.
    const char *value = enable ? RH3_TWEAK_REQUEST_ENABLE : RH3_TWEAK_REQUEST_DISABLE;
    char temp[96];
    int fd = -1;
    for (unsigned attempt = 0; attempt < 16; attempt++) {
        snprintf(temp, sizeof(temp), ".roothide3-tweak-pending-%ld-%u", (long)getpid(), attempt);
        fd = openat(directory, temp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0 || errno != EEXIST) break;
    }
    if (fd < 0) { error = errno; close(directory); return error; }
    size_t length = strlen(value);
    if (write(fd, value, length) != (ssize_t)length) error = errno ? errno : EIO;
    if (!error && fchmod(fd, 0600)) error = errno;
    if (!error && fsync(fd)) error = errno;
    if (close(fd) && !error) error = errno;
    if (!error && renameat(directory, temp, directory, RH3_TWEAK_REQUEST_NAME)) error = errno;
    if (!error && fsync(directory)) error = errno;
    if (error) (void)unlinkat(directory, temp, 0);
    close(directory);
    return error;
}

#endif
