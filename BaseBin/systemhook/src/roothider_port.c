// RootHide userspace integration for Dopamine 3's existing systemhook.
// Keep the 3.x spawn/exec and hookd paths authoritative.
#include "common/common.h"
#include "common/roothide_trust_policy.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbroot.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <pwd.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// jbclient_roothide.c supplies the image-path resolver in both libjailbreak
// and systemhook. Do not duplicate that global symbol here.

static bool root_contains_executable(const char *root, const char *executable)
{
    if (!root || !executable) return false;
    char realRoot[PATH_MAX], realExe[PATH_MAX];
    if (!realpath(root, realRoot) || !realpath(executable, realExe)) return false;
    size_t length = strlen(realRoot);
    if (length == 0 || length >= PATH_MAX - 2) return false;
    // Keep the comparison at a directory boundary.
    return !strncmp(realExe, realRoot, length)
        && (realExe[length] == '/' || realExe[length] == '\0');
}

static void roothide_redirect_home(const char *root)
{
    const char *home = getenv("CFFIXED_USER_HOME");
    // Respect Apple's own app/extension container.
    if (!issetugid() && home && (!strncmp(home, "/private/var/mobile/Containers/Data/", 36)
              || !strncmp(home, "/var/mobile/Containers/Data/", 28))) return;

    // Non-container values belong to the parent. In particular, do not send
    // mobile apps to an inherited /var/root or prefix an already hidden home
    // a second time. Match RootHide's user-based home selection.
    struct passwd *pwd = getpwuid(geteuid());
    home = pwd && pwd->pw_dir ? pwd->pw_dir : "/var/empty";

    char redirected[PATH_MAX];
    size_t rootLen = strlen(root), homeLen = strlen(home);
    if (!rootLen || rootLen + homeLen >= sizeof(redirected)) return;
    memcpy(redirected, root, rootLen);
    memcpy(redirected + rootLen, home, homeLen + 1);
    setenv("CFFIXED_USER_HOME", redirected, 1);
}

static void roothide_call_pathhook(const char *root)
{
    // pathhook installs an in-process CoreFoundation hook. Only load the
    // package-owned dylib from this process's authenticated hidden root;
    // access(R_OK) alone would also accept a symlink to a foreign library.
    if (!root || !systemhook_is_roothide_root_path(root)) return;
    const char *path = JBROOT_PATH("/basebin/roothidehooks.dylib");
    if (!path || !rh3_trust_is_active_root_child(path, root)) return;
    struct stat st = {0};
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_nlink != 1 || st.st_size <= 0 || (st.st_mode & 0022)) return;
    char resolvedRoot[PATH_MAX] = {0}, resolvedHook[PATH_MAX] = {0};
    if (!realpath(root, resolvedRoot) || !realpath(path, resolvedHook) ||
        !rh3_trust_is_active_root_child(resolvedHook, resolvedRoot)) return;
    void *library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) return;
    void (*install)(void) = dlsym(library, "pathhook");
    if (install) install();
}

static void rh3_load_rooted_init(const char *root)
{
    // RootHide 2/3 initializes every checked-in process, not just executables
    // located within the hidden bootstrap. Without this, SpringBoard and
    // ordinary apps never initialize RootHide's per-process runtime.
    const char *init = JBROOT_PATH("/usr/lib/roothideinit.dylib");
    if (!init) return;
    struct stat st = {0};
    if (lstat(init, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_nlink != 1 || st.st_size <= 0 || (st.st_mode & 0022)) return;
    char resolvedRoot[PATH_MAX] = {0}, resolvedInit[PATH_MAX] = {0};
    if (!realpath(root, resolvedRoot) || !realpath(init, resolvedInit)) return;
    if (!rh3_trust_is_active_root_child(init, root) ||
        !rh3_trust_is_active_root_child(resolvedInit, resolvedRoot)) return;
    // Match the upstream loader visibility; never overwrite or re-sign the
    // bootstrap library, and leave stock Dopamine when it is absent.
    (void)dlopen(init, RTLD_NOW);
}

static void rh3_load_rooted_patch(const char *root)
{
    // RootHide's post-executable runtime is a separate phase from global
    // roothideinit. It is optional in the pinned bootstrap and may arrive
    // later through dpkg; never synthesize/install it in a running process.
    if (!root || !systemhook_is_roothide_root_path(root)) return;
    const char *patch = JBROOT_PATH("/usr/lib/roothidepatch.dylib");
    if (!patch || !rh3_trust_is_active_root_child(patch, root)) return;
    struct stat st = {0};
    if (lstat(patch, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != 0 ||
        st.st_nlink != 1 || st.st_size <= 0 || (st.st_mode & 0022)) return;
    char resolvedRoot[PATH_MAX] = {0}, resolvedPatch[PATH_MAX] = {0};
    if (!realpath(root, resolvedRoot) || !realpath(patch, resolvedPatch) ||
        !rh3_trust_is_active_root_child(resolvedPatch, resolvedRoot)) return;
    // Trust is mediated by the existing dyld hook when active. Do not add a
    // second synchronous trust XPC request to an executable's constructor:
    // unavailable launchd/jailbreakd services must not stall its startup.
    (void)dlopen(patch, RTLD_NOW); // Keep the package runtime loaded.
}

void roothide_prepare_checked_in_process(const char *root)
{
    // The systemhook constructor calls this only AFTER a successful dyld
    // check-in (or its authenticated process_checkin fallback). Do not issue a
    // second launchd XPC query here: during userspace reboot that server can
    // temporarily reject a redundant request and would otherwise silently
    // skip RootHide's global initializer in every affected process.
    // Require the actual authenticated root to retain stock Dopamine behavior
    // and avoid treating a lookalike/old randomized path as RootHide.
    if (!root || !systemhook_is_roothide_root_path(root)) return;

    // RootHide 2 runs roothideinit after authenticated check-in, NOT only if
    // _NSGetExecutablePath + realpath work. On a short-lived xpcproxy job or
    // a process with an inaccessible image path that latter lookup can fail,
    // yet this global initialization is still required for RootHide services.
    rh3_load_rooted_init(root);
}

void roothide_prepare_process(const char *root, const char *executable)
{
    if (!root || !systemhook_is_roothide_root_path(root) || !executable) return;

    // HOME/path redirection is narrower: only the hidden-root executables.
    // Never rewrite containers for ordinary UIKit apps or Apple daemons.
    if (root_contains_executable(root, executable)) {
        roothide_redirect_home(root);
        roothide_call_pathhook(root);
        rh3_load_rooted_patch(root);
    }

}

int roothide_trust_injected_libraries(char *const envp[])
{
    if (!envp) return 0;
    const char *root = get_jbroot();
    if (!systemhook_is_roothide_root_path(root)) return 0;
    char resolvedRoot[PATH_MAX] = {0};
    if (!realpath(root, resolvedRoot)) return 0;
    const char *inserts = NULL;
    for (size_t i = 0; envp[i]; ++i) {
        if (!strncmp(envp[i], "DYLD_INSERT_LIBRARIES=", sizeof("DYLD_INSERT_LIBRARIES=") - 1)) {
            inserts = envp[i] + sizeof("DYLD_INSERT_LIBRARIES=") - 1;
            break;
        }
    }
    if (!inserts || !*inserts) return 0;
    char *copy = strdup(inserts);
    if (!copy) return ENOMEM;
    char *save = NULL;
    for (char *entry = strtok_r(copy, ":", &save); entry; entry = strtok_r(NULL, ":", &save)) {
        if (entry[0] == '/' && strcmp(entry, HOOK_DYLIB_PATH) != 0) {
            // The parent's DYLD_INSERT_LIBRARIES is untrusted input. Trust
            // neither a stock-system path nor another root's insertion, even
            // when a symlink inside this root resolves outside of it.
            if (!rh3_trust_is_active_root_child(entry, root)) continue;
            char resolved[PATH_MAX] = {0};
            if (!realpath(entry, resolved) ||
                !rh3_trust_is_active_root_child(resolved, resolvedRoot)) continue;
            // Trusting a package-owned inserted dylib is part of child
            // preparation. An unsuccessful trust operation on a real Mach-O
            // must abort spawn before dyld fails with an opaque EBADEXEC.
            // Never elevate or trust an insertion outside the active root.
            int result = jbclient_trust_library_recurse(entry, NULL);
            if (result != 0 && rh3_trust_looks_like_macho(entry)) {
                free(copy);
                return EACCES;
            }
        }
    }
    free(copy);
    return 0;
}
