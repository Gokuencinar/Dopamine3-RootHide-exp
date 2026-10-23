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

static void roothide_call_pathhook(void)
{
    const char *path = JBROOT_PATH("/basebin/roothidehooks.dylib");
    if (!path || access(path, R_OK) != 0) return;
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

void roothide_prepare_process(const char *root, const char *executable)
{
    if (!root || !systemhook_is_roothide_root_path(root) ||
        !jbclient_roothide_jailbroken()) return;

    // HOME/path redirection is narrower: only the hidden-root executables.
    // Never rewrite containers for ordinary UIKit apps or Apple daemons.
    if (root_contains_executable(root, executable)) {
        roothide_redirect_home(root);
        roothide_call_pathhook();
    }

    rh3_load_rooted_init(root);
}

void roothide_trust_injected_libraries(char *const envp[])
{
    if (!envp) return;
    const char *root = get_jbroot();
    if (!systemhook_is_roothide_root_path(root)) return;
    char resolvedRoot[PATH_MAX] = {0};
    if (!realpath(root, resolvedRoot)) return;
    const char *inserts = NULL;
    for (size_t i = 0; envp[i]; ++i) {
        if (!strncmp(envp[i], "DYLD_INSERT_LIBRARIES=", sizeof("DYLD_INSERT_LIBRARIES=") - 1)) {
            inserts = envp[i] + sizeof("DYLD_INSERT_LIBRARIES=") - 1;
            break;
        }
    }
    if (!inserts || !*inserts) return;
    char *copy = strdup(inserts);
    if (!copy) return;
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
            jbclient_trust_library_recurse(entry, NULL);
        }
    }
    free(copy);
}
