// RootHide userspace integration for Dopamine 3's existing systemhook.
// Keep the 3.x spawn/exec and hookd paths authoritative.
#include "common/common.h"
#include <libjailbreak/jbclient_xpc.h>
#include <libjailbreak/jbroot.h>
#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <pwd.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
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

void roothide_prepare_process(const char *root, const char *executable)
{
	if (!root || !jbclient_roothide_jailbroken() ||
	    !root_contains_executable(root, executable)) return;

    roothide_redirect_home(root);
    roothide_call_pathhook();

    // Optional RootHide components can arrive with the bootstrap. Do not
    // prevent normal Dopamine launch when they are not installed.
    const char *init = JBROOT_PATH("/usr/lib/roothideinit.dylib");
    if (init && access(init, R_OK) == 0) dlopen(init, RTLD_NOW | RTLD_LOCAL);
}

void roothide_trust_injected_libraries(char *const envp[])
{
    if (!envp) return;
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
            jbclient_trust_library_recurse(entry, NULL);
        }
    }
    free(copy);
}
