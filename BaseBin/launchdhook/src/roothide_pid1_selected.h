#ifndef RH3_PID1_SELECTED_H
#define RH3_PID1_SELECTED_H

#include <stdbool.h>
#include <string.h>

// Opt-in on the *requested job*, not every Apple xpcproxy instance. Keep
// comparison exact and reject malformed/truncated UIKit labels. This is a
// narrow runtime repair, not authorization to modify ordinary system jobs.
static bool rh3_pid1_selected_child(const char *path, char *const argv[], const char *rootSshd)
{
    if (!path) return false;
    if (rootSshd && !strcmp(path, rootSshd)) return true;
    // LaunchServices sometimes starts bootstrap apps as direct executables,
    // not UIKitApplication xpcproxy jobs. Bound that selection to the exact
    // currently authenticated .jbroot: never accept a suffix from an
    // arbitrary bundle, a stale root, or an Apple/system executable.
    static const char sshSuffix[] = "/usr/sbin/sshd";
    static const char *const directApps[] = {
        "/Applications/Sileo.app/Sileo",
        "/Applications/Zebra.app/Zebra",
        "/Applications/RootHide.app/RootHide",
        "/Applications/NewTerm.app/NewTerm"
    };
    if (rootSshd) {
        // /var and /private/var refer to the same data volume. The path
        // comparison remains lexical and exact; do not follow symlinks in
        // launchd/PID1's hot spawn path.
        const char *root = rootSshd;
        const char *candidate = path;
        if (!strncmp(root, "/private/var/", sizeof("/private/var/") - 1))
            root += sizeof("/private") - 1;
        if (!strncmp(candidate, "/private/var/", sizeof("/private/var/") - 1))
            candidate += sizeof("/private") - 1;
        size_t sshLength = strlen(root);
        size_t suffixLength = sizeof(sshSuffix) - 1;
        if (sshLength > suffixLength &&
            !strcmp(root + sshLength - suffixLength, sshSuffix)) {
            size_t rootLength = sshLength - suffixLength;
            if (!strncmp(candidate, root, rootLength)) {
                for (unsigned i = 0; i < sizeof(directApps) / sizeof(directApps[0]); i++) {
                    if (!strcmp(candidate + rootLength, directApps[i])) return true;
                }
            }
        }
    }
    if (strcmp(path, "/usr/libexec/xpcproxy") || !argv || !argv[0] || !argv[1]) return false;
    const char *label = argv[1];
    if (!strcmp(label, "com.openssh.sshd")) return true;
    static const char *const bundles[] = {
        "ws.hbang.Terminal", "org.coolstar.SileoStore",
        "xyz.willy.Zebra", "com.roothide.manager"
    };
    static const char prefix[] = "UIKitApplication:";
    if (strncmp(label, prefix, sizeof(prefix) - 1)) return false;
    label += sizeof(prefix) - 1;
    for (unsigned i = 0; i < sizeof(bundles) / sizeof(bundles[0]); i++) {
        const size_t n = strlen(bundles[i]);
        if (!strncmp(label, bundles[i], n) && label[n] == '[') return true;
    }
    return false;
}

#endif
