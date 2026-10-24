#ifndef RH3_PID1_SELECTED_H
#define RH3_PID1_SELECTED_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

// The package manager bundles shipped in the immutable RootHide packages
// have verified executable suffixes and bundle identifiers. Use ONE mapping
// both for blacklist policy and for opting into PID1's deferred patch.
// Optional NewTerm is user-installed and its CFBundleExecutable/identifier
// cannot be established here: never opt its direct path into deferred patch.
static const char *rh3_pid1_direct_bundle_id(const char *path, const char *rootSshd)
{
    if (!path || !rootSshd) return NULL;
    static const char sshSuffix[] = "/usr/sbin/sshd";
    static const struct {
        const char *suffix;
        const char *bundleId;
    } directApps[] = {
        {"/Applications/Sileo.app/Sileo", "org.coolstar.SileoStore"},
        {"/Applications/Zebra.app/Zebra", "xyz.willy.Zebra"},
        {"/Applications/RootHide.app/RootHide", "com.roothide.manager"}
    };
    // /private/var and /var are aliases on the data volume. Only match
    // the complete active root and one immutable package executable suffix;
    // no arbitrary substring, symlink resolution, or XPC from PID1.
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
                if (!strcmp(candidate + rootLength, directApps[i].suffix))
                    return directApps[i].bundleId;
            }
        }
    }
    return NULL;
}

// Opt in on the requested job, not every Apple xpcproxy instance. Rooted
// direct app opt-ins must have passed matching blacklist policy *before* use.
static bool rh3_pid1_selected_child(const char *path, char *const argv[], const char *rootSshd)
{
    if (!path) return false;
    if (rootSshd && !strcmp(path, rootSshd)) return true;
    if (rh3_pid1_direct_bundle_id(path, rootSshd)) return true;
    if (strcmp(path, "/usr/libexec/xpcproxy") || !argv || !argv[0] || !argv[1]) return false;
    const char *label = argv[1];
    if (!strcmp(label, "com.openssh.sshd")) return true;
    static const char *const bundles[] = {
        "ws.hbang.Terminal", "com.hbang.NewTerm", "org.coolstar.SileoStore",
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
