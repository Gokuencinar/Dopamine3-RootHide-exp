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
