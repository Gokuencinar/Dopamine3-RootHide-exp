#include <string.h>

// Diagnostics only: fixed names for the three bundled managers. Never print
// arbitrary launch labels, environment values or unrelated app identifiers.
static const char *rh3_manager_spawn_name(const char *path, char *const argv[])
{
    if (!path) return NULL;
    const char *ids[] = {"org.coolstar.SileoStore", "xyz.willy.Zebra", "com.roothide.manager"};
    const char *names[] = {"Sileo", "Zebra", "RootHide"};
    const char *suffixes[] = {"/Applications/Sileo.app/Sileo", "/Applications/Zebra.app/Zebra", "/Applications/RootHide.app/RootHide"};
    if (!strcmp(path, "/usr/libexec/xpcproxy")) {
        if (!argv || !argv[0] || !argv[1]) return NULL;
        static const char prefix[] = "UIKitApplication:";
        if (strncmp(argv[1], prefix, sizeof(prefix)-1)) return NULL;
        const char *id = argv[1] + sizeof(prefix)-1;
        for (unsigned i=0; i<3; i++) {
            size_t length = strlen(ids[i]);
            if (!strncmp(id, ids[i], length) && id[length]=='[') return names[i];
        }
    } else {
        size_t length = strlen(path);
        for (unsigned i=0; i<3; i++) {
            size_t n = strlen(suffixes[i]);
            if (length>=n && !strcmp(path+length-n, suffixes[i])) return names[i];
        }
    }
    return NULL;
}
