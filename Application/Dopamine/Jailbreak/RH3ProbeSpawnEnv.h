#ifndef RH3_PROBE_SPAWN_ENV_H
#define RH3_PROBE_SPAWN_ENV_H

// An isolated probe launched by Dopamine does not necessarily inherit
// systemhook.dylib: patching a suspended child's trust state is NOT itself
// DYLD_INSERT_LIBRARIES injection. Build this environment only for the
// short-lived, verified rh3tweakprobe binary, never for arbitrary commands.
#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline int rh3_probe_env_is_override(const char *entry)
{
    static const char *const keys[] = {
        "DYLD_INSERT_LIBRARIES=", "DYLD_IN_CACHE=", "DISABLE_TWEAKS=",
        "_SafeMode=", "_MSSafeMode=", "RH3_TWEAK_PROBE_SYSTEMHOOK=",
        "RH3_TWEAK_PROBE_LOADER=", "RH3_TWEAK_PROBE_TARGET=",
        "RH3_TWEAK_PROBE_ENTERED=", "RH3_TWEAK_PROBE_CHECKIN="
    };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (!strncmp(entry, keys[i], strlen(keys[i]))) return 1;
    }
    return 0;
}

// The caller must verify the absolute systemhook path is a trusted file
// within the active hidden root. Only the three first elements are owned; all
// other strings point at the parent's immutable environment values.
static inline int rh3_probe_env_build(char *const parent[], const char *systemhook,
                                      char ***environmentOut)
{
    if (!environmentOut) return EINVAL;
    *environmentOut = NULL;
    if (!systemhook || systemhook[0] != '/' || strchr(systemhook, ':') ||
        strchr(systemhook, '\n') || strchr(systemhook, '\r')) return EINVAL;
    const size_t pathLen = strlen(systemhook);
    if (pathLen == 0 || pathLen >= PATH_MAX) return ENAMETOOLONG;
    size_t count = 0, kept = 0;
    for (size_t i = 0; parent && parent[i]; i++) {
        if (++count > 4096) return E2BIG;
        if (!rh3_probe_env_is_override(parent[i])) kept++;
    }
    char **result = calloc(kept + 4, sizeof(*result));
    if (!result) return ENOMEM;
    static const char prefix[] = "DYLD_INSERT_LIBRARIES=";
    result[0] = malloc(sizeof(prefix) + pathLen);
    result[1] = strdup("DYLD_IN_CACHE=0");
    result[2] = strdup("RH3_TWEAK_PROBE_TARGET=1");
    if (!result[0] || !result[1] || !result[2]) {
        free(result[0]); free(result[1]); free(result[2]); free(result);
        return ENOMEM;
    }
    memcpy(result[0], prefix, sizeof(prefix) - 1);
    memcpy(result[0] + sizeof(prefix) - 1, systemhook, pathLen + 1);
    size_t out = 3;
    for (size_t i = 0; parent && parent[i]; i++) {
        if (!rh3_probe_env_is_override(parent[i])) result[out++] = parent[i];
    }
    result[out] = NULL;
    *environmentOut = result;
    return 0;
}

static inline void rh3_probe_env_free(char **environment)
{
    if (!environment) return;
    free(environment[0]);
    free(environment[1]);
    free(environment[2]);
    free(environment);
}

#endif
