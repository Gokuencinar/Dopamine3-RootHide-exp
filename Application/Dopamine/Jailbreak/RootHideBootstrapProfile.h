#ifndef RH3_BOOTSTRAP_PROFILE_H
#define RH3_BOOTSTRAP_PROFILE_H

// Package ABI, not CPU subtype or proof of runtime support. RootHide's
// iphoneos-arm64e packages also contain ARM64 slices. Exploit availability
// must be checked separately by DOEnvironmentManager on the actual device.
// Reusing 1900 on 17/18/26 is experimental; no future OS fallback.
static inline int rh3_bootstrap_version_for_os(int major)
{
    switch (major) {
        case 15: return 1800;
        case 16:
        case 17:
        case 18:
        case 26: return 1900;
        default: return 0;
    }
}

#endif
