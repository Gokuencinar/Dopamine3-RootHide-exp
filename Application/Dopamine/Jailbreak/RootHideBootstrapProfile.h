#ifndef RH3_BOOTSTRAP_PROFILE_H
#define RH3_BOOTSTRAP_PROFILE_H

// Archive/repository ABI, not the OS version and not proof of device support.
// iOS 18 is an experimental reuse of the arm64e 1900 userspace. The caller
// must separately require an available kernel + PPL exploit combination.
static inline int rh3_bootstrap_version_for_os(int major)
{
    switch (major) {
        case 15: return 1800;
        case 16: return 1900;
        case 18: return 1900;
        default: return 0;
    }
}

#endif
