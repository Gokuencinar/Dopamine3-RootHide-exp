// Read-only, host-testable classification of an observed LaunchServices proxy.
// Neither nil proxy nor a missing bundle URL establishes that a package is
// absent from the filesystem. A different URL is NOT authorization to remove
// or overwrite another app's LaunchServices record.
#ifndef ROOT_HIDE_LS_RECORD_STATUS_H
#define ROOT_HIDE_LS_RECORD_STATUS_H

#include <stdbool.h>

typedef enum {
    RH3LSProxyNil = 0,
    RH3LSBundleURLMissing = 1,
    RH3LSExpectedRootUnknown = 2,
    RH3LSWrongRoot = 3,
    RH3LSProxyNotInstalled = 4,
    RH3LSRegisteredCurrentRoot = 5,
} RH3LSRecordStatus;

static inline RH3LSRecordStatus RH3ClassifyLSRecord(bool proxyPresent,
                                                   bool bundleURLPresent,
                                                   bool expectedRootKnown,
                                                   bool canonicalPathsMatch,
                                                   bool proxyInstalled)
{
    if (!proxyPresent) return RH3LSProxyNil;
    if (!bundleURLPresent) return RH3LSBundleURLMissing;
    if (!expectedRootKnown) return RH3LSExpectedRootUnknown;
    if (!canonicalPathsMatch) return RH3LSWrongRoot;
    if (!proxyInstalled) return RH3LSProxyNotInstalled;
    return RH3LSRegisteredCurrentRoot;
}

static inline const char *RH3LSRecordStatusName(RH3LSRecordStatus status)
{
    switch (status) {
        case RH3LSProxyNil: return "proxy_nil";
        case RH3LSBundleURLMissing: return "bundleURL_missing";
        case RH3LSExpectedRootUnknown: return "expected_root_unknown";
        case RH3LSWrongRoot: return "wrong_root";
        case RH3LSProxyNotInstalled: return "proxy_not_installed";
        case RH3LSRegisteredCurrentRoot: return "registered_current_root";
    }
    return "invalid_state";
}

#endif
