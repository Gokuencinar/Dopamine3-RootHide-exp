#ifndef RH3_APP_OWNER_POLICY_H
#define RH3_APP_OWNER_POLICY_H

#include <stdbool.h>
#include <string.h>

// Pinned official RootHide manager debs ship Zebra and RootHide as uid 501,
// mode 0755. The Apps parent can also be reset to 501 when dpkg unpacks a
// package. This is package data, NOT an elevation of the mobile account.
static inline bool rh3_apps_directory_owner_allowed(unsigned actual, unsigned rootOwner,
                                                     unsigned mode)
{
    return (actual == rootOwner || (rootOwner == 0 && actual == 501)) &&
           (mode & 0022) == 0;
}

// Do not generalize uid501 to arbitrary applications or installed tweaks.
static inline bool rh3_bundle_mobile_owner_allowed(const char *name)
{
    return name && (!strcmp(name, "Zebra.app") || !strcmp(name, "RootHide.app"));
}

static inline bool rh3_app_descendant_owner_allowed(bool mobileBundle, unsigned actual,
                                                    unsigned rootOwner)
{
    return actual == rootOwner || (mobileBundle && rootOwner == 0 && actual == 501);
}

static inline bool rh3_bundle_owner_allowed(const char *name, unsigned actual,
                                           unsigned rootOwner)
{
    return rh3_app_descendant_owner_allowed(rh3_bundle_mobile_owner_allowed(name),
                                           actual, rootOwner);
}

#endif
