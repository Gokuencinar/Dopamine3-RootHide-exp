#ifndef RH3_MACHO_LIBRARY_TYPE_H
#define RH3_MACHO_LIBRARY_TYPE_H

#include <stdint.h>
#include <stdbool.h>

// MH_EXECUTE is never an old-ABI arm64e library. Restrict the exception
// to actual dynamically loaded Mach-O image types.
// MH_DYLIB and MH_BUNDLE come from mach-o/loader.h in production.
static inline bool rh3_macho_is_library_type(uint32_t filetype)
{
    return filetype == MH_DYLIB || filetype == MH_BUNDLE;
}

#endif
