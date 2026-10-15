#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "machomerger_hook.h"
#include "dyld_jbinfo.h"
#include "dyld.h"

#define ROOTHIDE_LOADER_PREFIX "@loader_path/.jbroot"

// Apple dyld-1285.19/dyld/Loader.cpp retains this exact C++ signature.
// MachOMerger must resolve it in the device's actual dyld; source-level ABI
// agreement alone is not evidence of compatibility with every iOS 18 build.
#if IOS <= 18

typedef struct Loader Loader;
typedef struct LoadOptions LoadOptions;
typedef struct RuntimeState RuntimeState;

//class static method, no "this" parameter
extern bool ORIG(_ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc)(RuntimeState* state, const char* loadPath, const LoadOptions* options, const Loader* ldr, bool fromLCRPATH, char fixedPath[]);
bool HOOK(_ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc)(RuntimeState* state, const char* loadPath, const LoadOptions* options, const Loader* ldr, bool fromLCRPATH, char fixedPath[])
{
    bool ret = ORIG(_ZN5dyld46Loader18expandAtLoaderPathERNS_12RuntimeStateEPKcRKNS0_11LoadOptionsEPKS0_bPc)(state, loadPath, options, ldr, fromLCRPATH, fixedPath);
    if(ret && loadPath && fixedPath) {
        if(strncmp(loadPath, ROOTHIDE_LOADER_PREFIX, sizeof(ROOTHIDE_LOADER_PREFIX)-1) == 0)
        {
            if ( (loadPath[sizeof(ROOTHIDE_LOADER_PREFIX)-1] != '/')
             && (loadPath[sizeof(ROOTHIDE_LOADER_PREFIX)-1] != '\0') ) {
                return ret;
            }

            char *jbroot = jbinfo_get_jbroot();
            const char *suffix = &loadPath[sizeof(ROOTHIDE_LOADER_PREFIX)-1];
            if (jbroot && jbroot[0] == '/' && strlen(jbroot) + strlen(suffix) < PATH_MAX) {
                strlcpy(fixedPath, jbroot, PATH_MAX);
                strlcat(fixedPath, suffix, PATH_MAX);
            }
        }
    }
    return ret;
}
#endif

bool SPINLOCK_FIX_DISABLED = false;

void dyldhook_init_roothide(uintptr_t kernelParams)
{
#if IOS==15 && __arm64e__
	uintptr_t argc = *(uintptr_t *)(kernelParams + sizeof(void *));
	char **envp = (char **)(kernelParams + sizeof(void *) + sizeof(argc) + (sizeof(const char *) * argc) + sizeof(void *));

    //when we disable dyld patch globally, we may still inject dyld patch for some processes such as WebContent, but we don't need spinlock fix
    // but dyldpatch for WebContent is only for ios16???
	if(_simple_getenv(envp, "SPINLOCK_FIX_DISABLED")) {
		SPINLOCK_FIX_DISABLED = true;
	}
#endif
}
