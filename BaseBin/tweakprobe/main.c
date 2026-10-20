#include <stdlib.h>
#include <string.h>

// The systemhook constructor sets this only in this isolated short-lived
// executable after successfully dlopen'ing the REAL TweakLoader.dylib.
// Exit codes distinguish missed systemhook injection from failed dlopen.
int main(void)
{
    const char *hook = getenv("RH3_TWEAK_PROBE_SYSTEMHOOK");
    const char *loader = getenv("RH3_TWEAK_PROBE_LOADER");
    if (!hook || strcmp(hook, "1") != 0) return 81;
    if (!loader || strcmp(loader, "1") != 0) return 82;
    return 0;
}
