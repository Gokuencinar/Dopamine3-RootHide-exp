#include <stdlib.h>
#include <string.h>

// The systemhook constructor sets this only in this isolated short-lived
// executable after successfully dlopen'ing the REAL TweakLoader.dylib.
// Exit codes distinguish missed injection (81), constructor entered without
// check-in (83), completed check-in without executable resolution (84), and
// missing TweakLoader after reaching the verified systemhook stage (82).
int main(void)
{
    const char *hook = getenv("RH3_TWEAK_PROBE_SYSTEMHOOK");
    const char *loader = getenv("RH3_TWEAK_PROBE_LOADER");
    if (!hook || strcmp(hook, "1") != 0) {
        const char *entered = getenv("RH3_TWEAK_PROBE_ENTERED");
        if (!entered || strcmp(entered, "1") != 0) return 81;
        const char *checkedIn = getenv("RH3_TWEAK_PROBE_CHECKIN");
        return checkedIn && strcmp(checkedIn, "1") == 0 ? 84 : 83;
    }
    if (!loader || strcmp(loader, "1") != 0) return 82;
    return 0;
}
