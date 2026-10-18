#include <stdbool.h>

// Identifies the loaded RootHide launchd image before boomerang primitives
// are available; unlike roothide_is_active(), it needs no restored jbrand.
bool roothide_launchdhook_origin_verified(void);
void initSpawnHooks(void);
