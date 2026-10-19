#import <Foundation/Foundation.h>

static NSString *RH3CanonicalAppPath(NSString *path)
{
    if (![path isKindOfClass:NSString.class] || !path.isAbsolutePath || [path.pathComponents containsObject:@".."])
        return nil;
    NSString *normalized = path.stringByResolvingSymlinksInPath.stringByStandardizingPath;
    if ([normalized hasPrefix:@"/private/var/"]) normalized = [normalized substringFromIndex:8];
    return normalized;
}

// Only an identical bundle name in another RootHide Applications directory.
// Caller must additionally validate brand, absence of the old root, ownership,
// current bootstrap identity and the bundle identifier before refreshing it.
static NSString *RH3StaleRegisteredRoot(NSString *registered, NSString *current)
{
    NSString *old = RH3CanonicalAppPath(registered), *now = RH3CanonicalAppPath(current);
    if (!old || !now || [old isEqual:now] || ![old.lastPathComponent isEqual:now.lastPathComponent] ||
        ![old.pathExtension isEqual:@"app"]) return nil;
    NSString *apps = old.stringByDeletingLastPathComponent;
    NSString *root = apps.stringByDeletingLastPathComponent;
    if (![apps.lastPathComponent isEqual:@"Applications"] ||
        ![root.stringByDeletingLastPathComponent isEqual:@"/var/containers/Bundle/Application"] ||
        ![root.lastPathComponent hasPrefix:@".jbroot-"]) return nil;
    return root;
}
