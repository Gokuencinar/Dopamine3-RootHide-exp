//
//  DOUIManager.m
//  Dopamine
//
//  Created by tomt000 on 24/01/2024.
//

#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOThemeManager.h"
#import "DOTheme.h"
#import "NSString+Version.h"
#import <pthread.h>
#import <fcntl.h>
#import <unistd.h>
#import <sys/stat.h>
#import <errno.h>

#ifndef RH3_FULL_APP_EXPERIMENTAL
#define RH3_FULL_APP_EXPERIMENTAL 0
#endif

@implementation DOUIManager

+ (instancetype)sharedInstance
{
    static DOUIManager *sharedInstance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedInstance = [[DOUIManager alloc] init];
    });
    return sharedInstance;
}

- (id)init
{
    if (self = [super init]){
        _bootlogoPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/bootlogo.png"];
        _preferenceManager = [DOPreferenceManager sharedManager];
        _logRecord = [NSMutableArray new];
        _logLock = [NSLock new];
#if RH3_FULL_APP_EXPERIMENTAL
        // Cache the ORIGINAL app container, before elevatePrivileges changes
        // HOME to /var/root. The file must survive a SpringBoard/launchd crash.
        _rh3DiagnosticPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/RootHide3-last-attempt.log"];
#endif
    }
    return self;
}

- (BOOL)isUpdateAvailable
{
    NSString *latestVersion = [self getLatestReleaseTag];
    NSString *currentVersion = [self getLaunchedReleaseTag];
    return [latestVersion numericalVersionRepresentation] > [currentVersion numericalVersionRepresentation];
}

- (NSArray *)getUpdatesInRange:(NSString *)start end:(NSString *)end
{
    NSArray *releases = [self getLatestReleases];
    if (releases.count == 0)
        return @[];

    long long startVersion = [start numericalVersionRepresentation];
    long long endVersion = [end numericalVersionRepresentation];
    NSMutableArray *updates = [NSMutableArray new];
    for (NSDictionary *release in releases) {
        NSString *version = release[@"tag_name"];
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            // Skip prereleases
            continue;
        }
        long long numericalVersion = [version numericalVersionRepresentation];
        if (numericalVersion > startVersion && numericalVersion <= endVersion) {
            [updates addObject:release];
        }
    }
    return updates;
}

- (NSArray *)getLatestReleases
{
    static dispatch_once_t onceToken;
    static NSArray *releases;
    dispatch_once(&onceToken, ^{
        NSURL *url = [NSURL URLWithString:@"https://api.github.com/repos/opa334/Dopamine/releases"];
        NSData *data = [NSData dataWithContentsOfURL:url];
        if (data) {
            NSError *error;
            releases = [NSJSONSerialization JSONObjectWithData:data options:kNilOptions error:&error];
            if (error)
            {
                onceToken = 0;
                releases = @[];
            }
        }
    });
    return releases;
}

- (BOOL)environmentUpdateAvailable
{
    if (![[DOEnvironmentManager sharedManager] jailbrokenVersion])
        return NO;

    NSString *jailbrokenVersion = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
    NSString *launchedVersion = [self getLaunchedReleaseTag];
    
    return [launchedVersion numericalVersionRepresentation] > [jailbrokenVersion numericalVersionRepresentation];
}

- (bool)launchedReleaseNeedsManualUpdate
{
    NSString *launchedTag = [self getLaunchedReleaseTag];
    NSDictionary *launchedVersion;
    for (NSDictionary *release in [self getLatestReleases]) {
        if ([release[@"tag_name"] isEqualToString:launchedTag]) {
            launchedVersion = release;
            break;
        }
    }
    if (!launchedVersion)
        return false;
    return [launchedVersion[@"body"] containsString:@"*Manual Updates*"];
}

- (NSString*)getLatestReleaseTag
{
    NSArray *releases = [self getLatestReleases];
    for (NSDictionary *release in releases) {
        NSNumber *prerelease = release[@"prerelease"];
        if ([prerelease boolValue]) {
            continue;
        }
        return release[@"tag_name"];
    }
    return nil;
}

- (NSString*)getLaunchedReleaseTag
{
    return [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
}

- (NSArray*)availablePackageManagers
{
    NSString *path = [[NSBundle mainBundle] pathForResource:@"PkgManagers" ofType:@"plist"];
    return [NSArray arrayWithContentsOfFile:path];
}

- (NSArray*)enabledPackageManagerKeys
{
    NSArray *enabledPkgManagers = [_preferenceManager preferenceValueForKey:@"enabledPkgManagers"] ?: @[];
    NSMutableArray *enabledKeys = [NSMutableArray new];
    NSArray *availablePkgManagers = [self availablePackageManagers];

    [availablePkgManagers enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledPkgManagers containsObject:key]) {
            [enabledKeys addObject:key];
        }
    }];

    return enabledKeys;
}

- (NSArray*)enabledPackageManagers
{
    NSMutableArray *enabledPkgManagers = [NSMutableArray new];
    NSArray *enabledKeys = [self enabledPackageManagerKeys];

    [[self availablePackageManagers] enumerateObjectsUsingBlock:^(id  _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSString *key = obj[@"Key"];
        if ([enabledKeys containsObject:key]) {
            [enabledPkgManagers addObject:obj];
        }
    }];

    return enabledPkgManagers;
}

- (void)resetPackageManagers
{
    [_preferenceManager removePreferenceValueForKey:@"enabledPkgManagers"];
}

- (void)resetSettings
{
    [_preferenceManager removePreferenceValueForKey:@"verboseLogsEnabled"];
    [_preferenceManager removePreferenceValueForKey:@"tweakInjectionEnabled"];
    [self resetPackageManagers];
}

- (void)setPackageManager:(NSString*)key enabled:(BOOL)enabled
{
    NSMutableArray *pkgManagers = [self enabledPackageManagerKeys].mutableCopy;
    
    if (enabled && ![pkgManagers containsObject:key]) {
        [pkgManagers addObject:key];
    }
    else if (!enabled && [pkgManagers containsObject:key]) {
        [pkgManagers removeObject:key];
    }

    [_preferenceManager setPreferenceValue:pkgManagers forKey:@"enabledPkgManagers"];
}

- (BOOL)isDebug
{
    NSNumber *debug = [_preferenceManager preferenceValueForKey:@"verboseLogsEnabled"];
    return debug == nil ? NO : [debug boolValue];
}

- (BOOL)enableTweaks
{
    NSNumber *tweaks = [_preferenceManager preferenceValueForKey:@"tweakInjectionEnabled"];
    return tweaks == nil ? YES : [tweaks boolValue];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug update:(BOOL)update
{
    if (!self.logView || !log)
        return;

    [_logLock lock];

    [self.logRecord addObject:log];

    BOOL isDebug = self.logView.class == DODebugLogView.class;
    if (debug && !isDebug) {
        [_logLock unlock];
        return;
    }
        
    
    if (update) {
        if ([self.logView respondsToSelector:@selector(updateLog:)]) {
            [self.logView updateLog:log];
        }
    }
    else {
        [self.logView showLog:log];
    }
    [_logLock unlock];
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug
{
    [self sendLog:log debug:debug update:NO];
}

// Do not rely on the in-memory log view for experimental launchd injection:
// a kernel panic/reboot destroys it. Write a short, bounded record to the
// app's own Documents directory, which can be shared after the next launch.
- (void)rh3WriteDiagnosticLine:(NSString *)line truncate:(BOOL)truncate
{
#if RH3_FULL_APP_EXPERIMENTAL
    if (!_rh3DiagnosticPath || !line) return;
    [_logLock lock];
    int flags = O_WRONLY | O_CREAT | O_CLOEXEC | O_NOFOLLOW | (truncate ? O_TRUNC : O_APPEND);
    int fd = open(_rh3DiagnosticPath.fileSystemRepresentation, flags, 0600);
    if (fd >= 0) {
        struct stat st = {0};
        if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size <= 65536) {
            NSString *entry = [NSString stringWithFormat:@"%@ %@\n", [NSDate date], line];
            NSData *bytes = [entry dataUsingEncoding:NSUTF8StringEncoding];
            const uint8_t *cursor = bytes.bytes;
            size_t remaining = bytes.length;
            while (remaining) {
                ssize_t written = write(fd, cursor, remaining);
                if (written < 0 && errno == EINTR) continue;
                if (written <= 0) break;
                cursor += written;
                remaining -= (size_t)written;
            }
            (void)fsync(fd);
        }
        close(fd);
    }
    [_logLock unlock];
#else
    (void)line;
    (void)truncate;
#endif
}

- (void)rh3BeginDiagnosticAttempt
{
    [self rh3WriteDiagnosticLine:@"BEGIN RootHide 3 experimental jailbreak attempt (no success implied)" truncate:YES];
}

- (void)rh3RecordDiagnosticStage:(NSString *)stage
{
    [self rh3WriteDiagnosticLine:stage truncate:NO];
}

- (NSURL *)rh3PreviousDiagnosticURL
{
#if RH3_FULL_APP_EXPERIMENTAL
    if (_rh3DiagnosticPath && [[NSFileManager defaultManager] fileExistsAtPath:_rh3DiagnosticPath])
        return [NSURL fileURLWithPath:_rh3DiagnosticPath];
#endif
    return nil;
}

- (void)shareLogRecordFromView:(UIView *)sourceView
{
    if (self.logRecord.count == 0)
        return;

    NSString *log = [self.logRecord componentsJoinedByString:@"\n"];
    UIActivityViewController *activityViewController = [[UIActivityViewController alloc] initWithActivityItems:@[log] applicationActivities:nil];
    activityViewController.popoverPresentationController.sourceView = sourceView;
    activityViewController.popoverPresentationController.sourceRect = sourceView.bounds;
    [[UIApplication sharedApplication].keyWindow.rootViewController presentViewController:activityViewController animated:YES completion:nil];
}

- (void)completeJailbreak
{
    if (!self.logView)
        return;

    [self.logView didComplete];
}

- (void)observeFileDescriptor:(int)fd withCallback:(void (^)(char *line))callbackBlock
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        int stdout_pipe[2];
        int stdout_orig[2];
        if (pipe(stdout_pipe) != 0 || pipe(stdout_orig) != 0) {
            return;
        }

        dup2(fd, stdout_orig[1]);
        close(stdout_orig[0]);
        
        dup2(stdout_pipe[1], fd);
        close(stdout_pipe[1]);
        
        char cur = 0;
        char line[1024];
        int line_index = 0;
        ssize_t bytes_read;

        while ((bytes_read = read(stdout_pipe[0], &cur, sizeof(cur))) > 0) {
            @autoreleasepool {
                write(stdout_orig[1], &cur, bytes_read);

                if (cur == '\n') {
                    line[line_index] = '\0';
                    callbackBlock(line);
                    line_index = 0;
                } else {
                    if (line_index < sizeof(line) - 1) {
                        line[line_index++] = cur;
                    }
                }
            }
        }
        close(stdout_pipe[0]);
    });
}

- (void)startLogCapture
{
    [self observeFileDescriptor:STDOUT_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
    
    [self observeFileDescriptor:STDERR_FILENO withCallback:^(char *line) {
        NSString *str = [NSString stringWithUTF8String:line];
        [self sendLog:str debug:YES];
    }];
}

- (NSString *)localizedStringForKey:(NSString*)key
{
    NSString *candidate = NSLocalizedString(key, nil);
    if ([candidate isEqualToString:key]) {
        if (!_fallbackLocalizations) {
            _fallbackLocalizations = [NSDictionary dictionaryWithContentsOfFile:[[NSBundle mainBundle].bundlePath stringByAppendingPathComponent:@"en.lproj/Localizable.strings"]];
        }
        candidate = _fallbackLocalizations[key];
        if (!candidate) candidate = key;
    }
    return candidate;
}

- (UIImage *)renderBootLogo
{
    return [[[DOThemeManager sharedInstance] enabledTheme] generateBootLogo];
}

@end


NSString *DOLocalizedString(NSString *key)
{
    return [[DOUIManager sharedInstance] localizedStringForKey:key];
}
