#import "DOUIManager.h"

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

- (void)sendLog:(NSString*)log debug:(BOOL)debug update:(BOOL)update
{
	if (!debug) {
		printf("%s\n", log.UTF8String);
	}
	else {
		printf("[d] %s\n", log.UTF8String);
	}
}

- (void)sendLog:(NSString*)log debug:(BOOL)debug
{
	[self sendLog:log debug:debug update:NO];
}

// These are intentionally inert in the command-line helper. The full iOS
// application's DOUIManager owns the persisted diagnostic log and export UI.
- (BOOL)rh3BeginDiagnosticAttempt
{
    return YES;
}

- (void)rh3RecordDiagnosticStage:(NSString *)stage
{
    (void)stage;
}

- (NSURL *)rh3PreviousDiagnosticURL
{
    return nil;
}

- (NSArray *)enabledPackageManagers
{
	return nil;
}

- (id)renderBootLogo
{
    return nil;
}

@end


NSString *DOLocalizedString(NSString *string)
{
	return string;
}
