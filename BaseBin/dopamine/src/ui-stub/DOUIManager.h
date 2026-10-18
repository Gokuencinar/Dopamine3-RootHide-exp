//
//  DOUIManager.h
//  Dopamine
//
//  Created by tomt000 on 24/01/2024.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOUIManager : NSObject
{
}
@property (nonatomic, readonly) NSString *bootlogoPath;

+ (instancetype)sharedInstance;

- (void)sendLog:(NSString*)log debug:(BOOL)debug update:(BOOL)update;
- (void)sendLog:(NSString*)log debug:(BOOL)debug;

// The standalone dopamine CLI shares DOJailbreaker.m with the app, but must
// not write UI-sandbox diagnostic checkpoints or depend on the app container.
- (void)rh3BeginDiagnosticAttempt;
- (void)rh3RecordDiagnosticStage:(NSString *)stage;
- (nullable NSURL *)rh3PreviousDiagnosticURL;

- (NSArray *)enabledPackageManagers;
- (id)renderBootLogo;

@end

NSString *DOLocalizedString(NSString *string);

NS_ASSUME_NONNULL_END
