//
//  PreferenceManager.h
//  Dopamine
//
//  Created by Lars Fröder on 13.01.24.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface DOPreferenceManager : NSObject
{
    NSString *_preferencesPath;
    NSMutableDictionary *_preferences;
}

+ (instancetype)sharedManager;

- (id)preferenceValueForKey:(NSString *)key;
- (BOOL)boolPreferenceValueForKey:(NSString *)key fallback:(BOOL)fallback;

- (void)setPreferenceValue:(NSObject *)obj forKey:(NSString *)key;
// Consent-critical settings must be verified on disk, not only updated in
// _preferences. Returns NO without retaining the new in-memory value if save
// or readback fails.
- (BOOL)setVerifiedPreferenceValue:(NSObject *)obj forKey:(NSString *)key;
- (void)removePreferenceValueForKey:(NSString *)key;

@end

NS_ASSUME_NONNULL_END
