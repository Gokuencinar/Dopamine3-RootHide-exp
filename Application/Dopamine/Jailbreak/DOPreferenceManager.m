//
//  PreferenceManager.m
//  Dopamine
//
//  Created by Lars Fröder on 13.01.24.
//

#import "DOPreferenceManager.h"

@implementation DOPreferenceManager

+ (instancetype)sharedManager
{
    static DOPreferenceManager *preferenceManager;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        preferenceManager = [[DOPreferenceManager alloc] init];
    });
    return preferenceManager;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        NSString *home = [NSString stringWithUTF8String:getenv("HOME")];
        _preferencesPath = [home stringByAppendingPathComponent:@"Library/Preferences/com.opa334.Dopamine.plist"];
        [self loadPreferences];
    }
    return self;
}

- (void)loadPreferences
{
    _preferences = [NSDictionary dictionaryWithContentsOfFile:_preferencesPath].mutableCopy ?: [NSMutableDictionary new];
}

- (void)savePreferences
{
    [_preferences writeToFile:_preferencesPath atomically:YES];
}

- (id)preferenceValueForKey:(NSString *)key
{
    return [_preferences objectForKey:key];
}

- (BOOL)boolPreferenceValueForKey:(NSString *)key fallback:(BOOL)fallback
{
    NSNumber *num = [self preferenceValueForKey:key];
    if (num) {
        return num.boolValue;
    }
    return fallback;
}

- (void)setPreferenceValue:(NSObject *)obj forKey:(NSString *)key
{
    [_preferences setObject:obj forKey:key];
    [self savePreferences];
}

- (BOOL)setVerifiedPreferenceValue:(NSObject *)obj forKey:(NSString *)key
{
    if (!obj || !key.length) return NO;
    NSObject *oldValue = _preferences[key];
    _preferences[key] = obj;
    BOOL persisted = [_preferences writeToFile:_preferencesPath atomically:YES];
    NSDictionary *onDisk = persisted ? [NSDictionary dictionaryWithContentsOfFile:_preferencesPath] : nil;
    if (persisted && [onDisk[key] isEqual:obj]) return YES;
    if (oldValue) _preferences[key] = oldValue;
    else [_preferences removeObjectForKey:key];
    return NO;
}

- (void)removePreferenceValueForKey:(NSString *)key
{
    [_preferences removeObjectForKey:key];
    [self savePreferences];
}

@end
