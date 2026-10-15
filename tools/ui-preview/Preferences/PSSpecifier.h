// UI-preview-only stand-in; never included in the device application's build.
#import <UIKit/UIKit.h>
@interface PSSpecifier : NSObject
@property NSMutableDictionary *properties;
- (id)propertyForKey:(NSString *)key;
- (void)setProperty:(id)value forKey:(NSString *)key;
@end
