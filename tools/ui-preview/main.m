// Isolated UIKit visual preview. No exploits, bootstrap or jailbreak libraries.
// Uses original view components; controller composition and device state are
// simulated. Every screenshot carries a visible provenance label.
#import <UIKit/UIKit.h>
#include <math.h>
#import "PSSpecifier.h"
#import "DOPreferenceManager.h"
#import "DOThemeManager.h"
#import "DOGlobalAppearance.h"
#import "DOHeaderView.h"
#import "DOActionMenuView.h"
#import "DOActionMenuButton.h"
#import "DOCreditsCell.h"
#import "DOHeaderCell.h"

@implementation PSSpecifier
- (instancetype)init { if ((self=[super init])) _properties=[NSMutableDictionary new]; return self; }
- (id)propertyForKey:(NSString *)key { return self.properties[key]; }
- (void)setProperty:(id)value forKey:(NSString *)key { self.properties[key]=value; }
@end

// Theme preference only. Never read the device app's filesystem/preferences.
@implementation DOPreferenceManager
+ (instancetype)sharedManager { static id instance; static dispatch_once_t once; dispatch_once(&once, ^{ instance=[self new]; }); return instance; }
- (id)preferenceValueForKey:(NSString *)key { return nil; }
- (BOOL)boolPreferenceValueForKey:(NSString *)key fallback:(BOOL)fallback { return fallback; }
- (void)setPreferenceValue:(NSObject *)obj forKey:(NSString *)key {}
- (void)removePreferenceValueForKey:(NSString *)key {}
@end

@interface DOCreditsCell (PreviewConstruction)
- (instancetype)initWithSpecifier:(PSSpecifier *)specifier;
- (CGFloat)preferredHeightForWidth:(CGFloat)width;
@end
@interface DOHeaderCell (PreviewConstruction)
- (instancetype)initWithSpecifier:(PSSpecifier *)specifier;
@end

static NSString *L(NSString *key) { return [NSBundle.mainBundle localizedStringForKey:key value:key table:nil]; }
static UILabel *Label(NSString *text, CGFloat size, UIColor *color) {
    UILabel *label=[UILabel new]; label.text=text; label.font=[UIFont systemFontOfSize:size];
    label.textColor=color; label.numberOfLines=0; label.translatesAutoresizingMaskIntoConstraints=NO; return label;
}

@interface RHPreviewController : UIViewController <DOActionMenuDelegate>
@end
@implementation RHPreviewController
- (BOOL)actionMenuShowsChevronForAction:(UIAction *)action { return [@[@"settings", @"credits"] containsObject:action.identifier]; }
- (BOOL)actionMenuActionIsEnabled:(UIAction *)action { return [@[@"settings", @"credits"] containsObject:action.identifier]; }
- (UIStatusBarStyle)preferredStatusBarStyle { return UIStatusBarStyleLightContent; }
- (void)viewDidLoad {
    [super viewDidLoad]; self.overrideUserInterfaceStyle=UIUserInterfaceStyleDark;
    DOTheme *theme=[[DOThemeManager sharedInstance] enabledTheme];
    UIImageView *background=[[UIImageView alloc] initWithImage:theme.image]; background.frame=self.view.bounds;
    background.autoresizingMask=UIViewAutoresizingFlexibleWidth|UIViewAutoresizingFlexibleHeight;
    background.contentMode=UIViewContentModeScaleAspectFill; background.clipsToBounds=YES; [self.view addSubview:background];
    // Render the provenance inside the preview UI itself. A separate raster
    // layer stays visible when Preferences-style cells affect text rendering.
    CGFloat width=UIScreen.mainScreen.bounds.size.width;
    UIGraphicsImageRenderer *renderer=[[UIGraphicsImageRenderer alloc] initWithSize:CGSizeMake(width,40)];
    UIImage *noticeImage=[renderer imageWithActions:^(UIGraphicsImageRendererContext *context) {
        [[UIColor colorWithWhite:0 alpha:0.7] setFill]; UIRectFill(CGRectMake(0,0,width,40));
        NSMutableParagraphStyle *style=[NSMutableParagraphStyle new]; style.alignment=NSTextAlignmentCenter;
        [@"VISTA PREVIA UIKIT · ESTADO SIMULADO\nNo es una captura de la IPA instalada" drawInRect:CGRectMake(6,5,width-12,34)
           withAttributes:@{NSFontAttributeName:[UIFont systemFontOfSize:11],NSForegroundColorAttributeName:UIColor.whiteColor,NSParagraphStyleAttributeName:style}];
    }];
    UIImageView *provenance=[[UIImageView alloc] initWithImage:noticeImage]; provenance.translatesAutoresizingMaskIntoConstraints=NO;
    [self.view addSubview:provenance];
    [NSLayoutConstraint activateConstraints:@[[provenance.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor],
       [provenance.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor], [provenance.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
       [provenance.heightAnchor constraintEqualToConstant:40]]];
    BOOL credits=[NSProcessInfo.processInfo.arguments containsObject:@"--credits"];
    if (credits) [self buildCreditsBelow:provenance]; else [self buildMainBelow:provenance];
    [self.view bringSubviewToFront:provenance];
}
- (void)buildMainBelow:(UIView *)banner {
    UIStackView *stack=[UIStackView new]; stack.axis=UILayoutConstraintAxisVertical;
    stack.distribution=UIStackViewDistributionEqualSpacing; stack.translatesAutoresizingMaskIntoConstraints=NO;
    [self.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[[stack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:30],
      [stack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-30],
      [stack.topAnchor constraintEqualToAnchor:banner.bottomAnchor constant:45],
      [stack.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor constant:-35]]];
    DOHeaderView *header=[[DOHeaderView alloc] initWithImage:[UIImage imageNamed:@"Dopamine"] subtitles:@[
      [DOGlobalAppearance mainSubtitleString:@"A12/A13 · iOS 18 · selección simulada"],
      [DOGlobalAppearance secondarySubtitleString:L(@"Credits_Made_By")]]];
    [stack addArrangedSubview:header];
    UILabel *notice=Label(@"RootHide 3 — Experimental port; not validated on an iPhone",12,UIColor.systemOrangeColor);
    notice.textAlignment=NSTextAlignmentCenter; [stack addArrangedSubview:notice];
    NSMutableArray *actions=[NSMutableArray new];
    NSArray *entries=@[@[@"Menu_Settings_Title",@"gearshape",@"settings"],@[@"Menu_Restart_SpringBoard_Title",@"arrow.clockwise",@"respring"],
      @[@"Menu_Reboot_Userspace_Title",@"arrow.clockwise.circle",@"reboot"],@[@"Menu_Credits_Title",@"info.circle",@"credits"]];
    for (NSArray *entry in entries) [actions addObject:[UIAction actionWithTitle:L(entry[0]) image:[UIImage systemImageNamed:entry[1]] identifier:entry[2] handler:^(__kindof UIAction *action) {}]];
    DOActionMenuView *menu=[[DOActionMenuView alloc] initWithActions:actions delegate:self]; [stack addArrangedSubview:menu];
    // The original button's initial appearance; its execution/logging controller is deliberately absent.
    DOActionMenuButton *button=[DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:@"Jailbreak" image:[UIImage systemImageNamed:@"lock.open"] identifier:nil handler:^(__kindof UIAction *action) {}] chevron:NO];
    button.backgroundColor=[DOThemeManager menuColorWithAlpha:1]; button.layer.cornerRadius=14;
    button.contentHorizontalAlignment=UIControlContentHorizontalAlignmentCenter;
    [button.heightAnchor constraintEqualToConstant:60].active=YES; [stack addArrangedSubview:button];
}
- (void)buildCreditsBelow:(UIView *)banner {
    UIScrollView *scroll=[UIScrollView new]; scroll.translatesAutoresizingMaskIntoConstraints=NO; [self.view addSubview:scroll];
    [NSLayoutConstraint activateConstraints:@[[scroll.topAnchor constraintEqualToAnchor:banner.bottomAnchor constant:12],
      [scroll.bottomAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.bottomAnchor],
      [scroll.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:12], [scroll.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-12]]];
    scroll.backgroundColor=[[DOThemeManager sharedInstance] enabledTheme].windowColor; scroll.layer.cornerRadius=16;
    UIStackView *stack=[UIStackView new]; stack.axis=UILayoutConstraintAxisVertical; stack.translatesAutoresizingMaskIntoConstraints=NO; [scroll addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[[stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor],
      [stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor],
      [stack.leadingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.leadingAnchor],
      [stack.trailingAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.trailingAnchor], [stack.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor]]];
    NSDictionary *plist=[NSDictionary dictionaryWithContentsOfFile:[NSBundle.mainBundle pathForResource:@"Credits" ofType:@"plist"]];
    for (NSDictionary *item in plist[@"items"]) {
        if ([item[@"headerCellClass"] isEqual:@"DOHeaderCell"]) {
            PSSpecifier *spec=[PSSpecifier new]; [spec setProperty:@"Dopamine 3.0.11 — Créditos" forKey:@"title"];
            DOHeaderCell *cell=[[DOHeaderCell alloc] initWithSpecifier:spec]; [cell.heightAnchor constraintEqualToConstant:60].active=YES;
            cell.backgroundColor=UIColor.clearColor; [stack addArrangedSubview:cell];
        } else if ([item[@"headerCellClass"] isEqual:@"DOCreditsCell"]) {
            PSSpecifier *spec=[PSSpecifier new]; [spec setProperty:item[@"names"] forKey:@"names"];
            DOCreditsCell *cell=[[DOCreditsCell alloc] initWithSpecifier:spec]; cell.backgroundColor=UIColor.clearColor;
            [cell.heightAnchor constraintEqualToConstant:35*ceil([item[@"names"] count]/2.0)].active=YES; [stack addArrangedSubview:cell];
        } else if (item[@"label"]) {
            UILabel *label=Label(L(item[@"label"]),15,[UIColor colorWithWhite:1 alpha:0.8]);
            UIView *container=[UIView new]; [container addSubview:label];
            [NSLayoutConstraint activateConstraints:@[[container.heightAnchor constraintEqualToConstant:42],
              [label.leadingAnchor constraintEqualToAnchor:container.leadingAnchor constant:20], [label.bottomAnchor constraintEqualToAnchor:container.bottomAnchor constant:-5]]];
            [stack addArrangedSubview:container];
        } else if (item[@"title"]) {
            DOActionMenuButton *button=[DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:L(item[@"title"]) image:[UIImage systemImageNamed:item[@"image"]] identifier:nil handler:^(__kindof UIAction *action) {}] chevron:NO];
            [button.heightAnchor constraintEqualToConstant:44].active=YES; [stack addArrangedSubview:button];
        }
    }
}
@end

@interface RHPreviewDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end
@implementation RHPreviewDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)options {
    self.window=[[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    self.window.rootViewController=[RHPreviewController new]; [self.window makeKeyAndVisible]; return YES;
}
@end
int main(int argc, char **argv) { @autoreleasepool { return UIApplicationMain(argc,argv,nil,NSStringFromClass(RHPreviewDelegate.class)); } }
