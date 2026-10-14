// Standalone RootHide 3 install/open test. No jailbreak imports or actions.
#import <UIKit/UIKit.h>

@interface RH3DiagnosticAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@implementation RH3DiagnosticAppDelegate
- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    self.window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
    UIViewController *controller = [[UIViewController alloc] init];
    controller.view.backgroundColor = UIColor.systemBackgroundColor;

    UIStackView *stack = [[UIStackView alloc] init];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.spacing = 18;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    // Runtime marker checked by the IPA verifier: never present in Dopamine.
    stack.accessibilityIdentifier = @"RH3_DEVICE_TEST_UIKIT_ONLY_V1";
    [controller.view addSubview:stack];

    UILabel *title = [[UILabel alloc] init];
    title.text = @"RootHide 3 — Device Test";
    title.font = [UIFont boldSystemFontOfSize:24];
    title.textColor = UIColor.labelColor;
    title.textAlignment = NSTextAlignmentCenter;
    title.numberOfLines = 0;
    [stack addArrangedSubview:title];

    UILabel *notice = [[UILabel alloc] init];
    notice.text = @"Diagnostic build: install/open test only. No jailbreak, bootstrap installation, kernel patches, or reboot functionality is included.";
    notice.font = [UIFont systemFontOfSize:16];
    notice.textColor = UIColor.secondaryLabelColor;
    notice.textAlignment = NSTextAlignmentCenter;
    notice.numberOfLines = 0;
    [stack addArrangedSubview:notice];

    UILabel *details = [[UILabel alloc] init];
    details.text = [NSString stringWithFormat:@"Device: %@\niOS: %@",
                    UIDevice.currentDevice.model, UIDevice.currentDevice.systemVersion];
    details.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    details.textColor = UIColor.labelColor;
    details.textAlignment = NSTextAlignmentCenter;
    details.numberOfLines = 0;
    [stack addArrangedSubview:details];

    UILayoutGuide *safe = controller.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [stack.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:safe.leadingAnchor constant:24],
        [stack.trailingAnchor constraintLessThanOrEqualToAnchor:safe.trailingAnchor constant:-24],
        [stack.widthAnchor constraintLessThanOrEqualToConstant:390],
    ]];

    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];
    return YES;
}
@end

int main(int argc, char *argv[])
{
    @autoreleasepool {
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([RH3DiagnosticAppDelegate class]));
    }
}
