//
//  SceneDelegate.m
//  Dopamine
//
//  Created by Lars Fröder on 23.09.23.
//

#import "DOSceneDelegate.h"
#import "DONavigationController.h"
#import "../UI/RH3DiagnosticFile.h"

@interface DOSceneDelegate ()

@end

@implementation DOSceneDelegate

- (void)scene:(UIScene *)scene willConnectToSession:(UISceneSession *)session options:(UISceneConnectionOptions *)connectionOptions {
    UIWindow *window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
#if RH3_FULL_APP_EXPERIMENTAL
    // Export must be available before DONavigationController/DOEnvironmentManager
    // performs synchronous IPC against a possibly broken launchd/jailbreakd.
    UIViewController *landing = [UIViewController new];
    landing.view.backgroundColor = UIColor.systemBackgroundColor;
    NSString *directory = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSURL *latest = RH3LatestDiagnosticURL(directory);
    UILabel *title = [UILabel new];
    title.text = @"RootHide 3";
    title.font = [UIFont boldSystemFontOfSize:28];
    UILabel *detail = [UILabel new];
    detail.numberOfLines = 0;
    detail.textAlignment = NSTextAlignmentCenter;
    NSDictionary *attributes = latest ? [NSFileManager.defaultManager attributesOfItemAtPath:latest.path error:nil] : nil;
    NSString *date = attributes[NSFileModificationDate] ? [NSDateFormatter localizedStringFromDate:attributes[NSFileModificationDate]
        dateStyle:NSDateFormatterMediumStyle timeStyle:NSDateFormatterMediumStyle] : @"Fecha no disponible";
    NSString *label = [latest.lastPathComponent isEqual:@"RootHide3-last-attempt.log"] ? @"Registro de una versión anterior:" : @"Último diagnóstico guardado:";
    detail.text = latest ? [NSString stringWithFormat:@"%@\n%@\n\nPuedes compartirlo antes de abrir RootHide.", label, date]
                         : @"No hay un diagnóstico legible guardado. Puedes entrar en RootHide para continuar.";
    UIButton *share = [UIButton buttonWithType:UIButtonTypeSystem];
    [share setTitle:@"Compartir último diagnóstico" forState:UIControlStateNormal];
    share.enabled = latest != nil;
    __weak UIViewController *weakLanding = landing;
    __weak UIButton *weakShare = share;
    [share addAction:[UIAction actionWithHandler:^(__kindof UIAction *action) {
        UIViewController *presenter = weakLanding;
        UIButton *source = weakShare;
        if (!presenter || !source || !latest) return;
        UIActivityViewController *sheet = [[UIActivityViewController alloc] initWithActivityItems:@[latest] applicationActivities:nil];
        sheet.popoverPresentationController.sourceView = source;
        sheet.popoverPresentationController.sourceRect = source.bounds;
        [presenter presentViewController:sheet animated:YES completion:nil];
    }] forControlEvents:UIControlEventTouchUpInside];
    UIButton *enter = [UIButton buttonWithType:UIButtonTypeSystem];
    [enter setTitle:@"Entrar en RootHide" forState:UIControlStateNormal];
    __weak UIWindow *weakWindow = window;
    [enter addAction:[UIAction actionWithHandler:^(__kindof UIAction *action) {
        weakWindow.rootViewController = [[DONavigationController alloc] init];
    }] forControlEvents:UIControlEventTouchUpInside];
    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[title, detail, share, enter]];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.alignment = UIStackViewAlignmentCenter;
    stack.spacing = 24;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [landing.view addSubview:stack];
    [NSLayoutConstraint activateConstraints:@[
        [stack.centerYAnchor constraintEqualToAnchor:landing.view.safeAreaLayoutGuide.centerYAnchor],
        [stack.leadingAnchor constraintEqualToAnchor:landing.view.safeAreaLayoutGuide.leadingAnchor constant:24],
        [stack.trailingAnchor constraintEqualToAnchor:landing.view.safeAreaLayoutGuide.trailingAnchor constant:-24],
        [detail.widthAnchor constraintEqualToAnchor:stack.widthAnchor]
    ]];
    window.rootViewController = landing;
#else
    window.rootViewController = [[DONavigationController alloc] init];
#endif
    [window makeKeyAndVisible];
    self.window = window;
}

+ (void)relaunch
{
    UIWindowScene *windowScene = (UIWindowScene *)[[[UIApplication sharedApplication] connectedScenes] anyObject];
    DOSceneDelegate *instance = (DOSceneDelegate *)windowScene.delegate;

    [UIView animateWithDuration:0.3 animations:^{
        instance.window.alpha = 0;
    } completion:^(BOOL finished) {
        UIWindow *window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)instance.window.windowScene];
        window.rootViewController = [[DONavigationController alloc] init];
        [window makeKeyAndVisible];
        instance.window = window;
        instance.window.alpha = 0;
        [UIView animateWithDuration:0.3 animations:^{
            instance.window.alpha = 1;
        }];
    }];
}

- (void)sceneDidDisconnect:(UIScene *)scene {
    // Called as the scene is being released by the system.
    // This occurs shortly after the scene enters the background, or when its session is discarded.
    // Release any resources associated with this scene that can be re-created the next time the scene connects.
    // The scene may re-connect later, as its session was not necessarily discarded (see `application:didDiscardSceneSessions` instead).
}


- (void)sceneDidBecomeActive:(UIScene *)scene {
    // Called when the scene has moved from an inactive state to an active state.
    // Use this method to restart any tasks that were paused (or not yet started) when the scene was inactive.
}


- (void)sceneWillResignActive:(UIScene *)scene {
    // Called when the scene will move from an active state to an inactive state.
    // This may occur due to temporary interruptions (ex. an incoming phone call).
}


- (void)sceneWillEnterForeground:(UIScene *)scene {
    // Called as the scene transitions from the background to the foreground.
    // Use this method to undo the changes made on entering the background.
}


- (void)sceneDidEnterBackground:(UIScene *)scene {
    // Called as the scene transitions from the foreground to the background.
    // Use this method to save data, release shared resources, and store enough scene-specific state information
    // to restore the scene back to its current state.
}


@end
