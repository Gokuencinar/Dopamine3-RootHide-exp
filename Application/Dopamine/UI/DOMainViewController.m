//
//  DOMainViewController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOMainViewController.h"
#import "DOUIManager.h"
#import "DOEnvironmentManager.h"
#import "DOJailbreaker.h"
#import "DOBootstrapper.h"
#import "DOGlobalAppearance.h"
#import "DOActionMenuButton.h"
#import "DOUpdateViewController.h"
#import "DOLogCrashViewController.h"
#import <pthread.h>
#import <sys/sysctl.h>
#import <libjailbreak/libjailbreak.h>

#ifndef RH3_INSTALLABLE_DIAGNOSTIC
#define RH3_INSTALLABLE_DIAGNOSTIC 0
#endif
#ifndef RH3_FULL_APP_EXPERIMENTAL
#define RH3_FULL_APP_EXPERIMENTAL 0
#endif

@interface DOMainViewController ()

@property DOJailbreakButton *jailbreakBtn;
@property NSArray<NSLayoutConstraint *> *jailbreakButtonConstraints;
@property DOActionMenuButton *updateButton;
@property(nonatomic) BOOL hideStatusBar;
@property(nonatomic) BOOL hideHomeIndicator;

@end

@implementation DOMainViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    [self setupStack];
}

-(void)setupStack
{
#if RH3_INSTALLABLE_DIAGNOSTIC
    // Install-and-open smoke-test only. Deliberately do not construct the
    // jailbreak / update / reboot / settings actions in this separate app.
    self.view.backgroundColor = [UIColor systemBackgroundColor];
    UIStackView *diagnostic = [[UIStackView alloc] init];
    diagnostic.axis = UILayoutConstraintAxisVertical;
    diagnostic.alignment = UIStackViewAlignmentCenter;
    diagnostic.spacing = 18;
    diagnostic.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:diagnostic];

    UILabel *title = [[UILabel alloc] init];
    title.text = @"RootHide 3 — Device Test";
    title.font = [UIFont boldSystemFontOfSize:25];
    title.textColor = [UIColor labelColor];
    title.textAlignment = NSTextAlignmentCenter;
    title.numberOfLines = 0;
    [diagnostic addArrangedSubview:title];

    UILabel *warning = [[UILabel alloc] init];
    warning.text = @"Diagnostic build. RootHide installation, jailbreak, kernel patches, and userspace reboot are disabled. This test only checks whether the app can be installed and opened.";
    warning.font = [UIFont systemFontOfSize:16];
    warning.textColor = [UIColor secondaryLabelColor];
    warning.textAlignment = NSTextAlignmentCenter;
    warning.numberOfLines = 0;
    [diagnostic addArrangedSubview:warning];

    UILabel *device = [[UILabel alloc] init];
    device.text = [NSString stringWithFormat:@"Device: %@\niOS: %@",
                   UIDevice.currentDevice.model, UIDevice.currentDevice.systemVersion];
    device.font = [UIFont monospacedSystemFontOfSize:14 weight:UIFontWeightRegular];
    device.textColor = [UIColor labelColor];
    device.textAlignment = NSTextAlignmentCenter;
    device.numberOfLines = 0;
    [diagnostic addArrangedSubview:device];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [diagnostic.centerXAnchor constraintEqualToAnchor:safe.centerXAnchor],
        [diagnostic.centerYAnchor constraintEqualToAnchor:safe.centerYAnchor],
        [diagnostic.leadingAnchor constraintGreaterThanOrEqualToAnchor:safe.leadingAnchor constant:24],
        [diagnostic.trailingAnchor constraintLessThanOrEqualToAnchor:safe.trailingAnchor constant:-24],
        [diagnostic.widthAnchor constraintLessThanOrEqualToConstant:390],
    ]];
    return;
#else
    UIStackView *stackView = [[UIStackView alloc] init];
    [stackView setAxis:UILayoutConstraintAxisVertical];
    [stackView setAlignment:UIStackViewAlignmentTrailing];
    [stackView setDistribution:UIStackViewDistributionEqualSpacing];
    [stackView setTranslatesAutoresizingMaskIntoConstraints:NO];

    [self.view addSubview:stackView];


    int statusBarHeight = fmax(15, [[UIApplication sharedApplication] keyWindow].safeAreaInsets.top - 20);

    [NSLayoutConstraint activateConstraints:@[
        [stackView.centerYAnchor constraintEqualToAnchor:self.view.centerYAnchor constant:statusBarHeight],//-35
        [stackView.heightAnchor constraintEqualToAnchor:self.view.heightAnchor multiplier:[DOGlobalAppearance isHomeButtonDevice] ? 0.78 : 0.73]
    ]];

    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPad)
    {
        NSLayoutConstraint *relativeWidthConstraint = [stackView.widthAnchor constraintEqualToAnchor:self.view.widthAnchor multiplier:0.8];
        relativeWidthConstraint.priority = UILayoutPriorityDefaultHigh;
        NSLayoutConstraint *maxWidthConstraint = [stackView.widthAnchor constraintLessThanOrEqualToConstant:UI_IPAD_MAX_WIDTH];
        maxWidthConstraint.priority = UILayoutPriorityRequired;

        [NSLayoutConstraint activateConstraints:@[
            relativeWidthConstraint,
            maxWidthConstraint,
            [stackView.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor]
        ]];
    }
    else
    {
        [NSLayoutConstraint activateConstraints:@[
            [stackView.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor constant:UI_PADDING],
            [stackView.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor constant:-UI_PADDING],
        ]];
    }

    //Header
    DOHeaderView *headerView = [[DOHeaderView alloc] initWithImage: [UIImage imageNamed:@"Dopamine"] subtitles: @[
        [DOGlobalAppearance mainSubtitleString:[[DOEnvironmentManager sharedManager] versionSupportString]],
        [DOGlobalAppearance secondarySubtitleString:DOLocalizedString(@"Credits_Made_By")],
    ]];
    
    [stackView addArrangedSubview:headerView];

    [NSLayoutConstraint activateConstraints:@[
        [headerView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor constant:5],
        [headerView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor]
    ]];

#if RH3_FULL_APP_EXPERIMENTAL
    UILabel *portNotice = [[UILabel alloc] init];
    portNotice.translatesAutoresizingMaskIntoConstraints = NO;
    portNotice.text = [DOBootstrapper rootHidePortEnabled] ?
        @"RootHide 3 — Experimental port; not validated on an iPhone" :
        @"RootHide 3 — Full Dopamine test build. Jailbreak disabled until runtime validation.";
    portNotice.font = [UIFont systemFontOfSize:12 weight:UIFontWeightSemibold];
    portNotice.textColor = [UIColor systemOrangeColor];
    portNotice.textAlignment = NSTextAlignmentCenter;
    portNotice.numberOfLines = 0;
    [stackView addArrangedSubview:portNotice];
    [NSLayoutConstraint activateConstraints:@[
        [portNotice.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor constant:8],
        [portNotice.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor constant:-8]
    ]];
#endif
    
    //Action Menu
    NSMutableArray<UIAction *> *mainMenuActions = [@[
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Settings_Title") image:[UIImage systemImageNamed:@"gearshape" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"settings" handler:^(__kindof UIAction * _Nonnull action) {
#if RH3_FULL_APP_EXPERIMENTAL
            if (![DOBootstrapper rootHidePortEnabled]) return;
#endif
            [self.navigationController pushViewController:[[DOSettingsController alloc] init] animated:YES];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Restart_SpringBoard_Title") image:[UIImage systemImageNamed:@"arrow.clockwise" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"respring" handler:^(__kindof UIAction * _Nonnull action) {
#if RH3_FULL_APP_EXPERIMENTAL
            if (![DOBootstrapper rootHidePortEnabled]) return;
#endif
            if ([DOBootstrapper rootHidePortEnabled]) {
                int result = [[DOEnvironmentManager sharedManager] respring];
                if (result != 0) {
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"No se pudo reiniciar SpringBoard"
                        message:[NSString stringWithFormat:@"La acción falló con el código %d.", result]
                        preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:alert animated:YES completion:nil];
                }
                return;
            }
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] respring];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Reboot_Userspace_Title") image:[UIImage systemImageNamed:@"arrow.clockwise.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"reboot-userspace" handler:^(__kindof UIAction * _Nonnull action) {
#if RH3_FULL_APP_EXPERIMENTAL
            if (![DOBootstrapper rootHidePortEnabled]) return;
#endif
            [self fadeToBlack:^{
                [[DOEnvironmentManager sharedManager] rebootUserspace];
            }];
        }],
        [UIAction actionWithTitle:DOLocalizedString(@"Menu_Credits_Title") image:[UIImage systemImageNamed:@"info.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"credits" handler:^(__kindof UIAction * _Nonnull action) {
            [self.navigationController pushViewController:[[DOCreditsViewController alloc] init] animated:YES];
        }]
    ] mutableCopy];
#if RH3_FULL_APP_EXPERIMENTAL
    // Keep the previous attempt accessible AFTER a reboot/panic. Do not
    // require jailbreak privileges, SSH or Sileo to export this sandbox file.
    [mainMenuActions addObject:[UIAction actionWithTitle:@"Share RootHide diagnostic log"
        image:[UIImage systemImageNamed:@"square.and.arrow.up"]
        identifier:@"rh3-share-previous-log"
        handler:^(__kindof UIAction * _Nonnull action) {
            NSURL *logURL = [[DOUIManager sharedInstance] rh3PreviousDiagnosticURL];
            if (!logURL) {
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"RootHide diagnostics"
                    message:@"No log has been recorded by this build. A previous IPA cannot recover its in-memory logs after a reboot."
                    preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:alert animated:YES completion:nil];
                return;
            }
            UIActivityViewController *share = [[UIActivityViewController alloc]
                initWithActivityItems:@[logURL] applicationActivities:nil];
            share.popoverPresentationController.sourceView = self.view;
            share.popoverPresentationController.sourceRect = CGRectMake(
                CGRectGetMidX(self.view.bounds), CGRectGetMidY(self.view.bounds), 1, 1);
            [self presentViewController:share animated:YES completion:nil];
        }]];
#endif
    DOActionMenuView *actionView = [[DOActionMenuView alloc] initWithActions:mainMenuActions delegate:self];
    
    [stackView addArrangedSubview: actionView];

    [NSLayoutConstraint activateConstraints:@[
        [actionView.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [actionView.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
    ]];
    
    
    UIView *buttonPlaceHolder = [[UIView alloc] init];
    [buttonPlaceHolder setTranslatesAutoresizingMaskIntoConstraints:NO];
    [stackView addArrangedSubview:buttonPlaceHolder];
    [NSLayoutConstraint activateConstraints:@[
        [buttonPlaceHolder.heightAnchor constraintEqualToConstant:60]
    ]];
    
    //Jailbreak Button
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken] || [[DOEnvironmentManager sharedManager] isJailbrokenWithOtherJailbreak];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];

    NSString *jailbreakButtonTitle = [self jailbreakButtonTitle];
        
    UIImage *jailbreakButtonImage;
    if (isSupported)
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.open" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    else
        jailbreakButtonImage = [UIImage systemImageNamed:@"lock.slash" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]];
    
    self.jailbreakBtn = [[DOJailbreakButton alloc] initWithAction: [UIAction actionWithTitle:jailbreakButtonTitle image:jailbreakButtonImage identifier:@"jailbreak" handler:^(__kindof UIAction * _Nonnull action) {
        [actionView hide];
        [self.jailbreakBtn expandButton: self.jailbreakButtonConstraints];

        self.updateButton.userInteractionEnabled = NO;
        [UIView animateWithDuration:0.75 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
            [headerView setTransform:CGAffineTransformMakeTranslation(0, -25)];
            self.updateButton.alpha = 0;
        } completion:nil];
        
        [self startJailbreak];
        
    }]];
    self.jailbreakBtn.enabled = !isJailbroken && isSupported;
#if RH3_FULL_APP_EXPERIMENTAL
    // Do not offer stock Dopamine jailbreak or removal through the separate
    // RootHide full build when its RootHide-specific runtime gate is closed.
    self.jailbreakBtn.enabled = self.jailbreakBtn.enabled &&
                                [DOBootstrapper rootHidePortEnabled];
#endif

    [self.view addSubview:self.jailbreakBtn];

    [NSLayoutConstraint activateConstraints:(self.jailbreakButtonConstraints = @[
        [self.jailbreakBtn.leadingAnchor constraintEqualToAnchor:stackView.leadingAnchor],
        [self.jailbreakBtn.trailingAnchor constraintEqualToAnchor:stackView.trailingAnchor],
        [self.jailbreakBtn.heightAnchor constraintEqualToAnchor:buttonPlaceHolder.heightAnchor],
        [self.jailbreakBtn.centerYAnchor constraintEqualToAnchor:buttonPlaceHolder.centerYAnchor]
    ])];

#if !RH3_FULL_APP_EXPERIMENTAL
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 0.1 * NSEC_PER_SEC), dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_LOW, 0), ^{
        if ([[DOUIManager sharedInstance] environmentUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:YES];
            });
        }
        else if ([[DOUIManager sharedInstance] isUpdateAvailable])
        {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self setupUpdateAvailable:NO];
            });
        }
    });
#endif
#endif // RH3_INSTALLABLE_DIAGNOSTIC
}

- (NSString *)jailbreakButtonTitle
{
#if RH3_FULL_APP_EXPERIMENTAL
    if (![DOBootstrapper rootHidePortEnabled]) {
        return @"RootHide runtime unavailable";
    }
#endif
    BOOL isJailbroken = [[DOEnvironmentManager sharedManager] isJailbroken];
    BOOL isSupported = [[DOEnvironmentManager sharedManager] isSupported];
    BOOL removeJailbreakEnabled = [[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"removeJailbreakEnabled" fallback:NO];

    NSString *jailbreakButtonTitle = DOLocalizedString(@"Button_Jailbreak_Title");
    if (!isSupported)
        jailbreakButtonTitle = DOLocalizedString(@"Unsupported");
    else if (isJailbroken)
        jailbreakButtonTitle = DOLocalizedString(@"Status_Title_Jailbroken");
    else if (removeJailbreakEnabled)
        jailbreakButtonTitle = DOLocalizedString(@"Button_Remove_Jailbreak");
    
    return jailbreakButtonTitle;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
#if !RH3_INSTALLABLE_DIAGNOSTIC
    [self.jailbreakBtn.button setTitle:[self jailbreakButtonTitle] forState:UIControlStateNormal];
#endif
}

- (void)startJailbreak
{
#if RH3_INSTALLABLE_DIAGNOSTIC
    // Defense in depth: no indirect call into the jailbreak UI flow.
    return;
#else
#if RH3_FULL_APP_EXPERIMENTAL
    if (![DOBootstrapper rootHidePortEnabled]) return;
#endif
    DOJailbreaker *jailbreaker = [[DOJailbreaker alloc] init];

    [[DOUIManager sharedInstance] startLogCapture];
    
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
#if RH3_FULL_APP_EXPERIMENTAL
        // Even the contiguous-memory workaround can restart backboardd. Reject
        // incompatible hardware, foreign roots and damaged assets before it.
        NSError *preflightError = [jailbreaker rootHidePreflightError];
        if (preflightError) {
            [[DOUIManager sharedInstance] sendLog:preflightError.localizedDescription debug:NO];
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *alert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Log_Error")
                    message:preflightError.localizedDescription preferredStyle:UIAlertControllerStyleAlert];
                [alert addAction:[UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Close")
                    style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) { exit(0); }]];
                [self presentViewController:alert animated:YES completion:nil];
            });
            return;
        }
#endif
        if ([jailbreaker contiguousMappingWorkaroundNeeded]) {
            
            cpu_subtype_t cpuFamily = 0;
            size_t cpuFamilySize = sizeof(cpuFamily);
            sysctlbyname("hw.cpufamily", &cpuFamily, &cpuFamilySize, NULL, 0);
            NSString *workaroundMessage = DOLocalizedString(@"Respring_Required_Message");
            if (cpuFamily == CPUFAMILY_ARM_TYPHOON) {
                workaroundMessage = [workaroundMessage stringByAppendingString:[NSString stringWithFormat:@"\n\n%@", DOLocalizedString(@"Respring_Required_Notice_A8")]];
            }

            UIAlertController *contiguousMappingWorkaroundAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Respring_Required") message:workaroundMessage preferredStyle:UIAlertControllerStyleAlert];
            
            UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Respring_Cancel") style:UIAlertActionStyleCancel handler:^(UIAlertAction * _Nonnull action) {
                exit(0);
            }];
            
            UIAlertAction *workaroundAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Apply_Workaround") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                [jailbreaker applyContiguousMappingWorkaround];
            }];
            
            [contiguousMappingWorkaroundAlertController addAction:cancelAction];
            [contiguousMappingWorkaroundAlertController addAction:workaroundAction];
            contiguousMappingWorkaroundAlertController.preferredAction = workaroundAction;

            dispatch_async(dispatch_get_main_queue(), ^{
                [self presentViewController:contiguousMappingWorkaroundAlertController animated:YES completion:nil];
            });
            return;
        }

        //We need to get the preconfig mutex to start the jailbreak (self.jailbreakBtn.canStartJailbreak)
        [self.jailbreakBtn lockMutex];
        dispatch_async(dispatch_get_main_queue(), ^{
            self.hideHomeIndicator = YES;
        });

        NSError *error;
        BOOL didRemove = NO;
        BOOL showLogs = YES;
        [jailbreaker runWithError:&error didRemoveJailbreak:&didRemove showLogs:&showLogs];
#if RH3_FULL_APP_EXPERIMENTAL
        if (error) [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
            [NSString stringWithFormat:@"END FAILED: %@", error.localizedDescription]];
#endif
        dispatch_async(dispatch_get_main_queue(), ^{
            if (error && showLogs) {
                [[DOUIManager sharedInstance] sendLog:[NSString stringWithFormat:@"Jailbreak failed with error: %@", error] debug:NO];
                [self.navigationController pushViewController:[[DOLogCrashViewController alloc] initWithTitle:[error localizedDescription]] animated:YES];
            }
            else if (error && !showLogs) {
                // Used when there is an error that is explainable in such detail that additional logs are not needed
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Log_Error") message:[error localizedDescription] preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Reboot") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exec_cmd_trusted(JBROOT_PATH("/sbin/reboot"), NULL);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else if (didRemove) {
                UIAlertController *alertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Removed_Jailbreak_Alert_Title") message:DOLocalizedString(@"Removed_Jailbreak_Alert_Message") preferredStyle:UIAlertControllerStyleAlert];
                UIAlertAction *rebootAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Close") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
                    exit(0);
                }];
                [alertController addAction:rebootAction];
                [self presentViewController:alertController animated:YES completion:nil];
            }
            else {
                // No errors
                [[DOUIManager sharedInstance] completeJailbreak];
                [self fadeToBlack: ^{
                    [jailbreaker finalize];
                }];
            }
        });
        [self.jailbreakBtn unlockMutex];
    });
#endif
}

-(void)setupUpdateAvailable:(BOOL)environmentUpdate
{
#if RH3_INSTALLABLE_DIAGNOSTIC || RH3_FULL_APP_EXPERIMENTAL
    // No update navigation or installed-jailbreak probing in the device test.
    return;
#else
    if (self.jailbreakBtn.didExpand)
        return;

    NSString *title = environmentUpdate ? DOLocalizedString(@"Button_Update_Environment") : DOLocalizedString(@"Button_Update_Available");
    
    NSString *releaseFrom = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    NSString *releaseTo = [[DOUIManager sharedInstance] getLatestReleaseTag];

    if (environmentUpdate)
    {
        releaseFrom = [[DOEnvironmentManager sharedManager] jailbrokenVersion];
        releaseTo = [[DOUIManager sharedInstance] getLaunchedReleaseTag];
    }

    self.updateButton = [DOActionMenuButton buttonWithAction:[UIAction actionWithTitle:title image:[UIImage systemImageNamed:@"arrow.down.circle" withConfiguration:[DOGlobalAppearance smallIconImageConfiguration]] identifier:@"update-available" handler:^(__kindof UIAction * _Nonnull action) {
        [self.navigationController pushViewController:[[DOUpdateViewController alloc] initFromTag:releaseFrom toTag:releaseTo] animated:YES];
    }] chevron:NO];

    self.updateButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:self.updateButton];

    [NSLayoutConstraint activateConstraints:@[
        [self.updateButton.centerXAnchor constraintEqualToAnchor:self.view.centerXAnchor],
        [self.updateButton.heightAnchor constraintEqualToConstant:30],
        [self.updateButton.bottomAnchor constraintEqualToAnchor:self.jailbreakBtn.topAnchor constant:[DOGlobalAppearance isHomeButtonDevice] ? -10 : -20]
    ]];

    [self.updateButton setTransform:CGAffineTransformMakeTranslation(0, 25)];
    [self.updateButton setAlpha:0];
    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0  options: UIViewAnimationOptionCurveEaseInOut animations:^{
        [self.updateButton setTransform:CGAffineTransformIdentity];
        [self.updateButton setAlpha:1];
    } completion:nil];
#endif
}

-(void)simulateJailbreak
{
    // Let's simulate a "jailbreak" using grand central dispatch

    DOUIManager *uiManager = [DOUIManager sharedInstance];

    static BOOL didFinish = NO; //not thread safe lol
    

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
        [uiManager completeJailbreak];
        [uiManager sendLog:@"Rebooting Userspace" debug: NO];
        didFinish = YES;
        [self fadeToBlack: ^{

        }];
    });

    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        [NSThread sleepForTimeInterval:0.2];
        [uiManager sendLog:@"Launching kexploitd" debug: NO];
        [NSThread sleepForTimeInterval:0.5];
        [uiManager sendLog:@"Launching oobPCI" debug: NO];
        [NSThread sleepForTimeInterval:0.15];
        [uiManager sendLog:@"Gaining r/w" debug: NO];
        [NSThread sleepForTimeInterval:0.8];
        [uiManager sendLog:@"Patchfinding" debug: NO];
        NSArray *types = @[@"AMFI", @"PAC", @"KTRR", @"KPP", @"PPL", @"KPF", @"APRR", @"AMCC", @"PAN", @"PXN", @"ASLR", @"OPA"]; //Ever heard of the legendary opa bypass
        while (true)
        {
            [NSThread sleepForTimeInterval:0.6 * rand() / RAND_MAX];
            if (didFinish) break;
            NSString *type = types[arc4random_uniform((uint32_t)types.count)];
            [uiManager sendLog:[NSString stringWithFormat:@"Bypassing %@", type] debug: NO];
        }
    });
}

- (void)fadeToBlack:(void (^)(void))completion
{
    static bool didFade = false;
    if (didFade)
        return;
    didFade = true;
    UIView *mainView = self.parentViewController.view;
    float deviceCornerRadius = [[[UIScreen mainScreen] valueForKey:@"_displayCornerRadius"] floatValue];

    mainView.layer.cornerRadius = deviceCornerRadius;
    mainView.layer.cornerCurve = kCACornerCurveContinuous;
    mainView.layer.masksToBounds = YES;
    
    self.hideStatusBar = YES;

    [UIView animateWithDuration:0.5 delay:0 usingSpringWithDamping:0.9 initialSpringVelocity:2.0 options: UIViewAnimationOptionCurveEaseInOut animations:^{
        mainView.transform = CGAffineTransformMakeScale(0.9, 0.9);
        mainView.alpha = 0.0;
    } completion:^(BOOL success) {
        completion();
    }];
}

#pragma mark - Action Menu Delegate

- (BOOL)actionMenuShowsChevronForAction:(UIAction *)action
{
    if ([action.identifier isEqualToString:@"settings"] || [action.identifier isEqualToString:@"credits"]) return YES;
    return NO;
}

- (BOOL)actionMenuActionIsEnabled:(UIAction *)action
{
#if RH3_FULL_APP_EXPERIMENTAL
    if (![DOBootstrapper rootHidePortEnabled] &&
        ([action.identifier isEqualToString:@"settings"] ||
         [action.identifier isEqualToString:@"respring"] ||
         [action.identifier isEqualToString:@"reboot-userspace"])) return NO;
#endif
    if ([action.identifier isEqualToString:@"respring"] || [action.identifier isEqualToString:@"reboot-userspace"]) {
        return [[DOEnvironmentManager sharedManager] isJailbroken];
    }
    return YES;
}

#pragma mark - Status Bar

- (UIStatusBarStyle)preferredStatusBarStyle
{
    return UIStatusBarStyleLightContent;
}

- (BOOL)prefersStatusBarHidden
{
    return self.hideStatusBar;
}

- (BOOL)prefersHomeIndicatorAutoHidden
{
    return self.hideHomeIndicator;
}

- (void)setHideStatusBar:(BOOL)hideStatusBar
{
    _hideStatusBar = hideStatusBar;
    [self setNeedsStatusBarAppearanceUpdate];
}

- (void)setHideHomeIndicator:(BOOL)hideHomeIndicator
{
    _hideHomeIndicator = hideHomeIndicator;
    [self setNeedsUpdateOfHomeIndicatorAutoHidden];
}

@end
