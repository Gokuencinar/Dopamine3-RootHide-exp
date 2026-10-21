//
//  DOSettingsController.m
//  Dopamine
//
//  Created by tomt000 on 08/01/2024.
//

#import "DOSettingsController.h"
#import <objc/runtime.h>
#import <Photos/Photos.h>
#import <libjailbreak/util.h>
#import "DOUIManager.h"
#import "DOPkgManagerPickerViewController.h"
#import "DOHeaderCell.h"
#import "DOEnvironmentManager.h"
#import "DOExploitManager.h"
#import "DOPSListItemsController.h"
#import "DOPSExploitListItemsController.h"
#import "DOThemeManager.h"
#import "DOSceneDelegate.h"
#import "DOPSJetsamListItemsController.h"
#import "DOButtonCell.h"
#include <errno.h>

#ifndef RH3_FULL_APP_EXPERIMENTAL
#define RH3_FULL_APP_EXPERIMENTAL 0
#endif

// Accessed only by UIKit callbacks on the main queue. A timed-out worker may
// still be running, so closing its progress alert must not permit a duplicate.
static BOOL gRootHideAppsRefreshInFlight = NO;
static BOOL gRootHideProviderRepairInFlight = NO;

@interface DOSettingsController ()

@end

@implementation DOSettingsController

- (void)viewDidLoad
{
    _lastKnownTheme = [[DOThemeManager sharedInstance] enabledTheme].key;
    [super viewDidLoad];
}

- (void)viewWillAppear:(BOOL)arg1
{
    [super viewWillAppear:arg1];
    if (_lastKnownTheme != [[DOThemeManager sharedInstance] enabledTheme].key)
    {
        [DOSceneDelegate relaunch];
        NSString *icon = [[DOThemeManager sharedInstance] enabledTheme].icon;
        [[UIApplication sharedApplication] setAlternateIconName:icon completionHandler:^(NSError * _Nullable error) {
            if (error)
                NSLog(@"Error changing app icon: %@", error);
        }];

#if !RH3_FULL_APP_EXPERIMENTAL
        if ([DOEnvironmentManager sharedManager].isJailbroken) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                [[DOEnvironmentManager sharedManager] updateBootLogo];
            });
        }
#endif
    }
}

- (NSArray *)availableKernelExploitIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    for (DOExploit *exploit in _availableKernelExploits) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availableKernelExploitNames
{
    NSMutableArray *names = [NSMutableArray new];
    for (DOExploit *exploit in _availableKernelExploits) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)availablePACBypassIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    if (![DOEnvironmentManager sharedManager].isPACBypassRequired) {
        [identifiers addObject:@"none"];
    }
    for (DOExploit *exploit in _availablePACBypasses) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availablePACBypassNames
{
    NSMutableArray *names = [NSMutableArray new];
    if (![DOEnvironmentManager sharedManager].isPACBypassRequired) {
        [names addObject:DOLocalizedString(@"None")];
    }
    for (DOExploit *exploit in _availablePACBypasses) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)availablePPLBypassIdentifiers
{
    NSMutableArray *identifiers = [NSMutableArray new];
    for (DOExploit *exploit in _availablePPLBypasses) {
        [identifiers addObject:exploit.identifier];
    }
    return identifiers;
}

- (NSArray *)availablePPLBypassNames
{
    NSMutableArray *names = [NSMutableArray new];
    for (DOExploit *exploit in _availablePPLBypasses) {
        [names addObject:exploit.name];
    }
    return names;
}

- (NSArray *)themeIdentifiers
{
    return [[DOThemeManager sharedInstance] getAvailableThemeKeys];
}

- (NSArray *)themeNames
{
    return [[DOThemeManager sharedInstance] getAvailableThemeNames];
}

- (NSArray *)jetsamOptionNumbers
{
    return @[
    @2,
    @3,
    @4,
    @5,
    @6,
    @7,
    @8,
    ];
}

- (NSArray *)jetsamOptionTitles
{
    return @[
        @"1x",
        @"1.5x",
        @"2x",
        @"2.5x",
        [NSString stringWithFormat:@"3x (%@)", DOLocalizedString(@"Recommended")],
        @"3.5x",
        @"4x",
    ];
}

- (id)specifiers
{
    if(_specifiers == nil) {
        NSMutableArray *specifiers = [NSMutableArray new];
        DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
        DOExploitManager *exploitManager = [DOExploitManager sharedManager];

        NSNumber *buttonHeight = @(44);
        
        SEL defGetter = @selector(readPreferenceValue:);
        SEL defSetter = @selector(setPreferenceValue:specifier:);
        SEL expGetter = @selector(readExploitPreferenceValue:);
        
        NSSortDescriptor *prioritySortDescriptor = [NSSortDescriptor sortDescriptorWithKey:@"priority" ascending:NO];
        
        _availableKernelExploits = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_KERNEL] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
        if (envManager.isArm64e) {
            _availablePACBypasses = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_PAC] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
            _availablePPLBypasses = [[exploitManager availableExploitsForType:EXPLOIT_TYPE_PPL] sortedArrayUsingDescriptors:@[prioritySortDescriptor]];
        }
        
        PSSpecifier *headerSpecifier = [PSSpecifier emptyGroupSpecifier];
        [headerSpecifier setProperty:@"DOHeaderCell" forKey:@"headerCellClass"];
        [headerSpecifier setProperty:[NSString stringWithFormat:@"Settings"] forKey:@"title"];
        [specifiers addObject:headerSpecifier];
        
        if (envManager.isSupported) {
            if (!envManager.isJailbroken) {
                PSSpecifier *exploitGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                exploitGroupSpecifier.name = DOLocalizedString(@"Section_Exploits");
                [specifiers addObject:exploitGroupSpecifier];
                
                PSSpecifier *kernelExploitSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Kernel Exploit") target:self set:defSetter get:expGetter detail:nil cell:PSLinkListCell edit:nil];
                [kernelExploitSpecifier setProperty:@YES forKey:@"enabled"];
                [kernelExploitSpecifier setProperty:exploitManager.preferredKernelExploit.identifier forKey:@"default"];
                kernelExploitSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                [kernelExploitSpecifier setProperty:@"availableKernelExploitIdentifiers" forKey:@"valuesDataSource"];
                [kernelExploitSpecifier setProperty:@"availableKernelExploitNames" forKey:@"titlesDataSource"];
                [kernelExploitSpecifier setProperty:@"selectedKernelExploit" forKey:@"key"];
                [kernelExploitSpecifier setProperty:(_availableKernelExploits.firstObject.identifier ?: @"none") forKey:@"recommendedExploitIdentifier"];
                [specifiers addObject:kernelExploitSpecifier];
                
                if (envManager.isArm64e) {
                    PSSpecifier *pacBypassSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"PAC Bypass") target:self set:defSetter get:expGetter detail:nil cell:PSLinkListCell edit:nil];
                    [pacBypassSpecifier setProperty:@YES forKey:@"enabled"];
                    DOExploit *preferredPACBypass = exploitManager.preferredPACBypass;
                    if (!preferredPACBypass) {
                        [pacBypassSpecifier setProperty:@"none" forKey:@"default"];
                    }
                    else {
                        [pacBypassSpecifier setProperty:preferredPACBypass.identifier forKey:@"default"];
                    }
                    pacBypassSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                    [pacBypassSpecifier setProperty:@"availablePACBypassIdentifiers" forKey:@"valuesDataSource"];
                    [pacBypassSpecifier setProperty:@"availablePACBypassNames" forKey:@"titlesDataSource"];
                    [pacBypassSpecifier setProperty:@"selectedPACBypass" forKey:@"key"];
                    [pacBypassSpecifier setProperty:([envManager isPACBypassRequired] ? _availablePACBypasses.firstObject.identifier : @"none") forKey:@"recommendedExploitIdentifier"];
                    [specifiers addObject:pacBypassSpecifier];
                    
                    NSString *pplBypassName = @"PPL Bypass";
                    if ([DOEnvironmentManager sharedManager].isSPTM) {
                        // SPTM bypasses are also handled as PPL bypasses in the code, we just change the name of the setting in the UI
                        pplBypassName = @"SPTM Bypass";
                    }

                    PSSpecifier *pplBypassSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(pplBypassName) target:self set:defSetter get:expGetter detail:nil cell:PSLinkListCell edit:nil];
                    [pplBypassSpecifier setProperty:@YES forKey:@"enabled"];
                    [pplBypassSpecifier setProperty:exploitManager.preferredPPLBypass.identifier forKey:@"default"];
                    pplBypassSpecifier.detailControllerClass = [DOPSExploitListItemsController class];
                    [pplBypassSpecifier setProperty:@"availablePPLBypassIdentifiers" forKey:@"valuesDataSource"];
                    [pplBypassSpecifier setProperty:@"availablePPLBypassNames" forKey:@"titlesDataSource"];
                    [pplBypassSpecifier setProperty:@"selectedPPLBypass" forKey:@"key"];
                    [pplBypassSpecifier setProperty:(_availablePPLBypasses.firstObject.identifier ?: @"none") forKey:@"recommendedExploitIdentifier"];
                    [specifiers addObject:pplBypassSpecifier];
                }
            }
            
            PSSpecifier *settingsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
            settingsGroupSpecifier.name = DOLocalizedString(@"Section_Jailbreak_Settings");
            [specifiers addObject:settingsGroupSpecifier];
            
            PSSpecifier *tweakInjectionSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Tweak_Injection") target:self set:@selector(setTweakInjectionEnabled:specifier:) get:@selector(readTweakInjectionEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [tweakInjectionSpecifier setProperty:@YES forKey:@"enabled"];
            [tweakInjectionSpecifier setProperty:@"tweakInjectionEnabled" forKey:@"key"];
            [tweakInjectionSpecifier setProperty:@YES forKey:@"default"];
            [specifiers addObject:tweakInjectionSpecifier];
            
            if (!envManager.isJailbroken) {
                PSSpecifier *verboseLogSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Verbose_Logs") target:self set:defSetter get:defGetter detail:nil cell:PSSwitchCell edit:nil];
                [verboseLogSpecifier setProperty:@YES forKey:@"enabled"];
                [verboseLogSpecifier setProperty:@"verboseLogsEnabled" forKey:@"key"];
                [verboseLogSpecifier setProperty:@NO forKey:@"default"];
                [specifiers addObject:verboseLogSpecifier];
            }
            
#if RH3_FULL_APP_EXPERIMENTAL
            if (!envManager.isJailbroken) {
                PSSpecifier *recovery = [PSSpecifier preferenceSpecifierNamed:@"Recuperar instalación interrumpida" target:self set:defSetter get:defGetter detail:nil cell:PSSwitchCell edit:nil];
                [recovery setProperty:@"rootHideRecoveryRequested" forKey:@"key"];
                [recovery setProperty:@NO forKey:@"default"];
                [specifiers addObject:recovery];
                PSSpecifier *hint = [PSSpecifier emptyGroupSpecifier];
                [hint setProperty:@"Reinicia el iPhone antes. Al pulsar Jailbreak se conservará el entorno fallido y se creará uno nuevo. Las copias anteriores se mantienen. La opción se consume en un intento." forKey:@"footerText"];
                [specifiers addObject:hint];
            }
#endif

            PSSpecifier *idownloadSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_iDownload") target:self set:@selector(setIDownloadEnabled:specifier:) get:@selector(readIDownloadEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [idownloadSpecifier setProperty:@YES forKey:@"enabled"];
            [idownloadSpecifier setProperty:@"idownloadEnabled" forKey:@"key"];
            [idownloadSpecifier setProperty:@NO forKey:@"default"];
            [specifiers addObject:idownloadSpecifier];
            
            PSSpecifier *appJitSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Apps_JIT") target:self set:@selector(setAppJITEnabled:specifier:) get:@selector(readAppJITEnabled:) detail:nil cell:PSSwitchCell edit:nil];
            [appJitSpecifier setProperty:@YES forKey:@"enabled"];
            [appJitSpecifier setProperty:@"appJITEnabled" forKey:@"key"];
            [appJitSpecifier setProperty:@YES forKey:@"default"];
            [specifiers addObject:appJitSpecifier];
            
            PSSpecifier *jetsamSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Settings_Jetsam_Multiplier") target:self set:@selector(setJetsamMultiplier:specifier:) get:@selector(readJetsamMultiplier:) detail:nil cell:PSLinkListCell edit:nil];
            [jetsamSpecifier setProperty:@YES forKey:@"enabled"];
            [jetsamSpecifier setProperty:@"jetsamMultiplier" forKey:@"key"];
            [jetsamSpecifier setProperty:@6 forKey:@"default"];
            jetsamSpecifier.detailControllerClass = [DOPSJetsamListItemsController class];
            [jetsamSpecifier setProperty:@"jetsamOptionNumbers" forKey:@"valuesDataSource"];
            [jetsamSpecifier setProperty:@"jetsamOptionTitles" forKey:@"titlesDataSource"];
            [specifiers addObject:jetsamSpecifier];
            
            if (!envManager.isJailbroken && !envManager.isInstalledThroughTrollStore) {
                PSSpecifier *removeJailbreakSwitchSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Button_Remove_Jailbreak") target:self set:@selector(setRemoveJailbreakEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
                [removeJailbreakSwitchSpecifier setProperty:@YES forKey:@"enabled"];
                [removeJailbreakSwitchSpecifier setProperty:@"removeJailbreakEnabled" forKey:@"key"];
                [specifiers addObject:removeJailbreakSwitchSpecifier];
            }

            if (envManager.isBootstrapped) {
                PSSpecifier *actionsGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
                actionsGroupSpecifier.name = DOLocalizedString(@"Section_Actions");
                [specifiers addObject:actionsGroupSpecifier];

                if (envManager.isJailbroken) {
                    PSSpecifier *refreshAppsSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [refreshAppsSpecifier setProperty:@"Button_Refresh_Jailbreak_Apps" forKey:@"title"];
                    [refreshAppsSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [refreshAppsSpecifier setProperty:buttonHeight forKey:@"height"];
                    [refreshAppsSpecifier setProperty:@"arrow.triangle.2.circlepath" forKey:@"image"];
                    [refreshAppsSpecifier setProperty:@"refreshJailbreakAppsPressed" forKey:@"action"];
                    [specifiers addObject:refreshAppsSpecifier];
                    
                    PSSpecifier *changeMobilePasswordSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [changeMobilePasswordSpecifier setProperty:@"Button_Change_Mobile_Password" forKey:@"title"];
                    [changeMobilePasswordSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [changeMobilePasswordSpecifier setProperty:buttonHeight forKey:@"height"];
                    [changeMobilePasswordSpecifier setProperty:@"key" forKey:@"image"];
                    [changeMobilePasswordSpecifier setProperty:@"changeMobilePasswordWithAuthenticationPressed" forKey:@"action"];
                    [specifiers addObject:changeMobilePasswordSpecifier];
                    
                    PSSpecifier *reinstallPackageManagersSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [reinstallPackageManagersSpecifier setProperty:@"Button_Reinstall_Package_Managers" forKey:@"title"];
                    [reinstallPackageManagersSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [reinstallPackageManagersSpecifier setProperty:buttonHeight forKey:@"height"];
                    if (@available(iOS 16.0, *))
                        [reinstallPackageManagersSpecifier setProperty:@"shippingbox.and.arrow.backward" forKey:@"image"];
                    else
                        [reinstallPackageManagersSpecifier setProperty:@"shippingbox" forKey:@"image"];
                    [reinstallPackageManagersSpecifier setProperty:@"reinstallPackageManagersPressed" forKey:@"action"];
                    [specifiers addObject:reinstallPackageManagersSpecifier];
                    if ([DOBootstrapper rootHidePortEnabled]) {
                        PSSpecifier *repairProvider = [PSSpecifier preferenceSpecifierNamed:@"Reparar dependencia libkrw (Sileo)" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                        [repairProvider setProperty:[DOButtonCell class] forKey:@"cellClass"];
                        [repairProvider setProperty:buttonHeight forKey:@"height"];
                        [repairProvider setProperty:@"wrench.adjustable" forKey:@"image"];
                        [repairProvider setProperty:@"repairRootHideLibkrwPressed" forKey:@"action"];
                        [specifiers addObject:repairProvider];
                        PSSpecifier *diagnoseRuntime = [PSSpecifier preferenceSpecifierNamed:@"Diagnosticar tweaks, NewTerm y SSH" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                        [diagnoseRuntime setProperty:[DOButtonCell class] forKey:@"cellClass"];
                        [diagnoseRuntime setProperty:buttonHeight forKey:@"height"];
                        [diagnoseRuntime setProperty:@"stethoscope" forKey:@"image"];
                        [diagnoseRuntime setProperty:@"diagnoseRootHideRuntimePressed" forKey:@"action"];
                        [specifiers addObject:diagnoseRuntime];
                        PSSpecifier *probeTweaks = [PSSpecifier preferenceSpecifierNamed:@"Verificar carga real de tweaks" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                        [probeTweaks setProperty:[DOButtonCell class] forKey:@"cellClass"];
                        [probeTweaks setProperty:buttonHeight forKey:@"height"];
                        [probeTweaks setProperty:@"checkmark.shield" forKey:@"image"];
                        [probeTweaks setProperty:@"verifyRootHideTweaksPressed" forKey:@"action"];
                        [specifiers addObject:probeTweaks];
                        PSSpecifier *repairSSH = [PSSpecifier preferenceSpecifierNamed:@"Preparar OpenSSH en RootHide" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                        [repairSSH setProperty:[DOButtonCell class] forKey:@"cellClass"];
                        [repairSSH setProperty:buttonHeight forKey:@"height"];
                        [repairSSH setProperty:@"key.horizontal" forKey:@"image"];
                        [repairSSH setProperty:@"repairRootHideSSHPressed" forKey:@"action"];
                        [specifiers addObject:repairSSH];
                        PSSpecifier *sshSocket = [PSSpecifier preferenceSpecifierNamed:@"Diagnosticar arranque de OpenSSH (solo lectura)" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                        [sshSocket setProperty:[DOButtonCell class] forKey:@"cellClass"];
                        [sshSocket setProperty:buttonHeight forKey:@"height"];
                        [sshSocket setProperty:@"waveform.path.ecg" forKey:@"image"];
                        [sshSocket setProperty:@"diagnoseRootHideOpenSSHSocketPressed" forKey:@"action"];
                        [specifiers addObject:sshSocket];
                    }
                }

                BOOL hideJailbreakButtonShown =
                    ![DOBootstrapper rootHidePortEnabled] &&
                    (envManager.isJailbroken || (envManager.isInstalledThroughTrollStore && !envManager.isJailbreakHidden));
                if (hideJailbreakButtonShown) {
                    // The "Hide Jailbreak" button should be shown
                    // - When jailbroken
                    // - When Dopamine is installed by TrollStore and the jailbreak is not hidden yet
                    PSSpecifier *hideUnhideJailbreakSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [hideUnhideJailbreakSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [hideUnhideJailbreakSpecifier setProperty:buttonHeight forKey:@"height"];
                    if (envManager.isJailbreakHidden) {
                        [hideUnhideJailbreakSpecifier setProperty:@"Button_Unhide_Jailbreak" forKey:@"title"];
                        [hideUnhideJailbreakSpecifier setProperty:@"eye" forKey:@"image"];
                    }
                    else {
                        [hideUnhideJailbreakSpecifier setProperty:@"Button_Hide_Jailbreak" forKey:@"title"];
                        [hideUnhideJailbreakSpecifier setProperty:@"eye.slash" forKey:@"image"];
                    }
                    [hideUnhideJailbreakSpecifier setProperty:@"hideUnhideJailbreakPressed" forKey:@"action"];
                    [specifiers addObject:hideUnhideJailbreakSpecifier];
                }

                if (!envManager.isJailbroken && envManager.isInstalledThroughTrollStore) {
                    // The "Remove Jailbreak" button cannot show when being jailbroken since pressing it would kinda be russian roulette
                    // It might work, it might not and panic your device and leave it in a half uninstalled state
                    // So this button is only for when you're not jailbroken and have Dopamine installed with TrollStore
                    // The only supported uninstallation flow without TrollStore is to reboot and "rejailbreak" with "Remove Jailbreak" toggle enabled
                    PSSpecifier *removeJailbreakSpecifier = [PSSpecifier preferenceSpecifierNamed:@"" target:self set:defSetter get:defGetter detail:nil cell:PSStaticTextCell edit:nil];
                    [removeJailbreakSpecifier setProperty:@"Button_Remove_Jailbreak" forKey:@"title"];
                    [removeJailbreakSpecifier setProperty:[DOButtonCell class] forKey:@"cellClass"];
                    [removeJailbreakSpecifier setProperty:buttonHeight forKey:@"height"];
                    [removeJailbreakSpecifier setProperty:@"trash" forKey:@"image"];
                    [removeJailbreakSpecifier setProperty:@"removeJailbreakPressed" forKey:@"action"];
                    [specifiers addObject:removeJailbreakSpecifier];
                }
                
                if (hideJailbreakButtonShown) {
                    [actionsGroupSpecifier setProperty:DOLocalizedString(envManager.isJailbroken ? @"Hint_Hide_Jailbreak_Jailbroken" : @"Hint_Hide_Jailbreak") forKey:@"footerText"];
                }
            }
        }
        
        PSSpecifier *themingGroupSpecifier = [PSSpecifier emptyGroupSpecifier];
        themingGroupSpecifier.name = DOLocalizedString(@"Section_Customization");
        [specifiers addObject:themingGroupSpecifier];
        
        PSSpecifier *themeSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Theme") target:self set:defSetter get:defGetter detail:nil cell:PSLinkListCell edit:nil];
        themeSpecifier.detailControllerClass = [DOPSListItemsController class];
        [themeSpecifier setProperty:@YES forKey:@"enabled"];
        [themeSpecifier setProperty:@"theme" forKey:@"key"];
        [themeSpecifier setProperty:[[self themeIdentifiers] firstObject] forKey:@"default"];
        [themeSpecifier setProperty:@"themeIdentifiers" forKey:@"valuesDataSource"];
        [themeSpecifier setProperty:@"themeNames" forKey:@"titlesDataSource"];
        [specifiers addObject:themeSpecifier];

        PSSpecifier *bootlogoGropSpecifier = [PSSpecifier emptyGroupSpecifier];
        bootlogoGropSpecifier.name = DOLocalizedString(@"Section_Boot_Logo");
        [specifiers addObject:bootlogoGropSpecifier];

        PSSpecifier *bootlogoEnabledSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Enabled") target:self set:@selector(setBootlogoEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [bootlogoEnabledSpecifier setProperty:@YES forKey:@"enabled"];
        [bootlogoEnabledSpecifier setProperty:@"bootlogoEnabled" forKey:@"key"];
        [bootlogoEnabledSpecifier setProperty:@YES forKey:@"default"];
        bootlogoEnabledSpecifier.identifier = @"bootlogoEnabled";
        [specifiers addObject:bootlogoEnabledSpecifier];

        _customBootlogoEnabledSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Custom_Boot_Logo") target:self set:@selector(setCustomBootlogoEnabled:specifier:) get:defGetter detail:nil cell:PSSwitchCell edit:nil];
        [_customBootlogoEnabledSpecifier setProperty:@YES forKey:@"enabled"];
        [_customBootlogoEnabledSpecifier setProperty:@"customBootlogoEnabled" forKey:@"key"];
        [_customBootlogoEnabledSpecifier setProperty:@NO forKey:@"default"];
        _customBootlogoEnabledSpecifier.identifier = @"customBootlogoEnabled";

        _customBootlogoSpecifier = [PSSpecifier preferenceSpecifierNamed:DOLocalizedString(@"Select_Image") target:self set:defSetter get:defGetter detail:nil cell:PSButtonCell edit:nil];
        _customBootlogoSpecifier.buttonAction = @selector(selectCustomBootlogoPressed);
        [_customBootlogoSpecifier setProperty:@YES forKey:@"enabled"];
        [_customBootlogoSpecifier setProperty:@"customBootlogo" forKey:@"key"];
        _customBootlogoSpecifier.identifier = @"customBootlogo";

        if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"bootlogoEnabled" fallback:YES]) {
            [specifiers addObject:_customBootlogoEnabledSpecifier];

            if ([[DOPreferenceManager sharedManager] boolPreferenceValueForKey:@"customBootlogoEnabled" fallback:NO]) {
                [specifiers addObject:_customBootlogoSpecifier];
            }
        }

        _specifiers = specifiers;
    }
    return _specifiers;
}

#pragma mark - Getters & Setters

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier
{
    NSString *key = [specifier propertyForKey:@"key"];
    [[DOPreferenceManager sharedManager] setPreferenceValue:value forKey:key];
}

- (id)readPreferenceValue:(PSSpecifier*)specifier
{
    NSString *key = [specifier propertyForKey:@"key"];
    id value = [[DOPreferenceManager sharedManager] preferenceValueForKey:key];
    if (!value) {
        return [specifier propertyForKey:@"default"];
    }
    return value;
}

- (id)readExploitPreferenceValue:(PSSpecifier *)specifier
{
    id value = [self readPreferenceValue:specifier];

    SEL dataSourceSel = nil;
    NSString *selString = [specifier propertyForKey:@"valuesDataSource"];
    if (selString) {
        dataSourceSel = NSSelectorFromString(selString);
    }

    if (dataSourceSel && [value isKindOfClass:[NSString class]]) {
        NSString *valueString = (NSString *)value;

        IMP imp = [specifier.target methodForSelector:dataSourceSel];
        if (imp) {
            NSArray *(*func)(id, SEL) = (void *)imp;
            NSArray *availableIdentifiers = func(specifier.target, dataSourceSel);
            if (![availableIdentifiers containsObject:valueString]) {
                return [specifier propertyForKey:@"default"];
            }
        }
    }

    return value;
}

- (id)readIDownloadEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @([DOEnvironmentManager sharedManager].isIDownloadEnabled);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setIDownloadEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        [[DOEnvironmentManager sharedManager] setIDownloadLoaded:((NSNumber *)value).boolValue needsUnsandbox:YES];
    }
}

- (id)readTweakInjectionEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        return @([DOEnvironmentManager sharedManager].isTweakInjectionEnabled);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setTweakInjectionEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        int status = [envManager setTweakInjectionEnabled:((NSNumber *)value).boolValue];
        if ([DOBootstrapper rootHidePortEnabled] && status) {
            [self setPreferenceValue:@(envManager.isTweakInjectionEnabled) specifier:specifier];
            UIAlertController *failed = [UIAlertController alertControllerWithTitle:@"No se cambió la inyección"
                message:[NSString stringWithFormat:@"No se pudo actualizar el modo seguro (código %d). Comparte el diagnóstico. No se reiniciará el entorno.", status]
                preferredStyle:UIAlertControllerStyleAlert];
            [failed addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:failed animated:YES completion:nil];
            return;
        }
        [self setPreferenceValue:value specifier:specifier];
        UIAlertController *userspaceRebootAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Title") message:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Body") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *rebootNowAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Reboot_Now") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
                int result = [[DOEnvironmentManager sharedManager] rebootUserspace];
                if (result != 0 && [DOBootstrapper rootHidePortEnabled]) dispatch_async(dispatch_get_main_queue(), ^{
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"No se pudo reiniciar el entorno"
                        message:[NSString stringWithFormat:@"Código %d. Comparte el diagnóstico desde el menú.", result]
                        preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:alert animated:YES completion:nil];
                });
            });
        }];
        UIAlertAction *rebootLaterAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Alert_Tweak_Injection_Toggled_Reboot_Later") style:UIAlertActionStyleCancel handler:nil];
        
        [userspaceRebootAlertController addAction:rebootNowAction];
        [userspaceRebootAlertController addAction:rebootLaterAction];
        [self presentViewController:userspaceRebootAlertController animated:YES completion:nil];
    } else {
        [self setPreferenceValue:value specifier:specifier];
    }
}

- (id)readAppJITEnabled:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        bool v = jbclient_jbsettings_get_bool("markAppsAsDebugged");
        return @(v);
    }
    return [self readPreferenceValue:specifier];
}

- (void)setAppJITEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_bool("markAppsAsDebugged", ((NSNumber *)value).boolValue);
    }
}

- (id)readJetsamMultiplier:(PSSpecifier *)specifier
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        double v = jbclient_jbsettings_get_double("jetsamMultiplier");
        return @((v < 1 || isnan(v)) ? 6 : ceil(v * 2));
    }
    return [self readPreferenceValue:specifier];
}

- (void)setJetsamMultiplier:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    if (envManager.isJailbroken) {
        jbclient_platform_jbsettings_set_double("jetsamMultiplier", ((NSNumber *)value).doubleValue / 2);
    }
}

- (void)setRemoveJailbreakEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    [self setPreferenceValue:value specifier:specifier];
    if (((NSNumber *)value).boolValue) {
        UIAlertController *confirmationAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Remove_Jailbreak_Title") message:DOLocalizedString(@"Alert_Remove_Jailbreak_Enabled_Body") preferredStyle:UIAlertControllerStyleAlert];
        UIAlertAction *uninstallAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Continue") style:UIAlertActionStyleDestructive handler:nil];
        UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action) {
            [self setPreferenceValue:@NO specifier:specifier];
            [self reloadSpecifiers];
        }];
        [confirmationAlertController addAction:uninstallAction];
        [confirmationAlertController addAction:cancelAction];
        [self presentViewController:confirmationAlertController animated:YES completion:nil];
    }
}

- (void)setBootlogoEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    bool prevValueBool = ((NSNumber *)[self readPreferenceValue:specifier]).boolValue;
    [self setPreferenceValue:value specifier:specifier];
    bool valueBool = ((NSNumber *)value).boolValue;

    if (prevValueBool != valueBool) {
        NSMutableArray *affectedSpecifiers = [NSMutableArray new];
        [affectedSpecifiers addObject:_customBootlogoEnabledSpecifier];

        if (valueBool == ![self containsSpecifier:_customBootlogoSpecifier]) {
            [affectedSpecifiers addObject:_customBootlogoSpecifier];
        }

        if (valueBool) {
            [self insertContiguousSpecifiers:affectedSpecifiers afterSpecifier:specifier animated:YES];
        }
        else {
            [self removeContiguousSpecifiers:affectedSpecifiers animated:YES];
        }
    }

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }
}

- (void)setCustomBootlogoEnabled:(id)value specifier:(PSSpecifier *)specifier
{
    bool prevValueBool = ((NSNumber *)[self readPreferenceValue:specifier]).boolValue;
    [self setPreferenceValue:value specifier:specifier];
    bool valueBool = ((NSNumber *)value).boolValue;

    if (prevValueBool != valueBool) {
        if (valueBool) {
            [self insertSpecifier:_customBootlogoSpecifier afterSpecifier:specifier animated:YES];
        }
        else {
            [self removeSpecifier:_customBootlogoSpecifier animated:YES];
        }
    }

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }
}

- (void)selectCustomBootlogoPressed
{
    PHAuthorizationStatus status = [PHPhotoLibrary authorizationStatus];
    if (status == PHAuthorizationStatusDenied || status == PHAuthorizationStatusRestricted) {
        return;
    } else if (status == PHAuthorizationStatusNotDetermined) {
        [PHPhotoLibrary requestAuthorization:^(PHAuthorizationStatus status) {
            if (status == PHAuthorizationStatusAuthorized) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    [self selectCustomBootlogoPressed];
                });
            }
        }];
        return;
    }

    UIImagePickerController *picker = [[UIImagePickerController alloc] init];
    picker.delegate = self;
    picker.sourceType = UIImagePickerControllerSourceTypePhotoLibrary;
    [self presentViewController:picker animated:YES completion:nil];
}

#pragma mark - Boot Logo Picker

- (void)imagePickerController:(UIImagePickerController *)picker didFinishPickingMediaWithInfo:(NSDictionary<NSString *,id> *)info {
    UIImage *chosenImage = info[UIImagePickerControllerEditedImage];
    if (!chosenImage) {
        chosenImage = info[UIImagePickerControllerOriginalImage];
    }

    // Force correct the orientation
    // For some reason without rerendering the image, the stored file will have a wrong orientation for photos taken with the camera‚
    UIGraphicsBeginImageContextWithOptions(chosenImage.size, NO, 1.0);
    [chosenImage drawInRect:CGRectMake(0,0, chosenImage.size.width, chosenImage.size.height)];
    chosenImage = UIGraphicsGetImageFromCurrentImageContext();
    UIGraphicsEndImageContext();

    [UIImagePNGRepresentation(chosenImage) writeToFile:[DOUIManager sharedInstance].bootlogoPath atomically:YES];

    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            [[DOEnvironmentManager sharedManager] updateBootLogo];
        });
    }

    [picker dismissViewControllerAnimated:YES completion:nil];
}

- (void)imagePickerControllerDidCancel:(UIImagePickerController *)picker {
    [picker dismissViewControllerAnimated:YES completion:nil];
}

#pragma mark - Button Actions

- (void)verifyRootHideTweaksPressed
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int result = [[DOEnvironmentManager sharedManager] verifyRootHideTweakInjection];
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *body = result
                ? [NSString stringWithFormat:@"No se ha demostrado la carga de TweakLoader (código %d). Comprueba el modo seguro y comparte el log de RootHide. No se han activado tweaks a la fuerza.", result]
                : @"La prueba aislada confirmó que systemhook se ejecutó y TweakLoader se abrió correctamente. Esto no garantiza que cada tweak funcione en todas las apps.";
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:
                result ? @"Inyección sin confirmar" : @"Inyección verificada en el proceso de prueba"
                message:body preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

- (void)repairRootHideSSHPressed
{
    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Preparar OpenSSH"
        message:@"Solo si ya has cambiado las contraseñas de acceso. Se comprobará OpenSSH, se creará una clave ED25519 privada solo si falta, y se verificará su configuración en el bootstrap oculto. No se inicia el servidor ni se cambia el plist instalado. Después necesitas un reinicio de espacio de usuario."
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancelar" style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Continuar" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
            int result = [[DOEnvironmentManager sharedManager] repairRootHideSSH];
            dispatch_async(dispatch_get_main_queue(), ^{
                UIAlertController *done = [UIAlertController alertControllerWithTitle:
                    result ? @"OpenSSH no preparado" : @"OpenSSH preparado"
                    message:result ? [NSString stringWithFormat:@"Falló una comprobación (código %d). No se han iniciado servicios. Comparte el diagnóstico.", result] :
                        @"La clave y configuración ocultas están verificadas. Reinicia una vez el espacio de usuario para que launchd importe la ruta corregida y prueba SSH desde tu ordenador."
                    preferredStyle:UIAlertControllerStyleAlert];
                [done addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                [self presentViewController:done animated:YES completion:nil];
            });
        });
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

- (void)diagnoseRootHideRuntimePressed
{
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int result = [[DOEnvironmentManager sharedManager] diagnoseRootHideRuntime];
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:
                result ? @"Diagnóstico incompleto" : @"Diagnóstico guardado"
                message:result ? [NSString stringWithFormat:@"No se pudo verificar el entorno (código %d). Comparte el registro de RootHide.", result] :
                    @"Se han comprobado en modo de solo lectura el estado seguro y la presencia de TweakLoader, NewTerm y SSH. Comparte el registro de diagnóstico para analizar los resultados; esta acción no inicia servicios."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

- (void)diagnoseRootHideOpenSSHSocketPressed
{
    // Never bootstrap, kickstart, enable or stop OpenSSH from this UI.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        int result = [[DOEnvironmentManager sharedManager] diagnoseRootHideOpenSSHSocket];
        dispatch_async(dispatch_get_main_queue(), ^{
            UIAlertController *alert = [UIAlertController alertControllerWithTitle:
                result ? @"Consulta de OpenSSH incompleta" : @"Estado de OpenSSH registrado"
                message:result
                    ? [NSString stringWithFormat:@"La consulta devolvió el código %d. Comparte el diagnóstico de RootHide. No se ha cambiado ningún servicio.", result]
                    : @"Se han consultado el plist y el estado real de launchd para com.openssh.sshd. Comparte el diagnóstico de RootHide para comparar los indicadores; no se ha iniciado SSH ni se han cambiado claves."
                preferredStyle:UIAlertControllerStyleAlert];
            [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:alert animated:YES completion:nil];
        });
    });
}

- (void)refreshJailbreakAppsPressed
{
    if ([DOBootstrapper rootHidePortEnabled]) {
        if (gRootHideAppsRefreshInFlight) {
            UIAlertController *busy = [UIAlertController alertControllerWithTitle:@"La actualización sigue en marcha" message:@"No inicies otra actualización. Comparte el diagnóstico para comprobar dónde se ha detenido." preferredStyle:UIAlertControllerStyleAlert];
            [busy addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:busy animated:YES completion:nil];
            return;
        }
        gRootHideAppsRefreshInFlight = YES;
        __block BOOL completed = NO;
        __block BOOL timedOut = NO;
        UIAlertController *progress = [UIAlertController alertControllerWithTitle:@"Actualizando apps" message:@"Comprobando los enlaces y el registro de las apps…" preferredStyle:UIAlertControllerStyleAlert];
        [self presentViewController:progress animated:YES completion:^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 45 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                if (completed) return;
                timedOut = YES;
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:@"apps: refresh UI deadline reached; worker still running; duplicate refresh blocked"];
                [progress dismissViewControllerAnimated:YES completion:^{
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:@"La actualización no ha terminado" message:@"Han pasado 45 segundos. Puedes cerrar este aviso y compartir el diagnóstico. La operación puede seguir activa; no se ha cancelado ni se considera completada." preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:alert animated:YES completion:nil];
                }];
            });
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                int result = [[DOEnvironmentManager sharedManager] refreshJailbreakApps];
                dispatch_async(dispatch_get_main_queue(), ^{
                    completed = YES;
                    // A child timeout does not establish that uicache exited.
                    gRootHideAppsRefreshInFlight = result == ETIMEDOUT;
                    if (timedOut) {
                        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:[NSString stringWithFormat:@"apps: refresh worker returned after UI deadline; result=%d", result]];
                        return;
                    }
                    [progress dismissViewControllerAnimated:YES completion:^{
                        UIAlertController *alert = [UIAlertController alertControllerWithTitle:result ? @"No se pudieron actualizar las apps" : @"Apps actualizadas"
                            message:result ? [NSString stringWithFormat:@"Código %d. Comparte el diagnóstico. Si se agotó el tiempo, el proceso puede seguir en marcha; no repitas la acción.", result] : @"Prueba a abrir Sileo y RootHide."
                            preferredStyle:UIAlertControllerStyleAlert];
                        [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                        [self presentViewController:alert animated:YES completion:nil];
                    }];
                });
            });
        }];
        return;
    }
    int result = [[DOEnvironmentManager sharedManager] refreshJailbreakApps];
    if (result != 0 || [DOBootstrapper rootHidePortEnabled]) {
        UIAlertController *alert = [UIAlertController alertControllerWithTitle:result ? @"No se pudieron actualizar las apps" : @"El comando ha terminado"
            message:result ? [NSString stringWithFormat:@"La acción falló con el código %d. No se ha reinstalado el bootstrap.", result] : @"Comprueba si aparecen Sileo y RootHide. Si siguen sin aparecer, comparte el diagnóstico de RootHide, que ahora incluye el resultado de esta acción."
            preferredStyle:UIAlertControllerStyleAlert];
        [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:alert animated:YES completion:nil];
    }
}

- (void)repairRootHideLibkrwPressed
{
    if (gRootHideProviderRepairInFlight || gRootHideAppsRefreshInFlight) {
        UIAlertController *busy = [UIAlertController alertControllerWithTitle:@"Operación pendiente"
            message:@"No inicies otra reparación mientras esté ejecutándose una operación RootHide. Comparte el diagnóstico si se ha bloqueado."
            preferredStyle:UIAlertControllerStyleAlert];
        [busy addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
        [self presentViewController:busy animated:YES completion:nil];
        return;
    }
    UIAlertController *confirm = [UIAlertController alertControllerWithTitle:@"Reparar libkrw0-plugin"
        message:@"Registra únicamente el proveedor de la dependencia libkrw en el bootstrap RootHide existente. No reinstala Sileo, Zebra ni el bootstrap. Úsalo una sola vez si Sileo informa de libkrw0-plugin."
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Cancelar" style:UIAlertActionStyleCancel handler:nil]];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Reparar" style:UIAlertActionStyleDefault handler:^(__unused UIAlertAction *action) {
        if (gRootHideProviderRepairInFlight) return;
        gRootHideProviderRepairInFlight = YES;
        __block BOOL finished = NO;
        __block BOOL timedOut = NO;
        UIAlertController *progress = [UIAlertController alertControllerWithTitle:@"Registrando proveedor libkrw"
            message:@"Comprobando la biblioteca y registrando sus metadatos en dpkg…"
            preferredStyle:UIAlertControllerStyleAlert];
        [self presentViewController:progress animated:YES completion:^{
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 135 * NSEC_PER_SEC), dispatch_get_main_queue(), ^{
                if (finished) return;
                timedOut = YES;
                [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                    @"packages: libkrw repair UI deadline reached; operation outcome unknown; duplicate repair blocked"];
                [progress dismissViewControllerAnimated:YES completion:^{
                    UIAlertController *warning = [UIAlertController alertControllerWithTitle:@"La reparación sigue pendiente"
                        message:@"Comparte el diagnóstico. No repitas la operación: un timeout no confirma que dpkg haya terminado."
                        preferredStyle:UIAlertControllerStyleAlert];
                    [warning addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:warning animated:YES completion:nil];
                }];
            });
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                NSError *error = [[DOEnvironmentManager sharedManager] repairRootHideLibkrwProvider];
                dispatch_async(dispatch_get_main_queue(), ^{
                    finished = YES;
                    gRootHideProviderRepairInFlight = error && error.code == ETIMEDOUT;
                    if (timedOut) {
                        [[DOUIManager sharedInstance] rh3RecordDiagnosticStage:
                            [NSString stringWithFormat:@"packages: libkrw repair returned after UI deadline result=%ld", (long)error.code]];
                        return;
                    }
                    [progress dismissViewControllerAnimated:YES completion:^{
                        UIAlertController *result = [UIAlertController alertControllerWithTitle:
                            error ? @"No se completó la reparación" : @"Dependencia registrada"
                            message:error ? [NSString stringWithFormat:@"%@. Comparte el diagnóstico y no repitas la acción si hubo un timeout.", error.localizedDescription] :
                                @"Vuelve a abrir Sileo y actualiza las fuentes; comprueba si desaparece el error libkrw0-plugin."
                            preferredStyle:UIAlertControllerStyleAlert];
                        [result addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                        [self presentViewController:result animated:YES completion:nil];
                    }];
                });
            });
        }];
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}

- (void)reinstallPackageManagersPressed
{
    [self.navigationController pushViewController:[[DOPkgManagerPickerViewController alloc] init] animated:YES];
}

- (void)changeMobilePasswordWithAuthenticationPressed
{
	LAContext *context = [[LAContext alloc] init];
	NSError *authError = nil;
	NSString *reason = DOLocalizedString(@"Password_Auth_Required");
	
	if ([context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&authError]) {
		[context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
			localizedReason:reason
			reply:^(BOOL success, NSError * _Nullable error) {
			dispatch_async(dispatch_get_main_queue(), ^{
				if (success) {
					[self changeMobilePassword];
				}
			});
		}];
	}
	else {
		[self changeMobilePassword];
	}
}

- (void)changeMobilePassword
{
    UIAlertController *changeMobilePasswordAlert = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Button_Change_Mobile_Password") message:DOLocalizedString(@"Alert_Change_Mobile_Password_Body") preferredStyle:UIAlertControllerStyleAlert];
    
    [changeMobilePasswordAlert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = DOLocalizedString(@"Password_Placeholder");
        textField.secureTextEntry = YES;
    }];
    
    [changeMobilePasswordAlert addTextFieldWithConfigurationHandler:^(UITextField * _Nonnull textField) {
        textField.placeholder = DOLocalizedString(@"Repeat_Password_Placeholder");
        textField.secureTextEntry = YES;
    }];
    
    UIAlertAction *changeButton = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Change") style:UIAlertActionStyleDefault handler:^(UIAlertAction * _Nonnull action){
        NSString *password = changeMobilePasswordAlert.textFields[0].text;
        NSString *repeatPassword = changeMobilePasswordAlert.textFields[1].text;
        if (![password isEqualToString:repeatPassword]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [self changeMobilePassword];
            });
        }
        else {
            dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
                int result = [[DOEnvironmentManager sharedManager] changeMobilePassword:password];
                if ([DOBootstrapper rootHidePortEnabled]) dispatch_async(dispatch_get_main_queue(), ^{
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:result ? @"No se confirmó el cambio" : @"Contraseña actualizada"
                        message:result ? [NSString stringWithFormat:@"Código %d. Consulta el diagnóstico.", result] : @"El comando terminó correctamente y cambió el registro de mobile en el bootstrap."
                        preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:nil]];
                    [self presentViewController:alert animated:YES completion:nil];
                });
            });
        }
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleCancel handler:nil];
    [changeMobilePasswordAlert addAction:changeButton];
    [changeMobilePasswordAlert addAction:cancelAction];
    [self presentViewController:changeMobilePasswordAlert animated:YES completion:nil];
}

- (void)hideUnhideJailbreakPressed
{
    DOEnvironmentManager *envManager = [DOEnvironmentManager sharedManager];
    [envManager setJailbreakHidden:!envManager.isJailbreakHidden];
    [self reloadSpecifiers];
}

- (void)removeJailbreakPressed
{
    UIAlertController *confirmationAlertController = [UIAlertController alertControllerWithTitle:DOLocalizedString(@"Alert_Remove_Jailbreak_Title") message:DOLocalizedString(@"Alert_Remove_Jailbreak_Pressed_Body") preferredStyle:UIAlertControllerStyleAlert];
    UIAlertAction *uninstallAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Continue") style:UIAlertActionStyleDestructive handler:^(UIAlertAction * _Nonnull action) {
        NSError *deleteError = [[DOEnvironmentManager sharedManager] deleteBootstrap];
        if (deleteError) {
            // A RootHide removal can leave owned containers in quarantine for
            // recovery. Never reboot or clear the active root after failure.
            UIAlertController *errorAlert = [UIAlertController
                alertControllerWithTitle:DOLocalizedString(@"Alert_Remove_Jailbreak_Title")
                               message:deleteError.localizedDescription
                        preferredStyle:UIAlertControllerStyleAlert];
            [errorAlert addAction:[UIAlertAction actionWithTitle:@"OK"
                                                            style:UIAlertActionStyleCancel handler:nil]];
            [self presentViewController:errorAlert animated:YES completion:nil];
            return;
        }
        if ([DOEnvironmentManager sharedManager].isJailbroken) {
            [[DOEnvironmentManager sharedManager] reboot];
        }
        else {
            if (gSystemInfo.jailbreakInfo.rootPath) {
                free(gSystemInfo.jailbreakInfo.rootPath);
                gSystemInfo.jailbreakInfo.rootPath = NULL;
                [[DOEnvironmentManager sharedManager] locateJailbreakRoot];
            }
            [self reloadSpecifiers];
        }
    }];
    UIAlertAction *cancelAction = [UIAlertAction actionWithTitle:DOLocalizedString(@"Button_Cancel") style:UIAlertActionStyleDefault handler:nil];
    [confirmationAlertController addAction:uninstallAction];
    [confirmationAlertController addAction:cancelAction];
    [self presentViewController:confirmationAlertController animated:YES completion:nil];
}

- (void)resetSettingsPressed
{
    [[DOUIManager sharedInstance] resetSettings];
    [self.navigationController popToRootViewControllerAnimated:YES];
    [self reloadSpecifiers];
}


@end
