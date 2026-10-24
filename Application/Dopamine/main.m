//
//  main.m
//  Dopamine
//
//  Created by Lars Fröder on 23.09.23.
//

#import <UIKit/UIKit.h>
#import "DOAppDelegate.h"

#import "DOEnvironmentManager.h"
#import <libjailbreak/info.h>
#import <libjailbreak/jbclient_xpc.h>
#import <unistd.h>

#ifndef RH3_INSTALLABLE_DIAGNOSTIC
#define RH3_INSTALLABLE_DIAGNOSTIC 0
#endif
#ifndef RH3_FULL_APP_EXPERIMENTAL
#define RH3_FULL_APP_EXPERIMENTAL 0
#endif
#ifndef ROOTHIDE3_BOOTSTRAP_READY
#define ROOTHIDE3_BOOTSTRAP_READY 0
#endif
#ifndef ROOTHIDE3_TWEAKS_DEFAULT_ON
#define ROOTHIDE3_TWEAKS_DEFAULT_ON 0
#endif

#if RH3_FULL_APP_EXPERIMENTAL
// Included in the complete Dopamine executable to distinguish the guarded
// RootHide experiment from the harmless UIKit-only diagnostic and stock app.
__attribute__((used)) static const char RH3FullExperimentMarker[] =
    "RH3_FULL_APP_EXPERIMENTAL_GUARDED_V1";
#if ROOTHIDE3_BOOTSTRAP_READY
__attribute__((used)) static const char RH3ActivationMarker[] =
    "RH3_HARDWARE_BETA_ACTIVATED_V1";
#if ROOTHIDE3_TWEAKS_DEFAULT_ON
__attribute__((used)) static const char RH3TweakModeMarker[] =
    "RH3_TWEAKS_DEFAULT_ENABLED_V1";
#else
__attribute__((used)) static const char RH3TweakModeMarker[] =
    "RH3_TWEAKS_DEFAULT_SAFE_V1";
#endif
#else
__attribute__((used)) static const char RH3ActivationMarker[] =
    "RH3_JAILBREAK_DISABLED_V1";
#endif
#endif

int main(int argc, char * argv[]) {
#if RH3_FULL_APP_EXPERIMENTAL && ROOTHIDE3_BOOTSTRAP_READY && !RH3_INSTALLABLE_DIAGNOSTIC
    // The hardware beta needs its root helper for offline removal after a
    // reboot. Permit exactly this operation; never run stock TrollStore actions.
    if (argc >= 2 && !strcmp(argv[1], "trollstore")) {
        if (argc != 3 || strcmp(argv[2], "delete-bootstrap") || geteuid() != 0) return 77;
        @autoreleasepool {
            // The RootHide implementation verifies ownership and both linked
            // containers before quarantining and removing either of them.
            NSError *error = [[DOBootstrapper new] deleteBootstrap];
            if (error) {
                NSLog(@"RootHide 3 removal helper failed: %@", error.localizedDescription);
                return 1;
            }
            return 0;
        }
    }
#endif
#if RH3_FULL_APP_EXPERIMENTAL
    // A live use also keeps the build marker in the final linked Mach-O.
    NSLog(@"RootHide 3 guarded full experiment: %s", RH3FullExperimentMarker);
    NSLog(@"RootHide 3 bootstrap setting: %s", RH3ActivationMarker);
#if ROOTHIDE3_BOOTSTRAP_READY
    NSLog(@"RootHide 3 tweak default setting: %s", RH3TweakModeMarker);
#endif
#endif
#if !RH3_INSTALLABLE_DIAGNOSTIC && !RH3_FULL_APP_EXPERIMENTAL
    if (argc >= 3) {
        if (!strcmp(argv[1], "trollstore")) {
            if (!strcmp(argv[2], "delete-bootstrap")) {
                [[DOEnvironmentManager sharedManager] deleteBootstrap];
            }
            else if (!strcmp(argv[2], "hide-jailbreak")) {
                [[DOEnvironmentManager sharedManager] setJailbreakHidden:YES];
            }
            return 0;
        }
    }
    
    if (argc >= 2) {
        // Legacy, called by Dopamine 1.x before initiating a jbupdate
        // As updating from 1.x to 2.x is unsupported, just initiate a device reboot
        if (!strcmp(argv[1], "prepare_jbupdate")) {
            [[DOEnvironmentManager sharedManager] reboot];
            return 0;
        }
    }
    
    if ([DOEnvironmentManager sharedManager].isJailbroken) {
        setenv("PATH", "/sbin:/bin:/usr/sbin:/usr/bin:/var/jb/sbin:/var/jb/bin:/var/jb/usr/sbin:/var/jb/usr/bin", 1);
        setenv("TERM", "xterm-256color", 1);
    }
#endif // !RH3_INSTALLABLE_DIAGNOSTIC && !RH3_FULL_APP_EXPERIMENTAL
    
    NSString * appDelegateClassName;
    @autoreleasepool {
        // Setup code that might create autoreleased objects goes here.
        appDelegateClassName = NSStringFromClass([DOAppDelegate class]);
    }
    return UIApplicationMain(argc, argv, nil, appDelegateClassName);
}
