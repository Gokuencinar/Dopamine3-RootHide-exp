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

#ifndef RH3_INSTALLABLE_DIAGNOSTIC
#define RH3_INSTALLABLE_DIAGNOSTIC 0
#endif
#ifndef RH3_FULL_APP_EXPERIMENTAL
#define RH3_FULL_APP_EXPERIMENTAL 0
#endif

#if RH3_FULL_APP_EXPERIMENTAL
// Included in the complete Dopamine executable to distinguish the guarded
// RootHide experiment from the harmless UIKit-only diagnostic and stock app.
__attribute__((used)) static const char RH3FullExperimentMarker[] =
    "RH3_FULL_APP_EXPERIMENTAL_GUARDED_V1";
#endif

int main(int argc, char * argv[]) {
#if RH3_FULL_APP_EXPERIMENTAL
    // A live use also keeps the build marker in the final linked Mach-O.
    NSLog(@"RootHide 3 guarded full experiment: %s", RH3FullExperimentMarker);
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
