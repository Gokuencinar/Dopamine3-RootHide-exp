//
//  DOPkgManagerPickerViewController.m
//  Dopamine
//
//  Created by tomt000 on 11/02/2024.
//

#import "DOPkgManagerPickerViewController.h"
#import "DOPkgManagerPickerView.h"
#import "DOEnvironmentManager.h"
#import "DOBootstrapper.h"


@interface DOPkgManagerPickerViewController ()

@end

@implementation DOPkgManagerPickerViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    DOPkgManagerPickerView *picker = [[DOPkgManagerPickerView alloc] initWithCallback:^(BOOL success) {
        if (!success) return;
        self.view.userInteractionEnabled = NO;
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
            NSError *error = [[DOEnvironmentManager sharedManager] reinstallPackageManagers];
            dispatch_async(dispatch_get_main_queue(), ^{
                self.view.userInteractionEnabled = YES;
                if ([DOBootstrapper rootHidePortEnabled]) {
                    UIAlertController *alert = [UIAlertController alertControllerWithTitle:error ? @"No se pudieron reinstalar los gestores" : @"Gestores reinstalados"
                        message:error ? error.localizedDescription : @"La instalación y los enlaces han terminado. Puedes volver a probar las apps."
                        preferredStyle:UIAlertControllerStyleAlert];
                    [alert addAction:[UIAlertAction actionWithTitle:@"Aceptar" style:UIAlertActionStyleCancel handler:^(UIAlertAction *action) {
                        if (!error) [self.navigationController popViewControllerAnimated:YES];
                    }]];
                    [self presentViewController:alert animated:YES completion:nil];
                    return;
                }
                [self.navigationController popViewControllerAnimated:YES];
            });
        });
    }];
    picker.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:picker];
    [NSLayoutConstraint activateConstraints:@[
        [picker.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor],
        [picker.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor],
        [picker.topAnchor constraintEqualToAnchor:self.view.topAnchor],
        [picker.bottomAnchor constraintEqualToAnchor:self.view.bottomAnchor]
    ]];
}


@end
