// Equivalent to the pinned donor's NO_PASSWORD_PROMPT=1 branch, on a fresh root only.
// Labels contain no arguments, account database contents or passwords.
static int RH3RunFreshSetup(int (^run)(NSString *, NSString *))
{
    NSArray<NSArray<NSString *> *> *steps = @[
        @[@"probe-spawn", @"test \"$DYLD_IN_CACHE\" = 0 && /bin/sh -c 'exit 0' && :"],
        @[@"probe-setexec", @"exec /bin/sh -c 'exit 0'"],
        @[@"firmware", @"exec /usr/libexec/firmware"],
        @[@"pwd-mkdb-initial", @"exec /usr/sbin/pwd_mkdb -p /etc/master.passwd"],
        @[@"debianutils-postinst", @"exec /Library/dpkg/info/debianutils.postinst configure 99999"],
        @[@"apt-postinst", @"exec /Library/dpkg/info/apt.postinst configure 999999"],
        @[@"dash-postinst", @"exec /Library/dpkg/info/dash.postinst configure 999999"],
        @[@"zsh-postinst", @"exec /Library/dpkg/info/zsh.postinst configure 999999"],
        @[@"bash-postinst", @"exec /Library/dpkg/info/bash.postinst configure 999999"],
        @[@"vi-postinst", @"exec /Library/dpkg/info/vi.postinst configure 999999"],
        @[@"pwd-mkdb-final", @"exec /usr/sbin/pwd_mkdb -p /etc/master.passwd"],
        @[@"chsh-mobile", @"exec /usr/bin/chsh -s /usr/bin/zsh mobile"],
        @[@"chsh-root", @"exec /usr/bin/chsh -s /usr/bin/zsh root"]
    ];
    for (NSArray *step in steps) {
        int status = run(step[0], step[1]);
        if (status != 0) return status;
    }
    return 0;
}
