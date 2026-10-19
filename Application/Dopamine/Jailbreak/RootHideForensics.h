#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <math.h>

// No commands are executed and no recovery files are changed here.
static int RH3ForensicOpen(NSString *path, BOOL directory)
{
    if (![path hasPrefix:@"/"]) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    NSArray *parts = path.pathComponents;
    for (NSUInteger i = 1; fd >= 0 && i < parts.count; i++) {
        NSString *part = parts[i];
        if ([part isEqualToString:@".."] || [part isEqualToString:@"."]) { close(fd); return -1; }
        int flags = O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK;
        if (i + 1 < parts.count || directory) flags |= O_DIRECTORY;
        int next = openat(fd, part.fileSystemRepresentation, flags);
        close(fd);
        fd = next;
    }
    return fd;
}

static NSData *RH3ForensicRead(int fd, NSUInteger limit)
{
    struct stat before = {0}, after = {0};
    if (fd < 0 || fstat(fd, &before) || !S_ISREG(before.st_mode) ||
        before.st_nlink != 1 || (before.st_uid != 0 && before.st_uid != 501) ||
        before.st_size <= 0 || before.st_size > (off_t)limit) return nil;
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)before.st_size];
    NSUInteger used = 0;
    while (used < data.length) {
        ssize_t n = read(fd, (char *)data.mutableBytes + used, data.length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return nil;
        used += (NSUInteger)n;
    }
    if (fstat(fd, &after) || before.st_size != after.st_size ||
        before.st_ino != after.st_ino || before.st_dev != after.st_dev ||
        before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
        before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
        before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
        before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec) return nil;
    return data;
}

static NSString *RH3ForensicScalar(id value)
{
    if (![value isKindOfClass:NSString.class] && ![value isKindOfClass:NSNumber.class]) return @"unknown";
    NSString *text = [value description];
    if (text.length > 160) text = [text substringToIndex:160];
    return [[text componentsSeparatedByCharactersInSet:NSCharacterSet.controlCharacterSet]
            componentsJoinedByString:@" "];
}

static BOOL RH3ForensicProcess(NSString *name)
{
    return [name isKindOfClass:NSString.class] &&
        [@[@"firmware", @"sh", @"dash", @"pwd_mkdb", @"dpkg", @"chsh",
           @"update-alternatives", @"bash", @"apt", @"rm", @"uialert", @"Dopamine", @"jailbreakd"] containsObject:name];
}

static BOOL RH3ForensicFilename(NSString *name)
{
    if (![name.pathExtension.lowercaseString isEqualToString:@"ips"]) return NO;
    for (NSString *prefix in @[@"firmware", @"sh", @"dash", @"pwd_mkdb", @"dpkg", @"chsh",
                              @"update-alternatives", @"bash", @"apt", @"rm", @"uialert",
                              @"Dopamine", @"jailbreakd", @"JetsamEvent"]) {
        if ([name hasPrefix:[prefix stringByAppendingString:@"-"]] ||
            [name hasPrefix:[prefix stringByAppendingString:@"_"]]) return YES;
    }
    return NO;
}

static NSDictionary *RH3ForensicDictionary(id value)
{
    return [value isKindOfClass:NSDictionary.class] ? value : @{};
}

static NSDate *RH3ForensicDate(id value)
{
    if (![value isKindOfClass:NSString.class]) return nil;
    for (NSString *format in @[@"yyyy-MM-dd HH:mm:ss.SSS Z", @"yyyy-MM-dd HH:mm:ss Z",
                               @"yyyy-MM-dd'T'HH:mm:ss.SSSZZZZZ", @"yyyy-MM-dd'T'HH:mm:ssZZZZZ"]) {
        NSDateFormatter *formatter = [NSDateFormatter new];
        formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
        formatter.dateFormat = format;
        formatter.lenient = NO;
        NSDate *date = [formatter dateFromString:value];
        if (date) return date;
    }
    return nil;
}

static void RH3ForensicReports(NSString *directory, NSDate *anchor, void (^log)(NSString *))
{
    int fd = RH3ForensicOpen(directory, YES);
    if (fd < 0) { log([NSString stringWithFormat:@"FORENSICS report directory unavailable: %@; errno=%d", directory, errno]); return; }
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); log(@"FORENSICS report directory could not be enumerated"); return; }
    NSUInteger entries = 0, candidates = 0, matched = 0, unreadable = 0, bytes = 0;
    struct dirent *entry;
    while (entries < 1024 && candidates < 32 && matched < 32 && bytes < 4 * 1024 * 1024 && (entry = readdir(dir))) {
        entries++;
        NSString *name = [NSString stringWithUTF8String:entry->d_name];
        if (!RH3ForensicFilename(name)) continue;
        candidates++;
        int report = openat(dirfd(dir), entry->d_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        NSData *data = RH3ForensicRead(report, MIN(1024 * 1024, 4 * 1024 * 1024 - bytes));
        if (report >= 0) close(report);
        if (!data) { unreadable++; continue; }
        bytes += data.length;
        NSString *text = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
        NSRange newline = [text rangeOfString:@"\n"];
        if (!text || newline.location == NSNotFound) { unreadable++; continue; }
        NSDictionary *header = RH3ForensicDictionary([NSJSONSerialization JSONObjectWithData:
            [[text substringToIndex:newline.location] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil]);
        NSDictionary *body = RH3ForensicDictionary([NSJSONSerialization JSONObjectWithData:
            [[text substringFromIndex:NSMaxRange(newline)] dataUsingEncoding:NSUTF8StringEncoding] options:0 error:nil]);
        NSDate *date = RH3ForensicDate(header[@"timestamp"]) ?: RH3ForensicDate(body[@"captureTime"]);
        if (!date) { unreadable++; continue; }
        if (fabs([date timeIntervalSinceDate:anchor]) > 300) continue;
        NSString *process = body[@"procName"] ?: header[@"app_name"];
        if ([name hasPrefix:@"JetsamEvent"]) {
            id processes = body[@"processes"];
            if (![processes isKindOfClass:NSArray.class]) { unreadable++; continue; }
            for (id item in processes) {
                NSDictionary *p = RH3ForensicDictionary(item);
                if (matched >= 32) break;
                if (!RH3ForensicProcess(p[@"name"]) || !p[@"reason"]) continue;
                matched++;
                log([NSString stringWithFormat:@"FORENSICS jetsam: time=%@; process=%@; pid=%@; reason=%@",
                    date, RH3ForensicScalar(p[@"name"]), RH3ForensicScalar(p[@"pid"]), RH3ForensicScalar(p[@"reason"])]);
            }
        } else if (RH3ForensicProcess(process)) {
            matched++;
            NSDictionary *termination = RH3ForensicDictionary(body[@"termination"]);
            NSDictionary *exception = RH3ForensicDictionary(body[@"exception"]);
            log([NSString stringWithFormat:@"FORENSICS report: time=%@; process=%@; pid=%@; simulated=%@; exception=%@; namespace=%@; code=%@; indicator=%@",
                date, RH3ForensicScalar(process), RH3ForensicScalar(body[@"pid"]), RH3ForensicScalar(header[@"is_simulated"]),
                RH3ForensicScalar(exception[@"type"]), RH3ForensicScalar(termination[@"namespace"]),
                RH3ForensicScalar(termination[@"code"]), RH3ForensicScalar(termination[@"indicator"])]);
        }
    }
    closedir(dir);
    log([NSString stringWithFormat:@"FORENSICS scan: directory=%@; entries=%lu; candidates=%lu; matches=%lu; unreadable=%lu; bytes=%lu; bounded=%@",
        directory, (unsigned long)entries, (unsigned long)candidates, (unsigned long)matched,
        (unsigned long)unreadable, (unsigned long)bytes,
        entries >= 1024 || candidates >= 32 || matched >= 32 || bytes >= 4 * 1024 * 1024 ? @"yes" : @"no"]);
    if (!matched) log(@"FORENSICS no matching termination evidence in this scan; cause remains unknown");
}

static void RH3CollectForensics(NSString *root, void (^log)(NSString *))
{
    // /var is the fixed iOS alias of /private/var; other links stay forbidden.
    if ([root hasPrefix:@"/var/"]) root = [@"/private" stringByAppendingString:root];
    int marker = RH3ForensicOpen([root stringByAppendingPathComponent:@".installing_roothide3"], NO);
    struct stat st = {0};
    NSData *stage = RH3ForensicRead(marker, 64);
    BOOL valid = marker >= 0 && fstat(marker, &st) == 0 && st.st_uid == 0 &&
        [stage isEqualToData:[@"running-script" dataUsingEncoding:NSUTF8StringEncoding]];
    if (marker >= 0) close(marker);
    if (!valid) { log(@"FORENSICS marker unavailable or changed; collection refused"); return; }
    NSDate *anchor = [NSDate dateWithTimeIntervalSince1970:st.st_mtime];
    log([NSString stringWithFormat:@"FORENSICS read-only collection; script marker time=%@; report window=+/-300s; no script replay", anchor]);
    for (NSString *directory in @[@"/private/var/mobile/Library/Logs/CrashReporter", @"/private/var/logs/CrashReporter"])
        RH3ForensicReports(directory, anchor, log);
    for (NSString *relative in @[@"prep_bootstrap.sh", @"usr/bin/dash", @"usr/libexec/firmware",
        @"usr/sbin/pwd_mkdb", @"usr/bin/dpkg", @"usr/bin/chsh", @"Library/dpkg/info/debianutils.postinst",
        @"Library/dpkg/info/apt.postinst", @"Library/dpkg/info/dash.postinst", @"Library/dpkg/info/zsh.postinst",
        @"Library/dpkg/info/bash.postinst", @"Library/dpkg/info/vi.postinst"]) {
        int file = RH3ForensicOpen([root stringByAppendingPathComponent:relative], NO);
        NSData *data = RH3ForensicRead(file, 4 * 1024 * 1024);
        if (file >= 0) close(file);
        if (!data) { log([NSString stringWithFormat:@"FORENSICS file unavailable, linked or outside limits: %@", relative]); continue; }
        unsigned char digest[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(data.bytes, (CC_LONG)data.length, digest);
        NSMutableString *hash = [NSMutableString string];
        for (NSUInteger i = 0; i < sizeof(digest); i++) [hash appendFormat:@"%02x", digest[i]];
        log([NSString stringWithFormat:@"FORENSICS file: %@; bytes=%lu; sha256=%@", relative, (unsigned long)data.length, hash]);
    }
    log(@"FORENSICS collection finished; hashes alone do not establish execution or corruption; installation remains incomplete");
}
