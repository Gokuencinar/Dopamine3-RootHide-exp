#ifndef RH3_BOOTLOG_H
#define RH3_BOOTLOG_H
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <stdint.h>
#ifndef RH3_BOOTLOG_PREFIX
#define RH3_BOOTLOG_PREFIX "/private/var/mobile/Containers/Data/Application/"
#endif
// No Foundation, dispatch, XPC, os_log or signal handlers in PID 1 checkpoints.
static int rh3_bootlog_open(const char *path)
{
    if (!path || path[0] != '/' || strlen(path) >= PATH_MAX) return -1;
    char copy[PATH_MAX]; strcpy(copy, path);
    int directory = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    char *cursor = copy + 1, *component;
    while ((component = strsep(&cursor, "/"))) {
        if (!component[0] || !strcmp(component,".") || !strcmp(component,"..")) { close(directory); return -1; }
        int next = openat(directory, component, (cursor ? O_RDONLY | O_DIRECTORY : O_WRONLY | O_APPEND | O_NONBLOCK) | O_NOFOLLOW | O_CLOEXEC);
        close(directory); directory = next;
        if (directory < 0) return -1;
    }
    return directory;
}
static int rh3_bootlog_path_valid(const char *path)
{
    size_t prefix = strlen(RH3_BOOTLOG_PREFIX);
    if (strncmp(path, RH3_BOOTLOG_PREFIX, prefix)) return 0;
    const char *tail = path + prefix;
    // The only supported destination is an existing attempt log in this app's Documents.
    const char *slash = strchr(tail,'/');
    if (!slash || slash-tail != 36) return 0;
    for (int i=0;i<36;i++) {
        if (i==8 || i==13 || i==18 || i==23) { if(tail[i]!='-') return 0; }
        else if (!strchr("0123456789abcdefABCDEF",tail[i])) return 0;
    }
    const char *name = slash + 1;
    if (strncmp(name,"Documents/RootHide3-attempt-",28)) return 0;
    name += 28;
    if (strlen(name)!=40 || strcmp(name+36,".log")) return 0;
    for (int i=0;i<36;i++) {
        if (i==8 || i==13 || i==18 || i==23) { if(name[i]!='-') return 0; }
        else if (!strchr("0123456789abcdefABCDEF",name[i])) return 0;
    }
    return 1;
}
static void rh3_bootlog(const char *stage)
{
    const char *path=getenv("RH3_BOOT_LOG_PATH"), *device=getenv("RH3_BOOT_LOG_DEV"), *inode=getenv("RH3_BOOT_LOG_INO");
    if (!path || !device || !inode || !rh3_bootlog_path_valid(path)) return;
    int fd=rh3_bootlog_open(path); if(fd<0) return;
    struct stat st;
    if (fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_nlink!=1 || (st.st_uid!=501 && st.st_uid!=0) ||
        (st.st_mode & 0777)!=0600 || (uint64_t)st.st_dev!=strtoull(device,NULL,10) ||
        (uint64_t)st.st_ino!=strtoull(inode,NULL,10) || st.st_size<0 || st.st_size>120*1024) { close(fd); return; }
    char line[256]; int size=snprintf(line,sizeof(line),"%lld BOOT pid=%d %.160s\n",(long long)time(NULL),getpid(),stage);
    if(size>0 && size<(int)sizeof(line)) { (void)write(fd,line,(size_t)size); (void)fsync(fd); }
    close(fd);
}
static int rh3_bootlog_configure(int source)
{
    char path[PATH_MAX], value[32]; struct stat original, reopened;
    if(fstat(source,&original) || !S_ISREG(original.st_mode) || original.st_nlink!=1 ||
       (original.st_uid!=501 && original.st_uid!=0) || (original.st_mode & 0777)!=0600 ||
       fcntl(source,F_GETPATH,path) || !rh3_bootlog_path_valid(path)) return EINVAL;
    int check=rh3_bootlog_open(path);
    if(check<0) return EINVAL;
    int valid=!fstat(check,&reopened) && original.st_dev==reopened.st_dev && original.st_ino==reopened.st_ino;
    close(check); if(!valid) return EINVAL;
    if(setenv("RH3_BOOT_LOG_PATH",path,1)) return errno;
    snprintf(value,sizeof(value),"%llu",(unsigned long long)(uint64_t)original.st_dev);
    if(setenv("RH3_BOOT_LOG_DEV",value,1)) return errno;
    snprintf(value,sizeof(value),"%llu",(unsigned long long)original.st_ino);
    if(setenv("RH3_BOOT_LOG_INO",value,1)) return errno;
    rh3_bootlog("diagnostic destination registered");
    return 0;
}
#endif
