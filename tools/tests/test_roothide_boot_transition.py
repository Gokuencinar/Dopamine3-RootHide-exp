"""Native checks for stale registrations and persistent PID 1 diagnostics."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
ROOT=Path(__file__).resolve().parents[2]
class BootTransition(unittest.TestCase):
    def test_recorder_is_app_only_and_does_not_intercept_faults(self):
        header=(ROOT/'BaseBin/libjailbreak/src/roothide_bootlog.h').read_text(encoding='utf-8-sig')
        for item in ('O_NOFOLLOW','O_DIRECTORY','st_nlink!=1','original.st_ino==reopened.st_ino','fsync(fd)','st.st_size>120*1024'):
            self.assertIn(item,header)
        for forbidden in ('dispatch_', 'NSLog(', 'os_log(', 'sigaction(', 'signal(', 'O_CREAT', 'O_TRUNC'):
            self.assertNotIn(forbidden,header)
        server=(ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c').read_text()
        self.assertIn('.permissionHandler = dopamine_domain_allowed',server)
        self.assertIn('roothide_is_active() ? rh3_bootlog_configure(fd) : ENOTSUP',server)
        app=(ROOT/'Application/Dopamine/Jailbreak/DOJailbreaker.m').read_text(encoding='utf-8')
        self.assertIn('oldError == ENOENT',app)
        self.assertIn('S_ISDIR(appInfo.st_mode) && appInfo.st_uid == 0',app)
        self.assertIn('applicationProxyForIdentifier:dopamineAppId',app)
        self.assertIn('RH3WaitForBootstrapChild(child, 30)',app)

    @unittest.skipUnless(sys.platform=='darwin','native Darwin filesystem test')
    def test_boot_log_survives_exec_and_rejects_replacement_links_and_overflow(self):
        self.run_native(r'''
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
static char fixturePrefix[4096];
#define RH3_BOOTLOG_PREFIX fixturePrefix
#include "roothide_bootlog.h"
static off_t size(const char*p){struct stat st;return stat(p,&st)?-1:st.st_size;}
int main(int argc,char**argv){
 if(argc==2){strcpy(fixturePrefix,argv[1]);rh3_bootlog("after exec");return 0;}
 char tmp[]="/private/tmp/rh3-boot-XXXXXX"; if(!mkdtemp(tmp)) return 1;
 snprintf(fixturePrefix,sizeof(fixturePrefix),"%s/",tmp);
 char container[4096],docs[4096],path[4096],other[4096];
 snprintf(container,sizeof(container),"%s12345678-1234-1234-1234-123456789ABC",fixturePrefix);mkdir(container,0700);
 snprintf(docs,sizeof(docs),"%s/Documents",container);mkdir(docs,0700);
 snprintf(path,sizeof(path),"%s/RootHide3-attempt-12345678-1234-1234-1234-123456789ABC.log",docs);
 int fd=open(path,O_WRONLY|O_CREAT|O_APPEND,0600);if(fd<0)return 2;
 if(rh3_bootlog_configure(fd))return 3;fcntl(fd,F_SETFD,FD_CLOEXEC);
 off_t before=size(path);pid_t child=fork();if(child<0)return 4;
 if(!child){execl(argv[0],argv[0],fixturePrefix,NULL);_exit(9);}int status;waitpid(child,&status,0);
 if(status || size(path)<=before)return 5;
 before=size(path);setenv("RH3_BOOT_LOG_INO","0",1);rh3_bootlog("must not write");if(size(path)!=before)return 6;
 if(rh3_bootlog_configure(fd))return 7;before=size(path);
 snprintf(other,sizeof(other),"%s/saved",tmp);rename(path,other);
 int replacement=open(path,O_WRONLY|O_CREAT,0600);close(replacement);
 rh3_bootlog("replacement");if(size(path)!=0)return 8;
 unlink(path);symlink(other,path);rh3_bootlog("symlink");if(size(other)!=before)return 9;
 unlink(path);rename(other,path);link(path,other);rh3_bootlog("hardlink");if(size(path)!=before)return 10;unlink(other);
 if(ftruncate(fd,121*1024))return 11;rh3_bootlog("overflow");if(size(path)!=121*1024)return 12;
 chmod(path,0644);if(rh3_bootlog_configure(fd)==0)return 13;chmod(path,0600);
 snprintf(other,sizeof(other),"%s/../other.log",docs);if(rh3_bootlog_path_valid(other))return 14;
 close(fd);unlink(path);rmdir(docs);rmdir(container);rmdir(tmp);return 0;
}
''', 'BaseBin/libjailbreak/src',False)

    @unittest.skipUnless(sys.platform=='darwin','native Foundation path semantics')
    def test_registration_aliases_and_foreign_paths(self):
        self.run_native(r'''
#import <Foundation/Foundation.h>
#include "RootHideAppRegistration.h"
int main(void){@autoreleasepool{
 NSString *current=@"/var/containers/Bundle/Application/.jbroot-0100000000000001/Applications/Sileo.app";
 NSString *alias=[@"/private" stringByAppendingString:current];
 if(![RH3CanonicalAppPath(alias) isEqual:RH3CanonicalAppPath(current)])return 1;
 NSString *old=@"/private/var/containers/Bundle/Application/.jbroot-0200000000000002/Applications/Sileo.app";
 if(![RH3StaleRegisteredRoot(old,current).lastPathComponent isEqual:@".jbroot-0200000000000002"])return 2;
 for(NSString *bad in @[@"/var/containers/Bundle/Application/UUID/Sileo.app",@"/var/containers/Bundle/Application/.jbroot-0200000000000002/Applications/Sileo.app.other",@"/var/containers/Bundle/Application/.jbroot-0200000000000002/Applications/Other.app",@"/var/containers/Bundle/Application/.jbroot-0200000000000002/Applications/../Sileo.app"])
  if(RH3StaleRegisteredRoot(bad,current))return 3;
 if(RH3StaleRegisteredRoot(alias,current))return 4;
 return 0;
}}
''','Application/Dopamine/Jailbreak',True)

    def run_native(self,source,include,foundation):
        with tempfile.TemporaryDirectory() as tmp:
            src=Path(tmp)/('test.m' if foundation else 'test.c');binary=Path(tmp)/'test'
            src.write_text(source,encoding='utf-8')
            cmd=['xcrun','clang','-I',str(ROOT/include),str(src),'-o',str(binary)]
            if foundation:cmd+=['-fobjc-arc','-framework','Foundation']
            build=subprocess.run(cmd,capture_output=True,text=True)
            self.assertEqual(build.returncode,0,build.stderr)
            result=subprocess.run([str(binary)],capture_output=True,text=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
if __name__=='__main__':unittest.main()
