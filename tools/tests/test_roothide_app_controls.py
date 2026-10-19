from pathlib import Path
import sys
import unittest
import test_roothide_boot_transition as boot

ROOT = Path(__file__).resolve().parents[2]

class AppControls(unittest.TestCase):
    def test_repairs_existing_install_and_reports_controls_without_main_thread_wait(self):
        bootstrap = (ROOT/'Application/Dopamine/Jailbreak/DOBootstrapper.m').read_text()
        finalize = bootstrap.split('- (NSError *)finalizeRootHideBootstrap\n', 1)[1].split('- (NSError *)deleteRootHideBootstrap', 1)[0]
        self.assertIn('NSError *appLinksError = [self repairRootHideAppLinks]', finalize)
        self.assertLess(finalize.index('repairRootHideAppLinks'), finalize.index('RootHide finalization committed'))
        env = (ROOT/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
        refresh = env.split('- (int)refreshJailbreakApps',1)[1].split('- (void)unregisterJailbreakApps',1)[0]
        hidden = refresh.split('    [self runAsRoot:',1)[0]
        self.assertIn('repairRootHideAppLinks', hidden)
        self.assertIn('@[@"-p", path]', hidden)
        self.assertNotIn('"-a"', hidden)
        self.assertIn('timeout:30', hidden)
        settings = (ROOT/'Application/Dopamine/UI/Settings/DOSettingsController.m').read_text()
        refreshUI = settings.split('- (void)refreshJailbreakAppsPressed',1)[1].split('- (void)reinstallPackageManagersPressed',1)[0]
        self.assertLess(refreshUI.index('dispatch_async(dispatch_get_global_queue'), refreshUI.index('refreshJailbreakApps]'))
        picker = (ROOT/'Application/Dopamine/UI/PkgManagers/DOPkgManagerPickerViewController.m').read_text()
        self.assertIn('NSError *error =', picker)
        self.assertIn('error.localizedDescription', picker)
        password = env.split('- (int)changeMobilePassword:',1)[1].split('- (NSError*)updateEnvironment',1)[0].split('    [self runAsRoot:',1)[0]
        self.assertIn('@[@"usermod", @"501", @"-h", @"0"]',password)
        self.assertNotIn('dash',password)
        self.assertIn('![after isEqualToString:before]',password)
        self.assertIn('input:[[newPassword stringByAppendingString:',password)
        ctl = (ROOT/'BaseBin/jbctl/src/main.m').read_text()
        respring = ctl.split('else if (!strcmp(cmd, "respring"))',1)[1].split('else if (!strcmp(cmd, "rebuild_icon_cache"))',1)[0]
        self.assertIn('jbclient_roothide_jailbroken()',respring)
        self.assertNotIn('roothide_is_active()',respring)

    @unittest.skipUnless(sys.platform == 'darwin', 'native rooted bundle backlink tests')
    def test_links_survive_root_rename_and_refuse_directory_replacement_or_escape(self):
        boot.BootTransition().run_native(r'''
#include "RootHideAppLinks.h"
#include <stdlib.h>
static int macho(int fd,const char *name){int f=openat(fd,name,O_CREAT|O_WRONLY|O_EXCL,0600);uint32_t m=0xfeedfacf;if(f<0)return -1;int r=write(f,&m,4)==4?0:-1;close(f);return r;}
int main(void){
 char temp[]="/tmp/rh3-app-links-XXXXXX";if(!mkdtemp(temp)||chdir(temp))return 1;
 if(mkdir("root",0700)||mkdir("outside",0700))return 2;
 int root=open("root",O_DIRECTORY|O_RDONLY);if(root<0||mkdirat(root,"Applications",0700))return 3;
 int apps=openat(root,"Applications",O_DIRECTORY|O_RDONLY);if(apps<0||mkdirat(apps,"Sileo.app",0700))return 4;
 int app=openat(apps,"Sileo.app",O_DIRECTORY|O_RDONLY);if(app<0||macho(app,"Sileo"))return 5;
 if(symlinkat("../../../../outside",app,"Escape"))return 6;
 if(RH3RepairAppLinks(root,getuid()))return 7;
 char dest[128];ssize_t n=readlinkat(app,".jbroot",dest,sizeof(dest)-1);if(n<0)return 8;dest[n]=0;if(strcmp(dest,"../.."))return 9;
 struct stat a,b;if(fstat(root,&a)||fstatat(app,".jbroot",&b,0)||a.st_ino!=b.st_ino||a.st_dev!=b.st_dev)return 10;
 if(rename("root","renamed")||fstatat(app,".jbroot",&b,0)||a.st_ino!=b.st_ino)return 11;
 if(access("outside/.jbroot",F_OK)==0)return 12;
 if(unlinkat(app,".jbroot",0)||symlinkat("/old/root",app,".jbroot")||RH3RepairAppLinks(root,getuid()))return 13;
 if(unlinkat(app,".jbroot",0)||mkdirat(app,".jbroot",0700)||RH3RepairAppLinks(root,getuid())!=EPERM)return 14;
 if(fstatat(app,".jbroot",&b,AT_SYMLINK_NOFOLLOW)||!S_ISDIR(b.st_mode))return 15;
 if(RH3RepairAppLinks(root,getuid()+1)!=EPERM)return 16;
 close(app);close(apps);close(root);
 return 0;
}
''','Application/Dopamine/Jailbreak',False)

    @unittest.skipUnless(sys.platform == 'darwin', 'native exact daemon respring selection')
    def test_respring_never_signals_pid_one_or_an_unrelated_process(self):
        helper=(ROOT/'BaseBin/jbctl/src/roothide_respring.h').read_text()
        helper=helper.replace('#include <libproc.h>','').replace('#include <signal.h>','')
        boot.BootTransition().run_native(r'''
#include <sys/types.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>
#define SIGTERM 15
static int mode,kills,last;
static int proc_listallpids(void *buffer,int size){(void)size;if(mode==4)return 0;if(!buffer)return 3;pid_t *p=buffer;p[0]=1;p[1]=99;p[2]=100;return 3;}
static int proc_pidpath(int pid,void *path,unsigned size){(void)size;strcpy(path,pid==100&&mode!=2?"/usr/libexec/backboardd":"/usr/libexec/other");return 1;}
static int fake_kill(int pid,int signal){if(signal!=15)return -1;kills++;last=pid;if(mode==3){errno=EPERM;return -1;}return 0;}
#define kill fake_kill
'''+helper+r'''
int main(void){
 if(rh3_respring_backboardd()||kills!=1||last!=100)return 1;
 mode=2;if(rh3_respring_backboardd()!=ESRCH||kills!=1)return 2;
 mode=3;if(rh3_respring_backboardd()!=EPERM||kills!=2||last!=100)return 3;
 mode=4;if(rh3_respring_backboardd()!=ESRCH||kills!=2)return 4;
 return 0;
}
''','BaseBin/jbctl/src',False)
