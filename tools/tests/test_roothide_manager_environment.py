from pathlib import Path
import sys
import unittest
import test_roothide_boot_transition as boot

ROOT = Path(__file__).resolve().parents[2]


class ManagerEnvironment(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin', 'native manager launch diagnostic filter')
    def test_launch_diagnostics_only_recognize_exact_manager_names(self):
        boot.BootTransition().run_native(r'''
#include "roothide_manager_spawn.h"
int main(void) {
 char *args[]={"xpcproxy","UIKitApplication:xyz.willy.Zebra[abc]",NULL};
 if(strcmp(rh3_manager_spawn_name("/usr/libexec/xpcproxy",args),"Zebra"))return 1;
 args[1]="UIKitApplication:xyz.willy.Zebra.extra[abc]";
 if(rh3_manager_spawn_name("/usr/libexec/xpcproxy",args))return 2;
 args[1]="service:org.coolstar.SileoStore[abc]";
 if(rh3_manager_spawn_name("/usr/libexec/xpcproxy",args))return 3;
 if(rh3_manager_spawn_name("/usr/libexec/xpcproxy",NULL))return 4;
 if(strcmp(rh3_manager_spawn_name("/hidden/Applications/Sileo.app/Sileo",NULL),"Sileo"))return 5;
 if(rh3_manager_spawn_name("/hidden/Applications/Sileo.app/SileoOther",NULL))return 6;
 if(rh3_manager_spawn_name(NULL,NULL))return 7;
 return 0;
}
''', 'BaseBin/launchdhook/src', False)

    def test_home_is_selected_for_current_user_and_refresh_timeout_is_not_success(self):
        source = (ROOT/'BaseBin/systemhook/src/roothider_port.c').read_text(encoding='utf-8')
        home = source.split('static void roothide_redirect_home', 1)[1].split('static void roothide_call_pathhook', 1)[0]
        self.assertIn('!issetugid()', home)
        self.assertNotIn("if (!home || home[0] != '/')", home)
        self.assertIn('getpwuid(geteuid())', home)
        settings = (ROOT/'Application/Dopamine/UI/Settings/DOSettingsController.m').read_text(encoding='utf-8')
        refresh = settings.split('- (void)refreshJailbreakAppsPressed', 1)[1].split('- (void)reinstallPackageManagersPressed', 1)[0]
        self.assertIn('45 * NSEC_PER_SEC', refresh)
        self.assertIn('if (completed) return', refresh)
        self.assertIn('if (gRootHideAppsRefreshInFlight)', refresh)
        self.assertIn('gRootHideAppsRefreshInFlight = result == ETIMEDOUT', refresh)
        self.assertIn('if (timedOut)', refresh)
        bootstrap = (ROOT/'Application/Dopamine/Jailbreak/DOBootstrapper.m').read_text(encoding='utf-8')
        finalize = bootstrap.split('- (NSError *)finalizeRootHideBootstrap\n', 1)[1]
        self.assertLess(finalize.index('RH3PrepareMobileHomeAtRoot(root)'), finalize.index('[self installPackageManagers]'))
        self.assertIn('RH3PrepareMobileHome(fd, 0, 501, 501)', bootstrap)

    @unittest.skipUnless(sys.platform == 'darwin', 'native owned mobile directory preparation')
    def test_mobile_directories_preserve_files_private_modes_and_reject_symlinks(self):
        boot.BootTransition().run_native(r'''
#include "RootHideMobileHome.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
int main(void) {
 char temp[]="/tmp/rh3-mobile-home-XXXXXX";
 if(!mkdtemp(temp)||chdir(temp)||mkdir("var",0755))return 1;
 int root=open(".",O_RDONLY|O_DIRECTORY);
 if(root<0 || RH3PrepareMobileHome(root,getuid(),getuid(),getgid()))return 2;
 struct stat st;
 if(stat("var/mobile/Library/Caches",&st)||st.st_uid!=getuid())return 3;
 int f=open("var/mobile/Library/Caches/preserve",O_CREAT|O_WRONLY,0600);
 if(f<0||write(f,"data",4)!=4)return 4;close(f);
 if(chmod("var/mobile/Library",0700))return 5;
 if(RH3PrepareMobileHome(root,getuid(),getuid(),getgid()))return 6;
 char content[4];f=open("var/mobile/Library/Caches/preserve",O_RDONLY);
 if(f<0||read(f,content,4)!=4||memcmp(content,"data",4))return 7;close(f);
 if(stat("var/mobile/Library",&st)||(st.st_mode&0777)!=0700)return 8;
 if(RH3PrepareMobileHome(root,getuid()+1,getuid(),getgid())!=EPERM)return 9;
 if(rename("var/mobile/Library/Caches","saved")||mkdir("outside",0700)||
    symlink("../../../outside","var/mobile/Library/Caches"))return 10;
 if(!RH3PrepareMobileHome(root,getuid(),getuid(),getgid()))return 11;
 if(stat("outside",&st)||(st.st_mode&0777)!=0700)return 12;
 if(lstat("var/mobile/Library/Caches",&st)||!S_ISLNK(st.st_mode))return 13;
 close(root);return 0;
}
''', 'Application/Dopamine/Jailbreak', False)

    @unittest.skipUnless(sys.platform == 'darwin', 'native RootHide home selection')
    def test_parent_root_home_is_not_inherited_by_mobile_or_prefixed_twice(self):
        source = (ROOT/'BaseBin/systemhook/src/roothider_port.c').read_text(encoding='utf-8')
        function = 'static void roothide_redirect_home' + source.split(
            'static void roothide_redirect_home', 1)[1].split('static void roothide_call_pathhook', 1)[0]
        boot.BootTransition().run_native(r'''
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <limits.h>
static char *inherited;
static char output[PATH_MAX];
static int writes, changed, noUser;
static uid_t user=501;
static struct passwd pwd;
static char *fixture_getenv(const char *name) { return inherited; }
static int fixture_setenv(const char *name,const char *value,int overwrite) {
 if(strcmp(name,"CFFIXED_USER_HOME") || !overwrite)return -1;
 writes++;strcpy(output,value);return 0;
}
static uid_t fixture_geteuid(void) { return user; }
static int fixture_issetugid(void) { return changed; }
static struct passwd *fixture_getpwuid(uid_t uid) {
 if(noUser)return NULL;
 pwd.pw_dir=uid==501?"/var/mobile":"/var/root";return &pwd;
}
#define getenv fixture_getenv
#define setenv fixture_setenv
#define geteuid fixture_geteuid
#define issetugid fixture_issetugid
#define getpwuid fixture_getpwuid
''' + function + r'''
int main(void) {
 inherited="/var/root";roothide_redirect_home("/hidden");
 if(writes!=1 || strcmp(output,"/hidden/var/mobile"))return 1;
 inherited="/old-hidden/var/root";roothide_redirect_home("/hidden");
 if(writes!=2 || strcmp(output,"/hidden/var/mobile"))return 2;
 inherited="/hidden/var/mobile";roothide_redirect_home("/hidden");
 if(writes!=3 || strcmp(output,"/hidden/var/mobile"))return 3;
 inherited="/private/var/mobile/Containers/Data/Application/example";
 roothide_redirect_home("/hidden");if(writes!=3)return 4;
 changed=1;roothide_redirect_home("/hidden");
 if(writes!=4 || strcmp(output,"/hidden/var/mobile"))return 5;
 changed=0;inherited=NULL;user=0;roothide_redirect_home("/hidden");
 if(writes!=5 || strcmp(output,"/hidden/var/root"))return 6;
 noUser=1;roothide_redirect_home("/hidden");
 if(writes!=6 || strcmp(output,"/hidden/var/empty"))return 7;
 return 0;
}
''', 'BaseBin/systemhook/src', False)
