"""Postboot app controls: source contracts and native protocol rejection cases."""
from pathlib import Path
import sys
import unittest
import test_roothide_boot_transition as boot

ROOT = Path(__file__).resolve().parents[2]


class PostbootActions(unittest.TestCase):
    def test_relaunch_restores_server_root_and_validated_brand_together(self):
        source = (ROOT/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
        init = source.split('- (instancetype)init', 1)[1].split('- (NSString *)nightlyHash', 1)[0]
        self.assertIn('RH3CanonicalAppPath', init)
        self.assertIn('[DOBootstrapper rootHideBrandForPath:root]', init)
        self.assertIn('if (brand)', init)
        self.assertIn('gSystemInfo.jailbreakInfo.jbrand = brand', init)
        checked = source.split('- (int)rh3PerformPrivilegedAction:', 1)[1].split('- (int)spawnJbctlAsRootWithArgs:', 1)[0]
        self.assertIn('!self.isJailbroken || !roothide_is_active()', checked)
        self.assertIn('geteuid() != 0 || getegid() != 0', checked)
        self.assertLess(checked.index('jbclient_dopamine_get_root()'), checked.index('action()'))
        self.assertIn('@finally', checked)
        self.assertIn('jbclient_root_set_mac_label(1, labelBackup, NULL)', checked)
        self.assertIn('jbclient_dopamine_drop_root()', checked)

    def test_failed_spawn_never_waits_on_pid_zero_and_controls_display_failure(self):
        env = (ROOT/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
        spawn = env.split('- (int)spawnJbctlAsRootWithArgs:', 1)[1].split('- (int)runTrollStoreAction:', 1)[0]
        self.assertIn('if (r != 0 || pid <= 0) return', spawn)
        self.assertLess(spawn.index('if (r != 0 || pid <= 0) return'), spawn.index('cmd_wait_for_exit(pid)'))
        self.assertIn('needsLegacySolution && r == 0 && pid > 0', spawn)
        self.assertIn('posix_spawn_file_actions_addclose(&act, waitPipe[1])', spawn)
        settings = (ROOT/'Application/Dopamine/UI/Settings/DOSettingsController.m').read_text()
        self.assertIn('No se pudieron actualizar las apps', settings)
        main = (ROOT/'Application/Dopamine/UI/DOMainViewController.m').read_text()
        self.assertIn('No se pudo reiniciar SpringBoard', main)
        ctl = (ROOT/'BaseBin/jbctl/src/main.m').read_text()
        self.assertIn('if (result != 0) return result;', ctl.split('jbctl_wait_for_parent(fd)', 1)[1])

    @unittest.skipUnless(sys.platform == 'darwin', 'native parent/child pipe protocol')
    def test_parent_wait_rejects_eof_bad_tokens_and_invalid_descriptor(self):
        boot.BootTransition().run_native(r'''
#include "parent_wait.h"
int main(void){
 int p[2];if(pipe(p))return 1;close(p[1]);if(jbctl_wait_for_parent(p[0])!=EIO)return 2;
 if(pipe(p))return 3;if(write(p[1],"x",1)!=1)return 4;close(p[1]);if(jbctl_wait_for_parent(p[0])!=EIO)return 5;
 if(pipe(p))return 6;if(write(p[1],"w",1)!=1)return 7;close(p[1]);if(jbctl_wait_for_parent(p[0]))return 8;
 if(jbctl_wait_for_parent(-1)!=EBADF)return 9;
 return 0;
}
''', 'BaseBin/jbctl/src', False)

    @unittest.skipUnless(sys.platform == 'darwin', 'native typed XPC reply contract')
    def test_status_query_rejects_errors_and_root_calls_preserve_error_codes(self):
        source = (ROOT/'BaseBin/libjailbreak/src/jbclient_xpc.c').read_text()
        functions = source[source.index('bool jbclient_dopamine_is_jailbroken('):source.index('int jbclient_dopamine_roothide_bootlog(')]
        fixture = r'''
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
typedef struct { int type; int64_t number; } object;
typedef object *xpc_object_t;
#define XPC_TYPE_INT64 1
#define JBS_DOMAIN_DOPAMINE 5
#define JBS_DOPAMINE_IS_JAILBROKEN 1
#define JBS_DOPAMINE_GET_ROOT 2
#define JBS_DOPAMINE_DROP_ROOT 3
static object value={1,1},reply;
static bool available=true,present=true;
static xpc_object_t jbserver_xpc_send(int d,int a,void *v){(void)d;(void)a;(void)v;return available?&reply:NULL;}
static xpc_object_t xpc_dictionary_get_value(xpc_object_t r,const char *k){(void)r;(void)k;return present?&value:NULL;}
static const char *xpc_dictionary_get_string(xpc_object_t r,const char *k){(void)r;(void)k;return "3.0.11";}
static int xpc_get_type(xpc_object_t v){return v->type;}
static int64_t xpc_int64_get_value(xpc_object_t v){return v->number;}
static void xpc_release(xpc_object_t v){(void)v;}
'''+functions+r'''
int main(void){
 char *version=NULL;if(!jbclient_dopamine_is_jailbroken(&version)||!version)return 1;free(version);
 int statuses[]={0,-1,2,71};for(unsigned i=0;i<4;i++){value.number=statuses[i];if(jbclient_dopamine_is_jailbroken(NULL))return 2;if(jbclient_dopamine_get_root()!=statuses[i]||jbclient_dopamine_drop_root()!=statuses[i])return 3;}
 present=false;if(jbclient_dopamine_is_jailbroken(NULL)||jbclient_dopamine_get_root()!=EPROTO)return 4;
 present=true;value.type=2;if(jbclient_dopamine_is_jailbroken(NULL)||jbclient_dopamine_drop_root()!=EPROTO)return 5;
 available=false;if(jbclient_dopamine_is_jailbroken(NULL)||jbclient_dopamine_get_root()!=-1)return 6;
 return 0;
}
'''
        boot.BootTransition().run_native(fixture, 'BaseBin/libjailbreak/src', False)
