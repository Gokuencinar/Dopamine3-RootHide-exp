"""Postboot app controls: source contracts and native protocol rejection cases."""
from pathlib import Path
import sys
import unittest
import test_roothide_boot_transition as boot

ROOT = Path(__file__).resolve().parents[2]


class PostbootActions(unittest.TestCase):
    def test_reboot_failure_is_reported_before_any_root_hide_fade(self):
        main = (ROOT/'Application/Dopamine/UI/DOMainViewController.m').read_text()
        run = main.split('[jailbreaker runWithError:', 1)[1].split('-(void)setupUpdateAvailable:', 1)[0]
        self.assertLess(run.index('int result = [jailbreaker finalize]'), run.index('if (error && showLogs)'))
        self.assertIn('error = [NSError errorWithDomain:@"RootHide" code:result', run)
        self.assertLess(run.index('if ([DOBootstrapper rootHidePortEnabled]) return;'), run.index('[self fadeToBlack:'))
        env = (ROOT/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
        reboot = env.split('- (int)rebootUserspace', 1)[1].split('- (void)rebuildIconCache', 1)[0]
        self.assertIn('return result;', reboot)
        server = (ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c').read_text()
        self.assertIn('.permissionHandler = dopamine_domain_allowed', server)
        root = (ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_root.c').read_text()
        self.assertIn('audit_token_to_euid(clientToken) == 0', root)

    @unittest.skipUnless(sys.platform == 'darwin', 'native caller-only sandbox permission checks')
    def test_sandbox_action_checks_kernel_credentials_and_changes_only_caller_slot(self):
        source = (ROOT/'BaseBin/launchdhook/src/jbserver/jbdomain_dopamine.c').read_text()
        handler = source[source.index('static int dopamine_roothide_set_sandbox_label('):source.index('struct jbserver_domain gDopamineDomain')]
        boot.BootTransition().run_native(r'''
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
typedef struct {int pid;int auditUID;} audit_token_t;
static bool active=true,hasProc=true,hasCred=true,hasLabel=true,writeFails=false;
static uint32_t uid,gid;static uint64_t seatbelt=123;static int writes;
#define koffsetof(a,b) offset_##b
enum {offset_uid=4,offset_groups=8,offset_label=16};
static bool roothide_is_active(void){return active;}
static int audit_token_to_pid(audit_token_t t){return t.pid;}
static uint64_t proc_find(int pid){return hasProc&&pid==278?100:0;}
static uint64_t proc_ucred(uint64_t proc){return hasCred&&proc==100?200:0;}
static uint32_t kread32(uint64_t addr){return addr==204?uid:gid;}
static uint64_t kread_ptr(uint64_t addr){return hasLabel&&addr==216?300:0;}
static uint64_t mac_label_get(uint64_t label,int slot){return label==300&&slot==1?seatbelt:0;}
static void mac_label_set(uint64_t label,int slot,uint64_t value){if(label==300&&slot==1){writes++;if(!writeFails)seatbelt=value;}}
'''+handler+r'''
int main(void){
 audit_token_t caller={278,501};uint64_t old=0;
 if(dopamine_roothide_set_sandbox_label(&caller,UINT64_MAX,&old)||old!=123||seatbelt!=UINT64_MAX||writes!=1)return 1;
 if(dopamine_roothide_set_sandbox_label(&caller,old,&old)||seatbelt!=123||old!=UINT64_MAX)return 2;
 uid=501;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=EPERM||writes!=2)return 3;
 uid=0;gid=501;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=EPERM||writes!=2)return 4;
 gid=0;hasProc=false;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=ESRCH||writes!=2)return 5;
 hasProc=true;hasCred=false;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=ESRCH||writes!=2)return 6;
 hasCred=true;hasLabel=false;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=EINVAL||writes!=2)return 7;
 hasLabel=true;active=false;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=ENOTSUP||writes!=2)return 8;
 active=true;caller.pid=999;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=ESRCH||writes!=2)return 9;
 caller.pid=278;writeFails=true;if(dopamine_roothide_set_sandbox_label(&caller,0,&old)!=EIO)return 10;
 return 0;
}
''', 'BaseBin/libjailbreak/src', False)

    @unittest.skipUnless(sys.platform == 'darwin', 'native sandbox XPC reply validation')
    def test_sandbox_client_rejects_incomplete_or_untyped_reply(self):
        source = (ROOT/'BaseBin/libjailbreak/src/jbclient_xpc.c').read_text()
        client = source[source.index('int jbclient_dopamine_roothide_set_sandbox_label('):]
        boot.BootTransition().run_native(r'''
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <stddef.h>
typedef struct {int type;int64_t number;} object;typedef object *xpc_object_t;
enum {XPC_TYPE_INT64=1,XPC_TYPE_UINT64=2,JBS_DOMAIN_DOPAMINE=5,JBS_DOPAMINE_ROOTHIDE_SET_SANDBOX_LABEL=5};
static object status={1,0},previous={2,123},reply,args;
static bool available=true,hasStatus=true,hasOld=true;static uint64_t sent;
static xpc_object_t xpc_dictionary_create_empty(void){return &args;}
static void xpc_dictionary_set_uint64(xpc_object_t a,const char *k,uint64_t v){(void)a;(void)k;sent=v;}
static xpc_object_t jbserver_xpc_send(int d,int a,xpc_object_t v){return available&&d==5&&a==5&&v==&args?&reply:NULL;}
static void xpc_release(xpc_object_t v){(void)v;}
static xpc_object_t xpc_dictionary_get_value(xpc_object_t r,const char *k){(void)r;return !strcmp(k,"result")?(hasStatus?&status:NULL):(hasOld?&previous:NULL);}
static int xpc_get_type(xpc_object_t v){return v->type;}
static int64_t xpc_int64_get_value(xpc_object_t v){return v->number;}
static uint64_t xpc_uint64_get_value(xpc_object_t v){return (uint64_t)v->number;}
'''+client+r'''
int main(void){
 uint64_t old=999;if(jbclient_dopamine_roothide_set_sandbox_label(UINT64_MAX,&old)||old!=123||sent!=UINT64_MAX)return 1;
 old=999;status.number=EPERM;if(jbclient_dopamine_roothide_set_sandbox_label(0,&old)!=EPERM||old!=999)return 2;
 status.number=0;hasOld=false;if(jbclient_dopamine_roothide_set_sandbox_label(0,&old)!=EPROTO||old!=999)return 3;
 hasOld=true;previous.type=1;if(jbclient_dopamine_roothide_set_sandbox_label(0,NULL)!=EPROTO)return 4;
 previous.type=2;hasStatus=false;if(jbclient_dopamine_roothide_set_sandbox_label(0,&old)!=EPROTO)return 5;
 hasStatus=true;status.type=2;if(jbclient_dopamine_roothide_set_sandbox_label(0,&old)!=EPROTO)return 6;
 available=false;if(jbclient_dopamine_roothide_set_sandbox_label(0,&old)!=ENOTCONN)return 7;
 available=true;status.type=1;if(jbclient_dopamine_roothide_set_sandbox_label(0,NULL))return 8;
 return 0;
}
''', 'BaseBin/libjailbreak/src', False)

    @unittest.skipUnless(sys.platform == 'darwin', 'native numeric version ordering')
    def test_jbctl_3011_uses_parent_pipe_instead_of_legacy_suspension(self):
        source = (ROOT/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
        helper = source.split('static BOOL DOUsesLegacyJbctl', 1)[1].split('@implementation', 1)[0]
        boot.BootTransition().run_native('#import <Foundation/Foundation.h>\nstatic BOOL DOUsesLegacyJbctl'+helper+r'''
int main(void){@autoreleasepool{
 if(!DOUsesLegacyJbctl(@"3.0.4"))return 1;
 for(NSString *version in @[@"3.0.5",@"3.0.11",@"3.0.100",@"3.1.0",@"4.0.0"])
  if(DOUsesLegacyJbctl(version))return 2;
 if(DOUsesLegacyJbctl(nil))return 3;
 return 0;
}}
''','Application/Dopamine/Jailbreak',True)

    def test_relaunch_restores_server_root_and_validated_brand_together(self):
        source = (ROOT/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
        init = source.split('- (instancetype)init', 1)[1].split('- (NSString *)nightlyHash', 1)[0]
        self.assertIn('RH3CanonicalAppPath', init)
        self.assertIn('[DOBootstrapper rootHideBrandForPath:root]', init)
        self.assertIn('if (brand)', init)
        self.assertIn('gSystemInfo.jailbreakInfo.jbrand = brand', init)
        checked = source.split('- (int)rh3PerformPrivilegedAction:', 1)[1].split('- (int)spawnJbctlAsRootWithArgs:', 1)[0]
        self.assertIn('BOOL jailbroken = self.isJailbroken', checked)
        self.assertIn('BOOL active = roothide_is_active()', checked)
        self.assertIn('if (!jailbroken || !active)', checked)
        self.assertIn('geteuid() != 0 || getegid() != 0', checked)
        self.assertLess(checked.index('jbclient_dopamine_get_root()'), checked.index('action()'))
        self.assertIn('@finally', checked)
        self.assertIn('jbclient_dopamine_roothide_set_sandbox_label(labelBackup, NULL)', checked)
        self.assertNotIn('jbclient_root_set_mac_label', checked)
        self.assertIn('jbclient_dopamine_drop_root()', checked)

    def test_failed_spawn_never_waits_on_pid_zero_and_controls_display_failure(self):
        env = (ROOT/'Application/Dopamine/Jailbreak/DOEnvironmentManager.m').read_text()
        spawn = env.split('- (int)spawnJbctlAsRootWithArgs:', 1)[1].split('- (int)runTrollStoreAction:', 1)[0]
        self.assertIn('if (r != 0 || pid <= 0) {', spawn)
        self.assertIn('int failure = r != 0 ? r : ECHILD;', spawn)
        self.assertLess(spawn.index('if (r != 0 || pid <= 0) {'), spawn.index('cmd_wait_for_exit(pid)'))
        self.assertIn('needsLegacySolution && r == 0 && pid > 0', spawn)
        self.assertIn('posix_spawn_file_actions_addclose(&act, waitPipe[1])', spawn)
        self.assertIn('RootHide jbctl failed before wait: result=%d pid=%d pipe_error=%d', spawn)
        self.assertIn('RootHide jbctl request %@: jailbroken=%d active_root=%d legacy=%d', spawn)
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
