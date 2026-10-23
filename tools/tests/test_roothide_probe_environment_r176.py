"""Real C harness for RootHide's isolated probe environment and caller gate.

Host tests are not proof that iOS dyld loaded the injected library.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HEADER = ROOT / "Application/Dopamine/Jailbreak/RH3ProbeSpawnEnv.h"
ENVIRONMENT = ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m"


class ProbeEnvironmentTests(unittest.TestCase):
    def test_only_verified_short_lived_probe_can_request_environment(self):
        text = ENVIRONMENT.read_text(encoding="utf-8")
        method = text.split("- (int)rh3RunCommand:", 1)[1].split(
            "- (int)refreshJailbreakApps", 1
        )[0]
        self.assertIn('isEqualToString:@"rh3tweakprobe"', method)
        self.assertIn('basebin/rh3tweakprobe', method)
        self.assertIn('basebin/systemhook.dylib', method)
        self.assertIn('rootHideExistingRootWithError:&rootError', method)
        self.assertIn('jbclient_get_jbroot()', method)
        self.assertIn('hookInfo.st_uid != 0', method)
        self.assertIn('rh3_probe_env_build(environ', method)
        self.assertIn('rh3_probe_env_free(probeEnvironment)', method)
        self.assertIn('probeEnvironment ? probeEnvironment : environ', method)

    def test_real_environment_builder_filters_only_probe_specific_flags(self):
        compiler = shutil.which("gcc") or shutil.which("clang") or shutil.which("cc")
        if not compiler:
            self.skipTest("Host C compiler unavailable")
        source = r'''
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include "RH3ProbeSpawnEnv.h"
#define CHECK(x) do { if (!(x)) {fprintf(stderr, "check line %d: %s\n",__LINE__,#x);return 1;} } while (0)
static int count_prefix(char **e, const char *prefix) {
    int n=0;
    for(size_t i=0; e && e[i];i++) if(!strncmp(e[i],prefix,strlen(prefix))) n++;
    return n;
}
static bool has(char **e, const char *value) {
    for(size_t i=0; e && e[i];i++) if(!strcmp(e[i],value)) return true;
    return false;
}
int main(void) {
    char *parent[]={"A=one","DISABLE_TWEAKS=1","DYLD_IN_CACHE=1",
        "DYLD_INSERT_LIBRARIES=/unrelated.dylib", "_SafeMode=1", "_MSSafeMode=1",
        "DYLD_IN_CACHE=4", "Z=two", "RH3_TWEAK_PROBE_SYSTEMHOOK=1",
        "RH3_TWEAK_PROBE_LOADER=1",NULL};
    char **e=NULL;
    const char *hook="/var/containers/Bundle/Application/.jbroot-0123456789ABCDEF/basebin/systemhook.dylib";
    CHECK(rh3_probe_env_build(parent,hook,&e)==0 && e);
    CHECK(has(e,"DYLD_IN_CACHE=0"));
    CHECK(has(e,"A=one") && has(e,"Z=two"));
    CHECK(count_prefix(e,"DYLD_IN_CACHE=")==1);
    CHECK(count_prefix(e,"DYLD_INSERT_LIBRARIES=")==1);
    CHECK(count_prefix(e,"DISABLE_TWEAKS=")==0);
    CHECK(count_prefix(e,"_SafeMode=")==0);
    CHECK(count_prefix(e,"_MSSafeMode=")==0);
    CHECK(count_prefix(e,"RH3_TWEAK_PROBE_SYSTEMHOOK=")==0);
    CHECK(count_prefix(e,"RH3_TWEAK_PROBE_LOADER=")==0);
    CHECK(strstr(e[0],hook)!=NULL && !strcmp(parent[2],"DYLD_IN_CACHE=1"));
    rh3_probe_env_free(e);
    e=(char**)0x1;
    CHECK(rh3_probe_env_build(parent,"relative/path",&e)==EINVAL && e==NULL);
    CHECK(rh3_probe_env_build(parent,"/path:bad",&e)==EINVAL && e==NULL);
    CHECK(rh3_probe_env_build(parent,"/path\nbad",&e)==EINVAL && e==NULL);
    CHECK(rh3_probe_env_build(NULL,hook,&e)==0 && e);
    CHECK(count_prefix(e,"DYLD_IN_CACHE=")==1 && count_prefix(e,"DYLD_INSERT_LIBRARIES=")==1);
    rh3_probe_env_free(e);
    char *oversize[4098];
    for (int i=0;i<4097;i++) oversize[i]="A=one";
    oversize[4097]=NULL;
    CHECK(rh3_probe_env_build(oversize,hook,&e)==E2BIG && e==NULL);
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "probe.c"
            executable = Path(directory) / "probe.exe"
            source_path.write_text(source, encoding="utf-8")
            result = subprocess.run([
                compiler, "-std=gnu11", "-Wall", "-Wextra", "-I", str(HEADER.parent),
                str(source_path), "-o", str(executable),
            ], capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            ran = subprocess.run([str(executable)], capture_output=True, text=True, timeout=10)
            self.assertEqual(ran.returncode, 0, ran.stderr)


if __name__ == "__main__":
    unittest.main()
