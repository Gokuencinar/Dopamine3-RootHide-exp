"""Regression guards for the one-shot RootHide exec patch launch race."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RootHideExecPatchRaceTests(unittest.TestCase):
    def test_exec_registration_precedes_kevent_one_shot(self):
        src = (ROOT / "BaseBin/libjailbreak/src/roothider/exec_patch.m").read_text()
        add = src.split("int spawnExecPatchAdd(int pid, bool resume)", 1)[1].split(
            "int spawnExecPatchDel(int pid)", 1
        )[0]
        self.assertIn("dispatch_sync(gExecPatchDataQueue", add)
        self.assertNotIn("dispatch_async(gExecPatchDataQueue", add)
        self.assertLess(add.index("[gExecPatchArray setObject:@(resume)"),
                        add.index("kevent(kq, &kev, 1, NULL, 0, NULL)"))
        self.assertIn("if (alreadyRegistered) return -1", add)
        self.assertGreater(add.rfind("[gExecPatchArray removeObjectForKey:@(pid)]"),
                           add.index("kevent(kq, &kev, 1, NULL, 0, NULL)"))

    def test_openssh_import_never_silently_rebases_without_opt_in(self):
        src = (ROOT / "BaseBin/launchdhook/src/daemon_hook.m").read_text()
        self.assertNotIn("rh3_prepare_openssh_socket_job", src)
        method = src.split("void xpc_dictionary_add_launch_daemon_plist_at_path", 1)[1].split(
            "xpc_object_t (*xpc_dictionary_get_value_orig)", 1
        )[0]
        self.assertIn("xpc_create_from_plist(addr, len)", method)
        self.assertIn("xpc_dictionary_set_value(xdict, path, daemonXdict)", method)
        self.assertNotIn('xpc_dictionary_set_string(job, "Program"', method)
        self.assertNotIn('xpc_dictionary_set_value(job, "ProgramArguments"', method)

    def test_lsd_auto_uicache_cannot_launch_concurrent_rebuild_children(self):
        src = (ROOT / "BaseBin/roothidehooks/lsd.x").read_text()
        hook = src.split("int new_LSServer_RebuildApplicationDatabases()", 1)[1].split(
            "void lsdInit(void)", 1
        )[0]
        self.assertIn("rh3AutoUICacheInFlight", src)
        self.assertIn("__sync_bool_compare_and_swap(&rh3AutoUICacheInFlight, 0, 1)", hook)
        self.assertIn("__sync_lock_release(&rh3AutoUICacheInFlight)", hook)
        self.assertLess(hook.index("__sync_bool_compare_and_swap"),
                        hook.index("dispatch_async("))
        self.assertLess(hook.index("wait_for_exit(pid)"),
                        hook.index("__sync_lock_release(&rh3AutoUICacheInFlight)"))

    def test_refresh_skips_verifiably_registered_active_root_apps(self):
        src = (ROOT / "Application/Dopamine/Jailbreak/DOEnvironmentManager.m").read_text()
        refresh = src.split("- (int)refreshJailbreakApps", 1)[1].split(
            "- (int)diagnoseRootHideRuntime", 1
        )[0]
        self.assertIn("LSApplicationProxy applicationProxyForIdentifier:bundleID", refresh)
        self.assertIn("registered.installed", refresh)
        self.assertIn("RH3CanonicalAppPath(registered.bundleURL.path)", refresh)
        self.assertIn("isEqualToString:RH3CanonicalAppPath(path)", refresh)
        self.assertLess(refresh.index("registration already points to active root"),
                        refresh.index('arguments:@[@"-p", path]'))
        self.assertIn("registration summary already_present=", refresh)


if __name__ == "__main__":
    unittest.main()
