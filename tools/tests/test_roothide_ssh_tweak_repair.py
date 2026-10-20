"""Regression guards for opt-in OpenSSH setup and actual tweak-load probing."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def source(path):
    return (ROOT / path).read_text(encoding="utf-8")


class RootHideSSHTweakRepairTests(unittest.TestCase):
    def test_donor_shsh_not_confused_with_openssh(self):
        hook = source("BaseBin/launchdhook/src/daemon_hook.m")
        self.assertIn('strcmp(label, "com.openssh.sshd")', hook)
        self.assertIn('xpc_dictionary_get_value(job, "Sockets")', hook)
        self.assertIn('JBROOT_PATH(@"/usr/sbin/sshd")', hook)
        self.assertIn('JBROOT_PATH(@"/etc/ssh/sshd_config")', hook)
        self.assertIn('JBROOT_PATH(@"/etc/ssh/ssh_host_ed25519_key")', hook)
        self.assertIn('@"-i", @"-f", config, @"-h", key', hook)
        self.assertIn('rh3_prepare_openssh_socket_job(daemonXdict)', hook)
        self.assertNotIn('us.diatr.shshd', hook)

    def test_repair_is_explicit_and_never_writes_stock_rootfs_or_plist(self):
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        repair = env.split("- (int)repairRootHideSSH", 1)[1].split(
            "- (int)verifyRootHideTweakInjection", 1)[0]
        self.assertIn('rootHideExistingRootWithError:&error', repair)
        self.assertIn('jbclient_get_jbroot()', repair)
        self.assertIn('O_DIRECTORY | O_NOFOLLOW', repair)
        self.assertIn('if (plistPath) return EEXIST', repair)
        self.assertIn('publicKeyPath = [keyPath stringByAppendingString:@".pub"]', repair)
        self.assertIn('lstat(publicKeyPath.fileSystemRepresentation, &publicInfo)', repair)
        self.assertIn('if (errno != ENOENT) return errno', repair)
        self.assertIn('fsync(directory)', repair)
        self.assertIn('@"com.openssh.sshd"', repair)
        self.assertIn('@"-t", @"ed25519", @"-N", @"", @"-f", keyPath', repair)
        self.assertIn('@"-t", @"-f", configPath, @"-h", keyPath', repair)
        self.assertNotIn('@"-A"', repair)
        for name in ('launchctl', 'kickstart', 'writeToFile:plistPath', 'chmod(plistPath',
                     'master.passwd', '/rootfs/'):
            self.assertNotIn(name, repair)

    def test_tweaks_use_authoritative_marker_and_watchdog_fails_closed(self):
        jb = source("Application/Dopamine/Jailbreak/DOJailbreaker.m")
        self.assertIn('if (!tweaksEnabled && ![DOBootstrapper rootHidePortEnabled])', jb)
        self.assertIn('existing RootHide marker authoritative', jb)
        watchdog = source("BaseBin/launchdhook/src/jbserver/jbdomain_watchdog.c")
        self.assertIn('O_WRONLY | O_CREAT | O_NOFOLLOW', watchdog)
        self.assertIn('fsync(markerFD)', watchdog)
        self.assertIn('if (markerError) return markerError', watchdog)
        self.assertNotIn('fclose(touchFile)', watchdog)
        hook = source("BaseBin/systemhook/src/main.c")
        self.assertIn('if (errno != ENOENT) return false', hook)

    def test_probe_is_real_process_runtime_check_not_file_presence(self):
        helper = source("BaseBin/tweakprobe/main.c")
        self.assertIn('RH3_TWEAK_PROBE_SYSTEMHOOK', helper)
        self.assertIn('RH3_TWEAK_PROBE_LOADER', helper)
        hook = source("BaseBin/systemhook/src/main.c")
        self.assertIn('string_has_suffix(gExecutablePath, "/basebin/rh3tweakprobe")', hook)
        self.assertIn('if (rh3Probe) setenv("RH3_TWEAK_PROBE_LOADER", "1", 1)', hook)
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        check = env.split("- (int)verifyRootHideTweakInjection", 1)[1].split(
            "- (void)unregisterJailbreakApps", 1)[0]
        self.assertIn('[self isTweakInjectionEnabled]', check)
        self.assertIn('rh3RunCommand:helper', check)
        self.assertIn('rootHideExistingRootWithError:&rootError', check)
        self.assertIn('jbclient_get_jbroot()', check)

    def test_privileged_marker_write_checks_same_root_and_fsync(self):
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        setter = env.split("- (int)setTweakInjectionEnabled:", 1)[1].split(
            "- (BOOL)isIDownloadEnabled", 1)[0]
        self.assertIn('rootHideExistingRootWithError:&rootError', setter)
        self.assertIn('jbclient_get_jbroot()', setter)
        self.assertIn('fsync(dir)', setter)
        ui = source("Application/Dopamine/UI/Settings/DOSettingsController.m")
        self.assertIn('verifyRootHideTweaksPressed', ui)
        self.assertIn('repairRootHideSSHPressed', ui)
        self.assertIn('Solo si ya has cambiado las contraseñas', ui)


if __name__ == "__main__":
    unittest.main()
