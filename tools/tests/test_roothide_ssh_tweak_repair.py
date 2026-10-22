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

    def test_repair_is_explicit_and_never_writes_stock_rootfs_or_starts_service(self):
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        repair = env.split("- (int)repairRootHideSSH", 1)[1].split(
            "// Read the effective launchd disabled override", 1)[0]
        self.assertIn('rootHideExistingRootWithError:&error', repair)
        self.assertIn('jbclient_get_jbroot()', repair)
        self.assertIn('O_DIRECTORY | O_NOFOLLOW', repair)
        self.assertIn('if (plistPath) {', repair)
        self.assertIn('SSH preflight: duplicate OpenSSH socket job', repair)
        self.assertIn('return EEXIST; // Ambiguous OpenSSH service', repair)
        self.assertIn('publicKeyPath = [keyPath stringByAppendingString:@".pub"]', repair)
        self.assertIn('lstat(publicKeyPath.fileSystemRepresentation, &publicInfo)', repair)
        self.assertIn('if (errno != ENOENT) return errno', repair)
        self.assertIn('fsync(directory)', repair)
        self.assertIn('@"com.openssh.sshd"', repair)
        self.assertIn('@"-t", @"ed25519", @"-N", @"", @"-f", keyPath', repair)
        self.assertIn('@"-t", @"-f", configPath, @"-h", keyPath', repair)
        self.assertIn('RH3SSHRebaseInstalledPlist(plistPath, sshdPath, configPath, keyPath, &changed, &failedAt)', repair)
        self.assertIn('config/key validated; socket job atomic rebase', repair)
        self.assertIn('stage=%s; no service started', repair)
        self.assertNotIn('@"-A"', repair)
        for name in ('launchctl', 'kickstart', 'writeToFile:plistPath', 'chmod(plistPath',
                     'master.passwd', '/rootfs/'):
            self.assertNotIn(name, repair)

    def test_atomic_ssh_plist_rebase_is_single_job_and_preserves_sockets(self):
        env = source("Application/Dopamine/Jailbreak/DOEnvironmentManager.m")
        repair = env.split('static int RH3SSHRebaseInstalledPlist(', 1)[1].split(
            '// Procursus names the entries SSHListener', 1)[0]
        self.assertIn('@"com.openssh.sshd.plist"', repair)
        self.assertIn('const char *jobName = "com.openssh.sshd.plist"', repair)
        self.assertIn('const char *backupName = ".com.openssh.sshd.rh3-original"', repair)
        self.assertIn('const char *nextName = ".com.openssh.sshd.rh3-next"', repair)
        self.assertIn('job[@"Program"] = sshd;', repair)
        self.assertIn('job[@"ProgramArguments"] = args;', repair)
        self.assertIn('@[sshd, @"-i", @"-f", config, @"-h", key]', repair)
        self.assertIn('job[@"Sockets"]', repair)
        self.assertIn('job[@"inetdCompatibility"]', repair)
        self.assertNotIn('job[@"Sockets"] =', repair)
        self.assertNotIn('job[@"Disabled"] =', repair)
        self.assertNotIn('job[@"inetdCompatibility"] =', repair)
        self.assertIn('O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC', repair)
        self.assertIn('O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC', repair)
        self.assertIn('before.st_nlink != 1', repair)
        self.assertIn('bs.st_nlink != 1', repair)
        self.assertIn('fstatat(dir, jobName, &current, AT_SYMLINK_NOFOLLOW)', repair)
        self.assertIn('renameat(dir, nextName, dir, jobName)', repair)
        self.assertIn('if (fsync(dir))', repair)
        self.assertIn('RH3SSHReadBounded(checked, checkedInfo.st_size)', repair)
        self.assertIn('if (madeBackup && result && !renamedJob)', repair)
        self.assertIn('const char **stageOut', repair)
        for stage in ('directory_stat', 'directory_owner', 'directory_permissions',
                      'open_original', 'original_group', 'original_permissions',
                      'original_links', 'backup_owner', 'backup_permissions',
                      'backup_metadata', 'backup_contract', 'create_replacement',
                      'replacement_owner', 'replacement_permissions',
                      'replacement_write_sync', 'replace_atomic'):
            self.assertIn('"' + stage + '"', repair)
        for forbidden in ('launchctl', 'kickstart', 'bootout', 'reboot3', 'chmod(plistPath',
                          'chown(plistPath', 'us.diatr.shshd', 'master.passwd'):
            self.assertNotIn(forbidden, repair)

    def test_ui_confirms_persistent_and_delayed_service_change(self):
        ui = source("Application/Dopamine/UI/Settings/DOSettingsController.m")
        self.assertIn('Reparar OpenSSH en RootHide (con respaldo)', ui)
        self.assertIn('únicamente Program y ProgramArguments', ui)
        self.assertIn('No se activará ningún servicio', ui)
        self.assertIn('El servicio activo aún no se ha recargado', ui)

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
