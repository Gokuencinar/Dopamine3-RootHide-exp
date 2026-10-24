"""Installer write rights must be limited to trusted hidden-root helpers."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class RootHideScopedInstallerRights(unittest.TestCase):
    def test_verified_helper_and_root_parent_required(self):
        server = (ROOT / "BaseBin/jailbreakd/src/server.m").read_text(encoding="utf-8")
        method = server.split("static bool rh3_installer_child_is_trusted(", 1)[1].split(
            "static int rh3_patch_installer_right", 1
        )[0]
        self.assertIn("roothide_is_active()", method)
        self.assertIn("jbinfo(rootPath)", method)
        self.assertIn("strcmp(childPath, expected) == 0", method)
        for helper in ("/usr/bin/dpkg", "/usr/bin/ssh-keygen", "/usr/sbin/pw", "/usr/sbin/pwd_mkdb"):
            self.assertIn(helper, method)
        self.assertIn("lstat(childPath, &info)", method)
        self.assertIn("info.st_uid != 0", method)
        self.assertIn("info.st_mode & 0022", method)
        case = server.split("case JBD_MSG_SPAWN_PATCH_CHILD:", 1)[1].split(
            "case JBD_MSG_SPAWN_EXEC_START:", 1
        )[0]
        self.assertIn("ppid == clientPid && sameChild", case)
        self.assertIn("clientPid != 1 && clientUid == 0", case)
        self.assertIn("rh3_installer_child_is_trusted(childPath)", case)
        self.assertIn("rh3_patch_installer_right(pid, maySpawnMaintainer)", case)
        self.assertIn("result == 0 && resume", case)

    def test_only_package_account_managers_inherit_right(self):
        server = (ROOT / "BaseBin/jailbreakd/src/server.m").read_text(encoding="utf-8")
        impl = server.split("static int rh3_patch_installer_right(", 1)[1].split(
            "void jailbreakd_reply_message", 1
        )[0]
        self.assertIn("CS_INSTALLER", impl)
        self.assertIn("childExecInheritance ? CS_EXEC_INHERIT_SIP : 0", impl)
        self.assertIn("(proc_getcsflags(proc) & required) == required", impl)
        self.assertIn('string_has_suffix(childPath, "/usr/bin/dpkg")', server)
        self.assertIn('string_has_suffix(childPath, "/usr/sbin/pw")', server)
        self.assertNotIn("CS_INSTALLER | CS_EXEC_INHERIT_SIP", server.split(
            "void jailbreakd_reply_message", 1)[1].split("case JBD_MSG_SPAWN_PATCH_CHILD", 1)[0])


if __name__ == "__main__":
    unittest.main()
