# NewTerm / RootHide3 launchd parity candidate (disabled)

## Scope and evidence

- Target: iPhone X (iPhone10,3), iOS 16.7.15, NewTerm original bundle `ws.hbang.Terminal`.
- RootHide2 suspends ordinary launchd children, asks jailbreakd to patch the new process, and only then resumes it (`BaseBin/launchdhook/src/roothider.m`).
- RootHide3's shared spawn path excludes PID 1 from its `rh3_spawn_patched` cycle. This is a real code difference **but has not been proven causal** for NewTerm's failure.
- The last known `NewTerm.dpkg-tmp` crash started before the updated package was installed. Do not infer the behavior of the newly installed executable from that crash.

## Staged candidate

`BaseBin/launchdhook/src/spawn_hook.c` defines `RH3_EXPERIMENTAL_NEWTERM_LAUNCHD_PATCH_CHILD` to **0** unless explicitly overridden during compilation. No launchd changes are activated by the default build, app settings, an environment variable, or installation.

If deliberately compiled as `1` for a recovery-capable experiment, only `UIKitApplication:ws.hbang.Terminal[...]` executed through `/usr/libexec/xpcproxy` is considered, after all existing early-boot, first-load and blacklist bypasses. It additionally requires a launchdhook image in the verified RootHide root and authenticated jailbreakd check-in. DriverKit, SETEXEC, missing spawn attributes and already-suspended callers preserve existing semantics. Ordinary Dopamine3, Apple services and every other UIKit app take the unchanged path.

The child is launched suspended, the caller's flags are restored and launchd sends `JBD_MSG_SPAWN_PATCH_CHILD` directly to jailbreakd before resume. An unsuccessful patch kills only that child. This is *not* a runtime-tested safe patch: **synchronous IPC from PID 1 can deadlock if jailbreakd tries to launch a required service or process during the patch**. Authenticated daemon check-in is necessary, not sufficient, to rule that out. Do not enable on a user's functioning jailbreak until the IPC/reentrancy path and recovery route are independently validated.

## Recommended validation before any hardware beta

1. Preserve the current working r155 on the device. Finish inspecting r157 CI and run its read-only UUID/login diagnostic only through a separately validated update path.
2. Capture a fresh attempted launch of NewTerm original and inspect the *new* crash `procLaunch`, Mach-O UUID and dyld/XPC messages. Establish whether it fails before the UI, while starting `login`, or in SwiftUI.
3. Verify `jailbreakd_has_checked_in()` is true when the NewTerm xpcproxy job is launched and that `roothide_patch_proc` cannot synchronously request a launchd operation that waits for this same spawn to return. Require a timeout/recovery design before changing PID 1.
4. Run differential tests for xpcproxy label ambiguity, non-RootHide roots, first boot, user-space reboot, blacklist, missing attrs, DriverKit, SETEXEC, already-suspended caller, patch failure and daemon unavailable. The Python source-level tests are guards, **not hardware validation**.
5. Only after these checks, build a separate guarded candidate and compare stock NewTerm under otherwise identical conditions. Keep a known-good IPA and device recovery method available; never automatically install or perform userspace reboot as part of compilation.

`DYLD_IN_CACHE=0`, RootHide cwd relocation and alternate `systemhook` initialization remain separate hypotheses and are deliberately not changed here.
