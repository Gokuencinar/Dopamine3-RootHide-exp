# RootHide3: r188 failed on hardware — stop publishing unvalidated IPAs

**Status:** failure confirmed by device operator; investigation and source-only corrective work. Do not build, publish, install, uninstall or migrate a bootstrap from this document. Do not infer that an IPA, an ad-hoc signature, a trustcache upload or an XPC reply demonstrates a functioning jailbreak.

## Physical result (highest-priority evidence)

On October 23, 2026, the operator tested `RootHide3-Hardware-Beta-r188-a1-25efa75.ipa` after trying earlier r185. On the iPhone X / iOS 16.7.15, the operator reports **all five functions still failing**, unchanged: NewTerm cannot run; Zebra does not open; the `mobile` password cannot be changed; tweaks neither execute nor appear in Settings; OpenSSH does not function. This supersedes any suggestion in earlier release notes that r188 fixes these symptoms. No r188 diagnostic log or crash report has yet been supplied with this physical report; no banner/TCP test or daemon-state snapshot was supplied. Do not fabricate it.

## Source-level causes / gaps that must be distinguished

1. **Spawn/injection path:** `BaseBin/systemhook/src/common/common.c:462` explicitly excludes PID 1 from the RootHide `rh3_spawn_patched` branch (lines 477-485); `BaseBin/launchdhook/src/spawn_hook.c` uses a separate PID1 wrapper which injects the already-selected systemhook and selects private dyld, but does not patch-before-resume. `roothide_patch_proc` in `BaseBin/libjailbreak/src/roothider/common.m:257-264` may apply only `CS_GET_TASK_ALLOW` when dyld patch is off. The last physical probe before r188 exited `81`, not proof that a constructor ran. This gap plausibly relates to tweaks and process initialization, but is not yet proven as the sole hardware cause. **Do not** copy RootHide2's synchronous PID1→jailbreakd patch request: it can deadlock launchd and lacks safe proc lifetime/PID-generation protection.
2. **Existing root and managers:** `Application/Dopamine/Jailbreak/DOBootstrapper.m:1687-1689,1862-1899` interprets `.installed_roothide3=3` as installed, skips manager `dpkg` and the first-registration `RH3RegisterPinnedJailbreakApps` on subsequent attempts. Root rerandomization or LaunchServices records can therefore stay stale. `refreshJailbreakApps` and explicit manager reinstall exist, but their post-install success does not establish that Zebra's UI actually runs. Do not erase the marker to force reinstalls.
3. **SSH:** the auto repair of `com.openssh.sshd` is opt-in and subject to installer checks (`DOEnvironmentManager.m`); the normal jailbreak flow does not explicitly run the commented-out `launchctl bootstrap` calls at `DOJailbreaker.m:1315-1319`. Past `launchctl` status `runs=0` is not enough to tell if socket activation failed without a new actual connection and before/after snapshot. Preserve host keys and plist backups.
4. **Mobile account:** `DOEnvironmentManager.m:2461-2521` runs `pw -V <active-root>/etc usermod mobile -h 0`, preflights ownership/database existence and compares hashes; a physical `pw` exit 1 has been reported after spawn/patch. Root cause could be db semantics, permission, or process execution; do not modify `master.passwd` or `spwd.db` by hand or blindly retry the password operation.
5. **Daemon IPC safety hole in legacy clients:** `BaseBin/libjailbreak/src/roothider/jailbreakd.c` registered the `HOST_LAUNCHCTL_PORT` fast send right before authenticated checkin, and non-PID1 clients selected that right without a checkin gate, before trying the guarded launchd lookup. They could then block indefinitely in `xpc_pipe_routine` on an unserviced port. Local source fix removes the fast-path publication/selection, routes external clients exclusively via the launchd domain that already requires checkin, and requires checkin for PID1's direct return. **The modern process lifecycle client** (`jbclient_roothide.c:13-72`) **already used guarded lookup**: this repair closes the legacy route, not a proven cause of all five r188 failures. The daemon can still die after checkin; XPC request itself still has no deadline.

## New release safeguard

r188 Actions run `40026582113` completed native Build, architecture and IPA signature/structure checks, and **published a public prerelease**; the strict 7/9 port audit then failed because neither `ROOTHIDE3_BOOTSTRAP_READY=1` as source-default nor `validation/device-tests.json` hardware evidence was present. That ordering made a failed workflow yield a public downloadable IPA. The local workflow change runs the existing strict audit **before** the public GitHub Release step. A manually requested hardware-beta CI artifact remains possible for testing, but a public GitHub Release is blocked without completing the unchanged gate; no fake evidence and no enabling the global default bootstrap flag. No push or new workflow was started.

## Evidence still required before any further candidate

Need one complete **r188** read-only RootHide diagnostic export and, if available, the NewTerm/Zebra crash reason (no credentials, SSH keys, password hashes, full private paths or other personal data). Distinguish in order: authenticated jailbreakd checkin and liveness; actual PID1 systemhook inserts and private dyld checkin; disposable tweakprobe constructor and loader; LaunchServices actual proxy from privileged/unprivileged contexts; `sshd` job's before/after socket activation; `pw` exit stage and root database metadata. Fix individual reproduced failure modes and demonstrate them with instrumented tests before any further hardware artifact. Do not erase or reconstruct the user's existing bootstrap to obtain a clean test.

## Validation boundary

The local CI workflow ordering and fast-port checkin tests are host/static regressions. They do not validate launchd's private XPC protocol on iOS, dyld/PAC/SPTM, or the user's installed packages; userspace/hardware validation remains blocked. Preserve the existing untracked `tools/tests/__pycache__/`, package database, RootHide root, package manager choices, settings, SSH keys and accounts.

## Reference fork checked after the r188 failure (24 October 2026)

The proposed "fully working" RootHide/Dopamine 3 donor is
`https://github.com/devnoname120/Dopamine/tree/roothide-dopamine3`, pinned at
`3a9c8dc212294f25fc9a03bba3aab38e1cc1a9a3` (12 October 2026 UTC),
fetched as the read-only git ref
`refs/remotes/reference/devnoname120-roothide-dopamine3`. Its own README and
BUILD.md explicitly say **no physical iPhone validation**. It is not evidence
of a functional replacement IPA. Source comparison is useful nevertheless:

- Donor `BaseBin/launchdhook/src/roothider.m` suspends non-driver children,
  invokes synchronous `jbdSpawnPatchChild` from PID 1 and resumes or kills.
  Local launchdhook skips that high-risk round trip. Do not transplant it
  without an asynchronous, bounded authenticated protocol and PID generation
  checks. Parent PID matching alone does not protect against PID reuse.
- Donor `BaseBin/systemhook/src/main.c` and `roothider_main.c` separate
  `roothide_init`, checked-in process initialization and executable-specific
  late hooks. Local `roothider_port.c` consolidates these, does not copy
  sysctl/dyld fallback hooks, and loads `roothideinit.dylib` only after checkin.
  These are **architecture differences, not proof of runtime causation**.
- The pinned `roothide_bootstrap_1900.tar.zst` has
  `./usr/lib/roothideinit.dylib` (verified using native bsdtar) but does not
  initially carry `TweakLoader.dylib` or `roothidepatch.dylib`. Absence from
  the *initial* bootstrap alone does not prove absence after installing
  packages; check the already-installed root read-only before attributing
  the tweak failure to missing loader.
- RootHide's official developer guide states that its CLI tools operate in
  a virtual bootstrap root. In particular, the explicit `pw -V <physical
  hidden/etc>` argument in the current password change deserves verification
  against the on-device `pw`/vroot implementation, not an unguarded replacement
  with host `/etc`. Changing an account database before proving confinement
  could modify the wrong user records. Keep the existing guard until a
  read-only account lookup verifies the virtual path model.

Do not push an untested reference-fork merge to devices. First compile
source changes and run native CI regressions, then obtain one device log for
the five physical acceptance gates before publishing a "functional" build.
