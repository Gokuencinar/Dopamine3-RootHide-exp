# RootHide/Dopamine 3.x source release: comparison baseline (2026-10-24)

## What was published

- Upstream repository: `https://github.com/roothide/Dopamine-roothide` (default branch `3.x`).
- New GitHub Release name `3.x`, tag `28`, published 2026-10-24, announcement: “roothide Dopamine 3 is now open source on github for everyone”.
- Release tag `28` resolves to commit `e180427d58e95115e88ba2553ca8aa3371f9b32b`. Its release assets array was **empty** when checked: it is **not** a downloadable or verified Dopamine 3 RootHide IPA.
- Current upstream branch `3.x` resolves to `24ea745b33cd3a1eba9b7196a875e42eed1fa34e`; the diff from tag `28` changes only README.md (one line replaced). Thus the two references are equivalent for implementation comparison at this checkpoint.
- `3.x` source itself mentions arm64 and iOS up to 18.7.1, but this is **not** evidence of working RootHide on the user's iPhone X/iOS 16.7.15.

The upstream source was fetched into **read-only references** in the existing local Git object store, without checkout over our files:

```
refs/tags/official-roothide3-initial-28 -> e180427
refs/remotes/official/3.x            -> 24ea745
```

The in-progress experimental RootHide3 branch before upstream review is `fix/roothide3-pid1-deferred-resume-r197`, commit `0c453ad433edc992670166b1993f0086b86ee727`. Existing untracked `.rh3-apt-study/` and generated Python caches were left untouched. Git comparison `0c453ad..24ea745` touches approximately 392 files with 7,555 insertions and 31,516 deletions **as a tree diff**: this is a substantial alternate implementation, not an ordinary patch release.

## Verified architectural differences

| Area | Official `3.x` source | Local experimental RootHide3 r219 | Integration significance |
| --- | --- | --- | --- |
| Core RootHide runtime | New `BaseBin/libroothider` with `src/launchd.m`, `exec_patch.m`, `dyld_patch.m`, `signatures.m`, and ABI headers | RootHide logic largely integrated in `BaseBin/libjailbreak/src/roothider` and existing PID1 patches | Must preserve ABI, signing, dyld and process lifecycle **together** if migrating |
| PID1 child patch and liveness | `launchdhook/src/roothider.m` submits a synchronous jailbreakd patch request for a suspended child, with signal-based failure handling; `libroothider/src/jailbreakd.c` participates in this IPC contract | r219 bounds deferred post-reexec child work by authenticated PID/uniqueid and deadlines | Do not import synchronous PID1 behavior without proving it cannot block or crash launchd |
| Reexec recovery | Official `launchdhook/src/main.m` uses fatal failure behavior around boomerang; its alternative jailbreakd Mach port has a separate initialization contract | r219 records stages and isolates incomplete RootHide initialization from Apple PID1 where possible | Retain crash containment and rollback; migrating requires testing the whole handoff and IPC graph |
| Code signatures and trustcache | Official `libroothider/src/signatures.m` can reuse cached cdhash without all page checks; official `libjailbreak/src/trustcache.c` relies on unchecked linked-list reads/writes in inspected operations | r219 validates pinned SuperBlob/ad-hoc pages, strengthens trustcache pointer and write checks, and has transaction rollback during brand/hash work | Keep existing fail-closed checks unless the new algorithm is independently validated, especially after previous physical libgnutls signature failures |
| Private dyld and constructor | Official `systemhook` has explicit check-in/executable stages and a separate `roothider_main.c`; `dyldhook` uses a different mapping/entry-point contract | r219 has its own authenticated check-in and TweakLoader initialization path, plus arm64/iOS-version guards | Preserve guardrails and instrument evidence of real constructor execution; code presence or successful `posix_spawn` is not proof |
| Native build | `BaseBin/Makefile` builds `libroothider-stub` before `libjailbreak`, then the real `libroothider` | Different dependency graph | Copying only hooks or a new dylib without link ordering/loader verification is unsafe |
| LaunchServices | `DOEnvironmentManager.m` refreshes apps through `uicache -a`; `roothidehooks/src/lsd.x` has `__LSServer_RebuildApplicationDatabases` hook triggering another `-a` | `uicache -p` for owned bundles; root/LS verification and bounded diagnostics. Earlier code suppresses recursive automatic `-a` when the RootHide3 marker is present | Three physical user refreshes in r218 exited zero yet LS records stayed `bundleURL_missing`; neither design proves `lsd` hook/registration succeeded on that device |
| OpenSSH | No built-in counterpart to local SHA-pinned offline `openssh-server` recovery was identified in `DOEnvironmentManager.m` or packaged `Resources` | Guarded partial receipt recovery for r218 `Status: install ok not-installed`, no config/key overwrite | Do not drop our SSH recovery without a distinct verified provisioning plan |
| Mobile password | `DOEnvironmentManager.m` constructs a shell command with user-supplied password interpolated into quoted command text | `pw -V <verified hidden etc>` with secret transmitted on stdin and post-write hash-change check | Keep the safer secret-handling path; official implementation does not prove resolution of physical `pw` exit code 1 |
| Daemon registration after userspace reboot | Official `launchdhook/src/daemon_hook.m` deliberately excludes `/Library/LaunchDaemons` from its initial PID1 job enumeration; `jbctl/src/internal.m` uses Procursus `launchctl bootstrap system` after the hook is active | r219 adds hidden-root `/Library/LaunchDaemons` directly through PID1; our `sshd` launchd socket has not been demonstrated | These are *different orchestration contracts*. Before adopting official service loading, test which exact job owns the SSH socket and prevent duplicate loads |
| Bootstrap package versions | Official bundled 1900 bootstrap is a different archive; its bundled launchctl and manager packages have changed | r219 pins its 1900 bootstrap and installed package/SSH receipts | New upstream payload must not be overlaid onto a populated randomized root as if it were an in-place package update |
| First bootstrap | Official `DOBootstrapper.m` installs bundled Sileo/RootHide manager and includes initial SplashBoard snapshot clean-up | Additional recovery journal, app registration and preservation checks | Do not transfer first-install deletion/mutation to an existing user root without a migration contract |
| Acceptance and diagnostics | Official code has a materially different logging and test infrastructure | Persistent device logs, fail-closed service actions and physical readiness gate, 7/9 prior acceptance | Preserve diagnostics and user data; no publication of public release without device proof |

## Constraints for subsequent integration

1. Do **not** replace the local branch with upstream wholesale, reset working trees, or install an official `2.x` binary over an experimental `3.x` hidden root. No 3.x IPA is attached to release `28` at this checkpoint.
2. Use the upstream commit as a coherent execution-reference graph. Review `launchdhook`/`libroothider`/`libjailbreak`/`dyldhook`/`systemhook`/`roothidehooks` plus their Makefiles, entitlements, and trustcache/signature logic as one integration unit.
3. Keep existing device-owner SSH configurations, host keys, package database, bootstrap contents and `mobile` password hashes unchanged. Do not reuse unbounded `lsd`-initiated `uicache` waits or shell-interpolated credentials.
4. Confirm using device logs that actual `systemhook`/TweakLoader constructors execute, manager apps have installed LS proxies with correct active-root `bundleURL`, `sshd` serves a real banner on port 22, and installed packages run. Successful `posix_spawn`, `uicache` exit zero, host tests or a GitHub IPA artifact cannot substitute for those runtime checks.
5. The previous beta CI (`r219`, SHA `0c453ad`) is a *separate* build from the newly published upstream source. Any future build using official code needs its own named branch, pinned upstream SHA, native compile and fresh hardware acceptance.

Notably, both the official and our bootstrap-1900 archives lack a preinstalled OpenSSH server. Upstream's different launchctl registration lifecycle can inform the missing-socket investigation, but does not by itself supply `sshd`, host keys or compatible dpkg receipts.

At audit time the previous r219 All Enabled hardware-beta workflow had completed native build, verification and artifact upload, then failed the **intentional** public-release prerequisite gate. Its artifact name is `RootHide3-ALL-ENABLED-BETA-JAILBREAK-AND-TWEAKS-ON-r219-a1`, GitHub artifact ID `12576528533`, ZIP digest `sha256:b63c31144c466bf303f413a06cacc599c7f55e5f8538b508a6443a69bc1bb61a`. This is our earlier implementation, **not** an official RootHide 3.x IPA and **not** hardware acceptance.

This file is a verified **source comparison and migration constraint**, not a claim that an official-code migration has been implemented or tested.
