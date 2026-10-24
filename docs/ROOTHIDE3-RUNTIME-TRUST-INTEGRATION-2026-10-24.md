# RootHide3 — bounded spawn trust and runtime recovery (24 Oct 2026)

## Source of truth

- Base commit: `3bf396f` on `fix/roothide3-ssh-preboot-installer-rc`.
- Donor source: `devnoname120/Dopamine`, branch `roothide-dopamine3`, exact
  commit `3a9c8dc212294f25fc9a03bba3aab38e1cc1a9a3`. Donor README and
  BUILD.md explicitly deny physical-iPhone validation; do not describe its
  branch as a tested jailbreak. Earlier physical r188 left NewTerm EBADEXEC,
  Zebra unable to launch, no SSH banner, mobile password change unsuccessful,
  and no active tweak injection.
- Actions r189 / run `40036769661`: native build, tests, arm slices and
  quarantine packaging passed, two archives uploaded, but the **workflow
  failed strict readiness 7/9**, exactly because activation remains guarded
  and `validation/device-tests.json` is not available. Neither archive is a
  functional jailbreak-enabled IPA for installation.
- Actions r190 / run `40038034483` (SHA `3bf396f`): native Build,
  regression checks, architecture slices and full disabled-IPA inspection
  **passed**. Workflow conclusion `failure` is the intentional strict 7/9
  release gate. Neither artifact enables jailbreak. r191 / `40039325319`
  builds the subsequent `c5e709e` commit; verify its final native result
  separately from this report.

## Implemented in this phase

1. `systemhook/src/common/common.c` no longer silently discards a failed
   `trust_binary(path)` when an authenticated active-root executable is a
   Mach-O and the caller is not PID1. Return the bounded `EACCES` decision,
   using the same policy as the earlier explicit pre-spawn recursive trust.
   Leave Apple paths, non-Mach-O scripts, other roots and PID1 unchanged.
2. `systemhook/src/roothider_port.c` now returns an error for unsuccessful
   recursive trust on an active-root injected Mach-O. `systemhook/src/main.c`
   propagates the result into the shared `posix_spawn` hook instead of
   claiming success and waiting for a later dyld EBADEXEC. Existing code
   checks path and canonical confinement before issuing trust requests; no
   unrelated insertions are automatically trusted.
3. The privileged RootHide pathhook loader checks that its dylib is a
   regular, root-owned, nonempty, single-link, non-group/world-writable file
   canonically confined to the authenticated hidden root. A symlink escape
   or arbitrary readable replacement can no longer be dlopened through it.
4. `launchdhook/src/spawn_hook.c` now checks `_NSGetExecutablePath` success
   before comparing its output with a requested child path. A failed or
   truncated lookup no longer routes an unrelated PID1 child into userspace
   reboot/provider teardown logic.

## Evidence and safety boundaries

Host suite after the source changes: **380 cases, OK (36 skipped)**. New
tests include failures-before-fixes for trust error propagation and the
actual extracted PID1 self-exec preflight, and a native mocked pathhook
loader checking both valid and adversarial path ownership. Source checks
assert restricted access and propagation into spawn. `git diff --check`
passed. The strict static audit remains **7/9** and must not be weakened.

Critical missing functionality remains: launchd PID1 child patch-before-run
is not implemented with a bounded authenticated asynchronous transaction.
The donor does it by synchronous PID1-to-jailbreakd XPC and variable-cost
recursive Mach-O trust, which are inappropriate to copy unguarded. Existing
tests or green macOS builds cannot prove that systemhook's constructor ran,
that TweakLoader loaded, or that sshd actually received a socket activation.

The RootHide bootstrap, SSH host keys, usernames, password database, app
containers, dpkg packages and preferences were not modified by this source
work. The single private diagnostic export remains unchanged.

## One directed physical acceptance attempt (no uninstall)

After a separately justified, fully reviewed build has been provided for
testing, update **only the RootHide3 application**, preserving its bootstrap.
Start exactly one jailbreak activation, export its full private diagnostic,
and in the same attempt check the following without revealing credentials:

1. The disposable tweak probe: did `systemhook` enter its constructor (probe
   81 versus 83/84/82/0)? Was process check-in accepted? Was TweakLoader
   present and loadable and was a real installed tweak's Settings pane shown?
2. Launch Zebra and Sileo once each, capturing the category of failure or
   successful UI without repeating package installs.
3. Launch NewTerm once and test `id` and a harmless command; record any
   EBADEXEC and executable path, without modifying accounts.
4. Probe SSH's unauthenticated `SSH-2.0` banner once. Compare launchd job
   run/exit counters and listening socket ownership before/after the probe;
   do not disclose host keys or authenticate with a password for diagnosis.
5. Use only the guarded existing UI path for the `mobile` password change
   once when other process execution is working; never paste the password,
   overwrite `master.passwd`, or repeat an outcome-unknown operation.

If the bootstrap cannot be activated safely or diagnostics show a launchd
child suspended/crashing, stop: retain the current installation and log.
Do not label an untested IPA fully functional, fabricate device results, or
relax `ROOTHIDE3_BOOTSTRAP_READY` / physical test gates.

## Subsequent scoped source integration (after `c5e709e`)

- `systemhook/main.c`: the non-PID1 pre-spawn policy now requests recursive
  executable trust **only for an executable lexically and canonically located
  inside the authenticated current RootHide root**. Symlinks escaping the root,
  obsolete randomized roots, and failed resolution of a hidden Mach-O are not
  passed to privileged recursive trust; the active-root Mach-O fails with
  `EACCES` rather than claiming successful preparation. Outside executables
  retain their stock path; their legitimate hidden-root inserted libraries
  are evaluated separately. PID1 receives no new trust XPC or filesystem walk.
- `systemhook/roothider_port.c`: restores the fork's optional
  `roothidepatch.dylib` post-executable phase **only for already authenticated
  hidden-root executables**. Requires root-owned, regular, single-link,
  nonempty, non-writable-by-group/world library with canonical root confinement.
  If unavailable it leaves the existing bootstrap untouched. This stage uses
  the existing dyld trust mechanism, avoiding any extra synchronous trust XPC
  in the constructor. Loaded handle remains live; it does not imply the
  library's constructor succeeded or that tweak injection is working.
- Native mocked C tests extract and execute the actual new policies with
  positive/negative cases including symlink escape, old roots, unresolvable
  paths, metadata failures and dlopen failure. These host tests do **not**
  substitute for an iPhone's private dyld or kernel trustcache execution.
- `libjailbreak/roothider/common.m`: fixes an unsafe shortcut in the bootstrap
  spawn helper. `RTLD_NOLOAD(systemhook)` alone was treated as proof that
  `posix_spawn` was hooked; a failed constructor/check-in could leave the dylib
  mapped but still bypass all patch-child preparation. `systemhook/main.c`
  now exports an atomic readiness getter set **only after** `litehook_hook_function`
  returns `KERN_SUCCESS` for the spawn hook (or after successful iOS 15 filter
  binding). The helper checks this getter with `dlsym`; unknown/not-ready
  still uses its existing non-PID1 suspended-child patch path, while ready
  avoids double patch. Native mocked tests verify loaded+unready, loaded+ready,
  failed patch cleanup and flags restoration. This changes no PID1 flow.
- The trust preflight still has a possible rename race between `realpath` and
  the trust-server request. Server-side inode/identity validation remains a
  separate hardening task; no attempt was made to add unsafe PID1 synchronous
  patch-child transactions. No live SSH keys, accounts, packages or data were
  modified, and strict readiness remains 7/9.

## RootHide upstream PatchLoader ABI and constructor recovery (follow-on)

- RootHide's actual `PatchLoader.c` from `roothide/PatchLoader` resolves
  `PLRequiredJIT` from `RTLD_DEFAULT` during its constructor and aborts if
  absent. Our preceding port loaded the optional dylib without exporting the
  symbol. `systemhook/main.c` now exports the exact `int64_t (void)` ABI,
  returning zero without enabling JIT or elevating process privileges. CI
  checks the `_PLRequiredJIT` and `_rh3_systemhook_spawn_hooks_ready` defined
  symbols in **both** arm64 and arm64e slices, not only the library's presence.
- `roothideinit.dylib` is mandatory on an active hidden bootstrap. Its loader
  now checks file metadata, canonical confinement, Mach-O magic and the
  `dlopen(RTLD_NOW)` result. A failed/missing initializer stops subsequent
  RootHide-only stages without crashing a system service; stock Dopamine
  remains unaffected. This is not a proof of the initializer's semantics.
- `roothidepatch.dylib` remains optional, consistent with the bootstrap 1900
  lacking this file initially. Only a regular, root-owned, non-writable,
  single-link Mach-O in the active root can be loaded. Before `dlopen`, check
  the PatchLoader package's expected rooted `/var/jb` symlink; otherwise its
  own constructor could abort app launches. No package, key or symlink is
  created, modified, or removed. The library is loaded **only when the
  existing tweak policy permits injection** (including selected UIKit and
  system processes such as Settings/SpringBoard), after authenticated
  check-in and initializer, before TweakLoader. Safe mode bypasses both.
- `dlopen` failure when the optional library exists returns `EIO`, invalid
  metadata returns `EACCES`/`ENOEXEC`, and a completely absent optional
  library returns success. RootHide-aware tweak injection is then skipped
  for that process only, preserving app boot and the installed packages.
  The platform's dyld/AMFI and the existing trustcache mechanism still own
  cryptographic signature and selected-architecture enforcement; a Mach-O
  magic check or mocked host result is **not** a signature verification.
- C-executed host tests cover success, missing files, invalid ownership,
  unsafe permissions, symlink escape, wrong file kind, missing package link,
  non-Mach-O input and `dlopen` failure. No new synchronous XPC to PID1,
  systemwide trust grants, password writes, app reinstalls or bootstrap wipes.

Readiness remains **7/9** and this work is not hardware validation. Pending:
real PID1 child patch-before-run contract, private dyld loaded from the
expected trustcache, actual `systemhook` constructor and `TweakLoader`
execution, one unauthenticated SSH banner probe, NewTerm login spawning,
LaunchServices activation, and a real tweak Settings pane on the same iPhone.

## Authenticated process check-in carries across subsequent spawns

`jbclient_roothide_jailbroken()` sends a new launchd XPC domain request each
time it is called, and returns `false` when the reply is missing. Previously
`systemhook` re-issued it from both `rh3_trust_before_spawn` and the shared
spawn/exec pipeline **after** dyld or `jbclient_process_checkin` had already
authenticated its RootHide root. A transient launchd server disruption could
therefore skip patch-before-run for an otherwise checked-in process and leave
later children failing to execute. The exact source path was identified;
physical causality for r188 is not asserted.

The shared C hook now keeps a per-process, atomic RootHide check-in token with
the **exact root path captured only after successful check-in**. No token is
created from a directory name alone, from a failed check-in, or in PID1.
The token is rejected when the current root no longer matches that exact
path. The non-PID1 spawn/exec preflight and dyld hook selection reuse the
authenticated state, eliminating redundant RootHide-status XPC round trips
without changing the separate, audit-token-checked jailbreakd patch request.
The server still controls patch authorization; this grants no new privileges
and makes no assumption that `posix_spawn == 0` proves child execution.

A compiled C harness exercises the production cache for an unchecked process,
invalid root, authenticated active root, PID1, changed root and return to the
original path. Source contracts verify constructor order and lack of repeated
status XPC; a device run is still necessary to confirm NewTerm's actual
Mach-O, `systemhook` constructor, private dyld and spawned child lifetimes.

## Scoped asynchronous launchd-child lifecycle (experimental)

RootHide2 waits synchronously for a daemon after creating a suspended child.
The previous NewTerm parity candidate was deliberately disabled because that
wait can deadlock PID1. This follow-on confines the new asynchronous path to
the exact selected NewTerm, Sileo, Zebra, RootHide Manager and OpenSSH jobs,
after verified RootHide activation and daemon check-in. Other system services,
blacklisted apps, early boot and safe mode retain their existing behavior.

The selected child starts suspended, and a background worker handles its
daemon request without blocking the launchd spawn callback. A matching unique
process identifier is checked on both sides before resuming; the watchdog
is bounded to three seconds and a maximum of four pending workers. Failures
affect only the selected child, never the installed bootstrap or user data.

The new C host tests check strict label selection, fallback behavior, and
atomic success/expiry/backpressure. A successful host simulation or native
binary build **cannot** prove the child executed or its tweak constructor ran.
PID reuse has a residual check-to-signal race. An iPhone X test must verify
launchd responsiveness, private dyld, hook constructor, app startup and SSH
banner before any public release. Strict readiness remains 7/9.

### Follow-up: two lifetime bugs fixed before another enabled hardware IPA

The first r196 daemon operation used `resume=true`: a stalled daemon could
send `SIGCONT` after launchd's three-second watchdog marked the child expired.
The follow-up changes identified requests to **patch-only** (`resume=false`,
`deferred_resume=true`), while retaining the full `roothide_patch_proc`
implementation rather than the older PID1 spinlock-only compatibility path.
After a successful reply, only the original launchd worker that atomically
wins the watchdog state race can resume its *same uniquely identified* child.
The donor's ordinary non-deferred spawn protocol remains unchanged. Regression
tests reproduced the old late-resume path before the change.

The systemhook's cached authenticated RootHide root was also inherited across
`fork()`. That let a fork child mistake its parent's completed check-in for
its own. The cache is now bound to the PID that actually passed check-in.
The native C harness reproduced and then rejected the inherited grant.

These fixes do not grant additional global privileges, modify account or SSH
files, install any packages, or bypass the 7/9 hardware readiness barrier.
No native build or physical constructor test is implied by host tests alone.
