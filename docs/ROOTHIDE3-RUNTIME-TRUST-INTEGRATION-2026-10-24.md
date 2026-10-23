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
- Actions r190 / run `40038034483`: compiling prior source commit `3bf396f`;
  its final status must be read directly from Actions before making a claim.

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
