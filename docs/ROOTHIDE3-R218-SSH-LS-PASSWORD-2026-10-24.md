# RootHide3 r218 physical attempt: SSH receipt, LaunchServices and mobile password

Date: 2026-10-24. Device: iPhone X, iOS 16.7.15. Installed revision: `748fe0b8de0a163bb629376eb478a5e3590de773`, All Enabled hardware beta. This note describes **physical diagnostics**, not an acceptance pass.

## Source reconciliation

Three uploaded attempt logs have respectively 975, 1,076 and 1,103 text lines. Each shorter file is an **exact prefix** of the next. They are cumulative snapshots of one jailbreak attempt that began at `21:10:39 UTC`, not three independent launches. The full snapshot ends around `21:15:14 UTC`. No comprehensive read-only diagnostic (`RH3 FULL DIAG END`) was present in these attempt logs.

The exploit, bootstrap, BaseBin trustcache, opainject, boomerang handshake, PID 1 `launchdhook` constructor, named hook initializers, userspace re-exec and authenticated jailbreakd checkin are recorded as completed. Numerous `PID1 private dyld: spawn_result=0` and manager-launch events attest to spawn preparation, **not** successful systemhook/TweakLoader constructors or interactive app functionality. There is no measured tweak-load or SSH banner proof.

## SSH: specific dpkg state now known

The new bounded SSH receipt diagnostic reports:

```
SSH inventory: package=client state=installed item=0 reason=verified error=0
SSH inventory: package=sftp state=installed item=0 reason=verified error=0
SSH inventory mismatch: package=server version=missing status=install ok not-installed reason=version_mismatch; no dpkg writes
SSH inventory: package=server state=untrusted item=0 reason=version_mismatch error=17
```

This is materially more precise than r216. The `openssh-server` dpkg status **stanza exists**, but has **no Version field** and explicitly declares `install ok not-installed`. Do not interpret it as an installed older version. The current scanner checks for pinned `Version: 9.2p1` before considering this non-installed state; it conservatively returns `EEXIST` and does not run dpkg.

A safe recovery candidate may treat only this exact standard non-installed triple with absent Version as `RH3SSHAbsent`, contingent on the existing no-manifest/no-footprints/ownership/root checks and detection of ambiguous duplicate fields, scripts or conffiles. Other status triples (`config-files`, `half-installed`, `reinstreq`, `installed`, etc.) must continue to fail closed. Do not delete a dpkg status record or overwrite SSH config/keys. Runtime proof still requires the server binary, keys, launchd socket job and a real SSH banner.

## LaunchServices: repeated explicit registration does not persist

The user invoked the explicit Settings app-refresh action **three times**, at about `21:12:17`, `21:12:47` and `21:14:21 UTC`. Each run refreshed four bundled apps (Sileo, RootHide, Zebra, Patcher); all **12** traced `uicache` children exited with `raw_wait=0 result=0`, and each action's command-side summary returned zero.

However, each post-refresh read-only verification reported Sileo/Zebra/RootHide `state=bundleURL_missing`, `proxy_present=1`, `bundleURL_present=0`, `proxy_installed=0`; fresh server root was known and matched the app root. All three actions correctly returned **EAGAIN (35)** at the LaunchServices verification boundary. Later manager launches can have `proxy=0`, and `spawn_result=0` is not functional UI proof.

This *does* refute the earlier uncertainty about whether the user tried the post-reexec button. More `uicache -p` repeats or merely raising the verification timeout are not supported as fixes. Investigate why accepted exit status has no authoritative `lsd` registration: IPC/permissions, application identity, registration database and command semantics. Avoid unregistering foreign app IDs, deleting `lsd` databases or automatic relaunch loops without proof.

## `mobile` password: command executed but account unchanged

The final snapshot adds one authenticated password-change attempt at `21:15:04 UTC`:

```
mobile password write capability: csops_ok=1 installer=0 platform=0 uid0=1; no privilege change attempted
mobile password preflight: master_safe=1 passwd_present=1 pwd_db_present=1 spwd_db_present=1 pwd_mkdb_executable=1 mobile_record_present=1
BOOT ... jailbreakd: verified hidden-root installer child entitled
RootHide child pw: pid=1120 raw_wait=256 result=1
mobile password failed-command verification: record_readable=1 hash_changed=0; no automatic retry
```

The app process itself lacks `CS_INSTALLER`; the suspended authenticated `pw` child was granted its scoped installer right by `jailbreakd`. That does **not** establish that `pw` could update the password database or that its own subprocesses inherited all needed rights. The exact cause of exit 1 was not captured. There is no basis for changing `master.passwd`, `spwd.db`, credentials or retrying blindly. No password or hash material is in the supplied diagnostic.

## Build versus device acceptance

GitHub Actions r218 (`40128426880`) verified the Xcode build, regression suite, architecture slices, hardware-beta IPA verification and All Enabled artifact upload. Its build job as a whole reports failure only because `Check RootHide prerequisites before public release` intentionally blocks unvalidated public release. Artifact `RootHide3-ALL-ENABLED-BETA-JAILBREAK-AND-TWEAKS-ON-r218-a1` (ID `12574940938`) belongs to `748fe0b`; its ZIP digest is `sha256:ec4f1583c400a3ba328e6d2357bd921f0ca10a0e6ef073f84932e489722d03af`.

**No SSH listener, successful package-manager launch, APT transaction, tweak constructor, or changed mobile password was demonstrated on device.** Hardware acceptance stays at 7/9 until independent positive tests.
