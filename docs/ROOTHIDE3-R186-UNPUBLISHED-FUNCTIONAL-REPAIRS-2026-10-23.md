# RootHide3 r186 source repairs — UNPUBLISHED, no IPA

Base: `fix/roothide3-ssh-preboot-installer-rc`, `6ee2c7e17bd2a7951f9955371bdb0445ba153e8e` (r185). Reference: `devnoname120/Dopamine` branch `roothide-dopamine3`, `3a9c8dc212294f25fc9a03bba3aab38e1cc1a9a3`.

## Physical failure remains unresolved

The user tested r185 on iPhone X, iOS 16.7.15, and reports unchanged failure of SSH, tweak injection, managers and NewTerm. The attached October 23 logs show boomerang handoff, PID 1 launchdhook constructor and jailbreakd XPC startup, but do **not** show SSH banner, loaded tweak constructor, working LS registrations or successful UI launches. `uicache -p` exit 0 and `spawn_result=0` are not proof of registration or process initialization. The r185 first-install pinned registration function was not executed with an existing RootHide marker.

## Source corrections, not device validation

1. `BaseBin/launchdhook/src/spawn_hook.c`: match the donor's private dyld policy for any already-injected PID 1 child, but require the **exact** active-root `systemhook.dylib` entry, verified loaded launchdhook origin, RootHide active, no first-load/early boot, and preserve SETEXEC/DriverKit checks. This does not broaden insertion to unrelated children or perform XPC on PID 1. `test_roothide_pid1_private_dyld_parity_r185.py` exercises the production routine; the historical r173 test has been updated to the same contract.
2. `BaseBin/libjailbreak/src/trustcache.c`: checked kernel I/O for list traversal and publication; verify staging with readback; stage replacement cache before publishing it, and publish before attempting removal of the old UUID. On uncertain publication, retain allocation rather than risk a kernel use-after-free. Existing UUID replacement on SPTM/TXM is explicitly refused. Dynamic JB trustcache growth and entry writes now check I/O. `test_roothide_trustcache_io_r186.py` compiles extracted production C with failure-injecting kernel mocks, including larger/smaller/equal-UUID replacements.
3. `trustcache_file_build_from_cdhashes`: reject counts too large for a single trustcache, do not dereference failed allocations, and leave output NULL on error. Host tests demonstrated the pre-fix OOM/oversize crashes and pass after the fix.
4. `BaseBin/libjailbreak/src/roothider/common.m`: `proc_patch_csflags` now checks the kernel read, write, and CS_GET_TASK_ALLOW readback before returning success. `test_roothide_proc_csflags_r186.py` runs that real source routine with simulated I/O errors and both proc/proc_ro layouts. This does **not** solve unsafe proc lifetime or PID reuse.

## The unsafe donor behavior was not copied

The donor suspends PID 1 children then makes synchronous `jbdSpawnPatchChild` calls and resumes them. Current `jailbreakd` authenticates the request with `proc_get_ppid(child)==clientPid`. Asking PID 1 to wait for its own jailbreakd XPC transaction risks a launchd deadlock; the direct `roothide_patch_proc` alternate can call unbounded Mach/dyld operations and uses `proc_find` without a retained proc reference or generation/uniqueid guard. Verified CS flags readback closes one silent failure but **does not** make synchronous PID 1 patching safe. Do not enable it until a bounded, authenticated patch-before-resume transaction with child generation checks, rollback/timeout and a nonblocking launchd owner exists and has been tested.

## Verification boundaries

Host tests exercise extracted production C with mock kernel and spawn, not Apple SDK, dyld, PAC/PPL/SPTM/TXM or a physical device. A Windows host cannot certify Darwin arm64/arm64e linking, injection or iOS 16–18 compatibility. The real hardware acceptance gate must demonstrate actual trustcache reads/writes on the target device, dyld constructor/check-in, TweakLoader activation, LaunchServices query from a context that can observe registrations, Sileo/Zebra/RootHide Manager/NewTerm launches and SSH-2.0 banner/socket activation. Do not alter existing keys, packages, accounts or bootstrap to obtain these results. Do not change `ROOTHIDE3_BOOTSTRAP_READY` or fabricate `validation/device-tests.json`.

No IPA or release was built, installed or published in this phase. Do not trigger the hardware-beta workflow as a side effect of pushing until a safe functional path and physical validation plan justify a new candidate.
