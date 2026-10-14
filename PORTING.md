# RootHide for Dopamine 3: integration worktree

**Status: incomplete, not installable as RootHide.** This worktree is the
beginning of a port. Do not distribute its normal Dopamine IPA as a RootHide
release or run it as a RootHide updater.

## Source provenance

| Role | Repository / branch | Pinned source commit |
| --- | --- | --- |
| RootHide 3.x starting point | `roothide/Dopamine-roothide` `3.x` | `7e0a9243594b271b3db673bb5194b00be6096ab8` |
| Dopamine 3 base | `opa334/Dopamine` `3.x` | `448ff1a83d2bb807346f1f3d36332e4afbf9794a` (3.0.11) |
| Working RootHide donor | `roothide/Dopamine2-roothide` `v2.4.9.x` | `e8de6e5035fee52ca732536dbb3ca1734889d914` |

The public RootHide 3.x branch contains no RootHide implementation commits
relative to its Dopamine 3 ancestor; its only fork-specific commit empties
`README.md`. The RootHide 2.x implementation cannot be transplanted unchanged.

## Local experimental progress (13 October 2026)

This branch now carries the RootHide 2 IPC client, process/blacklist/trust
sources, dyld loader hook candidates, package-manager hooks, and experimental
launchd integration alongside Dopamine 3's existing hookd/rootlesshooks.
It also includes the two RootHide bootstrap archives and the Sileo, Zebra,
and RootHide Manager packages. All five assets are SHA-256-pinned and attached
to the iOS application target. A **compile-only** artifact has since been
built; this is **not a working RootHide jailbreak**.

The RootHide IPC domain is isolated as ID `6`, and the XPC dispatcher now
rejects out-of-range domain and action indices. RootHide activation is tied
to a nonzero `jbrand` and a hidden `.jbroot-*` root path; that state is not
initialized by the stock Dopamine 3 bootstrap. Unresolved kernel offsets are
guarded where identified rather than used as kernel addresses.

The experimental RootHide bootstrap uses `.jbroot-<brand>` and a separate
AppGroup, rather than overwriting Dopamine's `/var/jb`; it rejects
unrecognized and incomplete installs, offers rollback, and installs RootHide
repositories and managers. It is **disabled by default** with
`ROOTHIDE3_BOOTSTRAP_READY=0`; stock Dopamine continues to use its original
Procursus path. The experimental path is deliberately limited to iOS 15/16;
iOS 17+ is rejected until separately ported.

**Remaining blockers:** Although macOS has compiled the staged source,
RootHide 2 kernel/dyld patches, code-signing/trust handling, bootstrap
dependencies and jailbroken runtime have **not been validated on iPhone**.
Some offsets required by the donor
are absent from Dopamine 3's kernel patchfinder and are guarded instead of
being used unchecked. RootHide's executable `bootstrapper` in the donor
was only a placeholder. The audit checks source wiring, an explicit
activation flag, and independent physical-device evidence. Activation
and hardware evidence deliberately remain absent. Enabling RootHide based
on source presence alone would be unsafe. No **installable, functional**
RootHide IPA/TIPA has been validated on hardware in this workspace.

## Build attempt and reviewed defects (14 October 2026)

The experimental tree is backed up in
`Gokuencinar/Dopamine3-RootHide-Experimental` on branch
`roothide-dopamine3-integration`. **Visibility warning (14 October 2026):**
GitHub's repository API reported `visibility: public`, contrary to the
previous description of a private experimental fork. Verify that it is
private before pushing further work; do not publish to a public fork.
An earlier GitHub Actions attempt
(`38482080417`) reported a billing/spending-limit restriction. Subsequent
attempts **did start a real macOS runner** without any billing changes:

- Run `38485486288` built dependencies and started BaseBin compilation,
  but `libjailbreak` failed on an undeclared logging function and invalid
  CoreSymbolication reference checks. Commit `1b76080` corrected these.
- Run `38486441884`, at `1b76080`, advanced through `libjailbreak` and
  failed while compiling `launchdhook`: the RootHide 2 crash reporter
  header redefined Dopamine 3's state enum and declared incompatible
  `crashreporter_pause` / `crashreporter_resume` signatures. The donor
  implementation also exported these conflicting names. This revision
  removes its unused source from `libjailbreak` and the donor header from
  the public RootHide header, retaining Dopamine 3's own launchd reporter.
- Run `38489040563`, at `9e6aa9b`, successfully compiled `libjailbreak`,
  `systemhook`, `launchdhook` and subsequent BaseBin components, then failed
  compiling the RootHide donor's `jailbreakd`. Its entry point still called
  `crashreporter_start` from the now-excluded donor reporter; its XPC server
  used manual `xpc_retain`/`xpc_release` while compiling with Objective-C
  ARC, which the iOS 26.2 SDK disallows. The donor reporter invocation is
  omitted rather than reintroducing its conflicting ABI and unsafe panic
  path; the XPC daemon now relies on ARC block capture for async replies.
  These changes require another macOS build for confirmation.

Independent link-graph review found that the packaged `BaseBin/dopamine`
command-line executable compiled the original flat libjailbreak sources but
did not link the RootHide routines in the sibling `libjailbreak.dylib`.
It now links `-ljailbreak` from the existing BaseBin staging directory;
tests assert the missing `ensure_dyld_trustcache`/`exec_set_patch` dependency
and adjacent `@loader_path` packaging. This is a build dependency fix, not
a claim that the legacy CLI is a RootHide installer: its `install` and
`activate` subcommands are still stock Dopamine/Corellium flows, and the
guarded RootHide app installer does not call them. Framework references for
iOS targets now use the iPhoneOS `SDKROOT` instead of incorrectly selecting
IOKit from the macOS SDK. The macOS CI run `38583786037` built and packaged
this revision successfully.

Further local hardening, pending a new macOS build, makes disabled
`jailbreakd` systemwide logging return `-ENOTSUP` rather than aborting the
daemon on an IPC request, and declares RootHide-specific `DOBootstrapper`
methods in their implementation category to avoid compiler warnings. The
recursive trustcache collector now bounds traversal and checks `realloc`
before writing into a resized buffer; it propagates allocation or limit
failures to its caller instead of uploading a partial array. These are
source-level fixes only, without iPhone runtime evidence.

The post-build verifier was also hardened from a four-byte Mach-O magic
check to checking real ARM64/ARM64E thin/fat slice headers, per-slice CPU
architecture, load-command bounds, referenced sections and data ranges.
Synthetic malformed-header/offset/architecture cases now fail the local
tests. This structural inspection does **not** verify code-signature
authenticity, entitlements or execution. The stronger verifier has not yet
been run in macOS CI against the compiled diagnostic IPA; run `38583786037`
used the previous, weaker version.

**Unresolved blacklist path:** The RootHide `launchdhook` direct spawn check
identifies blacklisted apps by the `.app` executable path. App launches
routed through `/usr/libexec/xpcproxy` can bypass that path comparison;
the subsequent exec handling does not clearly register the resulting PID
as blacklisted before it can request privileged IPC. Audit the complete
launch/exec/injection route and test on hardware before activation.

Run `38583786037` at `1068eea` completed Build, arm64/arm64e architecture
checks, quarantined package inspection and artifact upload successfully.
The overall job finished **failure** because the final strict RootHide
activation/hardware gate intentionally refused release. GitHub artifact
`11905401984`, `RootHide3-COMPILE-ONLY-NOT-FOR-INSTALL`, contains an IPA,
basebin archive, JSON inspection and a no-install warning. The ZIP is
105,944,525 bytes with SHA-256
`5883d145856c9e6c551d6292eaf0b083dd37b6f07c8652eef14b1068b476b01b`.
The app remains ordinary Dopamine with RootHide activation disabled; this
artifact is **not a usable RootHide IPA**. Locally updated sources after
`1068eea` are not yet covered by this macOS run.

Static review corrected a first-run state bug: both bundled RootHide
`prep_bootstrap.sh` scripts can delete themselves on success. Marker
creation now follows verified completion rather than depending on the
script continuing to exist. The RootHide path also prevents a stock
`/var/jb` symlink from being created via the settings UI, excludes
stock Procursus apt sources from the hidden bootstrap, and separates dyld
initialization from the ordinary Dopamine protection/fakelib path.
The macOS CI workflow now unpacks the iOS SDK's `.tar.xz` with XZ,
not `gunzip`.

Subsequent source work retargets RootHide-owned absolute links during
re-randomization with rollback, stages explicit libroot/libkrw/basebin-link
file payloads and prevents settings from creating `/var/jb`. New roots
now record a `creating` ownership state before lengthy extraction. A crash
with an intact pair of root/AppGroup links can resume; an incomplete layout
is deliberately left for explicit manual recovery, not auto-deleted.
Failed uninstall operations report their error and do not reboot or clear
the active root state. These are source protections, **not runtime proof**.

The CI workflow now classifies an experimental RootHide build using both
the checked-out source and the source branch (including pull requests),
so PR merge refs do not bypass the quarantined artifact and strict audit.
Xcode project references used by momentarius/Titan no longer hardcode
macOS SDK version numbers. Kernel offsets, dyld hooks, package-manager
integration, launchd state, signatures and reboot flows still need live
device testing. No interrupted-creation cleanup may automatically delete
an unrecognized RootHide 2 container.

The launchd userspace-reboot path now avoids mounting stock fakelib when
RootHide is active. Spawn/exec injection chooses the hidden bootstrap's
`basebin/systemhook.dylib` instead of the inaccessible stock
`/usr/lib/systemhook.dylib`, while preserving the stock Dopamine path.
Source-level checks cover both branches; process injection after reboot
still requires an actual iPhone test. The compile-only IPA verifier now
requires the packaged `bootstrapper`, `dopamine`, `jailbreakd` executables
and all six expected dyldhook binaries, with negative tests for missing or
malformed Mach-O payloads.

## Conservative recovery hardening from earlier Dopamine and RootHide versions

Comparison with the local RootHide 2 donor and previous Dopamine behavior
identified two patterns not safe to import unchanged: the donor could remove
unrecognized/half-extracted `.jbroot` directories, while stock Dopamine's
recovery of preboot/dyld assets assumes a conventional `/var/jb` root. Neither
operation may be applied to an uncertain RootHide 3 container. Instead the
new RootHide-only recovery path keeps the original root and AppGroup data
untouched, records installation stages, rejects malformed ownership markers,
orphaned AppGroups, leftover dependency staging/backup directories and
partially executed package scripts. Interruption at `running-script` stops
reinstallation for explicit manual repair; the non-idempotent donor script
is **never** rerun automatically after a possible partial execution.

The RootHide BaseBin replacement preserves the Dopamine `.safe_mode` marker
or rolls back the replacement if preservation fails. Before experimental
launchd injection, the app validates the owned hidden root and essential
on-disk executables, checks the marker type and atomically enables safe mode
(no tweak injection). In the RootHide-only launchd handshake, `jbctl` must
exit successfully within 15 seconds and the boomerang IPC must complete
within 60 seconds; errors abort the attempted activation without requesting
a userspace reboot, with a separately retained IPC context to avoid a
detached-thread reference to a dead stack. The original stock Dopamine 3
handshake is unchanged. A bootstrap preparation failure now triggers
post-exploitation cleanup for RootHide before any launchd hook attempt.

These mechanisms reduce foreseeable mistakes and hang paths, **not** boot
loop risk to zero. Once opainject has modified launchd, an IPC timeout
cannot safely undo those process/kernel modifications. No automatic
panic-loop recovery, working RootHide startup, or real hardware rollback
has been proven. Before enabling RootHide, resolve xpcproxy blacklist
bypass, verify all dyld/kernel hooks and signatures, and test interrupted
install/boot, userspace reboot and recovery on a spare supported iPhone.
No production device should install the compile-only artifact.

## Reconstructing the RootHide 2 / Dopamine 3 build path

The local historical donor is `../RootHide-Dopamine2-ref` on
`v2.4.9.x` at `e8de6e5`; the 3.0.11 upstream baseline is
`dopamine/3.x` at `448ff1a`. RootHide 2 produced a jailbreak by building
`BaseBin/Makefile` (libjailbreak, launchdhook, systemhook, dyldhook,
roothidehooks, jailbreakd, basebin trustcache, then `basebin.tar`), and
then using Xcode and `Application/Makefile` to bundle dependencies, sign
and package the app as a `.tipa`. Its App Makefile added the
`Dopamine.roothide` marker on installable builds. The marker must not be
copied blindly to our compile-only IPA: it would falsely suggest a
functioning RootHide jailbreak, while the activation gate remains zero.

| Component | RootHide 2 donor method | Current Dopamine 3 adaptation |
| --- | --- | --- |
| BaseBin and trustcache | Stage RootHide-specific tools, sign/load trustcache, package tar | Added RootHide tools alongside stock `hookd`, `rootlesshooks`, Dopamine CLI; structural ARM64(E) checks |
| Hidden bootstrap and package managers | `.jbroot-<brand>`, RootHide Procursus and Manager packages | Owned `.jbroot` plus AppGroup, pinned SHA-256 resources, transaction stages, manual recovery; runtime not verified |
| Initial `launchd` activation | `launchdhookFirstLoad` prevents broad injection until userspace reboot | Set only after boomerang recovery with valid RootHide identity; RootHide-only spawn guard, stock path retained |
| `dyld` and library trust | RootHide dyld patches, recursive signing and userspace injection | Source-port for known iOS 15–17 layout, preserving 3.x hooks; iOS 18+ RootHide runtime still unsupported |
| Blacklisted apps | Direct app executable spawn interception and PID tracking | Similar interception; launches via `xpcproxy`/later exec remain an unresolved P1 |
| CLI installer | RootHide 2 installation is app-driven | Dopamine 3's Corellium CLI remains stock `/var/jb`; experimental builds reject CLI `install`/`activate` before any KRW action |
| `bootstrapper` helper | Donor's executable is an unimplemented always-successful placeholder | Kept for packaging compatibility, but now returns failure instead of falsely indicating a completed bootstrap |
| IPA/TIPA | Xcode, bundled `.deb`, ad-hoc `ldid`, `.tipa` and marker | Same general compilation chain, with diagnostic quarantine and no-install warning; marker deliberately absent |

The `ROOTHIDE_EXPERIMENTAL_BUILD=1` GitHub workflow environment flag is now
propagated to the standalone Dopamine CLI compiler. Direct local builds
default to experimental mode when RootHide's `roothider.h` is present.
In this configuration,
neither `install` nor `activate` can reach the conventional `/var/jb`,
preboot or fakelib mutation code. `ROOTHIDE_EXPERIMENTAL_BUILD=0` retains
the original Dopamine 3 CLI behavior. The donor's separate `bootstrapper`
helper never performed real work; returning nonzero is preferable to
claiming success from a no-op.

These are targeted integration and build-safety changes, not an assertion
that the RootHide2 and Dopamine3 runtime code paths are equivalent. Before
changing `ROOTHIDE3_BOOTSTRAP_READY=0`, the remaining work includes a
RootHide-capable CLI if required, P1 blacklist/xpcproxy correctness,
kernel/dyld hook compatibility and patch trust, real code-signature checks,
clean installation/recovery and full userspace reboot tests on supported
spare iPhones. The currently configured private GitHub Actions macOS build
may remain blocked by the account's runner billing restriction; static
Python tests alone cannot replace the macOS compilation.

## Reproducible macOS diagnostic build

The experimental fork uses `.github/workflows/main.yml` on
`macos-15`. RootHide uses Theos revision
`cfba89a53a05b4a1b822121158acc3669c20602f`; stock Dopamine uses
the separate pinned official Theos revision. The iPhoneOS 16.5 SDK from
release `master-146e41f` has SHA-256
`5e0fd3f01266cce4ce012d4a99b38eb56578fca40d09edc81cd83dee958202fb`.
Both stock Procursus bootstrap downloads are pinned by SHA-256 as well.
The CI checkout pulls pinned BaseBin submodules, and pins procursus-action
and trustcache source revisions.

For a Mac with Xcode, Theos, a validated SDK, ldid, trustcache, GNU Make
and libarchive (as installed by the workflow), execute:

```bash
git submodule update --init --recursive
export THEOS="$(pwd)/theos"
export ROOTHIDE_EXPERIMENTAL_BUILD=1
bash tools/macos_build_readiness.sh
cd Application/Dopamine/Resources
bash download_bootstraps.sh
cd ../../..
gmake -j"$(sysctl -n hw.logicalcpu)" NIGHTLY=1
python3 tools/verify_roothide_build.py --ipa Application/Dopamine.ipa --json
```

If compilation and package inspection pass on a RootHide branch, Actions
stores `RootHide3-COMPILE-ONLY-NOT-FOR-INSTALL` for seven days.
This is **not** a verified jailbreak release and must not be installed.
Its inspection checks the five pinned RootHide assets, IPA and BaseBin
structure, structural ARM64 Mach-O headers and load-command ranges, and
required hooks; CI also verifies
arm64/arm64e slices via `lipo`. The standard `Dopamine` artifact is
not published for RootHide branches. The strict publish gate additionally
requires reviewed activation and genuine device evidence following
`validation/README.md`; it intentionally fails until then.

The Windows source-work machine has no Xcode/macOS compiler. GitHub-hosted
macOS now completes a compile-only IPA at `1068eea`; the archive was inspected
independently after download and its SHA-256 matches GitHub. No billing
modification was performed. This evidence must not be confused with
signature authenticity, successful installation or RootHide functionality.

## Integration boundaries

1. **IPC and authorization.** Dopamine 3 reserves domain ID `5` for
   `JBS_DOMAIN_DOPAMINE`; RootHide 2 uses `5` for `JBS_DOMAIN_ROOTHIDE`.
	 RootHide uses domain ID `6` with a distinct server handler. Validate the
	 caller and operation permissions and test denial paths on hardware before
	 exposing privileged requests.
2. **Shared jailbreak state.** Preserve Dopamine 3 `info.h` state, kernel
   offsets and SPTM/TXM code while integrating RootHide `jbrand`, trust,
   dyld-patching and blacklist state. Check serialization and rollback.
3. **Hidden bootstrap and filesystem.** Adapt RootHide's `.jbroot-...`
   installation, auxiliary container paths, package repositories and
   RootHide Manager. Cover fresh install, existing Dopamine bootstrap,
   switching after reboot, updates, and complete removal without deleting
   another environment.
4. **Runtime integration.** Port RootHide 2's `roothider/*`,
   `jbclient_roothide.c`, `roothidehooks`, `launchdhook` and `dyldhook`.
   Reconcile with Dopamine 3 `hookd`, `rootlesshooks`, `litehook` and dynamic
   trustcaches, including the newer iOS kernel/loader variations.
5. **Build and packaging.** Select matching RootHide Procursus,
   Theos package scheme, replacement manager, entitlements and
   arm64/arm64e binaries. Audit all resources and build artifacts.

## Verification gates

From this repository, run:

```
python3 tools/roothide_port_audit.py
python3 tools/roothide_port_audit.py --strict
```

The first command prints source prerequisites; `--strict` exits nonzero
until the opt-in RootHide bootstrap has explicitly been enabled after device
validation. It deliberately blocks publication of an ordinary Dopamine IPA
as a RootHide release. Run `python3 -m unittest discover -s tools/tests` to
verify the IPC and source guard regressions. Neither check proves runtime
correctness or installation safety.

The next gates require a macOS build with Xcode, Theos, SDK, submodules and
RootHide-specific packages; inspection of the resulting `.tipa`, basebin
and entitlements; and device testing on supported arm64 and arm64e targets.
Start with iOS 15.x and iOS 16.x, then validate iOS 17+ separately.
For each target test bootstrap coexistence, first activation, reload,
respring, userspace reboot, disabled/enabled tweak injection, RootHide
blacklist, app and dylib trust, package installation, updates and uninstall.
Keep a recovery path and logs available before trying kernel changes.
