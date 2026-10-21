# RootHide3 CI: parallel compilation, safe caches and `.deb` outputs

## Why r158 had no `.deb`

The r158 `device-test` and `build` jobs were cancelled before uploading any
artifacts. The previous workflow did not upload `.deb` files even when `make`
produced them. The principal jailbreak application is built as an **IPA**;
the three packages generated in `Packages/` are **auxiliary dependencies**,
not an installable jailbreak or a fix for NewTerm.

## Parallel build graph

`gmake -j` now uses explicit dependencies instead of a top-level recipe that
serially invokes four builds:

```
BaseBin (its subprojects already build in parallel)
   |
Packages (libkrw-provider, libroot, basebin-link in parallel)
   |                    |
Application IPA      Standalone Dopamine.tar
   (these two are allowed to run concurrently)
```

The application embeds the BaseBin archive and dependency packages; launching
it while either producer is still building would be a correctness bug. Do not
run all four top-level directories concurrently. Separate GitHub Actions runs
may now execute at the same time without cancelling each other; runner quotas
and capacity can still delay a job.

## Cache scope and integrity

- `ccache` stores compiler object results only; it is limited to 512 MiB and
  keyed by macOS/Xcode fingerprint, hardware mode, version and UTC day. Within
  the current trusted branch, an exact daily cache is reused; a new day
  restores the latest compatible prefix. Each branch has its own cache scope.
- RootHide diagnostic branches named `roothide-*` can now restore and save
  these objects. They previously could not cache anything except downloads
  already saved on the default branch. Pull requests never write these
  caches. Cache upload errors are not compilation failures.
- The pinned Theos SDK `.tar.xz` is checked against its full SHA-256 on every
  restore; the two Procursus `.tar.zst` bootstrap archives are checked against
  SHA-256 and archive magic. Only these downloads, not signed IPA files or
  the assembled BaseBin archive, are stored in download caches.
- A separate source-only cache can restore the RootHide Theos git checkout
  pinned to `cfba89a5`; before any build its origin/commit are checked, the
  checkout is reset/cleaned, and every submodule is updated to the recorded
  revision. The SDK directory is explicitly excluded from this source cache.
- GitHub caches are scoped by branch; a newly created diagnostic branch may
  still have a cold start. Speedups require measuring ccache hit/miss and
  download cache-hit results in at least two successful builds.

## Debian artifacts

After a successful RootHide build, CI verifies `Package` and `Architecture`
from each of these compiled files with `dpkg-deb`:

- `Packages/libkrw-provider/libkrw-dopamine.deb` (`libkrw0-dopamine`)
- `Packages/libroot/libroot.deb` (`libroot-dopamine`)
- `Packages/basebin-link/basebin-link.deb` (`dopamine-basebin-link`)

CI also checks the package listing, records SHA-256 sums and uploads the
individual `.deb` files in `RootHide3-INTERNAL-DEBS-NOT-FOR-INSTALL-rN-aN`.
It is a **diagnostic artifact only**, not a package repository or installer.
The packages inherit stock `/var/jb` paths/symlinks and must **not** be
installed on a functioning hidden RootHide bootstrap without a separate
compatibility audit. In particular, `basebin-link.deb` does not replace
`launchdhook.dylib` in the randomized root. Updating PID 1 remains disabled.

The strict RootHide readiness gate remains intact: a build may produce
compile-only IPA and internal DEBs while the workflow ends with an expected
failure because hardware safety evidence is still missing. Never equate a
compiled package with on-device compatibility.
