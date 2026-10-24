# RootHide3 — APT backlink/trust failure handling (2026-10-24)

## Provenance and hardware limit

- Baseline: `9ac6213` on `fix/roothide3-pid1-deferred-resume-r197`.
- Last user-tested hardware candidate remains r198 (`ea482ab`), with `apt/methods/http` failing to load an existing `@rpath/libgnutls.30.dylib` because its signature was rejected.
- The r204 beta (`ea5c47e`) compiled but has **no device test**. r205 (`9ac6213`) is ordinary CI unless separately manually dispatched with `hardware_beta=true`.
- Archive-level finding: the **original** bootstrap 1900 already ships `./.jbroot -> .`, `./usr/libexec/apt/methods/.jbroot -> ../../../../.jbroot` and `./usr/lib/.jbroot -> ../../.jbroot`. When faithfully extracted, those links are already correct and the backlink helper should do nothing. It would be unsound to identify a missing methods backlink as the proven cause of the r198 `code signature invalid` error; the installed iPhone tree has not been inspected. The primary unresolved hypothesis remains signature/trustcache acceptance and effective parent `systemhook` execution.
- These changes operate on source code and host tests **only**. They do not prove the parent APT process loaded `systemhook`, uploaded its CDHash closure or ran any tweak constructor on iPhone X / iOS 16.7.15. Readiness remains **7/9**.

## Additional failure modes corrected after `9ac6213`

1. The dependency walker in `BaseBin/libjailbreak/src/roothider/signatures.m` invoked `ensure_jbroot_symlink` and ignored the result. In `common.m`, permission failures from `symlink`, conflicts with regular `.jbroot` entries, and some path-resolution errors were silently suppressed or went through `assert`. A missing backlink can prevent the bootstrap's intentional `@loader_path/.jbroot/usr/lib` RPATH from finding APT dependencies.
2. `ensure_jbroot_symlink()` now returns a POSIX error (zero for an existing correct link or a path outside the current hidden root). It does not overwrite an existing directory or regular file; its caller marks recursive trust as failed for **mandatory** dependencies rather than presenting an incomplete closure as trusted. Weak/lazy libraries remain optional as in the existing walker. Existing stale symlink replacement is otherwise preserved; no bootstrap reinstall or global symlink rewrite was added.
3. `systemwide_trust_file()` previously attempted signature attachment after a nonzero result from `trust_signatures()`. This is now gated on a successful trust result, preserving trustcache upload failures fixed in `9ac6213` and preventing a second operation on an untrusted signature.

## Regression evidence

`tools/tests/test_roothide_apt_backlink_result.py` extracts the production native code to exercise successful/existing links, conflicting nonlinks, failed symlink creation, failed unlink, denied lstat and out-of-root preservation. A separate compiled C harness exercises the production server trust/attach control flow with a simulated upload error. `tools/tests/test_roothide_apt_bootstrap_macho.py` now also checks the actual archived symlink types, targets and canonical relative chain, without extracting onto a device. No tests access the iPhone or modify a real jailbreak root.

The backlink tests were added first and failed against the old void-return interface. They pass after the correction; the native trust/attach gate also passes. This is host-level correctness, not proof of kernel signature acceptance or entitlement correctness on Apple's SDK.

Safety/compatibility residuals: the donor helper replaces a stale symlink with an unlink+symlink pair using mutable pathnames (inherited TOCTOU window). This patch only surfaces operation failures; it does not make symlink replacement atomic or descriptor-anchored. Existing nonsymlink `.jbroot` entries are preserved but now cause a conservative trust-preparation failure for **required** files, even if their particular Mach-O does not need that `@rpath` backlink; weak/lazy dependencies remain optional. No physical example of such a conflict is known.

Separate uncorrected installer observation: `libarchive_unarchive()` in `BaseBin/libjailbreak/src/util.c` logs `ARCHIVE_WARN` for archive header/write/finish operations yet may return overall success. A skipped symlink during extraction could therefore escape notice; `DOBootstrapper.m` does not explicitly validate the three APT links after extraction. The existing physical r198 message is **signature invalid**, not merely a missing image, and the real installed links were not inspected. Do not attribute the observed failure to this conditional possibility or mutate an installed root to test it. A separate narrowly scoped integrity check for **fresh roots** would be appropriate before another fresh installation.

## Still needed on hardware

- Show the parent that spawns `apt/methods/http` completed the `systemhook` constructor and pretrusted the dependency closure.
- Confirm the installed `libgnutls.30.dylib` CDHash and file hash, kernel trustcache acceptance, and a successful dyld load/HTTP method execution. The original bootstrap archive's valid ad-hoc signature is insufficient.
- Verify actual tweak injection, TweakLoader constructors, Sileo/Zebra, OpenSSH, NewTerm, `CS_INSTALLER`, and `mobile` password change separately.
- No USB writes, agents, package operations, SSH retries, or device reboots are authorized as part of this source/CI phase.
