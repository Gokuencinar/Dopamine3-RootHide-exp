# RootHide3 r198: physical APT library signature failure

## Observed (physical iPhone X, iOS 16.7.15)

The r198 jailbreak-enabled IPA (commit `ea482ab`) was installed and tested by
the owner. The APT HTTP method failed before its entry point could run:
`@rpath/libgnutls.30.dylib` yielded `code signature invalid` from the hidden
`.jbroot`, followed by `errno=1` from the direct hidden-root library path.
APT's package-not-found front-end message is **not** evidence that the package
or repository is missing.

The bundled 1900 bootstrap was inspected without modifying the phone:
`usr/libexec/apt/methods/http` and `usr/lib/libgnutls.30.dylib` are present.
Their original thin arm64 Mach-O CodeDirectories and code-page hashes verify,
including the APT method's `@rpath/libgnutls.30.dylib` dependency.
This says nothing about the hashes or trustcache state of the *installed*
files, which have not been read or changed.

## Targeted source changes

1. `roothider/recdhash.m`: earlier code opened an executable writable
   before checking its signature, then could leave its `__TEXT` brand and
   CodeDirectory page hash partially written on failure. The writer now
   validates the first code-page hash and write offsets read-only first, compares
   the signature and section on a later writable open, checks the persisted
   CodeDirectory and page hash, and attempts rollback of both writes on
   error. It refuses a first-page mismatch rather than accepting a CDHash
   that the kernel will reject for that page. This is **not** a full-file
   validation of other code pages, and rollback on I/O failure is best-effort.
2. `dyldhook/src/lv_bypass.c`: honor the kernel's actual
   `F_ADDFILESIGS*` result first; cover INFO/RETURN; propagate failed
   trust/attach instead of fabricating `fs_file_start` on success. Private
   dyld uses its existing `cerror` assembly trampoline to set POSIX errors;
   writing directly to `errno` would import unresolved `___error`.
3. `launchdhook/src/roothide_pid1_selected.h`: Sileo, Zebra and RootHide
   may launch as direct binaries rather than UIKit xpcproxy labels. Select
   only their exact package-verified executable paths within the active root
   for the existing *asynchronous* PID1 patch-before-resume path. Use the
   same pinned path-to-bundle-ID mapping before dispatch to honor the
   RootHide user blacklist; `isBlacklistedPath` alone only recognizes
   UUID containers, not `.jbroot-*` bundles. NewTerm's optional on-device
   executable is **not** bundled/verified and is excluded from the direct
   whitelist until its CFBundleExecutable and blacklist identity can be
   verified. The `com.hbang.NewTerm` xpcproxy base label is recognized,
   alongside the existing `ws.hbang.Terminal` label. No new synchronous
   XPC or arbitrary Apple process policy is added.

## Verified locally

- New source-contract regression tests failed before changing the code.
- The packaged Mach-O test reads the **actual** immutable 1900 bootstrap
  archive and verifies the APT library dependencies and original page hashes.
  A deliberately altered in-memory `libgnutls` code page fails validation.
- Host suite: **403 total, 367 passed, 36 skipped, 0 failed** (Windows).
- These tests do **not** prove iOS runtime trustcache upload, Mach-O attach,
  suspended-child patch, constructor completion, APT downloads or tweak load.

## Safety and remaining work

- No existing hidden root, apt/dpkg database, packages, SSH keys, passwords,
  system binaries or device settings were modified. Do not overwrite the
  installed `libgnutls` merely because a packaged original is available.
- An already-corrupted installed Mach-O will be refused, not silently
  repaired; a separate physically authorized, reversible, identity-checked
  recovery plan is needed if read-only evidence confirms corruption.
- `launchdhook` check-in, `posix_spawn` success and queued trustcache
  hashes cannot substitute for actual dyld mapping and constructor evidence.
- OpenSSH service/files, NewTerm execution, Sileo/Zebra registration, tweak
  constructors, and `pw` exit status remain unproven/failed per r198.
- **Readiness stays 7/9**. A successful compiler run must not turn this into
  a public release or claim that r198's device failures are resolved.
