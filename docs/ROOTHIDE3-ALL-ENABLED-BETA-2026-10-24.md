# RootHide3: explicit jailbreak + tweaks initial activation (2026-10-24)

## Scope and request

Requested a test IPA with everything enabled instead of repeated automatic `JAILBREAK-DISABLED` builds. Added a distinct manual-only `all_enabled` input that requires `hardware_beta=true` and generates a separately named artifact. Ordinary push CI still produces the guarded disabled full experimental app; ordinary manual hardware beta still starts safe on first activation.

`ROOTHIDE_ALL_ENABLED=YES` in GNU Make requires `ROOTHIDE_HARDWARE_TEST=YES`, sets `ROOTHIDE3_TWEAKS_DEFAULT_ON=1` at Xcode compile time and changes only the **first activation** policy on a genuinely new hidden bootstrap: skip automatic creation of `basebin/.safe_mode`. Do **not** delete any existing safe-mode marker, watchdog latch, pending tweak request, package or user data. Subsequent activations continue to respect effective persisted safe mode and the authorized staged toggle. The `DISABLE_TWEAKS=1` environment of the installer helper remains deliberately constrained for bootstrap package scripts, not a global switch for processes after userspace reboot. Keep systemhook exclusions and watchdog fail-closed behavior.

The main Mach-O carries distinguishable markers (`RH3_HARDWARE_BETA_ACTIVATED_V1` and `RH3_TWEAKS_DEFAULT_ENABLED_V1`), checked in the real IPA verifier. A regular hardware beta carries `RH3_TWEAKS_DEFAULT_SAFE_V1`; contradictory and missing markers fail validation.

## What this does not activate or prove

- The initial RootHide bootstrap does **not** bundle the OpenSSH daemon; no unauthenticated SSH service is started. SSH preparation remains opt-in after account credential verification. NewTerm is an optional installed package.
- Per-process `systemhook`/`TweakLoader` loading, RootHide package managers, dyld/CDHash/trustcache acceptance and APT `libgnutls` must still function. The last **physical failure** remains r198 on iPhone X iOS 16.7.15, APT method `@rpath/libgnutls.30.dylib` `code signature invalid`. This beta does not independently fix that problem.
- Validation must separately distinguish code changes, local tests, macOS build, IPA packaging, signed binary markers, and actual device behavior. Do not claim functional success without a hardware report. Readiness remains 7/9 pending physical evidence.
- USB interaction is read-only. Do not install the IPA, alter the iPhone, change accounts or reboot as part of this build.
