# RootHide3 OpenSSH 1900: offline package installation (2026-10-24)

## Physical evidence

r209, iPhone X iOS 16.7.15: in `RootHide3-attempt-89B5DF5D-C472-4786-B6CD-6BBA963C737F.log`, the protected installer phase reached `SSH preflight: directory etc/ssh cannot be opened safely (errno=2)`; the later user-launched repair was denied `installer right unavailable`. The pinned RootHide bootstrap 1900 archive contains none of `etc/ssh`, `usr/sbin/sshd`, `usr/bin/ssh-keygen`, or `com.openssh.sshd.plist`. The existing repair was therefore attempting to adjust a package that was never installed. Tweaks are still reported broken; new SSH code does not fix that.

## Verified upstream inputs

The following RootHide iOS 16 `iphoneos-arm64e/1900` packages were downloaded from `https://roothide.github.io/procursus/pool/main/iphoneos-arm64e/1900/openssh/`, checked against the SHA-256 values published in the matching repository package index and inspected locally:

| Artifact | SHA-256 |
| --- | --- |
| `openssh-client_9.2p1_iphoneos-arm64e.deb` | `f178c962e65862f5c42bd7317cd234b0f61c5e374901a8811a5e89141d4b7f08` |
| `openssh-server_9.2p1_iphoneos-arm64e.deb` | `7030f44fdbb1851cb6e702c02a60842dff54ac7fcabb80745bf34069757d9c6a` |
| `openssh-sftp-server_9.2p1_iphoneos-arm64e.deb` | `07670c829ba94722ab69a8457363c0eb737c2e9951cb558668d0ce724a529431` |

The original server package has an `extrainst_` script that runs `launchctl load -w` and a default `sshd_config` with `PermitRootLogin yes`; this is not acceptable for pre-import automatic setup. `tools/build_roothide_ssh_server_payload.py` creates a deterministic local derivative after verifying the original server SHA-256. Its **only** content modifications are (1) replace `extrainst_` and `prerm` with no-op scripts, (2) set `PermitRootLogin prohibit-password`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, `PermitEmptyPasswords no`, and (3) recalculate the matching `etc/ssh/sshd_config` entry in the package's `md5sums` manifest. Binary executables and linked libraries are retained without modification. The derived package is embedded as `roothide_ssh_server_safe_1900.deb` SHA-256 `ccd27b95690071f181dfb3869d59b721efa1e27e0ab6f0c8c5937f29e9bd7bfd`. Provenance uses an upstream package index, but repository GPG signature verification is still to be established separately.

Only the 1900 packages are currently integrated: iOS 15/1800 must return ENOTSUP rather than installing the wrong ABI. The 1900 bootstrap already has all the packages named as dependencies of these three OpenSSH packages except OpenSSH itself.

## Installation contract and safety

`rh3SSHInstallerRepairOptIn=true` must be persisted for the SSH path to run. During the **already privileged initial jailbreak installer phase**, after bootstrap and packages have finished, `DOEnvironmentManager` checks an exact active hidden root, `CS_INSTALLER`, verified pinned resources and installed package records. If the three OpenSSH packages are absent **and no old SSH config, key, binary or job path exists**, a single offline dpkg transaction installs client + SFTP + patched server. A partial installation or conflicting previous state is preserved without an automatic retry. If all are already installed, no package is reinstalled; existing SSH config and host keys remain untouched. An absent ED25519 host key is generated once at an exact hidden-root path. Next, the existing atomic, backed-up SSH plist rebase replaces **only** Program/ProgramArguments with paths into the active root. The existing launchdhook adds root-owned daemon jobs during subsequent userspace restart; no immediate launchctl load is attempted while PID1 is in the delicate injection phase.

The initial server configuration permits **public-key authentication only**, never remote root password access. The app's mobile password-change feature is a separate workstream; passing tests or delivering a packaged IPA does not prove remote login is available, that a password changed, or that `sshd` emits a real `SSH-2.0` banner. `launchctl print`/`print-disabled`, socket connection, constructor evidence, host-key modes and user authentication must all be checked on the device after the reboot. Never test with default passwords, never log password contents or key bytes, never replace `/etc` on the stock filesystem.

The USB connection is to be used **read-only**. Do not pair, install agents, reboot, change credentials, or deploy the IPA from the PC without separate permission. Readiness remains 7/9 until runtime validation.

## Mobile password-change status

This SSH package integration does **not** certify or repair `mobile` password writes. The app's `pw -V <verified-hidden-etc> usermod mobile -h 0` execution and post-write hash change verification already exist, but physical failures have previously reported exit 1. The app does not retain `CS_INSTALLER` on relaunch; `pw` may also call `pwd_mkdb` as a child which needs write permissions. A direct edit to `master.passwd`/`spwd.db`, blanket app entitlement inheritance, or unconditional retry could lock the user out and must not be introduced. The next app build records only `csops_ok/installer/platform/uid0` before the password command and refuses to skip device-owner authentication when LA is unavailable. A secure, narrowly scoped password helper is future work; no password contents or hashes are logged or stored.

## Post-r211 diagnosis and experimental default correction

The owner installed r211 (run `40106673421`, commit `de9fb04`, artifact `12564633553`, ZIP SHA-256 `8530f6c655238d1da5e6f3e3d009d0c5b0df42be47880ba2f786da6d6737ed9a`) and reported that SSH still rejects connections. The native build, source tests, hardware-beta verifier and artifact upload succeeded; the strict physical-readiness gate failed as expected. Neither the client's exact error nor the r211 attempt log was supplied. **Do not attribute the physical failure to any single stage without the log.**

The r211 code had a reproducible mismatch against the user's *explicit* All Enabled Beta request: missing preference `rh3SSHInstallerRepairOptIn` defaulted to NO and silently skipped the entire SSH package-installation and launchd preparation path. Subsequent experimental builds now pass `ROOTHIDE3_SSH_DEFAULT_PREPARE=1` **only** when both `hardware_beta=true` and `all_enabled=true`. The ordinary build and non-All-Enabled hardware beta still default to zero. A previously saved explicit NO always disables this behavior; no existing SSH keys, plist overrides, packages, or configuration are replaced. The UI shows the effective state and preserves an explicit confirmation to change it. This opt-in-by-build is justified by the owner's request to enable SSH in this exact experimental profile; public/general builds must not inherit the default.

The read-only in-app SSH diagnostic now records the policy's default/saved/effective bits; a bounded, symlink-resistant dpkg status probe with a bitmask of fully installed SSH receipts (`7` means client+SFTP+server); and trusted sshd/config/ED25519-key presence. These checks precede the launchd job inspection, so a missing job is distinguishable from absent/partial packages and from a disabled or unimported live service. No network listeners, services, accounts or device content are modified by this diagnostic. On-device banner and port-22 proof remain required, along with separate restoration of password-change rights and tweak execution.
