# Signature fixes and targeted port research — 15 October 2026

Base reviewed: `5b356861379b7d63acd4943291a4fc459889c870`.

## Applied fixes

- The shared pinned ChOma page-hash routine now uses incremental SHA-384 for
  SHA-384 CodeDirectories, and checks the declared digest size for every
  supported algorithm. It writes the output only after successful completion.
- Page geometry is validated before I/O: the port supports unpaged signatures
  (`pageSize=0`), 4 KiB and 16 KiB pages, with a positive 32-bit codeLimit,
  consistent nCodeSlots, a valid requested slot and file bounds. Other page
  layouts fail explicitly instead of using an attacker-sized VLA or pow().
- All reads use a fixed 16 KiB chunk. Unpaged signatures are streamed rather
  than allocating the complete signed region on the stack.
- The RootHide SuperBlob validator checks the same geometry. Randomization
  checks the bounded page-hash consumer before its first __TEXT write and uses
  a fixed 48-byte digest buffer. This does not make later filesystem writes
  transactional or certify all of ChOma's Mach-O parsing.

`BaseBin/ChOma` remains pinned to its original upstream commit. The tracked
overlay `BaseBin/patches/choma_page_hash.c` is applied before compiling ChOma
by `tools/apply_choma_fixes.py`. The applicator verifies the original function
SHA-256, refuses source drift and is idempotent. XPF uses this same library via
`CHOMA_PATH=../ChOma`; the standalone CLI also compiles the patched shared
source. Do not update the submodule pointer to a nonexistent local commit.

For a fresh checkout:

```sh
git submodule update --init --recursive
python3 tools/apply_choma_fixes.py
python3 tools/apply_choma_fixes.py --check
python3 -m unittest discover -s tools/tests
```

The host test compiles and executes the production replacement C with real
digest implementations and an independent hashlib comparison. On macOS it
uses CommonCrypto directly; on Windows it adapts the same operations to
CryptoAPI, allowing 32-bit MinGW executables to be tested by 64-bit Python.
Tests cover SHA-1, SHA-256, truncated SHA-256, SHA-384, partial final pages,
unpaged streaming, output canaries, invalid page exponents/slot counts/file
bounds, read failures, patch idempotence/source drift and build wiring.

## Research results and decisions

This is a targeted search, not a claim to have read every forum or issue.
Community search results were used as leads; the decisions below use primary
project discussions and code. Reports do not establish the same fault in this
port without a matching trace.

| Primary source | Evidence and decision for this port |
|---|---|
| [Apple XNU CodeDirectory layout](https://github.com/apple-oss-distributions/xnu/blob/main/osfmk/kern/cs_blobs.h) | pageSize is a base-2 exponent; zero denotes unpaged data. Retain zero with bounded streaming, rather than treating it as a one-byte page. SHA-384 uses a 48-byte hash. |
| [Pinned ChOma CodeDirectory.c](https://github.com/opa334/ChOma/blob/7dccded6bc17081c08f5f5cdbd7a4b051543a825/src/CodeDirectory.c) | Directly confirmed wrong SHA-256 call in SHA-384 page hashing and untrusted VLA. Fixed through the build overlay; CDHash calculation is a separate routine. |
| [RootHide PR 142](https://github.com/roothide/Dopamine2-roothide/pull/142) | The maintainer disputes the proposed deadlock explanation and warns that a timeout can hide the real bug. No blind cherry-pick or arbitrary timeout reduction. Obtain a stackshot and wait chain before changing exec queues. |
| [RootHide PR 149](https://github.com/roothide/Dopamine2-roothide/pull/149) | Closed after discussion of p_uniqueid and its stability across xpcproxy exec. A synthetic PID-cache model alone does not prove the launchd lifecycle reaches that state. Do not import the rejected fix as an established defect. |
| [RootHide issue 108](https://github.com/roothide/Dopamine2-roothide/issues/108) | Frida failures depended on dyld patch being enabled; the reporter confirmed a test build fixed the case. Test spawn/attach separately with the exact Frida and dyld configuration; avoid attributing every crash to the hook library. |
| [RootHide issue 113](https://github.com/roothide/Dopamine2-roothide/issues/113) | App Store install/update failure warrants a lifecycle acceptance case. It does not identify the cause in this port; collect appstored/installd logs before changing caches. |
| [Dopamine issue 573](https://github.com/opa334/Dopamine/issues/573) | Non-default Mach-O slice execution was reported fixed in 2.1.5. Preserve preferred-architecture behavior and test actual slices, rather than reapplying a historical workaround. |
| [RootHide releases](https://github.com/roothide/Dopamine2-roothide/releases) | 2.4.9.23 documents an iOS 15 arm64e userspace-reboot panic; 2.4.9.24 reports its fix. Preserve a distinct first boot/re-jailbreak/userspace reboot test matrix; copying the latest file is not proof of parity with Dopamine 3. |

## Remaining runtime work

The spawn/exec and dyld state machine still needs a complete reconciliation
with Dopamine 3. In particular: suspended child ownership, patch success,
resume/cancel, xpcproxy/SETEXEC, prewarm, extensions, DriverKit and WebContent.
RootHide's old wrappers must not be connected indiscriminately: some failure
branches deliberately leave a child suspended. New timeout handling does not
undo an interrupted opainject modification of launchd.

XPC reply filtering, ABI compatibility, entitlements, sandbox access before
library initialization and userspace reboot/recovery require physical tests.
The new signature fixes do not enable the bootstrap gate and do not certify
an installable or functional RootHide jailbreak.

CI run [38625490115](https://github.com/Gokuencinar/Dopamine3-RootHide-exp/actions/runs/38625490115)
for the *base* commit completed compilation and reached the final strict
activation/hardware gate, where the job failed. That distinction corrects the
earlier in-progress snapshot. It does not compile the local fixes in this note.
