#!/usr/bin/env python3
"""Static prerequisites for the RootHide 2 -> Dopamine 3 port.

An all-green report means only that the listed components are connected in
source. It does not establish that a jailbreak is safe or works on a device.
"""

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DOMAIN_RE = re.compile(r"^\s*#define\s+(JBS_DOMAIN_\w+)\s+(\d+)\b", re.M)


def read(relative: str) -> str:
    path = ROOT / relative
    return path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""


def require(label: str, files: tuple[str, ...], text_checks: tuple[tuple[str, str], ...] = ()) -> dict:
    absent = [path for path in files if not (ROOT / path).is_file()]
    absent += [f"{path} (missing {token!r})" for path, token in text_checks if token not in read(path)]
    return {"component": label, "ready": not absent, "missing": absent}


def ipc_domain_check() -> dict:
    path = "BaseBin/libjailbreak/src/jbserver_domains.h"
    domains = {name: int(value) for name, value in DOMAIN_RE.findall(read(path))}
    problems = []
    if "JBS_DOMAIN_DOPAMINE" not in domains:
        problems.append("Preserve the Dopamine app IPC domain")
    if "JBS_DOMAIN_ROOTHIDE" not in domains:
        problems.append("Add a RootHide IPC domain and its explicit authorization policy")
    by_id: dict[int, list[str]] = {}
    for name, value in domains.items():
        by_id.setdefault(value, []).append(name)
    for number, names in by_id.items():
        if len(names) > 1:
            problems.append(f"IPC domain number {number} is shared: {', '.join(names)}")
    if "gRootHideDomain" not in read("BaseBin/launchdhook/src/jbserver/jbserver_global.c"):
        problems.append("Wire an authorized RootHide server domain before enabling the client")
    return {"component": "XPC domain separation", "ready": not problems, "missing": problems}


REQUIRED_DEVICE_CHECKS = (
    "initial_boot",
    "hidden_bootstrap",
    "path_and_process_hiding",
    "package_installation",
    "tweak_injection_and_blacklist",
    "re_jailbreak_and_userspace_reboot",
    "uninstall_and_recovery",
    "stock_dopamine_coexistence",
)


def hardware_evidence_check() -> dict:
    """An explicit human-reviewed evidence index, never a source-only green."""
    path = ROOT / "validation/device-tests.json"
    if not path.is_file():
        return {"component": "Hardware validation evidence",
                "ready": False,
                "missing": ["validation/device-tests.json (not supplied; do not fabricate device results)"]}
    problems = []
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
        tested_commit = manifest.get("tested_commit")
        if not isinstance(tested_commit, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", tested_commit):
            problems.append("Evidence needs a full tested Git commit hash")
        else:
            # Evidence logs necessarily require a later commit. Allow only
            # validation/** changes after the exact *tested code*; any source
            # modification invalidates the recorded device evidence.
            ancestor = subprocess.run(["git", "merge-base", "--is-ancestor",
                                       tested_commit, "HEAD"], cwd=ROOT,
                                      capture_output=True, check=False)
            if ancestor.returncode != 0:
                problems.append("Tested Git commit is not an ancestor of HEAD")
            else:
                changed = subprocess.check_output(
                    ["git", "diff", "--name-only", tested_commit, "HEAD"],
                    cwd=ROOT, text=True).splitlines()
                if any(not name.startswith("validation/") for name in changed):
                    problems.append("Source code changed since device validation")
        if not manifest.get("device_model") or not manifest.get("ios_version"):
            problems.append("Device model and iOS version are required")
        scenarios = manifest.get("scenarios")
        if not isinstance(scenarios, dict):
            scenarios = {}
        for name in REQUIRED_DEVICE_CHECKS:
            entry = scenarios.get(name)
            if not isinstance(entry, dict) or entry.get("result") != "pass":
                problems.append(f"No passing hardware evidence for {name}")
                continue
            relative = entry.get("log")
            digest = entry.get("sha256")
            if not isinstance(relative, str) or not relative.startswith("validation/logs/"):
                problems.append(f"Log path is missing or outside validation/logs for {name}")
                continue
            absolute = (ROOT / relative).resolve()
            if not absolute.is_relative_to((ROOT / "validation/logs").resolve()) or not absolute.is_file():
                problems.append(f"Hardware log not present for {name}")
            elif hashlib.sha256(absolute.read_bytes()).hexdigest() != digest:
                problems.append(f"Hardware log hash does not match for {name}")
    except (OSError, ValueError, TypeError, subprocess.CalledProcessError) as exc:
        problems.append(f"Hardware evidence cannot be verified: {exc}")
    return {"component": "Hardware validation evidence", "ready": not problems,
            "missing": problems}


def inspect() -> list[dict]:
    return [
        ipc_domain_check(),
        require(
            "RootHide state and trust client",
            (
                "BaseBin/libjailbreak/src/jbclient_roothide.c",
                "BaseBin/libjailbreak/src/roothider/common.h",
                "BaseBin/libjailbreak/src/roothider/exec_patch.m",
            ),
            (("BaseBin/libjailbreak/Makefile", "src/roothider/"),),
        ),
        require(
            "Hidden bootstrap and randomized root",
            ("Application/Dopamine/Jailbreak/DOBootstrapper.m",),
            (
                ("Application/Dopamine/Jailbreak/DOBootstrapper.m", ".jbroot-"),
                ("Application/Dopamine/Jailbreak/DOBootstrapper.m", "RH3NewBrand"),
                ("Application/Dopamine/Jailbreak/DOEnvironmentManager.m", "rootHideBrandForPath"),
            ),
        ),
        require(
            "Dopamine 3-compatible RootHide process and dyld integration",
            (
                "BaseBin/systemhook/src/roothider_port.c",
                "BaseBin/dyldhook/src/roothider.c",
                "BaseBin/dyldhook/src/roothider.S",
            ),
            (
                ("BaseBin/systemhook/src/main.c", "roothide_prepare_process"),
                ("BaseBin/dyldhook/src/main.c", "dyldhook_init_roothide"),
            ),
        ),
        require(
            "RootHide launchd and IPC integration",
            (
                "BaseBin/launchdhook/src/jbserver/jbdomain_roothide.c",
                "BaseBin/jailbreakd/src/server.m",
            ),
            (
                ("BaseBin/launchdhook/src/main.m", "initJailbreakd(firstLoad, &gGlobalServer)"),
                ("BaseBin/libjailbreak/src/roothider/jailbreakd.c", "RH3DispatchBootstrapMessage(gJailbreakdBootstrapServer, xdict)"),
                ("BaseBin/launchdhook/src/spawn_hook.c", "commitBlacklistProcessId"),
                ("BaseBin/libjailbreak/src/roothider/common.m", "roothide_is_active"),
            ),
        ),
        require(
            "Filesystem and package-manager hooks",
            (
                "BaseBin/roothidehooks/Makefile",
                "BaseBin/roothidehooks/pathhook.x",
                "BaseBin/roothidehooks/installd.x",
                "BaseBin/roothidehooks/lsd.x",
                "BaseBin/roothidehooks/cfprefsd.x",
            ),
            (("BaseBin/Makefile", "roothidehooks"),),
        ),
        require(
            "RootHide-specific bootstrap packages and manager",
            ("Application/Dopamine/Resources/roothideapp.deb",),
            (
                ("Application/Dopamine/Jailbreak/DOBootstrapper.m", "roothideapp.deb"),
                ("Application/Dopamine/Jailbreak/DOBootstrapper.m", "roothide.github.io"),
            ),
        ),
        require(
            "Explicit RootHide activation gate",
            ("Application/Dopamine/Jailbreak/DOBootstrapper.m",),
            (
                ("Application/Dopamine/Jailbreak/DOBootstrapper.m", "#define ROOTHIDE3_BOOTSTRAP_READY 1"),
            ),
        ),
        hardware_evidence_check(),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--strict", action="store_true", help="Fail if any port prerequisite is missing")
    parser.add_argument("--json", action="store_true", help="Emit a machine-readable report")
    args = parser.parse_args()

    checks = inspect()
    complete = sum(check["ready"] for check in checks)
    if args.json:
        print(json.dumps({"static_prerequisites": f"{complete}/{len(checks)}", "checks": checks}, indent=2))
    else:
        print(f"RootHide/Dopamine 3 static prerequisites: {complete}/{len(checks)}")
        for check in checks:
            print(f"  {'PASS' if check['ready'] else 'MISSING'}  {check['component']}")
            for detail in check["missing"]:
                print(f"           {detail}")
        print("Static checks do not prove build, installation, kernel stability, or hiding effectiveness.")
    return 2 if args.strict and complete != len(checks) else 0


if __name__ == "__main__":
    raise SystemExit(main())
