#!/usr/bin/env python3
"""Apply the reviewed page-hash overlay to pinned ChOma, without repinning it.

Fail on source drift; never overwrite unrelated submodule changes. BaseBin's
shared ChOma is also used by XPF and the standalone CLI build.
"""
from pathlib import Path
import argparse
import hashlib

ROOT = Path(__file__).resolve().parents[1]
ORIGINAL_FUNCTION_SHA256 = "7acc0c59a38a7f98d6ef4b1d3584dffb4b81c0d2eb4d4b1c95339f1d9b2210e1"


def patched_source(source: str) -> str:
    start = source.index("bool code_directory_calculate_page_hash(")
    end = source.index("\nbool csd_code_directory_verify_code_slot(", start)
    replacement = (ROOT / "BaseBin/patches/choma_page_hash.c").read_text(encoding="utf-8")
    # Comments above the replacement function stay in the tracked overlay.
    replacement = replacement[replacement.index("bool code_directory_calculate_page_hash("):].rstrip() + "\n"
    original = source[start:end]
    if original == replacement:
        return source
    if hashlib.sha256(original.encode()).hexdigest() != ORIGINAL_FUNCTION_SHA256:
        raise ValueError("ChOma page-hash source drift: review before applying this overlay")
    return source[:start] + replacement + source[end:]


def apply(path: Path, check: bool = False) -> None:
    source = path.read_text(encoding="utf-8")
    result = patched_source(source)
    if check and result != source:
        raise ValueError("ChOma page-hash overlay has not been applied")
    if result != source:
        path.write_text(result, encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    apply(ROOT / "BaseBin/ChOma/src/CodeDirectory.c", args.check)
    print("ChOma page-hash overlay verified")
