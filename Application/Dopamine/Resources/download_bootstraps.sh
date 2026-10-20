#!/usr/bin/env bash
set -euo pipefail

# These are upstream stock Dopamine assets, separate from the pinned RootHide
# archives. A 404 or an HTML error body must never silently become a resource.
for version in 1800 1900; do
    file="bootstrap_${version}.tar.zst"
    case "$version" in
        1800) expected_sha256=a99b39bb0344ee3b42bb961325038dceae7daaec500976f3b822cf36cccf020a ;;
        1900) expected_sha256=8354c3aa1ecdad8ebc47d9a76dfca6f830a2b757278068bd33b98bf1d638a9cb ;;
    esac
    # Verify restored cache contents just like a fresh download.
    if [[ -f "$file" && ! -L "$file" ]] &&
        echo "${expected_sha256}  ${file}" | shasum -a 256 -c - >/dev/null 2>&1 &&
        python3 -c 'from pathlib import Path; import sys; p = Path(sys.argv[1]); assert p.stat().st_size > 1024 and p.open("rb").read(4) == bytes.fromhex("28b52ffd")' "$file"; then
        echo "Using verified cached Procursus $file"
        continue
    fi
    rm -f "$file" "${file}.download"
    curl --fail --location --retry 3 --retry-delay 2 \
        "https://apt.procurs.us/bootstraps/${version}/bootstrap-iphoneos-arm64.tar.zst" \
        --output "${file}.download"
    echo "${expected_sha256}  ${file}.download" | shasum -a 256 -c -
    python3 -c 'from pathlib import Path; import sys; p = Path(sys.argv[1]); assert p.stat().st_size > 1024 and p.open("rb").read(4) == bytes.fromhex("28b52ffd"), f"invalid zstd archive: {p}"' "${file}.download"
    mv -f "${file}.download" "$file"
done
