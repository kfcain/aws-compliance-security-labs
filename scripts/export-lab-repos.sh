#!/usr/bin/env bash
# Export each lab as a sibling git repository (ready to push to its own remote).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/../compliance-lab-repos}"
mkdir -p "$OUT"

python3 - <<PY
import json, shutil
from pathlib import Path
root = Path("$ROOT")
out = Path("$OUT")
catalog = json.loads((root / "labs/catalog.json").read_text())
for lab in catalog["labs"]:
    src = root / lab["path"]
    dest = out / lab["repo_name"]
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=shutil.ignore_patterns(".git"))
    vendor = dest / "vendor"
    vendor.mkdir(exist_ok=True)
    if (vendor / "scf-mapper").exists():
        shutil.rmtree(vendor / "scf-mapper")
    shutil.copytree(root / "shared/scf-mapper", vendor / "scf-mapper")
    pkg = json.loads((dest / "package.json").read_text())
    pkg["scripts"]["scf:map"] = "node ./vendor/scf-mapper/src/cli.js ./scf/lab-spec.json --out ./scf/scf-mapping.generated.json"
    (dest / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")
    print("Exported", lab["repo_name"])
PY
