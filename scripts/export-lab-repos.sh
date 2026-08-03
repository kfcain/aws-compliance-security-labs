#!/usr/bin/env bash
# Export each lab as a sibling git repository (initialized and committed,
# ready to push to its own remote).
#
# Usage: scripts/export-lab-repos.sh [output-dir]
#
# Paths are passed to Python via the environment (never interpolated into
# code) and the heredoc delimiter is quoted, so hostile arguments cannot
# inject Python. Destination names from catalog.json are validated and
# confined to the output directory before anything is removed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-$ROOT/../compliance-lab-repos}"
mkdir -p "$OUT"

EXPORT_ROOT="$ROOT" EXPORT_OUT="$OUT" python3 - <<'PY'
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

root = Path(os.environ["EXPORT_ROOT"]).resolve()
out = Path(os.environ["EXPORT_OUT"]).resolve()

REPO_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
IGNORE = shutil.ignore_patterns(
    ".git", "node_modules", ".aws-sam", "__pycache__", ".pytest_cache",
    ".venv", "dist", "coverage", ".scf-cache",
)

catalog = json.loads((root / "labs/catalog.json").read_text())
for lab in catalog["labs"]:
    repo_name = lab["repo_name"]
    if not REPO_NAME_RE.fullmatch(repo_name):
        raise SystemExit(f"refusing invalid repo_name: {repo_name!r}")
    src = (root / lab["path"]).resolve()
    if not src.is_relative_to(root / "labs"):
        raise SystemExit(f"refusing lab path outside labs/: {lab['path']!r}")
    dest = (out / repo_name).resolve()
    if not dest.is_relative_to(out) or dest == out:
        raise SystemExit(f"refusing destination outside output dir: {dest}")
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(src, dest, ignore=IGNORE)

    vendor = dest / "vendor"
    vendor.mkdir(exist_ok=True)
    shutil.copytree(root / "shared/scf-mapper", vendor / "scf-mapper", ignore=IGNORE)

    for governance in ("LICENSE", "SECURITY.md"):
        gov_src = root / governance
        if gov_src.exists():
            shutil.copy2(gov_src, dest / governance)

    pkg_path = dest / "package.json"
    pkg = json.loads(pkg_path.read_text())
    pkg.setdefault("scripts", {})["scf:map"] = (
        "node ./vendor/scf-mapper/src/cli.js ./scf/lab-spec.json"
        " --out ./scf/scf-mapping.generated.json"
    )
    pkg["license"] = "MIT"
    pkg_path.write_text(json.dumps(pkg, indent=2) + "\n")

    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=dest, check=True)
    subprocess.run(["git", "add", "-A"], cwd=dest, check=True)
    subprocess.run(
        ["git", "-c", "user.name=export-script", "-c", "user.email=export@localhost",
         "commit", "-q", "-m", f"Export {repo_name} from aws-compliance-security-labs"],
        cwd=dest, check=True,
    )
    print("Exported", repo_name)
PY
