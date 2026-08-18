# Contributing

Contributions are welcome — this is a portfolio of reference labs, and fixes
that make the patterns more correct, more least-privilege, or more assessable
are exactly on mission.

## Ground rules

1. **Every lab stays self-contained.** `scripts/export-lab-repos.sh` copies
   each `labs/<id>/` directory verbatim into a standalone repository. Nothing
   under `labs/<id>/src/` may import from outside its own directory; the
   shared runtime is vendored (see below).
2. **`lab_common.py` is vendored, not imported.** The canonical copy lives at
   `shared/lambda-common/lab_common.py`. Every lab carries a byte-identical
   copy at `labs/<id>/src/lab_common.py`. After editing the canonical copy,
   run `node scripts/check-common-sync.mjs --write` to resync, and never edit
   a vendored copy directly.
3. **Fail closed.** Handlers report `CONFIG_ERROR` when unconfigured — never
   `PASS`. Simulation data requires `{"mode": "simulation"}` and is stamped in
   the evidence artifact.
4. **Generated artifacts are rebuilt, not hand-edited.** `scf-mapping.generated.json`,
   `oscal-component.json`, `COVERAGE.md`, `coverage.json`, `RISKS.md`, and
   `docs/learn/index.html`, `docs/walkthroughs/00-operator-playbook.md`, and
   `labs/*/WALKTHROUGH.md` are produced by scripts under `scripts/`; CI rejects
   drift. Regenerate with:
   ```bash
   node scripts/postprocess-mappings.mjs
   node scripts/build-coverage.mjs
   node scripts/build-oscal.mjs
   node scripts/build-risk-register.mjs
   node scripts/build-walkthroughs.mjs
   node scripts/build-learn.mjs
   ```
5. **No new runtime dependencies.** Node tooling is dependency-free by design.
   Python handlers may use the stdlib and `boto3` (provided by the Lambda
   runtime). Dev-only tools are pinned in `requirements-dev.txt`.

## Local verification

```bash
pip install -r requirements-dev.txt
make lint     # ruff + cfn-lint + checkov
make test     # pytest + node --test (fully offline)
make check    # generated-artifact drift checks
```

All of the above run without network access. The live SCF crosswalk
regeneration only happens in the scheduled `scf-refresh` workflow (or locally
with `SCF_LIVE=1 npm run scf:map:all` if you have egress).

## Pull requests

- Keep commits scoped (one lab or one concern per commit where practical).
- New checks need tests; fixed bugs need regression tests named after the bug.
- Template changes must pass `cfn-lint` and `checkov` with suppressions only
  as inline `Metadata` entries carrying a justification.
