# SCF Mapper

Client for the [Secure Controls Framework static JSON API](https://grcengclub.github.io/scf-api/).

## Commands

```bash
node src/cli.js --list-frameworks
node src/cli.js --list-ksi
node src/cli.js ../../labs/01-mfa-continuous-validation/scf/lab-spec.json --out /tmp/map.json
```

## API

- `mapControl(controlId, { frameworks, ksi })`
- `mapLab({ lab_id, scf_controls, ksi, frameworks })`
- `reverseLookup(frameworkId, frameworkControlId)`
- `FEDRAMP_20X_KSI` — CR26 / FedRAMP 20x overlay (not in the SCF Excel workbook)

## Target frameworks (defaults)

| Alias | SCF framework_id |
|-------|------------------|
| NIST 800-53 R5 | `general-nist-800-53-r5-2` |
| NIST 800-171 R3 | `general-nist-800-171-r3` |
| ISO 27001:2022 | `general-iso-27001-2022` |
| PCI DSS 4.0.1 | `general-pci-dss-4-0-1` |
| FedRAMP Moderate R5 | `usa-federal-gsa-fedramp-5-mod` |
