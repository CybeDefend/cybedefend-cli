# Release v2.0.4

Version v2.0.4 — September 3, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.0.4`

This release fixes one bug in the SARIF exporter. It is a drop-in replacement: no configuration change, no migration, no re-login.

---

## Bug Fixes

### A scan with no findings produced a SARIF file that could not be uploaded

`results --output sarif` built its result list as a nil slice, and Go writes a nil slice as JSON `null` rather than `[]`. A scan that found nothing therefore produced:

```json
"runs": [ { "tool": { … }, "results": null } ]
```

The SARIF 2.1.0 schema types `run.results` as an array, so this file fails validation:

```
None is not of type 'array'   @ runs[0].results
```

`github/codeql-action/upload-sarif` validates against that schema, so a repository with **nothing to report** could not publish its results to the GitHub Code scanning tab — the steady state of a healthy project, and the whole point of running the scan. A report that contained findings was unaffected, which is why this went unnoticed: it only appears once a project is clean.

The exporter now always emits an array, empty or not. `json`, `html` and `markdown` were never affected.

---

## Upgrade Notes

Nothing to do beyond upgrading. If you export SARIF from CI, a clean scan now produces a file `upload-sarif` accepts instead of rejecting it.

`CybeDefend/cybedefend-action` consumes this fix from v2.1.0, where `report_format: sarif` writes the report and exposes its path as a step output.
