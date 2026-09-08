# Release v2.0.8

Version v2.0.8 — September 8, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.0.8`

This release adds `--scores` to `cybedefend results`: the CVE identifiers and the risk scores the platform computes, in every output format. It is a drop-in replacement — the flag is opt-in and the default output is unchanged.

---

## Changes

### `--scores` exposes CVE identifiers and risk scores

Until now `cybedefend results` returned the finding and its references — CWE, OWASP, location, severity — but none of the scoring the platform computes on top of it. The prioritization you see in the UI could not be reached from the CLI, so a CI pipeline could sort findings by severity and nothing else.

```bash
cybedefend results --project-id your-project-id --type sca --scores --output markdown
```

With `--scores`, each vulnerability additionally carries:

- `cve` — the CVE identifier, for SCA and container findings. For an advisory that carries it only among its aliases, the alias is used.
- `currentSeverity` / `currentPriority` — the effective severity and the treatment priority (`critical_urgent`, `urgent`, `normal`, `low`, `very_low`).
- `scores.priorityScore` — the 0–100 priority score blending CVSS 4.0 environmental, EPSS, exploitability and business context.
- `scores.cvss4BaseScore` / `scores.cvss4Vector` — CVSS 4.0 base score and vector.
- `scores.cvss4EnvironmentalScore` / `scores.cvss4EnvironmentalVector` — the same, contextualized with the project security context.
- `scores.cvss4Breakdown` — the vectors decoded metric by metric as in the UI: base metrics grouped into Exploitability, Vulnerable System Impact and Subsequent System Impact, plus the threat, environmental and supplemental metrics that are defined (`AV:N` → Attack Vector: Network, `CR:H` → Confidentiality Requirement: High).
- `scores.epssScore` / `scores.epssPercentile` — EPSS exploitation probability and percentile.
- `scores.exploitabilityScore` / `scores.exploitabilityVerdict` — the exploitability assessment (`not_exploitable`, `theoretical`, `proven`, `actively_exploited`).
- `scores.scoringSource` — whether the scoring came from `static` heuristics or from `agent` analysis.

A field is omitted when the platform has not computed it. Absent and zero are distinct: a score of `0` is a real score and is reported as such, while a score that was never computed does not appear at all — so a missing `epssScore` never reads as "no exploitation probability".

### Risk data in every output format

`--scores` is not JSON-only. The four formats carry the same data in the shape each consumer expects:

- **JSON** — the `cve`, `currentSeverity`, `currentPriority` and `scores` fields described above.
- **SARIF** — a standard property bag on each result, plus a GitHub-compatible `security-severity` value. GitHub Code Scanning reads that key to assign its own severity, preferring the environmental score over the base score when both exist, so an uploaded SARIF now ranks findings the way the platform does.
- **HTML** — a "Risk Scores" block per finding, with the priority badge and the CVSS 4.0 breakdown.
- **Markdown** — the CVE in the finding title and linked to its NVD entry, the priority, CVSS 4.0 base and environmental scores with their vectors, EPSS and the exploitability verdict, followed by the CVSS 4.0 breakdown table.

### The default output keeps its historical shape

`--scores` is off by default and the fields it adds are stripped when it is not set. A pipeline that parses `results.json` today sees byte-identical output after upgrading; nothing has to be adapted before you are ready to consume the new fields.

---

## Documentation

The `results` section of the README documented a subset of the flags the command actually accepts. Four already-shipped behaviours are now written down — no code change, only documentation catching up:

- `--type all` is the default and returns every scan type, grouped by category. The README still described `sast` as the default.
- `--branch, -b` filters results by branch.
- `--grouped, -g` returns results grouped by rule/CVE, in JSON output.
- `markdown` is accepted by `--output`, alongside `json`, `html` and `sarif`.

---

## Upgrade Notes

Nothing to do beyond upgrading. `--scores` is opt-in; without it the output is unchanged.

If you upload SARIF to GitHub Code Scanning and want the platform's prioritization reflected in GitHub's own severity column, add `--scores` to the command that produces the report.
