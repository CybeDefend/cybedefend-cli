# Release v2.0.2

Version v2.0.2 — February 25, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.0.2`

---

## What's New

### Markdown output

The `results` command now supports `--output markdown` (`-o markdown`). The generated report lists all findings grouped by severity with their location, description, remediation steps, and CWE / OWASP tags — ready to paste into a pull-request description, a wiki, or a Slack message.

```bash
cybedefend results --project-id <ID> -o markdown -f report.md
```

---

### Fetch all scan types at once

`cybedefend results` now defaults to fetching **all six scan types** — SAST, SCA, IAC, Secret, CICD, and Container — in a single command. No need to run the command once per type.

```bash
# All types — new default
cybedefend results --project-id <ID> -o html -f full-report.html

# Single type when needed
cybedefend results --project-id <ID> --type sast
```

For JSON output, results are organised by category. For HTML, SARIF, and Markdown they are merged into a single unified report.

---

### Branch filter — `--branch` / `-b`

Filter results to a specific branch when a project has multi-branch scanning enabled.

```bash
cybedefend results --project-id <ID> --branch main
cybedefend results --project-id <ID> -b feature/my-branch -o sarif -f results.sarif
```

---

## Bug Fixes

- **Vulnerabilities returned with empty fields** — Running `cybedefend results` after a successful scan could return a JSON file where all vulnerability fields (`name`, `description`, `severity`, `path`, etc.) were empty, even though the `total` count was correct. All fields are now populated correctly.
- **SCA vulnerabilities missing from all reports** — SCA findings were not shown in any output format (HTML, SARIF, Markdown, JSON). All SCA vulnerabilities, including package name, version, advisory description, severity, and remediation advice, are now correctly included.
- **SARIF — rule names instead of IDs** — The SARIF output now uses human-readable rule names, making it compatible with GitHub Code Scanning and standard SARIF viewers.
- **HTML report overflowing to the right** — Long advisory descriptions and URLs no longer cause the report to overflow horizontally.
- **HTML report — raw Markdown in descriptions** — Headings, links, lists, and code blocks inside vulnerability descriptions are now rendered as formatted HTML instead of being shown as raw Markdown syntax.
- **Output file written to wrong location** — Using a relative path with `-f` (e.g. `-f report.html`) now correctly resolves to the current working directory.
- **Access denied — clearer error message** — When the CLI encounters a permissions error on a project, it now stops immediately and displays: `Access denied to project <ID>. Make sure you have access to this project.`
- **Banner display on some terminals** — The CLI banner is now rendered correctly on terminals that do not support 24-bit colour.
