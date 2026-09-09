# Release v2.1.0

Version v2.1.0 — September 9, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.1.0`

Three filters and gates that were silently doing nothing now do what they say: `--break-on-severity` blocks a build, the `results` status filter reaches the API, and every `report` command writes an actual report. Upgrade if you gate a pipeline on this CLI.

---

## Bug Fixes

### `--break-on-severity` never blocked a build

The severity gate read `currentSeverity` and `currentState` at the top level of a response that nests them under `base`. The type assertion matched nothing, every finding was skipped, and the counts came back empty — so the gate reported a clean build. In the same run, on the same scan, the policy evaluation was blocking:

```
[SUCCESS] No vulnerabilities found at or above CRITICAL severity
[ERROR]   🚫 BLOCKING VIOLATIONS (1)
[ERROR]     • [Block Critical Vulnerabilities] Affected vulnerabilities: 13
```

Counted correctly, that branch had **17** critical findings. A gate that fails open is worse than no gate, because a pipeline is built to trust it.

Two further defects in the same path:

- The scan type was hard-coded to `sast`, so a critical CVE in a dependency, a leaked secret or an IaC misconfiguration never blocked a build.
- Only the first page of results was read, with no page size and no branch filter — 10 findings out of 52, counted across every branch rather than the one just scanned.

The gate now decodes through the same typed path the `results` command uses, covers every scan type, walks all pages and filters on the branch that was scanned. A scan type outside your plan answers `403` and is skipped; any other error still fails **closed**.

If a pipeline of yours has been passing on `--break-on-severity`, expect it to start failing on findings that were always there.

### The `results` status filter never reached the API

The filter was sent with a bracketed query key (`status[]`), which the gateway keeps verbatim, so it matched nothing and **every state was exported** — including findings already marked `ignored` or `resolved`. The filter is now sent as repeated keys (`status=a&status=b`), on both the flat and the grouped endpoints.

Severity and priority are no longer sent as filters at all. The CLI used to list every accepted level as a way of saying "no restriction", but the API only accepts the *rated* levels as filter values, so what looked like a no-op was quietly dropping findings without a rating — an SCA advisory with no CVSS score, for instance.

### Every report command wrote an empty file and called it a success

The report endpoints no longer return a report. They enqueue one and answer with a job, and the report is fetched once that job is ready. The CLI wrote the job envelope to the output file:

| command | before | after |
|---|---|---|
| `report owasp --format json` | 205 bytes of envelope | 343 KB |
| `report owasp --format html` | 205 bytes of *JSON* in a `.html` | 192 KB |
| `report org` | 285 bytes | 4.0 MB |
| `report team` | 277 bytes | 933 KB |
| `report batch` | **0 bytes**, reported as a success | 353 KB |

`report batch` produced nothing at all. This is the same failure mode the v2.0.4 notes recorded for SARIF: a file a downstream consumer cannot use, delivered as if it were fine.

The CLI now waits for the report and downloads it. A report that cannot be produced is an error rather than an empty file, and a report with **zero findings** is unaffected — it is a valid document, not an empty one.

Deployments that still answer synchronously, and the older inline envelope, both keep working.

---

## New Features

### `--status` on `results`

Pick which triage states to export, instead of taking whatever the API defaults to:

```bash
cybedefend results --status confirmed
cybedefend results --status to_verify,confirmed,ignored
```

The default is `to_verify,confirmed`. Values are trimmed, lower-cased, de-duplicated and validated against the states the API accepts, so a typo is refused before the call rather than silently widening the export.

Every finding now carries `currentState` in the output, so an exported file says for itself which states it contains.

### Input validation across every command

Flags, environment variables and the config file are now checked against a declared schema before anything is sent. Every rejected flag is reported at once, named as you typed it:

```
$ cybedefend results --project-id "../admin" --type bogus
[ERROR] invalid --project-id: "../admin" is not a valid identifier (letters, digits, '.', '_' and '-' only); invalid --type: "bogus" (allowed: sast, sca, iac, secret, cicd, container, all)
```

Identifiers are the ones that matter: they are interpolated into API paths, so a value carrying `/`, `?`, `#` or `%` could aim a request somewhere other than where the command reads. Every id the platform issues is a UUID, so nothing legitimate is refused.

Output paths stay permissive on purpose — `--filepath ../artifacts` and absolute paths keep working, because that is how a CI job says where to put its artifacts.

### `--timeout` on the report commands

Reports are generated asynchronously, so `report` now waits, up to `--timeout` seconds (default `300`). The job outlives the wait: a timeout tells you where to find the report rather than implying it was lost.

The output filename now defaults to the one the API suggests, which carries the right extension for the requested format.

---

## Build

### The project now builds on Go 1.26

Input validation brought in `go-playground/validator`, which pulls `golang.org/x/crypto`. On Go 1.22 no patched version of it was reachable — every release that fixes the known advisories requires Go 1.25 or later — so the build moved forward rather than shipping a dependency that could not be updated.

- `go.mod`, both CI workflows and the Docker base image are now on **Go 1.26**.
- `golang.org/x/crypto` is on **v0.56.0**, clearing every open advisory against it.
- `golang.org/x/net` is gone entirely: `mimetype` v1.4.15 no longer needs it.

This only concerns you if you build from source — the precompiled binaries and the Docker image are unaffected. Go 1.26's stricter `vet` also surfaced a handful of non-constant format strings, now fixed; one of them meant a policy message containing a `%` could be mangled in the GitHub step summary.

### A `.dockerignore` now guards the build context

The `Dockerfile` copies the working directory with `COPY . .`, and Docker copies what is on disk rather than what git tracks. Published images were never affected — CI builds from a clean checkout — but a local `docker build .` on a maintainer's machine baked in `private-key.asc`, the GPG signing key, along with the local `config.yml` and the full `.git` history. The build context is now filtered.

---

## Upgrade Notes

Drop-in replacement: no configuration change, no migration, no re-login. Building from source now requires **Go 1.26**.

Four behaviours change on purpose, and each can surface something that was previously silent:

- A pipeline using `--break-on-severity` will now fail on findings the gate had been ignoring, including non-SAST ones.
- `results` exports fewer findings than before, because the status filter now applies. Pass `--status` to widen it.
- `results` output gains a `currentState` field on every finding.
- A `report` command now exits non-zero instead of writing an empty file.

`--interval` and `--policy-timeout` must be at least `1`; `--break-on-severity none` remains the explicit way to disable the gate.
