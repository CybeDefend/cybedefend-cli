# Release v2.0.3

Version v2.0.3 — August 14, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: `ghcr.io/CybeDefend/cybedefend-cli:v2.0.3`

This release fixes authentication. Two independent bugs both surfaced as the same opaque `invalid_grant` error after a login that had reported success. No re-login and no migration are required to upgrade.

---

## Bug Fixes

### A leftover `pat` made `cybedefend login` a no-op

A `pat:` left in `config.yaml`, or exported as `$CYBEDEFEND_PAT`, was read **before** the credentials written by `cybedefend login`. A successful login therefore had no effect on the next command: the stale token was sent instead, and every command failed with `invalid_grant`. Since the `--pat` flag wins at login time, the login itself still reported success — which made the failure hard to trace back to the config file.

Credentials are now resolved in this order:

1. an explicit `--pat` flag on the command line;
2. the credentials written by `cybedefend login`;
3. `CYBEDEFEND_PAT`, or `pat:` in the config file (deprecated).

When both 2 and 3 are set, the login credentials are used and the CLI reports the ambiguity instead of silently picking one:

```
a PAT is set in the config file or in $CYBEDEFEND_PAT, and credentials from `cybedefend login`
also exist. The login credentials are used. Remove one of the two to lift the ambiguity.
```

---

### Self-hosted, on-premise and local logins were retargeted to production US

`login` stored a two-value region enum derived from a literal string comparison against the EU production auth endpoint. Any other endpoint — self-hosted, on-premise, local — was recorded as `us`, and the next command rebuilt every endpoint from that single field, ignoring `api_url` / `auth_endpoint` coming from both the config file and the flags. The result was the same opaque `invalid_grant`.

`login` now persists the endpoints it actually used — `api_url`, `auth_endpoint`, `client_id`, `api_resource` — and later commands reuse them verbatim. A login against a self-hosted instance stays on that instance.

Existing `~/.cybedefend/credentials.json` files written by CLI ≤ v2.0.2 keep resolving through their `region` field, so **no migration and no re-login are needed**.

---

### `login` against an unrecognised auth endpoint no longer silently defaults to `us`

When the region cannot be inferred from the auth endpoint and no `--region` was passed, `login` now fails with an actionable message and writes nothing, instead of recording `us` and producing a broken credentials file:

```
cannot infer the region from auth endpoint "https://auth.example.internal".
Pass --region explicitly (us or eu)
```

---

### OAuth token refresh dropped the stored endpoints

Refreshing an expired OAuth access token rebuilt `credentials.json` from the region alone, discarding the endpoints captured at login time and silently retargeting the CLI mid-session. The refresh now updates the stored file in place.

---

### Ignored flags are reported instead of silently discarded

`--api-url` and `--region` cannot override the endpoints pinned by stored credentials. Rather than being dropped without a word, they are now reported:

```
--region us is ignored: the credentials stored by `cybedefend login` are for region eu.
Run `cybedefend logout` then log in again to switch region.
```

A `credentials.json` that cannot be read is also reported now, instead of being swallowed into an authentication error further down the line. `cybedefend --debug <command>` prints the credential source and the endpoints actually in use.

---

## What's New

### Test suite — `make test`

The repository now has a test suite: `make test` (`scripts/test.sh`) runs `go test ./...`. A new **Test** workflow runs `gofmt`, `go vet`, the build and the tests on every push and pull request with read-only repository permissions, and the release workflow now runs the tests before building the binaries.

### Container image scanning is documented

The README now covers `cybedefend container scan`: the supported registries (GitLab, GitHub/GHCR, DockerHub, GCR, ECR, ACR, Quay, Harbor, JFrog), every flag, which registries require a `--credential-id`, and usage examples. The command itself is unchanged — this is documentation only.

### Authentication section in the README

The README documents the credential precedence, where credentials are stored, and why `--api-url` / `--region` are ignored once logged in.

---

## Deprecations

- **`pat:` in `config.yaml` is deprecated** and will be removed in a future release: the config file is world-readable (`0644`), unlike `~/.cybedefend/credentials.json` which is written `0600`. Use `cybedefend login --pat <PAT>` instead, and revoke any PAT that was left in a config file. A `pat:` still works for now — but only when no `cybedefend login` credentials exist — and the CLI prints a deprecation warning.

---

## Upgrade Notes

Upgrading is a drop-in replacement: stored credentials stay valid and no re-login is required.

If a `pat:` in your `config.yaml` (or a `$CYBEDEFEND_PAT`) was previously masking your login credentials, v2.0.3 will start using the login credentials and warn about the duplicate. Remove the `pat:` from the config file — and revoke that PAT, since it was sitting in a world-readable file.
