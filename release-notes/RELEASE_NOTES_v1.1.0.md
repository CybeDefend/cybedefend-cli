# Release v1.1.0

Version v1.1.0 — February 23, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v1.1.0

---

## ⚠️ Breaking Change — API Key Authentication Removed

API key authentication (`--api-key` / `CYBEDEFEND_API_KEY` / `api_key:` in config) is **permanently deprecated** and no longer functional. The CybeDefend API now rejects API keys with **HTTP 410 Gone**.

If you attempt to use any of the old authentication methods, the CLI will output a clear error message and exit immediately with instructions on how to migrate.

---

## What Changed

### Authentication: API Key → Personal Access Token (PAT)

Authentication now uses **Personal Access Tokens (PATs)** managed through Logto IAM. A PAT is exchanged for a short-lived `Bearer` access token (TTL: 600 s) automatically by the CLI — no manual token management required.

#### How token exchange works

1. You create a PAT once in your account settings.
2. Before every API call the CLI silently exchanges the PAT for a short-lived access token via `POST {logto_endpoint}/oidc/token`.
3. The access token is cached in memory with a 30 s safety margin and refreshed automatically when it expires.
4. All API requests now carry `Authorization: Bearer <access_token>` instead of `x-api-key`.

---

## Migration Guide

### 1. Create a Personal Access Token

| Region | URL |
|--------|-----|
| EU | https://eu.cybedefend.com/profile/personal-access-tokens |
| US | https://us.cybedefend.com/profile/personal-access-tokens |

### 2. Update your config file

**Before (`~/.cybedefend/config.yaml`):**
```yaml
api_key: "your-old-api-key"
api_url: "https://api-eu.cybedefend.com"
project_id: "proj_xxx"
```

**After:**
```yaml
pat: "pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
region: "eu"   # or "us" — sets api_url and logto_endpoint automatically
project_id: "proj_xxx"
```

### 3. Update environment variables

| Old | New |
|-----|-----|
| `CYBEDEFEND_API_KEY` | `CYBEDEFEND_PAT` |

### 4. Update CLI flags

| Old | New |
|-----|-----|
| `--api-key <key>` | `--pat <pat>` |

### 5. Update CI/CD pipelines

**GitHub Actions — before:**
```yaml
- name: Run security scan
  run: cybedefend scan --dir ./ --ci --api-key ${{ secrets.CYBEDEFEND_API_KEY }} --project-id ${{ secrets.CYBEDEFEND_PROJECT_ID }} --region ${{ vars.CYBEDEFEND_REGION }} --branch ${{ github.ref_name }}
```

**GitHub Actions — after:**
```yaml
- name: Run security scan
  run: cybedefend scan --dir ./ --ci --pat ${{ secrets.CYBEDEFEND_PAT }} --project-id ${{ secrets.CYBEDEFEND_PROJECT_ID }} --region ${{ vars.CYBEDEFEND_REGION }} --branch ${{ github.ref_name }}
```

**GitLab CI — before:**
```yaml
- cybedefend scan --dir . --ci --api-key "${CYBEDEFEND_API_KEY}" --project-id "${CYBEDEFEND_PROJECT_ID}" --region "${CYBEDEFEND_REGION}" --branch "${CI_COMMIT_BRANCH}"
```

**GitLab CI — after:**
```yaml
- cybedefend scan --dir . --ci --pat "${CYBEDEFEND_PAT}" --project-id "${CYBEDEFEND_PROJECT_ID}" --region "${CYBEDEFEND_REGION}" --branch "${CI_COMMIT_BRANCH}"
```

Rename your CI/CD secret from `CYBEDEFEND_API_KEY` to `CYBEDEFEND_PAT` and store the PAT value.

---

## New Flags

| Flag | Description |
|------|-------------|
| `--pat` | Personal Access Token for authentication |
| `--logto-endpoint` | Override the Logto auth endpoint (optional, derived from `--region` by default) |
| `--logto-client-id` | Override the Logto application client ID (optional) |

### Region-aware Logto endpoints (automatic)

| Region | Logto Endpoint |
|--------|---------------|
| `us` (default) | `https://auth-us.cybedefend.com` |
| `eu` | `https://auth-eu.cybedefend.com` |

---

## Error Messages

The CLI now provides actionable, specific authentication errors:

| Situation | Error |
|-----------|-------|
| `--api-key` / `CYBEDEFEND_API_KEY` / `api_key:` detected | Deprecation error with region-specific PAT creation link, CLI exits immediately |
| PAT is empty | `"authentication required: provide a PAT via --pat flag, CYBEDEFEND_PAT env variable, or pat field in config file."` |
| PAT invalid or revoked (401/403) | `"PAT authentication failed: the token may be invalid or revoked. Generate a new PAT from Account Settings."` |
| Token exchange disabled on app (400 `token_exchange_not_allowed`) | `"Token exchange is not enabled for this application. Contact CybeDefend support."` |

---

## Files Changed

| File | Change |
|------|--------|
| `pkg/utils/config.go` | `APIKey` → `PAT`, added `LogtoEndpoint` / `LogtoClientID`, region-aware Logto defaults |
| `pkg/api/client.go` | Full rewrite — token-exchange client with in-memory caching |
| `pkg/api/scan.go` | `x-api-key` → `Authorization: Bearer` |
| `pkg/api/results.go` | `x-api-key` → `Authorization: Bearer` |
| `pkg/api/policy.go` | `x-api-key` → `Authorization: Bearer` |
| `cmd/root.go` | `--api-key` deprecated (hidden, triggers hard stop), new `--pat` / `--logto-endpoint` / `--logto-client-id` flags |
| `cmd/scan.go` | Uses `pat` from viper, updated validation error messages |
| `cmd/results.go` | Uses `pat` from viper, updated validation error messages |
| `README.md` | All auth references updated, migration guide added |
