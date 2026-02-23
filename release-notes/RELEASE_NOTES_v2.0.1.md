# Release v2.0.1

Version v2.0.1 — February 23, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v2.0.1

## New Features

### Authentication — `cybedefend login` & `cybedefend logout` 🔐

The CLI now supports persistent authentication, removing the need to pass credentials on every command. Two authentication modes are available: **OAuth browser flow** and **Personal Access Token (PAT)**.

---

#### OAuth Browser Flow (recommended for interactive use)

```bash
cybedefend login --region eu
```

Launches a secure OAuth Authorization Code + PKCE flow in your browser:

1. The CLI opens `https://auth-eu.cybedefend.com` (or US equivalent) in your default browser
2. You log in with your CybeDefend account
3. On success, the browser displays a confirmation page and the CLI stores your session automatically

Credentials (access token + refresh token) are saved to `~/.cybedefend/credentials.json` (mode `0600`).  
Access tokens are **automatically refreshed** when they expire — no need to re-login.

---

#### PAT-Based Login (recommended for CI/CD and scripted environments)

```bash
cybedefend login --pat <your-pat> --region eu
```

Validates the PAT against the API and stores it locally. Subsequent commands will use it automatically without requiring `--pat` on every call.

```bash
# Before: every command required explicit credentials
cybedefend scan --dir . --pat <your-pat> --region eu

# After: credentials are stored once
cybedefend login --pat <your-pat> --region eu
cybedefend scan --dir .
cybedefend results --project-id <id>
```

---

#### Logout

```bash
cybedefend logout
```

Deletes `~/.cybedefend/credentials.json` and clears the stored session.

---

### Credential Priority Order

When running any command, credentials are resolved in the following order:

1. `--pat` flag (explicit, highest priority)
2. `CYBEDEFEND_PAT` environment variable
3. `pat` field in config file (`config.yml`)
4. Stored credentials from `cybedefend login` (PAT or OAuth)

---

### Automatic Region Detection

Once logged in, the `--region` flag is **no longer required** on subsequent commands. The region is read from the stored credentials and applied automatically.

```bash
cybedefend login --pat <your-pat> --region eu

# No --region needed from now on
cybedefend scan --dir .
cybedefend results --project-id <id>
```

---

### Styled OAuth Callback Page

The OAuth callback page (`http://localhost:9877/callback`) now displays a branded confirmation screen matching the CybeDefend design — dark background, white card, logo, and a clear success or error state.

---

## Technical Notes

- Credentials are stored at `~/.cybedefend/credentials.json` with permissions `0600`
- OAuth tokens use the **PKCE** (Proof Key for Code Exchange) security extension
- Refresh tokens are requested via `prompt=consent` and persisted automatically after each refresh
- OAuth callback server runs locally on port `9877` with a 5-minute timeout
- Client IDs are fetched dynamically from `{apiURL}/client-apps` at runtime, with hardcoded fallback values for offline resilience
