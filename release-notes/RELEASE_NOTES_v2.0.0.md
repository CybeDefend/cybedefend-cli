# Release v2.0.0

Version v2.0.0 — February 23, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v2.0.0

---

## ⚠️ Breaking Change — API Key Authentication Removed

API key authentication (`--api-key` / `CYBEDEFEND_API_KEY` / `api_key:` in config) is **permanently deprecated** and no longer functional. The CybeDefend API now rejects API keys with **HTTP 410 Gone**.

Authentication now uses **Personal Access Tokens (PATs)** managed through Logto IAM. A PAT is exchanged for a short-lived `Bearer` access token (TTL: 600 s) automatically by the CLI — no manual token management required.

If you are upgrading from v1.0.x, see the [Migration Guide](#migration-guide) below.

---

## Highlights

**CybeDefend CLI v2** is a major feature release that adds **30+ new commands** covering project management, team operations, security overviews, compliance monitoring, report generation, and container image scanning — all from the command line.

The existing `scan` and `results` commands remain unchanged. All new commands use PAT-based authentication.

---

## New Commands

### 🗂️ Project Management (`project`)

Manage CybeDefend projects directly from the CLI.

| Command | Description |
|---------|-------------|
| `cybedefend project create` | Create a new project under a team |
| `cybedefend project get` | Get project details |
| `cybedefend project delete` | Delete a project |

**Example:**
```bash
cybedefend project create --name "my-app" --team-id <TEAM_ID> --pat <PAT> --region eu
cybedefend project get --project-id <PROJECT_ID> --pat <PAT> --region eu
cybedefend project delete --project-id <PROJECT_ID> --pat <PAT> --region eu
```

---

### 👥 Team Management (`team`)

Full CRUD for teams and team membership.

| Command | Description |
|---------|-------------|
| `cybedefend team create` | Create a new team |
| `cybedefend team get` | Get team details |
| `cybedefend team list` | List all teams in an organization |
| `cybedefend team update` | Update a team's name/description |
| `cybedefend team delete` | Delete a team |
| `cybedefend team members` | List team members |
| `cybedefend team add-member` | Add a member to a team |
| `cybedefend team update-member` | Update a member's role |
| `cybedefend team remove-member` | Remove a member from a team |

**Example:**
```bash
cybedefend team list --organization-id <ORG_ID> --pat <PAT> --region eu
cybedefend team create --name "Backend" --description "Backend team" --organization-id <ORG_ID> --pat <PAT> --region eu
cybedefend team add-member --team-id <TEAM_ID> --email user@company.com --role member --pat <PAT> --region eu
```

---

### 📊 Security Overviews (`overview`)

Get aggregated security dashboards at project or organization level.

| Command | Description |
|---------|-------------|
| `cybedefend overview project` | Project security overview (severity counts, trends, analysis type distribution) |
| `cybedefend overview org` | Organization-wide security overview |

**Example:**
```bash
cybedefend overview project --project-id <PROJECT_ID> --pat <PAT> --region eu
cybedefend overview org --organization-id <ORG_ID> --pat <PAT> --region eu
```

The project overview supports optional `--branches` flag to filter by specific branches.

---

### 📋 Reports (`report`)

Generate and download security reports in **JSON**, **HTML**, or **PDF** formats.

| Command | Description |
|---------|-------------|
| `cybedefend report sbom` | Download SBOM report (JSON) |
| `cybedefend report owasp` | Generate OWASP Top 10 report |
| `cybedefend report cwe` | Generate CWE Top 25 report |
| `cybedefend report org` | Aggregated report for an organization |
| `cybedefend report team` | Aggregated report for a team |
| `cybedefend report batch` | Report for a custom selection of projects |

**Supported formats:** `json`, `html`, `pdf`

**Example:**
```bash
# SBOM
cybedefend report sbom --project-id <PROJECT_ID> --pat <PAT> --region eu

# OWASP PDF report
cybedefend report owasp --project-id <PROJECT_ID> --format pdf --output report.pdf --pat <PAT> --region eu

# Organization-wide CWE report
cybedefend report org --organization-id <ORG_ID> --type cwe --format json --pat <PAT> --region eu

# Batch report for selected projects
cybedefend report batch --organization-id <ORG_ID> --project-ids <ID1>,<ID2> --type owasp --format json --pat <PAT> --region eu
```

All report commands accept `--output` to specify the output file path. If omitted, a default filename is generated automatically.

---

### ✅ Compliance (`compliance`)

Monitor policy compliance and violations.

| Command | Description |
|---------|-------------|
| `cybedefend compliance history` | View compliance history for a project |
| `cybedefend compliance violations` | List policy violations with pagination |
| `cybedefend compliance stats` | Get violation statistics breakdown |

**Example:**
```bash
cybedefend compliance history --project-id <PROJECT_ID> --pat <PAT> --region eu
cybedefend compliance violations --project-id <PROJECT_ID> --branch main --page 1 --limit 50 --pat <PAT> --region eu
cybedefend compliance stats --project-id <PROJECT_ID> --pat <PAT> --region eu
```

---

### 🐳 Container Scanning (`container`)

Scan container images from **9 supported registries**.

| Command | Registry |
|---------|----------|
| `cybedefend container scan gitlab` | GitLab Container Registry |
| `cybedefend container scan github` | GitHub Container Registry (GHCR) |
| `cybedefend container scan dockerhub` | DockerHub |
| `cybedefend container scan gcr` | Google Container Registry (GCR) |
| `cybedefend container scan ecr` | Amazon Elastic Container Registry (ECR) |
| `cybedefend container scan acr` | Azure Container Registry (ACR) |
| `cybedefend container scan quay` | Quay.io |
| `cybedefend container scan harbor` | Harbor |
| `cybedefend container scan jfrog` | JFrog Artifactory |

Each registry command accepts registry-specific credentials (username, password/token) and an image name with tag.

**Example:**
```bash
cybedefend container scan dockerhub \
  --project-id <PROJECT_ID> \
  --username myuser \
  --password mytoken \
  --image myorg/myimage:latest \
  --pat <PAT> --region eu
```

---

## Full Command Reference

```
cybedefend
├── scan                  (existing — start a security scan)
├── results               (existing — get scan results)
├── version               (existing — show CLI version)
├── project
│   ├── create
│   ├── get
│   └── delete
├── team
│   ├── create
│   ├── get
│   ├── list
│   ├── update
│   ├── delete
│   ├── members
│   ├── add-member
│   ├── update-member
│   └── remove-member
├── overview
│   ├── project
│   └── org
├── report
│   ├── sbom
│   ├── owasp
│   ├── cwe
│   ├── org
│   ├── team
│   └── batch
├── compliance
│   ├── history
│   ├── violations
│   └── stats
└── container
    └── scan
        ├── gitlab
        ├── github
        ├── dockerhub
        ├── gcr
        ├── ecr
        ├── acr
        ├── quay
        ├── harbor
        └── jfrog
```

---

## Global Flags

All commands support these flags:

| Flag | Description | Default |
|------|-------------|---------|
| `--pat` | Personal Access Token | — |
| `--region` | Platform region (`us` or `eu`) | `us` |
| `--ci` | CI mode (non-interactive output) | `false` |
| `--debug` | Enable debug logging | `false` |
| `--config` | Path to config file | `$HOME/.cybedefend/config.yaml` |
| `--api-url` | Override API URL | derived from region |
| `--logto-endpoint` | Override Logto endpoint | derived from region |

---

## Upgrade

```bash
# Homebrew
brew upgrade cybedefend

# Or download the latest binary from:
# https://github.com/CybeDefend/cybedefend-cli/releases/tag/v2.0.0
```

No configuration changes required from v1.1.0. The same PAT and config file work with all new commands.

---

## Migration Guide

If you are upgrading from **v1.0.x** (API key authentication), follow these steps:

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

| Before | After |
|--------|-------|
| `CYBEDEFEND_API_KEY` | `CYBEDEFEND_PAT` |
| `CYBEDEFEND_API_URL` | `CYBEDEFEND_REGION` (`eu` or `us`) |

### 4. Update CI pipelines

```yaml
# Before
env:
  CYBEDEFEND_API_KEY: ${{ secrets.CYBEDEFEND_API_KEY }}

# After
env:
  CYBEDEFEND_PAT: ${{ secrets.CYBEDEFEND_PAT }}
  CYBEDEFEND_REGION: "eu"
```

Or pass flags directly:
```bash
cybedefend scan --pat $PAT --region eu --ci
```
