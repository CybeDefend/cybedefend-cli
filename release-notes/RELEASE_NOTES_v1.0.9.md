# Release v1.0.9

Version v1.0.9 — January 29, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v1.0.9

## New Features

### Policy Evaluation & Break Build System
The CLI now integrates with CybeDefend's Policy Evaluation system to enforce security policies and break builds based on policy violations.

- **Automatic Policy Check**: After a scan completes, the CLI automatically evaluates security policies configured for your project
- **BLOCK/WARN Actions**: Policies can be configured to either BLOCK (exit code 1) or WARN (informational only)
- **Acknowledged Violations**: Violations that have been acknowledged in the platform are displayed but don't block the build
- **Affected Vulnerabilities Display**: See the specific vulnerabilities that triggered each policy violation with direct links to the CybeDefend platform

#### New Flags for Policy Evaluation

- `--policy-check`: Enable/disable policy evaluation after scan (Default: `true`)
- `--policy-timeout`: Timeout in seconds for policy evaluation (Default: `300`)
- `--show-policy-vulns`: Show affected vulnerabilities in policy evaluation output (Default: `true`)
- `--show-all-policy-vulns`: Show all affected vulnerabilities without limit (Default: `false`, shows max 5 per violation)

### Branch Configuration Support
You can now specify the branch in your `config.yaml` file instead of always passing it via command-line flag.

```yaml
# config.yaml
api_key: "your-api-key"
project_id: "your-project-id"
branch: "main"
```

The priority order is:
1. Command-line flag `--branch` / `-b`
2. Configuration file (`branch:` in config.yaml)
3. Default value (`main`)

## Usage

### Policy Evaluation

```bash
# Run scan with policy evaluation (enabled by default)
cybedefend scan --dir ./my-project --ci

# Disable policy evaluation
cybedefend scan --dir ./my-project --policy-check=false

# Show all vulnerabilities for each violation (no limit)
cybedefend scan --dir ./my-project --show-all-policy-vulns

# Hide vulnerability details in policy output
cybedefend scan --dir ./my-project --show-policy-vulns=false

# Set custom timeout for policy evaluation
cybedefend scan --dir ./my-project --policy-timeout 600
```

### Example Output

```
✓ Scan completed successfully
ℹ Checking policy evaluation status...
✓ Policy evaluation completed
ℹ Policy violations found: 2 BLOCK, 1 WARN

⛔ BLOCK Actions:
  ✗ No Critical Vulnerabilities (BLOCK)
    Affected: 3 vulnerabilities
      → [CRITICAL] SQL Injection - src/api/users.ts (L45-48)
        https://us.cybedefend.com/project/xxx/sast/issue/yyy
      → [CRITICAL] Path Traversal - src/utils/file.ts (L12)
        https://us.cybedefend.com/project/xxx/sast/issue/zzz

⚠️ WARN Actions:
  ⚠ Dependency Check (WARN)
    Affected: 1 vulnerability
      → [HIGH] Prototype Pollution - lodash@4.17.15
        https://us.cybedefend.com/project/xxx/sca/issue/aaa

✓ Acknowledged Violations (not blocking):
  ⚠ No High Vulnerabilities (BLOCK)
    ✓ Acknowledged: Risk accepted for legacy code
```

## Improvements

- Policy evaluation polls the `/evaluation-status` endpoint until completion before fetching violations
- Pagination support for fetching all policy violations
- Region-aware URL generation for vulnerability links (us.cybedefend.com / eu.cybedefend.com)
- Support for custom `app_url` in configuration for self-hosted deployments

## Bug Fixes

- Fixed URL generation for vulnerability links when vulnerability type was missing
- Fixed branch configuration not being read from config.yaml

## Documentation

- Updated README.md with policy evaluation documentation and examples
- Added new flags documentation for policy-related options
- Updated configuration file examples with branch support

## Upgrade Notes

- No breaking changes
- Policy evaluation is enabled by default; use `--policy-check=false` to disable
- Existing workflows will continue to work without modification
- The exit code behavior changes: if any policy has a BLOCK action with violations, the CLI will exit with code 1

## Technical Details

- Policy evaluation uses two endpoints:
  - `GET /projects/:projectId/scans/:scanId/evaluation-status` - Poll until COMPLETED/FAILED
  - `GET /projects/:projectId/scans/:scanId/violations` - Fetch violations with pagination
- Acknowledged violations are tracked via the `isAcknowledged` field and don't affect exit code
- Vulnerability links are constructed based on `region` config or `app_url` override
