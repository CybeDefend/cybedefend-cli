# Release v1.0.8

Version v1.0.8 — December 30, 2025

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v1.0.8

## New Features
- **Branch Support for Scans**: You can now specify a branch name when starting a scan using the `--branch` (or `-b`) flag. This allows you to associate scans with specific Git branches (e.g., `main`, `develop`, `feature/my-feature`) for better organization and tracking of vulnerabilities across different branches of your codebase.

## Usage

```bash
# Scan a directory with a specific branch
cybedefend scan --dir ./my-project --branch main

# Scan with branch in CI/CD pipeline
cybedefend scan --dir ./ --ci --branch $CI_COMMIT_BRANCH
```

## Improvements
- The `POST /project/{projectId}/scan/start` endpoint now accepts a JSON body with the `branch` field
- Added `-b` shorthand for the `--branch` flag for convenience

## Bug Fixes
- No bug fixes in this release

## Documentation
- Updated README.md with branch flag documentation and examples
- Added examples for GitHub Actions and GitLab CI integration with branch support

## Upgrade Notes
- No breaking changes
- The `--branch` flag is optional; existing workflows will continue to work without modification
- If no branch is specified, the scan will proceed without branch association (backward compatible)

## Technical Details
- Branch name is sent in the request body as JSON: `{"branch": "branch-name"}`
- The Content-Type header is set to `application/json` when a branch is provided
