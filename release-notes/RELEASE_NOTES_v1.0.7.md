# Release v1.0.7

Version v1.0.7 — December 17, 2025

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v1.0.7

## Bug Fixes
- **Fixed panic on nil severity**: Resolved a critical panic that occurred when processing vulnerabilities with missing or null `currentSeverity` field. The application now safely handles vulnerabilities where the severity is not set, skipping them instead of crashing.

## Technical Details
- Added safe type assertion with `ok` pattern for `currentSeverity` field in `countVulnerabilitiesBySeverity` function
- Vulnerabilities with missing or empty severity values are now gracefully skipped during counting

## Upgrade Notes
- No breaking changes
- Recommended upgrade for all users experiencing crashes during scan result processing
- Backward compatible with all existing configurations
