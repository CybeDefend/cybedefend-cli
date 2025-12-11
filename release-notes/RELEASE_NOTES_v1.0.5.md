# Release v1.0.5 — Pre-release

Version v1.0.5 — August 12, 2025

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v1.0.5

## New Features
- Two-step scan initiation with support for pre-signed uploads (GCS and OVH S3).
- Region selection: new `--region` flag and `CYBEDEFEND_REGION` env (`us`/`eu`).

## Improvements
- Default API endpoint set to `https://api-us.cybedefend.com` (easy switch to EU via region).
- Clear URL precedence: `--api-url` > `CYBEDEFEND_API_URL` > config `api_url` > derived from region.
- Safer logs: signed upload URLs are masked to avoid leaking query parameters.

## Documentation
- README updated for region selection and new default API URL.

## Upgrade Notes
- No breaking changes expected.
- If you specify a custom API URL, it still overrides the selected region.
