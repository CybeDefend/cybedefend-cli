# Release v1.0.6

Version v1.0.6 — December 11, 2025

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v1.0.6

## New Features
- **Upload Progress Tracking**: Real-time upload progress indicator showing percentage (0%, 10%, 20%... 100%) with file size display
- **Upload Status Messages**: Clear feedback with "Uploading file (X.XX MB)..." at start and "Upload completed successfully" at end

## Improvements
- **Fixed Upload Compatibility**: `Content-Type: application/zip` header now set for all storage backends (GCS, OVH S3, AWS S3, etc.), not just Google Cloud Storage
- **Code Quality Improvements**:
  - Eliminated duplicate string literals by introducing API URL constants (`APIURLUs` and `APIURLEu`)
  - Reduced cognitive complexity in `GetVulnerabilitiesBySeverity` function by extracting helper functions
  - Reduced cognitive complexity in scan command by refactoring into smaller, focused functions
- **Better User Experience**: Users can now track upload progress instead of waiting blindly during file transfer

## Bug Fixes
- Fixed upload failures to non-GCS storage backends (OVH S3, AWS S3) due to missing Content-Type header
- Upload now works correctly with localhost development environments

## Code Refactoring
- Introduced `buildVulnerabilitiesURL` helper function for URL construction
- Introduced `countVulnerabilitiesBySeverity` helper function for cleaner vulnerability counting
- Split scan command logic into focused functions: `validateScanRequirements`, `prepareZipFile`, `validateBreakOnSeverity`, `executeScan`, `handleScanCompletion`, `handleBreakOnSeverity`
- Added `progressReader` struct to track and display upload progress

## Documentation
- No documentation changes in this release

## Upgrade Notes
- No breaking changes
- Upload behavior is enhanced but remains backward compatible
- Users will now see upload progress indicators during file transfer

## Technical Details
- Upload progress is displayed in 10% increments to avoid excessive logging
- Progress tracking works with files of any size
- Compatible with all S3-compatible storage backends
