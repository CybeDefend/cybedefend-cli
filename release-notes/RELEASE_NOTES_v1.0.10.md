# Release v1.0.10

Version v1.0.10 — February 2, 2026

- Built for multiple platforms
- Precompiled binaries included
- Docker image available at: ghcr.io/CybeDefend/cybedefend-cli:v1.0.10

## New Features

### GitHub Actions Step Summary Integration 🎉

The CLI now automatically generates beautiful, interactive markdown summaries in GitHub Actions when running in CI mode (`--ci` flag). This provides immediate visibility into scan results, policy violations, and vulnerabilities directly in your GitHub Actions workflow summary.

#### Features

- **Automatic Detection**: Detects `GITHUB_STEP_SUMMARY` environment variable and activates only in CI mode
- **Comprehensive Scan Report**: Displays scan ID, project ID, branch, and timestamp in a clean table format
- **Visual Scan Status**: Shows scan completion status with emojis (✅ success, ❌ failed, 🔄 running)
- **Vulnerability Breakdown**: Table showing count by severity (Critical 🔴, High 🟠, Medium 🟡, Low 🟢)
- **Policy Evaluation Summary**: Detailed breakdown of violations by type (🚫 Blocking, ⚠️ Warnings, ✅ Acknowledged)
- **Collapsible Sections**: Uses `<details>` tags for vulnerability details to keep the summary clean and scannable
- **Direct Links**: Every vulnerability includes a clickable link to view it in the CybeDefend platform
- **Severity Indicators**: Color-coded emojis for easy visual scanning
- **Final Status**: Clear ✅ PASSED or ❌ FAILED status with explanation

#### Summary Sections Generated

1. **🔒 CybeDefend Security Scan Report**
   - Metadata table with Scan ID, Project ID, Branch, and Timestamp

2. **Scan Status** (✅/❌/🔄)
   - Completion status (completed/failed/running)
   - Total vulnerabilities detected

3. **📊 Vulnerability Summary** (when applicable)
   - Breakdown by severity with counts
   - Total vulnerabilities found

4. **⚠️ Policy Evaluation** (when enabled)
   - Summary table: Blocking, Warnings, Acknowledged counts
   - Expandable sections for each violation type:
     - **🚫 Blocking Violations**: Violations that fail the build
     - **⚠️ Warning Violations**: Informational violations
     - **✅ Acknowledged Violations**: Previously acknowledged issues
   - Each section contains vulnerability tables with:
     - Severity with emoji
     - Vulnerability name
     - Location (file path with line numbers or package@version)
     - Direct link to CybeDefend platform

5. **Final Result** (✅ PASSED / ❌ FAILED)
   - Clear status indicator
   - Explanation message

#### How It Works

1. The CLI detects the `GITHUB_STEP_SUMMARY` environment variable (automatically set by GitHub Actions)
2. When `--ci` flag is used, the GitHub Summary Writer is initialized
3. Throughout the scan, information is collected and formatted
4. At the end, a complete markdown summary is written to `$GITHUB_STEP_SUMMARY`
5. GitHub Actions automatically displays this in the workflow summary tab

#### Usage

**In GitHub Actions:**

```yaml
name: Security Scan

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v3

      - name: Install CybeDefend CLI
        run: |
          curl -L https://github.com/CybeDefend/cybedefend-cli/releases/download/v1.0.10/cybedefend-linux-amd64 -o cybedefend
          chmod +x cybedefend
          sudo mv cybedefend /usr/local/bin/

      - name: Run CybeDefend Security Scan
        run: |
          cybedefend scan \
            --dir ./ \
            --ci \
            --api-key ${{ secrets.CYBEDEFEND_API_KEY }} \
            --project-id ${{ secrets.CYBEDEFEND_PROJECT_ID }} \
            --branch ${{ github.ref_name }}
```

**The `--ci` flag enables:**
- Colorless, emoji-free console output for better log readability
- Automatic GitHub Step Summary generation (when `GITHUB_STEP_SUMMARY` is available)
- Clean, parseable output for CI/CD systems

**Example Summary Output:**

When you run the scan, you'll see a beautifully formatted summary in the "Summary" tab of your GitHub Actions workflow, showing:

- Complete scan metadata and status
- Vulnerability counts by severity
- Expandable policy violation details
- Direct links to each vulnerability
- Final PASSED/FAILED status

## Improvements

- **CI-Mode Only Activation**: GitHub Summary Writer only initializes when `--ci` flag is used, avoiding unnecessary overhead in local development
- **Null-Safe Operations**: All summary write operations check if the writer is initialized before executing
- **Error Resilience**: Failed summary writes are logged as debug messages and don't interrupt the scan process
- **Conditional Vulnerability Details**: Respects the `--show-policy-vulns` flag for including vulnerability details in the summary

## Technical Details

### GitHub Summary Writer (`pkg/utils/github_summary.go`)

- **Environment Detection**: Checks for `GITHUB_STEP_SUMMARY` environment variable
- **Markdown Generation**: Builds complete markdown with tables, lists, and collapsible sections
- **Append Mode**: Uses `O_APPEND` flag to add to existing summary if present
- **Helper Functions**:
  - `formatVulnLocation()`: Formats vulnerability location based on type (SAST/SCA)
  - `getSeverityEmoji()`: Returns appropriate emoji for severity level
- **Structured Data Types**:
  - `PolicyViolationInfo`: Violation metadata and affected vulnerabilities
  - `VulnerabilityInfo`: Complete vulnerability details with links

### Integration Points

The summary writer is integrated at key points in the scan lifecycle:

1. **Scan Start**: Header with metadata
2. **Scan Completion**: Status and vulnerability counts
3. **Policy Evaluation**: Complete violations breakdown
4. **Errors**: Error status and messages
5. **Final Result**: Success/failure status

All integration points are conditional on `githubSummary != nil` to ensure CI-mode only operation.

### Example Markdown Output

```markdown
# 🔒 CybeDefend Security Scan Report

| Property | Value |
|----------|-------|
| **Scan ID** | `abc-123-def` |
| **Project ID** | `my-project-id` |
| **Branch** | `main` |
| **Date** | 2026-02-02 10:30:00 UTC |

## ✅ Scan Status: COMPLETED

**Vulnerabilities Detected:** 15

### 📊 Vulnerability Summary

| Severity | Count |
|----------|-------|
| 🔴 **Critical** | 2 |
| 🟠 **High** | 5 |
| 🟡 **Medium** | 6 |
| 🟢 **Low** | 2 |
| **Total** | **15** |

## ⚠️ Policy Evaluation

| Status | Count |
|--------|-------|
| 🚫 **Blocking** | 1 |
| ⚠️ **Warnings** | 2 |

### 🚫 Blocking Violations

<details>
<summary><strong>No Critical Vulnerabilities</strong> - 2 vulnerabilities</summary>

> Critical vulnerabilities must be fixed before deployment

| Severity | Name | Location | Link |
|----------|------|----------|------|
| 🔴 CRITICAL | SQL Injection | `src/api/users.ts` (L45-48) | [View](https://us.cybedefend.com/...) |
| 🔴 CRITICAL | Path Traversal | `src/utils/file.ts` (L12) | [View](https://us.cybedefend.com/...) |

</details>

---

## ✅ Result: PASSED

Policy check passed with 2 warning(s)
```

## Documentation

- Added GitHub Actions integration examples
- Updated CI mode documentation to mention summary generation
- Added example summary output screenshots (in documentation)

## Upgrade Notes

- **No Breaking Changes**: Existing workflows continue to work without modification
- **Automatic Activation**: Simply use `--ci` flag in GitHub Actions to enable summary
- **Optional**: Summary generation only occurs when `GITHUB_STEP_SUMMARY` is available
- **Backward Compatible**: All previous flags and behaviors remain unchanged

## Benefits

✅ **Immediate Visibility**: See scan results without opening logs  
✅ **Better PR Reviews**: Security status visible in PR checks summary  
✅ **Team Collaboration**: Non-technical stakeholders can understand results  
✅ **Historical Record**: Summaries are preserved with workflow runs  
✅ **Actionable Information**: Direct links to vulnerabilities for quick remediation  
✅ **Professional Presentation**: Clean, organized markdown output  

## Next Steps

After upgrading to v1.0.10:

1. Update your GitHub Actions workflow to use `--ci` flag
2. Check the "Summary" tab after workflow runs
3. Share summaries with your team for better security visibility
4. Use the direct links to review and fix vulnerabilities

---

**Full Changelog**: v1.0.9...v1.0.10
