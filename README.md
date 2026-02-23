# CybeDefend CLI

![License](https://img.shields.io/badge/license-apache--2.0-blue)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.22-blue)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

The **CybeDefend CLI** is a command-line interface tool for interacting with the CybeDefend API. It allows you to perform security scans, retrieve scan results, and manage your projects with ease. Designed for simplicity and portability, this CLI supports multiple platforms and can be integrated into CI/CD pipelines.

---

## Features

- Start a new security scan by uploading files or directories.
- Retrieve detailed scan results in multiple formats.
- **Policy Evaluation & Break Build**: Automatically enforce security policies and break builds based on policy violations.
- Cross-platform support: Linux, macOS, and Windows.
- CI/CD-friendly mode with simplified, colorless output.
- Personal Access Token (PAT) authentication via Logto IAM.
- Customizable configurations via flags, environment variables, or configuration files.
- Designed for use in CI/CD pipelines, Docker containers, and local environments.

---

## Installation

### Pre-built Binaries

Pre-built binaries for multiple platforms are available in the [Releases](https://github.com/CybeDefend/cybedefend-cli/releases) section of this repository. Follow these steps to download and install the appropriate binary for your system:

#### Supported Platforms
- **macOS**
  - `cybedefend-darwin-amd64`: For macOS on Intel-based systems.
  - `cybedefend-darwin-arm64`: For macOS on Apple Silicon (M1/M2).
- **Linux**
  - `cybedefend-linux-386`: For 32-bit Linux systems.
  - `cybedefend-linux-amd64`: For 64-bit Linux systems.
- **Windows**
  - `cybedefend-windows-386.exe`: For 32-bit Windows systems.
  - `cybedefend-windows-amd64.exe`: For 64-bit Windows systems.

#### Installation Steps

1. **Download the binary:**
   - Visit the [Releases](https://github.com/CybeDefend/cybedefend-cli/releases) page and download the appropriate binary for your platform.
   - For example:
     - macOS (Intel): `cybedefend-darwin-amd64`
     - Linux (64-bit): `cybedefend-linux-amd64`
     - Windows (64-bit): `cybedefend-windows-amd64.exe`

2. **Verify the Signature (Optional):**
   - Download the corresponding `.sig` file for the binary.
   - Verify the signature using GPG:
     ```bash
     gpg --verify cybedefend-<platform>.<ext>.sig cybedefend-<platform>.<ext>
     ```

3. **Install the binary:**
   - Make the binary executable (Linux/macOS):
     ```bash
     chmod +x cybedefend-<platform>
     ```
   - Move the binary to a directory in your `PATH`:
     ```bash
     sudo mv cybedefend-<platform> /usr/local/bin/cybedefend
     ```

4. **Run the CLI:**
   - Verify the installation:
     ```bash
     cybedefend --version
     ```

#### For Windows Users:
- Rename the binary to `cybedefend.exe` if desired for easier usage.
- Ensure the binary is in a directory included in your `PATH`, or run it from its current directory.

### Verify Installation

After installation, you can verify that the CLI is working by running:
```bash
cybedefend --help
```

### Build from Source

If you'd prefer to build the CLI from source, follow these steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/CybeDefend/cybedefend-cli.git
   cd cybedefend-cli
   ```

2. Build the binary:
   ```bash
   go build -o cybedefend
   ```

3. Move the binary to your `PATH`:
   ```bash
   mv cybedefend /usr/local/bin
   ```

4. Verify the installation:
   ```bash
   cybedefend --version
   ```

---

## Configuration

### Configuration File

You can create a `config.yaml` file in one of the following locations:
- Current directory (`./config.yaml`)
- User's home directory (`$HOME/.cybedefend/config.yaml`)
- System-wide directory (`/etc/cybedefend/config.yaml`)

Example `config.yaml`:
```yaml
api_url: "https://api-us.cybedefend.com" # default if not overridden
pat: "pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"   # Personal Access Token — create in Account Settings → Personal Access Tokens
project_id: "your-project-id"
branch: "main" # Optional: default branch for scans
# Optional: choose region (us/eu). If set, api_url and auth_endpoint will be derived unless overridden.
# region: "eu"
# Optional: custom app URL for vulnerability links (for self-hosted deployments)
# app_url: "https://app.example.com"
# Optional: override auth endpoint (derived from region by default)
# auth_endpoint: "https://auth-eu.cybedefend.com"
# logto_client_id: "cybedefend-cli"
```

### Environment Variables

The CLI also supports environment variables:

- `CYBEDEFEND_API_URL`: API base URL.
- `CYBEDEFEND_REGION`: Platform region (`us` or `eu`). Ignored if `CYBEDEFEND_API_URL` is set.
- `CYBEDEFEND_PAT`: Personal Access Token for authentication.
- `CYBEDEFEND_PROJECT_ID`: Default project ID.

### Command-Line Flags

You can override configurations using flags:

- `--region`: Platform region to use: `us` (default) or `eu`. If set, it selects `https://api-us.cybedefend.com` or `https://api-eu.cybedefend.com`.
- `--api-url`: API base URL (manual override; takes precedence over `--region`).
- `--pat`: Personal Access Token (PAT). Create one in Account Settings → Personal Access Tokens.
- `--project-id`: Project ID.

> ⚠️ `--api-key` / `CYBEDEFEND_API_KEY` / `api_key:` are permanently deprecated. API keys issued before the migration return `HTTP 410 Gone`. Migrate to PAT.

---

## Commands

### `scan`

The `scan` command starts a new security scan for a directory or zip file.

#### Syntax

```bash
cybedefend scan [flags]
```

#### Flags

- `--dir, -d`: Directory to scan. The directory will be zipped before uploading.
- `--file, -f`: A pre-zipped file to scan. (Cannot be used with `--dir`.)
- `--project-id`: Project ID for the scan. If not provided, the value from the configuration or environment variables will be used.
- `--branch, -b`: Branch name for the scan (e.g., `main`, `develop`). Associates the scan with a specific Git branch.
- `--wait, -w`: Wait for the scan to complete before exiting. (Default: `true`)
- `--interval`: Interval in seconds between scan status checks when waiting for completion. (Default: `5`)
- `--break-on-fail`: Exit with error code if scan fails. Only applies when waiting for scan completion. (Default: `false`)
- `--break-on-severity`: Exit with error code if vulnerabilities of specified severity or above are found. Possible values: `critical`, `high`, `medium`, `low`. Only applies when waiting for scan completion.
- `--policy-check`: Enable policy evaluation after scan completion. (Default: `true`)
- `--policy-timeout`: Timeout in seconds for policy evaluation. (Default: `300`)
- `--show-policy-vulns`: Show affected vulnerabilities in policy evaluation output. (Default: `true`)
- `--show-all-policy-vulns`: Show all affected vulnerabilities without limit. (Default: `false`, shows max 5 per violation)
- `--ci`: Enables CI/CD-friendly output. Disables colors, ASCII art, and additional formatting for plain text output.

#### Examples

1. Scan a directory:
   ```bash
   cybedefend scan --dir ./my-project --pat your-pat --project-id your-project-id
   ```

2. Scan a zip file:
   ```bash
   cybedefend scan --file ./my-project.zip
   ```

3. Use CI/CD-friendly mode:
   ```bash
   cybedefend scan --dir ./my-project --ci
   ```

4. Select the EU platform region:
   ```bash
   cybedefend scan --dir ./my-project --region eu
   ```

5. Manually override the API URL (takes precedence over region):
   ```bash
   cybedefend scan --dir ./my-project --api-url https://api-eu.cybedefend.com
   ```

6. Start a scan and wait for its completion:
   ```bash
   cybedefend scan --dir ./my-project --wait
   ```

7. Start a scan, wait for completion and make the build fail if the scan fails:
   ```bash
   cybedefend scan --dir ./my-project --wait --break-on-fail
   ```

8. Start a scan, wait for completion and make the build fail if critical vulnerabilities are detected:
   ```bash
   cybedefend scan --dir ./my-project --wait --break-on-severity critical
   ```

9. Start a scan, wait for completion and make the build fail if medium or higher vulnerabilities are detected:
   ```bash
   cybedefend scan --dir ./my-project --wait --break-on-severity medium
   ```

10. Change the interval for checking scan status to 10 seconds:
   ```bash
   cybedefend scan --dir ./my-project --wait --interval 10
   ```

11. Scan a directory with a specific branch:
    ```bash
    cybedefend scan --dir ./my-project --branch main
    ```

12. Scan with branch in CI/CD (using environment variable for branch name):
    ```bash
    cybedefend scan --dir ./ --ci --branch $GIT_BRANCH
    ```

13. Run scan with policy evaluation (enabled by default):
    ```bash
    cybedefend scan --dir ./my-project --ci
    ```

14. Disable policy evaluation:
    ```bash
    cybedefend scan --dir ./my-project --policy-check=false
    ```

15. Show all policy vulnerabilities (no limit):
    ```bash
    cybedefend scan --dir ./my-project --show-all-policy-vulns
    ```

16. Hide vulnerability details in policy output:
    ```bash
    cybedefend scan --dir ./my-project --show-policy-vulns=false
    ```

---

### `results`

The `results` command retrieves scan results for a specific project and outputs them in the desired format.

#### Syntax

```bash
cybedefend results [flags]
```

#### Default Behavior

By default, the command fetches results in `json` format for the `sast` type and saves them to `results.json` in the current directory.

#### Flags

- `--project-id`: Project ID for which to fetch results. If not provided, the value from the configuration or environment variables will be used.
- `--type, -t`: Type of results to fetch. Options:
  - `sast`: Static Application Security Testing (default).
  - `iac`: Infrastructure as Code.
- `--page, -p`: Page number to fetch (default: `1`). Ignored if `--all` is set.
- `--all, -a`: Fetch all results across all pages.
- `--output, -o`: Format of the output file. Options:
  - `json` (default): Saves results as a JSON file.
  - `html`: Saves results as an HTML file.
  - `sarif`: Saves results in SARIF format.
- `--filename, -f`: Name of the output file (default: `results.json`).
- `--filepath`: Path to save the output file (default: `.`).
- `--ci`: Enables CI/CD-friendly output. Disables colors, ASCII art, and additional formatting for plain text output.

#### Examples

1. Fetch results in `json` format (default):
   ```bash
   cybedefend results --project-id your-project-id
   ```

2. Fetch all results in `html` format:
   ```bash
   cybedefend results --project-id your-project-id --all --output html --filename results.html
   ```

3. Fetch results in `sarif` format and save to a specific path:
   ```bash
   cybedefend results --project-id your-project-id --output sarif --filepath ./reports
   ```

4. Fetch results for the `iac` type:
   ```bash
   cybedefend results --project-id your-project-id --type iac
   ```

5. Use CI/CD-friendly mode:
   ```bash
   cybedefend results --project-id your-project-id --ci
   ```

---

## Policy Evaluation & Break Build

The CLI integrates with CybeDefend's Policy Evaluation system to enforce security policies and optionally break builds based on policy violations.

### How It Works

1. After a scan completes, the CLI automatically checks for policy violations
2. The CLI polls the evaluation status until it completes (or times out)
3. All violations are fetched and displayed, grouped by action type:
   - **BLOCK**: Violations that will cause the CLI to exit with code 1
   - **WARN**: Informational violations that won't affect the exit code
   - **Acknowledged**: Violations that have been acknowledged in the platform (won't block)

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

⚠️ WARN Actions:
  ⚠ Dependency Check (WARN)
    Affected: 1 vulnerability

✓ Acknowledged Violations (not blocking):
  ⚠ No High Vulnerabilities (BLOCK)
    ✓ Acknowledged: Risk accepted for legacy code
```

### Configuration

Policy evaluation is enabled by default. You can customize its behavior:

```bash
# Disable policy evaluation
cybedefend scan --dir ./my-project --policy-check=false

# Increase timeout for large projects
cybedefend scan --dir ./my-project --policy-timeout 600

# Show all vulnerabilities per violation (default: max 5)
cybedefend scan --dir ./my-project --show-all-policy-vulns

# Hide vulnerability details
cybedefend scan --dir ./my-project --show-policy-vulns=false
```

---

## CI/CD Mode (`--ci`)

The `--ci` flag is available for both the `scan` and `results` commands. When enabled, the CLI suppresses colors, ASCII art, and other visual formatting, providing clean and minimal output suitable for CI/CD pipelines.

## Output Formats

### JSON (Default)

Results are saved in a JSON file with detailed vulnerability data, including severity, affected files, and remediation recommendations.

### HTML

Generates a human-readable HTML report summarizing vulnerabilities and their impact.

### SARIF

Generates a SARIF (Static Analysis Results Interchange Format) file, commonly used for integration with IDEs and CI/CD systems.

---

## CI/CD Integration

You can integrate the CLI into CI/CD pipelines to automate security scans.

### GitHub Actions

Here's an example for GitHub Actions:

```yaml
name: Security Scan

on:
  push:
    branches:
      - main

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v2

      - name: Install CybeDefend CLI
        run: |
          curl -L https://github.com/CybeDefend/cybedefend-cli/releases/download/v1.1.0/cybedefend-linux-amd64 -o cybedefend
          chmod +x cybedefend
          sudo mv cybedefend /usr/local/bin/

      - name: Run security scan
        run: cybedefend scan --dir ./ --ci --pat ${{ secrets.CYBEDEFEND_PAT }} --project-id ${{ secrets.CYBEDEFEND_PROJECT_ID }} --region ${{ vars.CYBEDEFEND_REGION }} --branch ${{ github.ref_name }}
```

### GitLab CI

Here's an example for GitLab CI:

```yaml
# .gitlab-ci.yml
stages:
  - security-scan

variables:
  CYBEDEFEND_CLI_VERSION: "v1.1.0"
  CYBEDEFEND_CLI_BINARY: "cybedefend-linux-amd64"
  CYBEDEFEND_REGION: "eu"  # or "us"

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: always
    - when: never

security_scan:
  stage: security-scan
  image: alpine:3.23
  before_script:
    - apk add --no-cache curl ca-certificates
  script:
    - echo "Downloading CybeDefend CLI ${CYBEDEFEND_CLI_VERSION}"
    - |
      curl -fsSL "https://github.com/CybeDefend/cybedefend-cli/releases/download/${CYBEDEFEND_CLI_VERSION}/${CYBEDEFEND_CLI_BINARY}" \
        -o /tmp/cybedefend
    - chmod 0755 /tmp/cybedefend
    - mv /tmp/cybedefend /usr/local/bin/cybedefend
    - echo "Running CybeDefend security scan"
    - >
      cybedefend scan
      --dir .
      --ci
      --pat "${CYBEDEFEND_PAT}"
      --project-id "${CYBEDEFEND_PROJECT_ID}"
      --region "${CYBEDEFEND_REGION}"
      --branch "${CI_COMMIT_BRANCH}"
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
      when: on_success
```

> **Note:** Store `CYBEDEFEND_PAT` and `CYBEDEFEND_PROJECT_ID` as protected CI/CD variables in your GitLab project settings.

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

---

## Support

For issues or questions, please open an [issue](https://github.com/CybeDefend/cybedefend-cli/issues) on GitHub.
