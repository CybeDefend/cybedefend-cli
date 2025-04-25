# CybeDefend CLI

![License](https://img.shields.io/badge/license-apache--2.0-blue)
![Go Version](https://img.shields.io/badge/go-%3E%3D1.22-blue)
![Build Status](https://img.shields.io/badge/build-passing-brightgreen)

The **CybeDefend CLI** is a command-line interface tool for interacting with the CybeDefend API. It allows you to perform security scans, retrieve scan results, and manage your projects with ease. Designed for simplicity and portability, this CLI supports multiple platforms and can be integrated into CI/CD pipelines.

---

## Features

- Start a new security scan by uploading files or directories.
- Retrieve detailed scan results in multiple formats.
- Cross-platform support: Linux, macOS, and Windows.
- CI/CD-friendly mode with simplified, colorless output.
- API key-based authentication.
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
api_url: "https://api-preprod.cybedefend.com"
api_key: "your-api-key"
project_id: "your-project-id"
```

### Environment Variables

The CLI also supports environment variables:

- `CYBEDEFEND_API_URL`: API base URL.
- `CYBEDEFEND_API_KEY`: API key for authentication.
- `CYBEDEFEND_PROJECT_ID`: Default project ID.

### Command-Line Flags

You can override configurations using flags:

- `--api-url`: API base URL.
- `--api-key`: API key.
- `--project-id`: Project ID.

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
- `--ci`: Enables CI/CD-friendly output. Disables colors, ASCII art, and additional formatting for plain text output.

#### Examples

1. Scan a directory:
   ```bash
   cybedefend scan --dir ./my-project --api-key your-api-key --project-id your-project-id
   ```

2. Scan a zip file:
   ```bash
   cybedefend scan --file ./my-project.zip
   ```

3. Use CI/CD-friendly mode:
   ```bash
   cybedefend scan --dir ./my-project --ci
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

You can integrate the CLI into CI/CD pipelines to automate security scans. Here’s an example for GitHub Actions:

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
          curl -L https://github.com/CybeDefend/cybedefend-cli/releases/download/v1.0.0/cybedefend-linux-amd64 -o cybedefend
          chmod +x cybedefend
          sudo mv cybedefend /usr/local/bin/

      - name: Run security scan
        run: cybedefend scan --dir ./ --ci --api-key ${{ secrets.CYBEDEFEND_API_KEY }} --project-id ${{ secrets.CYBEDEFEND_PROJECT_ID }}
```

---

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for details.

---

## Support

For issues or questions, please open an [issue](https://github.com/CybeDefend/cybedefend-cli/issues) on GitHub.
