# Shai-hulud-2.0-Checker

A simple bash script that will scan your project dir for package-lock.json, pnpm-lock.yaml & yarn.lock files that contain vulnerabilities listed in the wiz-sec vulnerability CSV.

NPM packages had a vulnerabiltiy that steals API keys.
Ref: https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

## Requirements

    curl - Download vulnerability data from remote source
    jq   - Parse and process JSON data from package-lock.json
    find - Locate package-lock.json & pnpm-lock.yaml files in the project directory
    awk  - Process and filter CSV vulnerability data
    yq   - Parse and handle YAML configuration files

For macOS: You can brew install above ^

## Usage

    ./shai-hulud-2-check.sh /Users/<username>/my/project

If you prefer to use a local copy of the vulnerability CSV, set the `SHAI_HULUD_CSV` environment variable:

    SHAI_HULUD_CSV=./shai-hulud-2-packages.csv ./shai-hulud-2-check.sh /Users/<username>/my/project

#### Example usage/ output

./check-shai-hulud-2.sh /Users/<username>/Desktop/<yourProjectName>/<dir>

⬇ Downloading vulnerability CSV from Github...
   https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv

ℹ Scanning pnpm lockfile: /Users/<username>/Desktop/<yourProjectName>/<dir>/pnpm-lock.yaml
ℹ Scanning yarn lockfile: /Users/<username>/Desktop/<yourProjectName>/<dir>/node_modules/.pnpm/uri-js@4.4.1/node_modules/uri-js/yarn.lock
ℹ Scanning yarn lockfile: /Users/<username>/Desktop/<yourProjectName>/<dir>/node_modules/.pnpm/combined-stream@1.0.8/node_modules/combined-stream/yarn.lock

✓ [OK] No vulnerable packages detected.

## Architecture

The script follows a multi-stage pipeline to detect vulnerable packages in JavaScript/TypeScript projects:

### 1. **Initialization & Validation**
   - Validates command-line arguments and directory existence
   - Checks for required dependencies (`jq`, `curl`, `find`, `awk`, `yq`)
   - Creates temporary files for processing vulnerability data

### 2. **Vulnerability Data Acquisition**
   - **Primary**: Downloads the vulnerability CSV from Wiz Security's GitHub repository
   - **Alternative**: Uses a local CSV file if `SHAI_HULUD_CSV` environment variable is set
   - The CSV contains package names and vulnerable version ranges in the format:
     ```
     "package-name","= 1.2.3 || = 1.2.4"
     ```

### 3. **Vulnerability Data Normalization**
   - Parses the CSV using `awk` to extract package-version pairs
   - Handles version ranges (splits on `||` to create individual entries)
   - Normalizes format to: `package<TAB>version` for efficient matching
   - Stores normalized data in a temporary file

### 4. **Lock File Discovery**
   - Recursively searches the target directory for:
     - `package-lock.json` (npm)
     - `pnpm-lock.yaml` (pnpm)
     - `yarn.lock` (Yarn)
   - Uses `find` command to locate all lock files in subdirectories

### 5. **Package Extraction** (Format-Specific)

   **For `package-lock.json` (npm):**
   - Uses `jq` to parse JSON structure
   - Handles both v1 (dependencies tree) and v2+ (packages flat structure) formats
   - Extracts package names and versions from the dependency tree
   - Output format: `package-name version`

   **For `pnpm-lock.yaml` (pnpm):**
   - Uses `yq` to parse YAML structure
   - Extracts package entries from `.packages` section
   - Parses package specifiers like `/package@version` or `/@scope/package@version`
   - Handles peer dependency suffixes: `(peer@version)`
   - Uses `awk` to normalize package names and versions

   **For `yarn.lock` (Yarn):**
   - Uses `awk` to parse the lock file format
   - Extracts package names from header lines (format: `"package@version":`)
   - Extracts versions from `version` fields
   - Matches names with their corresponding versions

### 6. **Vulnerability Matching**
   - For each extracted package-version pair from lock files:
     - Performs exact match against normalized vulnerability database
     - Compares both package name and version
     - Uses `awk` for efficient pattern matching
   - Flags matches as vulnerable and displays them immediately

### 7. **Output & Exit**
   - **If vulnerabilities found:**
     - Displays each vulnerable package with red ✗ indicator
     - Shows package name, version, and lock file location
     - Exits with code `1` (failure)
   - **If no vulnerabilities:**
     - Displays success message with green ✓ indicator
     - Exits with code `0` (success)

### Data Flow Diagram

```
Target Directory
    │
    ├─> find (recursive search)
    │   ├─> package-lock.json files
    │   ├─> pnpm-lock.yaml files
    │   └─> yarn.lock files
    │
    ├─> Vulnerability CSV (GitHub/local)
    │   └─> awk normalization → temp file
    │
    └─> For each lock file:
        │
        ├─> Extract packages (jq/yq/awk)
        │   └─> package-name version pairs
        │
        └─> Match against vulnerability DB
            ├─> Match found → ✗ VULNERABLE
            └─> No match → continue
                │
                └─> Final: ✓ OK or ✗ EMERGENCY
```

### Key Design Decisions

- **Format-Agnostic**: Supports all major package managers (npm, pnpm, Yarn)
- **Recursive Scanning**: Finds lock files in nested directories (e.g., `node_modules`)
- **Exact Version Matching**: Compares exact versions, not semantic version ranges
- **Streaming Processing**: Processes files one at a time to minimize memory usage
- **Early Exit**: Can be integrated into CI/CD pipelines via exit codes
- **Temporary File Cleanup**: Uses `trap` to ensure temp files are removed on exit

## Disclaimer

This script is provided "AS IS" without any warranties. The author assumes no liability for any damages or losses arising from the use of this script.

## More Info

https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains

https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack
