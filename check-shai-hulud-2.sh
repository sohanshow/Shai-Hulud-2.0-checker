#!/usr/bin/env bash
set -euo pipefail

# Author: @opctim https://github.com/opctim/shai-hulud-2-check
# More info:
# https://www.aikido.dev/blog/shai-hulud-strikes-again-hitting-zapier-ensdomains
# https://www.wiz.io/blog/shai-hulud-2-0-ongoing-supply-chain-attack

# THIS SCRIPT IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
# INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
# SCRIPT OR THE USE OR OTHER DEALINGS IN THE SCRIPT.

CSV_URL="https://raw.githubusercontent.com/wiz-sec-public/wiz-research-iocs/refs/heads/main/reports/shai-hulud-2-packages.csv"

# Color and icon definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Icons
CHECKMARK="✓"
CROSS="✗"
INFO="ℹ"
WARNING="⚠"
DOWNLOAD="⬇"

[ $# -eq 1 ] || { echo -e "${RED}${CROSS}${NC} Usage: $0 DIRECTORY" >&2; exit 2; }
DIR="$1"
[ -d "$DIR" ] || { echo -e "${RED}${CROSS}${NC} Error: not a directory: $DIR" >&2; exit 2; }

for cmd in jq curl find awk yq; do
  command -v "$cmd" >/dev/null 2>&1 || { echo -e "${RED}${CROSS}${NC} Error: ${BOLD}$cmd${NC} is required." >&2; exit 2; }
done

# Temp files
TMP_CSV="$(mktemp)"
TMP_VULN="$(mktemp)"
trap 'rm -f "$TMP_CSV" "$TMP_VULN"' EXIT

# Decide CSV source: env var or download
if [ -n "${SHAI_HULUD_CSV:-}" ]; then
  if [ ! -f "$SHAI_HULUD_CSV" ]; then
    echo -e "${RED}${CROSS}${NC} Error: SHAI_HULUD_CSV is set, but file does not exist: ${BOLD}$SHAI_HULUD_CSV${NC}" >&2
    exit 2
  fi
  CSV_SOURCE="$SHAI_HULUD_CSV"
  printf "\n${CYAN}${INFO}${NC} Using vulnerability CSV from SHAI_HULUD_CSV: ${BOLD}%s${NC}\n\n" "$CSV_SOURCE" >&2
else
  CSV_SOURCE="$TMP_CSV"
  printf "\n${BLUE}${DOWNLOAD}${NC} Downloading vulnerability CSV from Github...\n${CYAN}   ${CSV_URL}${NC}\n\n" >&2
  curl -fsSL "$CSV_URL" -o "$CSV_SOURCE"
fi

# Normalize CSV -> lines: "package<TAB>version"
# Handles cases like: "@scope/pkg","= 1.2.3 || = 1.2.4"
awk -F, 'NR>1 {
  gsub(/"/,"");          # drop quotes
  pkg=$1; vers=$2;
  n=split(vers, parts, /\|\|/);
  for (i=1; i<=n; i++) {
    gsub(/^ *= */,"", parts[i]); # strip leading " = "
    gsub(/ *$/,"",  parts[i]);   # trim trailing spaces
    if (parts[i] != "") {
      print pkg "\t" parts[i];
    }
  }
}' "$CSV_SOURCE" > "$TMP_VULN"

# jq program reused for each npm package-lock.json
read -r -d '' JQ_PROG <<'EOF' || true
  if .packages then
    .packages
    | to_entries[]
    | select(.key | startswith("node_modules/"))
    | "\(.key | sub("^node_modules/";"")) \(.value.version)"
  else
    def walk_deps:
      to_entries[]
      | .key as $name
      | .value as $v
      | ($v.version // empty) as $ver
      | if $ver != "" then "\($name) \($ver)" else empty end,
        ( $v.dependencies // {} | walk_deps );
    .dependencies // {} | walk_deps
  end
EOF

FOUND_ANY=0

# Find and scan all package-lock.json files recursively
while IFS= read -r LOCKFILE; do
  echo -e "${CYAN}${INFO}${NC} Scanning npm lockfile: ${BOLD}$LOCKFILE${NC}" >&2

  INSTALLED_PACKAGES="$(jq -r "$JQ_PROG" "$LOCKFILE" 2>/dev/null || true)"

  while read -r NAME VER; do
    [ -z "$NAME" ] || [ -z "$VER" ] && continue

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo -e "${RED}${CROSS}${NC} ${RED}${BOLD}VULNERABLE:${NC} ${BOLD}$NAME@$VER${NC} (in $LOCKFILE)"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "$DIR" -type f -name "package-lock.json")

# Find and scan all pnpm-lock.yaml files recursively
while IFS= read -r PLOCK; do
  echo -e "${CYAN}${INFO}${NC} Scanning pnpm lockfile: ${BOLD}$PLOCK${NC}" >&2

  # Extract "name version" pairs from pnpm-lock.yaml
  # .packages keys look like:
  #   "/left-pad@1.3.0"
  #   "/@scope/name@2.0.0"
  #   "/foo@1.0.0(bar@2.0.0)"  (peer suffix)
  INSTALLED_PACKAGES="$(
    yq -r '.packages // {} | to_entries[].key' "$PLOCK" 2>/dev/null \
    | awk '
      {
        key = $0
        gsub(/^\/+/, "", key)        # remove leading "/"
        sub(/\([^)]*\)$/, "", key)   # drop "(...)" peer suffix if present

        # Split at last "@": before -> name, after -> version
        i = match(key, /@[^@]*$/)
        if (i > 0) {
          name = substr(key, 1, i-1)
          ver  = substr(key, i+1)
          if (name != "" && ver != "") {
            print name " " ver
          }
        }
      }
    '
  )"

  while read -r NAME VER; do
    [ -z "$NAME" ] || [ -z "$VER" ] && continue

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo -e "${RED}${CROSS}${NC} ${RED}${BOLD}VULNERABLE:${NC} ${BOLD}$NAME@$VER${NC} (in $PLOCK)"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "$DIR" -type f -name "pnpm-lock.yaml")

# Find and scan all yarn.lock files recursively
while IFS= read -r YLOCK; do
  echo -e "${CYAN}${INFO}${NC} Scanning yarn lockfile: ${BOLD}$YLOCK${NC}" >&2

  INSTALLED_PACKAGES="$(
    awk '
      /^[^[:space:]].*:$/ {
        # remove trailing colon + quotes
        line = $0
        gsub(/"/, "", line)
        sub(/:$/, "", line)

        # extract name before the last "@"
        i = match(line, /@[^@]*$/)
        if (i > 0) {
          name = substr(line, 1, i-1)
        } else {
          next
        }
        next
      }

      /version / {
        gsub(/"/, "", $0)
        ver = $2
        if (name != "" && ver != "")
          print name, ver
      }
    ' "$YLOCK"
  )"

  while read -r NAME VER; do
    [ -z "$NAME" ] || [ -z "$VER" ] && continue

    if awk -v n="$NAME" -v v="$VER" '
        $1 == n && $2 == v { found=1 }
        END { exit found ? 0 : 1 }
      ' "$TMP_VULN"; then
      FOUND_ANY=1
      echo -e "${RED}${CROSS}${NC} ${RED}${BOLD}VULNERABLE:${NC} ${BOLD}$NAME@$VER${NC} (in $YLOCK)"
    fi
  done <<< "$INSTALLED_PACKAGES"

done < <(find "$DIR" -type f -name "yarn.lock")

if (( FOUND_ANY )); then
  printf "\n${RED}${CROSS}${NC} ${RED}${BOLD}[EMERGENCY]${NC} ${RED}Vulnerable packages found.${NC}\n" >&2
  exit 1
else
  printf "\n${GREEN}${CHECKMARK}${NC} ${GREEN}${BOLD}[OK]${NC} ${GREEN}No vulnerable packages detected.${NC}\n" >&2
  exit 0
fi
