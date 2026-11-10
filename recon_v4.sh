#!/usr/bin/env bash
#
# recon.sh (v5) - Web recon: JS + secrets (SecretFinder / TruffleHog / Gitleaks)
#                 + tech fingerprint + content discovery (ffuf / kiterunner /
#                 SecLists) + OWASP header analysis + vulnerability validation.
#
# What's new in v5:
#   * -s/--secret also runs TruffleHog (with live verification of the secrets
#     it finds) and Gitleaks over the downloaded files; Gitleaks findings are
#     cross-checked against TruffleHog's verified results.
#   * -d/--dirs uses ffuf + SecLists (no wordlist required anymore); dirsearch
#     is only used as a fallback when ffuf is not installed.
#   * -k/--kite: API route discovery with Assetnote kiterunner.
#   * Fixes in the WPScan / Nuclei / httpx / searchsploit integrations.
#   * Everything translated to English.
#
# Examples:
#   ./recon_v4.sh -u https://site.com/ --install-deps
#   ./recon_v4.sh -u https://site.com/ -f -s -v
#   ./recon_v4.sh -u https://site.com/ -t --json
#   ./recon_v4.sh -u https://site.com/ -T            # tech-deep (WhatWeb) + vuln validation
#   ./recon_v4.sh -u https://site.com/ -d            # ffuf + SecLists raft-medium
#   ./recon_v4.sh -u https://site.com/ -d -k         # ffuf + kiterunner
#   ./recon_v4.sh -u https://site.com/ --all
#   ./recon_v4.sh -l sites.txt -f -s                 # several targets, one per line
#   ./recon_v4.sh -l sites.txt -u extra.com -t       # list + an extra target
#
set -uo pipefail

# Keep the original arguments BEFORE the parser consumes them (shift), so that
# self_update() can re-exec the script with the same flags after a git pull.
ORIGINAL_ARGS=("$@")

RECON_VERSION="5.0"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
URL=""
LIST_FILE=""                 # file with a list of targets (one per line)
declare -a URL_ARGS=()       # targets passed with -u (repeatable)
declare -a MODES=()          # accumulated modes (combinable)
declare -a TARGETS=()        # final list of targets to process
VERBOSE=0
JSON=0
OUT_FILE=""
JS_LIST_FILE=""
CUSTOM_AGENT=0
WORDLIST=""
WORDLIST_SIZE="medium"       # SecLists raft-<size>-directories.txt for -d (small|medium|large)
GF_PATTERN="xss"
TIMEOUT=15
NO_COLOR=0
AUTO_INSTALL=0               # install deps without asking (--install-deps / --yes)
NO_AUTO_INSTALL=0            # never install anything automatically (--no-install)
DO_CHECK_ONLY=0              # only check deps and exit (--check)
DO_INSTALL_ONLY=0            # install deps and exit (--install-deps)
NO_VULN=0                    # disable vulnerability validation (--no-vuln)
NO_PREFLIGHT=0               # skip the httpx liveness check (--no-preflight)
SELF_UPDATE=1                # update script/templates/DBs before recon (--no-self-update disables)
HISTORY_DIR="${HISTORY_DIR:-./history}"  # run history (read by the dashboard)

# Secret scanners (-s)
SECRET_VERIFY=1                    # TruffleHog live verification (--no-verify disables)

# Vulnerability validation tuning
WPSCAN_DETECTION="${WPSCAN_DETECTION:-mixed}"  # WPScan plugin/theme detection: passive|mixed|aggressive
NUCLEI_EXTRA_TAGS="${NUCLEI_EXTRA_TAGS:-}"     # extra nuclei tags added to the detected ones (--nuclei-tags)
HTTPX_BIN=""                       # ProjectDiscovery httpx binary (see find_httpx)

# ffuf / SecLists / kiterunner
SECLISTS_DIR="${SECLISTS_DIR:-}"   # auto-detected when empty (see find_seclists)
FFUF_THREADS="${FFUF_THREADS:-40}"
FFUF_RECURSION_DEPTH="${FFUF_RECURSION_DEPTH:-1}"
KITE_WORDLIST="${KITE_WORDLIST:-}" # .kite routes file; auto-detected when empty
KITE_DIR="${KITE_DIR:-./kiterunner}"

SECRETFINDER_PATH="${SECRETFINDER_PATH:-./SecretFinder/SecretFinder.py}"

# .env file (API keys) and vuln tool options
ENV_FILE="${ENV_FILE:-./.env}"
WPSCAN_ENUM="${WPSCAN_ENUM:-vp,vt,u}"   # vulnerable plugins, vulnerable themes, users

# Consolidated security headers (OWASP) report, all targets
HEADERS_REPORT="${HEADERS_REPORT:-./owasp-headers-report.md}"

# Security headers that MUST be present (missing = finding).
# Source: OWASP HTTP Security Response Headers Cheat Sheet.
#   header_name|value/recommendation
OWASP_SEC_HEADERS=(
  "Strict-Transport-Security|HSTS: max-age=63072000; includeSubDomains; preload"
  "Content-Security-Policy|CSP: mitigates XSS/content injection"
  "X-Content-Type-Options|nosniff (blocks MIME sniffing)"
  "X-Frame-Options|DENY (anti-clickjacking; or CSP frame-ancestors)"
  "Referrer-Policy|strict-origin-when-cross-origin"
  "Permissions-Policy|disable unused browser features"
  "Cross-Origin-Opener-Policy|COOP: same-origin"
  "Cross-Origin-Embedder-Policy|COEP: require-corp"
  "Cross-Origin-Resource-Policy|CORP: same-site"
)

# Information DISCLOSURE headers that should be ABSENT (present = finding).
OWASP_DISCLOSURE_HEADERS=(
  "Server|Remove the version or use a non-informative value"
  "X-Powered-By|Remove"
  "X-AspNet-Version|Remove"
  "X-AspNetMvc-Version|Remove"
)

REQ_COUNT=0
UA_POOL=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (Android 14; Mobile; rv:125.0) Gecko/125.0 Firefox/125.0"
)
UA_FIXED="${UA_POOL[0]}"

# ---------------------------------------------------------------------------
# Log helpers
# ---------------------------------------------------------------------------
setup_colors() {
  if [ "$NO_COLOR" -eq 1 ] || [ ! -t 2 ]; then
    c_red=''; c_grn=''; c_yel=''; c_blu=''; c_cyn=''; c_bold=''; c_dim=''; c_rst=''
  else
    c_red='\033[0;31m'; c_grn='\033[0;32m'; c_yel='\033[1;33m'; c_blu='\033[0;34m'
    c_cyn='\033[0;36m'; c_bold='\033[1m'; c_dim='\033[2m'; c_rst='\033[0m'
  fi
}
c_red=''; c_grn=''; c_yel=''; c_blu=''; c_cyn=''; c_bold=''; c_dim=''; c_rst=''
log()  { echo -e "${c_blu}[*]${c_rst} $*" >&2; }
ok()   { echo -e "${c_grn}[+]${c_rst} $*" >&2; }
warn() { echo -e "${c_yel}[!]${c_rst} $*" >&2; }
err()  { echo -e "${c_red}[-]${c_rst} $*" >&2; }
vlog() { [ "$VERBOSE" -eq 1 ] && log "$*"; return 0; }

# ---------------------------------------------------------------------------
# Visual helpers (banner, section separators, per-target header)
# ---------------------------------------------------------------------------
_rule() { printf "${c_cyn}%s${c_rst}\n" "$(printf -- '─%.0s' $(seq 1 "${1:-64}"))" >&2; }

print_banner() {
  [ "$NO_COLOR" -eq 1 ] && { echo "recon.sh v${RECON_VERSION} — web reconnaissance" >&2; return; }
  echo -e "${c_cyn}${c_bold}" >&2
  cat >&2 <<BANNER
┌─────────────────────────────────────────────────────────────┐
│                      recon.sh — v${RECON_VERSION}                        │
│  subdomains · deep JS · ffuf · kiterunner · OWASP · vulns   │
└─────────────────────────────────────────────────────────────┘
BANNER
  echo -e "${c_rst}" >&2
}

# section "Title" — stage separator (Phase 1/2, Phase 2/2, etc.)
section() {
  echo >&2
  _rule 64
  echo -e "${c_bold}${c_cyn}▶ $*${c_rst}" >&2
  _rule 64
}

# target_header "N" "TOTAL" "url" — per-target header in Phase 2
target_header() {
  echo >&2
  echo -e "${c_bold}${c_cyn}[$1/$2]${c_rst} ${c_bold}$3${c_rst}" >&2
}

# Join array elements with an arbitrary (multi-character) separator.
#   join_by ", " "${arr[@]}"
join_by() {
  local sep="$1"; shift
  [ "$#" -eq 0 ] && return 0
  local out="$1"; shift
  printf '%s' "$out"
  printf '%s' "${@/#/$sep}"
}

WORKDIR="$(mktemp -d /tmp/jsrecon.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# API key management (.env)
# ---------------------------------------------------------------------------
# Load KEY=VALUE pairs from .env without executing code (safe parsing, no `source`).
load_env() {
  [ -f "$ENV_FILE" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in ''|\#*) continue ;; esac
    k="$(echo "$k" | tr -d '[:space:]')"
    [ -z "$k" ] && continue
    v="${v%\"}"; v="${v#\"}"          # strip surrounding quotes
    export "$k=$v"
  done < "$ENV_FILE"
  vlog ".env loaded from $ENV_FILE"
}

# Write/update a key in .env with mode 600.
save_env_var() {
  local key="$1" val="$2"
  touch "$ENV_FILE" 2>/dev/null || { warn "Cannot write to $ENV_FILE"; return 1; }
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i -E "s|^${key}=.*|${key}=\"${val}\"|" "$ENV_FILE"
  else
    echo "${key}=\"${val}\"" >> "$ENV_FILE"
  fi
}

# Make sure an API key is available: if it is missing from the environment/.env,
# ask the user (hidden input) and persist it to .env. Without a TTY, only warn.
#   ensure_api_key <VAR_NAME> "<prompt>" [required=0|1]
ensure_api_key() {
  local key="$1" prompt="$2" required="${3:-0}" cur val
  cur="$(printenv "$key" 2>/dev/null || true)"
  if [ -n "$cur" ]; then
    vlog "$key already set (environment or $ENV_FILE)"
    return 0
  fi
  if [ ! -e /dev/tty ]; then
    if [ "$required" -eq 1 ]; then
      warn "$key is not set and there is no interactive terminal. Set it in $ENV_FILE or export it."
    else
      vlog "$key missing; no terminal to ask for it (optional). Continuing."
    fi
    return 1
  fi
  printf '%b[?]%b %s: ' "$c_yel" "$c_rst" "$prompt" >&2
  read -r -s val </dev/tty 2>/dev/null; echo >&2
  if [ -z "$val" ]; then
    [ "$required" -eq 1 ] && warn "$key left blank."
    return 1
  fi
  export "$key=$val"
  save_env_var "$key" "$val" && ok "$key saved to $ENV_FILE (chmod 600)"
  return 0
}

# ---------------------------------------------------------------------------
# Help
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
recon.sh v${RECON_VERSION} — web reconnaissance (deep JS, secrets, tech, subdomains, content discovery...)

Usage:
  $0 -u <URL> [modes...] [options]

Modes (can be COMBINED in a single run):
  -f, --files        Extract .js from the HTML, resolve the URLs and download the files
  -s, --secret       Secret scanning: SecretFinder + TruffleHog (verified) + Gitleaks
  -t, --tech         Technology fingerprint + version guess
  -T, --tech-deep    Deep fingerprint (WhatWeb) + OWASP security headers analysis
  -S, --subdomains   Enumerate subdomains (sublist3r; crt.sh fallback)
  -U, --urls         Collect historical URLs for the domain (gau)
  -p, --probe        Port scan (naabu, top 100) + live hosts/URLs (httpx)
  -d, --dirs         Content discovery with ffuf + SecLists (dirsearch fallback)
  -k, --kite         API route discovery with kiterunner (Assetnote routes + SecLists)
  -g, --gf           Filter collected URLs with dangerous patterns (gf + Gf-Patterns)
  -a, --all          Run every available module, in logical order

Options:
  -u, --url <URL>          Target URL (repeatable; can be combined with -l)
  -l, --list <file>        File with a list of targets, one per line
                           (bare domain or URL; lines starting with # are ignored)
  -o, --output <file>      Specific output file (ignored with multiple targets)
  -w, --wordlist <file>    Wordlist for --dirs (default: SecLists raft-<size>-directories.txt)
      --wordlist-size <s>  SecLists raft wordlist size for --dirs: small|medium|large (default: ${WORDLIST_SIZE})
      --kite-wordlist <f>  kiterunner routes file (.kite) (default: auto-detect in ${KITE_DIR}/)
      --seclists <dir>     SecLists directory (default: auto-detect)
      --jsfile <file>      Reuse an existing JS URL list (skips crawling in --secret)
      --no-verify          Do not let TruffleHog verify secrets against the provider APIs
      --gf-pattern <name>  gf pattern to use (default: xss)
      --env <file>         .env file with API keys (default: ${ENV_FILE})
      --wpscan-enum <e>    WPScan enumeration (default: ${WPSCAN_ENUM})
      --wpscan-detection <m>  WPScan plugin/theme detection: passive|mixed|aggressive (default: ${WPSCAN_DETECTION})
      --nuclei-tags <t>    Extra nuclei tags (comma-separated) added to the detected ones
      --no-vuln            Disable vulnerability validation (wpscan/nuclei)
      --no-preflight       Do not check liveness with httpx before running modules
      --no-self-update     Do not update the script/nuclei-templates/WPScan DB/Exploit-DB before running
      --rotate-agent       Rotate the User-Agent every 5 requests
      --timeout <sec>      Per-request timeout (default: ${TIMEOUT})
  -v, --verbose            Verbose logging to stderr
  -j, --json               JSON output (where applicable)
      --no-color           Disable colors

Dependencies:
      --check              Check every tool/module and exit
      --install-deps       Install what is missing (Python, SecretFinder, SecLists, kiterunner routes) and exit
      --yes                Answer "yes" to installs (non-interactive)
      --no-install         Never install anything automatically
  -h, --help               This help

Secret scanning (-s):
  SecretFinder (regex, per JS URL), TruffleHog (filesystem scan of js/, with live
  verification unless --no-verify) and Gitleaks (filesystem scan of js/).
  Gitleaks findings on the same file/line as a TruffleHog-verified secret are
  marked as confirmed. Outputs: results/trufflehog.jsonl, results/gitleaks.json,
  results/secrets-all.txt (consolidated, values redacted).

Vulnerability validation (automatic after -t/-T; disable with --no-vuln):
  WordPress            -> WPScan (uses WPSCAN_API_TOKEN when available)
  Nginx / Apache       -> Nuclei (by tag) + searchsploit by version
  API keys are requested at startup and saved to ${ENV_FILE} (chmod 600).

Two-phase preflight: Phase 1 checks ALL targets with httpx and builds the list
of live ones (./live-targets.txt); Phase 2 runs the modules only on live targets.
--no-preflight skips Phase 1 (every target goes straight to the modules).

Self-update (meant for a daily cron; disable with --no-self-update):
  Before each run the script updates itself (git pull, when applicable),
  nuclei-templates, the WPScan metadata DB and the local Exploit-DB, so a new
  CVE published today is detected in tomorrow's run against the same software
  version. Each run writes a snapshot to ./history/ and highlights in the logs
  (and in SUMMARY.md) any finding that did not exist in that domain's previous
  run, with 🆕.

Web dashboard (separate file — dashboard.py):
  python3 dashboard.py --set-password   # set user/password (once)
  python3 dashboard.py --port 8765      # start the authenticated dashboard
  Reads ./history/ and shows, per domain, the run history and what changed
  between runs. See the README for security/exposure details.

Security headers (in -T mode): compares the headers with the OWASP Cheat Sheet,
highlights the missing ones in the logs and writes a consolidated report to
${HEADERS_REPORT} (applications + missing headers).

Output:
  Everything is saved to ./recon_<domain>/ with js/ and results/ subfolders
  Port scan (-p): results/naabu.txt (top 100 ports)
  Content discovery (-d): results/ffuf.json, results/dirs.txt
  API routes (-k): results/kiterunner.txt, results/api-routes.txt
  OWASP header analysis: results/security-headers.txt (per target) and
  ${HEADERS_REPORT} (consolidated)
EOF
}

# ---------------------------------------------------------------------------
# Dependency management
# ---------------------------------------------------------------------------
# Python modules required by SecretFinder (import_name:pip_package)
PY_DEPS=( "jsbeautifier:jsbeautifier" "requests:requests" "lxml:lxml" "requests_file:requests-file" )

pymod_ok() { python3 -c "import $1" >/dev/null 2>&1; }

# pip with a fallback for Kali/Debian PEP 668 (externally-managed-environment)
pip_install() {
  local pkgs=("$@")
  log "pip install --user ${pkgs[*]}"
  if pip3 install --user "${pkgs[@]}" 2>/dev/null; then return 0; fi
  warn "Plain pip failed; retrying with --break-system-packages (Kali/Debian PEP 668)"
  if pip3 install --user --break-system-packages "${pkgs[@]}" 2>/dev/null; then return 0; fi
  return 1
}

confirm() {
  # Returns 0 (yes) when AUTO_INSTALL; never installs when NO_AUTO_INSTALL.
  [ "$NO_AUTO_INSTALL" -eq 1 ] && return 1
  [ "$AUTO_INSTALL" -eq 1 ] && return 0
  local ans
  printf '%b[?]%b %s [y/N] ' "$c_yel" "$c_rst" "$1" >&2
  read -r ans </dev/tty 2>/dev/null || return 1
  [[ "$ans" =~ ^[yYsS] ]]
}

# Make sure SecretFinder's Python modules are present. Called before -secret.
ensure_python_deps() {
  local need_import need_pip=()
  for pair in "${PY_DEPS[@]}"; do
    need_import="${pair%%:*}"
    if ! pymod_ok "$need_import"; then
      need_pip+=( "${pair##*:}" )
    fi
  done
  if [ "${#need_pip[@]}" -eq 0 ]; then
    vlog "SecretFinder Python modules OK"
    return 0
  fi
  warn "Python modules missing for SecretFinder: ${need_pip[*]}"
  if confirm "Install them now with pip?"; then
    if pip_install "${need_pip[@]}"; then
      ok "Python modules installed"
      return 0
    fi
    err "Failed to install Python modules. Install them manually:"
    err "  pip3 install --user --break-system-packages ${need_pip[*]}"
    return 1
  fi
  err "Modules missing; SecretFinder will not run. Use --install-deps or --yes."
  return 1
}

# Make sure SecretFinder.py exists (clones it if the user allows).
ensure_secretfinder() {
  if [ -f "$SECRETFINDER_PATH" ]; then
    vlog "SecretFinder found at $SECRETFINDER_PATH"
    return 0
  fi
  warn "SecretFinder.py not found at: $SECRETFINDER_PATH"
  if ! command -v git >/dev/null 2>&1; then
    err "git is not installed; cannot clone SecretFinder."
    return 1
  fi
  if confirm "Clone SecretFinder into ./SecretFinder?"; then
    if git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git ./SecretFinder 2>/dev/null; then
      SECRETFINDER_PATH="./SecretFinder/SecretFinder.py"
      ok "SecretFinder cloned into ./SecretFinder"
      return 0
    fi
    err "Failed to clone SecretFinder."
    return 1
  fi
  err "Set SECRETFINDER_PATH or clone it manually:"
  err "  git clone https://github.com/m4ll0k/SecretFinder.git"
  return 1
}

# ---------------------------------------------------------------------------
# httpx (ProjectDiscovery) resolver
# ---------------------------------------------------------------------------
# The name "httpx" collides with the Python HTTP client CLI. Kali ships
# ProjectDiscovery's httpx as "httpx-toolkit". Find the real one and cache it in
# $HTTPX_BIN. A binary is accepted only if `-version` mentions projectdiscovery
# or the help lists the -silent flag (absent from the Python CLI).
find_httpx() {
  [ -n "$HTTPX_BIN" ] && { echo "$HTTPX_BIN"; return 0; }
  local c
  for c in httpx-toolkit httpx "$HOME/go/bin/httpx"; do
    command -v "$c" >/dev/null 2>&1 || [ -x "$c" ] || continue
    if "$c" -version 2>&1 | grep -qi 'projectdiscovery\|current version' \
       || "$c" -h 2>&1 | grep -q '\-silent'; then
      HTTPX_BIN="$c"; echo "$c"; return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# SecLists (wordlists for ffuf/kiterunner)
# ---------------------------------------------------------------------------
# Prints the SecLists root directory, or returns 1 when it cannot be found.
# Order: --seclists / $SECLISTS_DIR, Kali package paths, ./SecLists.
find_seclists() {
  local d
  for d in "$SECLISTS_DIR" /usr/share/seclists /usr/share/wordlists/seclists /opt/SecLists ./SecLists "$HOME/SecLists"; do
    [ -n "$d" ] && [ -d "$d/Discovery/Web-Content" ] && { echo "$d"; return 0; }
  done
  return 1
}

# Clone SecLists (shallow) into ./SecLists when missing and the user allows it.
ensure_seclists() {
  local d
  if d="$(find_seclists)"; then
    vlog "SecLists found at $d"
    return 0
  fi
  warn "SecLists not found (checked /usr/share/seclists, /usr/share/wordlists/seclists, ./SecLists)"
  command -v git >/dev/null 2>&1 || { err "git is not installed; cannot clone SecLists."; return 1; }
  if confirm "Clone SecLists into ./SecLists (shallow, ~1 GB)?"; then
    if git clone --depth 1 https://github.com/danielmiessler/SecLists.git ./SecLists; then
      ok "SecLists cloned into ./SecLists"
      return 0
    fi
    err "Failed to clone SecLists."
    return 1
  fi
  err "Install SecLists manually: sudo apt install seclists  (or git clone --depth 1 https://github.com/danielmiessler/SecLists.git)"
  return 1
}

# Wordlist used by -d: -w wins; otherwise SecLists raft-<size>-directories.txt.
resolve_dir_wordlist() {
  if [ -n "$WORDLIST" ]; then
    [ -f "$WORDLIST" ] && { echo "$WORDLIST"; return 0; }
    err "Wordlist not found: $WORDLIST"
    return 1
  fi
  local sl wl
  sl="$(find_seclists)" || { err "No -w/--wordlist given and SecLists not found. Run --install-deps or pass -w."; return 1; }
  wl="${sl}/Discovery/Web-Content/raft-${WORDLIST_SIZE}-directories.txt"
  [ -f "$wl" ] || wl="${sl}/Discovery/Web-Content/common.txt"
  [ -f "$wl" ] || { err "No usable wordlist inside $sl"; return 1; }
  echo "$wl"
}

# SecLists API wordlist used by kiterunner's brute pass.
resolve_api_wordlist() {
  local sl f
  sl="$(find_seclists)" || return 1
  for f in "Discovery/Web-Content/api/api-endpoints.txt" \
           "Discovery/Web-Content/common-api-endpoints-mazen160.txt" \
           "Discovery/Web-Content/api/objects.txt"; do
    [ -f "${sl}/${f}" ] && { echo "${sl}/${f}"; return 0; }
  done
  return 1
}

# ---------------------------------------------------------------------------
# kiterunner routes (.kite)
# ---------------------------------------------------------------------------
find_kite_wordlist() {
  if [ -n "$KITE_WORDLIST" ]; then
    [ -f "$KITE_WORDLIST" ] && { echo "$KITE_WORDLIST"; return 0; }
    return 1
  fi
  local f
  for f in "${KITE_DIR}/routes-large.kite" "${KITE_DIR}/routes-small.kite" \
           /usr/share/kiterunner/routes-large.kite /usr/share/kiterunner/routes-small.kite; do
    [ -f "$f" ] && { echo "$f"; return 0; }
  done
  return 1
}

# Download Assetnote's routes-small.kite into $KITE_DIR when missing.
ensure_kite_wordlist() {
  local f
  if f="$(find_kite_wordlist)"; then
    vlog "kiterunner routes found at $f"
    return 0
  fi
  warn "kiterunner routes (.kite) not found in ${KITE_DIR}/"
  if confirm "Download Assetnote routes-small.kite into ${KITE_DIR}/?"; then
    mkdir -p "$KITE_DIR"
    if curl -sSL --max-time 300 -o "${KITE_DIR}/routes-small.kite.tar.gz" \
         "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-small.kite.tar.gz" \
       && tar -xzf "${KITE_DIR}/routes-small.kite.tar.gz" -C "$KITE_DIR"; then
      rm -f "${KITE_DIR}/routes-small.kite.tar.gz"
      ok "routes-small.kite saved to ${KITE_DIR}/"
      warn "For better coverage also fetch routes-large.kite (same URL, 'large')."
      return 0
    fi
    err "Failed to download routes-small.kite."
    return 1
  fi
  return 1
}

# Report (and optionally install) every dependency.
check_dependencies() {
  local install="$1"   # 1 = try to install what is missing

  ok "== Base dependencies =="
  local base_missing=0
  for bin in curl grep sed awk python3 pip3 git tar; do
    if command -v "$bin" >/dev/null 2>&1; then
      echo "  [ok]      $bin" >&2
    else
      echo "  [MISSING] $bin" >&2
      base_missing=1
    fi
  done
  [ "$base_missing" -eq 1 ] && warn "Install the missing base tools (e.g. sudo apt install curl git python3-pip)"

  ok "== Python modules (SecretFinder) =="
  local py_need=()
  for pair in "${PY_DEPS[@]}"; do
    if pymod_ok "${pair%%:*}"; then
      echo "  [ok]      ${pair%%:*}" >&2
    else
      echo "  [MISSING] ${pair%%:*} (package: ${pair##*:})" >&2
      py_need+=( "${pair##*:}" )
    fi
  done
  if [ "${#py_need[@]}" -gt 0 ] && [ "$install" -eq 1 ]; then
    pip_install "${py_need[@]}" && ok "Python modules installed" \
      || err "Failed to install: ${py_need[*]}"
  fi

  ok "== SecretFinder =="
  if [ -f "$SECRETFINDER_PATH" ]; then
    echo "  [ok]      $SECRETFINDER_PATH" >&2
  else
    echo "  [MISSING] $SECRETFINDER_PATH" >&2
    [ "$install" -eq 1 ] && ensure_secretfinder
  fi

  ok "== Wordlists =="
  local sl kite
  if sl="$(find_seclists)"; then
    echo "  [ok]      SecLists ($sl)" >&2
  else
    echo "  [MISSING] SecLists  ->  sudo apt install seclists  (or --install-deps to clone into ./SecLists)" >&2
    [ "$install" -eq 1 ] && ensure_seclists
  fi
  if kite="$(find_kite_wordlist)"; then
    echo "  [ok]      kiterunner routes ($kite)" >&2
  else
    echo "  [MISSING] kiterunner routes (.kite)  ->  --install-deps downloads routes-small.kite into ${KITE_DIR}/" >&2
    [ "$install" -eq 1 ] && ensure_kite_wordlist
  fi

  ok "== Optional external tools =="
  # name:command:install_hint
  local tools=(
    "Sublist3r:sublist3r:git clone https://github.com/aboul3la/Sublist3r.git"
    "Gau:gau:go install github.com/lc/gau/v2/cmd/gau@latest"
    "Naabu:naabu:go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest  (needs libpcap-dev)"
    "Ffuf:ffuf:go install github.com/ffuf/ffuf/v2@latest   (or sudo apt install ffuf)"
    "TruffleHog:trufflehog:sudo apt install trufflehog  (or https://github.com/trufflesecurity/trufflehog/releases)"
    "Gitleaks:gitleaks:sudo apt install gitleaks  (or go install github.com/zricethezav/gitleaks/v8@latest)"
    "Kiterunner:kr:release binary from https://github.com/assetnote/kiterunner/releases  (or git clone + make build)"
    "Dirsearch (ffuf fallback):dirsearch:git clone https://github.com/maurosoria/dirsearch.git"
    "Gf:gf:go install github.com/tomnomnom/gf@latest  (+ git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf)"
    "WhatWeb:whatweb:sudo apt install whatweb   (or gem install whatweb)"
    "WPScan:wpscan:sudo apt install wpscan   (or gem install wpscan)"
    "Nuclei:nuclei:go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "searchsploit:searchsploit:sudo apt install exploitdb   (local Exploit-DB, optional)"
  )
  # httpx: the Python "httpx" CLI shares the name with ProjectDiscovery's httpx
  # (Kali ships the latter as "httpx-toolkit"); report which one will be used.
  if find_httpx >/dev/null; then
    echo "  [ok]      Httpx ($(find_httpx), ProjectDiscovery)" >&2
  else
    echo "  [MISSING] Httpx (ProjectDiscovery)  ->  sudo apt install httpx-toolkit  (or go install github.com/projectdiscovery/httpx/cmd/httpx@latest)" >&2
    command -v httpx >/dev/null 2>&1 && echo "            note: the 'httpx' in PATH is not ProjectDiscovery's (probably the Python CLI)" >&2
  fi
  for t in "${tools[@]}"; do
    local name rest cmd hint
    name="${t%%:*}"
    rest="${t#*:}"
    cmd="${rest%%:*}"
    hint="${rest#*:}"
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "  [ok]      $name ($cmd)" >&2
    else
      echo "  [MISSING] $name  ->  $hint" >&2
    fi
  done
  warn "Go tools need Go installed (sudo apt install golang-go) and \$HOME/go/bin in PATH."

  ok "== API keys ($ENV_FILE) =="
  load_env
  for pair in "WPSCAN_API_TOKEN:WPScan (vulnerability database)" "PDCP_API_KEY:ProjectDiscovery/Nuclei (optional)"; do
    if [ -n "$(printenv "${pair%%:*}" 2>/dev/null || true)" ]; then
      echo "  [ok]      ${pair%%:*} (${pair#*:})" >&2
    else
      echo "  [MISSING] ${pair%%:*} (${pair#*:}) — will be asked for at runtime, or set it in $ENV_FILE" >&2
    fi
  done
}

# ---------------------------------------------------------------------------
# Rotating User-Agent
# ---------------------------------------------------------------------------
current_ua() {
  if [ "$CUSTOM_AGENT" -eq 1 ]; then
    local idx=$(( (REQ_COUNT / 5) % ${#UA_POOL[@]} ))
    echo "${UA_POOL[$idx]}"
  else
    echo "$UA_FIXED"
  fi
}

fetch() {
  local target="$1" ua
  ua="$(current_ua)"
  REQ_COUNT=$((REQ_COUNT + 1))
  vlog "[req #$REQ_COUNT] UA=$ua -> $target"
  curl -s -L -A "$ua" --max-time "$TIMEOUT" "$target"
}

fetch_headers() {
  local target="$1" ua
  ua="$(current_ua)"
  REQ_COUNT=$((REQ_COUNT + 1))
  vlog "[req #$REQ_COUNT] UA=$ua -> HEAD $target"
  curl -s -I -L -A "$ua" --max-time "$TIMEOUT" "$target"
}

# Download <url> to <file> WITHOUT a subshell, so REQ_COUNT is kept.
# Sets FETCH_CODE (HTTP status, 000 on network error) and FETCH_EFFECTIVE
# (final URL after redirects).
FETCH_CODE="000"; FETCH_EFFECTIVE=""
fetch_to() {
  local target="$1" out="$2" ua res
  ua="$(current_ua)"
  REQ_COUNT=$((REQ_COUNT + 1))
  vlog "[req #$REQ_COUNT] UA=$ua -> $target"
  mkdir -p "$(dirname "$out")" 2>/dev/null
  res="$(curl -s -L -A "$ua" --max-time "$TIMEOUT" -o "$out" -w '%{http_code} %{url_effective}' "$target" 2>/dev/null)"
  FETCH_CODE="${res%% *}"
  FETCH_EFFECTIVE="${res#* }"
  [ -z "$FETCH_CODE" ] && FETCH_CODE="000"
  return 0
}

# ---------------------------------------------------------------------------
# Resolve a relative/absolute path -> full URL
# ---------------------------------------------------------------------------
resolve_url() {
  local path="$1"
  case "$path" in
    http://*|https://*) echo "$path" ;;
    //*)                echo "https:${path}" ;;
    /*)                 echo "${BASE_SCHEME_HOST}${path}" ;;
    *)                  echo "${BASE_DIR}${path}" ;;
  esac
}

extract_js_paths() {
  local content="$1"
  echo "$content" | grep -oE '(["'"'"'(])[a-zA-Z0-9_./@-]*\.js(["'"'"')?])' \
    | sed -E 's/^["'"'"'(]//; s/["'"'"')?]$//' \
    | grep -v '^$'
  echo "$content" | grep -oE '(src|href)=["'"'"'][^"'"'"']+\.js(\?[^"'"'"']*)?["'"'"']' \
    | sed -E 's/^(src|href)=["'"'"']//; s/["'"'"']$//'
}

# ---------------------------------------------------------------------------
# Mode: -files (extract + DOWNLOAD the JS into the target folder)
# ---------------------------------------------------------------------------
run_files() {
  vlog "Fetching home page: $URL"
  local html
  html="$(fetch "$URL")"
  [ -z "$html" ] && { err "Failed to fetch content from $URL"; return 1; }

  local raw_list final_list
  raw_list="$(extract_js_paths "$html" | sort -u)"

  final_list=""
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    final_list+="$(resolve_url "$path")"$'\n'
  done <<< "$raw_list"
  # Merge with any JS discovered via gau (-U) when that ran first.
  [ -s "${RESDIR}/files-js-gau.txt" ] && final_list+="$(cat "${RESDIR}/files-js-gau.txt")"$'\n'
  final_list="$(echo "$final_list" | grep -v '^$' | sort -u)"

  local total
  total=$(echo "$final_list" | grep -c . || true)
  ok "Unique JS files: $total"

  local list_path="${OUT_FILE:-${RESDIR}/files-js.txt}"
  echo "$final_list" > "$list_path"
  ok "List saved to: $list_path"

  local ok_n=0 fail_n=0
  : > "${RESDIR}/js-failed.txt"
  while IFS= read -r jsurl; do
    [ -z "$jsurl" ] && continue
    local fname
    fname="$(echo "$jsurl" | sed -E 's#https?://##; s#\?.*$##; s#[^a-zA-Z0-9._-]#_#g')"
    fetch_to "$jsurl" "${JSDIR}/${fname}"
    if [ "$FETCH_CODE" = "200" ] && [ -s "${JSDIR}/${fname}" ]; then
      ok_n=$((ok_n + 1))
    else
      fail_n=$((fail_n + 1))
      echo "$jsurl [HTTP $FETCH_CODE]" >> "${RESDIR}/js-failed.txt"
      rm -f "${JSDIR}/${fname}" 2>/dev/null
    fi
  done <<< "$final_list"
  ok "JS downloaded to $JSDIR ($ok_n ok, $fail_n failed)"
  [ "$fail_n" -gt 0 ] && vlog "Failed downloads listed in ${RESDIR}/js-failed.txt"
}

# ---------------------------------------------------------------------------
# Mode: -secret (SecretFinder + TruffleHog + Gitleaks)
# ---------------------------------------------------------------------------
# SecretFinder runs its regexes over each JS URL/HTML. TruffleHog and Gitleaks
# scan the already-downloaded files on disk (js/). TruffleHog verifies the
# secrets it finds against the provider APIs (unless --no-verify); Gitleaks
# findings that land on the same file+line as a verified TruffleHog secret are
# flagged as confirmed in the consolidated report.
run_secret() {
  run_secretfinder
  run_trufflehog
  run_gitleaks
  consolidate_secrets
}

run_secretfinder() {
  ensure_secretfinder || { warn "Skipping SecretFinder"; return 1; }
  ensure_python_deps  || { warn "Skipping SecretFinder"; return 1; }

  local list_file="${RESDIR}/files-js.txt"
  if [ -n "$JS_LIST_FILE" ] && [ -f "$JS_LIST_FILE" ]; then
    cp "$JS_LIST_FILE" "$list_file"
  elif [ ! -f "$list_file" ]; then
    run_files
  fi
  echo "$URL" >> "$list_file"
  sort -u -o "$list_file" "$list_file"

  local total
  total=$(grep -c . "$list_file" || true)
  ok "[SecretFinder] Analyzing $total file(s)"

  local json_out="[" first=1
  while IFS= read -r target; do
    [ -z "$target" ] && continue
    vlog "SecretFinder -> $target"
    if [ "$JSON" -eq 1 ]; then
      local result esc
      result="$(python3 "$SECRETFINDER_PATH" -i "$target" -o cli 2>/dev/null)"
      if [ -n "$result" ]; then
        esc="$(python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' <<< "$result")"
        [ "$first" -eq 0 ] && json_out+=","
        json_out+="{\"target\":\"$target\",\"output\":$esc}"
        first=0
      fi
    else
      python3 "$SECRETFINDER_PATH" -i "$target" -o cli
    fi
  done < "$list_file"

  if [ "$JSON" -eq 1 ]; then
    json_out+="]"
    local out="${OUT_FILE:-${RESDIR}/secrets.json}"
    echo "$json_out" > "$out"
    ok "[SecretFinder] JSON result saved to: $out"
  fi
}

# TruffleHog: filesystem scan of the downloaded JS, with live verification.
run_trufflehog() {
  if ! command -v trufflehog >/dev/null 2>&1; then
    warn "TruffleHog not found. Install: sudo apt install trufflehog  (or a release from"
    warn "  https://github.com/trufflesecurity/trufflehog/releases)"
    return 1
  fi
  if [ ! -d "$JSDIR" ] || [ -z "$(ls -A "$JSDIR" 2>/dev/null)" ]; then
    vlog "[TruffleHog] no downloaded files in $JSDIR; running -f first"
    run_files
  fi

  local out="${RESDIR}/trufflehog.jsonl"
  local -a args=( filesystem "$JSDIR" --json --no-update )
  if [ "$SECRET_VERIFY" -eq 1 ]; then
    ok "[TruffleHog] Scanning $JSDIR (with verification)"
  else
    args+=( --no-verification )
    ok "[TruffleHog] Scanning $JSDIR (verification disabled)"
  fi

  # TruffleHog prints one JSON object per finding to stdout.
  trufflehog "${args[@]}" 2>/dev/null > "$out" || warn "TruffleHog returned an error code (continuing anyway)"

  local total verified
  total=$(grep -c '"SourceMetadata"' "$out" 2>/dev/null || echo 0)
  verified=$(grep -c '"Verified":true' "$out" 2>/dev/null || echo 0)
  ok "[TruffleHog] ${total} finding(s), ${verified} verified — ${out}"
  [ "$verified" -gt 0 ] && warn "[TruffleHog] ${verified} VERIFIED secret(s) — live and valid, triage immediately"
}

# Gitleaks: filesystem scan of the downloaded JS (regex + entropy).
run_gitleaks() {
  if ! command -v gitleaks >/dev/null 2>&1; then
    warn "Gitleaks not found. Install: sudo apt install gitleaks  (or go install"
    warn "  github.com/zricethezav/gitleaks/v8@latest)"
    return 1
  fi
  if [ ! -d "$JSDIR" ] || [ -z "$(ls -A "$JSDIR" 2>/dev/null)" ]; then
    vlog "[Gitleaks] no downloaded files in $JSDIR; running -f first"
    run_files
  fi

  local out="${RESDIR}/gitleaks.json"
  # Gitleaks v8: "directory" source; older builds used "detect --no-git".
  local -a args=( dir "$JSDIR" --report-format json --report-path "$out" --exit-code 0 )
  [ "$NO_COLOR" -eq 1 ] && args+=( --no-color )
  ok "[Gitleaks] Scanning $JSDIR"
  if ! gitleaks "${args[@]}" >/dev/null 2>&1; then
    # Fallback for gitleaks < 8.19 where the subcommand is "detect".
    gitleaks detect --source "$JSDIR" --no-git --report-format json \
      --report-path "$out" --exit-code 0 >/dev/null 2>&1 \
      || warn "Gitleaks returned an error code (continuing anyway)"
  fi

  local total
  total=$(python3 -c 'import json,sys
try: print(len(json.load(open(sys.argv[1]))))
except Exception: print(0)' "$out" 2>/dev/null || echo 0)
  ok "[Gitleaks] ${total} finding(s) — ${out}"
}

# Merge TruffleHog + Gitleaks into one redacted report and cross-check them.
consolidate_secrets() {
  local out="${RESDIR}/secrets-all.txt"
  python3 - "${RESDIR}/trufflehog.jsonl" "${RESDIR}/gitleaks.json" "$out" <<'PY' 2>/dev/null || return 0
import json, os, sys

th_path, gl_path, out_path = sys.argv[1:4]

def redact(s):
    s = (s or "").strip().replace("\n", " ")
    if len(s) <= 10:
        return "*" * len(s)
    return s[:4] + "..." + s[-4:]

verified_locs = set()   # (file, line) with a TruffleHog-verified secret
th_rows = []
try:
    with open(th_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
            except ValueError:
                continue
            det = d.get("DetectorName", "?")
            ver = bool(d.get("Verified"))
            meta = (((d.get("SourceMetadata") or {}).get("Data") or {}).get("Filesystem") or {})
            fpath = meta.get("file", "")
            line_no = meta.get("line", "")
            raw = d.get("Raw") or d.get("RawV2") or ""
            if ver and fpath:
                verified_locs.add((os.path.basename(fpath), str(line_no)))
            th_rows.append((det, ver, os.path.basename(fpath), str(line_no), redact(raw)))
except FileNotFoundError:
    pass

gl_rows = []
try:
    data = json.load(open(gl_path))
    for d in data if isinstance(data, list) else []:
        rule = d.get("RuleID", "?")
        fpath = os.path.basename(d.get("File", ""))
        line_no = str(d.get("StartLine", ""))
        confirmed = (fpath, line_no) in verified_locs
        gl_rows.append((rule, fpath, line_no, confirmed, redact(d.get("Secret", ""))))
except (FileNotFoundError, ValueError):
    pass

th_ver = sum(1 for r in th_rows if r[1])
gl_conf = sum(1 for r in gl_rows if r[3])
with open(out_path, "w") as f:
    f.write("# Consolidated secrets report (values redacted)\n")
    f.write(f"# TruffleHog: {len(th_rows)} finding(s), {th_ver} verified\n")
    f.write(f"# Gitleaks:   {len(gl_rows)} finding(s), {gl_conf} confirmed by TruffleHog\n\n")
    f.write("## TruffleHog\n")
    for det, ver, fp, ln, red in th_rows:
        tag = "VERIFIED" if ver else "unverified"
        f.write(f"  [{tag}] {det} {fp}:{ln} {red}\n")
    if not th_rows:
        f.write("  (none)\n")
    f.write("\n## Gitleaks\n")
    for rule, fp, ln, conf, red in gl_rows:
        tag = "CONFIRMED (TruffleHog-verified)" if conf else "unconfirmed"
        f.write(f"  [{tag}] {rule} {fp}:{ln} {red}\n")
    if not gl_rows:
        f.write("  (none)\n")

print(f"{len(th_rows)} {th_ver} {len(gl_rows)} {gl_conf}")
PY
  [ -s "$out" ] && ok "[secrets] Consolidated report: $out"
}

# ---------------------------------------------------------------------------
# Technology registry for the vulnerability-validation stage.
# Each line: normalized_name|version (version may be empty).
# Consumed by run_vuln_validation() at the end of the recon.
# ---------------------------------------------------------------------------
record_tech() {
  local name="$1" ver="${2:-}"
  [ -z "$name" ] && return 0
  echo "${name}|${ver}" >> "${RESDIR}/tech-detected.txt"
}

# ---------------------------------------------------------------------------
# Mode: -tech (with a version guess)
# ---------------------------------------------------------------------------
detect_version() {
  local combined="$1" tech="$2"
  case "$tech" in
    jQuery)
      echo "$combined" | grep -oE 'jQuery v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' ;;
    "React")
      echo "$combined" | grep -oE '"react"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' ;;
    "Next.js")
      echo "$combined" | grep -oiE 'next\.js[[:space:]]+v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' ;;
    "Vue.js")
      echo "$combined" | grep -oE 'Vue\.js v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' ;;
    "Angular")
      echo "$combined" | grep -oE 'ng-version=["'"'"'][0-9]+\.[0-9]+\.[0-9]+["'"'"']' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' ;;
    "Bootstrap")
      echo "$combined" | grep -oE 'Bootstrap v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' ;;
    "WordPress")
      echo "$combined" | grep -oiE 'wordpress[[:space:]]+[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' ;;
    "PHP")
      echo "$combined" | grep -oiE 'php/[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' ;;
    "Nginx")
      echo "$combined" | grep -oiE 'nginx/[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' ;;
    "Apache")
      echo "$combined" | grep -oiE 'apache/[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' ;;
  esac
}

run_tech() {
  local headers html
  headers="$(fetch_headers "$URL")"
  html="$(fetch "$URL")"

  declare -A found
  local server powered gen
  server=$(echo "$headers" | grep -i '^server:' | sed -E 's/^[Ss]erver:\s*//I' | tr -d '\r')
  powered=$(echo "$headers" | grep -i '^x-powered-by:' | sed -E 's/^[Xx]-[Pp]owered-[Bb]y:\s*//I' | tr -d '\r')
  gen=$(echo "$html" | grep -oiE '<meta[^>]*name=["'"'"']generator["'"'"'][^>]*content=["'"'"'][^"'"'"']+["'"'"']' | grep -oE 'content=["'"'"'][^"'"'"']+["'"'"']' | sed -E 's/content=["'"'"']//; s/["'"'"']$//')

  [ -n "$server" ]  && found["Server"]="$server"
  [ -n "$powered" ] && found["X-Powered-By"]="$powered"
  [ -n "$gen" ]     && found["Generator"]="$gen"

  declare -A patterns=(
    ["React"]='data-reactroot|react-dom|__NEXT_DATA__'
    ["Next.js"]='_next/static|__NEXT_DATA__'
    ["Vue.js"]='__vue__|vue\.runtime|data-v-'
    ["Nuxt.js"]='__NUXT__|_nuxt/'
    ["Angular"]='ng-version|angular\.min\.js'
    ["jQuery"]='jquery(\.min)?\.js'
    ["Webpack"]='webpackJsonp|__webpack_require__'
    ["Turbopack"]='turbopack'
    ["Tailwind CSS"]='tailwind'
    ["WordPress"]='wp-content|wp-includes'
    ["Bootstrap"]='bootstrap(\.min)?\.(js|css)'
    ["Cloudflare"]='cloudflare'
    ["Google Analytics"]='gtag\(|googletagmanager\.com'
  )

  local combined="$html
$headers"

  for tech in "${!patterns[@]}"; do
    if echo "$combined" | grep -qiE "${patterns[$tech]}"; then
      local ver
      ver="$(detect_version "$combined" "$tech")"
      if [ -n "$ver" ]; then
        found["$tech"]="version $ver"
      else
        found["$tech"]="detected (version not identified)"
      fi
    fi
  done

  for t in Nginx Apache PHP; do
    local v
    v="$(detect_version "$combined" "$t")"
    [ -n "$v" ] && found["$t"]="version $v"
  done

  if [ -z "${found[*]+x}" ]; then
    warn "No technology identified with the current heuristics"
  fi

  # Register targets of interest for the end-of-run vulnerability validation.
  local server_lc
  server_lc="$(echo "$server" | tr '[:upper:]' '[:lower:]')"
  if echo "$combined" | grep -qiE 'wp-content|wp-includes|wordpress'; then
    record_tech wordpress "$(detect_version "$combined" WordPress)"
  fi
  case "$server_lc" in
    *nginx*)  record_tech nginx  "$(detect_version "$combined" Nginx)" ;;
  esac
  case "$server_lc" in
    *apache*) record_tech apache "$(detect_version "$combined" Apache)" ;;
  esac

  if [ "$JSON" -eq 1 ]; then
    local json_out="{" first=1
    [ -n "${found[*]+x}" ] && for key in "${!found[@]}"; do
      [ "$first" -eq 0 ] && json_out+=","
      local esc_val
      esc_val="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${found[$key]}")"
      json_out+="\"$key\":$esc_val"
      first=0
    done
    json_out+="}"
    local out="${OUT_FILE:-${RESDIR}/tech.json}"
    echo "$json_out" > "$out"
    ok "JSON result saved to: $out"
  else
    ok "Technologies identified for $URL:"
    if [ -n "${found[*]+x}" ]; then
      for key in "${!found[@]}"; do
        echo "  - $key: ${found[$key]}"
      done | tee "${RESDIR}/tech.txt" >&2
    fi
  fi
}

# ---------------------------------------------------------------------------
# Security headers analysis vs. the OWASP Cheat Sheet
# ---------------------------------------------------------------------------
# Compares the response headers with OWASP best practices:
#   * highlights MISSING security headers;
#   * highlights PRESENT information-disclosure headers.
# Saves a per-target detail and feeds the consolidated report ($HEADERS_REPORT).
analyze_security_headers() {
  local headers block
  headers="$(fetch_headers "$URL")"
  if [ -z "$headers" ]; then
    warn "[owasp-headers] No headers to analyze for $URL"
    return 1
  fi
  # Keep only the FINAL response block (after the last redirect hop). Strip \r
  # BEFORE splitting on the blank line: with CRLF the separator between hops
  # keeps a stray \r and awk (paragraph mode) would not split the blocks.
  block="$(echo "$headers" | tr -d '\r' | awk 'BEGIN{RS="";} {b=$0} END{print b}')"
  [ -z "$block" ] && block="$(echo "$headers" | tr -d '\r')"

  # X-Frame-Options may be satisfied by CSP frame-ancestors.
  local has_csp_fa=0
  echo "$block" | grep -qiE '^content-security-policy:.*frame-ancestors' && has_csp_fa=1

  local -a present=() missing=() missing_desc=() leaks=()
  local pair name desc total=0 have=0
  for pair in "${OWASP_SEC_HEADERS[@]}"; do
    name="${pair%%|*}"; desc="${pair#*|}"
    total=$((total + 1))
    if echo "$block" | grep -qiE "^${name}:"; then
      present+=("$name"); have=$((have + 1))
    elif [ "$name" = "X-Frame-Options" ] && [ "$has_csp_fa" -eq 1 ]; then
      present+=("X-Frame-Options (via CSP frame-ancestors)"); have=$((have + 1))
    else
      missing+=("$name"); missing_desc+=("${name} -> ${desc}")
    fi
  done

  local val
  for pair in "${OWASP_DISCLOSURE_HEADERS[@]}"; do
    name="${pair%%|*}"
    val="$(echo "$block" | grep -iE "^${name}:" | head -1 | sed -E 's/^[^:]*:[[:space:]]*//' | tr -d '\r')"
    [ -n "$val" ] && leaks+=("${name}: ${val}")
  done

  # ---------- Visible log ----------
  ok "[owasp-headers] $URL — ${have}/${total} security headers present"
  if [ "${#missing[@]}" -gt 0 ]; then
    err "[owasp-headers] SECURITY MISSING (${#missing[@]}): $(join_by ', ' "${missing[@]}")"
  else
    ok "[owasp-headers] No security header missing"
  fi
  if [ "${#leaks[@]}" -gt 0 ]; then
    warn "[owasp-headers] INFO DISCLOSURE (${#leaks[@]}): $(join_by ' | ' "${leaks[@]}")"
  fi

  # ---------- Per-target detail ----------
  local out="${RESDIR}/security-headers.txt"
  {
    echo "# Security headers analysis (OWASP) — $URL"
    echo "# Ref: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
    echo
    echo "Score: ${have}/${total} security headers present"
    echo
    echo "Present:"
    if [ "${#present[@]}" -gt 0 ]; then
      for h in "${present[@]}"; do echo "  [+] $h"; done
    else
      echo "  (none)"
    fi
    echo
    echo "MISSING (implement):"
    if [ "${#missing_desc[@]}" -gt 0 ]; then
      for h in "${missing_desc[@]}"; do echo "  [-] $h"; done
    else
      echo "  (none)"
    fi
    echo
    echo "Information disclosure (remove/hide):"
    if [ "${#leaks[@]}" -gt 0 ]; then
      for l in "${leaks[@]}"; do echo "  [!] $l"; done
    else
      echo "  (none)"
    fi
  } > "$out"
  ok "[owasp-headers] Detail saved to: $out"

  # ---------- Consolidated report (all targets) ----------
  {
    echo "## ${URL}"
    echo "- Score: ${have}/${total} security headers present"
    if [ "${#missing[@]}" -gt 0 ]; then
      echo "- **MISSING** security headers: $(join_by ', ' "${missing[@]}")"
    else
      echo "- MISSING security headers: none"
    fi
    if [ "${#leaks[@]}" -gt 0 ]; then
      echo "- Information disclosure: $(join_by ' | ' "${leaks[@]}")"
    fi
    echo
  } >> "$HEADERS_REPORT"
}

# ---------------------------------------------------------------------------
# Mode: -tech-deep (deep fingerprint with WhatWeb)
# ---------------------------------------------------------------------------
# Runs WhatWeb at aggression 3, random User-Agent, verbose + JSON logs.
# The JSON is parsed to feed the vulnerability-validation stage
# (WordPress -> wpscan; Nginx/Apache -> nuclei/searchsploit).
run_tech_deep() {
  if ! command -v whatweb >/dev/null 2>&1; then
    warn "WhatWeb not found. Install: sudo apt install whatweb  (or gem install whatweb)"
    # Still run the OWASP header analysis, which does not depend on WhatWeb.
    analyze_security_headers
    return 1
  fi

  local random="${RANDOM}${RANDOM}"
  local verbose_log="${RESDIR}/whatweb_verbose.txt"
  local json_log="${RESDIR}/whatweb.json"

  ok "[tech-deep] WhatWeb (aggression=3) on $URL"

  local -a args=(
    "$URL"
    --user-agent="$(current_ua)"
    --aggression=3
    --quiet
    --log-verbose="$verbose_log"
    --log-json="$json_log"
    --max-threads=5
  )
  if [ "$NO_COLOR" -eq 1 ]; then
    args+=( --colour=never )
  else
    args+=( --colour=always )
  fi

  whatweb "${args[@]}" >/dev/null 2>&1 || warn "WhatWeb returned an error code (continuing anyway)"
  ok "[tech-deep] Full logs saved to: $verbose_log and $json_log"

  # Extract plugins of interest from the JSON, register them for the vuln stage
  # AND print a short console overview (without dumping the whole JSON/verbose).
  if [ -s "$json_log" ]; then
    local summary
    summary="$(python3 - "$json_log" "${RESDIR}/tech-detected.txt" <<'PY'
import json, sys

json_path, techfile = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(json_path))
except Exception:
    print("")
    sys.exit(0)

NOISE = {
    "uncommonheaders", "md5", "title", "cookies", "headerhash",
    "footerhash", "taghash", "country", "ip",
}

def first_version(info):
    if isinstance(info, dict):
        v = info.get("version") or []
        if isinstance(v, list):
            v = [str(x) for x in v if x]
            return v[0] if v else ""
        return str(v) if v else ""
    return ""

def http_kind(info):
    s = ""
    if isinstance(info, dict):
        ss = info.get("string") or []
        if isinstance(ss, list) and ss:
            s = " ".join(str(x) for x in ss).lower()
        elif isinstance(ss, str):
            s = ss.lower()
    return s

techlines = []
display = []
status = None

for entry in (data if isinstance(data, list) else [data]):
    if not isinstance(entry, dict):
        continue
    status = entry.get("http_status", status)
    plugins = entry.get("plugins", {}) or {}
    for name, info in plugins.items():
        ln = name.lower()
        ver = first_version(info)
        if ln == "wordpress":
            techlines.append(f"wordpress|{ver}")
        elif ln == "nginx":
            techlines.append(f"nginx|{ver}")
        elif ln in ("apache", "apache-modules"):
            techlines.append(f"apache|{ver}")
        elif ln == "httpserver":
            s = http_kind(info)
            if "nginx" in s:
                techlines.append(f"nginx|{ver}")
            elif "apache" in s:
                techlines.append(f"apache|{ver}")
        if ln not in NOISE:
            display.append(f"{name} {ver}".strip())

with open(techfile, "a") as f:
    for line in techlines:
        f.write(line + "\n")

total = len(display)
preview = ", ".join(display[:8])
extra = total - min(8, total)
out = f"{total} technolog{'y' if total == 1 else 'ies'} identified"
if status:
    out += f" | HTTP {status}"
if preview:
    out += f": {preview}"
    if extra > 0:
        out += f" (+{extra} more)"
print(out)
PY
)"
    if [ -n "$summary" ]; then
      ok "[tech-deep] $summary"
    fi
    vlog "[tech-deep] WhatWeb technologies registered for validation"
  fi

  # Security headers analysis vs. OWASP (highlights the missing ones).
  analyze_security_headers
}

# ---------------------------------------------------------------------------
# Vulnerability validation (runs at the END of the recon)
# WordPress  -> WPScan (validates vulnerable plugins/themes + users)
# Nginx      -> Nuclei (templates by tag) + searchsploit by version
# Apache     -> Nuclei (templates by tag) + searchsploit by version
# ---------------------------------------------------------------------------

# WPScan: checks whether the WordPress install is vulnerable.
run_wpscan() {
  if ! command -v wpscan >/dev/null 2>&1; then
    warn "WPScan not found. Install: sudo apt install wpscan  (or gem install wpscan)"
    return 1
  fi

  # --ignore-main-redirect does NOT follow the redirect (it just avoids WPScan's
  # interactive prompt and forces the scan on the original URL). So we resolve
  # the final URL here and point WPScan at it ONLY when the destination is the
  # same host/subdomain (deliberately never following off to a third-party host).
  local target_url="$URL" effective host_eff
  effective="$(curl -s -o /dev/null -w '%{url_effective}' -L -A "$(current_ua)" --max-time "$TIMEOUT" "$URL" 2>/dev/null)"
  REQ_COUNT=$((REQ_COUNT + 1))
  if [ -n "$effective" ] && [ "$effective" != "$URL" ]; then
    host_eff="$(echo "$effective" | awk -F/ '{print $3}' | sed -E 's/:.*$//')"
    if [ "$host_eff" = "$DOMAIN" ] || [[ "$host_eff" == *".$DOMAIN" ]] || [[ "$DOMAIN" == *".$host_eff" ]]; then
      ok "[WordPress] $URL redirects to $effective (same host) — WPScan will use the destination"
      target_url="$effective"
    else
      warn "[WordPress] $URL redirects to another host ($host_eff) — keeping the original URL for safety"
    fi
  fi

  ok "[WordPress] Validating vulnerabilities with WPScan -> $target_url"

  local out_txt="${RESDIR}/wpscan.txt"
  local -a args=(
    --url "$target_url"
    --enumerate "$WPSCAN_ENUM"
    --detection-mode "$WPSCAN_DETECTION"
    --plugins-detection "$WPSCAN_DETECTION"
    --random-user-agent
    --stealthy
    --force                      # do not abort if WPScan is unsure it is WordPress (we detected it)
    --ignore-main-redirect
    --disable-tls-checks
    --request-timeout "$TIMEOUT"
    --connect-timeout "$TIMEOUT"
  )
  [ "$NO_COLOR" -eq 1 ] && args+=( --no-color )

  local token
  token="$(printenv WPSCAN_API_TOKEN 2>/dev/null || true)"
  if [ -n "$token" ]; then
    args+=( --api-token "$token" )
  else
    warn "No WPSCAN_API_TOKEN: running without the vulnerability database (limited results)."
    warn "  Get a free token at https://wpscan.com/api and run again."
  fi

  # Single pass: show on screen and save to file.
  wpscan "${args[@]}" 2>&1 | tee "$out_txt" >&2
  ok "[WordPress] WPScan output saved to: $out_txt"
}

# Nuclei: looks for known vulnerabilities by technology tag (nginx/apache) plus
# generic CVEs. Reads PDCP_API_KEY from the environment when set.
run_nuclei() {
  local -a tags=("$@")
  if ! command -v nuclei >/dev/null 2>&1; then
    warn "Nuclei not found. Install:"
    warn "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    return 1
  fi

  # Merge detected tags with any user-supplied extra tags (--nuclei-tags).
  local t
  if [ -n "$NUCLEI_EXTRA_TAGS" ]; then
    IFS=',' read -ra _extra <<< "$NUCLEI_EXTRA_TAGS"
    for t in "${_extra[@]}"; do
      t="$(echo "$t" | tr -d '[:space:]')"
      [ -n "$t" ] && tags+=("$t")
    done
  fi

  local tagcsv
  tagcsv="$(IFS=,; echo "${tags[*]:-}")"
  ok "[Vuln] Nuclei on $URL (tags: ${tagcsv:-generic cves})"

  local out="${RESDIR}/nuclei.txt"
  local jsonl="${RESDIR}/nuclei.jsonl"
  local -a args=(
    -u "$URL"
    -o "$out"
    -jsonl-export "$jsonl"
    -stats
    -timeout "$TIMEOUT"
    -retries 1
    -rl 50
    -fr
    -mr 5
    -duc                              # don't auto-update mid-run (self_update already did)
    -severity low,medium,high,critical
  )
  [ -n "$tagcsv" ] && args+=( -tags "$tagcsv" )
  [ "$NO_COLOR" -eq 1 ] && args+=( -nc )
  # PDCP_API_KEY is read automatically from the environment by nuclei (optional upload).

  nuclei "${args[@]}" >&2 || warn "Nuclei returned an error code (continuing anyway)"
  ok "[Vuln] Nuclei result saved to: $out"
}

# searchsploit: maps a detected version -> known exploits (local Exploit-DB).
run_searchsploit() {
  local name="$1" ver="${2:-}"
  command -v searchsploit >/dev/null 2>&1 || return 0   # optional complement
  [ -z "$ver" ] && { vlog "searchsploit: no version for '$name', skipping"; return 0; }
  ok "[Vuln] searchsploit '$name $ver'"
  # Piping disables colour automatically; --nmap not needed. Keep terms ANDed.
  searchsploit "$name" "$ver" 2>/dev/null | tee -a "${RESDIR}/searchsploit.txt" >&2 || true
}

# Orchestrates validation based on what -tech and/or -tech-deep detected.
run_vuln_validation() {
  local detfile="${RESDIR}/tech-detected.txt"
  if [ ! -s "$detfile" ]; then
    vlog "No technology registered; nothing to validate."
    return 0
  fi
  sort -u -o "$detfile" "$detfile"

  local wp=0
  local -a nuclei_tags=()
  local name ver
  while IFS='|' read -r name ver; do
    [ -z "$name" ] && continue
    case "$name" in
      wordpress) wp=1 ;;
      nginx)  nuclei_tags+=(nginx);  run_searchsploit "nginx"  "$ver" ;;
      apache) nuclei_tags+=(apache); run_searchsploit "apache" "$ver" ;;
    esac
  done < "$detfile"

  if [ "$wp" -eq 1 ]; then
    ok "== Vulnerability validation: WordPress =="
    run_wpscan
  fi

  if [ "${#nuclei_tags[@]}" -gt 0 ]; then
    ok "== Vulnerability validation: Nginx/Apache =="
    # Deduplicate tags while preserving order.
    local -A _t=(); local -a uniq=()
    local t
    for t in "${nuclei_tags[@]}"; do
      [ -n "${_t[$t]:-}" ] && continue
      _t["$t"]=1; uniq+=("$t")
    done
    run_nuclei "${uniq[@]}"
  fi

  if [ "$wp" -eq 0 ] && [ "${#nuclei_tags[@]}" -eq 0 ]; then
    vlog "No WordPress/Nginx/Apache detected; nothing to validate."
  fi
}

# ---------------------------------------------------------------------------
# Mode: -subdomains (Sublist3r when available, crt.sh fallback)
# ---------------------------------------------------------------------------
run_subdomains() {
  local out="${OUT_FILE:-${RESDIR}/subdomains.txt}"
  if command -v sublist3r >/dev/null 2>&1; then
    ok "Using Sublist3r"
    sublist3r -d "$DOMAIN" -o "$out"
  elif [ -f "./Sublist3r/sublist3r.py" ]; then
    ok "Using Sublist3r (local script)"
    python3 ./Sublist3r/sublist3r.py -d "$DOMAIN" -o "$out"
  else
    warn "Sublist3r not found. Using the crt.sh fallback (equivalent to Ctfr)"
    warn "Install with: git clone https://github.com/aboul3la/Sublist3r.git"
    curl -s "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
      | python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    data=[]
names=set()
for e in data:
    for n in e.get("name_value","").split("\n"):
        names.add(n.strip().lstrip("*."))
for n in sorted(names):
    print(n)' > "$out"
  fi
  local total
  total=$(grep -c . "$out" 2>/dev/null || echo 0)
  ok "Subdomains saved to: $out ($total found)"
}

# ---------------------------------------------------------------------------
# Mode: -urls (gau)
# ---------------------------------------------------------------------------
run_urls() {
  local out="${OUT_FILE:-${RESDIR}/urls.txt}"
  if command -v gau >/dev/null 2>&1; then
    ok "Using gau to collect historical URLs"
    gau "$DOMAIN" > "$out"
    local total
    total=$(grep -c . "$out" || echo 0)
    ok "URLs saved to: $out ($total found)"
    grep -E '\.js(\?|$)' "$out" | sort -u > "${RESDIR}/files-js-gau.txt"
    ok "Extra JS found via gau: ${RESDIR}/files-js-gau.txt"
  else
    warn "gau not found. Install with: go install github.com/lc/gau/v2/cmd/gau@latest"
  fi
}

# ---------------------------------------------------------------------------
# Mode: -probe (naabu + httpx)
# ---------------------------------------------------------------------------
run_probe() {
  # Port scan (top 100 ports) with naabu, before the web probe with httpx.
  run_naabu

  local input="${RESDIR}/subdomains.txt"
  [ -f "$input" ] || echo "$DOMAIN" > "$input"
  local out="${OUT_FILE:-${RESDIR}/probe.txt}"
  local hx
  if hx="$(find_httpx)"; then
    ok "Using httpx ($hx) to probe for live hosts"
    "$hx" -l "$input" -title -tech-detect -status-code -location -fr -maxr 5 -timeout "$TIMEOUT" -o "$out"
    ok "Result saved to: $out"
  else
    warn "ProjectDiscovery httpx not found. Install: sudo apt install httpx-toolkit"
    warn "  (or go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"
  fi
}

# ---------------------------------------------------------------------------
# Port scan with naabu — top 100 most common ports (part of -p/--probe)
# ---------------------------------------------------------------------------
run_naabu() {
  if ! command -v naabu >/dev/null 2>&1; then
    warn "naabu not found. Install with:"
    warn "  go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    warn "  (needs libpcap-dev: sudo apt install libpcap-dev)"
    return 1
  fi

  local out="${RESDIR}/naabu.txt"
  ok "[probe] naabu — scanning the top 100 ports on $DOMAIN"

  local -a args=(
    -host "$DOMAIN"
    -top-ports 100
    -silent
    -o "$out"
    -rate 1000
  )
  [ "$NO_COLOR" -eq 1 ] && args+=( -nc )

  naabu "${args[@]}" >/dev/null 2>&1 || warn "naabu returned an error code (continuing anyway)"

  if [ -s "$out" ]; then
    local ports
    ports="$(awk -F: '{print $NF}' "$out" | sort -n -u | tr '\n' ',' | sed 's/,$//')"
    ok "[probe] Open ports on ${DOMAIN}: ${ports:-none}"
    ok "[probe] Full naabu result saved to: $out"
  else
    ok "[probe] naabu: no open port among the top 100 on ${DOMAIN}"
  fi
}

# ---------------------------------------------------------------------------
# Mode: -dirs (content discovery with ffuf + SecLists; dirsearch fallback)
# ---------------------------------------------------------------------------
run_dirs() {
  local out="${OUT_FILE:-${RESDIR}/dirs.txt}"

  if command -v ffuf >/dev/null 2>&1; then
    local wl base
    wl="$(resolve_dir_wordlist)" || { warn "Skipping -d (no wordlist)"; return 1; }
    base="${URL%/}"
    ok "[dirs] ffuf on ${base}/FUZZ  (wordlist: $wl)"

    local json="${RESDIR}/ffuf.json"
    local -a args=(
      -u "${base}/FUZZ"
      -w "$wl"
      -mc all -fc 404 -ac
      -recursion -recursion-depth "$FFUF_RECURSION_DEPTH"
      -t "$FFUF_THREADS"
      -timeout "$TIMEOUT"
      -H "User-Agent: $(current_ua)"
      -of json -o "$json"
      -s
    )
    [ "$NO_COLOR" -eq 0 ] && args+=( -c )
    ffuf "${args[@]}" 2>/dev/null || warn "ffuf returned an error code (continuing anyway)"

    # Convert ffuf JSON -> dirs.txt (status  url  size), keeping dirsn counting.
    python3 - "$json" "$out" <<'PY' 2>/dev/null || true
import json, sys
jpath, opath = sys.argv[1], sys.argv[2]
try:
    data = json.load(open(jpath))
except Exception:
    data = {}
rows = []
for r in data.get("results", []):
    rows.append(f"{r.get('status','')}\t{r.get('url','')}\t{r.get('length','')}")
with open(opath, "w") as f:
    f.write("\n".join(rows) + ("\n" if rows else ""))
print(len(rows))
PY
    ok "[dirs] ffuf result: $json  (list: $out)"
    return 0
  fi

  # --- Fallback: dirsearch ---
  warn "ffuf not found; falling back to dirsearch"
  warn "  install ffuf: go install github.com/ffuf/ffuf/v2@latest  (or sudo apt install ffuf)"
  local wl="$WORDLIST"
  if [ -z "$wl" ]; then
    wl="$(resolve_dir_wordlist)" || { err "dirsearch needs a wordlist (-w) and SecLists is unavailable"; return 1; }
  fi
  if command -v dirsearch >/dev/null 2>&1; then
    ok "Using dirsearch"
    dirsearch -u "$URL" -w "$wl" -F -o "$out"
  elif [ -f "./dirsearch/dirsearch.py" ]; then
    ok "Using dirsearch (local script)"
    python3 ./dirsearch/dirsearch.py -u "$URL" -w "$wl" -F -o "$out"
  else
    warn "dirsearch not found either. Install: git clone https://github.com/maurosoria/dirsearch.git"
  fi
}

# ---------------------------------------------------------------------------
# Mode: -kite (API route discovery with kiterunner)
# ---------------------------------------------------------------------------
run_kite() {
  if ! command -v kr >/dev/null 2>&1; then
    warn "kiterunner (kr) not found. Install a release binary from:"
    warn "  https://github.com/assetnote/kiterunner/releases  (or git clone + make build)"
    return 1
  fi

  local routes raw="${RESDIR}/kiterunner.txt" api="${RESDIR}/api-routes.txt"
  : > "$raw"

  # Pass 1 — Assetnote compiled routes (.kite), when available.
  if routes="$(find_kite_wordlist)"; then
    ok "[kite] kr scan on $URL  (routes: $routes)"
    kr scan "$URL" -w "$routes" -x 5 -j 100 \
       --fail-status-codes 400,404,403,501,502,426 --timeout "${TIMEOUT}s" \
       2>/dev/null | tee -a "$raw" >&2 || warn "kr scan returned an error code (continuing anyway)"
  else
    warn "[kite] no .kite routes found; run --install-deps to fetch routes-small.kite"
  fi

  # Pass 2 — plain SecLists API wordlist brute (text routes), when available.
  local api_wl
  if api_wl="$(resolve_api_wordlist)"; then
    ok "[kite] kr brute on $URL  (wordlist: $api_wl)"
    kr brute "$URL" -w "$api_wl" -x 5 -j 100 \
       --fail-status-codes 400,404,403,501,502,426 --timeout "${TIMEOUT}s" \
       2>/dev/null | tee -a "$raw" >&2 || warn "kr brute returned an error code (continuing anyway)"
  fi

  # Extract the discovered routes/URLs into a clean list.
  grep -oE 'https?://[^[:space:]]+' "$raw" 2>/dev/null | sort -u > "$api" || true
  local total
  total=$(grep -c . "$api" 2>/dev/null || echo 0)
  ok "[kite] ${total} route(s) found — raw: $raw | clean: $api"
}

# ---------------------------------------------------------------------------
# Mode: -gf (dangerous patterns over the collected URLs)
# ---------------------------------------------------------------------------
run_gf() {
  local input="${RESDIR}/urls.txt"
  [ -f "$input" ] || run_urls
  local out="${OUT_FILE:-${RESDIR}/gf-${GF_PATTERN}.txt}"
  if command -v gf >/dev/null 2>&1; then
    ok "Using gf with pattern '$GF_PATTERN'"
    gf "$GF_PATTERN" < "$input" > "$out"
    ok "Result saved to: $out"
  else
    warn "gf not found. Install with:"
    warn "  go install github.com/tomnomnom/gf@latest"
    warn "  git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf"
  fi
}

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
add_mode() { MODES+=("$1"); }

[ $# -eq 0 ] && { usage; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    -u|--url)           URL_ARGS+=("${2:-}"); shift 2 ;;
    -l|--list)          LIST_FILE="${2:-}"; shift 2 ;;
    -f|--files)         add_mode files; shift ;;
    -s|--secret)        add_mode secret; shift ;;
    -t|--tech)          add_mode tech; shift ;;
    -T|--tech-deep)     add_mode techdeep; shift ;;
    -S|--subdomains)    add_mode subdomains; shift ;;
    -U|--urls)          add_mode urls; shift ;;
    -p|--probe)         add_mode probe; shift ;;
    -d|--dirs)          add_mode dirs; shift ;;
    -k|--kite)          add_mode kite; shift ;;
    -g|--gf)            add_mode gf; shift ;;
    -a|--all)           add_mode all; shift ;;
    -o|--output)        OUT_FILE="${2:-}"; shift 2 ;;
    -w|--wordlist)      WORDLIST="${2:-}"; shift 2 ;;
    --wordlist-size)    WORDLIST_SIZE="${2:-}"; shift 2 ;;
    --kite-wordlist)    KITE_WORDLIST="${2:-}"; shift 2 ;;
    --seclists)         SECLISTS_DIR="${2:-}"; shift 2 ;;
    --jsfile)           JS_LIST_FILE="${2:-}"; shift 2 ;;
    --no-verify)        SECRET_VERIFY=0; shift ;;
    --gf-pattern)       GF_PATTERN="${2:-}"; shift 2 ;;
    --env)              ENV_FILE="${2:-}"; shift 2 ;;
    --wpscan-enum)      WPSCAN_ENUM="${2:-}"; shift 2 ;;
    --wpscan-detection) WPSCAN_DETECTION="${2:-}"; shift 2 ;;
    --nuclei-tags)      NUCLEI_EXTRA_TAGS="${2:-}"; shift 2 ;;
    --no-vuln)          NO_VULN=1; shift ;;
    --no-preflight)     NO_PREFLIGHT=1; shift ;;
    --no-self-update)   SELF_UPDATE=0; shift ;;
    --rotate-agent)     CUSTOM_AGENT=1; shift ;;
    --timeout)          TIMEOUT="${2:-}"; shift 2 ;;
    -v|--verbose)       VERBOSE=1; shift ;;
    -j|--json)          JSON=1; shift ;;
    --no-color)         NO_COLOR=1; shift ;;
    --check)            DO_CHECK_ONLY=1; shift ;;
    --install-deps)     DO_INSTALL_ONLY=1; AUTO_INSTALL=1; shift ;;
    --yes)              AUTO_INSTALL=1; shift ;;
    --no-install)       NO_AUTO_INSTALL=1; shift ;;
    -h|--help)          usage; exit 0 ;;
    *) err "Unknown argument: $1"; usage; exit 1 ;;
  esac
done

setup_colors
load_env
print_banner

# ---------------------------------------------------------------------------
# Dependency-only modes (do not require a URL)
# ---------------------------------------------------------------------------
if [ "$DO_CHECK_ONLY" -eq 1 ]; then
  check_dependencies 0
  exit 0
fi
if [ "$DO_INSTALL_ONLY" -eq 1 ]; then
  check_dependencies 1
  exit 0
fi

# ---------------------------------------------------------------------------
# Normalize a target -> full URL (accepts "site.com" or "https://site.com/...")
# ---------------------------------------------------------------------------
normalize_url() {
  local u="$1"
  u="$(echo "$u" | tr -d '[:space:]')"
  [ -z "$u" ] && { echo ""; return; }
  case "$u" in
    http://*|https://*) echo "$u" ;;
    *)                  echo "https://$u" ;;
  esac
}

# ---------------------------------------------------------------------------
# Build the final target list: -u (repeatable) + lines from -l
# ---------------------------------------------------------------------------
for a in ${URL_ARGS[@]+"${URL_ARGS[@]}"}; do
  norm="$(normalize_url "$a")"
  [ -n "$norm" ] && TARGETS+=("$norm")
done

if [ -n "$LIST_FILE" ]; then
  [ -f "$LIST_FILE" ] || { err "List file not found: $LIST_FILE"; exit 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="$(echo "$line" | tr -d '\r')"
    [ -z "${line// /}" ] && continue          # empty line
    [ "${line:0:1}" = "#" ] && continue        # comment
    norm="$(normalize_url "$line")"
    [ -n "$norm" ] && TARGETS+=("$norm")
  done < "$LIST_FILE"
fi

# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
[ "${#TARGETS[@]}" -eq 0 ] && { err "Provide at least one target with -u/--url or -l/--list"; usage; exit 1; }
[ "${#MODES[@]}" -eq 0 ]   && { err "Provide at least one mode (-f, -s, -t, -S, -U, -p, -d, -k, -g or -a)"; usage; exit 1; }

for bin in curl grep sed awk python3; do
  command -v "$bin" >/dev/null 2>&1 || { err "Missing base dependency: $bin"; exit 1; }
done

# Deduplicate targets while preserving order
declare -A _seen=()
declare -a UNIQ=()
for t in "${TARGETS[@]}"; do
  [ -n "${_seen[$t]:-}" ] && continue
  _seen["$t"]=1
  UNIQ+=("$t")
done
TARGETS=("${UNIQ[@]}")

# -o makes no sense with several targets (one would overwrite the other)
if [ -n "$OUT_FILE" ] && [ "${#TARGETS[@]}" -gt 1 ]; then
  warn "-o/--output ignored with multiple targets; each target writes to its own folder."
  OUT_FILE=""
fi

# ---------------------------------------------------------------------------
# Mode expansion (target-independent) — canonical pipeline order
# ---------------------------------------------------------------------------
ORDER=(subdomains urls files tech techdeep secret probe dirs kite gf techvuln)
declare -A want=()
for m in "${MODES[@]}"; do
  if [ "$m" = "all" ]; then
    for o in "${ORDER[@]}"; do want["$o"]=1; done
  else
    want["$m"]=1
  fi
done

# Vulnerability validation runs automatically at the end whenever there was a
# fingerprint (-tech and/or -tech-deep).
if [ "${want[tech]:-0}" -eq 1 ] || [ "${want[techdeep]:-0}" -eq 1 ]; then
  want[techvuln]=1
fi

# --no-vuln removes the stage even with -a/--all or -t/-T selected.
if [ "$NO_VULN" -eq 1 ]; then
  unset 'want[techvuln]'
  vlog "Vulnerability validation disabled (--no-vuln)"
fi

# Ask for API keys BEFORE starting (persisted to .env).
if [ "${want[techvuln]:-0}" -eq 1 ]; then
  log "Preparing API keys for the vulnerability validation (.env: $ENV_FILE)"
  ensure_api_key WPSCAN_API_TOKEN "WPScan API token (Enter to skip)" 0 || true
  ensure_api_key PDCP_API_KEY     "ProjectDiscovery/Nuclei API key (optional, Enter to skip)" 0 || true
fi

# Initialize (reset) the consolidated OWASP headers report when -T is active.
if [ "${want[techdeep]:-0}" -eq 1 ]; then
  {
    echo "# OWASP Security Headers Report"
    echo "# Generated by recon.sh at $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Ref: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
    echo
  } > "$HEADERS_REPORT" 2>/dev/null || warn "Could not initialize $HEADERS_REPORT"
fi

# ---------------------------------------------------------------------------
# Configure the globals for a target (output folder, base URL, etc.)
# ---------------------------------------------------------------------------
setup_target() {
  URL="$1"
  local quiet="${2:-0}"
  DOMAIN="$(echo "$URL" | awk -F/ '{print $3}' | sed -E 's/:.*$//')"
  [ -z "$DOMAIN" ] && { err "Could not extract the domain from: $URL"; return 1; }
  OUTDIR="./recon_${DOMAIN}"
  JSDIR="${OUTDIR}/js"
  RESDIR="${OUTDIR}/results"
  mkdir -p "$JSDIR" "$RESDIR"
  [ "$quiet" -eq 1 ] || ok "Target folder: $OUTDIR"
  BASE_SCHEME_HOST="$(echo "$URL" | awk -F/ '{print $1"//"$3}')"
  BASE_DIR="$(echo "$URL" | sed -E 's#([^?]*/)[^/]*(\?.*)?$#\1#')"
  return 0
}

# ---------------------------------------------------------------------------
# Preflight: check the application status with httpx BEFORE running the modules.
# Returns 0 if the target is live/reachable, 1 otherwise. --no-preflight skips
# it. Without httpx, falls back to a HEAD via curl.
# ---------------------------------------------------------------------------
preflight_httpx() {
  if [ "$NO_PREFLIGHT" -eq 1 ]; then
    vlog "Preflight disabled (--no-preflight)"
    return 0
  fi
  local out="${RESDIR}/httpx-preflight.txt" hx
  if hx="$(find_httpx)"; then
    local -a hxargs=( -silent -status-code -title -tech-detect -location -fr -maxr 5 -timeout "$TIMEOUT" -o "$out" )
    [ "$NO_COLOR" -eq 1 ] && hxargs+=( -nc )
    local result
    result="$(echo "$URL" | "$hx" "${hxargs[@]}" 2>/dev/null)"
    if [ -n "$result" ]; then
      ok "[preflight] Application live (httpx): $result"
      return 0
    fi
    warn "[preflight] httpx got no live response from $URL"
    return 1
  fi

  # Fallback: no httpx -> check the HTTP code with curl.
  warn "ProjectDiscovery httpx not found; using curl for the preflight"
  warn "  install: sudo apt install httpx-toolkit  (or go install github.com/projectdiscovery/httpx/cmd/httpx@latest)"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -L -A "$(current_ua)" --max-time "$TIMEOUT" "$URL" 2>/dev/null)"
  REQ_COUNT=$((REQ_COUNT + 1))
  if [ -n "$code" ] && [ "$code" != "000" ]; then
    ok "[preflight] $URL responded HTTP $code"
    echo "$URL [HTTP $code]" > "$out"
    return 0
  fi
  warn "[preflight] $URL did not respond (curl code=${code:-empty})"
  return 1
}

# Run the selected modes for the already-configured target
dispatch_modes() {
  for mode in "${ORDER[@]}"; do
    [ "${want[$mode]:-0}" -eq 1 ] || continue
    case "$mode" in
      files)       run_files ;;
      secret)      run_secret ;;
      tech)        run_tech ;;
      techdeep)    run_tech_deep ;;
      techvuln)    run_vuln_validation ;;
      subdomains)  run_subdomains ;;
      urls)        run_urls ;;
      probe)       run_probe ;;
      dirs)        run_dirs ;;
      kite)        run_kite ;;
      gf)          run_gf ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Consolidated summary — per target (SUMMARY.md inside recon_<domain>/) and
# global (./recon-final-report.md at the end of the whole run).
# ---------------------------------------------------------------------------

# Count non-empty lines of a file, 0 if it does not exist/is empty.
_count_lines() { [ -s "$1" ] && grep -c . "$1" 2>/dev/null || echo 0; }

# Build SUMMARY.md for the current target ($DOMAIN/$RESDIR) and accumulate the
# global totals used in the final report (G_* variables).
write_target_summary() {
  local sfile="${OUTDIR}/SUMMARY.md"
  local subd urlsn jsn techn secretsn th_verified dirsn kiten gfn ports wp_line nuclei_matches

  subd="$(_count_lines "${RESDIR}/subdomains.txt")"
  urlsn="$(_count_lines "${RESDIR}/urls.txt")"
  jsn="$(_count_lines "${RESDIR}/files-js.txt")"
  techn="$(_count_lines "${RESDIR}/tech-detected.txt")"
  secretsn=0; [ -s "${RESDIR}/secrets.json" ] && secretsn="$(grep -c '"' "${RESDIR}/secrets.json" 2>/dev/null || echo 0)"
  th_verified=0; [ -s "${RESDIR}/trufflehog.jsonl" ] && th_verified="$(grep -c '"Verified":true' "${RESDIR}/trufflehog.jsonl" 2>/dev/null || echo 0)"
  dirsn="$(_count_lines "${RESDIR}/dirs.txt")"
  kiten="$(_count_lines "${RESDIR}/api-routes.txt")"
  gfn=0; for f in "${RESDIR}"/gf-*.txt; do [ -f "$f" ] && gfn=$((gfn + $(_count_lines "$f"))); done
  ports=""
  [ -s "${RESDIR}/naabu.txt" ] && ports="$(awk -F: '{print $NF}' "${RESDIR}/naabu.txt" | sort -n -u | tr '\n' ',' | sed 's/,$//')"
  nuclei_matches=0
  [ -s "${RESDIR}/nuclei.txt" ] && nuclei_matches="$(_count_lines "${RESDIR}/nuclei.txt")"
  wp_line="not evaluated"
  if [ -s "${RESDIR}/wpscan.txt" ]; then
    local vulns
    vulns="$(grep -ci 'vulnerab' "${RESDIR}/wpscan.txt" 2>/dev/null || echo 0)"
    wp_line="${vulns} vulnerability mention(s) — see wpscan.txt"
  fi

  # History + diff against the previous run (what is new since the last run).
  local news
  news="$(write_history_and_diff)"

  {
    echo "# Summary — ${DOMAIN}"
    echo "_Generated at $(date '+%Y-%m-%d %H:%M:%S')_"
    echo
    echo "| Item | Result |"
    echo "|---|---|"
    echo "| Subdomains (-S) | ${subd} |"
    echo "| Historical URLs (-U) | ${urlsn} |"
    echo "| JS files (-f) | ${jsn} |"
    echo "| Technologies registered (-t/-T) | ${techn} |"
    [ -s "${RESDIR}/security-headers.txt" ] && echo "| OWASP headers (-T) | see \`results/security-headers.txt\` |"
    [ -n "$ports" ] && echo "| Open ports — top 100 (-p, naabu) | ${ports} |"
    [ -s "${RESDIR}/probe.txt" ] && echo "| Live hosts (-p, httpx) | see \`results/probe.txt\` |"
    [ "$dirsn" -gt 0 ] && echo "| Directories found (-d) | ${dirsn} |"
    [ "$kiten" -gt 0 ] && echo "| API routes found (-k) | ${kiten} |"
    [ "$gfn" -gt 0 ] && echo "| gf pattern matches (-g) | ${gfn} |"
    [ "$secretsn" -gt 0 ] && echo "| Secrets (SecretFinder) (-s) | ${secretsn} |"
    [ -s "${RESDIR}/trufflehog.jsonl" ] && echo "| TruffleHog verified secrets (-s) | ${th_verified} |"
    [ -s "${RESDIR}/secrets-all.txt" ] && echo "| Consolidated secrets (-s) | see \`results/secrets-all.txt\` |"
    [ -s "${RESDIR}/wpscan.txt" ] && echo "| WordPress (WPScan) | ${wp_line} |"
    [ "$nuclei_matches" -gt 0 ] && echo "| Vulnerabilities (Nuclei) | ${nuclei_matches} finding(s) — see \`results/nuclei.txt\` |"
    [ -s "${RESDIR}/searchsploit.txt" ] && echo "| Known exploits (searchsploit) | see \`results/searchsploit.txt\` |"
    echo
    if [ -n "$news" ]; then
      echo "## 🆕 New since the last run"
      echo "$news" | sed 's/^/- /'
      echo
    fi
    echo "All detailed files are in \`results/\`. Full history in \`${HISTORY_DIR}/${DOMAIN}/\`."
  } > "$sfile" 2>/dev/null

  # Accumulate into the final report's global totals.
  G_SUBDOMAINS=$((G_SUBDOMAINS + subd))
  G_URLS=$((G_URLS + urlsn))
  G_TECHS=$((G_TECHS + techn))
  G_SECRETS=$((G_SECRETS + secretsn))
  G_SECRETS_VERIFIED=$((G_SECRETS_VERIFIED + th_verified))
  G_DIRS=$((G_DIRS + dirsn))
  G_APIROUTES=$((G_APIROUTES + kiten))
  G_NUCLEI=$((G_NUCLEI + nuclei_matches))
  [ -n "$ports" ] && G_PORTS_TARGETS=$((G_PORTS_TARGETS + 1))
  [ -s "${RESDIR}/wpscan.txt" ] && G_WORDPRESS=$((G_WORDPRESS + 1))
  grep -q '^wordpress|' "${RESDIR}/tech-detected.txt" 2>/dev/null && G_WORDPRESS_DETECTED=$((G_WORDPRESS_DETECTED + 1))
  grep -q '^nginx|'     "${RESDIR}/tech-detected.txt" 2>/dev/null && G_NGINX=$((G_NGINX + 1))
  grep -q '^apache|'    "${RESDIR}/tech-detected.txt" 2>/dev/null && G_APACHE=$((G_APACHE + 1))
  [ -n "$news" ] && G_NEW_FINDINGS=$((G_NEW_FINDINGS + $(echo "$news" | grep -c .)))

  echo "$DOMAIN|$subd|$urlsn|$techn|$ports|$nuclei_matches|$secretsn" >> "$FINAL_REPORT_ROWS"
}

# ---------------------------------------------------------------------------
# Persistent history (for the dashboard) + diff against the previous run.
# Writes a JSON snapshot to history/<domain>/<timestamp>.json, one line to the
# global index history/index.jsonl, and prints (stdout) the finding lines that
# did NOT exist in that domain's previous snapshot — this is how the script
# flags when a new CVE starts affecting an already-seen version.
# ---------------------------------------------------------------------------
write_history_and_diff() {
  local dom="$DOMAIN" ts hdir snapshot
  ts="$(date '+%Y%m%d-%H%M%S')"
  hdir="${HISTORY_DIR}/${dom}"
  mkdir -p "$hdir" 2>/dev/null || { warn "Could not create ${hdir} (history disabled for ${dom})"; return 0; }
  snapshot="${hdir}/${ts}.json"

  local diffout
  diffout="$(python3 - "$snapshot" "$hdir" "${RESDIR}" "$dom" "$URL" "$ts" <<'PY'
import json, sys, glob, os

snapshot_path, hdir, resdir, domain, url, ts = sys.argv[1:7]

def read_lines(path):
    try:
        with open(path) as f:
            return [l.rstrip("\n") for l in f if l.strip()]
    except FileNotFoundError:
        return []

techs = []
for line in read_lines(os.path.join(resdir, "tech-detected.txt")):
    if "|" in line:
        name, ver = line.split("|", 1)
        techs.append({"name": name, "version": ver})

ports = []
for line in read_lines(os.path.join(resdir, "naabu.txt")):
    if ":" in line:
        ports.append(line.rsplit(":", 1)[-1])
ports = sorted(set(ports), key=lambda x: int(x) if x.isdigit() else 0)

nuclei_findings = read_lines(os.path.join(resdir, "nuclei.txt"))
wpscan_vulns = [l.strip() for l in read_lines(os.path.join(resdir, "wpscan.txt")) if "vulnerab" in l.lower()]

trufflehog_verified = sum(
    1 for l in read_lines(os.path.join(resdir, "trufflehog.jsonl")) if '"Verified":true' in l
)

snapshot = {
    "domain": domain, "url": url, "timestamp": ts,
    "techs": techs, "ports": ports,
    "nuclei_findings": nuclei_findings,
    "wpscan_vulnerabilities": wpscan_vulns,
    "secrets_count": len(read_lines(os.path.join(resdir, "secrets.json"))),
    "trufflehog_verified": trufflehog_verified,
    "dirs_count": len(read_lines(os.path.join(resdir, "dirs.txt"))),
    "api_routes_count": len(read_lines(os.path.join(resdir, "api-routes.txt"))),
    "subdomains_count": len(read_lines(os.path.join(resdir, "subdomains.txt"))),
    "urls_count": len(read_lines(os.path.join(resdir, "urls.txt"))),
}
with open(snapshot_path, "w") as f:
    json.dump(snapshot, f, ensure_ascii=False, indent=2)

prev_files = sorted(
    p for p in glob.glob(os.path.join(hdir, "*.json"))
    if os.path.basename(p) != os.path.basename(snapshot_path)
)
if prev_files:
    try:
        prev = json.load(open(prev_files[-1]))
    except Exception:
        prev = {}
    prev_nuclei = set(prev.get("nuclei_findings", []))
    prev_wp = set(prev.get("wpscan_vulnerabilities", []))
    for l in nuclei_findings:
        if l not in prev_nuclei:
            print(f"Nuclei: {l}")
    for l in wpscan_vulns:
        if l not in prev_wp:
            print(f"WPScan: {l}")
PY
)"
  # Global index (full history, all domains) for the dashboard.
  printf '{"domain":"%s","timestamp":"%s","file":"%s"}\n' "$dom" "$ts" "$snapshot" >> "${HISTORY_DIR}/index.jsonl" 2>/dev/null

  if [ -n "$diffout" ]; then
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      warn "🆕 [NEW on ${DOMAIN}] $line"
    done <<< "$diffout"
  fi
  echo "$diffout"
}

# Build ./recon-final-report.md with everything obtained in the run and print a
# summary box to the terminal.
build_final_report() {
  local report="./recon-final-report.md"
  {
    echo "# recon.sh final report"
    echo "_Generated at $(date '+%Y-%m-%d %H:%M:%S')_"
    echo
    echo "## Overview"
    echo "| Metric | Total |"
    echo "|---|---|"
    echo "| Targets processed | ${LIVE_COUNT:-0} |"
    echo "| Subdomains found | ${G_SUBDOMAINS:-0} |"
    echo "| Historical URLs collected | ${G_URLS:-0} |"
    echo "| Technologies registered | ${G_TECHS:-0} |"
    echo "| Targets with WordPress detected | ${G_WORDPRESS_DETECTED:-0} |"
    echo "| Targets with Nginx detected | ${G_NGINX:-0} |"
    echo "| Targets with Apache detected | ${G_APACHE:-0} |"
    echo "| Targets with open ports (naabu) | ${G_PORTS_TARGETS:-0} |"
    echo "| Nuclei findings (total) | ${G_NUCLEI:-0} |"
    echo "| 🆕 New since the last run | ${G_NEW_FINDINGS:-0} |"
    echo "| Secrets found (SecretFinder) | ${G_SECRETS:-0} |"
    echo "| Verified secrets (TruffleHog) | ${G_SECRETS_VERIFIED:-0} |"
    echo "| Directories found (total) | ${G_DIRS:-0} |"
    echo "| API routes found (total) | ${G_APIROUTES:-0} |"
    [ -s "$HEADERS_REPORT" ] && echo "| OWASP headers | see \`${HEADERS_REPORT}\` |"
    echo
    if [ -s "$FINAL_REPORT_ROWS" ]; then
      echo "## Per target"
      echo "| Domain | Subdomains | URLs | Techs | Open ports | Nuclei | Secrets |"
      echo "|---|---|---|---|---|---|---|"
      while IFS='|' read -r d s u t p n sec; do
        echo "| ${d} | ${s} | ${u} | ${t} | ${p:-—} | ${n} | ${sec} |"
      done < "$FINAL_REPORT_ROWS"
      echo
    fi
    echo "## Where to find each thing"
    echo "- Per-target detail: \`recon_<domain>/SUMMARY.md\` and \`recon_<domain>/results/\`"
    echo "- Live targets (Phase 1): \`./live-targets.txt\`"
    [ -s "$HEADERS_REPORT" ] && echo "- Consolidated OWASP headers: \`${HEADERS_REPORT}\`"
  } > "$report" 2>/dev/null

  section "Final result"
  ok "Live targets processed   : ${LIVE_COUNT:-0}"
  ok "Subdomains found         : ${G_SUBDOMAINS:-0}"
  ok "Historical URLs          : ${G_URLS:-0}"
  ok "Technologies registered  : ${G_TECHS:-0}  (WordPress: ${G_WORDPRESS_DETECTED:-0} | Nginx: ${G_NGINX:-0} | Apache: ${G_APACHE:-0})"
  ok "Targets with open ports  : ${G_PORTS_TARGETS:-0}"
  ok "Nuclei findings          : ${G_NUCLEI:-0}"
  if [ "${G_NEW_FINDINGS:-0}" -gt 0 ]; then
    err "🆕 New since the last run: ${G_NEW_FINDINGS}  (see each target's SUMMARY.md)"
  else
    ok "🆕 New since the last run: 0"
  fi
  ok "Secrets found            : ${G_SECRETS:-0}  (TruffleHog verified: ${G_SECRETS_VERIFIED:-0})"
  ok "Directories found        : ${G_DIRS:-0}"
  ok "API routes found         : ${G_APIROUTES:-0}"
  [ -s "$HEADERS_REPORT" ] && ok "OWASP headers (consolidated): ${HEADERS_REPORT}"
  ok "Full report saved to     : ${report}"
  _rule 64
}

# ---------------------------------------------------------------------------
# Self-update — meant to run via cron once a day without intervention.
# Updates the script itself (git pull, when applicable) and the databases used
# to find vulnerabilities: nuclei-templates, WPScan DB and Exploit-DB. This is
# what makes the script "catch up" when a new CVE is published tomorrow for a
# technology/version already seen today: the detection engine is updated before
# each run, so the same target can start matching the next day.
# ---------------------------------------------------------------------------
self_update() {
  if [ "$SELF_UPDATE" -eq 0 ]; then
    vlog "Self-update disabled (--no-self-update)"
    return 0
  fi
  section "Self-update (script + CVE databases)"

  # 1) The script itself, if it lives inside a git repository.
  if [ -z "${_RECON_SELF_UPDATED:-}" ]; then
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if git -C "$script_dir" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      local before after
      before="$(git -C "$script_dir" rev-parse HEAD 2>/dev/null)"
      if git -C "$script_dir" pull --ff-only --quiet 2>/dev/null; then
        after="$(git -C "$script_dir" rev-parse HEAD 2>/dev/null)"
        if [ -n "$before" ] && [ "$before" != "$after" ]; then
          ok "recon.sh updated ($before -> $after). Restarting with the new version..."
          export _RECON_SELF_UPDATED=1
          exec "$0" "${ORIGINAL_ARGS[@]}"
        else
          ok "recon.sh is already up to date"
        fi
      else
        warn "Could not update recon.sh via git pull (continuing with the current version)"
      fi
    else
      vlog "recon.sh is not in a git repository; skipping the script self-update"
    fi
  fi

  # 2) nuclei templates (new nginx/apache/etc CVEs show up here).
  if command -v nuclei >/dev/null 2>&1; then
    ok "Updating nuclei-templates..."
    if nuclei -update-templates >/dev/null 2>&1; then
      ok "nuclei-templates updated"
    else
      warn "Failed to update nuclei-templates (continuing with the current base)"
    fi
  fi

  # 3) WPScan metadata database (known WordPress versions/plugins).
  if command -v wpscan >/dev/null 2>&1; then
    ok "Updating the WPScan metadata database..."
    if wpscan --update >/dev/null 2>&1; then
      ok "WPScan database updated"
    else
      warn "Failed to update the WPScan database (continuing with the current base)"
    fi
  fi

  # 4) Local Exploit-DB (searchsploit).
  if command -v searchsploit >/dev/null 2>&1; then
    ok "Updating Exploit-DB (searchsploit)..."
    if searchsploit -u >/dev/null 2>&1; then
      ok "Exploit-DB updated"
    else
      warn "Failed to update Exploit-DB (continuing with the current base)"
    fi
  fi
}

self_update

# ---------------------------------------------------------------------------
# Main loop over the targets
# ---------------------------------------------------------------------------
TOTAL_TARGETS="${#TARGETS[@]}"
GRAND_TOTAL=0
[ "$TOTAL_TARGETS" -gt 1 ] && ok "Processing $TOTAL_TARGETS targets"

# ---------------------------------------------------------------------------
# PHASE 1 — Preflight (liveness): validate ALL targets first and build the list
# of the live ones. Only then (Phase 2) are the modules executed.
# With --no-preflight, every valid target is treated as live.
# ---------------------------------------------------------------------------
LIVE_TARGETS=()
DEAD_COUNT=0
idx=0

# Final report accumulators (./recon-final-report.md).
G_SUBDOMAINS=0; G_URLS=0; G_TECHS=0; G_SECRETS=0; G_SECRETS_VERIFIED=0; G_DIRS=0
G_APIROUTES=0; G_NUCLEI=0; G_PORTS_TARGETS=0; G_WORDPRESS=0; G_WORDPRESS_DETECTED=0
G_NGINX=0; G_APACHE=0; G_NEW_FINDINGS=0
FINAL_REPORT_ROWS="$(mktemp /tmp/recon-rows.XXXXXX)"
mkdir -p "$HISTORY_DIR" 2>/dev/null

if [ "$NO_PREFLIGHT" -eq 1 ]; then
  section "Phase 1/2 — preflight disabled (--no-preflight); all targets continue"
else
  section "Phase 1/2 — checking which of the ${TOTAL_TARGETS} target(s) are live (httpx)"
fi

for tgt in "${TARGETS[@]}"; do
  idx=$((idx + 1))
  [ "$TOTAL_TARGETS" -gt 1 ] && log "----- preflight [$idx/$TOTAL_TARGETS] $tgt -----"
  REQ_COUNT=0
  if setup_target "$tgt" 1; then
    if preflight_httpx; then
      LIVE_TARGETS+=("$tgt")
    else
      DEAD_COUNT=$((DEAD_COUNT + 1))
      warn "[$DOMAIN] Down/unreachable — will not enter Phase 2."
      # Remove the folder created for the dead target (only if empty).
      rm -f "$RESDIR/httpx-preflight.txt" 2>/dev/null
      rmdir "$JSDIR" "$RESDIR" "$OUTDIR" 2>/dev/null || true
    fi
  else
    DEAD_COUNT=$((DEAD_COUNT + 1))
    warn "Invalid target, ignored: $tgt"
  fi
  GRAND_TOTAL=$((GRAND_TOTAL + REQ_COUNT))
done

LIVE_COUNT="${#LIVE_TARGETS[@]}"
ok "Phase 1/2 done: ${c_bold}${LIVE_COUNT} live${c_rst}, ${DEAD_COUNT} down/invalid of ${TOTAL_TARGETS}"

# Record the live list for later reference.
if [ "$LIVE_COUNT" -gt 0 ]; then
  printf '%s\n' "${LIVE_TARGETS[@]}" > ./live-targets.txt 2>/dev/null \
    && ok "Live targets saved to: ./live-targets.txt"
fi

# ---------------------------------------------------------------------------
# PHASE 2 — Run the modules only on the live targets.
# ---------------------------------------------------------------------------
if [ "$LIVE_COUNT" -eq 0 ]; then
  warn "No live target; nothing to do in Phase 2."
else
  section "Phase 2/2 — running the modules on ${LIVE_COUNT} live target(s)"
  idx=0
  for tgt in "${LIVE_TARGETS[@]}"; do
    idx=$((idx + 1))
    [ "$LIVE_COUNT" -gt 1 ] && target_header "$idx" "$LIVE_COUNT" "$tgt"
    REQ_COUNT=0
    if setup_target "$tgt"; then
      dispatch_modes
      write_target_summary
      [ "$LIVE_COUNT" -gt 1 ] && ok "[$DOMAIN] Requests: $REQ_COUNT | summary in ${OUTDIR}/SUMMARY.md"
    fi
    GRAND_TOTAL=$((GRAND_TOTAL + REQ_COUNT))
  done
fi

if [ "$TOTAL_TARGETS" -gt 1 ]; then
  ok "Done. ${LIVE_COUNT}/${TOTAL_TARGETS} live targets processed. Total requests: $GRAND_TOTAL"
else
  ok "Done. Total requests made: $GRAND_TOTAL"
fi

# Final consolidated result (everything obtained in the run).
build_final_report
rm -f "$FINAL_REPORT_ROWS" 2>/dev/null
