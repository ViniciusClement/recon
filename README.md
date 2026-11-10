# recon.sh - v5.0

Web reconnaissance in Bash: subdomains, historical URLs, `.js` extraction and
secret discovery (**SecretFinder + TruffleHog + Gitleaks**), technology
fingerprinting, probing, **content discovery with ffuf + SecLists**, **API route
discovery with kiterunner**, `gf` filters, **OWASP security-header analysis** and
**automatic vulnerability validation**.

Modes are **combinable** in a single run and the pipeline always executes in a
logical order, regardless of the order in which the flags were passed.

```
./recon.sh -u <URL> [modes...] [options]
```

---

## What's new in 5.0

- **Secret scanning with three engines (`-s`)** — on top of the regex-based
  **SecretFinder**, the script now runs **[TruffleHog](https://github.com/trufflesecurity/trufflehog)**
  (filesystem scan of the downloaded JS, with **live verification** of the
  secrets it finds against the provider APIs) and
  **[Gitleaks](https://github.com/gitleaks/gitleaks)** (regex + entropy). The
  results are cross-checked: any Gitleaks hit on the same file+line as a
  TruffleHog-**verified** secret is flagged as *confirmed*. A consolidated,
  value-redacted report is written to `results/secrets-all.txt`.
- **Content discovery with ffuf + SecLists (`-d`)** — `--dirs` now uses
  **[ffuf](https://github.com/ffuf/ffuf)** with a **SecLists** wordlist by
  default (no `-w` required). dirsearch is kept only as a fallback when ffuf is
  not installed.
- **API route discovery with kiterunner (`-k`)** — the new `--kite` mode runs
  **[kiterunner](https://github.com/assetnote/kiterunner)** against the target
  using Assetnote's compiled routes (`.kite`) plus a SecLists API wordlist.
- **Tool-integration review/fixes** — WPScan now runs with a configurable
  detection mode and `--force` (so it does not abort when it is unsure the site
  is WordPress, since we already detected it) and request/connect timeouts;
  Nuclei also exports JSONL, disables its mid-run auto-update (`-duc`, since
  self-update already refreshes templates) and accepts extra tags
  (`--nuclei-tags`); **httpx** is resolved to ProjectDiscovery's binary even when
  the Python `httpx` CLI shadows the name (Kali ships it as `httpx-toolkit`).
- **Everything translated to English** (script, dashboard and this README).
- **SecLists / kiterunner routes auto-detected and installable** via
  `--install-deps`.

Everything from 4.0 is still here: two-phase preflight, OWASP header analysis,
automatic WordPress→WPScan and Nginx/Apache→Nuclei/searchsploit validation,
self-update for a daily cron, per-run history snapshots with 🆕 new-finding
detection, the `dashboard.py` web panel, and the consolidated reports.

---

## Best command

Full pipeline (fingerprint + tech-deep + OWASP headers + content discovery + vuln validation):

```bash
./recon.sh -u https://target.com/ --all --rotate-agent -v
```

For a list of targets (the two-phase preflight runs automatically):

```bash
./recon.sh -l all-sites.txt -U -f -s -T -p -v --rotate-agent
```

Leaner, less noisy variant (no directory brute-force):

```bash
./recon.sh -u https://target.com/ -S -U -f -T -p -v
```

> `--all` already includes `-T`, `-d`, `-k` and the vulnerability-validation
> stage — no need to repeat them. API tokens are requested at the start and the
> preflight runs before any module.

---

## Modes (combinable)

| Flag | Description |
|------|-------------|
| `-f, --files`      | Extract `.js` from the HTML, resolve URLs and download the files |
| `-s, --secret`     | Secret scanning: SecretFinder + TruffleHog (verified) + Gitleaks |
| `-t, --tech`       | Technology fingerprint + version guess |
| `-T, --tech-deep`  | Deep fingerprint (WhatWeb) + OWASP security-header analysis |
| `-S, --subdomains` | Enumerate subdomains (sublist3r; crt.sh fallback) |
| `-U, --urls`       | Collect historical URLs for the domain (gau) |
| `-p, --probe`      | Port scan (naabu, top 100) + live hosts/URLs (httpx) |
| `-d, --dirs`       | Content discovery with ffuf + SecLists (dirsearch fallback) |
| `-k, --kite`       | API route discovery with kiterunner (Assetnote routes + SecLists) |
| `-g, --gf`         | Filter collected URLs for dangerous patterns (gf + Gf-Patterns) |
| `-a, --all`        | Run every available module, in logical order |

**Canonical pipeline order** (independent of flag order):
`subdomains → urls → files → tech → tech-deep → secret → probe → dirs → kite → gf → vulnerability validation`.

---

## Options

| Flag | Description |
|------|-------------|
| `-u, --url <URL>`         | Target URL (repeatable `-u`; combines with `-l`) |
| `-l, --list <file>`       | File with a list of targets, one per line (bare domain or URL; `#` = comment) |
| `-o, --output <file>`     | Specific output file (ignored with multiple targets) |
| `-w, --wordlist <file>`   | Wordlist for `--dirs` (default: SecLists `raft-<size>-directories.txt`) |
| `--wordlist-size <s>`     | SecLists raft size for `--dirs`: `small\|medium\|large` (default: `medium`) |
| `--kite-wordlist <file>`  | kiterunner routes file (`.kite`) (default: auto-detect in `./kiterunner/`) |
| `--seclists <dir>`        | SecLists directory (default: auto-detect) |
| `--no-verify`             | Do not let TruffleHog verify secrets against the provider APIs |
| `--jsfile <file>`         | Reuse an already-extracted JS list (skips crawling in `--secret`) |
| `--gf-pattern <name>`     | gf pattern to use (default: `xss`) |
| `--env <file>`            | `.env` file with API keys (default: `./.env`) |
| `--wpscan-enum <e>`       | WPScan enumeration (default: `vp,vt,u`) |
| `--wpscan-detection <m>`  | WPScan plugin/theme detection: `passive\|mixed\|aggressive` (default: `mixed`) |
| `--nuclei-tags <t>`       | Extra nuclei tags (comma-separated) added to the detected ones |
| `--no-vuln`               | Disable vulnerability validation (wpscan/nuclei/searchsploit) |
| `--no-preflight`          | Skip Phase 1 liveness; all targets go straight to the modules |
| `--no-self-update`        | Do not update the script/nuclei-templates/WPScan DB/Exploit-DB before running |
| `--rotate-agent`          | Rotate the User-Agent every 5 requests |
| `--timeout <sec>`         | Per-request timeout (default: `15`) |
| `-v, --verbose`           | Verbose logging to stderr |
| `-j, --json`              | JSON output (where applicable) |
| `--no-color`              | Disable colors |

---

## Secret scanning (`-s`)

Three engines run over the target, each covering what the others miss:

| Engine | Input | What it does |
|--------|-------|--------------|
| **SecretFinder** | each JS URL + the HTML | Regex set for API keys/tokens embedded in JavaScript |
| **TruffleHog**   | the downloaded files (`js/`) | 800+ detectors, and **live-verifies** each secret against the provider's API (disable with `--no-verify`) |
| **Gitleaks**     | the downloaded files (`js/`) | Regex + Shannon-entropy detection |

The script cross-checks the two filesystem scanners: a Gitleaks finding that
lands on the same `file:line` as a TruffleHog **verified** secret is marked
`CONFIRMED` in the consolidated report. Outputs:

- `results/trufflehog.jsonl` — one JSON object per TruffleHog finding (`"Verified":true` = live/valid).
- `results/gitleaks.json` — Gitleaks JSON report.
- `results/secrets-all.txt` — consolidated, human-readable report with **values redacted** (first/last 4 chars only).

> A **verified** secret is live and valid right now — triage it immediately.
> The run also records how many verified secrets each target had, into the
> history and the dashboard.

---

## Content discovery (`-d`) — ffuf + SecLists

`--dirs` fuzzes `URL/FUZZ` with ffuf and a SecLists wordlist. It no longer
requires `-w`: when none is given it uses
`SecLists/Discovery/Web-Content/raft-<size>-directories.txt`
(`--wordlist-size small|medium|large`, default `medium`). `-w` still overrides it.

Equivalent command run internally:

```bash
ffuf -u "$URL/FUZZ" -w "$WORDLIST" -mc all -fc 404 -ac \
     -recursion -recursion-depth 1 -t 40 -timeout "$TIMEOUT" \
     -H "User-Agent: <rotating>" -of json -o results/ffuf.json -s
```

The JSON is converted to `results/dirs.txt` (`status  url  size`). If ffuf is
not installed, the script falls back to **dirsearch**.

---

## API route discovery (`-k`) — kiterunner

`--kite` probes the target for API routes with kiterunner (`kr`):

```bash
# Pass 1: Assetnote compiled routes
kr scan "$URL" -w <routes.kite> -x 5 -j 100 --fail-status-codes 400,404,403,501,502,426
# Pass 2: plain SecLists API wordlist
kr brute "$URL" -w <SecLists .../api/api-endpoints.txt> -x 5 -j 100 ...
```

Raw output is saved to `results/kiterunner.txt` and the discovered routes are
extracted to `results/api-routes.txt`. The `.kite` routes file is auto-detected
in `./kiterunner/` (download `routes-small.kite` with `--install-deps`, or point
at one with `--kite-wordlist`).

---

## Vulnerability validation

Runs **at the end of the recon**, automatically, whenever a fingerprint ran
(`-t` and/or `-T`). Disable with `--no-vuln`.

| Detection | Tool | What it does |
|-----------|------|--------------|
| WordPress      | **WPScan**       | Enumerates vulnerable plugins/themes and users. Uses `WPSCAN_API_TOKEN` when available. |
| Nginx / Apache | **Nuclei**       | Runs technology-tag templates + known CVEs, filtered by severity. |
| Nginx / Apache | **searchsploit** | Maps `version → known exploits` (local Exploit-DB, complementary). |

Equivalent commands fired internally:

```bash
# WordPress
wpscan --url "$URL" --enumerate vp,vt,u --detection-mode mixed --plugins-detection mixed \
       --random-user-agent --stealthy --force --ignore-main-redirect \
       --disable-tls-checks --request-timeout "$TIMEOUT" --connect-timeout "$TIMEOUT" \
       --api-token "$WPSCAN_API_TOKEN"

# Nginx / Apache
nuclei -u "$URL" -o results/nuclei.txt -jsonl-export results/nuclei.jsonl -stats \
       -timeout "$TIMEOUT" -retries 1 -rl 50 -fr -mr 5 -duc \
       -severity low,medium,high,critical -tags nginx,apache
searchsploit nginx <version>
```

> WPScan enumeration is tunable: `--wpscan-enum vp,vt,tt,u` (or `at` for all
> themes) and `--wpscan-detection passive|mixed|aggressive`. Extra nuclei tags
> can be added with `--nuclei-tags`. `PDCP_API_KEY` is not turned into a flag —
> nuclei reads it from the environment for the optional ProjectDiscovery Cloud
> upload.

---

## API keys (`.env`)

Keys are **requested at the start** of the run (hidden input) and saved to
`./.env` with mode `600`. On later runs they are loaded automatically (safe
parsing, no `source`).

| Variable | Use | Required |
|----------|-----|----------|
| `WPSCAN_API_TOKEN` | WPScan vulnerability database (https://wpscan.com/api) | No (without it, limited results) |
| `PDCP_API_KEY`     | ProjectDiscovery/Nuclei (optional upload) | No |

> **Add `.env` to `.gitignore`** so the tokens are never committed. You can also
> point at another file with `--env /path/to/file.env`.

---

## Dependencies

```bash
./recon.sh --check          # check tools, Python modules, wordlists and API keys
./recon.sh --install-deps   # install what's missing (Python + SecretFinder + SecLists + kiterunner routes) and exit
```

| Flag | Description |
|------|-------------|
| `--check`        | Check all tools/modules and exit |
| `--install-deps` | Install what's missing and exit |
| `--yes`          | Answer "yes" to installs (non-interactive) |
| `--no-install`   | Never install anything automatically |
| `-h, --help`     | This help |

### External tools

| Tool | Install |
|------|---------|
| Sublist3r    | `git clone https://github.com/aboul3la/Sublist3r.git` |
| gau          | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| httpx        | `sudo apt install httpx-toolkit` (Kali) or `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| naabu        | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` (needs `libpcap-dev`) |
| **ffuf**     | `go install github.com/ffuf/ffuf/v2@latest` (or `sudo apt install ffuf`) |
| **kiterunner** (`kr`) | release binary from https://github.com/assetnote/kiterunner/releases (or clone + `make build`) |
| **SecLists** | `sudo apt install seclists` (or `--install-deps` clones into `./SecLists`) |
| **TruffleHog** | `sudo apt install trufflehog` (or a release from https://github.com/trufflesecurity/trufflehog/releases) |
| **Gitleaks** | `sudo apt install gitleaks` (or `go install github.com/zricethezav/gitleaks/v8@latest`) |
| dirsearch    | `git clone https://github.com/maurosoria/dirsearch.git` (ffuf fallback) |
| gf           | `go install github.com/tomnomnom/gf@latest` (+ `git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf`) |
| WhatWeb      | `sudo apt install whatweb` (or `gem install whatweb`) |
| WPScan       | `sudo apt install wpscan` (or `gem install wpscan`) |
| Nuclei       | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| searchsploit | `sudo apt install exploitdb` |

> On Kali the Python `httpx` CLI occupies the `httpx` name; the script detects
> ProjectDiscovery's binary (often `httpx-toolkit`) and tells you in `--check`
> which one it will use.
>
> Go tools need Go installed (`sudo apt install golang-go`) and `$HOME/go/bin`
> on `PATH`. `--install-deps` clones SecretFinder and SecLists and downloads the
> kiterunner routes, but does **not** install Sublist3r/Go/other external tools.

---

## Two-phase preflight

When there is more than one target (`-l`), recon runs in **two phases**:

**Phase 1 — liveness scan.** *All* targets are checked first with **httpx**
(curl fallback when httpx is not installed). At the end a summary is printed
(`N live, M down/invalid of TOTAL`), the live list is saved to
`./live-targets.txt`, and folders created for dead targets are removed (only if
empty — data from previous runs is never deleted).

**Phase 2 — modules.** The selected modules run **only on the targets that
passed Phase 1**. `--no-preflight` skips Phase 1. A host that answers
`403/401/500` counts as *live* (it responded); only a total non-response
(timeout, DNS failure, refused connection) is discarded.

---

## OWASP security-header analysis

In **`-T/--tech-deep`** mode the script collects the final response headers and
compares them with the
[OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html):
security headers that should be present (absence = finding) and
information-disclosure headers that should be absent (presence = finding).
Findings are highlighted in the logs (`[owasp-headers]` lines) and written to
`results/security-headers.txt` (per target) and `./owasp-headers-report.md`
(consolidated). `X-Frame-Options` is considered satisfied when a
`Content-Security-Policy` with `frame-ancestors` is present.

---

## Self-update, history and 🆕 detection

Meant to run via cron once a day. Before each run (unless `--no-self-update`)
the script updates itself (`git pull --ff-only`, re-exec'ing with the same
arguments when a new commit arrives), `nuclei-templates`, the WPScan metadata DB
and the local Exploit-DB. Each run writes a per-domain snapshot to
`./history/<domain>/<timestamp>.json` and a line to `./history/index.jsonl`, and
flags — in the logs and in `SUMMARY.md` — any Nuclei finding or WPScan
vulnerability that did **not** exist in that domain's previous run:

```
[!] 🆕 [NEW on fps.example.com] Nuclei: [wordpress-cve-2026-xxxx] [http] [critical] ...
```

This covers exactly the case of a new CVE affecting a version already seen
before: since Nuclei runs with freshly updated templates each run, the same
target on the same version can produce a new finding from one day to the next.

---

## Web dashboard (`dashboard.py`)

A separate, dependency-free file (Python 3 standard library only). It reads the
history in `./history/` and serves an authenticated panel.

```bash
python3 dashboard.py --set-password   # set user/password (once)
python3 dashboard.py --port 8765      # start on http://127.0.0.1:8765/
```

Credentials are stored in `.env` as `DASHBOARD_USER` and `DASHBOARD_PASS_HASH`
(salted SHA-256 — never in clear text). The default bind is `127.0.0.1`; serve
TLS directly with `--cert/--key`, or put it behind a reverse proxy. The home
page lists every domain with its technologies, open ports, Nuclei count,
**verified secrets**, **API routes** and a **N new** badge; the per-domain page
shows the full timeline with new findings highlighted. `GET /health` answers
without authentication.

> ⚠️ Never expose it with `--host 0.0.0.0` without `--cert/--key` and without a
> reverse proxy: Basic Auth over plain HTTP sends the password in clear text.

---

## Running daily via cron

```cron
0 3 * * * cd /opt/recon && ./recon.sh -l domains.txt -a >> /opt/recon/logs/recon-$(date +\%Y\%m\%d).log 2>&1
```

Since the script asks for the API keys only the *first* time and then reads them
from `.env`, cron runs without interaction — as long as `.env` already exists
with the keys before you schedule it. Run the dashboard permanently via systemd
(see the `recon-dashboard.service` example below).

```ini
[Unit]
Description=recon.sh dashboard
After=network.target

[Service]
Type=simple
User=recon
WorkingDirectory=/opt/recon
ExecStart=/usr/bin/python3 dashboard.py --port 8765 --host 127.0.0.1
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Output

```
recon_<domain>/
├── SUMMARY.md                # per-target summary
├── js/                       # downloaded .js files
└── results/
    ├── files-js.txt          # JS files found
    ├── js-failed.txt         # JS URLs that failed to download
    ├── secrets.json          # SecretFinder (with -j)
    ├── trufflehog.jsonl      # TruffleHog findings (Verified=true => live)
    ├── gitleaks.json         # Gitleaks findings
    ├── secrets-all.txt       # consolidated secrets report (values redacted)
    ├── tech.txt / tech.json  # fingerprint (-t)
    ├── whatweb_verbose.txt   # WhatWeb, readable (-T)
    ├── whatweb.json          # WhatWeb JSON (-T)
    ├── security-headers.txt  # OWASP header analysis (-T)
    ├── tech-detected.txt     # techs registered for vuln validation
    ├── httpx-preflight.txt   # preflight status (Phase 1)
    ├── subdomains.txt        # subdomains (-S)
    ├── urls.txt              # historical URLs (-U)
    ├── probe.txt             # live hosts (-p, httpx)
    ├── naabu.txt             # open ports, top 100 (-p)
    ├── ffuf.json / dirs.txt  # content discovery (-d)
    ├── kiterunner.txt        # kiterunner raw output (-k)
    ├── api-routes.txt        # extracted API routes (-k)
    ├── gf-<pattern>.txt       # gf filters (-g)
    ├── wpscan.txt            # WordPress validation
    ├── nuclei.txt / .jsonl   # Nginx/Apache validation
    └── searchsploit.txt      # exploits by version

./owasp-headers-report.md    # consolidated OWASP report (all applications)
./recon-final-report.md      # final consolidated result (all targets)
./live-targets.txt           # live targets found in Phase 1 (preflight)
./.env                       # API keys + dashboard credentials (chmod 600)
./history/
├── index.jsonl               # global index (all domains, all runs)
└── <domain>/<timestamp>.json # per-run snapshot (techs, ports, findings...)
./dashboard.py                # authenticated web panel (history + new findings)
```

---

## Legal notice

This tool is intended for **authorized** testing only. `--all`, `-T`
(aggression 3), ffuf/kiterunner fuzzing, TruffleHog verification and the
wpscan/nuclei stage generate significant traffic and are visible in the target's
logs. Use it only against systems you have explicit written permission to test.
Misuse is the sole responsibility of whoever runs it.
