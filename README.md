# recon.sh — v5.1

A single-file **web reconnaissance** toolkit in Bash. It chains the tools you'd
otherwise run by hand into one combinable pipeline:

- **Subdomains** (sublist3r / crt.sh) and **DNS brute-force** (enumdns)
- **JS crawling** — recursively mirror a site's front-end (SPA-aware)
- **Secrets** in that JS (SecretFinder + TruffleHog *verified* + Gitleaks)
- **JS dependencies → CVEs** (versions from bundles → OSV.dev)
- **Tech fingerprint** + **OWASP header** analysis + **vulnerability validation**
  (WPScan / Nuclei / searchsploit)
- **Content & API discovery** (ffuf + SecLists, kiterunner), historical URLs (gau)
- A **web dashboard** with per-run history and 🆕 new-finding detection

Modes are **combinable** and always run in a sensible order, whatever order you
pass the flags in.

```bash
./recon.sh -u https://target.com/ [modes...] [options]
```

> **Authorized testing only.** See [Legal notice](#legal-notice).

---

## Install

```bash
git clone https://github.com/ViniciusClement/recon.git
cd recon
chmod +x recon.sh

./recon.sh --check           # show what's installed / missing
./recon.sh --install-deps    # install what recon can install, then exit
```

`--install-deps` sets up the things recon bundles locally (Python modules,
SecretFinder, SecLists, kiterunner routes, and **enumdns** — cloned + built into
`./enumdns/`, needs **Go 1.23+**). External tools (gau, httpx, naabu, ffuf,
nuclei, whatweb, wpscan…) are installed per their own instructions — run
`--check` to see the exact command for each. See [Dependencies](#dependencies).

Base requirements: `bash`, `curl`, `python3`, `git`.

---

## Quick examples

```bash
# Everything, one target
./recon.sh -u https://target.com/ --all -v

# Crawl the JS and hunt secrets in it
./recon.sh -u https://target.com/ -f -s

# JS dependencies + known CVEs (auto-crawls first)
./recon.sh -u https://target.com/ -J

# DNS brute-force the domain
./recon.sh -u https://target.com/ -B

# Tech + deep fingerprint + OWASP headers (vuln validation runs automatically)
./recon.sh -u https://target.com/ -T

# Attack-surface map: subdomains + DNS brute + port/live probe
./recon.sh -u https://target.com/ -S -B -p

# Content & API discovery
./recon.sh -u https://target.com/ -d -k

# A whole list of targets (one per line; a liveness preflight runs first)
./recon.sh -l targets.txt -S -U -f -T -p -v
```

Targets can be a bare domain or a full URL; `-u` is repeatable and combines with
`-l`. Each target writes to its own `./recon_<domain>/` folder.

---

## Modes (combinable)

| Flag | Does |
|------|------|
| `-f, --files`      | Recursively **download** the site's JS/CSS/images (SPA-aware mirror under `js/`) |
| `-s, --secret`     | Find secrets in the downloaded JS (SecretFinder + TruffleHog *verified* + Gitleaks) |
| `-J, --libs`       | **JS dependencies + versions + CVEs** (OSV.dev; retire.js if installed) |
| `-t, --tech`       | Technology fingerprint + version guess |
| `-T, --tech-deep`  | Deep fingerprint (WhatWeb) + OWASP security-header analysis |
| `-S, --subdomains` | Enumerate subdomains (sublist3r; crt.sh fallback) |
| `-B, --brute`      | **DNS brute-force** with enumdns |
| `-U, --urls`       | Historical URLs for the domain (gau) |
| `-p, --probe`      | Port scan (naabu top 100) + live hosts (httpx) |
| `-d, --dirs`       | Content discovery — ffuf + SecLists (dirsearch fallback) |
| `-k, --kite`       | API route discovery — kiterunner |
| `-g, --gf`         | Flag dangerous URLs (gf + Gf-Patterns) |
| `-a, --all`        | Run every module, in order |

**Pipeline order:** subdomains → brute → urls → files → tech → tech-deep →
secret → libs → probe → dirs → kite → gf → vulnerability validation.

Vulnerability validation (WPScan / Nuclei / searchsploit) runs **automatically**
after `-t`/`-T`; disable it with `--no-vuln`.

---

## Feature notes & examples

### DNS brute-force (`-B`, enumdns)

recon.sh **wraps the real [enumdns](https://github.com/helviojunior/enumdns)
binary** (cloned + built into `./enumdns/`) and runs `enumdns brute` — you get
enumdns's full resolution engine, not a bash reimplementation.

```bash
./recon.sh -u target.com -B                                  # default wordlist
./recon.sh -u target.com -B --brute-wordlist words.txt       # custom wordlist
./recon.sh -u target.com -B --brute-quick --resolver 8.8.8.8 # A-only, custom DNS
./recon.sh -u target.com -B --enumdns-args "--allow-tld"     # pass raw enumdns flags
```

Wordlist resolves from `--brute-wordlist` → `-w` → a SecLists `Discovery/DNS`
list. Output: `results/dns-brute.txt`.

### Full-site mirror (`-f`)

Breadth-first, same-origin crawl that downloads JS/CSS/images and follows
references inside each text asset (Vite/webpack lazy chunks, `srcset`, `url()`,
sourcemaps). It drops SPA fallbacks (a missing path that returns `200 text/html`)
so the mirror stays clean.

```bash
./recon.sh -u target.com -f                                  # default: depth 8, 5000 files
./recon.sh -u target.com -f --js-depth 12 --js-max 20000     # exhaustive full-site mirror
./recon.sh -u target.com -f --js-third-party                 # also pull CDN/3rd-party assets
```

Output: mirror under `js/<host>/…`, `results/files-js.txt`, `results/assets-all.txt`.

### JS dependencies & CVEs (`-J`)

Inventories the JS libraries a site ships and flags vulnerable versions. Versions
come from inlined `package.json` manifests, `/*! jQuery v… */` / `ng-version=…`
banners and `node_modules/<pkg>/` paths; each `name@version` is checked against
**[OSV.dev](https://osv.dev)** for CVEs.

```bash
./recon.sh -u target.com -J                    # crawl (if needed) + deps + CVEs
./recon.sh -u target.com -f -J                 # explicit crawl, then analyse
./recon.sh -u target.com -J --no-cve-lookup    # offline inventory only
```

Privacy: only public **package names/versions** are sent to OSV.dev — never the
target URL or any of your data. Outputs: `results/js-libs.txt`,
`results/js-libs.json`, `results/js-dependencies-report.md`.

### Secret scanning (`-s`)

Runs over the downloaded JS mirror (auto-crawls if needed). TruffleHog
**live-verifies** each secret against the provider API — a *verified* secret is
valid right now, triage it immediately. Consolidated to `results/secrets-all.txt`.

```bash
./recon.sh -u target.com -f -s                 # crawl deep, then scan
./recon.sh -u target.com -s --no-verify        # skip live verification
```

---

## Common options

| Option | Meaning |
|--------|---------|
| `-u, --url <URL>` / `-l, --list <file>` | Target(s); `-u` repeatable, `-l` is one per line (`#` = comment) |
| `-o, --output <file>` | Specific output file (ignored with multiple targets) |
| `-w, --wordlist <file>` / `--wordlist-size <s>` | Wordlist for `-d` (SecLists raft `small\|medium\|large`) |
| `--brute-wordlist <f>` / `--brute-quick` / `--resolver <ip>` / `--enumdns-args <s>` | `-B` tuning |
| `--no-cve-lookup` | `-J`: inventory only, no OSV.dev (offline) |
| `--js-depth <n>` / `--js-max <n>` / `--js-third-party` | `-f` crawl bounds & scope (default 8 / 5000) |
| `--no-verify` | `-s`: don't live-verify secrets |
| `--no-vuln` | Disable the WPScan/Nuclei/searchsploit stage |
| `--timeout <sec>` | Per-request timeout (default 15) |
| `--rotate-agent` | Rotate the User-Agent every 5 requests |
| `--no-self-update` | Skip updating the script / CVE databases before running |
| `-v, --verbose` · `-j, --json` · `--no-color` | Logging / output |
| `--check` · `--install-deps` · `--yes` · `--no-install` | Dependency management |

Run `./recon.sh --help` for the full list.

---

## Output

Everything for a target lives in `./recon_<domain>/`:

```
recon_target.com/
├── js/<host>/…               mirrored assets (-f)
├── SUMMARY.md                per-target summary
└── results/
    ├── subdomains.txt  dns-brute.txt      files-js.txt  assets-all.txt
    ├── secrets-all.txt trufflehog.jsonl   js-dependencies-report.md
    ├── tech.txt  security-headers.txt  nuclei.txt  wpscan.txt
    └── ffuf.json  api-routes.txt  urls.txt  probe.txt
```

A global `./recon-final-report.md` is written across all targets, and per-run
snapshots go to `./history/` for the dashboard.

---

## Web dashboard

A zero-dependency (stdlib only) web UI over the run history, with per-domain
timelines and 🆕 new-finding highlighting.

```bash
python3 dashboard.py --set-password      # once: set user + password (stored hashed in .env)
python3 dashboard.py --port 8765         # serves on 127.0.0.1 only by default
```

Expose it only behind TLS: use `--cert/--key` for direct HTTPS, or a reverse
proxy. Basic-Auth over plain HTTP on a public address leaks the password.

---

## Dependencies

| Tool | Role | Install |
|------|------|---------|
| **enumdns** | `-B` DNS brute-force | `--install-deps` (clone + `go build`, Go 1.23+) or a [release binary](https://github.com/helviojunior/enumdns/releases) |
| **js-deps-cve.py** | `-J` scanner (bundled) | ships with recon; CVE lookup via OSV.dev (stdlib only) |
| retire.js | optional extra `-J` detector | `npm i -g retire` |
| SecretFinder / SecLists / kiterunner routes | `-s` / `-d` / `-k` | installed/cloned by `--install-deps` |
| TruffleHog / Gitleaks | `-s` | `sudo apt install trufflehog gitleaks` (or releases) |
| Sublist3r / gau / httpx / naabu / ffuf / gf | various | see `--check` for each command |
| WhatWeb / WPScan / Nuclei / searchsploit | `-T` / vuln validation | see `--check` |

`--install-deps` does **not** install Go, Node, or the Go/Ruby external tools —
run `./recon.sh --check` and it prints the exact install line for anything missing.

---

## Legal notice

This tool is for **authorized security testing and education only**. Only run it
against systems you own or have **explicit written permission** to test.
Unauthorized scanning may be illegal. You are responsible for how you use it.

Licensed under the [MIT License](LICENSE).
