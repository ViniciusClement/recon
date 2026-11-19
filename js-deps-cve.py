#!/usr/bin/env python3
"""
js-deps-cve.py — identify JavaScript dependencies + versions in a downloaded JS
mirror, then look up known CVEs for them via the OSV.dev database.

Called by recon.sh's -J/--libs mode over the ./recon_<domain>/js mirror that the
-f crawler produces. Can also be run standalone:

    python3 js-deps-cve.py --js-dir recon_site.com/js --out-dir recon_site.com/results

It extracts dependencies three ways:
  1. Inlined manifests — bundlers (Angular/Vite/webpack) often ship the app's
     package.json data inside a chunk: name/version plus "dependencies": {...}
     with "pkg":"range" pairs. These are the highest-signal source.
  2. Version banners / globals — /*! jQuery v3.6.0 */, ng-version="19.2.14",
     Vue.version, React version, generic "Name vX.Y.Z" license headers.
  3. node_modules/<pkg>/ paths left in source maps / webpack output (name only).

CVE lookup uses the OSV.dev HTTP API (ecosystem: npm). Only public library
names and versions leave the machine — no target URL, host or user data. Disable
with --no-cve-lookup for a fully offline inventory.
"""
import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error

# --------------------------------------------------------------------------- IO
TEXT_EXT = (".js", ".mjs", ".cjs", ".map", ".json", ".html", ".htm", ".txt")
MAX_FILE_BYTES = 12 * 1024 * 1024          # skip reading past 12 MB of one file
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"

SEMVER = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-+][0-9A-Za-z.\-]+)?)")


def clean_version(raw):
    """Strip range operators (^ ~ >= etc.) and return a concrete semver or None."""
    if not raw:
        return None
    m = SEMVER.search(raw)
    return m.group(1) if m else None


def iter_text_files(js_dir):
    for root, _dirs, files in os.walk(js_dir):
        for f in files:
            if f.lower().endswith(TEXT_EXT):
                yield os.path.join(root, f)


def read_text(path):
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE_BYTES if size > MAX_FILE_BYTES else size)
        return data.decode("utf-8", "ignore")
    except OSError:
        return ""


# ----------------------------------------------------------------- extraction
DEP_BLOCK_KEYS = ("dependencies", "devDependencies", "peerDependencies",
                  "optionalDependencies")
# "pkg":"range"  — pkg may be @scope/name; range starts with a digit or ^~>=<v
DEP_PAIR = re.compile(r'"(@?[\w.\-]+(?:/[\w.\-]+)?)"\s*:\s*"([\^~>=<v\s]*\d[^"]*)"')


def _matching_brace(text, open_idx):
    """Given index of a '{', return index just past its matching '}' (or len)."""
    depth = 0
    i = open_idx
    n = len(text)
    while i < n:
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def extract_manifest_deps(text, rel, found):
    """Find dependencies:{...} blocks and pull "pkg":"version" pairs."""
    for key in DEP_BLOCK_KEYS:
        for m in re.finditer(r'[\'"]?' + key + r'[\'"]?\s*:\s*\{', text):
            brace = text.index("{", m.end() - 1)
            block = text[brace:_matching_brace(text, brace)]
            for pm in DEP_PAIR.finditer(block):
                name, rng = pm.group(1), pm.group(2)
                ver = clean_version(rng)
                if ver:
                    found.append((name, ver, "manifest:" + key, rel))


# (needle in lower(text), compiled regex, canonical package name) heuristics.
BANNER_PATTERNS = [
    (r'angular', re.compile(r'ng-version="(\d+\.\d+\.\d+)"'), "@angular/core"),
    (r'jquery', re.compile(r'jQuery JavaScript Library v(\d+\.\d+\.\d+)'), "jquery"),
    (r'jquery', re.compile(r'\bjquery["\']?\s*[:=]\s*["\'](\d+\.\d+\.\d+)'), "jquery"),
    (r'vue', re.compile(r'Vue\.version\s*=\s*["\'](\d+\.\d+\.\d+)'), "vue"),
    (r'bootstrap', re.compile(r'Bootstrap v(\d+\.\d+\.\d+)'), "bootstrap"),
    (r'lodash', re.compile(r'lodash[\s\S]{0,80}?VERSION\s*=\s*["\'](\d+\.\d+\.\d+)'), "lodash"),
    (r'moment', re.compile(r'moment[\s\S]{0,40}?version["\']?\s*[:=]\s*["\'](\d+\.\d+\.\d+)'), "moment"),
]

GENERIC_BANNER = re.compile(
    r'(?:/\*!?|\*|@license)\s*([A-Za-z][A-Za-z0-9_.\- ]{1,40}?)[\s\-]+v?(\d+\.\d+\.\d+[\w.\-]*)')
NODE_MODULES = re.compile(r'node_modules/((?:@[\w.\-]+/)?[\w.\-]+)')


def extract_banners(text, rel, found, names_only):
    low = text.lower()
    for needle, rx, pkg in BANNER_PATTERNS:
        if needle in low:
            m = rx.search(text)
            if m:
                found.append((pkg, m.group(1), "banner", rel))
    for m in GENERIC_BANNER.finditer(text):
        name = m.group(1).strip().lower().replace(" ", "-")
        ver = clean_version(m.group(2))
        if name and ver and 2 <= len(name) <= 40:
            found.append((name, ver, "banner", rel))
    for m in NODE_MODULES.finditer(text):
        names_only.add(m.group(1))


def extract_all(js_dir):
    found = []                 # (name, version, source, file)
    names_only = set()         # packages seen without a version
    files = 0
    for path in iter_text_files(js_dir):
        text = read_text(path)
        if not text:
            continue
        files += 1
        rel = os.path.relpath(path, js_dir).replace("\\", "/")
        extract_manifest_deps(text, rel, found)
        extract_banners(text, rel, found, names_only)
    # Dedup (name, version), keeping the first source/file seen.
    seen = {}
    for name, ver, src, rel in found:
        key = (name.lower(), ver)
        if key not in seen:
            seen[key] = {"name": name, "version": ver, "source": src, "file": rel}
    have = {d["name"].lower() for d in seen.values()}
    names_only = sorted(n for n in names_only if n.lower() not in have)
    return list(seen.values()), names_only, files


# ------------------------------------------------------------------- OSV / CVE
def _post_json(url, payload, timeout):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body,
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": "recon-sh-js-deps"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))


def _get_json(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": "recon-sh-js-deps"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "ignore"))


def osv_lookup(inventory, timeout):
    """Query OSV.dev for each name@version. Returns ({idx:[ids]}, {id:details})."""
    queries = [{"package": {"ecosystem": "npm", "name": d["name"]},
                "version": d["version"]} for d in inventory]
    if not queries:
        return {}, {}
    id_by_idx = {}
    for start in range(0, len(queries), 500):      # querybatch caps ~1000
        chunk = queries[start:start + 500]
        try:
            resp = _post_json(OSV_BATCH_URL, {"queries": chunk}, timeout)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
            raise RuntimeError("OSV batch query failed: %s" % e)
        for i, res in enumerate(resp.get("results", [])):
            vulns = res.get("vulns") or []
            if vulns:
                id_by_idx[start + i] = [v["id"] for v in vulns]
    # Enrich: fetch details (CVE aliases, severity, summary) per unique vuln id.
    details = {}
    unique_ids = {vid for ids in id_by_idx.values() for vid in ids}
    for vid in sorted(unique_ids)[:200]:           # cap detail fetches
        try:
            d = _get_json(OSV_VULN_URL + vid, timeout)
        except (urllib.error.URLError, TimeoutError, ValueError, OSError):
            continue
        aliases = [a for a in d.get("aliases", []) if a.startswith("CVE-")]
        sev = ""
        for s in d.get("severity", []) or []:
            sev = s.get("score", "") or sev
        db_sev = (d.get("database_specific") or {}).get("severity", "")
        details[vid] = {"cve": aliases,
                        "summary": (d.get("summary", "") or "")[:160],
                        "severity": db_sev or sev}
    return id_by_idx, details


# ---------------------------------------------------------------------- output
def write_outputs(out_dir, domain, inventory, names_only, id_by_idx, details,
                  cve_enabled, cve_error):
    os.makedirs(out_dir, exist_ok=True)

    for i, d in enumerate(inventory):
        d["vulns"] = id_by_idx.get(i, [])
    with open(os.path.join(out_dir, "js-libs.json"), "w", encoding="utf-8") as fh:
        json.dump({"domain": domain, "dependencies": inventory,
                   "packages_without_version": names_only}, fh, indent=2)

    with open(os.path.join(out_dir, "js-libs.txt"), "w", encoding="utf-8") as fh:
        for d in sorted(inventory, key=lambda x: x["name"].lower()):
            fh.write("%s\t%s\t%s\t%s\n" % (d["name"], d["version"],
                                           d["source"], d["file"]))
        for n in names_only:
            fh.write("%s\t(version unknown)\tpath\t-\n" % n)

    vulnerable = [(d, id_by_idx.get(i, []))
                  for i, d in enumerate(inventory) if id_by_idx.get(i)]
    total_cves = sum(len(v) for _d, v in vulnerable)
    lines = ["# JavaScript dependencies & CVEs — %s" % domain, ""]
    lines.append("- Dependencies with a version: **%d**" % len(inventory))
    lines.append("- Packages seen without a version: **%d**" % len(names_only))
    if cve_enabled and not cve_error:
        lines.append("- Vulnerable dependencies: **%d** (%d advisory/-ies)"
                     % (len(vulnerable), total_cves))
    elif cve_error:
        lines.append("- CVE lookup: **failed** (%s) — inventory only" % cve_error)
    else:
        lines.append("- CVE lookup: **disabled** (--no-cve-lookup) — inventory only")
    lines.append("")

    if vulnerable:
        lines.append("## Vulnerable dependencies")
        lines.append("")
        lines.append("| Package | Version | Advisories | CVEs | Max severity | Summary |")
        lines.append("|---|---|---|---|---|---|")
        for d, ids in sorted(vulnerable, key=lambda x: -len(x[1])):
            cves, sev, summ = set(), "", ""
            for vid in ids:
                det = details.get(vid, {})
                cves.update(det.get("cve", []))
                sev = det.get("severity", "") or sev
                summ = summ or det.get("summary", "")
            cve_str = ", ".join(sorted(cves)) if cves else ", ".join(ids[:4])
            lines.append("| `%s` | %s | %d | %s | %s | %s |"
                         % (d["name"], d["version"], len(ids), cve_str,
                            sev or "-", summ.replace("|", "/")))
        lines.append("")

    lines.append("## All detected dependencies")
    lines.append("")
    lines.append("| Package | Version | Source |")
    lines.append("|---|---|---|")
    for d in sorted(inventory, key=lambda x: x["name"].lower()):
        flag = " (!)" if d.get("vulns") else ""
        lines.append("| `%s`%s | %s | %s |" % (d["name"], flag, d["version"], d["source"]))
    lines.append("")

    report = os.path.join(out_dir, "js-dependencies-report.md")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return len(inventory), len(vulnerable), total_cves, report


# ------------------------------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser(description="JS dependency + CVE scanner for recon.sh")
    ap.add_argument("--js-dir", required=True, help="the js/ mirror directory")
    ap.add_argument("--out-dir", required=True, help="results/ output directory")
    ap.add_argument("--domain", default="target", help="domain label for reports")
    ap.add_argument("--timeout", type=float, default=20.0, help="per-request timeout (s)")
    ap.add_argument("--no-cve-lookup", action="store_true",
                    help="skip OSV.dev — produce an offline inventory only")
    args = ap.parse_args()

    if not os.path.isdir(args.js_dir):
        print("js-deps-cve: no JS mirror at %s (run -f first)" % args.js_dir,
              file=sys.stderr)
        return 2

    inventory, names_only, nfiles = extract_all(args.js_dir)
    print("js-deps-cve: scanned %d file(s); %d versioned dependency/-ies, "
          "%d package(s) without a version" % (nfiles, len(inventory), len(names_only)),
          file=sys.stderr)

    id_by_idx, details, cve_error = {}, {}, ""
    if not args.no_cve_lookup and inventory:
        try:
            id_by_idx, details = osv_lookup(inventory, args.timeout)
        except RuntimeError as e:
            cve_error = str(e)
            print("js-deps-cve: %s" % cve_error, file=sys.stderr)

    n, nvuln, ncve, report = write_outputs(
        args.out_dir, args.domain, inventory, names_only, id_by_idx, details,
        cve_enabled=not args.no_cve_lookup, cve_error=cve_error)
    print("js-deps-cve: %d dependency/-ies, %d vulnerable, %d advisory/-ies -> %s"
          % (n, nvuln, ncve, report), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
