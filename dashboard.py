#!/usr/bin/env python3
"""
dashboard.py — painel web autenticado para o histórico do recon.sh

Lê o histórico gravado pelo recon.sh em ./history/ (index.jsonl + snapshots
JSON por domínio) e serve uma dashboard HTML simples, sem dependências além
da biblioteca padrão do Python 3 (nenhum pip install necessário).

Uso:
  # 1) Defina usuário/senha do dashboard (uma vez só; grava em .env)
  python3 dashboard.py --set-password

  # 2) Suba o servidor (por padrão só em 127.0.0.1 — use um reverse proxy
  #    com TLS, ou --cert/--key abaixo, para expor na internet)
  python3 dashboard.py --port 8765

  # 2b) Com HTTPS direto (certificado próprio ou autoassinado)
  python3 dashboard.py --port 8765 --cert cert.pem --key key.pem

Segurança:
  - As credenciais ficam em .env como DASHBOARD_USER e DASHBOARD_PASS_HASH
    (sha256 salgado — nunca em texto puro).
  - Autenticação HTTP Basic, comparação por hmac.compare_digest (evita
    timing attack).
  - Bind padrão é 127.0.0.1: para acessar de fora, use --host 0.0.0.0 SOMENTE
    atrás de um reverse proxy com TLS (Caddy/Nginx/Traefik) ou --cert/--key.
    Basic Auth em HTTP puro exposto à internet vaza a senha em texto claro.
"""
import argparse
import base64
import glob
import hashlib
import hmac
import html
import json
import os
import secrets
import ssl
import sys
from datetime import datetime
from getpass import getpass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, unquote

ENV_FILE = "./.env"
HISTORY_DIR = "./history"


# ---------------------------------------------------------------------------
# .env — mesmo formato usado pelo recon.sh (parsing simples, sem exec/source)
# ---------------------------------------------------------------------------
def load_env(path=ENV_FILE):
    env = {}
    if not os.path.exists(path):
        return env
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip()
            if v.startswith('"') and v.endswith('"') and len(v) >= 2:
                v = v[1:-1]
            env[k] = v
    return env


def save_env_var(key, value, path=ENV_FILE):
    lines = []
    found = False
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    for i, line in enumerate(lines):
        if line.strip().startswith(f"{key}="):
            lines[i] = f'{key}="{value}"\n'
            found = True
            break
    if not found:
        lines.append(f'{key}="{value}"\n')
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def hash_password(password, salt=None):
    if salt is None:
        salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${digest}"


def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
    except ValueError:
        return False
    expected = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return hmac.compare_digest(expected, digest)


def cmd_set_password():
    user = input("Usuário do dashboard [admin]: ").strip() or "admin"
    while True:
        pw1 = getpass("Senha: ")
        pw2 = getpass("Confirme a senha: ")
        if not pw1:
            print("Senha vazia não é permitida.")
            continue
        if pw1 != pw2:
            print("As senhas não coincidem, tente novamente.")
            continue
        break
    save_env_var("DASHBOARD_USER", user)
    save_env_var("DASHBOARD_PASS_HASH", hash_password(pw1))
    print(f"Credenciais salvas em {ENV_FILE} (chmod 600).")


# ---------------------------------------------------------------------------
# Leitura do histórico gravado pelo recon.sh
# ---------------------------------------------------------------------------
def read_index():
    """Lê history/index.jsonl -> lista de {domain, timestamp, file}."""
    idx_path = os.path.join(HISTORY_DIR, "index.jsonl")
    rows = []
    if not os.path.exists(idx_path):
        return rows
    with open(idx_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def load_snapshot(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def domains_overview():
    """Agrupa o índice por domínio, retornando o snapshot mais recente de
    cada um mais a contagem de runs e se o último run trouxe novidade."""
    rows = read_index()
    by_domain = {}
    for r in rows:
        by_domain.setdefault(r["domain"], []).append(r)

    overview = []
    for domain, entries in by_domain.items():
        entries.sort(key=lambda e: e.get("timestamp", ""))
        files = [e["file"] for e in entries if os.path.exists(e.get("file", ""))]
        if not files:
            continue
        latest = load_snapshot(files[-1])
        previous = load_snapshot(files[-2]) if len(files) > 1 else None
        if latest is None:
            continue
        new_findings = diff_findings(previous, latest)
        overview.append({
            "domain": domain,
            "runs": len(files),
            "last_run": latest.get("timestamp", ""),
            "latest": latest,
            "new_findings": new_findings,
        })
    overview.sort(key=lambda o: o["last_run"], reverse=True)
    return overview


def domain_timeline(domain):
    """Lista todos os snapshots de um domínio, mais antigo -> mais novo,
    cada um já com as novidades em relação ao anterior calculadas."""
    rows = [r for r in read_index() if r["domain"] == domain]
    rows.sort(key=lambda r: r.get("timestamp", ""))
    timeline = []
    prev_snap = None
    for r in rows:
        snap = load_snapshot(r.get("file", ""))
        if snap is None:
            continue
        new_findings = diff_findings(prev_snap, snap)
        timeline.append({"snapshot": snap, "new_findings": new_findings})
        prev_snap = snap
    timeline.reverse()  # mais recente primeiro na tela
    return timeline


def diff_findings(previous, current):
    """Achados do snapshot atual que não existiam no anterior (mesma lógica
    do recon.sh, refeita aqui para exibição na dashboard)."""
    if current is None:
        return []
    prev_nuclei = set((previous or {}).get("nuclei_findings", []))
    prev_wp = set((previous or {}).get("wpscan_vulnerabilities", []))
    new = []
    for line in current.get("nuclei_findings", []):
        if line not in prev_nuclei:
            new.append(("Nuclei", line))
    for line in current.get("wpscan_vulnerabilities", []):
        if line not in prev_wp:
            new.append(("WPScan", line))
    return new


def fmt_ts(ts):
    """20260924-030512 -> 2026-09-24 03:05:12"""
    try:
        d = datetime.strptime(ts, "%Y%m%d-%H%M%S")
        return d.strftime("%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return ts or "—"


# ---------------------------------------------------------------------------
# HTML (sem dependências externas, CSS embutido)
# ---------------------------------------------------------------------------
BASE_CSS = """
:root{--bg:#0b0f14;--panel:#121820;--border:#1f2833;--text:#e6edf3;
--muted:#8b98a5;--accent:#4fd1c5;--warn:#f0b429;--bad:#f25f5c;--ok:#3fb950;}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
margin:0;padding:0 0 3rem;}
header{padding:1.5rem 2rem;border-bottom:1px solid var(--border);display:flex;
align-items:center;justify-content:space-between;}
header h1{font-size:1.25rem;margin:0;}
header a{color:var(--accent);text-decoration:none;font-size:.9rem;}
main{max-width:1080px;margin:0 auto;padding:1.5rem 2rem;}
table{width:100%;border-collapse:collapse;margin-top:1rem;}
th,td{text-align:left;padding:.6rem .5rem;border-bottom:1px solid var(--border);font-size:.92rem;}
th{color:var(--muted);font-weight:600;text-transform:uppercase;font-size:.72rem;letter-spacing:.04em;}
tr:hover td{background:#0f151c;}
.badge{display:inline-block;padding:.15rem .5rem;border-radius:999px;font-size:.72rem;font-weight:600;margin-right:.25rem;}
.badge-wp{background:#21455311;color:#4fd1c5;border:1px solid #214553;}
.badge-nginx{background:#1a2e22;color:#3fb950;border:1px solid #234a2f;}
.badge-apache{background:#2e2a1a;color:#f0b429;border:1px solid #4a4123;}
.badge-new{background:#3a1414;color:#f25f5c;border:1px solid #5c1f1f;font-weight:700;}
.badge-ok{background:#132a19;color:#3fb950;border:1px solid #1f4a2b;}
.pill{color:var(--muted);font-size:.85rem;}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:1rem 1.25rem;margin-bottom:1rem;}
.finding{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.82rem;
padding:.4rem .6rem;border-radius:6px;background:#0f151c;margin:.25rem 0;border-left:3px solid var(--border);}
.finding.new{border-left-color:var(--bad);background:#1a0f10;}
.section-title{margin:1.5rem 0 .5rem;font-size:1rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;}
a.domain-link{color:var(--text);text-decoration:none;font-weight:600;}
a.domain-link:hover{color:var(--accent);}
.empty{color:var(--muted);padding:2rem 0;text-align:center;}
"""


def page(title, body, back_link=None):
    back = f'<a href="{back_link}">&larr; voltar</a>' if back_link else ""
    return f"""<!doctype html>
<html lang="pt-br"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — recon.sh dashboard</title>
<style>{BASE_CSS}</style></head>
<body>
<header><h1>🛰️ recon.sh — dashboard</h1>{back}</header>
<main>{body}</main>
</body></html>"""


def render_home():
    overview = domains_overview()
    if not overview:
        body = '<div class="empty">Nenhum histórico encontrado ainda em <code>./history/</code>.<br>' \
               'Rode o recon.sh pelo menos uma vez (com -t ou -T) para começar a popular a dashboard.</div>'
        return page("Domínios", body)

    rows = []
    for o in overview:
        snap = o["latest"]
        badges = []
        for t in snap.get("techs", []):
            name = t.get("name", "")
            ver = t.get("version", "")
            label = f"{name} {ver}".strip()
            css = {"wordpress": "badge-wp", "nginx": "badge-nginx", "apache": "badge-apache"}.get(name, "badge-ok")
            badges.append(f'<span class="badge {css}">{html.escape(label)}</span>')
        badges_html = "".join(badges) or '<span class="pill">—</span>'

        new_badge = ""
        if o["new_findings"]:
            new_badge = f'<span class="badge badge-new">🆕 {len(o["new_findings"])} novo(s)</span>'

        ports = ",".join(snap.get("ports", [])) or "—"
        nuclei_n = len(snap.get("nuclei_findings", []))

        rows.append(f"""<tr>
<td><a class="domain-link" href="/domain/{html.escape(o['domain'])}">{html.escape(o['domain'])}</a></td>
<td>{badges_html}</td>
<td class="pill">{html.escape(ports)}</td>
<td class="pill">{nuclei_n}</td>
<td>{new_badge}</td>
<td class="pill">{fmt_ts(o['last_run'])}</td>
<td class="pill">{o['runs']}</td>
</tr>""")

    body = f"""
<p class="pill">{len(overview)} domínio(s) com histórico. Clique em um domínio para ver a linha do tempo completa.</p>
<table>
<thead><tr><th>Domínio</th><th>Tecnologias</th><th>Portas</th><th>Nuclei</th><th>Novidades</th><th>Último run</th><th>Runs</th></tr></thead>
<tbody>{"".join(rows)}</tbody>
</table>
"""
    return page("Domínios", body)


def render_domain(domain):
    timeline = domain_timeline(domain)
    if not timeline:
        return page(domain, '<div class="empty">Nenhum histórico para este domínio.</div>', back_link="/")

    cards = []
    for entry in timeline:
        snap = entry["snapshot"]
        new = entry["new_findings"]
        ts = fmt_ts(snap.get("timestamp", ""))

        techs = ", ".join(
            f"{t.get('name')} {t.get('version')}".strip() for t in snap.get("techs", [])
        ) or "—"
        ports = ", ".join(snap.get("ports", [])) or "—"

        finding_lines = []
        new_set = set(new)
        for line in snap.get("nuclei_findings", []):
            is_new = ("Nuclei", line) in new_set
            cls = "finding new" if is_new else "finding"
            mark = "🆕 " if is_new else ""
            finding_lines.append(f'<div class="{cls}">{mark}{html.escape(line)}</div>')
        for line in snap.get("wpscan_vulnerabilities", []):
            is_new = ("WPScan", line) in new_set
            cls = "finding new" if is_new else "finding"
            mark = "🆕 " if is_new else ""
            finding_lines.append(f'<div class="{cls}">{mark}[WPScan] {html.escape(line)}</div>')
        findings_html = "".join(finding_lines) or '<span class="pill">Nenhum finding registrado neste run.</span>'

        new_badge = f'<span class="badge badge-new">🆕 {len(new)} novidade(s) desde o run anterior</span>' if new else ""

        cards.append(f"""
<div class="card">
  <strong>{ts}</strong> {new_badge}
  <div class="pill" style="margin-top:.4rem">
    Techs: {html.escape(techs)} &nbsp;·&nbsp;
    Portas: {html.escape(ports)} &nbsp;·&nbsp;
    Subdomínios: {snap.get('subdomains_count', 0)} &nbsp;·&nbsp;
    URLs: {snap.get('urls_count', 0)} &nbsp;·&nbsp;
    Segredos: {snap.get('secrets_count', 0)} &nbsp;·&nbsp;
    Diretórios: {snap.get('dirs_count', 0)}
  </div>
  <div class="section-title">Findings</div>
  {findings_html}
</div>""")

    body = f'<h2 style="margin-top:0">{html.escape(domain)}</h2>' + "".join(cards)
    return page(domain, body, back_link="/")


# ---------------------------------------------------------------------------
# Servidor HTTP com Basic Auth
# ---------------------------------------------------------------------------
class Handler(BaseHTTPRequestHandler):
    server_version = "recon-dashboard/1.0"

    def log_message(self, fmt, *args):
        sys.stderr.write("[dashboard] " + (fmt % args) + "\n")

    def _authenticated(self):
        user = self.server.dash_user
        pass_hash = self.server.dash_pass_hash
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(auth[6:]).decode("utf-8", errors="replace")
            got_user, got_pass = decoded.split(":", 1)
        except Exception:
            return False
        if not hmac.compare_digest(got_user, user):
            return False
        return verify_password(got_pass, pass_hash)

    def _deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="recon-dashboard"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write(b"Autenticacao necessaria.")

    def _send_html(self, content, status=200):
        body = content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        path = unquote(parsed.path)

        if path == "/health":
            self._send_html("ok")
            return

        if not self._authenticated():
            self._deny()
            return

        if path == "/" or path == "":
            self._send_html(render_home())
        elif path.startswith("/domain/"):
            domain = path[len("/domain/"):].strip("/")
            if not domain:
                self._send_html(render_home())
                return
            self._send_html(render_domain(domain))
        else:
            self._send_html(page("Não encontrado", '<div class="empty">404 — página não encontrada.</div>'), status=404)


def run_server(host, port, cert=None, key=None):
    env = load_env()
    user = env.get("DASHBOARD_USER")
    pass_hash = env.get("DASHBOARD_PASS_HASH")
    if not user or not pass_hash:
        print("Credenciais do dashboard não configuradas.", file=sys.stderr)
        print(f"Rode primeiro: python3 {sys.argv[0]} --set-password", file=sys.stderr)
        sys.exit(1)

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.dash_user = user
    httpd.dash_pass_hash = pass_hash

    scheme = "http"
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert, keyfile=key)
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
        scheme = "https"

    if host not in ("127.0.0.1", "localhost") and scheme == "http":
        print("AVISO: servindo HTTP (sem TLS) em um endereço não-local.", file=sys.stderr)
        print("       Basic Auth em HTTP puro expõe a senha em texto claro na rede.", file=sys.stderr)
        print("       Use --cert/--key, ou coloque atrás de um reverse proxy com TLS.", file=sys.stderr)

    print(f"Dashboard em {scheme}://{host}:{port}/  (usuário: {user})", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    global HISTORY_DIR
    ap = argparse.ArgumentParser(description="Dashboard web do histórico do recon.sh")
    ap.add_argument("--set-password", action="store_true", help="Define/atualiza usuário e senha do dashboard")
    ap.add_argument("--host", default="127.0.0.1", help="Endereço para bind (default: 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8765, help="Porta (default: 8765)")
    ap.add_argument("--history-dir", default=HISTORY_DIR, help="Diretório de histórico do recon.sh")
    ap.add_argument("--cert", default=None, help="Certificado TLS (PEM) para servir HTTPS diretamente")
    ap.add_argument("--key", default=None, help="Chave privada TLS (PEM) correspondente ao --cert")
    args = ap.parse_args()

    HISTORY_DIR = args.history_dir

    if args.set_password:
        cmd_set_password()
        return

    if bool(args.cert) != bool(args.key):
        print("Erro: --cert e --key precisam ser usados juntos.", file=sys.stderr)
        sys.exit(1)

    run_server(args.host, args.port, cert=args.cert, key=args.key)


if __name__ == "__main__":
    main()
