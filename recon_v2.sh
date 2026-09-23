#!/usr/bin/env bash
#
# recon.sh (v3) - Recon de JS + secrets + tech fingerprint + integrações opcionais
#
# Principais melhorias em relação à v2:
#   * Modos agora são COMBINÁVEIS (ex.: -f -s -t) em vez de um sobrescrever o outro.
#   * Flags curtas + longas no padrão getopts (-u/--url, -f/--files, ...).
#   * Verificador/instalador de dependências (--check / --install-deps), incluindo
#     os módulos Python do SecretFinder (jsbeautifier, requests, lxml, requests-file),
#     com tratamento do "externally-managed-environment" do Kali/Debian.
#   * Auto-clone opcional do SecretFinder quando ausente.
#
# Exemplos:
#   ./recon.sh -u https://site.com/ --install-deps
#   ./recon.sh -u https://site.com/ -f -s -v
#   ./recon.sh -u https://site.com/ -t --json
#   ./recon.sh -u https://site.com/ -T            # tech-deep (WhatWeb) + validação de vulns
#   ./recon.sh -u https://site.com/ --all
#   ./recon.sh -u https://site.com/ -d -w wordlist.txt
#   ./recon.sh -l sites.txt -f -s          # vários alvos, um por linha
#   ./recon.sh -l sites.txt -u extra.com -t # lista + alvo avulso juntos
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
URL=""
LIST_FILE=""                 # arquivo com uma lista de alvos (um por linha)
declare -a URL_ARGS=()       # alvos passados via -u (pode repetir)
declare -a MODES=()          # modos acumulados (combináveis)
declare -a TARGETS=()        # lista final de alvos a processar
VERBOSE=0
JSON=0
OUT_FILE=""
JS_LIST_FILE=""
CUSTOM_AGENT=0
WORDLIST=""
GF_PATTERN="xss"
TIMEOUT=15
NO_COLOR=0
AUTO_INSTALL=0               # instala deps sem perguntar (--install-deps / --yes)
NO_AUTO_INSTALL=0            # nunca tenta instalar automaticamente (--no-install)
DO_CHECK_ONLY=0              # apenas checa deps e sai (--check)
DO_INSTALL_ONLY=0           # instala deps e sai (--install-deps)
NO_VULN=0                    # desativa a validação de vulnerabilidades (--no-vuln)
NO_PREFLIGHT=0              # pula a checagem de liveness com httpx (--no-preflight)

SECRETFINDER_PATH="${SECRETFINDER_PATH:-./SecretFinder/SecretFinder.py}"

# Arquivo .env (chaves de API) e opções das ferramentas de vuln
ENV_FILE="${ENV_FILE:-./.env}"
WPSCAN_ENUM="${WPSCAN_ENUM:-vp,vt,u}"   # vulnerable plugins, vulnerable themes, users

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
    c_red=''; c_grn=''; c_yel=''; c_blu=''; c_rst=''
  else
    c_red='\033[0;31m'; c_grn='\033[0;32m'; c_yel='\033[1;33m'; c_blu='\033[0;34m'; c_rst='\033[0m'
  fi
}
c_red=''; c_grn=''; c_yel=''; c_blu=''; c_rst=''
log()  { echo -e "${c_blu}[*]${c_rst} $*" >&2; }
ok()   { echo -e "${c_grn}[+]${c_rst} $*" >&2; }
warn() { echo -e "${c_yel}[!]${c_rst} $*" >&2; }
err()  { echo -e "${c_red}[-]${c_rst} $*" >&2; }
vlog() { [ "$VERBOSE" -eq 1 ] && log "$*"; return 0; }

WORKDIR="$(mktemp -d /tmp/jsrecon.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Gerenciamento de chaves de API (.env)
# ---------------------------------------------------------------------------
# Carrega KEY=VALUE do .env sem executar código (parsing seguro, sem `source`).
load_env() {
  [ -f "$ENV_FILE" ] || return 0
  local k v
  while IFS='=' read -r k v; do
    case "$k" in ''|\#*) continue ;; esac
    k="$(echo "$k" | tr -d '[:space:]')"
    [ -z "$k" ] && continue
    v="${v%\"}"; v="${v#\"}"          # remove aspas de abertura/fechamento
    export "$k=$v"
  done < "$ENV_FILE"
  vlog ".env carregado de $ENV_FILE"
}

# Grava/atualiza uma chave no .env com permissão 600.
save_env_var() {
  local key="$1" val="$2"
  touch "$ENV_FILE" 2>/dev/null || { warn "Não foi possível escrever em $ENV_FILE"; return 1; }
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  if grep -qE "^${key}=" "$ENV_FILE" 2>/dev/null; then
    sed -i -E "s|^${key}=.*|${key}=\"${val}\"|" "$ENV_FILE"
  else
    echo "${key}=\"${val}\"" >> "$ENV_FILE"
  fi
}

# Garante uma chave de API: se ausente no ambiente/.env, solicita ao usuário
# (entrada oculta) e persiste no .env. Sem terminal interativo, apenas avisa.
#   ensure_api_key <NOME_VAR> "<prompt>" [obrigatoria=0|1]
ensure_api_key() {
  local key="$1" prompt="$2" required="${3:-0}" cur val
  cur="$(printenv "$key" 2>/dev/null || true)"
  if [ -n "$cur" ]; then
    vlog "$key já definido (via ambiente ou $ENV_FILE)"
    return 0
  fi
  if [ ! -e /dev/tty ]; then
    if [ "$required" -eq 1 ]; then
      warn "$key não definido e sem terminal interativo. Defina no $ENV_FILE ou exporte a variável."
    else
      vlog "$key ausente; sem terminal para solicitar (opcional). Seguindo."
    fi
    return 1
  fi
  printf '%b[?]%b %s: ' "$c_yel" "$c_rst" "$prompt" >&2
  read -r -s val </dev/tty 2>/dev/null; echo >&2
  if [ -z "$val" ]; then
    [ "$required" -eq 1 ] && warn "$key deixado em branco."
    return 1
  fi
  export "$key=$val"
  save_env_var "$key" "$val" && ok "$key salvo em $ENV_FILE (chmod 600)"
  return 0
}

# ---------------------------------------------------------------------------
# Ajuda
# ---------------------------------------------------------------------------
usage() {
  cat <<EOF
recon.sh — reconhecimento web (JS, secrets, tech, subdomínios, etc.)

Uso:
  $0 -u <URL> [modos...] [opções]

Modos (podem ser COMBINADOS numa mesma execução):
  -f, --files        Extrai .js do HTML, resolve URLs e baixa os arquivos
  -s, --secret       Roda o SecretFinder nos .js (e no HTML) em busca de segredos
  -t, --tech         Fingerprint de tecnologias + tentativa de versão
  -T, --tech-deep    Fingerprint aprofundado com WhatWeb (aggression=3, logs)
  -S, --subdomains   Enumera subdomínios (sublist3r; fallback crt.sh)
  -U, --urls         Coleta URLs históricas do domínio (gau)
  -p, --probe        Sonda hosts/URLs vivos (httpx)
  -d, --dirs         Brute-force de diretórios (dirsearch) — requer --wordlist
  -g, --gf           Filtra URLs coletadas por padrões perigosos (gf + Gf-Patterns)
  -a, --all          Roda todos os módulos disponíveis, em ordem lógica

Opções:
  -u, --url <URL>          URL alvo (aceita vários -u; combina com -l)
  -l, --list <arq>         Arquivo com lista de alvos, um por linha
                           (aceita domínio puro ou URL; linhas iniciadas por # são ignoradas)
  -o, --output <arq>       Arquivo de saída específico (ignorado com múltiplos alvos)
  -w, --wordlist <arq>     Wordlist para --dirs
      --jsfile <arq>       Reutiliza lista de JS já extraída (pula crawling em --secret)
      --gf-pattern <nome>  Nome do padrão gf a usar (default: xss)
      --env <arq>          Arquivo .env com chaves de API (default: ${ENV_FILE})
      --wpscan-enum <e>    Enumeração do WPScan (default: ${WPSCAN_ENUM})
      --no-vuln            Desativa a validação de vulnerabilidades (wpscan/nuclei)
      --no-preflight       Não checa liveness com httpx antes de rodar os módulos
      --rotate-agent       Rotaciona o User-Agent a cada 5 requisições
      --timeout <seg>      Timeout por requisição (default: ${TIMEOUT})
  -v, --verbose            Log detalhado em stderr
  -j, --json               Saída em JSON (onde aplicável)
      --no-color           Desativa cores

Dependências:
      --check              Verifica todas as ferramentas/módulos e sai
      --install-deps       Instala o que estiver ausente (Python + SecretFinder) e sai
      --yes                Responde "sim" a instalações (não interativo)
      --no-install         Nunca instala nada automaticamente
  -h, --help               Esta ajuda

Validação de vulnerabilidades (automática após -t/-T; desligue com --no-vuln):
  WordPress            -> WPScan (usa WPSCAN_API_TOKEN se disponível)
  Nginx / Apache       -> Nuclei (por tag) + searchsploit por versão
  As chaves de API são solicitadas no início e salvas em ${ENV_FILE} (chmod 600).

Antes de cada alvo, o status da aplicação é validado com httpx (--no-preflight pula).

Saída:
  Tudo é salvo em ./recon_<dominio>/ com subpastas js/ e results/
EOF
}

# ---------------------------------------------------------------------------
# Gerenciamento de dependências
# ---------------------------------------------------------------------------
# Módulos Python exigidos pelo SecretFinder (nome_import:pacote_pip)
PY_DEPS=( "jsbeautifier:jsbeautifier" "requests:requests" "lxml:lxml" "requests_file:requests-file" )

pymod_ok() { python3 -c "import $1" >/dev/null 2>&1; }

# pip com fallback para o PEP 668 do Kali/Debian (externally-managed-environment)
pip_install() {
  local pkgs=("$@")
  log "pip install --user ${pkgs[*]}"
  if pip3 install --user "${pkgs[@]}" 2>/dev/null; then return 0; fi
  warn "pip normal falhou; tentando --break-system-packages (Kali/Debian PEP 668)"
  if pip3 install --user --break-system-packages "${pkgs[@]}" 2>/dev/null; then return 0; fi
  return 1
}

confirm() {
  # Retorna 0 (sim) se AUTO_INSTALL; nunca instala se NO_AUTO_INSTALL.
  [ "$NO_AUTO_INSTALL" -eq 1 ] && return 1
  [ "$AUTO_INSTALL" -eq 1 ] && return 0
  local ans
  printf '%b[?]%b %s [s/N] ' "$c_yel" "$c_rst" "$1" >&2
  read -r ans </dev/tty 2>/dev/null || return 1
  [[ "$ans" =~ ^[sSyY] ]]
}

# Garante os módulos Python do SecretFinder. Chamado antes do modo -secret.
ensure_python_deps() {
  local need_import need_pip=()
  for pair in "${PY_DEPS[@]}"; do
    need_import="${pair%%:*}"
    if ! pymod_ok "$need_import"; then
      need_pip+=( "${pair##*:}" )
    fi
  done
  if [ "${#need_pip[@]}" -eq 0 ]; then
    vlog "Módulos Python do SecretFinder OK"
    return 0
  fi
  warn "Módulos Python ausentes para o SecretFinder: ${need_pip[*]}"
  if confirm "Instalar agora via pip?"; then
    if pip_install "${need_pip[@]}"; then
      ok "Módulos Python instalados"
      return 0
    fi
    err "Falha ao instalar módulos Python. Instale manualmente:"
    err "  pip3 install --user --break-system-packages ${need_pip[*]}"
    return 1
  fi
  err "Módulos ausentes; o SecretFinder não vai rodar. Use --install-deps ou --yes."
  return 1
}

# Garante que o SecretFinder.py exista (clona se o usuário permitir).
ensure_secretfinder() {
  if [ -f "$SECRETFINDER_PATH" ]; then
    vlog "SecretFinder encontrado em $SECRETFINDER_PATH"
    return 0
  fi
  warn "SecretFinder.py não encontrado em: $SECRETFINDER_PATH"
  if ! command -v git >/dev/null 2>&1; then
    err "git não instalado; não é possível clonar o SecretFinder."
    return 1
  fi
  if confirm "Clonar o SecretFinder em ./SecretFinder?"; then
    if git clone --depth 1 https://github.com/m4ll0k/SecretFinder.git ./SecretFinder 2>/dev/null; then
      SECRETFINDER_PATH="./SecretFinder/SecretFinder.py"
      ok "SecretFinder clonado em ./SecretFinder"
      return 0
    fi
    err "Falha ao clonar o SecretFinder."
    return 1
  fi
  err "Defina SECRETFINDER_PATH ou clone manualmente:"
  err "  git clone https://github.com/m4ll0k/SecretFinder.git"
  return 1
}

# Relata (e opcionalmente instala) todas as dependências.
check_dependencies() {
  local install="$1"   # 1 = tentar instalar o que faltar

  ok "== Dependências base =="
  local base_missing=0
  for bin in curl grep sed awk python3 pip3 git; do
    if command -v "$bin" >/dev/null 2>&1; then
      echo "  [ok]   $bin" >&2
    else
      echo "  [FALTA] $bin" >&2
      base_missing=1
    fi
  done
  [ "$base_missing" -eq 1 ] && warn "Instale as base ausentes (ex.: sudo apt install curl git python3-pip)"

  ok "== Módulos Python (SecretFinder) =="
  local py_need=()
  for pair in "${PY_DEPS[@]}"; do
    if pymod_ok "${pair%%:*}"; then
      echo "  [ok]   ${pair%%:*}" >&2
    else
      echo "  [FALTA] ${pair%%:*} (pacote: ${pair##*:})" >&2
      py_need+=( "${pair##*:}" )
    fi
  done
  if [ "${#py_need[@]}" -gt 0 ] && [ "$install" -eq 1 ]; then
    pip_install "${py_need[@]}" && ok "Módulos Python instalados" \
      || err "Falha ao instalar: ${py_need[*]}"
  fi

  ok "== SecretFinder =="
  if [ -f "$SECRETFINDER_PATH" ]; then
    echo "  [ok]   $SECRETFINDER_PATH" >&2
  else
    echo "  [FALTA] $SECRETFINDER_PATH" >&2
    [ "$install" -eq 1 ] && ensure_secretfinder
  fi

  ok "== Ferramentas externas opcionais =="
  # nome:comando:instrução_de_instalação
  local tools=(
    "Sublist3r:sublist3r:git clone https://github.com/aboul3la/Sublist3r.git"
    "Gau:gau:go install github.com/lc/gau/v2/cmd/gau@latest"
    "Httpx:httpx:go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
    "Dirsearch:dirsearch:git clone https://github.com/maurosoria/dirsearch.git"
    "Gf:gf:go install github.com/tomnomnom/gf@latest  (+ git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf)"
    "WhatWeb:whatweb:sudo apt install whatweb   (ou gem install whatweb)"
    "WPScan:wpscan:sudo apt install wpscan   (ou gem install wpscan)"
    "Nuclei:nuclei:go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    "searchsploit:searchsploit:sudo apt install exploitdb   (Exploit-DB local, opcional)"
  )
  for t in "${tools[@]}"; do
    local name rest cmd hint
    name="${t%%:*}"
    rest="${t#*:}"
    cmd="${rest%%:*}"
    hint="${rest#*:}"
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "  [ok]   $name ($cmd)" >&2
    else
      echo "  [FALTA] $name  ->  $hint" >&2
    fi
  done
  warn "Ferramentas em Go exigem o Go instalado (sudo apt install golang-go) e \$HOME/go/bin no PATH."

  ok "== Chaves de API ($ENV_FILE) =="
  load_env
  for pair in "WPSCAN_API_TOKEN:WPScan (base de vulnerabilidades)" "PDCP_API_KEY:ProjectDiscovery/Nuclei (opcional)"; do
    if [ -n "$(printenv "${pair%%:*}" 2>/dev/null || true)" ]; then
      echo "  [ok]   ${pair%%:*} (${pair#*:})" >&2
    else
      echo "  [FALTA] ${pair%%:*} (${pair#*:}) — será solicitada ao rodar, ou defina no $ENV_FILE" >&2
    fi
  done
}

# ---------------------------------------------------------------------------
# User-Agent rotativo
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

# ---------------------------------------------------------------------------
# Resolve caminho relativo/absoluto -> URL completa
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
# Modo: -files (extrai + BAIXA os js para a pasta do site)
# ---------------------------------------------------------------------------
run_files() {
  vlog "Baixando página inicial: $URL"
  local html
  html="$(fetch "$URL")"
  [ -z "$html" ] && { err "Falha ao obter conteúdo de $URL"; return 1; }

  local raw_list final_list
  raw_list="$(extract_js_paths "$html" | sort -u)"

  final_list=""
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    final_list+="$(resolve_url "$path")"$'\n'
  done <<< "$raw_list"
  final_list="$(echo "$final_list" | grep -v '^$' | sort -u)"

  local total
  total=$(echo "$final_list" | grep -c . || true)
  ok "Total de arquivos JS únicos: $total"

  local list_path="${OUT_FILE:-${RESDIR}/files-js.txt}"
  echo "$final_list" > "$list_path"
  ok "Lista salva em: $list_path"

  while IFS= read -r jsurl; do
    [ -z "$jsurl" ] && continue
    local fname
    fname="$(echo "$jsurl" | sed -E 's#https?://##; s#[^a-zA-Z0-9._-]#_#g')"
    vlog "Baixando: $jsurl"
    fetch "$jsurl" > "${JSDIR}/${fname}"
  done <<< "$final_list"
  ok "Arquivos JS baixados em: $JSDIR"
}

# ---------------------------------------------------------------------------
# Modo: -secret
# ---------------------------------------------------------------------------
run_secret() {
  ensure_secretfinder || return 1
  ensure_python_deps  || return 1

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
  ok "Analisando $total arquivo(s) com SecretFinder"

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
    ok "Resultado JSON salvo em: $out"
  fi
}

# ---------------------------------------------------------------------------
# Registro de tecnologias para a etapa de validação de vulnerabilidades.
# Formato de cada linha: nome_normalizado|versao (versao pode ser vazia).
# Consumido por run_vuln_validation() ao final do recon.
# ---------------------------------------------------------------------------
record_tech() {
  local name="$1" ver="${2:-}"
  [ -z "$name" ] && return 0
  echo "${name}|${ver}" >> "${RESDIR}/tech-detected.txt"
}

# ---------------------------------------------------------------------------
# Modo: -tech (com tentativa de versão)
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
        found["$tech"]="versão $ver"
      else
        found["$tech"]="detectado (versão não identificada)"
      fi
    fi
  done

  for t in Nginx Apache PHP; do
    local v
    v="$(detect_version "$combined" "$t")"
    [ -n "$v" ] && found["$t"]="versão $v"
  done

  if [ -z "${found[*]+x}" ]; then
    warn "Nenhuma tecnologia identificada com as heurísticas atuais"
  fi

  # Registra alvos de interesse para a validação de vulnerabilidades no final.
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
    ok "Resultado JSON salvo em: $out"
  else
    ok "Tecnologias identificadas para $URL:"
    if [ -n "${found[*]+x}" ]; then
      for key in "${!found[@]}"; do
        echo "  - $key: ${found[$key]}"
      done | tee "${RESDIR}/tech.txt" >&2
    fi
  fi
}

# ---------------------------------------------------------------------------
# Modo: -tech-deep (fingerprint aprofundado com WhatWeb)
# ---------------------------------------------------------------------------
# Roda o WhatWeb com agressividade 3, User-Agent aleatório e logs verbose+JSON.
# O JSON é parseado para alimentar a etapa de validação de vulnerabilidades
# (WordPress -> wpscan; Nginx/Apache -> nuclei/searchsploit).
run_tech_deep() {
  if ! command -v whatweb >/dev/null 2>&1; then
    warn "WhatWeb não encontrado. Instale com: sudo apt install whatweb  (ou gem install whatweb)"
    return 1
  fi

  local random="${RANDOM}${RANDOM}"
  local verbose_log="${RESDIR}/whatweb_verbose.txt"
  local json_log="${RESDIR}/whatweb.json"

  ok "[tech-deep] WhatWeb (aggression=3) em $URL"

  local -a args=(
    "$URL"
    --user-agent="Bypass_${random}"
    --aggression=3
    -v
    --log-verbose="$verbose_log"
    --log-json="$json_log"
    --max-threads=5
  )
  if [ "$NO_COLOR" -eq 1 ]; then
    args+=( --colour=never )
  else
    args+=( --colour=always )
  fi

  whatweb "${args[@]}" >&2 || warn "WhatWeb retornou código de erro (seguindo mesmo assim)"
  ok "[tech-deep] Logs salvos em: $verbose_log e $json_log"

  # Extrai plugins de interesse do JSON e registra para a etapa de vulns.
  if [ -s "$json_log" ]; then
    python3 - "$json_log" >> "${RESDIR}/tech-detected.txt" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)

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

for entry in (data if isinstance(data, list) else [data]):
    plugins = entry.get("plugins", {}) if isinstance(entry, dict) else {}
    for name, info in plugins.items():
        ln = name.lower()
        ver = first_version(info)
        if ln == "wordpress":
            print(f"wordpress|{ver}")
        elif ln == "nginx":
            print(f"nginx|{ver}")
        elif ln in ("apache", "apache-modules"):
            print(f"apache|{ver}")
        elif ln == "httpserver":
            s = http_kind(info)
            if "nginx" in s:
                print(f"nginx|{ver}")
            elif "apache" in s:
                print(f"apache|{ver}")
PY
    vlog "[tech-deep] Tecnologias do WhatWeb registradas para validação"
  fi
}

# ---------------------------------------------------------------------------
# Validação de vulnerabilidades (executada ao FINAL do recon)
# ---------------------------------------------------------------------------
# WordPress  -> WPScan (valida plugins/temas vulneráveis + usuários)
# Nginx      -> Nuclei (templates por tag) + searchsploit por versão
# Apache     -> Nuclei (templates por tag) + searchsploit por versão
# ---------------------------------------------------------------------------

# WPScan: valida se a instalação WordPress está vulnerável.
run_wpscan() {
  if ! command -v wpscan >/dev/null 2>&1; then
    warn "WPScan não encontrado. Instale com: sudo apt install wpscan  (ou gem install wpscan)"
    return 1
  fi
  ok "[WordPress] Validando vulnerabilidades com WPScan -> $URL"

  local out_txt="${RESDIR}/wpscan.txt"
  local -a args=(
    --url "$URL"
    --enumerate "$WPSCAN_ENUM"
    --random-user-agent
    --stealthy
    --ignore-main-redirect
    --disable-tls-checks
  )
  [ "$NO_COLOR" -eq 1 ] && args+=( --no-color )

  local token
  token="$(printenv WPSCAN_API_TOKEN 2>/dev/null || true)"
  if [ -n "$token" ]; then
    args+=( --api-token "$token" )
  else
    warn "Sem WPSCAN_API_TOKEN: rodando sem a base de vulnerabilidades (resultados limitados)."
    warn "  Gere um token grátis em https://wpscan.com/api e rode novamente."
  fi

  # Uma única passada: mostra na tela e salva em arquivo.
  wpscan "${args[@]}" 2>&1 | tee "$out_txt" >&2
  ok "[WordPress] Saída do WPScan salva em: $out_txt"
}

# Nuclei: busca vulnerabilidades conhecidas por tag de tecnologia (nginx/apache)
# além de CVEs genéricos. Usa PDCP_API_KEY (se definido) via ambiente.
run_nuclei() {
  local -a tags=("$@")
  if ! command -v nuclei >/dev/null 2>&1; then
    warn "Nuclei não encontrado. Instale com:"
    warn "  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    return 1
  fi

  local tagcsv
  tagcsv="$(IFS=,; echo "${tags[*]:-}")"
  ok "[Vuln] Nuclei em $URL (tags: ${tagcsv:-cves genéricos})"

  local out="${RESDIR}/nuclei.txt"
  local -a args=(
    -u "$URL"
    -o "$out"
    -stats
    -timeout "$TIMEOUT"
    -rl 50
    -severity low,medium,high,critical
  )
  [ -n "$tagcsv" ] && args+=( -tags "$tagcsv" )
  [ "$NO_COLOR" -eq 1 ] && args+=( -nc )
  # PDCP_API_KEY é lido automaticamente do ambiente pelo nuclei (upload opcional).

  nuclei "${args[@]}" >&2 || warn "Nuclei retornou código de erro (seguindo mesmo assim)"
  ok "[Vuln] Resultado do Nuclei salvo em: $out"
}

# searchsploit: mapeia versão detectada -> exploits conhecidos (Exploit-DB local).
run_searchsploit() {
  local name="$1" ver="${2:-}"
  command -v searchsploit >/dev/null 2>&1 || return 0   # complemento opcional
  [ -z "$ver" ] && { vlog "searchsploit: sem versão para '$name', pulando"; return 0; }
  ok "[Vuln] searchsploit '$name $ver'"
  searchsploit "$name" "$ver" 2>/dev/null | tee -a "${RESDIR}/searchsploit.txt" >&2 || true
}

# Orquestra a validação com base no que foi detectado por -tech e/ou -tech-deep.
run_vuln_validation() {
  local detfile="${RESDIR}/tech-detected.txt"
  if [ ! -s "$detfile" ]; then
    vlog "Nenhuma tecnologia registrada; nada a validar."
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
    ok "== Validação de vulnerabilidades: WordPress =="
    run_wpscan
  fi

  if [ "${#nuclei_tags[@]}" -gt 0 ]; then
    ok "== Validação de vulnerabilidades: Nginx/Apache =="
    # Deduplica as tags preservando a ordem.
    local -A _t=(); local -a uniq=()
    local t
    for t in "${nuclei_tags[@]}"; do
      [ -n "${_t[$t]:-}" ] && continue
      _t["$t"]=1; uniq+=("$t")
    done
    run_nuclei "${uniq[@]}"
  fi

  if [ "$wp" -eq 0 ] && [ "${#nuclei_tags[@]}" -eq 0 ]; then
    vlog "Sem WordPress/Nginx/Apache detectados; sem validação a fazer."
  fi
}

# ---------------------------------------------------------------------------
# Modo: -subdomains (Sublist3r se disponível, senão fallback crt.sh)
# ---------------------------------------------------------------------------
run_subdomains() {
  local out="${OUT_FILE:-${RESDIR}/subdomains.txt}"
  if command -v sublist3r >/dev/null 2>&1; then
    ok "Usando Sublist3r"
    sublist3r -d "$DOMAIN" -o "$out"
  elif [ -f "./Sublist3r/sublist3r.py" ]; then
    ok "Usando Sublist3r (script local)"
    python3 ./Sublist3r/sublist3r.py -d "$DOMAIN" -o "$out"
  else
    warn "Sublist3r não encontrado. Usando fallback via crt.sh (equivalente ao Ctfr)"
    warn "Instale com: git clone https://github.com/aboul3la/Sublist3r.git"
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
  ok "Subdomínios salvos em: $out ($total encontrados)"
}

# ---------------------------------------------------------------------------
# Modo: -urls (Gau)
# ---------------------------------------------------------------------------
run_urls() {
  local out="${OUT_FILE:-${RESDIR}/urls.txt}"
  if command -v gau >/dev/null 2>&1; then
    ok "Usando Gau para coletar URLs históricas"
    gau "$DOMAIN" > "$out"
    local total
    total=$(grep -c . "$out" || echo 0)
    ok "URLs salvas em: $out ($total encontradas)"
    grep -E '\.js(\?|$)' "$out" | sort -u > "${RESDIR}/files-js-gau.txt"
    ok "JS extras encontrados via Gau: ${RESDIR}/files-js-gau.txt"
  else
    warn "Gau não encontrado. Instale com: go install github.com/lc/gau/v2/cmd/gau@latest"
  fi
}

# ---------------------------------------------------------------------------
# Modo: -probe (Httpx)
# ---------------------------------------------------------------------------
run_probe() {
  local input="${RESDIR}/subdomains.txt"
  [ -f "$input" ] || echo "$DOMAIN" > "$input"
  local out="${OUT_FILE:-${RESDIR}/probe.txt}"
  if command -v httpx >/dev/null 2>&1; then
    ok "Usando Httpx para sondar hosts vivos"
    httpx -l "$input" -title -tech-detect -status-code -o "$out"
    ok "Resultado salvo em: $out"
  else
    warn "Httpx não encontrado. Instale com: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  fi
}

# ---------------------------------------------------------------------------
# Modo: -dirs (Dirsearch)
# ---------------------------------------------------------------------------
run_dirs() {
  [ -z "$WORDLIST" ] && { err "Informe --wordlist para o modo --dirs"; return 1; }
  local out="${OUT_FILE:-${RESDIR}/dirs.txt}"
  if command -v dirsearch >/dev/null 2>&1; then
    ok "Usando Dirsearch"
    dirsearch -u "$URL" -w "$WORDLIST" -o "$out"
  elif [ -f "./dirsearch/dirsearch.py" ]; then
    ok "Usando Dirsearch (script local)"
    python3 ./dirsearch/dirsearch.py -u "$URL" -w "$WORDLIST" -o "$out"
  else
    warn "Dirsearch não encontrado. Instale com: git clone https://github.com/maurosoria/dirsearch.git"
  fi
}

# ---------------------------------------------------------------------------
# Modo: -gf (padrões perigosos sobre URLs coletadas)
# ---------------------------------------------------------------------------
run_gf() {
  local input="${RESDIR}/urls.txt"
  [ -f "$input" ] || run_urls
  local out="${OUT_FILE:-${RESDIR}/gf-${GF_PATTERN}.txt}"
  if command -v gf >/dev/null 2>&1; then
    ok "Usando Gf com padrão '$GF_PATTERN'"
    gf "$GF_PATTERN" < "$input" > "$out"
    ok "Resultado salvo em: $out"
  else
    warn "Gf não encontrado. Instale com:"
    warn "  go install github.com/tomnomnom/gf@latest"
    warn "  git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf"
  fi
}

# ---------------------------------------------------------------------------
# Parsing de argumentos
# ---------------------------------------------------------------------------
add_mode() { MODES+=("$1"); }

[ $# -eq 0 ] && { usage; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    -u|--url)          URL_ARGS+=("${2:-}"); shift 2 ;;
    -l|--list)         LIST_FILE="${2:-}"; shift 2 ;;
    -f|--files)        add_mode files; shift ;;
    -s|--secret)       add_mode secret; shift ;;
    -t|--tech)         add_mode tech; shift ;;
    -T|--tech-deep)    add_mode techdeep; shift ;;
    -S|--subdomains)   add_mode subdomains; shift ;;
    -U|--urls)         add_mode urls; shift ;;
    -p|--probe)        add_mode probe; shift ;;
    -d|--dirs)         add_mode dirs; shift ;;
    -g|--gf)           add_mode gf; shift ;;
    -a|--all)          add_mode all; shift ;;
    -o|--output)       OUT_FILE="${2:-}"; shift 2 ;;
    -w|--wordlist)     WORDLIST="${2:-}"; shift 2 ;;
    --jsfile)          JS_LIST_FILE="${2:-}"; shift 2 ;;
    --gf-pattern)      GF_PATTERN="${2:-}"; shift 2 ;;
    --env)             ENV_FILE="${2:-}"; shift 2 ;;
    --wpscan-enum)     WPSCAN_ENUM="${2:-}"; shift 2 ;;
    --no-vuln)         NO_VULN=1; shift ;;
    --no-preflight)    NO_PREFLIGHT=1; shift ;;
    --rotate-agent)    CUSTOM_AGENT=1; shift ;;
    --timeout)         TIMEOUT="${2:-}"; shift 2 ;;
    -v|--verbose)      VERBOSE=1; shift ;;
    -j|--json)         JSON=1; shift ;;
    --no-color)        NO_COLOR=1; shift ;;
    --check)           DO_CHECK_ONLY=1; shift ;;
    --install-deps)    DO_INSTALL_ONLY=1; AUTO_INSTALL=1; shift ;;
    --yes)             AUTO_INSTALL=1; shift ;;
    --no-install)      NO_AUTO_INSTALL=1; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) err "Argumento desconhecido: $1"; usage; exit 1 ;;
  esac
done

setup_colors
load_env

# ---------------------------------------------------------------------------
# Modos de dependência (não exigem URL)
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
# Normaliza um alvo -> URL completa (aceita "site.com" ou "https://site.com/...")
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
# Monta a lista final de alvos: -u (repetível) + linhas de -l
# ---------------------------------------------------------------------------
for a in ${URL_ARGS[@]+"${URL_ARGS[@]}"}; do
  norm="$(normalize_url "$a")"
  [ -n "$norm" ] && TARGETS+=("$norm")
done

if [ -n "$LIST_FILE" ]; then
  [ -f "$LIST_FILE" ] || { err "Arquivo de lista não encontrado: $LIST_FILE"; exit 1; }
  while IFS= read -r line || [ -n "$line" ]; do
    line="$(echo "$line" | tr -d '\r')"
    [ -z "${line// /}" ] && continue          # linha vazia
    [ "${line:0:1}" = "#" ] && continue        # comentário
    norm="$(normalize_url "$line")"
    [ -n "$norm" ] && TARGETS+=("$norm")
  done < "$LIST_FILE"
fi

# ---------------------------------------------------------------------------
# Validação
# ---------------------------------------------------------------------------
[ "${#TARGETS[@]}" -eq 0 ] && { err "Informe ao menos um alvo com -u/--url ou -l/--list"; usage; exit 1; }
[ "${#MODES[@]}" -eq 0 ]   && { err "Informe ao menos um modo (-f, -s, -t, -S, -U, -p, -d, -g ou -a)"; usage; exit 1; }

for bin in curl grep sed awk python3; do
  command -v "$bin" >/dev/null 2>&1 || { err "Dependência base ausente: $bin"; exit 1; }
done

# Deduplica alvos preservando a ordem
declare -A _seen=()
declare -a UNIQ=()
for t in "${TARGETS[@]}"; do
  [ -n "${_seen[$t]:-}" ] && continue
  _seen["$t"]=1
  UNIQ+=("$t")
done
TARGETS=("${UNIQ[@]}")

# -o não faz sentido com vários alvos (um sobrescreveria o outro)
if [ -n "$OUT_FILE" ] && [ "${#TARGETS[@]}" -gt 1 ]; then
  warn "-o/--output ignorado com múltiplos alvos; cada alvo grava na própria pasta."
  OUT_FILE=""
fi

# ---------------------------------------------------------------------------
# Expansão dos modos (independe do alvo) — ordem canônica do pipeline
# ---------------------------------------------------------------------------
ORDER=(subdomains urls files tech techdeep secret probe dirs gf techvuln)
declare -A want=()
for m in "${MODES[@]}"; do
  if [ "$m" = "all" ]; then
    for o in "${ORDER[@]}"; do want["$o"]=1; done
  else
    want["$m"]=1
  fi
done

# A validação de vulnerabilidades roda automaticamente ao final sempre que
# houve fingerprint (-tech e/ou -tech-deep).
if [ "${want[tech]:-0}" -eq 1 ] || [ "${want[techdeep]:-0}" -eq 1 ]; then
  want[techvuln]=1
fi

# --no-vuln remove a etapa mesmo com -a/--all ou -t/-T selecionados.
if [ "$NO_VULN" -eq 1 ]; then
  unset 'want[techvuln]'
  vlog "Validação de vulnerabilidades desativada (--no-vuln)"
fi

# Solicita as chaves de API ANTES de iniciar (persistidas no .env).
if [ "${want[techvuln]:-0}" -eq 1 ]; then
  log "Preparando chaves de API para a validação de vulnerabilidades (.env: $ENV_FILE)"
  ensure_api_key WPSCAN_API_TOKEN "Token da API do WPScan (Enter p/ pular)" 0 || true
  ensure_api_key PDCP_API_KEY     "API key do ProjectDiscovery/Nuclei (opcional, Enter p/ pular)" 0 || true
fi

# ---------------------------------------------------------------------------
# Configura os globais de um alvo (pasta de saída, base URL, etc.)
# ---------------------------------------------------------------------------
setup_target() {
  URL="$1"
  DOMAIN="$(echo "$URL" | awk -F/ '{print $3}' | sed -E 's/:.*$//')"
  [ -z "$DOMAIN" ] && { err "Não foi possível extrair o domínio de: $URL"; return 1; }
  OUTDIR="./recon_${DOMAIN}"
  JSDIR="${OUTDIR}/js"
  RESDIR="${OUTDIR}/results"
  mkdir -p "$JSDIR" "$RESDIR"
  ok "Pasta do alvo: $OUTDIR"
  BASE_SCHEME_HOST="$(echo "$URL" | awk -F/ '{print $1"//"$3}')"
  BASE_DIR="$(echo "$URL" | sed -E 's#([^?]*/)[^/]*(\?.*)?$#\1#')"
  return 0
}

# ---------------------------------------------------------------------------
# Preflight: valida o status da aplicação com httpx ANTES de rodar os módulos.
# Retorna 0 se o alvo está vivo/acessível, 1 caso contrário. Com --no-preflight
# a checagem é ignorada. Sem httpx, cai para um HEAD via curl.
# ---------------------------------------------------------------------------
preflight_httpx() {
  if [ "$NO_PREFLIGHT" -eq 1 ]; then
    vlog "Preflight desativado (--no-preflight)"
    return 0
  fi
  local out="${RESDIR}/httpx-preflight.txt"

  if command -v httpx >/dev/null 2>&1; then
    local -a hxargs=( -silent -status-code -title -tech-detect -timeout "$TIMEOUT" -o "$out" )
    [ "$NO_COLOR" -eq 1 ] && hxargs+=( -nc )
    local result
    result="$(echo "$URL" | httpx "${hxargs[@]}" 2>/dev/null)"
    if [ -n "$result" ]; then
      ok "[preflight] Aplicação ativa (httpx): $result"
      return 0
    fi
    warn "[preflight] httpx não obteve resposta viva de $URL"
    return 1
  fi

  # Fallback: httpx ausente -> checa o código HTTP com curl.
  warn "httpx não encontrado; usando curl no preflight"
  warn "  instale: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' -L -A "$(current_ua)" --max-time "$TIMEOUT" "$URL" 2>/dev/null)"
  REQ_COUNT=$((REQ_COUNT + 1))
  if [ -n "$code" ] && [ "$code" != "000" ]; then
    ok "[preflight] $URL respondeu HTTP $code"
    echo "$URL [HTTP $code]" > "$out"
    return 0
  fi
  warn "[preflight] $URL não respondeu (curl code=${code:-vazio})"
  return 1
}

# Roda os modos selecionados para o alvo já configurado
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
      gf)          run_gf ;;
    esac
  done
}

# ---------------------------------------------------------------------------
# Loop principal sobre os alvos
# ---------------------------------------------------------------------------
TOTAL_TARGETS="${#TARGETS[@]}"
GRAND_TOTAL=0
idx=0
[ "$TOTAL_TARGETS" -gt 1 ] && ok "Processando $TOTAL_TARGETS alvos"

for tgt in "${TARGETS[@]}"; do
  idx=$((idx + 1))
  [ "$TOTAL_TARGETS" -gt 1 ] && log "===== [$idx/$TOTAL_TARGETS] $tgt ====="
  REQ_COUNT=0
  if setup_target "$tgt"; then
    if preflight_httpx; then
      dispatch_modes
      [ "$TOTAL_TARGETS" -gt 1 ] && ok "[$DOMAIN] Requisições: $REQ_COUNT"
    else
      warn "[$DOMAIN] Alvo fora do ar ou inacessível; módulos não executados. (use --no-preflight para forçar)"
    fi
  else
    warn "Pulando alvo inválido: $tgt"
  fi
  GRAND_TOTAL=$((GRAND_TOTAL + REQ_COUNT))
done

if [ "$TOTAL_TARGETS" -gt 1 ]; then
  ok "Concluído. $TOTAL_TARGETS alvos processados. Requisições totais: $GRAND_TOTAL"
else
  ok "Concluído. Requisições totais realizadas: $GRAND_TOTAL"
fi
