#!/usr/bin/env bash
#
# script.sh (v2) - Recon de JS + secrets + tech fingerprint + integrações opcionais
#
# Uso:
#   ./script.sh -url https://site.com/ -files   -verbose -o files-js.txt
#   ./script.sh -url https://site.com/ -secret  -verbose -json
#   ./script.sh -url https://site.com/ -tech    -json
#   ./script.sh -url https://site.com/ -subdomains
#   ./script.sh -url https://site.com/ -urls
#   ./script.sh -url https://site.com/ -probe
#   ./script.sh -url https://site.com/ -dirs -wordlist wordlist.txt
#   ./script.sh -url https://site.com/ -gf -gf-pattern xss
#   ./script.sh -url https://site.com/ -all -custom-agent
#
# Requisitos base : curl, grep, sed, awk, python3
# Integrações opt.: sublist3r, ctfr(via crt.sh), gau, httpx, dirsearch, gf (+ gf-patterns)
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
URL=""
MODE=""
VERBOSE=0
JSON=0
OUT_FILE=""
JS_LIST_FILE=""
CUSTOM_AGENT=0
WORDLIST=""
GF_PATTERN="xss"
TIMEOUT=15
SECRETFINDER_PATH="${SECRETFINDER_PATH:-./SecretFinder/SecretFinder.py}"

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
c_red='\033[0;31m'; c_grn='\033[0;32m'; c_yel='\033[1;33m'; c_blu='\033[0;34m'; c_rst='\033[0m'
log()  { echo -e "${c_blu}[*]${c_rst} $*" >&2; }
ok()   { echo -e "${c_grn}[+]${c_rst} $*" >&2; }
warn() { echo -e "${c_yel}[!]${c_rst} $*" >&2; }
err()  { echo -e "${c_red}[-]${c_rst} $*" >&2; }
vlog() { [ "$VERBOSE" -eq 1 ] && log "$*"; }

WORKDIR="$(mktemp -d /tmp/jsrecon.XXXXXX)"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

usage() {
  cat <<EOF
Uso: $0 -url <URL> [modo] [opções]

Modos:
  -files        Extrai .js do HTML, resolve URLs e BAIXA os arquivos para a pasta do site
  -secret       Roda o SecretFinder nos .js (e no HTML) em busca de segredos
  -tech         Fingerprint de tecnologias + tentativa de detectar versão
  -subdomains   Enumera subdomínios (sublist3r se instalado, senão crt.sh via ctfr-like)
  -urls         Coleta URLs históricas do domínio (gau, se instalado)
  -probe        Sonda hosts/URLs vivos com detecção de tech (httpx, se instalado)
  -dirs         Brute-force de diretórios (dirsearch, se instalado) — requer -wordlist
  -gf           Filtra URLs coletadas por padrões perigosos (gf + gf-patterns)
  -all          Roda files -> tech -> secret -> urls -> subdomains -> probe (o que estiver disponível)

Opções:
  -url          URL alvo (obrigatório)
  -o            Arquivo de saída específico (por padrão tudo vai para a pasta do site)
  -jsfile       Reutiliza lista de JS já extraída (pula crawling em -secret)
  -wordlist     Wordlist para -dirs
  -gf-pattern   Nome do padrão gf a usar (default: xss)
  -custom-agent Ativa rotação de User-Agent a cada 5 requisições
  -verbose      Log detalhado em stderr
  -json         Saída em JSON (onde aplicável)
  -h            Ajuda

Pasta de saída:
  Tudo é salvo em ./recon_<dominio>/ com subpastas js/, results/

Ferramentas do enunciado — status de integração:
  Integradas (chamadas automaticamente se o binário existir no PATH):
    - SecretFinder   -> modo -secret
    - Sublist3r      -> modo -subdomains
    - Gau             -> modo -urls
    - Httpx           -> modo -probe
    - Dirsearch       -> modo -dirs
    - Gf + Gf-Patterns-> modo -gf
  Fallback sem dependência externa:
    - Ctfr            -> modo -subdomains usa consulta ao crt.sh via curl quando Sublist3r
                          não está instalado (mesma ideia do Ctfr: certificate transparency)
  Fora do escopo deste script (input/uso muito diferente de "site -> JS/secrets"),
  mas com hint de comando quando fizer sentido rodar à parte:
    - Aquatone         (screenshots de massa de subdomínios; rode após -subdomains)
    - CloudFlair       (bypass de Cloudflare via Censys; requer API key própria)
    - Imperva-detect    (fingerprint de WAF; não relacionado a JS/secrets)
    - MetaFinder        (metadados de documentos indexados no Google; não é JS)
    - Pagodo/Yagooglesearch/Go-Dork (Google dorking; requer scraping do Google, alto risco de bloqueio)
    - H8mail            (busca de vazamento por e-mail; input é e-mail, não URL)
    - Sudomy            (framework completo que já orquestra várias dessas; redundante aqui)
    - Enumerepo         (enumeração de repositórios de código; não relacionado ao alvo web)
EOF
  exit 1
}

[ $# -eq 0 ] && usage

while [ $# -gt 0 ]; do
  case "$1" in
    -url)          URL="$2"; shift 2 ;;
    -files)        MODE="files"; shift ;;
    -secret)       MODE="secret"; shift ;;
    -tech)         MODE="tech"; shift ;;
    -subdomains)   MODE="subdomains"; shift ;;
    -urls)         MODE="urls"; shift ;;
    -probe)        MODE="probe"; shift ;;
    -dirs)         MODE="dirs"; shift ;;
    -gf)           MODE="gf"; shift ;;
    -all)          MODE="all"; shift ;;
    -o)             OUT_FILE="$2"; shift 2 ;;
    -jsfile)        JS_LIST_FILE="$2"; shift 2 ;;
    -wordlist)      WORDLIST="$2"; shift 2 ;;
    -gf-pattern)    GF_PATTERN="$2"; shift 2 ;;
    -custom-agent)  CUSTOM_AGENT=1; shift ;;
    -verbose)       VERBOSE=1; shift ;;
    -json)          JSON=1; shift ;;
    -h|--help)      usage ;;
    *) err "Argumento desconhecido: $1"; usage ;;
  esac
done

[ -z "$URL" ] && { err "Informe -url"; usage; }
[ -z "$MODE" ] && { err "Informe um modo (-files, -secret, -tech, -subdomains, -urls, -probe, -dirs, -gf, -all)"; usage; }

for bin in curl grep sed awk python3; do
  command -v "$bin" >/dev/null 2>&1 || { err "Dependência ausente: $bin"; exit 1; }
done

# ---------------------------------------------------------------------------
# Domínio + pasta de saída
# ---------------------------------------------------------------------------
DOMAIN="$(echo "$URL" | awk -F/ '{print $3}' | sed -E 's/:.*$//')"
[ -z "$DOMAIN" ] && { err "Não foi possível extrair o domínio de $URL"; exit 1; }

OUTDIR="./recon_${DOMAIN}"
JSDIR="${OUTDIR}/js"
RESDIR="${OUTDIR}/results"
mkdir -p "$JSDIR" "$RESDIR"
ok "Pasta do alvo: $OUTDIR"

BASE_SCHEME_HOST="$(echo "$URL" | awk -F/ '{print $1"//"$3}')"
BASE_DIR="$(echo "$URL" | sed -E 's#([^?]*/)[^/]*(\?.*)?$#\1#')"

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
  local target="$1"
  local ua
  ua="$(current_ua)"
  REQ_COUNT=$((REQ_COUNT + 1))
  vlog "[req #$REQ_COUNT] UA=$ua -> $target"
  curl -s -L -A "$ua" --max-time "$TIMEOUT" "$target"
}

fetch_headers() {
  local target="$1"
  local ua
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
  [ -z "$html" ] && { err "Falha ao obter conteúdo de $URL"; exit 1; }

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

  # Baixa cada JS para a pasta js/ do alvo
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
  if [ ! -f "$SECRETFINDER_PATH" ]; then
    err "SecretFinder.py não encontrado em: $SECRETFINDER_PATH"
    err "Defina SECRETFINDER_PATH ou clone: git clone https://github.com/m4ll0k/SecretFinder.git"
    exit 1
  fi

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
# Modo: -tech (com tentativa de versão)
# ---------------------------------------------------------------------------
detect_version() {
  # $1 = conteúdo combinado, $2 = tech
  local combined="$1" tech="$2"
  case "$tech" in
    jQuery)
      echo "$combined" | grep -oE 'jQuery v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
      ;;
    "React")
      echo "$combined" | grep -oE '"react"[[:space:]]*:[[:space:]]*"[^"]+"' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
      ;;
    "Next.js")
      echo "$combined" | grep -oiE 'next\.js[[:space:]]+v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
      ;;
    "Vue.js")
      echo "$combined" | grep -oE 'Vue\.js v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
      ;;
    "Angular")
      echo "$combined" | grep -oE 'ng-version=["'"'"'][0-9]+\.[0-9]+\.[0-9]+["'"'"']' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
      ;;
    "Bootstrap")
      echo "$combined" | grep -oE 'Bootstrap v?[0-9]+\.[0-9]+\.[0-9]+' | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+'
      ;;
    "WordPress")
      echo "$combined" | grep -oiE 'wordpress[[:space:]]+[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?'
      ;;
    "PHP")
      echo "$combined" | grep -oiE 'php/[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?'
      ;;
    "Nginx")
      echo "$combined" | grep -oiE 'nginx/[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?'
      ;;
    "Apache")
      echo "$combined" | grep -oiE 'apache/[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?'
      ;;
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

  # versão de server/php/etc pode vir junto no header Server: nginx/1.25.3
  for t in Nginx Apache PHP; do
    local v
    v="$(detect_version "$combined" "$t")"
    [ -n "$v" ] && found["$t"]="versão $v"
  done

  if [ "${#found[@]}" -eq 0 ]; then
    warn "Nenhuma tecnologia identificada com as heurísticas atuais"
  fi

  if [ "$JSON" -eq 1 ]; then
    local json_out="{" first=1
    for key in "${!found[@]}"; do
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
    for key in "${!found[@]}"; do
      echo "  - $key: ${found[$key]}"
    done | tee "${RESDIR}/tech.txt" >&2
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
    # também extrai .js adicionais que o crawling simples não pegaria
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
  [ -z "$WORDLIST" ] && { err "Informe -wordlist para o modo -dirs"; exit 1; }
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
# Modo: -all
# ---------------------------------------------------------------------------
run_all() {
  run_files
  run_tech
  run_secret
  run_urls
  run_subdomains
  run_probe
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "$MODE" in
  files)       run_files ;;
  secret)      run_secret ;;
  tech)        run_tech ;;
  subdomains)  run_subdomains ;;
  urls)        run_urls ;;
  probe)       run_probe ;;
  dirs)        run_dirs ;;
  gf)          run_gf ;;
  all)         run_all ;;
  *) err "Modo inválido"; usage ;;
esac

ok "Concluído. Requisições totais realizadas: $REQ_COUNT"
