#!/usr/bin/env bash
#
# script.sh - Recon de arquivos JS + busca de secrets (SecretFinder) + fingerprint de tecnologias
#
# Uso:
#   ./script.sh -url https://site.com/ -files -verbose -o files-js.txt
#   ./script.sh -url https://site.com/ -secret -verbose -json
#   ./script.sh -url https://site.com/ -tech -json
#
# Requisitos: curl, grep, sed, awk, python3
# Opcional  : SecretFinder.py (defina SECRETFINDER_PATH ou deixe em ./SecretFinder/SecretFinder.py)
#
set -uo pipefail

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
URL=""
MODE=""              # files | secret | tech
VERBOSE=0
JSON=0
OUT_FILE=""
JS_LIST_FILE=""       # permite reaproveitar uma lista já extraída (-jsfile)
UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
TIMEOUT=15
WORKDIR="$(mktemp -d /tmp/jsrecon.XXXXXX)"
SECRETFINDER_PATH="${SECRETFINDER_PATH:-./SecretFinder/SecretFinder.py}"

# ---------------------------------------------------------------------------
# Helpers de log
# ---------------------------------------------------------------------------
c_red='\033[0;31m'; c_grn='\033[0;32m'; c_yel='\033[1;33m'; c_blu='\033[0;34m'; c_rst='\033[0m'

log()  { echo -e "${c_blu}[*]${c_rst} $*" >&2; }
ok()   { echo -e "${c_grn}[+]${c_rst} $*" >&2; }
warn() { echo -e "${c_yel}[!]${c_rst} $*" >&2; }
err()  { echo -e "${c_red}[-]${c_rst} $*" >&2; }
vlog() { [ "$VERBOSE" -eq 1 ] && log "$*"; }

cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

usage() {
  cat <<EOF
Uso: $0 -url <URL> [-files|-secret|-tech] [-verbose] [-json] [-o <arquivo>] [-jsfile <lista>]

Modos:
  -files    Extrai caminhos de arquivos .js do HTML de origem e monta lista de URLs completas
  -secret   Baixa os .js (e o HTML) e roda o SecretFinder em busca de segredos
  -tech     Faz fingerprint de tecnologias (headers, meta tags, libs JS conhecidas)

Opções:
  -url      URL alvo (obrigatório)
  -o        Arquivo de saída (usado em -files para salvar a lista de JS)
  -jsfile   Reutiliza uma lista de JS já extraída (pula a etapa de crawling em -secret)
  -verbose  Log detalhado em stderr
  -json     Saída em formato JSON (em -secret e -tech)
  -h        Ajuda

Exemplos:
  $0 -url https://site.com/ -files -verbose -o files-js.txt
  $0 -url https://site.com/ -secret -verbose -json
  $0 -url https://site.com/ -secret -jsfile files-js.txt -json
  $0 -url https://site.com/ -tech -json
EOF
  exit 1
}

# ---------------------------------------------------------------------------
# Parse de argumentos
# ---------------------------------------------------------------------------
[ $# -eq 0 ] && usage

while [ $# -gt 0 ]; do
  case "$1" in
    -url)     URL="$2"; shift 2 ;;
    -files)   MODE="files"; shift ;;
    -secret)  MODE="secret"; shift ;;
    -tech)    MODE="tech"; shift ;;
    -o)       OUT_FILE="$2"; shift 2 ;;
    -jsfile)  JS_LIST_FILE="$2"; shift 2 ;;
    -verbose) VERBOSE=1; shift ;;
    -json)    JSON=1; shift ;;
    -h|--help) usage ;;
    *) err "Argumento desconhecido: $1"; usage ;;
  esac
done

[ -z "$URL" ] && { err "Informe -url"; usage; }
[ -z "$MODE" ] && { err "Informe o modo: -files, -secret ou -tech"; usage; }

for bin in curl grep sed awk python3; do
  command -v "$bin" >/dev/null 2>&1 || { err "Dependência ausente: $bin"; exit 1; }
done

# Normaliza a URL base (esquema + host)
BASE_SCHEME_HOST="$(echo "$URL" | awk -F/ '{print $1"//"$3}')"
BASE_DIR="$(echo "$URL" | sed -E 's#([^?]*/)[^/]*(\?.*)?$#\1#')"

# ---------------------------------------------------------------------------
# Resolve um caminho relativo/absoluto de JS para uma URL completa
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

# ---------------------------------------------------------------------------
# Baixa uma URL com timeout/UA padrão
# ---------------------------------------------------------------------------
fetch() {
  curl -s -L -A "$UA" --max-time "$TIMEOUT" "$1"
}

# ---------------------------------------------------------------------------
# Extrai caminhos .js do corpo HTML/JS (regex ampla: cobre src=, import, chunks, etc)
# ---------------------------------------------------------------------------
extract_js_paths() {
  local content="$1"
  echo "$content" | grep -oE '(["'"'"'(])[a-zA-Z0-9_./@-]*\.js(["'"'"')?])' \
    | sed -E 's/^["'"'"'(]//; s/["'"'"')?]$//' \
    | grep -v '^$'

  # Padrões adicionais: src="..." / href="..." explícitos com querystring
  echo "$content" | grep -oE '(src|href)=["'"'"'][^"'"'"']+\.js(\?[^"'"'"']*)?["'"'"']' \
    | sed -E 's/^(src|href)=["'"'"']//; s/["'"'"']$//'
}

# ---------------------------------------------------------------------------
# Modo: -files
# ---------------------------------------------------------------------------
run_files() {
  vlog "Baixando página inicial: $URL"
  local html
  html="$(fetch "$URL")"
  [ -z "$html" ] && { err "Falha ao obter conteúdo de $URL"; exit 1; }

  vlog "Extraindo caminhos .js do HTML"
  local raw_list
  raw_list="$(extract_js_paths "$html" | sort -u)"

  local count_raw
  count_raw=$(echo "$raw_list" | grep -c . || true)
  vlog "Encontrados $count_raw caminhos brutos"

  local final_list=""
  while IFS= read -r path; do
    [ -z "$path" ] && continue
    resolved="$(resolve_url "$path")"
    final_list+="$resolved"$'\n'
    vlog "  -> $resolved"
  done <<< "$raw_list"

  final_list="$(echo "$final_list" | grep -v '^$' | sort -u)"

  local total
  total=$(echo "$final_list" | grep -c . || true)
  ok "Total de arquivos JS únicos: $total"

  if [ -n "$OUT_FILE" ]; then
    echo "$final_list" > "$OUT_FILE"
    ok "Lista salva em: $OUT_FILE"
  else
    echo "$final_list"
  fi
}

# ---------------------------------------------------------------------------
# Modo: -secret
# ---------------------------------------------------------------------------
run_secret() {
  if [ ! -f "$SECRETFINDER_PATH" ]; then
    err "SecretFinder.py não encontrado em: $SECRETFINDER_PATH"
    err "Defina a variável de ambiente SECRETFINDER_PATH ou clone:"
    err "  git clone https://github.com/m4ll0k/SecretFinder.git"
    exit 1
  fi

  local list_file="$WORKDIR/js_list.txt"

  if [ -n "$JS_LIST_FILE" ] && [ -f "$JS_LIST_FILE" ]; then
    vlog "Reaproveitando lista de JS: $JS_LIST_FILE"
    cp "$JS_LIST_FILE" "$list_file"
  else
    vlog "Nenhuma -jsfile informada, extraindo JS a partir de $URL"
    local html
    html="$(fetch "$URL")"
    [ -z "$html" ] && { err "Falha ao obter conteúdo de $URL"; exit 1; }
    extract_js_paths "$html" | sort -u | while IFS= read -r path; do
      [ -z "$path" ] && continue
      resolve_url "$path"
    done > "$list_file"
  fi

  # Também analisa a própria página (HTML) além dos JS
  echo "$URL" >> "$list_file"
  sort -u -o "$list_file" "$list_file"

  local total
  total=$(grep -c . "$list_file" || true)
  ok "Analisando $total arquivo(s) com SecretFinder"

  local json_out="["
  local first=1

  while IFS= read -r target; do
    [ -z "$target" ] && continue
    vlog "Rodando SecretFinder em: $target"

    if [ "$JSON" -eq 1 ]; then
      local tmp_json="$WORKDIR/sf_out.json"
      python3 "$SECRETFINDER_PATH" -i "$target" -o cli 2>/dev/null > "$WORKDIR/sf_raw.txt"
      # SecretFinder não tem -o json nativo em todas as versões; então empacotamos a saída CLI
      local result
      result="$(cat "$WORKDIR/sf_raw.txt")"
      if [ -n "$result" ]; then
        local esc
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
    if [ -n "$OUT_FILE" ]; then
      echo "$json_out" > "$OUT_FILE"
      ok "Resultado JSON salvo em: $OUT_FILE"
    else
      echo "$json_out" | python3 -m json.tool 2>/dev/null || echo "$json_out"
    fi
  fi
}

# ---------------------------------------------------------------------------
# Modo: -tech (fingerprint simples de tecnologias)
# ---------------------------------------------------------------------------
run_tech() {
  vlog "Coletando headers de $URL"
  local headers
  headers="$(curl -s -I -L -A "$UA" --max-time "$TIMEOUT" "$URL")"

  vlog "Baixando HTML de $URL"
  local html
  html="$(fetch "$URL")"

  declare -A found

  # --- Headers ---
  server=$(echo "$headers" | grep -i '^server:' | sed -E 's/^[Ss]erver:\s*//I' | tr -d '\r')
  powered=$(echo "$headers" | grep -i '^x-powered-by:' | sed -E 's/^[Xx]-[Pp]owered-[Bb]y:\s*//I' | tr -d '\r')
  [ -n "$server" ]  && found["Server"]="$server"
  [ -n "$powered" ] && found["X-Powered-By"]="$powered"

  # --- Meta generator ---
  gen=$(echo "$html" | grep -oiE '<meta[^>]*name=["'"'"']generator["'"'"'][^>]*content=["'"'"'][^"'"'"']+["'"'"']' | grep -oE 'content=["'"'"'][^"'"'"']+["'"'"']' | sed -E 's/content=["'"'"']//; s/["'"'"']$//')
  [ -n "$gen" ] && found["Generator"]="$gen"

  # --- Heurísticas de frameworks/libs JS ---
  declare -A patterns=(
    ["React"]='data-reactroot|react-dom|__NEXT_DATA__'
    ["Next.js"]='_next/static|__NEXT_DATA__'
    ["Vue.js"]='__vue__|vue\.runtime|data-v-'
    ["Nuxt.js"]='__NUXT__|_nuxt/'
    ["Angular"]='ng-version|angular\.min\.js'
    ["jQuery"]='jquery(\.min)?\.js'
    ["Vercel"]='vercel\.app|x-vercel-id'
    ["Webpack"]='webpackJsonp|__webpack_require__'
    ["Turbopack"]='turbopack'
    ["Tailwind CSS"]='tailwind'
    ["WordPress"]='wp-content|wp-includes'
    ["Cloudflare"]='cloudflare'
    ["Google Analytics"]='gtag\(|googletagmanager\.com'
  )

  local combined="$html
$headers"

  for tech in "${!patterns[@]}"; do
    if echo "$combined" | grep -qiE "${patterns[$tech]}"; then
      found["$tech"]="detectado"
    fi
  done

  if [ "${#found[@]}" -eq 0 ]; then
    warn "Nenhuma tecnologia identificada com as heurísticas atuais"
  fi

  if [ "$JSON" -eq 1 ]; then
    local json_out="{"
    local first=1
    for key in "${!found[@]}"; do
      [ "$first" -eq 0 ] && json_out+=","
      esc_val="$(python3 -c 'import json,sys; print(json.dumps(sys.argv[1]))' "${found[$key]}")"
      json_out+="\"$key\":$esc_val"
      first=0
    done
    json_out+="}"
    if [ -n "$OUT_FILE" ]; then
      echo "$json_out" > "$OUT_FILE"
      ok "Resultado JSON salvo em: $OUT_FILE"
    else
      echo "$json_out" | python3 -m json.tool 2>/dev/null || echo "$json_out"
    fi
  else
    ok "Tecnologias identificadas para $URL:"
    for key in "${!found[@]}"; do
      echo "  - $key: ${found[$key]}"
    done
  fi
}

# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
case "$MODE" in
  files)  run_files ;;
  secret) run_secret ;;
  tech)   run_tech ;;
  *)      err "Modo inválido"; usage ;;
esac
