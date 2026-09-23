# recon.sh - v3.0

Reconhecimento web em Bash: JS, secrets, fingerprint de tecnologias, subdomínios,
URLs históricas, probing, brute-force de diretórios, filtros `gf` e **validação
automática de vulnerabilidades**.

Os modos são **combináveis** numa mesma execução e o pipeline roda sempre em ordem
lógica, independentemente da ordem das flags.

```
./recon.sh -u <URL> [modos...] [opções]
```

---

## Novidades da 2.0

- **`-T, --tech-deep`** — fingerprint aprofundado com **WhatWeb** (aggression 3,
  User-Agent aleatório, logs verbose + JSON).
- **Validação de vulnerabilidades ao final do recon** (automática após `-t`/`-T`):
  - **WordPress → WPScan** (valida plugins/temas vulneráveis e usuários).
  - **Nginx / Apache → Nuclei** (templates por tag) + **searchsploit** por versão.
- **Chaves de API via `.env`** — solicitadas no início e persistidas em `./.env`
  (`chmod 600`); carregadas automaticamente nas execuções seguintes.
- **Preflight com httpx** — o status da aplicação é validado antes de rodar os
  módulos; alvos fora do ar são pulados (com fallback via `curl`).
- Novos flags: `--no-vuln`, `--no-preflight`, `--env`, `--wpscan-enum`.

---

## Melhor comando

Pipeline completo (fingerprint + tech-deep + validação de vulnerabilidades):

```bash
./recon.sh -u https://dominio.com.br/ --all -w dir.txt --rotate-agent -v
```

Variante mais enxuta e menos barulhenta (sem brute-force de diretório):

```bash
./recon.sh -u https://dominio.com.br/ -S -U -f -T -p -v
```

> `--all` já inclui `-T` e a etapa de validação de vulnerabilidades — não precisa
> repetir. Os tokens de API são pedidos no início e o preflight roda antes de cada alvo.

---

## Modos (combináveis)

| Flag | Descrição |
|------|-----------|
| `-f, --files`      | Extrai `.js` do HTML, resolve URLs e baixa os arquivos |
| `-s, --secret`     | Roda o SecretFinder nos `.js` (e no HTML) em busca de segredos |
| `-t, --tech`       | Fingerprint de tecnologias + tentativa de versão |
| `-T, --tech-deep`  | Fingerprint aprofundado com WhatWeb (aggression 3, logs) |
| `-S, --subdomains` | Enumera subdomínios (sublist3r; fallback crt.sh) |
| `-U, --urls`       | Coleta URLs históricas do domínio (gau) |
| `-p, --probe`      | Sonda hosts/URLs vivos (httpx) |
| `-d, --dirs`       | Brute-force de diretórios (dirsearch) — requer `--wordlist` |
| `-g, --gf`         | Filtra URLs coletadas por padrões perigosos (gf + Gf-Patterns) |
| `-a, --all`        | Roda todos os módulos disponíveis, em ordem lógica |

---

## Opções

| Flag | Descrição |
|------|-----------|
| `-u, --url <URL>`       | URL alvo (aceita vários `-u`; combina com `-l`) |
| `-l, --list <arq>`      | Arquivo com lista de alvos, um por linha (domínio puro ou URL; `#` = comentário) |
| `-o, --output <arq>`    | Arquivo de saída específico (ignorado com múltiplos alvos) |
| `-w, --wordlist <arq>`  | Wordlist para `--dirs` |
| `--jsfile <arq>`        | Reutiliza lista de JS já extraída (pula crawling em `--secret`) |
| `--gf-pattern <nome>`   | Nome do padrão gf a usar (default: `xss`) |
| `--env <arq>`           | Arquivo `.env` com chaves de API (default: `./.env`) |
| `--wpscan-enum <e>`     | Enumeração do WPScan (default: `vp,vt,u`) |
| `--no-vuln`             | Desativa a validação de vulnerabilidades (wpscan/nuclei/searchsploit) |
| `--no-preflight`        | Não checa liveness com httpx antes de rodar os módulos |
| `--rotate-agent`        | Rotaciona o User-Agent a cada 5 requisições |
| `--timeout <seg>`       | Timeout por requisição (default: `15`) |
| `-v, --verbose`         | Log detalhado em stderr |
| `-j, --json`            | Saída em JSON (onde aplicável) |
| `--no-color`            | Desativa cores |

---

## Validação de vulnerabilidades

Executada **ao final do recon**, de forma automática, sempre que houve fingerprint
(`-t` e/ou `-T`). Desligue com `--no-vuln`.

| Detecção | Ferramenta | O que faz |
|----------|-----------|-----------|
| WordPress     | **WPScan**       | Enumera plugins/temas vulneráveis e usuários. Usa `WPSCAN_API_TOKEN` se disponível. |
| Nginx / Apache | **Nuclei**       | Roda templates por tag da tecnologia + CVEs conhecidos. |
| Nginx / Apache | **searchsploit** | Mapeia `versão → exploits conhecidos` (Exploit-DB local, complementar). |

Comandos equivalentes disparados internamente:

```bash
# WordPress
wpscan --url "$URL" --enumerate vp,vt,u --random-user-agent --stealthy \
       --ignore-main-redirect --disable-tls-checks --api-token "$WPSCAN_API_TOKEN"

# Nginx / Apache
nuclei -u "$URL" -tags nginx,apache -severity low,medium,high,critical
searchsploit nginx <versão>
```

> A enumeração do WPScan é ajustável: `--wpscan-enum vp,vt,tt,u` (ou `at` para todos
> os temas).

---

## Chaves de API (`.env`)

As chaves são **solicitadas no início** da execução (entrada oculta) e salvas em
`./.env` com permissão `600`. Nas próximas execuções elas são carregadas
automaticamente (parsing seguro, sem `source`).

| Variável | Uso | Obrigatória |
|----------|-----|-------------|
| `WPSCAN_API_TOKEN` | Base de vulnerabilidades do WPScan (https://wpscan.com/api) | Não (sem ela, resultados limitados) |
| `PDCP_API_KEY`     | ProjectDiscovery/Nuclei (upload opcional) | Não |

Exemplo de `.env`:

```dotenv
WPSCAN_API_TOKEN="seu_token_aqui"
PDCP_API_KEY="opcional"
```

> **Adicione `.env` ao `.gitignore`** para não versionar os tokens.
> Você também pode apontar outro arquivo com `--env /caminho/arquivo.env`.

---

## Preflight (liveness com httpx)

Antes de rodar os módulos em cada alvo, o status da aplicação é validado com
**httpx**:

- **Vivo** → segue normalmente; status/título/tech salvos em `results/httpx-preflight.txt`.
- **Fora do ar** → alvo é pulado (útil para listas grandes com `-l`).
- **Sem httpx instalado** → fallback automático para `curl` (código HTTP).
- **`--no-preflight`** → pula a checagem e força a execução.

---

## Dependências

```bash
./recon.sh --check          # verifica ferramentas, módulos Python e chaves de API
./recon.sh --install-deps   # instala o que faltar (Python + SecretFinder) e sai
```

| Flag | Descrição |
|------|-----------|
| `--check`        | Verifica todas as ferramentas/módulos e sai |
| `--install-deps` | Instala o que estiver ausente e sai |
| `--yes`          | Responde "sim" a instalações (não interativo) |
| `--no-install`   | Nunca instala nada automaticamente |
| `-h, --help`     | Esta ajuda |

### Ferramentas externas

| Ferramenta | Instalação |
|------------|-----------|
| Sublist3r    | `git clone https://github.com/aboul3la/Sublist3r.git` |
| gau          | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| httpx        | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| dirsearch    | `git clone https://github.com/maurosoria/dirsearch.git` |
| gf           | `go install github.com/tomnomnom/gf@latest` (+ `git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf`) |
| WhatWeb      | `sudo apt install whatweb` (ou `gem install whatweb`) |
| WPScan       | `sudo apt install wpscan` (ou `gem install wpscan`) |
| Nuclei       | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| searchsploit | `sudo apt install exploitdb` |

> Ferramentas em Go exigem o Go instalado (`sudo apt install golang-go`) e
> `$HOME/go/bin` no `PATH`.

---

## Saída

Tudo é salvo em `./recon_<dominio>/`:

```
recon_<dominio>/
├── js/                       # arquivos .js baixados
└── results/
    ├── files-js.txt          # lista de JS encontrados
    ├── secrets.json          # segredos (com -j)
    ├── tech.txt / tech.json  # fingerprint (-t)
    ├── whatweb_verbose.txt   # WhatWeb legível (-T)
    ├── whatweb.json          # WhatWeb JSON (-T)
    ├── tech-detected.txt     # techs registradas p/ validação de vulns
    ├── httpx-preflight.txt   # status do preflight
    ├── subdomains.txt        # subdomínios (-S)
    ├── urls.txt              # URLs históricas (-U)
    ├── probe.txt             # hosts vivos (-p)
    ├── dirs.txt              # diretórios (-d)
    ├── gf-<padrão>.txt       # filtros gf (-g)
    ├── wpscan.txt            # validação WordPress
    ├── nuclei.txt            # validação Nginx/Apache
    └── searchsploit.txt      # exploits por versão
```

---

## Exemplos

```bash
# Pipeline completo com brute-force de diretórios
./recon.sh -u https://alvo.com.br/ --all -w dir.txt --rotate-agent -v

# Fingerprint aprofundado + validação de vulnerabilidades
./recon.sh -u https://alvo.com.br/ -T

# Só fingerprint, sem wpscan/nuclei
./recon.sh -u https://alvo.com.br/ -t -T --no-vuln

# Vários alvos (preflight pula automaticamente os que estão fora do ar)
./recon.sh -l alvos.txt -S -U -f -T -p

# Forçar execução mesmo sem resposta no preflight
./recon.sh -l alvos.txt -a --no-preflight

# Conferir ambiente e status das chaves
./recon.sh --check
```

---

## Aviso legal

Ferramenta destinada a testes **autorizados**. `--all`, `-T` (aggression 3) e a
etapa de wpscan/nuclei geram tráfego significativo e ficam visíveis nos logs do
alvo. Use somente em sistemas para os quais você tem permissão explícita por
escrito. O uso indevido é de responsabilidade exclusiva de quem executa.
