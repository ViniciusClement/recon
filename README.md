# recon.sh - v4.0

Reconhecimento web em Bash: subdomínios, URLs históricas, extração de `.js` e
segredos, fingerprint de tecnologias, probing, brute-force de diretórios,
filtros `gf`, **análise de headers de segurança (OWASP)** e **validação
automática de vulnerabilidades**.

Os modos são **combináveis** numa mesma execução e o pipeline roda sempre em
ordem lógica, independentemente da ordem em que as flags foram passadas.

```
./recon.sh -u <URL> [modos...] [opções]
```

---

## Novidades da 4.0

- **`-T, --tech-deep`** — fingerprint aprofundado com **WhatWeb** (aggression 3,
  User-Agent aleatório). O console recebe apenas uma **visão breve** (contagem
  de tecnologias + HTTP status); o detalhe completo continua indo para
  `whatweb_verbose.txt`/`whatweb.json`.
- **`-p, --probe`** agora também roda **naabu** (top 100 portas mais comuns)
  antes do probe web com httpx.
- **Análise de headers de segurança vs. OWASP** (dentro do `-T`) — compara os
  headers da resposta com a
  [HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html),
  destaca os ausentes nos logs e gera um relatório consolidado por aplicação.
- **Validação de vulnerabilidades ao final do recon** (automática após `-t`/`-T`):
  - **WordPress → WPScan** (plugins/temas vulneráveis, usuários).
  - **Nginx / Apache → Nuclei** (templates por tag) + **searchsploit** por versão.
- **Chaves de API via `.env`** — solicitadas no início e persistidas em `./.env`
  (`chmod 600`); carregadas automaticamente nas execuções seguintes.
- **Preflight em duas fases** — *todos* os alvos de uma lista são validados com
  **httpx antes** de qualquer módulo rodar; os módulos executam só nos ativos.
- **Segue redirecionamentos** em httpx (preflight/probe), nuclei e dirsearch
  (`-fr`/`-F`); o WPScan resolve a URL final antes de escanear (dentro do
  mesmo host, por segurança) já que sua flag `--ignore-main-redirect` não
  segue automaticamente.
- **Saída visual melhorada** — banner, separadores de seção e cabeçalho por
  alvo.
- **Feito para rodar 1x/dia via cron**: auto-atualiza a si mesmo e as bases de
  CVE (nuclei-templates, WPScan DB, Exploit-DB) antes de cada execução, grava
  histórico em `./history/` e sinaliza com 🆕 qualquer achado novo desde o
  último run — inclusive quando a versão do software não mudou, mas uma CVE
  nova passou a afetá-la.
- **`dashboard.py`** — painel web autenticado (arquivo separado) para navegar
  o histórico de todos os domínios já testados.
- **Relatório final consolidado** — `SUMMARY.md` por alvo e
  `./recon-final-report.md` com tudo que foi obtido na execução.
- Novos flags: `--no-vuln`, `--no-preflight`, `--env`, `--wpscan-enum`.

---

## Melhor comando

Pipeline completo (fingerprint + tech-deep + headers OWASP + validação de vulns):

```bash
./recon.sh -u https://dominio.com.br/ --all -w dir.txt --rotate-agent -v
```

Para uma lista de alvos (preflight em duas fases roda automaticamente):

```bash
./recon.sh -l all-sites.txt -U -f -T -p -v --rotate-agent
```

Variante mais enxuta e menos barulhenta (sem brute-force de diretório):

```bash
./recon.sh -u https://dominio.com.br/ -S -U -f -T -p -v
```

> `--all` já inclui `-T` e a etapa de validação de vulnerabilidades — não
> precisa repetir. Os tokens de API são pedidos no início e o preflight roda
> antes de qualquer módulo.

---

## Modos (combináveis)

| Flag | Descrição |
|------|-----------|
| `-f, --files`      | Extrai `.js` do HTML, resolve URLs e baixa os arquivos |
| `-s, --secret`     | Roda o SecretFinder nos `.js` (e no HTML) em busca de segredos |
| `-t, --tech`       | Fingerprint de tecnologias + tentativa de versão |
| `-T, --tech-deep`  | Fingerprint aprofundado (WhatWeb, visão breve no console) + headers OWASP |
| `-S, --subdomains` | Enumera subdomínios (sublist3r; fallback crt.sh) |
| `-U, --urls`       | Coleta URLs históricas do domínio (gau) |
| `-p, --probe`      | Sonda portas (naabu, top 100) + hosts/URLs vivos (httpx) |
| `-d, --dirs`       | Brute-force de diretórios (dirsearch) — requer `--wordlist` |
| `-g, --gf`         | Filtra URLs coletadas por padrões perigosos (gf + Gf-Patterns) |
| `-a, --all`        | Roda todos os módulos disponíveis, em ordem lógica |

**Ordem canônica do pipeline** (independe da ordem das flags):
`subdomains → urls → files → tech → tech-deep → secret → probe → dirs → gf → validação de vulnerabilidades`.

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
| `--no-preflight`        | Pula a Fase 1 de liveness; todos os alvos seguem direto para os módulos |
| `--no-self-update`      | Não atualiza o script/nuclei-templates/WPScan DB/Exploit-DB antes de rodar |
| `--rotate-agent`        | Rotaciona o User-Agent a cada 5 requisições |
| `--timeout <seg>`       | Timeout por requisição (default: `15`) |
| `-v, --verbose`         | Log detalhado em stderr |
| `-j, --json`            | Saída em JSON (onde aplicável) |
| `--no-color`            | Desativa cores |

---

## Redirecionamentos

| Ferramenta | Segue redirect? |
|---|---|
| `curl` (fetch, headers, fallback do preflight) | ✅ Sim (`-L`) |
| WhatWeb (`-T`) | ✅ Sim (padrão) |
| httpx (preflight e `-p`) | ✅ Sim (`-fr -maxr 5 -location`) |
| Nuclei | ✅ Sim (`-fr -mr 5`) |
| dirsearch (`-d`) | ✅ Sim (`-F`) |
| WPScan | ⚠️ A flag `--ignore-main-redirect` **não segue** — o script resolve a URL final antes e aponta o WPScan pra ela, **somente se o destino for o mesmo host/subdomínio** (nunca escapa para um domínio de terceiros) |

## Preflight em duas fases

Quando há mais de um alvo (`-l`), o reconhecimento roda em **duas fases**:

**Fase 1 — varredura de liveness.** *Todos* os alvos são checados primeiro com
**httpx** (fallback para `curl` se o httpx não estiver instalado). Ao final:
- é exibido um resumo (`N ativo(s), M fora/inválido(s) de TOTAL`);
- a lista dos ativos é salva em `./live-targets.txt`;
- pastas criadas para alvos fora do ar são removidas (somente se vazias —
  dados de execuções anteriores nunca são apagados).

**Fase 2 — módulos.** Os módulos selecionados (`-U`, `-f`, `-T`, `-p`, etc.)
rodam **apenas nos alvos que passaram na Fase 1**.

```
== Fase 1/2: verificando quais alvos estão ativos (httpx) ==
----- preflight [1/113] https://adfs.contoso.com.br -----
[!] [preflight] httpx não obteve resposta viva de https://adfs.contoso.com.br
...
== Fase 1/2 concluída: 96 ativo(s), 17 fora/inválido(s) de 113 ==
[+] Alvos ativos salvos em: ./live-targets.txt
== Fase 2/2: executando módulos em 96 alvo(s) ativo(s) ==
===== [1/96] https://www.contoso.com.br =====
```

- **`--no-preflight`** → pula a Fase 1; todos os alvos válidos entram direto na
  Fase 2.
- Um host que responde `403/401/500` conta como *ativo* (respondeu); só é
  descartado quando não há resposta alguma (timeout, DNS falho, conexão
  recusada).

---

## Análise de headers de segurança (OWASP)

No modo **`-T/--tech-deep`**, além do WhatWeb, o script coleta os headers da
resposta final (ignorando hops de redirect) e compara com a
[OWASP HTTP Security Response Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html),
em dois eixos:

**Headers de segurança que deveriam estar presentes** (ausência = achado):

| Header | Recomendação OWASP |
|--------|--------------------|
| `Strict-Transport-Security` | `max-age=63072000; includeSubDomains; preload` |
| `Content-Security-Policy`   | mitiga XSS/injeção |
| `X-Content-Type-Options`    | `nosniff` |
| `X-Frame-Options`           | `DENY` (ou CSP `frame-ancestors`) |
| `Referrer-Policy`           | `strict-origin-when-cross-origin` |
| `Permissions-Policy`        | desativa features não usadas |
| `Cross-Origin-Opener-Policy`   | `same-origin` |
| `Cross-Origin-Embedder-Policy` | `require-corp` |
| `Cross-Origin-Resource-Policy` | `same-site` |

**Headers de divulgação de informação que deveriam estar ausentes** (presença = achado):
`Server` (com versão), `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`.

Os achados são **destacados nos logs** (linhas `[owasp-headers]`) e gravados em:

- `recon_<dominio>/results/security-headers.txt` — detalhe por alvo (presentes, ausentes, divulgação).
- `./owasp-headers-report.md` — **relatório consolidado** com todas as aplicações e seus headers faltantes.

> `X-Frame-Options` é considerado satisfeito quando há `Content-Security-Policy`
> com `frame-ancestors` (orientação atual da OWASP/MDN).

---

## Validação de vulnerabilidades

Executada **ao final do recon**, de forma automática, sempre que houve
fingerprint (`-t` e/ou `-T`). Desligue com `--no-vuln`.

| Detecção | Ferramenta | O que faz |
|----------|-----------|-----------|
| WordPress      | **WPScan**       | Enumera plugins/temas vulneráveis e usuários. Usa `WPSCAN_API_TOKEN` se disponível. |
| Nginx / Apache | **Nuclei**       | Roda templates por tag da tecnologia + CVEs conhecidos, filtrados por severidade. |
| Nginx / Apache | **searchsploit** | Mapeia `versão → exploits conhecidos` (Exploit-DB local, complementar). |

Comandos equivalentes disparados internamente:

```bash
# WordPress
wpscan --url "$URL" --enumerate vp,vt,u --random-user-agent --stealthy \
       --ignore-main-redirect --disable-tls-checks --api-token "$WPSCAN_API_TOKEN"

# Nginx / Apache
nuclei -u "$URL" -o results/nuclei.txt -stats -timeout "$TIMEOUT" -rl 50 \
       -severity low,medium,high,critical -tags nginx,apache
searchsploit nginx <versão>
```

> A enumeração do WPScan é ajustável: `--wpscan-enum vp,vt,tt,u` (ou `at` para
> todos os temas). O `PDCP_API_KEY` não vira flag — o nuclei o lê direto do
> ambiente para o upload opcional no ProjectDiscovery Cloud.

---

## Chaves de API (`.env`)

As chaves são **solicitadas no início** da execução (entrada oculta) e salvas
em `./.env` com permissão `600`. Nas próximas execuções elas são carregadas
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

> **Adicione `.env` ao `.gitignore`** para não versionar os tokens. Você
> também pode apontar outro arquivo com `--env /caminho/arquivo.env`.

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
| naabu        | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` (requer `libpcap-dev`) |
| dirsearch    | `git clone https://github.com/maurosoria/dirsearch.git` |
| gf           | `go install github.com/tomnomnom/gf@latest` (+ `git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf`) |
| WhatWeb      | `sudo apt install whatweb` (ou `gem install whatweb`) |
| WPScan       | `sudo apt install wpscan` (ou `gem install wpscan`) |
| Nuclei       | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| searchsploit | `sudo apt install exploitdb` |

> Ferramentas em Go exigem o Go instalado (`sudo apt install golang-go`) e
> `$HOME/go/bin` no `PATH`. `--install-deps` clona o SecretFinder
> automaticamente, mas **não** instala Sublist3r/Go/ferramentas externas — sem
> Sublist3r, o modo `-S` cai no fallback via crt.sh sozinho.

---

## Resultado final consolidado

Ao final de cada alvo (Fase 2), é gerado um `SUMMARY.md` dentro de
`recon_<dominio>/` com os números daquele alvo (subdomínios, URLs, techs,
portas abertas, findings do Nuclei, segredos, etc.).

Ao final de **toda** a execução, o script imprime uma caixa-resumo no
terminal e gera `./recon-final-report.md`, agregando tudo que foi obtido:
alvos processados, tecnologias por tipo (WordPress/Nginx/Apache), portas
abertas, findings do Nuclei, segredos encontrados, diretórios, e uma tabela
por alvo.

```
▶ Resultado final
[+] Alvos ativos processados : 37
[+] Subdomínios encontrados  : 12
[+] URLs históricas          : 8.431
[+] Tecnologias registradas  : 41  (WordPress: 3 | Nginx: 22 | Apache: 9)
[+] Alvos com portas abertas : 35
[+] Findings do Nuclei       : 6
[+] Segredos encontrados     : 2
[+] Diretórios encontrados   : 118
[+] Relatório completo salvo em: ./recon-final-report.md
```

## Auto-atualização (pensado para cron 1x/dia)

O objetivo deste script é rodar sozinho, todo dia, contra uma lista de
domínios — e continuar achando coisas novas mesmo quando nada mudou no
alvo, porque **a base de CVEs muda**. Por isso, antes de cada execução
(desligável com `--no-self-update`), o script:

1. **Atualiza a si mesmo** — se `recon.sh` estiver dentro de um repositório
   git, roda `git pull --ff-only`; se houver commit novo, o script **reinicia
   automaticamente** com a versão atualizada, preservando os mesmos argumentos
   da chamada original (não precisa reagendar nada no cron).
2. **Atualiza o `nuclei-templates`** (`nuclei -update-templates`) — é daqui
   que vêm as CVEs novas de Nginx/Apache/etc.
3. **Atualiza a base de metadados do WPScan** (`wpscan --update`).
4. **Atualiza o Exploit-DB local** (`searchsploit -u`), se instalado.

Isso é o que resolve o cenário: hoje uma aplicação está com WordPress 7.1.2
(sem vulnerabilidade conhecida); amanhã sai uma CVE nova para essa versão.
Como o script atualiza o `nuclei-templates`/WPScan DB antes de rodar, a
mesma versão que passou limpo hoje pode dar match amanhã — sem precisar
trocar nada manualmente.

```bash
./recon.sh -l domains.txt -a                 # com auto-atualização (padrão)
./recon.sh -l domains.txt -a --no-self-update  # pula a auto-atualização
```

---

## Histórico e detecção de novidades (🆕)

Toda execução grava um snapshot por domínio em `./history/<dominio>/<timestamp>.json`
(tecnologias, versões, portas abertas, findings do Nuclei, vulnerabilidades do
WPScan, contagens de subdomínios/URLs/segredos/diretórios) e uma linha no
índice global `./history/index.jsonl`.

A cada run, o script compara o snapshot atual com o **último snapshot daquele
mesmo domínio** e sinaliza, nos logs e no `SUMMARY.md`, qualquer finding do
Nuclei ou vulnerabilidade do WPScan que **não existia no run anterior**:

```
[!] 🆕 [NOVO em fps.contosodev.com.br] Nuclei: [wordpress-cve-2026-xxxx] [http] [critical] ...
```

Isso cobre exatamente o caso de uma CVE nova afetando uma versão que já foi
vista antes e não tinha dado match: como o Nuclei roda com templates
atualizados a cada execução (ver seção anterior), o mesmo alvo — na mesma
versão — pode produzir um finding novo de um dia para o outro, e o script
destaca isso automaticamente em vez de enterrar no meio do log.

O relatório final (`./recon-final-report.md`) também soma o total de
novidades da execução inteira.

---

## Dashboard web (`dashboard.py`)

Arquivo separado, **sem dependências externas** (só a biblioteca padrão do
Python 3 — não precisa `pip install` nada). Lê o histórico gravado em
`./history/` e serve um painel autenticado.

### Configuração inicial

```bash
python3 dashboard.py --set-password
# Usuário do dashboard [admin]: admin
# Senha: ********
# Confirme a senha: ********
# Credenciais salvas em ./.env (chmod 600).
```

As credenciais ficam em `.env` como `DASHBOARD_USER` e `DASHBOARD_PASS_HASH`
(hash SHA-256 salgado — nunca em texto puro), no mesmo arquivo que já guarda
`WPSCAN_API_TOKEN`/`PDCP_API_KEY`.

### Subindo o painel

```bash
python3 dashboard.py --port 8765
# Dashboard em http://127.0.0.1:8765/  (usuário: admin)
```

- **Bind padrão: `127.0.0.1`** — só acessível localmente ou via túnel SSH
  (`ssh -L 8765:localhost:8765 usuario@servidor`), até você decidir como
  expor.
- **HTTPS direto**, se preferir não usar reverse proxy:
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365
  python3 dashboard.py --port 8765 --host 0.0.0.0 --cert cert.pem --key key.pem
  ```
- **Ou atrás de um reverse proxy com TLS** (Caddy, Nginx, Traefik) — a opção
  mais comum em produção; nesse caso o dashboard pode continuar em
  `127.0.0.1` e o proxy repassa a requisição.
- ⚠️ **Nunca** exponha com `--host 0.0.0.0` sem `--cert/--key` e sem reverse
  proxy: Basic Auth em HTTP puro trafega a senha em texto claro. O próprio
  script avisa isso no terminal se detectar essa combinação.

### O que o dashboard mostra

- **Página inicial**: todos os domínios com histórico, tecnologias
  detectadas (WordPress/Nginx/Apache com versão), portas abertas, quantidade
  de findings do Nuclei, badge **🆕 N novo(s)** quando o último run trouxe
  algo que não existia antes, data do último run e quantos runs já existem.
- **Página por domínio** (`/domain/<nome>`): linha do tempo completa,
  execução por execução, com cada finding do Nuclei/WPScan daquele dia —
  os que são novos em relação ao dia anterior aparecem destacados em
  vermelho com 🆕.
- `GET /health` responde sem autenticação (para health-check de
  monitoramento/systemd).

---

## Rodando 1x/dia via cron

Exemplo de configuração completa num servidor Linux: recon diário às 3h da
manhã, com o dashboard rodando permanentemente como serviço.

**1) Lista de domínios** (`/opt/recon/domains.txt`):
```
exemplo.com.br
outrosite.com.br
# comentários e linhas em branco são ignorados
```

**2) Crontab** (`crontab -e`):
```cron
0 3 * * * cd /opt/recon && ./recon.sh -l domains.txt -a >> /opt/recon/logs/recon-$(date +\%Y\%m\%d).log 2>&1
```

Como o script já pede as chaves de API (`WPSCAN_API_TOKEN`/`PDCP_API_KEY`) só
na *primeira* vez e depois lê do `.env`, o cron roda sem interação — desde
que o `.env` já exista com as chaves preenchidas antes de agendar.

**3) Dashboard como serviço** (`systemd`), para ficar sempre no ar:

`/etc/systemd/system/recon-dashboard.service`:
```ini
[Unit]
Description=Dashboard do recon.sh
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

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now recon-dashboard
```

Com isso: o cron roda o recon todo dia, atualiza sozinho as bases de CVE,
grava o histórico, e o dashboard (sempre no ar via systemd, atrás de um
reverse proxy com TLS ou de um túnel SSH) mostra a evolução de cada domínio
e destaca o que apareceu de novo.

---

## Saída

```
recon_<dominio>/
├── SUMMARY.md                # resumo do alvo (novo)
├── js/                       # arquivos .js baixados
└── results/
    ├── files-js.txt          # lista de JS encontrados
    ├── secrets.json          # segredos (com -j)
    ├── tech.txt / tech.json  # fingerprint (-t)
    ├── whatweb_verbose.txt   # WhatWeb legível (-T)
    ├── whatweb.json          # WhatWeb JSON (-T)
    ├── security-headers.txt  # análise OWASP de headers (-T)
    ├── tech-detected.txt     # techs registradas p/ validação de vulns
    ├── httpx-preflight.txt   # status do preflight (Fase 1)
    ├── subdomains.txt        # subdomínios (-S)
    ├── urls.txt              # URLs históricas (-U)
    ├── probe.txt             # hosts vivos (-p)
    ├── naabu.txt             # portas abertas, top 100 (-p)
    ├── dirs.txt              # diretórios (-d)
    ├── gf-<padrão>.txt       # filtros gf (-g)
    ├── wpscan.txt            # validação WordPress
    ├── nuclei.txt            # validação Nginx/Apache
    └── searchsploit.txt      # exploits por versão

./owasp-headers-report.md    # relatório OWASP consolidado (todas as aplicações)
./recon-final-report.md      # resultado final consolidado (todos os alvos)
./live-targets.txt           # alvos ativos detectados na Fase 1 (preflight)
./.env                       # chaves de API + credenciais do dashboard (chmod 600)
./history/
├── index.jsonl               # índice global (todos os domínios, todos os runs)
└── <dominio>/
    └── <timestamp>.json      # snapshot de um run (techs, portas, findings...)
./dashboard.py                # painel web autenticado (histórico + novidades)
```

---

## Exemplos

```bash
# Pipeline completo com brute-force de diretórios
./recon.sh -u https://alvo.com.br/ --all -w dir.txt --rotate-agent -v

# Lista de alvos: Fase 1 (liveness) roda antes de qualquer módulo
./recon.sh -l all-sites.txt -U -f -T -p -v --rotate-agent

# Fingerprint aprofundado + headers OWASP + validação de vulnerabilidades
./recon.sh -u https://alvo.com.br/ -T

# Só fingerprint e headers, sem wpscan/nuclei
./recon.sh -u https://alvo.com.br/ -t -T --no-vuln

# Forçar execução mesmo sem resposta no preflight (pula a Fase 1)
./recon.sh -l alvos.txt -a --no-preflight

# Reprocessar só os alvos que já se confirmaram ativos numa execução anterior
./recon.sh -l live-targets.txt -a

# Conferir ambiente e status das chaves
./recon.sh --check
```

---

## Aviso legal

Ferramenta destinada a testes **autorizados**. `--all`, `-T` (aggression 3) e a
etapa de wpscan/nuclei geram tráfego significativo e ficam visíveis nos logs do
alvo. Use somente em sistemas para os quais você tem permissão explícita por
escrito. O uso indevido é de responsabilidade exclusiva de quem executa.
