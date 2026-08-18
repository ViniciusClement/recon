# recon
```
recon.sh — reconhecimento web (JS, secrets, tech, subdomínios, etc.)

Uso:
  ./recon.sh -u <URL> [modos...] [opções]

Modos (podem ser COMBINADOS numa mesma execução):
  -f, --files        Extrai .js do HTML, resolve URLs e baixa os arquivos
  -s, --secret       Roda o SecretFinder nos .js (e no HTML) em busca de segredos
  -t, --tech         Fingerprint de tecnologias + tentativa de versão
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
      --rotate-agent       Rotaciona o User-Agent a cada 5 requisições
      --timeout <seg>      Timeout por requisição (default: 15)
  -v, --verbose            Log detalhado em stderr
  -j, --json               Saída em JSON (onde aplicável)
      --no-color           Desativa cores

Dependências:
      --check              Verifica todas as ferramentas/módulos e sai
      --install-deps       Instala o que estiver ausente (Python + SecretFinder) e sai
      --yes                Responde "sim" a instalações (não interativo)
      --no-install         Nunca instala nada automaticamente
  -h, --help               Esta ajuda

Saída:
  Tudo é salvo em ./recon_<dominio>/ com subpastas js/ e results/
```
