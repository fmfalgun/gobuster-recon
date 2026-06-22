# gobuster-recon

Directory brute-force wrapper — hidden path discovery, status code + redirect mapping, admin/login/phpMyAdmin/.git/.env/backup exposure flags. HTTP fallback mode when gobuster is not installed. Community Directory Board.

**[→ Directory Board](https://fmfalgun.github.io/gobuster-recon/dir-board.html)** — community directory scans, browsable without the tool.

## Requirements

- Python 3.8+ (stdlib only — no pip install needed)
- `gobuster` Go binary: `apt install gobuster` ← required for full scan
- Without gobuster: HTTP fallback mode runs a built-in 60-path wordlist automatically

## Wordlist resolution order

1. `-w` / `--wordlist` flag (if given and exists)
2. `/usr/share/wordlists/dirb/common.txt` (Kali Linux)
3. `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt`
4. `/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt`
5. Built-in 60-entry wordlist (always available)

## Usage

```bash
# basic directory scan
python3 gobuster-recon.py -u https://target.com

# with extensions + custom wordlist
python3 gobuster-recon.py -u https://target.com -w /usr/share/wordlists/dirb/common.txt -x php,html

# save structured JSON
python3 gobuster-recon.py -u https://target.com -o results.json

# bypass 24h cache
python3 gobuster-recon.py -u https://target.com --no-cache

# submit to Directory Board
python3 gobuster-recon.py -u https://target.com --submit
```

## Output schema

```json
{
  "url": "https://nmap.org",
  "mode": "dir",
  "wordlist": "common.txt",
  "method": "gobuster",
  "findings": [
    {"path": "/download", "status": 200, "size": 12847, "redirect": null},
    {"path": "/book",     "status": 301, "size": 0,     "redirect": "https://nmap.org/book/"}
  ],
  "finding_count": 8,
  "status_codes": {"200": 6, "301": 2},
  "has_admin": false,
  "has_login": false,
  "has_git": false,
  "has_env": false,
  "has_backup": false
}
```

## Flags

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Target URL |
| `-w`, `--wordlist` | Custom wordlist path |
| `-m`, `--mode` | Scan mode: dir, dns, vhost (default: dir) |
| `-x`, `--extensions` | File extensions to append (e.g., php,html) |
| `-t`, `--threads` | Threads (default: 10) |
| `-s`, `--status-codes` | Status codes to include |
| `-o`, `--output` | Write JSON to file |
| `--no-cache` | Bypass 24h SQLite cache |
| `--ttl` | Cache TTL hours (default: 24) |
| `--submit` | Submit result to Directory Board |
| `--reconfigure` | Update stored credentials |

## High-value finds

- `.git/HEAD` — full source code disclosure via `git clone https://target.com/.git`
- `.env` — database passwords, API keys in plaintext
- `phpmyadmin` — unauthenticated DB access if misconfigured
- `backup.sql`, `backup.zip` — credential dumps
- `admin/dashboard` — credential attack surface

## Pairs with

- [wpscan-recon](https://github.com/fmfalgun/wpscan-recon) — WordPress plugin/user enumeration
- [dig-recon](https://github.com/fmfalgun/dig-recon) — DNS sweep + SPF/DMARC
- [subfinder-recon](https://github.com/fmfalgun/subfinder-recon) — passive subdomain enumeration

---

MIT License · Built by [Falgun Marothia](https://fmfalgun.github.io)
