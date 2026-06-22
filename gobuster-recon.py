#!/usr/bin/env python3
"""
gobuster-recon — directory brute-force with TTL cache and community submission.

Primary mode : wraps the gobuster Go binary (dir mode), parses text output.
Fallback mode : HEAD-based HTTP path probing via urllib (stdlib only) when
                gobuster is absent.
Cache         : SQLite (cache.db), 24h TTL, keyed by normalised URL.
Submit        : posts full JSON result to GitHub Issues as [submission] entry.
"""

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import urllib.error
from pathlib import Path

# ── constants ─────────────────────────────────────────────────────────────────

__version__       = "1.0.0"
CACHE_DB          = "./cache.db"
CONFIG_PATH       = Path.home() / ".config" / "gobuster-recon" / "config.json"
GITHUB_ISSUES_URL = "https://api.github.com/repos/fmfalgun/gobuster-recon/issues"

DEFAULT_STATUS_CODES = "200,204,301,302,307,401,403,405,500"
DEFAULT_THREADS      = 10
DEFAULT_WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
]

BUILTIN_WORDLIST = [
    "admin", "login", "wp-admin", "wp-login.php", "phpmyadmin", "phpMyAdmin",
    "administrator", "admin.php", "login.php", "dashboard", "panel", "cpanel",
    "manager", "management", "config", "configuration", "backup", "backups",
    "api", "api/v1", "api/v2", ".env", "robots.txt", "sitemap.xml",
    "security.txt", ".well-known/security.txt", "xmlrpc.php", "wp-config.php",
    "readme.txt", "readme.html", "CHANGELOG", "install", "setup",
    "test", "test.php", "phpinfo.php", "info.php", "server-status",
    ".htaccess", ".git/HEAD", ".git/config",
    "uploads", "images", "img", "static", "assets", "css", "js",
    "about", "contact", "help", "support", "blog", "news", "search",
    "download", "downloads", "register", "signup", "logout",
    "user", "users", "account", "settings", "profile",
]

# gobuster dir output line pattern:
#   /admin                (Status: 301) [Size: 314] [--> https://example.com/admin/]
#   /login                (Status: 200) [Size: 5423]
LINE_RE = re.compile(
    r'^(/\S*)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\](?:\s*\[-->\s*(.+?)\])?',
    re.MULTILINE,
)

# ── url helpers ───────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    """Ensure https:// scheme; strip trailing slash."""
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def normalize_filename(url: str) -> str:
    """
    Convert URL to a safe filename.
      https://nmap.org                        → nmap.org.json
      https://cpanel.startbitsolutions.com    → cpanel.startbitsolutions.com.json
    """
    name = re.sub(r"^https?://", "", url)
    name = name.rstrip("/")
    name = name.replace("/", "-")
    return name + ".json"

# ── cache ─────────────────────────────────────────────────────────────────────

def get_cache_db():
    import sqlite3 as _sqlite3
    conn = _sqlite3.connect(CACHE_DB)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS gobuster_cache (
            url       TEXT PRIMARY KEY,
            data      TEXT NOT NULL,
            cached_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def cache_get(url: str, ttl_hours: int = 24):
    """Return parsed dict if cached and within TTL, else None."""
    try:
        conn = get_cache_db()
        row = conn.execute(
            "SELECT data, cached_at FROM gobuster_cache WHERE url = ?", (url,)
        ).fetchone()
        conn.close()
        if row is None:
            return None
        data_str, cached_at_str = row
        cached_at = datetime.datetime.strptime(cached_at_str, "%Y-%m-%dT%H:%M:%SZ")
        age = (datetime.datetime.utcnow() - cached_at).total_seconds() / 3600
        if age > ttl_hours:
            return None
        return json.loads(data_str)
    except Exception:
        return None


def cache_put(url: str, data: dict):
    """Upsert result into cache."""
    try:
        conn = get_cache_db()
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute(
            """INSERT INTO gobuster_cache (url, data, cached_at) VALUES (?, ?, ?)
               ON CONFLICT(url) DO UPDATE SET data=excluded.data, cached_at=excluded.cached_at""",
            (url, json.dumps(data), now),
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[WARN] cache write failed: {e}", file=sys.stderr)

# ── config / setup / submit ───────────────────────────────────────────────────

def load_config() -> dict:
    """Load config from CONFIG_PATH; return {} if absent or corrupt."""
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def save_config(cfg: dict):
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)
    print(f"[+] config saved → {CONFIG_PATH}")


def setup_wizard() -> dict:
    """Interactive first-run prompt; persists to CONFIG_PATH."""
    print("\n── gobuster-recon setup ────────────────────────────────")
    print("  (press Enter to skip any field)")
    cfg = load_config()

    def ask(prompt, key, secret=False):
        current = cfg.get(key, "")
        display = ("*" * 8) if (secret and current) else (current or "not set")
        val = input(f"  {prompt} [{display}]: ").strip()
        if val:
            cfg[key] = val

    ask("GitHub PAT (Issues write scope)", "github_pat", secret=True)
    ask("Display name (shown on submission)", "display_name")
    ask("Display location (optional)",        "display_loc")

    save_config(cfg)
    print("────────────────────────────────────────────────────────\n")
    return cfg


def submit_result(result: dict, config: dict):
    """POST result to GitHub Issues as a community submission."""
    pat = config.get("github_pat") or os.environ.get("GITHUB_PAT")
    if not pat:
        print("[ERROR] No GitHub PAT found. Run --reconfigure to add one.", file=sys.stderr)
        return

    domain = result.get("domain", result.get("url", "unknown"))
    consent = input(f"\n  Submit scan of {domain} to the community board? [y/N]: ").strip().lower()
    if consent != "y":
        print("  Submission cancelled.")
        return

    display_name = config.get("display_name", "anonymous")
    display_loc  = config.get("display_loc", "")
    credit_line  = display_name + (f" ({display_loc})" if display_loc else "")

    body = (
        f"**Submitted by:** {credit_line}\n\n"
        f"**Scanned at:** {result.get('scanned_at', 'unknown')}\n\n"
        f"**Method:** {result.get('method', 'unknown')}\n\n"
        f"**Wordlist:** {result.get('wordlist', 'unknown')}\n\n"
        f"**Findings:** {result.get('finding_count', 0)} paths\n\n"
        "```json\n"
        + json.dumps(result, indent=2)
        + "\n```"
    )

    payload = json.dumps({
        "title": f"[submission] {domain}",
        "body":  body,
        "labels": ["submission"],
    }).encode()

    req = urllib.request.Request(
        GITHUB_ISSUES_URL,
        data=payload,
        headers={
            "Authorization": f"token {pat}",
            "Accept":        "application/vnd.github+json",
            "Content-Type":  "application/json",
            "User-Agent":    f"gobuster-recon/{__version__}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read())
            print(f"[+] submitted → {resp_data.get('html_url', '(no URL)')}")
    except urllib.error.HTTPError as e:
        body_err = e.read().decode(errors="replace")
        print(f"[ERROR] GitHub API {e.code}: {body_err[:300]}", file=sys.stderr)
    except Exception as e:
        print(f"[ERROR] submission failed: {e}", file=sys.stderr)

# ── gobuster wrapper ──────────────────────────────────────────────────────────

def check_gobuster() -> bool:
    """Return True if gobuster binary is on PATH."""
    return shutil.which("gobuster") is not None


def resolve_wordlist(wordlist_arg=None):
    """
    Returns (path_or_None, label).

    Priority:
      1. Explicit --wordlist arg (if path exists on disk)
      2. First hit in DEFAULT_WORDLIST_CANDIDATES
      3. (None, "builtin") — caller must write BUILTIN_WORDLIST to a temp file
    """
    if wordlist_arg:
        if Path(wordlist_arg).exists():
            return wordlist_arg, Path(wordlist_arg).name
        print(
            f"[WARN] wordlist not found: {wordlist_arg} — searching defaults",
            file=sys.stderr,
        )
    for candidate in DEFAULT_WORDLIST_CANDIDATES:
        if Path(candidate).exists():
            return candidate, Path(candidate).name
    return None, "builtin"


def make_temp_wordlist() -> str:
    """Write BUILTIN_WORDLIST to a temp file and return its path."""
    fd, path = tempfile.mkstemp(prefix="gobuster_recon_wl_", suffix=".txt")
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(BUILTIN_WORDLIST) + "\n")
    return path


def parse_gobuster_output(text: str) -> list:
    """
    Parse gobuster dir text output into a list of finding dicts.

    Expected line format:
      /admin     (Status: 301) [Size: 314] [--> https://example.com/admin/]
      /login     (Status: 200) [Size: 5423]
    """
    findings = []
    for m in LINE_RE.finditer(text):
        path, status, size, redirect = m.group(1), m.group(2), m.group(3), m.group(4)
        findings.append({
            "path":     path,
            "status":   int(status),
            "size":     int(size),
            "redirect": redirect.strip() if redirect else None,
            "source":   "dir",
        })
    return findings


def run_gobuster(
    url,
    wordlist_path,
    mode="dir",
    extensions=None,
    threads=DEFAULT_THREADS,
    status_codes=DEFAULT_STATUS_CODES,
) -> list:
    """Invoke gobuster subprocess and return parsed findings list."""
    cmd = [
        "gobuster", mode,
        "-u", url,
        "-w", wordlist_path,
        "-t", str(threads),
        "-s", status_codes,
        "--no-error", "-q",
    ]
    if extensions:
        cmd += ["-x", extensions]

    # gobuster may exit non-zero even on success (e.g. when forbidden paths exist)
    # — capture stdout regardless of return code
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    findings = parse_gobuster_output(proc.stdout)
    if not findings and proc.returncode != 0:
        print(f"[WARN] gobuster stderr: {proc.stderr[:300]}", file=sys.stderr)
    return findings

# ── HTTP fallback ─────────────────────────────────────────────────────────────

def http_fallback(url: str, wordlist_paths=None) -> list:
    """
    Stdlib-only directory probing via HEAD requests when gobuster is absent.

    Uses wordlist_paths list (path strings) if supplied, otherwise falls back
    to the built-in BUILTIN_WORDLIST path names.
    """
    paths   = wordlist_paths or BUILTIN_WORDLIST
    findings = []
    headers  = {"User-Agent": "Mozilla/5.0 (gobuster-recon http-fallback)"}

    for path in paths:
        target = url.rstrip("/") + "/" + path.lstrip("/")
        try:
            req = urllib.request.Request(target, headers=headers, method="HEAD")
            with urllib.request.urlopen(req, timeout=8) as resp:
                status = resp.status
                size   = int(resp.headers.get("Content-Length") or 0)
                redir  = resp.url if resp.url != target else None
                findings.append({
                    "path":     "/" + path.lstrip("/"),
                    "status":   status,
                    "size":     size,
                    "redirect": redir,
                    "source":   "http_fallback",
                })
        except urllib.error.HTTPError as e:
            # 401/403/405/500 are interesting even as errors
            if e.code in (401, 403, 405, 500):
                findings.append({
                    "path":     "/" + path.lstrip("/"),
                    "status":   e.code,
                    "size":     0,
                    "redirect": None,
                    "source":   "http_fallback",
                })
        except Exception:
            pass  # timeout, connection refused — skip silently

    return findings

# ── classification ────────────────────────────────────────────────────────────

def classify_findings(findings: list) -> dict:
    """Derive boolean flags and status-code distribution from findings list."""
    paths_lower = [f["path"].lower() for f in findings]

    def path_match(*keywords):
        return any(any(kw in p for kw in keywords) for p in paths_lower)

    status_dist = {}
    for f in findings:
        key = str(f["status"])
        status_dist[key] = status_dist.get(key, 0) + 1

    return {
        "has_admin":      path_match("admin", "administrator", "dashboard", "panel"),
        "has_login":      path_match("login", "signin", "sign-in", "auth"),
        "has_phpmyadmin": path_match("phpmyadmin", "pma", "mysql"),
        "has_git":        path_match(".git"),
        "has_env":        path_match(".env"),
        "has_backup":     path_match("backup", ".bak", ".sql", ".zip"),
        "status_codes":   status_dist,
        "status_2xx":     sum(v for k, v in status_dist.items() if k.startswith("2")),
        "status_3xx":     sum(v for k, v in status_dist.items() if k.startswith("3")),
        "status_4xx":     sum(v for k, v in status_dist.items() if k.startswith("4")),
    }

# ── terminal output ───────────────────────────────────────────────────────────

def print_result(result: dict):
    """Pretty-print scan result to stdout."""
    sep    = "─" * 48
    target = result.get("url", "")
    method = result.get("method", "unknown")
    wl     = result.get("wordlist", "unknown")
    count  = result.get("finding_count", 0)
    s2xx   = result.get("status_2xx", 0)
    s3xx   = result.get("status_3xx", 0)
    s4xx   = result.get("status_4xx", 0)
    cached = result.get("cached", False)

    def yn(flag): return "YES" if result.get(flag) else "NO"

    print(sep)
    print(f"  target      : {target}" + (" [CACHED]" if cached else ""))
    print(f"  method      : {method}")
    print(f"  wordlist    : {wl}")
    print(f"  findings    : {count} paths")
    print(f"  2xx / 3xx / 4xx  : {s2xx} / {s3xx} / {s4xx}")
    print(
        f"  admin       : {yn('has_admin')}   "
        f"login: {yn('has_login')}   "
        f"phpMyAdmin: {yn('has_phpmyadmin')}"
    )
    print(
        f"  git exposed : {yn('has_git')}   "
        f".env: {yn('has_env')}   "
        f"backup: {yn('has_backup')}"
    )

    findings = result.get("findings") or []
    if findings:
        print(sep)
        for f in findings:
            path   = f.get("path", "")
            status = f.get("status", "")
            size   = f.get("size", 0)
            redir  = f.get("redirect")
            line   = f"  {path:<22} [{status}]  {size}b"
            if redir:
                line += f"  → {redir}"
            print(line)

    print(sep)

# ── orchestration ─────────────────────────────────────────────────────────────

def run(
    url,
    wordlist=None,
    mode="dir",
    extensions=None,
    threads=DEFAULT_THREADS,
    status_codes=DEFAULT_STATUS_CODES,
) -> dict:
    """Run the scan (gobuster or fallback), print result, return dict."""
    url     = normalize_url(url)
    domain  = url.split("://", 1)[1].split("/")[0]
    now     = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    temp_wl = None

    if check_gobuster():
        wl_path, wl_label = resolve_wordlist(wordlist)
        if wl_path is None:
            temp_wl  = make_temp_wordlist()
            wl_path  = temp_wl
            wl_label = "builtin"
        findings = run_gobuster(url, wl_path, mode, extensions, threads, status_codes)
        method   = "gobuster"
    else:
        print("[WARN] gobuster not found — falling back to HTTP checks", file=sys.stderr)
        print(
            "[WARN] Install: apt install gobuster  or  "
            "go install github.com/OJ/gobuster/v3@latest",
            file=sys.stderr,
        )
        wl_label = "builtin"
        findings = http_fallback(url)
        method   = "http_fallback"

    # clean up temp wordlist file
    if temp_wl:
        try:
            Path(temp_wl).unlink()
        except Exception:
            pass

    flags  = classify_findings(findings)
    result = {
        "url":           url,
        "domain":        domain,
        "d":             domain,
        "mode":          mode,
        "wordlist":      wl_label,
        "extensions":    extensions or "",
        "threads":       threads,
        "scanned_at":    now,
        "cached":        False,
        "method":        method,
        "findings":      findings,
        "finding_count": len(findings),
        **flags,
    }
    print_result(result)
    return result

# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description=f"gobuster-recon {__version__} — directory brute-force with TTL cache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  %(prog)s -u https://cpanel.startbitsolutions.com
  %(prog)s -u shop.startbitsolutions.com -w /usr/share/wordlists/dirb/common.txt
  %(prog)s -u https://example.com -x php,html -t 20 --output result.json
  %(prog)s -u https://example.com --no-cache --submit
  %(prog)s -u https://example.com -m vhost
  %(prog)s --reconfigure
        """,
    )
    parser.add_argument("-u", "--url",          metavar="URL",
                        help="Target URL to scan")
    parser.add_argument("-w", "--wordlist",     metavar="FILE",
                        help="Wordlist path (default: auto-detect system wordlists)")
    parser.add_argument("-m", "--mode",         default="dir",
                        choices=["dir", "dns", "vhost"],
                        help="gobuster mode (default: dir)")
    parser.add_argument("-x", "--extensions",   metavar="php,html",
                        help="File extensions to probe (e.g. php,html,txt)")
    parser.add_argument("-t", "--threads",      type=int, default=DEFAULT_THREADS,
                        metavar="N",
                        help=f"Number of threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-s", "--status-codes", default=DEFAULT_STATUS_CODES,
                        metavar="CODES",
                        help=f"Comma-separated status codes to show (default: {DEFAULT_STATUS_CODES})")
    parser.add_argument("-o", "--output",       metavar="FILE",
                        help="Write JSON result to file")
    parser.add_argument("--no-cache",           action="store_true",
                        help="Skip cache lookup; always rescan")
    parser.add_argument("--ttl",               type=int, default=24, metavar="HOURS",
                        help="Cache TTL in hours (default: 24)")
    parser.add_argument("--submit",             action="store_true",
                        help="Post result to community board via GitHub Issues")
    parser.add_argument("--reconfigure",        action="store_true",
                        help="Re-run setup wizard to update stored credentials")
    parser.add_argument("--version",            action="store_true",
                        help="Print version and exit")
    args = parser.parse_args()

    # ── dispatch ──────────────────────────────────────────────────────────────

    if args.version:
        print(f"gobuster-recon {__version__}")
        sys.exit(0)

    if args.reconfigure:
        setup_wizard()
        sys.exit(0)

    if not args.url:
        parser.error("--url is required (or use --reconfigure / --version)")

    url = normalize_url(args.url)

    # cache check
    result = None
    if not args.no_cache:
        result = cache_get(url, args.ttl)
        if result:
            result["cached"] = True
            print_result(result)

    if result is None:
        result = run(
            url,
            wordlist=args.wordlist,
            mode=args.mode,
            extensions=args.extensions,
            threads=args.threads,
            status_codes=args.status_codes,
        )
        cache_put(url, result)

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with open(out_path, "w") as f:
            json.dump(result, f, indent=2)
        print(f"[+] written → {out_path}")

    if args.submit:
        cfg = load_config()
        if not cfg:
            cfg = setup_wizard()
        submit_result(result, cfg)


if __name__ == "__main__":
    main()
