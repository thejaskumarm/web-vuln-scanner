#!/usr/bin/env python3
"""
Web Vulnerability Scanner v2.1
================================
An educational tool to check websites for common security misconfigurations
based on the OWASP Top 10 web application risks.

Usage:
    python scanner.py <URL>                         # Basic scan
    python scanner.py <URL> --report                # Scan + save HTML & JSON report
    python scanner.py <URL> --report --output myreport  # Custom filename

Checks:
    1.  Security Headers        (OWASP A05)
    2.  HTTPS / TLS             (OWASP A02)
    3.  Sensitive File Exposure (OWASP A01/A05)
    4.  Cookie Security         (OWASP A02/A07)
    5.  CSRF Token Detection    (OWASP A01)
    6.  Server/Tech Disclosure  (OWASP A05)
    7.  XSS Indicators in HTML  (OWASP A03)
    8.  SQL Injection Probing   (OWASP A03)
    9.  Open Redirect Detection (OWASP A01)
    10. Directory Listing       (OWASP A05)
"""

import sys
import json
import uuid
import argparse
import datetime
import logging
import threading
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import (
    urljoin, urlparse, urlencode, parse_qs, urlunparse, quote_plus
)
import re

logger = logging.getLogger("scanner")

# ─────────────────────────────────────────────
#  Terminal colors
# ─────────────────────────────────────────────
class Color:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def banner():
    print(f"""
{Color.CYAN}{Color.BOLD}
╔══════════════════════════════════════════════════════╗
║         🔍  Web Vulnerability Scanner v2.1          ║
║          Educational OWASP Top 10 Checker            ║
╚══════════════════════════════════════════════════════╝
{Color.RESET}""")


def ok(msg):   print(f"  {Color.GREEN}[✔] {msg}{Color.RESET}")
def warn(msg): print(f"  {Color.YELLOW}[!] {msg}{Color.RESET}")
def vuln(msg): print(f"  {Color.RED}[✘] VULNERABLE: {msg}{Color.RESET}")
def info(msg): print(f"  {Color.BLUE}[i] {msg}{Color.RESET}")


def section(title):
    print(f"\n{Color.BOLD}{Color.CYAN}{'─'*54}")
    print(f"  {title}")
    print(f"{'─'*54}{Color.RESET}")


# ─────────────────────────────────────────────
#  Per-scan session — fresh for each scan so
#  cookies/state never bleed between targets
# ─────────────────────────────────────────────
_tls = threading.local()
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def get_session() -> requests.Session:
    """Return the current scan's thread-local session.
    Always call new_scan_session() before starting a scan."""
    if not hasattr(_tls, "session") or _tls.session is None:
        # Fallback: create one if new_scan_session() was not called
        _tls.session = requests.Session()
        _tls.session.headers.update({"User-Agent": _UA})
    return _tls.session


def new_scan_session() -> requests.Session:
    """Create a brand-new session for this scan.
    Call this at the START of every scan to prevent cookie/state bleed
    between different target websites."""
    _tls.session = requests.Session()
    _tls.session.headers.update({"User-Agent": _UA})
    return _tls.session


def fetch(url: str, timeout: int = 12, verify: bool = True, _retry: bool = True):
    """Fetch a URL. Returns (response, soup) or (None, None).
    _retry guards against infinite SSL recursion."""
    try:
        resp = get_session().get(
            url, timeout=timeout, allow_redirects=True, verify=verify
        )
        soup = BeautifulSoup(resp.text, "html.parser")
        return resp, soup
    except requests.exceptions.SSLError:
        if _retry:
            warn("SSL error — retrying without cert verification.")
            return fetch(url, timeout=timeout, verify=False, _retry=False)
        logger.error("SSL error (no-verify retry also failed): %s", url)
        return None, None
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to %s", url)
        return None, None
    except requests.exceptions.Timeout:
        logger.error("Request timed out: %s", url)
        return None, None
    except Exception as e:
        logger.error("Fetch error: %s", e)
        return None, None


def quick_get(url: str, timeout: int = 5, follow_redirects: bool = False):
    """Quick GET for probing paths. Tight timeout for parallel workers."""
    try:
        return get_session().get(
            url, timeout=timeout, allow_redirects=follow_redirects
        )
    except Exception:
        return None


def count_issues(findings: dict) -> int:
    """Return total issues across all 10 check categories."""
    return sum([
        len(findings.get("security_headers", [])),
        len(findings.get("https", [])),
        len(findings.get("sensitive_files", [])),
        len(findings.get("cookies", [])),
        len(findings.get("csrf", [])),
        len(findings.get("server_disclosure", [])),
        len(findings.get("xss_indicators", [])),
        len(findings.get("sqli", [])),
        len(findings.get("open_redirect", [])),
        len(findings.get("directory_listing", [])),
    ])


# ══════════════════════════════════════════════════
#  CHECK 1 – Security Headers  (OWASP A05)
# ══════════════════════════════════════════════════
def check_security_headers(response: requests.Response, findings: dict):
    section("CHECK 1 │ Security Headers  (OWASP A05)")

    headers = response.headers
    checks = [
        ("X-Frame-Options",
         "Clickjacking risk — site can be embedded in iframes"),
        ("X-Content-Type-Options",
         "Browser may execute files with wrong MIME type"),
        ("Strict-Transport-Security",
         "Users may connect over insecure HTTP (no HSTS)"),
        ("Content-Security-Policy",
         "No CSP → higher XSS and injection risk"),
        ("Referrer-Policy",
         "Sensitive URLs may leak to third parties"),
        ("Permissions-Policy",
         "Camera / mic / geolocation may be abused"),
    ]

    missing = []
    for header_name, risk in checks:
        value = headers.get(header_name)
        if value:
            # Extra accuracy: flag weak HSTS (max-age too short)
            if header_name == "Strict-Transport-Security":
                m = re.search(r"max-age\s*=\s*(\d+)", value, re.IGNORECASE)
                if m and int(m.group(1)) < 86400:
                    warn(f"HSTS max-age is very short ({m.group(1)}s) — recommend ≥ 86400")
                    missing.append({
                        "header": header_name,
                        "risk": f"HSTS max-age too short ({m.group(1)}s)"
                    })
                else:
                    ok(f"{header_name}: {value[:80]}")
            else:
                ok(f"{header_name}: {value[:80]}")
        else:
            vuln(f"Missing '{header_name}' — {risk}")
            missing.append({"header": header_name, "risk": risk})

    findings["security_headers"] = missing
    return missing


# ══════════════════════════════════════════════════
#  CHECK 2 – HTTPS / TLS  (OWASP A02)
# ══════════════════════════════════════════════════
def check_https(url: str, findings: dict):
    section("CHECK 2 │ HTTPS / TLS  (OWASP A02 – Cryptographic Failures)")

    issues = []
    parsed = urlparse(url)

    if parsed.scheme == "https":
        ok("Site is served over HTTPS.")
    else:
        vuln("Site uses plain HTTP — data is in clear text!")
        issues.append("No HTTPS")

    # BUG FIX: Use follow_redirects=True and check final URL
    http_url = "http://" + parsed.netloc + (parsed.path or "/")
    r = quick_get(http_url, follow_redirects=True)
    if r is not None:
        if r.url.startswith("https://"):
            ok("HTTP → HTTPS redirect is in place.")
        else:
            vuln("HTTP version does NOT redirect to HTTPS automatically.")
            issues.append("No HTTP→HTTPS redirect")
    else:
        info("Could not reach HTTP version to check redirect.")

    findings["https"] = issues


# ══════════════════════════════════════════════════
#  CHECK 3 – Sensitive File Exposure  (OWASP A01/A05)
# ══════════════════════════════════════════════════

# Files that are always public and should never count as vulnerabilities
_ALWAYS_PUBLIC = {
    "robots.txt", "sitemap.xml", "favicon.ico",
}

# Files that are genuinely dangerous if exposed
_SENSITIVE_PATHS = [
    ".git/HEAD", ".git/config",
    ".env", ".env.local", ".env.production",
    "config.php", "wp-config.php", "configuration.php",
    "web.config", "phpinfo.php",
    "backup.zip", "backup.tar.gz", "database.sql", "dump.sql",
    "server.key", "server.pem", "id_rsa", "id_rsa.pub",
    ".bash_history", ".ssh/authorized_keys",
    ".htaccess", ".htpasswd",
    "admin/", "administrator/",
    "phpmyadmin/", "pma/",
    "Dockerfile", ".dockerenv",
    "docker-compose.yml", "docker-compose.yaml",
    "composer.json", "composer.lock",
    "yarn.lock", "package-lock.json",
]

def check_sensitive_files(base_url: str, findings: dict):
    section("CHECK 3 │ Sensitive File Exposure  (OWASP A01 / A05)")

    base = base_url.rstrip("/") + "/"
    target_host = urlparse(base_url).netloc

    def _probe(path: str):
        full = urljoin(base, path)
        # Safety: never probe outside the target domain
        if urlparse(full).netloc != target_host:
            return None

        r = quick_get(full, timeout=5)
        if r is None:
            return None

        if r.status_code == 200:
            body_lower = r.text[:4096].lower()  # only check first 4KB

            # Detect soft-404 pages
            soft_404 = [
                "404 not found", "page not found", "file not found",
                "<title>404", "does not exist", "not found",
                "error 404", "cannot be found",
            ]
            if any(ind in body_lower for ind in soft_404):
                ok(f"Soft-404 ignored: /{path}")
                return None

            # robots.txt — only flag if it reveals sensitive admin paths
            if path == "robots.txt":
                sensitive_paths_in_robots = [
                    "/admin", "/backup", "/config", "/private",
                    "/secret", "/internal", "/api/", "/.env",
                ]
                if any(p in body_lower for p in sensitive_paths_in_robots):
                    vuln(f"robots.txt discloses sensitive paths → {full}")
                    return full
                else:
                    ok(f"robots.txt present but no sensitive paths disclosed.")
                    return None

            # For config/credential files: validate content looks real
            if path in ("composer.json", "package-lock.json", "yarn.lock"):
                # These are common in open-source projects; flag only if
                # they contain credentials or tokens
                if any(kw in body_lower for kw in [
                    "password", "secret", "token", "api_key", "private_key"
                ]):
                    vuln(f"Credentials in {path} → {full}")
                    return full
                else:
                    ok(f"/{path} exposed but no credentials detected.")
                    return None

            vuln(f"Accessible → {full}  [HTTP {r.status_code}]")
            return full

        elif r.status_code in (401, 403):
            info(f"/{path} exists but access is restricted [HTTP {r.status_code}] ✔")
        elif r.status_code in (301, 302):
            # Follow redirect manually to see final destination
            location = r.headers.get("Location", "")
            if location and urlparse(location).netloc not in ("", target_host):
                warn(f"/{path} redirects off-site → {location}")
        # 404, 410, 500 etc. — not exposed
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_probe, _SENSITIVE_PATHS))

    exposed = [r for r in results if r]
    if not exposed:
        ok("No sensitive files found exposed.")
    findings["sensitive_files"] = exposed


# ══════════════════════════════════════════════════
#  CHECK 4 – Cookie Security  (OWASP A02 / A07)
# ══════════════════════════════════════════════════
def check_cookies(response: requests.Response, findings: dict):
    section("CHECK 4 │ Cookie Security  (OWASP A02 / A07)")

    # BUG FIX: Also parse raw Set-Cookie headers — requests.cookies
    # misses attributes like HttpOnly on some responses.
    raw_set_cookies = response.headers.getlist("Set-Cookie") if hasattr(
        response.headers, "getlist"
    ) else response.raw.headers.getlist("Set-Cookie")

    # Build a dict of cookie_name → raw Set-Cookie header string
    raw_cookie_map: dict[str, str] = {}
    for raw in raw_set_cookies:
        name = raw.split("=")[0].strip()
        raw_cookie_map[name] = raw.lower()

    cookies = response.cookies
    if not cookies and not raw_cookie_map:
        info("No cookies set in the response.")
        findings["cookies"] = []
        return

    # Merge: use raw map when available, fall back to parsed cookies
    seen = set()
    issues = []

    for cookie in cookies:
        seen.add(cookie.name)
        raw = raw_cookie_map.get(cookie.name, "")
        flags = []

        secure = cookie.secure or "secure" in raw
        if not secure:
            flags.append("missing Secure flag")

        httponly = cookie.has_nonstandard_attr("HttpOnly") or "httponly" in raw
        if not httponly:
            flags.append("missing HttpOnly flag")

        samesite_match = re.search(r"samesite\s*=\s*(\w+)", raw)
        samesite = samesite_match.group(1).lower() if samesite_match else ""
        if samesite not in ("strict", "lax"):
            flags.append(f"SameSite={samesite or 'not set'}")

        if flags:
            vuln(f"Cookie '{cookie.name}': {', '.join(flags)}")
            issues.append({"name": cookie.name, "flags": flags})
        else:
            ok(f"Cookie '{cookie.name}': Secure ✔ HttpOnly ✔ SameSite ✔")

    # Check any cookies only visible in raw headers (not in parsed jar)
    for name, raw in raw_cookie_map.items():
        if name in seen:
            continue
        flags = []
        if "secure" not in raw:
            flags.append("missing Secure flag")
        if "httponly" not in raw:
            flags.append("missing HttpOnly flag")
        samesite_match = re.search(r"samesite\s*=\s*(\w+)", raw)
        samesite = samesite_match.group(1).lower() if samesite_match else ""
        if samesite not in ("strict", "lax"):
            flags.append(f"SameSite={samesite or 'not set'}")
        if flags:
            vuln(f"Cookie '{name}': {', '.join(flags)}")
            issues.append({"name": name, "flags": flags})
        else:
            ok(f"Cookie '{name}': Secure ✔ HttpOnly ✔ SameSite ✔")

    findings["cookies"] = issues


# ══════════════════════════════════════════════════
#  CHECK 5 – Forms & CSRF  (OWASP A01)
# ══════════════════════════════════════════════════
def check_forms(soup: BeautifulSoup, url: str, findings: dict):
    section("CHECK 5 │ Forms & CSRF Tokens  (OWASP A01)")

    forms = soup.find_all("form")
    if not forms:
        info("No HTML forms found on this page.")
        findings["csrf"] = []
        return

    info(f"Found {len(forms)} form(s).")
    csrf_keywords = [
        "csrf", "token", "_token", "authenticity_token",
        "nonce", "xsrf", "__requestverificationtoken",
    ]
    issues = []

    # BUG FIX: Also check <meta> CSRF tags (used by Rails, Django, Angular)
    meta_csrf = soup.find(
        "meta",
        attrs={"name": re.compile(r"csrf|xsrf", re.IGNORECASE)}
    )
    has_global_meta_csrf = meta_csrf is not None

    for i, form in enumerate(forms, 1):
        action = form.get("action", "(none)")
        method = form.get("method", "GET").upper()

        # Check hidden inputs and all inputs for CSRF token names
        inp_names = [
            inp.get("name", "").lower()
            for inp in form.find_all("input")
        ]
        # Also check data attributes on the form element itself
        form_attrs = " ".join(str(v).lower() for v in form.attrs.values())

        has_csrf = (
            any(any(kw in name for kw in csrf_keywords) for name in inp_names)
            or any(kw in form_attrs for kw in csrf_keywords)
            or has_global_meta_csrf
        )

        if method == "POST" and not has_csrf:
            vuln(f"Form {i} (action='{action}'): POST without CSRF token!")
            issues.append({"form": i, "action": action})
        elif method == "POST":
            ok(f"Form {i} (action='{action}'): CSRF token present ✔")
        else:
            info(f"Form {i} (action='{action}'): {method} — CSRF less critical")

    findings["csrf"] = issues


# ══════════════════════════════════════════════════
#  CHECK 6 – Server / Tech Disclosure  (OWASP A05)
# ══════════════════════════════════════════════════
def check_server_disclosure(response: requests.Response, findings: dict):
    section("CHECK 6 │ Server / Tech Disclosure  (OWASP A05)")

    disclosure_headers = [
        "Server", "X-Powered-By", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Generator", "X-Runtime",
        "X-Framework", "Via", "X-Backend-Server",
    ]

    exposed = []
    for h in disclosure_headers:
        val = response.headers.get(h)
        if val:
            # Flag only if it reveals specific version info (not just product name)
            version_revealed = bool(re.search(r"\d+\.\d+", val))
            if version_revealed:
                vuln(f"'{h}' reveals version: {val}")
            else:
                warn(f"'{h}' discloses: {val}")
            exposed.append(f"{h}: {val}")
        else:
            ok(f"'{h}' not exposed.")

    findings["server_disclosure"] = exposed


# ══════════════════════════════════════════════════
#  CHECK 7 – XSS Indicators  (OWASP A03)
# ══════════════════════════════════════════════════
def check_xss_indicators(soup: BeautifulSoup, findings: dict):
    section("CHECK 7 │ XSS Indicators in HTML  (OWASP A03 – Injection)")

    html = str(soup)
    found = []

    # 1. javascript: URIs in href/src/action (genuine XSS risk)
    js_uri_count = len(re.findall(
        r'(?:href|src|action)\s*=\s*["\']?\s*javascript\s*:',
        html, re.IGNORECASE
    ))
    if js_uri_count:
        warn(f"javascript: URI in href/src/action: {js_uri_count} instance(s)")
        found.append({"pattern": "javascript: URI in href/src/action", "count": js_uri_count})

    # 2. External cross-origin <script> tags (potential supply-chain XSS)
    scripts = soup.find_all("script", src=True)
    from urllib.parse import urlparse as _up
    base_host = _up(soup.find("base", href=True)["href"]).netloc if soup.find(
        "base", href=True
    ) else None
    external_scripts = [
        s["src"] for s in scripts
        if s["src"].startswith(("http://", "//"))
        and not s["src"].startswith("https://")
    ]
    if external_scripts:
        warn(f"HTTP (non-HTTPS) external <script> tags: {len(external_scripts)}")
        found.append({
            "pattern": "HTTP external <script> (MitM risk)",
            "count": len(external_scripts)
        })

    # 3. document.write() — dangerous sink
    dw_count = len(re.findall(r"document\.write\s*\(", html, re.IGNORECASE))
    if dw_count:
        warn(f"document.write() call: {dw_count} instance(s)")
        found.append({"pattern": "document.write() call", "count": dw_count})

    # 4. eval() — dangerous sink (only flag non-whitespace content)
    eval_matches = re.findall(
        r"eval\s*\(\s*(?![\s\)])([^\n]{1,100})", html, re.IGNORECASE
    )
    if eval_matches:
        warn(f"eval() call: {len(eval_matches)} instance(s)")
        found.append({"pattern": "eval() call", "count": len(eval_matches)})

    # 5. innerHTML assignment
    inner_count = len(re.findall(r"\.innerHTML\s*=\s*[^=]", html, re.IGNORECASE))
    if inner_count:
        warn(f"innerHTML assignment: {inner_count} instance(s)")
        found.append({"pattern": "innerHTML assignment", "count": inner_count})

    if not found:
        ok("No obvious XSS patterns detected.")

    info("Note: Dynamic XSS testing (input fuzzing) is out of scope for a passive scan.")
    findings["xss_indicators"] = found


# ══════════════════════════════════════════════════
#  CHECK 8 – SQL Injection Probing  (OWASP A03)
# ══════════════════════════════════════════════════
def check_sqli(url: str, soup: BeautifulSoup, findings: dict):
    section("CHECK 8 │ SQL Injection Probe  (OWASP A03 – Injection)")

    parsed = urlparse(url)
    # BUG FIX: Use copy() to avoid mutating the original parse_qs result
    params = dict(parse_qs(parsed.query, keep_blank_values=True))

    # Collect GET params from anchor links on the page (limited to 20 links)
    for a in list(soup.find_all("a", href=True))[:20]:
        href = a["href"]
        if "?" in href:
            link_parsed = urlparse(href)
            for k, v in parse_qs(link_parsed.query).items():
                if k not in params:
                    params[k] = v

    if not params:
        info("No URL parameters found to probe for SQLi.")
        findings["sqli"] = []
        return

    info(f"Found {len(params)} URL parameter(s) to probe: {list(params.keys())}")

    # Error-based SQLi payloads
    payloads = [
        "'", "''", "`", "' OR '1'='1", "' OR 1=1--", '" OR "1"="1',
        "1' AND SLEEP(0)--", "1; SELECT 1--",
    ]

    # Common DB error signatures (lowercase)
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query()", "pg_exec()",
        "sqlite3.operationalerror",
        "odbc_exec", "odbc sql",
        "sqlstate[",
        "ora-0", "ora-1",
        "microsoft ole db",
        "jdbc.sqlexception",
        "syntax error in query",
        "division by zero",
        "invalid query",
        "sql syntax",
    ]

    # BUG FIX: Track vulnerable params to avoid duplicates
    vulnerable_params = []
    found_params = set()

    for param_name in list(params.keys())[:5]:  # cap at 5 params for speed
        if param_name in found_params:
            continue
        for payload in payloads:
            # Build test URL with injected payload
            test_params = {k: v[0] if isinstance(v, list) else v
                           for k, v in params.items()}
            test_params[param_name] = payload

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params), ""
            ))

            r = quick_get(test_url, timeout=6)
            if r is None:
                continue

            body = r.text.lower()
            triggered = next(
                (sig for sig in error_signatures if sig in body), None
            )
            if triggered:
                vuln(
                    f"Parameter '{param_name}' with payload '{payload}' "
                    f"triggered: '{triggered}'"
                )
                vulnerable_params.append({
                    "param": param_name,
                    "payload": payload,
                    "signature": triggered,
                    "test_url": test_url,
                })
                found_params.add(param_name)
                break  # BUG FIX: break out of payload loop only, move to next param

    if not vulnerable_params:
        ok("No SQL error signatures triggered by basic probes.")
        info("Note: Absence of errors does not rule out blind/time-based SQLi.")

    findings["sqli"] = vulnerable_params


# ══════════════════════════════════════════════════
#  CHECK 9 – Open Redirect  (OWASP A01)
# ══════════════════════════════════════════════════
def check_open_redirect(url: str, soup: BeautifulSoup, findings: dict):
    section("CHECK 9 │ Open Redirect Detection  (OWASP A01)")

    evil_domain = "evil-attacker.example.com"
    # BUG FIX: URL-encode the evil domain value so it's a valid query value
    evil_value = quote_plus(f"https://{evil_domain}/pwned")

    redirect_param_names = {
        "url", "redirect", "next", "return", "returnurl", "return_url",
        "redirect_to", "redirect_url", "goto", "target", "dest", "destination",
        "forward", "location", "continue", "link", "out", "ref",
    }

    parsed = urlparse(url)

    # Collect redirect-like params from the URL query string
    url_params = set(parse_qs(parsed.query).keys())

    # Also collect from anchor links on the page (limited)
    page_link_params = set()
    for a in list(soup.find_all("a", href=True))[:30]:
        href = a["href"]
        if "?" in href:
            link_parsed = urlparse(href)
            page_link_params.update(parse_qs(link_parsed.query).keys())

    # Only probe params that match known redirect param names
    all_params = url_params | page_link_params
    page_params = list(all_params & redirect_param_names)

    if not page_params:
        info("No redirect-like query parameters found; skipping open redirect probes.")
        findings["open_redirect"] = []
        return

    info(f"Testing {len(page_params)} redirect-like parameter(s) for open redirect…")

    def _probe_redirect(param: str):
        # BUG FIX: properly URL-encode the value
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, f"{param}={evil_value}", ""
        ))
        try:
            r = get_session().get(test_url, timeout=5, allow_redirects=False)
            location = r.headers.get("Location", "")
            if not location:
                return None
            loc_parsed = urlparse(location)
            # Check if the server is redirecting to our evil domain
            if (r.status_code in (301, 302, 303, 307, 308)
                    and loc_parsed.netloc == evil_domain):
                vuln(f"Open Redirect via '?{param}=' → redirects to {location}")
                return {"param": param, "test_url": test_url}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(_probe_redirect, page_params))

    vulnerable = [r for r in results if r]

    if not vulnerable:
        ok("No open redirect vulnerabilities detected.")

    findings["open_redirect"] = vulnerable


# ══════════════════════════════════════════════════
#  CHECK 10 – Directory Listing  (OWASP A05)
# ══════════════════════════════════════════════════
def check_directory_listing(url: str, findings: dict):
    section("CHECK 10 │ Directory Listing  (OWASP A05)")

    common_dirs = [
        "images/", "img/", "assets/", "static/", "files/", "uploads/",
        "media/", "docs/", "css/", "js/", "scripts/", "backup/",
        "tmp/", "temp/", "logs/", "data/", "private/", "internal/",
    ]

    # Strong indicators of directory listing (Apache/Nginx/IIS style)
    listing_signatures = [
        "index of /",
        "parent directory",
        "directory listing for",
        "<title>index of",
        "[to parent directory]",       # IIS
        "last modified</a>",
    ]

    base = url.rstrip("/") + "/"
    info(f"Testing {len(common_dirs)} common directories…")

    def _probe_dir(d: str):
        full = urljoin(base, d)
        r = quick_get(full, timeout=5)
        if r is None:
            return None
        if r.status_code == 200:
            body = r.text[:8192].lower()
            if any(sig in body for sig in listing_signatures):
                vuln(f"Directory listing ENABLED at: {full}")
                return full
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_probe_dir, common_dirs))

    exposed = [r for r in results if r]

    if not exposed:
        ok("No directory listing found.")

    findings["directory_listing"] = exposed


# ══════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════
def save_json_report(url: str, findings: dict, filename: str) -> str:
    """Save findings as a JSON file."""
    report = {
        "scanner": "Web Vulnerability Scanner v2.1",
        "target": url,
        "timestamp": datetime.datetime.now().isoformat(),
        "total_issues": count_issues(findings),
        "findings": findings,
    }
    path = f"{filename}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  {Color.GREEN}[✔] JSON report saved: {path}{Color.RESET}")
    return path


def save_html_report(url: str, findings: dict, filename: str) -> str:
    """Generate a styled HTML report."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total = count_issues(findings)
    risk_color = "#e74c3c" if total > 5 else "#f39c12" if total > 2 else "#2ecc71"
    risk_label = "HIGH RISK" if total > 5 else "MEDIUM RISK" if total > 2 else "LOW RISK"

    def render_list(items, key=None):
        if not items:
            return '<p class="ok">✔ None found</p>'
        html = "<ul>"
        for item in items:
            text = item[key] if key and isinstance(item, dict) and key in item else str(item)
            # Escape HTML special chars
            text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            html += f"<li>⚠ {text}</li>"
        html += "</ul>"
        return html

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Scan Report – {url}</title>
  <style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: #0f0f1a;
      color: #e0e0f0;
      padding: 2rem;
    }}
    h1 {{
      font-size: 2rem;
      color: #7ecfff;
      margin-bottom: 0.25rem;
    }}
    .subtitle {{ color: #888; margin-bottom: 2rem; font-size: 0.9rem; }}
    .meta {{
      background: #1a1a2e;
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 2rem;
      border: 1px solid #2a2a50;
    }}
    .meta p {{ margin: 0.4rem 0; }}
    .meta strong {{ color: #7ecfff; }}
    .badge {{
      display: inline-block;
      padding: 0.4rem 1.2rem;
      border-radius: 999px;
      font-weight: bold;
      font-size: 0.85rem;
      background: {risk_color}22;
      color: {risk_color};
      border: 1px solid {risk_color};
      margin-top: 0.5rem;
    }}
    .grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(420px, 1fr));
      gap: 1.5rem;
    }}
    .card {{
      background: #1a1a2e;
      border-radius: 12px;
      padding: 1.5rem;
      border: 1px solid #2a2a50;
      transition: border-color 0.2s;
    }}
    .card:hover {{ border-color: #7ecfff55; }}
    .card h2 {{
      font-size: 1rem;
      color: #aad4ff;
      margin-bottom: 1rem;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}
    .card ul {{ list-style: none; padding-left: 0; }}
    .card li {{
      padding: 0.4rem 0.6rem;
      margin: 0.3rem 0;
      background: #e74c3c1a;
      color: #f19696;
      border-radius: 6px;
      font-size: 0.88rem;
      border-left: 3px solid #e74c3c;
      word-break: break-all;
    }}
    .ok {{
      color: #2ecc71;
      font-size: 0.9rem;
      padding: 0.4rem 0;
    }}
    .footer {{
      text-align: center;
      margin-top: 3rem;
      color: #444;
      font-size: 0.85rem;
    }}
    a {{ color: #7ecfff; }}
  </style>
</head>
<body>
  <h1>🔍 Web Vulnerability Report</h1>
  <p class="subtitle">Generated by Web Vulnerability Scanner v2.1</p>

  <div class="meta">
    <p><strong>Target:</strong> <a href="{url}" target="_blank">{url}</a></p>
    <p><strong>Scanned At:</strong> {timestamp}</p>
    <p><strong>Total Issues Found:</strong> {total}</p>
    <div class="badge">{risk_label} — {total} issue(s)</div>
  </div>

  <div class="grid">

    <div class="card">
      <h2>🛡️ Missing Security Headers (OWASP A05)</h2>
      {render_list(findings.get("security_headers", []), key="header")}
    </div>

    <div class="card">
      <h2>🔐 HTTPS / TLS Issues (OWASP A02)</h2>
      {render_list(findings.get("https", []))}
    </div>

    <div class="card">
      <h2>📂 Sensitive Files Exposed (OWASP A01/A05)</h2>
      {render_list(findings.get("sensitive_files", []))}
    </div>

    <div class="card">
      <h2>🍪 Insecure Cookies (OWASP A02/A07)</h2>
      {render_list(findings.get("cookies", []), key="name")}
    </div>

    <div class="card">
      <h2>🔒 CSRF Missing on Forms (OWASP A01)</h2>
      {render_list(findings.get("csrf", []), key="action")}
    </div>

    <div class="card">
      <h2>💉 SQL Injection (OWASP A03)</h2>
      {render_list(findings.get("sqli", []), key="param")}
    </div>

    <div class="card">
      <h2>↗️ Open Redirect (OWASP A01)</h2>
      {render_list(findings.get("open_redirect", []), key="param")}
    </div>

    <div class="card">
      <h2>📁 Directory Listing (OWASP A05)</h2>
      {render_list(findings.get("directory_listing", []))}
    </div>

    <div class="card">
      <h2>🔎 Server Disclosure (OWASP A05)</h2>
      {render_list(findings.get("server_disclosure", []))}
    </div>

    <div class="card">
      <h2>⚡ XSS Indicators (OWASP A03)</h2>
      {render_list(findings.get("xss_indicators", []), key="pattern")}
    </div>

  </div>

  <div class="footer">
    <p>🔗 Learn more: <a href="https://owasp.org/www-project-top-ten/" target="_blank">OWASP Top 10</a></p>
    <p style="margin-top:0.5rem">⚠ This tool is for educational purposes only. Only scan websites you own or have permission to test.</p>
  </div>
</body>
</html>"""

    path = f"{filename}.html"
    with open(path, "w") as f:
        f.write(html)
    print(f"  {Color.GREEN}[✔] HTML report saved: {path}{Color.RESET}")
    return path


# ══════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════
def print_summary(url: str, findings: dict):
    section("SCAN SUMMARY")

    category_totals = {
        "Missing Security Headers":  len(findings.get("security_headers", [])),
        "HTTPS Issues":              len(findings.get("https", [])),
        "Exposed Sensitive Files":   len(findings.get("sensitive_files", [])),
        "Insecure Cookies":          len(findings.get("cookies", [])),
        "CSRF Vulnerabilities":      len(findings.get("csrf", [])),
        "Server Disclosure":         len(findings.get("server_disclosure", [])),
        "XSS Indicators":            len(findings.get("xss_indicators", [])),
        "SQL Injection":             len(findings.get("sqli", [])),
        "Open Redirects":            len(findings.get("open_redirect", [])),
        "Directory Listings":        len(findings.get("directory_listing", [])),
    }

    total = count_issues(findings)
    info(f"Target: {url}")
    print()

    for label, cnt in category_totals.items():
        if cnt > 0:
            print(f"  {Color.RED}  {label}: {cnt}{Color.RESET}")
        else:
            print(f"  {Color.GREEN}  {label}: {cnt}{Color.RESET}")

    print()
    if total == 0:
        print(f"  {Color.GREEN}{Color.BOLD}✔ No issues found — great security posture!{Color.RESET}")
    elif total <= 3:
        print(f"  {Color.YELLOW}{Color.BOLD}⚠ {total} issue(s) found. Review the warnings above.{Color.RESET}")
    else:
        print(f"  {Color.RED}{Color.BOLD}✘ {total} issue(s) found. Significant improvements needed.{Color.RESET}")

    print(f"\n  {Color.BLUE}Reference: https://owasp.org/www-project-top-ten/{Color.RESET}\n")


# ══════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════
def main():
    banner()

    parser = argparse.ArgumentParser(
        description="Web Vulnerability Scanner — Educational OWASP Top 10 checker"
    )
    parser.add_argument("url",       help="Target URL (e.g. https://example.com)")
    parser.add_argument("--report",  action="store_true", help="Save HTML + JSON report")
    parser.add_argument("--output",  default="report",    help="Output filename (no extension). Default: report")
    args = parser.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"{Color.BOLD}Target:{Color.RESET}  {url}")
    if args.report:
        print(f"{Color.BOLD}Report:{Color.RESET}  {args.output}.html / {args.output}.json")

    # BUG FIX: Initialize a fresh session before CLI scan too
    new_scan_session()

    # Fetch main page
    response, soup = fetch(url)
    if response is None:
        print(f"\n{Color.RED}Scan aborted — could not connect.{Color.RESET}")
        sys.exit(1)

    info(f"HTTP Status : {response.status_code}")
    info(f"Final URL   : {response.url}")

    findings = {}

    # Run all 10 checks
    check_security_headers(response, findings)
    check_https(url, findings)
    check_sensitive_files(url, findings)
    check_cookies(response, findings)
    check_forms(soup, url, findings)
    check_server_disclosure(response, findings)
    check_xss_indicators(soup, findings)
    check_sqli(url, soup, findings)
    check_open_redirect(url, soup, findings)
    check_directory_listing(url, findings)

    # Summary
    print_summary(url, findings)

    # Reports
    if args.report:
        section("SAVING REPORTS")
        save_json_report(url, findings, args.output)
        save_html_report(url, findings, args.output)
        print()


if __name__ == "__main__":
    main()
