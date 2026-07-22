#!/usr/bin/env python3
"""
Web Vulnerability Scanner v2.0
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

Author: Web Vuln Scanner Project
"""

import sys
import json
import argparse
import datetime
import logging
import threading
import concurrent.futures
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse
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
║         🔍  Web Vulnerability Scanner v2.0          ║
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
#  Thread-local session (one per scan thread)
# ─────────────────────────────────────────────
_tls = threading.local()
_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)


def get_session():
    """Return a thread-local requests.Session.
    Each Flask worker / scan thread gets its own session,
    preventing cookie bleed between concurrent users."""
    if not hasattr(_tls, "session"):
        _tls.session = requests.Session()
        _tls.session.headers.update({"User-Agent": _UA})
    return _tls.session


def fetch(url, timeout=10, verify=True):
    """Fetch a URL. Returns (response, soup) or (None, None)."""
    try:
        resp = get_session().get(url, timeout=timeout, allow_redirects=True, verify=verify)
        soup = BeautifulSoup(resp.text, "html.parser")
        return resp, soup
    except requests.exceptions.SSLError:
        warn("SSL error — retrying without cert verification.")
        return fetch(url, timeout=timeout, verify=False)
    except requests.exceptions.ConnectionError:
        logger.error("Cannot connect to %s", url)
        return None, None
    except requests.exceptions.Timeout:
        logger.error("Request timed out: %s", url)
        return None, None
    except Exception as e:
        logger.error("Fetch error: %s", e)
        return None, None


def quick_get(url, timeout=4):
    """Quick GET for probing paths. Tight timeout for parallel workers."""
    try:
        return get_session().get(url, timeout=timeout, allow_redirects=False)
    except Exception:
        return None


def count_issues(findings):
    """Return the total number of issues across all 10 check categories.
    Single source of truth used by both app.py and save_html_report()."""
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
def check_security_headers(response, findings):
    section("CHECK 1 │ Security Headers  (OWASP A05)")

    headers = response.headers
    checks = [
        ("X-Frame-Options",         "Prevents Clickjacking",            "Clickjacking risk — site can be embedded in iframes"),
        ("X-Content-Type-Options",  "Prevents MIME-type sniffing",      "Browser may execute files with wrong MIME type"),
        ("Strict-Transport-Security","Forces HTTPS (HSTS)",             "Users may connect over insecure HTTP"),
        ("Content-Security-Policy", "Mitigates XSS / injection",        "No CSP → higher XSS and injection risk"),
        ("Referrer-Policy",         "Controls referrer leakage",        "Sensitive URLs may leak to third parties"),
        ("Permissions-Policy",      "Restricts browser feature access", "Camera/mic/geolocation may be abused"),
    ]

    missing = []
    for header_name, desc, risk in checks:
        value = headers.get(header_name)
        if value:
            ok(f"{header_name}: {value}")
        else:
            vuln(f"Missing '{header_name}' — {risk}")
            missing.append({"header": header_name, "risk": risk})

    findings["security_headers"] = missing
    return missing


# ══════════════════════════════════════════════════
#  CHECK 2 – HTTPS / TLS  (OWASP A02)
# ══════════════════════════════════════════════════
def check_https(url, findings):
    section("CHECK 2 │ HTTPS / TLS  (OWASP A02 – Cryptographic Failures)")

    issues = []
    parsed = urlparse(url)

    if parsed.scheme == "https":
        ok("Site is served over HTTPS.")
    else:
        vuln("Site uses plain HTTP — data is in clear text!")
        issues.append("No HTTPS")

    http_url = "http://" + parsed.netloc + parsed.path
    r = quick_get(http_url)
    if r:
        if r.url.startswith("https://"):
            ok("HTTP correctly redirects to HTTPS.")
        else:
            warn("HTTP version does NOT redirect to HTTPS automatically.")
            issues.append("No HTTP→HTTPS redirect")
    else:
        info("Could not check HTTP→HTTPS redirect.")

    findings["https"] = issues


# ══════════════════════════════════════════════════
#  CHECK 3 – Sensitive File Exposure  (OWASP A01/A05)
# ══════════════════════════════════════════════════
def check_sensitive_files(base_url, findings):
    section("CHECK 3 │ Sensitive File Exposure  (OWASP A01 / A05)")

    paths = [
        "robots.txt", ".git/HEAD", ".env", "config.php", "wp-config.php",
        "web.config", "phpinfo.php", "admin/", "backup.zip", "database.sql",
        ".DS_Store", "README.md", "CHANGELOG.md", ".htaccess",
        "server.key", "id_rsa", ".bash_history", "composer.json",
        "package.json", "yarn.lock", "Makefile", "Dockerfile",
    ]

    base = base_url.rstrip("/") + "/"

    def _probe(path):
        full = urljoin(base, path)
        r = quick_get(full)
        if r is None:
            info(f"Could not check: /{path}")
            return None
        if r.status_code == 200:
            # Check for Soft-404s (e.g. customized 404 pages returning HTTP 200)
            body_lower = r.text.lower()
            soft_404_indicators = ["404 not found", "page not found", "file not found", "<title>404", "does not exist"]
            if any(ind in body_lower for ind in soft_404_indicators):
                ok(f"Soft 404 ignored: /{path}")
                return None

            # Ignore robots.txt as vulnerability unless it reveals sensitive admin paths
            if path == "robots.txt":
                if any(p in body_lower for p in ["/admin", "/backup", "/config", "/private", "/secret"]):
                    vuln(f"Disclosing paths in robots.txt → {full}")
                    return full
                else:
                    ok(f"Standard public file: /{path}")
                    return None

            vuln(f"Accessible → {full}  [HTTP {r.status_code}]")
            return full
        elif r.status_code in (301, 302):
            warn(f"Redirect at /{path}  [HTTP {r.status_code}]")
        else:
            ok(f"Not exposed: /{path}  [HTTP {r.status_code}]")
        return None

    # Fire all path probes concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_probe, paths))

    exposed = [r for r in results if r]
    findings["sensitive_files"] = exposed


# ══════════════════════════════════════════════════
#  CHECK 4 – Cookie Security  (OWASP A02 / A07)
# ══════════════════════════════════════════════════
def check_cookies(response, findings):
    section("CHECK 4 │ Cookie Security  (OWASP A02 / A07)")

    cookies = response.cookies
    if not cookies:
        info("No cookies set in the response.")
        findings["cookies"] = []
        return

    issues = []
    for cookie in cookies:
        flags = []
        if not cookie.secure:
            flags.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            flags.append("missing HttpOnly flag")
        samesite = cookie.get_nonstandard_attr("SameSite", "").lower()
        if samesite not in ("strict", "lax"):
            flags.append(f"SameSite={samesite or 'not set'}")

        if flags:
            vuln(f"Cookie '{cookie.name}': {', '.join(flags)}")
            issues.append({"name": cookie.name, "flags": flags})
        else:
            ok(f"Cookie '{cookie.name}': Secure ✔ HttpOnly ✔ SameSite ✔")

    findings["cookies"] = issues


# ══════════════════════════════════════════════════
#  CHECK 5 – Forms & CSRF  (OWASP A01)
# ══════════════════════════════════════════════════
def check_forms(soup, url, findings):
    section("CHECK 5 │ Forms & CSRF Tokens  (OWASP A01)")

    forms = soup.find_all("form")
    if not forms:
        info("No HTML forms found on this page.")
        findings["csrf"] = []
        return

    info(f"Found {len(forms)} form(s).")
    csrf_keywords = ["csrf", "token", "_token", "authenticity_token", "nonce", "xsrf"]
    issues = []

    for i, form in enumerate(forms, 1):
        action = form.get("action", "(none)")
        method = form.get("method", "GET").upper()
        inp_names = [
            inp.get("name", "").lower()
            for inp in form.find_all("input")
        ]
        has_csrf = any(
            any(kw in name for kw in csrf_keywords)
            for name in inp_names
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
def check_server_disclosure(response, findings):
    section("CHECK 6 │ Server / Tech Disclosure  (OWASP A05)")

    disclosure_headers = [
        "Server", "X-Powered-By", "X-AspNet-Version",
        "X-AspNetMvc-Version", "X-Generator", "X-Runtime",
        "X-Framework", "Via",
    ]

    exposed = []  # list of "Header: value" strings (consistent with all other findings)
    for h in disclosure_headers:
        val = response.headers.get(h)
        if val:
            warn(f"'{h}' discloses: {val}")
            exposed.append(f"{h}: {val}")
        else:
            ok(f"'{h}' not exposed.")

    findings["server_disclosure"] = exposed


# ══════════════════════════════════════════════════
#  CHECK 7 – XSS Indicators  (OWASP A03)
# ══════════════════════════════════════════════════
def check_xss_indicators(soup, findings):
    section("CHECK 7 │ XSS Indicators in HTML  (OWASP A03 – Injection)")

    html = str(soup)
    patterns = [
        (r"javascript\s*:",             "javascript: URI"),
        (r"on\w+\s*=\s*[\"'][^\"']+[\"']", "Inline event handler (onclick/onerror…)"),
        (r"<script[^>]*src\s*=\s*[\"']https?://(?!.*\.example\.)[^\"']+[\"']",
         "External cross-origin <script> tag"),
        (r"document\.write\s*\(",       "document.write() call"),
        (r"eval\s*\(",                  "eval() call"),
        (r"innerHTML\s*=",              "innerHTML assignment"),
    ]

    found = []
    for pattern, label in patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        if matches:
            warn(f"{label}: {len(matches)} instance(s)")
            found.append({"pattern": label, "count": len(matches)})

    if not found:
        ok("No obvious inline XSS patterns detected.")

    info("Note: Dynamic XSS testing (input fuzzing) is out of scope for a passive scan.")
    findings["xss_indicators"] = found


# ══════════════════════════════════════════════════
#  CHECK 8 – SQL Injection Probing  (OWASP A03)
# ══════════════════════════════════════════════════
def check_sqli(url, soup, findings):
    section("CHECK 8 │ SQL Injection Probe  (OWASP A03 – Injection)")

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Also collect GET params from anchor links on the page
    for a in soup.find_all("a", href=True):
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
    payloads = ["'", "''", "`", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"]

    # Common DB error signatures
    error_signatures = [
        "you have an error in your sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "pg_query()",
        "sqlite3.operationalerror",
        "odbc_exec",
        "sqlstate",
        "ora-",
        "microsoft ole db",
        "jdbc.SQLException",
    ]

    vulnerable_params = []

    for param_name in params:
        for payload in payloads:
            # Build a test URL with the injected payload
            test_params = dict(params)        # copy all original params
            test_params[param_name] = payload  # overwrite the one param

            test_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, urlencode(test_params, doseq=True), ""
            ))

            r = quick_get(test_url, timeout=8)
            if r is None:
                continue

            body = r.text.lower()
            for sig in error_signatures:
                if sig in body:
                    vuln(f"Parameter '{param_name}' with payload '{payload}' "
                         f"triggered a DB error: '{sig}'")
                    vulnerable_params.append({
                        "param": param_name,
                        "payload": payload,
                        "signature": sig,
                        "test_url": test_url,
                    })
                    break  # no need to try more payloads for this param+payload

    if not vulnerable_params:
        ok("No SQL error signatures triggered by basic probes.")
        info("Note: Absence of errors does not guarantee SQLi safety (blind SQLi exists).")

    findings["sqli"] = vulnerable_params


# ══════════════════════════════════════════════════
#  CHECK 9 – Open Redirect  (OWASP A01)
# ══════════════════════════════════════════════════
def check_open_redirect(url, soup, findings):
    section("CHECK 9 │ Open Redirect Detection  (OWASP A01)")

    redirect_params = [
        "url", "redirect", "next", "return", "returnurl", "return_url",
        "redirect_to", "redirect_url", "goto", "target", "dest", "destination",
        "forward", "location", "continue", "link", "out",
    ]

    # Only test parameters present in the URL or query parameters discovered on the page
    if not page_params:
        info("No query parameters in target URL; skipping speculative open redirect probes.")
        findings["open_redirect"] = []
        return

    info(f"Testing {len(page_params)} parameter(s) for open redirect…")

    def _probe_redirect(param):
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, f"{param}={evil_domain}", ""
        ))
        try:
            r = get_session().get(test_url, timeout=4, allow_redirects=False)
            location = r.headers.get("Location", "")
            # Ensure it redirects specifically to the untrusted evil domain host
            loc_parsed = urlparse(location)
            if r.status_code in (301, 302, 303, 307, 308) and loc_parsed.netloc == "evil-attacker.example.com":
                vuln(f"Open Redirect via '?{param}=' → redirects to {location}")
                return {"param": param, "test_url": test_url}
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_probe_redirect, page_params))

    vulnerable = [r for r in results if r]

    if not vulnerable:
        ok("No open redirect vulnerabilities detected.")

    findings["open_redirect"] = vulnerable


# ══════════════════════════════════════════════════
#  CHECK 10 – Directory Listing  (OWASP A05)
# ══════════════════════════════════════════════════
def check_directory_listing(url, findings):
    section("CHECK 10 │ Directory Listing  (OWASP A05)")

    common_dirs = [
        "images/", "img/", "assets/", "static/", "files/", "uploads/",
        "media/", "docs/", "css/", "js/", "scripts/", "backup/",
        "tmp/", "temp/", "logs/", "data/",
    ]

    # Signatures that indicate directory listing is enabled
    listing_signatures = [
        "index of /", "parent directory", "last modified",
        "directory listing for", "<title>index of",
    ]

    base = url.rstrip("/") + "/"
    info(f"Testing {len(common_dirs)} common directories…")

    def _probe_dir(d):
        full = urljoin(base, d)
        r = quick_get(full)
        if r and r.status_code == 200:
            body = r.text.lower()
            if any(sig in body for sig in listing_signatures):
                vuln(f"Directory listing ENABLED at: {full}")
                return full
            ok(f"/{d} returns 200 but no listing detected.")
        elif r:
            ok(f"/{d}  [HTTP {r.status_code}]")
        else:
            info(f"Could not reach /{d}")
        return None

    # Fire all directory probes concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(_probe_dir, common_dirs))

    exposed = [r for r in results if r]

    if not exposed:
        ok("No directory listing found.")

    findings["directory_listing"] = exposed


# ══════════════════════════════════════════════════
#  REPORT GENERATION
# ══════════════════════════════════════════════════
def save_json_report(url, findings, filename):
    """Save findings as a JSON file."""
    report = {
        "scanner": "Web Vulnerability Scanner v2.0",
        "target": url,
        "timestamp": datetime.datetime.now().isoformat(),
        "findings": findings,
    }
    path = f"{filename}.json"
    with open(path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  {Color.GREEN}[✔] JSON report saved: {path}{Color.RESET}")
    return path


def save_html_report(url, findings, filename):
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
            text = item[key] if key and isinstance(item, dict) else str(item)
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
  <p class="subtitle">Generated by Web Vulnerability Scanner v2.0</p>

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
def print_summary(url, findings):
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

    total = count_issues(findings)  # authoritative count across all 10 categories
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
    parser.add_argument("url",    help="Target URL (e.g. https://example.com)")
    parser.add_argument("--report",  action="store_true", help="Save HTML + JSON report")
    parser.add_argument("--output",  default="report",    help="Output filename (no extension). Default: report")
    args = parser.parse_args()

    url = args.url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    print(f"{Color.BOLD}Target:{Color.RESET}  {url}")
    if args.report:
        print(f"{Color.BOLD}Report:{Color.RESET}  {args.output}.html / {args.output}.json")

    # Fetch main page
    response, soup = fetch(url)
    if response is None:
        print(f"\n{Color.RED}Scan aborted — could not connect.{Color.RESET}")
        sys.exit(1)

    info(f"HTTP Status : {response.status_code}")
    info(f"Final URL   : {response.url}")

    # Collect all findings in a shared dict
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
