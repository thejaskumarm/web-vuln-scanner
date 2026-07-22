#!/usr/bin/env python3
"""
Web Vulnerability Scanner — Flask Web Application
===================================================
Serves a browser UI where users enter a URL and see
scan results streamed in real-time via Server-Sent Events.

Run:
    source venv/bin/activate
    python app.py
Then open: http://localhost:5000
"""

import json
import time
import ipaddress
from flask import Flask, render_template, request, Response, jsonify
from flask_cors import CORS

# Import all scanner checks and helpers from scanner.py
from scanner import (
    fetch,
    check_security_headers,
    check_https,
    check_sensitive_files,
    check_cookies,
    check_forms,
    check_server_disclosure,
    check_xss_indicators,
    check_sqli,
    check_open_redirect,
    check_directory_listing,
    count_issues,
    save_html_report,
)

app = Flask(__name__)
CORS(app)

# ──────────────────────────────────────────────────────
#  Routes
# ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan")
def scan():
    """
    SSE endpoint — streams JSON progress events as each check completes.
    Client connects with: new EventSource('/scan?url=https://...')
    """
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    # — SSRF protection: block private/loopback addresses ——————————————
    try:
        from urllib.parse import urlparse as _up
        hostname = (_up(url).hostname or "").lower()
        blocked_names = {"localhost", "localhost.localdomain", "0.0.0.0", "[::1]"}
        if hostname in blocked_names:
            return jsonify({"error": "Scanning localhost/internal addresses is not allowed."}), 403
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
                return jsonify({"error": "Scanning private or internal IP addresses is not allowed."}), 403
        except ValueError:
            pass  # hostname is a domain name, not an IP — allow it
    except Exception:
        pass  # parsing edge-case: let the scan attempt proceed

    def generate():
        findings = {}
        scan_start = time.time()

        def emit(event_type, data):
            """Format and yield an SSE message."""
            payload = json.dumps({"type": event_type, "data": data})
            yield f"data: {payload}\n\n"

        # ── Start ──────────────────────────────────────────
        yield from emit("start", {"url": url, "total_checks": 10})

        # ── Fetch page ─────────────────────────────────────
        yield from emit("progress", {"check": 0, "label": "Connecting to target…"})
        response, soup = fetch(url)
        if response is None:
            yield from emit("error", {"message": f"Cannot connect to {url}"})
            return

        yield from emit("connected", {
            "status": response.status_code,
            "final_url": response.url,
        })

        # ── Check 1: Security Headers ──────────────────────
        yield from emit("progress", {"check": 1, "label": "Checking Security Headers…"})
        check_security_headers(response, findings)
        yield from emit("result", {
            "check": 1,
            "title": "Security Headers",
            "owasp": "A05",
            "issues": [
                f"Missing '{h['header']}' — {h['risk']}"
                for h in findings.get("security_headers", [])
            ],
        })

        # ── Check 2: HTTPS ─────────────────────────────────
        yield from emit("progress", {"check": 2, "label": "Checking HTTPS / TLS…"})
        check_https(url, findings)
        yield from emit("result", {
            "check": 2,
            "title": "HTTPS / TLS",
            "owasp": "A02",
            "issues": findings.get("https", []),
        })

        # ── Check 3: Sensitive Files ───────────────────────
        yield from emit("progress", {"check": 3, "label": "Probing sensitive files…"})
        check_sensitive_files(url, findings)
        yield from emit("result", {
            "check": 3,
            "title": "Sensitive File Exposure",
            "owasp": "A01/A05",
            "issues": findings.get("sensitive_files", []),
        })

        # ── Check 4: Cookies ───────────────────────────────
        yield from emit("progress", {"check": 4, "label": "Inspecting cookies…"})
        check_cookies(response, findings)
        issues = [
            f"Cookie '{c['name']}': " + ", ".join(c["flags"])
            for c in findings.get("cookies", [])
        ]
        yield from emit("result", {
            "check": 4,
            "title": "Cookie Security",
            "owasp": "A02/A07",
            "issues": issues,
        })

        # ── Check 5: CSRF ──────────────────────────────────
        yield from emit("progress", {"check": 5, "label": "Checking forms for CSRF…"})
        check_forms(soup, url, findings)
        issues = [
            f"Form action='{c['action']}' — POST without CSRF token!"
            for c in findings.get("csrf", [])
        ]
        yield from emit("result", {
            "check": 5,
            "title": "CSRF Protection",
            "owasp": "A01",
            "issues": issues,
        })

        # ── Check 6: Server Disclosure ─────────────────────
        yield from emit("progress", {"check": 6, "label": "Checking server disclosure…"})
        check_server_disclosure(response, findings)
        # server_disclosure is now a flat list of "Header: value" strings
        yield from emit("result", {
            "check": 6,
            "title": "Server / Tech Disclosure",
            "owasp": "A05",
            "issues": findings.get("server_disclosure", []),
        })

        # ── Check 7: XSS ───────────────────────────────────
        yield from emit("progress", {"check": 7, "label": "Scanning for XSS indicators…"})
        check_xss_indicators(soup, findings)
        issues = [f"{x['pattern']}: {x['count']} instance(s)"
                  for x in findings.get("xss_indicators", [])]
        yield from emit("result", {
            "check": 7,
            "title": "XSS Indicators",
            "owasp": "A03",
            "issues": issues,
        })

        # ── Check 8: SQLi ──────────────────────────────────
        yield from emit("progress", {"check": 8, "label": "Probing for SQL Injection…"})
        check_sqli(url, soup, findings)
        issues = [f"Param '{s['param']}' triggered: {s['signature']}"
                  for s in findings.get("sqli", [])]
        yield from emit("result", {
            "check": 8,
            "title": "SQL Injection",
            "owasp": "A03",
            "issues": issues,
        })

        # ── Check 9: Open Redirect ─────────────────────────
        yield from emit("progress", {"check": 9, "label": "Testing for open redirects…"})
        check_open_redirect(url, soup, findings)
        issues = [f"Param '?{r['param']}=' allows open redirect"
                  for r in findings.get("open_redirect", [])]
        yield from emit("result", {
            "check": 9,
            "title": "Open Redirect",
            "owasp": "A01",
            "issues": issues,
        })

        # ── Check 10: Directory Listing ────────────────────
        yield from emit("progress", {"check": 10, "label": "Checking directory listing…"})
        check_directory_listing(url, findings)
        yield from emit("result", {
            "check": 10,
            "title": "Directory Listing",
            "owasp": "A05",
            "issues": findings.get("directory_listing", []),
        })

        # ── Done ──────────────────────────────────────────────────
        elapsed = round(time.time() - scan_start, 1)
        yield from emit("done", {
            "total_issues": count_issues(findings),
            "elapsed": elapsed,
        })

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


if __name__ == "__main__":
    print("\n  🔍 Web Vulnerability Scanner — Web App")
    print("  Open in browser: http://localhost:8080\n")
    app.run(debug=True, threaded=True, host="0.0.0.0", port=8080)
