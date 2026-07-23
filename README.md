# 🔍 Web Vulnerability Scanner (OWASP Top 10)

An interactive, web-based vulnerability scanner and security assessment tool powered by Python (Flask) and a modern dark-mode interface. It performs automated, parallelized checks based on the OWASP Top 10 web application risks.

---

## 📌 Summary

Web Vulnerability Scanner provides website owners and security enthusiasts with real-time feedback on potential web application misconfigurations.

### Core Features:
- 🛡️ **Security Headers Analysis** (X-Frame-Options, CSP, HSTS, Referrer-Policy, etc.)
- 🔐 **HTTPS / TLS Configuration Verification**
- 📂 **Sensitive File Exposure Detection** (soft-404 filtering for `.env`, `.git`, backups)
- 🍪 **Cookie Flag Inspection** (`Secure`, `HttpOnly`, `SameSite`)
- 🔒 **CSRF Token Verification on Forms**
- 🔎 **Server & Technology Information Leak Checks**
- ⚡ **Inline XSS & Unsafe Script Pattern Detection**
- 💉 **SQL Injection Error Probing**
- ↗️ **Open Redirect Vulnerability Checks**
- 📁 **Directory Listing Probing**
- ⏱️ **Real-Time SSE Streaming**: Live progress tracking and dynamic report generation.
- ⬇️ **Export & Copy Capabilities**: One-click HTML report download and finding clipboard copy.

---

## 📸 Interface Preview

![Web Vulnerability Scanner Interface](https://raw.githubusercontent.com/bhuvangm/web-vuln-scanner/main/static/preview.png)

---

## 🚀 Step-by-Step Usage & Process Guide

### Step 1: Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/thejaskumarm/web-vuln-scanner.git
   cd web-vuln-scanner
   ```

2. **Set up a virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

### Step 2: Running the Application

- **Web Application Mode (Flask UI):**
  ```bash
  python app.py
  ```
  Open your browser at `http://localhost:8080`.

- **Command-Line Interface (CLI Mode):**
  ```bash
  python scanner.py https://example.com --report --output scan_results
  ```

---

### Step 3: Performing a Scan

1. Open `http://localhost:8080` in your web browser.
2. Enter the target URL (e.g., `https://example.com`) in the scan bar.
3. Click **Scan Now**.
4. Monitor the live SSE progress panel as checks complete in parallel.
5. Review the categorized findings cards.
6. Click **⬇ Report** to download the offline HTML report or click 📋 next to any finding to copy it.

---

## 🛠️ Technology Stack

- **Backend:** Python 3, Flask, Requests, BeautifulSoup4, Concurrent Futures (ThreadPoolExecutor)
- **Frontend:** Vanilla HTML5, Vanilla CSS3 (Glassmorphism design system), JavaScript (Server-Sent Events)
- **Deployment:** Vercel / Docker / Gunicorn

---

## ⚠️ Disclaimer

This tool is created strictly for **educational and defensive security purposes**. Only scan websites you own or have explicit authorization to test.
