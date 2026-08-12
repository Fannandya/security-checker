# Open Source Code Scanner (OSC)

- **Author:** mamay
- **Language:** Python 3 (3.8+)
- **License:** MIT
- **Version:** 2.4.0

OSC is a Python-based security tool for testing the security posture of websites and web applications. Every scan is a full scan by design — there is no separate "basic" vs "aggressive" mode to remember to enable. Running `osc TARGET_URL` with no flags always performs: secret detection (API keys, tokens, passwords, database credentials, private keys, config/backup/log files), a full security posture audit (HTTP security headers, cookie flags, CORS policy, risky HTTP methods, TLS/certificate health, mixed content, missing SRI, security.txt, GraphQL introspection, directory listing, open redirects), path/endpoint brute-force discovery, and recon (subdomain enumeration, port scanning, tech fingerprinting, WAF detection) against every discovered endpoint. The one exception is active vulnerability probing (`-X`) — reflected XSS, error-based SQLi, path traversal, and SSTI — which stays opt-in because it sends real test payloads rather than just observing the response, and is the check with the most legal/impact weight. OSC prioritizes accuracy by implementing soft-404 detection, content-type verification, entropy filtering, and (as of 2.4) baseline-aware SSTI detection and wildcard-DNS-aware subdomain brute-force, to significantly reduce false positives.

> **LEGAL WARNING**
> Use this tool strictly on web applications you own or have explicit written permission to test. Unauthorized scanning is illegal and prohibited.

---

## Key Features

- **Secret Detection:** Identifies API keys, JWTs, AWS credentials (`AKIA…`), Google API keys (`AIza…`), GitHub tokens (`ghp_…`), Slack webhooks (`xox…`), SendGrid keys (`SG.…`), Stripe keys (`sk_live_…`), private keys, and connection strings.
- **Security Posture Audit (always on):** Checks HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookie flags (`Secure` / `HttpOnly` / `SameSite`), CORS misconfiguration (origin reflection, wildcard + credentials), risky HTTP methods (`PUT`, `DELETE`, `TRACE`, `CONNECT`), and TLS/certificate health (weak protocol, expiry, validation failures). Disable with `--skip-audit` if you only want raw secret-scanning.
- **Passive Vulnerability Checks:** Flags open redirects, directory listing / autoindex exposure, mixed content (HTTP subresources on an HTTPS page), and missing Subresource Integrity (SRI) on cross-origin scripts — all detected for free from the normal crawl, with no extra requests.
- **Info-Leak Checks:** `security.txt` (RFC 9116) presence and GraphQL introspection exposure, run once per scan alongside the security posture audit.
- **Endpoint Discovery + Recon (always on):** Wordlist-based path/endpoint brute-force (soft-404 aware, to avoid alert fatigue on catch-all servers) combined with subdomain enumeration (certificate-transparency lookup via crt.sh, plus wildcard-DNS-aware DNS brute-force), a lightweight common-port scan, technology fingerprinting (server/framework/CMS + version), and WAF/CDN detection — every discovered subdomain/endpoint gets the same security posture audit as the original target.
- **Active Vulnerability Probing (`-X`, opt-in):** Reflected XSS, error-based SQL injection, path traversal/LFI, baseline-aware Server-Side Template Injection (SSTI), and an SSRF-candidate-parameter heuristic — tested against query parameters on already-crawled, in-scope URLs only. The one part of OSC that sends real test payloads instead of just observing, so it stays opt-in.
- **False Positive Filtering:** Utilizes soft-404 baseline detection, pre-flag content verification, entropy checks, placeholder filtering, automated deduplication, wildcard-DNS detection (subdomain brute-force), and baseline comparison for SSTI detection.
- **Risk Assessment:** Assigns confidence levels (`high`, `medium`, `low`) per finding and provides a comprehensive risk summary.
- **Intelligent Crawling:** Uses BeautifulSoup for scope-controlled link discovery, respecting depth limits and URL caps.
- **Multi-format Reporting:** Exports findings to JSON, HTML, and CSV. Outputs are cleanly managed within an isolated `output/` directory.
- **Configurable Engine:** Supports multi-threading, request delays, custom user agents, flexible session cookies, and robust retry mechanisms.

---

## Project Structure

```
security-checker/
├── osc.py                # Command-line launcher (e.g., python3 osc.py ...)
├── requirements.txt      # Dependencies
├── README.md             # Documentation
├── LICENSE               # MIT License
├── pyproject.toml        # Package configuration
├── tests/                # pytest suite (unit tests, no real network)
├── .github/workflows/    # CI (runs the test suite on push/PR)
└── osc/                  # Core package directory
    ├── __init__.py
    ├── __main__.py       # Package entry point (python -m osc ...)
    ├── cli.py            # Argument parsing and output path management
    ├── scanner.py        # EnhancedOSCScanner main engine
    ├── patterns.py       # Regex patterns, sensitive file list, risk levels
    ├── discovery.py      # Aggressive mode and brute-force engine
    ├── security_audit.py # Headers, cookies, CORS, methods, TLS, mixed-content,
    │                      # SRI, security.txt, GraphQL introspection checks
    ├── recon.py           # Subdomain enum, port scan, tech fingerprint, WAF detection
    ├── active_scan.py     # Opt-in active probing: XSS, SQLi, traversal, SSTI, SSRF-candidate
    ├── reporting.py       # JSON, HTML, and CSV report generators
    └── wordlists/
        ├── common.txt     # Default content-discovery wordlist
        └── subdomains.txt # Default DNS subdomain brute-force wordlist
```

---

## Installation

OSC requires **Python 3.8+** and `pip`, and works the same way on **Windows**, **macOS**, and **Linux**.

> Run each command on its own line and wait for it to finish before running the next one — pasting multiple commands as a single line can make `venv` misbehave.

### 1. Clone the repository

```bash
git clone https://github.com/Fannandya/security-checker.git
cd security-checker
```

### 2. Create a virtual environment (recommended)

<table>
<tr><th>OS</th><th>Shell</th><th>Command</th></tr>
<tr><td>macOS / Linux</td><td>bash / zsh</td><td><code>python3 -m venv venv</code></td></tr>
<tr><td>Windows</td><td>PowerShell / Command Prompt</td><td><code>py -m venv venv</code></td></tr>
</table>

### 3. Activate the virtual environment

<table>
<tr><th>OS</th><th>Shell</th><th>Command</th></tr>
<tr><td>macOS / Linux</td><td>bash / zsh</td><td><code>source venv/bin/activate</code></td></tr>
<tr><td>Windows</td><td>Command Prompt (cmd.exe)</td><td><code>venv\Scripts\activate.bat</code></td></tr>
<tr><td>Windows</td><td>PowerShell</td><td><code>venv\Scripts\Activate.ps1</code></td></tr>
</table>

Your prompt should now be prefixed with `(venv)`. If PowerShell blocks the activation script with an execution-policy error, run this once and try again: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`.

### 4. Install the package

```bash
pip install .
```

*Note for Ubuntu/Debian (including WSL) users: Using a virtual environment is strongly recommended to comply with externally managed environment restrictions.*

*Note for Windows users without a venv: if `python`/`pip` aren't recognized, reinstall Python from [python.org](https://www.python.org/downloads/) and check "Add python.exe to PATH" during setup, or use the `py` launcher (`py -m pip install .`).*

---

## Usage

OSC can be executed either via the global command, the launcher script, or the Python module. Use `python3` on macOS/Linux and `python` (or `py`) on Windows:

```bash
osc [OPTIONS] TARGET_URL                 # Installed via pip (all platforms)
python3 osc.py [OPTIONS] TARGET_URL      # Via launcher (macOS/Linux)
python  osc.py [OPTIONS] TARGET_URL      # Via launcher (Windows)
python -m osc  [OPTIONS] TARGET_URL      # Via package (all platforms)
```

### Options

| Option | Description |
|--------|-------------|
| `-s, --session SESSION` | Session cookie: `"value"` or `"name=value; name2=value2"` |
| `-t, --threads N` | Number of concurrent threads (default: 10) |
| `--timeout SECONDS` | Request timeout in seconds (default: 10) |
| `-d, --depth N` | In-scope link crawl depth (0 = seeds only, default: 1) |
| `--max-urls N` | Maximum number of URLs to scan (default: 2500 — sized for the bundled wordlist's ~2,000 brute-force candidates) |
| `--delay SECONDS` | Delay between requests per worker (default: 0) |
| `--retries N` | Retries on transient HTTP errors (default: 2) |
| `--user-agent UA` | Custom User-Agent string |
| `--verify` | Enable TLS certificate verification (default: disabled) |
| `--wordlist FILE` | Custom wordlist file for path/endpoint brute-force (default: bundled) |
| `--extensions LIST` | Comma-separated extensions to test (e.g., `php,bak,sql`) |
| `--skip-audit` | Skip the security posture audit (headers/cookies/CORS/TLS/methods) |
| `--subdomain-wordlist FILE` | Custom wordlist for DNS subdomain brute-force (default: bundled; requires `dnspython`) |
| `-X, --active` | Enable active vulnerability probing (XSS/SQLi/traversal/SSTI/SSRF-candidate) — the only opt-in mode |
| `--active-checks LIST` | Comma-separated active checks to run (default: all; `xss,sqli,traversal,ssti,ssrf`) |
| `-o, --output FILE` | Write JSON report to the specified filename |
| `--html FILE` | Write HTML report to the specified filename |
| `--csv FILE` | Write CSV report to the specified filename |
| `-v, --verbose` | Enable verbose logging (errors and progress) |
| `-h, --help` | Display the help menu |

*Note: All output reports are automatically saved to the `output/` directory unless an absolute path is provided.*

### Path/Endpoint Discovery (always on)

There is no separate "basic" vs "aggressive" mode — every scan maps the application structure using crawling, sitemaps, robots.txt, common paths, *and* wordlist-based brute-force discovery (`osc/wordlists/common.txt`) with extension permutations (e.g., testing `backup`, `backup.php`, `backup.bak`) in a single pass.

All candidate paths undergo soft-404 filtering, preventing false positives on servers configured to return `200 OK` for nonexistent resources.

*Because this generates a high volume of requests by default, `--max-urls` defaults to 2500 (roughly the bundled wordlist's candidate count) and can be raised further (e.g. `--max-urls 5000`) for large sites; use `--delay` to reduce server impact.*

### Security Posture Audit (always on)

In addition to secret scanning, OSC runs a lightweight, read-only security audit against every scanned target and discovered endpoint/subdomain (a handful of extra requests per host — not per-URL). Disable it with `--skip-audit` if you only want the secret-scanning behavior.

| Category | Check | Risk |
|---|---|---|
| `security_headers` | Missing `Content-Security-Policy`, `Strict-Transport-Security` (HTTPS only), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy` | Medium |
| `cookie_security` | Cookies missing `Secure` (HTTPS), `HttpOnly`, or `SameSite` flags | Medium/Low |
| `cors_misconfiguration` | `Access-Control-Allow-Origin` reflects an arbitrary Origin, or `*` combined with `Access-Control-Allow-Credentials: true` | High |
| `http_methods` | Risky methods advertised via `OPTIONS` (`PUT`, `DELETE`, `TRACE`, `TRACK`, `CONNECT`) | Medium |
| `tls_issues` | Weak/legacy TLS protocol negotiated, certificate expired or expiring soon, or certificate validation failure | High |
| `directory_listing` | Apache/nginx-style autoindex ("Index of /") pages found during the crawl | Medium |
| `open_redirect` | A query-string parameter drives a redirect to an off-scope host, detected passively from the crawl's redirect chain | Medium |
| `tech_fingerprint` | `Server` / `X-Powered-By` banners (informational, helps map attack surface) | Low |
| `mixed_content` | HTTPS page loads a `<script>`/`<link>`/`<img>` resource over plain HTTP | Medium |
| `sri_missing` | Cross-origin `<script>`/`<link>` without an `integrity` attribute | Low |
| `security_txt_missing` | No `security.txt` (RFC 9116) at `/.well-known/security.txt` or `/security.txt` | Low |
| `graphql_introspection` | A discovered GraphQL endpoint (`/graphql`, `/api/graphql`, `/v1/graphql`) returns its schema on an introspection query | High |

These findings flow through the same pipeline as secret findings, so they appear in the console output, the summary report, and every export format (JSON/HTML/CSV).

### Recon (always on)

Recon goes beyond the crawled pages themselves and runs automatically on every scan — no flag needed:

| Category | Check | Risk |
|---|---|---|
| `subdomain_found` | Subdomains discovered via certificate-transparency logs (crt.sh) and, if `dnspython` is installed, DNS brute-force against `osc/wordlists/subdomains.txt` (override with `--subdomain-wordlist`). Brute-force automatically detects and skips wildcard-DNS domains (where every name resolves) to avoid a flood of false positives. | Low |
| `open_port` | Common TCP ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8080, 8443) found open on the target host | Medium (DB/RDP/Redis/Telnet ports) / Low (others) |
| `tech_fingerprint` | Server/framework/CMS detection from headers, cookies, and HTML (WordPress, Drupal, Joomla, Laravel, Django, Express, Next.js, nginx/Apache/IIS versions, etc.), with a CVE-search link for the detected version | Low |
| `waf_detected` | WAF/CDN fingerprint (Cloudflare, Akamai, Sucuri, Imperva Incapsula, AWS WAF, F5 BIG-IP ASM) — informational, helps set expectations for `-X` | Low |

DNS brute-force is entirely optional: without `dnspython` installed, recon still runs crt.sh lookup, port scan, fingerprinting, and WAF detection. Install it with `pip install "osc[recon]"` or `pip install dnspython`.

*Every subdomain recon discovers is fed back into the crawl queue, so it gets the same secret-pattern scanning, sensitive-file/directory-listing checks, and mixed-content/SRI/open-redirect checks as the primary target's own pages. The one-shot per-host checks (security headers, cookie flags, CORS, TLS/certificate, `security.txt`, GraphQL introspection, port scan) still run against the primary target only — running those against every discovered subdomain too is on the roadmap.*

### Active Vulnerability Probing (`-X, --active`)

> **Opt-in and higher-impact than the rest of OSC.** This sends actual test payloads (not just passive observation) to every query-string parameter on already-crawled, in-scope URLs. Only use `-X` against targets you own or have explicit written permission to test.

| Category | Check | Risk |
|---|---|---|
| `xss_reflected` | A unique marker injected into a query parameter reflects back unescaped in the HTML response | High |
| `sqli_error` | Appending a single quote (`'`) to a parameter value triggers a database error signature (MySQL/PostgreSQL/MSSQL/SQLite/Oracle) not present in the unmodified baseline response | High |
| `path_traversal` | A file-like parameter (`file`, `path`, `page`, `include`, ...) returns `/etc/passwd` contents when given a traversal payload | High |
| `ssti` | A template-syntax payload (e.g. `{{13*17}}`) evaluates to its arithmetic result in the response, indicating server-side template injection | High |
| `ssrf_candidate` | A parameter name matches a known SSRF-prone pattern (`url`, `redirect`, `callback`, `webhook`, ...) — heuristic only, flagged for manual verification, no requests to third-party hosts are made | Low |

Only error-based SQLi is used (no time-based/blind payloads) and every check is a single bounded request per parameter — no exploitation, no destructive payloads. Narrow the checks with `--active-checks xss,sqli` if you only want a subset.

### Output Formats

- **JSON (`-o`)**: Comprehensive scan data including `scan_info`, `summary` (category counts and risk assessment), and detailed `findings`.
- **HTML (`--html`)**: A standalone, interactive report featuring risk badges, category summaries, and finding tables.
- **CSV (`--csv`)**: A flat data structure (`category, confidence, risk, url, value, …`) optimized for spreadsheet analysis.

---

## Examples

```bash
# Full scan: discovery + recon + audit + secret detection, all automatic
osc https://example.com

# Authenticated scan with increased crawl depth
osc -s "PHPSESSID=abc123" -d 2 https://example.com

# All report formats, higher URL cap for a large site
osc --max-urls 5000 -o result.json --html result.html --csv result.csv https://example.com

# Custom wordlist and extensions with request delays
osc --wordlist custom.txt --extensions php,bak,sql --delay 0.5 https://example.com

# High-concurrency scan with verbose logging
osc -t 20 --timeout 15 -v https://example.com

# Secret-scanning + discovery only, no security header/CORS/TLS audit
osc --skip-audit https://example.com

# Active vulnerability probing (authorized targets only), narrowed to XSS + SQLi
osc -X --active-checks xss,sqli https://example.com

# Everything, including active probing, plus all report formats
osc -X --max-urls 5000 -o result.json --html result.html --csv result.csv https://example.com
```

---

## Usage as a Library

OSC is designed to be easily integrated into broader Python automation workflows. `aggressive` and `recon` default to `True` (matching the CLI's always-on behavior); pass `False` explicitly if your integration wants a narrower scan.

```python
from osc.scanner import EnhancedOSCScanner

# Initialize the scanner (aggressive discovery + recon on by default)
scanner = EnhancedOSCScanner("https://example.com", depth=1)

# Execute the scan and export reports
report = scanner.run_scan(output_file="report.json", html_file="report.html")

# Access the generated metrics programmatically
print("Overall Risk Level:", report["summary"]["risk_assessment"])
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `can't open file '.../install': No such file or directory` | Typed `python3 install .` instead of `pip install .` | Use `pip install .` (not `python3 install .`) |
| `Unable to create directory '.../venv/bin/activate'` | Two commands were pasted/run as one line (e.g. `python3 -m venv venv source venv/bin/activate`) | Run the create and activate commands separately, one per line |
| `ModuleNotFoundError: No module named 'osc.cli'` after `pip install .` | Ran `pip install .` from the wrong folder (not the repo root containing `pyproject.toml`) | `cd` into the cloned `security-checker` folder first, then `pip install .` |
| `'venv1\Scripts\Activate.ps1' cannot be loaded because running scripts is disabled` (Windows) | PowerShell execution policy blocks the script | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned`, then retry activation |
| `error: externally-managed-environment` (Debian/Ubuntu/WSL) | Trying to `pip install` outside a virtual environment | Create and activate a venv first (see Installation), then `pip install .` |
| `command not found: osc` / `'osc' is not recognized` | Virtual environment isn't activated, or install happened in a different venv | Re-activate the venv (step 3) before running `osc` |

To leave the virtual environment when you're done, run `deactivate` (same command on all platforms).

---

## Disclaimer

The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
