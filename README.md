# Open Source Code Scanner (OSC)

- **Author:** [Fannandya](https://github.com/Fannandya)
- **Language:** Python 3 (3.8+)
- **License:** [AGPL-3.0-or-later](LICENSE)
- **Version:** 2.5.0

OSC is a Python-based security tool for testing the security posture of websites and web applications. Every scan is a full scan by design — there is no separate "basic" vs "aggressive" mode to remember to enable. Running `osc TARGET_URL` with no flags always performs: secret detection (API keys, tokens, passwords, database credentials, private keys, config/backup/log files), a full security posture audit (HTTP security headers, cookie flags, CORS policy, risky HTTP methods, TLS/certificate health, mixed content, missing SRI, security.txt, GraphQL introspection, directory listing, open redirects), path/endpoint brute-force discovery, and recon (subdomain enumeration, port scanning, tech fingerprinting, WAF detection) against every discovered endpoint. The one exception is active vulnerability probing (`-X`) — reflected XSS, error-based SQLi, path traversal, and SSTI — which stays opt-in because it sends real test payloads rather than just observing the response, and is the check with the most legal/impact weight. OSC prioritizes accuracy by implementing soft-404 detection, content-type verification, entropy filtering, and (as of 2.4) baseline-aware SSTI detection, wildcard-DNS-aware subdomain brute-force, and interception-aware port scanning, to significantly reduce false positives.

> **LEGAL WARNING**
> Use this tool strictly on web applications you own or have explicit written permission to test. Unauthorized scanning is illegal and prohibited.

---

## Key Features

- **Secret Detection:** Identifies API keys, JWTs, AWS credentials (`AKIA…`), Google API keys (`AIza…`), GitHub tokens (`ghp_…`), Slack webhooks (`xox…`), SendGrid keys (`SG.…`), Stripe keys (`sk_live_…`), private keys, and connection strings.
- **Security Posture Audit (always on):** Checks HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), cookie flags (`Secure` / `HttpOnly` / `SameSite`), CORS misconfiguration (origin reflection, wildcard + credentials), risky HTTP methods (`PUT`, `DELETE`, `TRACE`, `CONNECT`), and TLS/certificate health (weak protocol, expiry, validation failures). Disable with `--skip-audit` if you only want raw secret-scanning.
- **Passive Vulnerability Checks:** Flags open redirects, directory listing / autoindex exposure, mixed content (HTTP subresources on an HTTPS page), and missing Subresource Integrity (SRI) on cross-origin scripts — all detected for free from the normal crawl, with no extra requests.
- **Info-Leak Checks:** `security.txt` (RFC 9116) presence and GraphQL introspection exposure, run once per scan alongside the security posture audit.
- **Endpoint Discovery + Recon (always on):** Wordlist-based path/endpoint brute-force (soft-404 aware, to avoid alert fatigue on catch-all servers) combined with subdomain enumeration (certificate-transparency lookup via crt.sh, plus wildcard-DNS-aware DNS brute-force), a lightweight common-port scan (interception-aware — canary-probes random unassigned ports first and skips reporting if a proxy/VPN/firewall is answering for every port, rather than flooding the report with false "open" ports), technology fingerprinting (server/framework/CMS + version), and WAF/CDN detection — every discovered subdomain/endpoint gets the same security posture audit as the original target.
- **Active Vulnerability Probing (`-X`, opt-in):** Reflected XSS, error-based SQL injection, path traversal/LFI, baseline-aware Server-Side Template Injection (SSTI), and an SSRF-candidate-parameter heuristic — tested against query parameters on already-crawled, in-scope URLs only. The one part of OSC that sends real test payloads instead of just observing, so it stays opt-in.
- **False Positive Filtering:** Utilizes soft-404 baseline detection, pre-flag content verification, entropy checks, placeholder filtering, automated deduplication, wildcard-DNS detection (subdomain brute-force), TCP-interception detection (port scan), and baseline comparison for SSTI detection.
- **Risk Assessment:** Assigns confidence levels (`high`, `medium`, `low`) per finding, maps each category to a standard CWE ID and concrete remediation advice (for QA/defect-tracker workflows), and provides a comprehensive risk summary.
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
| `--max-urls N` | Maximum number of URLs to scan (default: 10000 — sized for the bundled wordlist's ~6,000 brute-force candidates) |
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
| `-o, --output FILE` | Write report to FILE. Format is auto-detected from the extension: `.csv` → CSV, `.html` → HTML, anything else → JSON |
| `--html FILE` | Write HTML report to the specified filename |
| `--csv FILE` | Write CSV report to the specified filename |
| `-v, --verbose` | Enable verbose logging (errors and progress) |
| `-h, --help` | Display the help menu |

*Note: All output reports are automatically saved to the `output/` directory unless an absolute path is provided.*

### Path/Endpoint Discovery (always on)

There is no separate "basic" vs "aggressive" mode — every scan maps the application structure using crawling, sitemaps, robots.txt, common paths, *and* wordlist-based brute-force discovery (`osc/wordlists/common.txt`) with extension permutations (e.g., testing `backup`, `backup.php`, `backup.bak`) in a single pass.

All candidate paths undergo soft-404 filtering, preventing false positives on servers configured to return `200 OK` for nonexistent resources.

*Because this generates a high volume of requests by default, `--max-urls` defaults to 10000 (roughly the bundled wordlist's candidate count) and can be raised further (e.g. `--max-urls 20000`) for large sites; use `--delay` to reduce server impact.*

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
| `open_port` | A curated ~35-port list (web, mail, remote-admin, and — notably — data-store/container ports: MongoDB 27017, Elasticsearch 9200/9300, Redis 6379, Memcached 11211, CouchDB 5984, Docker API 2375, MSSQL/Oracle/MySQL/PostgreSQL, SMB/NFS/RPCbind) found open on the target host. Each open port gets a best-effort, read-only banner grab (an HTTP HEAD for web-like ports, or just reading the greeting a service like SSH/FTP/SMTP/MySQL sends unprompted on connect — no credentials or protocol commands are ever sent) and a CVE-search link when a banner is captured. Override the list with `--ports 21,22,80,443,...`. Before scanning the real list, a few random unassigned high ports (49152-65535) are probed as a canary; if any of *those* come back "open" too, something between the scanner and the target (proxy, VPN, firewall) is answering for every port, so the scan is skipped entirely and reported as `port_scan_unreliable` instead of a false-positive flood. | Medium (data-store/remote-admin/container ports) / Low (others) |
| `port_scan_unreliable` | The canary probe above tripped — the port scan was skipped because the network path can't be trusted to distinguish an open port from a middlebox intercepting every connection. Re-run from a network without transparent TCP interception to get real port-scan results. | Low (informational) |
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

- **JSON (`-o`)**: Comprehensive scan data including `scan_info` (with `reproducibility` — the CLI command with any `-s`/`--session` value redacted, Python version, `--verify`/`-X` state — and `scope_and_limitations`, a plain-language list of what the scan did *not* test), `summary` (category counts, risk assessment, and a separate count of `informational_findings` vs `actionable_findings`), and detailed `findings`. Every finding carries an `evidence` field (the raw response headers / matched string) so results can be re-verified, a `cwe_id` (standard CWE identifier per category, for defect-tracking/compliance workflows) and `remediation` (concrete fix guidance for that finding), and an `informational` flag separating expected-but-informational observations (e.g. open ports 80/443, server banners, WAF/CDN, discovered subdomains) from actionable findings.
- **HTML (`--html`)**: A standalone, interactive report featuring risk badges, category summaries, a Reproducibility table, a Scope & Limitations section, and finding tables with CWE ID, evidence, and remediation.
- **CSV (`--csv`)**: A flat structure (`cwe_id, category, confidence, risk, url, value, content_type, status_code, pattern, context, evidence, informational, remediation`) optimized for spreadsheet analysis and QA defect-tracker import.

> **Risk assessment note:** the overall risk verdict is weighted by category severity × confidence × (dampened) volume. `CRITICAL` additionally requires a *confirmed* severe finding (a HIGH-risk category reported at medium-or-higher confidence — e.g. reflected XSS, SQL injection, path traversal, SSTI, TLS failure, CORS-with-credentials) **and** a high weighted score (≈ ≥8; in practice several confirmed high-severity classes). A single confirmed XSS alone reports `HIGH`, not `CRITICAL`. A large volume of low-severity hygiene findings (missing SRI, exposed emails, file references) will not by itself produce a `CRITICAL` verdict. Informational findings never move the risk needle.

> **Soft-404 content filtering:** secret/content-pattern scanning (emails, mixed content, missing SRI, sensitive-file references, API keys, etc.) is suppressed for URLs whose response matches the target's catch-all / soft-404 template. This prevents a single-page app that returns the same HTML for every path from producing hundreds of duplicate, misleading findings on paths that never existed. Link extraction is deliberately **not** suppressed by this filter — a soft-404 match can still be a real, in-scope page (e.g. a client-rendered SPA route served from the same shell), so crawling still continues from it.

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

---

## License

OSC is licensed under the **[GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)](LICENSE)** — free and open source, and it stays that way for every derivative.

In plain language, this means:

- **You can** use, study, modify, and redistribute OSC for free, including commercially.
- **You can** fork it and build your own version under a different name.
- **If you distribute a modified version — including running it as a hosted web service/SaaS that users interact with over a network** — you must make the complete corresponding source code of *your* version available to those users, under the same AGPL-3.0-or-later license. This is stricter than a typical GPL project: even offering it purely as an online service counts as "distribution" under AGPLv3 Section 13, so a modified version can't be kept closed-source just because the code itself was never handed out.
- **You must** keep the copyright notice, the [LICENSE](LICENSE) file, and the [NOTICE](NOTICE) file intact, and preserve the `SPDX-License-Identifier` headers in source files you keep.
- **You must not** represent a modified/forked version as the official OSC project or as being authored by someone other than its actual authors — see [AUTHORS.md](AUTHORS.md) and [NOTICE](NOTICE).

This project was previously MIT-licensed; it moved to AGPL-3.0-or-later at v2.5.0 specifically to prevent the "fork it, close the source, sell it" pattern that a permissive license doesn't guard against. See [CITATION.cff](CITATION.cff) for a machine-readable citation record, and [CONTRIBUTING.md](CONTRIBUTING.md) if you'd like to contribute back to the original project instead of maintaining a separate fork.

---

## Glossary

This section is a plain-language dictionary of the terms, settings, and finding categories you will see when running OSC. Use it as a reference while reading the console banner, the summary report, or the JSON/HTML/CSV exports.

### Console banner & scan settings

| Term | Meaning |
|---|---|
| `Target` | The URL being scanned. All crawling and scope checks are limited to this host and its subdomains. |
| `Session: Not Provided` | No session cookie was given (`-s/--session`). The scan runs **unauthenticated**: pages behind a login will not have their content analyzed. |
| `Session: Provided` | A session cookie was loaded, letting OSC scan pages that require a logged-in session. |
| `Mode: AGGRESSIVE` | Wordlist-based path/endpoint brute-force discovery is **always on** (there is no separate "basic" mode). The scanner guesses URLs (e.g. `/admin`, `/.env`, `/config.php`) in addition to analyzing pages it actually found. |
| `Security audit: on` | The security posture audit is running: security headers, cookie flags, CORS, risky HTTP methods, TLS/certificate health, `security.txt`, and GraphQL introspection. Disable with `--skip-audit`. |
| `Recon: on` | Recon is running: subdomain enumeration (crt.sh + optional DNS brute-force), port scanning, technology fingerprinting, and WAF/CDN detection. Always on. |
| `Active probing: off` | The opt-in `-X` mode is **not** enabled, so no XSS/SQLi/traversal/SSTI payloads are sent. The scan only observes responses. |
| `Active probing: ON` | `-X` is enabled and real test payloads are being sent to query parameters on already-crawled, in-scope URLs. Only use this on targets you own or are authorized to test. |
| `Threads` | Number of concurrent request workers (default: 10). Higher values scan faster but are more aggressive toward the server. |
| `Timeout` | Per-request timeout in seconds (default: 10). Requests that hang longer than this are treated as failed. |
| `Depth` | How many levels of links to follow from the seed pages (default: 1). `0` means only the seed URLs are scanned. |
| `Max URLs` | The cap on the total number of URLs scanned (default: 10000). Raise it (e.g. `--max-urls 20000`) for large sites. |

### `Engine:` library indicators

| Term | Meaning |
|---|---|
| `bs4=on` | BeautifulSoup is installed — used for accurate, robust link extraction from HTML. A core dependency. |
| `lxml=on` | The fast lxml HTML/XML parser is installed — used by BeautifulSoup for speed. A core dependency. |
| `brotli=on` | Brotli is installed, so OSC can decode responses compressed with `Content-Encoding: br`. A core dependency. |
| `dnspython=off` | dnspython is **not** installed, so DNS subdomain brute-force is skipped (crt.sh lookup, port scan, fingerprinting, and WAF detection still run). Enable it with `pip install "osc[recon]"` or `pip install dnspython`, then re-run — the line changes to `dnspython=on`. |

### Scan phases & concepts

| Term | Meaning |
|---|---|
| Seed URL | The initial URLs scanned (target root, common paths, `robots.txt` and sitemap entries) before brute-forced candidates. |
| Crawling | Following in-scope links (`<a href>`, `<script src>`, etc.) found on scanned pages, up to the configured `--depth`. |
| Brute-force discovery | Guessing paths/endpoints from the bundled wordlist (`osc/wordlists/common.txt`) with extension permutations (`backup`, `backup.php`, `backup.bak`, ...). |
| Baseline / soft-404 | A few random, definitely-nonexistent paths are requested first to fingerprint the target's catch-all ("page not found but HTTP 200") response, so that identical catch-all pages are not reported as findings on every guessed URL. |
| Wildcard DNS | A DNS zone that resolves *any* subdomain to the same host. OSC detects it and skips DNS brute-force to avoid reporting every wordlist entry as a "discovered" subdomain. |
| Canary probe | Before the real port list, a few random unassigned high ports are probed. If those are "open" too, something between you and the target (proxy/VPN/firewall) is answering for every port, so the port scan is skipped and reported as `port_scan_unreliable`. |
| Scope / in-scope | URLs belonging to the target host or one of its subdomains. Only in-scope links are crawled; off-scope redirects are flagged instead. |
| MITM | "Man-in-the-middle". With `--verify` disabled (the default), TLS is not validated, so traffic could theoretically be intercepted. Pass `--verify` to enable certificate verification. |
| Session cookie | A cookie (`-s/--session`) used to scan content that requires a logged-in session. |
| False positive | A reported finding that is actually not a real issue (e.g. a placeholder value or the catch-all page matching a secret pattern). OSC filters many of these via entropy checks, placeholder filters, soft-404 detection, and content verification. |
| Entropy filter | A Shannon-entropy check used to decide whether a value looks random enough to be a real secret (rather than a placeholder like `xxxxx`). |

### Finding categories

Each category below is reported by its module with its own `risk` level. See the "Security Posture Audit", "Recon", and "Active Vulnerability Probing" sections above for check details.

**Secret detection** (content/pattern scanning of every analyzed page)

| Category | Meaning |
|---|---|
| `api_keys` | Stripe, AWS, Google, GitHub, Slack, SendGrid, and similar credential formats. |
| `tokens` | Bearer/JWT and generic tokens. |
| `passwords` | Hard-coded passwords or credentials in code/config. |
| `database` | Database connection strings and credentials. |
| `financial` | Payment/merchant keys (e.g. Stripe `sk_…`, PayPal, Braintree). |
| `private_keys` | Private key material (`-----BEGIN … PRIVATE KEY-----`). |
| `emails` | Email addresses exposed in page content. |
| `internal_ips` | Private/loopback IP addresses leaking into public responses. |
| `config_files` | Configuration file content served to visitors. |
| `exposed_sensitive_file` | A sensitive file (`.env`, `.git`, backups, logs, config) that is directly reachable and served as the raw file. |
| `sensitive_file_reference` | A reference to a sensitive filename inside page content (e.g. a comment mentioning `backup.sql`). |

**Security posture audit** (headers/cookies/CORS/methods/TLS/network-level checks)

| Category | Meaning |
|---|---|
| `security_headers` | A required HTTP security header (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) is missing or weak. |
| `cookie_security` | A cookie is set without `Secure`, `HttpOnly`, or `SameSite`. |
| `cors_misconfiguration` | `Access-Control-Allow-Origin` reflects any Origin, or `*` is combined with `Access-Control-Allow-Credentials: true`. |
| `http_methods` | Risky HTTP methods (`PUT`, `DELETE`, `TRACE`, `TRACK`, `CONNECT`) are advertised. |
| `tls_issues` | Weak/legacy TLS protocol, expired/expiring certificate, or certificate validation failure. |
| `mixed_content` | An HTTPS page loads subresources over plain HTTP. |
| `sri_missing` | A cross-origin script/link is loaded without an `integrity` (SRI) attribute. |
| `security_txt_missing` | No `security.txt` (RFC 9116) is published. |
| `graphql_introspection` | A discovered GraphQL endpoint exposes its full schema via introspection. |
| `directory_listing` | Apache/nginx-style "Index of /" autoindex page found during the crawl. |
| `open_redirect` | A query-string parameter drives a redirect to an off-scope host. |

**Recon**

| Category | Meaning |
|---|---|
| `subdomain_found` | A subdomain discovered via crt.sh certificate logs or DNS brute-force. |
| `open_port` | A port on the target host accepts connections (web, mail, remote-admin, data-store, container ports, ...). |
| `port_scan_unreliable` | The canary probe tripped — the port scan was skipped because the network path can't be trusted. |
| `tech_fingerprint` | Server/framework/CMS detected from headers, cookies, or HTML (with a CVE-search link for the version). |
| `waf_detected` | A WAF/CDN fingerprint was matched (Cloudflare, Akamai, Sucuri, Imperva, AWS WAF, F5 ...). |

**Active probing (`-X`)**

| Category | Meaning |
|---|---|
| `xss_reflected` | An injected marker is echoed back unescaped in the HTML response. |
| `sqli_error` | Appending a quote to a parameter triggers a database error signature not present in the baseline. |
| `path_traversal` | A file-like parameter returns `/etc/passwd` contents for a traversal payload. |
| `ssti` | A template-syntax payload evaluates to its arithmetic result in the response. |
| `ssrf_candidate` | A parameter name matches a known SSRF-prone pattern — heuristic only, flagged for manual verification. |

### Report fields

| Term | Meaning |
|---|---|
| `finding` | A single detected issue. Every finding records `url`, `category`, `value`, `confidence`, `context`, `evidence`, `cwe_id`, `remediation`, `informational`, and `status_code`. |
| `confidence` | How sure OSC is that the finding is real: `high`, `medium`, or `low`. |
| `risk` | The per-category severity (`LOW`, `MEDIUM`, or `HIGH`) defined by OSC for that category. |
| `risk_assessment` | The overall verdict for the whole scan, weighted by severity × confidence × volume: `NONE`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. |
| `informational` | An expected-but-observational finding (e.g. open ports 80/443, server banners, WAF/CDN, discovered subdomains). These never affect the risk verdict. |
| `actionable` | Any finding that is not `informational` — i.e. worth acting on. |
| `evidence` | The raw data captured for a finding (response headers, matched string, injected payload) so you can re-verify it. |
| `cwe_id` | The Common Weakness Enumeration identifier (e.g. `CWE-798`) mapped to the finding's category for defect-tracking/compliance workflows. |
| `remediation` | Concrete fix guidance for the finding. |
| `reproducibility` | The `scan_info` block recording the CLI command (with any `-s/--session` value redacted), Python version, `--verify`/`-X` state, threads, timeout, and max URLs — so a scan can be reproduced exactly. |
| `scope_and_limitations` | A plain-language list of what the scan did **not** test (e.g. active probing disabled, TLS verification off, per-host checks only against the primary target). |
| `category_counts` | The number of findings per category in the `summary` block. |
| `-o, --output` | Writes the report to a file; the format is auto-detected from the extension (`.csv`, `.html`, otherwise JSON). |
| `--html` / `--csv` | Write the report in HTML or CSV format regardless of filename. |
| `output/` | The default folder where report files are saved (unless an absolute path is given). |
