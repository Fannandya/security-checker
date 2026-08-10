# Open Source Code Scanner (OSC)

- **Author:** mamay
- **Language:** Python 3 (3.8+)
- **License:** MIT
- **Version:** 2.1

OSC is a Python-based security tool designed to identify exposed sensitive data on websites and web applications. It detects API keys, authentication tokens, passwords, database credentials, private keys, configuration files, and backup/log files. OSC prioritizes accuracy by implementing soft-404 detection, content-type verification, and entropy filtering to significantly reduce false positives.

> **LEGAL WARNING**
> Use this tool strictly on web applications you own or have explicit written permission to test. Unauthorized scanning is illegal and prohibited.

---

## Key Features

- **Secret Detection:** Identifies API keys, JWTs, AWS credentials (`AKIA…`), Google API keys (`AIza…`), GitHub tokens (`ghp_…`), Slack webhooks (`xox…`), SendGrid keys (`SG.…`), Stripe keys (`sk_live_…`), private keys, and connection strings.
- **False Positive Filtering:** Utilizes soft-404 baseline detection, pre-flag content verification, entropy checks, placeholder filtering, and automated deduplication.
- **Risk Assessment:** Assigns confidence levels (`high`, `medium`, `low`) per finding and provides a comprehensive risk summary.
- **Intelligent Crawling:** Uses BeautifulSoup for scope-controlled link discovery, respecting depth limits and URL caps.
- **Aggressive Mode (`-A`):** Features wordlist-based path discovery while maintaining soft-404 awareness to prevent alert fatigue on catch-all servers.
- **Multi-format Reporting:** Exports findings to JSON, HTML, and CSV. Outputs are cleanly managed within an isolated `output/` directory.
- **Configurable Engine:** Supports multi-threading, request delays, custom user agents, flexible session cookies, and robust retry mechanisms.

---

## Project Structure

```
osc/
├── osc.py                # Command-line launcher (e.g., python3 osc.py ...)
├── requirements.txt      # Dependencies
├── README.md             # Documentation
├── LICENSE               # MIT License
├── pyproject.toml        # Package configuration
└── osc/                  # Core package directory
    ├── __init__.py
    ├── __main__.py       # Package entry point (python -m osc ...)
    ├── cli.py            # Argument parsing and output path management
    ├── scanner.py        # EnhancedOSCScanner main engine
    ├── patterns.py       # Regex patterns and sensitive file definitions
    ├── discovery.py      # Aggressive mode and brute-force engine
    ├── reporting.py      # JSON, HTML, and CSV report generators
    └── wordlists/
        └── common.txt    # Default content-discovery wordlist
```

---

## Installation

OSC requires **Python 3.8+** and `pip`.

```bash
# 1. Clone the repository
git clone https://github.com/Fannandya/security-checker.git
cd osc

# 2. Create and activate a virtual environment (Recommended)
python3 -m venv venv
source venv/bin/activate        # On Windows: venv\Scripts\activate

# 3. Install the package
pip install .
```

*Note for Ubuntu/Debian (including WSL) users: Using a virtual environment is strongly recommended to comply with externally managed environment restrictions.*

---

## Usage

OSC can be executed either via the global command, the launcher script, or the Python module:

```bash
osc [OPTIONS] TARGET_URL                 # Installed via pip
python3 osc.py [OPTIONS] TARGET_URL      # Via launcher
python -m osc  [OPTIONS] TARGET_URL      # Via package
```

### Options

| Option | Description |
|--------|-------------|
| `-s, --session SESSION` | Session cookie: `"value"` or `"name=value; name2=value2"` |
| `-t, --threads N` | Number of concurrent threads (default: 10) |
| `--timeout SECONDS` | Request timeout in seconds (default: 10) |
| `-d, --depth N` | In-scope link crawl depth (0 = seeds only, default: 1) |
| `--max-urls N` | Maximum number of URLs to scan (default: 500) |
| `--delay SECONDS` | Delay between requests per worker (default: 0) |
| `--retries N` | Retries on transient HTTP errors (default: 2) |
| `--user-agent UA` | Custom User-Agent string |
| `--verify` | Enable TLS certificate verification (default: disabled) |
| `-A, --aggressive` | Enable wordlist-based content discovery (path brute-forcing) |
| `--wordlist FILE` | Custom wordlist file for aggressive mode (default: bundled) |
| `--extensions LIST` | Comma-separated extensions to test (e.g., `php,bak,sql`) |
| `-o, --output FILE` | Write JSON report to the specified filename |
| `--html FILE` | Write HTML report to the specified filename |
| `--csv FILE` | Write CSV report to the specified filename |
| `-v, --verbose` | Enable verbose logging (errors and progress) |
| `-h, --help` | Display the help menu |

*Note: All output reports are automatically saved to the `output/` directory unless an absolute path is provided.*

### Aggressive Mode (`-A`)

By default, OSC maps the application structure using standard crawling, sitemaps, robots.txt, and common paths. When aggressive mode (`-A`) is enabled, OSC performs targeted path discovery using the bundled wordlist (`osc/wordlists/common.txt`) and applies extension permutations (e.g., testing `backup`, `backup.php`, `backup.bak`).

All candidate paths undergo soft-404 filtering, preventing false positives on servers configured to return `200 OK` for nonexistent resources.

*Recommendation: Aggressive mode generates a high volume of requests. Consider increasing `--max-urls` (e.g., `--max-urls 2000`) and utilizing `--delay` to minimize server impact.*

### Output Formats

- **JSON (`-o`)**: Comprehensive scan data including `scan_info`, `summary` (category counts and risk assessment), and detailed `findings`.
- **HTML (`--html`)**: A standalone, interactive report featuring risk badges, category summaries, and finding tables.
- **CSV (`--csv`)**: A flat data structure (`category, confidence, risk, url, value, …`) optimized for spreadsheet analysis.

---

## Examples

```bash
# Standard unauthenticated scan
osc https://example.com

# Authenticated scan with increased crawl depth
osc -s "PHPSESSID=abc123" -d 2 https://example.com

# Aggressive mode with multi-format reporting
osc -A --max-urls 2000 -o result.json --html result.html --csv result.csv https://example.com

# Custom wordlist and extensions with request delays
osc -A --wordlist custom.txt --extensions php,bak,sql --delay 0.5 https://example.com

# High-concurrency scan with verbose logging
osc -t 20 --timeout 15 -v https://example.com
```

---

## Usage as a Library

OSC is designed to be easily integrated into broader Python automation workflows.

```python
from osc.scanner import EnhancedOSCScanner

# Initialize the scanner
scanner = EnhancedOSCScanner("https://example.com", depth=1, aggressive=True)

# Execute the scan and export reports
report = scanner.run_scan(output_file="report.json", html_file="report.html")

# Access the generated metrics programmatically
print("Overall Risk Level:", report["summary"]["risk_assessment"])
```

---

## Disclaimer

The developer assumes no liability and is not responsible for any misuse or damage caused by this program.
