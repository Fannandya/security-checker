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
security-checker/
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
