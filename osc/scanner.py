#!/usr/bin/env python3
"""
OSC - Open Source Code Scanner (core engine)
Accurate secret & sensitive-file discovery for authorized web testing.
Author : mamay

Legal: only scan targets you own or have explicit written permission to test.
"""

import re
import sys
import time
import math
import random
import string
import difflib
import hashlib
import threading
from collections import Counter
from urllib.parse import urljoin, urlparse, parse_qsl
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from colorama import Fore, Style, init

from osc.patterns import (
    PATTERNS, SENSITIVE_FILES, KNOWN_SECRET_PREFIXES, RISK_LEVELS, REMEDIATION_ADVICE, CWE_MAPPINGS,
)
from osc import security_audit
from osc import recon

# urllib3 Retry lives in different places depending on version
try:
    from urllib3.util.retry import Retry
except ImportError:  # pragma: no cover - very old urllib3
    from requests.packages.urllib3.util.retry import Retry  # type: ignore

# Silence the noisy InsecureRequestWarning we intentionally trigger with verify=False
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# Optional dependency: BeautifulSoup for robust link extraction (falls back to regex)
try:
    from bs4 import BeautifulSoup
    _HAS_BS4 = True
except ImportError:
    _HAS_BS4 = False

try:
    import lxml  # noqa: F401
    _HAS_LXML = True
except ImportError:
    _HAS_LXML = False

# Optional dependency: brotli so requests can decode Content-Encoding: br
try:
    import brotli  # noqa: F401
    _HAS_BROTLI = True
except ImportError:
    try:
        import brotlicffi  # noqa: F401
        _HAS_BROTLI = True
    except ImportError:
        _HAS_BROTLI = False

# Make console output robust on limited-encoding terminals (e.g. Windows cp1252),
# otherwise the banner's box-drawing characters raise UnicodeEncodeError.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Initialize colorama
init(autoreset=True)

__version__ = "2.4.0"


class EnhancedOSCScanner:
    def __init__(self, target, session_cookie=None, max_threads=10, timeout=10,
                 depth=1, max_urls=2500, delay=0.0, retries=2, user_agent=None,
                 verify=False, verbose=False,
                 aggressive=True, wordlist=None, extensions=None,
                 skip_audit=False,
                 recon=True, subdomain_wordlist=None, ports=None,
                 active=False, active_checks=None):
        self.target = target.rstrip('/')
        self.session_cookie = session_cookie
        self.max_threads = max_threads
        self.timeout = timeout
        self.depth = max(0, depth)
        self.max_urls = max_urls
        self.delay = max(0.0, delay)
        self.retries = max(0, retries)
        self.verify = verify
        self.verbose = verbose
        self.crawl = self.depth > 0

        # Aggressive content-discovery options
        self.aggressive = aggressive
        self.wordlist = wordlist
        self.extensions = extensions  # None -> discovery.DEFAULT_EXTENSIONS
        self.skip_audit = skip_audit

        # Recon (always on): subdomain enumeration, port scan, tech fingerprint, WAF detection
        self.recon = recon
        self.subdomain_wordlist = subdomain_wordlist
        self.ports = ports  # None -> recon.COMMON_PORTS

        # Active vulnerability probing (-X): XSS/SQLi/traversal/SSTI/SSRF-candidate
        self.active = active
        self.active_checks = active_checks  # None -> active_scan.ALL_CHECKS

        self.user_agent = user_agent or (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        )

        self.found_sensitive_data = []
        self.visited_urls = set()
        self._finding_keys = set()      # for de-duplication
        self.errors = 0
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.baseline = []              # soft-404 fingerprints
        self.cli_command = ''           # exact CLI invocation (set by cli.py) for audit trail

        self.max_content = 10_000_000   # skip bodies larger than 10 MB
        self.scan_chars = 2_000_000     # only regex-scan the first N chars

        self.session = self._build_session()

        # Add session cookie(s) if provided. Accepts either a bare value
        # (kept as the historic "session" cookie) or a full "k=v; k2=v2" string.
        if session_cookie:
            self._load_cookies(session_cookie)
            print(f"{Fore.GREEN}[+] Session cookie loaded{Style.RESET_ALL}")

        # Detection data (shared, read-only) + per-instance compiled regexes
        self.patterns = PATTERNS
        self.sensitive_files = list(SENSITIVE_FILES)
        self._compiled = {
            category: [(re.compile(pat), grp, conf) for pat, grp, conf in plist]
            for category, plist in self.patterns.items()
        }

    # ------------------------------------------------------------------ #
    # Session / networking helpers
    # ------------------------------------------------------------------ #
    def _build_session(self):
        session = requests.Session()

        retry = Retry(
            total=self.retries,
            connect=self.retries,
            read=self.retries,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(['GET', 'HEAD']),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=max(10, self.max_threads),
            pool_maxsize=max(10, self.max_threads),
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)

        # Only advertise brotli if we can actually decode it, otherwise responses
        # come back as undecoded bytes and every regex matches garbage.
        accept_encoding = 'gzip, deflate'
        if _HAS_BROTLI:
            accept_encoding += ', br'

        session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': accept_encoding,
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
        })
        return session

    def _load_cookies(self, session_cookie):
        if '=' in session_cookie:
            for part in session_cookie.split(';'):
                if '=' in part:
                    name, value = part.strip().split('=', 1)
                    if name.strip():
                        self.session.cookies.set(name.strip(), value.strip())
        else:
            self.session.cookies.set('session', session_cookie)

    def _log_error(self, url, exc):
        self.errors += 1
        if self.verbose:
            print(f"{Fore.YELLOW}[!] {url} -> {type(exc).__name__}: {exc}{Style.RESET_ALL}")

    # ------------------------------------------------------------------ #
    # Banner / help
    # ------------------------------------------------------------------ #
    def print_banner(self):
        banner = f"""
{Fore.RED}
  ██████  ███████  ██████  ███████
 ██    ██ ██      ██       ██
 ██    ██ ███████ ██       ███████
 ██    ██      ██ ██            ██
  ██████  ███████  ██████  ███████
{Style.RESET_ALL}
{Fore.CYAN}OSC - Open Source Code Scanner  {Fore.WHITE}v{__version__}
{Fore.YELLOW}Author : mamay
{Style.RESET_ALL}
Target : {self.target}
Session: {'Provided' if self.session_cookie else 'Not Provided'}
Mode   : {(Fore.MAGENTA + 'AGGRESSIVE' + Style.RESET_ALL) if self.aggressive else 'standard'} | Security audit: {'off' if self.skip_audit else 'on'}
Recon  : {(Fore.MAGENTA + 'on' + Style.RESET_ALL) if self.recon else 'off'} | Active probing: {(Fore.RED + 'ON' + Style.RESET_ALL) if self.active else 'off'}
Threads: {self.max_threads} | Timeout: {self.timeout}s | Depth: {self.depth} | Max URLs: {self.max_urls}
Engine : bs4={'on' if _HAS_BS4 else 'off'} lxml={'on' if _HAS_LXML else 'off'} brotli={'on' if _HAS_BROTLI else 'off'} dnspython={'on' if recon._HAS_DNSPYTHON else 'off'}
        """
        print(banner)
        if self.active:
            print(f"{Fore.RED}[!] Active vulnerability probing is ENABLED (-X). This sends XSS/SQLi/"
                  f"traversal/SSTI payloads to in-scope URLs. Only use this against targets you "
                  f"own or are explicitly authorized to test.{Style.RESET_ALL}")

    def print_help(self):
        """Print help information"""
        help_text = f"""
{Fore.CYAN}OSC - Open Source Code Scanner v{__version__}{Style.RESET_ALL}
{Fore.YELLOW}Author: mamay{Style.RESET_ALL}

{Fore.GREEN}USAGE:{Style.RESET_ALL}
    python3 osc.py [OPTIONS] TARGET_URL
    python -m osc [OPTIONS] TARGET_URL

{Fore.GREEN}OPTIONS:{Style.RESET_ALL}
    -s, --session SESSION    Session cookie ("value" or "name=value; name2=value2")
    -t, --threads THREADS    Number of threads (default: 10)
        --timeout TIMEOUT    Request timeout in seconds (default: 10)
    -d, --depth DEPTH        Crawl depth for in-scope links (0 = seeds only, default: 1)
        --max-urls N         Maximum URLs to scan (default: 2500)
        --delay SECONDS      Delay between requests per worker (default: 0)
        --retries N          HTTP retries on transient errors (default: 2)
        --user-agent UA      Custom User-Agent string
        --verify             Enable TLS certificate verification (default: off)
        --wordlist FILE      Custom wordlist for path/endpoint brute-force (default: bundled)
        --extensions LIST    Comma-separated extensions to try (e.g. php,bak,sql)
        --skip-audit         Skip the security posture audit (headers/cookies/CORS/TLS/methods)
        --subdomain-wordlist FILE  Custom wordlist for DNS subdomain brute-force (default: bundled)
        --ports LIST         Comma-separated TCP ports to scan during recon (default: ~35-port list)
    -X, --active             Enable active vulnerability probing (XSS/SQLi/traversal/SSTI/SSRF-candidate)
        --active-checks LIST Comma-separated active checks to run (default: all; xss,sqli,traversal,ssti,ssrf)
    -o, --output FILE        Write report to FILE (format auto-detected from extension:
                             .csv -> CSV, .html -> HTML, anything else -> JSON)
        --html FILE          Write HTML report to FILE
        --csv FILE           Write CSV report to FILE
    -v, --verbose            Verbose output (errors + progress)
    -h, --help               Show this help message

{Fore.YELLOW}Every scan always runs full path/endpoint brute-force discovery and recon
(subdomain enumeration, port scan, tech fingerprint, WAF detection) - there is
no separate "basic" mode. Only -X (active payload probing) is opt-in.{Style.RESET_ALL}

{Fore.GREEN}EXAMPLES:{Style.RESET_ALL}
    {Fore.WHITE}Full scan (discovery + recon + audit, all automatic):{Style.RESET_ALL}
    python3 osc.py https://example.com

    {Fore.WHITE}All report formats, higher URL cap:{Style.RESET_ALL}
    python3 osc.py --max-urls 5000 -o r.json --html r.html --csv r.csv https://example.com

    {Fore.WHITE}Authenticated + deeper crawl:{Style.RESET_ALL}
    python3 osc.py -s "PHPSESSID=abc123" -d 2 https://example.com

    {Fore.WHITE}Active vulnerability probing (authorized targets only):{Style.RESET_ALL}
    python3 osc.py -X --active-checks xss,sqli https://example.com

{Fore.GREEN}FEATURES:{Style.RESET_ALL}
    • API Keys, Tokens & JWT detection (with entropy filtering)
    • Database credentials & connection strings
    • Private key / sensitive file discovery (soft-404 aware)
    • Configuration files detection
    • Email addresses and internal IPs
    • Financial data scanning (Stripe/PayPal/Braintree)
    • Security header audit (CSP, HSTS, X-Frame-Options, nosniff, Referrer/Permissions-Policy)
    • Cookie flag audit (Secure / HttpOnly / SameSite)
    • CORS misconfiguration detection (origin reflection / wildcard+credentials)
    • Risky HTTP method detection (PUT/DELETE/TRACE/CONNECT)
    • TLS/certificate health check (weak protocol, expiry, validation failures)
    • Passive open-redirect and directory-listing (autoindex) detection
    • Mixed-content, missing-SRI, security.txt and GraphQL introspection checks
    • Path/endpoint brute-force discovery and recon (subdomain enumeration via crt.sh
      + optional DNS brute-force, port scan, tech fingerprinting, WAF/CDN detection)
      - always on, no flag needed
    • Active probing: reflected XSS, error-based SQLi, path traversal/LFI, SSTI,
      SSRF-candidate parameters (-X, opt-in)
    • Real link crawling + endpoint brute-force discovery
    • Multi-threaded scanning + JSON/HTML/CSV reports

{Fore.RED}LEGAL DISCLAIMER:{Style.RESET_ALL}
    Use this tool only on websites you own or have explicit permission to test.
    Unauthorized scanning may be illegal in your jurisdiction.
        """
        print(help_text)

    # ------------------------------------------------------------------ #
    # Soft-404 / baseline detection
    # ------------------------------------------------------------------ #
    def _fingerprint(self, text):
        """Stable fingerprint of a page with volatile bits (numbers/whitespace) normalized."""
        if not text:
            return None
        norm = re.sub(r'\d+', '#', text[:4000])
        norm = re.sub(r'\s+', ' ', norm).strip()
        return hashlib.md5(norm.encode('utf-8', 'ignore')).hexdigest()

    def establish_baseline(self):
        """Request a few random, definitely-nonexistent paths so we can recognize
        the target's catch-all / soft-404 response and avoid flagging it as an
        exposed file for every path we probe."""
        probes = [
            '/' + ''.join(random.choices(string.ascii_lowercase, k=16)) + '.html',
            '/' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)),
            '/' + ''.join(random.choices(string.ascii_lowercase, k=10)) + '.php',
        ]
        for probe in probes:
            try:
                resp = self.session.get(
                    urljoin(self.target + '/', probe.lstrip('/')),
                    timeout=self.timeout, verify=self.verify, allow_redirects=True,
                )
                self.baseline.append({
                    'status': resp.status_code,
                    'length': len(resp.content),
                    'fp': self._fingerprint(resp.text),
                    'body': (resp.text or '')[:2000],
                })
            except Exception as exc:
                self._log_error(probe, exc)
        if self.verbose and self.baseline:
            sigs = ', '.join(f"{b['status']}/{b['length']}b" for b in self.baseline)
            print(f"{Fore.CYAN}[*] Baseline (soft-404) signatures: {sigs}{Style.RESET_ALL}")

    def _is_soft_404(self, response):
        """True if the response matches the target's generic catch-all page.

        Uses an exact normalized fingerprint first (catch-all pages that are byte-identical
        across paths), then a content-similarity check gated by a tight relative length
        window (catch-all pages that embed the requested path and so differ slightly)."""
        if not self.baseline:
            return False
        try:
            body = response.text
            rlen = len(response.content)
            fp = self._fingerprint(body)
        except Exception:
            return False
        cand = body[:1000]
        for b in self.baseline:
            if b['status'] != response.status_code:
                continue
            if fp and b['fp'] and fp == b['fp']:
                return True
            blen = b.get('length') or 0
            base_body = b.get('body', '')
            # Only compare content when sizes are close enough to plausibly be the same template
            if not (base_body and blen and abs(rlen - blen) <= max(32, int(0.15 * blen))):
                continue
            matcher = difflib.SequenceMatcher(None, cand, base_body[:1000])
            if (matcher.real_quick_ratio() >= 0.9 and matcher.quick_ratio() >= 0.9
                    and matcher.ratio() >= 0.9):
                return True
        return False

    # ------------------------------------------------------------------ #
    # Scanning
    # ------------------------------------------------------------------ #
    def _should_visit(self, url):
        """Atomically claim a URL for scanning (thread-safe de-dup + max-urls cap)."""
        with self.lock:
            if url in self.visited_urls or len(self.visited_urls) >= self.max_urls:
                return False
            self.visited_urls.add(url)
            return True

    @staticmethod
    def _is_text_content(content_type):
        return any(t in content_type for t in (
            'text/html', 'application/javascript', 'text/javascript',
            'application/json', 'text/plain', 'application/xml', 'text/xml',
            'text/css', 'application/xhtml',
        ))

    def scan_url(self, url):
        """Scan a single URL; return the set of new in-scope links discovered."""
        links = set()
        if not self._should_visit(url):
            return links

        try:
            if self.delay:
                time.sleep(self.delay)

            response = self.session.get(
                url, timeout=self.timeout, verify=self.verify, allow_redirects=True,
            )

            if response.status_code == 200:
                content_type = response.headers.get('content-type', '').lower()
                content_length = len(response.content)

                # Catch-all / soft-404 servers return the SAME template for every
                # nonexistent path (e.g. Next.js on Vercel, or a client-rendered SPA
                # shell). Without this filter, the homepage's real content (emails,
                # CDN links, file refs) would be reported as findings on every
                # brute-forced URL that never existed. This only suppresses
                # secret/content-pattern scanning, NOT link extraction: a soft-404
                # match can still be a genuinely real, in-scope page (an SPA route
                # served from the same shell, for instance), and skipping crawl
                # continuation from it would silently stall discovery across the
                # whole site instead of just avoiding duplicate-content noise.
                is_soft_404 = self._is_soft_404(response)

                if content_length <= self.max_content and self._is_text_content(content_type):
                    text = response.text
                    if not is_soft_404:
                        self.analyze_content(url, text, content_type)
                    if self.crawl and self._same_scope(url):
                        links = self.extract_links(url, text)

                # Also check whether the URL itself is an exposed sensitive file
                self.check_sensitive_file_by_url(url, response, is_soft_404=is_soft_404)

            self._check_open_redirect(url, response)

        except Exception as exc:
            self._log_error(url, exc)

        return links

    _DIR_LISTING_TITLE_RE = re.compile(r'<title>\s*index of\s*/', re.I)
    _DIR_LISTING_MARKER_RE = re.compile(r'parent directory|\[to parent directory\]', re.I)

    def _check_open_redirect(self, url, response):
        """Passively flag redirects that land off-scope and were steered by a
        query-string parameter — no extra requests, reuses the redirect chain
        `requests` already followed via allow_redirects=True."""
        if not response.history or not response.url:
            return
        parsed_orig = urlparse(url)
        if not parsed_orig.query or self._same_scope(response.url):
            return

        final_host = urlparse(response.url).netloc.lower()
        for key, value in parse_qsl(parsed_orig.query):
            if not value:
                continue
            if final_host and (final_host in value.lower() or value.rstrip('/') in response.url):
                self._add_finding({
                    'url': url,
                    'category': 'open_redirect',
                    'value': f"Parameter '{key}' steers redirect to external host: {final_host}",
                    'confidence': 'medium',
                    'pattern': 'redirect_chain',
                    'content_type': '',
                    'context': f"{url} -> {response.url}",
                })
                return

    def _check_directory_listing(self, url, content_type, scan_text):
        if 'text/html' not in content_type:
            return
        if self._DIR_LISTING_TITLE_RE.search(scan_text) and self._DIR_LISTING_MARKER_RE.search(scan_text):
            self._add_finding({
                'url': url,
                'category': 'directory_listing',
                'value': 'Directory listing (autoindex) is enabled',
                'confidence': 'high',
                'pattern': 'directory_listing',
                'content_type': content_type,
                'context': '',
            })

    def analyze_content(self, url, content, content_type):
        """Analyze content for sensitive data patterns"""
        scan_text = content[:self.scan_chars]
        findings = []

        self._check_directory_listing(url, content_type, scan_text)

        if 'text/html' in content_type:
            findings.extend(security_audit.audit_mixed_content(url, scan_text))
            findings.extend(security_audit.audit_missing_sri(url, scan_text))

        for category, compiled in self._compiled.items():
            for regex, value_group, confidence in compiled:
                try:
                    for match in regex.finditer(scan_text):
                        value = match.group(value_group) if value_group else match.group(0)
                        if value and self.is_valid_finding(category, value, url):
                            findings.append({
                                'url': url,
                                'category': category,
                                'value': self.sanitize_value(value),
                                'confidence': confidence,
                                'pattern': regex.pattern,
                                'content_type': content_type,
                                'context': self._context(scan_text, match),
                            })
                except Exception:
                    continue

        # Check for sensitive file references inside the content
        findings.extend(self.find_file_references(url, scan_text))

        for finding in findings:
            self._add_finding(finding)

    @staticmethod
    def _context(text, match):
        start = text.rfind('\n', 0, match.start()) + 1
        end = text.find('\n', match.end())
        if end == -1:
            end = min(len(text), match.end() + 80)
        snippet = text[start:end].strip()
        return snippet[:160]

    def sanitize_value(self, value):
        """Sanitize value for display"""
        value = value.strip()
        if len(value) > 100:
            return value[:100] + '...'
        return value

    @staticmethod
    def _shannon_entropy(s):
        if not s:
            return 0.0
        counts = Counter(s)
        n = len(s)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())

    @staticmethod
    def _has_known_secret_prefix(value):
        low = value.lower()
        return any(low.startswith(p) for p in KNOWN_SECRET_PREFIXES)

    def is_valid_finding(self, category, value, url):
        """Validate if the finding is actually sensitive (reduce false positives)."""
        if value is None:
            return False
        value = value.strip()
        if not value:
            return False
        low = value.lower()

        # Obvious placeholders / examples
        exact_placeholders = {
            'password', 'passwd', 'pwd', 'secret', 'key', 'token', 'changeme',
            'none', 'null', 'undefined', 'true', 'false', 'test', 'example',
        }
        if low in exact_placeholders:
            return False
        placeholder_substr = (
            'example.com', 'your_', 'your-', 'yourapi', 'changeme', 'change_me',
            'placeholder', 'xxxxx', '<your', '{{', '}}', 'lorem', 'dummy',
            'test_key', 'sample', 'xxxx-xxxx', 'aaaaaaaa', '123456789',
        )
        if any(s in low for s in placeholder_substr):
            return False

        if category == 'emails':
            asset_ext = ('.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.ico', '.css', '.js')
            if url.lower().endswith(asset_ext):
                return False
            domain = value.rsplit('@', 1)[-1].lower()
            tld = domain.rsplit('.', 1)[-1]
            if tld in ('png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico', 'css',
                       'js', 'json', 'woff', 'woff2', 'ttf', 'eot', 'map'):
                return False
            if '@2x' in low or '@3x' in low:
                return False
            return True

        if category in ('internal_ips', 'private_keys', 'config_files', 'database'):
            return True

        if category in ('api_keys', 'tokens', 'financial'):
            if self._has_known_secret_prefix(value):
                return True
            if len(value) < 8:
                return False
            # Generic assignment values must look random enough to be a real secret
            if self._shannon_entropy(value) < 2.5:
                return False
            return True

        if category == 'passwords':
            # Real passwords can be low-entropy, so only filter by length here
            return 3 <= len(value) <= 64

        return True

    def find_file_references(self, url, content):
        """Find references to sensitive files inside page content (precise, no binary noise)."""
        findings = []
        ref_re = re.compile(
            r'''["'(]([A-Za-z0-9_./\-]{2,200}\.'''
            r'''(?:env|sql|bak|backup|old|log|pem|key|crt|sqlite|db|dump|ya?ml|ini|conf|config))'''
            r'''(?:["')\s>]|$)''',
            re.IGNORECASE,
        )
        seen = set()
        for match in ref_re.finditer(content):
            file_path = match.group(1)
            if file_path in seen:
                continue
            seen.add(file_path)
            if self.is_potential_sensitive_file(file_path):
                findings.append({
                    'url': url,
                    'category': 'sensitive_file_reference',
                    'value': file_path,
                    'confidence': 'low',
                    'pattern': 'file_reference',
                    'content_type': 'file_reference',
                    'context': '',
                })
        return findings

    def is_potential_sensitive_file(self, file_path):
        """Check if a referenced path looks like a genuinely sensitive file."""
        if not file_path or len(file_path) > 200:
            return False
        if '�' in file_path or any(ord(c) < 32 for c in file_path):
            return False

        fl = file_path.lower()
        known_exts = (
            '.env', '.sql', '.bak', '.backup', '.old', '.log', '.pem', '.key',
            '.crt', '.cert', '.pfx', '.sqlite', '.db', '.mdb', '.dump',
            '.yml', '.yaml', '.ini', '.conf', '.config', '.htaccess',
        )
        known_names = (
            'wp-config.php', 'config.php', 'configuration.php', 'settings.php',
            'id_rsa', 'id_dsa', '.htpasswd',
        )
        if fl.endswith(known_exts):
            return True
        base = fl.rsplit('/', 1)[-1]
        if base in known_names:
            return True
        return False

    def _looks_like_exposed_file(self, filename, response):
        """Confirm a 200 response actually contains the sensitive file's content
        (not a rendered HTML page that merely lives at that path)."""
        content_type = response.headers.get('content-type', '').lower()
        try:
            raw = response.text[:5000] if response.content else ''
        except Exception:
            raw = ''
        low = filename.lower()

        if low.endswith('.json') or 'json' in content_type:
            try:
                import json
                json.loads(response.text)
                return True
            except Exception:
                return raw.strip().startswith(('{', '['))
        if '.env' in low:
            return bool(re.search(r'^[A-Z][A-Z0-9_]{1,}\s*=', raw, re.M))
        if low.endswith(('.yml', '.yaml')):
            return bool(re.search(r'^\s*[\w\-]+\s*:\s', raw, re.M))
        if low.endswith('.php') or 'wp-config' in low or low.endswith('config.php'):
            return '<?php' in raw or '<?=' in raw  # exposed *source*, not rendered output
        if low.endswith(('.sql', '.dump')):
            return bool(re.search(r'\b(CREATE TABLE|INSERT INTO|DROP TABLE|ALTER TABLE)\b', raw, re.I))
        if low.endswith('.log'):
            return ('text/html' not in content_type) or bool(
                re.search(r'(\bGET\b|\bPOST\b|ERROR|WARN|\[\d{4}-\d{2}-\d{2})', raw))
        if low.endswith(('.xml',)):
            return raw.lstrip().startswith('<?xml')
        if low.endswith(('.key', '.pem', '.crt', '.cert', '.pfx')) or low in ('id_rsa', 'id_dsa'):
            return '-----BEGIN' in raw
        if low.endswith(('.htaccess', '.htpasswd', '.ini', '.conf', '.config')):
            return 'text/html' not in content_type
        # Binary-ish or unknown: only when the server returned the raw file (non-HTML)
        return 'text/html' not in content_type

    def check_sensitive_file_by_url(self, url, response, is_soft_404=None):
        """Flag the URL only when it truly serves an exposed sensitive file.

        `is_soft_404` lets a caller that already computed this (scan_url) pass
        it in and skip the duplicate difflib comparison; if omitted it's
        computed here as before.
        """
        if response.status_code != 200:
            return
        if is_soft_404 is None:
            is_soft_404 = self._is_soft_404(response)
        if is_soft_404:
            return
        if len(response.content) > 5_000_000:
            return

        path = urlparse(url).path.lower()
        base = path.rsplit('/', 1)[-1]

        matched = None
        # Longest patterns first so ".env.production" wins over ".env", "access.log" over ".log"
        for file_pattern in sorted(self.sensitive_files, key=len, reverse=True):
            fp = file_pattern.lower()
            if base == fp or base.endswith(fp) or path.endswith(fp):
                matched = file_pattern
                break
        if not matched:
            return
        if not self._looks_like_exposed_file(matched, response):
            return

        self._add_finding({
            'url': url,
            'category': 'exposed_sensitive_file',
            'value': f"Exposed {matched} file ({len(response.content)} bytes)",
            'confidence': 'high',
            'pattern': 'direct_access',
            'status_code': response.status_code,
            'content_type': response.headers.get('content-type', '').lower(),
            'context': '',
        })

    def _add_finding(self, finding):
        """Thread-safe, de-duplicated finding recorder + printer."""
        # Normalize fields so every finding is uniform across report formats.
        finding.setdefault('status_code', None)
        finding.setdefault('evidence', '')
        finding.setdefault('informational', False)
        # Only fills the gap for scanner.py's own secret/file findings, which
        # never set this key; security_audit.py/recon.py/active_scan.py already
        # attach their own remediation text, so setdefault leaves those alone.
        finding.setdefault('remediation', REMEDIATION_ADVICE.get(finding.get('category'), ''))
        # Standardize the CWE identifier too: security_audit sets its own
        # per-check CWE upfront, but scanner/recon/active_scan findings don't,
        # so the JSON report would otherwise carry findings with no cwe_id even
        # though CSV/HTML render one via CWE_MAPPINGS lookup.
        finding.setdefault('cwe_id', CWE_MAPPINGS.get(finding.get('category'), 'CWE-200'))
        key = (finding.get('url'), finding.get('category'), str(finding.get('value'))[:200])
        with self.lock:
            if key in self._finding_keys:
                return False
            self._finding_keys.add(key)
            self.found_sensitive_data.append(finding)
            self.print_finding(finding)
        return True

    # ------------------------------------------------------------------ #
    # URL discovery / crawling
    # ------------------------------------------------------------------ #
    def _same_scope(self, url):
        """Restrict crawling to the target host and its subdomains."""
        try:
            host = urlparse(url).netloc.lower()
            base = urlparse(self.target).netloc.lower()
            host = host[4:] if host.startswith('www.') else host
            base = base[4:] if base.startswith('www.') else base
            return host == base or host.endswith('.' + base)
        except Exception:
            return False

    def extract_links(self, base_url, html):
        """Extract in-scope links from a page (BeautifulSoup with regex fallback)."""
        hrefs = []
        if _HAS_BS4:
            try:
                soup = BeautifulSoup(html, 'lxml' if _HAS_LXML else 'html.parser')
                for tag, attr in (('a', 'href'), ('link', 'href'), ('script', 'src'),
                                  ('img', 'src'), ('form', 'action'), ('iframe', 'src')):
                    for el in soup.find_all(tag):
                        val = el.get(attr)
                        if val:
                            hrefs.append(val)
            except Exception:
                hrefs = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.I)
        else:
            hrefs = re.findall(r'(?:href|src|action)\s*=\s*["\']([^"\']+)["\']', html, re.I)

        links = set()
        for href in hrefs:
            href = href.strip()
            if not href or href.startswith(('#', 'mailto:', 'tel:', 'javascript:', 'data:')):
                continue
            full = urljoin(base_url, href)
            full = full.split('#', 1)[0]
            if full.startswith(('http://', 'https://')) and self._same_scope(full):
                links.add(full)
        return links

    def discover_urls(self, base_url):
        """Discover seed URLs from common paths, robots.txt and sitemap."""
        urls_to_scan = set()
        urls_to_scan.add(base_url)
        urls_to_scan.add(base_url + '/')

        common_paths = [
            # Root and common files
            '/', '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
            '/sitemap/', '/sitemap1.xml', '/sitemap-index.xml',
            # Configuration files
            '/.env', '/.env.local', '/.env.production',
            '/config.php', '/wp-config.php', '/configuration.php',
            '/config.json', '/settings.json', '/app/config.json',
            # VCS / IDE leaks
            '/.git/config', '/.git/HEAD', '/.svn/entries', '/.DS_Store',
            # API endpoints
            '/api', '/api/v1', '/api/v2', '/graphql', '/rest',
            '/api/users', '/api/config', '/api/settings',
            '/api/admin', '/api/auth', '/api/token',
            # Admin panels
            '/admin', '/administrator', '/wp-admin', '/manager',
            '/login', '/signin', '/dashboard', '/console',
            # Backup directories
            '/backup', '/backups', '/bak', '/old', '/temp',
            '/tmp', '/archive', '/archives',
            # Source code
            '/src', '/source', '/js', '/javascript', '/static',
            '/assets', '/resources', '/includes',
            # Documentation
            '/docs', '/documentation', '/api-docs', '/swagger',
            '/redoc', '/api.json', '/swagger.json',
            # Log files
            '/logs', '/log', '/error.log', '/access.log',
        ]
        for path in common_paths:
            urls_to_scan.add(urljoin(base_url, path))

        # robots.txt
        try:
            robots_url = urljoin(base_url, '/robots.txt')
            response = self.session.get(robots_url, timeout=self.timeout, verify=self.verify)
            if response.status_code == 200:
                for line in response.text.split('\n'):
                    line = line.strip()
                    if line.lower().startswith(('allow:', 'disallow:', 'sitemap:')):
                        path = line.split(':', 1)[1].strip()  # keep full https:// values intact
                        if path and path != '/':
                            urls_to_scan.add(urljoin(base_url, path))
        except Exception as exc:
            self._log_error('robots.txt', exc)

        # sitemap(s)
        try:
            sitemap_urls = [urljoin(base_url, '/sitemap.xml'),
                            urljoin(base_url, '/sitemap_index.xml')]
            for sitemap_url in sitemap_urls:
                response = self.session.get(sitemap_url, timeout=self.timeout, verify=self.verify)
                if response.status_code == 200:
                    for loc in re.findall(r'<loc>\s*(.*?)\s*</loc>', response.text, re.I):
                        loc = loc.strip()
                        if loc.startswith(('http://', 'https://')) and self._same_scope(loc):
                            urls_to_scan.add(loc)
        except Exception as exc:
            self._log_error('sitemap', exc)

        return urls_to_scan

    # ------------------------------------------------------------------ #
    # Reporting
    # ------------------------------------------------------------------ #
    def print_finding(self, finding):
        """Print finding with colored output"""
        colors = {
            'api_keys': Fore.RED,
            'tokens': Fore.MAGENTA,
            'passwords': Fore.RED,
            'database': Fore.YELLOW,
            'private_keys': Fore.RED,
            'emails': Fore.BLUE,
            'internal_ips': Fore.CYAN,
            'config_files': Fore.GREEN,
            'sensitive_file_reference': Fore.YELLOW,
            'exposed_sensitive_file': Fore.RED,
            'financial': Fore.RED,
            'tls_issues': Fore.RED,
            'cors_misconfiguration': Fore.RED,
            'directory_listing': Fore.YELLOW,
            'security_headers': Fore.YELLOW,
            'cookie_security': Fore.YELLOW,
            'http_methods': Fore.YELLOW,
            'open_redirect': Fore.YELLOW,
            'tech_fingerprint': Fore.CYAN,
            'mixed_content': Fore.YELLOW,
            'sri_missing': Fore.YELLOW,
            'security_txt_missing': Fore.CYAN,
            'graphql_introspection': Fore.RED,
            'subdomain_found': Fore.CYAN,
            'open_port': Fore.YELLOW,
            'waf_detected': Fore.CYAN,
            'xss_reflected': Fore.RED,
            'sqli_error': Fore.RED,
            'path_traversal': Fore.RED,
            'ssti': Fore.RED,
            'ssrf_candidate': Fore.YELLOW,
        }

        color = colors.get(finding['category'], Fore.WHITE)
        category_display = finding['category'].upper().replace('_', ' ')
        confidence = finding.get('confidence', '')
        conf_tag = f" {Fore.WHITE}({confidence})" if confidence else ''

        print(f"{color}[{category_display}]{conf_tag} {Fore.WHITE}{finding['url']}")
        print(f"     {Fore.CYAN}Data: {Fore.WHITE}{finding['value']}")
        if finding.get('context'):
            print(f"     {Fore.CYAN}Line: {Fore.WHITE}{finding['context']}")
        if finding.get('content_type'):
            print(f"     {Fore.CYAN}Type: {Fore.WHITE}{finding['content_type']}")
        print()

    def print_summary_report(self):
        """Print comprehensive summary report at the end"""
        print(f"\n{Fore.GREEN}{'=' * 60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{' OSC SCAN SUMMARY REPORT ':^60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}{'=' * 60}{Style.RESET_ALL}")

        print(f"{Fore.YELLOW}Scan Information:{Style.RESET_ALL}")
        print(f"  Target: {self.target}")
        print(f"  Session: {'Provided' if self.session_cookie else 'Not Provided'}")
        print(f"  URLs Scanned: {len(self.visited_urls)}")
        print(f"  Errors: {self.errors}")
        print(f"  Scan Duration: {round(time.time() - self.start_time, 2)} seconds")

        print(f"\n{Fore.YELLOW}Findings Summary:{Style.RESET_ALL}")
        print(f"  Total Findings: {len(self.found_sensitive_data)}")

        findings_by_category = self._group_by_category()

        risk_colors = {'CRITICAL': Fore.RED + Style.BRIGHT, 'HIGH': Fore.RED,
                       'MEDIUM': Fore.YELLOW, 'LOW': Fore.GREEN, 'NONE': Fore.WHITE}
        for category, findings in findings_by_category.items():
            risk_level = self.get_risk_level(category)
            color = risk_colors.get(risk_level, Fore.WHITE)
            category_display = category.upper().replace('_', ' ')
            print(f"  {color}{category_display}: {len(findings)} findings ({risk_level} risk){Style.RESET_ALL}")

        overall_risk = self.assess_overall_risk(findings_by_category)
        risk_color = risk_colors.get(overall_risk, Fore.WHITE)
        print(f"\n{Fore.YELLOW}Overall Risk Assessment:{Style.RESET_ALL}")
        print(f"  {risk_color}{overall_risk} RISK{Style.RESET_ALL}")

        critical_categories = ['api_keys', 'passwords', 'database', 'financial', 'private_keys', 'tokens',
                               'tls_issues', 'cors_misconfiguration', 'graphql_introspection',
                               'xss_reflected', 'sqli_error', 'path_traversal', 'ssti']
        critical_findings = []
        for category in critical_categories:
            critical_findings.extend(findings_by_category.get(category, []))

        if critical_findings:
            print(f"\n{Fore.RED}CRITICAL FINDINGS ({len(critical_findings)}):{Style.RESET_ALL}")
            for i, finding in enumerate(critical_findings[:5], 1):
                print(f"  {i}. {finding['url']}")
                print(f"     Data: {finding['value']}")
            if len(critical_findings) > 5:
                print(f"  ... and {len(critical_findings) - 5} more critical findings")

        print(f"{Fore.GREEN}{'=' * 60}{Style.RESET_ALL}")

    def _group_by_category(self):
        grouped = {}
        for finding in self.found_sensitive_data:
            grouped.setdefault(finding['category'], []).append(finding)
        return grouped

    def get_risk_level(self, category):
        """Get risk level for a category"""
        return RISK_LEVELS.get(category, 'LOW')

    def assess_overall_risk(self, findings_by_category):
        """Weighted overall risk: category severity x confidence x volume.

        - Informational findings (ports 80/443, banners, WAF/CDN, subdomains)
          are excluded so expected-but-open services never inflate the verdict.
        - Per-category volume is dampened (capped at 3) so 100+ low-severity
          hygiene issues do not by themselves reach CRITICAL.
        - 'CRITICAL' additionally requires a genuinely severe, confirmed
          finding (a HIGH-risk category with at least medium confidence):
          without XSS/SQLi/traversal/TLS-failure/CORS-with-credentials, the
          report cannot claim the worst severity.
        """
        risk_weight = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        conf_weight = {'high': 1.0, 'medium': 0.7, 'low': 0.4}
        severe_categories = {'HIGH'}

        score = 0.0
        has_severe = False
        has_high_category = False
        for category, findings in findings_by_category.items():
            actionable = [f for f in findings if not f.get('informational')]
            if not actionable:
                continue
            category_risk = self.get_risk_level(category)
            conf = max(conf_weight.get(f.get('confidence', 'low'), 0.4) for f in actionable)
            score += risk_weight.get(category_risk, 0) * min(len(actionable), 3) * conf
            if category_risk in severe_categories:
                has_high_category = True
                if conf >= 0.7:
                    has_severe = True

        if has_severe and score >= 8:
            return 'CRITICAL'
        if has_severe:
            return 'HIGH'
        if score >= 5:
            return 'HIGH'
        if has_high_category:
            # Any actionable HIGH-risk-category finding - even one only reported
            # at low confidence by a custom/merged finding - should never round
            # all the way down to LOW/NONE; low confidence means "verify this
            # before fixing", not "safe to ignore".
            score = max(score, 2.5)
        if score >= 2.5:
            return 'MEDIUM'
        if score > 0:
            return 'LOW'
        return 'NONE'

    def _scope_limitations(self):
        """Honest list of what this scan did NOT test, so consumers (QA, dev)
        never mistake the report for proof the application code is secure."""
        limits = [
            'Security headers, cookies, CORS, TLS, security.txt and GraphQL checks ran '
            'against the primary target root only (not each discovered subdomain).',
        ]
        if not self.active:
            limits.append(
                'Active vulnerability probing (-X) was DISABLED: no XSS, SQL injection, '
                'path traversal or SSTI payloads were sent, so application-level '
                'vulnerabilities were NOT tested.',
            )
        if not self.verify:
            limits.append(
                'TLS certificate verification was DISABLED (--verify not set); TLS/expiry '
                'findings are advisory and should be re-checked against a verified handshake.',
            )
        if not self.active and (not self.skip_audit or self.recon):
            # The audit (headers/cookies/CORS/TLS/etc.) and recon (ports/banners/WAF/
            # tech-fingerprint) are both passive/observational; either one running is
            # enough for this disclaimer to apply, so it isn't gated on skip_audit alone.
            # It is, however, skipped when active probing (-X) ran: those checks send
            # real payloads and CAN confirm exploits, so claiming "none are confirmed
            # exploits" wholesale would be wrong.
            limits.append(
                'Findings are passive/config observations (headers, ports, banners); none are '
                'confirmed exploits. Re-verify each finding with the evidence captured before fixing.',
            )
        return limits

    def generate_report(self, output_file=None):
        """Build the report dict; write JSON if output_file is given."""
        findings_by_category = self._group_by_category()
        total = len(self.found_sensitive_data)
        informational_count = sum(1 for f in self.found_sensitive_data if f.get('informational'))

        report = {
            'scan_info': {
                'target': self.target,
                'session_provided': bool(self.session_cookie),
                'aggressive': self.aggressive,
                'recon': self.recon,
                'active': self.active,
                'scan_duration': round(time.time() - self.start_time, 2),
                'urls_scanned': len(self.visited_urls),
                'errors': self.errors,
                'depth': self.depth,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'scanner_version': __version__,
                'reproducibility': {
                    'command': self.cli_command or 'N/A (library use)',
                    'python': sys.version.split()[0],
                    'tls_verify': self.verify,
                    'active_probing': self.active,
                    'threads': self.max_threads,
                    'timeout': self.timeout,
                    'max_urls': self.max_urls,
                },
                'scope_and_limitations': self._scope_limitations(),
            },
            'summary': {
                'total_findings': total,
                'informational_findings': informational_count,
                'actionable_findings': total - informational_count,
                'category_counts': {c: len(f) for c, f in findings_by_category.items()},
                'findings_by_category': findings_by_category,
                'risk_assessment': self.assess_overall_risk(findings_by_category),
            },
            'findings': self.found_sensitive_data,
        }

        if output_file:
            from osc import reporting
            reporting.write_json(report, output_file)

        return report

    # ------------------------------------------------------------------ #
    # Main driver
    # ------------------------------------------------------------------ #
    def run_scan(self, output_file=None, html_file=None, csv_file=None):
        """Main scanning function"""
        self.print_banner()

        if not self.verify:
            print(f"{Fore.YELLOW}[!] TLS verification is DISABLED (default). Traffic is exposed to "
                  f"MITM; pass --verify to enable it. Only scan hosts you trust.{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[*] Starting OSC Scan...{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Establishing baseline (soft-404 detection)...{Style.RESET_ALL}")
        self.establish_baseline()

        if not self.skip_audit:
            print(f"{Fore.GREEN}[*] Auditing security headers, cookies, CORS, "
                  f"HTTP methods, TLS, security.txt and GraphQL introspection...{Style.RESET_ALL}")
            try:
                for finding in security_audit.run_all(self.session, self.target, self.timeout, self.verify):
                    self._add_finding(finding)
            except Exception as exc:
                self._log_error('security_audit', exc)

        discovered_subdomains = set()
        if self.recon:
            print(f"{Fore.GREEN}[*] Running recon: subdomain enumeration, port scan, "
                  f"tech fingerprint, WAF detection...{Style.RESET_ALL}")
            try:
                for finding in recon.run_all(self.session, self.target, self.timeout, self.verify,
                                              subdomain_wordlist=self.subdomain_wordlist,
                                              ports=self.ports):
                    self._add_finding(finding)
                    if finding.get('category') == 'subdomain_found' and finding.get('url'):
                        discovered_subdomains.add(finding['url'])
            except Exception as exc:
                self._log_error('recon', exc)

        print(f"{Fore.GREEN}[*] Discovering URLs...{Style.RESET_ALL}")
        seed_urls = self.discover_urls(self.target)
        current = set(seed_urls)
        # Scanned first (see submit_order below) so a small --max-urls budget is
        # spent on the primary target's own real paths before wordlist noise.
        priority_urls = list(seed_urls)

        if discovered_subdomains:
            # Feed every discovered subdomain in as a crawl seed so it gets the same
            # secret-pattern / directory-listing / mixed-content / open-redirect checks
            # as the primary target's own pages (not just listed as a bare finding).
            # Per-host checks (security headers, TLS, CORS, port scan) still run only
            # against the primary target - see README "Recon" section.
            current |= discovered_subdomains
            priority_urls.extend(discovered_subdomains)
            print(f"{Fore.MAGENTA}[*] +{len(discovered_subdomains)} discovered subdomain(s) "
                  f"queued for scanning{Style.RESET_ALL}")

        if self.aggressive:
            from osc import discovery
            words = discovery.load_wordlist(self.wordlist)
            brute = discovery.generate_bruteforce_urls(self.target, words, self.extensions)
            current |= brute
            print(f"{Fore.MAGENTA}[*] Aggressive mode: +{len(brute)} wordlist candidates "
                  f"from {len(words)} words{Style.RESET_ALL}")
            if len(current) > self.max_urls:
                print(f"{Fore.YELLOW}[!] {len(current)} candidates > max-urls ({self.max_urls}); "
                      f"raise --max-urls to scan more.{Style.RESET_ALL}")

        print(f"{Fore.GREEN}[*] Found {len(current)} URLs queued{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[*] Scanning for sensitive data...{Style.RESET_ALL}\n")

        # Breadth-first crawl, one depth level at a time
        for level in range(self.depth + 1):
            if not current:
                break
            if self.verbose:
                print(f"{Fore.CYAN}[*] Depth {level}: {len(current)} URLs "
                      f"(scanned so far: {len(self.visited_urls)}){Style.RESET_ALL}")

            if level == 0:
                # Submit the target's own seeds/subdomains ahead of wordlist
                # brute-force candidates. ThreadPoolExecutor starts queued tasks
                # in submission order as workers free up, so this - not the
                # nondeterministic order a plain set would iterate in - decides
                # which URLs actually get to claim a slot when --max-urls is small.
                seen_order = set()
                submit_order = []
                for url in priority_urls:
                    if url in current and url not in seen_order:
                        seen_order.add(url)
                        submit_order.append(url)
                for url in current:
                    if url not in seen_order:
                        seen_order.add(url)
                        submit_order.append(url)
            else:
                submit_order = current

            next_level = set()
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = {executor.submit(self.scan_url, url): url for url in submit_order}
                for future in as_completed(futures):
                    try:
                        for link in future.result():
                            if link not in self.visited_urls:
                                next_level.add(link)
                    except Exception:
                        continue

            remaining = max(0, self.max_urls - len(self.visited_urls))
            current = set(list(next_level)[:remaining]) if remaining else set()

        if self.active:
            from osc import active_scan
            print(f"\n{Fore.RED}[*] Running active vulnerability probing on "
                  f"{len(self.visited_urls)} scanned URLs...{Style.RESET_ALL}")
            try:
                checks = self.active_checks or active_scan.ALL_CHECKS
                for finding in active_scan.run_all(
                        self.session, list(self.visited_urls), self.timeout, self.verify,
                        checks=checks, max_threads=self.max_threads):
                    self._add_finding(finding)
            except Exception as exc:
                self._log_error('active_scan', exc)

        report = self.generate_report(output_file)

        if html_file or csv_file:
            from osc import reporting
            if html_file:
                reporting.write_html(report, html_file)
            if csv_file:
                reporting.write_csv(report, csv_file)

        self.print_summary_report()
        return report
