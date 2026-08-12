"""Recon module: subdomain enumeration, lightweight port scan, tech
fingerprinting, and WAF/CDN detection.

Runs automatically on every scan (no opt-in flag - see scanner.py), unlike
active_scan.py which stays opt-in because it sends real exploit-style
payloads. Findings are plain dicts shaped like scanner findings so they
flow straight through the existing report pipeline (JSON/HTML/CSV).
"""

import os
import random
import re
import socket
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import quote, urlparse

# Optional dependency: DNS brute-force subdomain resolution. crt.sh
# enumeration (below) works without it using only `requests`.
try:
    import dns.resolver
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False


def _finding(url, category, value, confidence, context=''):
    return {
        'url': url,
        'category': category,
        'value': value,
        'confidence': confidence,
        'pattern': 'recon',
        'content_type': '',
        'context': context,
    }


# ---------------------------------------------------------------------- #
# Tech fingerprinting
# ---------------------------------------------------------------------- #
# (product, header name or None for HTML body, pattern - group 1, if present, is the version)
TECH_SIGNATURES = [
    ('Nginx', 'server', re.compile(r'nginx(?:/([\d.]+))?', re.I)),
    ('Apache', 'server', re.compile(r'apache(?:/([\d.]+))?', re.I)),
    ('Microsoft-IIS', 'server', re.compile(r'microsoft-iis(?:/([\d.]+))?', re.I)),
    ('PHP', 'x-powered-by', re.compile(r'php(?:/([\d.]+))?', re.I)),
    ('Express', 'x-powered-by', re.compile(r'express', re.I)),
    ('ASP.NET', 'x-powered-by', re.compile(r'asp\.net', re.I)),
    ('Laravel', 'set-cookie', re.compile(r'laravel_session', re.I)),
    ('Django', 'set-cookie', re.compile(r'csrftoken', re.I)),
    ('WordPress', None, re.compile(r'wp-content|wp-includes', re.I)),
    ('Drupal', None, re.compile(r'Drupal\.settings|/sites/default/files', re.I)),
    ('Joomla', None, re.compile(r'/media/jui/|Joomla!', re.I)),
    ('Next.js', None, re.compile(r'__NEXT_DATA__|/_next/static', re.I)),
    ('React', None, re.compile(r'data-reactroot|react-dom', re.I)),
]
_META_GENERATOR_RE = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_FINGERPRINT_SCAN_CHARS = 200_000


def fingerprint_tech(url, headers, html):
    findings = []
    low_headers = {k.lower(): v for k, v in headers.items()}
    body = (html or '')[:_FINGERPRINT_SCAN_CHARS]
    matched = set()

    for product, header_name, pattern in TECH_SIGNATURES:
        haystack = low_headers.get(header_name, '') if header_name else body
        match = pattern.search(haystack)
        if not match or product in matched:
            continue
        matched.add(product)
        version = match.group(1) if match.groups() and match.group(1) else ''
        label = f"{product} {version}".strip()
        findings.append(_finding(
            url, 'tech_fingerprint', f"Detected: {label}", 'low',
            f"Check for known CVEs affecting {label}: "
            f"https://www.cvedetails.com/google-search-results.php?q={quote(label)}",
        ))

    meta = _META_GENERATOR_RE.search(body)
    if meta:
        findings.append(_finding(
            url, 'tech_fingerprint', f"Detected via meta generator tag: {meta.group(1)}",
            'low', 'Verbose generator tags help attackers target known CVEs for that version.',
        ))

    return findings


# ---------------------------------------------------------------------- #
# WAF / CDN detection
# ---------------------------------------------------------------------- #
WAF_SIGNATURES = {
    'Cloudflare': {'headers': {'server': 'cloudflare', 'cf-ray': None}, 'cookies': ('__cfduid', 'cf_clearance')},
    'Akamai': {'headers': {'server': 'akamaighost'}, 'cookies': ()},
    'Sucuri': {'headers': {'server': 'sucuri/cloudproxy', 'x-sucuri-id': None}, 'cookies': ()},
    'Imperva Incapsula': {'headers': {'x-iinfo': None}, 'cookies': ('incap_ses', 'visid_incap')},
    'AWS WAF': {'headers': {'x-amzn-waf-action': None}, 'cookies': ('awswaf',)},
    'F5 BIG-IP ASM': {'headers': {'x-wa-info': None}, 'cookies': ('ts', 'big-ip')},
}


def detect_waf(url, headers):
    findings = []
    low_headers = {k.lower(): str(v).lower() for k, v in headers.items()}
    cookie_blob = low_headers.get('set-cookie', '')

    for name, sig in WAF_SIGNATURES.items():
        matched = any(
            hkey in low_headers and (hval is None or hval in low_headers[hkey])
            for hkey, hval in sig['headers'].items()
        )
        if not matched:
            matched = any(cookie_name in cookie_blob for cookie_name in sig['cookies'])
        if matched:
            findings.append(_finding(
                url, 'waf_detected', f"WAF/CDN detected: {name}", 'low',
                'Informational - active probing may be filtered, rate-limited, or logged by this WAF.',
            ))

    return findings


# ---------------------------------------------------------------------- #
# Subdomain enumeration
# ---------------------------------------------------------------------- #
_CRTSH_URL = 'https://crt.sh/'


def enumerate_subdomains_crtsh(session, domain, timeout):
    """Passive subdomain discovery via certificate-transparency logs (crt.sh)."""
    findings = []
    try:
        resp = session.get(_CRTSH_URL, params={'q': f'%.{domain}', 'output': 'json'}, timeout=timeout)
        if resp.status_code != 200:
            return findings
        entries = resp.json()
    except Exception:
        return findings

    found = set()
    for entry in entries if isinstance(entries, list) else []:
        for name in str(entry.get('name_value', '')).split('\n'):
            name = name.strip().lower().lstrip('*.')
            if name and name.endswith(domain) and name != domain:
                found.add(name)

    for name in sorted(found):
        findings.append(_finding(
            f'https://{name}', 'subdomain_found',
            f"Subdomain discovered via certificate transparency: {name}", 'low',
            'Confirm this subdomain is intentionally exposed and receives the same security scrutiny.',
        ))
    return findings


def default_subdomain_wordlist_path():
    return os.path.join(os.path.dirname(__file__), 'wordlists', 'subdomains.txt')


def load_subdomain_wordlist(path=None):
    path = path or default_subdomain_wordlist_path()
    words = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                word = line.strip()
                if word and not word.startswith('#'):
                    words.append(word)
    except Exception:
        pass
    return words


def _resolves(host):
    try:
        dns.resolver.resolve(host, 'A', lifetime=3)
        return True
    except Exception:
        return False


def _has_wildcard_dns(domain):
    """True if the zone resolves *any* subdomain (wildcard A/CNAME record).

    Without this check, a brute-force pass against a wildcard domain would
    report every single wordlist entry as a "discovered" subdomain - a 100%
    false-positive result set that looks like real findings but proves nothing.
    """
    probe = ''.join(random.choices(string.ascii_lowercase + string.digits, k=24))
    return _resolves(f'{probe}.{domain}')


def enumerate_subdomains_bruteforce(domain, wordlist=None, max_threads=20):
    """Active DNS brute-force. No-op (returns []) if dnspython isn't installed
    or the zone uses wildcard DNS (every name would resolve -> unreliable)."""
    findings = []
    if not _HAS_DNSPYTHON:
        return findings
    if _has_wildcard_dns(domain):
        return findings

    words = load_subdomain_wordlist(wordlist)
    found = set()
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(_resolves, f'{word}.{domain}'): word for word in words}
        for future in as_completed(futures):
            word = futures[future]
            try:
                if future.result():
                    found.add(f'{word}.{domain}')
            except Exception:
                continue

    for name in sorted(found):
        findings.append(_finding(
            f'https://{name}', 'subdomain_found',
            f"Subdomain discovered via DNS brute-force: {name}", 'low',
            'Confirm this subdomain is intentionally exposed and receives the same security scrutiny.',
        ))
    return findings


# ---------------------------------------------------------------------- #
# Lightweight port scan
# ---------------------------------------------------------------------- #
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS',
    3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 6379: 'Redis',
    8080: 'HTTP-alt', 8443: 'HTTPS-alt',
}
_SENSITIVE_PORTS = {3306, 3389, 5432, 6379, 23}


def _probe_port(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except Exception:
        return False


def scan_ports(host, ports=None, timeout=1.5, max_threads=20):
    findings = []
    ports = ports or COMMON_PORTS
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(_probe_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if not future.result():
                    continue
            except Exception:
                continue
            service = COMMON_PORTS.get(port, 'unknown')
            confidence = 'medium' if port in _SENSITIVE_PORTS else 'low'
            findings.append(_finding(
                f'{host}:{port}', 'open_port', f"Open port {port} ({service})", confidence,
                'Confirm this service is intentionally exposed to the internet and hardened '
                '(firewalled, patched, strong auth).',
            ))
    return findings


# ---------------------------------------------------------------------- #
# Driver
# ---------------------------------------------------------------------- #
def run_all(session, target, timeout, verify, subdomain_wordlist=None):
    """Run every recon check against the target and return combined findings.

    Network/DNS failures are swallowed per-check so one unreachable check
    never blocks the others.
    """
    findings = []
    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return findings
    domain = host[4:] if host.startswith('www.') else host

    try:
        resp = session.get(target, timeout=timeout, verify=verify, allow_redirects=True)
        findings.extend(fingerprint_tech(resp.url, resp.headers, resp.text))
        findings.extend(detect_waf(resp.url, resp.headers))
    except Exception:
        pass

    findings.extend(enumerate_subdomains_crtsh(session, domain, timeout))
    findings.extend(enumerate_subdomains_bruteforce(domain, subdomain_wordlist))
    findings.extend(scan_ports(host))
    return findings
