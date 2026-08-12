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


def _finding(url, category, value, confidence, context='', evidence='', informational=False):
    return {
        'url': url,
        'category': category,
        'value': value,
        'confidence': confidence,
        'pattern': 'recon',
        'content_type': '',
        'evidence': evidence,
        'informational': informational,
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
        evidence = f"{header_name}: {haystack.strip()}" if header_name else body[0:120]
        findings.append(_finding(
            url, 'tech_fingerprint', f"Detected: {label}", 'low',
            f"Check for known CVEs affecting {label}: "
            f"https://www.cvedetails.com/google-search-results.php?q={quote(label)}",
            evidence=evidence, informational=True,
        ))

    meta = _META_GENERATOR_RE.search(body)
    if meta:
        findings.append(_finding(
            url, 'tech_fingerprint', f"Detected via meta generator tag: {meta.group(1)}",
            'low', 'Verbose generator tags help attackers target known CVEs for that version.',
            evidence=meta.group(0), informational=True,
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
        header_matched = any(
            hkey in low_headers and (hval is None or hval in low_headers[hkey])
            for hkey, hval in sig['headers'].items()
        )
        matched_cookie_names = [c for c in sig['cookies'] if c in cookie_blob]
        if not (header_matched or matched_cookie_names):
            continue

        evidence_lines = [
            f"{k}: {v}" for k, v in headers.items() if k.lower() in sig['headers']
        ]
        if matched_cookie_names:
            # Only the matched WAF cookie NAME(s), never the raw Set-Cookie
            # header - `requests` merges multiple Set-Cookie headers into one
            # value, so it can carry an unrelated session cookie's live
            # value alongside the WAF's own tracking cookie.
            evidence_lines.append(f"Set-Cookie contains: {', '.join(matched_cookie_names)}")

        findings.append(_finding(
            url, 'waf_detected', f"WAF/CDN detected: {name}", 'low',
            'Informational - active probing may be filtered, rate-limited, or logged by this WAF.',
            evidence='\n'.join(evidence_lines), informational=True,
        ))

    return findings


# ---------------------------------------------------------------------- #
# Subdomain enumeration
# ---------------------------------------------------------------------- #
_CRTSH_URL = 'https://crt.sh/'


def enumerate_subdomains_crtsh(session, domain, timeout, wildcard=False):
    """Passive subdomain discovery via certificate-transparency logs (crt.sh).

    `wildcard` should be True when the zone is known to use wildcard DNS (every
    hostname resolves to the same catch-all host). crt.sh names are real issued
    certificates, not guesses, so they're still reported - but on a wildcard
    zone they'd all crawl down to identical duplicate content, so they're
    flagged in the context/value instead of being silently indistinguishable
    from a non-wildcard finding.
    """
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

    suffix = ' (wildcard DNS zone: likely resolves to the same catch-all host as every other name here)' if wildcard else ''
    for name in sorted(found):
        findings.append(_finding(
            f'https://{name}', 'subdomain_found',
            f"Subdomain discovered via certificate transparency: {name}{suffix}", 'low',
            'Confirm this subdomain is intentionally exposed and receives the same security scrutiny.',
            evidence=name, informational=True,
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


def _resolves_socket(host, timeout=3):
    """Dependency-free fallback DNS check (stdlib only) - used for the
    wildcard-DNS probe when dnspython isn't installed, since that probe also
    guards the crt.sh subdomain source, which never required dnspython."""
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(host)
        return True
    except Exception:
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)


def _has_wildcard_dns(domain):
    """True if the zone resolves *any* subdomain (wildcard A/CNAME record).

    Without this check, a brute-force pass against a wildcard domain would
    report every single wordlist entry as a "discovered" subdomain - a 100%
    false-positive result set that looks like real findings but proves nothing.
    Uses dnspython when available (matches the resolver brute-force uses),
    falling back to stdlib socket resolution otherwise so the crt.sh source
    (which has no dnspython dependency) can still be wildcard-checked.
    """
    probe = ''.join(random.choices(string.ascii_lowercase + string.digits, k=24))
    host = f'{probe}.{domain}'
    return _resolves(host) if _HAS_DNSPYTHON else _resolves_socket(host)


def enumerate_subdomains_bruteforce(domain, wordlist=None, max_threads=20, wildcard=None):
    """Active DNS brute-force. No-op (returns []) if dnspython isn't installed
    or the zone uses wildcard DNS (every name would resolve -> unreliable).
    `wildcard` lets a caller pass an already-computed result (see run_all) to
    avoid probing twice; if None, it's computed here as before."""
    findings = []
    if not _HAS_DNSPYTHON:
        return findings
    if wildcard is None:
        wildcard = _has_wildcard_dns(domain)
    if wildcard:
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
            evidence=name, informational=True,
        ))
    return findings


# ---------------------------------------------------------------------- #
# Lightweight port scan
# ---------------------------------------------------------------------- #
COMMON_PORTS = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 111: 'RPCbind', 135: 'MSRPC', 139: 'NetBIOS-SSN',
    143: 'IMAP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB',
    465: 'SMTPS', 587: 'SMTP-Submission', 993: 'IMAPS', 995: 'POP3S',
    1433: 'MSSQL', 1521: 'Oracle-DB', 2049: 'NFS', 2375: 'Docker-API',
    3000: 'HTTP-dev', 3306: 'MySQL', 3389: 'RDP', 5000: 'HTTP-dev',
    5432: 'PostgreSQL', 5601: 'Kibana', 5900: 'VNC', 5984: 'CouchDB',
    6379: 'Redis', 8000: 'HTTP-alt', 8080: 'HTTP-alt', 8443: 'HTTPS-alt',
    9200: 'Elasticsearch', 9300: 'Elasticsearch-transport', 11211: 'Memcached',
    27017: 'MongoDB',
}
# Ports where an open, internet-facing service is itself the red flag (data
# stores, remote-admin, container/orchestration APIs) - rarely meant to be
# reachable from outside the host/VPC, unlike a plain web port.
_SENSITIVE_PORTS = {
    23, 111, 139, 445, 1433, 1521, 2049, 2375, 3306, 3389,
    5432, 5900, 5984, 6379, 9200, 9300, 11211, 27017,
}
# Ports where the service is expected to speak HTTP, so a minimal HEAD
# request (rather than just listening for an unsolicited banner) is the way
# to get a Server header back.
_HTTP_LIKE_PORTS = {80, 443, 3000, 5000, 8000, 8080, 8443, 5601, 9200}
_BANNER_READ_BYTES = 512


def _probe_port(host, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0
    except Exception:
        return False


def _grab_banner(host, port, timeout):
    """Best-effort, read-only service banner for an already-open port.

    For HTTP-like ports, sends a minimal HEAD request and reads back the
    Server header. For everything else, just recv()s whatever the service
    sends unprompted immediately after the TCP handshake - SSH, FTP, SMTP,
    POP3, IMAP, MySQL and friends all greet first. No protocol-specific
    commands or credentials are ever sent, so this stays purely passive,
    same risk profile as the TCP connect scan_ports already does.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            sock.connect((host, port))
            if port in _HTTP_LIKE_PORTS:
                sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            data = sock.recv(_BANNER_READ_BYTES)
    except Exception:
        return ''
    if not data:
        return ''
    text = data.decode('utf-8', errors='replace')
    if port in _HTTP_LIKE_PORTS:
        for line in text.splitlines():
            if line.lower().startswith('server:'):
                return line.split(':', 1)[1].strip()
        return ''
    first_line = next((ln.strip() for ln in text.splitlines() if ln.strip()), '')
    return first_line[:200]


def scan_ports(host, ports=None, timeout=1.5, max_threads=20, grab_banners=True):
    ports = ports or COMMON_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(_probe_port, host, port, timeout): port for port in ports}
        for future in as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                continue

    banners = {}
    if grab_banners and open_ports:
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(_grab_banner, host, port, timeout): port for port in open_ports}
            for future in as_completed(futures):
                port = futures[future]
                try:
                    banners[port] = future.result()
                except Exception:
                    banners[port] = ''

    findings = []
    for port in open_ports:
        service = COMMON_PORTS.get(port, 'unknown')
        confidence = 'medium' if port in _SENSITIVE_PORTS else 'low'
        # Standard web ports (80/443) being open is expected for any public site:
        # informational, not a finding that should move the risk needle.
        informational = port in (80, 443)
        banner = banners.get(port, '')
        value = f"Open port {port} ({service})"
        evidence = f"TCP connect to {host}:{port} succeeded"
        context = ('Confirm this service is intentionally exposed to the internet and hardened '
                   '(firewalled, patched, strong auth).')
        if banner:
            value += f" - banner: {banner}"
            evidence += f"\nBanner: {banner}"
            context += (f" Check for known CVEs affecting this banner: "
                        f"https://www.cvedetails.com/google-search-results.php?q={quote(banner)}")
        findings.append(_finding(
            f'{host}:{port}', 'open_port', value, confidence, context,
            evidence=evidence, informational=informational,
        ))
    return findings


# ---------------------------------------------------------------------- #
# Driver
# ---------------------------------------------------------------------- #
def run_all(session, target, timeout, verify, subdomain_wordlist=None, ports=None):
    """Run every recon check against the target and return combined findings.

    Network/DNS failures are swallowed per-check so one unreachable check
    never blocks the others. `ports` overrides the default COMMON_PORTS scan
    list (see --ports).
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

    wildcard = _has_wildcard_dns(domain)
    findings.extend(enumerate_subdomains_crtsh(session, domain, timeout, wildcard=wildcard))
    findings.extend(enumerate_subdomains_bruteforce(domain, subdomain_wordlist, wildcard=wildcard))
    findings.extend(scan_ports(host, ports=ports))
    return findings
