"""Web security posture checks: HTTP security headers, cookie flags, CORS
misconfiguration, risky HTTP methods, and TLS/certificate health.

Every check here is read-only / non-destructive and adds at most one extra
request (or one raw TLS handshake) against the target — safe for authorized
security testing. Findings are plain dicts shaped like scanner findings so
they flow straight through the existing report pipeline (JSON/HTML/CSV).
"""

import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

# Headers whose *absence* is itself the finding.
_REQUIRED_HEADERS = {
    'strict-transport-security': {
        'label': 'Strict-Transport-Security (HSTS)',
        'advice': 'Set "Strict-Transport-Security: max-age=31536000; includeSubDomains" to force HTTPS and stop downgrade/sslstrip attacks.',
        'https_only': True,
    },
    'content-security-policy': {
        'label': 'Content-Security-Policy',
        'advice': 'Define a CSP to restrict script/style/frame sources and mitigate XSS and data-injection attacks.',
    },
    'x-frame-options': {
        'label': 'X-Frame-Options',
        'advice': 'Set "X-Frame-Options: DENY" or "SAMEORIGIN" (or a CSP frame-ancestors directive) to prevent clickjacking.',
        'csp_alt': 'frame-ancestors',
    },
    'x-content-type-options': {
        'label': 'X-Content-Type-Options',
        'advice': 'Set "X-Content-Type-Options: nosniff" to stop browsers from MIME-sniffing responses into executable types.',
    },
    'referrer-policy': {
        'label': 'Referrer-Policy',
        'advice': 'Set a Referrer-Policy (e.g. "strict-origin-when-cross-origin") to avoid leaking full URLs to third parties.',
    },
    'permissions-policy': {
        'label': 'Permissions-Policy',
        'advice': 'Set a Permissions-Policy to restrict access to sensitive browser features (camera, geolocation, etc.).',
    },
}

_RISKY_METHODS = {'PUT', 'DELETE', 'TRACE', 'TRACK', 'CONNECT'}
_WEAK_TLS_VERSIONS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}


def _finding(url, category, value, confidence, context=''):
    return {
        'url': url,
        'category': category,
        'value': value,
        'confidence': confidence,
        'pattern': 'security_audit',
        'content_type': '',
        'context': context,
    }


# ---------------------------------------------------------------------- #
# HTTP security headers
# ---------------------------------------------------------------------- #
def audit_security_headers(url, headers):
    findings = []
    low = {k.lower(): v for k, v in headers.items()}
    is_https = urlparse(url).scheme == 'https'
    csp = low.get('content-security-policy', '').lower()

    for key, meta in _REQUIRED_HEADERS.items():
        if meta.get('https_only') and not is_https:
            continue
        if key in low:
            continue
        if meta.get('csp_alt') and meta['csp_alt'] in csp:
            continue
        findings.append(_finding(
            url, 'security_headers', f"Missing header: {meta['label']}",
            'medium', meta['advice'],
        ))

    xcto = low.get('x-content-type-options', '').strip().lower()
    if xcto and xcto != 'nosniff':
        findings.append(_finding(
            url, 'security_headers', f"Weak X-Content-Type-Options value: {xcto!r}",
            'low', 'Expected exactly "nosniff".',
        ))

    for hdr in ('server', 'x-powered-by'):
        val = low.get(hdr)
        if val:
            findings.append(_finding(
                url, 'tech_fingerprint', f"{hdr.title()}: {val}", 'low',
                'Verbose version banners help attackers target known CVEs; consider suppressing them.',
            ))

    return findings


# ---------------------------------------------------------------------- #
# Cookie flags
# ---------------------------------------------------------------------- #
def audit_cookies(url, response):
    findings = []
    try:
        raw_cookies = response.raw.headers.get_all('Set-Cookie') or []
    except Exception:
        sc = response.headers.get('Set-Cookie')
        raw_cookies = [sc] if sc else []

    is_https = urlparse(url).scheme == 'https'
    for raw in raw_cookies:
        name = raw.split('=', 1)[0].strip()
        low = raw.lower()
        missing = []
        if is_https and 'secure' not in low:
            missing.append('Secure')
        if 'httponly' not in low:
            missing.append('HttpOnly')
        if 'samesite' not in low:
            missing.append('SameSite')
        if missing:
            findings.append(_finding(
                url, 'cookie_security',
                f"Cookie '{name}' missing flag(s): {', '.join(missing)}",
                'medium' if 'Secure' in missing or 'HttpOnly' in missing else 'low',
                'Cookies without Secure/HttpOnly/SameSite are exposed to theft over unencrypted '
                'links, JS-based (XSS) access, or cross-site request forgery.',
            ))
    return findings


# ---------------------------------------------------------------------- #
# CORS misconfiguration
# ---------------------------------------------------------------------- #
def check_cors(session, target, timeout, verify):
    findings = []
    probe_origin = 'https://osc-cors-probe.invalid'
    try:
        resp = session.get(target, headers={'Origin': probe_origin},
                            timeout=timeout, verify=verify, allow_redirects=True)
    except Exception:
        return findings

    acao = resp.headers.get('Access-Control-Allow-Origin', '')
    acac = resp.headers.get('Access-Control-Allow-Credentials', '').strip().lower() == 'true'

    if acao == '*' and acac:
        findings.append(_finding(
            target, 'cors_misconfiguration',
            'CORS: Access-Control-Allow-Origin=* combined with Access-Control-Allow-Credentials=true',
            'high',
            'This combination is invalid per spec but signals a misconfigured CORS policy; '
            'browsers that honor it would leak credentialed responses to any origin.',
        ))
    elif acao == probe_origin:
        findings.append(_finding(
            target, 'cors_misconfiguration',
            f"CORS: server reflects arbitrary Origin header back ({probe_origin})",
            'high' if acac else 'medium',
            'Reflecting any Origin (optionally with credentials) lets any external site '
            'read authenticated responses via cross-origin requests.',
        ))
    return findings


# ---------------------------------------------------------------------- #
# HTTP method enumeration
# ---------------------------------------------------------------------- #
def check_http_methods(session, target, timeout, verify):
    findings = []
    try:
        resp = session.request('OPTIONS', target, timeout=timeout, verify=verify)
    except Exception:
        return findings

    allow = resp.headers.get('Allow') or resp.headers.get('Access-Control-Allow-Methods') or ''
    methods = {m.strip().upper() for m in allow.split(',') if m.strip()}
    risky = sorted(methods & _RISKY_METHODS)
    if risky:
        findings.append(_finding(
            target, 'http_methods', f"Potentially risky HTTP methods enabled: {', '.join(risky)}",
            'medium', f"Advertised via Allow: {allow}",
        ))
    return findings


# ---------------------------------------------------------------------- #
# TLS / certificate health
# ---------------------------------------------------------------------- #
def check_tls(target, timeout=10):
    findings = []
    parsed = urlparse(target)
    if parsed.scheme != 'https':
        return findings
    host = parsed.hostname
    if not host:
        return findings
    port = parsed.port or 443

    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
    except ssl.SSLCertVerificationError as exc:
        findings.append(_finding(
            target, 'tls_issues', f"TLS certificate validation failed: {exc.verify_message}",
            'high', str(exc),
        ))
        return findings
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        return findings
    except Exception:
        return findings

    if proto in _WEAK_TLS_VERSIONS:
        findings.append(_finding(
            target, 'tls_issues', f"Weak TLS protocol negotiated: {proto}",
            'high', 'Disable legacy protocols and only allow TLS 1.2+.',
        ))

    not_after = cert.get('notAfter') if cert else None
    if not_after:
        try:
            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                findings.append(_finding(
                    target, 'tls_issues', f"TLS certificate expired {-days_left} day(s) ago",
                    'high', f"notAfter: {not_after}",
                ))
            elif days_left <= 14:
                findings.append(_finding(
                    target, 'tls_issues', f"TLS certificate expires in {days_left} day(s)",
                    'medium', f"notAfter: {not_after}",
                ))
        except Exception:
            pass

    return findings


# ---------------------------------------------------------------------- #
# Mixed content & missing Subresource Integrity (SRI)
#
# Both are derived from HTML the crawler already fetched - no extra
# requests - so they're called directly from scanner.analyze_content for
# every crawled page, the same way directory-listing detection is.
# ---------------------------------------------------------------------- #
_RESOURCE_TAG_RE = re.compile(
    r'<(script|link)\b([^>]*?)\b(?:src|href)\s*=\s*["\']'
    r'(https?://[^"\']+)["\']([^>]*)>',
    re.IGNORECASE,
)


def audit_mixed_content(url, html_content):
    findings = []
    if urlparse(url).scheme != 'https':
        return findings
    seen = set()
    for tag, _before, resource_url, _after in _RESOURCE_TAG_RE.findall(html_content):
        if not resource_url.lower().startswith('http://') or resource_url in seen:
            continue
        seen.add(resource_url)
        findings.append(_finding(
            url, 'mixed_content',
            f"Insecure <{tag.lower()}> resource loaded over HTTP on an HTTPS page: {resource_url}",
            'medium',
            'Loading subresources over plain HTTP on an HTTPS page exposes them to '
            'tampering or injection by a network attacker; switch to HTTPS.',
        ))
    return findings


def audit_missing_sri(url, html_content):
    findings = []
    base_host = urlparse(url).netloc.lower()
    seen = set()
    for tag, before, resource_url, after in _RESOURCE_TAG_RE.findall(html_content):
        resource_host = urlparse(resource_url).netloc.lower()
        if not resource_host or resource_host == base_host or resource_url in seen:
            continue
        if 'integrity=' in (before + after).lower():
            continue
        seen.add(resource_url)
        findings.append(_finding(
            url, 'sri_missing',
            f"Cross-origin <{tag.lower()}> without Subresource Integrity: {resource_url}",
            'low',
            'Add an integrity="sha384-..." attribute (and crossorigin="anonymous") so the '
            'browser refuses the resource if the third-party host is compromised or tampered with.',
        ))
    return findings


# ---------------------------------------------------------------------- #
# security.txt presence (RFC 9116)
# ---------------------------------------------------------------------- #
_SECURITY_TXT_PATHS = ('/.well-known/security.txt', '/security.txt')


def check_security_txt(session, target, timeout, verify):
    for path in _SECURITY_TXT_PATHS:
        try:
            url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
            resp = session.get(url, timeout=timeout, verify=verify, allow_redirects=True)
            if resp.status_code == 200 and resp.text.strip():
                return []
        except Exception:
            continue
    return [_finding(
        target, 'security_txt_missing',
        'No security.txt found at /.well-known/security.txt or /security.txt',
        'low',
        'Publish a security.txt (RFC 9116) so researchers know how to report '
        'vulnerabilities responsibly.',
    )]


# ---------------------------------------------------------------------- #
# GraphQL introspection
# ---------------------------------------------------------------------- #
_GRAPHQL_INTROSPECTION_QUERY = {'query': '{__schema{queryType{name}}}'}
_GRAPHQL_PATHS = ('/graphql', '/api/graphql', '/v1/graphql')


def check_graphql_introspection(session, target, timeout, verify):
    for path in _GRAPHQL_PATHS:
        url = urljoin(target.rstrip('/') + '/', path.lstrip('/'))
        try:
            resp = session.post(url, json=_GRAPHQL_INTROSPECTION_QUERY,
                                 timeout=timeout, verify=verify)
        except Exception:
            continue
        if resp.status_code != 200:
            continue
        try:
            data = resp.json()
        except Exception:
            continue
        if isinstance(data, dict) and (data.get('data') or {}).get('__schema'):
            return [_finding(
                url, 'graphql_introspection',
                'GraphQL introspection is enabled, exposing the full API schema',
                'high',
                'Disable introspection in production (e.g. Apollo Server: '
                '"introspection: false"; graphql-ruby: "schema.introspection = false") '
                'to avoid leaking the entire API surface to attackers.',
            )]
    return []


def run_all(session, target, timeout, verify):
    """Run every audit check against the target root and return combined findings.

    Fetches the target once (for headers/cookies/mixed-content/SRI on the
    root page), then runs the CORS, HTTP method, TLS, security.txt, and
    GraphQL introspection probes. Network failures are swallowed per-check
    so one unreachable check never blocks the others.
    """
    findings = []
    try:
        resp = session.get(target, timeout=timeout, verify=verify, allow_redirects=True)
        findings.extend(audit_security_headers(resp.url, resp.headers))
        findings.extend(audit_cookies(resp.url, resp))
        if 'text/html' in resp.headers.get('content-type', '').lower():
            findings.extend(audit_mixed_content(resp.url, resp.text))
            findings.extend(audit_missing_sri(resp.url, resp.text))
    except Exception:
        pass

    findings.extend(check_cors(session, target, timeout, verify))
    findings.extend(check_http_methods(session, target, timeout, verify))
    findings.extend(check_tls(target, timeout))
    findings.extend(check_security_txt(session, target, timeout, verify))
    findings.extend(check_graphql_introspection(session, target, timeout, verify))
    return findings
