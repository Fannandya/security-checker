"""Web security posture checks: HTTP security headers, cookie flags, CORS
misconfiguration, risky HTTP methods, and TLS/certificate health.

Every check here is read-only / non-destructive and adds at most one extra
request (or one raw TLS handshake) against the target — safe for authorized
security testing. Findings are plain dicts shaped like scanner findings so
they flow straight through the existing report pipeline (JSON/HTML/CSV).
"""

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

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


def run_all(session, target, timeout, verify):
    """Run every audit check against the target root and return combined findings.

    Fetches the target once (for headers/cookies), then runs the CORS, HTTP
    method, and TLS probes. Network failures are swallowed per-check so one
    unreachable check never blocks the others.
    """
    findings = []
    try:
        resp = session.get(target, timeout=timeout, verify=verify, allow_redirects=True)
        findings.extend(audit_security_headers(resp.url, resp.headers))
        findings.extend(audit_cookies(resp.url, resp))
    except Exception:
        pass

    findings.extend(check_cors(session, target, timeout, verify))
    findings.extend(check_http_methods(session, target, timeout, verify))
    findings.extend(check_tls(target, timeout))
    return findings
