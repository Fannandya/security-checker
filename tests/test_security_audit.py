"""Unit tests for osc/security_audit.py using mocked HTTP (no real network)."""

import requests
import responses

from osc import security_audit


# ---------------------------------------------------------------------- #
# audit_security_headers
# ---------------------------------------------------------------------- #
def test_audit_security_headers_flags_all_missing_on_https():
    findings = security_audit.audit_security_headers('https://example.test/', {})
    categories = {f['value'] for f in findings if f['category'] == 'security_headers'}
    assert any('Strict-Transport-Security' in c for c in categories)
    assert any('Content-Security-Policy' in c for c in categories)
    assert any('X-Frame-Options' in c for c in categories)


def test_audit_security_headers_skips_hsts_on_http():
    findings = security_audit.audit_security_headers('http://example.test/', {})
    assert not any('Strict-Transport-Security' in f['value'] for f in findings)


def test_audit_security_headers_no_findings_when_all_present():
    headers = {
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'",
        'X-Frame-Options': 'DENY',
        'X-Content-Type-Options': 'nosniff',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=()',
    }
    findings = security_audit.audit_security_headers('https://example.test/', headers)
    assert not any(f['category'] == 'security_headers' for f in findings)


def test_audit_security_headers_csp_frame_ancestors_satisfies_xfo():
    headers = {'Content-Security-Policy': "frame-ancestors 'none'"}
    findings = security_audit.audit_security_headers('https://example.test/', headers)
    assert not any('X-Frame-Options' in f['value'] for f in findings)


def test_audit_security_headers_flags_server_banner():
    headers = {'Server': 'nginx/1.18.0'}
    findings = security_audit.audit_security_headers('https://example.test/', headers)
    assert any(f['category'] == 'tech_fingerprint' and 'nginx/1.18.0' in f['value']
               for f in findings)


# ---------------------------------------------------------------------- #
# audit_cookies
# ---------------------------------------------------------------------- #
@responses.activate
def test_audit_cookies_flags_missing_flags():
    responses.add(
        responses.GET, 'https://example.test/',
        body='ok', status=200,
        headers=[('Set-Cookie', 'sessionid=abc123; Path=/')],
    )
    resp = requests.get('https://example.test/')
    findings = security_audit.audit_cookies('https://example.test/', resp)
    assert len(findings) == 1
    assert "sessionid" in findings[0]['value']
    assert 'Secure' in findings[0]['value']
    assert 'HttpOnly' in findings[0]['value']
    assert 'SameSite' in findings[0]['value']


@responses.activate
def test_audit_cookies_no_findings_when_fully_flagged():
    responses.add(
        responses.GET, 'https://example.test/',
        body='ok', status=200,
        headers=[('Set-Cookie', 'sessionid=abc123; Secure; HttpOnly; SameSite=Strict')],
    )
    resp = requests.get('https://example.test/')
    findings = security_audit.audit_cookies('https://example.test/', resp)
    assert findings == []


# ---------------------------------------------------------------------- #
# check_cors
# ---------------------------------------------------------------------- #
@responses.activate
def test_check_cors_flags_wildcard_with_credentials():
    responses.add(
        responses.GET, 'https://example.test/',
        body='ok', status=200,
        headers={'Access-Control-Allow-Origin': '*',
                 'Access-Control-Allow-Credentials': 'true'},
    )
    session = requests.Session()
    findings = security_audit.check_cors(session, 'https://example.test/', 5, False)
    assert len(findings) == 1
    assert findings[0]['confidence'] == 'high'
    assert 'wildcard' in findings[0]['value'].lower() or '*' in findings[0]['value']


@responses.activate
def test_check_cors_flags_origin_reflection():
    def cors_callback(request):
        origin = request.headers.get('Origin', '')
        return (200, {'Access-Control-Allow-Origin': origin}, 'ok')

    responses.add_callback(responses.GET, 'https://example.test/', callback=cors_callback)
    session = requests.Session()
    findings = security_audit.check_cors(session, 'https://example.test/', 5, False)
    assert len(findings) == 1
    assert 'reflects arbitrary Origin' in findings[0]['value']


@responses.activate
def test_check_cors_no_findings_when_locked_down():
    responses.add(
        responses.GET, 'https://example.test/',
        body='ok', status=200,
        headers={'Access-Control-Allow-Origin': 'https://trusted.example.test'},
    )
    session = requests.Session()
    findings = security_audit.check_cors(session, 'https://example.test/', 5, False)
    assert findings == []


# ---------------------------------------------------------------------- #
# check_http_methods
# ---------------------------------------------------------------------- #
@responses.activate
def test_check_http_methods_flags_risky_methods():
    responses.add(
        responses.OPTIONS, 'https://example.test/',
        body='', status=200,
        headers={'Allow': 'GET, POST, PUT, DELETE, TRACE'},
    )
    session = requests.Session()
    findings = security_audit.check_http_methods(session, 'https://example.test/', 5, False)
    assert len(findings) == 1
    assert 'PUT' in findings[0]['value']
    assert 'DELETE' in findings[0]['value']
    assert 'TRACE' in findings[0]['value']


@responses.activate
def test_check_http_methods_no_findings_for_safe_methods():
    responses.add(
        responses.OPTIONS, 'https://example.test/',
        body='', status=200,
        headers={'Allow': 'GET, POST, HEAD, OPTIONS'},
    )
    session = requests.Session()
    findings = security_audit.check_http_methods(session, 'https://example.test/', 5, False)
    assert findings == []


# ---------------------------------------------------------------------- #
# check_tls
# ---------------------------------------------------------------------- #
def test_check_tls_skips_non_https_targets():
    assert security_audit.check_tls('http://example.test/', timeout=1) == []


# ---------------------------------------------------------------------- #
# audit_mixed_content
# ---------------------------------------------------------------------- #
def test_audit_mixed_content_flags_http_script_on_https_page():
    html = '<html><head><script src="http://cdn.example.net/lib.js"></script></head></html>'
    findings = security_audit.audit_mixed_content('https://example.test/', html)
    assert len(findings) == 1
    assert 'http://cdn.example.net/lib.js' in findings[0]['value']


def test_audit_mixed_content_ignores_https_resources():
    html = '<script src="https://cdn.example.net/lib.js"></script>'
    assert security_audit.audit_mixed_content('https://example.test/', html) == []


def test_audit_mixed_content_skips_http_pages():
    html = '<script src="http://cdn.example.net/lib.js"></script>'
    assert security_audit.audit_mixed_content('http://example.test/', html) == []


# ---------------------------------------------------------------------- #
# audit_missing_sri
# ---------------------------------------------------------------------- #
def test_audit_missing_sri_flags_cross_origin_script_without_integrity():
    html = '<script src="https://cdn.example.net/lib.js"></script>'
    findings = security_audit.audit_missing_sri('https://example.test/', html)
    assert len(findings) == 1
    assert findings[0]['category'] == 'sri_missing'


def test_audit_missing_sri_ignores_script_with_integrity():
    html = ('<script src="https://cdn.example.net/lib.js" '
            'integrity="sha384-abc123" crossorigin="anonymous"></script>')
    assert security_audit.audit_missing_sri('https://example.test/', html) == []


def test_audit_missing_sri_ignores_same_origin_resources():
    html = '<script src="https://example.test/static/app.js"></script>'
    assert security_audit.audit_missing_sri('https://example.test/', html) == []


# ---------------------------------------------------------------------- #
# check_security_txt
# ---------------------------------------------------------------------- #
@responses.activate
def test_check_security_txt_no_finding_when_present():
    responses.add(
        responses.GET, 'https://example.test/.well-known/security.txt',
        body='Contact: mailto:security@example.test\nExpires: 2027-01-01T00:00:00Z',
        status=200,
    )
    session = requests.Session()
    findings = security_audit.check_security_txt(session, 'https://example.test', 5, False)
    assert findings == []


@responses.activate
def test_check_security_txt_flags_when_missing():
    responses.add(responses.GET, 'https://example.test/.well-known/security.txt',
                   body='Not Found', status=404)
    responses.add(responses.GET, 'https://example.test/security.txt',
                   body='Not Found', status=404)
    session = requests.Session()
    findings = security_audit.check_security_txt(session, 'https://example.test', 5, False)
    assert len(findings) == 1
    assert findings[0]['category'] == 'security_txt_missing'


# ---------------------------------------------------------------------- #
# check_graphql_introspection
# ---------------------------------------------------------------------- #
@responses.activate
def test_check_graphql_introspection_flags_enabled_schema():
    responses.add(
        responses.POST, 'https://example.test/graphql',
        json={'data': {'__schema': {'queryType': {'name': 'Query'}}}},
        status=200,
    )
    session = requests.Session()
    findings = security_audit.check_graphql_introspection(session, 'https://example.test', 5, False)
    assert len(findings) == 1
    assert findings[0]['category'] == 'graphql_introspection'


@responses.activate
def test_check_graphql_introspection_no_finding_when_disabled():
    responses.add(
        responses.POST, 'https://example.test/graphql',
        json={'errors': [{'message': 'introspection disabled'}]},
        status=200,
    )
    responses.add(responses.POST, 'https://example.test/api/graphql', status=404)
    responses.add(responses.POST, 'https://example.test/v1/graphql', status=404)
    session = requests.Session()
    findings = security_audit.check_graphql_introspection(session, 'https://example.test', 5, False)
    assert findings == []


@responses.activate
def test_check_graphql_introspection_no_finding_when_no_endpoint():
    for path in ('/graphql', '/api/graphql', '/v1/graphql'):
        responses.add(responses.POST, f'https://example.test{path}', status=404)
    session = requests.Session()
    findings = security_audit.check_graphql_introspection(session, 'https://example.test', 5, False)
    assert findings == []
