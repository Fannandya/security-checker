"""Unit tests for osc/active_scan.py (opt-in active vulnerability probing)."""

from urllib.parse import parse_qs, urlparse

import requests
import responses

from osc import active_scan


# ---------------------------------------------------------------------- #
# _urls_with_params / _build_url
# ---------------------------------------------------------------------- #
def test_urls_with_params_skips_urls_without_query():
    urls = ['https://example.test/', 'https://example.test/search?q=hello']
    results = list(active_scan._urls_with_params(urls))
    assert len(results) == 1
    assert results[0][0] == 'https://example.test/search?q=hello'


def test_build_url_replaces_only_target_param():
    from urllib.parse import parse_qsl, urlsplit
    parts = urlsplit('https://example.test/search?q=hello&page=2')
    pairs = parse_qsl(parts.query)
    new_url = active_scan._build_url(parts, pairs, 0, 'PAYLOAD')
    parsed = urlparse(new_url)
    q = parse_qs(parsed.query)
    assert q['q'] == ['PAYLOAD']
    assert q['page'] == ['2']


# ---------------------------------------------------------------------- #
# Reflected XSS
# ---------------------------------------------------------------------- #
@responses.activate
def test_run_all_detects_reflected_xss():
    def callback(request):
        query = parse_qs(urlparse(request.url).query)
        value = query.get('q', [''])[0]
        return (200, {}, f'<html>Results for: {value}</html>')

    responses.add_callback(responses.GET, 'https://example.test/search', callback=callback)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/search?q=hello'], timeout=5, verify=False,
        checks=('xss',),
    )
    assert len(findings) == 1
    assert findings[0]['category'] == 'xss_reflected'


@responses.activate
def test_run_all_no_xss_finding_when_escaped():
    def callback(request):
        query = parse_qs(urlparse(request.url).query)
        value = query.get('q', [''])[0]
        escaped = value.replace('<', '&lt;').replace('>', '&gt;')
        return (200, {}, f'<html>Results for: {escaped}</html>')

    responses.add_callback(responses.GET, 'https://example.test/search', callback=callback)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/search?q=hello'], timeout=5, verify=False,
        checks=('xss',),
    )
    assert findings == []


# ---------------------------------------------------------------------- #
# SQL injection (error-based)
# ---------------------------------------------------------------------- #
@responses.activate
def test_run_all_detects_sql_error():
    def callback(request):
        query = parse_qs(urlparse(request.url).query)
        value = query.get('id', [''])[0]
        if "'" in value:
            return (500, {}, 'Warning: mysqli_fetch_array() expects parameter 1 to be mysqli_result')
        return (200, {}, '<html>Item 42</html>')

    responses.add_callback(responses.GET, 'https://example.test/item', callback=callback)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/item?id=42'], timeout=5, verify=False,
        checks=('sqli',),
    )
    assert len(findings) == 1
    assert findings[0]['category'] == 'sqli_error'


@responses.activate
def test_run_all_no_sqli_finding_when_error_already_in_baseline():
    # Server always returns a SQL-error-shaped page regardless of input -
    # should not be flagged since it's present in the baseline too.
    responses.add(responses.GET, 'https://example.test/item',
                   body='you have an error in your sql syntax', status=200)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/item?id=42'], timeout=5, verify=False,
        checks=('sqli',),
    )
    assert findings == []


# ---------------------------------------------------------------------- #
# Path traversal / LFI
# ---------------------------------------------------------------------- #
@responses.activate
def test_run_all_detects_path_traversal():
    def callback(request):
        query = parse_qs(urlparse(request.url).query)
        value = query.get('file', [''])[0]
        if 'etc/passwd' in value:
            return (200, {}, 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin')
        return (200, {}, '<html>report.pdf</html>')

    responses.add_callback(responses.GET, 'https://example.test/download', callback=callback)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/download?file=report.pdf'], timeout=5, verify=False,
        checks=('traversal',),
    )
    assert len(findings) == 1
    assert findings[0]['category'] == 'path_traversal'


@responses.activate
def test_run_all_skips_traversal_for_non_file_params():
    responses.add(responses.GET, 'https://example.test/search',
                   body='root:x:0:0:root:/root:/bin/bash', status=200)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/search?q=hello'], timeout=5, verify=False,
        checks=('traversal',),
    )
    assert findings == []


# ---------------------------------------------------------------------- #
# SSTI
# ---------------------------------------------------------------------- #
@responses.activate
def test_run_all_detects_ssti():
    def callback(request):
        query = parse_qs(urlparse(request.url).query)
        value = query.get('name', [''])[0]
        try:
            result = eval(value.strip('{}$#'))  # noqa: S307 - test-only, controlled input
            return (200, {}, f'<html>Hello {result}</html>')
        except Exception:
            return (200, {}, f'<html>Hello {value}</html>')

    responses.add_callback(responses.GET, 'https://example.test/greet', callback=callback)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/greet?name=world'], timeout=5, verify=False,
        checks=('ssti',),
    )
    assert len(findings) == 1
    assert findings[0]['category'] == 'ssti'


@responses.activate
def test_run_all_no_ssti_finding_when_payload_echoed_raw():
    def callback(request):
        query = parse_qs(urlparse(request.url).query)
        value = query.get('name', [''])[0]
        return (200, {}, f'<html>Hello {value}</html>')  # not evaluated, just echoed

    responses.add_callback(responses.GET, 'https://example.test/greet', callback=callback)
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/greet?name=world'], timeout=5, verify=False,
        checks=('ssti',),
    )
    assert findings == []


# ---------------------------------------------------------------------- #
# SSRF candidate heuristic (no requests made)
# ---------------------------------------------------------------------- #
def test_check_ssrf_candidate_flags_known_param_names():
    finding = active_scan._check_ssrf_candidate(
        'https://example.test/fetch?url=https://internal', [('url', 'https://internal')], 0)
    assert finding is not None
    assert finding['category'] == 'ssrf_candidate'
    assert finding['confidence'] == 'low'


def test_check_ssrf_candidate_ignores_unrelated_params():
    finding = active_scan._check_ssrf_candidate(
        'https://example.test/search?q=hello', [('q', 'hello')], 0)
    assert finding is None


@responses.activate
def test_run_all_ssrf_check_makes_no_requests():
    session = requests.Session()
    findings = active_scan.run_all(
        session, ['https://example.test/fetch?url=https://internal.example'],
        timeout=5, verify=False, checks=('ssrf',),
    )
    assert len(findings) == 1
    assert findings[0]['category'] == 'ssrf_candidate'


# ---------------------------------------------------------------------- #
# run_all general behavior
# ---------------------------------------------------------------------- #
def test_run_all_returns_empty_for_urls_without_query_params():
    session = requests.Session()
    findings = active_scan.run_all(session, ['https://example.test/'], timeout=5, verify=False)
    assert findings == []


def test_run_all_default_checks_is_all_categories():
    assert set(active_scan.ALL_CHECKS) == {'xss', 'sqli', 'traversal', 'ssti', 'ssrf'}
