"""Unit tests for osc/recon.py (subdomain enum, port scan, fingerprint, WAF)."""

import socket

import requests
import responses

from osc import recon


# ---------------------------------------------------------------------- #
# fingerprint_tech
# ---------------------------------------------------------------------- #
def test_fingerprint_tech_detects_server_header():
    findings = recon.fingerprint_tech('https://example.test/', {'Server': 'nginx/1.18.0'}, '')
    assert any('nginx' in f['value'].lower() and '1.18.0' in f['value'] for f in findings)


def test_fingerprint_tech_detects_wordpress_from_html():
    html = '<link rel="stylesheet" href="/wp-content/themes/x/style.css">'
    findings = recon.fingerprint_tech('https://example.test/', {}, html)
    assert any('WordPress' in f['value'] for f in findings)


def test_fingerprint_tech_detects_meta_generator():
    html = '<meta name="generator" content="Joomla! 4.2">'
    findings = recon.fingerprint_tech('https://example.test/', {}, html)
    assert any('Joomla! 4.2' in f['value'] for f in findings)


def test_fingerprint_tech_no_findings_for_empty_input():
    assert recon.fingerprint_tech('https://example.test/', {}, '') == []


def test_fingerprint_tech_does_not_duplicate_same_product():
    html = 'wp-content wp-content wp-content wp-includes'
    findings = recon.fingerprint_tech('https://example.test/', {}, html)
    wp_findings = [f for f in findings if 'WordPress' in f['value']]
    assert len(wp_findings) == 1


# ---------------------------------------------------------------------- #
# detect_waf
# ---------------------------------------------------------------------- #
def test_detect_waf_cloudflare_via_header():
    findings = recon.detect_waf('https://example.test/', {'Server': 'cloudflare', 'CF-RAY': 'abc123'})
    assert any('Cloudflare' in f['value'] for f in findings)


def test_detect_waf_incapsula_via_header():
    findings = recon.detect_waf('https://example.test/', {'X-Iinfo': '1-abc'})
    assert any('Incapsula' in f['value'] for f in findings)


def test_detect_waf_no_match_for_plain_server():
    findings = recon.detect_waf('https://example.test/', {'Server': 'nginx/1.18.0'})
    assert findings == []


def test_detect_waf_cookie_match_does_not_leak_unrelated_session_value():
    # Regression: evidence used to embed the raw Set-Cookie header, which
    # `requests` merges into one comma-joined value for multiple Set-Cookie
    # headers - a WAF match on __cfduid could carry an unrelated app session
    # cookie's live value along with it.
    findings = recon.detect_waf('https://example.test/', {
        'Set-Cookie': '__cfduid=abc123def; Path=/, PHPSESSID=super-secret-session-abc123; Path=/',
    })
    assert any('Cloudflare' in f['value'] for f in findings)
    cf_finding = next(f for f in findings if 'Cloudflare' in f['value'])
    assert 'super-secret-session-abc123' not in cf_finding['evidence']
    assert '__cfduid' in cf_finding['evidence']


# ---------------------------------------------------------------------- #
# enumerate_subdomains_crtsh
# ---------------------------------------------------------------------- #
@responses.activate
def test_enumerate_subdomains_crtsh_parses_entries():
    responses.add(
        responses.GET, 'https://crt.sh/',
        json=[
            {'name_value': 'api.example.test\nwww.example.test'},
            {'name_value': '*.staging.example.test'},
        ],
        status=200,
    )
    session = requests.Session()
    findings = recon.enumerate_subdomains_crtsh(session, 'example.test', 5)
    names = {f['value'].rsplit(': ', 1)[-1] for f in findings}
    assert 'api.example.test' in names
    assert 'www.example.test' in names
    assert 'staging.example.test' in names
    assert 'example.test' not in names  # apex domain itself must be excluded


@responses.activate
def test_enumerate_subdomains_crtsh_handles_non_200():
    responses.add(responses.GET, 'https://crt.sh/', status=503)
    session = requests.Session()
    assert recon.enumerate_subdomains_crtsh(session, 'example.test', 5) == []


@responses.activate
def test_enumerate_subdomains_crtsh_handles_malformed_json():
    responses.add(responses.GET, 'https://crt.sh/', body='not json', status=200,
                   content_type='application/json')
    session = requests.Session()
    assert recon.enumerate_subdomains_crtsh(session, 'example.test', 5) == []


@responses.activate
def test_enumerate_subdomains_crtsh_flags_wildcard_domain():
    # Regression: crt.sh results used to carry no wildcard-DNS signal at all,
    # unlike the brute-force source, even though both feed the same crawl queue.
    responses.add(
        responses.GET, 'https://crt.sh/',
        json=[{'name_value': 'api.example.test'}],
        status=200,
    )
    session = requests.Session()
    findings = recon.enumerate_subdomains_crtsh(session, 'example.test', 5, wildcard=True)
    assert len(findings) == 1
    assert 'wildcard' in findings[0]['value'].lower()
    assert findings[0]['informational'] is True


# ---------------------------------------------------------------------- #
# enumerate_subdomains_bruteforce (dnspython optional)
# ---------------------------------------------------------------------- #
def test_enumerate_subdomains_bruteforce_noop_without_dnspython(monkeypatch):
    monkeypatch.setattr(recon, '_HAS_DNSPYTHON', False)
    assert recon.enumerate_subdomains_bruteforce('example.test') == []


def test_enumerate_subdomains_bruteforce_skips_dns_probe_when_wildcard_precomputed(monkeypatch):
    monkeypatch.setattr(recon, '_HAS_DNSPYTHON', True)

    def fail_if_called(domain):
        raise AssertionError('_has_wildcard_dns should not be called when wildcard is precomputed')

    monkeypatch.setattr(recon, '_has_wildcard_dns', fail_if_called)
    assert recon.enumerate_subdomains_bruteforce('example.test', wildcard=True) == []


# ---------------------------------------------------------------------- #
# _has_wildcard_dns (dnspython optional, falls back to stdlib socket)
# ---------------------------------------------------------------------- #
def test_has_wildcard_dns_uses_socket_fallback_without_dnspython(monkeypatch):
    monkeypatch.setattr(recon, '_HAS_DNSPYTHON', False)
    monkeypatch.setattr(recon.socket, 'gethostbyname', lambda host: '1.2.3.4')
    assert recon._has_wildcard_dns('example.test') is True


def test_has_wildcard_dns_socket_fallback_false_on_nxdomain(monkeypatch):
    monkeypatch.setattr(recon, '_HAS_DNSPYTHON', False)

    def raise_nxdomain(host):
        raise socket.gaierror('nxdomain')

    monkeypatch.setattr(recon.socket, 'gethostbyname', raise_nxdomain)
    assert recon._has_wildcard_dns('example.test') is False


# ---------------------------------------------------------------------- #
# run_all: wildcard-DNS status must be computed once and shared by both
# subdomain sources (crt.sh and brute-force)
# ---------------------------------------------------------------------- #
@responses.activate
def test_run_all_passes_wildcard_flag_to_both_subdomain_sources(monkeypatch):
    responses.add(responses.GET, 'https://example.test', body='<html></html>', status=200)
    responses.add(responses.GET, 'https://crt.sh/', json=[], status=200)
    monkeypatch.setattr(recon, '_has_wildcard_dns', lambda domain: True)
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: False)

    seen = {}

    def fake_crtsh(session, domain, timeout, wildcard=False):
        seen['crtsh'] = wildcard
        return []

    def fake_bruteforce(domain, wordlist=None, max_threads=20, wildcard=None):
        seen['bruteforce'] = wildcard
        return []

    monkeypatch.setattr(recon, 'enumerate_subdomains_crtsh', fake_crtsh)
    monkeypatch.setattr(recon, 'enumerate_subdomains_bruteforce', fake_bruteforce)

    session = requests.Session()
    recon.run_all(session, 'https://example.test', 5, False)

    assert seen == {'crtsh': True, 'bruteforce': True}


@responses.activate
def test_run_all_passes_custom_ports_to_scan_ports(monkeypatch):
    responses.add(responses.GET, 'https://example.test', body='<html></html>', status=200)
    responses.add(responses.GET, 'https://crt.sh/', json=[], status=200)
    monkeypatch.setattr(recon, '_has_wildcard_dns', lambda domain: False)
    monkeypatch.setattr(recon, 'enumerate_subdomains_bruteforce', lambda *a, **kw: [])

    seen = {}

    def fake_scan_ports(host, ports=None, **kw):
        seen['ports'] = ports
        return []

    monkeypatch.setattr(recon, 'scan_ports', fake_scan_ports)

    session = requests.Session()
    recon.run_all(session, 'https://example.test', 5, False, ports=[22, 8080])

    assert seen['ports'] == [22, 8080]


# ---------------------------------------------------------------------- #
# scan_ports
# ---------------------------------------------------------------------- #
def test_scan_ports_reports_open_ports(monkeypatch):
    def fake_probe(host, port, timeout):
        return port == 443

    monkeypatch.setattr(recon, '_probe_port', fake_probe)
    findings = recon.scan_ports('example.test', ports=[80, 443, 3306], grab_banners=False)
    values = {f['value'] for f in findings}
    assert len(findings) == 1
    assert any('443' in v for v in values)


def test_scan_ports_flags_sensitive_ports_medium_confidence(monkeypatch):
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: port == 3306)
    findings = recon.scan_ports('example.test', ports=[3306], grab_banners=False)
    assert findings[0]['confidence'] == 'medium'


def test_scan_ports_no_open_ports(monkeypatch):
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: False)
    assert recon.scan_ports('example.test', ports=[80, 443], grab_banners=False) == []


def test_scan_ports_default_list_covers_common_infra_services(monkeypatch):
    # Regression: the original ~15-port default missed a lot of classic
    # "should never be internet-facing" services (Docker API, Elasticsearch,
    # MongoDB, Memcached, CouchDB, SMB, NFS, MSSQL, Oracle) - a scan against
    # the default list should actually be able to find them.
    for port in (2375, 9200, 27017, 11211, 5984, 445, 2049, 1433, 1521):
        assert port in recon.COMMON_PORTS
        assert port in recon._SENSITIVE_PORTS


def test_probe_port_returns_false_on_connection_error():
    # Port 1 on a name that won't resolve should fail closed, not raise.
    assert recon._probe_port('this-host-should-not-resolve.invalid', 1, 0.5) is False


def test_port_scan_reliable_when_canary_ports_are_closed(monkeypatch):
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: False)
    assert recon._port_scan_reliable('example.test', 0.5) is True


def test_port_scan_unreliable_when_canary_port_is_open(monkeypatch):
    # A transparent proxy/VPN/firewall that accepts every TCP connection makes
    # a random unassigned high port come back "open" too - that's the signal
    # the scan can't be trusted, not that the target listens on it.
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: True)
    assert recon._port_scan_reliable('example.test', 0.5) is False


def test_scan_ports_skips_open_port_findings_when_scan_is_unreliable(monkeypatch):
    # Every port "open", including ones never passed in - simulates a
    # middlebox that intercepts all connections instead of a real scan.
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: True)
    findings = recon.scan_ports('example.test', ports=[80, 443, 3306], grab_banners=False)
    assert len(findings) == 1
    assert findings[0]['category'] == 'port_scan_unreliable'
    assert findings[0]['informational'] is True
    assert not any(f['category'] == 'open_port' for f in findings)


# ---------------------------------------------------------------------- #
# _grab_banner / banner enrichment in scan_ports
# ---------------------------------------------------------------------- #
def test_grab_banner_reads_unsolicited_banner_for_non_http_port(monkeypatch):
    class FakeSocket:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def recv(self, n):
            return b'SSH-2.0-OpenSSH_7.4\r\n'

    monkeypatch.setattr(recon.socket, 'socket', lambda *a, **kw: FakeSocket())
    banner = recon._grab_banner('example.test', 22, 1.5)
    assert banner == 'SSH-2.0-OpenSSH_7.4'


def test_grab_banner_sends_head_request_for_http_like_port(monkeypatch):
    sent = []

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def settimeout(self, t):
            pass

        def connect(self, addr):
            pass

        def sendall(self, data):
            sent.append(data)

        def recv(self, n):
            return b'HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n'

    monkeypatch.setattr(recon.socket, 'socket', lambda *a, **kw: FakeSocket())
    banner = recon._grab_banner('example.test', 80, 1.5)
    assert banner == 'nginx/1.18.0'
    assert sent and b'HEAD / HTTP/1.0' in sent[0]


def test_grab_banner_returns_empty_on_no_data_or_error(monkeypatch):
    monkeypatch.setattr(recon.socket, 'socket',
                         lambda *a, **kw: (_ for _ in ()).throw(OSError('refused')))
    assert recon._grab_banner('example.test', 22, 1.5) == ''


def test_scan_ports_enriches_finding_with_banner(monkeypatch):
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: port == 22)
    monkeypatch.setattr(recon, '_grab_banner', lambda host, port, timeout: 'SSH-2.0-OpenSSH_7.4')
    findings = recon.scan_ports('example.test', ports=[22], grab_banners=True)
    assert len(findings) == 1
    assert 'SSH-2.0-OpenSSH_7.4' in findings[0]['value']
    assert 'SSH-2.0-OpenSSH_7.4' in findings[0]['evidence']
    assert 'cvedetails.com' in findings[0]['context']


def test_scan_ports_grab_banners_false_skips_banner_lookup(monkeypatch):
    def boom(host, port, timeout):
        raise AssertionError('_grab_banner should not be called when grab_banners=False')

    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: True)
    monkeypatch.setattr(recon, '_grab_banner', boom)
    findings = recon.scan_ports('example.test', ports=[22], grab_banners=False)
    assert len(findings) == 1
    assert 'banner' not in findings[0]['value'].lower()
