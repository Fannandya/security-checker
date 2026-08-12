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


# ---------------------------------------------------------------------- #
# enumerate_subdomains_bruteforce (dnspython optional)
# ---------------------------------------------------------------------- #
def test_enumerate_subdomains_bruteforce_noop_without_dnspython(monkeypatch):
    monkeypatch.setattr(recon, '_HAS_DNSPYTHON', False)
    assert recon.enumerate_subdomains_bruteforce('example.test') == []


# ---------------------------------------------------------------------- #
# scan_ports
# ---------------------------------------------------------------------- #
def test_scan_ports_reports_open_ports(monkeypatch):
    def fake_probe(host, port, timeout):
        return port == 443

    monkeypatch.setattr(recon, '_probe_port', fake_probe)
    findings = recon.scan_ports('example.test', ports=[80, 443, 3306])
    values = {f['value'] for f in findings}
    assert len(findings) == 1
    assert any('443' in v for v in values)


def test_scan_ports_flags_sensitive_ports_medium_confidence(monkeypatch):
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: port == 3306)
    findings = recon.scan_ports('example.test', ports=[3306])
    assert findings[0]['confidence'] == 'medium'


def test_scan_ports_no_open_ports(monkeypatch):
    monkeypatch.setattr(recon, '_probe_port', lambda host, port, timeout: False)
    assert recon.scan_ports('example.test', ports=[80, 443]) == []


def test_probe_port_returns_false_on_connection_error():
    # Port 1 on a name that won't resolve should fail closed, not raise.
    assert recon._probe_port('this-host-should-not-resolve.invalid', 1, 0.5) is False
