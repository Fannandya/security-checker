"""Unit tests for EnhancedOSCScanner's false-positive filtering and soft-404 logic."""

import types

import pytest

from osc.scanner import EnhancedOSCScanner


# ---------------------------------------------------------------------- #
# is_valid_finding
# ---------------------------------------------------------------------- #
@pytest.mark.parametrize('category, value', [
    ('api_keys', 'password'),
    ('api_keys', 'changeme'),
    ('api_keys', 'your_api_key_here'),
    ('passwords', 'example'),
    ('tokens', 'placeholder'),
])
def test_is_valid_finding_rejects_placeholders(scanner, category, value):
    assert scanner.is_valid_finding(category, value, 'https://example.test/x') is False


def test_is_valid_finding_rejects_low_entropy_generic_secret(scanner):
    # No known prefix, long enough, but low-entropy (repetitive) - should be rejected.
    assert scanner.is_valid_finding('api_keys', 'aaaaaaaaaaaaaaaaaaaa', 'https://x') is False


def test_is_valid_finding_accepts_known_prefix_regardless_of_entropy(scanner):
    value = 'AKIAIOSFODNN7EXAMPLE'
    assert scanner.is_valid_finding('api_keys', value, 'https://x') is True


def test_is_valid_finding_accepts_high_entropy_generic_secret(scanner):
    value = 'zXk93jQpLm2Rvt8Ns0Yc7Wb'
    assert scanner.is_valid_finding('api_keys', value, 'https://x') is True


def test_is_valid_finding_email_rejects_asset_urls(scanner):
    assert scanner.is_valid_finding('emails', 'icon@2x.png', 'https://x/icon@2x.png') is False


def test_is_valid_finding_email_accepts_real_address(scanner):
    assert scanner.is_valid_finding('emails', 'security@acmecorp.test', 'https://x/contact') is True


def test_is_valid_finding_passwords_length_bounds(scanner):
    assert scanner.is_valid_finding('passwords', 'ab', 'https://x') is False
    assert scanner.is_valid_finding('passwords', 'x' * 65, 'https://x') is False
    assert scanner.is_valid_finding('passwords', 'S3cur3P@ss', 'https://x') is True


def test_is_valid_finding_rejects_empty(scanner):
    assert scanner.is_valid_finding('api_keys', '', 'https://x') is False
    assert scanner.is_valid_finding('api_keys', None, 'https://x') is False


# ---------------------------------------------------------------------- #
# sanitize_value
# ---------------------------------------------------------------------- #
def test_sanitize_value_truncates_long_values(scanner):
    long_value = 'a' * 150
    result = scanner.sanitize_value(long_value)
    assert result.endswith('...')
    assert len(result) == 103  # 100 chars + '...'


def test_sanitize_value_strips_whitespace(scanner):
    assert scanner.sanitize_value('  secret123  ') == 'secret123'


# ---------------------------------------------------------------------- #
# Soft-404 / baseline fingerprinting
# ---------------------------------------------------------------------- #
def _fake_response(status_code, text, url='https://example.test/x'):
    resp = types.SimpleNamespace()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode('utf-8')
    resp.url = url
    resp.history = []
    resp.headers = {'content-type': 'text/html'}
    return resp


def test_is_soft_404_false_without_baseline(scanner):
    resp = _fake_response(404, '<html>Not Found</html>')
    assert scanner._is_soft_404(resp) is False


def test_is_soft_404_matches_identical_catchall_page(scanner):
    catchall = ('<html><body><h1>404 Not Found</h1><p>The requested path was not '
                'found on this server. Reference: 482910</p></body></html>')
    scanner.baseline = [{
        'status': 200,
        'length': len(catchall.encode('utf-8')),
        'fp': scanner._fingerprint(catchall),
        'body': catchall[:2000],
    }]
    # Only the numeric reference id differs - _fingerprint normalizes digits,
    # so this should match via the exact-fingerprint path.
    resp = _fake_response(200, catchall.replace('482910', '119933'))
    assert scanner._is_soft_404(resp) is True


# ---------------------------------------------------------------------- #
# scan_url must not report catch-all content as per-path findings
# ---------------------------------------------------------------------- #
def test_scan_url_skips_content_analysis_on_soft404(scanner):
    catchall = ('<html><body><h1>Site</h1>admin@example.test '
                '<script src="http://cdn.example.net/x.js"></script></body></html>')
    scanner.baseline = [{
        'status': 200,
        'length': len(catchall.encode('utf-8')),
        'fp': scanner._fingerprint(catchall),
        'body': catchall[:2000],
    }]

    analyzed = []
    scanner.analyze_content = lambda url, text, ctype: analyzed.append(url)

    def fake_get(url, **kwargs):
        return _fake_response(200, catchall, url=url)

    scanner.session.get = fake_get
    scanner.scan_url('https://example.test/Dockerfile.backup')
    assert analyzed == []                      # content analysis skipped
    assert scanner.found_sensitive_data == []  # nothing falsely reported


def test_scan_url_analyzes_content_on_real_page(scanner):
    real = '<html><body>Welcome. Contact: admin@example.test</body></html>'
    scanner.baseline = [{
        'status': 200,
        'length': len(real.encode('utf-8')),
        'fp': scanner._fingerprint(real),
        'body': real[:2000],
    }]

    analyzed = []
    scanner.analyze_content = lambda url, text, ctype: analyzed.append(url)

    def fake_get(url, **kwargs):
        # A genuinely different page must not be treated as the catch-all.
        page = '<html><body>Distinct login page content here.</body></html>'
        return _fake_response(200, page, url=url)

    scanner.session.get = fake_get
    scanner.scan_url('https://example.test/login')
    assert analyzed == ['https://example.test/login']


def test_scan_url_still_extracts_links_on_soft404(scanner):
    # Regression: a soft-404 match used to also suppress link extraction, so a
    # client-rendered SPA that serves the same shell for every route (a real,
    # in-scope page - not a guessed nonexistent path) would silently stop the
    # crawler from discovering anything past the first matched page. Content
    # scanning should still be suppressed; crawling must not be.
    catchall = ('<html><body><h1>Site</h1>'
                '<a href="https://example.test/dashboard">Dashboard</a></body></html>')
    scanner.baseline = [{
        'status': 200,
        'length': len(catchall.encode('utf-8')),
        'fp': scanner._fingerprint(catchall),
        'body': catchall[:2000],
    }]
    scanner.depth = 1
    scanner.crawl = True

    analyzed = []
    scanner.analyze_content = lambda url, text, ctype: analyzed.append(url)

    def fake_get(url, **kwargs):
        return _fake_response(200, catchall, url=url)

    scanner.session.get = fake_get
    links = scanner.scan_url('https://example.test/')
    assert analyzed == []                                        # content scan still skipped
    assert 'https://example.test/dashboard' in links              # but crawling continues


def test_check_sensitive_file_by_url_accepts_precomputed_soft404(scanner):
    # Regression: scan_url() and check_sensitive_file_by_url() used to each run
    # their own independent (and identical) difflib soft-404 comparison for
    # every scanned URL. Passing the value scan_url() already computed avoids
    # redoing that work; assert it's actually honored (not recomputed).
    def boom(response):
        raise AssertionError('_is_soft_404 should not be called when is_soft_404 is given')

    scanner._is_soft_404 = boom
    resp = _fake_response(200, '<html>whatever</html>')
    scanner.check_sensitive_file_by_url('https://example.test/.env', resp, is_soft_404=True)
    assert scanner.found_sensitive_data == []


def test_is_soft_404_does_not_match_real_content(scanner):
    catchall = '<html><body>Nothing here at all</body></html>'
    scanner.baseline = [{
        'status': 200,
        'length': len(catchall.encode('utf-8')),
        'fp': scanner._fingerprint(catchall),
        'body': catchall[:2000],
    }]
    real_page = '<html><body>' + ('Real unique product content. ' * 20) + '</body></html>'
    resp = _fake_response(200, real_page)
    assert scanner._is_soft_404(resp) is False


def test_fingerprint_normalizes_numbers_and_whitespace(scanner):
    a = scanner._fingerprint('Error 404: page   not found')
    b = scanner._fingerprint('Error 999: page not\nfound')
    assert a == b


def test_fingerprint_none_for_empty_text(scanner):
    assert scanner._fingerprint('') is None
    assert scanner._fingerprint(None) is None


# ---------------------------------------------------------------------- #
# _add_finding dedup
# ---------------------------------------------------------------------- #
def test_add_finding_deduplicates(scanner, sample_finding):
    assert scanner._add_finding(dict(sample_finding)) is True
    assert scanner._add_finding(dict(sample_finding)) is False
    assert len(scanner.found_sensitive_data) == 1


def test_add_finding_distinct_urls_not_deduplicated(scanner, sample_finding):
    other = dict(sample_finding)
    other['url'] = 'https://example.test/other-leak.env'
    assert scanner._add_finding(dict(sample_finding)) is True
    assert scanner._add_finding(other) is True
    assert len(scanner.found_sensitive_data) == 2


def test_add_finding_fills_remediation_for_secret_categories(scanner, sample_finding):
    # Regression: scanner.py's own secret/file findings (api_keys, passwords,
    # database, ...) never set `remediation`, so reports fell back to
    # `context` (a matched code snippet, or nothing) instead of fix guidance -
    # for the tool's core secret-leak findings.
    finding = dict(sample_finding)
    assert 'remediation' not in finding
    scanner._add_finding(finding)
    assert 'rotate' in scanner.found_sensitive_data[0]['remediation'].lower()


def test_add_finding_fills_remediation_for_directory_listing_and_open_redirect(scanner):
    # Regression: these two scanner-native categories were missing from
    # REMEDIATION_ADVICE (and their own `context` is empty/evidence-only), so
    # findings shipped with completely empty remediation text.
    scanner._add_finding({
        'url': 'https://example.test/uploads/', 'category': 'directory_listing',
        'value': 'Directory listing (autoindex) is enabled', 'confidence': 'high',
        'pattern': 'directory_listing', 'content_type': 'text/html', 'context': '',
    })
    scanner._add_finding({
        'url': 'https://example.test/go?next=evil.test', 'category': 'open_redirect',
        'value': "Parameter 'next' steers redirect to external host: evil.test",
        'confidence': 'medium', 'pattern': 'redirect_chain', 'content_type': '',
        'context': 'https://example.test/go?next=evil.test -> https://evil.test',
    })
    by_category = {f['category']: f for f in scanner.found_sensitive_data}
    assert by_category['directory_listing']['remediation']
    assert by_category['open_redirect']['remediation']


def test_add_finding_fills_cwe_id_for_scanner_findings(scanner, sample_finding):
    # Regression: JSON reports promised a `cwe_id` per finding, but only
    # security_audit findings set one - scanner/recon/active_scan findings
    # flowed through without it, so JSON consumers got an inconsistent schema
    # (CSV/HTML compensated via CWE_MAPPINGS lookup, JSON did not).
    finding = dict(sample_finding)
    assert 'cwe_id' not in finding
    scanner._add_finding(finding)
    assert scanner.found_sensitive_data[0]['cwe_id'] == 'CWE-798'  # api_keys


def test_add_finding_does_not_override_explicit_remediation(scanner, sample_finding):
    finding = dict(sample_finding)
    finding['remediation'] = 'Custom advice from the check that created this finding.'
    scanner._add_finding(finding)
    assert scanner.found_sensitive_data[0]['remediation'] == \
        'Custom advice from the check that created this finding.'


# ---------------------------------------------------------------------- #
# _same_scope
# ---------------------------------------------------------------------- #
def test_same_scope_matches_host_and_www(scanner):
    assert scanner._same_scope('https://example.test/page') is True
    assert scanner._same_scope('https://www.example.test/page') is True


def test_same_scope_rejects_other_hosts(scanner):
    assert scanner._same_scope('https://evil.test/page') is False


def test_same_scope_matches_subdomains(scanner):
    assert scanner._same_scope('https://api.example.test/page') is True


# ---------------------------------------------------------------------- #
# assess_overall_risk (weighted)
# ---------------------------------------------------------------------- #
def test_assess_overall_risk_ignores_informational_findings(scanner):
    grouped = {
        'open_port': [
            {'category': 'open_port', 'confidence': 'low', 'informational': True},
            {'category': 'open_port', 'confidence': 'low', 'informational': True},
        ],
    }
    assert scanner.assess_overall_risk(grouped) == 'NONE'


def test_assess_overall_risk_weights_actionable_findings(scanner):
    grouped = {
        'security_headers': [{'category': 'security_headers', 'confidence': 'medium'}],
    }
    # medium risk (2) x medium confidence (0.7) = 1.4 -> LOW
    assert scanner.assess_overall_risk(grouped) == 'LOW'


def test_assess_overall_risk_high_for_severe_findings(scanner):
    grouped = {
        'cors_misconfiguration': [
            {'category': 'cors_misconfiguration', 'confidence': 'high'},
            {'category': 'cors_misconfiguration', 'confidence': 'high'},
        ],
    }
    # 2 x (3 x 1.0) = 6 -> HIGH
    assert scanner.assess_overall_risk(grouped) == 'HIGH'


def test_assess_overall_risk_floors_low_confidence_high_category_at_medium(scanner):
    # Regression: a HIGH-risk-category finding used to be able to round all
    # the way down to LOW when reported at low confidence (e.g. a custom
    # finding merged in by a library caller), silently losing the old
    # guarantee that any HIGH-risk category kept the overall verdict elevated.
    grouped = {
        'private_keys': [{'category': 'private_keys', 'confidence': 'low'}],
    }
    # score = 3 (HIGH) x 1 x 0.4 (low) = 1.2, which alone would be 'LOW'
    assert scanner.assess_overall_risk(grouped) == 'MEDIUM'


# ---------------------------------------------------------------------- #
# generate_report metadata
# ---------------------------------------------------------------------- #
def test_generate_report_has_reproducibility_and_scope(scanner, sample_finding):
    scanner.found_sensitive_data = [dict(sample_finding)]
    scanner.cli_command = 'osc https://example.test --verify'
    report = scanner.generate_report()
    repro = report['scan_info']['reproducibility']
    assert repro['command'] == 'osc https://example.test --verify'
    assert 'python' in repro
    assert repro['tls_verify'] is False
    assert report['scan_info']['scope_and_limitations']  # non-empty list
    assert report['summary']['actionable_findings'] == 1
    assert report['summary']['informational_findings'] == 0


def test_generate_report_counts_informational(scanner):
    base = {'category': 'open_port', 'confidence': 'low', 'informational': True,
            'value': 'Open port 80 (HTTP)', 'url': 'example.test:80'}
    scanner.found_sensitive_data = [dict(base), dict(base)]
    report = scanner.generate_report()
    assert report['summary']['informational_findings'] == 2
    assert report['summary']['actionable_findings'] == 0


def test_generate_report_scope_mentions_disabled_active_scan(scanner):
    assert any('Active vulnerability probing' in lim
               for lim in scanner._scope_limitations())


def test_print_summary_report_has_distinct_color_for_critical(scanner, capsys):
    # Regression: assess_overall_risk() can return 'CRITICAL', but the color
    # lookup used to only have HIGH/MEDIUM/LOW/NONE entries, so a CRITICAL
    # verdict silently fell back to the same white used for a clean scan.
    from colorama import Style
    scanner.assess_overall_risk = lambda grouped: 'CRITICAL'
    scanner.print_summary_report()
    out = capsys.readouterr().out
    critical_line = next(line for line in out.splitlines() if 'CRITICAL RISK' in line)
    assert Style.BRIGHT in critical_line


def test_scope_limitations_passive_disclaimer_present_when_only_recon_ran():
    # Regression: the "findings are passive observations" disclaimer used to
    # be gated on `not skip_audit` alone, so it silently disappeared with
    # --skip-audit even though recon (ports/banners/WAF/fingerprint - also
    # passive) still ran and still produced unconfirmed findings.
    s = EnhancedOSCScanner('https://example.test', max_threads=2, timeout=1, depth=0,
                            skip_audit=True, recon=True)
    assert any('passive/config observations' in lim for lim in s._scope_limitations())


def test_scope_limitations_passive_disclaimer_absent_when_nothing_passive_ran():
    s = EnhancedOSCScanner('https://example.test', max_threads=2, timeout=1, depth=0,
                            skip_audit=True, recon=False)
    assert not any('passive/config observations' in lim for lim in s._scope_limitations())


def test_scope_limitations_passive_disclaimer_absent_when_active_probing_ran():
    # Regression: with -X enabled some findings ARE confirmed exploits (XSS/
    # SQLi/traversal), but the disclaimer claimed "none are confirmed exploits"
    # whenever audit or recon ran simply because those run by default.
    s = EnhancedOSCScanner('https://example.test', max_threads=2, timeout=1, depth=0,
                            skip_audit=True, recon=True, active=True)
    assert not any('passive/config observations' in lim for lim in s._scope_limitations())
