"""Unit tests for EnhancedOSCScanner's false-positive filtering and soft-404 logic."""

import types

import pytest


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
def _fake_response(status_code, text):
    resp = types.SimpleNamespace()
    resp.status_code = status_code
    resp.text = text
    resp.content = text.encode('utf-8')
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
