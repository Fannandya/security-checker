"""Unit tests for osc/reporting.py output writers."""

import csv
import json

from osc import reporting


def test_write_json_roundtrips_report(tmp_path, sample_report):
    out = tmp_path / 'report.json'
    reporting.write_json(sample_report, str(out))
    loaded = json.loads(out.read_text(encoding='utf-8'))
    assert loaded['summary']['total_findings'] == 1
    assert loaded['findings'][0]['category'] == 'api_keys'


def test_write_json_handles_bad_path_without_raising(tmp_path):
    bad_path = str(tmp_path / 'nonexistent_dir' / 'report.json')
    # Should not raise - errors are caught and printed internally.
    reporting.write_json({'a': 1}, bad_path)


def test_write_csv_contains_header_and_rows(tmp_path, sample_report):
    out = tmp_path / 'report.csv'
    reporting.write_csv(sample_report, str(out))
    with open(out, newline='', encoding='utf-8') as fh:
        rows = list(csv.reader(fh))
    assert rows[0] == ['cwe_id', 'category', 'confidence', 'risk', 'url', 'value',
                       'content_type', 'status_code', 'pattern', 'context',
                       'evidence', 'informational', 'remediation']
    assert rows[1][0] == 'CWE-798'
    assert rows[1][1] == 'api_keys'
    assert rows[1][3] == 'HIGH'  # risk level looked up from RISK_LEVELS


def test_write_csv_empty_findings(tmp_path):
    out = tmp_path / 'empty.csv'
    reporting.write_csv({'findings': []}, str(out))
    with open(out, newline='', encoding='utf-8') as fh:
        rows = list(csv.reader(fh))
    assert len(rows) == 1  # header only


def test_write_csv_includes_evidence_and_informational(tmp_path, sample_finding):
    sample_finding = dict(sample_finding)
    sample_finding['evidence'] = 'Server: nginx'
    sample_finding['informational'] = True
    report = {
        'summary': {'category_counts': {'api_keys': 1}},
        'findings': [sample_finding],
    }
    out = tmp_path / 'report.csv'
    reporting.write_csv(report, str(out))
    with open(out, newline='', encoding='utf-8') as fh:
        rows = list(csv.reader(fh))
    assert rows[1][10] == 'Server: nginx'
    assert rows[1][11] == 'yes'


def test_write_html_embeds_target_and_findings(tmp_path, sample_report):
    out = tmp_path / 'report.html'
    reporting.write_html(sample_report, str(out))
    content = out.read_text(encoding='utf-8')
    assert 'https://example.test' in content
    assert 'api_keys' in content
    assert 'HIGH RISK' in content


def test_write_html_escapes_finding_values(tmp_path, sample_report):
    sample_report['findings'][0]['value'] = '<script>alert(1)</script>'
    sample_report['summary']['findings_by_category']['api_keys'][0]['value'] = '<script>alert(1)</script>'
    out = tmp_path / 'xss.html'
    reporting.write_html(sample_report, str(out))
    content = out.read_text(encoding='utf-8')
    assert '<script>alert(1)</script>' not in content
    assert '&lt;script&gt;' in content


def test_write_html_critical_risk_has_distinct_badge_color(tmp_path, sample_report):
    # Regression: _RISK_HEX had no 'CRITICAL' entry, so a CRITICAL verdict
    # rendered the same gray badge as 'NONE' (no risk found at all).
    sample_report['summary']['risk_assessment'] = 'CRITICAL'
    out = tmp_path / 'critical.html'
    reporting.write_html(sample_report, str(out))
    content = out.read_text(encoding='utf-8')
    assert reporting._RISK_HEX['CRITICAL'] in content
    assert reporting._RISK_HEX['CRITICAL'] != reporting._RISK_HEX['NONE']


def test_write_html_empty_remediation_renders_em_dash_not_escaped_entity(tmp_path, sample_report):
    # Regression: the Remediation column's "&mdash;" fallback was inside
    # esc(), so it got double-escaped and rendered as the literal text
    # "&amp;mdash;" instead of an em dash, unlike the Evidence column's
    # identical fallback (which was correctly outside esc()).
    sample_report['findings'][0]['remediation'] = ''
    sample_report['findings'][0]['context'] = ''
    out = tmp_path / 'report.html'
    reporting.write_html(sample_report, str(out))
    content = out.read_text(encoding='utf-8')
    assert '&amp;mdash;' not in content
    assert '&mdash;' in content


def test_write_html_no_findings_placeholder(tmp_path):
    empty_report = {
        'scan_info': {'target': 'https://example.test'},
        'summary': {'total_findings': 0, 'category_counts': {}, 'risk_assessment': 'NONE'},
        'findings': [],
    }
    out = tmp_path / 'empty.html'
    reporting.write_html(empty_report, str(out))
    content = out.read_text(encoding='utf-8')
    assert 'No findings' in content


def test_write_html_includes_evidence_and_scope(tmp_path, sample_report):
    sample_report['scan_info']['scope_and_limitations'] = [
        'Active vulnerability probing (-X) was DISABLED.',
    ]
    sample_report['scan_info']['reproducibility'] = {'command': 'osc --verify https://x'}
    sample_report['findings'][0]['evidence'] = 'Header: value'
    sample_report['findings'][0]['informational'] = True
    out = tmp_path / 'report.html'
    reporting.write_html(sample_report, str(out))
    content = out.read_text(encoding='utf-8')
    assert 'Header: value' in content
    assert 'Active vulnerability probing (-X) was DISABLED.' in content
    assert 'osc --verify https://x' in content
    assert 'Scope &amp; Limitations' in content
    # Regression: reproducibility/scope_and_limitations used to also be
    # dumped as raw Python repr text into the generic Scan Information table
    # (e.g. "{&#x27;command&#x27;: ...}") in addition to their own sections.
    assert content.count('osc --verify https://x') == 1
    assert '{&#x27;command&#x27;' not in content
    assert "{'command'" not in content
