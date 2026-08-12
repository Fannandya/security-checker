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
    assert rows[0] == ['category', 'confidence', 'risk', 'url', 'value',
                        'content_type', 'status_code', 'pattern', 'context']
    assert rows[1][0] == 'api_keys'
    assert rows[1][2] == 'HIGH'  # risk level looked up from RISK_LEVELS


def test_write_csv_empty_findings(tmp_path):
    out = tmp_path / 'empty.csv'
    reporting.write_csv({'findings': []}, str(out))
    with open(out, newline='', encoding='utf-8') as fh:
        rows = list(csv.reader(fh))
    assert len(rows) == 1  # header only


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
