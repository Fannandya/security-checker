"""Unit tests for osc/cli.py output-path resolution (-o format auto-detect),
reproducibility-command redaction, and --ports parsing."""

import pytest

from osc.cli import parse_ports, redacted_command, resolve_output_paths


# ---------------------------------------------------------------------- #
# parse_ports
# ---------------------------------------------------------------------- #
def test_parse_ports_none_when_not_given():
    assert parse_ports(None) is None
    assert parse_ports('') is None


def test_parse_ports_parses_comma_separated_list():
    assert parse_ports('21,22,80,443') == [21, 22, 80, 443]


def test_parse_ports_strips_whitespace():
    assert parse_ports(' 22 , 80 , 443 ') == [22, 80, 443]


def test_parse_ports_raises_on_non_numeric_entry():
    with pytest.raises(ValueError):
        parse_ports('22,not-a-port,443')


# ---------------------------------------------------------------------- #
# redacted_command
#
# Redaction is driven by the already-parsed args.session VALUE (not by
# pattern-matching argv tokens for "-s"/"--session" spellings), so every form
# argparse accepts is covered without having to reimplement its short-option
# clustering rules.
# ---------------------------------------------------------------------- #
def test_redacted_command_masks_short_session_flag_value():
    # Regression: the reproducibility.command field used to record the raw
    # session cookie verbatim (a live credential) into the JSON/HTML report.
    cmd = redacted_command(['https://example.test', '-s', 'PHPSESSID=supersecret'],
                            session_value='PHPSESSID=supersecret')
    assert 'supersecret' not in cmd
    assert '-s <REDACTED>' in cmd


def test_redacted_command_masks_long_session_flag_value():
    cmd = redacted_command(['https://example.test', '--session', 'name=abc123secret'],
                            session_value='name=abc123secret')
    assert 'abc123secret' not in cmd
    assert '--session <REDACTED>' in cmd


def test_redacted_command_masks_inline_session_equals_form():
    cmd = redacted_command(['https://example.test', '--session=abc123secret'],
                            session_value='abc123secret')
    assert 'abc123secret' not in cmd
    assert '--session=<REDACTED>' in cmd


def test_redacted_command_masks_attached_short_session_flag():
    # argparse accepts "-sVALUE" as a combined form.
    cmd = redacted_command(['https://example.test', '-ssupersecret'],
                            session_value='supersecret')
    assert 'supersecret' not in cmd
    assert '-s<REDACTED>' in cmd


def test_redacted_command_masks_short_equals_form():
    # argparse also accepts "-s=VALUE".
    cmd = redacted_command(['https://example.test', '-s=supersecret'],
                            session_value='supersecret')
    assert 'supersecret' not in cmd
    assert '-s=<REDACTED>' in cmd


def test_redacted_command_masks_clustered_short_flags():
    # Regression: argparse clusters boolean short flags with a value-taking
    # one (e.g. "-vs VALUE" = "-v -s VALUE"). A token-pattern redactor that
    # only recognized tokens starting with "-s" missed "-vs" entirely and
    # leaked the cookie verbatim.
    cmd = redacted_command(['https://example.test', '-vs', 'PHPSESSID=supersecret'],
                            session_value='PHPSESSID=supersecret')
    assert 'supersecret' not in cmd


def test_redacted_command_masks_clustered_attached_form():
    cmd = redacted_command(['https://example.test', '-vssupersecret'],
                            session_value='supersecret')
    assert 'supersecret' not in cmd


def test_redacted_command_no_session_leaves_argv_untouched():
    cmd = redacted_command(['https://example.test', '--verify'], session_value=None)
    assert cmd == 'osc https://example.test --verify'


def test_redacted_command_preserves_non_secret_flags():
    cmd = redacted_command(['https://example.test', '--verify', '-d', '2'])
    assert cmd == 'osc https://example.test --verify -d 2'


def test_plain_o_defaults_to_json():
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.json', None, None)
    assert out_json == 'output/report.json'
    assert html_path is None and csv_path is None
    assert extra_html is None and extra_csv is None


def test_o_csv_extension_is_promoted_to_csv_output():
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.csv', None, None)
    assert out_json is None
    assert csv_path == 'output/report.csv'
    assert extra_csv is None


def test_o_html_extension_is_promoted_to_html_output():
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.html', None, None)
    assert out_json is None
    assert html_path == 'output/report.html'
    assert extra_html is None


def test_o_csv_extension_is_case_insensitive():
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.CSV', None, None)
    assert out_json is None
    assert csv_path == 'output/report.CSV'


def test_o_html_extension_is_case_insensitive():
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.HTML', None, None)
    assert out_json is None
    assert html_path == 'output/report.HTML'


def test_o_csv_matching_explicit_csv_path_is_not_duplicated():
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.csv', None, 'output/report.csv')
    assert out_json is None
    assert csv_path == 'output/report.csv'
    assert extra_csv is None


def test_o_csv_with_different_explicit_csv_path_writes_both_not_dropped():
    # Regression: -o used to be silently discarded here instead of written.
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.csv', None, 'output/other.csv')
    assert out_json is None
    assert csv_path == 'output/other.csv'
    assert extra_csv == 'output/report.csv'


def test_o_html_with_different_explicit_html_path_writes_both_not_dropped():
    out_json, html_path, csv_path, extra_html, extra_csv = resolve_output_paths(
        'output/report.html', 'output/other.html', None)
    assert out_json is None
    assert html_path == 'output/other.html'
    assert extra_html == 'output/report.html'


def test_no_output_flags_returns_all_none():
    assert resolve_output_paths(None, None, None) == (None, None, None, None, None)
