"""Report writers for OSC: JSON, CSV and a self-contained HTML report."""

import csv
import json
import html
import time

from colorama import Fore, Style

from osc.patterns import RISK_LEVELS, CWE_MAPPINGS

_RISK_HEX = {'CRITICAL': '#7c0a0a', 'HIGH': '#e5484d', 'MEDIUM': '#f5a623',
             'LOW': '#30a46c', 'NONE': '#8b8b8b'}


def _risk_for(category):
    return RISK_LEVELS.get(category, 'LOW')


def _ok(fmt, path):
    print(f"{Fore.GREEN}[+] {fmt} report saved to: {path}{Style.RESET_ALL}")


def _err(fmt, exc):
    print(f"{Fore.RED}[-] Error saving {fmt} report: {exc}{Style.RESET_ALL}")


def write_json(report, path):
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)
        _ok('JSON', path)
    except Exception as exc:
        _err('JSON', exc)


def write_csv(report, path):
    try:
        with open(path, 'w', encoding='utf-8', newline='') as fh:
            writer = csv.writer(fh)
            writer.writerow(['cwe_id', 'category', 'confidence', 'risk', 'url', 'value',
                             'content_type', 'status_code', 'pattern', 'context',
                             'evidence', 'informational', 'remediation'])
            for f in report.get('findings', []):
                cat = f.get('category', '')
                cwe = f.get('cwe_id') or CWE_MAPPINGS.get(cat, 'CWE-200')
                rem = f.get('remediation') or f.get('context', '')
                writer.writerow([
                    cwe, cat, f.get('confidence', ''), _risk_for(cat),
                    f.get('url', ''), f.get('value', ''),
                    f.get('content_type', ''), f.get('status_code', ''),
                    f.get('pattern', ''), f.get('context', ''),
                    f.get('evidence', ''), 'yes' if f.get('informational') else '',
                    rem,
                ])
        _ok('CSV', path)
    except Exception as exc:
        _err('CSV', exc)


def _html_document(report):
    info = report.get('scan_info', {})
    summary = report.get('summary', {})
    findings = report.get('findings', [])
    risk = summary.get('risk_assessment', 'NONE')
    counts = summary.get('category_counts', {})
    risk_hex = _RISK_HEX.get(risk, '#8b8b8b')

    def esc(value):
        return html.escape(str(value), quote=True)

    def info_pill(finding):
        return " <span class='pill info'>info</span>" if finding.get('informational') else ''

    # reproducibility/scope_and_limitations get their own dedicated sections
    # below (repro_rows/limit_rows) - skip them here so they don't also show
    # up as raw Python repr text in the generic Scan Information table.
    _info_own_section = {'reproducibility', 'scope_and_limitations'}
    info_rows = ''.join(
        f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
        for k, v in info.items() if k not in _info_own_section
    )
    summary_rows = ''.join(
        f"<tr><td>{esc(cat)}</td><td class='num'>{esc(n)}</td>"
        f"<td><span class='pill {_risk_for(cat).lower()}'>{_risk_for(cat)}</span></td></tr>"
        for cat, n in counts.items()
    ) or "<tr><td colspan='3' class='muted'>No findings</td></tr>"

    finding_rows = ''.join(
        "<tr>"
        f"<td><span class='pill cwe'>{esc(f.get('cwe_id') or CWE_MAPPINGS.get(f.get('category',''), 'CWE-200'))}</span><br/>"
        f"<span class='pill {_risk_for(f.get('category','')).lower()}'>{esc(f.get('category',''))}</span></td>"
        f"<td>{esc(f.get('confidence',''))}"
        f"{info_pill(f)}</td>"
        f"<td class='mono url'>{esc(f.get('url',''))}</td>"
        f"<td class='mono val'>{esc(f.get('value',''))}</td>"
        f"<td class='mono ev'>{(esc(f.get('evidence','')) or '&mdash;')}</td>"
        f"<td class='mono ctx'>{esc(f.get('context',''))}</td>"
        f"<td class='mono rem'>{esc(f.get('remediation') or f.get('context','')) or '&mdash;'}</td>"
        "</tr>"
        for f in findings
    ) or "<tr><td colspan='7' class='muted'>No findings</td></tr>"

    limitations = info.get('scope_and_limitations', [])
    limit_rows = ''.join(
        f"<li>{esc(item)}</li>" for item in limitations
    ) or '<li class="muted">None recorded for this scan.</li>'

    reproducibility = info.get('reproducibility', {})
    repro_rows = ''.join(
        f"<tr><th>{esc(k)}</th><td class='mono'>{esc(v)}</td></tr>"
        for k, v in reproducibility.items()
    )

    generated = time.strftime('%Y-%m-%d %H:%M:%S')
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OSC Report - {esc(info.get('target', ''))}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin: 0; background: #0f1115; color: #e6e6e6;
         font-family: -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; }}
  .wrap {{ max-width: 1200px; margin: 0 auto; padding: 24px 16px 64px; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }}
  .sub {{ color: #9aa0aa; font-size: 13px; margin-bottom: 20px; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 999px;
            font-weight: 700; color: #fff; background: {risk_hex}; }}
  h2 {{ font-size: 15px; margin: 28px 0 10px; color: #c9ced6;
        border-bottom: 1px solid #262a33; padding-bottom: 6px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .scroll {{ overflow-x: auto; border: 1px solid #262a33; border-radius: 8px; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #1e222a;
            vertical-align: top; }}
  th {{ color: #9aa0aa; font-weight: 600; }}
  tr:last-child td {{ border-bottom: none; }}
  .num {{ text-align: right; }}
  .muted {{ color: #6b7280; text-align: center; }}
  .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }}
  .val {{ color: #ffd479; word-break: break-all; max-width: 300px; }}
  .url {{ color: #7cc7ff; word-break: break-all; max-width: 240px; }}
  .ev {{ color: #9fe8a4; word-break: break-all; max-width: 260px; white-space: pre-wrap; }}
  .ctx {{ color: #8b929e; word-break: break-all; max-width: 260px; white-space: pre-wrap; }}
  .rem {{ color: #a5d6ff; word-break: break-all; max-width: 260px; white-space: pre-wrap; }}
  .limits {{ margin: 0 0 0 18px; padding: 0; color: #8b929e; font-size: 13px; }}
  .limits li {{ margin: 4px 0; }}
  .info th {{ width: 180px; }}
  .pill {{ display: inline-block; padding: 2px 9px; border-radius: 999px;
           font-size: 11px; font-weight: 700; color: #fff; margin-bottom: 2px; }}
  .pill.cwe {{ background: #6e56cf; font-family: ui-monospace, monospace; }}
  .pill.high {{ background: #e5484d; }}
  .pill.medium {{ background: #f5a623; color: #201600; }}
  .pill.low {{ background: #30a46c; }}
  .pill.info {{ background: #3b82f6; }}
  footer {{ margin-top: 32px; color: #6b7280; font-size: 12px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>OSC - Open Source Code Scanner Report</h1>
  <div class="sub">Target: {esc(info.get('target', ''))} &middot; Generated {esc(generated)}</div>
  <div>Overall risk: <span class="badge">{esc(risk)} RISK</span>
       &nbsp; Total findings: <strong>{esc(summary.get('total_findings', 0))}</strong></div>

  <h2>Scan Information</h2>
  <div class="scroll"><table class="info">{info_rows}</table></div>

  <h2>Reproducibility</h2>
  <div class="scroll"><table class="info">{repro_rows}</table></div>

  <h2>Scope &amp; Limitations</h2>
  <ul class="limits">{limit_rows}</ul>

  <h2>Findings by Category</h2>
  <div class="scroll"><table>
    <tr><th>Category</th><th class="num">Count</th><th>Risk</th></tr>
    {summary_rows}
  </table></div>

  <h2>Findings ({esc(len(findings))})</h2>
  <div class="scroll"><table>
    <tr><th>Category / CWE</th><th>Confidence</th><th>URL</th><th>Value</th><th>Evidence</th><th>Context</th><th>Remediation</th></tr>
    {finding_rows}
  </table></div>

  <footer>
    Generated by OSC. Use only on systems you own or are explicitly authorized to test.
    Unauthorized scanning may be illegal in your jurisdiction.
  </footer>
</div>
</body>
</html>"""


def write_html(report, path):
    try:
        with open(path, 'w', encoding='utf-8') as fh:
            fh.write(_html_document(report))
        _ok('HTML', path)
    except Exception as exc:
        _err('HTML', exc)
