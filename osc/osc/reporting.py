"""Report writers for OSC: JSON, CSV and a self-contained HTML report."""

import csv
import json
import html
import time

from colorama import Fore, Style

from osc.patterns import RISK_LEVELS

_RISK_HEX = {'HIGH': '#e5484d', 'MEDIUM': '#f5a623', 'LOW': '#30a46c', 'NONE': '#8b8b8b'}


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
            writer.writerow(['category', 'confidence', 'risk', 'url', 'value',
                             'content_type', 'status_code', 'pattern', 'context'])
            for f in report.get('findings', []):
                cat = f.get('category', '')
                writer.writerow([
                    cat, f.get('confidence', ''), _risk_for(cat),
                    f.get('url', ''), f.get('value', ''),
                    f.get('content_type', ''), f.get('status_code', ''),
                    f.get('pattern', ''), f.get('context', ''),
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

    info_rows = ''.join(
        f"<tr><th>{esc(k)}</th><td>{esc(v)}</td></tr>"
        for k, v in info.items()
    )
    summary_rows = ''.join(
        f"<tr><td>{esc(cat)}</td><td class='num'>{esc(n)}</td>"
        f"<td><span class='pill {_risk_for(cat).lower()}'>{_risk_for(cat)}</span></td></tr>"
        for cat, n in counts.items()
    ) or "<tr><td colspan='3' class='muted'>No findings</td></tr>"

    finding_rows = ''.join(
        "<tr>"
        f"<td><span class='pill {_risk_for(f.get('category','')).lower()}'>{esc(f.get('category',''))}</span></td>"
        f"<td>{esc(f.get('confidence',''))}</td>"
        f"<td class='mono url'>{esc(f.get('url',''))}</td>"
        f"<td class='mono val'>{esc(f.get('value',''))}</td>"
        f"<td class='mono ctx'>{esc(f.get('context',''))}</td>"
        "</tr>"
        for f in findings
    ) or "<tr><td colspan='5' class='muted'>No findings</td></tr>"

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
  .wrap {{ max-width: 1100px; margin: 0 auto; padding: 24px 16px 64px; }}
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
  .val {{ color: #ffd479; word-break: break-all; max-width: 340px; }}
  .url {{ color: #7cc7ff; word-break: break-all; max-width: 260px; }}
  .ctx {{ color: #8b929e; word-break: break-all; max-width: 320px; }}
  .info th {{ width: 180px; }}
  .pill {{ display: inline-block; padding: 2px 9px; border-radius: 999px;
           font-size: 11px; font-weight: 700; color: #fff; }}
  .pill.high {{ background: #e5484d; }}
  .pill.medium {{ background: #f5a623; color: #201600; }}
  .pill.low {{ background: #30a46c; }}
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

  <h2>Findings by Category</h2>
  <div class="scroll"><table>
    <tr><th>Category</th><th class="num">Count</th><th>Risk</th></tr>
    {summary_rows}
  </table></div>

  <h2>Findings ({esc(len(findings))})</h2>
  <div class="scroll"><table>
    <tr><th>Category</th><th>Confidence</th><th>URL</th><th>Value</th><th>Context</th></tr>
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
