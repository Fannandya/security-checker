#!/usr/bin/env python3
"""Command-line interface for OSC - Open Source Code Scanner."""

import sys
import os
import argparse

from colorama import Fore, Style

from osc.scanner import EnhancedOSCScanner


def build_parser():
    parser = argparse.ArgumentParser(description='OSC - Open Source Code Scanner', add_help=False)
    parser.add_argument('target', nargs='?', help='Target URL to scan')
    parser.add_argument('-s', '--session', help='Session cookie for authenticated scanning')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('-d', '--depth', type=int, default=1,
                        help='Crawl depth for in-scope links (0 = seeds only, default: 1)')
    parser.add_argument('--max-urls', type=int, default=2500, dest='max_urls',
                        help='Maximum URLs to scan (default: 2500)')
    parser.add_argument('--delay', type=float, default=0.0,
                        help='Delay in seconds between requests per worker (default: 0)')
    parser.add_argument('--retries', type=int, default=2,
                        help='HTTP retries on transient errors (default: 2)')
    parser.add_argument('--user-agent', dest='user_agent', help='Custom User-Agent string')
    parser.add_argument('--verify', action='store_true',
                        help='Enable TLS certificate verification (default: disabled)')
    parser.add_argument('--wordlist', help='Custom wordlist file for path/endpoint brute-force '
                                            '(default: bundled)')
    parser.add_argument('--extensions', help='Comma-separated extensions to try (e.g. php,bak,sql)')
    parser.add_argument('--skip-audit', dest='skip_audit', action='store_true',
                        help='Skip the security posture audit (headers/cookies/CORS/TLS/methods)')
    parser.add_argument('--subdomain-wordlist', dest='subdomain_wordlist',
                        help='Custom wordlist for DNS subdomain brute-force (default: bundled; '
                             'requires dnspython)')
    parser.add_argument('--ports', help='Comma-separated TCP ports to scan during recon '
                                         '(default: curated ~35-port common-service list)')
    parser.add_argument('-X', '--active', action='store_true',
                        help='Enable active vulnerability probing (XSS/SQLi/traversal/SSTI/SSRF-candidate)')
    parser.add_argument('--active-checks', dest='active_checks',
                        help='Comma-separated active checks to run (default: all; '
                             'xss,sqli,traversal,ssti,ssrf)')
    parser.add_argument('-o', '--output', help='Write report to FILE (format auto-detected '
                                                'from extension: .csv, .html, otherwise JSON)')
    parser.add_argument('--html', help='Write HTML report to FILE')
    parser.add_argument('--csv', help='Write CSV report to FILE')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output (errors + progress)')
    parser.add_argument('-h', '--help', action='store_true', help='Show help message')
    return parser


def _prepare_output_path(filename):
    if not filename:
        return None
    # Jika user sudah memberi path spesifik (misal /tmp/hasil.json), gunakan itu
    if os.path.dirname(filename):
        return filename
    # Jika hanya nama file (misal hasil.json), buat dan masukkan ke folder output/
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)
    return os.path.join(output_dir, filename)


def redacted_command(argv, session_value=None):
    """Build a display-safe copy of the parsed CLI invocation for the report's
    reproducibility.command field: same flags, but the -s/--session VALUE
    (often a live session cookie) is masked so a shared/archived report never
    leaks it. Takes the argv actually parsed (not raw sys.argv), so a
    programmatic `main(argv=...)` call is reflected accurately too.

    `session_value` should be the already-parsed `args.session` (the exact
    string argparse extracted), not something re-derived from argv here.
    Matching against the known value - rather than pattern-matching argv
    tokens for "-s"/"--session" spellings - means every form argparse accepts
    is covered for free: space-separated, "--session=...", attached
    "-sVALUE", and short-option clusters like "-vsVALUE" or "-Xs VALUE"
    (a hand-rolled token classifier missed the clustered forms and leaked
    the cookie verbatim).
    """
    if not session_value:
        return 'osc ' + ' '.join(argv)
    redacted = [tok.replace(session_value, '<REDACTED>') if session_value in tok else tok
                for tok in argv]
    return 'osc ' + ' '.join(redacted)


def resolve_output_paths(out_json, html_path, csv_path):
    """Work out the final (json, html, csv, extra_html, extra_csv) paths to write.

    -o auto-detects format from its extension: .csv -> CSV, .html -> HTML,
    else JSON. This prevents the old footgun of "osc -o hasil.csv" silently
    writing JSON. If --csv/--html was ALSO given pointing at a different file,
    -o is not discarded; it's returned as an extra_* path so the caller can
    write it separately and no requested output is lost.
    """
    extra_csv_path = None
    extra_html_path = None
    out_ext = out_json.lower() if out_json else ''
    if out_ext.endswith('.csv'):
        if csv_path and csv_path != out_json:
            extra_csv_path = out_json
        else:
            csv_path = out_json
        out_json = None
    elif out_ext.endswith('.html'):
        if html_path and html_path != out_json:
            extra_html_path = out_json
        else:
            html_path = out_json
        out_json = None
    return out_json, html_path, csv_path, extra_html_path, extra_csv_path


def parse_ports(raw):
    """Parse --ports' comma-separated value into a list of ints, or None if
    `raw` is empty/falsy. Raises ValueError on a non-numeric entry."""
    if not raw:
        return None
    return [int(p.strip()) for p in raw.split(',') if p.strip()]


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.help or not args.target:
        EnhancedOSCScanner('http://example.com').print_help()
        sys.exit(0)

    target = args.target
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target

    extensions = None
    if args.extensions:
        extensions = [e.strip() for e in args.extensions.split(',') if e.strip()]

    active_checks = None
    if args.active_checks:
        active_checks = [c.strip() for c in args.active_checks.split(',') if c.strip()]

    try:
        ports = parse_ports(args.ports)
    except ValueError:
        print(f"{Fore.RED}[!] --ports must be a comma-separated list of numbers "
              f"(e.g. --ports 21,22,80,443){Style.RESET_ALL}")
        sys.exit(1)

    try:
        scanner = EnhancedOSCScanner(
            target=target,
            session_cookie=args.session,
            max_threads=args.threads,
            timeout=args.timeout,
            depth=args.depth,
            max_urls=args.max_urls,
            delay=args.delay,
            retries=args.retries,
            user_agent=args.user_agent,
            verify=args.verify,
            verbose=args.verbose,
            aggressive=True,  # always on - no manual/aggressive mode switch (see README)
            wordlist=args.wordlist,
            extensions=extensions,
            skip_audit=args.skip_audit,
            recon=True,  # always on - no manual/aggressive mode switch (see README)
            subdomain_wordlist=args.subdomain_wordlist,
            ports=ports,
            active=args.active,
            active_checks=active_checks,
        )
        # Audit trail: record the (session-redacted) command so reports are
        # reproducible without leaking a live session cookie into the report.
        scanner.cli_command = redacted_command(
            argv if argv is not None else sys.argv[1:], session_value=args.session)

        out_json, html_path, csv_path, extra_html_path, extra_csv_path = resolve_output_paths(
            _prepare_output_path(args.output),
            _prepare_output_path(args.html),
            _prepare_output_path(args.csv),
        )

        report = scanner.run_scan(
            output_file=out_json,
            html_file=html_path,
            csv_file=csv_path
        )

        if extra_csv_path or extra_html_path:
            from osc import reporting
            if extra_csv_path:
                reporting.write_csv(report, extra_csv_path)
            if extra_html_path:
                reporting.write_html(report, extra_html_path)
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!] Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as exc:
        print(f"{Fore.RED}[!] Error: {str(exc)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main()
