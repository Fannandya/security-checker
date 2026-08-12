"""Active vulnerability probing: reflected XSS, error-based SQL injection,
path traversal/LFI, basic SSTI, and an SSRF-candidate-parameter heuristic.

Opt-in only (-X/--active). Every check sends a small, bounded number of
extra, non-destructive requests per query-string parameter on URLs the
crawler already discovered - no time-based/blind payloads, no exploitation,
no requests outside the already-scanned scope. Findings are plain dicts
shaped like scanner findings so they flow straight through the existing
report pipeline (JSON/HTML/CSV).
"""

import random
import re
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

ALL_CHECKS = ('xss', 'sqli', 'traversal', 'ssti', 'ssrf')


def _finding(url, category, value, confidence, context=''):
    return {
        'url': url,
        'category': category,
        'value': value,
        'confidence': confidence,
        'pattern': 'active_scan',
        'content_type': '',
        'context': context,
    }


def _urls_with_params(urls):
    """Yield (url, split_parts, query_pairs) for URLs that carry query params."""
    for url in urls:
        parts = urlsplit(url)
        if not parts.query:
            continue
        pairs = parse_qsl(parts.query, keep_blank_values=True)
        if pairs:
            yield url, parts, pairs


def _build_url(parts, pairs, target_index, payload):
    mutated = list(pairs)
    key, _ = mutated[target_index]
    mutated[target_index] = (key, payload)
    new_query = urlencode(mutated)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


# ---------------------------------------------------------------------- #
# Reflected XSS
# ---------------------------------------------------------------------- #
def _check_xss(session, parts, pairs, index, timeout, verify):
    marker = 'oscXSS' + ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    payload = f'"><{marker}>'
    test_url = _build_url(parts, pairs, index, payload)
    try:
        resp = session.get(test_url, timeout=timeout, verify=verify)
    except Exception:
        return None
    if payload in resp.text:
        key = pairs[index][0]
        return _finding(
            test_url, 'xss_reflected',
            f"Reflected XSS: parameter '{key}' echoes an unescaped HTML payload",
            'high', f"Injected: {payload}",
        )
    return None


# ---------------------------------------------------------------------- #
# SQL injection (error-based only - no time-based/blind to avoid target load)
# ---------------------------------------------------------------------- #
_SQL_ERROR_SIGNATURES = [
    re.compile(r'you have an error in your sql syntax', re.I),
    re.compile(r'warning:\s*mysqli?_', re.I),
    re.compile(r'unclosed quotation mark after the character string', re.I),
    re.compile(r'quoted string not properly terminated', re.I),
    re.compile(r'pg_query\(\)|postgresql query failed', re.I),
    re.compile(r'sqlite3?\.OperationalError|sqlite_error|sqlstate\[hy000\]', re.I),
    re.compile(r'ora-\d{5}', re.I),
    re.compile(r'microsoft ole db provider for odbc drivers', re.I),
    re.compile(r'odbc (sql server driver|drivers)', re.I),
]


def _looks_like_sql_error(text):
    return bool(text) and any(pattern.search(text) for pattern in _SQL_ERROR_SIGNATURES)


def _check_sqli(session, parts, pairs, index, timeout, verify, baseline_text):
    key, original = pairs[index]
    payload = (original or '') + "'"
    test_url = _build_url(parts, pairs, index, payload)
    try:
        resp = session.get(test_url, timeout=timeout, verify=verify)
    except Exception:
        return None
    if _looks_like_sql_error(resp.text) and not _looks_like_sql_error(baseline_text):
        return _finding(
            test_url, 'sqli_error',
            f"Possible SQL injection: parameter '{key}' triggers a DB error signature "
            f"when a single quote is appended",
            'high', "Injected payload appended: '",
        )
    return None


# ---------------------------------------------------------------------- #
# Path traversal / LFI
# ---------------------------------------------------------------------- #
_TRAVERSAL_PARAM_HINTS = re.compile(r'file|path|page|include|template|doc|dir|folder', re.I)
_TRAVERSAL_PAYLOAD = '../' * 6 + 'etc/passwd'
_PASSWD_SIGNATURE = re.compile(r'root:.*:0:0:')


def _check_traversal(session, parts, pairs, index, timeout, verify):
    key, _original = pairs[index]
    if not _TRAVERSAL_PARAM_HINTS.search(key):
        return None
    test_url = _build_url(parts, pairs, index, _TRAVERSAL_PAYLOAD)
    try:
        resp = session.get(test_url, timeout=timeout, verify=verify)
    except Exception:
        return None
    if _PASSWD_SIGNATURE.search(resp.text):
        return _finding(
            test_url, 'path_traversal',
            f"Path traversal / LFI: parameter '{key}' returns /etc/passwd contents",
            'high', f"Injected: {_TRAVERSAL_PAYLOAD}",
        )
    return None


# ---------------------------------------------------------------------- #
# Basic SSTI (Jinja2/Twig, FreeMarker/EL, Ruby ERB syntaxes)
# ---------------------------------------------------------------------- #
_SSTI_TEMPLATES = ('{{%d*%d}}', '${%d*%d}', '#{%d*%d}')


def _check_ssti(session, parts, pairs, index, timeout, verify):
    key, original = pairs[index]
    a, b = random.randint(13, 19), random.randint(13, 19)
    product = str(a * b)
    original = original or ''
    for template in _SSTI_TEMPLATES:
        payload = template % (a, b)
        test_url = _build_url(parts, pairs, index, payload)
        try:
            resp = session.get(test_url, timeout=timeout, verify=verify)
        except Exception:
            continue
        # Guard against the product coincidentally already being present via the
        # original param value rather than actual template evaluation.
        if product in resp.text and str(a) not in original and str(b) not in original:
            return _finding(
                test_url, 'ssti',
                f"Possible Server-Side Template Injection: parameter '{key}' evaluates "
                f"'{payload}' to {product}",
                'high', f"Injected: {payload}",
            )
    return None


# ---------------------------------------------------------------------- #
# SSRF candidate parameters (heuristic only - no OOB collaborator, so this
# cannot confirm exploitation; it flags parameters worth manual follow-up)
# ---------------------------------------------------------------------- #
_SSRF_PARAM_NAMES = re.compile(
    r'^(url|uri|link|target|dest|destination|redirect|callback|webhook|proxy|fetch|src|feed)$',
    re.I,
)


def _check_ssrf_candidate(url, pairs, index):
    key, _value = pairs[index]
    if _SSRF_PARAM_NAMES.match(key.strip()):
        return _finding(
            url, 'ssrf_candidate',
            f"Parameter '{key}' accepts what looks like a URL - possible SSRF sink",
            'low',
            'Heuristic only, not exploited here (confirming SSRF needs an out-of-band '
            'listener). Manually test by pointing this parameter at a host you control.',
        )
    return None


# ---------------------------------------------------------------------- #
# Driver
# ---------------------------------------------------------------------- #
def run_all(session, urls, timeout, verify, checks=None, max_threads=10):
    """Run the selected active checks against every query param of every
    URL in `urls` that carries a query string. `checks` is an iterable
    subset of ALL_CHECKS (default: all)."""
    checks = set(checks) if checks else set(ALL_CHECKS)
    tasks = []

    for url, parts, pairs in _urls_with_params(urls):
        baseline_text = ''
        if 'sqli' in checks:
            try:
                baseline_text = session.get(url, timeout=timeout, verify=verify).text
            except Exception:
                baseline_text = ''
        for index in range(len(pairs)):
            tasks.append((url, parts, pairs, index, baseline_text))

    def _run_one(task):
        url, parts, pairs, index, baseline_text = task
        results = []
        if 'xss' in checks:
            result = _check_xss(session, parts, pairs, index, timeout, verify)
            if result:
                results.append(result)
        if 'sqli' in checks:
            result = _check_sqli(session, parts, pairs, index, timeout, verify, baseline_text)
            if result:
                results.append(result)
        if 'traversal' in checks:
            result = _check_traversal(session, parts, pairs, index, timeout, verify)
            if result:
                results.append(result)
        if 'ssti' in checks:
            result = _check_ssti(session, parts, pairs, index, timeout, verify)
            if result:
                results.append(result)
        if 'ssrf' in checks:
            result = _check_ssrf_candidate(url, pairs, index)
            if result:
                results.append(result)
        return results

    findings = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(_run_one, task) for task in tasks]
        for future in as_completed(futures):
            try:
                findings.extend(future.result())
            except Exception:
                continue

    return findings
