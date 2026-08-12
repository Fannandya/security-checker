"""Detection data for OSC: regex patterns, sensitive-file lists, risk levels.

Kept free of logic and heavy imports so every other module can import it safely.
"""

# Known high-signal secret prefixes: these bypass the entropy filter because the
# format itself is already strong evidence of a real credential.
KNOWN_SECRET_PREFIXES = (
    'sk_live_', 'sk_test_', 'rk_live_', 'rk_test_', 'akia', 'aiza', 'ya29.',
    'ghp_', 'gho_', 'ghs_', 'ghr_', 'github_pat_',
    'xoxb-', 'xoxp-', 'xoxa-', 'xoxr-', 'xoxs-', 'sg.', 'eyj', '-----begin',
)

# Regex patterns: category -> list of (pattern, value_group, confidence).
# value_group 0 = whole match; otherwise the capture group holding the value.
# Assignment patterns carry an inline (?i) so only the KEY name is case-insensitive;
# fixed-format prefixes (AKIA, ghp_, eyJ, ...) stay case-sensitive on purpose.
PATTERNS = {
    'api_keys': [
        (r'(?i)["\']?(?:api[_-]?key|apikey)["\']?\s*[=:]\s*["\']([^"\']{8,100})["\']', 1, 'medium'),
        (r'(?i)["\']?(?:api[_-]?secret|secret[_-]?key|client[_-]?secret)["\']?\s*[=:]\s*["\']([^"\']{8,100})["\']', 1, 'medium'),
        # Unquoted (.env / config style) KEY=VALUE
        (r'(?i)(?:api[_-]?key|apikey|secret[_-]?key|client[_-]?secret)\s*[=:]\s*([A-Za-z0-9_\-]{12,100})', 1, 'medium'),
        (r'sk_(?:live|test)_[A-Za-z0-9]{16,}', 0, 'high'),
        (r'AKIA[0-9A-Z]{16}', 0, 'high'),
        (r'ya29\.[0-9A-Za-z\-_]+', 0, 'high'),
        (r'AIza[0-9A-Za-z\-_]{35}', 0, 'high'),
        (r'gh[pousr]_[A-Za-z0-9]{36,}', 0, 'high'),
        (r'github_pat_[A-Za-z0-9_]{60,}', 0, 'high'),
        (r'xox[baprs]-[A-Za-z0-9-]{10,}', 0, 'high'),
        (r'SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}', 0, 'high'),
    ],
    'tokens': [
        (r'(?i)["\']?(?:token|access[_-]?token|auth[_-]?token)["\']?\s*[=:]\s*["\']([^"\']{12,300})["\']', 1, 'medium'),
        (r'(?i)["\']?(?:refresh[_-]?token|bearer[_-]?token)["\']?\s*[=:]\s*["\']([^"\']{12,300})["\']', 1, 'medium'),
        # Unquoted (.env / config style) token assignments
        (r'(?i)(?:access[_-]?token|auth[_-]?token|api[_-]?token)\s*[=:]\s*([A-Za-z0-9_\-.]{16,300})', 1, 'medium'),
        # Proper JWT: base64url header starting with eyJ, then two more segments
        (r'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}', 0, 'high'),
    ],
    'passwords': [
        (r'(?i)["\']?(?:password|passwd|pwd)["\']?\s*[=:]\s*["\']([^"\']{4,64})["\']', 1, 'medium'),
        (r'(?i)["\']?(?:db[_-]?password|database[_-]?pass)["\']?\s*[=:]\s*["\']([^"\']{4,64})["\']', 1, 'high'),
        (r'(?i)["\']?(?:passphrase)["\']?\s*[=:]\s*["\']([^"\']{4,64})["\']', 1, 'medium'),
        # Unquoted (.env / config style) password assignments
        (r'(?i)(?:password|passwd|db[_-]?password|database[_-]?pass)\s*[=:]\s*([^\s"\'<>&]{6,64})', 1, 'medium'),
    ],
    'database': [
        (r'(?i)["\']?(?:database[_-]?url|db[_-]?url|connection[_-]?string)["\']?\s*[=:]\s*["\']([^"\']+?)["\']', 1, 'high'),
        (r'(?:mysql|postgresql|postgres|mongodb|redis|mssql)://[^"\'\s<>]{4,}', 0, 'high'),
    ],
    'private_keys': [
        (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----', 0, 'high'),
    ],
    'emails': [
        (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', 0, 'low'),
    ],
    'internal_ips': [
        (r'\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 0, 'medium'),
        (r'\b192\.168\.\d{1,3}\.\d{1,3}\b', 0, 'medium'),
        (r'\b172\.(?:1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}\b', 0, 'medium'),
    ],
    'config_files': [
        (r'(?i)["\']?(?:config|configuration|settings)["\']?\s*[=:]\s*["\']([^"\']+?\.(?:json|ya?ml|ini|conf|config|php|py))["\']', 1, 'low'),
    ],
    'financial': [
        (r'(?i)(?:stripe|paypal|braintree)_(?:secret|key|token)["\']?\s*[=:]\s*["\']([^"\']{10,80})["\']', 1, 'high'),
        (r'rk_(?:live|test)_[A-Za-z0-9]{16,}', 0, 'high'),
    ],
}

# Extended sensitive files list (used both as discovery seeds and exposure checks)
SENSITIVE_FILES = [
    # Environment files
    '.env', '.env.local', '.env.production', '.env.development',
    # Configuration files
    'config.php', 'configuration.php', 'settings.php', 'wp-config.php',
    'config.json', 'settings.json', 'configuration.json',
    'config.yml', 'config.yaml', 'settings.yml', 'app.config',
    'web.config', '.htaccess', '.htpasswd',
    # Database files
    'database.yml', 'database.json', 'db.config',
    # Backup files
    '.bak', '.backup', '.old', '.tmp', '.temp', '.save',
    '.orig', '.copy', '.bk', '.back', '.swp',
    # Log files
    '.log', 'logs.txt', 'error.log', 'access.log',
    # Key files
    '.pem', '.key', '.crt', '.cert', '.pfx',
    'id_rsa', 'id_dsa', 'private.key',
    # Data files
    '.sql', '.db', '.sqlite', '.mdb',
    '.dump', '.export', '.dat',
    # VCS metadata
    '.git/config', '.git/HEAD', '.svn/entries', '.DS_Store',
]

# Risk level per finding category
RISK_LEVELS = {
    'api_keys': 'HIGH',
    'passwords': 'HIGH',
    'database': 'HIGH',
    'financial': 'HIGH',
    'tokens': 'HIGH',
    'private_keys': 'HIGH',
    'exposed_sensitive_file': 'MEDIUM',
    'config_files': 'MEDIUM',
    'internal_ips': 'MEDIUM',
    'sensitive_file_reference': 'LOW',
    'emails': 'LOW',
    # Web security posture (osc/security_audit.py) + passive crawl checks
    'tls_issues': 'HIGH',
    'cors_misconfiguration': 'HIGH',
    'directory_listing': 'MEDIUM',
    'security_headers': 'MEDIUM',
    'cookie_security': 'MEDIUM',
    'http_methods': 'MEDIUM',
    'open_redirect': 'MEDIUM',
    'tech_fingerprint': 'LOW',
    # Quick-win info-leak checks (osc/security_audit.py)
    'mixed_content': 'MEDIUM',
    'sri_missing': 'LOW',
    'security_txt_missing': 'LOW',
    'graphql_introspection': 'HIGH',
    # Recon (osc/recon.py)
    'subdomain_found': 'LOW',
    'open_port': 'MEDIUM',
    'waf_detected': 'LOW',
    # Active vulnerability probing (osc/active_scan.py)
    'xss_reflected': 'HIGH',
    'sqli_error': 'HIGH',
    'path_traversal': 'HIGH',
    'ssti': 'HIGH',
    'ssrf_candidate': 'LOW',
}

# Standard CWE ID mapping per category for QA & defect tracking compliance
CWE_MAPPINGS = {
    'api_keys': 'CWE-798',
    'passwords': 'CWE-798',
    'database': 'CWE-312',
    'financial': 'CWE-798',
    'tokens': 'CWE-798',
    'private_keys': 'CWE-321',
    'exposed_sensitive_file': 'CWE-538',
    'config_files': 'CWE-538',
    'internal_ips': 'CWE-200',
    'sensitive_file_reference': 'CWE-538',
    'emails': 'CWE-200',
    'tls_issues': 'CWE-326',
    'cors_misconfiguration': 'CWE-942',
    'directory_listing': 'CWE-548',
    'security_headers': 'CWE-693',
    'cookie_security': 'CWE-614',
    'http_methods': 'CWE-749',
    'open_redirect': 'CWE-601',
    'tech_fingerprint': 'CWE-200',
    'mixed_content': 'CWE-311',
    'sri_missing': 'CWE-353',
    'security_txt_missing': 'CWE-1008',
    'graphql_introspection': 'CWE-200',
    'subdomain_found': 'CWE-200',
    'open_port': 'CWE-319',
    'waf_detected': 'CWE-200',
    'xss_reflected': 'CWE-79',
    'sqli_error': 'CWE-89',
    'path_traversal': 'CWE-22',
    'ssti': 'CWE-1336',
    'ssrf_candidate': 'CWE-918',
}

# Remediation advice for the scanner's own secret/sensitive-file categories
# (osc/scanner.py's pattern-matching findings). security_audit.py, recon.py,
# and active_scan.py already attach their own category-specific remediation
# text at the point each finding is created; this dict only fills the gap for
# categories scanner.py produces directly, where `context` otherwise holds a
# matched code snippet (or nothing) rather than fix guidance.
REMEDIATION_ADVICE = {
    'api_keys': 'Revoke and rotate the exposed key immediately; remove it from source control '
                'history; load secrets from environment variables or a secrets manager, never '
                'commit them.',
    'passwords': 'Rotate the exposed password immediately; remove it from source control '
                 'history; store credentials in environment variables or a secrets manager, '
                 'never in code/config committed to a repo.',
    'database': 'Rotate the database credentials/connection string immediately; remove it from '
                'source control history; load it from environment variables or a secrets '
                'manager, and restrict database network access.',
    'financial': 'Rotate/revoke the exposed financial credential immediately; remove it from '
                 'source control history; store it in a secrets manager, never in committed '
                 'code.',
    'tokens': 'Revoke and rotate the exposed token immediately; remove it from source control '
              'history; load tokens from environment variables or a secrets manager.',
    'private_keys': 'Revoke/reissue the exposed private key immediately - it must be treated as '
                     'fully compromised; remove it from source control history; store keys '
                     'outside the web root and never commit them.',
    'exposed_sensitive_file': 'Remove or restrict access to this file (e.g. deny .env/.git in '
                               'nginx/Apache config); ensure it is never deployed to a publicly '
                               'reachable directory.',
    'config_files': 'Remove this file from the publicly served directory or block access to it '
                     'via web server config; move sensitive config out of the web root.',
    'internal_ips': 'Avoid leaking internal network topology in public responses; scrub '
                     'internal IPs from error messages, comments, and client-facing output.',
    'sensitive_file_reference': 'Verify the referenced file is not actually reachable; remove '
                                 'references to sensitive filenames from public-facing '
                                 'content/comments.',
    'emails': 'Low severity - consider whether this address needs to be publicly listed, or '
              'replace with a contact form to reduce scraping/spam exposure.',
    'directory_listing': 'Disable autoindex/directory listing at the web server (e.g. '
                          '"Options -Indexes" in Apache, "autoindex off;" in nginx); confirm no '
                          'sensitive files are reachable in the listed directory in the meantime.',
    'open_redirect': 'Validate redirect targets against an allowlist of in-scope hosts/paths '
                      'instead of trusting a query-string parameter directly; if external '
                      'redirects are required, show an interstitial warning page first.',
}

